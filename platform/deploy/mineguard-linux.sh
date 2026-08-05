#!/usr/bin/env bash

set -Eeuo pipefail

umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PLATFORM_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." >/dev/null 2>&1 && pwd -P)"
VENV_DIRECTORY="${PLATFORM_ROOT}/.venv"
VENV_PYTHON="${VENV_DIRECTORY}/bin/python"
MINEGUARD_BIN="${VENV_DIRECTORY}/bin/mineguard"
DEFAULT_DEMO_STATE="${PLATFORM_ROOT}/.mineguard-v2-demo"
DEFAULT_FORMAL_STATE="${PLATFORM_ROOT}/.mineguard-v2"

FORMAL_STATE_DIRECTORY="${DEFAULT_FORMAL_STATE}"
LAST_PORT="8080"

say() {
    printf '%s\n' "$*"
}

find_python3() {
    local python_path
    python_path="$(command -v python3 2>/dev/null || true)"
    if [[ -z "${python_path}" ]]; then
        say "未找到 python3。请先从本单位批准的离线软件源安装 Python 3.11 或更高版本。" >&2
        return 1
    fi
    if ! "${python_path}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        say "当前 python3 版本低于 3.11，无法运行 MineGuard Platform。" >&2
        say "请先从本单位批准的离线软件源安装 Python 3.11 或更高版本。" >&2
        return 1
    fi
    printf '%s\n' "${python_path}"
}

resolve_wheelhouse() {
    local configured="${MINEGUARD_WHEELHOUSE:-}"
    local candidate
    if [[ -n "${configured}" ]]; then
        candidate="${configured}"
    elif [[ -d "${PLATFORM_ROOT}/wheelhouse" ]]; then
        candidate="${PLATFORM_ROOT}/wheelhouse"
    else
        return 1
    fi

    if [[ ! -d "${candidate}" ]]; then
        say "离线依赖目录不存在：${candidate}" >&2
        return 2
    fi
    (cd -- "${candidate}" >/dev/null 2>&1 && pwd -P)
}

install_local_runtime() {
    local python_path
    local wheelhouse=""
    local wheelhouse_status=0
    local -a install_arguments

    python_path="$(find_python3)" || return 1
    if [[ ! -f "${PLATFORM_ROOT}/pyproject.toml" || ! -d "${PLATFORM_ROOT}/src/mineguard" ]]; then
        say "当前目录不是完整的 MineGuard Platform 离线发行目录：${PLATFORM_ROOT}" >&2
        say "请确认 U 盘中的 platform 目录已完整复制，再重新运行本脚本。" >&2
        return 1
    fi

    if [[ ! -x "${VENV_PYTHON}" ]]; then
        if [[ -e "${VENV_DIRECTORY}" ]]; then
            say "发现不完整的虚拟环境：${VENV_DIRECTORY}" >&2
            say "为避免覆盖现有文件，本脚本没有自动删除它。请由运维人员核对后移走该目录再重试。" >&2
            return 1
        fi
        say "正在创建本地运行环境（不会写入系统目录）……"
        if ! "${python_path}" -m venv "${VENV_DIRECTORY}"; then
            say "创建本地运行环境失败。请确认离线安装的 Python 包含 venv 组件。" >&2
            return 1
        fi
    fi

    if ! "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
        say "本地 Python 环境缺少 pip，无法从离线介质安装依赖。" >&2
        say "请换用包含 pip 和 venv 的完整 Python 3.11+ 离线安装包。" >&2
        return 1
    fi

    if wheelhouse="$(resolve_wheelhouse)"; then
        install_arguments=(
            --disable-pip-version-check
            --no-input
            --no-index
            --find-links "${wheelhouse}"
        )
    else
        wheelhouse_status=$?
        if (( wheelhouse_status == 2 )); then
            return 1
        fi
        say "未找到完整的离线依赖目录，无法安全安装且不会尝试连接互联网。" >&2
        say "请把发行包的 wheelhouse 文件夹放到：${PLATFORM_ROOT}/wheelhouse" >&2
        say "也可在运行前将 MINEGUARD_WHEELHOUSE 指向 U 盘上的离线依赖文件夹。" >&2
        return 1
    fi

    if [[ -f "${PLATFORM_ROOT}/constraints.txt" ]]; then
        install_arguments+=(--constraint "${PLATFORM_ROOT}/constraints.txt")
    fi
    install_arguments+=("${PLATFORM_ROOT}")

    say "正在从离线介质安装 MineGuard Platform……"
    if ! PIP_CONFIG_FILE=/dev/null \
        PIP_NO_INDEX=1 \
        PIP_INDEX_URL= \
        PIP_EXTRA_INDEX_URL= \
        PIP_FIND_LINKS= \
        "${VENV_PYTHON}" -m pip install "${install_arguments[@]}"; then
        say "离线安装未完成。wheelhouse 中可能缺少依赖或版本与本机 Python 不匹配。" >&2
        say "请让发布人员提供与本机系统、Python 版本匹配的完整离线依赖包；本脚本未联网。" >&2
        return 1
    fi
    if [[ ! -x "${MINEGUARD_BIN}" ]]; then
        say "安装命令已结束，但未生成 mineguard 入口；请保留上方输出并联系运维人员。" >&2
        return 1
    fi
    say "本地运行环境已准备完成。"
}

ensure_runtime() {
    if [[ -x "${MINEGUARD_BIN}" ]]; then
        return 0
    fi
    install_local_runtime
}

read_with_default() {
    local prompt="$1"
    local default_value="$2"
    local answer
    printf '%s' "${prompt} [${default_value}]：" >&2
    if ! IFS= read -r answer; then
        printf '\n' >&2
        return 1
    fi
    if [[ -z "${answer}" ]]; then
        answer="${default_value}"
    fi
    printf '%s\n' "${answer}"
}

read_port() {
    local answer
    while true; do
        answer="$(read_with_default "监听端口" "${LAST_PORT}")" || return 1
        if [[ "${answer}" =~ ^[0-9]{1,5}$ ]] && (( 10#${answer} >= 1 && 10#${answer} <= 65535 )); then
            printf '%s\n' "$((10#${answer}))"
            return 0
        fi
        say "端口必须是 1 到 65535 之间的整数。" >&2
    done
}

run_demo() {
    local status
    ensure_runtime || return 1
    say ""
    say "正在启动本机演示。浏览器地址会显示在下方；按 Ctrl+C 可停止并返回菜单。"
    if "${MINEGUARD_BIN}" demo \
        --state-directory "${DEFAULT_DEMO_STATE}" \
        --port "${LAST_PORT}"; then
        return 0
    else
        status=$?
    fi
    if (( status == 130 )); then
        say "演示已停止。"
        return 0
    fi
    say "演示启动失败（退出码 ${status}）。请查看上方中文提示。" >&2
    return 1
}

run_setup() {
    local requested_state
    local requested_port
    local status
    ensure_runtime || return 1
    say ""
    say "正式配置只写入你指定的状态目录，不会改系统服务。"
    say "随后程序会询问 clients.json、HTTPS、管理员账号和密码；密码输入时不会显示。"
    requested_state="$(read_with_default "正式数据目录" "${FORMAL_STATE_DIRECTORY}")" || return 1
    requested_port="$(read_port)" || return 1

    if "${MINEGUARD_BIN}" setup \
        --state-directory "${requested_state}" \
        --port "${requested_port}"; then
        FORMAL_STATE_DIRECTORY="${requested_state}"
        LAST_PORT="${requested_port}"
        say "正式配置完成。请选择菜单 3 启动现有配置。"
        return 0
    else
        status=$?
    fi
    if (( status == 130 )); then
        say "已取消正式配置。"
        return 0
    fi
    say "正式配置未完成（退出码 ${status}）。原有业务数据不会被本脚本删除。" >&2
    return 1
}

run_existing() {
    local requested_state
    local status
    ensure_runtime || return 1
    requested_state="$(read_with_default "正式数据目录" "${FORMAL_STATE_DIRECTORY}")" || return 1
    FORMAL_STATE_DIRECTORY="${requested_state}"
    say "正在启动正式平台；按 Ctrl+C 可停止并返回菜单。"
    if "${MINEGUARD_BIN}" start --state-directory "${requested_state}"; then
        return 0
    else
        status=$?
    fi
    if (( status == 130 )); then
        say "平台已停止。"
        return 0
    fi
    say "平台启动失败（退出码 ${status}）。若尚未配置，请先选择菜单 2。" >&2
    return 1
}

health_check() {
    local python_path
    local requested_port
    python_path="${VENV_PYTHON}"
    if [[ ! -x "${python_path}" ]]; then
        python_path="$(find_python3)" || return 1
    fi
    requested_port="$(read_port)" || return 1
    LAST_PORT="${requested_port}"

    if "${python_path}" - "${requested_port}" <<'PY'
import json
import sys
import urllib.error
import urllib.request

port = int(sys.argv[1])
url = f"http://127.0.0.1:{port}/healthz"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with opener.open(request, timeout=3) as response:
        status = response.status
        payload = response.read(4096)
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        document = None
    if not isinstance(document, dict) or document.get("service") != "mineguard-v2":
        raise RuntimeError("端口响应不是 MineGuard Platform")
    if document.get("status") != "ok":
        raise RuntimeError("服务返回了非健康状态")
except (OSError, RuntimeError, urllib.error.URLError) as error:
    print(f"健康检查失败：{url}（{error}）", file=sys.stderr)
    raise SystemExit(1)
print(f"健康检查通过：{url}")
PY
    then
        return 0
    fi
    say "请确认平台已经启动、端口输入正确，并查看启动窗口中的报错。" >&2
    return 1
}

print_menu() {
    say ""
    say "MineGuard Platform · Linux 启动菜单"
    say "平台目录：${PLATFORM_ROOT}"
    say "1  演示启动"
    say "2  正式首次配置"
    say "3  启动现有配置"
    say "4  健康检查"
    say "5  退出"
}

main() {
    local choice
    cd -- "${PLATFORM_ROOT}"
    while true; do
        print_menu
        printf '%s' "请输入序号 [1-5]："
        if ! IFS= read -r choice; then
            printf '\n'
            return 0
        fi
        case "${choice}" in
            1) run_demo || true ;;
            2) run_setup || true ;;
            3) run_existing || true ;;
            4) health_check || true ;;
            5)
                say "已退出。"
                return 0
                ;;
            *) say "请输入 1、2、3、4 或 5。" >&2 ;;
        esac
    done
}

main "$@"
