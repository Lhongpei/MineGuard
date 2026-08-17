"""Production CLI for the government five-quantity V2 product.

Legacy analysis utilities are not imported or installed as a command.  This
keeps the supported runtime independent from the retired edge/safety/casework
stack while old source remains available only for controlled data migration.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import sys
from collections.abc import Sequence
from datetime import date
from hashlib import sha256
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__
from .auth import (
    CURRENT_CREDENTIAL_POLICY_VERSION,
    AuthError,
    InvalidCredentialsError,
    LocalAuthStore,
    Role,
    inspect_auth_database,
)
from .instance_lock import StateInstanceLock
from .operations import BackupManager, OperationsError
from .regulatory_v2_demo import (
    DEFAULT_V2_DEMO_STATE_DIRECTORY,
    V2_WORKBOOK_DEMO_MINES,
    V2DemoSeedError,
    seed_v2_demo_state,
)
from .regulatory_v2_http import serve
from .resources import read_package_resource
from .runtime_manifest import build_runtime_manifest


class ProductConfigurationError(ValueError):
    """Safe operator-facing configuration error."""


_DEMO_DEFAULT_PASSWORD = "123123123"
_MIN_PASSWORD_LENGTH = 8
_FORMAL_MIN_PASSWORD_LENGTH = 12
_COMMON_WEAK_PASSWORDS = frozenset(
    {
        "12345678",
        "123456789",
        "123123123",
        "admin123",
        "admin123456",
        "password",
        "password123",
        "qwerty123",
    }
)
_MINE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PLACEHOLDER_SECRET = re.compile(
    r"(?i)(?:replace(?:[_ -]|\b)|change[_ -]?me|demo[_ -]?only|"
    r"not[_ -]?for[_ -]?production)"
)
_QUICK_START_SETTINGS = ".mineguard-start.json"
_QUICK_START_SETTINGS_KIND = "mineguard-platform-start"
_QUICK_START_SETTINGS_SCHEMA = 1
_QUICK_START_SETTINGS_MAX_BYTES = 32 * 1024
_DEMO_STATE_MARKER = ".mineguard-v2-synthetic-owner.json"
_WINDOWS_STATE_MARKER = ".mineguard-platform-state.json"
_CLIENT_REGISTRY_ENVIRONMENT = (
    "MINEGUARD_V2_CLIENTS_JSON",
    "MINEGUARD_V2_CLIENTS_FILE",
)
_LOCAL_CONTROL_ENVIRONMENT = "MINEGUARD_LOCAL_CONTROL_TOKEN"
_LOCAL_CONTROL_TOKEN = re.compile(r"[0-9a-f]{64}")
_BOOTSTRAP_PASSWORD_FILENAME = "bootstrap-admin-password.txt"
_BOOTSTRAP_PASSWORD_MAX_BYTES = 4096
_ROLE_LABELS = {
    Role.ADMIN: "系统管理员（查看全部煤矿）",
    Role.SUPERVISOR: "辖区监管负责人（只读）",
    Role.REVIEWER: "监管复核人员（只读）",
    Role.VIEWER: "领导查看账号（只读）",
}


def _port(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("端口必须是整数") from error
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1-65535 之间")
    return result


def _calendar_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("日期必须为 YYYY-MM-DD") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mineguard",
        description=(
            "MineGuard · 矿安智察——煤矿智能辅助监管系统"
            "（唯一算法、只读业务前端）"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("serve", help="启动政府 V2 API 与只读大屏")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=_port, default=8080)
    server.add_argument("--state-directory", default=".mineguard-v2")
    server.add_argument("--admin-username", default="admin")
    server.add_argument(
        "--no-auth",
        action="store_true",
        help="仅限回环地址隔离演示；关闭领导端登录",
    )
    server.add_argument(
        "--secure-cookie", action="store_true", help="HTTPS 代理部署时启用"
    )
    server.add_argument(
        "--production",
        action="store_true",
        help="正式运行门禁：拒绝演示状态、临时口令和非 Secure Cookie",
    )

    demo_run = commands.add_parser(
        "demo",
        help="一条命令准备演示数据并启动本机展示",
    )
    demo_run.add_argument(
        "--state-directory", default=DEFAULT_V2_DEMO_STATE_DIRECTORY
    )
    demo_run.add_argument("--port", type=_port, default=8080)
    demo_run.add_argument(
        "--through-month",
        type=_calendar_date,
        help="演示截止月份内任一日期；默认上一个完整自然月",
    )

    setup = commands.add_parser(
        "setup",
        help="通过安全向导生成正式启动配置",
    )
    setup.add_argument("--state-directory", default=".mineguard-v2")
    setup.add_argument("--port", type=_port, default=8080)
    setup.add_argument("--clients-file")
    setup.add_argument("--admin-username")
    cookie = setup.add_mutually_exclusive_group()
    cookie.add_argument(
        "--secure-cookie",
        dest="secure_cookie",
        action="store_true",
        help="已由 HTTPS 反向代理对外提供服务",
    )
    cookie.add_argument(
        "--no-secure-cookie",
        dest="secure_cookie",
        action="store_false",
        help="仅在本机 HTTP 访问",
    )
    setup.set_defaults(secure_cookie=None)
    setup.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "禁用提问；首次创建管理员时必须从 "
            "MINEGUARD_ADMIN_PASSWORD 读取密码"
        ),
    )

    start = commands.add_parser(
        "start",
        help="使用 setup 生成的配置启动平台",
    )
    start.add_argument("--state-directory", default=".mineguard-v2")

    bootstrap_admin = commands.add_parser(
        "bootstrap-admin",
        help="正式首启短进程：从受保护的固定文件读取一次密码并仅写入摘要",
    )
    bootstrap_admin.add_argument(
        "--state-directory", default=".mineguard-v2"
    )
    bootstrap_admin.add_argument("--admin-username", default="admin")
    bootstrap_admin.add_argument("--password-file", required=True)
    bootstrap_admin.add_argument("--production", action="store_true")

    demo = commands.add_parser(
        "seed-v2-demo",
        help="生成隔离演示库（8个合成场景 + 太岳/梗阳7月样表原值）",
    )
    demo.add_argument(
        "--state-directory", default=DEFAULT_V2_DEMO_STATE_DIRECTORY
    )
    demo.add_argument(
        "--through-month",
        type=_calendar_date,
        help="演示截止月份内任一日期；默认上一个完整自然月",
    )

    backup = commands.add_parser("backup", help="一致性备份 V2 SQLite 状态")
    backup.add_argument("backup_id")
    backup.add_argument("--state-directory", default=".mineguard-v2")
    backup.add_argument("--backup-directory")
    backup.add_argument("--key-file")
    backup.add_argument("--key-id", default="mineguard-v2-backup-key")

    verify = commands.add_parser("verify-backup", help="离线核验备份")
    verify.add_argument("backup_id")
    verify.add_argument("--state-directory", default=".mineguard-v2")
    verify.add_argument("--backup-directory")
    verify.add_argument("--key-file")
    verify.add_argument("--key-id", default="mineguard-v2-backup-key")

    restore = commands.add_parser("restore-backup", help="恢复到新的 V2 状态目录")
    restore.add_argument("backup_id")
    restore.add_argument("--state-directory", required=True)
    restore.add_argument("--backup-directory", required=True)
    restore.add_argument("--key-file", required=True)
    restore.add_argument("--key-id", default="mineguard-v2-backup-key")

    config_check = commands.add_parser(
        "config-check",
        help="只读校验客户端注册表或管理员账号库，供冻结运行时运维脚本使用",
    )
    config_check.add_argument("--clients-file")
    config_check.add_argument("--auth-database")
    config_check.add_argument("--state-directory")
    config_check.add_argument("--platform-system-id")
    config_check.add_argument("--platform-party-id")
    config_check.add_argument("--platform-key-id")
    config_check.add_argument(
        "--production",
        action="store_true",
        help="按正式运行标准拒绝演示状态或临时/默认凭据",
    )

    commands.add_parser(
        "self-check",
        help="验证前端资源、时区、数值求解器和版本元数据是否完整",
    )

    provisioning = commands.add_parser(
        "provision",
        help="签发每矿配置包并把配对的注册包导入 clients.json",
    )
    provisioning_commands = provisioning.add_subparsers(
        dest="provision_command", required=True
    )
    issuer_init = provisioning_commands.add_parser(
        "issuer-init", help="生成口令加密的 Ed25519 配置签发密钥"
    )
    issuer_init.add_argument("--private-key", required=True)
    issuer_init.add_argument("--public-key", required=True)
    issuer_init.add_argument(
        "--passphrase-file",
        help="仅限受保护的本机文件；省略时从交互终端无回显输入两次",
    )

    create_pair = provisioning_commands.add_parser(
        "create-pair", help="从审批 profile 生成 Agent/Platform 配对配置包"
    )
    create_pair.add_argument("--profile", required=True)
    create_pair.add_argument("--issuer-private-key", required=True)
    create_pair.add_argument(
        "--issuer-passphrase-file",
        help="仅限受保护的本机文件；省略时从交互终端无回显输入",
    )
    create_pair.add_argument(
        "--enterprise-bundle-directory",
        help="企业交付区：只写入一个自包含 .mgprov 文件",
    )
    create_pair.add_argument(
        "--platform-registration-directory",
        help="政府留存区：仅写入 .mgreg 和完整签发清单",
    )
    create_pair.add_argument(
        "--enterprise-activation-directory",
        help="企业激活码区；必须与其余三个输出目录树完全隔离",
    )
    create_pair.add_argument(
        "--platform-activation-directory",
        help="政府注册激活码区；必须与其余三个输出目录树完全隔离",
    )
    create_pair.add_argument(
        "--output-directory",
        help="兼容旧自动化的共享包目录；不得与四区参数混用",
    )
    create_pair.add_argument(
        "--activation-directory",
        help="兼容旧自动化的共享激活码目录；不得与四区参数混用",
    )
    create_pair.add_argument(
        "--previous-registration-bundle",
        help="更新时必填：上一版本 .mgreg；初始 version 1 不填写",
    )
    create_pair.add_argument(
        "--previous-registration-activation-code-file",
        help="更新时必填：上一版本 Platform 激活码受保护文件",
    )

    import_registration = provisioning_commands.add_parser(
        "import-registration",
        help="验签、解密并原子合并一个 .mgreg 到 clients.json",
    )
    import_registration.add_argument("--bundle", required=True)
    import_registration.add_argument("--activation-code-file", required=True)
    import_registration.add_argument("--issuer-public-key", required=True)
    import_registration.add_argument(
        "--expected-public-key-sha256",
        required=True,
        help="通过独立审批渠道取得的 Ed25519 SPKI-DER SHA-256（64位小写hex）",
    )
    import_registration.add_argument(
        "--expected-issuer-key-id",
        required=True,
        help="通过独立审批渠道取得的 provisioning issuer key ID",
    )
    import_registration.add_argument("--clients-file", required=True)
    import_registration.add_argument(
        "--allow-update",
        action="store_true",
        help="仅允许同矿同系统的更高 profile_version 更新",
    )

    users = commands.add_parser(
        "user",
        help="管理政府领导端登录账号（独立运维命令，不改变业务数据）",
    )
    user_commands = users.add_subparsers(dest="user_command", required=True)

    user_list = user_commands.add_parser("list", help="列出账号和煤矿查看范围")
    user_list.add_argument("--state-directory", default=".mineguard-v2")

    user_mines = user_commands.add_parser("mines", help="列出可授权的煤矿 ID")
    user_mines.add_argument("--state-directory", default=".mineguard-v2")

    user_add = user_commands.add_parser("add", help="新增领导端账号")
    user_add.add_argument("username")
    user_add.add_argument(
        "--role",
        choices=tuple(role.value for role in Role),
        default=Role.VIEWER.value,
    )
    user_add_scope = user_add.add_mutually_exclusive_group()
    user_add_scope.add_argument(
        "--mine-id",
        dest="mine_scopes",
        action="append",
        default=[],
        help="允许查看的煤矿 ID；非管理员至少指定一次，可重复",
    )
    user_add_scope.add_argument(
        "--all-mines",
        action="store_true",
        help="把当前监管库中的全部煤矿授予该只读账号",
    )
    user_add.add_argument("--state-directory", default=".mineguard-v2")
    user_add.add_argument(
        "--demo-default-password",
        action="store_true",
        help="非交互演示时使用默认初始密码 123123123",
    )

    user_access = user_commands.add_parser(
        "set-access", help="替换账号角色和煤矿查看范围，并撤销其现有会话"
    )
    user_access.add_argument("username")
    user_access.add_argument(
        "--role",
        choices=tuple(role.value for role in Role),
        required=True,
    )
    user_access_scope = user_access.add_mutually_exclusive_group()
    user_access_scope.add_argument(
        "--mine-id",
        dest="mine_scopes",
        action="append",
        default=[],
        help="允许查看的煤矿 ID；非管理员至少指定一次，可重复",
    )
    user_access_scope.add_argument(
        "--all-mines",
        action="store_true",
        help="用当前监管库中的全部煤矿替换账号查看范围",
    )
    user_access.add_argument("--state-directory", default=".mineguard-v2")

    for action, help_text in (
        ("enable", "启用账号"),
        ("disable", "停用账号并撤销其现有会话"),
    ):
        status = user_commands.add_parser(action, help=help_text)
        status.add_argument("username")
        status.add_argument("--state-directory", default=".mineguard-v2")

    reset = user_commands.add_parser(
        "reset-password", help="重置初始密码并撤销该账号现有会话"
    )
    reset.add_argument("username")
    reset.add_argument("--state-directory", default=".mineguard-v2")
    reset.add_argument(
        "--demo-default-password",
        action="store_true",
        help="非交互演示时重置为 123123123",
    )
    rotate = user_commands.add_parser(
        "change-password",
        help="在服务器本机验证当前密码并安全轮换为正式密码",
    )
    rotate.add_argument("username")
    rotate.add_argument("--state-directory", default=".mineguard-v2")
    return parser


def _state_root(value: str) -> Path:
    if not value.strip():
        raise ProductConfigurationError("状态目录不能为空")
    root = Path(value).expanduser().resolve()
    if root == Path(root.anchor):
        raise ProductConfigurationError("状态目录不能是文件系统根目录")
    return root


def _prompt(label: str) -> str:
    try:
        return input(label)
    except (EOFError, KeyboardInterrupt) as error:
        raise ProductConfigurationError(
            "当前终端无法交互输入；请在终端中重试，"
            "或使用 --non-interactive 和必需参数"
        ) from error


def _prompt_yes_no(label: str, *, default: bool = False) -> bool:
    answer = _prompt(label).strip().casefold()
    if not answer:
        return default
    if answer in {"y", "yes", "1", "是", "是的"}:
        return True
    if answer in {"n", "no", "0", "否", "不"}:
        return False
    raise ProductConfigurationError("请输入 y 或 n")


def _unquote_path(value: str) -> str:
    rendered = value.strip()
    if (
        len(rendered) >= 2
        and rendered[0] == rendered[-1]
        and rendered[0] in {"'", '"'}
    ):
        return rendered[1:-1].strip()
    return rendered


def _validate_clients_file(
    value: str, *, production: bool = False
) -> tuple[Path, int]:
    raw = _unquote_path(value)
    if not raw:
        raise ProductConfigurationError("clients.json 路径不能为空")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.absolute()
    from .exchange_v2 import (
        load_exchange_clients,
        validate_production_exchange_clients,
        validate_production_platform_identity,
    )

    clients = load_exchange_clients(None, str(path))
    if not clients:
        raise ProductConfigurationError("clients.json 至少需要登记一座煤矿")
    if production:
        validate_production_exchange_clients(clients)
        validate_production_platform_identity(
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_SYSTEM_ID", "mineguard-qinyuan"
            ),
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_PARTY_ID", "regulator-qinyuan"
            ),
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_KEY_ID", "regulator-key-v2"
            ),
            clients=clients,
        )
    return path, len(clients)


def _assert_setup_state_boundary(root: Path) -> None:
    _assert_formal_state(root)
    if not root.exists():
        return
    if not root.is_dir():
        raise ProductConfigurationError("状态目录必须是目录")
    allowed = {
        _QUICK_START_SETTINGS,
        ".mineguard-platform.instance.lock",
        "mineguard.db",
        "mineguard.db-wal",
        "mineguard.db-shm",
        "auth.db",
        "auth.db-wal",
        "auth.db-shm",
        "backup.key",
        "backups",
    }
    unexpected = sorted(item.name for item in root.iterdir() if item.name not in allowed)
    if unexpected:
        raise ProductConfigurationError(
            "状态目录含有非 MineGuard 文件，已拒绝混用："
            + "、".join(unexpected[:5])
        )


def _demo_state_evidence(root: Path) -> list[str]:
    """Find durable demo evidence without changing the selected state tree."""

    evidence: list[str] = []
    for marker_name in (
        _DEMO_STATE_MARKER,
        ".mineguard-demo-owner.json",
    ):
        if (root / marker_name).exists():
            evidence.append(f"marker:{marker_name}")
    database = root / "mineguard.db"
    if not database.is_file():
        return evidence
    try:
        with sqlite3.connect(
            f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=5
        ) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if "demo_seed_manifests" in tables:
                row = connection.execute(
                    "SELECT 1 FROM demo_seed_manifests LIMIT 1"
                ).fetchone()
                if row is not None:
                    evidence.append("database:demo_seed_manifests")
            if "v2_exchange_messages" in tables:
                row = connection.execute(
                    """
                    SELECT 1 FROM v2_exchange_messages
                    WHERE message_type IN (
                        'synthetic_demo_five_quantity_submission_v2',
                        'provided_sample_demo_import_v1'
                    ) LIMIT 1
                    """
                ).fetchone()
                if row is not None:
                    evidence.append("database:v2_demo_exchange")
            if "v2_agent_mine_bindings" in tables:
                row = connection.execute(
                    """
                    SELECT 1 FROM v2_agent_mine_bindings
                    WHERE agent_id LIKE 'synthetic-demo-agent-%'
                       OR agent_id LIKE 'workbook-demo-agent-%'
                    LIMIT 1
                    """
                ).fetchone()
                if row is not None:
                    evidence.append("database:v2_demo_binding")
            if "v2_submissions" in tables:
                row = connection.execute(
                    """
                    SELECT 1 FROM v2_submissions
                    WHERE mine_id LIKE 'SYNTH-DEMO-%'
                       OR mine_id LIKE 'DEMO-WORKBOOK-%'
                    LIMIT 1
                    """
                ).fetchone()
                if row is not None:
                    evidence.append("database:v2_demo_submission")
    except sqlite3.Error as error:
        raise ProductConfigurationError(
            "mineguard.db 无法核验数据用途，正式运行已拒绝"
        ) from error
    return evidence


def _assert_formal_state(root: Path) -> None:
    evidence = _demo_state_evidence(root)
    if evidence:
        raise ProductConfigurationError(
            "演示或合成数据目录不能转为正式状态目录；请新建独立空目录"
        )


def _validate_formal_password(password: str, *, label: str) -> str:
    if secrets.compare_digest(password, _DEMO_DEFAULT_PASSWORD):
        raise ProductConfigurationError(
            f"正式配置不允许使用演示默认密码 {_DEMO_DEFAULT_PASSWORD}"
        )
    if password.casefold() in _COMMON_WEAK_PASSWORDS:
        raise ProductConfigurationError(f"{label}不能使用常见弱口令")
    if _PLACEHOLDER_SECRET.search(password):
        raise ProductConfigurationError(f"{label}不能使用示例或占位密码文本")
    if len(password) < _FORMAL_MIN_PASSWORD_LENGTH:
        raise ProductConfigurationError(
            f"{label}至少需要 {_FORMAL_MIN_PASSWORD_LENGTH} 个字符"
        )
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 3:
        raise ProductConfigurationError(
            f"{label}必须包含大写字母、小写字母、数字、符号中的至少三类"
        )
    return password


def _assert_formal_auth(store: LocalAuthStore) -> dict[str, object]:
    status = store.production_credential_status(
        forbidden_passwords=_COMMON_WEAK_PASSWORDS
    )
    if int(status["active_ready_admin_count"]) < 1:
        raise ProductConfigurationError(
            "正式运行至少需要一个已按当前密码策略确认的启用管理员账号。"
            "旧版本账号请在服务器本机运行 mineguard user change-password "
            "<账号> --state-directory <状态目录>，验证当前密码并轮换；"
            "密码不会回显或写入配置文件"
        )
    if int(status["blocked_user_count"]) > 0:
        names = "、".join(
            str(item["username"])
            for item in list(status["blocked_users"])[:5]
        )
        raise ProductConfigurationError(
            "现有账号库包含仍启用的旧策略凭据、已知弱口令、"
            "演示口令或临时演示账号"
            + (f"：{names}" if names else "")
            + "；请先在服务器本机运行 mineguard user change-password "
            "<账号> --state-directory <状态目录> 完成安全轮换，"
            "或停用不再使用的非管理员账号"
        )
    return status


def _formal_admin_password(*, non_interactive: bool) -> str:
    configured = os.environ.pop("MINEGUARD_ADMIN_PASSWORD", None)
    if configured is not None:
        password = configured
    elif non_interactive:
        raise ProductConfigurationError(
            "非交互首次配置必须设置 MINEGUARD_ADMIN_PASSWORD"
        )
    else:
        try:
            password = getpass.getpass("管理员密码（输入时不显示）：")
            confirmation = getpass.getpass("再次输入管理员密码：")
        except (EOFError, KeyboardInterrupt) as error:
            raise ProductConfigurationError(
                "无法安全读取密码；请在终端中重试"
            ) from error
        if not secrets.compare_digest(password, confirmation):
            raise ProductConfigurationError("两次输入的管理员密码不一致")
    return _validate_formal_password(password, label="管理员密码")


def _write_quick_start_settings(root: Path, value: dict[str, object]) -> Path:
    target = root / _QUICK_START_SETTINGS
    if target.is_symlink():
        raise ProductConfigurationError("快速启动配置不能是符号链接")
    temporary = root / f".{_QUICK_START_SETTINGS}.{secrets.token_hex(8)}.tmp"
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        try:
            target.chmod(0o600)
        except OSError:
            pass
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return target


def _load_quick_start_settings(root: Path) -> dict[str, object]:
    path = root / _QUICK_START_SETTINGS
    if path.is_symlink():
        raise ProductConfigurationError("快速启动配置不能是符号链接")
    try:
        payload = path.read_bytes()
    except FileNotFoundError as error:
        raise ProductConfigurationError(
            "尚未完成正式配置；请先运行 mineguard setup"
        ) from error
    if len(payload) > _QUICK_START_SETTINGS_MAX_BYTES:
        raise ProductConfigurationError("快速启动配置超过 32 KiB 限制")
    def without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"快速启动配置字段重复：{key}")
            result[key] = item
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=without_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProductConfigurationError("快速启动配置不是有效 UTF-8 JSON") from error
    required = {
        "schema_version",
        "kind",
        "host",
        "port",
        "secure_cookie",
        "clients_file",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProductConfigurationError("快速启动配置字段不完整")
    port = value.get("port")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != _QUICK_START_SETTINGS_SCHEMA
        or value["kind"] != _QUICK_START_SETTINGS_KIND
        or value["host"] != "127.0.0.1"
        or type(port) is not int
        or not 1 <= port <= 65535
        or type(value["secure_cookie"]) is not bool
        or not isinstance(value["clients_file"], str)
        or not value["clients_file"].strip()
    ):
        raise ProductConfigurationError("快速启动配置值不合法")
    return value


def _state_database(args: argparse.Namespace, name: str) -> tuple[Path, Path]:
    root = _state_root(args.state_directory)
    database = root / name
    if not database.is_file():
        raise ProductConfigurationError(
            f"状态目录中不存在 {name}：{root}。"
            "请使用正在运行的 serve 命令对应的同一 --state-directory。"
        )
    return root, database


def _known_mines(root: Path) -> list[dict[str, str]]:
    database = root / "mineguard.db"
    if not database.is_file():
        return []
    with sqlite3.connect(database) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        names: dict[str, str] = {}
        if "v2_submissions" in tables:
            rows = connection.execute(
                """
                SELECT mine_id,mine_name FROM v2_submissions
                ORDER BY period_end DESC,revision DESC,received_at DESC
                """
            )
            for mine_id, mine_name in rows:
                names.setdefault(str(mine_id), str(mine_name))
        if "v2_agent_mine_bindings" in tables:
            for (mine_id,) in connection.execute(
                "SELECT mine_id FROM v2_agent_mine_bindings ORDER BY mine_id"
            ):
                names.setdefault(str(mine_id), str(mine_id))
    return [
        {"mine_id": mine_id, "mine_name": names[mine_id]}
        for mine_id in sorted(names, key=lambda item: (names[item], item))
    ]


def _selected_access(
    args: argparse.Namespace, root: Path
) -> tuple[Role, tuple[str, ...], list[str]]:
    role = Role(args.role)
    if args.all_mines:
        scopes = tuple(item["mine_id"] for item in _known_mines(root))
        if not scopes:
            raise ProductConfigurationError(
                "当前监管库尚无煤矿，不能使用 --all-mines；"
                "请等待首份数据到达或明确指定 --mine-id"
            )
    else:
        scopes = tuple(
            sorted(
                {
                    str(value).strip()
                    for value in args.mine_scopes
                    if str(value).strip()
                }
            )
        )
    if role is Role.ADMIN:
        if scopes:
            raise ProductConfigurationError(
                "admin 自动查看全部煤矿，不应再指定 --mine-id"
            )
    elif not scopes:
        raise ProductConfigurationError(
            "非管理员账号至少需要一个 --mine-id 或 --all-mines；"
            "可先运行 mineguard user mines"
        )
    invalid = [scope for scope in scopes if _MINE_ID.fullmatch(scope) is None]
    if invalid:
        raise ProductConfigurationError(
            f"煤矿 ID 格式不合法：{', '.join(invalid)}"
        )
    known = {item["mine_id"] for item in _known_mines(root)}
    unknown = [scope for scope in scopes if known and scope not in known]
    return role, scopes, unknown


def _new_password(
    args: argparse.Namespace, *, formal: bool
) -> tuple[str, bool]:
    configured = os.environ.pop("MINEGUARD_NEW_USER_PASSWORD", None)
    used_demo_default = False
    if formal and configured is not None:
        raise ProductConfigurationError(
            "正式状态不接受 MINEGUARD_NEW_USER_PASSWORD 环境变量；"
            "请在服务器本机交互终端无回显输入初始密码"
        )
    if formal and args.demo_default_password:
        raise ProductConfigurationError(
            "正式状态不允许 --demo-default-password"
        )
    if formal and not sys.stdin.isatty():
        raise ProductConfigurationError(
            "正式账号密码只能在服务器本机交互终端输入；"
            "不接受命令行参数、管道或环境变量中的密码"
        )
    if configured is not None:
        password = configured
    elif args.demo_default_password:
        password = _DEMO_DEFAULT_PASSWORD
        used_demo_default = True
    else:
        try:
            prompt = (
                "初始密码（输入时不显示）："
                if formal
                else "初始密码（直接回车使用本机演示默认密码 123123123）："
            )
            password = getpass.getpass(prompt)
            if not password:
                if formal:
                    raise ProductConfigurationError("正式初始密码不能为空")
                password = _DEMO_DEFAULT_PASSWORD
                used_demo_default = True
            else:
                confirmation = getpass.getpass("再次输入初始密码：")
                if not secrets.compare_digest(password, confirmation):
                    raise ProductConfigurationError("两次输入的密码不一致")
        except (EOFError, KeyboardInterrupt) as error:
            if formal:
                raise ProductConfigurationError(
                    "无法安全读取密码；请在服务器本机交互终端重试"
                ) from error
            raise ProductConfigurationError(
                "无法交互读取密码；请设置 MINEGUARD_NEW_USER_PASSWORD，"
                "演示环境也可加 --demo-default-password"
            ) from error
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ProductConfigurationError(
            f"初始密码至少需要 {_MIN_PASSWORD_LENGTH} 个字符"
        )
    if formal:
        _validate_formal_password(password, label="初始密码")
    return password, used_demo_default


def _present_user(value: dict[str, object]) -> dict[str, object]:
    rendered = dict(value)
    role = Role(str(value["role"]))
    rendered["role_label"] = _ROLE_LABELS[role]
    return rendered


def _rotation_passwords() -> tuple[str, str]:
    """Read a credential rotation only from an attached local terminal."""

    if not sys.stdin.isatty():
        raise ProductConfigurationError(
            "change-password 只能在服务器本机交互终端运行；"
            "不接受命令行参数、管道或环境变量中的密码"
        )
    try:
        current_password = getpass.getpass("当前密码（输入时不显示）：")
        new_password = getpass.getpass("新密码（输入时不显示）：")
        confirmation = getpass.getpass("再次输入新密码：")
    except (EOFError, KeyboardInterrupt) as error:
        raise ProductConfigurationError(
            "无法安全读取密码；请在服务器本机交互终端重试"
        ) from error
    if not current_password:
        raise ProductConfigurationError("当前密码不能为空")
    if not secrets.compare_digest(new_password, confirmation):
        raise ProductConfigurationError("两次输入的新密码不一致")
    if secrets.compare_digest(current_password, new_password):
        raise ProductConfigurationError("新密码不能与当前密码相同")
    return current_password, _validate_formal_password(
        new_password, label="新密码"
    )


def _user_operation(args: argparse.Namespace) -> dict[str, object]:
    root, auth_database = _state_database(args, "auth.db")
    formal = (
        (root / _QUICK_START_SETTINGS).is_file()
        or (root / _WINDOWS_STATE_MARKER).is_file()
    ) and not (root / _DEMO_STATE_MARKER).exists()
    if args.user_command == "mines":
        mines = _known_mines(root)
        return {
            "status": "ok",
            "state_directory": str(root),
            "count": len(mines),
            "mines": mines,
        }

    with LocalAuthStore(auth_database) as store:
        if args.user_command == "list":
            users = [_present_user(item) for item in store.list_users()]
            return {
                "status": "ok",
                "state_directory": str(root),
                "count": len(users),
                "users": users,
            }

        if args.user_command == "add":
            role, scopes, unknown = _selected_access(args, root)
            password, used_demo_default = _new_password(args, formal=formal)
            user = store.create_user(
                args.username,
                password,
                role,
                scopes,
                must_change_password=True,
                temporary_demo=used_demo_default,
            )
            result: dict[str, object] = {
                "status": "created",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "restart_required": False,
            }
            warnings = []
            if used_demo_default:
                warnings.append(
                    "当前账号初始密码为 123123123，仅限受控演示；正式使用前请重置。"
                )
            if unknown:
                warnings.append(
                    "以下煤矿尚未出现在当前监管库中，账号将在数据到达后看到它们："
                    + "、".join(unknown)
                )
            if warnings:
                result["warnings"] = warnings
            return result

        if args.user_command == "set-access":
            role, scopes, unknown = _selected_access(args, root)
            user = store.update_user_access(args.username, role, scopes)
            result = {
                "status": "access_updated",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "sessions_revoked": True,
                "restart_required": False,
            }
            if unknown:
                result["warnings"] = [
                    "以下煤矿尚未出现在当前监管库中，账号将在数据到达后看到它们："
                    + "、".join(unknown)
                ]
            return result

        if args.user_command in {"enable", "disable"}:
            active = args.user_command == "enable"
            user = store.set_user_active(args.username, active)
            return {
                "status": "enabled" if active else "disabled",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "sessions_revoked": not active,
                "restart_required": False,
            }

        if args.user_command == "reset-password":
            password, used_demo_default = _new_password(args, formal=formal)
            store.reset_password(
                args.username,
                password,
                must_change_password=True,
                temporary_demo=used_demo_default,
                strict=formal,
            )
            result = {
                "status": "password_reset",
                "state_directory": str(root),
                "username": args.username,
                "sessions_revoked": True,
                "restart_required": False,
            }
            if used_demo_default:
                result["warnings"] = [
                    "密码已重置为 123123123，仅限受控演示；正式使用前请再次重置。"
                ]
            return result

        if args.user_command == "change-password":
            current_password, new_password = _rotation_passwords()
            try:
                store.change_password(
                    args.username,
                    current_password,
                    new_password,
                )
            except InvalidCredentialsError as error:
                raise ProductConfigurationError(
                    "账号不存在、已停用或当前密码不正确"
                ) from error
            user = store.get_user(args.username)
            assert user is not None
            return {
                "status": "password_changed",
                "state_directory": str(root),
                "username": user.username,
                "credential_policy_version": user.credential_policy_version,
                "sessions_revoked": True,
                "password_stored": False,
                "restart_required": False,
            }

    raise ProductConfigurationError(f"不支持的账号操作：{args.user_command}")


def _load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        value = path.read_bytes()
    except FileNotFoundError:
        value = secrets.token_bytes(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
    if len(value) < 32:
        raise ProductConfigurationError("备份认证密钥至少需要 32 字节")
    return value


def _read_key(path: Path) -> bytes:
    try:
        value = path.read_bytes()
    except FileNotFoundError as error:
        raise ProductConfigurationError(f"备份认证密钥不存在：{path}") from error
    if len(value) < 32:
        raise ProductConfigurationError("备份认证密钥至少需要 32 字节")
    return value


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    root = _state_root(args.state_directory)
    backup_directory = (
        Path(args.backup_directory).expanduser().resolve()
        if args.backup_directory
        else root / "backups"
    )
    key_file = (
        Path(args.key_file).expanduser().resolve()
        if args.key_file
        else root / "backup.key"
    )
    return root, backup_directory, key_file


def _bootstrap_admin(
    auth_database: Path,
    username: str,
    *,
    host: str,
    production: bool = False,
) -> tuple[str, str | None] | None:
    configured = os.environ.pop("MINEGUARD_ADMIN_PASSWORD", None)
    with LocalAuthStore(auth_database) as store:
        if store.list_users():
            return None
        if configured:
            password = configured
            display = None
        elif not production and host in {"127.0.0.1", "::1", "localhost"}:
            password = "123123123"
            display = password
        else:
            raise ProductConfigurationError(
                "非本机监听首次启动必须设置 MINEGUARD_ADMIN_PASSWORD"
            )
        if production:
            _validate_formal_password(password, label="管理员密码")
        else:
            if len(password) < 8:
                raise ProductConfigurationError("管理员密码至少需要 8 个字符")
            if _PLACEHOLDER_SECRET.search(password):
                raise ProductConfigurationError("管理员密码不能使用示例或占位文本")
        is_demo = secrets.compare_digest(password, _DEMO_DEFAULT_PASSWORD)
        user = store.bootstrap_admin(
            username,
            password,
            must_change_password=is_demo,
            temporary_demo=is_demo,
        )
        return user.username, display


def _serve(args: argparse.Namespace) -> None:
    production = bool(getattr(args, "production", False))
    if args.no_auth and args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ProductConfigurationError("--no-auth 只能与回环监听地址一起使用")
    if production and args.no_auth:
        raise ProductConfigurationError("正式运行不允许关闭账号认证")
    if production and not args.secure_cookie:
        raise ProductConfigurationError(
            "正式运行必须启用 --secure-cookie 并通过 HTTPS 反向代理访问"
        )
    if production:
        from .exchange_v2 import (
            load_exchange_clients,
            validate_production_exchange_clients,
            validate_production_platform_identity,
        )

        production_clients = load_exchange_clients(
            os.environ.get("MINEGUARD_V2_CLIENTS_JSON"),
            os.environ.get("MINEGUARD_V2_CLIENTS_FILE"),
        )
        validate_production_exchange_clients(production_clients)
        validate_production_platform_identity(
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_SYSTEM_ID", "mineguard-qinyuan"
            ),
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_PARTY_ID", "regulator-qinyuan"
            ),
            os.environ.get(
                "MINEGUARD_V2_PLATFORM_KEY_ID", "regulator-key-v2"
            ),
            clients=production_clients,
        )
    root = _state_root(args.state_directory)
    if production:
        _assert_formal_state(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    local_control_token = os.environ.pop(_LOCAL_CONTROL_ENVIRONMENT, None)
    if local_control_token is not None and not _LOCAL_CONTROL_TOKEN.fullmatch(
        local_control_token
    ):
        raise ProductConfigurationError("本机控制令牌格式无效，已拒绝启动")
    with StateInstanceLock(root):
        database = root / "mineguard.db"
        auth_database = root / "auth.db"
        backup_key = root / "backup.key"
        _load_or_create_key(backup_key)
        bootstrap = None
        if not args.no_auth:
            bootstrap = _bootstrap_admin(
                auth_database,
                args.admin_username,
                host=args.host,
                production=production,
            )
            if production:
                with LocalAuthStore(auth_database) as auth_store:
                    _assert_formal_auth(auth_store)
        if bootstrap is not None:
            username, displayed_password = bootstrap
            print(f"首次管理员账号：{username}", file=sys.stderr)
            if displayed_password is not None:
                print(f"本机演示默认密码：{displayed_password}", file=sys.stderr)
            else:
                print("管理员密码来自环境变量，未回显。", file=sys.stderr)
        print(
            f"MineGuard · 矿安智察监听 http://{args.host}:{args.port}\n"
            f"状态目录：{root}\n"
            "业务前端只读；按 Ctrl+C 安全停止。",
            file=sys.stderr,
        )
        serve(
            args.host,
            args.port,
            database_path=database,
            auth_database_path=auth_database,
            auth_required=not args.no_auth,
            secure_cookie=args.secure_cookie,
            local_control_token=local_control_token,
            production_mode=production,
        )


def _serve_with_registry(
    args: argparse.Namespace,
    *,
    clients_file: Path | None,
    clear_admin_password: bool = False,
) -> None:
    keys = list(_CLIENT_REGISTRY_ENVIRONMENT)
    if clear_admin_password:
        keys.append("MINEGUARD_ADMIN_PASSWORD")
    previous = {key: os.environ[key] for key in keys if key in os.environ}
    for key in keys:
        os.environ.pop(key, None)
    if clients_file is not None:
        os.environ["MINEGUARD_V2_CLIENTS_FILE"] = str(clients_file)
    try:
        _serve(args)
    finally:
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(
            {
                key: value
                for key, value in previous.items()
                if key != "MINEGUARD_ADMIN_PASSWORD"
            }
        )


def _demo(args: argparse.Namespace) -> None:
    result = _seed_demo(args)
    print(
        f"演示数据已就绪：{result['mine_count']} 座煤矿。",
        file=sys.stderr,
    )
    print(
        f"请用 Chrome 或 Edge 打开：http://127.0.0.1:{args.port}/",
        file=sys.stderr,
    )
    serve_args = argparse.Namespace(
        host="127.0.0.1",
        port=args.port,
        state_directory=args.state_directory,
        admin_username="admin",
        no_auth=False,
        secure_cookie=False,
        production=False,
    )
    _serve_with_registry(
        serve_args,
        clients_file=None,
        clear_admin_password=True,
    )


def _setup(args: argparse.Namespace) -> dict[str, object]:
    clients_value = args.clients_file
    if clients_value is None:
        if args.non_interactive:
            raise ProductConfigurationError(
                "非交互配置必须指定 --clients-file"
            )
        clients_value = _prompt("clients.json 完整路径：")
    clients_file, client_count = _validate_clients_file(
        clients_value, production=True
    )

    secure_cookie = args.secure_cookie
    if secure_cookie is None:
        if args.non_interactive:
            raise ProductConfigurationError(
                "非交互正式配置必须显式添加 --secure-cookie"
            )
        secure_cookie = _prompt_yes_no(
            "是否已配置 HTTPS 反向代理？正式运行必须选择 y [y/N]："
        )
    if not secure_cookie:
        raise ProductConfigurationError(
            "正式 setup 必须启用 Secure Cookie 并通过 HTTPS 反向代理访问；"
            "本机 HTTP 展示请使用 mineguard demo"
        )

    root = _state_root(args.state_directory)
    _assert_setup_state_boundary(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root.chmod(0o700)
    except OSError:
        pass

    created_admin: str | None = None
    with StateInstanceLock(root):
        auth_database = root / "auth.db"
        with LocalAuthStore(auth_database) as store:
            users = store.list_users()
            if not users:
                username = args.admin_username
                if username is None:
                    username = (
                        "admin"
                        if args.non_interactive
                        else (_prompt("管理员账号 [admin]：").strip() or "admin")
                    )
                password = _formal_admin_password(
                    non_interactive=args.non_interactive
                )
                created_admin = store.bootstrap_admin(username, password).username
            _assert_formal_auth(store)

        settings = {
            "schema_version": _QUICK_START_SETTINGS_SCHEMA,
            "kind": _QUICK_START_SETTINGS_KIND,
            "host": "127.0.0.1",
            "port": args.port,
            "secure_cookie": bool(secure_cookie),
            "clients_file": str(clients_file),
        }
        _write_quick_start_settings(root, settings)

    return {
        "status": "configured",
        "state_directory": str(root),
        "client_count": client_count,
        "administrator_created": created_admin,
        "password_stored_in_settings": False,
        "next_command": (
            "mineguard start"
            if args.state_directory == ".mineguard-v2"
            else f"mineguard start --state-directory {root}"
        ),
    }


def _bootstrap_password_file(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or path.name != _BOOTSTRAP_PASSWORD_FILENAME:
        raise ProductConfigurationError(
            "--password-file 必须是固定名称 bootstrap-admin-password.txt 的完整绝对路径"
        )
    return Path(os.path.abspath(path))


def _read_bootstrap_password(
    path: Path,
) -> tuple[str, tuple[int, int, int, int]]:
    """Read one ordinary file without following a symlink/reparse point."""

    try:
        before = os.lstat(path)
    except OSError as error:
        raise ProductConfigurationError(
            "首次管理员密码文件不存在或不可读取"
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & reparse_flag
    ):
        raise ProductConfigurationError(
            "首次管理员密码必须是普通文件，不能是符号链接或 reparse point"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProductConfigurationError(
            "首次管理员密码文件无法安全打开"
        ) from error
    try:
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            != identity
        ):
            raise ProductConfigurationError(
                "首次管理员密码文件在打开期间发生变化"
            )
        chunks: list[bytes] = []
        remaining = _BOOTSTRAP_PASSWORD_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != identity:
            raise ProductConfigurationError(
                "首次管理员密码文件在读取期间发生变化"
            )
    finally:
        os.close(descriptor)
    if len(payload) > _BOOTSTRAP_PASSWORD_MAX_BYTES:
        raise ProductConfigurationError("首次管理员密码文件超过 4096 字节上限")
    try:
        password = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        raise ProductConfigurationError(
            "首次管理员密码文件必须是严格 UTF-8 文本"
        ) from error
    if not password or any(character in password for character in "\r\n\x00"):
        raise ProductConfigurationError(
            "首次管理员密码不能为空，且不得包含换行或 NUL"
        )
    return password, identity


def _unlink_unchanged_bootstrap_password(
    path: Path, identity: tuple[int, int, int, int]
) -> None:
    try:
        current = os.lstat(path)
    except OSError as error:
        raise ProductConfigurationError(
            "管理员摘要已建立，但首启密码文件无法确认或删除"
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or getattr(current, "st_file_attributes", 0) & reparse_flag
        or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        )
        != identity
    ):
        raise ProductConfigurationError(
            "管理员摘要已建立，但首启密码文件在删除前发生变化"
        )
    try:
        path.unlink()
    except OSError as error:
        raise ProductConfigurationError(
            "管理员摘要已建立，但首启密码文件删除失败"
        ) from error
    if os.path.lexists(path):
        raise ProductConfigurationError(
            "管理员摘要已建立，但首启密码文件删除后仍然存在"
        )


def _bootstrap_admin_once(args: argparse.Namespace) -> dict[str, object]:
    """Create the first formal administrator, then exit without a secret."""

    os.environ.pop("MINEGUARD_ADMIN_PASSWORD", None)
    if not args.production:
        raise ProductConfigurationError(
            "bootstrap-admin 只允许与 --production 一起使用"
        )
    password_path = _bootstrap_password_file(args.password_file)
    root = _state_root(args.state_directory)
    _assert_formal_state(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    with StateInstanceLock(root):
        password, password_identity = _read_bootstrap_password(password_path)
        validated_password = _validate_formal_password(
            password, label="管理员密码"
        )
        with LocalAuthStore(root / "auth.db") as store:
            if store.list_users():
                raise ProductConfigurationError(
                    "bootstrap-admin 仅允许用于没有任何账号的空 auth.db"
                )
            user = store.bootstrap_admin(
                args.admin_username,
                validated_password,
            )
            status = _assert_formal_auth(store)
        _unlink_unchanged_bootstrap_password(
            password_path, password_identity
        )
    return {
        "status": "administrator_bootstrapped",
        "state_directory": str(root),
        "username": user.username,
        "credential_policy_version": user.credential_policy_version,
        "production_ready": bool(status["production_ready"]),
        "password_stored": False,
    }


def _start(args: argparse.Namespace) -> None:
    root = _state_root(args.state_directory)
    _assert_formal_state(root)
    settings = _load_quick_start_settings(root)
    clients_file, _ = _validate_clients_file(
        str(settings["clients_file"]), production=True
    )
    auth_database = root / "auth.db"
    if not auth_database.is_file():
        raise ProductConfigurationError(
            "管理员账号库不存在；请重新运行 mineguard setup"
        )
    with LocalAuthStore(auth_database) as store:
        _assert_formal_auth(store)
    configured_port = settings["port"]
    configured_secure_cookie = settings["secure_cookie"]
    assert type(configured_port) is int
    assert type(configured_secure_cookie) is bool
    if not configured_secure_cookie:
        raise ProductConfigurationError(
            "正式启动配置未启用 Secure Cookie；请完成 HTTPS 代理后重新运行 setup"
        )
    serve_args = argparse.Namespace(
        host="127.0.0.1",
        port=configured_port,
        state_directory=str(root),
        admin_username="admin",
        no_auth=False,
        secure_cookie=configured_secure_cookie,
        production=True,
    )
    _serve_with_registry(serve_args, clients_file=clients_file)


def _manager(
    args: argparse.Namespace, *, create_key: bool
) -> tuple[BackupManager, Path, Path, Path]:
    root, backup_directory, key_file = _paths(args)
    key = _load_or_create_key(key_file) if create_key else _read_key(key_file)
    return (
        BackupManager(backup_directory, key, args.key_id, __version__),
        root,
        backup_directory,
        key_file,
    )


def _backup(args: argparse.Namespace) -> dict[str, object]:
    manager, root, directory, key_file = _manager(args, create_key=True)
    databases = {
        name: path
        for name, path in {
            "mineguard.db": root / "mineguard.db",
            "auth.db": root / "auth.db",
        }.items()
        if path.is_file()
    }
    if not databases:
        raise ProductConfigurationError("状态目录中没有 V2 数据库")
    manifest = manager.create_backup(args.backup_id, databases)
    return {
        "status": "created",
        "backup": manifest,
        "backup_directory": str(directory),
        "key_file": str(key_file),
        "warning": "backup.key 不在备份中，必须另行离线保管",
    }


def _verify(args: argparse.Namespace) -> dict[str, object]:
    manager, _, directory, key_file = _manager(args, create_key=False)
    return {
        "status": "valid",
        "backup": manager.verify(args.backup_id),
        "backup_directory": str(directory),
        "key_file": str(key_file),
    }


def _restore(args: argparse.Namespace) -> dict[str, object]:
    manager, target, _, key_file = _manager(args, create_key=False)
    if target.exists() and any(target.iterdir()):
        raise ProductConfigurationError("恢复目标必须不存在或为空")
    existed = target.exists()
    restored = manager.restore(args.backup_id, target)
    try:
        destination_key = restored / "backup.key"
        if key_file.resolve() != destination_key.resolve():
            descriptor = os.open(
                destination_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with key_file.open("rb") as source, os.fdopen(descriptor, "wb") as sink:
                shutil.copyfileobj(source, sink)
                sink.flush()
                os.fsync(sink.fileno())
    except BaseException:
        if not existed:
            shutil.rmtree(restored, ignore_errors=True)
        raise
    return {
        "status": "restored",
        "state_directory": str(restored),
        "next_command": f"mineguard serve --state-directory {restored}",
    }


def _config_check(args: argparse.Namespace) -> dict[str, object]:
    if not args.clients_file and not args.auth_database and not args.state_directory:
        raise ProductConfigurationError(
            "config-check 至少需要 --clients-file、--auth-database 或 --state-directory"
        )
    result: dict[str, object] = {"status": "ok"}
    if args.clients_file:
        from .exchange_v2 import (
            load_exchange_clients,
            validate_production_exchange_clients,
            validate_production_platform_identity,
        )

        clients = load_exchange_clients(None, args.clients_file)
        if not clients:
            raise ProductConfigurationError("客户端注册表至少需要一座煤矿")
        result["client_count"] = len(clients)
        from .provisioning import registry_lock_status_file

        lock_status = registry_lock_status_file(args.clients_file)
        result["client_registry_managed"] = bool(lock_status["managed"])
        result["client_registry_locked_client_count"] = int(
            lock_status["locked_client_count"]
        )
        if not bool(lock_status["managed"]):
            result["client_registry_warning"] = (
                "兼容的手工 clients.json 未受 provisioning_lock 保护；"
                "建议逐矿改用签名注册包导入"
            )
        elif args.production and not bool(
            lock_status.get("managed_required_external", False)
        ):
            raise ProductConfigurationError(
                "受管 clients.json 正式运行必须在服务配置中设置 "
                "MINEGUARD_PROVISIONING_MANAGED_REQUIRED=true，"
                "防止删除注册锁后静默降级"
            )
        if args.production:
            validate_production_exchange_clients(clients)
            platform_system_id = (
                args.platform_system_id
                if args.platform_system_id is not None
                else os.environ.get(
                    "MINEGUARD_V2_PLATFORM_SYSTEM_ID", "mineguard-qinyuan"
                )
            )
            platform_party_id = (
                args.platform_party_id
                if args.platform_party_id is not None
                else os.environ.get(
                    "MINEGUARD_V2_PLATFORM_PARTY_ID", "regulator-qinyuan"
                )
            )
            platform_key_id = (
                args.platform_key_id
                if args.platform_key_id is not None
                else os.environ.get(
                    "MINEGUARD_V2_PLATFORM_KEY_ID", "regulator-key-v2"
                )
            )
            validate_production_platform_identity(
                platform_system_id,
                platform_party_id,
                platform_key_id,
                clients=clients,
            )
            locked_platform_identity = lock_status.get("platform_identity")
            if locked_platform_identity is not None and locked_platform_identity != {
                "key_id": platform_key_id,
                "party_id": platform_party_id,
                "system_id": platform_system_id,
            }:
                raise ProductConfigurationError(
                    "正式运行 Platform 身份与 provisioning_lock 签发身份不一致"
                )
            result["client_registry_production_ready"] = True
    if args.auth_database:
        database = Path(args.auth_database).expanduser().resolve()
        status = inspect_auth_database(
            database, forbidden_passwords=_COMMON_WEAK_PASSWORDS
        )
        result.update(
            {
                "auth_user_count": int(status["user_count"]),
                "auth_active_admin_count": int(status["active_admin_count"]),
                "auth_ready_admin_count": int(
                    status["active_ready_admin_count"]
                ),
                "auth_production_ready": bool(status["production_ready"]),
                "auth_blocked_user_count": int(status["blocked_user_count"]),
                "auth_blocked_users": status["blocked_users"],
                "auth_pending_password_change_user_count": int(
                    status["pending_password_change_user_count"]
                ),
                "auth_outdated_credential_policy_user_count": int(
                    status["outdated_credential_policy_user_count"]
                ),
                "auth_current_credential_policy_version": (
                    CURRENT_CREDENTIAL_POLICY_VERSION
                ),
            }
        )
        if args.production and not bool(status["production_ready"]):
            raise ProductConfigurationError(
                "管理员账号库没有按当前策略确认的正式管理员，"
                "或仍有启用的旧策略/弱口令/演示凭据账号。"
                "请在服务器本机运行 mineguard user change-password "
                "<账号> --state-directory <状态目录> 完成安全轮换"
            )
    if args.state_directory:
        root = _state_root(args.state_directory)
        evidence = _demo_state_evidence(root)
        result["state_demo_evidence_count"] = len(evidence)
        result["state_production_ready"] = not evidence
        if args.production and evidence:
            raise ProductConfigurationError(
                "演示或合成数据目录不能用于正式运行"
            )
    return result


def _self_check() -> dict[str, object]:
    assets: dict[str, dict[str, object]] = {}
    for directory, filename in (
        ("regulatory_web", "index.html"),
        ("regulatory_web", "app.js"),
        ("regulatory_web", "styles.css"),
        ("web", "index.html"),
        ("web", "app.js"),
        ("web", "styles.css"),
    ):
        payload = read_package_resource(directory, filename)
        if not payload:
            raise ProductConfigurationError(
                f"冻结运行时前端资源为空：{directory}/{filename}"
            )
        assets[f"{directory}/{filename}"] = {
            "bytes": len(payload),
            "sha256": sha256(payload).hexdigest(),
        }
    for mine in V2_WORKBOOK_DEMO_MINES:
        assert mine.bundled_filename is not None
        assert mine.expected_source_sha256 is not None
        payload = read_package_resource("demo_samples", mine.bundled_filename)
        digest = sha256(payload).hexdigest()
        if digest != mine.expected_source_sha256:
            raise ProductConfigurationError(
                f"冻结运行时演示样表完整性失败：{mine.bundled_filename}"
            )
        assets[f"demo_samples/{mine.bundled_filename}"] = {
            "bytes": len(payload),
            "sha256": digest,
        }

    try:
        from scipy.optimize import linprog

        solver = linprog([1.0], bounds=[(1.0, None)], method="highs")
    except (ImportError, RuntimeError) as error:
        raise ProductConfigurationError(
            "SciPy/HiGHS 数值求解器无法加载"
        ) from error
    if not solver.success or solver.x is None or abs(float(solver.x[0]) - 1.0) > 1e-8:
        raise ProductConfigurationError("SciPy/HiGHS 数值求解器自检失败")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        signing_key = Ed25519PrivateKey.generate()
        crypto_probe = b"mineguard-provisioning-frozen-runtime-self-check-v1"
        signature = signing_key.sign(crypto_probe)
        signing_key.public_key().verify(signature, crypto_probe)
        derived_key = Scrypt(
            salt=b"MineGuardSelfChk", length=32, n=1024, r=8, p=1
        ).derive(b"offline-self-check-only")
        encrypted = AESGCM(derived_key).encrypt(
            b"MGSelfCheck1", crypto_probe, b"mineguard-self-check-aad"
        )
        if (
            AESGCM(derived_key).decrypt(
                b"MGSelfCheck1", encrypted, b"mineguard-self-check-aad"
            )
            != crypto_probe
        ):
            raise ValueError("AES-GCM round trip mismatch")
    except (ImportError, RuntimeError, ValueError) as error:
        raise ProductConfigurationError(
            "冻结运行时缺少可用的 Ed25519/AES-GCM/scrypt 配置包密码组件"
        ) from error
    manifest = build_runtime_manifest()
    missing = [
        name
        for name, value in dict(manifest["dependencies"]).items()
        if value == "not-installed"
    ]
    if missing:
        raise ProductConfigurationError(
            "冻结运行时缺少依赖版本元数据：" + "、".join(missing)
        )
    try:
        timezone = ZoneInfo("Asia/Shanghai").key
    except (KeyError, OSError) as error:
        raise ProductConfigurationError(
            "冻结运行时缺少 Asia/Shanghai 时区数据"
        ) from error
    return {
        "status": "ok",
        "timezone": timezone,
        "solver": "scipy.optimize.linprog/highs",
        "solver_objective": float(solver.fun),
        "provisioning_crypto": "ed25519+aes-256-gcm+scrypt",
        "assets": assets,
        "runtime": manifest,
    }


def _print(value: dict[str, object], *, ascii_safe: bool = False) -> None:
    """Write one JSON document to stdout.

    ``ascii_safe`` is used at native-process boundaries that may be consumed by
    Windows PowerShell 5.1.  Escaping non-ASCII characters keeps the JSON
    byte-for-byte safe even when a legacy console code page is selected; JSON
    readers still recover the original Unicode strings.
    """

    print(
        json.dumps(
            value,
            ensure_ascii=ascii_safe,
            indent=2,
            allow_nan=False,
        )
    )


def _seed_demo(args: argparse.Namespace) -> dict[str, object]:
    result = seed_v2_demo_state(
        args.state_directory,
        through_month=args.through_month,
    )
    return result.model_dump(mode="json")


def _provisioning_secret(
    path_value: str | None, *, label: str, confirm: bool = False
) -> bytes:
    """Read provisioning credentials without accepting command-line secrets."""

    if path_value:
        from .provisioning import read_secret_file

        return read_secret_file(path_value, label=label)
    if not sys.stdin.isatty():
        raise ProductConfigurationError(
            f"{label} 只能从受保护文件或本机交互终端读取"
        )
    try:
        first = getpass.getpass(f"{label}（输入时不显示）：").encode("utf-8")
        if confirm:
            second = getpass.getpass(f"再次输入{label}：").encode("utf-8")
            if not secrets.compare_digest(first, second):
                raise ProductConfigurationError("两次输入的签发密钥口令不一致")
    except (EOFError, KeyboardInterrupt) as error:
        raise ProductConfigurationError(f"无法安全读取{label}") from error
    if not first:
        raise ProductConfigurationError(f"{label}不能为空")
    return first


def _provision(args: argparse.Namespace) -> dict[str, object]:
    from .provisioning import create_pair, import_registration, issuer_init

    if args.provision_command == "issuer-init":
        return issuer_init(
            private_key_path=args.private_key,
            public_key_path=args.public_key,
            passphrase=_provisioning_secret(
                args.passphrase_file,
                label="签发私钥口令",
                confirm=args.passphrase_file is None,
            ),
        )
    if args.provision_command == "create-pair":
        return create_pair(
            profile_path=args.profile,
            issuer_private_key_path=args.issuer_private_key,
            issuer_passphrase=_provisioning_secret(
                args.issuer_passphrase_file, label="签发私钥口令"
            ),
            output_directory=args.output_directory,
            activation_directory=args.activation_directory,
            enterprise_bundle_directory=args.enterprise_bundle_directory,
            platform_registration_directory=(
                args.platform_registration_directory
            ),
            enterprise_activation_directory=(
                args.enterprise_activation_directory
            ),
            platform_activation_directory=args.platform_activation_directory,
            previous_registration_bundle_path=(
                args.previous_registration_bundle
            ),
            previous_registration_activation_code_path=(
                args.previous_registration_activation_code_file
            ),
        )
    return import_registration(
        bundle_path=args.bundle,
        activation_code_path=args.activation_code_file,
        issuer_public_key_path=args.issuer_public_key,
        expected_public_key_sha256=args.expected_public_key_sha256,
        expected_issuer_key_id=args.expected_issuer_key_id,
        clients_file_path=args.clients_file,
        allow_update=args.allow_update,
    )


def main(argv: Sequence[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        if args.command == "serve":
            _serve(args)
        elif args.command == "demo":
            _demo(args)
        elif args.command == "setup":
            _print(_setup(args))
        elif args.command == "start":
            _start(args)
        elif args.command == "bootstrap-admin":
            _print(_bootstrap_admin_once(args))
        elif args.command == "seed-v2-demo":
            # The Windows GUI invokes this command from a PowerShell 5.1
            # background runspace.  Some Chinese Windows installations decode
            # native stdout with the active OEM/ANSI page before
            # ConvertFrom-Json sees it.  ASCII-safe JSON prevents that legacy
            # decoder from corrupting Chinese text or adjacent JSON quotes.
            _print(_seed_demo(args), ascii_safe=True)
        elif args.command == "backup":
            _print(_backup(args))
        elif args.command == "verify-backup":
            _print(_verify(args))
        elif args.command == "restore-backup":
            _print(_restore(args))
        elif args.command == "config-check":
            _print(_config_check(args))
        elif args.command == "self-check":
            _print(_self_check())
        elif args.command == "provision":
            _print(_provision(args))
        elif args.command == "user":
            _print(_user_operation(args))
        return 0
    except (
        AuthError,
        ProductConfigurationError,
        V2DemoSeedError,
        OperationsError,
        OSError,
        ValueError,
    ) as error:
        _print({"error": {"code": "operation_failed", "message": str(error)}})
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
