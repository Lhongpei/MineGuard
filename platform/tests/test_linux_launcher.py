from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "deploy" / "mineguard-linux.sh"
SHORT_LAUNCHER = ROOT / "start.sh"
SYSTEMD_TEMPLATE = ROOT / "deploy" / "mineguard.service.example"


def _source() -> str:
    return LAUNCHER.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="requires a native POSIX bash")
def test_linux_launcher_is_valid_strict_bash() -> None:
    for script in (LAUNCHER, SHORT_LAUNCHER):
        result = subprocess.run(
            ["bash", "-n", str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert os.access(script, os.X_OK)
    source = _source()
    assert source.startswith("#!/usr/bin/env bash\n")
    assert "set -Eeuo pipefail" in source
    assert "umask 077" in source
    short_source = SHORT_LAUNCHER.read_text(encoding="utf-8")
    assert 'exec "${PLATFORM_DIRECTORY}/deploy/mineguard-linux.sh" "$@"' in (
        short_source
    )


def test_linux_launcher_is_offline_only_and_does_not_handle_passwords() -> None:
    source = _source()
    lowered = source.casefold()
    for forbidden in ("curl", "wget", "eval", "sudo", "systemctl"):
        assert re.search(rf"\b{forbidden}\b", lowered) is None

    for required in (
        "MINEGUARD_WHEELHOUSE",
        "${PLATFORM_ROOT}/wheelhouse",
        "PIP_NO_INDEX=1",
        "PIP_CONFIG_FILE=/dev/null",
        "PIP_EXTRA_INDEX_URL=",
        "PIP_FIND_LINKS=",
        "--no-index",
        "--find-links",
        "--disable-pip-version-check",
        "--no-input",
        "python3",
        "sys.version_info >= (3, 11)",
    ):
        assert required in source

    assert "MINEGUARD_ADMIN_PASSWORD" not in source
    assert "read -s" not in source
    assert "getpass" not in source
    assert "https://" not in lowered
    assert "urllib.request.ProxyHandler({})" in source
    assert 'url = f"http://127.0.0.1:{port}/healthz"' in source
    assert 'document.get("service") != "mineguard-v2"' in source
    assert 'document.get("status") != "ok"' in source


def test_linux_launcher_has_the_five_plain_chinese_actions() -> None:
    source = _source()
    for label in (
        "1  演示启动",
        "2  正式首次配置",
        "3  启动现有配置",
        "4  健康检查",
        "5  退出",
    ):
        assert label in source

    assert re.search(r'"\$\{MINEGUARD_BIN\}"\s+demo\b', source)
    assert re.search(r'"\$\{MINEGUARD_BIN\}"\s+setup\b', source)
    assert re.search(r'"\$\{MINEGUARD_BIN\}"\s+start\b', source)


def test_linux_systemd_template_requests_a_bounded_graceful_stop() -> None:
    source = SYSTEMD_TEMPLATE.read_text(encoding="utf-8")
    assert "KillSignal=SIGINT" in source
    assert "KillMode=control-group" in source
    assert "TimeoutStopSec=30s" in source


@pytest.mark.skipif(os.name == "nt", reason="requires a native POSIX bash")
def test_linux_launcher_maps_menu_to_quickstart_commands_with_safe_paths(
    tmp_path: Path,
) -> None:
    platform_root = tmp_path / "离线 platform with spaces"
    deploy = platform_root / "deploy"
    binary = platform_root / ".venv" / "bin" / "mineguard"
    deploy.mkdir(parents=True)
    binary.parent.mkdir(parents=True)
    shutil.copyfile(LAUNCHER, deploy / LAUNCHER.name)
    binary.write_text(
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        ": \"${MINEGUARD_TEST_LOG:?}\"\n"
        "printf '<%s>' \"$@\" >> \"${MINEGUARD_TEST_LOG}\"\n"
        "printf '\\n' >> \"${MINEGUARD_TEST_LOG}\"\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    log = tmp_path / "calls.log"
    environment = os.environ.copy()
    environment["MINEGUARD_TEST_LOG"] = str(log)

    result = subprocess.run(
        ["bash", str(deploy / LAUNCHER.name)],
        # demo; setup with default state/port; start with remembered state; exit
        input="1\n2\n\n\n3\n\n5\n",
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        (
            f"<demo><--state-directory><{platform_root}/.mineguard-v2-demo>"
            "<--port><8080>"
        ),
        (
            f"<setup><--state-directory><{platform_root}/.mineguard-v2>"
            "<--port><8080>"
        ),
        f"<start><--state-directory><{platform_root}/.mineguard-v2>",
    ]
    assert "正式配置完成" in result.stdout
    assert "已退出" in result.stdout
