from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import tomllib
from xml.etree import ElementTree
from zoneinfo import ZoneInfo, reset_tzpath

import pytest

from mineguard.regulatory_v2_http import create_server


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "deploy" / "windows"
POWERSHELL_SCRIPTS = {
    "Install-MineGuardPlatform.ps1",
    "Set-MineGuardPlatformConfiguration.ps1",
    "Start-MineGuardPlatform.ps1",
    "Test-MineGuardPlatform.ps1",
    "Backup-MineGuardPlatform.ps1",
    "Restore-MineGuardPlatform.ps1",
    "Install-MineGuardPlatformService.ps1",
    "Remove-MineGuardPlatformService.ps1",
}


def _client_registry() -> dict[str, object]:
    return {
        "clients": [
            {
                "sender_id": "agent-mine-windows-001",
                "party_id": "operator-mine-windows-001",
                "mine_id": "MINE-WINDOWS-001",
                "message_secret": "windows-message-secret-material-0000000001",
                "transport_secret": "windows-transport-secret-material-0000001",
            }
        ]
    }


def test_windows_timezone_data_is_a_pinned_manifested_dependency(
    tmp_path: Path,
) -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    assert any(item.startswith("tzdata>=") for item in dependencies)
    assert "tzdata==2025.2" in (ROOT / "constraints.txt").read_text(encoding="utf-8")
    assert version("tzdata") == "2025.2"

    # Simulate Windows, where Python has no operating-system IANA tzdb.
    reset_tzpath([str(tmp_path)])
    ZoneInfo.clear_cache()
    try:
        shanghai = ZoneInfo("Asia/Shanghai")
        assert shanghai.key == "Asia/Shanghai"
    finally:
        reset_tzpath()
        ZoneInfo.clear_cache()


def test_windows_service_can_load_a_multi_mine_registry_from_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients_file = tmp_path / "clients.json"
    clients_file.write_text(
        json.dumps(_client_registry(), ensure_ascii=False),
        encoding="utf-8-sig",
    )
    monkeypatch.delenv("MINEGUARD_V2_CLIENTS_JSON", raising=False)
    monkeypatch.setenv("MINEGUARD_V2_CLIENTS_FILE", str(clients_file))

    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "mineguard.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
    )
    try:
        assert set(server.clients) == {"agent-mine-windows-001"}
        assert server.clients["agent-mine-windows-001"].mine_id == ("MINE-WINDOWS-001")
    finally:
        server.server_close()


def test_windows_powershell_surface_is_ps51_safe_and_bom_encoded() -> None:
    assert {path.name for path in WINDOWS.glob("*.ps1")} == POWERSHELL_SCRIPTS
    for name in POWERSHELL_SCRIPTS:
        payload = (WINDOWS / name).read_bytes()
        assert payload.startswith(b"\xef\xbb\xbf"), name
        source = payload.decode("utf-8-sig")
        assert source.startswith("[CmdletBinding("), name
        assert "Set-StrictMode" in source
        assert "$ErrorActionPreference = 'Stop'" in source
        assert "Activate.ps1" not in source
        assert "pwsh" not in source.casefold()

    install = (WINDOWS / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "-Wheelhouse" not in install  # parameters are named without a dash
    assert "[string] $Wheelhouse" in install
    assert "--no-index" in install
    assert "Invoke-WebRequest" not in install
    assert "Start-BitsTransfer" not in install
    assert "version[1] -ne 12" in install
    assert "icacls.exe" in install and "'/T' '/C'" in install

    start = (WINDOWS / "Start-MineGuardPlatform.ps1").read_text(encoding="utf-8-sig")
    assert "Scripts\\python.exe" in start
    assert "'-m', 'mineguard', 'serve'" in start
    assert "$env:PYTHONUTF8 = '1'" in start
    assert "MINEGUARD_V2_CLIENTS_FILE" in start
    assert "Remove-Item Env:MINEGUARD_V2_CLIENTS_JSON" in start
    assert "全新状态库缺少首次管理员密码" in start
    assert "仍含示例/占位秘密" in start
    assert "-isnot [bool]" in start


def test_windows_configuration_and_service_templates_fail_closed() -> None:
    xml_path = WINDOWS / "MineGuard.Platform.xml"
    xml = ElementTree.parse(xml_path).getroot()
    assert xml.findtext("id") == "MineGuardPlatform"
    assert xml.findtext("serviceaccount/username") == "NT AUTHORITY\\LocalService"
    assert "Start-MineGuardPlatform.ps1" in (xml.findtext("arguments") or "")
    assert xml.find("serviceaccount/password") is None
    xml_text = xml_path.read_text(encoding="utf-8")
    assert "MINEGUARD_ADMIN_PASSWORD" not in xml_text
    assert "MINEGUARD_V2_CLIENTS_JSON" not in xml_text

    configure = (WINDOWS / "Set-MineGuardPlatformConfiguration.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[Security.SecureString] $AdminPassword" in configure
    assert "Read-Host" in configure and "-AsSecureString" in configure
    assert "MINEGUARD_V2_CLIENTS_JSON" not in configure
    assert "SELECT COUNT(*) FROM users" in configure
    assert "-ClearBootstrapPassword" in configure
    assert "REPLACE(?:[_-]|\\b)" in configure

    service_install = (WINDOWS / "Install-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[ValidatePattern('^[A-Fa-f0-9]{64}$')]" in service_install
    assert "LocalService" in service_install
    assert "load_exchange_clients" in service_install
    assert "secureCookie" in service_install
    assert "-isnot [bool]" in service_install

    remove_service = (WINDOWS / "Remove-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "SupportsShouldProcess = $true" in remove_service
    assert "sc.exe" in remove_service
    assert "Remove-Item" not in remove_service
    assert "state" in remove_service and "backups" in remove_service

    backup = (WINDOWS / "Backup-MineGuardPlatform.ps1").read_text(encoding="utf-8-sig")
    restore = (WINDOWS / "Restore-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "'verify-backup'" in backup
    assert "'restore-backup'" in restore
    assert "settings.json" in backup and "$settings.stateDirectory" in backup
    assert "settings.json" in restore and "$settings.stateDirectory" in restore
    assert "Join-Path $InstallRoot 'state'" not in backup
    assert "Join-Path $InstallRoot 'state'" not in restore
    assert "必须不存在或为空" in restore
    assert "'/T' '/C'" in restore

    example = json.loads((WINDOWS / "clients.json.example").read_text(encoding="utf-8"))
    message_secret = next(iter(example["clients"][0]["message_keys"].values()))
    transport_secret = example["clients"][0]["transport_secrets"][0]
    assert len(message_secret.encode()) < 32
    assert "REPLACE" in transport_secret


def test_windows_operations_document_covers_the_complete_lifecycle() -> None:
    document = (ROOT / "docs" / "Windows原生部署与运维.md").read_text(encoding="utf-8")
    for required in (
        "Install-MineGuardPlatform.ps1",
        "Set-MineGuardPlatformConfiguration.ps1",
        "Start-MineGuardPlatform.ps1",
        "Test-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Install-MineGuardPlatformService.ps1",
        "Remove-MineGuardPlatformService.ps1",
        "MINEGUARD_V2_CLIENTS_FILE",
        "LocalService",
        "127.0.0.1",
        "Secure Cookie",
        "-Wheelhouse",
    ):
        assert required in document
