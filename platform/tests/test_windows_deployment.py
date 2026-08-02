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
    "Uninstall-MineGuardPlatformRuntime.ps1",
    "Resolve-MineGuardPlatformExecutable.ps1",
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

    for name in (
        "Start-MineGuardPlatform.ps1",
        "Test-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Remove-MineGuardPlatformService.ps1",
    ):
        source = (WINDOWS / name).read_text(encoding="utf-8-sig")
        assert "$PSVersionTable.PSVersion.Major -lt 5" in source, name
        assert "$PSVersionTable.PSVersion.Minor -lt 1" in source, name
        assert "Windows PowerShell 5.1" in source, name

    install = (WINDOWS / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "-Wheelhouse" not in install  # parameters are named without a dash
    assert "[string] $Wheelhouse" in install
    assert "--no-index" in install
    assert "Invoke-WebRequest" not in install
    assert "Start-BitsTransfer" not in install
    assert "version[1] -ne 12" in install
    assert "icacls.exe" in install and "@('/T', '/C')" in install

    start = (WINDOWS / "Start-MineGuardPlatform.ps1").read_text(encoding="utf-8-sig")
    assert "Resolve-MineGuardPlatformExecutable" in start
    assert "'serve'" in start
    assert "$env:PYTHONUTF8 = '1'" in start
    assert "MINEGUARD_V2_CLIENTS_FILE" in start
    assert "Remove-Item Env:MINEGUARD_V2_CLIENTS_JSON" in start
    assert "全新状态库缺少首次管理员密码" in start
    assert "仍含示例/占位秘密" in start
    assert "-isnot [bool]" in start
    for required in (
        "Get-SafeFixedNtfsPath",
        "^[A-Za-z]:\\\\",
        "DriveType]::Fixed",
        "DriveFormat -ne 'NTFS'",
        "现有祖先目录不能包含",
        "Assert-StateBoundary",
        "Assert-NoReparseTree",
        ".mineguard-platform-state.json",
    ):
        assert required in start


def test_windows_runtime_uninstall_is_transactional_and_data_preserving() -> None:
    script = (WINDOWS / "Uninstall-MineGuardPlatformRuntime.ps1").read_text(
        encoding="utf-8-sig"
    )
    for required in (
        "InternalInnoUninstall",
        "Assert-PlatformReleaseIdentity",
        "Assert-PlatformQuiescent",
        "$script:UninstallScriptPath",
        "does not match release metadata",
        "Get-CimInstance Win32_Process",
        "[IO.Directory]::Move($Target.Source, $Destination)",
        "for ($Index = $Moved.Count - 1; $Index -ge 0; $Index--)",
        "quarantine-marker.json",
        "Platform uninstall quarantine contains an unexpected item",
    ):
        assert required in script
    assert '$TargetNames = @("runtime", "deploy", "service", "release-metadata")' in script
    for preserved in ("config", "state", "backups", "logs"):
        expanded = (
            '$TargetNames = @("runtime", "deploy", "service", '
            f'"release-metadata", "{preserved}")'
        )
        assert expanded not in script


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
    assert "'config-check', '--auth-database'" in configure
    assert "'config-check', '--clients-file'" in configure
    assert "-ClearBootstrapPassword" in configure
    assert "REPLACE(?:[_-]|\\b)" in configure
    assert "Assert-StateBoundary" in configure
    assert "Assert-NoReparseTree" in configure
    assert ".mineguard-platform-state.json" in configure
    assert ".configuration-transaction." in configure
    assert "Platform 配置失败且自动回滚不完整" in configure
    assert "Set-ConfigAcl -Path $configDirectory" in configure
    assert "AuditFailAfterFirstMutation" in configure
    assert "configuration-rollback-test" in configure

    service_install = (WINDOWS / "Install-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[ValidatePattern('^[A-Fa-f0-9]{64}$')]" in service_install
    assert "LocalService" in service_install
    assert "'config-check', '--clients-file'" in service_install
    assert "secureCookie" in service_install
    assert "-isnot [bool]" in service_install
    assert "winsw-integrity.json" in service_install
    assert "wrapperSha256" in service_install
    assert "wrapperConfigSha256" in service_install

    remove_service = (WINDOWS / "Remove-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "SupportsShouldProcess = $true" in remove_service
    assert "sc.exe" in remove_service
    assert "Remove-Item -LiteralPath $exactPath" in remove_service
    for protected_delete in (
        "Remove-Item -LiteralPath $InstallRoot",
        "Remove-Item -LiteralPath (Join-Path $InstallRoot 'config')",
        "Remove-Item -LiteralPath (Join-Path $InstallRoot 'state')",
        "Remove-Item -LiteralPath (Join-Path $InstallRoot 'backups')",
        "Remove-Item -LiteralPath (Join-Path $InstallRoot 'logs')",
    ):
        assert protected_delete not in remove_service
    assert "state" in remove_service and "backups" in remove_service
    assert "$registered.Equals($ExpectedWrapper" in remove_service
    assert "-notlike ('*'" not in remove_service
    for required in (
        "Get-SafeFixedNtfsPath",
        "^[A-Za-z]:\\\\",
        "DriveType]::Fixed",
        "FileAttributes]::ReparsePoint",
    ):
        assert required in remove_service
    assert (
        "DriveFormat -ne 'NTFS'" in remove_service
        or "DriveFormat.Equals('NTFS'" in remove_service
    )


def test_platform_service_lifecycle_is_path_bound_and_transactional() -> None:
    install = (WINDOWS / "Install-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    remove = (WINDOWS / "Remove-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )

    for script in (install, remove):
        for required in (
            "$env:OS -ne 'Windows_NT'",
            "$PSVersionTable.PSVersion.Major -lt 5",
            "$PSVersionTable.PSVersion.Minor -lt 1",
            "WindowsBuiltInRole]::Administrator",
            "IndexOf([char]0)",
            ".Contains(':')",
            "$part -in @('.', '..')",
            "DriveType]::Fixed",
            "FileAttributes]::ReparsePoint",
            "Get-CimInstance Win32_Service",
            "Get-ServiceExecutablePath",
            "^[^\"\\r\\n]+$",
            "StringComparison]::OrdinalIgnoreCase",
            "NT AUTHORITY\\LocalService",
        ):
            assert required in script

    for required in (
        "Assert-PlatformReleaseIdentity",
        "release-manifest.json",
        "runtime/MineGuardPlatform.exe",
        "ExpectedConfigSha256",
        "FileMode]::CreateNew",
        "$stream.Flush($true)",
        "[IO.File]::Move($temporaryWrapper, $destination)",
        "[IO.File]::Move($temporaryIntegrity, $integrityPath)",
        "服务安装拒绝覆盖已有 WinSW 文件",
        "Remove-ServiceRegistrationChecked",
        "rollback incomplete",
        "Start-Service -Name 'MineGuardPlatform'",
        "WaitForStatus(",
        "Assert-ServiceIdentity -Service $registeredService",
    ):
        assert required in install
    assert install.count("Get-FileHash -LiteralPath $WinSWExecutable") >= 2
    assert install.count("Get-FileHash -LiteralPath $sourceConfig") >= 2
    assert "& $destination 'start'" not in install
    transaction_start = install.index("try {\n    # 最后一次复核")
    install_call = install.index("& $destination 'install'", transaction_start)
    transaction_catch = install.index("} catch {", install_call)
    assert transaction_start < install_call < transaction_catch

    for required in (
        "Assert-PlatformReleaseAndConfigurationIdentity",
        "Assert-WrapperIntegrity",
        "SupportsShouldProcess = $true",
        "RemoveWrapperFiles",
        "拒绝同名服务劫持",
        "Wait-ServiceRecordAbsent",
        "# 最后一次 sc.exe delete 之前重新读取",
        "$service = Get-RegisteredService",
    ):
        assert required in remove
    assert "(?:\\s|$)" not in remove
    final_query = remove.index("# 最后一次 sc.exe delete 之前重新读取")
    final_assert = remove.index(
        "Assert-ServiceTargetsWrapper -Service $service", final_query
    )
    delete = remove.index("'delete' 'MineGuardPlatform'", final_assert)
    wait = remove.index("Wait-ServiceRecordAbsent", delete)
    assert final_query < final_assert < delete < wait

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
    for script in (backup, restore):
        for required in (
            "Get-SafeFixedNtfsPath",
            "^[A-Za-z]:\\\\",
            "DriveType]::Fixed",
            "DriveFormat -ne 'NTFS'",
            "现有祖先目录不能包含",
            "Assert-NoReparseTree",
            "Assert-StateBoundary",
            ".mineguard-platform-state.json",
        ):
            assert required in script
    assert "Initialize-StateOwnership" in restore
    assert "Set-MineGuardPlatformConfiguration.ps1 -StateDirectory" in restore
    assert "配置事务原子切换" in restore
    assert "人工修改 settings.json" not in restore
    assert restore.index("$restored =") < restore.index(
        "Initialize-StateOwnership -Path $TargetStateDirectory"
    ) < restore.index("icacls.exe")

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
        "X:\\...",
        ".mineguard-platform-state.json",
        "固定 NTFS",
        "禁止手工编辑 `settings.json`",
        "Set-MineGuardPlatformConfiguration.ps1",
        "ExpectedConfigSha256",
        "Win32_Service.PathName",
        "RemoveWrapperFiles",
        "回滚不完整",
    ):
        assert required in document
