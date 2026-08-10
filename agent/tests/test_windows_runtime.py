from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from enterprise_agent import cli
from enterprise_agent.auth import hash_password
from enterprise_agent.cli import _configuration_errors, main
from enterprise_agent.environment import (
    load_authoritative_environment_file,
    load_environment_file,
    parse_environment_file,
)
from enterprise_agent.instance_lock import lock_for_database
from enterprise_agent.maintenance import backup_database, restore_database
from enterprise_agent.settings import Settings, split_path_list
from enterprise_agent.storage import Repository


def test_strict_environment_file_supports_bom_unicode_and_process_precedence(
    tmp_path: Path,
) -> None:
    config = tmp_path / "agent.env"
    config.write_bytes(
        (
            "\ufeff# comment\r\nENTERPRISE_MINE_NAME=示例煤矿\r\n"
            'ENTERPRISE_AGENT_USERS_JSON=\'[{"name":"张三"}]\'\r\n'
            "EMPTY=\r\n"
        ).encode()
    )
    parsed = parse_environment_file(config)
    assert parsed == {
        "ENTERPRISE_MINE_NAME": "示例煤矿",
        "ENTERPRISE_AGENT_USERS_JSON": '[{"name":"张三"}]',
        "EMPTY": "",
    }

    environment = {"ENTERPRISE_MINE_NAME": "inherited"}
    loaded = load_environment_file(config, environment=environment)
    assert "ENTERPRISE_MINE_NAME" not in loaded
    assert environment["ENTERPRISE_MINE_NAME"] == "inherited"
    assert environment["EMPTY"] == ""


def test_environment_file_rejects_relative_link_duplicate_and_oversize(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="绝对路径"):
        parse_environment_file("relative.env")

    duplicate = tmp_path / "duplicate.env"
    duplicate.write_text("A=1\nA=2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="重复定义"):
        parse_environment_file(duplicate)

    oversized = tmp_path / "oversized.env"
    oversized.write_bytes(b"A=" + (b"x" * (1024 * 1024)))
    with pytest.raises(ValueError, match="1 MiB"):
        parse_environment_file(oversized)

    target = tmp_path / "target.env"
    target.write_text("A=1\n", encoding="utf-8")
    link = tmp_path / "link.env"
    try:
        link.symlink_to(target)
    except OSError:
        return
    with pytest.raises(ValueError, match="链接|重解析点"):
        parse_environment_file(link)


def test_authoritative_environment_file_rejects_machine_configuration_pollution(
    tmp_path: Path,
) -> None:
    config = tmp_path / "agent.env"
    config.write_text(
        "\n".join(
            (
                r"ENTERPRISE_AGENT_DB=C:\Mine\mine-a.db",
                "ENTERPRISE_MINE_ID=mine-a",
                "ENTERPRISE_EXCHANGE_HMAC_SECRET=file-message-secret-32-bytes-long",
                "PLATFORM_V2_TRANSPORT_HMAC_SECRET=file-transport-secret-32-bytes-long",
                "ENTERPRISE_AGENT_PRODUCTION_MODE=true",
                "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED=true",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    environment = {
        "ENTERPRISE_AGENT_DB": r"C:\Other\mine-b.db",
        "ENTERPRISE_MINE_ID": "mine-b",
        "ENTERPRISE_EXCHANGE_HMAC_SECRET": "machine-message-secret",
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET": "machine-transport-secret",
        "PLATFORM_BEARER_TOKEN": "machine-only-value",
        "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET": "machine-only-value",
        "AGENT_V2_WORKER_COUNT": "8",
        "DEEPSEEK_API_KEY": "machine-only-value",
        "COAL_NEWS_SEARCH_ENABLED": "false",
        "ENTERPRISE_AGENT_ENV_FILE": r"C:\Other\agent.env",
        "MINEGUARD_SERVICE_PRODUCTION_MODE": "false",
        "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED": "false",
        "UNRELATED_KEEP_ME": "yes",
    }

    loaded = load_authoritative_environment_file(config, environment=environment)

    assert "ENTERPRISE_AGENT_DB" in loaded
    assert environment["ENTERPRISE_AGENT_DB"] == r"C:\Mine\mine-a.db"
    assert environment["ENTERPRISE_MINE_ID"] == "mine-a"
    assert environment["ENTERPRISE_EXCHANGE_HMAC_SECRET"].startswith("file-")
    assert environment["PLATFORM_V2_TRANSPORT_HMAC_SECRET"].startswith("file-")
    assert environment["ENTERPRISE_AGENT_PRODUCTION_MODE"] == "false"
    assert environment["ENTERPRISE_AGENT_FOUR_EYES_REQUIRED"] == "false"
    assert "PLATFORM_BEARER_TOKEN" not in environment
    assert "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET" not in environment
    assert "AGENT_V2_WORKER_COUNT" not in environment
    assert "DEEPSEEK_API_KEY" not in environment
    assert "COAL_NEWS_SEARCH_ENABLED" not in environment
    assert "ENTERPRISE_AGENT_ENV_FILE" not in environment
    assert "MINEGUARD_SERVICE_PRODUCTION_MODE" not in environment
    assert "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED" not in environment
    assert environment["UNRELATED_KEEP_ME"] == "yes"


def test_authoritative_environment_requires_explicit_absolute_file_and_strict_policy(
    tmp_path: Path,
) -> None:
    config = tmp_path / "agent.env"
    config.write_text("ENTERPRISE_MINE_ID=mine-a\n", encoding="utf-8")
    with pytest.raises(ValueError, match="true 或 false"):
        load_authoritative_environment_file(
            config,
            environment={"MINEGUARD_SERVICE_PRODUCTION_MODE": "1"},
        )
    reserved = tmp_path / "reserved.env"
    reserved.write_text(
        "MINEGUARD_SERVICE_PRODUCTION_MODE=true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="保留的 MINEGUARD_"):
        load_authoritative_environment_file(reserved, environment={})
    with pytest.raises(SystemExit):
        main(["--authoritative-env-file", "config-check"])
    with pytest.raises(SystemExit):
        main(
            [
                "--env-file",
                "relative.env",
                "--authoritative-env-file",
                "config-check",
            ]
        )


def test_authoritative_runtime_honors_restore_recovery_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = tmp_path / "config" / "agent.env"
    config.parent.mkdir()
    config.write_text("ENTERPRISE_MINE_ID=mine-a\n", encoding="utf-8")
    transaction_id = "a" * 32
    marker = tmp_path / "restore-recovery-block.json"
    marker.write_text(
        json.dumps(
            {
                "format": "mineguard-enterprise-agent-restore-recovery-block-v1",
                "transaction_id": transaction_id,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="未完成恢复阻断标记"):
        cli._assert_authoritative_restore_not_blocked(config, command="serve")

    monkeypatch.setenv(
        "MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID",
        transaction_id,
    )
    cli._assert_authoritative_restore_not_blocked(
        config,
        command="database-restore",
    )
    monkeypatch.setenv("MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID", "b" * 32)
    with pytest.raises(ValueError, match="不属于当前离线恢复事务"):
        cli._assert_authoritative_restore_not_blocked(
            config,
            command="database-restore",
        )


def test_windows_semicolon_watch_path_list_keeps_drive_colons() -> None:
    assert split_path_list(
        r"C:\MineGuard\Inbox;D:\煤矿 数据\收件箱",
        separator=";",
    ) == (r"C:\MineGuard\Inbox", r"D:\煤矿 数据\收件箱")


def test_production_config_rejects_loopback_http_platform(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    monkeypatch.setenv("PLATFORM_V2_BASE_URL", "http://127.0.0.1:8080")
    monkeypatch.setenv("PLATFORM_V2_SENDER_ID", "agent-demo-mine-001")
    monkeypatch.setenv(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "application-secret-at-least-thirty-two-bytes",
    )
    monkeypatch.setenv(
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
        "different-transport-secret-at-least-32-bytes",
    )
    errors = _configuration_errors(Settings.from_environment(), production=True)
    assert "正式服务连接政府 V2 平台必须使用 HTTPS" in errors


def test_production_config_rejects_default_and_placeholder_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    defaults = {
        "ENTERPRISE_MINE_ID": "demo-mine-001",
        "ENTERPRISE_MINE_NAME": "演示煤矿",
        "ENTERPRISE_OPERATOR_ID": "demo-operator-001",
        "ENTERPRISE_OPERATOR_NAME": "演示煤矿经营主体",
        "ENTERPRISE_SYSTEM_ID": "agent-demo-mine-001",
        "REGULATORY_SYSTEM_ID": "demo-regulatory-system",
        "REGULATORY_PARTY_ID": "demo-regulatory-party",
    }
    for name, value in defaults.items():
        monkeypatch.setenv(name, value)
    errors = _configuration_errors(Settings.from_environment(), production=True)
    for field_name in (
        "ENTERPRISE_MINE_ID",
        "ENTERPRISE_MINE_NAME",
        "ENTERPRISE_OPERATOR_ID",
        "ENTERPRISE_OPERATOR_NAME",
        "ENTERPRISE_SYSTEM_ID",
        "REGULATORY_SYSTEM_ID",
        "REGULATORY_PARTY_ID",
    ):
        assert any(field_name in error and "占位身份" in error for error in errors)
    for value in (
        "test-mine",
        "replace-me",
        "sample_source",
        "示例煤矿",
        "__SYSTEM_ID__",
    ):
        assert cli._placeholder_production_identity(value)
    assert not cli._placeholder_production_identity("MINE-SX-QY-2026-071")


@pytest.mark.parametrize(
    "url",
    (
        "https://replace-with-regulator-host.example",
        "https://portal.example.com",
        "https://portal.example.net",
        "https://portal.example.org",
        "https://coal.invalid",
        "https://coal.test",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://0.0.0.0",
        "https://[::]",
        "https://224.0.0.1",
        "https://[ff02::1]",
        "https://169.254.10.20",
        "https://[fe80::1]",
    ),
)
def test_production_urls_reject_reserved_example_and_loopback_hosts(url: str) -> None:
    assert cli._placeholder_production_url(url)


def test_production_urls_allow_real_internal_https_hosts() -> None:
    assert not cli._placeholder_production_url("https://mineguard.internal")
    assert not cli._placeholder_production_url("https://10.20.30.40:8443/v2")


def test_production_accounts_reject_placeholder_ids_and_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_USERS_JSON",
        json.dumps(
            [
                {
                    "actor_id": "preparer-2026",
                    "name": "测试账号",
                    "role": "经办人",
                    "password_hash": hash_password("MineGuard!Prepare2026"),
                    "credential_provenance": "production_hash_command",
                    "permissions": ["read", "write"],
                },
                {
                    "actor_id": "demo-reviewer",
                    "name": "李四",
                    "role": "复核负责人",
                    "password_hash": hash_password("MineGuard!Review2026"),
                    "credential_provenance": "production_hash_command",
                    "permissions": ["read", "confirm", "submit"],
                },
            ],
            ensure_ascii=False,
        ),
    )
    errors = _configuration_errors(Settings.from_environment(), production=True)
    assert any("demo-reviewer" in error and "actor_id" in error for error in errors)
    assert any("preparer-2026" in error and "name" in error for error in errors)
    assert not cli._placeholder_production_identity("张三")


def test_production_key_ids_align_with_formal_windows_recommendations() -> None:
    for placeholder in ("key", "key-v1", "key-v2", "current-key", "demo-key"):
        assert cli._placeholder_key_id(placeholder)
    assert not cli._placeholder_key_id("enterprise-key-v2")
    assert not cli._placeholder_key_id("regulator-key-v2")


def test_production_config_reports_reserved_https_origins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_PUBLIC_ORIGIN",
        "https://browser.example",
    )
    monkeypatch.setenv(
        "PLATFORM_V2_BASE_URL",
        "https://replace-with-regulator-host.example",
    )
    monkeypatch.setenv("ENTERPRISE_SYSTEM_ID", "agent-mine-sx-qy-2026")
    monkeypatch.setenv("PLATFORM_V2_SENDER_ID", "agent-mine-sx-qy-2026")
    monkeypatch.setenv(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "message-secret-with-at-least-thirty-two-bytes",
    )
    monkeypatch.setenv(
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
        "transport-secret-with-at-least-thirty-two-bytes",
    )
    errors = _configuration_errors(Settings.from_environment(), production=True)
    assert (
        "正式服务 PUBLIC_ORIGIN 不能使用保留、示例、回环或不可路由特殊地址"
        in errors
    )
    assert (
        "正式服务政府 V2 地址不能使用保留、示例、回环或不可路由特殊地址"
        in errors
    )


def test_production_config_rejects_placeholder_connector_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON",
        json.dumps(
            [
                {
                    "client_id": "sample-connector",
                    "secret": "connector-secret-with-at-least-thirty-two-bytes",
                    "permissions": ["autofill"],
                    "allowed_sources": {"test-source": "示例SCADA"},
                }
            ],
            ensure_ascii=False,
        ),
    )
    errors = _configuration_errors(Settings.from_environment(), production=True)
    assert any("connector client_id" in error for error in errors)
    assert any("connector source_id" in error for error in errors)
    assert any("connector source_system" in error for error in errors)


def test_windows_deployment_assets_keep_secrets_out_of_service_xml() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    expected = {
        "Install-EnterpriseAgent.ps1",
        "New-EnterpriseAgentInstance.ps1",
        "Start-EnterpriseAgent.ps1",
        "Test-EnterpriseAgentHealth.ps1",
        "Install-EnterpriseAgentService.ps1",
        "Uninstall-EnterpriseAgentService.ps1",
        "Backup-EnterpriseAgent.ps1",
        "Restore-EnterpriseAgent.ps1",
    }
    assert expected.issubset({path.name for path in root.glob("*.ps1")})
    for script in root.glob("*.ps1"):
        encoded = script.read_bytes()
        assert encoded.startswith(b"\xef\xbb\xbf") or encoded.isascii()
        lowered = encoded.lower()
        assert b"invoke-expression" not in lowered
        assert b"downloadfile" not in lowered
    service_xml = (root / "enterprise-agent-service.xml.template").read_text(
        encoding="utf-8"
    )
    assert "__ENV_FILE__" in service_xml
    assert "--authoritative-env-file" in service_xml
    assert "MINEGUARD_SERVICE_PRODUCTION_MODE" in service_xml
    assert "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED" in service_xml
    assert "HMAC_SECRET" not in service_xml
    assert "DEEPSEEK_API_KEY" not in service_xml
    installer = (root / "Install-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )
    assert "WinSWExpectedSha256" in installer
    assert '"--production"' in installer
    backup = (root / "Backup-EnterpriseAgent.ps1").read_text(encoding="utf-8")
    assert '"five-quantity-quarantine"' in backup
    assert '"snapshot.json"' in backup


def test_windows_service_lifecycle_is_path_bound_and_transactional() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    installer = (root / "Install-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )
    uninstaller = (root / "Uninstall-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )

    for script in (installer, uninstaller):
        assert "Set-StrictMode -Version 2.0" in script
        assert "Windows PowerShell 5.1 or later is required." in script
        assert "WindowsBuiltInRole]::Administrator" in script
        assert "Assert-SafeLocalFixedNtfsPath" in script
        assert "must be supplied as an X:\\ absolute local path" in script
        assert "alternate data stream (ADS)" in script
        assert "cannot contain dot path segments" in script
        assert "cannot contain empty path segments" in script
        assert "a path segment ending in a space or dot" in script
        assert "DriveType -ne 3" in script
        assert 'FileSystem).Equals("NTFS"' in script
        assert "Assert-NoReparseAncestors" in script
        assert "Assert-OrdinaryDirectoryTree" in script
        assert "ReparsePoint" in script
        assert ".mineguard-enterprise-agent-instances.json" in script
        assert "mineguard-enterprise-agent-state-root-v1" in script
        assert "Read-ValidatedInstanceMetadata" in script
        assert "mineguard-enterprise-agent-windows-instance-v1" in script
        assert "Assert-PathBelowRoot" in script
        assert "Get-CimInstance Win32_Service" in script
        assert "PathName" in script
        assert "Assert-ServiceTargetsWrapper" in script

    assert installer.index(
        '$InstallRoot = Assert-SafeLocalFixedNtfsPath -Name "InstallRoot"'
    ) < installer.index('Assert-OrdinaryDirectoryTree -Name "InstallRoot"')
    assert installer.index(
        '$StateRoot = Assert-SafeLocalFixedNtfsPath -Name "StateRoot"'
    ) < installer.index('Assert-OrdinaryDirectoryTree -Name "StateRoot"')
    assert installer.index(
        '$WinSWPath = Assert-SafeLocalFixedNtfsPath -Name "WinSWPath"'
    ) < installer.index('Assert-OrdinaryFile -Name "WinSW executable"')
    assert installer.count("Get-FileHash -LiteralPath $WinSWPath") >= 2
    assert "Get-FileHash -LiteralPath $TemporaryWrapper" in installer
    assert "Get-FileHash -LiteralPath $WrapperExecutable" in installer
    assert "FileMode]::CreateNew" in installer
    assert "$Stream.Flush($true)" in installer
    assert (
        "Service installation refuses to overwrite an existing wrapper file"
        in installer
    )
    assert (
        "Move-Item -LiteralPath $TemporaryWrapper -Destination "
        "$WrapperExecutable"
    ) in installer
    assert (
        "Move-Item -LiteralPath $TemporaryXml -Destination $WrapperXml"
        in installer
    )
    assert "Remove-ServiceRegistrationChecked" in installer
    assert "rollback was incomplete" in installer
    assert installer.index("Invoke-NativeChecked -FilePath $WrapperExecutable") > (
        installer.index("$InstalledWrapperHash =")
    )

    assert "same-name service hijack" in uninstaller
    assert "& $ScPath delete $ServiceId" in uninstaller
    assert "& $WrapperExecutable" not in uninstaller
    assert "Remove-Item -LiteralPath $ExactPath" in uninstaller
    assert "Remove-Item -LiteralPath $InstanceRoot" not in uninstaller
    assert "Configuration, database, evidence, logs and backups were preserved" in (
        uninstaller
    )


def test_windows_service_uses_a_dedicated_verified_service_sid() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    helper = (root / "EnterpriseAgent.WindowsSafety.ps1").read_text(
        encoding="utf-8"
    )
    creator = (root / "New-EnterpriseAgentInstance.ps1").read_text(
        encoding="utf-8"
    )
    runtime = (root / "Install-EnterpriseAgent.ps1").read_text(
        encoding="utf-8"
    )
    service = (root / "Install-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )
    uninstaller = (root / "Uninstall-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )
    restore = (root / "Restore-EnterpriseAgent.ps1").read_text(
        encoding="utf-8"
    )
    xml = (root / "enterprise-agent-service.xml.template").read_text(
        encoding="utf-8"
    )

    assert "__SERVICE_ACCOUNT__" in xml
    assert "LOCAL SERVICE" not in xml.upper()
    for path in root.glob("*.ps1"):
        script_text = path.read_text(encoding="utf-8-sig")
        assert "*S-1-5-19:(OI)(CI)" not in script_text, (
            f"shared LocalService authorization remains in {path.name}"
        )
    for token in (
        "sc.exe showsid",
        'AccountName = "NT SERVICE\\$ServiceId"',
        '"ServiceSidType"',
        "ServiceSidType -ne 1",
        "StartName",
        "Virtual service account SID does not match the derived service SID",
        "Set-EAInstanceCanonicalAcl",
        "Assert-EAInstanceWatchAcls",
        "Assert-EAInstanceGlobalIsolation",
        "Watch directory isolation violation",
        "Instance port isolation violation",
        "MineId isolation violation",
        "SystemId isolation violation",
    ):
        assert token in helper
    assert "S-1-5-19:(OI)(CI)" not in helper
    assert '"*S-1-5-80-0:(OI)(CI)RX"' in runtime
    assert '"*S-1-5-80-0:RX"' in runtime
    assert "S-1-5-19:(OI)(CI)" not in runtime
    assert "Assert-EARegisteredRuntimeServiceIdentity" in runtime
    assert "Registered service $ServiceId uses legacy/shared identity" in runtime

    assert '"*$($ServiceIdentity.Sid):(OI)(CI)RX"' in creator
    assert '"*$($ServiceIdentity.Sid):(OI)(CI)M"' in creator
    assert "-SkipAcl requires the explicit -DevelopmentOnly" in creator
    assert "Grant-EAServiceWatchReadAcl" in creator
    assert "$ExistingContexts" in creator
    assert "overlaps existing instance" in creator
    assert '"Global\\MineGuardEnterpriseAgent-StateRoot-' in creator
    assert "Threading.Mutex" in creator
    assert "WaitOne" in creator
    assert "ReleaseMutex" in creator
    assert creator.index("WaitOne") < creator.index("$ExistingContexts")
    assert creator.index("$Published = $true") < creator.index("ReleaseMutex")
    assert "MineId $MineId is already assigned" in creator
    assert "SystemId $SystemId is already assigned" in creator
    assert "S-1-5-19:(OI)(CI)" not in creator

    assert '"sidtype", $ServiceId, "unrestricted"' in service
    assert '"__SERVICE_ACCOUNT__"' in service
    assert "Assert-EARegisteredServiceIdentity" in service
    assert "Set-EAInstanceCanonicalAcl -Context $SharedContext" in service
    assert "Assert-EAInstanceWatchAcls -Context $SharedContext" in service
    assert "Assert-EAInstanceGlobalIsolation -Context $SharedContext" in service
    assert "Set-EAInstanceCanonicalAcl -Context $Context" in restore
    for broad_sid in (
        "S-1-1-0",
        "S-1-5-11",
        "S-1-5-19",
        "S-1-5-20",
        "S-1-5-32-545",
        "S-1-5-80-0",
    ):
        assert broad_sid in helper
    watch_grant = helper[
        helper.index("function Grant-EAServiceWatchReadAcl") : helper.index(
            "function Assert-EAServiceWatchReadAcl"
        )
    ]
    assert '"/remove:g"' not in watch_grant
    assert "does not remove business ACLs automatically" in helper

    assert "AllowLegacyLocalServiceRemoval" in uninstaller
    assert 'if ($LegacySid -ne "S-1-5-19")' in uninstaller
    assert "permits only the exact LocalService SID S-1-5-19" in uninstaller
    assert "Assert-ServiceIdentityForRemoval" in uninstaller


def test_windows_formal_install_uses_external_signer_pin_and_explicit_test_mode(
) -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    runtime = (root / "Install-EnterpriseAgent.ps1").read_text(
        encoding="utf-8"
    )
    service = (root / "Install-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )

    for script in (runtime, service):
        assert "ApprovedSignerThumbprint" in script
        assert "AllowUnsignedTestMedia" in script
        assert "Get-AuthenticodeSignature" in script
        assert 'Status.ToString() -ne "Valid"' in script
        assert "TimeStamperCertificate" in script
        assert "independently approved" in script
        assert '^[A-F0-9]{40}$' in script
    assert "Unsigned Agent media is refused by default" in runtime
    assert (
        "-AllowUnsignedTestMedia is valid only for actually unsigned "
        "internal-test media"
        in runtime
    )
    assert "Unsigned test media cannot claim an approved production signer" in runtime
    assert "Assert-InstalledAgentReleaseClassification" in service
    assert "mineguard-enterprise-agent-windows-binary-v1" in service
    assert (
        "metadata does not classify the binary under the independently approved signer"
        in service
    )
    assert "-AllowUnsignedTestMedia requires -AllowIncompleteDemo" in service
    assert "source-development Python runtime" in service
    isolated_check_call = service.index(
        "Invoke-IsolatedAgentConfigCheck -ExecutablePath $AgentExecutable"
    )
    assert service.rindex("Assert-InstalledAgentReleaseClassification") < (
        isolated_check_call
    )
    assert service.rindex("Assert-FormalAgentAuthenticode") < isolated_check_call
    for prefix in (
        "ENTERPRISE_",
        "PLATFORM_",
        "REGULATORY_",
        "AGENT_V2_",
        "DEEPSEEK_",
        "COAL_NEWS_",
        "MINEGUARD_SERVICE_",
    ):
        assert prefix in service
    assert "Invoke-IsolatedAgentConfigCheck" in service
    assert "[EnvironmentVariableTarget]::Process" in service
    assert "finally {" in service
    assert '"--authoritative-env-file", "config-check"' in service
    assert "Formal service installation requires -Start" in service
    start_wait = service.index("$ServiceController.WaitForStatus(")
    health_check = service.index("& $HealthScriptPath -InstanceName")
    install_success = service.index('Write-Host "Windows service installed')
    assert start_wait < health_check < install_success
    release_validation = runtime.index(
        "$ReleaseContract = Test-BinaryReleaseManifest -ReleaseRoot $SourceRoot"
    )
    executable_launch = runtime.index("$CandidateReportedVersion = (")
    state_claim = runtime.index("Initialize-EnterpriseAgentStateRoot -Root $StateRoot")
    assert release_validation < executable_launch < state_claim


def test_windows_powershell_has_no_adjacent_duplicate_param_or_throw_lines() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    for path in sorted(root.glob("*.ps1")):
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        for previous, current in zip(lines, lines[1:], strict=False):
            normalized = current.strip()
            if normalized.startswith(("param(", "throw ")):
                assert normalized != previous.strip(), (
                    f"adjacent duplicate statement in {path.name}: {normalized}"
                )


def test_windows_powershell_parses_when_native_parser_is_available() -> None:
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell parser is unavailable on this host")
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    parser = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$args[0],[ref]$tokens,[ref]$errors) | Out-Null; "
        "if ($errors.Count -ne 0) { $errors | ForEach-Object { "
        "[Console]::Error.WriteLine($_.Message) }; exit 1 }"
    )
    for path in sorted(root.glob("*.ps1")):
        completed = subprocess.run(
            [
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                parser,
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, (
            f"PowerShell parser rejected {path.name}: {completed.stderr}"
        )


def test_windows_runtime_uninstall_is_transactional_and_preserves_instances() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (
        root / "deploy" / "windows" / "Uninstall-EnterpriseAgentRuntime.ps1"
    ).read_text(encoding="utf-8")
    inno = (
        root.parent
        / "packaging"
        / "windows"
        / "inno"
        / "MineGuardEnterpriseAgent.iss"
    ).read_text(encoding="utf-8")
    for required in (
        "InternalInnoUninstall",
        "Assert-AgentReleaseIdentity",
        "Assert-AgentQuiescent",
        "$script:UninstallScriptPath",
        "does not match release metadata",
        "Get-CimInstance Win32_Process",
        "[IO.Directory]::Move($Target.Source, $Destination)",
        "for ($Index = $Moved.Count - 1; $Index -ge 0; $Index--)",
        "quarantine-marker.json",
        "Agent uninstall quarantine contains an unexpected item",
    ):
        assert required in script
    assert '$TargetNames = @("runtime", "deploy", "release-metadata")' in script
    assert "Remove-Item -LiteralPath $StateRoot" not in script
    assert '"config", "data", "logs", "backups", "inbox", "service"' not in script
    assert 'DestDir: "{app}\\uninstall-tools"' in inno
    assert "CurUninstallStepChanged" in inno
    assert "RaiseException" in inno


def test_windows_instance_operations_share_strict_path_and_identity_context() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    helper = (root / "EnterpriseAgent.WindowsSafety.ps1").read_text(
        encoding="utf-8"
    )
    operations = {
        name: (root / name).read_text(encoding="utf-8")
        for name in (
            "New-EnterpriseAgentInstance.ps1",
            "Start-EnterpriseAgent.ps1",
            "Backup-EnterpriseAgent.ps1",
            "Restore-EnterpriseAgent.ps1",
            "Test-EnterpriseAgentHealth.ps1",
        )
    }
    for script in operations.values():
        assert "Set-StrictMode -Version 2.0" in script
        assert "EnterpriseAgent.WindowsSafety.ps1" in script
        assert "Assert-EAPowerShell51" in script

    assert "must be supplied as an X:\\ absolute local path" in helper
    assert "DriveType -ne 3" in helper
    assert "must use an NTFS filesystem" in helper
    assert "reparse-point component" in helper
    assert "Assert-EAStateRootMarker" in helper
    assert "Assert-EAExactProperties" in helper
    assert "Instance configuration identity does not match instance.json" in helper
    assert "Windows service points outside the selected Agent instance" in helper
    assert "Get-CimInstance Win32_Process" in helper
    assert "The selected Agent instance still has running processes" in helper
    assert "(?:\\s|$)" not in helper
    assert "RNGCryptoServiceProvider" in helper
    assert '"snapshot-auth.key"' in helper
    assert "$Acl.AreAccessRulesProtected" in helper
    assert 'AllowedSids = @("S-1-5-18", "S-1-5-32-544")' in helper
    assert "HMACSHA256" in helper
    assert "Get-EASnapshotCanonicalBytes" in helper
    assert "[Array]::Sort($FileLines, [StringComparer]::Ordinal)" in helper
    assert "Test-EAFixedTimeHexEquals" in helper
    assert "Assert-EANoRestoreRecoveryBlock -Context $Context" in helper
    assert "Assert-EARestoreRecoveryBlockAcl" in helper
    assert 'return Join-Path $Context.InstanceRoot "restore-recovery-block.json"' in (
        helper
    )
    assert "blocked by an incomplete restore" in helper
    assert "manual database/quarantine recovery paths recorded" in helper

    creator = operations["New-EnterpriseAgentInstance.ps1"]
    assert ".instance-staging-" in creator
    assert "Move-Item -LiteralPath $StageRoot -Destination $InstanceRoot" in creator
    assert creator.index("Assert-EAOrdinaryTree -Root $StageRoot") < creator.index(
        "Move-Item -LiteralPath $StageRoot -Destination $InstanceRoot"
    )
    assert "unique and non-overlapping" in creator
    assert "must not overlap InstallRoot or StateRoot" in creator
    watch_acl = creator.index("# Set one inheritable read ACE")
    assert '"/T"' not in creator[watch_acl : watch_acl + 450]
    assert "Set-Acl -LiteralPath $WatchDirectory" in creator

    starter = operations["Start-EnterpriseAgent.ps1"]
    health = operations["Test-EnterpriseAgentHealth.ps1"]
    assert starter.count("Assert-EANoInstanceProcesses -Context $Context") >= 2
    assert '"--authoritative-env-file" "serve"' in starter
    assert "Assert-EAInstanceIsRunning -Context $Context" in health
    assert 'primary_contract_version -ne "five-quantity-submission-v2"' in health

    backup = operations["Backup-EnterpriseAgent.ps1"]
    restore = operations["Restore-EnterpriseAgent.ps1"]
    for script in (backup, restore):
        assert "MaximumSnapshotFiles = 10000" in script
        assert "MaximumSnapshotFileBytes = 32GB" in script
        assert "MaximumSnapshotTotalBytes = 256GB" in script
        assert "Assert-EAProtectedSnapshotAcl" in script
        assert "Get-EAServiceContext -Context $Context" in script
        assert "Assert-EANoInstanceProcesses -Context $Context" in script
        assert '"--authoritative-env-file"' in script
    assert (
        "A destination inside StateRoot must be inside this instance's backups"
        in backup
    )
    assert "Snapshot must not overlap InstallRoot" in restore
    should_process = restore.index("if ($PSCmdlet.ShouldProcess(")
    assert should_process < restore.index(
        'New-Item -ItemType Directory -Path $TransactionRoot', should_process
    )
    assert "restore-transactions" in restore
    assert "throw $OriginalError" in restore
    for token in (
        "mineguard-enterprise-agent-restore-recovery-block-v1",
        "Write-EAProtectedRestoreRecoveryBlock",
        "Get-EARestoreRecoveryBlockPath",
        "pre-restore-live-database.db",
        "failed-restored-database.db",
        "failed-restored-quarantine",
        "$DatabaseSwitchAttempted",
        "$RollbackErrors",
        "automatic rollback was incomplete",
        "MINEGUARD_INTERNAL_RESTORE_FAULT_INJECTION",
        'Invoke-EARestoreFaultInjection -Point "after-database-restore"',
        'Invoke-EARestoreFaultInjection -Point "after-acl-repair"',
        'Invoke-EARestoreFaultInjection -Point "after-rollback-publish"',
        "$Committed = $true",
    ):
        assert token in restore
    marker_publish = restore.index(
        "Write-EAProtectedRestoreRecoveryBlock -PathValue $RecoveryMarkerPath"
    )
    live_quarantine_switch = restore.index(
        "Move-Item -LiteralPath $CurrentQuarantine -Destination $OldQuarantine"
    )
    database_restore = restore.index(
        "Invoke-NativeChecked -FilePath $Context.Executable"
    )
    acl_repair = restore.index("Set-EAInstanceCanonicalAcl -Context $Context")
    rollback_publish = restore.index(
        "Move-Item -LiteralPath $TransactionRoot -Destination $RollbackRoot"
    )
    explicit_commit = restore.index("$Committed = $true")
    assert marker_publish < live_quarantine_switch < database_restore
    assert database_restore < acl_repair < rollback_publish < explicit_commit
    catch_block = restore[restore.index("    catch {", database_restore) :]
    assert "if ($DatabaseSwitchAttempted)" in catch_block
    assert "if ($OldQuarantineMoved -or $NewQuarantinePublished)" in catch_block
    assert catch_block.index("Database rollback:") < catch_block.index(
        "Recovery marker removal:"
    )
    assert "mineguard-enterprise-agent-state-snapshot-v2" in backup
    assert "hmac_key_id" in backup
    assert "Get-EASnapshotHmacSha256" in backup
    assert "SnapshotAuthenticationKeyFile" in backup
    assert (
        "Snapshot authentication key must remain outside the snapshot directory"
        in backup
    )
    assert "AllowUnauthenticatedLegacySnapshot" in restore
    assert "SnapshotAuthenticationKeyFile" in restore
    assert "must be delivered independently, outside SnapshotPath" in restore
    assert "Unauthenticated v1 snapshots are refused by default" in restore
    assert "Snapshot HMAC-SHA256 authentication failed" in restore


def test_frozen_executable_directory_is_the_first_frontend_location(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "standalone" / "MineGuardEnterpriseAgent.exe"
    web_root = executable.parent / "web"
    web_root.mkdir(parents=True)
    (web_root / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(executable))
    assert cli._default_web_root() == web_root


def test_windows_binary_build_is_standalone_source_free_and_binary_first() -> None:
    project_root = Path(__file__).resolve().parents[1]
    packaging = project_root / "packaging" / "windows"
    build = (packaging / "Build-EnterpriseAgentBinary.ps1").read_text(
        encoding="utf-8"
    )
    requirements = (packaging / "build-requirements.txt").read_text(
        encoding="utf-8"
    )
    smoke = (packaging / "Test-EnterpriseAgentBinary.ps1").read_text(
        encoding="utf-8"
    )
    assert "Nuitka==4.1.3" in requirements
    assert '"--mode=standalone"' in build
    assert '"--python-flag=isolated"' in build
    assert '"--python-flag=safe_path"' in build
    assert '"--python-flag=no_docstrings"' in build
    assert "--onefile" not in build
    assert "--output-filename=MineGuardEnterpriseAgent.exe" in build
    assert "--include-data-dir=$WebRoot=web" in build
    assert "--include-package=tzdata" in build
    assert "--include-package-data=tzdata" in build
    assert "AllowNuitkaToolDownloads" in build
    assert '"--assume-yes-for-downloads"' in build
    assert "mineguard-enterprise-agent-windows-binary-v1" in build
    assert "RequireSignedBinary" in build
    assert "Set-StrictMode -Version 2.0" in build
    assert "Assert-SafeLocalFixedPath" in build
    assert "$SigningEnabled -and -not $RequireSignedBinary" in build
    assert "$RequireSignedBinary -and $AllowNuitkaToolDownloads" in build
    assert (
        '$RequireSignedBinary -and [string]::IsNullOrWhiteSpace($Wheelhouse)'
        in build
    )
    assert "Windows PowerShell 5.1 or later is required." in build
    assert "Invoke-WindowsAuthenticodeSign.ps1" in build
    assert '"-CertificateThumbprint"' in build
    assert "authenticode_signed = $SigningVerified" in build
    assert "timestamp_verified = $TimestampVerified" in build
    assert "timestamp_url = if ($TimestampVerified)" in build
    assert "signing_certificate_thumbprint = if ($SigningVerified)" in build
    assert "Get-AuthenticodeSignature -LiteralPath $StagedExecutable" in build
    assert "TimeStamperCertificate" in build
    assert (
        "Move-Item -LiteralPath $ReleaseRoot -Destination $ReplacedReleaseRoot"
        in build
    )
    assert (
        "Move-Item -LiteralPath $ReplacedReleaseRoot -Destination $ReleaseRoot"
        in build
    )
    assert 'setuptools = $(Get-DistributionVersion' in build
    assert 'tzdata = $(Get-DistributionVersion' in build
    assert "python = $PythonPatchVersion" in build
    assert 'Extension -in @(".py", ".pyw", ".pyc"' in build
    assert '".pdb", ".ilk", ".map"' in build
    assert "/api/v1/health" in smoke
    assert "<!doctype html" in smoke
    assert "-UseNewEnvironment" not in smoke
    assert 'Name = "SystemRoot"' in smoke
    assert 'Name = "windir"' in smoke
    assert 'Name = "ComSpec"' in smoke
    assert "$EnvironmentVariablesToClear" in smoke
    assert "[EnvironmentVariableTarget]::Process" in smoke
    assert "[IO.File]::ReadAllText" in smoke
    assert "$Process.WaitForExit()" in smoke
    source_guard = build.index(
        'Assert-SafeLocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot'
    )
    source_normalization = build.index(
        "$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)"
    )
    assert source_guard < source_normalization
    artifacts_guard = build.index(
        'Assert-SafeLocalFixedPath -Name "ArtifactsRoot" -PathValue $ArtifactsRoot'
    )
    artifacts_normalization = build.index(
        "$ArtifactsRoot = [IO.Path]::GetFullPath($ArtifactsRoot)"
    )
    assert artifacts_guard < artifacts_normalization
    assert build.count(
        'Assert-SafeLocalFixedPath -Name "ArtifactsRoot"'
    ) >= 2
    assert build.count('Assert-SafeLocalFixedPath -Name "SignToolPath"') >= 2
    assert build.count('Assert-SafeLocalFixedPath -Name "Wheelhouse"') >= 2
    assert "Assert-OrdinaryDirectoryTree -Root $Wheelhouse" in build
    assert 'Assert-SafeLocalFixedPath -Name "WorkRoot"' in build
    assert 'Assert-SafeLocalFixedPath -Name "StageRoot"' in build

    deploy_root = project_root / "deploy" / "windows"
    installer = (deploy_root / "Install-EnterpriseAgent.ps1").read_text(
        encoding="utf-8"
    )
    assert 'Alias("ReleaseRoot")' in installer
    assert "Test-BinaryReleaseManifest" in installer
    assert "Get-AuthenticodeSignature" in installer
    assert "release-metadata" in installer
    assert "MineGuardEnterpriseAgent.exe" in installer
    assert "BuildFromSource" in installer
    assert "Set-StrictMode -Version 2.0" in installer
    assert "Windows PowerShell 5.1 or later is required." in installer
    assert "function Set-EACanonicalProductTreeAcl" in installer
    assert "Set-EACanonicalProductTreeAcl -Path $InstallRoot" in installer
    assert "AuditFailAfterRuntimeSwitch" in installer
    assert "installer-rollback-test" in installer
    assert "Agent downgrade from" in installer
    assert (
        "[version]$CandidateVersionText -lt [version]$ExistingVersionText"
        in installer
    )
    assert installer.count("Assert-NoEnterpriseAgentRuntimeProcesses") >= 3
    assert "Get-CimInstance Win32_Process" in installer
    assert "StartsWith($ExpectedPrefix" in installer
    assert "legacy source/venv Agent service" in installer
    assert "must be supplied as an X:\\ absolute local path" in installer
    assert "DriveType -ne 3" in installer
    assert "must use an NTFS filesystem" in installer
    assert "ReparsePoint" in installer
    assert "Read-ReleaseChecksums" in installer
    assert "does not describe the exact binary release file set" in installer
    assert "does not describe the exact active release file set" in installer
    assert "Get-RequiredBooleanProperty" in installer
    assert "Get-RequiredNullableStringProperty" in installer
    assert "timestamp_verified" in installer
    assert "timestamp_url" in installer
    assert "TimeStamperCertificate" in installer
    assert "Test-InstalledBinaryRuntime" in installer
    assert "incomplete release metadata" in installer
    assert "Active compiled Agent --version" in installer
    install_source_guard = installer.index(
        'Assert-LocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot'
    )
    install_source_normalization = installer.index(
        "$SourceRoot = ([IO.Path]::GetFullPath($SourceRoot)).TrimEnd('\\')"
    )
    assert install_source_guard < install_source_normalization
    assert ".mineguard-enterprise-agent-instances.json" in installer
    assert "mineguard-enterprise-agent-state-root-v1" in installer
    assert "Unmarked StateRoot must be empty" in installer
    assert '"instance directories:' in installer
    assert "cannot be a broad Windows/system data directory" in installer
    assert "Assert-StateRootOrdinary -Root $StateRoot" in installer
    assert "Assert-StateRootMarker -Root $StateRoot" in installer
    assert installer.count('Assert-LocalFixedPath -Name "Wheelhouse"') >= 2
    release_validation = installer.index(
        "$ReleaseContract = Test-BinaryReleaseManifest -ReleaseRoot $SourceRoot"
    )
    candidate_version_check = installer.index("$CandidateReportedVersion = (")
    first_state_claim = installer.index(
        "Initialize-EnterpriseAgentStateRoot -Root $StateRoot"
    )
    assert release_validation < candidate_version_check < first_state_claim
    runtime_move = installer.index(
        "-SourcePath $RuntimeRoot -SourceParent $InstallRoot"
    )
    assert installer.rfind(
        "Assert-NoEnterpriseAgentRuntimeProcesses", 0, runtime_move
    ) > installer.rfind("Get-Service -Name", 0, runtime_move)
    assert installer.index("if ($AuditFailAfterRuntimeSwitch) {") < installer.index(
        "if (Test-Path -LiteralPath $RollbackRuntime)"
    )
    assert installer.index(
        "Set-EACanonicalProductTreeAcl -Path $StagedMetadata"
    ) < installer.index(
        "-SourcePath $StagedMetadata -SourceParent $InstallRoot"
    )
    binary_cleanup = installer.index(
        'if (Test-Path -LiteralPath $RollbackRuntime)'
    )
    source_acl = installer.rindex("if ($BuildFromSource) {")
    assert binary_cleanup < source_acl
    operational = (
        "New-EnterpriseAgentInstance.ps1",
        "Start-EnterpriseAgent.ps1",
        "Install-EnterpriseAgentService.ps1",
        "Backup-EnterpriseAgent.ps1",
        "Restore-EnterpriseAgent.ps1",
    )
    safety_helper = (
        deploy_root / "EnterpriseAgent.WindowsSafety.ps1"
    ).read_text(encoding="utf-8")
    assert 'Join-Path $RuntimeRoot "MineGuardEnterpriseAgent.exe"' in (
        safety_helper
    )
    for name in operational:
        script = (deploy_root / name).read_text(encoding="utf-8")
        assert (
            'runtime\\MineGuardEnterpriseAgent.exe"' in script
            or "Get-EAAgentExecutable" in script
            or "Get-EAInstanceContext" in script
        )
    instance_creator = (deploy_root / "New-EnterpriseAgentInstance.ps1").read_text(
        encoding="utf-8"
    )
    assert (
        "Assert-StateRootOwnershipMarker" in instance_creator
        or "Assert-EAStateRootMarker" in instance_creator
    )
    assert ".mineguard-enterprise-agent-instances.json" in safety_helper


def test_database_backup_restore_manifest_rollback_and_instance_lock(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state" / "enterprise-agent.db"
    repository = Repository(database)
    original = repository.create_draft(
        {"draft_id": "draft-backup-001", "mine_name": "备份煤矿"},
        actor="tester",
    )

    backup = tmp_path / "backup" / "enterprise-agent.db"
    result = backup_database(database, backup)
    assert result["format"] == "enterprise-agent-sqlite-backup-v1"
    manifest_path = Path(result["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["database_file"] == backup.name
    assert len(manifest["sha256"]) == 64

    repository.create_draft(
        {"draft_id": "draft-later-002", "mine_name": "later"},
        actor="tester",
    )
    restored = restore_database(
        database,
        backup,
        rollback_directory=tmp_path / "rollback",
    )
    assert restored["rollback_backup"] is not None
    drafts = Repository(database).list_drafts(limit=20)
    assert len(drafts) == 1
    assert drafts[0]["draft_id"] == original["draft_id"]

    with (
        lock_for_database(database),
        pytest.raises(ValueError, match="已有企业 Agent"),
        lock_for_database(database),
    ):
        pass


def test_cli_restore_refuses_when_service_lock_is_held(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "state.db"
    Repository(database)
    backup = tmp_path / "backup.db"
    backup_database(database, backup)

    with lock_for_database(database):
        result = main(
            [
                "--db",
                str(database),
                "database-restore",
                "--input",
                str(backup),
                "--rollback-directory",
                str(tmp_path / "rollback"),
                "--yes-service-stopped",
            ]
        )
    assert result == 1
    assert "必须先停止服务" in capsys.readouterr().err


def test_restore_preserves_corrupt_current_database_as_raw_evidence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.db"
    Repository(database)
    backup = tmp_path / "backup.db"
    backup_database(database, backup)
    database.write_bytes(b"corrupt live database")

    restored = restore_database(
        database,
        backup,
        rollback_directory=tmp_path / "rollback",
    )
    assert restored["rollback_mode"] == "unverified_raw_corrupt_database"
    raw = Path(str(restored["rollback_backup"]))
    assert raw.read_bytes() == b"corrupt live database"
    assert Path(f"{raw}.notice.txt").is_file()
    Repository(database)
