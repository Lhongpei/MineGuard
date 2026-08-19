from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import re
import tomllib
from xml.etree import ElementTree
from zoneinfo import ZoneInfo, reset_tzpath

import pytest

from mineguard.regulatory_v2_http import create_server


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "deploy" / "windows"
POWERSHELL_SCRIPTS = {
    "Install-MineGuardPlatform.ps1",
    "MineGuardPlatform.WindowsAcl.ps1",
    "Set-MineGuardPlatformConfiguration.ps1",
    "Start-MineGuardPlatform.ps1",
    "Start-MineGuardPlatformWizard.ps1",
    "Test-MineGuardPlatform.ps1",
    "Backup-MineGuardPlatform.ps1",
    "Restore-MineGuardPlatform.ps1",
    "Install-MineGuardPlatformService.ps1",
    "Remove-MineGuardPlatformService.ps1",
    "Uninstall-MineGuardPlatformRuntime.ps1",
    "Resolve-MineGuardPlatformExecutable.ps1",
    "Configure-MineGuardPlatformFormal.ps1",
    "Invoke-MineGuardPlatformProvisioning.ps1",
    "Start-MineGuardPlatformProvisioningWizard.ps1",
}


def _client_registry() -> dict[str, object]:
    return {
        "clients": [
            {
                "sender_id": "agent-mine-windows-001",
                "party_id": "operator-mine-windows-001",
                "mine_id": "MINE-WINDOWS-001",
                "mine_name": "沁源 Windows 一号煤矿",
                "active_message_key_id": "minewin001-msg-2026q3-a7f4",
                "message_keys": {
                    "minewin001-msg-2026q3-a7f4": (
                        "windows-message-secret-material-0000000001"
                    )
                },
                "transport_secrets": [
                    "windows-transport-secret-material-0000001"
                ],
                "comparison_context": {
                    "capacity_band": "0.9-1.2Mtpa",
                    "mining_method": "underground-longwall",
                    "shift_system": "three-shift-eight-hour",
                    "coal_type": "thermal-coal",
                    "operating_regime": "normal-production",
                },
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
        "Start-MineGuardPlatformWizard.ps1",
        "Test-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Remove-MineGuardPlatformService.ps1",
        "Configure-MineGuardPlatformFormal.ps1",
    ):
        source = (WINDOWS / name).read_text(encoding="utf-8-sig")
        assert "$PSVersionTable.PSVersion.Major -lt 5" in source, name
        assert "$PSVersionTable.PSVersion.Minor -lt 1" in source, name
        assert "Windows PowerShell 5.1" in source, name

    for name in POWERSHELL_SCRIPTS:
        source = (WINDOWS / name).read_text(encoding="utf-8-sig")
        assert "Join-Path $env:ProgramData" not in source, name

    for name in (
        "Install-MineGuardPlatform.ps1",
        "Set-MineGuardPlatformConfiguration.ps1",
        "Start-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Install-MineGuardPlatformService.ps1",
        "Remove-MineGuardPlatformService.ps1",
    ):
        source = (WINDOWS / name).read_text(encoding="utf-8-sig")
        assert "System.Environment+SpecialFolder]::CommonApplicationData" in source

    install = (WINDOWS / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "-Wheelhouse" not in install  # parameters are named without a dash
    assert "[string] $Wheelhouse" in install
    assert "--no-index" in install
    assert "Invoke-WebRequest" not in install
    assert "Start-BitsTransfer" not in install
    assert "version[1] -ne 12" in install
    acl_start = install.index("function Set-MineGuardDirectoryAcl")
    acl_end = install.index("function Test-MineGuardPlatformRuntimeProcess", acl_start)
    acl_helper = install[acl_start:acl_end]
    for token in (
        "DirectorySecurity",
        "FileSecurity",
        "SetAccessRuleProtection($true, $false)",
        "[IO.Directory]::SetAccessControl",
        "[IO.File]::SetAccessControl",
    ):
        assert token in acl_helper
    assert "icacls" not in acl_helper.lower()
    assert "'/reset'" not in acl_helper and '"/reset"' not in acl_helper
    assert install.count("'Configure-MineGuardPlatformFormal.ps1'") >= 2
    assert "Assert-InstalledServiceSecurityBoundary" in install
    assert "platformSystemId = 'mineguard-qinyuan'" in install
    assert "platformPartyId = 'regulator-qinyuan'" in install
    assert "mineguard-government" not in install
    assert "regulator-government" not in install

    provisioning_core = (
        WINDOWS / "Invoke-MineGuardPlatformProvisioning.ps1"
    ).read_text(encoding="utf-8-sig")
    provisioning_wizard = (
        WINDOWS / "Start-MineGuardPlatformProvisioningWizard.ps1"
    ).read_text(encoding="utf-8-sig")
    for required in (
        "provision', 'issuer-init'",
        "provision', 'create-pair'",
        "provision', 'import-registration'",
        "--passphrase-file",
        "--activation-code-file",
        "--expected-public-key-sha256",
        "--expected-issuer-key-id",
        "ManagedProvisioningRequired = $true",
        "Set-AdministratorOnlyAcl",
        ".provisioning-work-",
        "--enterprise-bundle-directory",
        "--platform-registration-directory",
        "--enterprise-activation-directory",
        "--platform-activation-directory",
        "企业交付目录必须且只能包含一个 .mgprov 文件",
        "enterprise_agent_bundle",
        "enterprise_package_sha256",
        "Initialize-OwnedProtectedRoot",
        ".mineguard-provisioning-root.json",
        "Assert-NoReparseTree",
        "Assert-SeparateDirectoryTrees",
        "[switch] $ManageServiceLifecycle",
        "Stop-Service -Name 'MineGuardPlatform'",
        "Start-Service -Name 'MineGuardPlatform'",
        "WaitForStatus(",
    ):
        assert required in provisioning_core
    for removed in (
        "Assert-ValidPemCertificateChain",
        "Publish-FixedAuthorityCa",
        "platform-ca.pem",
        "authority_platform_ca_file",
        "independent_handover_record",
        "enterprise-install-manifest.json",
        "AgentPublicOrigin",
    ):
        assert removed not in provisioning_core
    assert "-Passphrase $plain" not in provisioning_core
    assert "-AdminPassword $" not in provisioning_core
    for required in (
        "System.Windows.Forms",
        "1. 初始化签发密钥",
        "2. 生成企业接入包",
        "3. 完成监管端配置",
        "*.activation",
        "SPKI SHA-256",
        "-STA",
        "Verb = 'runas'",
        "Assert-AuthorityPolicyMaterial",
        "issuer_public_key_sha256",
        "contains_secrets=false",
        "ManageServiceLifecycle",
        "确认短暂停服",
        "mineguard-authority-policy-pending-v1",
        "authority-policy.pending.json",
        "New-AuthorityPolicyPending",
        "Read-AuthorityPolicyPending",
        "[IO.FileMode]::CreateNew",
        ".authority-policy.",
        "-AllowMatchingPending",
        "mineguard-authority-policy-v2",
        "企业只需选择这个 .mgprov 文件",
    ):
        assert required in provisioning_wizard
    for removed in (
        "platform_ca_sha256",
        "independent_handover_record",
        "政府 HTTPS CA",
        "AgentPublicOrigin",
    ):
        assert removed not in provisioning_wizard
    for removed_legacy_control in (
        "previous_bundle",
        "previous_activation",
        "$updateCheck",
        "PreviousRegistrationBundle",
        "PreviousRegistrationActivationFile",
    ):
        assert removed_legacy_control not in provisioning_wizard
    assert "ProfileVersion = 1" in provisioning_wizard
    assert "Set-CurrentEnterpriseIdentifiers" in provisioning_wizard
    # TableLayoutStyleCollection.Add returns its inserted index.  If that
    # value escapes a helper function, PowerShell turns the intended Control
    # result into Object[], and the next Controls.Add(...) fails at runtime.
    assert provisioning_wizard.count("[void]$table.ColumnStyles.Add(") == 3
    assert provisioning_wizard.count("[void]$Table.RowStyles.Add(") == 3
    assert "\n    $table.ColumnStyles.Add(" not in provisioning_wizard
    assert "\n    $Table.RowStyles.Add(" not in provisioning_wizard
    assert "controls_constructed = $true" in provisioning_wizard
    assert provisioning_wizard.index("$selfTestResult = [ordered]@{") < (
        provisioning_wizard.index("$form = New-Object Windows.Forms.Form")
    ) < provisioning_wizard.index(
        "$selfTestResult | ConvertTo-Json -Compress | Write-Output"
    )
    self_test = provisioning_wizard.index("if ($SelfTest)")
    elevation_check = provisioning_wizard.index(
        "$identity = [Security.Principal.WindowsIdentity]::GetCurrent()"
    )
    protected_component_check = provisioning_wizard.index(
        "# The installed service tree is intentionally unreadable",
        elevation_check,
    )
    assert self_test < elevation_check < protected_component_check
    assert "$policyWarning" not in provisioning_wizard
    assert "注意：监管固定项未能保存" not in provisioning_wizard
    pending_create = provisioning_wizard.index(
        "$pendingTransactionId = New-AuthorityPolicyPending"
    )
    pair_create = provisioning_wizard.index("$result = & $coreScript @parameters")
    policy_publish = provisioning_wizard.index(
        "Save-AuthorityPolicy -Result $result"
    )
    success_status = provisioning_wizard.index('"生成成功（{0}')
    assert pending_create < pair_create < policy_publish < success_status
    assert provisioning_core.index("企业交付目录必须且只能包含一个 .mgprov 文件") > (
        provisioning_core.index("'provision', 'create-pair'")
    )
    assert provisioning_core.index("Stop-Service -Name 'MineGuardPlatform'") < (
        provisioning_core.index("& $configurationScript @configurationArguments")
    )
    assert provisioning_core.index("& $configurationScript @configurationArguments") < (
        provisioning_core.index("Start-Service -Name 'MineGuardPlatform'")
    )
    import_mutex = provisioning_core.index(
        "Global\\MineGuardPlatform.Configuration",
        provisioning_core.index("# ImportRegistration"),
    )
    settings_snapshot = provisioning_core.index(
        "Get-Content -LiteralPath $settingsPath", import_mutex
    )
    nested_configuration = provisioning_core.index(
        "& $configurationScript @configurationArguments", settings_snapshot
    )
    mutex_release = provisioning_core.index(
        "$configurationMutex.ReleaseMutex()", nested_configuration
    )
    service_restore = provisioning_core.index(
        "Start-Service -Name 'MineGuardPlatform'", mutex_release
    )
    assert (
        import_mutex
        < settings_snapshot
        < nested_configuration
        < mutex_release
        < service_restore
    )
    assert "Set-AdministratorOnlyAcl -Path $BundleOutputDirectory -Recurse" not in (
        provisioning_core
    )
    assert "Get-SafeLocalPath -Value $InstallRoot" in provisioning_core
    assert "$box.Tag = $button" in provisioning_wizard
    assert not any(mark in provisioning_wizard for mark in "“”‘’")
    provisioning_readme = (WINDOWS / "README.md").read_text(encoding="utf-8")
    for required in (
        "authority-policy.pending.json",
        "不会显示“生成成功”",
        "profile_version=1",
        "不显示旧版升级",
        "同一个 FQDN",
        "必须且只能包含一个 `.mgprov`",
        "不需企业域名或入站 HTTPS",
    ):
        assert required in provisioning_readme
    assert "platform-ca.pem" not in provisioning_readme

    start = (WINDOWS / "Start-MineGuardPlatform.ps1").read_text(encoding="utf-8-sig")
    assert "Resolve-MineGuardPlatformExecutable" in start
    assert "'serve'" in start
    assert "$env:PYTHONUTF8 = '1'" in start
    assert "MINEGUARD_V2_CLIENTS_FILE" in start
    assert "全新状态库缺少首次管理员密码" in start
    assert (
        "'config-check', '--clients-file', $clientsFile, '--production'" in start
    )
    assert "$clientsText" not in start
    assert "Get-Content -LiteralPath $clientsFile" not in start
    assert "'--production'" in start
    assert "'--state-directory', $stateDirectory, '--production'" in start
    assert "'--auth-database', $authDatabase, '--production'" in start
    assert "-isnot [bool]" in start
    managed_probe_environment = start.index(
        "$env:MINEGUARD_PROVISIONING_MANAGED_REQUIRED = 'true'"
    )
    managed_registry_probe = start.index(
        "'config-check', '--clients-file', $clientsFile"
    )
    assert managed_probe_environment < managed_registry_probe
    bootstrap_command = start.index("'bootstrap-admin'")
    password_file_argument = start.index("'--password-file', $bootstrapSecret")
    bootstrap_file_absent = start.index(
        "if (Test-Path -LiteralPath $bootstrapSecret)", bootstrap_command
    )
    post_bootstrap_check = start.index(
        "'--auth-database', $authDatabase, '--production'",
        bootstrap_command,
    )
    long_serve_arguments = start.index("'serve'", post_bootstrap_check)
    long_serve_invocation = start.index(
        "$serverProcess = [Diagnostics.Process]::Start($startInfo)",
        long_serve_arguments,
    )
    assert (
        bootstrap_command
        < password_file_argument
        < bootstrap_file_absent
        < post_bootstrap_check
        < long_serve_arguments
        < long_serve_invocation
    )
    assert "$env:MINEGUARD_ADMIN_PASSWORD =" not in start
    assert "ReadToEnd" not in start
    assert "$password" not in start
    assert "Remove-Item -LiteralPath $bootstrapSecret -Force" not in start
    assert ".mineguard-configuration-blocked.json" in start
    assert "Assert-NoResidualConfigurationTransaction" in start
    assert "^\\.configuration-transaction\\.[A-Fa-f0-9]{32}$" in start
    assert "$inspected -gt 256" in start
    mutex_name = start.index("Global\\MineGuardPlatform.Configuration")
    mutex_wait = start.index("$configurationMutex.WaitOne", mutex_name)
    residual_check = start.index(
        "Assert-NoResidualConfigurationTransaction", mutex_wait
    )
    marker_check = start.index(
        "if (Test-Path -LiteralPath $configurationBlockMarker)", residual_check
    )
    settings_read = start.index(
        "Get-Content -LiteralPath $settingsPath", marker_check
    )
    process_start = start.index(
        "$serverProcess = [Diagnostics.Process]::Start($startInfo)", settings_read
    )
    process_wait = start.index("$serverProcess.WaitForExit()", process_start)
    mutex_release = start.index(
        "$configurationMutex.ReleaseMutex()", process_wait
    )
    assert (
        mutex_name
        < mutex_wait
        < residual_check
        < marker_check
        < settings_read
        < process_start
        < process_wait
        < mutex_release
    )
    assert "[TimeSpan]::FromSeconds(30)" in start
    assert "$configurationMutexHeld = $false" in start
    assert "Join-WindowsCommandLineArguments -Arguments $arguments" in start
    control_capture = start.index(
        "'Env:MINEGUARD_LOCAL_CONTROL_TOKEN'", settings_read
    )
    environment_clear = start.index("Get-ChildItem Env:", control_capture)
    platform_identity = start.index(
        "$env:MINEGUARD_V2_PLATFORM_SYSTEM_ID", environment_clear
    )
    token_child_injection = start.index(
        "$startInfo.EnvironmentVariables['MINEGUARD_LOCAL_CONTROL_TOKEN']",
        platform_identity,
    )
    token_process_clear = start.index(
        "$startInfo.EnvironmentVariables.Remove(", token_child_injection
    )
    assert (
        control_capture
        < environment_clear
        < platform_identity
        < token_child_injection
        < process_start
        < token_process_clear
    )
    assert "$localControlToken -cnotmatch '^[0-9a-f]{64}$'" in start
    assert "'MINEGUARD_', [StringComparison]::OrdinalIgnoreCase" in start
    for inherited_only_name in (
        "MINEGUARD_EXTERNAL_CLIENTS_JSON",
        "MINEGUARD_EDGE_CLIENTS_JSON",
        "MINEGUARD_SAFETY_WEBHOOKS_JSON",
        "MINEGUARD_MAP_GEOJSON_PATH",
    ):
        assert inherited_only_name not in start

    configure = (
        WINDOWS / "Set-MineGuardPlatformConfiguration.ps1"
    ).read_text(encoding="utf-8-sig")
    platform_acl_helper = (
        WINDOWS / "MineGuardPlatform.WindowsAcl.ps1"
    ).read_text(encoding="utf-8-sig")
    assert "Grant-BootstrapPasswordDeleteToService" in configure
    assert "MineGuardPlatform.WindowsAcl.ps1" in configure
    assert "function Set-MineGuardPlatformCanonicalTreeAcl" in platform_acl_helper
    assert "function Set-MineGuardPlatformServiceReadableFileAcl" in platform_acl_helper
    assert (
        "function Grant-MineGuardPlatformBootstrapPasswordDeleteAcl"
        in platform_acl_helper
    )
    assert "SecurityIdentifier(" in platform_acl_helper
    assert "SetAccessRuleProtection($true, $false)" in platform_acl_helper
    assert "[IO.Directory]::SetAccessControl" in platform_acl_helper
    assert "[IO.File]::SetAccessControl" in platform_acl_helper
    assert "[Security.AccessControl.FileSystemRights]::Delete" in platform_acl_helper
    assert "icacls.exe" not in platform_acl_helper.lower()
    assert "('*{0}:(R,D)' -f $ServiceSid)" not in configure
    assert "Global\\MineGuardPlatform.Configuration" in configure
    assert ".mineguard-configuration-blocked.json" in configure
    assert "rollback_incomplete" in configure
    assert "Assert-NoResidualConfigurationTransaction" in configure
    assert "^\\.configuration-transaction\\.[A-Fa-f0-9]{32}$" in configure
    assert "$inspected -gt 256" in configure
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


def test_windows_control_center_is_gui_first_and_secret_safe() -> None:
    wizard = (WINDOWS / "Start-MineGuardPlatformWizard.ps1").read_text(
        encoding="utf-8-sig"
    )
    for required in (
        "System.Windows.Forms",
        "MineGuard Platform 首次配置与启动",
        "本机展示（推荐先看）",
        "正式内网配置",
        "正式服务安装",
        "一键准备并启动展示",
        "DemoWithoutClientRegistry = $true",
        "AllowDemoDefaultPassword = $true",
        "HttpOnlyDemo = $true",
        "Test-MineGuardHealth",
        "Test-MineGuardHealthUrl",
        "Request-MineGuardGracefulShutdown",
        "New-MineGuardLocalControlToken",
        "MINEGUARD_LOCAL_CONTROL_TOKEN",
        "/_mineguard/local-control/shutdown",
        "X-MineGuard-Local-Control-Token",
        "Test-LocalPortAvailable",
        "Get-ModernBrowserPath",
        "Resolve-FormalAccessUri",
        "Read-SavedFormalAccessUrl",
        "Save-FormalAccessUrl",
        "control-center.json",
        "$parsed.AbsolutePath -ne '/'",
        "[Net.SecurityProtocolType]::Tls12",
        "$securityProtocolChanged",
        "ConfigureFirst",
        ".mineguard-platform-state.json",
        "请不要使用 Internet Explorer",
        "ClosingApproved",
        "[switch] $SelfTest",
        "mineguard-platform-control-center",
        "control-center-{0:yyyyMMdd-HHmmss}-{1}.log",
        "演示数据未达到受控样例的 10 座煤矿、26 期报送",
        "演示数据已准备完成：{0} 座煤矿、{1} 期报送",
        "@('/PID', $pidText, '/T', '/F')",
        "数据库已完成收尾，端口已经释放",
        'Lines.Enqueue("[STDOUT] "',
        'Lines.Enqueue("[STDERR] "',
        "Write-ServerCaptureLine",
        "Install-MineGuardPlatformService.ps1",
        "Configure-MineGuardPlatformFormal.ps1",
        "$parameters['ExpectedSignerThumbprint'] = $ExpectedSignerThumbprint",
        "Production = $true",
        "签名者指纹必须是从介质外审批记录取得",
        "Get-InstalledPlatformReleaseClassification",
        "unsigned-internal-release",
        "ExpectedReleaseManifestSha256",
        "AllowUnsignedInternalRelease",
        "确认 INTERNAL-UNSIGNED 风险与外部摘要",
    ):
        assert required in wizard
    assert wizard.index("Test-MineGuardHealth -Port") < wizard.index(
        "Open-LeaderPage", wizard.index("Test-MineGuardHealth -Port")
    )
    assert "-AdminPassword'," not in wizard
    assert "Start-Job" not in wizard
    assert "Stop-Process" not in wizard
    assert "foreach ($force in @($false, $true))" not in wizard
    assert "正常停止命令未成功" not in wizard
    assert 'Lines.Enqueue("[错误] "' not in wizard
    demo_worker = wizard.index("function Start-DemoConfigurationOperation")
    assert wizard.index("& $ConfigScript @parameters", demo_worker) < wizard.index(
        "'seed-v2-demo'", demo_worker
    )
    demo_seed = wizard.index("'seed-v2-demo'", demo_worker)
    assert wizard.index("$env:PYTHONUTF8 = '1'", demo_worker) < demo_seed
    assert wizard.index("$env:PYTHONIOENCODING = 'utf-8'", demo_worker) < demo_seed
    assert wizard.index("$OutputEncoding = $utf8NoBom", demo_worker) < demo_seed
    assert wizard.index("[Console]::OutputEncoding = $utf8NoBom", demo_worker) < (
        demo_seed
    )
    operation_failure = wizard.index("if ($operationFailed)", demo_seed)
    service_success = wizard.index(
        "elseif ($purpose -eq 'service-install')", operation_failure
    )
    assert "Set-BusyState -Busy $false" in wizard[
        operation_failure:service_success
    ]
    assert "详细内容已隐藏" in wizard[demo_worker:operation_failure]
    assert '演示数据生成结果无法核验：$($_.Exception.Message)' not in wizard
    assert "formalAccessUrl = $Uri.AbsoluteUri" in wizard
    assert "Test-MineGuardHealthUrl -Url $formalHealthUrl.AbsoluteUri" in wizard
    assert "Test-Path -LiteralPath $path -PathType Leaf" in wizard
    assert wizard.count("build-metadata.json") == 1
    assert "signingCertificateThumbprint" not in wizard
    assert "$AdminPassword" not in wizard
    assert "-AdminPassword" not in wizard
    assert "$passwordInput" not in wizard
    assert "$confirmInput" not in wizard
    assert "FormalConfigProcess.HasExited" in wizard
    assert "FormalConfigCapture.Lines.TryDequeue" in wizard
    assert "Stop-FormalConfigurationProcess" in wizard
    assert "疑似敏感字段标签" in wizard
    assert "$text.Length -gt 2048" in wizard
    assert "Clear-BootstrapPasswordIfPresent" not in wizard
    assert "ClearBootstrapAttempted" not in wizard
    assert "$platformSystemInput.Text = 'mineguard-qinyuan'" in wizard
    assert "$platformPartyInput.Text = 'regulator-qinyuan'" in wizard
    assert "$platformKeyInput.Text = 'regulator-key-v2'" in wizard
    assert "'-PlatformSystemId', $PlatformSystemId" in wizard
    assert "'-PlatformPartyId', $PlatformPartyId" in wizard
    assert "'-PlatformKeyId', $PlatformKeyId" in wizard

    helper = (WINDOWS / "Configure-MineGuardPlatformFormal.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[Security.SecureString]" not in wizard
    assert "New-Object Security.SecureString" in helper
    assert "-AdminPassword $script:formalPassword" in helper
    assert "passwordBox.Text" in helper
    assert "exit 3" in helper
    assert "[string] $PlatformSystemId" in helper
    assert "[string] $PlatformPartyId" in helper
    assert "[string] $PlatformKeyId" in helper
    assert "-PlatformSystemId $PlatformSystemId" in helper
    assert "-PlatformPartyId $PlatformPartyId" in helper
    assert "-PlatformKeyId $PlatformKeyId" in helper


def test_windows_runtime_uninstall_is_transactional_and_data_preserving() -> None:
    script = (WINDOWS / "Uninstall-MineGuardPlatformRuntime.ps1").read_text(
        encoding="utf-8-sig"
    )
    for required in (
        "InternalInnoUninstall",
        "TrustedScriptSha256",
        "TrustedScriptBytes",
        "$script:TrustedInMemoryInvocation",
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
    assert "exit 0" not in script
    expected_targets = ["runtime", "deploy", "service", "release-metadata", "launcher"]
    target_match = re.search(r"\$TargetNames = @\(([^)]*)\)", script)
    assert target_match is not None
    target_names = re.findall(r'"([^"]+)"', target_match.group(1))
    assert target_names == expected_targets
    quarantine_match = re.search(
        r"\$Child\.Name -notin @\((.*?)\)\)", script, re.DOTALL
    )
    assert quarantine_match is not None
    assert re.findall(r'"([^"]+)"', quarantine_match.group(1)) == expected_targets
    for preserved in ("config", "state", "backups", "logs"):
        assert preserved not in target_names
    mutex_name = script.index("Global\\MineGuardPlatform.Configuration")
    mutex_wait = script.index("$configurationMutex.WaitOne", mutex_name)
    first_boundary_check = script.index("Assert-InnoInstallBoundary", mutex_wait)
    first_move = script.index("[IO.Directory]::Move($Target.Source, $Destination)")
    mutex_release = script.rindex("$configurationMutex.ReleaseMutex()")
    assert mutex_name < mutex_wait < first_boundary_check < first_move < mutex_release
    assert "[TimeSpan]::FromSeconds(30)" in script[mutex_name:first_boundary_check]
    assert "$configurationMutex.Dispose()" in script[mutex_release:]


def test_windows_configuration_and_service_templates_fail_closed() -> None:
    xml_path = WINDOWS / "MineGuard.Platform.xml"
    xml = ElementTree.parse(xml_path).getroot()
    assert xml.findtext("id") == "MineGuardPlatform"
    assert xml.findtext("serviceaccount/username") == (
        "NT SERVICE\\MineGuardPlatform"
    )
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
    assert (
        "'config-check', '--clients-file', $sourceClientsPath, '--production'"
        in configure
    )
    assert (
        "'config-check', '--clients-file', $stagedClients, '--production'"
        in configure
    )
    assert "'config-check', '--state-directory'" in configure
    assert "function Throw-ConfigurationValidationFailure" in configure
    assert "详情：{1}" in configure
    assert "$detail.Length -gt 512" in configure
    assert "$stagedCheckText = & $runtime.filePath @checkArguments" in configure
    assert "'--auth-database', $authDatabase, '--production'" in configure
    assert "正式配置禁止使用演示默认密码 123123123" in configure
    assert "正式管理员密码至少 12 个字符" in configure
    assert "-HttpOnlyDemo 仅允许" in configure
    assert "-ClearBootstrapPassword" in configure
    assert "REPLACE(?:[_-]|\\b)" in configure
    assert "Assert-StateBoundary" in configure
    assert "Assert-NoReparseTree" in configure
    assert ".mineguard-platform-state.json" in configure
    assert ".configuration-transaction." in configure
    assert "Platform 配置失败且自动回滚不完整" in configure
    assert "Set-ConfigAcl -Path $configDirectory" in configure
    assert "Set-MineGuardPlatformCanonicalTreeAcl -Path $Path" in configure
    assert "-ServicePermission 'RX'" in configure
    assert "-ServicePermission 'M'" in configure
    assert "Grant-MineGuardPlatformBootstrapPasswordDeleteAcl -Path $Path" in configure
    assert "AuditFailAfterFirstMutation" in configure
    assert "configuration-rollback-test" in configure
    assert "[string] $PlatformSystemId = 'mineguard-qinyuan'" in configure
    assert "[string] $PlatformPartyId = 'regulator-qinyuan'" in configure
    assert "'--platform-system-id', $PlatformSystemId" in configure
    assert "'--platform-party-id', $PlatformPartyId" in configure
    assert "'--platform-key-id', $PlatformKeyId" in configure

    service_install = (WINDOWS / "Install-MineGuardPlatformService.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[ValidatePattern('^[A-Fa-f0-9]{64}$')]" in service_install
    assert "NT SERVICE\\MineGuardPlatform" in service_install
    assert "S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346" in (
        service_install
    )
    assert "'sidtype' 'MineGuardPlatform'" in service_install
    assert "'showsid' 'MineGuardPlatform'" in service_install
    assert "ServiceSidType" in service_install
    assert "MineGuardPlatform.WindowsAcl.ps1" in service_install
    assert (
        "Set-MineGuardPlatformServiceReadableFileAcl -Path $integrityPath"
        in service_install
    )
    assert "('*{0}:R' -f $ServiceSid)" not in service_install
    assert "'config-check', '--clients-file'" in service_install
    assert (
        "'config-check', '--clients-file', $configuredClientsFile, '--production'"
        in service_install
    )
    assert "'--platform-system-id', ([string]$configuration.platformSystemId)" in (
        service_install
    )
    assert "'--platform-party-id', ([string]$configuration.platformPartyId)" in (
        service_install
    )
    assert "'--platform-key-id', ([string]$configuration.platformKeyId)" in (
        service_install
    )
    assert "'config-check', '--state-directory'" in service_install
    assert "'--auth-database', $authDatabase, '--production'" in service_install
    assert "'bootstrap-admin'" in service_install
    assert "'--password-file', $bootstrapSecret" in service_install
    assert "$bootstrapText" not in service_install
    assert "$configuredClientsText" not in service_install
    assert "Get-Content -LiteralPath $configuredClientsFile" not in service_install
    assert "secureCookie" in service_install
    assert "-isnot [bool]" in service_install
    assert "winsw-integrity.json" in service_install
    assert "wrapperSha256" in service_install
    assert "wrapperConfigSha256" in service_install
    assert "[switch] $Production" in service_install
    assert "ExpectedSignerThumbprint" in service_install
    assert "[switch] $AllowUnsignedInternalRelease" in service_install
    assert "[string] $ExpectedReleaseManifestSha256 = ''" in service_install
    assert "Assert-InternalUnsignedRuntimeIntegrity" in service_install
    assert "unsigned-internal-release" in service_install
    assert "Platform 子发行清单 SHA-256 与介质外独立批准值不一致" in service_install
    assert "release-trust-anchor.json" in service_install
    assert "演示配置不得声明 -Production、内网未签名授权" in service_install
    assert "signed-production-candidate" in service_install
    assert "Get-AuthenticodeSignature" in service_install
    assert "TimeStamperCertificate" in service_install
    assert "deploy/windows/Configure-MineGuardPlatformFormal.ps1" in service_install
    service_mutex = service_install.index(
        "Global\\MineGuardPlatform.Configuration"
    )
    service_mutex_wait = service_install.index(
        "$configurationMutex.WaitOne", service_mutex
    )
    service_settings_read = service_install.index(
        "Read-JsonObject -Path $settings", service_mutex_wait
    )
    service_bootstrap = service_install.index("'bootstrap-admin'", service_settings_read)
    service_registration = service_install.index(
        "& $destination 'install'", service_bootstrap
    )
    service_mutex_release = service_install.index(
        "$configurationMutex.ReleaseMutex()", service_registration
    )
    service_start = service_install.index(
        "Start-Service -Name 'MineGuardPlatform'", service_mutex_release
    )
    assert (
        service_mutex
        < service_mutex_wait
        < service_settings_read
        < service_bootstrap
        < service_registration
        < service_mutex_release
        < service_start
    )
    assert "[TimeSpan]::FromSeconds(30)" in service_install[
        service_mutex:service_settings_read
    ]
    assert service_install.count("$configurationMutex.ReleaseMutex()") >= 2
    service_outer_finally = service_install.rindex("} finally {")
    assert service_outer_finally > service_start
    assert "$configurationMutex.Dispose()" in service_install[service_outer_finally:]

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
            "NT SERVICE\\MineGuardPlatform",
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
        "'sidtype' 'MineGuardPlatform'",
        "'showsid' 'MineGuardPlatform'",
        "Security.Principal.NTAccount",
        "ExpectedSignerThumbprint",
        "Assert-ProductionRuntimeSignature",
        "Assert-InternalUnsignedRuntimeIntegrity",
        "AllowUnsignedInternalRelease",
        "ExpectedReleaseManifestSha256",
        "unsigned-internal-release",
        "release-trust-anchor.json",
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
    assert "MineGuardPlatform.WindowsAcl.ps1" in restore
    assert (
        "Set-MineGuardPlatformCanonicalTreeAcl -Path $TargetStateDirectory"
        in restore
    )
    assert "('*{0}:(OI)(CI)M' -f $ServiceSid)" not in restore
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
    ) < restore.index(
        "Set-MineGuardPlatformCanonicalTreeAcl -Path $TargetStateDirectory"
    )

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
        "NT SERVICE\\MineGuardPlatform",
        "ExpectedSignerThumbprint",
        "Global\\MineGuardPlatform.Configuration",
        ".mineguard-configuration-blocked.json",
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
        "演示数据不能原地",
    ):
        assert required in document


def test_linux_service_template_enables_explicit_production_gate() -> None:
    service = (ROOT / "deploy" / "mineguard.service.example").read_text(
        encoding="utf-8"
    )
    assert "mineguard serve --production" in service
    assert "--secure-cookie" in service
    assert "--backup-key-file" not in service

    environment = (ROOT / "deploy" / "mineguard.env.example").read_text(
        encoding="utf-8"
    )
    assert "MINEGUARD_ADMIN_PASSWORD=" not in environment
    assert "bootstrap-admin" in environment

    handbook = (ROOT / "docs" / "内网部署与运维手册.md").read_text(
        encoding="utf-8"
    )
    assert "serve --production --host 127.0.0.1" in handbook
    assert "bootstrap-admin" in handbook
    assert "至少 12 个字符" in handbook
    assert "四类中至少包含三类" in handbook
    assert "`serve` 没有\n`--backup-key-file`" in handbook

    v2_operations = (ROOT.parent / "docs" / "V2部署与运行.md").read_text(
        encoding="utf-8"
    )
    assert "至少 8 字符的 `MINEGUARD_ADMIN_PASSWORD`" not in v2_operations
    assert "bootstrap-admin --production" in v2_operations
