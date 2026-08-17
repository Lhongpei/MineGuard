from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

import pytest

from mineguard.resources import read_package_resource


ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "windows"
WINDOWS_DEPLOY = ROOT / "deploy" / "windows"
PLATFORM_INNO = ROOT.parent / "packaging" / "windows" / "inno" / "MineGuardPlatform.iss"


def test_resource_reader_is_cwd_independent_and_rejects_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert b"MineGuard" in read_package_resource("regulatory_web", "index.html")
    assert b"<!doctype html" in read_package_resource("web", "index.html").lower()
    assert len(read_package_resource("demo_samples", "taiyue-2026-07.et")) == 27_648
    assert (
        len(read_package_resource("demo_samples", "gengyang-2026-07.et"))
        == 27_648
    )
    with pytest.raises(ValueError):
        read_package_resource("regulatory_web", "../index.html")
    with pytest.raises(ValueError):
        read_package_resource("regulatory_web", "..\\index.html")
    with pytest.raises(ValueError):
        read_package_resource("regulatory_web", ".")
    with pytest.raises(ValueError):
        read_package_resource("regulatory_web", "..")
    with pytest.raises(ValueError):
        read_package_resource("unknown", "index.html")


def test_platform_nuitka_build_surface_has_a_pinned_traceable_contract() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version)

    requirements = (PACKAGING / "requirements-build.txt").read_text(
        encoding="utf-8"
    )
    assert "Nuitka==4.1.3" in requirements
    assert "ordered-set==4.1.0" in requirements
    assert "zstandard==0.25.0" in requirements
    assert "setuptools==83.0.0" in requirements

    entry = (PACKAGING / "MineGuardPlatform.py").read_text(encoding="utf-8")
    assert "from mineguard.product_cli import main" in entry
    assert "enterprise_agent" not in entry

    payload = (PACKAGING / "Build-MineGuardPlatform.ps1").read_bytes()
    assert payload.startswith(b"\xef\xbb\xbf")
    build = payload.decode("utf-8-sig")
    for required in (
        "--mode=standalone",
        "--deployment",
        "--msvc=latest",
        "--output-filename=MineGuardPlatform.exe",
        "mineguard/demo_samples",
        "--include-package=cryptography",
        "--include-package=cffi",
        "--include-module=_cffi_backend",
        "--include-package-data=tzdata",
        "--include-distribution-metadata=numpy",
        "--include-distribution-metadata=scipy",
        "--include-distribution-metadata=tzdata",
        "--include-distribution-metadata=cryptography",
        "--include-distribution-metadata=cffi",
        "MineGuardPlatform-{0}-windows-x64",
        "release-manifest.json",
        "build-metadata.json",
        "SHA256SUMS.txt",
        "Open-MineGuardPlatformControlCenter.ps1",
        "$desktopLauncherSource",
        "$desktopLauncherReleasePath",
        "manifest-covered original bytes",
        "'runtime'",
        "'deploy\\windows'",
        "'self-check'",
        "scipy.optimize.linprog/highs",
        "ed25519+aes-256-gcm+scrypt",
        "sourceLeaks",
        "SignToolPath",
        "SigningCertificateThumbprint",
        "RequireSignedBinary",
        "InternalUnsignedRelease",
        "unsigned-internal-release",
        "$productionCandidateBuild = $RequireSignedBinary -or $InternalUnsignedRelease",
        "RequireSignedBinary 与 InternalUnsignedRelease 不得同时使用",
        "INTERNAL-UNSIGNED",
        "$signingEnabled -and -not $RequireSignedBinary",
        "$productionCandidateBuild -and $AllowNuitkaToolDownloads",
        "$productionCandidateBuild -and [string]::IsNullOrWhiteSpace($Wheelhouse)",
        "Invoke-WindowsAuthenticodeSign.ps1",
        "sourceRevision",
        "builtUtc",
        "未签名内部测试版",
        "$PSVersionTable.PSVersion -lt [version]'5.1'",
        "必须是形如 C:\\\\path 的本机完全限定绝对路径",
        "DriveType -ne [System.IO.DriveType]::Fixed",
        "DriveFormat -ne 'NTFS'",
        "Assert-NoReparseTree -Path $SourceDirectory",
        "Assert-NoReparseTree -Path $Wheelhouse",
        "FileAttributes]::ReparsePoint",
        "-Label '发布时同级暂存目录'",
        "Test-ReleaseDirectoryIntegrity -ReleaseDirectory $publishIncoming",
        "[System.IO.Directory]::Move($releaseDirectory, $publishPrevious)",
        "[System.IO.Directory]::Move($publishIncoming, $releaseDirectory)",
        "[System.IO.Directory]::Move($publishPrevious, $releaseDirectory)",
        "SHA256SUMS.txt 文件覆盖范围不完整",
        "release-manifest.json 文件覆盖范围不完整",
        "[switch] $Force",
        "拒绝隐式覆盖",
    ):
        assert required in build
    assert build.index(
        "Test-ReleaseDirectoryIntegrity -ReleaseDirectory $publishIncoming"
    ) < build.index(
        "[System.IO.Directory]::Move($releaseDirectory, $publishPrevious)"
    ) < build.index(
        "[System.IO.Directory]::Move($publishIncoming, $releaseDirectory)"
    )
    assert "New-Item -ItemType Directory -Path $releaseDirectory" not in build
    assert "--mode=onefile" not in build
    assert "Invoke-WebRequest" not in build

    # PowerShell 5.1 Copy-Item still hits MAX_PATH. Transaction directories
    # must not repeat the long product/release name before the atomic rename.
    assert "('.in-{0}' -f $publishToken)" in build
    assert "('.prev-{0}' -f $publishToken)" in build
    assert "'.fail-{0}' -f [Guid]::NewGuid().ToString('N')" in build
    assert ".incoming.{1}" not in build


def test_unsigned_platform_setup_requires_explicit_test_authorization() -> None:
    installer = PLATFORM_INNO.read_text(encoding="utf-8")
    for required in (
        "#ifndef EnableSigning",
        "UnsignedTestPage: TInputOptionWizardPage",
        "function IsUnsignedTestMediaAuthorized(): Boolean",
        "{param:ALLOW_UNSIGNED_TEST_MEDIA|}",
        "CreateInputOptionPage",
        "I explicitly authorize this unsigned internal-test Platform installation.",
        "function NextButtonClick(CurPageID: Integer): Boolean",
        "Unsigned Platform internal-test media was not explicitly authorized",
        "Unsigned Platform test media was not explicitly authorized",
    ):
        assert required in installer

    prepare = installer[
        installer.index("function PrepareToInstall") : installer.index(
            "function GetProductTransactionId"
        )
    ]
    install = installer[
        installer.index("function InvokeProductTransactionAction") : installer.index(
            "function GetCustomSetupExitCode"
        )
    ]
    for guarded_region in (prepare, install):
        gate = guarded_region.index("#ifndef EnableSigning")
        gate_end = guarded_region.index("#endif", gate)
        authorization = guarded_region.index(
            "IsUnsignedTestMediaAuthorized()", gate
        )
        assert gate < authorization < gate_end

    assert "{param:ALLOW_UNSIGNED_TEST_MEDIA|}" not in installer[
        installer.index("[Setup]") : installer.index("[Languages]")
    ]


def test_platform_start_menu_wizards_use_the_public_uac_launcher() -> None:
    installer = PLATFORM_INNO.read_text(encoding="utf-8")
    launcher = (
        ROOT.parent
        / "packaging"
        / "windows"
        / "assets"
        / "Open-MineGuardPlatformControlCenter.ps1"
    ).read_text(encoding="utf-8-sig")
    provisioning_shortcut = next(
        line
        for line in installer.splitlines()
        if "MineGuard 企业接入包与注册向导" in line
    )

    assert "{app}\\launcher\\Open-MineGuardPlatformControlCenter.ps1" in (
        provisioning_shortcut
    )
    assert 'WorkingDir: "{app}\\launcher"' in provisioning_shortcut
    assert "-Provisioning" in provisioning_shortcut
    assert "{app}\\service\\Start-MineGuardPlatformProvisioningWizard.ps1" not in (
        provisioning_shortcut
    )
    for required in (
        "[switch] $Provisioning",
        "Start-MineGuardPlatformProvisioningWizard.ps1",
        "$modeArgument = if ($Provisioning)",
        "Verb = 'runas'",
        "$wizardPath -InstallRoot $resolvedRoot",
    ):
        assert required in launcher


def test_windows_delivery_docs_keep_setup_as_the_formal_trust_root() -> None:
    operations = (ROOT / "docs" / "Windows原生部署与运维.md").read_text(
        encoding="utf-8"
    )
    deployed_readme = (WINDOWS_DEPLOY / "README.md").read_text(
        encoding="utf-8-sig"
    )
    binary_guide = (
        ROOT.parent / "docs" / "Windows二进制发行与安装.md"
    ).read_text(encoding="utf-8")
    for document in (operations, deployed_readme, binary_guide):
        assert "正式安装的信任入口" in document
        assert "signed Setup" in document
        assert "INTERNAL-UNSIGNED" in document
        assert "staging" in document
        assert "不能认证" in document
        assert "信任根" in document

    assert "MineGuard-Platform-0.5.0-windows-x64.exe" not in binary_guide
    assert "MineGuard-EnterpriseAgent-0.2.1-windows-x64.exe" not in binary_guide
    assert "$PlatformVersion = '<platform-version>'" in binary_guide
    assert "$AgentVersion = '<agent-version>'" in binary_guide
    assert 'MineGuard-Platform-$PlatformVersion-windows-x64.exe' in binary_guide
    assert (
        'MineGuard-EnterpriseAgent-$AgentVersion-windows-x64.exe'
        in binary_guide
    )
    assert "必须与 Platform release-manifest.json 一致" in binary_guide
    assert "必须与 Agent release-manifest.json 一致" in binary_guide


def test_deployment_scripts_resolve_standalone_before_development_python() -> None:
    resolver = (
        WINDOWS_DEPLOY / "Resolve-MineGuardPlatformExecutable.ps1"
    ).read_text(encoding="utf-8-sig")
    assert resolver.index("runtimeDirectory 'MineGuardPlatform.exe'") < resolver.index(
        "Scripts\\python.exe"
    )
    assert "prefixArguments = [string[]]@()" in resolver
    assert "prefixArguments = [string[]]@('-m', 'mineguard')" in resolver

    for name in (
        "Start-MineGuardPlatform.ps1",
        "Set-MineGuardPlatformConfiguration.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Install-MineGuardPlatformService.ps1",
    ):
        script = (WINDOWS_DEPLOY / name).read_text(encoding="utf-8-sig")
        assert "Resolve-MineGuardPlatformExecutable" in script, name
        assert "'-c'" not in script, name


def test_operational_scripts_share_the_windows_path_and_state_contract() -> None:
    scripts = {
        name: (WINDOWS_DEPLOY / name).read_text(encoding="utf-8-sig")
        for name in (
            "Start-MineGuardPlatform.ps1",
            "Test-MineGuardPlatform.ps1",
            "Backup-MineGuardPlatform.ps1",
            "Restore-MineGuardPlatform.ps1",
            "Remove-MineGuardPlatformService.ps1",
        )
    }
    for name, script in scripts.items():
        assert "$PSVersionTable.PSVersion.Major -lt 5" in script, name
        assert "$PSVersionTable.PSVersion.Minor -lt 1" in script, name

    for name in (
        "Start-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
        "Remove-MineGuardPlatformService.ps1",
    ):
        script = scripts[name]
        for required in (
            "Get-SafeFixedNtfsPath",
            "^[A-Za-z]:\\\\",
            "DriveType]::Fixed",
            "DriveFormat -ne 'NTFS'",
            "FileAttributes]::ReparsePoint",
            "现有祖先目录不能包含",
        ):
            if required == "DriveFormat -ne 'NTFS'":
                assert (
                    required in script
                    or "DriveFormat.Equals('NTFS'" in script
                ), (name, required)
            elif required == "现有祖先目录不能包含":
                assert (
                    required in script
                    or "现有祖先不能包含" in script
                ), (name, required)
            else:
                assert required in script, (name, required)

    for name in (
        "Start-MineGuardPlatform.ps1",
        "Backup-MineGuardPlatform.ps1",
        "Restore-MineGuardPlatform.ps1",
    ):
        script = scripts[name]
        assert "Assert-StateBoundary" in script, name
        assert "Assert-NoReparseTree" in script, name
        assert ".mineguard-platform-state.json" in script, name

    restore = scripts["Restore-MineGuardPlatform.ps1"]
    assert "Initialize-StateOwnership" in restore
    assert "Set-MineGuardPlatformConfiguration.ps1 -StateDirectory" in restore
    assert "禁止手工编辑 settings.json" in restore


def test_binary_install_validates_then_atomically_switches_runtime() -> None:
    install = (WINDOWS_DEPLOY / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    for required in (
        "runtime\\MineGuardPlatform.exe",
        "SHA256SUMS.txt",
        "release-manifest.json",
        "Get-FileHash",
        "reparse point",
        "未列入 SHA256SUMS.txt",
        "nuitka-standalone",
        "runtime/MineGuardPlatform.exe",
        "Get-AuthenticodeSignature",
        "TimeStamperCertificate",
        "'.runtime.incoming.'",
        "'.runtime.previous.'",
        "'.service.incoming.'",
        "'.launcher.incoming.'",
        "'.launcher.previous.'",
        "'.release-metadata.incoming.'",
        "Move-MineGuardOwnedPathWithRetry",
        "-SourcePath $runtimeTarget -SourceParent $InstallRoot",
        "-SourcePath $runtimePrevious -SourceParent $InstallRoot",
        "MineGuardPlatform 服务",
        "Test-MineGuardPlatformRuntimeProcess",
        "Get-CimInstance Win32_Process",
        "runtime 目录中的全部前台进程",
        "AuditFailAfterRuntimeSwitch",
        "installer-rollback-test",
        "[version]$candidateVersionText -lt [version]$installedVersionText",
        "默认拒绝将 MineGuard Platform",
        "RequireFixedNtfs",
        "DriveType]::Fixed",
        "DriveFormat -ne 'NTFS'",
        "^[A-Za-z]:\\\\",
        "现有祖先目录不能包含",
        "Assert-NotBroadOrSystemInstallRoot",
        "安装目录不能是 ProgramData、Program Files、Public 等宽泛系统目录本身",
        "安装目录不能位于 Windows 系统目录内",
        "已安装的编译运行时但缺少 VERSION.txt",
        "已安装运行时版本与 release-metadata 不一致",
        "winsw-integrity.json",
        "wrapperSha256",
        "'.example'",
        "release-metadata",
        "未签名内部测试版",
        "deploy/windows/Open-MineGuardPlatformControlCenter.ps1",
        "Platform 子发行清单必须唯一认证桌面 launcher 原字节",
        "候选 launcher 未保持子发行清单认证的原字节",
        "切换后的公开 launcher 不是子发行清单认证的唯一原字节文件",
        "Assert-MineGuardNoReparseTree -Path $InstallRoot",
        "makes any ACL failure a",
    ):
        assert required in install
    assert install.index("AuditFailAfterRuntimeSwitch) {") < install.index(
        "$transactionComplete = $true"
    )
    assert install.index("$transactionComplete = $true") < install.index(
        "$runtimePrevious, $servicePrevious, $launcherPrevious,"
    )
    assert install.index("Set-MineGuardDirectoryAcl -Path $InstallRoot") < install.index(
        "-SourcePath $runtimeTarget -SourceParent $InstallRoot"
    )
    assert install.index(
        "Set-MineGuardDirectoryAcl -Path $InstallRoot `\n                -ServicePermission 'RX' -Recurse"
    ) < install.index(
        "-SourcePath $runtimeTarget -SourceParent $InstallRoot"
    )
    assert install.index(
        "切换后的公开 launcher 不是子发行清单认证的唯一原字节文件"
    ) < install.index("$transactionComplete = $true")
    transaction_start = install.index("if ($binaryMode) {\n    $runtimeTarget")
    transaction_end = install.index("\n} else {\n    $venvPython", transaction_start)
    binary_transaction = install[transaction_start:transaction_end]
    assert binary_transaction.count(
        "Set-MineGuardDirectoryAcl -Path $InstallRoot `\n                -ServicePermission 'RX' -Recurse"
    ) == 1
    assert "二进制发布包不接受 PythonExecutable 或 Wheelhouse" in install


def test_platform_trusted_bootstrap_transaction_preserves_existing_acls() -> None:
    install = (WINDOWS_DEPLOY / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    for required in (
        "[string] $TrustedBootstrapTransactionId = ''",
        "function Get-ValidatedTrustedBootstrapTransactionGuid",
        "^[a-f0-9]{32}$",
        "[Guid]::TryParseExact($Value, 'N', [ref]$parsed)",
        "$parsed -eq [Guid]::Empty",
        "$trustedBootstrapTransaction",
        "TrustedBootstrapTransactionId is reserved for verified binary installation.",
        "$newlyCreatedDirectories = @{}",
        "$newlyCreatedDirectories.ContainsKey(",
        "Only its fresh candidate",
        "function Assert-MineGuardExistingTreeAclSafe",
        "$trustedOwners",
        "$serviceRightsWithSynchronize",
        "$usersReadWithSynchronize",
        "向普通主体暴露访问权限",
        "AreAccessRulesProtected",
        "包含非规范拒绝规则",
        "AllowDedicatedServiceOwner",
        "$runtimeCreatedServiceOwner",
    ):
        assert required in install

    validation = install[
        install.index("function Get-ValidatedTrustedBootstrapTransactionGuid") :
        install.index("function Assert-Administrator")
    ]
    assert validation.index("^[a-f0-9]{32}$") < validation.index(
        "[Guid]::TryParseExact"
    ) < validation.index("$parsed -eq [Guid]::Empty")
    assert validation.index("Get-ValidatedTrustedBootstrapTransactionGuid `") < (
        validation.index("Resolve-Path")
    )

    source_rejection = install.index(
        "if (-not $binaryMode -and $sourceMode -and $trustedBootstrapTransaction)"
    )
    assert source_rejection < install.index("$directories = @(")
    directories = install[
        install.index("$directories = @(") :
        install.index("$newlyCreatedDirectories = @{}")
    ]
    assert "(Join-Path $InstallRoot 'docs')" in directories
    read_only_validation = install[
        install.index("if ($binaryMode -and $trustedBootstrapTransaction)") :
        install.index("$directories = @(")
    ]
    assert "-ExpectedServicePermission 'RX'" in read_only_validation
    assert read_only_validation.count("-ExpectedServicePermission 'M'") == 1
    assert "-AllowUsersReadExecute" in read_only_validation

    transaction_start = install.index("if ($binaryMode) {\n    $runtimeTarget")
    transaction_end = install.index("\n} else {\n    $venvPython", transaction_start)
    binary_transaction = install[transaction_start:transaction_end]
    root_recursive = (
        "Set-MineGuardDirectoryAcl -Path $InstallRoot `\n"
        "                -ServicePermission 'RX' -Recurse"
    )
    assert binary_transaction.count(root_recursive) == 1
    root_acl = binary_transaction.index(root_recursive)
    assert binary_transaction.rfind(
        "if (-not $trustedBootstrapTransaction)", 0, root_acl
    ) != -1

    candidate_acl_start = binary_transaction.index(
        "Set-MineGuardDirectoryAcl -Path $runtimeIncoming"
    )
    for candidate in (
        "$runtimeIncoming",
        "$serviceIncoming",
        "$metadataIncoming",
        "$launcherIncoming",
    ):
        assert (
            f"Set-MineGuardDirectoryAcl -Path {candidate}"
            in binary_transaction[candidate_acl_start:]
        )

    wrapper_business_start = binary_transaction.index(
        "        } else {\n            if ($newlyCreatedDirectories.ContainsKey(",
        candidate_acl_start,
    )
    wrapper_business_end = binary_transaction.index(
        "\n        }\n\n        $service = Get-Service",
        wrapper_business_start,
    )
    wrapper_business = binary_transaction[
        wrapper_business_start:wrapper_business_end
    ]
    assert wrapper_business.count("$newlyCreatedDirectories.ContainsKey(") == 3
    assert "Set-MineGuardDirectoryAcl -Path $InstallRoot" not in wrapper_business
    assert "Set-MineGuardDirectoryAcl -Path $configDirectory" in wrapper_business
    assert "Set-MineGuardDirectoryAcl -Path $writableDirectory" in wrapper_business
    assert "Set-MineGuardDirectoryAcl -Path $docsDirectory `" in wrapper_business
    assert "-ServicePermission 'RX' -UsersReadExecute -Recurse" in wrapper_business

    # Source/direct installs retain their original full-tree ACL path.
    source_tail = install[transaction_end:]
    assert (
        "Set-MineGuardDirectoryAcl -Path $InstallRoot `\n"
        "        -ServicePermission 'RX' -Recurse"
    ) in source_tail


def test_unsigned_internal_platform_release_is_explicit_and_fail_closed() -> None:
    build = (PACKAGING / "Build-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )
    install = (WINDOWS_DEPLOY / "Install-MineGuardPlatform.ps1").read_text(
        encoding="utf-8-sig"
    )

    for required in (
        "[switch] $InternalUnsignedRelease",
        "$productionCandidateBuild -and $AllowNuitkaToolDownloads",
        "$productionCandidateBuild -and [string]::IsNullOrWhiteSpace($Wheelhouse)",
        "$productionCandidateBuild -and\n    ($sourceRevision -eq 'unknown'",
        "elseif ($InternalUnsignedRelease)",
        "'unsigned-internal-release'",
    ):
        assert required in build
    assert build.count("'unsigned-internal-release'") >= 2
    assert "$AllowDirtySource" not in build[
        build.index("if ($productionCandidateBuild -and\n    ($sourceRevision") :
        build.index("$projectText =", build.index("if ($productionCandidateBuild"))
    ]

    for required in (
        "[switch] $AllowUnsignedInternalRelease",
        "-not $AllowUnsignedInternalRelease",
        "-AllowUnsignedInternalRelease",
        "拒绝扩大未签名授权范围",
        "后续安装正式服务必须再输入介质外独立批准的子发行清单 SHA-256",
    ):
        assert required in install


def test_platform_configuration_enforces_a_dedicated_transactional_state() -> None:
    configure = (WINDOWS_DEPLOY / "Set-MineGuardPlatformConfiguration.ps1").read_text(
        encoding="utf-8-sig"
    )
    platform_acl_helper = (
        WINDOWS_DEPLOY / "MineGuardPlatform.WindowsAcl.ps1"
    ).read_text(encoding="utf-8-sig")
    for required in (
        "Get-SafeLocalPath",
        "^[A-Za-z]:\\\\",
        "DriveType]::Fixed",
        "DriveFormat -ne 'NTFS'",
        "Assert-NoReparseTree",
        "Assert-StateBoundary",
        "不能是安装目录的祖先",
        ".mineguard-platform-state.json",
        "拒绝对宽泛目录递归授权",
        ".configuration-transaction.",
        "rollback",
        "$operation.Started",
        "$operation.HadOriginal",
        "$rollbackComplete",
        "Platform 配置失败且自动回滚不完整",
        "修改 Platform 配置或状态目录前必须停止",
        "AuditFailAfterFirstMutation",
        "configuration-rollback-test",
        "验证 clients/password/settings 配置事务回滚",
        "Throw-ConfigurationValidationFailure",
        "$detail.Length -gt 512",
        "MineGuardPlatform.WindowsAcl.ps1",
        "Set-MineGuardPlatformCanonicalTreeAcl -Path $Path",
    ):
        assert required in configure
    for required in (
        "function Set-MineGuardPlatformCanonicalTreeAcl",
        "function Set-MineGuardPlatformServiceReadableFileAcl",
        "function Grant-MineGuardPlatformBootstrapPasswordDeleteAcl",
        "SecurityIdentifier(",
        "SetAccessRuleProtection($true, $false)",
        "[IO.Directory]::SetAccessControl",
        "[IO.File]::SetAccessControl",
    ):
        assert required in platform_acl_helper
    assert "icacls.exe" not in platform_acl_helper.lower()
    assert configure.index("Assert-StateBoundary") < configure.index(
        "Set-StateAcl -Path $stateDirectory"
    )


def test_platform_service_wrapper_is_hash_pinned_across_upgrades() -> None:
    service_install = (
        WINDOWS_DEPLOY / "Install-MineGuardPlatformService.ps1"
    ).read_text(encoding="utf-8-sig")
    for required in (
        "winsw-integrity.json",
        "wrapperSha256",
        "wrapperConfigSha256",
        "Get-FileHash",
        "保护 WinSW 完整性记录失败",
    ):
        assert required in service_install


def test_pyproject_packages_all_frontend_binary_assets() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = set(project["tool"]["setuptools"]["package-data"]["mineguard"])
    assert "web/*.png" in package_data
    assert "regulatory_web/*.html" in package_data
    assert "regulatory_web/*.css" in package_data
    assert "regulatory_web/*.js" in package_data
    assert "demo_samples/*.et" in package_data


def test_clients_example_remains_json_after_release_copy() -> None:
    json.loads((WINDOWS_DEPLOY / "clients.json.example").read_text(encoding="utf-8"))


def test_installed_operations_readme_covers_the_service_handoff() -> None:
    readme = (WINDOWS_DEPLOY / "README.md").read_text(encoding="utf-8")
    for required in (
        "Windows PowerShell 5.1",
        "Set-MineGuardPlatformConfiguration.ps1",
        "Install-MineGuardPlatformService.ps1",
        "ExpectedSha256",
        "ExpectedConfigSha256",
        "Remove-MineGuardPlatformService.ps1",
        "RemoveWrapperFiles",
        "不会删除 `runtime/config/state/backups/logs`",
    ):
        assert required in readme
