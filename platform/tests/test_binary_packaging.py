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
        "--include-package-data=tzdata",
        "--include-distribution-metadata=numpy",
        "--include-distribution-metadata=scipy",
        "--include-distribution-metadata=tzdata",
        "MineGuardPlatform-{0}-windows-x64",
        "release-manifest.json",
        "build-metadata.json",
        "SHA256SUMS.txt",
        "'runtime'",
        "'deploy\\windows'",
        "'self-check'",
        "scipy.optimize.linprog/highs",
        "sourceLeaks",
        "SignToolPath",
        "SigningCertificateThumbprint",
        "RequireSignedBinary",
        "$signingEnabled -and -not $RequireSignedBinary",
        "$RequireSignedBinary -and $AllowNuitkaToolDownloads",
        "$RequireSignedBinary -and [string]::IsNullOrWhiteSpace($Wheelhouse)",
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
    ):
        assert required in install
    assert install.index("AuditFailAfterRuntimeSwitch) {") < install.index(
        "$transactionComplete = $true"
    )
    assert install.index("$transactionComplete = $true") < install.index(
        "$runtimePrevious, $servicePrevious, $metadataPrevious"
    )
    assert install.index("Set-MineGuardDirectoryAcl -Path $InstallRoot") < install.index(
        "-SourcePath $runtimeTarget -SourceParent $InstallRoot"
    )
    assert "二进制发布包不接受 PythonExecutable 或 Wheelhouse" in install


def test_platform_configuration_enforces_a_dedicated_transactional_state() -> None:
    configure = (WINDOWS_DEPLOY / "Set-MineGuardPlatformConfiguration.ps1").read_text(
        encoding="utf-8-sig"
    )
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
    ):
        assert required in configure
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
