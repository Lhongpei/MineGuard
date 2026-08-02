#!/usr/bin/env python3
"""Static, cross-platform release-contract checks for Windows packaging."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    path = ROOT / relative
    assert path.is_file(), f"missing packaging file: {relative}"
    return path.read_text(encoding="utf-8-sig")


def assert_pinned_requirements(relative: str) -> None:
    lines = [
        line.strip()
        for line in read(relative).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert "Nuitka==4.1.3" in lines, f"{relative} must pin Nuitka 4.1.3"
    assert all(
        re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s]+", line) for line in lines
    ), f"all build requirements must be exact pins: {relative}"


def test_layout() -> None:
    expected = {
        "packaging/windows/inno/MineGuardPlatform.iss",
        "packaging/windows/inno/MineGuardEnterpriseAgent.iss",
        "packaging/windows/assets/RELEASE-NOTICE.txt",
        "packaging/windows/assets/Windows-binary-release-guide.html",
        "scripts/Build-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsInstallerFailurePropagation.ps1",
        "scripts/Invoke-WindowsAuthenticodeSign.ps1",
        "scripts/New-WindowsWheelhouseManifest.ps1",
        ".github/workflows/windows-release.yml",
        "docs/Windows二进制发行与安装.md",
    }
    missing = [relative for relative in sorted(expected) if not (ROOT / relative).is_file()]
    assert not missing, f"missing release integration files: {missing}"
    assert not any((ROOT / "packaging/windows/entrypoints").glob("*")), (
        "root packaging must consume child staging, not duplicate entrypoints"
    )
    assert not (ROOT / "packaging/windows/requirements-build.txt").exists(), (
        "root packaging must not maintain a duplicate Nuitka environment"
    )


def test_child_toolchain_pins() -> None:
    assert_pinned_requirements("platform/packaging/windows/requirements-build.txt")
    assert_pinned_requirements("agent/packaging/windows/build-requirements.txt")
    for relative in (
        "platform/packaging/windows/Build-MineGuardPlatform.ps1",
        "agent/packaging/windows/Build-EnterpriseAgentBinary.ps1",
    ):
        builder = read(relative)
        for token in (
            "ExpectedPythonPatchVersion",
            "ExpectedPythonExecutableSha256",
            "ExpectedSignToolSha256",
            "Get-FileHash -LiteralPath $SignToolPath",
            "Get-FileHash -LiteralPath $PythonExecutable",
        ):
            assert token in builder, f"{relative} misses approved tool gate: {token}"


def test_inno_scripts() -> None:
    platform = read("packaging/windows/inno/MineGuardPlatform.iss")
    agent = read("packaging/windows/inno/MineGuardEnterpriseAgent.iss")
    app_ids = []
    for name, script, executable in (
        ("platform", platform, "MineGuardPlatform.exe"),
        ("agent", agent, "MineGuardEnterpriseAgent.exe"),
    ):
        match = re.search(r"(?m)^AppId=(.+)$", script)
        assert match, f"{name} installer lacks stable AppId"
        app_ids.append(match.group(1))
        required = (
            "ArchitecturesAllowed=x64compatible and not arm64",
            "ArchitecturesInstallIn64BitMode=x64compatible",
            "MinVersion=10.0.17763",
            "CloseApplications=no",
            "{#StageRoot}\\runtime\\*",
            "{#StageRoot}\\deploy\\windows\\*",
            "VERSION.txt",
            "build-metadata.json",
            "release-manifest.json",
            "SHA256SUMS.txt",
            executable,
            "AfterInstall: InstallProductRuntime",
            "ExecAndLogOutput",
            "ResultCode <> 0",
            "RaiseException",
            "PrepareToInstall",
            "InitializeUninstall",
            "Get-CimInstance Win32_Process",
            "ExecutablePath",
            "ExpandConstant('{app}\\runtime')",
            "$root.TrimEnd([char]92) + [char]92",
            "$candidate.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)",
            "SignedUninstaller=yes",
            "SignTool=release_signer",
            'Name: "chinesesimplified"',
            "ChineseSimplified.isl",
        )
        for token in required:
            assert token in script, f"{name} installer contract missing: {token}"
        process_guard = re.search(
            r"function HasActive.*?function PrepareToInstall", script, re.DOTALL
        )
        assert process_guard and "$_.Name -eq" not in process_guard.group(0), (
            f"{name} runtime guard must cover every executable in the runtime subtree"
        )
        assert script.index("RELEASE-NOTICE.txt") < script.index(
            "SHA256SUMS.txt\"; DestDir: \"{tmp}"
        ), f"{name} guarded product transaction must be the final [Files] action"
        assert "example.invalid" not in script
        deletion_lines = [
            line.lower()
            for line in script.splitlines()
            if line.strip().lower().startswith("type: filesandordirs")
        ]
        assert deletion_lines
        assert not any(
            re.search(r"\\(state|config|backups|logs)(?:\"|\\)", line)
            for line in deletion_lines
        ), f"{name} uninstaller must preserve operational state"
    assert len(set(app_ids)) == 2, "the two independent installers need distinct AppIds"
    assert "{app}\\service" in platform
    icons_section = platform.split("[Icons]", 1)[1].split("[Run]", 1)[0]
    assert "{app}\\deploy\\windows" not in icons_section
    assert "MineGuardEnterpriseAgent-*" in agent
    assert "Status -ne ''Stopped''" in platform
    assert "Status -ne ''Stopped''" in agent


def test_root_build_orchestration() -> None:
    build = read("scripts/Build-WindowsBinaryRelease.ps1")
    required = (
        "Build-MineGuardPlatform.ps1",
        "Build-EnterpriseAgentBinary.ps1",
        "platform-output",
        "agent-output",
        "artifact-stage",
        "Test-WindowsBinaryRelease.ps1",
        "Test-WindowsInstallerFailurePropagation.ps1",
        "UNSIGNED-TEST-ONLY",
        "signed-production-candidate",
        "unsigned-test-artifacts",
        "release-manifest.json",
        "SHA256SUMS.txt",
        "6.7.1",
        "$InnoVersion.Major -ne 6",
        "ISCC.exe was not found",
        "-RequireSignedBinary",
        "-SigningCertificateThumbprint",
        "WheelhouseManifest",
        "ExpectedWheelhouseManifestSha256",
        "ExpectedPythonPatchVersion",
        "ExpectedPythonExecutableSha256",
        "ExpectedInnoCompilerSha256",
        "ExpectedSignToolSha256",
        "Assert-ApprovedFileSha256",
        "Both child builders must use the same resolved root python.exe",
        "Signed child metadata does not match ExpectedPythonPatchVersion",
        "mineguard-wheelhouse-manifest-v1",
        "external_trust_anchor_verified",
        "python_external_anchor_verified",
        "inno_external_anchor_verified",
        "signtool_external_anchor_verified",
        "Get-SafeLocalNtfsPath",
        "Win32_LogicalDisk",
        "FileAttributes]::ReparsePoint",
        "must use a local fixed NTFS disk",
        "Assert-CleanGitSnapshot",
        "A signed child binary does not identify the clean root source revision",
        "A signed production candidate cannot allow Nuitka tool downloads",
        "Assert-PathsDoNotOverlap",
        "must not equal, contain, or be contained by one another",
        "OutputDirectory must not exist before atomic publication",
        ".incoming-",
        "[IO.Directory]::Move($PublishStage, $OutputDirectory)",
        "Copy-Item -LiteralPath $SourcePath",
        "Published artifact audit",
    )
    for token in required:
        assert token in build, f"root build contract missing: {token}"
    assert build.index("Final installer audit") < build.index("$FilesToPublish")
    assert build.index("Published artifact audit") < build.index(
        "[IO.Directory]::Move($PublishStage, $OutputDirectory)"
    )
    assert build.rfind("Assert-CleanGitSnapshot") < build.index(
        "[IO.Directory]::Move($PublishStage, $OutputDirectory)"
    )
    assert "Join-Path $OutputDirectory $FileName" not in build
    assert build.count("Assert-PathsDoNotOverlap") >= 4
    assert build.count('"-PythonExecutable", $ResolvedPythonExecutable') == 2
    assert build.count('"/DStageRoot=$StageRoot"') == 1
    lowered = build.lower()
    assert "choco " not in lowered and "winget " not in lowered
    assert "invoke-webrequest" not in lowered, "root builder must never fetch Inno Setup"


def test_audit_and_lifecycle() -> None:
    audit = read("scripts/Test-WindowsBinaryRelease.ps1")
    for extension in (
        ".py",
        ".pyw",
        ".pyc",
        ".pyi",
        ".pyx",
        ".pxd",
        ".ipynb",
        ".cc",
        ".cxx",
        ".hh",
        ".hpp",
        ".hxx",
        ".pdb",
        ".ilk",
        ".map",
        ".pfx",
        ".key",
    ):
        assert f'"{extension}"' in audit, f"root audit misses {extension}"
    for token in (
        "release-manifest.json",
        "SHA256SUMS.txt",
        "/healthz",
        "/api/v1/health",
        "Get-AuthenticodeSignature",
        "UNSIGNED-TEST-ONLY",
        "ci-state-sentinel.txt",
        "AddSeconds(30)",
        "release-metadata",
        "foreground-upgrade-rejection.log",
        "seed-v2-demo",
        '"2026-07-31"',
        "created_submission_count",
        "normal_candidate",
        "insufficient_data",
        "daily_shift_arithmetic_mismatch",
        "sustained_ratio_drift",
        "retrospective_change_point",
        "anonymous_peer",
        "runtime-smoke-",
        "AuditFailAfterFirstMutation",
        "configuration-rollback-test",
        "Platform configuration rollback changed protected content",
        ".configuration-transaction.*",
        "-----BEGIN",
        "sk-",
    ):
        assert token in audit, f"release audit contract missing: {token}"
    failure_probe = read("scripts/Test-WindowsInstallerFailurePropagation.ps1")
    assert "deliberately-tampered" in failure_probe
    assert "ProbeExitCode -eq 0" in failure_probe
    assert "left an installed runtime" in failure_probe
    for token in (
        "AuditFailAfterRuntimeSwitch",
        "installer-rollback-test",
        "Test-OneTransactionalRollbackAndDowngrade",
        "999.0.0",
        "post-switch rollback",
        "downgrade rejection",
        "prior-runtime-sentinel.txt",
        "legacy-python.exe",
        "running legacy runtime process",
        "active binary with missing release metadata",
        "Get-ProductTreeSnapshot",
        "Agent post-switch rollback",
        "Agent missing-metadata rejection",
    ):
        assert token in failure_probe, f"failure audit misses: {token}"


def test_authenticode_interface() -> None:
    signing = read("scripts/Invoke-WindowsAuthenticodeSign.ps1")
    for token in (
        "X509EnhancedKeyUsageExtension",
        "EnhancedKeyUsages",
        "1.3.6.1.5.5.7.3.3",
        '"/fd", "SHA256"',
        '"/tr"',
        '"/td", "SHA256"',
        '"/sm"',
        "TimeStamperCertificate",
        "signtool verify",
        "Get-SafeLocalNtfsPath",
        "Win32_LogicalDisk",
        "FileAttributes]::ReparsePoint",
        "$PSVersionTable.PSVersion.Minor -lt 1",
    ):
        assert token in signing, f"signing interface missing: {token}"
    assert "pfx" not in signing.lower(), "the signer must not accept PFX/password input"

    evidence = read("scripts/New-WindowsWheelhouseManifest.ps1")
    for token in (
        "Get-SafeLocalNtfsPath",
        "Win32_LogicalDisk",
        "FileAttributes]::ReparsePoint",
        "FileMode]::CreateNew",
        "[IO.File]::Move($TemporaryOutput, $OutputPath)",
        "mineguard-wheelhouse-manifest-v1",
    ):
        assert token in evidence, f"wheelhouse evidence generator missing: {token}"


def test_workflow() -> None:
    workflow = read(".github/workflows/windows-release.yml")
    for token in (
        "windows-2022",
        "self-hosted, windows, x64, signing",
        "TestInstallerFailurePropagation",
        "TestInstallerLifecycle",
        "UNSIGNED-TEST-ONLY",
        "WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "WINDOWS_RELEASE_WHEELHOUSE",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "platform/packaging/windows",
        "agent/packaging/windows",
        "WINDOWS_RELEASE_WHEELHOUSE_MANIFEST",
        "WINDOWS_RELEASE_WHEELHOUSE_MANIFEST_SHA256",
        "ExpectedWheelhouseManifestSha256",
        "needs: unsigned-test",
        "WINDOWS_RELEASE_PYTHON_EXECUTABLE",
        "WINDOWS_RELEASE_PYTHON_PATCH_VERSION",
        "WINDOWS_RELEASE_PYTHON_EXECUTABLE_SHA256",
        "WINDOWS_INNO_COMPILER_SHA256",
        "WINDOWS_SIGNTOOL_SHA256",
        "ExpectedPythonPatchVersion",
        "ExpectedPythonExecutableSha256",
        "ExpectedInnoCompilerSha256",
        "ExpectedSignToolSha256",
        "WINDOWS_RELEASE_OUTPUT",
    ):
        assert token in workflow, f"release workflow missing: {token}"
    lowered = workflow.lower()
    action_refs = re.findall(r"(?m)^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs and all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs), (
        "release workflow actions must be pinned to full commit SHAs"
    )
    assert "choco " not in lowered and "winget " not in lowered
    assert "curl " not in lowered and "invoke-webrequest" not in lowered
    assert "gh release" not in lowered and "softprops/action-gh-release" not in lowered
    signed_job = workflow.split("signed-production-candidate:", 1)[1]
    assert "actions/setup-python" not in signed_job, (
        "the controlled signing runner must use its approved preinstalled python.exe"
    )
    assert signed_job.index("Get-FileHash") < signed_job.index(
        "scripts/test_windows_packaging.py"
    )


def test_disclosure_and_documentation() -> None:
    combined = re.sub(
        r"\s+",
        " ",
        "\n".join(
            (
                read("packaging/windows/assets/RELEASE-NOTICE.txt"),
                read("docs/Windows二进制发行与安装.md"),
            )
        ).lower(),
    )
    for phrase in (
        "no mineguard backend python source",
        "html",
        "javascript",
        "powershell",
        "reverse engineer",
        "byte-for-byte",
        "nuitka builder/runtime exception",
        "inno setup commercial-use terms",
        "unsigned-test-only",
        "arm64",
    ):
        assert phrase in combined, f"release disclosure missing: {phrase}"


def main() -> int:
    tests = (
        test_layout,
        test_child_toolchain_pins,
        test_inno_scripts,
        test_root_build_orchestration,
        test_audit_and_lifecycle,
        test_authenticode_interface,
        test_workflow,
        test_disclosure_and_documentation,
    )
    for test in tests:
        test()
    print(f"Windows packaging static checks passed ({len(tests)} groups).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
