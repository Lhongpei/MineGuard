#!/usr/bin/env python3
"""Static, cross-platform release-contract checks for Windows packaging."""

from __future__ import annotations

import hashlib
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


def job_level_env_blocks(workflow: str) -> list[str]:
    """Return complete four-space job env blocks for this repository's YAML."""

    lines = workflow.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if line != "    env:":
            continue
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            stripped = candidate.lstrip(" ")
            indentation = len(candidate) - len(stripped)
            if stripped and indentation <= 4:
                break
            if not stripped.startswith("#"):
                block.append(candidate)
        blocks.append("\n".join(block))
    return blocks


def named_step_block(workflow: str, name: str) -> tuple[str, int, int]:
    marker = f"      - name: {name}"
    start = workflow.index(marker)
    next_step = workflow.find("\n      - name:", start + len(marker))
    end = len(workflow) if next_step < 0 else next_step
    return workflow[start:end], start, end


def test_layout() -> None:
    expected = {
        ".gitattributes",
        "packaging/windows/inno/MineGuardPlatform.iss",
        "packaging/windows/inno/MineGuardEnterpriseAgent.iss",
        "packaging/windows/inno/languages/ChineseSimplified.isl",
        "packaging/windows/inno/languages/INNO-SETUP-LICENSE.txt",
        "packaging/windows/inno/languages/README.md",
        "packaging/windows/assets/RELEASE-NOTICE.txt",
        "packaging/windows/assets/Windows-binary-release-guide.html",
        "scripts/Build-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsInstallerFailurePropagation.ps1",
        "scripts/Test-WindowsAclGrantSemantics.ps1",
        "scripts/Invoke-WindowsAuthenticodeSign.ps1",
        "scripts/New-WindowsWheelhouseManifest.ps1",
        ".github/actionlint.yaml",
        ".github/workflows/workflow-lint.yml",
        ".github/workflows/windows-native.yml",
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


def test_pinned_inno_chinese_language() -> None:
    relative = "packaging/windows/inno/languages/ChineseSimplified.isl"
    body = (ROOT / relative).read_bytes()
    expected_sha256 = (
        "7d544b9bb1d142cfa11f2e5d3cc8abe2e55f8e066c5124e3772675aa236e1278"
    )
    assert hashlib.sha256(body).hexdigest() == expected_sha256, (
        "the vendored Inno Setup translation must match the reviewed is-6_7_1 bytes"
    )
    assert not body.startswith(b"\xef\xbb\xbf"), "the reviewed translation has no BOM"
    assert b"\r" not in body, "the pinned translation must retain upstream LF line endings"
    language = body.decode("utf-8")
    assert "LanguageName=简体中文" in language

    attributes = read(".gitattributes")
    assert (
        "/packaging/windows/inno/languages/ChineseSimplified.isl text eol=lf "
        "whitespace=-blank-at-eol"
        in attributes
    ), "checkout and whitespace cleanup must preserve the byte-audited translation"

    provenance = read("packaging/windows/inno/languages/README.md")
    for token in (
        "is-6_7_1",
        "Files/Languages/Unofficial/ChineseSimplified.isl",
        "d6a11c4490de07dad443ade668289fc954dfa1ed",
        expected_sha256,
        "INNO-SETUP-LICENSE.txt",
    ):
        assert token in provenance, f"Inno language provenance misses: {token}"


def test_contract_transport_vectors_keep_lf_bytes() -> None:
    attributes = {
        line.strip()
        for line in read(".gitattributes").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "/contracts/examples/*.json text eol=lf" in attributes, (
        "contract examples must keep LF bytes on Windows checkouts because "
        "transport HMAC vectors authenticate the raw file body"
    )
    for relative in (
        "contracts/examples/enterprise-submission-v1.json",
        "contracts/examples/edge-telemetry-batch-v1.json",
    ):
        body = (ROOT / relative).read_bytes()
        assert body.endswith(b"\n"), f"transport vector must end in LF: {relative}"
        assert b"\r\n" not in body, f"transport vector must not contain CRLF: {relative}"


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

    agent_smoke = read("agent/packaging/windows/Test-EnterpriseAgentBinary.ps1")
    assert "-UseNewEnvironment" not in agent_smoke
    for token in (
        '$env:PYTHONIOENCODING = "utf-8"',
        'Name = "SystemRoot"',
        'Name = "windir"',
        'Name = "ComSpec"',
        "$EnvironmentVariablesToClear",
        "[EnvironmentVariableTarget]::Process",
        "[IO.File]::ReadAllText",
        "$Process.WaitForExit()",
    ):
        assert token in agent_smoke, f"agent smoke environment guard missing: {token}"


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
            "ProductInstallFailureExitCode = 1001",
            "ProductInstallFailed := True",
            "function GetCustomSetupExitCode: Integer",
            "Result := ProductInstallFailureExitCode",
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
            'MessagesFile: "languages\\ChineseSimplified.isl"',
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
        assert "compiler:Languages\\ChineseSimplified.isl" not in script
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
        "UnsignedCompilerCacheReadyMarker",
        "UnsignedCompilerCacheReadyMarker is forbidden for signed production candidates",
        "UnsignedCompilerCacheReadyMarker must be located under the process temporary directory",
        "Both child compilers completed for source",
        "ExpectedInnoChineseLanguageSha256",
        "ActualInnoChineseLanguageSha256",
        "inno_chinese_language_sha256",
        "7d544b9bb1d142cfa11f2e5d3cc8abe2e55f8e066c5124e3772675aa236e1278",
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
    signing_values = re.search(
        r"\$SigningValues\s*=\s*(.*?)\r?\n\$SigningEnabled\s*=",
        build,
        re.DOTALL,
    )
    signing_expression = (
        re.sub(r"\s+", "", signing_values.group(1)) if signing_values else ""
    )
    assert signing_expression.startswith("@(@(") and signing_expression.endswith("})"), (
        "the optional signing-parameter pipeline must be array-wrapped so an "
        "unsigned PowerShell 5.1 build receives an empty array instead of null"
    )
    inno_version_probe = build[
        build.index("function Get-InnoCompilerVersion") : build.index(
            "function Get-SemanticVersionFromStage"
        )
    ]
    for token in (
        'AppName=MineGuard Inno Version Probe',
        '$VersionProbeSource | & $PathValue "/O-" "-" 2>&1',
        'Compiler engine version:\\s+Inno Setup\\s+',
        "$VersionProbeExitCode -ne 0",
    ):
        assert token in inno_version_probe, (
            f"Inno version detection must use the compiler engine output: {token}"
        )
    assert "$InnoVersion = Get-InnoCompilerVersion" in build
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
    platform_build = build.index('-Label "Platform standalone build"')
    agent_build = build.index('-Label "Enterprise Agent standalone build"')
    compiler_cache_marker = build.index('$MarkerText = "Both child compilers completed')
    failure_audit = build.index('-Label "Installer failure-propagation audit"')
    assert platform_build < agent_build < compiler_cache_marker < failure_audit, (
        "the unsigned cache marker must be written only after both complete child builds"
    )
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
        "function Get-InnoUninstallerResidue",
        "function Wait-InnoUninstallerSelfCleanup",
        "^unins.*\\.(?:exe|dat|msg)$",
        "uninstaller self-cleanup timed out",
        "function Remove-VerificationRootWithRetry",
        '[Guid]::TryParseExact($RelativeRoot, "N"',
        "Lifecycle cleanup timed out after $TimeoutSeconds seconds",
        "$LifecycleAuditError = $null",
        "preserving the original lifecycle audit error",
        "-----BEGIN",
        "sk-",
    ):
        assert token in audit, f"release audit contract missing: {token}"
    for token in (
        'DefaultParameterSetName = "Release"',
        'ParameterSetName = "SecretAudit"',
        "$SecretAuditRoots",
        '$SensitiveName.Equals(',
        '"allowDemoDefaultPassword"',
        "[StringComparison]::OrdinalIgnoreCase",
        "'^\\[(?i:bool)\\]\\s*\\$[A-Za-z_][A-Za-z0-9_]*$'",
        "[regex]::IsMatch(",
        'Release contains a non-placeholder value for ${SensitiveName}',
        "Windows release text safety preflight passed",
    ):
        assert token in audit, f"release secret scanner regression guard missing: {token}"
    assert '$Value.StartsWith("[")' not in audit, (
        "release secret scanning must not broadly allow arbitrary typed expressions"
    )
    lifecycle = audit[
        audit.index("function Invoke-InstallerLifecycleTest") : audit.index(
            'if ($PSCmdlet.ParameterSetName -eq "SecretAudit")'
        )
    ]
    final_uninstall = lifecycle.rindex(
        "& $Uninstallers[0].FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
    )
    uninstaller_wait = lifecycle.index(
        "Wait-InnoUninstallerSelfCleanup -Product $Product"
    )
    assert lifecycle.count("Wait-InnoUninstallerSelfCleanup -Product $Product") == 1
    assert final_uninstall < uninstaller_wait < lifecycle.index(
        "$PathsExpectedRemoved", uninstaller_wait
    ), "only the final successful uninstall may wait for Inno self-cleanup"
    assert "-InstallRoot $InstallRoot -TimeoutSeconds 60" in lifecycle
    lifecycle_finally = lifecycle[lifecycle.rindex("finally {") :]
    assert "Remove-VerificationRootWithRetry" in lifecycle_finally
    assert "-TimeoutSeconds 30" in lifecycle_finally
    assert (
        "Remove-Item -LiteralPath $FullVerificationRoot -Recurse -Force"
        not in lifecycle_finally
    ), "lifecycle cleanup must use bounded retry instead of a one-shot delete"

    platform_configuration = read(
        "platform/deploy/windows/Set-MineGuardPlatformConfiguration.ps1"
    )
    boolean_switch = re.search(
        r"(?m)^\s*allowDemoDefaultPassword\s*=\s*(.+?)\s*$",
        platform_configuration,
    )
    assert boolean_switch and re.fullmatch(
        r"\[(?i:bool)\]\s*\$[A-Za-z_][A-Za-z0-9_]*",
        boolean_switch.group(1),
    ), "the audited demo-password setting must remain a typed boolean variable"

    platform_installer = read(
        "platform/deploy/windows/Install-MineGuardPlatform.ps1"
    )
    agent_installer = read("agent/deploy/windows/Install-EnterpriseAgent.ps1")
    for name, installer, tokens in (
        (
            "platform",
            platform_installer,
            (
                "function Remove-MineGuardOwnedPathWithRetry",
                "function Move-MineGuardOwnedPathWithRetry",
                "function Assert-MineGuardBinaryInstallPathBudget",
                "MINEGUARD_RELEASE_AUDIT_MARKER=platform-post-switch",
                "$PSCmdlet.ThrowTerminatingError($transactionError)",
                "Platform 安装失败且回滚不完整",
                "隔离候选 runtime",
                "恢复原 runtime",
            ),
        ),
        (
            "agent",
            agent_installer,
            (
                "function Remove-EAOwnedPathWithRetry",
                "function Move-EAOwnedPathWithRetry",
                "function Assert-EABinaryInstallPathBudget",
                "MINEGUARD_RELEASE_AUDIT_MARKER=agent-post-switch",
                "$PSCmdlet.ThrowTerminatingError($TransactionError)",
                "installation failed and rollback was incomplete",
                "quarantine candidate runtime",
                "restore prior runtime",
            ),
        ),
    ):
        for token in tokens:
            assert token in installer, f"{name} transactional installer misses: {token}"
        assert "[ValidateRange(1, 300)]" in installer
        assert "Start-Sleep -Milliseconds 250" in installer
        assert "[ValidateRange(200, 259)]" in installer
        assert "MaximumPathLength = 240" in installer
    assert "Remove-Item -LiteralPath $runtimeTarget -Recurse -Force" not in (
        platform_installer
    ), "platform rollback must quarantine the active candidate before restoration"
    assert "Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force" not in (
        agent_installer
    ), "agent rollback must quarantine the active candidate before restoration"

    failure_probe = read("scripts/Test-WindowsInstallerFailurePropagation.ps1")
    assert "deliberately-tampered" in failure_probe
    assert "ProbeExitCode -eq 0" in failure_probe
    assert "ProbeExitCode -ne 1001" in failure_probe
    assert (
        'foreach ($ImmutableDirectory in @('
        '"runtime", "release-metadata", "deploy", "service"))'
        in failure_probe
    )
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
        "ExpectedOutputPattern",
        "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-post-switch",
        ".prior-install-identity",
        'Join-Path ([IO.Path]::GetTempPath()) "mgfp"',
        "function Remove-DirectoryWithRetry",
        "function Remove-FileWithRetry",
        "function Wait-ProcessExecutableVisible",
        "Get-CimInstance Win32_Process",
        "if ($null -eq $ExitCode)",
        "installer-guard-test",
        "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-runtime-process",
        "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-missing-metadata",
        "MINEGUARD_RELEASE_AUDIT_MARKER=platform-downgrade",
        "function Write-FailureProbeLog",
        "failure-probe Inno log (diagnostic only)",
        "function Test-IsTransientAccessDenied",
        "[ComponentModel.Win32Exception]",
        "$CurrentException.NativeErrorCode -eq 5",
        "$CurrentException.HResult -eq -2147024891",
        "function ConvertTo-WindowsCommandLineArgument",
        "function Invoke-ProcessTreeWithTransientAccessRetry",
        "Start-Process -FilePath $FilePath",
        "-ArgumentList $SerializedArguments -Wait -PassThru",
        "return [int]$Process.ExitCode",
        "$Process.Dispose()",
        "-FilePath $ProbeInstaller -ArgumentList $InstallArguments",
        "[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)",
        "Start-Sleep -Milliseconds 250",
        "Failure-probe cleanup did not finish within $TimeoutSeconds seconds",
        "$FailurePropagationCompleted = $false",
        "$FailurePropagationCompleted = $true",
        "Failure-probe cleanup also failed after the primary audit failure",
    ):
        assert token in failure_probe, f"failure audit misses: {token}"
    final_cleanup = failure_probe[failure_probe.rindex("finally {") :]
    assert "Remove-DirectoryWithRetry" in final_cleanup
    assert "-PathValue $FullProbeRoot -TimeoutSeconds 30" in final_cleanup
    assert "if ($FailurePropagationCompleted) { throw }" in final_cleanup
    assert "Write-Warning" in final_cleanup
    cleanup_try = final_cleanup.index("try {")
    cleanup_catch = final_cleanup.index("catch {")
    assert cleanup_try < final_cleanup.index(
        "Refusing unsafe failure-probe cleanup path"
    ) < final_cleanup.index("Remove-DirectoryWithRetry") < cleanup_catch, (
        "all failure-probe cleanup errors must be handled without masking the "
        "primary audit failure"
    )
    assert (
        "Remove-Item -LiteralPath $FullProbeRoot -Recurse -Force"
        not in final_cleanup
    ), "failure-probe cleanup must use bounded retry instead of a one-shot delete"
    assert "& $ProbeInstaller @InstallArguments" not in failure_probe, (
        "Inno GUI probes must use Start-Process -Wait so their child process tree exits"
    )
    process_tree_retry = failure_probe[
        failure_probe.index("function Invoke-ProcessTreeWithTransientAccessRetry") :
        failure_probe.index("function Remove-DirectoryWithRetry")
    ]
    assert process_tree_retry.index("AddSeconds($TimeoutSeconds)") < (
        process_tree_retry.index("Start-Process -FilePath $FilePath")
    ) < process_tree_retry.index("return [int]$Process.ExitCode") < (
        process_tree_retry.index("finally {")
    ) < process_tree_retry.index("$Process.Dispose()")
    assert "Start-Sleep -Milliseconds 250" in process_tree_retry

    acl_probe = read("scripts/Test-WindowsAclGrantSemantics.ps1")
    for token in (
        '"/inheritance:r", "/T", "/C"',
        '"/grant:r", "*S-1-5-18:(OI)(CI)F"',
        '"/grant:r", "*S-1-5-32-544:(OI)(CI)F"',
        '(Join-Path $ProbeRoot "*"), "/reset", "/T", "/C"',
        "function Assert-AclContract",
        "ACL is missing trustee",
        "Stale explicit ACL fixture",
        "Empty directory ACL fixture",
        "Empty-tree descendant reset",
        "MineGuard canonical NTFS ACL grant semantics passed",
    ):
        assert token in acl_probe, f"Windows ACL regression probe misses: {token}"
    for name, installer, helper in (
        ("platform", platform_installer, "Set-MineGuardDirectoryAcl"),
        ("agent", agent_installer, "Set-EACanonicalProductTreeAcl"),
    ):
        assert f"function {helper}" in installer
        assert "/reset" in installer and "/T" in installer and "/C" in installer
        assert installer.count("'/grant:r'") >= 3 or installer.count('"/grant:r"') >= 3, (
            f"{name} ACL helper must give every trustee an explicit grant switch"
        )


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


def test_powershell_interpolation_is_ps51_unambiguous() -> None:
    ambiguous_variable_before_colon = re.compile(
        r"\$(?!(?:env|script|global|local|private):)"
        r"[A-Za-z_][A-Za-z0-9_]*:",
        re.IGNORECASE,
    )
    roots = (
        ROOT / "platform/deploy/windows",
        ROOT / "platform/packaging/windows",
        ROOT / "agent/deploy/windows",
        ROOT / "agent/packaging/windows",
        ROOT / "scripts",
    )
    failures: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.ps1")):
            source = path.read_text(encoding="utf-8-sig")
            for match in ambiguous_variable_before_colon.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0)}")
    assert not failures, (
        "PowerShell 5.1 requires ${name}: when a variable is followed by a colon: "
        + ", ".join(failures)
    )


def test_psscriptroot_is_resolved_after_parameter_binding() -> None:
    roots = (
        ROOT / "platform/deploy/windows",
        ROOT / "platform/packaging/windows",
        ROOT / "agent/deploy/windows",
        ROOT / "agent/packaging/windows",
        ROOT / "scripts",
    )
    failures: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.ps1")):
            source = path.read_text(encoding="utf-8-sig")
            script_param = re.search(
                r"\A\s*(?:\[CmdletBinding[^\]]*\]\s*)?param\s*\(",
                source,
                re.IGNORECASE,
            )
            if script_param is None:
                continue
            binding_end = re.search(
                r"(?im)^\s*(?:Set-StrictMode\b|\$ErrorActionPreference\s*=)",
                source[script_param.end() :],
            )
            header_end = (
                script_param.end() + binding_end.start()
                if binding_end is not None
                else len(source)
            )
            parameter_binding_source = source[script_param.start() : header_end]
            if re.search(
                r"\$PSScriptRoot\b", parameter_binding_source, re.IGNORECASE
            ):
                failures.append(path.relative_to(ROOT).as_posix())
    assert not failures, (
        "Windows PowerShell 5.1 may leave $PSScriptRoot empty while binding "
        f"script parameter defaults; resolve it after param(): {failures}"
    )


def test_windows_python_probe_quoting() -> None:
    roots = (
        ROOT / "platform/deploy/windows",
        ROOT / "platform/packaging/windows",
        ROOT / "agent/deploy/windows",
        ROOT / "agent/packaging/windows",
        ROOT / "scripts",
    )
    probes: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.ps1")):
            source = path.read_text(encoding="utf-8-sig")
            if "json.dumps(" not in source:
                continue
            relative = path.relative_to(ROOT).as_posix()
            probes.append(relative)
            assert 'json.dumps({"' not in source, (
                f"{relative} uses double-quoted Python literals that Windows "
                "PowerShell 5.1 removes when passing a native -c argument"
            )
            assert "json.dumps({'" in source, (
                f"{relative} must keep Python -c literals with native-safe single quotes"
            )
    assert len(probes) == 3, f"review every PowerShell JSON probe: {probes}"


def test_ps51_native_argument_roundtrip_guards() -> None:
    builders = (
        read("platform/packaging/windows/Build-MineGuardPlatform.ps1"),
        read("agent/packaging/windows/Build-EnterpriseAgentBinary.ps1"),
    )
    for source in builders:
        for token in (
            "function ConvertTo-WindowsCommandLineArgument",
            "System.Text.StringBuilder",
            "System.Diagnostics.ProcessStartInfo",
            ".UseShellExecute = $false",
            ".Arguments = $",
            "WindowsCommandLineArgument -Value",
            "ConvertTo-Json",
            "json.loads(sys.argv[1])",
            "actual=sys.argv[2:]",
            "C:\\path with spaces\\",
            'embedded"quote',
            'slashes\\\\\\"quote',
        ):
            assert token in source, f"PS5.1 native argv guard missing: {token}"
        assert "@Arguments\n" not in source
        assert "@ArgumentList\n" not in source
        assert not re.search(
            r"(?m)^\s*['\"]--[^'\"]+['\"]\s*\+.*?,\s*$", source
        ), "PowerShell comma binds before +; parenthesize dynamic argv elements"

    platform_builder = builders[0]
    for token in (
        "('--output-dir='",
        "('--file-version=",
        "('--product-version=",
        "--include-package=_yaml",
        "--include-distribution-metadata=PyYAML",
        "--low-memory",
        "--jobs=1",
        "--nofollow-import-to=scipy.integrate._lebedev",
        "$nuitkaPositionalArguments.Count -ne 1",
        "Nuitka 参数数组含意外的位置参数",
    ):
        assert token in platform_builder, f"Nuitka argv structure guard missing: {token}"


def test_workflow() -> None:
    native_workflow = read(".github/workflows/windows-native.yml")
    assert "Verify elevated NTFS ACL grant semantics" in native_workflow
    assert ".\\scripts\\Test-WindowsAclGrantSemantics.ps1" in native_workflow

    workflow = read(".github/workflows/windows-release.yml")
    for token in (
        "windows-2022",
        "self-hosted, windows, x64, signing",
        "TestInstallerFailurePropagation",
        "TestInstallerLifecycle",
        "UNSIGNED-TEST-ONLY",
        "WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "WINDOWS_RELEASE_WHEELHOUSE",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
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
        "Preflight release text safety scanner",
        "-SecretAuditRoots $auditRoots",
        "hard-coded-release-secret",
        "accepted a hard-coded password fixture",
        "$ErrorActionPreference = 'Continue'",
        "non-placeholder value for ADMIN_PASSWORD",
        "negative fixture failed for an unexpected reason",
        "$global:LASTEXITCODE = 0",
        "Prepare isolated unsigned Nuitka compiler cache",
        "Restore unsigned Nuitka compiler cache",
        "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "NUITKA_CACHE_DIR_CLCACHE",
        "MINEGUARD_UNSIGNED_CLCACHE_READY_MARKER",
        "-UnsignedCompilerCacheReadyMarker",
        "Qualify complete unsigned compiler cache",
        "Save complete unsigned Nuitka compiler cache",
        "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "steps.nuitka_cache_ready.outputs.ready == 'true'",
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
    unsigned_job = workflow.split("signed-production-candidate:", 1)[0]
    assert unsigned_job.index("Validate packaging contracts statically") < (
        unsigned_job.index("Build, audit, compile, install, health-check and uninstall")
    ), "unsigned packaging checks must run before the long Nuitka build"
    cache_prepare = unsigned_job.index("Prepare isolated unsigned Nuitka compiler cache")
    cache_restore = unsigned_job.index("Restore unsigned Nuitka compiler cache")
    unsigned_build = unsigned_job.index(
        "Build, audit, compile, install, health-check and uninstall"
    )
    cache_qualify = unsigned_job.index("Qualify complete unsigned compiler cache")
    cache_save = unsigned_job.index("Save complete unsigned Nuitka compiler cache")
    upload = unsigned_job.index("Upload explicit unsigned test media")
    assert cache_prepare < cache_restore < unsigned_build < cache_qualify < cache_save < upload
    cache_prepare_block, _, _ = named_step_block(
        unsigned_job, "Prepare isolated unsigned Nuitka compiler cache"
    )
    assert "$cacheRoot = Join-Path $env:RUNNER_TEMP" in cache_prepare_block
    assert "$readyMarker = Join-Path ([IO.Path]::GetTempPath())" in cache_prepare_block, (
        "the marker must share the Windows PowerShell process temporary root"
    )
    assert "github.sha" not in unsigned_job.split(
        "Prepare isolated unsigned Nuitka compiler cache", 1
    )[1].split("Restore unsigned Nuitka compiler cache", 1)[0], (
        "the cache key must use GITHUB_SHA at runtime, not an unavailable expression context"
    )
    signed_job = workflow.split("signed-production-candidate:", 1)[1]
    assert "actions/setup-python" not in signed_job, (
        "the controlled signing runner must use its approved preinstalled python.exe"
    )
    assert signed_job.index("Get-FileHash") < signed_job.index(
        "scripts/test_windows_packaging.py"
    )
    assert signed_job.index("scripts/test_windows_packaging.py") < signed_job.index(
        "Build, sign, audit and lifecycle-test both installers"
    ), "signed packaging checks must run before the long Nuitka build"
    assert "actions/cache/" not in signed_job
    assert "NUITKA_CACHE_DIR_CLCACHE" not in signed_job
    assert "UnsignedCompilerCacheReadyMarker" not in signed_job


def test_workflow_context_availability() -> None:
    workflows = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8-sig")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    }
    illegal_job_env_runner = re.compile(
        r"\$\{\{[^}\n]*\brunner\s*(?:\.|\[)", re.IGNORECASE
    )
    for relative, workflow in workflows.items():
        assert all(
            illegal_job_env_runner.search(block) is None
            for block in job_level_env_blocks(workflow)
        ), (
            f"{relative} uses runner context in jobs.<job_id>.env"
        )

    approved_node24_actions = {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
    }
    actual_official_actions = {
        match.group(1)
        for workflow in workflows.values()
        for match in re.finditer(
            r"(?m)^\s*uses:\s*(actions/[^@\s]+@[0-9a-f]{40})\s*(?:#.*)?$",
            workflow,
        )
    }
    assert actual_official_actions == approved_node24_actions, (
        "official Actions must use the reviewed Node 24 releases pinned by full SHA; "
        f"found {sorted(actual_official_actions)}"
    )

    native = workflows[".github/workflows/windows-native.yml"]
    assert "package-manager-cache: false" in native, (
        "setup-node must not infer an implicit dependency cache from package metadata"
    )
    initializer = "Define isolated runtime paths after runner allocation"
    installer = "Install both independent products and verification tools"
    init_block, _, init_end = named_step_block(native, initializer)
    for token in (
        "$env:RUNNER_TEMP",
        "$env:GITHUB_ENV",
        "PLATFORM_VENV=",
        "PLATFORM_PYTHON=",
        "AGENT_VENV=",
        "AGENT_PYTHON=",
    ):
        assert token in init_block, f"native workflow misses runtime setup: {token}"
    assert native.index(initializer) < native.index(installer)
    for variable in (
        "PLATFORM_VENV",
        "PLATFORM_PYTHON",
        "AGENT_VENV",
        "AGENT_PYTHON",
    ):
        consumer = re.search(
            rf"\$env:{variable}\b|\$\{{\{{\s*env\.{variable}\s*\}}\}}", native
        )
        assert consumer and consumer.start() >= init_end, (
            f"native workflow consumes {variable} before initializing it"
        )

    release = workflows[".github/workflows/windows-release.yml"]
    signed_build, _, _ = named_step_block(
        release, "Build, sign, audit and lifecycle-test both installers"
    )
    output_assignment = signed_build.index(
        "WINDOWS_RELEASE_OUTPUT: ${{ runner.temp }}"
    )
    run_block = signed_build.index("        run: |")
    output_use = signed_build.index("$env:WINDOWS_RELEASE_OUTPUT")
    assert output_assignment < run_block < output_use

    lint = workflows[".github/workflows/workflow-lint.yml"]
    for token in (
        'ACTIONLINT_VERSION: "1.7.12"',
        'ACTIONLINT_ARCHIVE_SHA256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "curl --proto '=https' --tlsv1.2 --fail",
        "sha256sum --check --strict",
        '"$ACTIONLINT" -color',
        "python3 scripts/test_windows_packaging.py",
    ):
        assert token in lint, f"workflow lint supply-chain gate missing: {token}"


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
        test_pinned_inno_chinese_language,
        test_contract_transport_vectors_keep_lf_bytes,
        test_child_toolchain_pins,
        test_inno_scripts,
        test_root_build_orchestration,
        test_audit_and_lifecycle,
        test_authenticode_interface,
        test_powershell_interpolation_is_ps51_unambiguous,
        test_psscriptroot_is_resolved_after_parameter_binding,
        test_windows_python_probe_quoting,
        test_ps51_native_argument_roundtrip_guards,
        test_workflow,
        test_workflow_context_availability,
        test_disclosure_and_documentation,
    )
    for test in tests:
        test()
    print(f"Windows packaging static checks passed ({len(tests)} groups).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
