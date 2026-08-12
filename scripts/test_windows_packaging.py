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
        "packaging/windows/assets/Invoke-MineGuardTrustedProductInstall.ps1",
        "packaging/windows/assets/Open-MineGuardPlatformControlCenter.ps1",
        "packaging/windows/assets/Windows-binary-release-guide.html",
        "scripts/Build-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsBinaryRelease.ps1",
        "scripts/Test-WindowsGuiProcessWait.ps1",
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


def test_inno_code_array_arguments_cannot_look_like_section_tags() -> None:
    """Inno scans a leading ``[`` as a section tag before compiling Pascal code."""
    for relative in (
        "packaging/windows/inno/MineGuardPlatform.iss",
        "packaging/windows/inno/MineGuardEnterpriseAgent.iss",
    ):
        source = read(relative)
        code_sections = re.split(r"(?m)^\[Code\]\s*$", source, maxsplit=1)
        assert len(code_sections) == 2, f"{relative} is missing its [Code] section"
        code = code_sections[1]
        ambiguous = [
            (line_number, line)
            for line_number, line in enumerate(code.splitlines(), start=1)
            if line.lstrip().startswith("[")
        ]
        assert not ambiguous, (
            f"{relative} has Pascal lines that Inno can parse as section tags: "
            f"{ambiguous}"
        )


def test_inno_transaction_ids_use_supported_strong_unique_names() -> None:
    for relative in (
        "packaging/windows/inno/MineGuardPlatform.iss",
        "packaging/windows/inno/MineGuardEnterpriseAgent.iss",
    ):
        source = read(relative)
        assert (
            "UniqueSeed := GenerateUniqueName(ExpandConstant('{tmp}'), '.tmp');"
            in source
        ), f"{relative} must derive transaction IDs from Inno's unique-name API"
        assert "GetTempFileName" not in source, (
            f"{relative} uses a .NET API that Inno Pascal does not expose"
        )
        assert "DeleteFile(UniqueSeed)" not in source, (
            f"{relative} must not delete a non-created GenerateUniqueName result"
        )


def test_powershell_text_encoding_is_safe_for_windows_powershell_51() -> None:
    roots = (
        ROOT / "platform/deploy/windows",
        ROOT / "platform/packaging/windows",
        ROOT / "agent/deploy/windows",
        ROOT / "agent/packaging/windows",
        ROOT / "packaging/windows/assets",
        ROOT / "scripts",
    )
    failures: list[str] = []
    typographic_quote_failures: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.ps1")):
            payload = path.read_bytes()
            has_utf8_bom = payload.startswith(b"\xef\xbb\xbf")
            content = payload[3:] if has_utf8_bom else payload
            text = content.decode("utf-8")
            if any(byte > 0x7F for byte in content) and not has_utf8_bom:
                failures.append(path.relative_to(ROOT).as_posix())
            if any(quote in text for quote in "“”‘’"):
                typographic_quote_failures.append(path.relative_to(ROOT).as_posix())
    assert not failures, (
        "PowerShell scripts containing non-ASCII text require a UTF-8 BOM "
        f"for Windows PowerShell 5.1: {failures}"
    )
    assert not typographic_quote_failures, (
        "PowerShell 5.1 treats typographic quotes as string delimiters; "
        f"use ASCII quotes or Chinese brackets instead: {typographic_quote_failures}"
    )
    launcher = ROOT / (
        "packaging/windows/assets/Open-MineGuardPlatformControlCenter.ps1"
    )
    assert launcher.read_bytes().startswith(b"\xef\xbb\xbf")


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
    launcher = read(
        "packaging/windows/assets/Open-MineGuardPlatformControlCenter.ps1"
    )
    for token in (
        "Verb = 'runas'",
        "Start-MineGuardPlatformWizard.ps1",
        "[Parameter(Mandatory = $true)]",
        "-InstallRoot",
        "-STA",
        "[switch] $Elevated",
        "WindowsBuiltInRole]::Administrator",
    ):
        assert token in launcher
    for forbidden in (
        "clients.json",
        "settings.json",
        "123123123",
        "MINEGUARD_ADMIN_PASSWORD",
    ):
        assert forbidden not in launcher
    assert '#define ApplicationId "{{8B391CBD-E234-46D7-9946-E9D37F2649C1}"' in (
        platform
    ), "the production Platform AppId default must remain stable"
    assert "AppId={#ApplicationId}" in platform
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
            '#define MinimumWindowsVersion "10.0.17763"',
            "MinVersion={#MinimumWindowsVersion}",
            "CloseApplications=no",
            "SetupMutex=MineGuard-Setup-Transaction-v1,Global\\MineGuard-Setup-Transaction-v1",
            "CheckForMutexes(ProductTransactionMutexes)",
            "CreateMutex(ProductTransactionLocalMutex)",
            "CreateMutex(ProductTransactionGlobalMutex)",
            "{#StageRoot}\\*",
            "dontcopy noencryption",
            executable,
            "ExtractTemporaryFiles",
            "if CurStep = ssInstall",
            "else if CurStep = ssPostInstall",
            "RequireProductTransactionAction('Begin')",
            "RequireProductTransactionAction('Prepare')",
            "RequireProductTransactionAction('Commit')",
            "InvokeProductTransactionAction('Finalize'",
            "InvokeProductTransactionAction('Rollback'",
            "procedure DeinitializeSetup()",
            "WrapperTransactionSucceeded",
            "ReleaseAuthorizationCaptured",
            "function IsWrapperTransactionConfirmed(): Boolean",
            "WrapperTransactionSucceeded and (not ProductInstallFailed)",
            "CaptureWrapperOriginalState",
            "CleanupWrapperCreatedEmptyInstallChain",
            "WrapperOriginalInstallRoot",
            "The install directory changed after its original state was captured",
            "FailureAfterWrapperPersistenceProbe",
            "Release audit fault injection after wrapper persistence",
            "ExecAndLogOutput",
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
        files_section = script.split("[Files]", 1)[1].split("[Icons]", 1)[0]
        assert files_section.index("Invoke-MineGuardTrustedProductInstall.ps1") < (
            files_section.index("uninstall-tools")
        ), f"{name} temporary transaction media must precede persistent files"
        assert "AfterInstall: InstallProductRuntime" not in files_section
        assert "AllowPostFilesFailureProbe" not in script
        run_section = script.split("[Run]", 1)[1].split("[UninstallDelete]", 1)[0]
        run_entries = [
            line for line in run_section.splitlines() if line.startswith("Filename:")
        ]
        assert run_entries and all(
            "Check: IsWrapperTransactionConfirmed" in line for line in run_entries
        ), f"{name} postinstall launch must wait for durable wrapper confirmation"
        stage_line = next(
            line for line in files_section.splitlines() if "{#StageRoot}\\*" in line
        )
        assert "dontcopy" in stage_line and "noencryption" in stage_line
        release_leaf = (
            "MineGuardPlatformRelease"
            if name == "platform"
            else "MineGuardEnterpriseAgentRelease"
        )
        assert "AddBackslash(ExpandConstant('{tmp}')) +" in script
        assert f"'{{tmp}}\\{release_leaf}'" in script
        assert f"Result := ExpandConstant('{{tmp}}\\{release_leaf}')" not in script
        assert "example.invalid" not in script
        assert "compiler:Languages\\ChineseSimplified.isl" not in script
        icons = script.split("[Icons]", 1)[1].split("[Run]", 1)[0]
        assert "{group}" not in icons, (
            f"{name} start-menu paths must not be mutable through /GROUP or "
            "a previous installation"
        )
        expected_shortcut_count = 3 if name == "platform" else 4
        assert icons.count('Name: "{commonprograms}\\MineGuard\\') == (
            expected_shortcut_count
        ), f"{name} start-menu shortcuts must use the fixed audited group"
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
    for token in (
        "MineGuard Platform 控制中心",
        "Open-MineGuardPlatformControlCenter.ps1",
        'Name: "{app}\\launcher"; Permissions: users-readexec',
        'Name: "{app}\\docs"; Permissions: users-readexec',
        "Start-MineGuardPlatformWizard.ps1",
        "-InstallRoot \"\"{app}\"\"",
        "-STA",
        'Name: "desktopicon"',
        "{commondesktop}\\MineGuard Platform 控制中心",
        'IconFilename: "{app}\\runtime\\MineGuardPlatform.exe"',
    ):
        assert token in platform
    assert "MineGuard Platform 高级运维" not in icons_section
    launcher_copy = platform.index("Open-MineGuardPlatformControlCenter.ps1")
    temporary_transaction = platform.index('{#StageRoot}\\*"; DestDir: "{tmp}')
    assert temporary_transaction < launcher_copy
    assert "MineGuardEnterpriseAgent-*" in agent
    assert "Status -ne ''Stopped''" in platform
    assert "Status -ne ''Stopped''" in agent
    for name, script in (("platform", platform), ("agent", agent)):
        for token in (
            "#ifdef InternalUnsignedRelease",
            "EnableSigning and InternalUnsignedRelease are mutually exclusive",
            "TryAuthorizeUnsignedInternalRelease",
            "ALLOWUNSIGNEDINTERNALRELEASE",
            "EXPECTEDINSTALLERSHA256",
            "GetSHA256OfFile(ExpandConstant('{srcexe}'))",
            "INTERNAL-UNSIGNED",
            "来自当前安装介质之外的独立渠道",
            "-AllowUnsignedInternalRelease",
            "ChildReleaseManifestSha256",
            "-ExpectedReleaseManifestSha256",
        ):
            assert token in script, (
                f"{name} internal-unsigned release gate missing: {token}"
            )
        prepare = script[
            script.index("function PrepareToInstall") : script.index(
                "function GetProductTransactionId"
            )
        ]
        invoke = script[
            script.index("function InvokeProductTransactionAction") : script.index(
                "procedure RequireProductTransactionAction"
            )
        ]
        deinitialize = script[
            script.index("procedure DeinitializeSetup") : script.index(
                "function GetCustomSetupExitCode"
            )
        ]
        assert "CaptureWrapperOriginalState();" in prepare
        assert "if not ReleaseAuthorizationCaptured then" in prepare
        assert "TryAuthorizeUnsignedInternalRelease" not in invoke, (
            f"{name} rollback/finalize must not re-read the source Setup"
        )
        assert "The locked INTERNAL-UNSIGNED authorization is unavailable" in invoke
        assert "CleanupWrapperCreatedEmptyInstallChain();" in deinitialize
        capture_start = script.index("procedure CaptureWrapperOriginalState")
        capture = script[capture_start : script.index("function HasActive", capture_start)]
        assert "WrapperOriginalInstallRoot := ExpandConstant('{app}')" in capture
        assert capture.count("Cursor := WrapperOriginalInstallRoot") == 2
        for token in (
            "TrustedBootstrapSha256",
            "Invoke-MineGuardTrustedProductInstall.ps1",
            "GetSHA256OfFile(BootstrapPath)",
            "[IO.File]::ReadAllBytes($p)",
            "$sha.ComputeHash($bytes)",
            "[System.Text.UTF8Encoding]::new($false,$true)",
            "[ScriptBlock]::Create($text)",
            "Trusted bootstrap changed after Setup verification",
            "TrustedScriptSha256",
            "TrustedScriptBytes",
            "ChildReleaseManifestSha256",
        ):
            assert token in script, f"{name} trusted bootstrap gate missing: {token}"
        assert not re.search(
            r'-File\s+"\{tmp\}\\MineGuard(?:Platform|EnterpriseAgent)Release'
            r'\\deploy\\windows\\Install-[^"]+\.ps1"',
            script,
            re.IGNORECASE,
        ), f"{name} must not directly execute a mutable {{tmp}} product installer"
        preflight_name = (
            "PreflightMineGuardPlatformInstallRoot"
            if name == "platform"
            else "PreflightEnterpriseAgentInstallRoot"
        )
        preflight_start = script.index(f"function {preflight_name}")
        prepare_start = script.index("function PrepareToInstall", preflight_start)
        preflight = script[preflight_start:prepare_start]
        for token in (
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command",
            "Assert-Ancestors $target",
            "Assert-AncestorSecurity $target",
            "[IO.FileAttributes]::ReparsePoint",
            "Assert-ExistingProduct $target",
            "Assert-CanonicalRoot $target",
            "Assert-CodeSecurity $target",
            "release-metadata",
            "Get-Sha256 $exe",
            "[IO.Directory]::CreateDirectory($target,$acl)",
            "$acl.SetAccessRuleProtection($true,$false)",
            "DeleteSubdirectoriesAndFiles",
            "Ordinary principal has write/delete control",
            "unins*.exe",
            "unins*.dat",
        ):
            assert token in preflight, (
                f"{name} install-root preflight misses security token: {token}"
            )
        assert " -File " not in preflight, (
            f"{name} install-root preflight must execute only embedded code"
        )
        assert "SetAccessControl($target,$acl)" not in preflight, (
            f"{name} must reject an unsafe existing root instead of repairing it"
        )
        trusted_start = preflight.index("$trusted=@{")
        trusted_end = preflight.index("$danger=", trusted_start)
        trusted_write_exemptions = preflight[trusted_start:trusted_end]
        assert "S-1-5-32-544" in trusted_write_exemptions
        assert "S-1-5-18" in trusted_write_exemptions
        assert (
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            in trusted_write_exemptions
        ), f"{name} must accept Windows TrustedInstaller ownership"
        for untrusted_service_sid in (
            "S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346",
            "S-1-5-80-0",
        ):
            assert untrusted_service_sid not in trusted_write_exemptions, (
                f"{name} product service identities may have RX but never a "
                "write/delete exemption"
            )
        assert "$trusted[$identity.User.Value]=$true" in trusted_write_exemptions
        create_index = preflight.index(
            "[IO.Directory]::CreateDirectory($target,$acl)"
        )
        assert preflight.find(
            "Assert-AncestorSecurity $target", create_index
        ) > create_index, (
            f"{name} must revalidate every newly created/raced parent after atomic creation"
        )
        prepare_end = script.index("function GetProductTransactionId", prepare_start)
        prepare = script[prepare_start:prepare_end]
        authorization_index = min(
            index
            for token in (
                "TryAuthorizeUnsignedInternalRelease",
                "TryResolveApprovedSigner",
                "IsUnsignedTestMediaAuthorized",
            )
            if (index := prepare.find(token)) >= 0
        )
        service_index = prepare.index("HasRunning")
        process_index = prepare.index("HasActive")
        preflight_call_index = prepare.index(preflight_name + "(PreflightError)")
        assert authorization_index < service_index < process_index < preflight_call_index
        assert prepare[:service_index].count("if Result <> '' then") >= 1
        assert prepare[process_index:preflight_call_index].count(
            "if Result <> '' then"
        ) >= 1, (
            f"{name} preflight must not mutate the target before all guards pass"
        )
        assert "-File \"' +\n    BootstrapPath" not in script
        assert not re.search(
            r'-File\s+"\{app\}\\uninstall-tools\\Uninstall-[^"]+\.ps1"',
            script,
            re.IGNORECASE,
        ), f"{name} uninstaller must execute only manifest-authenticated bytes"
    for token in (
        "CreateInputOptionPage",
        "ALLOW_UNSIGNED_TEST_MEDIA",
        "IsUnsignedTestMediaAuthorized",
        "Unsigned Platform internal-test media",
        "#ifndef EnableSigning",
    ):
        assert token in platform, f"Platform unsigned-media gate missing: {token}"
    for token in (
        "CreateInputQueryPage",
        "CreateInputFilePage",
        "APPROVED_SIGNER_THUMBPRINT",
        "ALLOW_UNSIGNED_TEST_MEDIA",
        "NormalizeSignerThumbprint",
        "Length(Normalized) = 40",
        "TryResolveApprovedSigner",
        "NextButtonClick",
        "PrepareToInstall",
        "independently delivered offline approval material",
        "-ApprovedSignerThumbprint",
        "-AllowUnsignedTestMedia",
    ):
        assert token in agent, f"Agent independent signer gate missing: {token}"
    assert "SignerCertificate.Thumbprint" not in agent, (
        "the GUI must not derive its trust pin from the bundled executable"
    )
    assert "signing_certificate_thumbprint" not in agent, (
        "the GUI must not derive its trust pin from bundled metadata"
    )
    install_command = agent[
        agent.index("function InvokeProductTransactionAction") : agent.index(
            "function GetCustomSetupExitCode"
        )
    ]
    signed_gate = install_command.index("#ifdef EnableSigning")
    unsigned_gate = install_command.index("#else", signed_gate)
    gate_end = install_command.index("#endif", unsigned_gate)
    assert "-ApprovedSignerThumbprint" in install_command[
        signed_gate:unsigned_gate
    ]
    assert "-AllowUnsignedTestMedia" not in install_command[
        signed_gate:unsigned_gate
    ]
    assert "-AllowUnsignedTestMedia" in install_command[unsigned_gate:gate_end]
    assert "SignerInputPage.Values[0]" not in install_command
    assert "SignerFilePage.Values[0]" not in install_command


def test_trusted_product_install_bootstrap() -> None:
    relative = "packaging/windows/assets/Invoke-MineGuardTrustedProductInstall.ps1"
    path = ROOT / relative
    bootstrap = read(relative)
    build = read("scripts/Build-WindowsBinaryRelease.ps1")

    for token in (
        "Set-StrictMode -Version 2.0",
        "Windows PowerShell 5.1 or later is required",
        "Assert-Administrator",
        "Get-SafeLocalNtfsPath",
        "DriveType -ne [IO.DriveType]::Fixed",
        "DriveFormat.Equals('NTFS'",
        "Assert-NoReparseTree",
        "SetAccessRuleProtection($true, $false)",
        "S-1-5-32-544",
        "S-1-5-18",
        "[Environment+SpecialFolder]::Windows",
        "[IO.Directory]::CreateDirectory($candidate, $acl)",
        "mineguard-platform-",
        "Assert-ProtectedDirectoryAcl",
        "Protected staging ACL is missing a required principal",
        "[Guid]::NewGuid().ToString('N')",
        "ExpectedReleaseManifestSha256",
        "The staged child release-manifest does not match the trusted Setup anchor",
        "release-manifest.json does not cover the exact staged file set",
        "SHA256SUMS.txt does not cover the exact staged file set",
        "Get-FileHash",
        "Install-MineGuardPlatform.ps1",
        "Install-EnterpriseAgent.ps1",
        "Remove-ProtectedStagingDirectory",
        "Trusted installer staging cleanup did not complete",
        "finally",
        "[ValidateSet('Install', 'Begin', 'Prepare', 'Commit', 'Rollback', 'Finalize')]",
        "product_committed_unconfirmed",
        "wrapper_succeeded",
        "function Recover-StaleTransactions",
        "function Restore-ManagedArtifacts",
        "function Capture-ArpRegistration",
        "function Restore-ArpRegistration",
        "RegistryView]::Registry64",
        "8B391CBD-E234-46D7-9946-E9D37F2649C1",
        "9B73DE95-6B38-4482-A8BC-2A4FC656D05A",
        "CommonPrograms",
        "CommonDesktopDirectory",
        "MineGuard Platform 控制中心.lnk",
        "MineGuard 企业接入配置向导.lnk",
        "uninstaller",
        "shortcut",
        "snapshot",
        "$generation.ToString(",
        "'D20', [Globalization.CultureInfo]::InvariantCulture",
        "payloadEncoding = 'utf-8-base64'",
        "payloadSha256",
        "payloadBase64",
        "[IO.FileMode]::CreateNew",
        "[IO.FileOptions]::WriteThrough",
        "$stream.Flush($true)",
        "function Read-TransactionJournalGeneration",
        "function Get-ValidTransactionJournalRecords",
        "function Test-SafeUninitializedTransactionOrphan",
        "function Sync-FileTreeToDisk",
        "Compatibility with transactions created by the schema-1 implementation",
        "because it contains snapshot, candidate, or unknown data",
    ):
        assert token in bootstrap, f"trusted bootstrap contract missing: {token}"

    assert "Move-Item -LiteralPath $temporary -Destination " not in bootstrap
    assert "[IO.File]::WriteAllText($temporary" not in bootstrap
    journal_writer = bootstrap[
        bootstrap.index("function Write-TransactionJournal") :
        bootstrap.index("function Assert-TransactionJournalIdentity")
    ]
    post_flush = journal_writer[journal_writer.index("$stream.Flush($true)") :]
    assert "$durableWriteCompleted = $true" in post_flush
    assert "Set-Acl" not in post_flush
    assert "Read-TransactionJournalGeneration" not in post_flush
    assert "try { $stream.Dispose() } catch { }" in post_flush
    assert bootstrap.index("Sync-FileTreeToDisk -Path $snapshotPath") < (
        bootstrap.index(
            "Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal",
            bootstrap.index("Sync-FileTreeToDisk -Path $snapshotPath"),
        )
    )
    prepare_start = bootstrap.index("    'Prepare' {")
    prepare_end = bootstrap.index("    'Commit' {", prepare_start)
    prepare = bootstrap[prepare_start:prepare_end]
    assert prepare.index("Sync-FileTreeToDisk -Path $candidate") < prepare.index(
        "state = 'prepared'"
    )
    orphan_check = bootstrap[
        bootstrap.index("function Test-TransactionContainsOnlyJournalArtifacts") :
        bootstrap.index("function Sync-FileTreeToDisk")
    ]
    assert "if ($item.PSIsContainer)" in orphan_check
    assert "return $false" in orphan_check
    cleanup = bootstrap[
        bootstrap.index("function Remove-TransactionDirectory") :
        bootstrap.index("function Write-TransactionJournal")
    ]
    assert cleanup.index("foreach ($item in $payloadItems)") < cleanup.index(
        "foreach ($journalFile in $journalFiles)"
    ) < cleanup.index("The final valid journal is deliberately the last file")
    assert "Remove-Item -LiteralPath $full -Recurse" not in cleanup
    restore = bootstrap[
        bootstrap.index("function Restore-ManagedArtifacts") :
        bootstrap.index("function Assert-TransactionContext")
    ]
    assert restore.index("Sync-FileTreeToDisk -Path $target") < restore.index(
        "state = 'rolledback'"
    )
    arp_restore = bootstrap[
        bootstrap.index("function Restore-ArpRegistration") :
        bootstrap.index("function Capture-ManagedArtifacts")
    ]
    assert "$key.Flush()" in arp_restore
    assert "Flush-ArpRegistryParent" in arp_restore

    # PowerShell single-quoted strings do not escape backslashes. These exact
    # forms are required for correct Windows relative-path calculation.
    for token in (
        ".TrimEnd('\\') + '\\'",
        ".Replace('\\', '/')",
        "$RelativePath.Contains('\\')",
        "$installerRelative.Replace('/', '\\')",
    ):
        assert token in bootstrap, f"trusted bootstrap path separator bug: {token}"
    for forbidden in (
        ".TrimEnd('\\\\') + '\\\\'",
        ".Replace('\\\\', '/')",
        ".Replace('/', '\\\\')",
    ):
        assert forbidden not in bootstrap, (
            "PowerShell single-quoted path separators must contain one literal "
            f"backslash: {forbidden}"
        )
    assert "$group = Join-Path $programs 'MineGuard'" in bootstrap

    assert "Get-ChildItem -LiteralPath $source -Force" in bootstrap
    assert "Copy-Item -LiteralPath $item.FullName -Destination $stage.Path" in bootstrap
    direct_install = bootstrap[
        bootstrap.index("function Invoke-DirectInstall") :
        bootstrap.index("Assert-Administrator", bootstrap.index("function Invoke-DirectInstall"))
    ]
    assert direct_install.index("Assert-TrustedReleaseTree -Root $stage.Path") < (
        direct_install.index("Invoke-StagedProductInstaller")
    )
    final_cleanup = bootstrap[bootstrap.rindex("finally {") :]
    assert "try {" in final_cleanup and "catch {" in final_cleanup
    assert "Write-Warning" in final_cleanup
    assert "& (Join-Path $source" not in bootstrap
    commit = bootstrap[bootstrap.index("    'Commit' {") : bootstrap.index(
        "    'Rollback' {", bootstrap.index("    'Commit' {")
    )]
    assert commit.index("state = 'committing'") < commit.index(
        "Invoke-StagedProductInstaller"
    ) < commit.index("state = 'product_committed_unconfirmed'")
    finalize = bootstrap[bootstrap.index("    'Finalize' {") :]
    assert finalize.index("state = 'wrapper_succeeded'") < finalize.index(
        "Remove-TransactionDirectory"
    )
    rollback = bootstrap[
        bootstrap.index("function Invoke-TransactionRollback") :
        bootstrap.index("function Recover-StaleTransactions")
    ]
    assert "product_committed_unconfirmed" not in rollback
    assert "wrapper_succeeded" in rollback
    assert "rolledback" in rollback
    assert "[long]$journalRecord.Generation -eq 0" in rollback
    assert "Legacy capturing transaction has payload and was preserved" in rollback
    stale_recovery = bootstrap[
        bootstrap.index("function Recover-StaleTransactions") :
        bootstrap.index("function Invoke-DirectInstall")
    ]
    stale_success = stale_recovery[
        stale_recovery.index(
            "if ([string]$journal.state -in @('rolledback', 'wrapper_succeeded'))"
        ) :
        stale_recovery.index("} elseif", stale_recovery.index(
            "if ([string]$journal.state -in @('rolledback', 'wrapper_succeeded'))"
        ))
    ]
    assert "Remove-TransactionDirectory -Descriptor $stale" in stale_success
    assert "release-manifest.json" not in stale_success
    invoke_start = bootstrap.index("function Invoke-StagedProductInstaller")
    platform_start = bootstrap.index("if ($Product -eq 'Platform') {", invoke_start)
    platform_arguments = bootstrap[
        platform_start : bootstrap.index("} else {", platform_start)
    ]
    assert platform_arguments.count("InstallRoot = $InstallRoot") == 1

    # The cross-Inno transaction covers Agent StateRoot ownership and its root
    # ACL without serializing every business-data descendant into every durable
    # journal generation. Existing descendants are verified read-only.
    begin = bootstrap[
        bootstrap.index("    'Begin' {") : bootstrap.index("    'Prepare' {")
    ]
    for token in (
        "Assert-SafeAgentStateRootScope",
        "Capture-AgentStateRootMetadata",
        "agentStateRootMetadata = $agentStateRootMetadata",
        "StateRoot is required only for the Enterprise Agent transaction",
    ):
        assert token in begin, f"Agent StateRoot Begin contract missing: {token}"
    assert begin.index("Assert-SafeAgentStateRootScope") < begin.index(
        "Recover-StaleTransactions"
    ) < begin.index("Capture-AgentStateRootMetadata") < begin.index(
        "New-ProtectedTransactionDirectory"
    )
    state_capture = bootstrap[
        bootstrap.index("function Capture-AgentStateRootMetadata") :
        bootstrap.index("function Restore-AgentStateRootMetadata")
    ]
    for token in (
        "Get-AgentStateAclInventory",
        "expectedMarkerRootId",
        "reserved transaction marker temporary path",
        "Assert-SafeAgentStateRootScope",
        "missingAncestors = @($missingAncestors)",
        "existingAncestor = $existingAncestor",
    ):
        assert token in state_capture
    state_acl_capture = bootstrap[
        bootstrap.index("function Get-AgentStateAclInventory") : bootstrap.index(
            "function Get-AgentStateAclEntryPath"
        )
    ]
    assert "path = '.'" in state_acl_capture
    assert "kind = 'directory'" in state_acl_capture
    assert "Get-ChildItem" not in state_acl_capture
    assert "-Recurse" not in state_acl_capture
    state_restore = bootstrap[
        bootstrap.index("function Restore-AgentStateRootMetadata") :
        bootstrap.index("function Get-TreeInventory")
    ]
    for token in (
        "Agent rollback StateRoot disappeared; business data recovery is required",
        "Agent StateRoot ACL snapshot must contain only its root entry",
        "Assert-TransactionCreatedAgentStateMarker",
        "ExpectedTransactionId $transactionId",
        "Assert-ExactSecuritySddl",
        "Agent StateRoot rollback chain crossed its existing ancestor",
        "Transaction-created Agent StateRoot ancestor contains unknown data",
    ):
        assert token in state_restore
    assert "CreateDirectory($root)" not in state_restore
    assert "contentBase64" not in state_restore
    marker_assertion = bootstrap[
        bootstrap.index("function Assert-TransactionCreatedAgentStateMarker") :
        bootstrap.index("function Get-AgentStateAclInventory")
    ]
    assert "[Guid]::ParseExact($transactionId, 'N').ToString('D')" in marker_assertion
    assert "installer_transaction_id" not in marker_assertion
    managed_restore = bootstrap[
        bootstrap.index("function Restore-ManagedArtifacts") :
        bootstrap.index("function Assert-TransactionContext")
    ]
    assert managed_restore.index("Restore-AgentStateRootMetadata") < (
        managed_restore.index("Complete-ProductRootMetadataRollback")
    ) < managed_restore.index("$Journal.state = 'rolledback'")
    context = bootstrap[
        bootstrap.index("function Assert-TransactionContext") :
        bootstrap.index("function Invoke-StagedProductInstaller")
    ]
    assert "IncludeCurrentStateRoot" in context
    assert "Installer transaction StateRoot changed between phases" in context
    staged = bootstrap[
        bootstrap.index("function Invoke-StagedProductInstaller") :
        bootstrap.index("function Invoke-TransactionRollback")
    ]
    assert "TrustedBootstrapTransactionId" in staged
    assert "Get-NormalizedTransactionId -Value $MarkerTransactionId" in staged
    platform_staged = staged[
        staged.index("if ($Product -eq 'Platform') {") : staged.index("} else {")
    ]
    assert "TrustedBootstrapTransactionId" in platform_staged
    assert "-MarkerTransactionId $journal.transactionId" in commit
    assert "IncludeCurrentStateRoot" not in stale_recovery
    assert bootstrap.count("-IncludeCurrentStateRoot") >= 5
    assert "SetSecurityDescriptorSddlForm($Sddl, $managedSections)" in bootstrap
    assert "existing Audit/SACL section is intentionally neither replaced nor cleared" in bootstrap
    assert "$leafPattern = '^\\.mineguard-" in bootstrap
    assert "$leafPattern = '^\\\\.mineguard-" not in bootstrap
    for token in (
        "WrapperInstallRootPreexisted",
        "WrapperShortcutGroupPreexisted",
        "Capture-ProductRootMetadata",
        "Get-ValidatedProductRootRollbackMetadata",
        "Restore-ProductRootMetadataBeforeArtifacts",
        "Complete-ProductRootMetadataRollback",
        "AllowMissingInstallRoot",
    ):
        assert token in bootstrap

    expected_match = re.search(
        r'\$ExpectedTrustedBootstrapSha256\s*=\s*`\s*\n\s*"([a-f0-9]{64})"',
        build,
    )
    assert expected_match, "root builder must pin the reviewed bootstrap SHA-256"
    assert expected_match.group(1) == hashlib.sha256(path.read_bytes()).hexdigest(), (
        "root builder trusted bootstrap pin does not match the reviewed bytes"
    )
    base_arguments = build.split("function Invoke-InnoCompile", 1)[1].split(
        "if ($SigningEnabled)", 1
    )[0]
    for define in (
        "/DChildReleaseManifestSha256=$ChildReleaseManifestSha256",
        "/DTrustedBootstrapSha256=$TrustedBootstrapSha256",
    ):
        assert define in base_arguments, (
            "all release classifications must embed the trusted tree anchor: "
            f"{define}"
        )
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
        "INTERNAL-UNSIGNED",
        "signed-production-candidate",
        "unsigned-internal-release",
        "unsigned-test-artifacts",
        "LegacyWindowsServer2012R2CompatibilityTest",
        "legacy-windows-server-2012r2-test-v1",
        "6.3.9600",
        "target_os_validated = $false",
        "cannot be signed as a production candidate",
        "/DMinimumWindowsVersion=$MinimumWindowsVersion",
        "ExpectLegacyServer2012R2CompatibilityTest",
        "release-manifest.json",
        "SHA256SUMS.txt",
        "6.7.1",
        "$InnoVersion.Major -ne 6",
        "ISCC.exe was not found",
        "-RequireSignedBinary",
        "-InternalUnsignedRelease",
        "RequireSigned and InternalUnsignedRelease are mutually exclusive",
        "ExpectInternalUnsignedRelease",
        'authenticity_mode = if ($SigningEnabled)',
        "out-of-band-sha256",
        "production_approved = [bool]($SigningEnabled -or $InternalUnsignedRelease)",
        "installer_external_sha256_required = [bool]$InternalUnsignedRelease",
        "unsigned_internal_release = [bool]$InternalUnsignedRelease",
        "-SigningCertificateThumbprint",
        "WheelhouseManifest",
        "ExpectedWheelhouseManifestSha256",
        "ModelIssuerTrustStore",
        "ExpectedModelIssuerTrustStoreSha256",
        "model_issuer_trust_sha256",
        "model_issuer_trust_external_anchor_verified",
        "model_issuer_trust_test_only",
        "A formal release refuses the TEST-ONLY model issuer trust store",
        "BundledTestOnlyModelTrustStoreSha256",
        "regardless of filename or JSON formatting",
        "mineguard-test-only",
        "test-only-no-private-key-2026",
        "e3df516dc9ce7cce905597484d794625a6ac4e6ac2a11dfc07dbc8e2f15fb413",
        "ExpectedPythonPatchVersion",
        "ExpectedPythonExecutableSha256",
        "ExpectedInnoCompilerSha256",
        "ExpectedSignToolSha256",
        "Assert-ApprovedFileSha256",
        "UnsignedCompilerCacheReadyMarker",
        "UnsignedCompilerCacheReadyMarker is forbidden for formal releases",
        "UnsignedCompilerCacheReadyMarker must be located under the process temporary directory",
        "Both child compilers completed for source",
        "ExpectedInnoChineseLanguageSha256",
        "ActualInnoChineseLanguageSha256",
        "inno_chinese_language_sha256",
        "7d544b9bb1d142cfa11f2e5d3cc8abe2e55f8e066c5124e3772675aa236e1278",
        "Both child builders must use the same resolved root python.exe",
        "Strict child metadata does not match ExpectedPythonPatchVersion",
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
        "A strict child binary does not identify the clean root source revision",
        "A formal release cannot allow Nuitka tool downloads",
        "Assert-PathsDoNotOverlap",
        "must not equal, contain, or be contained by one another",
        "OutputDirectory must not exist before atomic publication",
        ".incoming-",
        "[IO.Directory]::Move($PublishStage, $OutputDirectory)",
        "Copy-Item -LiteralPath $SourcePath",
        "Published artifact audit",
        '"-ApprovedAgentSignerThumbprint", $NormalizedThumbprint',
        "ChildReleaseManifestSha256",
        "PlatformChildManifestSha256",
        "AgentChildManifestSha256",
        "child_release_manifest_sha256",
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
    native_checked = build[
        build.index("function Invoke-NativeChecked") : build.index(
            "function Assert-CleanGitSnapshot"
        )
    ]
    assert re.search(
        r"&\s*\$FilePath\s+@ArgumentList\s*\|\s*Out-Host", native_checked
    ), (
        "native diagnostic output must go directly to the host; otherwise an "
        "assigned Invoke-InnoCompile call treats compiler output (including empty "
        "lines) as installer paths"
    )
    assert not re.search(
        r"(?m)^\s*&\s*\$FilePath\s+@ArgumentList\s*$", native_checked
    ), "Invoke-NativeChecked must not leak native stdout into the success pipeline"
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
    assert build.count('+= "-ExpectLegacyServer2012R2CompatibilityTest"') == 2, (
        "both final-stage and atomically published legacy artifacts must receive "
        "the explicit Server 2012 R2 audit profile"
    )
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
        "INTERNAL-UNSIGNED",
        "ExpectInternalUnsignedRelease",
        "out-of-band-sha256",
        "unsigned_internal_release",
        "/ALLOWUNSIGNEDINTERNALRELEASE=1",
        "/EXPECTEDINSTALLERSHA256=$InstallerSha256",
        "ExpectLegacyServer2012R2CompatibilityTest",
        "legacy-windows-server-2012r2-test-v1",
        "Legacy Windows Server 2012 R2 release evidence is missing or inconsistent",
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
        "$ScriptVersionMatch",
        "$StyleVersionMatch",
        "$FrontendVersion",
        "cache versions are missing or inconsistent",
        "application/javascript; charset=utf-8",
        'id=\"frontendBootGuard\"',
        "/v2/regulatory/overview",
        "configured_mines",
        "reporting_mines",
        "MINEGUARD_LOCAL_CONTROL_TOKEN",
        "/_mineguard/local-control/shutdown",
        "X-MineGuard-Local-Control-Token",
        "Test-LoopbackPortAvailable",
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
        "ApprovedAgentSignerThumbprint",
        "/APPROVED_SIGNER_THUMBPRINT=",
        "/ALLOW_UNSIGNED_TEST_MEDIA=1",
        "$LifecycleAuditError = $null",
        "preserving the original lifecycle audit error",
        "Start-EnterpriseAgentModelCredentialWizard.ps1",
        "release-metadata\\model-credential-trust.json",
        "enterprise-agent-model-credential-wizard",
        "trust_store_present",
        "trust_store_editable",
        "api_configuration_editable",
        "Agent model credential wizard headless self-test failed",
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
        "$IsPowerShellStringVariableCastExpression",
        "'^\\[(?i:string)\\]\\s*\\$[A-Za-z_][A-Za-z0-9_]*",
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
    assert lifecycle.count("Invoke-WindowsGuiProcessAndWait") == 7, (
        "all installer, upgrade and uninstaller lifecycle launches must wait for "
        "the GUI process and read its actual exit code"
    )
    for negative_gate in (
        "missing authorization and digest",
        "incorrect externally approved digest",
        "INTERNAL-UNSIGNED negative probe mutated product state",
        '"/EXPECTEDINSTALLERSHA256=$WrongInstallerSha256"',
    ):
        assert negative_gate in lifecycle
    assert lifecycle.index("$InstallExitCode = Invoke-WindowsGuiProcessAndWait") < (
        lifecycle.index("$ProbeService = New-ServiceStateProbe")
    ), (
        "the clean product install must complete before the deliberately "
        "identity-mismatched lifecycle probe service is registered"
    )
    assert not re.search(r"(?m)^\s*&\s*\$Installer\b", lifecycle)
    assert not re.search(r"(?m)^\s*&\s*\$Uninstallers\[", lifecycle)
    platform_unsigned_gate = lifecycle[
        lifecycle.index('if ($Product -eq "platform" -and $UnsignedPlatformTestMedia)') :
        lifecycle.index('if ($Product -eq "agent")')
    ]
    assert '"/ALLOW_UNSIGNED_TEST_MEDIA=1"' in platform_unsigned_gate
    assert "-UnsignedPlatformTestMedia:$ExpectUnsignedTestOnly" in audit
    gui_wait = audit[
        audit.index("function Invoke-WindowsGuiProcessAndWait") : audit.index(
            "function Invoke-ExecutableChecked"
        )
    ]
    for token in ("Start-Process", "-Wait", "-PassThru", ".ExitCode"):
        assert token in gui_wait, f"GUI wait helper contract missing: {token}"
    wait_probe = read("scripts/Test-WindowsGuiProcessWait.ps1")
    for token in (
        "WindowsApplication",
        "Thread.Sleep(1200)",
        "Invoke-WindowsGuiProcessAndWait",
        "$ExitCode -ne 37",
        "$Stopwatch.ElapsedMilliseconds -lt 900",
        "completed marker.txt",
        "fixture-gui-wait.iss",
        "MineGuard GUI wait probe fixture",
        '"/DFixturePayload=$ProbeExecutable"',
        '"/DFixtureAppId=$FixtureAppId"',
        '"/DIR=$FixtureInstallRoot"',
        '"/FIXTURECUSTOMEXIT=1001"',
        "$CustomExitCode -ne 1001",
        "FixtureCustomExitCode := 1001",
        "Result := FixtureCustomExitCode",
        "$CustomExitUninstallCode -ne 0",
        "afterinstall-root.txt",
        "Dedicated Inno /DIR, AfterInstall, exit-code and uninstall",
        'Get-ChildItem -LiteralPath $FixtureInstallRoot `\n        -Filter "unins*.exe"',
    ):
        assert token in wait_probe, f"fast GUI wait probe contract missing: {token}"
    assert "Intentional dedicated Inno fixture failure" not in wait_probe
    assert "FixtureInstallFailed" not in wait_probe
    for production_token in (
        "MineGuardPlatform.iss",
        "ChildReleaseManifestSha256",
        "TrustedBootstrapSha256",
        "ALLOW_UNSIGNED_TEST_MEDIA",
    ):
        assert production_token not in wait_probe, (
            "the GUI wait probe must remain independent from the production "
            f"installer contract: {production_token}"
        )
    final_uninstall = lifecycle.rindex(
        "$FinalUninstallExitCode = Invoke-WindowsGuiProcessAndWait"
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

    failure_probe = read("scripts/Test-WindowsInstallerFailurePropagation.ps1")
    unsigned_probe_start = failure_probe.index("$InstallArguments = @(")
    unsigned_probe_end = failure_probe.index(
        "$ProbeExitCode = Invoke-ProcessTreeWithTransientAccessRetry",
        unsigned_probe_start,
    )
    assert '"/ALLOW_UNSIGNED_TEST_MEDIA=1"' in failure_probe[
        unsigned_probe_start:unsigned_probe_end
    ]

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
    assert (ROOT / "scripts/Test-WindowsInstallerFailurePropagation.ps1").read_bytes().startswith(
        b"\xef\xbb\xbf"
    ), "the Windows PowerShell 5.1 failure probe needs a UTF-8 BOM"
    assert "deliberately-tampered" in failure_probe
    assert "ProbeExitCode -eq 0" in failure_probe
    assert "ProbeExitCode -ne 1001" not in failure_probe
    assert "FailureExit -ne 1001" in failure_probe
    for token in (
        "function Write-FailureProbeReleaseIntegrity",
        '"model-credential-trust.json"',
        '"/DChildReleaseManifestSha256=$ChildReleaseManifestSha256"',
        '"/DTrustedBootstrapSha256=$TrustedBootstrapSha256"',
        "ConvertTo-Json -Depth 50",
        'if ($Product -eq "agent") { " *" } else { "  " }',
        "function Test-OneWrapperPersistenceRollback",
        "function Test-OneSetupMutexExclusion",
        "function Test-OneUninstallMutexExclusion",
        "function Test-AgentStateRootMarkerRollback",
        "Global\\MineGuard-Setup-Transaction-v1",
        "The SetupMutex native probe must run in an elevated administrator process",
        "$Mutex.ReleaseMutex()",
        "$Mutex.Dispose()",
        "if ($null -eq $BlockedExit -or [int]$BlockedExit -eq 0)",
        "SetupMutex rejection created InstallRoot",
        "SetupMutex rejection created StateRoot",
        "SetupMutex rejection created an HKLM64 ARP registration",
        "SetupMutex rejection created a shortcut",
        "SetupMutex rejection created a retained transaction",
        "The uninstall SetupMutex probe must run in an elevated administrator process",
        "$Product blocked uninstall",
        "the blocked uninstaller did not return a nonzero exit code",
        "the blocked uninstaller changed HKLM64 ARP",
        ".mineguard-enterprise-agent-instances.json",
        "preexisting-empty-unmarked",
        "new-state-root",
        'StateRelative = "missing-parent-a\\missing-parent-b\\state"',
        'MissingAncestorRelative = "missing-parent-a"',
        "transaction-created StateRoot marker was retained",
        "the pre-existing empty unmarked StateRoot was not restored",
        "the transaction-created StateRoot was not removed",
        "the transaction-created InstallRoot was not removed",
        "transaction-created StateRoot ancestor directories were not removed",
        "Platform fresh wrapper persistence probe returned",
        "platform fresh wrapper persistence rollback",
        "Platform fresh wrapper fixture unexpectedly has HKLM64 ARP",
        "Platform fresh wrapper rollback left HKLM64 ARP",
        "Platform fresh wrapper rollback leaked transaction",
        "FailureAfterWrapperPersistenceProbe",
        "function Get-ExactArtifactSnapshot",
        "function Assert-ExactArtifactSnapshot",
        "function Get-ArpRegistrationSnapshot",
        "Get-WrapperShortcutPaths",
        "HKLM64 ARP",
        '"docs", "uninstall-tools"',
        "unins[0-9]",
    ):
        assert token in failure_probe, (
            f"native failure fixture misses trusted bootstrap input: {token}"
        )
    assert (
        'foreach ($ImmutableDirectory in @('
        '"runtime", "release-metadata", "deploy", "service"))'
        in failure_probe
    )
    assert failure_probe.count("Test-OneWrapperPersistenceRollback `") == 2
    assert '-Product platform -OriginalStage $PlatformStage' in failure_probe
    assert '-Product agent -OriginalStage $AgentStage' in failure_probe
    mutex_probe = failure_probe[
        failure_probe.index("function Test-OneSetupMutexExclusion") :
        failure_probe.index("function Test-OneWrapperPersistenceRollback")
    ]
    assert mutex_probe.index("[Threading.Mutex]::new(") < mutex_probe.index(
        "Invoke-ProcessTreeWithTransientAccessRetry"
    ) < mutex_probe.index("$Mutex.ReleaseMutex()") < mutex_probe.index(
        "$Mutex.Dispose()"
    ) < mutex_probe.index("[int]$BlockedExit -eq 0")
    uninstall_mutex_probe = failure_probe[
        failure_probe.index("function Test-OneUninstallMutexExclusion") :
        failure_probe.index("function Test-OneWrapperPersistenceRollback")
    ]
    assert uninstall_mutex_probe.index(
        "$BeforeArtifacts = Get-ExactArtifactSnapshot"
    ) < uninstall_mutex_probe.index(
        "$BeforeArp = Get-ArpRegistrationSnapshot"
    ) < uninstall_mutex_probe.index(
        "[Threading.Mutex]::new("
    ) < uninstall_mutex_probe.index(
        "-FilePath $UninstallerPath"
    ) < uninstall_mutex_probe.index(
        "$Mutex.ReleaseMutex()"
    ) < uninstall_mutex_probe.index(
        "[int]$BlockedExit -eq 0"
    ) < uninstall_mutex_probe.index(
        "Assert-ExactArtifactSnapshot -Expected $BeforeArtifacts"
    ) < uninstall_mutex_probe.index(
        "$AfterArp = Get-ArpRegistrationSnapshot"
    )
    assert '$SnapshotPaths += $StateRoot' in uninstall_mutex_probe
    state_root_probe = failure_probe[
        failure_probe.index("function Test-AgentStateRootMarkerRollback") :
        failure_probe.index("function Test-OneWrapperPersistenceRollback")
    ]
    assert state_root_probe.index(
        'Name = "preexisting-empty-unmarked"'
    ) < state_root_probe.index(
        'RootExisted = $true'
    ) < state_root_probe.index(
        'Name = "new-state-root"'
    ) < state_root_probe.index('RootExisted = $false')
    assert state_root_probe.index(
        "$BeforeState = Get-ExactArtifactSnapshot"
    ) < state_root_probe.index(
        "Invoke-ProcessTreeWithTransientAccessRetry"
    ) < state_root_probe.index(
        "$FailureExit -ne 1001"
    ) < state_root_probe.index(
        "Assert-ExactArtifactSnapshot -Expected $BeforeState"
    ) < state_root_probe.index(
        "transaction-created StateRoot marker was retained"
    )
    assert "Release audit fault injection after wrapper persistence" in (
        state_root_probe
    )
    assert 'Get-ChildItem -LiteralPath $StateRoot -Force).Count -ne 0' in (
        state_root_probe
    )
    assert 'elseif (Test-Path -LiteralPath $StateRoot)' in state_root_probe
    assert 'if (Test-Path -LiteralPath $InstallRoot)' in state_root_probe
    assert state_root_probe.index(
        'StateRelative = "missing-parent-a\\missing-parent-b\\state"'
    ) < state_root_probe.index(
        "Invoke-ProcessTreeWithTransientAccessRetry"
    ) < state_root_probe.index(
        "transaction-created StateRoot ancestor directories were not removed"
    )
    wrapper_probe = failure_probe[
        failure_probe.index("function Test-OneWrapperPersistenceRollback") :
        failure_probe.index("function Invoke-ProductInstallerExpectFailure")
    ]
    assert wrapper_probe.index('$Product -eq "agent"') < wrapper_probe.index(
        "$BeforeFreshArtifacts = Get-ExactArtifactSnapshot"
    ) < wrapper_probe.index("$BaselineExit =")
    fresh_platform_probe = wrapper_probe[
        wrapper_probe.index("$BeforeFreshArtifacts = Get-ExactArtifactSnapshot") :
        wrapper_probe.index("$BaselineExit =")
    ]
    assert "Get-ArpRegistrationSnapshot" not in fresh_platform_probe, (
        "fresh wrapper rollback starts without ARP and must not use the "
        "installed-baseline snapshot helper"
    )
    assert fresh_platform_probe.count(
        '"query", $ArpKey, "/reg:64"'
    ) == 2, "fresh wrapper rollback must prove ARP absence before and after"
    assert wrapper_probe.index("Test-OneSetupMutexExclusion `") < (
        wrapper_probe.index("$BaselineExit =")
    ), "each product's baseline must first prove SetupMutex exclusion"
    assert wrapper_probe.index("Test-OneSetupMutexExclusion `") < (
        wrapper_probe.index("Test-AgentStateRootMarkerRollback `")
    ) < wrapper_probe.index("$BaselineExit ="), (
        "the Agent fresh-StateRoot rollback probes must run before its baseline"
    )
    assert wrapper_probe.index("$BaselineExit =") < wrapper_probe.index(
        "Test-OneUninstallMutexExclusion `"
    ) < wrapper_probe.index("$ManagedPaths ="), (
        "each installed baseline must prove uninstall mutex exclusion before "
        "the wrapper rollback snapshot"
    )
    assert wrapper_probe.index("$ManagedPaths =") < wrapper_probe.index(
        'if ($Product -eq "agent") { $ManagedPaths += $StateRoot }'
    ) < wrapper_probe.index("$BeforeArtifacts = Get-ExactArtifactSnapshot"), (
        "the Agent wrapper rollback snapshot must cover the complete StateRoot"
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
        'switch ($ReleaseClassification)',
        '"-ApprovedSignerThumbprint", $ApprovedSignerThumbprint',
        '"-ExpectedReleaseManifestSha256", $ReleaseManifestSha256',
        '$Arguments += "-AllowUnsignedTestMedia"',
        '"SHA256SUMS.txt", "model-credential-trust.json"',
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
    platform_acl_start = platform_installer.index(
        "function Set-MineGuardDirectoryAcl"
    )
    platform_acl_end = platform_installer.index(
        "function Test-MineGuardPlatformRuntimeProcess", platform_acl_start
    )
    platform_acl = platform_installer[platform_acl_start:platform_acl_end]
    for token in (
        "DirectorySecurity",
        "FileSecurity",
        "SetAccessRuleProtection($true, $false)",
        "[IO.Directory]::SetAccessControl",
        "[IO.File]::SetAccessControl",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-32-545",
        "$ServiceSid",
    ):
        assert token in platform_acl, f"Platform atomic ACL helper misses: {token}"
    assert "icacls" not in platform_acl.lower()
    assert "'/reset'" not in platform_acl and '"/reset"' not in platform_acl

    agent_acl_start = agent_installer.index(
        "function Set-EACanonicalProductTreeAcl"
    )
    agent_acl_end = agent_installer.index(
        "function Get-EADerivedServiceIdentity", agent_acl_start
    )
    agent_acl = agent_installer[agent_acl_start:agent_acl_end]
    for token in (
        "DirectorySecurity",
        "FileSecurity",
        "SetAccessRuleProtection($true, $false)",
        "[IO.Directory]::SetAccessControl",
        "[IO.File]::SetAccessControl",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-0",
        "S-1-5-32-545",
    ):
        assert token in agent_acl, f"Agent atomic ACL helper misses: {token}"
    assert '"/reset"' not in agent_acl
    first_runtime_switch = agent_installer.index(
        "-SourcePath $StagedRuntime -SourceParent $InstallRoot"
    )
    whole_tree_acl = agent_installer.index(
        "Set-EACanonicalProductTreeAcl -Path $InstallRoot -Recurse"
    )
    assert whole_tree_acl < first_runtime_switch
    assert agent_installer.index(
        "Set-EACanonicalProductTreeAcl -Path $StagedDeploy"
    ) < first_runtime_switch
    post_commit_start = agent_installer.rindex("if (-not $BuildFromSource) {")
    post_commit_end = agent_installer.index(
        "if ($BuildFromSource) {", post_commit_start
    )
    post_commit = agent_installer[post_commit_start:post_commit_end]
    assert "Set-EACanonicalProductTreeAcl" not in post_commit
    assert "Post-commit ACL verification" in post_commit
    assert "Write-Warning" in post_commit


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
    doubled_concatenated_separator = re.compile(
        r"\+\s*(?P<quote>['\"])\\\\(?P=quote)"
    )
    doubled_contains_separator = re.compile(
        r"\.Contains\(\s*(?P<quote>['\"])\\\\(?P=quote)\s*\)"
    )
    doubled_replacement_separator = re.compile(
        r"\.Replace\(\s*(?P<source>['\"])\/(?P=source)\s*,\s*"
        r"(?P<replacement>['\"])\\\\(?P=replacement)\s*\)"
    )
    assert doubled_concatenated_separator.search(r"$prefix + '\\'")
    assert not doubled_concatenated_separator.search(r"$prefix + '\'")
    assert doubled_contains_separator.search(r"$value.Contains('\\')")
    assert not doubled_contains_separator.search(r"$value.Contains('\')")
    assert doubled_replacement_separator.search(r"$value.Replace('/', '\\')")
    assert not doubled_replacement_separator.search(r"$value.Replace('/', '\')")
    roots = (
        ROOT / "platform/deploy/windows",
        ROOT / "platform/packaging/windows",
        ROOT / "agent/deploy/windows",
        ROOT / "agent/packaging/windows",
        ROOT / "scripts",
    )
    failures: list[str] = []
    separator_failures: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.ps1")):
            source = path.read_text(encoding="utf-8-sig")
            for match in ambiguous_variable_before_colon.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0)}")
            for match in doubled_concatenated_separator.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                separator_failures.append(
                    f"{path.relative_to(ROOT)}:{line}: {match.group(0)}"
                )
            for pattern in (
                doubled_contains_separator,
                doubled_replacement_separator,
            ):
                for match in pattern.finditer(source):
                    line = source.count("\n", 0, match.start()) + 1
                    separator_failures.append(
                        f"{path.relative_to(ROOT)}:{line}: {match.group(0)}"
                    )
    assert not failures, (
        "PowerShell 5.1 requires ${name}: when a variable is followed by a colon: "
        + ", ".join(failures)
    )
    assert not separator_failures, (
        "PowerShell strings do not escape backslashes; ordinary path operations "
        "must use one separator, not two: " + ", ".join(separator_failures)
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

    actionlint_config = read(".github/actionlint.yaml")
    for runner_label in ("signing", "mineguard-release"):
        assert f"    - {runner_label}" in actionlint_config, (
            f"actionlint must recognize the protected self-hosted label: {runner_label}"
        )

    workflow = read(".github/workflows/windows-release.yml")
    for token in (
        "windows-2022",
        "self-hosted, windows, x64, signing",
        "TestInstallerFailurePropagation",
        "TestInstallerLifecycle",
        "UNSIGNED-TEST-ONLY",
        "release_mode",
        "internal-unsigned",
        "INTERNAL-UNSIGNED",
        "self-hosted, windows, x64, mineguard-release",
        "windows-internal-unsigned-release",
        "-InternalUnsignedRelease",
        "WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "WINDOWS_RELEASE_WHEELHOUSE",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "platform/packaging/windows",
        "agent/packaging/windows",
        "WINDOWS_RELEASE_WHEELHOUSE_MANIFEST",
        "WINDOWS_RELEASE_WHEELHOUSE_MANIFEST_SHA256",
        "ExpectedWheelhouseManifestSha256",
        "WINDOWS_MODEL_ISSUER_TRUST_STORE",
        "WINDOWS_MODEL_ISSUER_TRUST_STORE_SHA256",
        "ModelIssuerTrustStore",
        "ExpectedModelIssuerTrustStoreSha256",
        "The approved model issuer trust store is unavailable",
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
        "UnsignedCompilerCacheReadyMarker",
        "Qualify complete unsigned compiler cache",
        "IsNullOrWhiteSpace(",
        "Save complete unsigned Nuitka compiler cache",
        "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
        "steps.nuitka_cache_ready.outputs.ready == 'true'",
        "legacy_server_2012r2_compatibility_test",
        "LegacyWindowsServer2012R2CompatibilityTest",
        "LEGACY-SERVER-2012R2-UNSIGNED-TEST-ONLY",
        "A legacy Windows Server 2012 R2 test cannot also request signed production candidates",
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
    unsigned_job = workflow.split("internal-unsigned-release:", 1)[0]
    build_block, _, _ = named_step_block(
        unsigned_job, "Build, audit, compile, install, health-check and uninstall"
    )
    assert "'${{ inputs.release_mode }}' -eq 'signed'" in build_block
    assert "'${{ inputs.sign_artifacts }}' -eq 'true' -or" in build_block
    assert "'${{ inputs.legacy_server_2012r2_compatibility_test }}' -eq 'true'" in (
        build_block
    )
    assert "$releaseParameters = @{" in build_block
    assert "@releaseParameters" in build_block
    assert "@releaseArguments" not in build_block, (
        "PowerShell array splatting is positional and must not carry named release "
        "parameters; use hashtable splatting"
    )
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
    internal_job = workflow.split("internal-unsigned-release:", 1)[1].split(
        "signed-production-candidate:", 1
    )[0]
    assert "github.ref == 'refs/heads/main'" in internal_job, (
        "the elevated private release runner must not execute arbitrary branch refs"
    )
    for token in (
        "Validate controlled offline release inputs",
        "Parse release PowerShell with Windows PowerShell 5.1",
        "Preflight release text safety scanner",
        "-InternalUnsignedRelease",
        "MineGuard-Platform-*-INTERNAL-UNSIGNED.exe",
        "MineGuard-EnterpriseAgent-*-INTERNAL-UNSIGNED.exe",
        "release-manifest.json",
        "SHA256SUMS.txt",
        "if-no-files-found: error",
    ):
        assert token in internal_job, (
            f"internal-unsigned workflow gate missing: {token}"
        )
    for forbidden in (
        "WINDOWS_SIGNTOOL_PATH",
        "WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "-RequireSigned",
        "actions/setup-python",
        "AllowNuitkaToolDownloads",
    ):
        assert forbidden not in internal_job, (
            f"internal-unsigned workflow must not depend on signing/network mode: {forbidden}"
        )
    assert internal_job.index("scripts/test_windows_packaging.py") < (
        internal_job.index("Build audit lifecycle-test and publish four files")
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
    assert (
        "-ModelIssuerTrustStore $env:WINDOWS_MODEL_ISSUER_TRUST_STORE"
        in signed_job
    )
    assert (
        "-ExpectedModelIssuerTrustStoreSha256 "
        "$env:WINDOWS_MODEL_ISSUER_TRUST_STORE_SHA256" in signed_job
    )


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
        test_inno_code_array_arguments_cannot_look_like_section_tags,
        test_inno_transaction_ids_use_supported_strong_unique_names,
        test_powershell_text_encoding_is_safe_for_windows_powershell_51,
        test_pinned_inno_chinese_language,
        test_contract_transport_vectors_keep_lf_bytes,
        test_child_toolchain_pins,
        test_inno_scripts,
        test_trusted_product_install_bootstrap,
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
