[CmdletBinding()]
param([string]$AuditScript = "")

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "The GUI process wait probe requires native Windows."
}
if ([string]::IsNullOrWhiteSpace($AuditScript)) {
    $AuditScript = Join-Path $PSScriptRoot "Test-WindowsBinaryRelease.ps1"
}
$AuditScript = [IO.Path]::GetFullPath($AuditScript)
if (-not (Test-Path -LiteralPath $AuditScript -PathType Leaf)) {
    throw "Release audit script does not exist: $AuditScript"
}

$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $AuditScript,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if ($ParseErrors.Count -ne 0) {
    throw "Release audit script cannot be parsed for the GUI wait probe."
}
foreach ($FunctionName in @(
    "ConvertTo-QuotedNativeArgument",
    "Invoke-WindowsGuiProcessAndWait"
)) {
    $Matches = @($Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -eq $FunctionName
    }, $true))
    if ($Matches.Count -ne 1) {
        throw "Expected exactly one $FunctionName definition, found $($Matches.Count)."
    }
    . ([scriptblock]::Create($Matches[0].Extent.Text))
}

$ProbeParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$ProbeRoot = Join-Path $ProbeParent (
    "MineGuardGuiWaitProbe-" + [Guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $ProbeRoot | Out-Null
$FixtureInstallRoot = $null
$FailureLog = $null
$FixtureLog = $null
try {
    $ProbeExecutable = Join-Path $ProbeRoot "GuiWaitProbe.exe"
    $MarkerPath = Join-Path $ProbeRoot "completed marker.txt"
    $Source = @'
using System;
using System.IO;
using System.Threading;

internal static class MineGuardGuiWaitProbe
{
    [STAThread]
    public static int Main(string[] args)
    {
        Thread.Sleep(1200);
        if (args.Length != 3 || args[1] != "argument with spaces" ||
            args[2] != "trailing\\")
        {
            return 38;
        }
        File.WriteAllText(args[0], "completed");
        return 37;
    }
}
'@
    Add-Type -TypeDefinition $Source -Language CSharp `
        -OutputAssembly $ProbeExecutable -OutputType WindowsApplication

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $ExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $ProbeExecutable `
        -ArgumentList @($MarkerPath, "argument with spaces", 'trailing\')
    $Stopwatch.Stop()
    if ($ExitCode -ne 37) {
        throw "GUI wait probe returned $ExitCode instead of 37."
    }
    if ($Stopwatch.ElapsedMilliseconds -lt 900) {
        throw "GUI process helper returned before the GUI executable finished."
    }
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf) -or
        (Get-Content -LiteralPath $MarkerPath -Raw) -ne "completed") {
        throw "GUI process helper did not wait for the completion marker."
    }
    Write-Host "Windows GUI process wait and argument round-trip probe passed."

    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
    $InnoCompiler = Join-Path ${env:ProgramFiles(x86)} `
        "Inno Setup 6\ISCC.exe"
    $InnoScript = Join-Path $RepositoryRoot `
        "packaging\windows\inno\MineGuardPlatform.iss"
    $AssetsRoot = Join-Path $RepositoryRoot "packaging\windows\assets"
    foreach ($RequiredPath in @($InnoCompiler, $InnoScript, $AssetsRoot)) {
        if (-not (Test-Path -LiteralPath $RequiredPath)) {
            throw "Platform Inno fixture input is missing: $RequiredPath"
        }
    }

    $FixtureStage = Join-Path $ProbeRoot "stage"
    $FixtureRuntime = Join-Path $FixtureStage "runtime"
    $FixtureDeploy = Join-Path $FixtureStage "deploy\windows"
    $FixtureOutput = Join-Path $ProbeRoot "out"
    New-Item -ItemType Directory -Path $FixtureRuntime -Force | Out-Null
    New-Item -ItemType Directory -Path $FixtureDeploy -Force | Out-Null
    New-Item -ItemType Directory -Path $FixtureOutput -Force | Out-Null
    Copy-Item -LiteralPath $ProbeExecutable `
        -Destination (Join-Path $FixtureRuntime "MineGuardPlatform.exe")

    $FixtureInstallerScript = @'
[CmdletBinding()]
param([string]$SourceDirectory, [string]$InstallRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
Start-Sleep -Milliseconds 1200
if ($env:MINEGUARD_INNO_FIXTURE_FAIL -eq "1") {
    Write-Error "Intentional fixture failure after the Inno AfterInstall callback."
    exit 23
}
$runtime = Join-Path $InstallRoot "runtime"
$service = Join-Path $InstallRoot "service"
$metadata = Join-Path $InstallRoot "release-metadata"
foreach ($directory in @($runtime, $service, $metadata)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
Copy-Item -LiteralPath (Join-Path $SourceDirectory "runtime\MineGuardPlatform.exe") `
    -Destination $runtime
Copy-Item -LiteralPath (Join-Path $SourceDirectory "deploy\windows\Install-MineGuardPlatform.ps1") `
    -Destination $service
foreach ($name in @(
    "VERSION.txt", "build-metadata.json", "release-manifest.json", "SHA256SUMS.txt"
)) {
    Copy-Item -LiteralPath (Join-Path $SourceDirectory $name) -Destination $metadata
}
[IO.File]::WriteAllText(
    (Join-Path $runtime "afterinstall-root.txt"),
    [IO.Path]::GetFullPath($InstallRoot)
)
exit 0
'@
    $FixtureUninstallerScript = @'
[CmdletBinding()]
param([string]$InstallRoot, [switch]$InternalInnoUninstall)
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
foreach ($name in @("runtime", "service", "release-metadata")) {
    $path = Join-Path $InstallRoot $name
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
exit 0
'@
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        (Join-Path $FixtureDeploy "Install-MineGuardPlatform.ps1"),
        $FixtureInstallerScript,
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $FixtureDeploy "Uninstall-MineGuardPlatformRuntime.ps1"),
        $FixtureUninstallerScript,
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $FixtureStage "VERSION.txt"), "0.0.1", $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $FixtureStage "build-metadata.json"),
        '{"version":"0.0.1","fixture":true}',
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $FixtureStage "release-manifest.json"),
        '{"schemaVersion":1,"product":"MineGuard Platform","fixture":true}',
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        (Join-Path $FixtureStage "SHA256SUMS.txt"),
        "fixture-only; validated through the guarded AfterInstall boundary",
        $Utf8NoBom
    )

    $FixtureAppId = "MineGuardPlatformInnoFixture-" + `
        [Guid]::NewGuid().ToString("N")
    $FixtureArtifactName = "MineGuardPlatformInnoFixture"
    $CompileExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $InnoCompiler `
        -ArgumentList @(
            "/Qp",
            "/DStageRoot=$FixtureStage",
            "/DAssetsRoot=$AssetsRoot",
            "/DOutputDir=$FixtureOutput",
            "/DAppVersion=0.0.1",
            "/DNumericVersion=0.0.1.0",
            "/DArtifactFileName=$FixtureArtifactName",
            "/DApplicationId=$FixtureAppId",
            $InnoScript
        )
    if ($CompileExitCode -ne 0) {
        throw "Platform Inno fixture compilation returned $CompileExitCode."
    }
    $FixtureInstaller = Join-Path $FixtureOutput ($FixtureArtifactName + ".exe")
    if (-not (Test-Path -LiteralPath $FixtureInstaller -PathType Leaf)) {
        throw "Platform Inno fixture compiler did not create its installer."
    }

    $FailureInstallRoot = Join-Path $ProbeRoot "Failed Platform Root"
    $FailureLog = Join-Path $ProbeRoot "failed install.log"
    $PreviousFixtureFailure = $env:MINEGUARD_INNO_FIXTURE_FAIL
    try {
        $env:MINEGUARD_INNO_FIXTURE_FAIL = "1"
        $FailureStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $FailureExitCode = Invoke-WindowsGuiProcessAndWait `
            -FilePath $FixtureInstaller `
            -ArgumentList @(
                "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
                "/DIR=$FailureInstallRoot", "/LOG=$FailureLog",
                "/ALLOW_UNSIGNED_TEST_MEDIA=1"
            )
        $FailureStopwatch.Stop()
    }
    finally {
        if ($null -eq $PreviousFixtureFailure) {
            Remove-Item Env:MINEGUARD_INNO_FIXTURE_FAIL `
                -ErrorAction SilentlyContinue
        }
        else {
            $env:MINEGUARD_INNO_FIXTURE_FAIL = $PreviousFixtureFailure
        }
    }
    if ($FailureExitCode -ne 1001) {
        throw "Platform Inno fixture returned $FailureExitCode instead of 1001."
    }
    if ($FailureStopwatch.ElapsedMilliseconds -lt 900) {
        throw "Platform Inno failure path returned before AfterInstall finished."
    }
    if (Test-Path -LiteralPath (Join-Path $FailureInstallRoot "runtime")) {
        throw "Failed Platform Inno fixture left an installed runtime."
    }
    if (Test-Path -LiteralPath $FailureInstallRoot) {
        Remove-Item -LiteralPath $FailureInstallRoot -Recurse -Force
    }

    $FixtureInstallRoot = Join-Path $ProbeRoot "Custom Platform Root"
    $FixtureLog = Join-Path $ProbeRoot "successful install.log"
    $InstallStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $FixtureInstallExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureInstaller `
        -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/DIR=$FixtureInstallRoot", "/LOG=$FixtureLog",
            "/ALLOW_UNSIGNED_TEST_MEDIA=1"
        )
    $InstallStopwatch.Stop()
    if ($FixtureInstallExitCode -ne 0) {
        throw "Platform Inno fixture install returned $FixtureInstallExitCode."
    }
    if ($InstallStopwatch.ElapsedMilliseconds -lt 900) {
        throw "Platform Inno success path returned before AfterInstall finished."
    }
    $FixtureExpectedFiles = @(
        (Join-Path $FixtureInstallRoot "runtime\MineGuardPlatform.exe"),
        (Join-Path $FixtureInstallRoot "service\Install-MineGuardPlatform.ps1"),
        (Join-Path $FixtureInstallRoot "release-metadata\release-manifest.json"),
        (Join-Path $FixtureInstallRoot "runtime\afterinstall-root.txt"),
        $FixtureLog
    )
    foreach ($ExpectedFile in $FixtureExpectedFiles) {
        if (-not (Test-Path -LiteralPath $ExpectedFile -PathType Leaf)) {
            throw "Platform Inno fixture is missing: $ExpectedFile"
        }
    }
    $RecordedInstallRoot = Get-Content -LiteralPath (
        Join-Path $FixtureInstallRoot "runtime\afterinstall-root.txt"
    ) -Raw
    if (-not $RecordedInstallRoot.Equals(
            [IO.Path]::GetFullPath($FixtureInstallRoot),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Platform Inno fixture did not preserve the custom /DIR argument."
    }

    $FixtureUninstallers = @(Get-ChildItem -LiteralPath $FixtureInstallRoot `
        -Filter "unins*.exe" -File)
    if ($FixtureUninstallers.Count -ne 1) {
        throw "Platform Inno fixture must create exactly one uninstaller."
    }
    $FixtureUninstallExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureUninstallers[0].FullName `
        -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
    if ($FixtureUninstallExitCode -ne 0) {
        throw "Platform Inno fixture uninstall returned $FixtureUninstallExitCode."
    }
    $UninstallerCleanupDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $InnoResidue = @(Get-ChildItem -LiteralPath $FixtureInstallRoot `
            -Filter "unins*.*" -File -ErrorAction SilentlyContinue)
        if ($InnoResidue.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $UninstallerCleanupDeadline)
    if ($InnoResidue.Count -ne 0) {
        throw "Platform Inno fixture uninstaller did not clean up its own files."
    }
    foreach ($RemovedDirectory in @("runtime", "service", "release-metadata")) {
        if (Test-Path -LiteralPath (Join-Path $FixtureInstallRoot $RemovedDirectory)) {
            throw "Platform Inno fixture uninstall left $RemovedDirectory."
        }
    }
    Write-Host (
        "Real Platform Inno /DIR, AfterInstall, exit-code and uninstall " +
        "fixture passed."
    )
}
catch {
    foreach ($DiagnosticLog in @($FailureLog, $FixtureLog)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$DiagnosticLog) -and
            (Test-Path -LiteralPath $DiagnosticLog -PathType Leaf)) {
            Write-Host "--- fixture diagnostic: $([IO.Path]::GetFileName($DiagnosticLog)) ---"
            Get-Content -LiteralPath $DiagnosticLog -Tail 120 |
                ForEach-Object { Write-Host $_ }
        }
    }
    throw
}
finally {
    if ($null -ne $FixtureInstallRoot -and
        (Test-Path -LiteralPath $FixtureInstallRoot -PathType Container)) {
        $ResidualUninstallers = @(Get-ChildItem -LiteralPath $FixtureInstallRoot `
            -Filter "unins*.exe" -File -ErrorAction SilentlyContinue)
        if ($ResidualUninstallers.Count -eq 1) {
            try {
                [void](Invoke-WindowsGuiProcessAndWait `
                    -FilePath $ResidualUninstallers[0].FullName `
                    -ArgumentList @(
                        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
                    ))
            }
            catch {
                Write-Warning "Fixture uninstaller cleanup failed: $($_.Exception.Message)"
            }
        }
    }
    $FullProbeRoot = [IO.Path]::GetFullPath($ProbeRoot)
    $ProbePrefix = $ProbeParent + '\'
    if (-not $FullProbeRoot.StartsWith(
            $ProbePrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing unsafe GUI wait probe cleanup path: $FullProbeRoot"
    }
    Remove-Item -LiteralPath $FullProbeRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}
