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

    $InnoCompiler = Join-Path ${env:ProgramFiles(x86)} `
        "Inno Setup 6\ISCC.exe"
    if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
        throw "Inno compiler is unavailable for the dedicated GUI wait fixture: $InnoCompiler"
    }

    $FixtureOutput = Join-Path $ProbeRoot "out"
    New-Item -ItemType Directory -Path $FixtureOutput -Force | Out-Null
    $InnoScript = Join-Path $ProbeRoot "fixture-gui-wait.iss"
    $InnoSource = @'
#ifndef FixturePayload
  #error FixturePayload is required.
#endif
#ifndef OutputDir
  #error OutputDir is required.
#endif
#ifndef ArtifactFileName
  #error ArtifactFileName is required.
#endif
#ifndef FixtureAppId
  #error FixtureAppId is required.
#endif

[Setup]
AppId={#FixtureAppId}
AppName=MineGuard GUI wait probe fixture
AppVersion=0.0.1
DefaultDirName={localappdata}\MineGuard\GuiWaitProbeFixture
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible and not arm64
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename={#ArtifactFileName}
Compression=lzma2
SolidCompression=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=yes
UsePreviousAppDir=no
CloseApplications=no
RestartIfNeededByRun=no
SetupLogging=yes
CreateUninstallRegKey=no

[Files]
Source: "{#FixturePayload}"; DestDir: "{app}\runtime"; DestName: "GuiWaitProbe.exe"; Flags: ignoreversion; AfterInstall: CompleteFixtureInstall

[UninstallDelete]
Type: filesandordirs; Name: "{app}\runtime"

[Code]
const
  FixtureFailureExitCode = 1001;

var
  FixtureInstallFailed: Boolean;

procedure CompleteFixtureInstall();
var
  MarkerPath: String;
begin
  Sleep(1200);
  if CompareText(Trim(ExpandConstant('{param:FIXTUREFAIL|0}')), '1') = 0 then
  begin
    FixtureInstallFailed := True;
    RaiseException('Intentional dedicated Inno fixture failure.');
  end;
  MarkerPath := ExpandConstant('{app}\runtime\afterinstall-root.txt');
  if not SaveStringToFile(MarkerPath, ExpandConstant('{app}'), False) then
  begin
    FixtureInstallFailed := True;
    RaiseException('Dedicated Inno fixture could not write its completion marker.');
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  if FixtureInstallFailed then
    Result := FixtureFailureExitCode
  else
    Result := 0;
end;
'@
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $InnoScript, $InnoSource, $Utf8NoBom
    )

    $FixtureAppId = "MineGuardGuiWaitFixture-" + `
        [Guid]::NewGuid().ToString("N")
    $FixtureArtifactName = "MineGuardGuiWaitFixture"
    $CompileExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $InnoCompiler `
        -ArgumentList @(
            "/Qp",
            "/DFixturePayload=$ProbeExecutable",
            "/DOutputDir=$FixtureOutput",
            "/DArtifactFileName=$FixtureArtifactName",
            "/DFixtureAppId=$FixtureAppId",
            $InnoScript
        )
    if ($CompileExitCode -ne 0) {
        throw "Dedicated Inno fixture compilation returned $CompileExitCode."
    }
    $FixtureInstaller = Join-Path $FixtureOutput ($FixtureArtifactName + ".exe")
    if (-not (Test-Path -LiteralPath $FixtureInstaller -PathType Leaf)) {
        throw "Dedicated Inno fixture compiler did not create its installer."
    }

    $FailureInstallRoot = Join-Path $ProbeRoot "Failed Fixture Root"
    $FailureLog = Join-Path $ProbeRoot "failed install.log"
    $FailureStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $FailureExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureInstaller `
        -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/DIR=$FailureInstallRoot", "/LOG=$FailureLog",
            "/FIXTUREFAIL=1"
        )
    $FailureStopwatch.Stop()
    if ($FailureExitCode -ne 1001) {
        throw "Dedicated Inno fixture returned $FailureExitCode instead of 1001."
    }
    if ($FailureStopwatch.ElapsedMilliseconds -lt 900) {
        throw "Dedicated Inno failure path returned before AfterInstall finished."
    }
    if (Test-Path -LiteralPath (Join-Path $FailureInstallRoot "runtime")) {
        throw "Failed dedicated Inno fixture left an installed runtime."
    }
    if (Test-Path -LiteralPath $FailureInstallRoot) {
        Remove-Item -LiteralPath $FailureInstallRoot -Recurse -Force
    }

    $FixtureInstallRoot = Join-Path $ProbeRoot "Custom Fixture Root"
    $FixtureLog = Join-Path $ProbeRoot "successful install.log"
    $InstallStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $FixtureInstallExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureInstaller `
        -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/DIR=$FixtureInstallRoot", "/LOG=$FixtureLog"
        )
    $InstallStopwatch.Stop()
    if ($FixtureInstallExitCode -ne 0) {
        throw "Dedicated Inno fixture install returned $FixtureInstallExitCode."
    }
    if ($InstallStopwatch.ElapsedMilliseconds -lt 900) {
        throw "Dedicated Inno success path returned before AfterInstall finished."
    }
    $FixtureExpectedFiles = @(
        (Join-Path $FixtureInstallRoot "runtime\GuiWaitProbe.exe"),
        (Join-Path $FixtureInstallRoot "runtime\afterinstall-root.txt"),
        $FixtureLog
    )
    foreach ($ExpectedFile in $FixtureExpectedFiles) {
        if (-not (Test-Path -LiteralPath $ExpectedFile -PathType Leaf)) {
            throw "Dedicated Inno fixture is missing: $ExpectedFile"
        }
    }
    $RecordedInstallRoot = Get-Content -LiteralPath (
        Join-Path $FixtureInstallRoot "runtime\afterinstall-root.txt"
    ) -Raw
    if (-not $RecordedInstallRoot.Equals(
            [IO.Path]::GetFullPath($FixtureInstallRoot),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Dedicated Inno fixture did not preserve the custom /DIR argument."
    }

    $FixtureUninstallers = @(Get-ChildItem -LiteralPath $FixtureInstallRoot `
        -Filter "unins*.exe" -File)
    if ($FixtureUninstallers.Count -ne 1) {
        throw "Dedicated Inno fixture must create exactly one uninstaller."
    }
    $FixtureUninstallExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureUninstallers[0].FullName `
        -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
    if ($FixtureUninstallExitCode -ne 0) {
        throw "Dedicated Inno fixture uninstall returned $FixtureUninstallExitCode."
    }
    $UninstallerCleanupDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $InnoResidue = @(Get-ChildItem -LiteralPath $FixtureInstallRoot `
            -Filter "unins*.*" -File -ErrorAction SilentlyContinue)
        if ($InnoResidue.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $UninstallerCleanupDeadline)
    if ($InnoResidue.Count -ne 0) {
        throw "Dedicated Inno fixture uninstaller did not clean up its own files."
    }
    if (Test-Path -LiteralPath (Join-Path $FixtureInstallRoot "runtime")) {
        throw "Dedicated Inno fixture uninstall left its runtime directory."
    }
    Write-Host (
        "Dedicated Inno /DIR, AfterInstall, exit-code and uninstall " +
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
