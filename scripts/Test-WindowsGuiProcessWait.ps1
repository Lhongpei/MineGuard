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
    "Get-WindowsDiagnosticLogTail",
    "Stop-WindowsProcessTree",
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
$CustomExitInstallRoot = $null
$FixtureInstallRoot = $null
$CustomExitLog = $null
$FixtureLog = $null
$HangProcessIds = @()
try {
    $ProbeExecutable = Join-Path $ProbeRoot "GuiWaitProbe.exe"
    $MarkerPath = Join-Path $ProbeRoot "completed marker.txt"
    $Source = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

internal static class MineGuardGuiWaitProbe
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--hang")
        {
            string pingPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "ping.exe");
            var childInfo = new ProcessStartInfo(pingPath, "-t 127.0.0.1");
            childInfo.UseShellExecute = false;
            childInfo.CreateNoWindow = true;
            Process child = Process.Start(childInfo);
            if (child == null)
            {
                return 39;
            }
            File.WriteAllText(
                args[1],
                Process.GetCurrentProcess().Id + Environment.NewLine +
                child.Id + Environment.NewLine);
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }
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

    $HangPidPath = Join-Path $ProbeRoot "hung process ids.txt"
    $HangDiagnosticLog = Join-Path $ProbeRoot "hung process diagnostic.log"
    $HangDiagnosticMarker = "MINEGUARD_GUI_TIMEOUT_LOG_TAIL_MARKER"
    $SensitiveArgument = "MINEGUARD_SENSITIVE_ARGV_SENTINEL"
    [IO.File]::WriteAllText(
        $HangDiagnosticLog,
        ($HangDiagnosticMarker + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    $HangStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $HangFailure = $null
    try {
        [void](Invoke-WindowsGuiProcessAndWait `
            -FilePath $ProbeExecutable `
            -ArgumentList @("--hang", $HangPidPath, $SensitiveArgument) `
            -TimeoutSeconds 2 `
            -OperationLabel "hung GUI process-tree probe" `
            -DiagnosticLogPath $HangDiagnosticLog)
    }
    catch {
        $HangFailure = $_.Exception.Message
    }
    finally {
        $HangStopwatch.Stop()
    }
    if ([string]::IsNullOrWhiteSpace($HangFailure)) {
        throw "GUI process timeout probe unexpectedly completed."
    }
    foreach ($ExpectedDiagnostic in @(
        "hung GUI process-tree probe",
        "did not finish within 2 seconds",
        $HangDiagnosticMarker,
        "taskkill_exit=",
        "root_exited="
    )) {
        if ($HangFailure -notlike "*$ExpectedDiagnostic*") {
            throw "GUI process timeout diagnostic is missing: $ExpectedDiagnostic"
        }
    }
    if ($HangFailure -like "*$SensitiveArgument*") {
        throw "GUI process timeout diagnostic leaked a command-line argument."
    }
    if ($HangStopwatch.ElapsedMilliseconds -lt 1000 -or
        $HangStopwatch.ElapsedMilliseconds -gt 30000) {
        throw (
            "GUI process timeout was not bounded as expected: " +
            "$($HangStopwatch.ElapsedMilliseconds) ms"
        )
    }
    if (-not (Test-Path -LiteralPath $HangPidPath -PathType Leaf)) {
        throw "GUI process timeout fixture did not report its process IDs."
    }
    $HangProcessIds = @(
        Get-Content -LiteralPath $HangPidPath | ForEach-Object {
            if ([string]$_ -notmatch '^[1-9][0-9]*$') {
                throw "GUI process timeout fixture emitted an invalid process ID."
            }
            [int]$_
        }
    )
    if ($HangProcessIds.Count -ne 2) {
        throw "GUI process timeout fixture must report its parent and child IDs."
    }
    foreach ($HangProcessId in $HangProcessIds) {
        $ExitDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $ResidualProcess = Get-Process -Id $HangProcessId `
                -ErrorAction SilentlyContinue
            if ($null -eq $ResidualProcess) { break }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $ExitDeadline)
        if ($null -ne $ResidualProcess) {
            throw "GUI process timeout left process $HangProcessId running."
        }
    }
    # Do not retain exited numeric IDs while later Inno fixtures run; Windows
    # may reuse a PID before the outer cleanup block is reached.
    $HangProcessIds = @()
    Write-Host (
        "Windows GUI timeout, diagnostic-tail and process-tree cleanup probe passed."
    )

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
  FixtureCustomExitCode: Integer;

procedure CompleteFixtureInstall();
var
  MarkerPath: String;
begin
  Sleep(1200);
  MarkerPath := ExpandConstant('{app}\runtime\afterinstall-root.txt');
  if not SaveStringToFile(MarkerPath, ExpandConstant('{app}'), False) then
    RaiseException('Dedicated Inno fixture could not write its completion marker.');
  if CompareText(Trim(ExpandConstant(
      '{param:FIXTURECUSTOMEXIT|0}')), '1001') = 0 then
    FixtureCustomExitCode := 1001;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := FixtureCustomExitCode;
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

    $CustomExitInstallRoot = Join-Path $ProbeRoot "Custom Exit Fixture Root"
    $CustomExitLog = Join-Path $ProbeRoot "custom exit install.log"
    $CustomExitStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $CustomExitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $FixtureInstaller `
        -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/DIR=$CustomExitInstallRoot", "/LOG=$CustomExitLog",
            "/FIXTURECUSTOMEXIT=1001"
        )
    $CustomExitStopwatch.Stop()
    if ($CustomExitCode -ne 1001) {
        throw "Dedicated Inno fixture returned $CustomExitCode instead of 1001."
    }
    if ($CustomExitStopwatch.ElapsedMilliseconds -lt 900) {
        throw "Dedicated Inno custom-exit path returned before AfterInstall finished."
    }
    foreach ($ExpectedFile in @(
        (Join-Path $CustomExitInstallRoot "runtime\GuiWaitProbe.exe"),
        (Join-Path $CustomExitInstallRoot "runtime\afterinstall-root.txt"),
        $CustomExitLog
    )) {
        if (-not (Test-Path -LiteralPath $ExpectedFile -PathType Leaf)) {
            throw "Custom-exit Inno fixture is missing: $ExpectedFile"
        }
    }
    $CustomExitUninstallers = @(Get-ChildItem `
        -LiteralPath $CustomExitInstallRoot -Filter "unins*.exe" -File)
    if ($CustomExitUninstallers.Count -ne 1) {
        throw "Custom-exit Inno fixture must create exactly one uninstaller."
    }
    $CustomExitUninstallCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $CustomExitUninstallers[0].FullName `
        -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
    if ($CustomExitUninstallCode -ne 0) {
        throw "Custom-exit Inno fixture uninstall returned $CustomExitUninstallCode."
    }
    $CustomExitCleanupDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $CustomExitResidue = @(Get-ChildItem `
            -LiteralPath $CustomExitInstallRoot -Filter "unins*.*" -File `
            -ErrorAction SilentlyContinue)
        if ($CustomExitResidue.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $CustomExitCleanupDeadline)
    if ($CustomExitResidue.Count -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $CustomExitInstallRoot "runtime"))) {
        throw "Custom-exit Inno fixture uninstall left managed artifacts."
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
    foreach ($DiagnosticLog in @($CustomExitLog, $FixtureLog)) {
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
    foreach ($HangProcessId in $HangProcessIds) {
        Stop-Process -Id $HangProcessId -Force -ErrorAction SilentlyContinue
    }
    foreach ($ResidualRoot in @($CustomExitInstallRoot, $FixtureInstallRoot)) {
        if ($null -ne $ResidualRoot -and
            (Test-Path -LiteralPath $ResidualRoot -PathType Container)) {
            $ResidualUninstallers = @(Get-ChildItem -LiteralPath $ResidualRoot `
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
