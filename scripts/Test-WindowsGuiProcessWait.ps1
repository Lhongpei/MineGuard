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
}
finally {
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
