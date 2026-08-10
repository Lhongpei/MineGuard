[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$SafetyHelper = Join-Path $PSScriptRoot "EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $SafetyHelper -PathType Leaf)) {
    throw "Windows safety helper is missing: $SafetyHelper"
}
. $SafetyHelper
Assert-EAPowerShell51

# The shared context resolves the runtime\MineGuardEnterpriseAgent.exe contract,
# validates the StateRoot marker, and binds config/database identity to this mine.
$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
$ServiceContext = Get-EAServiceContext -Context $Context
if ($null -ne $ServiceContext -and $ServiceContext.Service.Status -ne "Stopped") {
    throw "Windows service $($Context.ServiceId) is not stopped. Do not run a second foreground instance."
}
Assert-EANoInstanceProcesses -Context $Context

Write-Host "Starting Enterprise Agent in the foreground. Ctrl+C stops it safely."
# Recheck immediately before process creation to narrow the validation/use race.
Assert-EANoInstanceProcesses -Context $Context
# Foreground operation has no WinSW policy envelope. Remove any machine-level
# values using these reserved names before the authoritative loader runs.
foreach ($PolicyName in @(
    "MINEGUARD_SERVICE_PRODUCTION_MODE",
    "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED"
)) {
    [Environment]::SetEnvironmentVariable(
        $PolicyName, $null, [EnvironmentVariableTarget]::Process
    )
}
& $Context.Executable "--env-file" $Context.ConfigPath `
    "--authoritative-env-file" "serve"
exit $LASTEXITCODE
