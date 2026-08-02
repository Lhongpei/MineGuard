[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances")
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$Executable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
$Config = Join-Path (Join-Path (Join-Path $StateRoot $InstanceName) "config") "agent.env"
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "Agent executable is missing: $Executable"
}
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw "Instance configuration is missing: $Config"
}

Write-Host "Starting Enterprise Agent in the foreground. Ctrl+C stops it safely."
& $Executable "--env-file" $Config "serve"
exit $LASTEXITCODE
