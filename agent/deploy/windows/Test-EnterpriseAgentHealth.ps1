[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$SafetyHelper = Join-Path $PSScriptRoot "EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $SafetyHelper -PathType Leaf)) {
    throw "Windows safety helper is missing: $SafetyHelper"
}
. $SafetyHelper
Assert-EAPowerShell51

$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
# A generic Agent response on the same port is insufficient. Bind the probe to
# the selected service wrapper or foreground process before accepting HTTP health.
Assert-EAInstanceIsRunning -Context $Context
$Uri = "http://127.0.0.1:$($Context.Port)/api/v1/health"
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSeconds
if ([int]$Response.StatusCode -ne 200) {
    throw "Health endpoint returned HTTP $($Response.StatusCode)."
}
try { $Body = $Response.Content | ConvertFrom-Json }
catch { throw "Health endpoint did not return valid JSON." }
if ($null -eq $Body -or $Body.status -ne "ok" -or
    $Body.service -ne "enterprise-reporting-agent" -or
    $Body.contract_version -ne "enterprise-submission-v1" -or
    $Body.primary_contract_version -ne "ten-quantity-submission-v3" -or
    [string]::IsNullOrWhiteSpace([string]$Body.version)) {
    throw "Health response does not identify the expected Enterprise Agent contract."
}
Write-Host "Healthy: $InstanceName at $Uri (version $($Body.version))"
$Body | ConvertTo-Json -Depth 8
