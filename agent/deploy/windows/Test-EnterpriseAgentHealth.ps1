[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$MetadataPath = Join-Path (Join-Path $StateRoot $InstanceName) "instance.json"
if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)) {
    throw "Instance metadata is missing: $MetadataPath"
}
$Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Port = [int]$Metadata.port
$Uri = "http://127.0.0.1:$Port/api/v1/health"
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSeconds
if ([int]$Response.StatusCode -ne 200) {
    throw "Health endpoint returned HTTP $($Response.StatusCode)."
}
$Body = $Response.Content | ConvertFrom-Json
if ($Body.status -ne "ok" -or $Body.service -ne "enterprise-reporting-agent") {
    throw "Health response does not identify a healthy Enterprise Agent."
}
Write-Host "Healthy: $InstanceName at $Uri (version $($Body.version))"
$Body | ConvertTo-Json -Depth 8
