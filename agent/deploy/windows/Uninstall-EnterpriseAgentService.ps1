[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$RemoveWrapperFiles
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$InstanceRoot = Join-Path ([IO.Path]::GetFullPath($StateRoot)) $InstanceName
$MetadataPath = Join-Path $InstanceRoot "instance.json"
if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)) {
    throw "Instance metadata is missing: $MetadataPath"
}
$Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$ServiceId = [string]$Metadata.service_id
$WrapperBase = Join-Path (Join-Path $InstanceRoot "service") $ServiceId
$WrapperExecutable = "$WrapperBase.exe"
if (-not (Test-Path -LiteralPath $WrapperExecutable -PathType Leaf)) {
    throw "WinSW wrapper is missing: $WrapperExecutable"
}
if ($PSCmdlet.ShouldProcess($ServiceId, "stop and uninstall Windows service")) {
    $Service = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
    if ($null -ne $Service -and $Service.Status -ne "Stopped") {
        & $WrapperExecutable "stop"
        if ($LASTEXITCODE -ne 0) { throw "WinSW stop failed." }
    }
    if ($null -ne (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue)) {
        & $WrapperExecutable "uninstall"
        if ($LASTEXITCODE -ne 0) { throw "WinSW uninstall failed." }
    }
    if ($RemoveWrapperFiles) {
        Remove-Item -LiteralPath $WrapperExecutable -Force
        $WrapperXml = "$WrapperBase.xml"
        if (Test-Path -LiteralPath $WrapperXml -PathType Leaf) {
            Remove-Item -LiteralPath $WrapperXml -Force
        }
    }
    Write-Host "Service removed. Configuration, database, evidence and backups were preserved."
}
