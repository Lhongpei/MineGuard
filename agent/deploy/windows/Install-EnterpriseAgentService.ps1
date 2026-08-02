[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$WinSWPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$WinSWExpectedSha256,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$AllowIncompleteDemo,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function ConvertTo-XmlText {
    param([string]$Value)
    return [Security.SecurityElement]::Escape($Value)
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath"
    }
}

if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$WinSWPath = [IO.Path]::GetFullPath($WinSWPath)
if (-not (Test-Path -LiteralPath $WinSWPath -PathType Leaf)) {
    throw "WinSW executable does not exist: $WinSWPath"
}
$ActualWinSWHash = (Get-FileHash -LiteralPath $WinSWPath -Algorithm SHA256).Hash
if (-not $ActualWinSWHash.Equals($WinSWExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "WinSW SHA-256 does not match the approved value."
}
$InstanceRoot = Join-Path $StateRoot $InstanceName
$MetadataPath = Join-Path $InstanceRoot "instance.json"
$ConfigPath = Join-Path (Join-Path $InstanceRoot "config") "agent.env"
$TemplatePath = Join-Path $InstallRoot "deploy\windows\enterprise-agent-service.xml.template"
$AgentExecutable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
foreach ($Required in @($MetadataPath, $ConfigPath, $TemplatePath, $AgentExecutable)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required file is missing: $Required"
    }
}
$Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not [bool]$Metadata.acl_hardened) {
    throw "Service installation refuses an instance created with -SkipAcl. Recreate it with ACL hardening."
}
$CheckArguments = @("--env-file", $ConfigPath, "config-check")
if (-not $AllowIncompleteDemo) {
    $CheckArguments += "--production"
}
Invoke-NativeChecked -FilePath $AgentExecutable -ArgumentList $CheckArguments
if ($AllowIncompleteDemo) {
    Write-Warning "Installing an incomplete loopback demo service. It is not production-ready."
}
$ServiceId = [string]$Metadata.service_id
if (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue) {
    throw "Windows service already exists: $ServiceId"
}

$ServiceDirectory = Join-Path $InstanceRoot "service"
$LogDirectory = Join-Path $InstanceRoot "logs"
New-Item -ItemType Directory -Path $ServiceDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
$WrapperBase = Join-Path $ServiceDirectory $ServiceId
$WrapperExecutable = "$WrapperBase.exe"
$WrapperXml = "$WrapperBase.xml"
Copy-Item -LiteralPath $WinSWPath -Destination $WrapperExecutable -Force

$Xml = [IO.File]::ReadAllText($TemplatePath)
$Replacements = @{
    "__SERVICE_ID__" = (ConvertTo-XmlText $ServiceId)
    "__SERVICE_NAME__" = (ConvertTo-XmlText ("MineGuard Enterprise Agent - " + $InstanceName))
    "__INSTANCE_NAME__" = (ConvertTo-XmlText $InstanceName)
    "__EXECUTABLE__" = (ConvertTo-XmlText $AgentExecutable)
    "__ENV_FILE__" = (ConvertTo-XmlText $ConfigPath)
    "__WORKING_DIRECTORY__" = (ConvertTo-XmlText $InstanceRoot)
    "__LOG_DIRECTORY__" = (ConvertTo-XmlText $LogDirectory)
}
foreach ($Entry in $Replacements.GetEnumerator()) {
    $Xml = $Xml.Replace([string]$Entry.Key, [string]$Entry.Value)
}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($WrapperXml, $Xml, $Utf8NoBom)

Invoke-NativeChecked -FilePath $WrapperExecutable -ArgumentList @("install")
if ($Start) {
    Invoke-NativeChecked -FilePath $WrapperExecutable -ArgumentList @("start")
}
Write-Host "Windows service installed: $ServiceId"
Write-Host "WinSW was supplied locally and was not downloaded by this script."
Write-Host "No user password or application secret was written to service XML or arguments."
