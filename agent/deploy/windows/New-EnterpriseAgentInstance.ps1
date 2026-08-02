[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$MineId,
    [Parameter(Mandatory = $true)][string]$MineName,
    [Parameter(Mandatory = $true)][string]$OperatorId,
    [Parameter(Mandatory = $true)][string]$OperatorName,
    [Parameter(Mandatory = $true)][string]$SystemId,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string[]]$WatchDirectories = @(),
    [switch]$GrantWatchReadAcl,
    [switch]$SkipAcl
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if (-not $SkipAcl) {
    $Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run in an elevated Administrator PowerShell, or use -SkipAcl only for local development."
    }
}

function Assert-InstanceName {
    param([string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "InstanceName must be 1-64 ASCII letters, digits, dot, underscore or dash."
    }
    $BaseName = ($Value.Split('.')[0]).ToUpperInvariant()
    $Reserved = @("CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9")
    if ($Reserved -contains $BaseName) {
        throw "InstanceName is a reserved Windows device name."
    }
}

function Assert-EnvironmentValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "$Name must be non-empty and contain no control characters."
    }
}

function Assert-ContractIdentifier {
    param([string]$Name, [string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "$Name must match the V2 identifier format and be at most 128 characters."
    }
}

function Assert-DisplayName {
    param([string]$Name, [string]$Value)
    Assert-EnvironmentValue -Name $Name -Value $Value
    if ($Value.Length -gt 256) {
        throw "$Name must be at most 256 characters."
    }
}

function Assert-LocalFixedPath {
    param([string]$PathValue)
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if ($FullPath.StartsWith("\\")) {
        throw "Agent state must not use a UNC/network path: $FullPath"
    }
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ($Root -match '^([A-Za-z]):\\$') {
        $DeviceId = $Matches[1] + ":"
        $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction SilentlyContinue
        if ($null -ne $Disk -and [int]$Disk.DriveType -ne 3) {
            throw "Agent state must use a local fixed disk: $FullPath"
        }
    }
}

function Invoke-IcaclsChecked {
    param([string[]]$ArgumentList)
    & icacls.exe @ArgumentList | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
}

Assert-InstanceName -Value $InstanceName
Assert-ContractIdentifier -Name "MineId" -Value $MineId
Assert-DisplayName -Name "MineName" -Value $MineName
Assert-ContractIdentifier -Name "OperatorId" -Value $OperatorId
Assert-DisplayName -Name "OperatorName" -Value $OperatorName
Assert-ContractIdentifier -Name "SystemId" -Value $SystemId
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
Assert-LocalFixedPath -PathValue $StateRoot
if (-not (Test-Path -LiteralPath $StateRoot -PathType Container)) {
    throw "StateRoot does not exist. Run Install-EnterpriseAgent.ps1 first."
}
$StateRootItem = Get-Item -LiteralPath $StateRoot -Force
if (($StateRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "StateRoot cannot be a symlink, junction or reparse point."
}

$AgentExecutable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
$Template = Join-Path $InstallRoot "deploy\windows\agent.env.template"
if (-not (Test-Path -LiteralPath $AgentExecutable -PathType Leaf)) {
    throw "Installed Agent executable is missing: $AgentExecutable"
}
if (-not (Test-Path -LiteralPath $Template -PathType Leaf)) {
    throw "Instance template is missing: $Template"
}

$InstanceRoot = Join-Path $StateRoot $InstanceName
if (Test-Path -LiteralPath $InstanceRoot) {
    throw "Instance already exists: $InstanceRoot"
}
foreach ($ExistingConfig in Get-ChildItem -LiteralPath $StateRoot -Filter "agent.env" -File -Recurse -ErrorAction SilentlyContinue) {
    foreach ($Line in Get-Content -LiteralPath $ExistingConfig.FullName) {
        if ($Line -match '^ENTERPRISE_AGENT_PORT=([0-9]+)$' -and [int]$Matches[1] -eq $Port) {
            throw "Port $Port is already assigned by $($ExistingConfig.FullName)"
        }
    }
}

$ConfigDirectory = Join-Path $InstanceRoot "config"
$DataDirectory = Join-Path $InstanceRoot "data"
$LogDirectory = Join-Path $InstanceRoot "logs"
$BackupDirectory = Join-Path $InstanceRoot "backups"
$InboxDirectory = Join-Path $InstanceRoot "inbox"
$ServiceDirectory = Join-Path $InstanceRoot "service"
foreach ($Directory in @($ConfigDirectory, $DataDirectory, $LogDirectory, $BackupDirectory, $InboxDirectory, $ServiceDirectory)) {
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
}
$UsingDefaultInbox = $WatchDirectories.Count -eq 0
if ($UsingDefaultInbox) {
    $WatchDirectories = @($InboxDirectory)
}
$ResolvedWatchDirectories = @()
foreach ($WatchDirectory in $WatchDirectories) {
    if ([string]::IsNullOrWhiteSpace($WatchDirectory) -or $WatchDirectory.Contains(";")) {
        throw "Watch directory must be non-empty and cannot contain a semicolon."
    }
    $ResolvedWatch = [IO.Path]::GetFullPath($WatchDirectory)
    if (-not (Test-Path -LiteralPath $ResolvedWatch -PathType Container)) {
        throw "Watch directory does not exist: $ResolvedWatch"
    }
    $WatchItem = Get-Item -LiteralPath $ResolvedWatch -Force
    if (($WatchItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Watch directory cannot be a symlink, junction or reparse point: $ResolvedWatch"
    }
    if ($ResolvedWatch.TrimEnd('\') -eq [IO.Path]::GetPathRoot($ResolvedWatch).TrimEnd('\')) {
        throw "Watch directory cannot be a filesystem root."
    }
    foreach ($ExistingWatch in $ResolvedWatchDirectories) {
        if ($ExistingWatch.Equals($ResolvedWatch, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Watch directories must be unique: $ResolvedWatch"
        }
    }
    $ResolvedWatchDirectories += $ResolvedWatch
}
$WatchValue = $ResolvedWatchDirectories -join ";"
$DatabasePath = Join-Path $DataDirectory "enterprise-agent.db"
$ConfigPath = Join-Path $ConfigDirectory "agent.env"
$Content = [IO.File]::ReadAllText($Template)
$Replacements = @{
    "__DATABASE_PATH__" = $DatabasePath
    "__PORT__" = $Port.ToString()
    "__MINE_ID__" = $MineId
    "__MINE_NAME__" = $MineName
    "__OPERATOR_ID__" = $OperatorId
    "__OPERATOR_NAME__" = $OperatorName
    "__SYSTEM_ID__" = $SystemId
    "__WATCH_DIRECTORIES__" = $WatchValue
}
foreach ($Entry in $Replacements.GetEnumerator()) {
    $Content = $Content.Replace([string]$Entry.Key, [string]$Entry.Value)
}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($ConfigPath, $Content, $Utf8NoBom)

$ServiceId = "MineGuardEnterpriseAgent-$InstanceName"
$Metadata = [ordered]@{
    format = "mineguard-enterprise-agent-windows-instance-v1"
    instance_name = $InstanceName
    service_id = $ServiceId
    port = $Port
    mine_id = $MineId
    system_id = $SystemId
    config_path = $ConfigPath
    database_path = $DatabasePath
    acl_hardened = (-not $SkipAcl.IsPresent)
}
[IO.File]::WriteAllText(
    (Join-Path $InstanceRoot "instance.json"),
    (($Metadata | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    $Utf8NoBom
)

if (-not $SkipAcl) {
    Invoke-IcaclsChecked -ArgumentList @($InstanceRoot, "/inheritance:r")
    Invoke-IcaclsChecked -ArgumentList @($InstanceRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX", "/T", "/C")
    foreach ($Writable in @($DataDirectory, $LogDirectory)) {
        Invoke-IcaclsChecked -ArgumentList @($Writable, "/grant:r", "*S-1-5-19:(OI)(CI)M", "/T", "/C")
    }
    Invoke-IcaclsChecked -ArgumentList @($BackupDirectory, "/inheritance:r")
    Invoke-IcaclsChecked -ArgumentList @($BackupDirectory, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C")
    if (-not $UsingDefaultInbox) {
        if ($GrantWatchReadAcl) {
            foreach ($WatchDirectory in $ResolvedWatchDirectories) {
                Invoke-IcaclsChecked -ArgumentList @($WatchDirectory, "/grant", "*S-1-5-19:(OI)(CI)RX", "/T", "/C")
            }
        }
        else {
            Write-Warning "Custom watch directories were not modified. Grant LocalService SID S-1-5-19 read access before service startup."
        }
    }
}
else {
    Write-Warning "ACL hardening was skipped. Do not use this instance in production."
}

Write-Host "Enterprise Agent instance created: $InstanceName"
Write-Host "Config: $ConfigPath"
Write-Host "Database: $DatabasePath"
Write-Host "Port: $Port"
Write-Host "Edit the ACL-protected config, then run Start-EnterpriseAgent.ps1."
