[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$RemoveWrapperFiles
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
    throw "Windows PowerShell 5.1 or later is required."
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function Assert-InstanceName {
    param([string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "Invalid InstanceName."
    }
    $BaseName = ($Value.Split('.')[0]).ToUpperInvariant()
    if (@(
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
        "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    ) -contains $BaseName) {
        throw "InstanceName is a reserved Windows device name."
    }
}

function Assert-NoReparseAncestors {
    param([string]$Name, [string]$FullPath)
    $Probe = $FullPath
    while (-not (Test-Path -LiteralPath $Probe)) {
        $Parent = [IO.Directory]::GetParent($Probe)
        if ($null -eq $Parent) { break }
        $Probe = $Parent.FullName
    }
    while (-not [string]::IsNullOrWhiteSpace($Probe)) {
        if (Test-Path -LiteralPath $Probe) {
            $Item = Get-Item -LiteralPath $Probe -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a symlink, junction, mount point or other reparse ancestor: $($Item.FullName)"
            }
        }
        $Root = [IO.Path]::GetPathRoot($Probe)
        if ($Probe.TrimEnd('\').Equals($Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $Parent = [IO.Directory]::GetParent($Probe)
        if ($null -eq $Parent) { break }
        $Probe = $Parent.FullName
    }
}

function Assert-SafeLocalFixedNtfsPath {
    param([string]$Name, [string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue.IndexOf([char]0) -ge 0 -or
        $PathValue -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Name must be supplied as an X:\ absolute local path. UNC and drive-relative paths are forbidden."
    }
    if ($PathValue.Substring(2).Contains(":")) {
        throw "$Name cannot contain an alternate data stream (ADS) path."
    }
    $Segments = @([Text.RegularExpressions.Regex]::Split($PathValue.Substring(3), '[\\/]'))
    foreach ($Segment in $Segments) {
        if ([string]::IsNullOrEmpty($Segment)) {
            throw "$Name cannot contain empty path segments or a trailing separator."
        }
        if ($Segment -eq "." -or $Segment -eq "..") {
            throw "$Name cannot contain dot path segments."
        }
        if ($Segment.EndsWith(" ") -or $Segment.EndsWith(".")) {
            throw "$Name cannot contain a path segment ending in a space or dot."
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if ($FullPath -notmatch '^[A-Za-z]:\\') {
        throw "$Name must resolve to an X:\ absolute local path."
    }
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.TrimEnd('\').Equals($Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name cannot be a filesystem root."
    }
    $DeviceId = $Root.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3) {
        throw "$Name must use a local fixed disk: $FullPath"
    }
    if (-not ([string]$Disk.FileSystem).Equals("NTFS", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must use an NTFS filesystem: $FullPath"
    }
    Assert-NoReparseAncestors -Name $Name -FullPath $FullPath
    return $FullPath.TrimEnd('\')
}

function Assert-OrdinaryDirectoryTree {
    param([string]$Name, [string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "$Name does not exist as a directory: $Root"
    }
    foreach ($Item in @((Get-Item -LiteralPath $Root -Force)) + @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse
    )) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Name contains a symlink, junction, mount point or other reparse point: $($Item.FullName)"
        }
    }
}

function Assert-OrdinaryFile {
    param([string]$Name, [string]$PathValue, [long]$MaximumBytes = 0)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
        throw "$Name is missing: $PathValue"
    }
    $Item = Get-Item -LiteralPath $PathValue -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Name cannot be a symlink or reparse point: $PathValue"
    }
    if ($MaximumBytes -gt 0 -and ($Item.Length -le 0 -or $Item.Length -gt $MaximumBytes)) {
        throw "$Name has an invalid size: $PathValue"
    }
}

function Assert-PathBelowRoot {
    param([string]$Name, [string]$PathValue, [string]$Root)
    $CanonicalPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $CanonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $CanonicalPath.StartsWith($CanonicalRoot + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must be located below StateRoot."
    }
}

function Read-JsonObject {
    param([string]$Name, [string]$PathValue, [long]$MaximumBytes)
    Assert-OrdinaryFile -Name $Name -PathValue $PathValue -MaximumBytes $MaximumBytes
    try {
        $Object = Get-Content -LiteralPath $PathValue -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "$Name is not valid JSON: $PathValue"
    }
    if ($null -eq $Object -or $Object -is [Array]) {
        throw "$Name must contain one JSON object: $PathValue"
    }
    return $Object
}

function Assert-StateRootOwnershipMarker {
    param([string]$Root)
    $MarkerPath = Join-Path $Root ".mineguard-enterprise-agent-instances.json"
    $Marker = Read-JsonObject -Name "StateRoot ownership marker" -PathValue $MarkerPath -MaximumBytes 65536
    $ExpectedProperties = @("format", "product", "canonical_path", "root_id", "created_utc")
    $ActualProperties = @($Marker.PSObject.Properties | ForEach-Object { $_.Name })
    if ($ActualProperties.Count -ne $ExpectedProperties.Count) {
        throw "StateRoot ownership marker has an unexpected schema."
    }
    foreach ($PropertyName in $ExpectedProperties) {
        if ($ActualProperties -notcontains $PropertyName) {
            throw "StateRoot ownership marker is missing $PropertyName."
        }
    }
    if ($Marker.format -ne "mineguard-enterprise-agent-state-root-v1" -or
        $Marker.product -ne "MineGuard Enterprise Agent") {
        throw "StateRoot ownership marker has the wrong product or format."
    }
    $MarkerCanonicalPath = Assert-SafeLocalFixedNtfsPath `
        -Name "StateRoot marker canonical_path" -PathValue ([string]$Marker.canonical_path)
    if (-not $MarkerCanonicalPath.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "StateRoot ownership marker does not identify this Agent state directory."
    }
    $RootId = [Guid]::Empty
    $CreatedUtc = [DateTimeOffset]::MinValue
    if (-not [Guid]::TryParseExact([string]$Marker.root_id, "D", [ref]$RootId) -or
        $RootId -eq [Guid]::Empty -or
        -not [DateTimeOffset]::TryParse([string]$Marker.created_utc, [ref]$CreatedUtc) -or
        $CreatedUtc.Offset -ne [TimeSpan]::Zero) {
        throw "StateRoot ownership marker contains an invalid identity or timestamp."
    }
}

function Read-ValidatedInstanceMetadata {
    param([string]$Root, [string]$Name)
    $InstanceRoot = Assert-SafeLocalFixedNtfsPath -Name "InstanceRoot" -PathValue (Join-Path $Root $Name)
    Assert-PathBelowRoot -Name "InstanceRoot" -PathValue $InstanceRoot -Root $Root
    Assert-OrdinaryDirectoryTree -Name "InstanceRoot" -Root $InstanceRoot
    $MetadataPath = Join-Path $InstanceRoot "instance.json"
    $Metadata = Read-JsonObject -Name "Instance metadata" -PathValue $MetadataPath -MaximumBytes 1048576
    foreach ($PropertyName in @(
        "format", "instance_name", "service_id", "port", "mine_id", "system_id",
        "config_path", "database_path", "acl_hardened"
    )) {
        if ($null -eq $Metadata.PSObject.Properties[$PropertyName]) {
            throw "Instance metadata is missing $PropertyName."
        }
    }
    $ExpectedServiceId = "MineGuardEnterpriseAgent-$Name"
    if ($Metadata.format -ne "mineguard-enterprise-agent-windows-instance-v1" -or
        -not ([string]$Metadata.instance_name).Equals($Name, [StringComparison]::Ordinal) -or
        -not ([string]$Metadata.service_id).Equals($ExpectedServiceId, [StringComparison]::Ordinal)) {
        throw "Instance metadata identity does not match the requested instance."
    }
    if ($Metadata.acl_hardened -isnot [bool] -or -not [bool]$Metadata.acl_hardened) {
        throw "Instance metadata does not prove ACL hardening."
    }
    $Port = 0
    if (-not [int]::TryParse([string]$Metadata.port, [ref]$Port) -or $Port -lt 1 -or $Port -gt 65535 -or
        [string]$Metadata.mine_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        [string]$Metadata.system_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "Instance metadata has invalid port or contract identifiers."
    }
    $ExpectedConfig = Join-Path $InstanceRoot "config\agent.env"
    $ExpectedDatabase = Join-Path $InstanceRoot "data\enterprise-agent.db"
    $MetadataConfig = Assert-SafeLocalFixedNtfsPath -Name "instance config_path" -PathValue ([string]$Metadata.config_path)
    $MetadataDatabase = Assert-SafeLocalFixedNtfsPath -Name "instance database_path" -PathValue ([string]$Metadata.database_path)
    Assert-PathBelowRoot -Name "instance config_path" -PathValue $MetadataConfig -Root $InstanceRoot
    Assert-PathBelowRoot -Name "instance database_path" -PathValue $MetadataDatabase -Root $InstanceRoot
    if (-not $MetadataConfig.Equals($ExpectedConfig, [StringComparison]::OrdinalIgnoreCase) -or
        -not $MetadataDatabase.Equals($ExpectedDatabase, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Instance metadata paths do not match the requested instance layout."
    }
    return [PSCustomObject]@{
        Root = $InstanceRoot
        ServiceId = $ExpectedServiceId
    }
}

function Get-RegisteredService {
    param([string]$ServiceId)
    $Services = @(Get-CimInstance Win32_Service -Filter "Name='$ServiceId'" -ErrorAction Stop)
    if ($Services.Count -gt 1) {
        throw "Multiple Win32_Service records unexpectedly use the same name: $ServiceId"
    }
    if ($Services.Count -eq 0) { return $null }
    return $Services[0]
}

function Get-ServiceExecutablePath {
    param([object]$Service, [string]$ServiceId)
    $PathName = ([string]$Service.PathName).Trim()
    if ($PathName -match '^"([^"\r\n]+)"\s*$') { return $Matches[1] }
    if ($PathName -match '^[^"\r\n]+$') { return $PathName }
    throw "Windows service $ServiceId has an unsafe or argument-bearing executable path."
}

function Assert-ServiceTargetsWrapper {
    param([object]$Service, [string]$ServiceId, [string]$ExpectedWrapper)
    $RegisteredRaw = Get-ServiceExecutablePath -Service $Service -ServiceId $ServiceId
    $RegisteredPath = Assert-SafeLocalFixedNtfsPath -Name "Win32_Service PathName" -PathValue $RegisteredRaw
    if (-not $RegisteredPath.Equals($ExpectedWrapper, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Windows service $ServiceId executable path does not equal the expected instance wrapper; refusing a same-name service hijack."
    }
}

function Wait-ServiceRecordAbsent {
    param([string]$ServiceId, [int]$Seconds)
    $Deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 200
        $Service = Get-RegisteredService -ServiceId $ServiceId
    } while ($null -ne $Service -and [DateTime]::UtcNow -lt $Deadline)
    if ($null -ne $Service) {
        throw "Windows service registration was not removed within $Seconds seconds: $ServiceId"
    }
}

Assert-InstanceName -Value $InstanceName

# Validate the raw caller-controlled path before GetFullPath can reinterpret it.
$StateRoot = Assert-SafeLocalFixedNtfsPath -Name "StateRoot" -PathValue $StateRoot
Assert-OrdinaryDirectoryTree -Name "StateRoot" -Root $StateRoot
Assert-StateRootOwnershipMarker -Root $StateRoot
$Instance = Read-ValidatedInstanceMetadata -Root $StateRoot -Name $InstanceName
$InstanceRoot = $Instance.Root
$ServiceId = $Instance.ServiceId
$ServiceDirectory = Assert-SafeLocalFixedNtfsPath -Name "Instance service directory" `
    -PathValue (Join-Path $InstanceRoot "service")
Assert-PathBelowRoot -Name "Instance service directory" -PathValue $ServiceDirectory -Root $InstanceRoot
Assert-OrdinaryDirectoryTree -Name "Instance service directory" -Root $ServiceDirectory
$WrapperBase = Join-Path $ServiceDirectory $ServiceId
$WrapperExecutable = Assert-SafeLocalFixedNtfsPath -Name "WinSW instance wrapper" -PathValue ($WrapperBase + ".exe")
$WrapperXml = Assert-SafeLocalFixedNtfsPath -Name "WinSW instance XML" -PathValue ($WrapperBase + ".xml")
Assert-PathBelowRoot -Name "WinSW instance wrapper" -PathValue $WrapperExecutable -Root $ServiceDirectory
Assert-PathBelowRoot -Name "WinSW instance XML" -PathValue $WrapperXml -Root $ServiceDirectory

$Service = Get-RegisteredService -ServiceId $ServiceId
if ($null -ne $Service) {
    Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $WrapperExecutable
}

if ($PSCmdlet.ShouldProcess($ServiceId, "stop and uninstall the exact registered Windows service")) {
    # Re-query immediately before every service mutation to resist name/path races.
    $Service = Get-RegisteredService -ServiceId $ServiceId
    if ($null -ne $Service) {
        Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $WrapperExecutable
        if (-not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Service -Name $ServiceId -Force -ErrorAction Stop
            $Deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 200
                $Service = Get-RegisteredService -ServiceId $ServiceId
                if ($null -eq $Service) { break }
                Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $WrapperExecutable
            } while (-not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase) -and
                [DateTime]::UtcNow -lt $Deadline)
            if ($null -ne $Service -and
                -not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase)) {
                throw "Windows service did not stop within 30 seconds: $ServiceId"
            }
        }
        $Service = Get-RegisteredService -ServiceId $ServiceId
        if ($null -ne $Service) {
            Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $WrapperExecutable
            & sc.exe delete $ServiceId | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe delete failed with exit code $LASTEXITCODE for $ServiceId"
            }
            Wait-ServiceRecordAbsent -ServiceId $ServiceId -Seconds 30
        }
    }

    if ($RemoveWrapperFiles) {
        if ($null -ne (Get-RegisteredService -ServiceId $ServiceId)) {
            throw "Wrapper files cannot be removed while the Windows service remains registered."
        }
        Assert-NoReparseAncestors -Name "Instance service directory" -FullPath $ServiceDirectory
        foreach ($ExactPath in @($WrapperXml, $WrapperExecutable)) {
            $LateService = Get-RegisteredService -ServiceId $ServiceId
            if ($null -ne $LateService) {
                Assert-ServiceTargetsWrapper -Service $LateService -ServiceId $ServiceId `
                    -ExpectedWrapper $WrapperExecutable
                throw "Wrapper files cannot be removed after a service registration reappeared."
            }
            if (Test-Path -LiteralPath $ExactPath) {
                Assert-OrdinaryFile -Name "Exact WinSW service file" -PathValue $ExactPath
                Remove-Item -LiteralPath $ExactPath -Force
            }
        }
    }
    Write-Host "Service removed. Configuration, database, evidence, logs and backups were preserved."
}
