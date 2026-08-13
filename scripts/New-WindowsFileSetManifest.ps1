[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$Purpose,
    [Parameter(Mandatory = $true)][string]$PythonVersion,
    [Parameter(Mandatory = $true)][string]$ToolVersion
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:OS -ne "Windows_NT") {
    throw "Windows release input manifests must be created on native Windows."
}
if ($Purpose -notmatch '^[a-z0-9][a-z0-9-]{2,63}$') {
    throw "Purpose must be a lowercase release-input identifier."
}
if ($PythonVersion -notmatch '^3\.12\.\d+$') {
    throw "PythonVersion must be an exact CPython 3.12 patch."
}
if ($ToolVersion -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') {
    throw "ToolVersion must be an exact numeric version."
}

function Get-SafeLocalNtfsPath {
    param([string]$Name, [string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue -ne $PathValue.Trim() -or
        $PathValue -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Name must be supplied as an X:\\ absolute local path."
    }
    foreach ($Part in $PathValue.Substring(3) -split '[\\/]') {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @('.', '..') -or
            $Part.Contains(':') -or $Part.EndsWith(' ') -or
            $Part.EndsWith('.')) {
            throw "$Name contains an unsafe or ambiguous path component."
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $Volume = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrWhiteSpace($Volume) -or $FullPath.Equals(
            $Volume.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must not be a filesystem root."
    }
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter (
        "DeviceID='" + $Volume.Substring(0, 2) + "'"
    ) -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3 -or
        -not ([string]$Disk.FileSystem).Equals(
            'NTFS', [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Name must use a local fixed NTFS disk."
    }
    $Current = $FullPath
    $VolumeRoot = $Volume.TrimEnd('\')
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a reparse point: $Current"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $VolumeRoot, [StringComparison]::OrdinalIgnoreCase
            )) { break }
        $Current = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($Current)) {
            throw "$Name path ancestry cannot be resolved safely."
        }
    }
    return $FullPath
}

$Root = Get-SafeLocalNtfsPath -Name 'Root' -PathValue $Root
$OutputPath = Get-SafeLocalNtfsPath -Name 'OutputPath' -PathValue $OutputPath
if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "Root does not exist: $Root"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "OutputPath already exists; refusing to overwrite evidence."
}
if ($OutputPath.StartsWith(
        $Root + '\', [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "OutputPath must be outside Root to avoid a circular manifest."
}

$Files = @()
foreach ($Item in @((Get-Item -LiteralPath $Root -Force)) + @(
    Get-ChildItem -LiteralPath $Root -Force -Recurse
)) {
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Root contains a reparse point: $($Item.FullName)"
    }
}
foreach ($File in Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
    Sort-Object FullName) {
    $Relative = $File.FullName.Substring($Root.Length + 1).Replace('\', '/')
    $Files += [ordered]@{
        path = $Relative
        bytes = [long]$File.Length
        sha256 = (Get-FileHash -LiteralPath $File.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
if ($Files.Count -eq 0) {
    throw "Root contains no files."
}

$Manifest = [ordered]@{
    format = "mineguard-windows-file-set-manifest-v1"
    purpose = $Purpose
    python = $PythonVersion
    tool = $ToolVersion
    architecture = "x64"
    files = $Files
}
$Parent = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
    New-Item -ItemType Directory -Path $Parent -Force | Out-Null
}
$Bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(
    (($Manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
)
$Temporary = Join-Path $Parent (
    '.' + [IO.Path]::GetFileName($OutputPath) + '.incoming.' +
    [Guid]::NewGuid().ToString('N')
)
$Stream = [IO.File]::Open(
    $Temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try {
    $Stream.Write($Bytes, 0, $Bytes.Length)
    $Stream.Flush($true)
    $Stream.Dispose()
    $Stream = $null
    [IO.File]::Move($Temporary, $OutputPath)
}
finally {
    if ($null -ne $Stream) { $Stream.Dispose() }
    if (Test-Path -LiteralPath $Temporary -PathType Leaf) {
        Remove-Item -LiteralPath $Temporary -Force
    }
}
Write-Host "Release input manifest created: $OutputPath"
Write-Host "Files: $($Files.Count)"
Write-Host "Manifest SHA-256: $((Get-FileHash -LiteralPath $OutputPath `
    -Algorithm SHA256).Hash.ToLowerInvariant())"
