[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedPurpose,
    [Parameter(Mandatory = $true)][string]$ExpectedPythonVersion,
    [Parameter(Mandatory = $true)][string]$ExpectedToolVersion
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:OS -ne "Windows_NT") {
    throw "Windows release input manifests must be verified on native Windows."
}
if ($ExpectedManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "ExpectedManifestSha256 must contain exactly 64 hexadecimal digits."
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
$ManifestPath = Get-SafeLocalNtfsPath `
    -Name 'ManifestPath' -PathValue $ManifestPath
if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "Root does not exist: $Root"
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "ManifestPath does not exist: $ManifestPath"
}
if ($ManifestPath.StartsWith(
        $Root + '\', [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "ManifestPath must be outside Root."
}
$ActualManifestSha256 = (Get-FileHash -LiteralPath $ManifestPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualManifestSha256 -ne $ExpectedManifestSha256.ToLowerInvariant()) {
    throw "ManifestPath does not match ExpectedManifestSha256."
}
try {
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
}
catch {
    throw "ManifestPath is not valid JSON: $($_.Exception.Message)"
}
if ([string]$Manifest.format -ne
        'mineguard-windows-file-set-manifest-v1' -or
    [string]$Manifest.purpose -ne $ExpectedPurpose -or
    [string]$Manifest.python -ne $ExpectedPythonVersion -or
    [string]$Manifest.tool -ne $ExpectedToolVersion -or
    [string]$Manifest.architecture -ne 'x64') {
    throw "The release input manifest identity does not match approved values."
}

$Expected = New-Object 'Collections.Generic.Dictionary[string,object]' `
    ([StringComparer]::OrdinalIgnoreCase)
foreach ($Entry in @($Manifest.files)) {
    $Relative = [string]$Entry.path
    $Parts = $Relative -split '/'
    if ([string]::IsNullOrWhiteSpace($Relative) -or
        [IO.Path]::IsPathRooted($Relative) -or
        $Relative.Contains('\') -or $Relative.Contains(':') -or
        $Parts -contains '.' -or $Parts -contains '..' -or
        [string]$Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        [long]$Entry.bytes -lt 0) {
        throw "Manifest contains an unsafe entry: $Relative"
    }
    if ($Expected.ContainsKey($Relative)) {
        throw "Manifest contains a duplicate entry: $Relative"
    }
    $Expected.Add($Relative, $Entry)
}
$Actual = New-Object 'Collections.Generic.Dictionary[string,object]' `
    ([StringComparer]::OrdinalIgnoreCase)
foreach ($Item in @((Get-Item -LiteralPath $Root -Force)) + @(
    Get-ChildItem -LiteralPath $Root -Force -Recurse
)) {
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Root contains a reparse point: $($Item.FullName)"
    }
}
foreach ($File in Get-ChildItem -LiteralPath $Root -File -Force -Recurse) {
    $Relative = $File.FullName.Substring($Root.Length + 1).Replace('\', '/')
    if ($Actual.ContainsKey($Relative)) {
        throw "Root contains a case-colliding path: $Relative"
    }
    $Actual.Add($Relative, $File)
}
if ($Expected.Count -eq 0 -or $Expected.Count -ne $Actual.Count) {
    throw "Root file set does not exactly match the approved manifest."
}
foreach ($Relative in $Expected.Keys) {
    if (-not $Actual.ContainsKey($Relative)) {
        throw "Root is missing an approved file: $Relative"
    }
    $File = $Actual[$Relative]
    $Entry = $Expected[$Relative]
    if ([long]$File.Length -ne [long]$Entry.bytes) {
        throw "Release input file size mismatch: $Relative"
    }
    $Hash = (Get-FileHash -LiteralPath $File.FullName `
        -Algorithm SHA256).Hash
    if (-not $Hash.Equals(
            [string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Release input file SHA-256 mismatch: $Relative"
    }
}
Write-Host "Approved release input manifest verified: $ExpectedPurpose"
Write-Host "Files: $($Actual.Count)"
Write-Host "Manifest SHA-256: $ActualManifestSha256"
