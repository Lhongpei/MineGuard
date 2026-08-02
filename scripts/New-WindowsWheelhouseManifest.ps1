[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Wheelhouse,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$PythonVersion = "3.12",
    [ValidateSet("x64")][string]$Architecture = "x64"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:OS -ne "Windows_NT") {
    throw "Wheelhouse evidence for the Windows release must be created on native Windows."
}
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw "Windows PowerShell 5.1 or later is required."
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
            $Part.Contains(':') -or $Part.EndsWith(' ') -or $Part.EndsWith('.')) {
            throw "$Name contains an unsafe or ambiguous path component."
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrWhiteSpace($Root) -or
        $FullPath.Equals($Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must not be a filesystem root."
    }
    $DeviceId = $Root.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3 -or
        -not ([string]$Disk.FileSystem).Equals('NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must use a local fixed NTFS disk."
    }
    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a symlink, junction or reparse-point component: $Current"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) { break }
        $ParentPath = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($ParentPath)) {
            throw "$Name path ancestry cannot be resolved safely."
        }
        $Current = $ParentPath
    }
    return $FullPath
}

$Wheelhouse = Get-SafeLocalNtfsPath -Name "Wheelhouse" -PathValue $Wheelhouse
$OutputPath = Get-SafeLocalNtfsPath -Name "OutputPath" -PathValue $OutputPath
if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
    throw "Wheelhouse does not exist: $Wheelhouse"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "OutputPath already exists; refusing to overwrite supply-chain evidence: $OutputPath"
}
$WheelhousePrefix = $Wheelhouse + '\'
if ($OutputPath.StartsWith($WheelhousePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath must be outside the wheelhouse to avoid a circular file-set hash."
}
if ($PythonVersion -notmatch '^3\.12(?:\.|$)') {
    throw "The current Windows release baseline requires CPython 3.12."
}

foreach ($Item in @((Get-Item -LiteralPath $Wheelhouse -Force)) + @(
    Get-ChildItem -LiteralPath $Wheelhouse -Force -Recurse
)) {
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Wheelhouse contains a symlink, junction or reparse point: $($Item.FullName)"
    }
}

$Files = @()
foreach ($File in Get-ChildItem -LiteralPath $Wheelhouse -File -Force -Recurse | Sort-Object FullName) {
    $Relative = $File.FullName.Substring($Wheelhouse.Length + 1).Replace('\', '/')
    if ($File.Extension.ToLowerInvariant() -ne ".whl") {
        throw "Wheelhouse must contain only built wheel files: $Relative"
    }
    $Files += [ordered]@{
        path = $Relative
        bytes = [long]$File.Length
        sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
if ($Files.Count -eq 0) {
    throw "Wheelhouse contains no wheel files."
}

$Manifest = [ordered]@{
    format = "mineguard-wheelhouse-manifest-v1"
    generated_utc = [DateTime]::UtcNow.ToString("o")
    python = $PythonVersion
    architecture = $Architecture
    files = $Files
}
$Parent = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
    New-Item -ItemType Directory -Path $Parent -Force | Out-Null
}
$OutputPath = Get-SafeLocalNtfsPath -Name "OutputPath" -PathValue $OutputPath
$ManifestBytes = (New-Object Text.UTF8Encoding($false)).GetBytes(
    (($Manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
)
$TemporaryOutput = Get-SafeLocalNtfsPath -Name "TemporaryOutput" -PathValue (
    Join-Path $Parent ("." + [IO.Path]::GetFileName($OutputPath) +
        ".incoming." + [Guid]::NewGuid().ToString("N"))
)
$ManifestStream = [IO.File]::Open(
    $TemporaryOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try {
    $ManifestStream.Write($ManifestBytes, 0, $ManifestBytes.Length)
    $ManifestStream.Flush($true)
    $ManifestStream.Dispose()
    $ManifestStream = $null
    [IO.File]::Move($TemporaryOutput, $OutputPath)
}
finally {
    if ($null -ne $ManifestStream) { $ManifestStream.Dispose() }
    if (Test-Path -LiteralPath $TemporaryOutput -PathType Leaf) {
        Remove-Item -LiteralPath $TemporaryOutput -Force
    }
}
Write-Host "Wheelhouse supply-chain manifest created: $OutputPath"
Write-Host "Files: $($Files.Count)"
Write-Host "Manifest SHA-256: $((Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant())"
