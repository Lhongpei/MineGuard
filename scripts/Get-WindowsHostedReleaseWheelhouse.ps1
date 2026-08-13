[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PythonExecutable,
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$Wheelhouse
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
$env:PIP_NO_INPUT = "1"
$env:PIP_CONFIG_FILE = [IO.Path]::GetTempFileName()

if ($env:OS -ne "Windows_NT") {
    throw "The hosted release wheelhouse must be prepared on native Windows."
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

$PythonExecutable = Get-SafeLocalNtfsPath `
    -Name 'PythonExecutable' -PathValue $PythonExecutable
$RepositoryRoot = Get-SafeLocalNtfsPath `
    -Name 'RepositoryRoot' -PathValue $RepositoryRoot
$Wheelhouse = Get-SafeLocalNtfsPath `
    -Name 'Wheelhouse' -PathValue $Wheelhouse
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "PythonExecutable does not exist."
}
$PythonIdentity = & $PythonExecutable -c (
    'import platform,struct;print(platform.python_version()+chr(124)+' +
    'str(struct.calcsize(chr(80))*8))'
)
if ($LASTEXITCODE -ne 0 -or
    ([string]$PythonIdentity).Trim() -notmatch '^3\.12\.\d+\|64$') {
    throw "PythonExecutable must be an exact CPython 3.12 x64 interpreter."
}
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "RepositoryRoot does not exist."
}
if (Test-Path -LiteralPath $Wheelhouse) {
    throw "Wheelhouse must not exist before qualification."
}
if ($Wheelhouse.StartsWith(
        $RepositoryRoot + '\', [StringComparison]::OrdinalIgnoreCase
    ) -or $RepositoryRoot.StartsWith(
        $Wheelhouse + '\', [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Wheelhouse and RepositoryRoot must not overlap."
}
New-Item -ItemType Directory -Path $Wheelhouse | Out-Null

$Inputs = @(
    'platform\packaging\windows\requirements-build.txt',
    'agent\packaging\windows\build-requirements.txt',
    'platform\constraints.txt',
    'agent\constraints.txt'
)
foreach ($Relative in $Inputs) {
    $InputPath = Join-Path $RepositoryRoot $Relative
    if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
        throw "Pinned dependency input is missing: $Relative"
    }
}
foreach ($Relative in $Inputs) {
    $Arguments = @(
        '-m', 'pip', '--isolated', '--no-cache-dir', 'wheel',
        '--disable-pip-version-check', '--no-input', '--prefer-binary',
        '--wheel-dir', $Wheelhouse,
        '--requirement', (Join-Path $RepositoryRoot $Relative)
    )
    & $PythonExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned hosted release wheel build failed: $Relative"
    }
}
$Items = @((Get-Item -LiteralPath $Wheelhouse -Force)) + @(
    Get-ChildItem -LiteralPath $Wheelhouse -Force -Recurse
)
if (@($Items | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -ne 0) {
    throw "Hosted release wheelhouse must not contain reparse points."
}
$Files = @(Get-ChildItem -LiteralPath $Wheelhouse -File -Force -Recurse)
if ($Files.Count -eq 0 -or @($Files | Where-Object {
        $_.Extension.ToLowerInvariant() -ne '.whl'
    }).Count -ne 0 -or @($Items | Where-Object {
        $_.PSIsContainer -and $_.FullName -ne $Wheelhouse
    }).Count -ne 0) {
    throw "Hosted release wheelhouse must contain only wheel files."
}
Write-Host "Hosted release wheelhouse prepared: $Wheelhouse"
Write-Host "Wheels: $($Files.Count)"
