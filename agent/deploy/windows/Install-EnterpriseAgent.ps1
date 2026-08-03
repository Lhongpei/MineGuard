[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [Alias("ReleaseRoot")][string]$SourceRoot = "",
    [switch]$BuildFromSource,
    [string]$PythonCommand = "py",
    [string[]]$PythonArguments = @("-3.12"),
    [string]$Wheelhouse = "",
    [switch]$AuditFailAfterRuntimeSwitch
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw "Windows PowerShell 5.1 or later is required."
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Assert-EAOwnedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$AllowedLeafPattern
    )
    $FullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $FullParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $ActualParent = [IO.Path]::GetDirectoryName($FullPath)
    $Leaf = [IO.Path]::GetFileName($FullPath)
    if (-not $ActualParent.Equals(
            $FullParent, [StringComparison]::OrdinalIgnoreCase
        ) -or -not [regex]::IsMatch(
            $Leaf,
            $AllowedLeafPattern,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )) {
        throw "Refusing to operate on a path not owned by this transaction: $FullPath"
    }
    if (Test-Path -LiteralPath $FullPath) {
        $Item = Get-Item -LiteralPath $FullPath -Force
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to operate on a reparse point: $FullPath"
        }
    }
}

function Remove-EAOwnedPathWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$AllowedLeafPattern,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 60
    )
    Assert-EAOwnedPath -Path $Path -ExpectedParent $ExpectedParent `
        -AllowedLeafPattern $AllowedLeafPattern
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $LastError = $null
    while ($true) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            $Item = Get-Item -LiteralPath $Path -Force
            if ($Item.PSIsContainer) {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            }
            else {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
        }
        catch {
            $LastError = $_
        }
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ([DateTime]::UtcNow -ge $Deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $Detail = if ($null -eq $LastError) {
        "the path still exists"
    }
    else {
        $LastError.Exception.Message
    }
    throw "Unable to remove transaction path within $TimeoutSeconds seconds: $Path. Last error: $Detail"
}

function Move-EAOwnedPathWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$SourceParent,
        [Parameter(Mandatory = $true)][string]$SourceLeafPattern,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$DestinationParent,
        [Parameter(Mandatory = $true)][string]$DestinationLeafPattern,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 60
    )
    Assert-EAOwnedPath -Path $SourcePath -ExpectedParent $SourceParent `
        -AllowedLeafPattern $SourceLeafPattern
    Assert-EAOwnedPath -Path $DestinationPath `
        -ExpectedParent $DestinationParent `
        -AllowedLeafPattern $DestinationLeafPattern
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Transaction source does not exist: $SourcePath"
    }
    if (Test-Path -LiteralPath $DestinationPath) {
        throw "Transaction destination already exists; refusing overwrite: $DestinationPath"
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $LastError = $null
    $MoveAttempted = $false
    while ($true) {
        if (-not (Test-Path -LiteralPath $SourcePath)) {
            if ($MoveAttempted -and
                (Test-Path -LiteralPath $DestinationPath)) { return }
            throw "Transaction source and destination are both absent: $SourcePath -> $DestinationPath"
        }
        if (Test-Path -LiteralPath $DestinationPath) {
            throw "Transaction destination already exists; refusing overwrite: $DestinationPath"
        }
        try {
            $MoveAttempted = $true
            Move-Item -LiteralPath $SourcePath -Destination $DestinationPath `
                -ErrorAction Stop
        }
        catch {
            $LastError = $_
        }
        if (-not (Test-Path -LiteralPath $SourcePath) -and
            (Test-Path -LiteralPath $DestinationPath)) {
            return
        }
        if ([DateTime]::UtcNow -ge $Deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $Detail = if ($null -eq $LastError) {
        "the move did not complete"
    }
    else {
        $LastError.Exception.Message
    }
    throw "Unable to move transaction path within $TimeoutSeconds seconds: $SourcePath. Last error: $Detail"
}

function Assert-EABinaryInstallPathBudget {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object]$Manifest,
        [ValidateRange(200, 259)][int]$MaximumPathLength = 240
    )
    $SyntheticGuid = "f" * 32
    $LongestPath = $Root
    foreach ($Entry in @($Manifest.files)) {
        $Relative = ([string]$Entry.path).Replace('\', '/')
        $TransactionLeaf = $null
        $TransactionRelative = $null
        if ($Relative.StartsWith(
                "runtime/", [StringComparison]::OrdinalIgnoreCase
            )) {
            $TransactionLeaf = ".runtime-rollback-" + $SyntheticGuid
            $TransactionRelative = $Relative.Substring("runtime/".Length)
        }
        elseif ($Relative.StartsWith(
                "deploy/windows/", [StringComparison]::OrdinalIgnoreCase
            )) {
            $TransactionLeaf = ".deploy-rollback-" + $SyntheticGuid
            $TransactionRelative = $Relative.Substring("deploy/windows/".Length)
        }
        elseif ($Relative -in @(
                "VERSION.txt", "build-metadata.json", "release-manifest.json",
                "SHA256SUMS.txt"
            )) {
            $TransactionLeaf = ".release-metadata-rollback-" + $SyntheticGuid
            $TransactionRelative = $Relative
        }
        if ($null -eq $TransactionLeaf) { continue }
        $Projected = Join-Path (Join-Path $Root $TransactionLeaf) `
            $TransactionRelative.Replace('/', '\')
        if ($Projected.Length -gt $LongestPath.Length) {
            $LongestPath = $Projected
        }
    }
    if ($LongestPath.Length -gt $MaximumPathLength) {
        throw (
            "InstallRoot is too deep: this release needs a transaction path of " +
            "$($LongestPath.Length) characters, above the safe limit of " +
            "$MaximumPathLength. Choose a shorter InstallRoot."
        )
    }
}

function Assert-LocalFixedPath {
    param([string]$Name, [string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { throw "$Name cannot be empty." }
    if ($PathValue -ne $PathValue.Trim() -or $PathValue.Contains("/") -or
        $PathValue -notmatch '^[A-Za-z]:\\') {
        throw "$Name must be supplied as an X:\ absolute local path: $PathValue"
    }
    $PathWithoutTrailingSeparator = $PathValue.TrimEnd('\')
    if ($PathWithoutTrailingSeparator.Length -le 2) {
        throw "$Name must not be a filesystem root."
    }
    $PathParts = $PathWithoutTrailingSeparator.Substring(3) -split '\\'
    foreach ($Part in $PathParts) {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @(".", "..") -or
            $Part.EndsWith(" ") -or $Part.EndsWith(".")) {
            throw "$Name contains an empty, dot or ambiguous path component: $PathValue"
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if ($FullPath -notmatch '^[A-Za-z]:\\' -or
        $FullPath.StartsWith("\\") -or $FullPath.Substring(2).Contains(":")) {
        throw "$Name must use an X:\ absolute local path without alternate data streams: $FullPath"
    }
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.TrimEnd('\') -eq $Root.TrimEnd('\')) {
        throw "$Name must not be a filesystem root."
    }
    $DeviceId = $Root.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction Stop
    if ($null -eq $Disk) {
        throw "$Name drive metadata is unavailable: $FullPath"
    }
    if ([int]$Disk.DriveType -ne 3) {
        throw "$Name must use a local fixed disk: $FullPath"
    }
    if (-not ([string]$Disk.FileSystem).Equals("NTFS", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must use an NTFS filesystem: $FullPath"
    }

    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $CurrentItem = Get-Item -LiteralPath $Current -Force
            if (($CurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a symlink, junction or reparse-point component: $Current"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $Parent = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($Parent)) {
            throw "$Name path ancestry cannot be resolved safely: $FullPath"
        }
        $Current = $Parent
    }
}

function Assert-NoEnterpriseAgentRuntimeProcesses {
    param([string]$RuntimeDirectory)
    $ExpectedRoot = [IO.Path]::GetFullPath($RuntimeDirectory).TrimEnd('\')
    $ExpectedPrefix = $ExpectedRoot + '\'
    $Running = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        if ([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)) { return $false }
        try { $ProcessPath = [IO.Path]::GetFullPath([string]$_.ExecutablePath) }
        catch { return $false }
        return $ProcessPath.Equals($ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $ProcessPath.StartsWith($ExpectedPrefix, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($Running.Count -ne 0) {
        $Descriptions = @($Running | ForEach-Object {
            "PID=$($_.ProcessId) Name=$($_.Name) Path=$($_.ExecutablePath)"
        }) -join "; "
        throw "Stop every process running from the installed Agent runtime before replacement: $Descriptions"
    }
}

function Assert-SafeReleaseRelativePath {
    param([string]$Relative, [string]$Context)
    $Parts = $Relative -split '/'
    if ([string]::IsNullOrWhiteSpace($Relative) -or $Relative -ne $Relative.Trim() -or
        [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains("\") -or
        $Relative.Contains(":") -or $Parts -contains "." -or
        $Parts -contains ".." -or $Parts -contains "") {
        throw "$Context contains an unsafe relative path: $Relative"
    }
}

function Read-ReleaseChecksums {
    param([string]$ChecksumsPath)
    $ChecksumFile = Get-Item -LiteralPath $ChecksumsPath -Force
    if ($ChecksumFile.Length -gt 16MB) {
        throw "SHA256SUMS.txt exceeds the 16 MiB safety limit."
    }
    $Checksums = @{}
    $Lines = [IO.File]::ReadAllLines($ChecksumsPath, [Text.Encoding]::UTF8)
    if ($Lines.Count -eq 0) { throw "SHA256SUMS.txt cannot be empty." }
    foreach ($Line in $Lines) {
        $Match = [regex]::Match($Line, '^(?<sha>[A-Fa-f0-9]{64}) \*(?<path>.+)$')
        if (-not $Match.Success) {
            throw "SHA256SUMS.txt contains a malformed line."
        }
        $Relative = $Match.Groups["path"].Value
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "SHA256SUMS.txt"
        if ($Relative -eq "SHA256SUMS.txt" -or $Checksums.ContainsKey($Relative)) {
            throw "SHA256SUMS.txt contains a self-reference or duplicate path: $Relative"
        }
        $Checksums[$Relative] = $Match.Groups["sha"].Value.ToLowerInvariant()
    }
    return $Checksums
}

function Assert-OrdinaryTree {
    param([string]$Root)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Binary release root cannot be a symlink, junction or reparse point."
    }
    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Binary release contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
}

function Assert-NotBroadProductRoot {
    param([string]$Name, [string]$PathValue)
    $ProtectedCandidates = @(
        $env:ProgramData,
        $env:ALLUSERSPROFILE,
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:CommonProgramFiles,
        ${env:CommonProgramFiles(x86)},
        $env:PUBLIC
    )
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $ProtectedCandidates += Join-Path $env:SystemDrive "Users"
    }
    $Normalized = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    foreach ($Candidate in @($ProtectedCandidates | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })) {
        $Protected = [IO.Path]::GetFullPath([string]$Candidate).TrimEnd('\')
        if ($Normalized.Equals($Protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Name cannot be a broad Windows/system data directory: $Normalized"
        }
    }
}

function Assert-StateRootOrdinary {
    param([string]$Root)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "StateRoot cannot be a symlink, junction or reparse point."
    }
    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "StateRoot contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
}

function Assert-StateRootMarker {
    param([string]$Root)
    $MarkerPath = Join-Path $Root ".mineguard-enterprise-agent-instances.json"
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        throw "StateRoot ownership marker is missing: $MarkerPath"
    }
    $MarkerItem = Get-Item -LiteralPath $MarkerPath -Force
    if (($MarkerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $MarkerItem.Length -le 0 -or $MarkerItem.Length -gt 64KB) {
        throw "StateRoot ownership marker is unsafe or invalid: $MarkerPath"
    }
    try {
        $Marker = Get-Content -LiteralPath $MarkerPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    catch {
        throw "StateRoot ownership marker is not valid JSON: $MarkerPath"
    }
    foreach ($PropertyName in @(
        "format", "product", "canonical_path", "root_id", "created_utc"
    )) {
        if ($null -eq $Marker.PSObject.Properties[$PropertyName]) {
            throw "StateRoot ownership marker is missing $PropertyName."
        }
    }
    $RootId = [Guid]::Empty
    $CreatedUtc = [DateTimeOffset]::MinValue
    if ($Marker.format -ne "mineguard-enterprise-agent-state-root-v1" -or
        $Marker.product -ne "MineGuard Enterprise Agent" -or
        -not ([string]$Marker.canonical_path).TrimEnd('\').Equals(
            [IO.Path]::GetFullPath($Root).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [Guid]::TryParse([string]$Marker.root_id, [ref]$RootId) -or
        $RootId -eq [Guid]::Empty -or
        -not [DateTimeOffset]::TryParse([string]$Marker.created_utc, [ref]$CreatedUtc)) {
        throw "StateRoot ownership marker does not identify this Agent state directory."
    }
}

function Test-RecognizableLegacyInstance {
    param([object]$Directory)
    if (-not $Directory.PSIsContainer -or
        ($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $Directory.Name -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        return $false
    }
    $MetadataPath = Join-Path $Directory.FullName "instance.json"
    $ConfigPath = Join-Path $Directory.FullName "config\agent.env"
    foreach ($RequiredDirectory in @("data", "logs", "backups", "inbox", "service")) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory.FullName $RequiredDirectory) `
            -PathType Container)) {
            return $false
        }
    }
    if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        return $false
    }
    $MetadataItem = Get-Item -LiteralPath $MetadataPath -Force
    if (($MetadataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $MetadataItem.Length -le 0 -or $MetadataItem.Length -gt 1MB) {
        return $false
    }
    try {
        $Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    catch { return $false }
    return $Metadata.format -eq "mineguard-enterprise-agent-windows-instance-v1" -and
        [string]$Metadata.instance_name -eq $Directory.Name -and
        [string]$Metadata.service_id -eq "MineGuardEnterpriseAgent-$($Directory.Name)"
}

function Initialize-EnterpriseAgentStateRoot {
    param([string]$Root)
    Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $Root
    if ((Test-Path -LiteralPath $Root) -and
        -not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "StateRoot exists but is not a directory: $Root"
    }
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $Root
    Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $Root
    Assert-StateRootOrdinary -Root $Root

    $MarkerPath = Join-Path $Root ".mineguard-enterprise-agent-instances.json"
    if (Test-Path -LiteralPath $MarkerPath) {
        Assert-StateRootMarker -Root $Root
        return
    }
    $ExistingItems = @(Get-ChildItem -LiteralPath $Root -Force)
    $AdoptingLegacyInstances = $ExistingItems.Count -ne 0
    foreach ($ExistingItem in $ExistingItems) {
        if (-not (Test-RecognizableLegacyInstance -Directory $ExistingItem)) {
            throw (
                "Unmarked StateRoot must be empty or contain only recognizable Agent " +
                "instance directories: $($ExistingItem.FullName)"
            )
        }
    }

    $Marker = [ordered]@{
        format = "mineguard-enterprise-agent-state-root-v1"
        product = "MineGuard Enterprise Agent"
        canonical_path = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        root_id = [Guid]::NewGuid().ToString("D")
        created_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $MarkerJson = ($Marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine
    $MarkerBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($MarkerJson)
    $MarkerTemporary = Join-Path $Root (
        ".mineguard-enterprise-agent-instances.tmp-" + [Guid]::NewGuid().ToString("N")
    )
    $MarkerStream = $null
    try {
        $MarkerStream = [IO.File]::Open(
            $MarkerTemporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $MarkerStream.Write($MarkerBytes, 0, $MarkerBytes.Length)
        $MarkerStream.Flush($true)
        $MarkerStream.Dispose()
        $MarkerStream = $null
        Move-Item -LiteralPath $MarkerTemporary -Destination $MarkerPath
    }
    finally {
        if ($null -ne $MarkerStream) { $MarkerStream.Dispose() }
        if (Test-Path -LiteralPath $MarkerTemporary) {
            Remove-Item -LiteralPath $MarkerTemporary -Force
        }
    }
    Assert-StateRootOrdinary -Root $Root
    Assert-StateRootMarker -Root $Root
    if ($AdoptingLegacyInstances) {
        Write-Warning "Added the StateRoot ownership marker to recognizable legacy Agent instances."
    }
}

function Test-BinaryReleaseManifest {
    param([string]$ReleaseRoot)
    $ManifestPath = Join-Path $ReleaseRoot "release-manifest.json"
    $ChecksumsPath = Join-Path $ReleaseRoot "SHA256SUMS.txt"
    $VersionPath = Join-Path $ReleaseRoot "VERSION.txt"
    $BuildMetadataPath = Join-Path $ReleaseRoot "build-metadata.json"
    foreach ($Required in @($ManifestPath, $ChecksumsPath, $VersionPath, $BuildMetadataPath)) {
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
            throw "Binary release is missing: $Required"
        }
    }
    Assert-OrdinaryTree -Root $ReleaseRoot
    $Checksums = Read-ReleaseChecksums -ChecksumsPath $ChecksumsPath
    $ActualChecksummed = @{}
    foreach ($File in Get-ChildItem -LiteralPath $ReleaseRoot -File -Recurse -Force) {
        $Relative = $File.FullName.Substring($ReleaseRoot.Length + 1).Replace('\', '/')
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "Binary release"
        if ($Relative -eq "SHA256SUMS.txt") { continue }
        if ($ActualChecksummed.ContainsKey($Relative)) {
            throw "Binary release contains a case-insensitive duplicate path: $Relative"
        }
        $ActualChecksummed[$Relative] = $File
    }
    if ($Checksums.Count -ne $ActualChecksummed.Count) {
        throw "SHA256SUMS.txt does not describe the exact binary release file set."
    }
    foreach ($Relative in $Checksums.Keys) {
        if (-not $ActualChecksummed.ContainsKey($Relative)) {
            throw "SHA256SUMS.txt references a missing release file: $Relative"
        }
        $Digest = (Get-FileHash -LiteralPath $ActualChecksummed[$Relative].FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Digest -ne [string]$Checksums[$Relative]) {
            throw "SHA256SUMS.txt hash mismatch: $Relative"
        }
    }
    if (-not $Checksums.ContainsKey("release-manifest.json")) {
        throw "SHA256SUMS.txt must authenticate release-manifest.json."
    }

    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($Manifest.format -ne "mineguard-enterprise-agent-windows-binary-v1" -or
        $Manifest.product -ne "MineGuard Enterprise Agent" -or
        $Manifest.architecture -ne "x64" -or
        $Manifest.entrypoint -ne "runtime/MineGuardEnterpriseAgent.exe") {
        throw "Unsupported or invalid Enterprise Agent binary release manifest."
    }
    if ([string]$Manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "Binary release manifest has an invalid product version."
    }
    $Expected = @{}
    foreach ($Entry in $Manifest.files) {
        $Relative = [string]$Entry.path
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "release-manifest.json"
        if ($Relative -in @("release-manifest.json", "SHA256SUMS.txt")) {
            throw "release-manifest.json cannot describe itself or SHA256SUMS.txt."
        }
        if ($Expected.ContainsKey($Relative)) {
            throw "Binary release manifest contains a duplicate path: $Relative"
        }
        $DeclaredBytes = 0L
        if (-not [long]::TryParse([string]$Entry.bytes, [ref]$DeclaredBytes) -or $DeclaredBytes -lt 0) {
            throw "Binary release manifest contains an invalid size: $Relative"
        }
        $DeclaredSha = [string]$Entry.sha256
        if ($DeclaredSha -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "Binary release manifest contains an invalid SHA-256: $Relative"
        }
        $Expected[$Relative] = $Entry
    }
    if ($Expected.Count -ne ($Checksums.Count - 1)) {
        throw "release-manifest.json and SHA256SUMS.txt describe different file sets."
    }
    foreach ($Relative in $Expected.Keys) {
        if (-not $Checksums.ContainsKey($Relative) -or
            [string]$Checksums[$Relative] -ne ([string]$Expected[$Relative].sha256).ToLowerInvariant()) {
            throw "release-manifest.json and SHA256SUMS.txt disagree: $Relative"
        }
        $File = $ActualChecksummed[$Relative]
        $Entry = $Expected[$Relative]
        if ([long]$File.Length -ne [long]$Entry.bytes) {
            throw "Binary release file size mismatch: $Relative"
        }
        $Digest = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
        if (-not $Digest.Equals([string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Binary release SHA-256 mismatch: $Relative"
        }
    }
    $VersionFile = Get-Item -LiteralPath $VersionPath -Force
    if ($VersionFile.Length -gt 128) { throw "VERSION.txt is unexpectedly large." }
    $VersionText = (Get-Content -LiteralPath $VersionPath -Raw -Encoding UTF8).Trim()
    if ($VersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        [string]$Manifest.version -ne $VersionText) {
        throw "VERSION.txt and release-manifest.json identify different Agent versions."
    }
    $BuildMetadata = Get-Content -LiteralPath $BuildMetadataPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ($BuildMetadata.format -ne "mineguard-enterprise-agent-build-metadata-v1" -or
        $BuildMetadata.product -ne "MineGuard Enterprise Agent" -or
        $BuildMetadata.architecture -ne "x64" -or
        [string]$BuildMetadata.version -ne $VersionText) {
        throw "build-metadata.json does not match this Enterprise Agent release."
    }
    $Executable = Join-Path $ReleaseRoot "runtime\MineGuardEnterpriseAgent.exe"
    Test-ReleaseSignatureContract -Manifest $Manifest -BuildMetadata $BuildMetadata `
        -ExecutablePath $Executable
    return [pscustomobject]@{
        Manifest = $Manifest
        BuildMetadata = $BuildMetadata
        Version = $VersionText
        Checksums = $Checksums
    }
}

function Get-RequiredBooleanProperty {
    param([object]$Object, [string]$Name, [string]$Document)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $Property.Value -isnot [bool]) {
        throw "$Document must contain a JSON boolean property named $Name."
    }
    return [bool]$Property.Value
}

function Get-RequiredNullableStringProperty {
    param([object]$Object, [string]$Name, [string]$Document)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or
        ($null -ne $Property.Value -and $Property.Value -isnot [string])) {
        throw "$Document must contain a JSON string-or-null property named $Name."
    }
    return [string]$Property.Value
}

function Test-ReleaseSignatureContract {
    param([object]$Manifest, [object]$BuildMetadata, [string]$ExecutablePath)
    $ManifestSigned = Get-RequiredBooleanProperty -Object $Manifest `
        -Name "authenticode_signed" -Document "release-manifest.json"
    $MetadataSigned = Get-RequiredBooleanProperty -Object $BuildMetadata `
        -Name "authenticode_signed" -Document "build-metadata.json"
    $ManifestTimestamp = Get-RequiredBooleanProperty -Object $Manifest `
        -Name "timestamp_verified" -Document "release-manifest.json"
    $MetadataTimestamp = Get-RequiredBooleanProperty -Object $BuildMetadata `
        -Name "timestamp_verified" -Document "build-metadata.json"
    if ($ManifestSigned -ne $MetadataSigned -or
        $ManifestTimestamp -ne $MetadataTimestamp -or
        $ManifestTimestamp -ne $ManifestSigned) {
        throw "Release signature and timestamp booleans are inconsistent."
    }

    $ManifestThumbprint = (Get-RequiredNullableStringProperty -Object $Manifest `
        -Name "signing_certificate_thumbprint" -Document "release-manifest.json")
    $MetadataThumbprint = (Get-RequiredNullableStringProperty -Object $BuildMetadata `
        -Name "signing_certificate_thumbprint" -Document "build-metadata.json")
    $ManifestTimestampUrl = Get-RequiredNullableStringProperty -Object $Manifest `
        -Name "timestamp_url" -Document "release-manifest.json"
    $MetadataTimestampUrl = Get-RequiredNullableStringProperty -Object $BuildMetadata `
        -Name "timestamp_url" -Document "build-metadata.json"
    $ManifestThumbprint = ($ManifestThumbprint -replace '\s', '').ToUpperInvariant()
    $MetadataThumbprint = ($MetadataThumbprint -replace '\s', '').ToUpperInvariant()
    $Signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($ManifestSigned) {
        if ($ManifestThumbprint -notmatch '^[A-F0-9]{40}$' -or
            $ManifestThumbprint -ne $MetadataThumbprint) {
            throw "Signed release certificate thumbprints are missing or inconsistent."
        }
        $TimestampUri = $null
        if ($ManifestTimestampUrl -ne $MetadataTimestampUrl -or
            -not [uri]::TryCreate($ManifestTimestampUrl, [UriKind]::Absolute, [ref]$TimestampUri) -or
            $TimestampUri.Scheme -ne "https" -or
            [string]::IsNullOrWhiteSpace($TimestampUri.DnsSafeHost) -or
            -not [string]::IsNullOrWhiteSpace($TimestampUri.UserInfo)) {
            throw "Signed release timestamp URLs are missing, inconsistent or not HTTPS."
        }
        if ($Signature.Status.ToString() -ne "Valid" -or
            $null -eq $Signature.SignerCertificate -or
            $null -eq $Signature.TimeStamperCertificate -or
            ($Signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() -ne
                $ManifestThumbprint) {
            throw "Authenticode status, signer thumbprint or timestamp does not match release metadata."
        }
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($ManifestThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($MetadataThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($ManifestTimestampUrl) -or
            -not [string]::IsNullOrWhiteSpace($MetadataTimestampUrl)) {
            throw "Unsigned release metadata cannot claim a signer or timestamp URL."
        }
        if ($Signature.Status.ToString() -ne "NotSigned" -or
            $null -ne $Signature.SignerCertificate -or
            $null -ne $Signature.TimeStamperCertificate) {
            throw "Unsigned release metadata does not match the executable Authenticode state."
        }
    }
}

function Test-InstalledBinaryRuntime {
    param([string]$ApplicationRoot, [string]$RuntimeDirectory)
    $Executable = Join-Path $RuntimeDirectory "MineGuardEnterpriseAgent.exe"
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $null }

    $MetadataRoot = Join-Path $ApplicationRoot "release-metadata"
    $DeployRoot = Join-Path $ApplicationRoot "deploy\windows"
    $VersionPath = Join-Path $MetadataRoot "VERSION.txt"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $BuildMetadataPath = Join-Path $MetadataRoot "build-metadata.json"
    $ChecksumsPath = Join-Path $MetadataRoot "SHA256SUMS.txt"
    foreach ($Required in @(
        $MetadataRoot, $DeployRoot, $VersionPath, $ManifestPath,
        $BuildMetadataPath, $ChecksumsPath
    )) {
        if (-not (Test-Path -LiteralPath $Required)) {
            throw "An active compiled Agent runtime has incomplete release metadata: $Required"
        }
    }
    foreach ($Tree in @($RuntimeDirectory, $DeployRoot, $MetadataRoot)) {
        Assert-OrdinaryTree -Root $Tree
    }

    $Checksums = Read-ReleaseChecksums -ChecksumsPath $ChecksumsPath
    $Actual = @{}
    foreach ($File in Get-ChildItem -LiteralPath $RuntimeDirectory -File -Recurse -Force) {
        $Relative = "runtime/" + $File.FullName.Substring(
            $RuntimeDirectory.Length
        ).TrimStart('\').Replace('\', '/')
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "Installed runtime"
        $Actual[$Relative] = $File
    }
    foreach ($File in Get-ChildItem -LiteralPath $DeployRoot -File -Recurse -Force) {
        $Relative = "deploy/windows/" + $File.FullName.Substring(
            $DeployRoot.Length
        ).TrimStart('\').Replace('\', '/')
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "Installed deployment"
        if ($Actual.ContainsKey($Relative)) {
            throw "Installed release contains a duplicate path: $Relative"
        }
        $Actual[$Relative] = $File
    }
    foreach ($File in Get-ChildItem -LiteralPath $MetadataRoot -File -Recurse -Force) {
        $Relative = $File.FullName.Substring($MetadataRoot.Length).TrimStart('\').Replace('\', '/')
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "Installed release metadata"
        if ($Relative -eq "SHA256SUMS.txt") { continue }
        if ($Relative -notin @("VERSION.txt", "build-metadata.json", "release-manifest.json") -or
            $Actual.ContainsKey($Relative)) {
            throw "Installed release metadata contains an unexpected or duplicate file: $Relative"
        }
        $Actual[$Relative] = $File
    }
    if ($Checksums.Count -ne $Actual.Count) {
        throw "Installed SHA256SUMS.txt does not describe the exact active release file set."
    }
    foreach ($Relative in $Checksums.Keys) {
        if (-not $Actual.ContainsKey($Relative)) {
            throw "Installed release file is missing: $Relative"
        }
        $Digest = (Get-FileHash -LiteralPath $Actual[$Relative].FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Digest -ne [string]$Checksums[$Relative]) {
            throw "Installed release hash mismatch: $Relative"
        }
    }

    $VersionText = (Get-Content -LiteralPath $VersionPath -Raw -Encoding UTF8).Trim()
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $BuildMetadata = Get-Content -LiteralPath $BuildMetadataPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ($VersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $Manifest.format -ne "mineguard-enterprise-agent-windows-binary-v1" -or
        $Manifest.product -ne "MineGuard Enterprise Agent" -or
        $Manifest.architecture -ne "x64" -or
        $Manifest.entrypoint -ne "runtime/MineGuardEnterpriseAgent.exe" -or
        [string]$Manifest.version -ne $VersionText -or
        $BuildMetadata.format -ne "mineguard-enterprise-agent-build-metadata-v1" -or
        $BuildMetadata.product -ne "MineGuard Enterprise Agent" -or
        $BuildMetadata.architecture -ne "x64" -or
        [string]$BuildMetadata.version -ne $VersionText) {
        throw "Installed VERSION, manifest and build metadata are inconsistent."
    }
    $ManifestEntries = @{}
    foreach ($Entry in $Manifest.files) {
        $Relative = [string]$Entry.path
        Assert-SafeReleaseRelativePath -Relative $Relative -Context "Installed release manifest"
        if ($Relative -in @("release-manifest.json", "SHA256SUMS.txt") -or
            $ManifestEntries.ContainsKey($Relative)) {
            throw "Installed release manifest contains an invalid duplicate path: $Relative"
        }
        $ManifestEntries[$Relative] = $Entry
    }
    if ($ManifestEntries.Count -ne ($Checksums.Count - 1) -or
        -not $Checksums.ContainsKey("release-manifest.json")) {
        throw "Installed release manifest and SHA256SUMS.txt file sets are inconsistent."
    }
    foreach ($Relative in $ManifestEntries.Keys) {
        $Entry = $ManifestEntries[$Relative]
        if (-not $Checksums.ContainsKey($Relative) -or
            ([string]$Entry.sha256).ToLowerInvariant() -ne [string]$Checksums[$Relative] -or
            [long]$Entry.bytes -ne [long]$Actual[$Relative].Length) {
            throw "Installed release manifest metadata mismatch: $Relative"
        }
    }
    Test-ReleaseSignatureContract -Manifest $Manifest -BuildMetadata $BuildMetadata `
        -ExecutablePath $Executable
    $ReportedVersion = (& $Executable --version | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $ReportedVersion -ne "enterprise-agent $VersionText") {
        throw "Active compiled Agent --version does not match installed release metadata."
    }
    return $VersionText
}

function Test-ManifestSubtree {
    param([string]$Root, [string]$ManifestPrefix, [object]$Manifest)
    Assert-OrdinaryTree -Root $Root
    $Expected = @{}
    foreach ($Entry in $Manifest.files) {
        $Path = [string]$Entry.path
        if ($Path.StartsWith($ManifestPrefix, [StringComparison]::Ordinal)) {
            $Expected[$Path] = $Entry
        }
    }
    $Actual = @{}
    foreach ($File in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $Relative = $File.FullName.Substring($Root.Length).TrimStart('\').Replace('\', '/')
        $Actual[$ManifestPrefix + $Relative] = $File
    }
    if ($Expected.Count -eq 0 -or $Expected.Count -ne $Actual.Count) {
        throw "Installed $ManifestPrefix file set does not match the verified release manifest."
    }
    foreach ($Path in $Expected.Keys) {
        if (-not $Actual.ContainsKey($Path)) {
            throw "Installed binary release file is missing: $Path"
        }
        $File = $Actual[$Path]
        $Entry = $Expected[$Path]
        $Digest = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
        if ([long]$File.Length -ne [long]$Entry.bytes -or
            -not $Digest.Equals([string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Installed binary release verification failed: $Path"
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

Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
Assert-LocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot
$InstallRoot = ([IO.Path]::GetFullPath($InstallRoot)).TrimEnd('\')
$StateRoot = ([IO.Path]::GetFullPath($StateRoot)).TrimEnd('\')
$SourceRoot = ([IO.Path]::GetFullPath($SourceRoot)).TrimEnd('\')
Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $StateRoot
$InstallPrefix = $InstallRoot.TrimEnd('\') + '\'
$StatePrefix = $StateRoot.TrimEnd('\') + '\'
if ($InstallRoot.Equals($StateRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $InstallRoot.StartsWith($StatePrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $StateRoot.StartsWith($InstallPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot and StateRoot must be separate, non-nested directories."
}

$RegisteredServices = @(Get-Service -Name "MineGuardEnterpriseAgent-*" `
    -ErrorAction SilentlyContinue)
$RunningServices = @($RegisteredServices | Where-Object { $_.Status -ne "Stopped" })
if ($RunningServices.Count -ne 0) {
    throw "Stop all MineGuardEnterpriseAgent-* services before installing or upgrading the shared runtime."
}
Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
Assert-LocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot
$RuntimeRoot = Join-Path $InstallRoot "runtime"
$DeploySource = Join-Path $SourceRoot "deploy\windows"
$DeployTarget = Join-Path $InstallRoot "deploy\windows"
$InstalledExecutable = Join-Path $RuntimeRoot "MineGuardEnterpriseAgent.exe"
$DeployInstalled = $false
Assert-LocalFixedPath -Name "RuntimeRoot" -PathValue $RuntimeRoot
Assert-LocalFixedPath -Name "DeployTarget" -PathValue $DeployTarget
Assert-NoEnterpriseAgentRuntimeProcesses -RuntimeDirectory $RuntimeRoot

if (-not $BuildFromSource) {
    $ReleaseContract = Test-BinaryReleaseManifest -ReleaseRoot $SourceRoot
    $Manifest = $ReleaseContract.Manifest
    $CandidateBuildMetadata = $ReleaseContract.BuildMetadata
    $CandidateVersionText = [string]$ReleaseContract.Version
    Assert-EABinaryInstallPathBudget -Root $InstallRoot -Manifest $Manifest
    $ExistingVersionText = Test-InstalledBinaryRuntime `
        -ApplicationRoot $InstallRoot -RuntimeDirectory $RuntimeRoot
    if ($null -ne $ExistingVersionText -and
        [version]$CandidateVersionText -lt [version]$ExistingVersionText) {
        throw "Agent downgrade from $ExistingVersionText to $CandidateVersionText is blocked by default."
    }
    $BinaryRuntime = Join-Path $SourceRoot "runtime"
    $BinaryExecutable = Join-Path $BinaryRuntime "MineGuardEnterpriseAgent.exe"
    foreach ($Required in @($BinaryExecutable, $DeploySource)) {
        if (-not (Test-Path -LiteralPath $Required)) {
            throw "Binary release is incomplete: $Required"
        }
    }
    $CandidateReportedVersion = (& $BinaryExecutable --version | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $CandidateReportedVersion -ne "enterprise-agent $CandidateVersionText") {
        throw "Binary executable version does not match the verified release metadata."
    }
    $SourcePrefix = $SourceRoot.TrimEnd('\') + '\'
    if ($InstallRoot.Equals($SourceRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $InstallRoot.StartsWith($SourcePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $SourceRoot.StartsWith($InstallPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "InstallRoot and binary ReleaseRoot must be separate, non-nested directories."
    }
    $LegacySourceExecutable = Join-Path $InstallRoot `
        "runtime\.venv\Scripts\enterprise-agent.exe"
    $ReleaseMetadataRoot = Join-Path $InstallRoot "release-metadata"
    if (-not (Test-Path -LiteralPath $InstalledExecutable -PathType Leaf)) {
        if ((Test-Path -LiteralPath $ReleaseMetadataRoot) -and
            $null -ne (Get-ChildItem -LiteralPath $ReleaseMetadataRoot -Force |
                Select-Object -First 1)) {
            throw "Release metadata exists without its compiled Agent runtime; recover or remove the incomplete installation before upgrade."
        }
        if ((Test-Path -LiteralPath $RuntimeRoot) -and
            -not (Test-Path -LiteralPath $LegacySourceExecutable -PathType Leaf) -and
            $null -ne (Get-ChildItem -LiteralPath $RuntimeRoot -Force |
                Select-Object -First 1)) {
            throw "An incomplete runtime directory exists without a compiled or legacy Agent entry point."
        }
    }
    if ($RegisteredServices.Count -ne 0 -and
        (Test-Path -LiteralPath $LegacySourceExecutable -PathType Leaf)) {
        throw (
            "A stopped legacy source/venv Agent service is still registered. " +
            "Uninstall each legacy service, install the binary runtime, then reinstall the services."
        )
    }
    if ($AuditFailAfterRuntimeSwitch -and
        $env:MINEGUARD_RELEASE_AUDIT_MODE -ne "installer-rollback-test") {
        throw "AuditFailAfterRuntimeSwitch is reserved for the release rollback audit."
    }

    # Do not create or adopt mutable product/state directories until the binary
    # media, signature contract, executable version and upgrade direction have
    # all passed their read-only checks above.
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Initialize-EnterpriseAgentStateRoot -Root $StateRoot
    Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot

    $StagedRuntime = Join-Path $InstallRoot (".runtime-stage-" + [Guid]::NewGuid().ToString("N"))
    $RollbackRuntime = Join-Path $InstallRoot (".runtime-rollback-" + [Guid]::NewGuid().ToString("N"))
    $ReleaseMetadata = Join-Path $InstallRoot "release-metadata"
    $StagedMetadata = Join-Path $InstallRoot (".release-metadata-stage-" + [Guid]::NewGuid().ToString("N"))
    $RollbackMetadata = Join-Path $InstallRoot (".release-metadata-rollback-" + [Guid]::NewGuid().ToString("N"))
    $StagedDeploy = Join-Path $InstallRoot (".deploy-stage-" + [Guid]::NewGuid().ToString("N"))
    $RollbackDeploy = Join-Path $InstallRoot (".deploy-rollback-" + [Guid]::NewGuid().ToString("N"))
    $DeployParent = Split-Path -Parent $DeployTarget
    $TransactionLeafPattern = `
        '^\.(?:runtime|deploy|release-metadata)-(?:stage|rollback)-[a-f0-9]{32}$'
    $RuntimeSwitched = $false
    $MetadataSwitched = $false
    $DeploySwitched = $false
    $TransactionError = $null
    $RollbackErrors = New-Object System.Collections.Generic.List[string]
    $CleanupErrors = New-Object System.Collections.Generic.List[string]
    try {
        New-Item -ItemType Directory -Path $StagedRuntime | Out-Null
        foreach ($Item in Get-ChildItem -LiteralPath $BinaryRuntime -Force) {
            Copy-Item -LiteralPath $Item.FullName -Destination $StagedRuntime -Recurse
        }
        Test-ManifestSubtree -Root $StagedRuntime -ManifestPrefix "runtime/" -Manifest $Manifest
        New-Item -ItemType Directory -Path $StagedDeploy | Out-Null
        foreach ($DeployFile in Get-ChildItem -LiteralPath $DeploySource -Force) {
            Copy-Item -LiteralPath $DeployFile.FullName -Destination $StagedDeploy -Recurse
        }
        Test-ManifestSubtree -Root $StagedDeploy -ManifestPrefix "deploy/windows/" -Manifest $Manifest
        Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
        Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
        Invoke-IcaclsChecked -ArgumentList @($InstallRoot, "/inheritance:r")
        Invoke-IcaclsChecked -ArgumentList @(
            $InstallRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX"
        )
        Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
        Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $StateRoot
        Assert-StateRootOrdinary -Root $StateRoot
        Assert-StateRootMarker -Root $StateRoot
        Invoke-IcaclsChecked -ArgumentList @($StateRoot, "/inheritance:r")
        Invoke-IcaclsChecked -ArgumentList @(
            $StateRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX"
        )
        foreach ($StagedReadOnlyTree in @($StagedRuntime, $StagedDeploy)) {
            Invoke-IcaclsChecked -ArgumentList @($StagedReadOnlyTree, "/inheritance:r")
            Invoke-IcaclsChecked -ArgumentList @(
                $StagedReadOnlyTree, "/grant:r", "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX",
                "/T", "/C"
            )
        }
        $StagedExecutable = Join-Path $StagedRuntime "MineGuardEnterpriseAgent.exe"
        Test-ReleaseSignatureContract -Manifest $Manifest `
            -BuildMetadata $CandidateBuildMetadata -ExecutablePath $StagedExecutable
        if (-not [bool]$Manifest.authenticode_signed) {
            Write-Warning "Installing an unsigned internal-test Enterprise Agent binary. It is not a production-trusted release."
        }
        $StagedVersion = (& $StagedExecutable --version | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0 -or $StagedVersion -ne "enterprise-agent $($Manifest.version)") {
            throw "Binary executable version does not match release-manifest.json."
        }
        Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
        Assert-LocalFixedPath -Name "RuntimeRoot" -PathValue $RuntimeRoot
        Assert-LocalFixedPath -Name "DeployTarget" -PathValue $DeployTarget
        Assert-LocalFixedPath -Name "ReleaseMetadata" -PathValue $ReleaseMetadata
        $RestartedServices = @(Get-Service -Name "MineGuardEnterpriseAgent-*" `
            -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne "Stopped" })
        if ($RestartedServices.Count -ne 0) {
            throw "An Enterprise Agent service restarted during upgrade; stop it before runtime replacement."
        }
        Assert-NoEnterpriseAgentRuntimeProcesses -RuntimeDirectory $RuntimeRoot
        if (Test-Path -LiteralPath $RuntimeRoot) {
            Move-EAOwnedPathWithRetry `
                -SourcePath $RuntimeRoot -SourceParent $InstallRoot `
                -SourceLeafPattern '^runtime$' `
                -DestinationPath $RollbackRuntime `
                -DestinationParent $InstallRoot `
                -DestinationLeafPattern $TransactionLeafPattern
        }
        Move-EAOwnedPathWithRetry `
            -SourcePath $StagedRuntime -SourceParent $InstallRoot `
            -SourceLeafPattern $TransactionLeafPattern `
            -DestinationPath $RuntimeRoot -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^runtime$'
        $RuntimeSwitched = $true
        $InstalledVersion = (& $InstalledExecutable --version | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0 -or $InstalledVersion -ne $StagedVersion) {
            throw "Installed binary failed post-install version verification."
        }
        New-Item -ItemType Directory -Path $DeployParent -Force | Out-Null
        if (Test-Path -LiteralPath $DeployTarget) {
            Move-EAOwnedPathWithRetry `
                -SourcePath $DeployTarget -SourceParent $DeployParent `
                -SourceLeafPattern '^windows$' `
                -DestinationPath $RollbackDeploy `
                -DestinationParent $InstallRoot `
                -DestinationLeafPattern $TransactionLeafPattern
        }
        Move-EAOwnedPathWithRetry `
            -SourcePath $StagedDeploy -SourceParent $InstallRoot `
            -SourceLeafPattern $TransactionLeafPattern `
            -DestinationPath $DeployTarget -DestinationParent $DeployParent `
            -DestinationLeafPattern '^windows$'
        $DeploySwitched = $true
        New-Item -ItemType Directory -Path $StagedMetadata | Out-Null
        foreach ($MetadataName in @("VERSION.txt", "build-metadata.json", "release-manifest.json", "SHA256SUMS.txt")) {
            $MetadataSource = Join-Path $SourceRoot $MetadataName
            if (-not (Test-Path -LiteralPath $MetadataSource -PathType Leaf)) {
                throw "Binary release trace metadata is missing: $MetadataName"
            }
            Copy-Item -LiteralPath $MetadataSource -Destination $StagedMetadata
        }
        $StagedMetadataFiles = @(Get-ChildItem -LiteralPath $StagedMetadata -File -Force)
        if ($StagedMetadataFiles.Count -ne 4) {
            throw "Installed release metadata staging must contain exactly four files."
        }
        $StagedChecksums = Read-ReleaseChecksums `
            -ChecksumsPath (Join-Path $StagedMetadata "SHA256SUMS.txt")
        if ($StagedChecksums.Count -ne $ReleaseContract.Checksums.Count) {
            throw "Staged SHA256SUMS.txt changed during installation."
        }
        foreach ($ChecksumPath in $ReleaseContract.Checksums.Keys) {
            if (-not $StagedChecksums.ContainsKey($ChecksumPath) -or
                [string]$StagedChecksums[$ChecksumPath] -ne
                    [string]$ReleaseContract.Checksums[$ChecksumPath]) {
                throw "Staged SHA256SUMS.txt changed during installation: $ChecksumPath"
            }
        }
        foreach ($VerifiedMetadataName in @(
            "VERSION.txt", "build-metadata.json", "release-manifest.json"
        )) {
            $MetadataFile = Get-Item -LiteralPath (Join-Path $StagedMetadata $VerifiedMetadataName)
            $MetadataDigest = (Get-FileHash -LiteralPath $MetadataFile.FullName -Algorithm SHA256).Hash
            if (-not $ReleaseContract.Checksums.ContainsKey($VerifiedMetadataName) -or
                -not $MetadataDigest.Equals(
                    [string]$ReleaseContract.Checksums[$VerifiedMetadataName],
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Installed release metadata verification failed: $VerifiedMetadataName"
            }
        }
        Invoke-IcaclsChecked -ArgumentList @($StagedMetadata, "/inheritance:r")
        Invoke-IcaclsChecked -ArgumentList @(
            $StagedMetadata, "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX",
            "/T", "/C"
        )
        if (Test-Path -LiteralPath $ReleaseMetadata) {
            Move-EAOwnedPathWithRetry `
                -SourcePath $ReleaseMetadata -SourceParent $InstallRoot `
                -SourceLeafPattern '^release-metadata$' `
                -DestinationPath $RollbackMetadata `
                -DestinationParent $InstallRoot `
                -DestinationLeafPattern $TransactionLeafPattern
        }
        Move-EAOwnedPathWithRetry `
            -SourcePath $StagedMetadata -SourceParent $InstallRoot `
            -SourceLeafPattern $TransactionLeafPattern `
            -DestinationPath $ReleaseMetadata `
            -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^release-metadata$'
        $MetadataSwitched = $true
        $PostInstallVersion = Test-InstalledBinaryRuntime `
            -ApplicationRoot $InstallRoot -RuntimeDirectory $RuntimeRoot
        if ($PostInstallVersion -ne $CandidateVersionText) {
            throw "Post-install release verification returned an unexpected Agent version."
        }
        if ($AuditFailAfterRuntimeSwitch) {
            Write-Host "MINEGUARD_RELEASE_AUDIT_MARKER=agent-post-switch"
            throw "Release audit fault injection: verify complete rollback after the Agent runtime switch."
        }
    }
    catch {
        $TransactionError = $_
        if ($DeploySwitched) {
            try {
                Move-EAOwnedPathWithRetry `
                    -SourcePath $DeployTarget -SourceParent $DeployParent `
                    -SourceLeafPattern '^windows$' `
                    -DestinationPath $StagedDeploy `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $TransactionLeafPattern
                $DeploySwitched = $false
            }
            catch {
                $RollbackErrors.Add(
                    "Unable to quarantine candidate deployment scripts: $($_.Exception.Message)"
                )
            }
        }
        if (Test-Path -LiteralPath $RollbackDeploy) {
            if ($DeploySwitched) {
                $RollbackErrors.Add(
                    "Candidate deployment scripts remain active; prior scripts cannot be restored."
                )
            }
            else {
                try {
                    Move-EAOwnedPathWithRetry `
                        -SourcePath $RollbackDeploy `
                        -SourceParent $InstallRoot `
                        -SourceLeafPattern $TransactionLeafPattern `
                        -DestinationPath $DeployTarget `
                        -DestinationParent $DeployParent `
                        -DestinationLeafPattern '^windows$'
                }
                catch {
                    $RollbackErrors.Add(
                        "Unable to restore prior deployment scripts: $($_.Exception.Message)"
                    )
                }
            }
        }
        if ($MetadataSwitched) {
            try {
                Move-EAOwnedPathWithRetry `
                    -SourcePath $ReleaseMetadata -SourceParent $InstallRoot `
                    -SourceLeafPattern '^release-metadata$' `
                    -DestinationPath $StagedMetadata `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $TransactionLeafPattern
                $MetadataSwitched = $false
            }
            catch {
                $RollbackErrors.Add(
                    "Unable to quarantine candidate release metadata: $($_.Exception.Message)"
                )
            }
        }
        if (Test-Path -LiteralPath $RollbackMetadata) {
            if ($MetadataSwitched) {
                $RollbackErrors.Add(
                    "Candidate release metadata remains active; prior metadata cannot be restored."
                )
            }
            else {
                try {
                    Move-EAOwnedPathWithRetry `
                        -SourcePath $RollbackMetadata `
                        -SourceParent $InstallRoot `
                        -SourceLeafPattern $TransactionLeafPattern `
                        -DestinationPath $ReleaseMetadata `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^release-metadata$'
                }
                catch {
                    $RollbackErrors.Add(
                        "Unable to restore prior release metadata: $($_.Exception.Message)"
                    )
                }
            }
        }
        if ($RuntimeSwitched) {
            try {
                Move-EAOwnedPathWithRetry `
                    -SourcePath $RuntimeRoot -SourceParent $InstallRoot `
                    -SourceLeafPattern '^runtime$' `
                    -DestinationPath $StagedRuntime `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $TransactionLeafPattern
                $RuntimeSwitched = $false
            }
            catch {
                $RollbackErrors.Add(
                    "Unable to quarantine candidate runtime: $($_.Exception.Message)"
                )
            }
        }
        if (Test-Path -LiteralPath $RollbackRuntime) {
            if ($RuntimeSwitched) {
                $RollbackErrors.Add(
                    "Candidate runtime remains active; prior runtime cannot be restored."
                )
            }
            else {
                try {
                    Move-EAOwnedPathWithRetry `
                        -SourcePath $RollbackRuntime `
                        -SourceParent $InstallRoot `
                        -SourceLeafPattern $TransactionLeafPattern `
                        -DestinationPath $RuntimeRoot `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^runtime$'
                }
                catch {
                    $RollbackErrors.Add(
                        "Unable to restore prior runtime: $($_.Exception.Message)"
                    )
                }
            }
        }
    }
    finally {
        foreach ($StagedPath in @(
            $StagedRuntime, $StagedMetadata, $StagedDeploy
        )) {
            try {
                Remove-EAOwnedPathWithRetry -Path $StagedPath `
                    -ExpectedParent $InstallRoot `
                    -AllowedLeafPattern $TransactionLeafPattern
            }
            catch {
                $CleanupErrors.Add(
                    "Unable to clean candidate transaction path ${StagedPath}: $($_.Exception.Message)"
                )
            }
        }
    }
    if ($null -ne $TransactionError) {
        $AllRecoveryErrors = @($RollbackErrors) + @($CleanupErrors)
        if ($AllRecoveryErrors.Count -gt 0) {
            $Message = (
                "Enterprise Agent installation failed and rollback was incomplete. " +
                "Original error: $($TransactionError.Exception.Message); " +
                "rollback errors: $($AllRecoveryErrors -join ' | ')"
            )
            throw [System.Exception]::new(
                $Message, $TransactionError.Exception
            )
        }
        $PSCmdlet.ThrowTerminatingError($TransactionError)
    }
    if ($CleanupErrors.Count -gt 0) {
        throw (
            "Enterprise Agent transaction cleanup did not complete: " +
            ($CleanupErrors -join " | ")
        )
    }
    if (Test-Path -LiteralPath $RollbackRuntime) {
        try {
            Remove-EAOwnedPathWithRetry -Path $RollbackRuntime `
                -ExpectedParent $InstallRoot `
                -AllowedLeafPattern $TransactionLeafPattern
        }
        catch {
            Write-Warning "Installation succeeded, but the old runtime is locked and remains at $RollbackRuntime. Remove it after confirming no process uses it."
        }
    }
    if (Test-Path -LiteralPath $RollbackMetadata) {
        try {
            Remove-EAOwnedPathWithRetry -Path $RollbackMetadata `
                -ExpectedParent $InstallRoot `
                -AllowedLeafPattern $TransactionLeafPattern
        }
        catch {
            Write-Warning "Installation succeeded, but old release metadata remains at $RollbackMetadata. It is not active and may be removed later."
        }
    }
    if (Test-Path -LiteralPath $RollbackDeploy) {
        try {
            Remove-EAOwnedPathWithRetry -Path $RollbackDeploy `
                -ExpectedParent $InstallRoot `
                -AllowedLeafPattern $TransactionLeafPattern
        }
        catch {
            Write-Warning "Installation succeeded, but old deployment scripts remain at $RollbackDeploy. They are not active and may be removed later."
        }
    }
    $DeployInstalled = $true
    Write-Host "Verified binary release version: $($Manifest.version)"
    Write-Host "Installed release trace: $ReleaseMetadata"
}
else {
    Write-Warning "Building an installed Python environment from source is for development only. Distributable media must use the verified binary release."
    if (Test-Path -LiteralPath $InstalledExecutable -PathType Leaf) {
        throw "Source-development mode refuses to mix with an installed binary runtime. Use a separate InstallRoot."
    }
    $ProjectFile = Join-Path $SourceRoot "pyproject.toml"
    $Constraints = Join-Path $SourceRoot "constraints.txt"
    foreach ($Required in @($ProjectFile, $Constraints, $DeploySource)) {
        if (-not (Test-Path -LiteralPath $Required)) {
            throw "Agent source tree is incomplete: $Required"
        }
    }
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Initialize-EnterpriseAgentStateRoot -Root $StateRoot
    Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    $VirtualEnvironment = Join-Path $RuntimeRoot ".venv"
    $VersionCheck = "import struct,sys; assert sys.version_info[:2] == (3,12) and struct.calcsize('P') == 8, sys.version"
    Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-c", $VersionCheck))
    if (-not (Test-Path -LiteralPath (Join-Path $VirtualEnvironment "Scripts\python.exe") -PathType Leaf)) {
        Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-m", "venv", $VirtualEnvironment))
    }
    $VenvPython = Join-Path $VirtualEnvironment "Scripts\python.exe"
    Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @("-c", $VersionCheck)
    if ($Wheelhouse) {
        Assert-LocalFixedPath -Name "Wheelhouse" -PathValue $Wheelhouse
        $Wheelhouse = [IO.Path]::GetFullPath($Wheelhouse)
        Assert-LocalFixedPath -Name "Wheelhouse" -PathValue $Wheelhouse
        if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
            throw "Wheelhouse directory does not exist: $Wheelhouse"
        }
        $AgentWheel = Get-ChildItem -LiteralPath $Wheelhouse -Filter "enterprise_reporting_agent-*.whl" -File |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($null -eq $AgentWheel) {
            throw "Wheelhouse must contain enterprise_reporting_agent-*.whl and all dependency wheels."
        }
        Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @(
            "-m", "pip", "install", "--disable-pip-version-check", "--no-index",
            "--find-links", $Wheelhouse, "--constraint", $Constraints, $AgentWheel.FullName
        )
    }
    else {
        Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @(
            "-m", "pip", "install", "--disable-pip-version-check",
            "--constraint", $Constraints, $SourceRoot
        )
    }
    $InstalledExecutable = Join-Path $VirtualEnvironment "Scripts\enterprise-agent.exe"
    Invoke-NativeChecked -FilePath $InstalledExecutable -ArgumentList @("--version")
}

if (-not $DeployInstalled) {
    New-Item -ItemType Directory -Path $DeployTarget -Force | Out-Null
    foreach ($DeployFile in Get-ChildItem -LiteralPath $DeploySource -Force) {
        Copy-Item -LiteralPath $DeployFile.FullName -Destination $DeployTarget -Recurse -Force
    }
}
if ($BuildFromSource) {
    Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
    Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
    Invoke-IcaclsChecked -ArgumentList @($InstallRoot, "/inheritance:r")
    Invoke-IcaclsChecked -ArgumentList @(
        $InstallRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX",
        "/T", "/C"
    )
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
    Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $StateRoot
    Assert-StateRootOrdinary -Root $StateRoot
    Assert-StateRootMarker -Root $StateRoot
    Invoke-IcaclsChecked -ArgumentList @($StateRoot, "/inheritance:r")
    Invoke-IcaclsChecked -ArgumentList @(
        $StateRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX"
    )
}

Write-Host "Enterprise Agent runtime installed."
Write-Host "Executable: $InstalledExecutable"
Write-Host "Instances: $StateRoot"
Write-Host "Next: run New-EnterpriseAgentInstance.ps1 once for each mine."
