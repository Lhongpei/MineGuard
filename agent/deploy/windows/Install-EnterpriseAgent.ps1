[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [Alias("ReleaseRoot")][string]$SourceRoot = "",
    [switch]$BuildFromSource,
    [string]$PythonCommand = "py",
    [string[]]$PythonArguments = @("-3.12"),
    [string]$Wheelhouse = "",
    [string]$ApprovedSignerThumbprint = "",
    [switch]$AllowUnsignedTestMedia,
    [switch]$AllowUnsignedInternalRelease,
    [string]$ExpectedReleaseManifestSha256 = "",
    [switch]$AuditFailAfterRuntimeSwitch,
    [string]$TrustedBootstrapTransactionId = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

function Get-ValidatedTrustedBootstrapTransactionGuid {
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) {
        return [Guid]::Empty
    }
    if ($Value -cnotmatch '^[a-f0-9]{32}$') {
        throw (
            "TrustedBootstrapTransactionId must be an exact lowercase " +
            "GUID in 32-character N format."
        )
    }
    $Parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, "N", [ref]$Parsed) -or
        $Parsed -eq [Guid]::Empty) {
        throw "TrustedBootstrapTransactionId must identify a non-empty GUID."
    }
    return $Parsed
}

# Validate the wrapper-only transaction token before any StateRoot operation.
# Keep the caller's exact lowercase N-format text; it is also the provisioning
# token used in the marker and temporary marker filename.
$null = Get-ValidatedTrustedBootstrapTransactionGuid `
    -Value $TrustedBootstrapTransactionId
if ($BuildFromSource -and
    -not [string]::IsNullOrEmpty($TrustedBootstrapTransactionId)) {
    throw "TrustedBootstrapTransactionId is reserved for verified binary installation."
}
$HasTrustedBootstrapTransaction =
    -not [string]::IsNullOrEmpty($TrustedBootstrapTransactionId)
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

function Get-NormalizedApprovedSignerThumbprint {
    param([string]$Value, [switch]$AllowEmpty)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($AllowEmpty) { return "" }
        throw "Formal binary installation requires -ApprovedSignerThumbprint from independently approved offline material."
    }
    if ($Value -notmatch '^[A-Fa-f0-9\s]+$') {
        throw "ApprovedSignerThumbprint must contain exactly 40 hexadecimal SHA-1 characters (whitespace is ignored)."
    }
    $Normalized = ($Value -replace '\s', '').ToUpperInvariant()
    if ($Normalized -notmatch '^[A-F0-9]{40}$') {
        throw "ApprovedSignerThumbprint must contain exactly 40 hexadecimal SHA-1 characters."
    }
    return $Normalized
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
                "model-credential-trust.json", "SHA256SUMS.txt"
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
        if ($env:MINEGUARD_RELEASE_AUDIT_MODE -eq "installer-guard-test") {
            Write-Host "MINEGUARD_RELEASE_AUDIT_MARKER=agent-runtime-process"
        }
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
    param(
        [string]$Root,
        [string]$BootstrapTransactionId = ""
    )
    # Defense in depth: validate before even creating an absent StateRoot and
    # before the early return for a pre-existing ownership marker.
    $BootstrapTransactionGuid = Get-ValidatedTrustedBootstrapTransactionGuid `
        -Value $BootstrapTransactionId
    $HasBootstrapTransaction = -not [string]::IsNullOrEmpty(
        $BootstrapTransactionId
    )
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

    $MarkerRootId = if ($HasBootstrapTransaction) {
        $BootstrapTransactionGuid.ToString("D")
    }
    else { [Guid]::NewGuid().ToString("D") }
    $Marker = [ordered]@{
        format = "mineguard-enterprise-agent-state-root-v1"
        product = "MineGuard Enterprise Agent"
        canonical_path = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        root_id = $MarkerRootId
        created_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $MarkerJson = ($Marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine
    $MarkerBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($MarkerJson)
    $MarkerTemporaryId = if ($HasBootstrapTransaction) {
        $BootstrapTransactionId
    }
    else { [Guid]::NewGuid().ToString("N") }
    $MarkerTemporary = Join-Path $Root (
        ".mineguard-enterprise-agent-instances.tmp-" + $MarkerTemporaryId
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
    param(
        [string]$ReleaseRoot,
        [string]$ApprovedSignerThumbprint,
        [switch]$AllowUnsignedTestMedia,
        [switch]$AllowUnsignedInternalRelease
    )
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
        -ExecutablePath $Executable `
        -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
        -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
        -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease
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

function Get-OptionalReleaseClassification {
    param([object]$Object, [string]$Document)
    $Property = $Object.PSObject.Properties["release_classification"]
    if ($null -eq $Property) { return "" }
    if ($Property.Value -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Property.Value)) {
        throw "$Document release_classification must be a non-empty JSON string when present."
    }
    $Value = [string]$Property.Value
    if ($Value -notin @(
            "signed-production-candidate",
            "unsigned-internal-release",
            "unsigned-test-only"
        )) {
        throw "$Document contains an unsupported release_classification."
    }
    return $Value
}

function Test-ReleaseSignatureContract {
    param(
        [object]$Manifest,
        [object]$BuildMetadata,
        [string]$ExecutablePath,
        [string]$ApprovedSignerThumbprint,
        [switch]$AllowUnsignedTestMedia,
        [switch]$AllowUnsignedInternalRelease
    )
    if ($AllowUnsignedTestMedia -and $AllowUnsignedInternalRelease) {
        throw "Unsigned test and unsigned internal release modes are mutually exclusive."
    }
    $ManifestClassification = Get-OptionalReleaseClassification `
        -Object $Manifest -Document "release-manifest.json"
    $MetadataClassification = Get-OptionalReleaseClassification `
        -Object $BuildMetadata -Document "build-metadata.json"
    if ($ManifestClassification -ne $MetadataClassification) {
        throw "Release manifest and build metadata classifications are inconsistent."
    }
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
        if ($AllowUnsignedTestMedia) {
            throw "-AllowUnsignedTestMedia is valid only for actually unsigned internal-test media."
        }
        if ($AllowUnsignedInternalRelease) {
            throw "-AllowUnsignedInternalRelease is valid only for an actually unsigned internal release."
        }
        if ($ManifestClassification -and
            $ManifestClassification -ne "signed-production-candidate") {
            throw "Signed release metadata has an incompatible release_classification."
        }
        if ($ApprovedSignerThumbprint -notmatch '^[A-F0-9]{40}$') {
            throw "A signed release requires an independently approved signer thumbprint."
        }
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
                $ManifestThumbprint -or
            ($Signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() -ne
                $ApprovedSignerThumbprint) {
            throw "Authenticode status, signer thumbprint or timestamp does not match release metadata."
        }
    }
    else {
        if ($AllowUnsignedInternalRelease) {
            if ($ManifestClassification -ne "unsigned-internal-release") {
                throw "-AllowUnsignedInternalRelease requires metadata explicitly classified as unsigned-internal-release."
            }
        }
        elseif ($AllowUnsignedTestMedia) {
            # Empty classification remains accepted solely for already-built
            # legacy test media. New builds state unsigned-test-only explicitly.
            if ($ManifestClassification -and
                $ManifestClassification -ne "unsigned-test-only") {
                throw "-AllowUnsignedTestMedia accepts only unsigned-test-only media."
            }
        }
        else {
            throw "Unsigned Agent media is refused by default. Use the separately controlled internal-release or test-media switch only for a matching release classification."
        }
        if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
            if ($AllowUnsignedInternalRelease) {
                throw "An unsigned internal release cannot claim an approved signer thumbprint."
            }
            throw "Unsigned test media cannot claim an approved production signer thumbprint."
        }
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
    param(
        [string]$ApplicationRoot,
        [string]$RuntimeDirectory,
        [string]$ApprovedSignerThumbprint,
        [switch]$AllowUnsignedTestMedia,
        [switch]$AllowUnsignedInternalRelease,
        [switch]$RequireModelTrustStore
    )
    $Executable = Join-Path $RuntimeDirectory "MineGuardEnterpriseAgent.exe"
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $null }

    $MetadataRoot = Join-Path $ApplicationRoot "release-metadata"
    $DeployRoot = Join-Path $ApplicationRoot "deploy\windows"
    $ModelTrustPath = Join-Path $MetadataRoot `
        "model-credential-trust.json"
    $VersionPath = Join-Path $MetadataRoot "VERSION.txt"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $BuildMetadataPath = Join-Path $MetadataRoot "build-metadata.json"
    $ChecksumsPath = Join-Path $MetadataRoot "SHA256SUMS.txt"
    $RequiredInstalledPaths = @(
        $MetadataRoot, $DeployRoot, $VersionPath, $ManifestPath,
        $BuildMetadataPath, $ChecksumsPath
    )
    if ($RequireModelTrustStore) {
        $RequiredInstalledPaths += $ModelTrustPath
    }
    foreach ($Required in $RequiredInstalledPaths) {
        if (-not (Test-Path -LiteralPath $Required)) {
            if ($env:MINEGUARD_RELEASE_AUDIT_MODE -eq "installer-guard-test") {
                Write-Host "MINEGUARD_RELEASE_AUDIT_MARKER=agent-missing-metadata"
            }
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
        if ($Relative -notin @(
                "VERSION.txt", "build-metadata.json", "release-manifest.json",
                "model-credential-trust.json"
            ) -or
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
        -ExecutablePath $Executable `
        -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
        -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
        -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease
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

function Set-EACanonicalProductTreeAcl {
    param(
        [string]$Path,
        [switch]$RootTraverseOnly,
        [switch]$Recurse,
        [switch]$UsersReadExecute
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Canonical ACL target does not exist: $Path"
    }
    $RootItem = Get-Item -LiteralPath $Path -Force
    if (-not $RootItem.PSIsContainer -or
        ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Canonical product-tree ACL root must be an ordinary directory: $Path"
    }
    $Administrators = New-Object Security.Principal.SecurityIdentifier(
        "S-1-5-32-544"
    )
    $System = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $AllServices = New-Object Security.Principal.SecurityIdentifier("S-1-5-80-0")
    $Users = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-545")
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $None = [Security.AccessControl.PropagationFlags]::None
    $ContainerAndObject = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit

    function Set-OneCanonicalAcl {
        param([IO.FileSystemInfo]$Item, [switch]$TraverseOnly)
        $IsDirectory = $Item.PSIsContainer
        $Security = if ($IsDirectory) {
            New-Object Security.AccessControl.DirectorySecurity
        }
        else {
            New-Object Security.AccessControl.FileSecurity
        }
        $Security.SetAccessRuleProtection($true, $false)
        $Security.SetOwner($Administrators)
        $Inheritance = if ($IsDirectory) {
            $ContainerAndObject
        }
        else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        foreach ($Definition in @(
            [pscustomobject]@{
                Sid = $System
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
                Inheritance = $Inheritance
            },
            [pscustomobject]@{
                Sid = $Administrators
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
                Inheritance = $Inheritance
            },
            [pscustomobject]@{
                Sid = $AllServices
                Rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
                Inheritance = $(if ($IsDirectory -and $TraverseOnly) {
                    [Security.AccessControl.InheritanceFlags]::None
                } else { $Inheritance })
            }
        )) {
            $Rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $Definition.Sid,
                $Definition.Rights,
                $Definition.Inheritance,
                $None,
                $Allow
            )
            [void]$Security.AddAccessRule($Rule)
        }
        if ($UsersReadExecute) {
            $UsersRule = New-Object Security.AccessControl.FileSystemAccessRule(
                $Users,
                [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                $Inheritance,
                $None,
                $Allow
            )
            [void]$Security.AddAccessRule($UsersRule)
        }
        if ($IsDirectory) {
            [IO.Directory]::SetAccessControl($Item.FullName, $Security)
            $Applied = [IO.Directory]::GetAccessControl($Item.FullName)
        }
        else {
            [IO.File]::SetAccessControl($Item.FullName, $Security)
            $Applied = [IO.File]::GetAccessControl($Item.FullName)
        }
        if (-not $Applied.AreAccessRulesProtected) {
            throw "Canonical ACL unexpectedly retained inheritance: $($Item.FullName)"
        }
    }

    # Set a complete protected DACL in one SetAccessControl operation per item;
    # never expose the /reset -> /inheritance:r partial-ACL window.
    Set-OneCanonicalAcl -Item $RootItem -TraverseOnly:$RootTraverseOnly
    if ($Recurse) {
        foreach ($Item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Canonical product tree cannot contain a reparse point: $($Item.FullName)"
            }
            Set-OneCanonicalAcl -Item $Item
        }
    }
}

function Assert-EAExistingAclSafe {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$AllowAllServicesRead
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Existing Agent state ACL target is a reparse point: $Path"
    }
    $trusted = @{
        'S-1-5-18' = $true
        'S-1-5-32-544' = $true
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $trusted[$identity.User.Value] = $true
    }
    # Use only atomic mutation bits here. Composite rights such as Modify
    # contain ReadAndExecute and would reject a legitimate read-only ACE.
    $dangerous = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $security = Get-Acl -LiteralPath $item.FullName
    $owner = $security.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    if (-not $trusted.ContainsKey($owner)) {
        throw "Existing Agent state path has an untrusted owner: $Path"
    }
    foreach ($rule in $security.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = $rule.IdentityReference.Value
        if ($trusted.ContainsKey($sid)) { continue }
        $allowedAllServicesRead = $AllowAllServicesRead -and
            $sid -eq 'S-1-5-80-0' -and
            ($rule.FileSystemRights -band $dangerous) -eq 0
        if (-not $allowedAllServicesRead) {
            throw "Existing Agent state path exposes access to a broad/different identity: $Path ($sid)"
        }
    }
}

function Set-EAStateRootMarkerAcl {
    param([Parameter(Mandatory = $true)] [string]$StateRootPath)
    $markerPath = Join-Path $StateRootPath `
        '.mineguard-enterprise-agent-instances.json'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw "Agent StateRoot marker is missing before ACL hardening: $markerPath"
    }
    $item = Get-Item -LiteralPath $markerPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Agent StateRoot marker ACL target is unsafe: $markerPath"
    }
    $administrators = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administrators)
    foreach ($sid in @($system, $administrators)) {
        [void]$security.AddAccessRule(
            (New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $allow
            )))
    }
    [IO.File]::SetAccessControl($markerPath, $security)
    $applied = [IO.File]::GetAccessControl($markerPath)
    if (-not $applied.AreAccessRulesProtected) {
        throw "Agent StateRoot marker ACL retained inheritance: $markerPath"
    }
}

function Get-EADerivedServiceIdentity {
    param([string]$ServiceId)
    if ($ServiceId -notmatch '^MineGuardEnterpriseAgent-[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "A registered Agent service has an invalid instance-derived name: $ServiceId"
    }
    $ScPath = Join-Path $env:SystemRoot "System32\sc.exe"
    if (-not (Test-Path -LiteralPath $ScPath -PathType Leaf)) {
        throw "Windows Service Controller is missing: $ScPath"
    }
    $Output = @(& $ScPath showsid $ServiceId 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe showsid failed for $ServiceId"
    }
    $SidMatches = [regex]::Matches(
        ($Output -join "`n"),
        '(?<![0-9])S-1-5-80-(?:[0-9]+-){4}[0-9]+(?![0-9])',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($SidMatches.Count -ne 1) {
        throw "Windows did not return exactly one service SID for $ServiceId."
    }
    return [pscustomobject]@{
        AccountName = "NT SERVICE\$ServiceId"
        Sid = $SidMatches[0].Value
    }
}

function Assert-EARegisteredRuntimeServiceIdentity {
    param([string]$ServiceId)
    $Services = @(Get-CimInstance Win32_Service -Filter "Name='$ServiceId'" `
        -ErrorAction Stop)
    if ($Services.Count -ne 1) {
        throw "The registered Agent service identity cannot be resolved uniquely: $ServiceId"
    }
    $Service = $Services[0]
    $Identity = Get-EADerivedServiceIdentity -ServiceId $ServiceId
    if (-not ([string]$Service.StartName).Equals(
            $Identity.AccountName, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            "Registered service $ServiceId uses legacy/shared identity " +
            "$($Service.StartName). Run Uninstall-EnterpriseAgentService.ps1 " +
            "with the documented legacy migration switch, then reinstall it."
        )
    }
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceId"
    $Registry = Get-ItemProperty -LiteralPath $RegistryPath `
        -Name "ServiceSidType" -ErrorAction Stop
    if ([int]$Registry.ServiceSidType -ne 1) {
        throw "Registered service $ServiceId does not have unrestricted service SID type. Reinstall it before runtime upgrade."
    }
    try {
        $TranslatedSid = (New-Object Security.Principal.NTAccount(
            $Identity.AccountName
        )).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Dedicated service account cannot be resolved for $ServiceId."
    }
    if (-not $TranslatedSid.Equals(
            $Identity.Sid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Dedicated service account SID does not match the service-derived SID for $ServiceId."
    }
}

function ConvertTo-EANativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $Builder = New-Object Text.StringBuilder
    [void]$Builder.Append([char]'"')
    $BackslashCount = 0
    foreach ($Character in $Value.ToCharArray()) {
        if ($Character -eq [char]'\') {
            $BackslashCount += 1
            continue
        }
        if ($Character -eq [char]'"') {
            [void]$Builder.Append([char]'\', (($BackslashCount * 2) + 1))
            [void]$Builder.Append([char]'"')
            $BackslashCount = 0
            continue
        }
        if ($BackslashCount -gt 0) {
            [void]$Builder.Append([char]'\', $BackslashCount)
            $BackslashCount = 0
        }
        [void]$Builder.Append($Character)
    }
    if ($BackslashCount -gt 0) {
        [void]$Builder.Append([char]'\', ($BackslashCount * 2))
    }
    [void]$Builder.Append([char]'"')
    return $Builder.ToString()
}

function Test-EAConfigurationEnvironmentName {
    param([string]$Name)
    foreach ($Prefix in @(
        "ENTERPRISE_", "PLATFORM_", "REGULATORY_", "AGENT_V2_",
        "DEEPSEEK_", "COAL_NEWS_", "MINEGUARD_"
    )) {
        if ($Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-EACandidateModelLockTrustCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$LockPath,
        [Parameter(Mandatory = $true)][string]$TrustStorePath,
        [ValidateRange(1024, 1048576)][int]$MaximumOutputCharacters = 65536
    )
    $Arguments = @(
        "model-credential-lock-trust-check",
        "--lock", $LockPath,
        "--trust-store", $TrustStorePath
    )
    $Serialized = @($Arguments | ForEach-Object {
        if ($null -eq $_) { throw "Candidate trust check has a null argument." }
        ConvertTo-EANativeArgument -Value ([string]$_)
    }) -join ' '
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = $Serialized
    $StartInfo.WorkingDirectory = Split-Path -Parent $Executable
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $StartInfo.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    foreach ($Name in @($StartInfo.EnvironmentVariables.Keys)) {
        if (Test-EAConfigurationEnvironmentName -Name ([string]$Name)) {
            $StartInfo.EnvironmentVariables.Remove([string]$Name)
        }
    }
    $StartInfo.EnvironmentVariables["PYTHONUTF8"] = "1"
    $StartInfo.EnvironmentVariables["PYTHONUNBUFFERED"] = "1"

    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) {
            throw "Candidate Agent trust-check process could not be started."
        }
        $Stdout = $Process.StandardOutput.ReadToEnd()
        $Stderr = $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()
        if ($Stdout.Length -gt $MaximumOutputCharacters -or
            $Stderr.Length -gt $MaximumOutputCharacters) {
            throw "Candidate Agent trust-check output exceeded the safety limit."
        }
        if ($Process.ExitCode -ne 0) {
            $SafeError = $Stderr.Trim()
            if ([string]::IsNullOrWhiteSpace($SafeError)) {
                $SafeError = "candidate Agent exited with code $($Process.ExitCode)"
            }
            throw "Candidate model trust rejected the active lock: $SafeError"
        }
        try { $Result = $Stdout | ConvertFrom-Json }
        catch { throw "Candidate model trust check did not return valid JSON." }
        if ($null -eq $Result -or $Result -is [Array] -or
            $Result.PSObject.Properties.Count -eq 0) {
            throw "Candidate model trust check did not return one JSON object."
        }
        return $Result
    }
    finally { $Process.Dispose() }
}

function Assert-EAUpgradeOrdinaryLeaf {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateRange(1, 16777216)][long]$MaximumBytes = 1MB
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name is missing: $Path"
    }
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $Item.Length -le 0 -or $Item.Length -gt $MaximumBytes) {
        throw "$Name is unsafe or outside its size limit: $Path"
    }
}

function Read-EAUpgradeModelBindings {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-EAUpgradeOrdinaryLeaf -Path $Path -Name "Instance configuration" `
        -MaximumBytes 1MB
    $SelectedNames = @(
        "ENTERPRISE_MINE_ID",
        "ENTERPRISE_SYSTEM_ID",
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE",
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE",
        "MINEGUARD_AGENT_MODEL_TRUST_STORE"
    )
    $Seen = @{}
    $Selected = @{}
    $LineNumber = 0
    foreach ($Original in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $LineNumber += 1
        $Line = $Original.Trim()
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith("#")) {
            continue
        }
        if ($Line.StartsWith("export ")) {
            $Line = $Line.Substring(7).TrimStart()
        }
        $Separator = $Line.IndexOf("=")
        if ($Separator -lt 1) {
            throw "Invalid KEY=VALUE record at config line $LineNumber."
        }
        $Key = $Line.Substring(0, $Separator).Trim()
        if ($Key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or
            $Seen.ContainsKey($Key)) {
            throw "Invalid or duplicate config key at line $LineNumber."
        }
        $Seen[$Key] = $true
        $Value = $Line.Substring($Separator + 1).Trim()
        if ($Value.Length -ge 1 -and $Value[0] -in @([char]34, [char]39)) {
            if ($Value.Length -lt 2 -or
                $Value[$Value.Length - 1] -ne $Value[0]) {
                throw "Unterminated quoted config value at line $LineNumber."
            }
            $Value = $Value.Substring(1, $Value.Length - 2)
        }
        if ($Value.IndexOf([char]0) -ge 0) {
            throw "Config value contains a forbidden control character at line $LineNumber."
        }
        if ($SelectedNames -contains $Key) { $Selected[$Key] = $Value }
    }
    return $Selected
}

function Invoke-EAActiveModelTrustCompatibilityPreflight {
    param(
        [Parameter(Mandatory = $true)][string]$InstancesRoot,
        [Parameter(Mandatory = $true)][string]$CandidateExecutable,
        [Parameter(Mandatory = $true)][string]$CandidateTrustStore
    )
    if (-not (Test-Path -LiteralPath $InstancesRoot)) {
        Write-Host "Candidate model trust preflight: no existing StateRoot."
        return
    }
    if (-not (Test-Path -LiteralPath $InstancesRoot -PathType Container)) {
        throw "StateRoot exists but is not a directory: $InstancesRoot"
    }
    Assert-StateRootOrdinary -Root $InstancesRoot
    $MarkerPath = Join-Path $InstancesRoot `
        ".mineguard-enterprise-agent-instances.json"
    $HasMarker = Test-Path -LiteralPath $MarkerPath -PathType Leaf
    if ($HasMarker) { Assert-StateRootMarker -Root $InstancesRoot }

    $ManagedCount = 0
    foreach ($Item in Get-ChildItem -LiteralPath $InstancesRoot -Force) {
        if (-not $Item.PSIsContainer) {
            if ($HasMarker -and $Item.FullName.Equals(
                    $MarkerPath, [StringComparison]::OrdinalIgnoreCase
                )) {
                continue
            }
            throw "StateRoot contains an unrecognized top-level item: $($Item.FullName)"
        }
        if (-not (Test-RecognizableLegacyInstance -Directory $Item)) {
            throw "StateRoot contains an unrecognized instance directory: $($Item.FullName)"
        }

        $ConfigPath = Join-Path $Item.FullName "config\agent.env"
        $Values = Read-EAUpgradeModelBindings -Path $ConfigPath
        $LockName = "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE"
        $StoreName = "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE"
        $TrustName = "MINEGUARD_AGENT_MODEL_TRUST_STORE"
        $LockValue = if ($Values.ContainsKey($LockName)) {
            ([string]$Values[$LockName]).Trim()
        } else { "" }
        $StoreValue = if ($Values.ContainsKey($StoreName)) {
            ([string]$Values[$StoreName]).Trim()
        } else { "" }
        if ($Values.ContainsKey($TrustName) -and
            -not [string]::IsNullOrWhiteSpace([string]$Values[$TrustName])) {
            throw "Instance $($Item.Name) overrides the release model trust store."
        }
        if ([string]::IsNullOrWhiteSpace($LockValue) -and
            [string]::IsNullOrWhiteSpace($StoreValue)) {
            continue
        }
        if ([string]::IsNullOrWhiteSpace($LockValue) -or
            [string]::IsNullOrWhiteSpace($StoreValue)) {
            throw "Instance $($Item.Name) has an incomplete managed model pointer pair."
        }

        $ExpectedLock = Join-Path $Item.FullName `
            "config\model-credential-lock.json"
        $ExpectedState = [IO.Path]::ChangeExtension(
            $ExpectedLock, ".state.json"
        )
        $ExpectedStore = Join-Path $Item.FullName `
            "config\model-credentials.dpapi"
        Assert-LocalFixedPath -Name "Instance model lock" -PathValue $LockValue
        Assert-LocalFixedPath -Name "Instance model secret store" `
            -PathValue $StoreValue
        $ResolvedLock = [IO.Path]::GetFullPath($LockValue)
        $ResolvedStore = [IO.Path]::GetFullPath($StoreValue)
        if (-not $ResolvedLock.Equals(
                [IO.Path]::GetFullPath($ExpectedLock),
                [StringComparison]::OrdinalIgnoreCase
            ) -or -not $ResolvedStore.Equals(
                [IO.Path]::GetFullPath($ExpectedStore),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Instance $($Item.Name) model credential pointers are not fixed inside its config directory."
        }
        Assert-EAUpgradeOrdinaryLeaf -Path $ResolvedLock `
            -Name "Instance model lock" -MaximumBytes 1MB
        Assert-EAUpgradeOrdinaryLeaf -Path $ExpectedState `
            -Name "Instance model anti-rollback state" -MaximumBytes 1MB
        Assert-EAUpgradeOrdinaryLeaf -Path $ResolvedStore `
            -Name "Instance model secret store" -MaximumBytes 1MB

        $Result = Invoke-EACandidateModelLockTrustCheck `
            -Executable $CandidateExecutable -LockPath $ResolvedLock `
            -TrustStorePath $CandidateTrustStore
        if ($Result.valid -isnot [bool] -or -not [bool]$Result.valid -or
            [string]$Result.verification_scope -ne
                "signed-envelope-and-issuer-only" -or
            $Result.secret_store_accessed -isnot [bool] -or
            [bool]$Result.secret_store_accessed -or
            $Result.api_key_accessed -isnot [bool] -or
            [bool]$Result.api_key_accessed -or
            -not $Values.ContainsKey("ENTERPRISE_MINE_ID") -or
            -not $Values.ContainsKey("ENTERPRISE_SYSTEM_ID") -or
            [string]$Result.mine_id -ne
                [string]$Values["ENTERPRISE_MINE_ID"] -or
            [string]$Result.system_id -ne
                [string]$Values["ENTERPRISE_SYSTEM_ID"] -or
            [string]::IsNullOrWhiteSpace([string]$Result.issuer_id) -or
            [string]::IsNullOrWhiteSpace([string]$Result.issuer_key_id)) {
            throw "Candidate model trust check returned an invalid or cross-instance result for $($Item.Name)."
        }
        $ManagedCount += 1
    }
    Write-Host (
        "Candidate model trust preflight passed for $ManagedCount active " +
        "managed model credential lock(s)."
    )
}

function Set-EAInstalledInstanceAcls {
    param(
        [string]$ApplicationRoot,
        [string]$InstancesRoot,
        [switch]$FormalMode,
        [switch]$VerifyOnly,
        [string]$HelperRoot = $ApplicationRoot
    )
    $HelperPath = Join-Path $HelperRoot `
        "deploy\windows\EnterpriseAgent.WindowsSafety.ps1"
    if (-not (Test-Path -LiteralPath $HelperPath -PathType Leaf)) {
        throw "Installed Windows safety helper is missing: $HelperPath"
    }
    . $HelperPath
    foreach ($Directory in Get-ChildItem -LiteralPath $InstancesRoot `
        -Directory -Force) {
        if ($Directory.Name -notmatch
                '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
            throw "StateRoot contains an unrecognized instance directory: $($Directory.FullName)"
        }
        $InstanceContext = Get-EAInstanceContext -InstanceName $Directory.Name `
            -InstallRoot $ApplicationRoot -StateRoot $InstancesRoot
        Assert-EAInstanceGlobalIsolation -Context $InstanceContext
        if (-not [bool]$InstanceContext.Metadata.acl_hardened) {
            if ($FormalMode) {
                throw "Formal runtime installation refuses an instance created with -SkipAcl: $($Directory.Name)"
            }
            Write-Warning "DEVELOPMENT ONLY instance retains skipped ACL hardening: $($Directory.Name)"
            continue
        }
        if ($VerifyOnly) {
            Assert-EAInstanceCanonicalAcl -Context $InstanceContext
            Assert-EAInstanceWatchAcls -Context $InstanceContext
            continue
        }
        Set-EAInstanceCanonicalAcl -Context $InstanceContext
        if ($FormalMode) {
            Assert-EAInstanceWatchAcls -Context $InstanceContext
        }
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

if ($BuildFromSource) {
    if ($AllowUnsignedTestMedia -or $AllowUnsignedInternalRelease -or
        -not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedReleaseManifestSha256)) {
        throw "-BuildFromSource is already an explicit development-only mode and cannot be combined with binary media trust options."
    }
}
else {
    if ($AllowUnsignedTestMedia -and $AllowUnsignedInternalRelease) {
        throw "-AllowUnsignedTestMedia and -AllowUnsignedInternalRelease are mutually exclusive."
    }
    $ApprovedSignerThumbprint = Get-NormalizedApprovedSignerThumbprint `
        -Value $ApprovedSignerThumbprint `
        -AllowEmpty:($AllowUnsignedTestMedia -or $AllowUnsignedInternalRelease)
    if ($AllowUnsignedTestMedia) {
        if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
            throw "Unsigned test media cannot be combined with an approved production signer thumbprint."
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedReleaseManifestSha256)) {
            throw "ExpectedReleaseManifestSha256 cannot be used with unsigned test media."
        }
        Write-Warning "UNSIGNED TEST MEDIA MODE: this installation is not production-trusted and cannot be used for a formal service."
    }
    elseif ($AllowUnsignedInternalRelease) {
        if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
            throw "An unsigned internal release cannot be combined with an approved signer thumbprint."
        }
        Write-Warning (
            "UNSIGNED INTERNAL RELEASE MODE: no publisher identity is available. " +
            "Continue only after the Setup SHA-256 was verified against " +
            "independently delivered approval material."
        )
        $ExpectedReleaseManifestSha256 = (
            $ExpectedReleaseManifestSha256 -replace '\s', ''
        ).ToUpperInvariant()
        if ($ExpectedReleaseManifestSha256 -cnotmatch '^[A-F0-9]{64}$') {
            throw "INTERNAL-UNSIGNED product installation requires ExpectedReleaseManifestSha256 from the already verified Setup."
        }
        $CandidateManifestPath = Join-Path $SourceRoot "release-manifest.json"
        if (-not (Test-Path -LiteralPath $CandidateManifestPath -PathType Leaf)) {
            throw "INTERNAL-UNSIGNED product installation is missing release-manifest.json."
        }
        $ActualReleaseManifestSha256 = (Get-FileHash -LiteralPath `
            $CandidateManifestPath -Algorithm SHA256).Hash
        if (-not $ActualReleaseManifestSha256.Equals(
                $ExpectedReleaseManifestSha256,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "The Agent child release manifest does not match the SHA-256 fixed by the verified Setup; candidate execution is blocked."
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace(
            $ExpectedReleaseManifestSha256
        )) {
        throw "ExpectedReleaseManifestSha256 is reserved for -AllowUnsignedInternalRelease."
    }
}

$RegisteredServices = @(Get-Service -Name "MineGuardEnterpriseAgent-*" `
    -ErrorAction SilentlyContinue)
$RunningServices = @($RegisteredServices | Where-Object { $_.Status -ne "Stopped" })
if ($RunningServices.Count -ne 0) {
    throw "Stop all MineGuardEnterpriseAgent-* services before installing or upgrading the shared runtime."
}
foreach ($RegisteredService in $RegisteredServices) {
    Assert-EARegisteredRuntimeServiceIdentity -ServiceId $RegisteredService.Name
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
    $ReleaseContract = Test-BinaryReleaseManifest -ReleaseRoot $SourceRoot `
        -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
        -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
        -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease
    $Manifest = $ReleaseContract.Manifest
    $CandidateBuildMetadata = $ReleaseContract.BuildMetadata
    $CandidateVersionText = [string]$ReleaseContract.Version
    Assert-EABinaryInstallPathBudget -Root $InstallRoot -Manifest $Manifest
    $ExistingVersionText = Test-InstalledBinaryRuntime `
        -ApplicationRoot $InstallRoot -RuntimeDirectory $RuntimeRoot `
        -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
        -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
        -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease
    if ($null -ne $ExistingVersionText -and
        [version]$CandidateVersionText -lt [version]$ExistingVersionText) {
        throw "Agent downgrade from $ExistingVersionText to $CandidateVersionText is blocked by default."
    }
    $BinaryRuntime = Join-Path $SourceRoot "runtime"
    $BinaryExecutable = Join-Path $BinaryRuntime "MineGuardEnterpriseAgent.exe"
    $ModelTrustSource = Join-Path $SourceRoot "model-credential-trust.json"
    foreach ($Required in @($BinaryExecutable, $DeploySource, $ModelTrustSource)) {
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

    # This uses only each active lock's signed envelope and the candidate
    # release trust store.  It deliberately runs before creating/adopting
    # directories, rewriting ACLs or switching runtime/release metadata, and
    # never opens the DPAPI secret store.  A removed issuer key therefore
    # leaves the complete prior installation untouched.
    Invoke-EAActiveModelTrustCompatibilityPreflight `
        -InstancesRoot $StateRoot `
        -CandidateExecutable $BinaryExecutable `
        -CandidateTrustStore $ModelTrustSource

    # Do not create or adopt mutable product/state directories until the binary
    # media, signature contract, executable version and upgrade direction have
    # all passed their read-only checks above.
    $StateRootExistedBeforeInstall =
        Test-Path -LiteralPath $StateRoot -PathType Container
    if ($HasTrustedBootstrapTransaction -and
        $StateRootExistedBeforeInstall) {
        Assert-EAExistingAclSafe -Path $StateRoot -AllowAllServicesRead
        $ExistingStateMarker = Join-Path $StateRoot `
            '.mineguard-enterprise-agent-instances.json'
        if (Test-Path -LiteralPath $ExistingStateMarker -PathType Leaf) {
            # Legacy markers inherited ALL SERVICES read access from the
            # StateRoot. Accept that non-secret migration state read-only; the
            # marker is made administrative-only immediately after adoption.
            Assert-EAExistingAclSafe -Path $ExistingStateMarker `
                -AllowAllServicesRead
        }
    }
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Initialize-EnterpriseAgentStateRoot -Root $StateRoot `
        -BootstrapTransactionId $TrustedBootstrapTransactionId
    Set-EAStateRootMarkerAcl -StateRootPath $StateRoot
    if ($HasTrustedBootstrapTransaction) {
        # Legacy adoption may create the transaction-bound marker immediately
        # above. Use the authenticated candidate helper now, while still
        # evaluating instances against the real application root and before
        # any runtime/deploy switch.
        Set-EAInstalledInstanceAcls -ApplicationRoot $InstallRoot `
            -HelperRoot $SourceRoot -InstancesRoot $StateRoot `
            -FormalMode:(-not $AllowUnsignedTestMedia) -VerifyOnly
    }
    Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
    Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
    # The trusted Setup bootstrap has authenticated the candidate source.
    # Harden the destination parent before executable staging directories are
    # created so ordinary local users cannot modify a copied file before use.
    if (-not $HasTrustedBootstrapTransaction) {
        Set-EACanonicalProductTreeAcl -Path $InstallRoot
    }

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
    $RollbackErrors = [System.Collections.Generic.List[string]]::new()
    $CleanupErrors = [System.Collections.Generic.List[string]]::new()
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
        Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
        Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $StateRoot
        Assert-StateRootOrdinary -Root $StateRoot
        Assert-StateRootMarker -Root $StateRoot
        if (-not $HasTrustedBootstrapTransaction -or
            -not $StateRootExistedBeforeInstall) {
            Set-EACanonicalProductTreeAcl -Path $StateRoot `
                -RootTraverseOnly
        }
        Set-EACanonicalProductTreeAcl -Path $StagedRuntime -Recurse
        Set-EACanonicalProductTreeAcl -Path $StagedDeploy `
            -UsersReadExecute -Recurse
        $StagedExecutable = Join-Path $StagedRuntime "MineGuardEnterpriseAgent.exe"
        Test-ReleaseSignatureContract -Manifest $Manifest `
            -BuildMetadata $CandidateBuildMetadata -ExecutablePath $StagedExecutable `
            -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
            -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
            -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease
        if ($AllowUnsignedInternalRelease) {
            Write-Warning "Installing an explicitly classified unsigned internal Enterprise Agent release."
        }
        elseif (-not [bool]$Manifest.authenticode_signed) {
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
        foreach ($LateRegisteredService in @(Get-Service `
            -Name "MineGuardEnterpriseAgent-*" -ErrorAction SilentlyContinue)) {
            Assert-EARegisteredRuntimeServiceIdentity `
                -ServiceId $LateRegisteredService.Name
        }
        Assert-NoEnterpriseAgentRuntimeProcesses -RuntimeDirectory $RuntimeRoot
        # Inno has already created its uninstaller, documentation and uninstall
        # helper by this point. Canonicalize the complete existing/staged tree
        # while every switch flag is still false, so any ACL failure is handled
        # by the guarded transaction before candidate code becomes active.
        if (-not $HasTrustedBootstrapTransaction) {
            Set-EACanonicalProductTreeAcl -Path $InstallRoot -Recurse
        }
        foreach ($PublicTree in @(
            $StagedDeploy,
            $DeployTarget,
            (Join-Path $InstallRoot "docs")
        )) {
            if (Test-Path -LiteralPath $PublicTree -PathType Container) {
                Set-EACanonicalProductTreeAcl -Path $PublicTree `
                    -UsersReadExecute -Recurse
            }
        }
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
        foreach ($MetadataName in @(
            "VERSION.txt", "build-metadata.json", "release-manifest.json",
            "model-credential-trust.json", "SHA256SUMS.txt"
        )) {
            $MetadataSource = Join-Path $SourceRoot $MetadataName
            if (-not (Test-Path -LiteralPath $MetadataSource -PathType Leaf)) {
                throw "Binary release trace metadata is missing: $MetadataName"
            }
            Copy-Item -LiteralPath $MetadataSource -Destination $StagedMetadata
        }
        $StagedMetadataFiles = @(Get-ChildItem -LiteralPath $StagedMetadata -File -Force)
        if ($StagedMetadataFiles.Count -ne 5) {
            throw "Installed release metadata staging must contain exactly five files."
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
            "VERSION.txt", "build-metadata.json", "release-manifest.json",
            "model-credential-trust.json"
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
        Set-EACanonicalProductTreeAcl -Path $StagedMetadata `
            -Recurse
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
        Set-EAInstalledInstanceAcls -ApplicationRoot $InstallRoot `
            -InstancesRoot $StateRoot `
            -FormalMode:(-not $AllowUnsignedTestMedia) `
            -VerifyOnly:$HasTrustedBootstrapTransaction
        $PostInstallVersion = Test-InstalledBinaryRuntime `
            -ApplicationRoot $InstallRoot -RuntimeDirectory $RuntimeRoot `
            -ApprovedSignerThumbprint $ApprovedSignerThumbprint `
            -AllowUnsignedTestMedia:$AllowUnsignedTestMedia `
            -AllowUnsignedInternalRelease:$AllowUnsignedInternalRelease `
            -RequireModelTrustStore
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
        $AllRecoveryErrors = $RollbackErrors.ToArray() + $CleanupErrors.ToArray()
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
    Initialize-EnterpriseAgentStateRoot -Root $StateRoot `
        -BootstrapTransactionId $TrustedBootstrapTransactionId
    Set-EAStateRootMarkerAcl -StateRootPath $StateRoot
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
if (-not $BuildFromSource) {
    # The guarded binary transaction applied every ACL before its first switch.
    # Post-commit is read-only and cannot convert a successful commit into a
    # failed Setup with no rollback path.
    try {
        $UnsafePostCommitAcl = @(
            @((Get-Item -LiteralPath $InstallRoot -Force)) + @(
                Get-ChildItem -LiteralPath $InstallRoot -Force -Recurse
            ) | Where-Object {
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Get-Acl -LiteralPath $_.FullName).AreAccessRulesProtected
            }
        )
        if ($UnsafePostCommitAcl.Count -ne 0) {
            Write-Warning (
                "Post-commit ACL verification found a non-canonical item; " +
                "the committed release remains active and requires administrator review: " +
                $UnsafePostCommitAcl[0].FullName
            )
        }
    }
    catch {
        Write-Warning (
            "Post-commit ACL verification could not complete; the committed " +
            "release remains active: $($_.Exception.Message)"
        )
    }
}
if ($BuildFromSource) {
    Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
    Assert-NotBroadProductRoot -Name "InstallRoot" -PathValue $InstallRoot
    Set-EACanonicalProductTreeAcl -Path $InstallRoot `
        -Recurse
    Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
    Assert-NotBroadProductRoot -Name "StateRoot" -PathValue $StateRoot
    Assert-StateRootOrdinary -Root $StateRoot
    Assert-StateRootMarker -Root $StateRoot
    Set-EACanonicalProductTreeAcl -Path $StateRoot `
        -RootTraverseOnly
    Set-EAInstalledInstanceAcls -ApplicationRoot $InstallRoot `
        -InstancesRoot $StateRoot
}

Write-Host "Enterprise Agent runtime installed."
Write-Host "Executable: $InstalledExecutable"
Write-Host "Instances: $StateRoot"
Write-Host "Next: run New-EnterpriseAgentInstance.ps1 once for each mine."
