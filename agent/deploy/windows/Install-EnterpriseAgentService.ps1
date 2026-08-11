[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$WinSWPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$WinSWExpectedSha256,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string]$ApprovedSignerThumbprint = "",
    [string]$ExpectedRuntimeSha256 = "",
    [string]$ExpectedReleaseManifestSha256 = "",
    [switch]$AllowIncompleteDemo,
    [switch]$AllowUnsignedTestMedia,
    [switch]$AllowUnsignedInternalRelease,
    [switch]$Start
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
    throw "Windows PowerShell 5.1 or later is required."
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}
if ($AllowUnsignedInternalRelease -and
    ($AllowUnsignedTestMedia -or $AllowIncompleteDemo)) {
    throw "-AllowUnsignedInternalRelease is a formal-only mode and cannot be combined with demo or unsigned-test switches."
}
$FormalServiceInstall = -not $AllowIncompleteDemo -and -not $AllowUnsignedTestMedia
if ($FormalServiceInstall -and -not $Start) {
    throw "Formal service installation requires -Start and must pass the bound health check before it can succeed."
}

function Get-NormalizedApprovedSignerThumbprint {
    param([string]$Value, [switch]$AllowEmpty)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($AllowEmpty) { return "" }
        throw "Formal service installation requires -ApprovedSignerThumbprint from independently approved offline material."
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

function Get-NormalizedExpectedRuntimeSha256 {
    param([string]$Value, [switch]$Required)
    $Normalized = ($Value -replace '\s', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($Normalized)) {
        if ($Required) {
            throw "INTERNAL-UNSIGNED service installation requires -ExpectedRuntimeSha256 from independently approved offline material."
        }
        return ""
    }
    if ($Normalized -cnotmatch '^[A-F0-9]{64}$') {
        throw "ExpectedRuntimeSha256 must contain exactly 64 hexadecimal SHA-256 characters."
    }
    return $Normalized
}

function Get-NormalizedExpectedReleaseManifestSha256 {
    param([string]$Value, [switch]$Required)
    $Normalized = ($Value -replace '\s', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($Normalized)) {
        if ($Required) {
            throw "INTERNAL-UNSIGNED service installation requires -ExpectedReleaseManifestSha256 from independently approved offline material."
        }
        return ""
    }
    if ($Normalized -cnotmatch '^[A-F0-9]{64}$') {
        throw "ExpectedReleaseManifestSha256 must contain exactly 64 hexadecimal SHA-256 characters."
    }
    return $Normalized
}

function Assert-FormalAgentAuthenticode {
    param([string]$ExecutablePath, [string]$ApprovedThumbprint)
    $Signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($Signature.Status.ToString() -ne "Valid" -or
        $null -eq $Signature.SignerCertificate -or
        $null -eq $Signature.TimeStamperCertificate) {
        throw "Formal service installation requires an Authenticode-valid, timestamped Agent executable."
    }
    $ActualThumbprint = (
        $Signature.SignerCertificate.Thumbprint -replace '\s', ''
    ).ToUpperInvariant()
    if ($ActualThumbprint -ne $ApprovedThumbprint) {
        throw "The installed Agent signer does not match the independently approved signer thumbprint."
    }
}

function Assert-InternalUnsignedRuntime {
    param([string]$ExecutablePath, [string]$ExpectedSha256)
    $Signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($Signature.Status.ToString() -ne "NotSigned" -or
        $null -ne $Signature.SignerCertificate -or
        $null -ne $Signature.TimeStamperCertificate) {
        throw "An INTERNAL-UNSIGNED accepts only an actually unsigned executable; signed or invalid signatures require a different trust mode."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $ActualSha256 = (Get-FileHash -LiteralPath $ExecutablePath `
            -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($ActualSha256 -ne $ExpectedSha256) {
            throw "Agent runtime SHA-256 does not match the independently approved value."
        }
    }
}

function Get-RequiredReleaseBoolean {
    param([object]$Object, [string]$Name, [string]$Document)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $Property.Value -isnot [bool]) {
        throw "$Document must contain a JSON boolean property named $Name."
    }
    return [bool]$Property.Value
}

function Get-RequiredReleaseNullableString {
    param([object]$Object, [string]$Name, [string]$Document)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or
        ($null -ne $Property.Value -and $Property.Value -isnot [string])) {
        throw "$Document must contain a JSON string-or-null property named $Name."
    }
    return [string]$Property.Value
}

function Assert-InstalledAgentReleaseClassification {
    param(
        [string]$ApplicationRoot,
        [string]$ApprovedThumbprint,
        [switch]$ExpectUnsigned,
        [switch]$ExpectInternalUnsignedRelease,
        [switch]$AllowMissingDevelopmentMetadata
    )
    if ($ExpectUnsigned -and $ExpectInternalUnsignedRelease) {
        throw "Unsigned test and INTERNAL-UNSIGNED classifications are mutually exclusive."
    }
    $MetadataRoot = Join-Path $ApplicationRoot "release-metadata"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $BuildMetadataPath = Join-Path $MetadataRoot "build-metadata.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $BuildMetadataPath -PathType Leaf)) {
        if ($AllowMissingDevelopmentMetadata) {
            Write-Warning "DEVELOPMENT ONLY: source runtime has no installed binary release classification metadata."
            return
        }
        throw "Installed Agent release classification metadata is missing."
    }
    Assert-OrdinaryFile -Name "Installed release manifest" `
        -PathValue $ManifestPath -MaximumBytes 8388608
    Assert-OrdinaryFile -Name "Installed build metadata" `
        -PathValue $BuildMetadataPath -MaximumBytes 8388608
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $BuildMetadata = Get-Content -LiteralPath $BuildMetadataPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    catch { throw "Installed Agent release classification metadata is invalid JSON." }
    if ($Manifest.format -ne "mineguard-enterprise-agent-windows-binary-v1" -or
        $Manifest.product -ne "MineGuard Enterprise Agent" -or
        $Manifest.architecture -ne "x64" -or
        $Manifest.entrypoint -ne "runtime/MineGuardEnterpriseAgent.exe" -or
        $BuildMetadata.format -ne "mineguard-enterprise-agent-build-metadata-v1" -or
        $BuildMetadata.product -ne "MineGuard Enterprise Agent" -or
        $BuildMetadata.architecture -ne "x64" -or
        [string]$Manifest.version -ne [string]$BuildMetadata.version) {
        throw "Installed Agent release metadata has the wrong classification identity."
    }
    $ManifestSigned = Get-RequiredReleaseBoolean -Object $Manifest `
        -Name "authenticode_signed" -Document "release-manifest.json"
    $BuildSigned = Get-RequiredReleaseBoolean -Object $BuildMetadata `
        -Name "authenticode_signed" -Document "build-metadata.json"
    $ManifestTimestamped = Get-RequiredReleaseBoolean -Object $Manifest `
        -Name "timestamp_verified" -Document "release-manifest.json"
    $BuildTimestamped = Get-RequiredReleaseBoolean -Object $BuildMetadata `
        -Name "timestamp_verified" -Document "build-metadata.json"
    $ManifestThumbprint = (Get-RequiredReleaseNullableString -Object $Manifest `
        -Name "signing_certificate_thumbprint" -Document "release-manifest.json")
    $BuildThumbprint = (Get-RequiredReleaseNullableString -Object $BuildMetadata `
        -Name "signing_certificate_thumbprint" -Document "build-metadata.json")
    $ManifestTimestampUrl = Get-RequiredReleaseNullableString -Object $Manifest `
        -Name "timestamp_url" -Document "release-manifest.json"
    $BuildTimestampUrl = Get-RequiredReleaseNullableString -Object $BuildMetadata `
        -Name "timestamp_url" -Document "build-metadata.json"
    $ManifestClassificationProperty = `
        $Manifest.PSObject.Properties["release_classification"]
    $BuildClassificationProperty = `
        $BuildMetadata.PSObject.Properties["release_classification"]
    $ManifestClassification = if ($null -eq $ManifestClassificationProperty) {
        ""
    } elseif ($ManifestClassificationProperty.Value -is [string]) {
        [string]$ManifestClassificationProperty.Value
    } else {
        throw "release-manifest.json release_classification must be a JSON string."
    }
    $BuildClassification = if ($null -eq $BuildClassificationProperty) {
        ""
    } elseif ($BuildClassificationProperty.Value -is [string]) {
        [string]$BuildClassificationProperty.Value
    } else {
        throw "build-metadata.json release_classification must be a JSON string."
    }
    if ($ManifestClassification -ne $BuildClassification -or
        $ManifestClassification -notin @(
            "", "signed-production-candidate",
            "unsigned-internal-release", "unsigned-test-only"
        )) {
        throw "Installed Agent release classifications are missing, inconsistent or unsupported."
    }
    $ManifestThumbprint = ($ManifestThumbprint -replace '\s', '').ToUpperInvariant()
    $BuildThumbprint = ($BuildThumbprint -replace '\s', '').ToUpperInvariant()
    if ($ManifestSigned -ne $BuildSigned -or
        $ManifestTimestamped -ne $BuildTimestamped -or
        $ManifestTimestamped -ne $ManifestSigned) {
        throw "Installed Agent signature classification booleans are inconsistent."
    }
    if ($ExpectUnsigned) {
        if ($ManifestClassification -and
            $ManifestClassification -ne "unsigned-test-only") {
            throw "Unsigned test service requires unsigned-test-only metadata."
        }
        if ($ManifestSigned -or
            -not [string]::IsNullOrWhiteSpace($ManifestThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($BuildThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($ManifestTimestampUrl) -or
            -not [string]::IsNullOrWhiteSpace($BuildTimestampUrl)) {
            throw "Unsigned test service requires metadata classified as unsigned with no signer or timestamp claim."
        }
        return
    }
    if ($ExpectInternalUnsignedRelease) {
        if ($ManifestClassification -ne "unsigned-internal-release" -or
            $ManifestSigned -or
            -not [string]::IsNullOrWhiteSpace($ManifestThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($BuildThumbprint) -or
            -not [string]::IsNullOrWhiteSpace($ManifestTimestampUrl) -or
            -not [string]::IsNullOrWhiteSpace($BuildTimestampUrl)) {
            throw "An INTERNAL-UNSIGNED service requires explicitly classified unsigned metadata with no signer or timestamp claim."
        }
        return
    }
    if ($ManifestClassification -and
        $ManifestClassification -ne "signed-production-candidate") {
        throw "Signed formal service requires signed-production-candidate metadata."
    }
    $TimestampUri = $null
    if (-not $ManifestSigned -or
        $ManifestThumbprint -ne $ApprovedThumbprint -or
        $BuildThumbprint -ne $ApprovedThumbprint -or
        $ManifestTimestampUrl -ne $BuildTimestampUrl -or
        -not [uri]::TryCreate($ManifestTimestampUrl, [UriKind]::Absolute, [ref]$TimestampUri) -or
        $TimestampUri.Scheme -ne "https" -or
        [string]::IsNullOrWhiteSpace($TimestampUri.DnsSafeHost) -or
        -not [string]::IsNullOrWhiteSpace($TimestampUri.UserInfo)) {
        throw "Installed Agent metadata does not classify the binary under the independently approved signer and HTTPS timestamp contract."
    }
}

function Assert-InstalledAgentReleaseTree {
    param(
        [string]$ApplicationRoot,
        [string]$ExpectedManifestSha256
    )
    $MetadataRoot = Join-Path $ApplicationRoot "release-metadata"
    $RuntimeRoot = Join-Path $ApplicationRoot "runtime"
    $DeployRoot = Join-Path $ApplicationRoot "deploy\windows"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $ChecksumsPath = Join-Path $MetadataRoot "SHA256SUMS.txt"
    foreach ($Tree in @($RuntimeRoot, $DeployRoot, $MetadataRoot)) {
        Assert-OrdinaryDirectoryTree -Name "Installed Agent release tree" -Root $Tree
    }
    Assert-OrdinaryFile -Name "Installed release manifest" `
        -PathValue $ManifestPath -MaximumBytes 8388608
    Assert-OrdinaryFile -Name "Installed release checksums" `
        -PathValue $ChecksumsPath -MaximumBytes 16777216
    $ActualManifestSha256 = (Get-FileHash -LiteralPath $ManifestPath `
        -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($ActualManifestSha256 -ne $ExpectedManifestSha256) {
        throw "Installed Agent release-manifest SHA-256 does not match the independently approved value."
    }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    catch { throw "Installed Agent release manifest is invalid JSON." }
    if ($Manifest.format -ne "mineguard-enterprise-agent-windows-binary-v1" -or
        $Manifest.product -ne "MineGuard Enterprise Agent" -or
        $Manifest.architecture -ne "x64" -or
        $Manifest.entrypoint -ne "runtime/MineGuardEnterpriseAgent.exe") {
        throw "Installed Agent release manifest has the wrong product identity."
    }

    $Expected = @{}
    foreach ($Entry in @($Manifest.files)) {
        $Relative = [string]$Entry.path
        if ([string]::IsNullOrWhiteSpace($Relative) -or
            [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains(':') -or
            $Relative.Contains('\') -or $Relative -ne $Relative.Trim() -or
            ($Relative.Split('/') -contains '') -or
            ($Relative.Split('/') -contains '.') -or
            ($Relative.Split('/') -contains '..') -or
            $Relative -in @("release-manifest.json", "SHA256SUMS.txt") -or
            $Expected.ContainsKey($Relative)) {
            throw "Installed Agent release manifest contains an unsafe or duplicate path: $Relative"
        }
        $DeclaredBytes = 0L
        if (-not [long]::TryParse([string]$Entry.bytes, [ref]$DeclaredBytes) -or
            $DeclaredBytes -lt 0 -or [string]$Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "Installed Agent release manifest contains invalid file evidence: $Relative"
        }
        $InstalledPath = if ($Relative.StartsWith(
                "runtime/", [StringComparison]::Ordinal
            )) {
            Join-Path $RuntimeRoot $Relative.Substring("runtime/".Length).Replace('/', '\')
        }
        elseif ($Relative.StartsWith(
                "deploy/windows/", [StringComparison]::Ordinal
            )) {
            Join-Path $DeployRoot $Relative.Substring("deploy/windows/".Length).Replace('/', '\')
        }
        elseif ($Relative -in @(
                "VERSION.txt", "build-metadata.json",
                "model-credential-trust.json"
            )) {
            Join-Path $MetadataRoot $Relative
        }
        else {
            throw "Installed Agent release manifest contains an unmappable path: $Relative"
        }
        Assert-OrdinaryFile -Name "Installed Agent release file $Relative" `
            -PathValue $InstalledPath
        $Item = Get-Item -LiteralPath $InstalledPath -Force
        $Digest = (Get-FileHash -LiteralPath $InstalledPath -Algorithm SHA256).Hash
        if ([long]$Item.Length -ne $DeclaredBytes -or
            -not $Digest.Equals(
                [string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Installed Agent release tree does not match the approved manifest: $Relative"
        }
        $Expected[$Relative] = $InstalledPath
    }
    if ($Expected.Count -eq 0 -or
        -not $Expected.ContainsKey("runtime/MineGuardEnterpriseAgent.exe")) {
        throw "Installed Agent release manifest has no executable file set."
    }

    $Actual = @{}
    foreach ($File in Get-ChildItem -LiteralPath $RuntimeRoot -File -Recurse -Force) {
        $Relative = "runtime/" + $File.FullName.Substring(
            $RuntimeRoot.Length
        ).TrimStart('\').Replace('\', '/')
        $Actual[$Relative] = $File.FullName
    }
    foreach ($File in Get-ChildItem -LiteralPath $DeployRoot -File -Recurse -Force) {
        $Relative = "deploy/windows/" + $File.FullName.Substring(
            $DeployRoot.Length
        ).TrimStart('\').Replace('\', '/')
        if ($Actual.ContainsKey($Relative)) {
            throw "Installed Agent release has a duplicate mapped path: $Relative"
        }
        $Actual[$Relative] = $File.FullName
    }
    foreach ($File in Get-ChildItem -LiteralPath $MetadataRoot -File -Recurse -Force) {
        $Relative = $File.FullName.Substring($MetadataRoot.Length).TrimStart('\').Replace('\', '/')
        if ($Relative -in @("release-manifest.json", "SHA256SUMS.txt")) {
            continue
        }
        if ($Relative -notin @(
                "VERSION.txt", "build-metadata.json",
                "model-credential-trust.json"
            ) -or $Actual.ContainsKey($Relative)) {
            throw "Installed Agent release metadata has an unexpected path: $Relative"
        }
        $Actual[$Relative] = $File.FullName
    }
    if ($Actual.Count -ne $Expected.Count) {
        throw "Installed Agent active file set differs from the approved release manifest."
    }
    foreach ($Relative in $Actual.Keys) {
        if (-not $Expected.ContainsKey($Relative)) {
            throw "Installed Agent release contains an unapproved file: $Relative"
        }
    }

    $ChecksumClaims = @{}
    foreach ($Line in Get-Content -LiteralPath $ChecksumsPath -Encoding UTF8) {
        if ($Line -notmatch '^(?<hash>[A-Fa-f0-9]{64}) \*(?<path>[^\r\n]+)$') {
            throw "Installed Agent SHA256SUMS.txt has an invalid line."
        }
        $Relative = [string]$Matches['path']
        if ($ChecksumClaims.ContainsKey($Relative)) {
            throw "Installed Agent SHA256SUMS.txt contains a duplicate path: $Relative"
        }
        $ChecksumClaims[$Relative] = ([string]$Matches['hash']).ToUpperInvariant()
    }
    if ($ChecksumClaims.Count -ne ($Expected.Count + 1) -or
        -not $ChecksumClaims.ContainsKey("release-manifest.json") -or
        $ChecksumClaims["release-manifest.json"] -ne $ActualManifestSha256) {
        throw "Installed Agent SHA256SUMS.txt does not bind the approved release manifest."
    }
    foreach ($Entry in @($Manifest.files)) {
        $Relative = [string]$Entry.path
        if (-not $ChecksumClaims.ContainsKey($Relative) -or
            $ChecksumClaims[$Relative] -ne ([string]$Entry.sha256).ToUpperInvariant()) {
            throw "Installed Agent SHA256SUMS.txt disagrees with the approved manifest: $Relative"
        }
    }
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
    $Prefix = $CanonicalRoot + "\"
    if (-not $CanonicalPath.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
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
    $InstanceRootRaw = Join-Path $Root $Name
    $InstanceRoot = Assert-SafeLocalFixedNtfsPath -Name "InstanceRoot" -PathValue $InstanceRootRaw
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
        throw "Service installation refuses an instance created with -SkipAcl. Recreate it with ACL hardening."
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
    Assert-OrdinaryFile -Name "Instance environment file" -PathValue $ExpectedConfig
    foreach ($DirectoryName in @("config", "data", "logs", "backups", "inbox", "service")) {
        if (-not (Test-Path -LiteralPath (Join-Path $InstanceRoot $DirectoryName) -PathType Container)) {
            throw "Instance directory is missing: $DirectoryName"
        }
    }
    return [PSCustomObject]@{
        Root = $InstanceRoot
        ConfigPath = $ExpectedConfig
        ServiceId = $ExpectedServiceId
        Metadata = $Metadata
    }
}

function ConvertTo-XmlText {
    param([string]$Value)
    return [Security.SecurityElement]::Escape($Value)
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Test-EAConfigurationEnvironmentName {
    param([string]$Name)
    if ($Name -in @(
        "MINEGUARD_AGENT_API_KEY",
        "MINEGUARD_AGENT_BASE_URL",
        "MINEGUARD_AGENT_MODEL",
        "MINEGUARD_AGENT_TIMEOUT_SECONDS",
        "MINEGUARD_AGENT_MAX_RETRIES",
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE",
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE",
        "MINEGUARD_AGENT_MODEL_TRUST_STORE"
    )) {
        return $true
    }
    foreach ($Prefix in @(
        "ENTERPRISE_", "PLATFORM_", "REGULATORY_", "AGENT_V2_",
        "DEEPSEEK_", "COAL_NEWS_", "MINEGUARD_SERVICE_"
    )) {
        if ($Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-IsolatedAgentConfigCheck {
    param(
        [string]$ExecutablePath,
        [string[]]$ArgumentList,
        [string]$ProductionMode,
        [string]$FourEyesRequired,
        [string]$ProvisioningManagedRequired
    )
    $OriginalEnvironment = @{}
    foreach ($Entry in @(Get-ChildItem Env:)) {
        if (Test-EAConfigurationEnvironmentName -Name ([string]$Entry.Name)) {
            $OriginalEnvironment[[string]$Entry.Name] = [string]$Entry.Value
        }
    }
    try {
        foreach ($Name in @($OriginalEnvironment.Keys)) {
            [Environment]::SetEnvironmentVariable(
                $Name, $null, [EnvironmentVariableTarget]::Process
            )
        }
        [Environment]::SetEnvironmentVariable(
            "MINEGUARD_SERVICE_PRODUCTION_MODE", $ProductionMode,
            [EnvironmentVariableTarget]::Process
        )
        [Environment]::SetEnvironmentVariable(
            "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED", $FourEyesRequired,
            [EnvironmentVariableTarget]::Process
        )
        [Environment]::SetEnvironmentVariable(
            "MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED",
            $ProvisioningManagedRequired,
            [EnvironmentVariableTarget]::Process
        )
        Invoke-NativeChecked -FilePath $ExecutablePath -ArgumentList $ArgumentList
    }
    finally {
        # Also clear any names a child/tooling hook added after the snapshot,
        # then restore the administrator shell exactly as it was found.
        foreach ($Entry in @(Get-ChildItem Env:)) {
            if (Test-EAConfigurationEnvironmentName -Name ([string]$Entry.Name)) {
                [Environment]::SetEnvironmentVariable(
                    ([string]$Entry.Name), $null,
                    [EnvironmentVariableTarget]::Process
                )
            }
        }
        foreach ($Name in @($OriginalEnvironment.Keys)) {
            [Environment]::SetEnvironmentVariable(
                $Name, [string]$OriginalEnvironment[$Name],
                [EnvironmentVariableTarget]::Process
            )
        }
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

function Assert-ServiceUsesDedicatedAccount {
    param([object]$Service, [string]$ServiceId, [string]$ExpectedAccount)
    if (-not ([string]$Service.StartName).Equals(
            $ExpectedAccount, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Windows service $ServiceId does not use its dedicated virtual service account."
    }
}

function Get-ServiceExecutablePath {
    param([object]$Service, [string]$ServiceId)
    $PathName = ([string]$Service.PathName).Trim()
    if ($PathName -match '^"([^"\r\n]+)"\s*$') {
        return $Matches[1]
    }
    if ($PathName -match '^[^"\r\n]+$') {
        return $PathName
    }
    throw "Windows service $ServiceId has an unsafe or argument-bearing executable path."
}

function Assert-ServiceTargetsWrapper {
    param([object]$Service, [string]$ServiceId, [string]$ExpectedWrapper)
    $RegisteredRaw = Get-ServiceExecutablePath -Service $Service -ServiceId $ServiceId
    $RegisteredPath = Assert-SafeLocalFixedNtfsPath -Name "Win32_Service PathName" -PathValue $RegisteredRaw
    if (-not $RegisteredPath.Equals($ExpectedWrapper, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Windows service $ServiceId executable path does not equal the expected instance wrapper."
    }
}

function Remove-ServiceRegistrationChecked {
    param(
        [string]$ServiceId,
        [string]$ExpectedWrapper,
        [string]$ExpectedAccount
    )
    $Service = Get-RegisteredService -ServiceId $ServiceId
    if ($null -eq $Service) { return }
    Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $ExpectedWrapper
    Assert-ServiceUsesDedicatedAccount -Service $Service -ServiceId $ServiceId `
        -ExpectedAccount $ExpectedAccount
    if (-not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase)) {
        Stop-Service -Name $ServiceId -Force -ErrorAction Stop
        $Deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 200
            $Service = Get-RegisteredService -ServiceId $ServiceId
            if ($null -eq $Service) { return }
            Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $ExpectedWrapper
            Assert-ServiceUsesDedicatedAccount -Service $Service -ServiceId $ServiceId `
                -ExpectedAccount $ExpectedAccount
        } while (-not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase) -and
            [DateTime]::UtcNow -lt $Deadline)
        if (-not ([string]$Service.State).Equals("Stopped", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows service did not stop within 30 seconds: $ServiceId"
        }
    }
    $Service = Get-RegisteredService -ServiceId $ServiceId
    if ($null -eq $Service) { return }
    Assert-ServiceTargetsWrapper -Service $Service -ServiceId $ServiceId -ExpectedWrapper $ExpectedWrapper
    Assert-ServiceUsesDedicatedAccount -Service $Service -ServiceId $ServiceId `
        -ExpectedAccount $ExpectedAccount
    $ScPath = Join-Path $env:SystemRoot "System32\sc.exe"
    & $ScPath delete $ServiceId | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete failed with exit code $LASTEXITCODE for $ServiceId"
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 200
        $Service = Get-RegisteredService -ServiceId $ServiceId
    } while ($null -ne $Service -and [DateTime]::UtcNow -lt $Deadline)
    if ($null -ne $Service) {
        throw "Windows service registration was not removed within 30 seconds: $ServiceId"
    }
}

function Write-NewFileDurably {
    param([string]$PathValue, [byte[]]$Bytes)
    $Stream = $null
    try {
        $Stream = [IO.File]::Open(
            $PathValue, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    }
    finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
    }
}

Assert-InstanceName -Value $InstanceName

# Validate raw caller-controlled paths before GetFullPath can reinterpret them.
$InstallRoot = Assert-SafeLocalFixedNtfsPath -Name "InstallRoot" -PathValue $InstallRoot
$StateRoot = Assert-SafeLocalFixedNtfsPath -Name "StateRoot" -PathValue $StateRoot
$WinSWPath = Assert-SafeLocalFixedNtfsPath -Name "WinSWPath" -PathValue $WinSWPath
Assert-OrdinaryDirectoryTree -Name "InstallRoot" -Root $InstallRoot
Assert-OrdinaryDirectoryTree -Name "StateRoot" -Root $StateRoot
Assert-StateRootOwnershipMarker -Root $StateRoot
Assert-OrdinaryFile -Name "WinSW executable" -PathValue $WinSWPath

$ActualWinSWHash = (Get-FileHash -LiteralPath $WinSWPath -Algorithm SHA256).Hash
if (-not $ActualWinSWHash.Equals($WinSWExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "WinSW SHA-256 does not match the approved value."
}

$Instance = Read-ValidatedInstanceMetadata -Root $StateRoot -Name $InstanceName
$InstanceRoot = $Instance.Root
$ConfigPath = $Instance.ConfigPath
$ServiceId = $Instance.ServiceId
$TemplatePath = Assert-SafeLocalFixedNtfsPath -Name "Service XML template" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\enterprise-agent-service.xml.template")
$SafetyHelperPath = Assert-SafeLocalFixedNtfsPath -Name "Windows safety helper" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\EnterpriseAgent.WindowsSafety.ps1")
$HealthScriptPath = Assert-SafeLocalFixedNtfsPath -Name "Agent health script" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\Test-EnterpriseAgentHealth.ps1")
$AgentExecutable = Join-Path $InstallRoot "runtime\MineGuardEnterpriseAgent.exe"
$UsingDevelopmentExecutable = $false
if (-not (Test-Path -LiteralPath $AgentExecutable -PathType Leaf)) {
    $DevelopmentExecutable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
    if (Test-Path -LiteralPath $DevelopmentExecutable -PathType Leaf) {
        Write-Warning "Using the source-development Python runtime. Production media must use MineGuardEnterpriseAgent.exe."
        $AgentExecutable = $DevelopmentExecutable
        $UsingDevelopmentExecutable = $true
    }
}
$AgentExecutable = Assert-SafeLocalFixedNtfsPath -Name "Agent executable" -PathValue $AgentExecutable
Assert-OrdinaryFile -Name "Service XML template" -PathValue $TemplatePath -MaximumBytes 1048576
Assert-OrdinaryFile -Name "Windows safety helper" -PathValue $SafetyHelperPath -MaximumBytes 4194304
Assert-OrdinaryFile -Name "Agent health script" -PathValue $HealthScriptPath -MaximumBytes 4194304
Assert-OrdinaryFile -Name "Agent executable" -PathValue $AgentExecutable

$ApprovedSignerThumbprint = Get-NormalizedApprovedSignerThumbprint `
    -Value $ApprovedSignerThumbprint `
    -AllowEmpty:($AllowUnsignedTestMedia -or $AllowUnsignedInternalRelease)
$ExpectedRuntimeSha256 = Get-NormalizedExpectedRuntimeSha256 `
    -Value $ExpectedRuntimeSha256
$ExpectedReleaseManifestSha256 = Get-NormalizedExpectedReleaseManifestSha256 `
    -Value $ExpectedReleaseManifestSha256 `
    -Required:$AllowUnsignedInternalRelease
if (-not $AllowUnsignedInternalRelease -and
    (-not [string]::IsNullOrWhiteSpace($ExpectedRuntimeSha256) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedReleaseManifestSha256))) {
    throw "Runtime/release-manifest SHA-256 approvals are reserved for -AllowUnsignedInternalRelease."
}
if ($AllowUnsignedTestMedia) {
    if (-not $AllowIncompleteDemo) {
        throw "-AllowUnsignedTestMedia requires -AllowIncompleteDemo so an unsigned service can never enter production mode."
    }
    if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
        throw "-ApprovedSignerThumbprint cannot be combined with -AllowUnsignedTestMedia; test mode must not impersonate formal approval."
    }
    Assert-InstalledAgentReleaseClassification -ApplicationRoot $InstallRoot `
        -ExpectUnsigned `
        -AllowMissingDevelopmentMetadata:$UsingDevelopmentExecutable
    $TestSignature = Get-AuthenticodeSignature -LiteralPath $AgentExecutable
    if ($TestSignature.Status.ToString() -ne "NotSigned" -or
        $null -ne $TestSignature.SignerCertificate -or
        $null -ne $TestSignature.TimeStamperCertificate) {
        throw "-AllowUnsignedTestMedia accepts only an actually unsigned executable; signed or invalid signatures cannot bypass formal trust."
    }
    Write-Warning "UNSIGNED DEMO/TEST ONLY: this service is not production-ready."
}
elseif ($AllowUnsignedInternalRelease) {
    if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
        throw "-ApprovedSignerThumbprint cannot be combined with -AllowUnsignedInternalRelease."
    }
    Assert-InstalledAgentReleaseTree -ApplicationRoot $InstallRoot `
        -ExpectedManifestSha256 $ExpectedReleaseManifestSha256
    Assert-InstalledAgentReleaseClassification -ApplicationRoot $InstallRoot `
        -ExpectInternalUnsignedRelease
    Assert-InternalUnsignedRuntime -ExecutablePath $AgentExecutable `
        -ExpectedSha256 $ExpectedRuntimeSha256
    Write-Warning (
        "INTERNAL-UNSIGNED: publisher identity is not available. The Agent " +
        "complete standalone tree matched the independently approved release-manifest SHA-256; preserve that " +
        "approval record for every install and upgrade."
    )
}
else {
    if ($UsingDevelopmentExecutable) {
        throw "Formal service installation refuses the source-development Python runtime."
    }
    Assert-InstalledAgentReleaseClassification -ApplicationRoot $InstallRoot `
        -ApprovedThumbprint $ApprovedSignerThumbprint
    Assert-FormalAgentAuthenticode -ExecutablePath $AgentExecutable `
        -ApprovedThumbprint $ApprovedSignerThumbprint
}

# The installed helper is part of the release file set. It is loaded only after
# the executable trust decision above and is used to enforce the same instance
# identity/ACL rules as start, health, backup and restore operations.
. $SafetyHelperPath
$SharedContext = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
if (-not $SharedContext.InstanceRoot.Equals(
        $InstanceRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or -not $SharedContext.ConfigPath.Equals(
        $ConfigPath, [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Shared instance validation does not match the service installation boundary."
}
$ServiceIdentity = $SharedContext.ServiceIdentity
Assert-EAInstanceGlobalIsolation -Context $SharedContext
Assert-EAInstanceWatchAcls -Context $SharedContext

$ServiceProductionMode = if ($AllowIncompleteDemo -or $AllowUnsignedTestMedia) { "false" } else { "true" }
$ServiceFourEyesRequired = if ($AllowIncompleteDemo -or $AllowUnsignedTestMedia) { "false" } else { "true" }
$ServiceProvisioningManagedRequired = if (
    $AllowIncompleteDemo -or $AllowUnsignedTestMedia
) { "false" } else { "true" }
$CheckArguments = @(
    "--env-file", $ConfigPath, "--authoritative-env-file", "config-check"
)
if (-not $AllowIncompleteDemo) {
    $CheckArguments += "--production"
}
Invoke-IsolatedAgentConfigCheck -ExecutablePath $AgentExecutable `
    -ArgumentList $CheckArguments -ProductionMode $ServiceProductionMode `
    -FourEyesRequired $ServiceFourEyesRequired `
    -ProvisioningManagedRequired $ServiceProvisioningManagedRequired
if ($AllowIncompleteDemo) {
    Write-Warning "Installing an explicitly marked incomplete loopback demo service. It is not production-ready."
}

if ($AllowUnsignedInternalRelease) {
    # Re-check immediately before any service state is changed. This expected
    # digest came from outside the unsigned media and is the trust anchor for
    # this explicitly selected deployment mode.
    Assert-InstalledAgentReleaseTree -ApplicationRoot $InstallRoot `
        -ExpectedManifestSha256 $ExpectedReleaseManifestSha256
    Assert-InternalUnsignedRuntime -ExecutablePath $AgentExecutable `
        -ExpectedSha256 $ExpectedRuntimeSha256
}

if ($null -ne (Get-RegisteredService -ServiceId $ServiceId)) {
    throw "Windows service already exists: $ServiceId"
}

$ServiceDirectory = Assert-SafeLocalFixedNtfsPath -Name "Instance service directory" `
    -PathValue (Join-Path $InstanceRoot "service")
$LogDirectory = Assert-SafeLocalFixedNtfsPath -Name "Instance log directory" `
    -PathValue (Join-Path $InstanceRoot "logs")
Assert-PathBelowRoot -Name "Instance service directory" -PathValue $ServiceDirectory -Root $InstanceRoot
Assert-PathBelowRoot -Name "Instance log directory" -PathValue $LogDirectory -Root $InstanceRoot
Assert-OrdinaryDirectoryTree -Name "Instance service directory" -Root $ServiceDirectory
Assert-OrdinaryDirectoryTree -Name "Instance log directory" -Root $LogDirectory

$WrapperBase = Join-Path $ServiceDirectory $ServiceId
$WrapperExecutable = Assert-SafeLocalFixedNtfsPath -Name "WinSW instance wrapper" -PathValue ($WrapperBase + ".exe")
$WrapperXml = Assert-SafeLocalFixedNtfsPath -Name "WinSW instance XML" -PathValue ($WrapperBase + ".xml")
Assert-PathBelowRoot -Name "WinSW instance wrapper" -PathValue $WrapperExecutable -Root $ServiceDirectory
Assert-PathBelowRoot -Name "WinSW instance XML" -PathValue $WrapperXml -Root $ServiceDirectory
foreach ($Target in @($WrapperExecutable, $WrapperXml)) {
    if (Test-Path -LiteralPath $Target) {
        throw "Service installation refuses to overwrite an existing wrapper file: $Target"
    }
}

# Canonicalize the complete private instance tree before publishing executable
# service files. This removes every legacy S-1-5-19 grant from internal state.
Set-EAInstanceCanonicalAcl -Context $SharedContext
Assert-EAInstanceWatchAcls -Context $SharedContext
Assert-EAInstanceGlobalIsolation -Context $SharedContext

$TransactionId = [Guid]::NewGuid().ToString("N")
$TemporaryWrapper = Assert-SafeLocalFixedNtfsPath -Name "Temporary WinSW wrapper" `
    -PathValue (Join-Path $ServiceDirectory (".winsw-" + $TransactionId + ".exe.tmp"))
$TemporaryXml = Assert-SafeLocalFixedNtfsPath -Name "Temporary WinSW XML" `
    -PathValue (Join-Path $ServiceDirectory (".winsw-" + $TransactionId + ".xml.tmp"))
$PublishedWrapper = $false
$PublishedXml = $false
try {
    # Revalidate the approved source immediately before the first mutation.
    Assert-OrdinaryFile -Name "WinSW executable" -PathValue $WinSWPath
    $ActualWinSWHash = (Get-FileHash -LiteralPath $WinSWPath -Algorithm SHA256).Hash
    if (-not $ActualWinSWHash.Equals($WinSWExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "WinSW SHA-256 changed before service installation."
    }
    $WinSWBytes = [IO.File]::ReadAllBytes($WinSWPath)
    Write-NewFileDurably -PathValue $TemporaryWrapper -Bytes $WinSWBytes
    $CopiedWinSWHash = (Get-FileHash -LiteralPath $TemporaryWrapper -Algorithm SHA256).Hash
    if (-not $CopiedWinSWHash.Equals($WinSWExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Copied WinSW wrapper failed the approved SHA-256 check."
    }

    $Xml = [IO.File]::ReadAllText($TemplatePath)
    $Replacements = @{
        "__SERVICE_ID__" = (ConvertTo-XmlText $ServiceId)
        "__SERVICE_NAME__" = (ConvertTo-XmlText ("MineGuard Enterprise Agent - " + $InstanceName))
        "__INSTANCE_NAME__" = (ConvertTo-XmlText $InstanceName)
        "__EXECUTABLE__" = (ConvertTo-XmlText $AgentExecutable)
        "__ENV_FILE__" = (ConvertTo-XmlText $ConfigPath)
        "__WORKING_DIRECTORY__" = (ConvertTo-XmlText $InstanceRoot)
        "__LOG_DIRECTORY__" = (ConvertTo-XmlText $LogDirectory)
        "__SERVICE_ACCOUNT__" = (ConvertTo-XmlText $ServiceIdentity.AccountName)
        "__PRODUCTION_MODE__" = $ServiceProductionMode
        "__FOUR_EYES_REQUIRED__" = $ServiceFourEyesRequired
        "__PROVISIONING_MANAGED_REQUIRED__" = `
            $ServiceProvisioningManagedRequired
    }
    foreach ($Entry in $Replacements.GetEnumerator()) {
        $Xml = $Xml.Replace([string]$Entry.Key, [string]$Entry.Value)
    }
    foreach ($Placeholder in $Replacements.Keys) {
        if ($Xml.Contains([string]$Placeholder)) {
            throw "Service XML still contains an unresolved placeholder: $Placeholder"
        }
    }
    try { $null = [xml]$Xml } catch { throw "Generated WinSW service XML is invalid." }
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Write-NewFileDurably -PathValue $TemporaryXml -Bytes $Utf8NoBom.GetBytes($Xml)

    if ($null -ne (Get-RegisteredService -ServiceId $ServiceId)) {
        throw "Windows service appeared during installation: $ServiceId"
    }
    Move-Item -LiteralPath $TemporaryWrapper -Destination $WrapperExecutable
    $PublishedWrapper = $true
    Move-Item -LiteralPath $TemporaryXml -Destination $WrapperXml
    $PublishedXml = $true
    Assert-OrdinaryFile -Name "Installed WinSW wrapper" -PathValue $WrapperExecutable
    Assert-OrdinaryFile -Name "Installed WinSW XML" -PathValue $WrapperXml -MaximumBytes 1048576
    $InstalledWrapperHash = (Get-FileHash -LiteralPath $WrapperExecutable -Algorithm SHA256).Hash
    if (-not $InstalledWrapperHash.Equals($WinSWExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installed WinSW wrapper failed the approved SHA-256 check."
    }

    Invoke-NativeChecked -FilePath $WrapperExecutable -ArgumentList @("install")
    $RegisteredService = Get-RegisteredService -ServiceId $ServiceId
    if ($null -eq $RegisteredService) {
        throw "WinSW returned success but did not register the expected Windows service."
    }
    Assert-ServiceTargetsWrapper -Service $RegisteredService -ServiceId $ServiceId `
        -ExpectedWrapper $WrapperExecutable
    Assert-ServiceUsesDedicatedAccount -Service $RegisteredService `
        -ServiceId $ServiceId -ExpectedAccount $ServiceIdentity.AccountName
    $ScPath = Join-Path $env:SystemRoot "System32\sc.exe"
    Invoke-NativeChecked -FilePath $ScPath -ArgumentList @(
        "sidtype", $ServiceId, "unrestricted"
    )
    $RegisteredService = Get-RegisteredService -ServiceId $ServiceId
    if ($null -eq $RegisteredService) {
        throw "Windows service disappeared while applying its SID type: $ServiceId"
    }
    Assert-ServiceTargetsWrapper -Service $RegisteredService -ServiceId $ServiceId `
        -ExpectedWrapper $WrapperExecutable
    [void](Assert-EARegisteredServiceIdentity -ServiceId $ServiceId `
        -CimService $RegisteredService)
    if ($Start) {
        Assert-EAInstanceGlobalIsolation -Context $SharedContext
        Assert-EAInstanceWatchAcls -Context $SharedContext
        Start-Service -Name $ServiceId -ErrorAction Stop
        $ServiceController = Get-Service -Name $ServiceId -ErrorAction Stop
        $ServiceController.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(30)
        )
        $RegisteredService = Get-RegisteredService -ServiceId $ServiceId
        if ($null -eq $RegisteredService) {
            throw "Windows service disappeared before its health check: $ServiceId"
        }
        Assert-ServiceTargetsWrapper -Service $RegisteredService `
            -ServiceId $ServiceId -ExpectedWrapper $WrapperExecutable
        [void](Assert-EARegisteredServiceIdentity -ServiceId $ServiceId `
            -CimService $RegisteredService)
        $HealthDeadline = [DateTime]::UtcNow.AddSeconds(30)
        $HealthVerified = $false
        $LastHealthError = "health probe did not run"
        do {
            try {
                & $HealthScriptPath -InstanceName $InstanceName `
                    -InstallRoot $InstallRoot -StateRoot $StateRoot `
                    -TimeoutSeconds 5
                $HealthVerified = $true
                break
            }
            catch {
                $LastHealthError = $_.Exception.Message
                Start-Sleep -Milliseconds 500
            }
        } while ([DateTime]::UtcNow -lt $HealthDeadline)
        if (-not $HealthVerified) {
            throw "Windows service did not pass its bound health check within 30 seconds: $LastHealthError"
        }
    }
}
catch {
    $OriginalError = $_
    $RollbackErrors = New-Object System.Collections.Generic.List[string]
    try {
        $RollbackService = Get-RegisteredService -ServiceId $ServiceId
        if ($null -ne $RollbackService) {
            Assert-ServiceTargetsWrapper -Service $RollbackService -ServiceId $ServiceId `
                -ExpectedWrapper $WrapperExecutable
            Assert-ServiceUsesDedicatedAccount -Service $RollbackService `
                -ServiceId $ServiceId -ExpectedAccount $ServiceIdentity.AccountName
            Remove-ServiceRegistrationChecked -ServiceId $ServiceId `
                -ExpectedWrapper $WrapperExecutable `
                -ExpectedAccount $ServiceIdentity.AccountName
        }
    }
    catch {
        $RollbackErrors.Add($_.Exception.Message)
    }
    $RemainingService = $null
    $RemainingServiceKnown = $false
    $RemainingServiceTargetsWrapper = $false
    try {
        $RemainingService = Get-RegisteredService -ServiceId $ServiceId
        $RemainingServiceKnown = $true
    }
    catch {
        $RollbackErrors.Add($_.Exception.Message)
    }
    if ($RemainingServiceKnown -and $null -ne $RemainingService) {
        try {
            Assert-ServiceTargetsWrapper -Service $RemainingService -ServiceId $ServiceId `
                -ExpectedWrapper $WrapperExecutable
            $RemainingServiceTargetsWrapper = $true
        }
        catch {
            $RollbackErrors.Add($_.Exception.Message)
        }
    }
    if ($RemainingServiceKnown -and -not $RemainingServiceTargetsWrapper) {
        $PublishedFiles = @(
            [PSCustomObject]@{ Path = $WrapperXml; Published = $PublishedXml },
            [PSCustomObject]@{ Path = $WrapperExecutable; Published = $PublishedWrapper }
        )
        foreach ($PublishedFile in $PublishedFiles) {
            if ($PublishedFile.Published -and (Test-Path -LiteralPath $PublishedFile.Path)) {
                try { Remove-Item -LiteralPath $PublishedFile.Path -Force -ErrorAction Stop } catch {
                    $RollbackErrors.Add($_.Exception.Message)
                }
            }
        }
    }
    elseif ($RemainingServiceTargetsWrapper) {
        $RollbackErrors.Add("The service registration remains; wrapper files were preserved to avoid breaking it.")
    }
    else {
        $RollbackErrors.Add("Service state could not be proven; wrapper files were preserved.")
    }
    foreach ($TemporaryPath in @($TemporaryXml, $TemporaryWrapper)) {
        if (Test-Path -LiteralPath $TemporaryPath) {
            try { Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction Stop } catch {
                $RollbackErrors.Add($_.Exception.Message)
            }
        }
    }
    if ($RollbackErrors.Count -gt 0) {
        throw ("Service installation failed: " + $OriginalError.Exception.Message +
            "; rollback was incomplete: " + ($RollbackErrors -join "; "))
    }
    throw $OriginalError
}
finally {
    foreach ($TemporaryPath in @($TemporaryXml, $TemporaryWrapper)) {
        if (Test-Path -LiteralPath $TemporaryPath) {
            Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "Windows service installed: $ServiceId"
Write-Host "Dedicated service identity: $($ServiceIdentity.AccountName) ($($ServiceIdentity.Sid))"
Write-Host "WinSW was supplied locally and was not downloaded by this script."
Write-Host "No user password or application secret was written to service XML or arguments."
if ($AllowIncompleteDemo -or $AllowUnsignedTestMedia) {
    Write-Warning "DEMO/TEST ONLY service installed; remove it before formal deployment."
}
elseif ($AllowUnsignedInternalRelease) {
    Write-Warning "Unsigned internal formal service installed with production, four-eyes and provisioning-managed policies enforced."
    Write-Host "The complete Agent standalone tree matched the independently approved release-manifest SHA-256."
}
else {
    Write-Host "Formal Agent signer matched the independently approved thumbprint."
}
