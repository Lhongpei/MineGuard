[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Files,
    [Parameter(Mandatory = $true)][string]$SignToolPath,
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [Parameter(Mandatory = $true)][uri]$TimestampUrl
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:OS -ne "Windows_NT") {
    throw "Authenticode signing must run on Windows."
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

$SignToolPath = Get-SafeLocalNtfsPath -Name "SignToolPath" -PathValue $SignToolPath
if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
    throw "signtool.exe was not found: $SignToolPath"
}
if ([IO.Path]::GetFileName($SignToolPath) -ne "signtool.exe") {
    throw "SignToolPath must identify signtool.exe."
}

$Thumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
if ($Thumbprint -notmatch '^[A-F0-9]{40}$') {
    throw "CertificateThumbprint must be a 40-digit SHA-1 certificate thumbprint."
}
if ($TimestampUrl.Scheme -ne "https" -or
    [string]::IsNullOrWhiteSpace($TimestampUrl.DnsSafeHost) -or
    -not [string]::IsNullOrWhiteSpace($TimestampUrl.UserInfo)) {
    throw "TimestampUrl must use HTTPS, include a host and contain no user information."
}

$MatchingCertificates = @()
foreach ($StoreDefinition in @(
    [pscustomobject]@{ path = "Cert:\CurrentUser\My"; location = "CurrentUser" },
    [pscustomobject]@{ path = "Cert:\LocalMachine\My"; location = "LocalMachine" }
)) {
    if (Test-Path -LiteralPath $StoreDefinition.path) {
        foreach ($StoreCertificate in Get-ChildItem -LiteralPath $StoreDefinition.path) {
            if (($StoreCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() -eq $Thumbprint) {
                $MatchingCertificates += [pscustomobject]@{
                    certificate = $StoreCertificate
                    location = $StoreDefinition.location
                }
            }
        }
    }
}
if ($MatchingCertificates.Count -ne 1) {
    throw "Exactly one matching signing certificate must exist in CurrentUser/My or LocalMachine/My. Found: $($MatchingCertificates.Count)"
}
$CertificateMatch = $MatchingCertificates[0]
$Certificate = $CertificateMatch.certificate
$CertificateStoreLocation = [string]$CertificateMatch.location
$Now = Get-Date
if ($Now -lt $Certificate.NotBefore -or $Now -gt $Certificate.NotAfter) {
    throw "The signing certificate is not currently valid."
}
$CodeSigningEku = "1.3.6.1.5.5.7.3.3"
$HasCodeSigningEku = $false
foreach ($Extension in $Certificate.Extensions) {
    if ($Extension.Oid.Value -eq "2.5.29.37") {
        $EnhancedKeyUsage = New-Object `
            -TypeName Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension `
            -ArgumentList @($Extension, [bool]$Extension.Critical)
        foreach ($Usage in $EnhancedKeyUsage.EnhancedKeyUsages) {
            if ($Usage.Value -eq $CodeSigningEku) {
                $HasCodeSigningEku = $true
            }
        }
    }
}
if (-not $HasCodeSigningEku) {
    throw "The selected certificate does not declare the Code Signing EKU."
}

$ResolvedFiles = @()
$ResolvedFileSet = @{}
foreach ($File in $Files) {
    $FullPath = Get-SafeLocalNtfsPath -Name "Signing input" -PathValue $File
    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "Signing input does not exist: $FullPath"
    }
    if ([IO.Path]::GetExtension($FullPath) -notin @(".exe", ".dll", ".msi")) {
        throw "Signing input must be an EXE, DLL or MSI: $FullPath"
    }
    if ($ResolvedFileSet.ContainsKey($FullPath)) {
        throw "Signing input is duplicated: $FullPath"
    }
    $ResolvedFileSet[$FullPath] = $true
    $ResolvedFiles += $FullPath
}
if ($ResolvedFiles.Count -eq 0) {
    throw "At least one file is required for signing."
}

foreach ($FullPath in $ResolvedFiles) {
    $SignArguments = @("sign", "/fd", "SHA256")
    if ($CertificateStoreLocation -eq "LocalMachine") {
        $SignArguments += "/sm"
    }
    $SignArguments += @(
        "/sha1", $Thumbprint,
        "/tr", $TimestampUrl.AbsoluteUri,
        "/td", "SHA256",
        $FullPath
    )
    & $SignToolPath @SignArguments
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed with exit code $LASTEXITCODE for $FullPath"
    }
    & $SignToolPath verify /pa /all /v $FullPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool verify failed with exit code $LASTEXITCODE for $FullPath"
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $FullPath
    if ($Signature.Status -ne "Valid") {
        throw "Authenticode status is not Valid for ${FullPath}: $($Signature.Status)"
    }
    if ($null -eq $Signature.SignerCertificate -or
        ($Signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() -ne $Thumbprint) {
        throw "The signer certificate does not match the requested thumbprint: $FullPath"
    }
    if ($null -eq $Signature.TimeStamperCertificate) {
        throw "The signed file has no verifiable timestamp: $FullPath"
    }
    Write-Host "Authenticode signature verified from $CertificateStoreLocation/My: $FullPath"
}
