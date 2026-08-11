[CmdletBinding()]
param(
    [ValidateSet('Install', 'Begin', 'Prepare', 'Commit', 'Rollback', 'Finalize')]
    [string] $TransactionAction = 'Install',
    [string] $TransactionId = '',
    [Parameter(Mandatory = $true)]
    [ValidateSet('Platform', 'EnterpriseAgent')]
    [string] $Product,
    [Parameter(Mandatory = $true)]
    [string] $SourceRoot,
    [Parameter(Mandatory = $true)]
    [string] $ExpectedReleaseManifestSha256,
    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,
    [string] $StateRoot = '',
    [string] $ApprovedSignerThumbprint = '',
    [switch] $AllowUnsignedTestMedia,
    [switch] $AllowUnsignedInternalRelease
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw 'Windows PowerShell 5.1 or later is required.'
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName `
        Security.Principal.WindowsPrincipal -ArgumentList $identity
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The trusted product bootstrap must run as Administrator.'
    }
}

function Get-SafeLocalNtfsPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Label,
        [switch] $MustExist
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -notmatch '^[A-Za-z]:\\') {
        throw "$Label must be an absolute local drive path."
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetPathRoot($full)
    if ($full.Equals($root.TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label cannot be a drive root."
    }
    $drive = New-Object -TypeName IO.DriveInfo -ArgumentList $root
    if (-not $drive.IsReady -or
        $drive.DriveType -ne [IO.DriveType]::Fixed -or
        -not $drive.DriveFormat.Equals('NTFS',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be on a ready local fixed NTFS volume."
    }
    if ($MustExist -and
        -not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "$Label does not exist as a directory: $full"
    }
    $current = $full
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label cannot be under a reparse point: $current"
            }
        }
        if ($current.TrimEnd('\').Equals($root.TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
    return $full
}

function Assert-NoReparseTree {
    param([string] $Path, [string] $Label)
    foreach ($item in @((Get-Item -LiteralPath $Path -Force)) + @(
            Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point: $($item.FullName)"
        }
    }
}

function New-ProtectedDirectorySecurity {
    $administrators = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $system = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in @($administrators, $system)) {
        $rule = New-Object -TypeName `
            Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-ProtectedDirectoryAcl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $actual = Get-Acl -LiteralPath $Path
    if (-not $actual.AreAccessRulesProtected) {
        throw "Protected staging ACL still inherits permissions: $Path"
    }
    $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
    $owner = $actual.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') {
        throw "Protected staging ACL has an unexpected owner: $Path"
    }
    $requiredInheritance = `
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $seen = @{}
    foreach ($rule in $actual.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne $allow -or
            $allowedSids -notcontains $rule.IdentityReference.Value -or
            ($rule.FileSystemRights -band $fullControl) -ne $fullControl -or
            $rule.InheritanceFlags -ne $requiredInheritance -or
            $rule.PropagationFlags -ne `
                [Security.AccessControl.PropagationFlags]::None) {
            throw "Protected staging ACL contains an unexpected principal: $Path"
        }
        $seen[$rule.IdentityReference.Value] = $true
    }
    foreach ($requiredSid in $allowedSids) {
        if (-not $seen.ContainsKey($requiredSid)) {
            throw "Protected staging ACL is missing a required principal: $Path"
        }
    }
}

function Set-ProtectedDirectoryAcl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $acl = New-ProtectedDirectorySecurity
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-ProtectedDirectoryAcl -Path $Path
}

function New-ProtectedStagingDirectory {
    # Windows owns this parent. A fresh unpredictable child is created with its
    # final protected DACL in the same CreateDirectory operation; there is no
    # fixed MineGuard staging parent to pre-create and no create-then-SetAcl
    # interval in which ordinary users can replace executable content.
    $systemRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    $stagingParent = Join-Path $systemRoot 'Temp'
    $stagingParent = Get-SafeLocalNtfsPath -Path $stagingParent `
        -Label 'installer staging parent'
    [void](Get-SafeLocalNtfsPath -Path $stagingParent `
        -Label 'installer staging parent' -MustExist)

    $prefix = if ($Product -eq 'Platform') {
        'mineguard-platform-'
    } else {
        'mineguard-agent-'
    }
    $acl = New-ProtectedDirectorySecurity
    do {
        $candidate = Join-Path $stagingParent (
            $prefix + [Guid]::NewGuid().ToString('N'))
    } while (Test-Path -LiteralPath $candidate)
    [void][IO.Directory]::CreateDirectory($candidate, $acl)
    [void](Get-SafeLocalNtfsPath -Path $candidate `
        -Label 'protected installer staging directory' -MustExist)
    Assert-ProtectedDirectoryAcl -Path $candidate
    return [pscustomobject]@{
        Parent = $stagingParent
        Path = $candidate
    }
}

function Get-ReleaseRelativePath {
    param([string] $Root, [string] $FullName)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($FullName)
    if (-not $full.StartsWith($prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release file escaped its root: $full"
    }
    return $full.Substring($prefix.Length).Replace('\', '/')
}

function Assert-SafeReleasePath {
    param([string] $RelativePath, [string] $Document)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.StartsWith('/') -or
        $RelativePath.StartsWith('\') -or
        $RelativePath.Contains('\') -or
        $RelativePath.Contains(':')) {
        throw "$Document contains an unsafe path: $RelativePath"
    }
    $segments = $RelativePath.Split('/')
    if ($segments -contains '' -or $segments -contains '.' -or
        $segments -contains '..') {
        throw "$Document contains an unsafe path: $RelativePath"
    }
}

function Assert-TrustedReleaseTree {
    param([string] $Root, [string] $ExpectedManifestHash, [string] $Kind)
    Assert-NoReparseTree -Path $Root -Label 'staged release'
    $manifestPath = Join-Path $Root 'release-manifest.json'
    $sumsPath = Join-Path $Root 'SHA256SUMS.txt'
    foreach ($required in @($manifestPath, $sumsPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Staged release is missing: $required"
        }
    }
    $normalizedHash = ($ExpectedManifestHash -replace '\s', '').ToLowerInvariant()
    if ($normalizedHash -cnotmatch '^[a-f0-9]{64}$') {
        throw 'ExpectedReleaseManifestSha256 must be exactly 64 hexadecimal characters.'
    }
    $actualManifestHash = (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualManifestHash -cne $normalizedHash) {
        throw 'The staged child release-manifest does not match the trusted Setup anchor.'
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw "release-manifest.json is invalid: $($_.Exception.Message)"
    }
    $expectedProduct = if ($Kind -eq 'Platform') {
        'MineGuard Platform'
    } else {
        'MineGuard Enterprise Agent'
    }
    $expectedEntryPoint = if ($Kind -eq 'Platform') {
        'runtime/MineGuardPlatform.exe'
    } else {
        'runtime/MineGuardEnterpriseAgent.exe'
    }
    if ([string]$manifest.product -cne $expectedProduct -or
        [string]$manifest.entryPoint -cne $expectedEntryPoint) {
        throw 'The staged release manifest identifies the wrong product or entry point.'
    }

    $manifestFiles = @{}
    foreach ($entry in @($manifest.files)) {
        if ($null -eq $entry) { throw 'release-manifest.json has an empty file entry.' }
        $relative = [string]$entry.path
        Assert-SafeReleasePath -RelativePath $relative `
            -Document 'release-manifest.json'
        if ($relative -in @('release-manifest.json', 'SHA256SUMS.txt') -or
            $manifestFiles.ContainsKey($relative)) {
            throw "release-manifest.json has a duplicate or self reference: $relative"
        }
        if ([string]$entry.sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or
            [long]$entry.bytes -lt 0) {
            throw "release-manifest.json has invalid metadata: $relative"
        }
        $manifestFiles[$relative] = $entry
    }
    $actualManifestFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
        Where-Object {
            (Get-ReleaseRelativePath -Root $Root -FullName $_.FullName) -notin
                @('release-manifest.json', 'SHA256SUMS.txt')
        })
    if ($manifestFiles.Count -ne $actualManifestFiles.Count) {
        throw 'release-manifest.json does not cover the exact staged file set.'
    }
    foreach ($file in $actualManifestFiles) {
        $relative = Get-ReleaseRelativePath -Root $Root -FullName $file.FullName
        if (-not $manifestFiles.ContainsKey($relative)) {
            throw "Staged release contains a file outside release-manifest.json: $relative"
        }
        $entry = $manifestFiles[$relative]
        $digest = (Get-FileHash -LiteralPath $file.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([long]$file.Length -ne [long]$entry.bytes -or
            $digest -cne ([string]$entry.sha256).ToLowerInvariant()) {
            throw "Staged release file failed size or SHA-256 validation: $relative"
        }
    }

    $sumEntries = @{}
    foreach ($line in Get-Content -LiteralPath $sumsPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line,
            '^(?<hash>[A-Fa-f0-9]{64})(?:  | \*)(?<path>.+)$')
        if (-not $match.Success) { throw 'SHA256SUMS.txt has an invalid line.' }
        $relative = [string]$match.Groups['path'].Value
        Assert-SafeReleasePath -RelativePath $relative -Document 'SHA256SUMS.txt'
        if ($relative -eq 'SHA256SUMS.txt' -or $sumEntries.ContainsKey($relative)) {
            throw "SHA256SUMS.txt has a duplicate or self reference: $relative"
        }
        $sumEntries[$relative] = [string]$match.Groups['hash'].Value.ToLowerInvariant()
    }
    $actualSummedFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
        Where-Object {
            (Get-ReleaseRelativePath -Root $Root -FullName $_.FullName) -ne
                'SHA256SUMS.txt'
        })
    if ($sumEntries.Count -ne $actualSummedFiles.Count) {
        throw 'SHA256SUMS.txt does not cover the exact staged file set.'
    }
    foreach ($file in $actualSummedFiles) {
        $relative = Get-ReleaseRelativePath -Root $Root -FullName $file.FullName
        if (-not $sumEntries.ContainsKey($relative)) {
            throw "Staged release contains a file outside SHA256SUMS.txt: $relative"
        }
        $digest = (Get-FileHash -LiteralPath $file.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne $sumEntries[$relative]) {
            throw "SHA256SUMS.txt mismatch: $relative"
        }
    }

    $installerRelative = if ($Kind -eq 'Platform') {
        'deploy/windows/Install-MineGuardPlatform.ps1'
    } else {
        'deploy/windows/Install-EnterpriseAgent.ps1'
    }
    if (-not $manifestFiles.ContainsKey($installerRelative)) {
        throw 'The fixed product installer is not covered by release-manifest.json.'
    }
    return Join-Path $Root $installerRelative.Replace('/', '\')
}

function Remove-ProtectedStagingDirectory {
    param([string] $Path, [string] $ExpectedParent)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    if (-not ([IO.Path]::GetDirectoryName($full)).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -notmatch `
            '^mineguard-(platform|agent)-[a-f0-9]{32}$') {
        throw "Refusing to remove an unexpected staging path: $full"
    }
    Assert-NoReparseTree -Path $full -Label 'staging cleanup target'
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $lastError = $null
    do {
        try { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop }
        catch { $lastError = $_ }
        if (-not (Test-Path -LiteralPath $full)) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $detail = if ($null -eq $lastError) {
        'the directory still exists'
    } else {
        $lastError.Exception.Message
    }
    throw "Unable to clean protected staging directory: $full. $detail"
}

Assert-Administrator
if ($AllowUnsignedTestMedia -and $AllowUnsignedInternalRelease) {
    throw 'Unsigned test and internal-release modes are mutually exclusive.'
}
$source = Get-SafeLocalNtfsPath -Path $SourceRoot `
    -Label 'Inno extracted child release' -MustExist
Assert-NoReparseTree -Path $source -Label 'Inno extracted child release'
$stage = $null
try {
    $stage = New-ProtectedStagingDirectory
    foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $stage.Path `
            -Recurse -Force
    }
    $stagedInstaller = Assert-TrustedReleaseTree -Root $stage.Path `
        -ExpectedManifestHash $ExpectedReleaseManifestSha256 -Kind $Product

    if ($Product -eq 'Platform') {
        $arguments = @{
            SourceDirectory = $stage.Path
            InstallRoot = $InstallRoot
        }
        if ($AllowUnsignedInternalRelease) {
            $arguments['AllowUnsignedInternalRelease'] = $true
            $arguments['ExpectedReleaseManifestSha256'] =
                $ExpectedReleaseManifestSha256
        }
    } else {
        $arguments = @{
            SourceRoot = $stage.Path
            InstallRoot = $InstallRoot
            StateRoot = $StateRoot
        }
        if (-not [string]::IsNullOrWhiteSpace($ApprovedSignerThumbprint)) {
            $arguments['ApprovedSignerThumbprint'] = $ApprovedSignerThumbprint
        }
        if ($AllowUnsignedTestMedia) {
            $arguments['AllowUnsignedTestMedia'] = $true
        }
        if ($AllowUnsignedInternalRelease) {
            $arguments['AllowUnsignedInternalRelease'] = $true
            $arguments['ExpectedReleaseManifestSha256'] =
                $ExpectedReleaseManifestSha256
        }
    }
    & $stagedInstaller @arguments
}
finally {
    if ($null -ne $stage) {
        try {
            Remove-ProtectedStagingDirectory -Path $stage.Path `
                -ExpectedParent $stage.Parent
        } catch {
            # The product transaction has its own rollback contract.  A locked
            # admin/SYSTEM-only scratch directory must never turn a committed
            # runtime switch into a false Setup failure or mask the original
            # product exception.  It is inert and can be removed by an
            # administrator after the locking process exits.
            Write-Warning (
                'Trusted installer staging cleanup did not complete: ' +
                $_.Exception.Message
            )
        }
    }
}
