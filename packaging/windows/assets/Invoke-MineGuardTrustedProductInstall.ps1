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

function New-ProtectedFileSecurity {
    $administrators = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $system = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object -TypeName Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in @($administrators, $system)) {
        $rule = New-Object -TypeName `
            Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-ProtectedTransactionTree {
    param([Parameter(Mandatory = $true)] [string] $Path)
    Assert-NoReparseTree -Path $Path -Label 'installer transaction tree'
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse)) {
        Set-Acl -LiteralPath $file.FullName -AclObject (New-ProtectedFileSecurity)
    }
    $directories = @(Get-ChildItem -LiteralPath $Path -Directory -Force -Recurse |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($directory in $directories) {
        Set-Acl -LiteralPath $directory.FullName `
            -AclObject (New-ProtectedDirectorySecurity)
    }
    Set-Acl -LiteralPath $Path -AclObject (New-ProtectedDirectorySecurity)
    Assert-ProtectedDirectoryAcl -Path $Path
}

function Get-NormalizedTransactionId {
    param([string] $Value)
    $normalized = ([string]$Value).Trim().ToLowerInvariant()
    if ($normalized -cnotmatch '^[a-f0-9]{32}$') {
        throw 'TransactionId must be exactly 32 hexadecimal characters.'
    }
    return $normalized
}

function Get-NormalizedPathText {
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label must be an absolute local drive path."
    }
    return [IO.Path]::GetFullPath($Value).TrimEnd('\\')
}

function Get-TransactionDescriptor {
    param([string] $Root, [string] $Kind, [string] $Id)
    $install = Get-SafeLocalNtfsPath -Path $Root `
        -Label 'transaction install root' -MustExist
    $parent = Split-Path -Parent $install
    [void](Get-SafeLocalNtfsPath -Path $parent `
        -Label 'transaction parent' -MustExist)
    $productLeaf = if ($Kind -eq 'Platform') { 'platform' } else { 'agent' }
    $leaf = '.mineguard-' + $productLeaf + '-inno-transaction-' + $Id
    return [pscustomobject]@{
        InstallRoot = $install
        Parent = $parent
        Prefix = '.mineguard-' + $productLeaf + '-inno-transaction-'
        Path = Join-Path $parent $leaf
        JournalPath = Join-Path (Join-Path $parent $leaf) 'journal.json'
    }
}

function New-ProtectedTransactionDirectory {
    param([Parameter(Mandatory = $true)] $Descriptor)
    if (Test-Path -LiteralPath $Descriptor.Path) {
        throw "Installer transaction already exists: $($Descriptor.Path)"
    }
    [void][IO.Directory]::CreateDirectory(
        $Descriptor.Path, (New-ProtectedDirectorySecurity))
    [void](Get-SafeLocalNtfsPath -Path $Descriptor.Path `
        -Label 'installer transaction directory' -MustExist)
    Assert-ProtectedDirectoryAcl -Path $Descriptor.Path
}

function Remove-TransactionDirectory {
    param([Parameter(Mandatory = $true)] $Descriptor)
    if (-not (Test-Path -LiteralPath $Descriptor.Path)) { return }
    $full = [IO.Path]::GetFullPath($Descriptor.Path).TrimEnd('\\')
    $parent = [IO.Path]::GetFullPath($Descriptor.Parent).TrimEnd('\\')
    $leafPattern = '^\\.mineguard-(?:platform|agent)-inno-transaction-[a-f0-9]{32}$'
    if (-not ([IO.Path]::GetDirectoryName($full)).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cnotmatch $leafPattern) {
        throw "Refusing to remove an unexpected transaction path: $full"
    }
    Assert-ProtectedDirectoryAcl -Path $full
    Assert-NoReparseTree -Path $full -Label 'installer transaction cleanup target'
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
    throw "Unable to clean installer transaction: $full. $detail"
}

function Write-TransactionJournal {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] $Journal)
    if (-not (Test-Path -LiteralPath $Descriptor.Path -PathType Container)) {
        throw 'The protected transaction directory disappeared.'
    }
    Assert-ProtectedDirectoryAcl -Path $Descriptor.Path
    $temporary = Join-Path $Descriptor.Path (
        '.journal-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = $Journal | ConvertTo-Json -Depth 12
    $utf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($temporary, $json, $utf8)
    Set-Acl -LiteralPath $temporary -AclObject (New-ProtectedFileSecurity)
    Move-Item -LiteralPath $temporary -Destination $Descriptor.JournalPath -Force
}

function Read-TransactionJournal {
    param([Parameter(Mandatory = $true)] $Descriptor)
    Assert-ProtectedDirectoryAcl -Path $Descriptor.Path
    if (-not (Test-Path -LiteralPath $Descriptor.JournalPath -PathType Leaf)) {
        throw "Installer transaction journal is missing: $($Descriptor.JournalPath)"
    }
    try {
        $journal = Get-Content -LiteralPath $Descriptor.JournalPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Installer transaction journal is invalid: $($_.Exception.Message)"
    }
    if ([int]$journal.schemaVersion -ne 1 -or
        [string]$journal.product -cne $Product -or
        [string]$journal.transactionId -cne `
            ([IO.Path]::GetFileName($Descriptor.Path).Substring(
                $Descriptor.Prefix.Length)) -or
        -not ([string]$journal.installRoot).Equals(
            $Descriptor.InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer transaction journal identity does not match its protected path.'
    }
    return $journal
}

function Get-OriginalSecuritySddl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $acl = Get-Acl -LiteralPath $Path
    return $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All)
}

function Get-TreeInventory {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootItem = Get-Item -LiteralPath $Root -Force
    $records = New-Object System.Collections.Generic.List[object]
    $items = @($rootItem)
    if ($rootItem.PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $Root -Force -Recurse |
            Sort-Object FullName)
    }
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\\') + '\\'
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Managed product artifact contains a reparse point: $($item.FullName)"
        }
        $relative = if ($item.FullName.Equals(
                [IO.Path]::GetFullPath($Root),
                [StringComparison]::OrdinalIgnoreCase)) {
            '.'
        } else {
            $item.FullName.Substring($prefix.Length).Replace('\\', '/')
        }
        if ($item.PSIsContainer) {
            $records.Add([pscustomobject]@{
                path = $relative
                kind = 'directory'
                bytes = 0
                sha256 = ''
                sddl = Get-OriginalSecuritySddl -Path $item.FullName
            })
        } else {
            $records.Add([pscustomobject]@{
                path = $relative
                kind = 'file'
                bytes = [long]$item.Length
                sha256 = (Get-FileHash -LiteralPath $item.FullName `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
                sddl = Get-OriginalSecuritySddl -Path $item.FullName
            })
        }
    }
    return @($records)
}

function Assert-InventoryContent {
    param([Parameter(Mandatory = $true)] [string] $Root,
          [Parameter(Mandatory = $true)] $Inventory)
    if (-not (Test-Path -LiteralPath $Root)) {
        throw "Managed artifact snapshot disappeared: $Root"
    }
    $actual = @(Get-TreeInventory -Root $Root)
    if ($actual.Count -ne @($Inventory).Count) {
        throw "Managed artifact snapshot file set changed: $Root"
    }
    $actualByPath = @{}
    foreach ($entry in $actual) { $actualByPath[[string]$entry.path] = $entry }
    foreach ($expected in @($Inventory)) {
        $relative = [string]$expected.path
        if (-not $actualByPath.ContainsKey($relative)) {
            throw "Managed artifact snapshot is missing: $relative"
        }
        $found = $actualByPath[$relative]
        if ([string]$found.kind -cne [string]$expected.kind -or
            [long]$found.bytes -ne [long]$expected.bytes -or
            [string]$found.sha256 -cne [string]$expected.sha256) {
            throw "Managed artifact snapshot changed: $relative"
        }
    }
}

function Get-ManagedArtifactSpecifications {
    param([string] $Root, [string] $Kind)
    $specifications = New-Object System.Collections.Generic.List[object]
    $directoryNames = if ($Kind -eq 'Platform') {
        @('runtime', 'service', 'launcher', 'release-metadata', 'docs',
          'uninstall-tools')
    } else {
        @('runtime', 'deploy', 'release-metadata', 'docs', 'uninstall-tools')
    }
    foreach ($name in $directoryNames) {
        $specifications.Add([pscustomobject]@{
            target = Join-Path $Root $name
            kind = 'directory'
            category = 'product'
        })
    }
    if ($Kind -eq 'Platform') {
        $specifications.Add([pscustomobject]@{
            target = Join-Path $Root 'config\settings.json'
            kind = 'file'
            category = 'product'
        })
    }
    foreach ($uninstaller in @(Get-ChildItem -LiteralPath $Root -File -Force |
            Where-Object {
                $_.Name -cmatch '^unins[0-9]{3}\.(?:exe|dat|msg)$'
            } | Sort-Object Name)) {
        $specifications.Add([pscustomobject]@{
            target = $uninstaller.FullName
            kind = 'file'
            category = 'uninstaller'
        })
    }
    $programs = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonPrograms)
    $group = Join-Path $programs 'MineGuard'
    $shortcutNames = if ($Kind -eq 'Platform') {
        @(
            'MineGuard Platform 控制中心.lnk',
            'MineGuard 企业接入包与注册向导.lnk',
            'MineGuard Platform 使用与部署说明.lnk'
        )
    } else {
        @(
            'MineGuard Enterprise Agent deployment guide.lnk',
            'MineGuard 企业接入配置向导.lnk',
            'MineGuard 模型授权导入向导.lnk',
            'Enterprise Agent operations console.lnk'
        )
    }
    foreach ($name in $shortcutNames) {
        $specifications.Add([pscustomobject]@{
            target = Join-Path $group $name
            kind = 'file'
            category = 'shortcut'
        })
    }
    if ($Kind -eq 'Platform') {
        $desktop = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonDesktopDirectory)
        $specifications.Add([pscustomobject]@{
            target = Join-Path $desktop 'MineGuard Platform 控制中心.lnk'
            kind = 'file'
            category = 'shortcut'
        })
    }
    return @($specifications)
}

function Assert-ManagedArtifactTarget {
    param([string] $Target, [string] $Kind, [string] $Category,
          [string] $Root)
    $full = [IO.Path]::GetFullPath($Target)
    $fixed = @(Get-ManagedArtifactSpecifications -Root $Root -Kind $Product |
        Where-Object { $_.category -ne 'uninstaller' } |
        ForEach-Object { [IO.Path]::GetFullPath([string]$_.target) })
    if ($fixed -contains $full) { return }
    if ($Category -eq 'uninstaller' -and $Kind -eq 'file' -and
        ([IO.Path]::GetDirectoryName($full)).Equals(
            $Root, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($full) -cmatch
            '^unins[0-9]{3}\.(?:exe|dat|msg)$') {
        return
    }
    throw "Transaction journal contains an unmanaged artifact target: $full"
}

function Get-ArpRegistrySubKey {
    param([string] $Kind)
    $applicationId = if ($Kind -eq 'Platform') {
        '{8B391CBD-E234-46D7-9946-E9D37F2649C1}'
    } else {
        '{9B73DE95-6B38-4482-A8BC-2A4FC656D05A}'
    }
    return 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' +
        $applicationId + '_is1'
}

function Convert-RegistryValueToRecord {
    param($Value, [Microsoft.Win32.RegistryValueKind] $Kind)
    if ($Kind -in @(
            [Microsoft.Win32.RegistryValueKind]::Binary,
            [Microsoft.Win32.RegistryValueKind]::None)) {
        return [pscustomobject]@{
            encoding = 'base64'
            data = [Convert]::ToBase64String([byte[]]$Value)
        }
    }
    if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
        return [pscustomobject]@{
            encoding = 'string-array'
            data = @([string[]]$Value)
        }
    }
    return [pscustomobject]@{
        encoding = 'scalar'
        data = [string]$Value
    }
}

function Convert-RecordToRegistryValue {
    param($Record, [Microsoft.Win32.RegistryValueKind] $Kind)
    switch ([string]$Record.encoding) {
        'base64' { return [Convert]::FromBase64String([string]$Record.data) }
        'string-array' { return [string[]]@($Record.data) }
        'scalar' {
            if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                return [int][string]$Record.data
            }
            if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::QWord) {
                return [long][string]$Record.data
            }
            return [string]$Record.data
        }
        default { throw 'ARP snapshot contains an unsupported value encoding.' }
    }
}

function Capture-ArpRegistration {
    $subKey = Get-ArpRegistrySubKey -Kind $Product
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $root = $base.OpenSubKey($subKey, $false)
        if ($null -eq $root) {
            return [pscustomobject]@{
                subKey = $subKey
                existed = $false
                keys = @()
            }
        }
        $root.Dispose()
        $pending = New-Object System.Collections.Generic.Queue[string]
        $pending.Enqueue('')
        $records = New-Object System.Collections.Generic.List[object]
        while ($pending.Count -gt 0) {
            $relative = $pending.Dequeue()
            $currentSubKey = if ($relative -eq '') {
                $subKey
            } else {
                $subKey + '\' + $relative
            }
            $key = $base.OpenSubKey($currentSubKey, $false)
            if ($null -eq $key) {
                throw "ARP registry key changed during snapshot: $currentSubKey"
            }
            try {
                $values = New-Object System.Collections.Generic.List[object]
                foreach ($name in @($key.GetValueNames() | Sort-Object)) {
                    $kind = $key.GetValueKind($name)
                    $option = if ($kind -eq
                            [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    } else {
                        [Microsoft.Win32.RegistryValueOptions]::None
                    }
                    $value = $key.GetValue($name, $null, $option)
                    $values.Add([pscustomobject]@{
                        name = [string]$name
                        kind = [string]$kind
                        value = Convert-RegistryValueToRecord `
                            -Value $value -Kind $kind
                    })
                }
                $security = $key.GetAccessControl()
                $records.Add([pscustomobject]@{
                    path = [string]$relative
                    sddl = $security.GetSecurityDescriptorSddlForm(
                        [Security.AccessControl.AccessControlSections]::All)
                    values = @($values)
                })
                foreach ($child in @($key.GetSubKeyNames() | Sort-Object)) {
                    $childRelative = if ($relative -eq '') {
                        $child
                    } else {
                        $relative + '\' + $child
                    }
                    $pending.Enqueue($childRelative)
                }
            } finally {
                $key.Dispose()
            }
        }
        return [pscustomobject]@{
            subKey = $subKey
            existed = $true
            keys = @($records)
        }
    } finally {
        $base.Dispose()
    }
}

function Restore-ArpRegistration {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $expectedSubKey = Get-ArpRegistrySubKey -Kind $Product
    if ([string]$Snapshot.subKey -cne $expectedSubKey) {
        throw 'ARP snapshot targets an unexpected registry key.'
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        try { $base.DeleteSubKeyTree($expectedSubKey, $false) } catch { throw }
        if (-not [bool]$Snapshot.existed) { return }
        $records = @($Snapshot.keys | Sort-Object {
            if ([string]$_.path -eq '') {
                0
            } else {
                ([string]$_.path).Split('\').Count
            }
        })
        if ($records.Count -eq 0 -or [string]$records[0].path -cne '') {
            throw 'ARP snapshot is missing its root key.'
        }
        foreach ($record in $records) {
            $currentSubKey = if ([string]$record.path -eq '') {
                $expectedSubKey
            } else {
                $expectedSubKey + '\' + [string]$record.path
            }
            $key = $base.CreateSubKey(
                $currentSubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
            try {
                foreach ($valueRecord in @($record.values)) {
                    $kind = [Microsoft.Win32.RegistryValueKind][Enum]::Parse(
                        [Microsoft.Win32.RegistryValueKind],
                        [string]$valueRecord.kind)
                    $value = Convert-RecordToRegistryValue `
                        -Record $valueRecord.value -Kind $kind
                    $key.SetValue([string]$valueRecord.name, $value, $kind)
                }
                $security = New-Object -TypeName `
                    Security.AccessControl.RegistrySecurity
                $security.SetSecurityDescriptorSddlForm([string]$record.sddl)
                $key.SetAccessControl($security)
            } finally {
                $key.Dispose()
            }
        }
    } finally {
        $base.Dispose()
    }
}

function Capture-ManagedArtifacts {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] $Journal)
    $snapshotRoot = Join-Path $Descriptor.Path 'snapshot'
    [void][IO.Directory]::CreateDirectory(
        $snapshotRoot, (New-ProtectedDirectorySecurity))
    $index = 0
    foreach ($specification in @(Get-ManagedArtifactSpecifications `
            -Root $Descriptor.InstallRoot -Kind $Product)) {
        $target = [IO.Path]::GetFullPath([string]$specification.target)
        $exists = Test-Path -LiteralPath $target
        $snapshotName = 'artifact-{0:D3}' -f $index
        $inventory = @()
        if ($exists) {
            $item = Get-Item -LiteralPath $target -Force
            if (($specification.kind -eq 'directory') -ne [bool]$item.PSIsContainer) {
                throw "Managed artifact has the wrong type: $target"
            }
            $inventory = @(Get-TreeInventory -Root $target)
            $snapshotPath = Join-Path $snapshotRoot $snapshotName
            Copy-Item -LiteralPath $target -Destination $snapshotPath `
                -Recurse -Force
            Set-ProtectedTransactionTree -Path $snapshotPath
            Assert-InventoryContent -Root $snapshotPath -Inventory $inventory
        }
        $artifact = [pscustomobject]@{
            target = $target
            kind = [string]$specification.kind
            category = [string]$specification.category
            existed = [bool]$exists
            snapshotName = $snapshotName
            inventory = $inventory
        }
        $Journal.artifacts += @($artifact)
        Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal
        $index++
    }
    Set-ProtectedTransactionTree -Path $Descriptor.Path
}

function Remove-ManagedTarget {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to traverse a managed-artifact reparse point: $Path"
    }
    if ($item.PSIsContainer) {
        Assert-NoReparseTree -Path $Path -Label 'managed rollback target'
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Set-RestoredTreeSecurity {
    param([string] $Root, $Inventory)
    $ordered = @($Inventory | Sort-Object {
        ([string]$_.path).Split('/').Count
    })
    foreach ($entry in $ordered) {
        $path = if ([string]$entry.path -eq '.') {
            $Root
        } else {
            Join-Path $Root ([string]$entry.path).Replace('/', '\\')
        }
        $acl = if ([string]$entry.kind -eq 'directory') {
            New-Object -TypeName Security.AccessControl.DirectorySecurity
        } else {
            New-Object -TypeName Security.AccessControl.FileSecurity
        }
        $acl.SetSecurityDescriptorSddlForm([string]$entry.sddl)
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}

function Restore-ManagedArtifacts {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] $Journal)
    $Journal.state = 'rollingback'
    Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal

    Restore-ArpRegistration -Snapshot $Journal.arpRegistration

    foreach ($currentUninstaller in @(Get-ChildItem `
            -LiteralPath $Descriptor.InstallRoot -File -Force |
            Where-Object {
                $_.Name -cmatch '^unins[0-9]{3}\.(?:exe|dat|msg)$'
            })) {
        Remove-ManagedTarget -Path $currentUninstaller.FullName
    }

    $snapshotRoot = Join-Path $Descriptor.Path 'snapshot'
    $index = 0
    foreach ($artifact in @($Journal.artifacts)) {
        $target = [IO.Path]::GetFullPath([string]$artifact.target)
        Assert-ManagedArtifactTarget -Target $target `
            -Kind ([string]$artifact.kind) `
            -Category ([string]$artifact.category) `
            -Root $Descriptor.InstallRoot
        if ([string]$artifact.snapshotName -cne ('artifact-{0:D3}' -f $index)) {
            throw 'Transaction journal artifact ordering is invalid.'
        }
        if (-not [bool]$artifact.existed) {
            Remove-ManagedTarget -Path $target
            $index++
            continue
        }
        $snapshotPath = Join-Path $snapshotRoot ([string]$artifact.snapshotName)
        Assert-InventoryContent -Root $snapshotPath `
            -Inventory @($artifact.inventory)
        $targetParent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $targetParent -PathType Container)) {
            New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        }
        [void](Get-SafeLocalNtfsPath -Path $targetParent `
            -Label 'managed rollback parent' -MustExist)
        $restorePath = Join-Path $targetParent (
            '.mineguard-inno-restore-' + $Journal.transactionId + '-' +
            ('{0:D3}' -f $index))
        Remove-ManagedTarget -Path $restorePath
        Copy-Item -LiteralPath $snapshotPath -Destination $restorePath `
            -Recurse -Force
        Assert-InventoryContent -Root $restorePath `
            -Inventory @($artifact.inventory)
        Set-RestoredTreeSecurity -Root $restorePath `
            -Inventory @($artifact.inventory)
        Remove-ManagedTarget -Path $target
        Move-Item -LiteralPath $restorePath -Destination $target
        Assert-InventoryContent -Root $target -Inventory @($artifact.inventory)
        $index++
    }
    $Journal.state = 'rolledback'
    Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal
}

function Assert-TransactionContext {
    param([Parameter(Mandatory = $true)] $Journal,
          [switch] $IncludeRelease)
    if ([string]$Journal.product -cne $Product -or
        -not ([string]$Journal.installRoot).Equals(
            [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer transaction context does not match the current product.'
    }
    if ($IncludeRelease) {
        $expected = ($ExpectedReleaseManifestSha256 -replace '\s', '').ToLowerInvariant()
        if ([string]$Journal.expectedReleaseManifestSha256 -cne $expected -or
            [bool]$Journal.allowUnsignedTestMedia -ne [bool]$AllowUnsignedTestMedia -or
            [bool]$Journal.allowUnsignedInternalRelease -ne
                [bool]$AllowUnsignedInternalRelease -or
            [string]$Journal.approvedSignerThumbprint -cne
                (($ApprovedSignerThumbprint -replace '\s', '').ToUpperInvariant())) {
            throw 'Installer transaction release authorization changed between phases.'
        }
    }
}

function Invoke-StagedProductInstaller {
    param([string] $CandidateRoot, [string] $InstallerPath)
    if ($Product -eq 'Platform') {
        $arguments = @{
            SourceDirectory = $CandidateRoot
            InstallRoot = $InstallRoot
        }
        if ($AllowUnsignedInternalRelease) {
            $arguments['AllowUnsignedInternalRelease'] = $true
            $arguments['ExpectedReleaseManifestSha256'] =
                $ExpectedReleaseManifestSha256
        }
    } else {
        $arguments = @{
            SourceRoot = $CandidateRoot
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
    & $InstallerPath @arguments
}

function Invoke-TransactionRollback {
    param([Parameter(Mandatory = $true)] $Descriptor)
    if (-not (Test-Path -LiteralPath $Descriptor.Path -PathType Container)) {
        return
    }
    $journal = Read-TransactionJournal -Descriptor $Descriptor
    Assert-TransactionContext -Journal $journal
    if ([string]$journal.state -eq 'capturing') {
        Remove-TransactionDirectory -Descriptor $Descriptor
        return
    }
    if ([string]$journal.state -eq 'wrapper_succeeded') {
        throw 'A wrapper-confirmed installer transaction cannot be rolled back.'
    }
    Restore-ManagedArtifacts -Descriptor $Descriptor -Journal $journal
    Remove-TransactionDirectory -Descriptor $Descriptor
}

function Recover-StaleTransactions {
    param([Parameter(Mandatory = $true)] $CurrentDescriptor)
    foreach ($directory in @(Get-ChildItem -LiteralPath $CurrentDescriptor.Parent `
            -Directory -Force | Where-Object {
                $_.Name.StartsWith(
                    $CurrentDescriptor.Prefix,
                    [StringComparison]::Ordinal) -and
                $_.Name -cne [IO.Path]::GetFileName($CurrentDescriptor.Path) -and
                $_.Name -cmatch ('^' + [regex]::Escape(
                    $CurrentDescriptor.Prefix) + '[a-f0-9]{32}$')
            })) {
        $staleId = $directory.Name.Substring($CurrentDescriptor.Prefix.Length)
        $stale = Get-TransactionDescriptor -Root $CurrentDescriptor.InstallRoot `
            -Kind $Product -Id $staleId
        $journal = Read-TransactionJournal -Descriptor $stale
        Assert-TransactionContext -Journal $journal
        if ([string]$journal.state -eq 'wrapper_succeeded') {
            $manifestPath = Join-Path $CurrentDescriptor.InstallRoot `
                'release-metadata\release-manifest.json'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
                (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash `
                    -cne ([string]$journal.expectedReleaseManifestSha256).ToUpperInvariant()) {
                throw 'A committed stale transaction does not match the active product manifest.'
            }
            Remove-TransactionDirectory -Descriptor $stale
        } elseif ([string]$journal.state -eq 'capturing') {
            Remove-TransactionDirectory -Descriptor $stale
        } else {
            Restore-ManagedArtifacts -Descriptor $stale -Journal $journal
            Remove-TransactionDirectory -Descriptor $stale
        }
    }
}

function Invoke-DirectInstall {
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
        Set-ProtectedTransactionTree -Path $stage.Path
        $stagedInstaller = Assert-TrustedReleaseTree -Root $stage.Path `
            -ExpectedManifestHash $ExpectedReleaseManifestSha256 -Kind $Product
        Invoke-StagedProductInstaller -CandidateRoot $stage.Path `
            -InstallerPath $stagedInstaller
    } finally {
        if ($null -ne $stage) {
            try {
                Remove-ProtectedStagingDirectory -Path $stage.Path `
                    -ExpectedParent $stage.Parent
            } catch {
                Write-Warning (
                    'Trusted installer staging cleanup did not complete: ' +
                    $_.Exception.Message)
            }
        }
    }
}

Assert-Administrator
if ($AllowUnsignedTestMedia -and $AllowUnsignedInternalRelease) {
    throw 'Unsigned test and internal-release modes are mutually exclusive.'
}
if ($TransactionAction -eq 'Install') {
    Invoke-DirectInstall
    return
}

$normalizedTransactionId = Get-NormalizedTransactionId -Value $TransactionId
$descriptor = Get-TransactionDescriptor -Root $InstallRoot `
    -Kind $Product -Id $normalizedTransactionId

switch ($TransactionAction) {
    'Begin' {
        Recover-StaleTransactions -CurrentDescriptor $descriptor
        New-ProtectedTransactionDirectory -Descriptor $descriptor
        $normalizedStateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
            ''
        } else {
            Get-NormalizedPathText -Value $StateRoot -Label 'StateRoot'
        }
        $normalizedExpectedHash = (
            $ExpectedReleaseManifestSha256 -replace '\s', '').ToLowerInvariant()
        if ($normalizedExpectedHash -cnotmatch '^[a-f0-9]{64}$') {
            throw 'ExpectedReleaseManifestSha256 must be exactly 64 hexadecimal characters.'
        }
        $journal = [pscustomobject]@{
            schemaVersion = 1
            product = $Product
            transactionId = $normalizedTransactionId
            installRoot = $descriptor.InstallRoot
            stateRoot = $normalizedStateRoot
            expectedReleaseManifestSha256 = $normalizedExpectedHash
            approvedSignerThumbprint = (
                $ApprovedSignerThumbprint -replace '\s', '').ToUpperInvariant()
            allowUnsignedTestMedia = [bool]$AllowUnsignedTestMedia
            allowUnsignedInternalRelease = [bool]$AllowUnsignedInternalRelease
            state = 'capturing'
            arpRegistration = $null
            artifacts = @()
        }
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
        $journal.arpRegistration = Capture-ArpRegistration
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
        Capture-ManagedArtifacts -Descriptor $descriptor -Journal $journal
        $journal.state = 'begun'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
    }
    'Prepare' {
        $journal = Read-TransactionJournal -Descriptor $descriptor
        Assert-TransactionContext -Journal $journal -IncludeRelease
        if ([string]$journal.state -cne 'begun') {
            throw 'Installer transaction is not ready for candidate preparation.'
        }
        $source = Get-SafeLocalNtfsPath -Path $SourceRoot `
            -Label 'Inno extracted child release' -MustExist
        Assert-NoReparseTree -Path $source -Label 'Inno extracted child release'
        $candidate = Join-Path $descriptor.Path 'candidate'
        if (Test-Path -LiteralPath $candidate) {
            throw 'Installer transaction candidate already exists.'
        }
        [void][IO.Directory]::CreateDirectory(
            $candidate, (New-ProtectedDirectorySecurity))
        foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
            Copy-Item -LiteralPath $item.FullName -Destination $candidate `
                -Recurse -Force
        }
        Set-ProtectedTransactionTree -Path $candidate
        [void](Assert-TrustedReleaseTree -Root $candidate `
            -ExpectedManifestHash $ExpectedReleaseManifestSha256 -Kind $Product)
        $journal.state = 'prepared'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
    }
    'Commit' {
        $journal = Read-TransactionJournal -Descriptor $descriptor
        Assert-TransactionContext -Journal $journal -IncludeRelease
        if ([string]$journal.state -cne 'prepared') {
            throw 'Installer transaction is not ready to commit.'
        }
        $candidate = Join-Path $descriptor.Path 'candidate'
        Set-ProtectedTransactionTree -Path $candidate
        $stagedInstaller = Assert-TrustedReleaseTree -Root $candidate `
            -ExpectedManifestHash $ExpectedReleaseManifestSha256 -Kind $Product
        $journal.state = 'committing'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
        Invoke-StagedProductInstaller -CandidateRoot $candidate `
            -InstallerPath $stagedInstaller
        $activeManifest = Join-Path $descriptor.InstallRoot `
            'release-metadata\release-manifest.json'
        if (-not (Test-Path -LiteralPath $activeManifest -PathType Leaf) -or
            (Get-FileHash -LiteralPath $activeManifest -Algorithm SHA256).Hash `
                -cne $journal.expectedReleaseManifestSha256.ToUpperInvariant()) {
            throw 'Committed product manifest does not match the Setup trust anchor.'
        }
        # The child product has committed, but the Inno wrapper has not.  Keep
        # the old snapshot and make this state rollbackable until ssPostInstall
        # confirms that Files, Icons, ARP and the uninstaller all succeeded.
        $journal.state = 'product_committed_unconfirmed'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
    }
    'Rollback' {
        Invoke-TransactionRollback -Descriptor $descriptor
    }
    'Finalize' {
        if (-not (Test-Path -LiteralPath $descriptor.Path -PathType Container)) {
            return
        }
        $journal = Read-TransactionJournal -Descriptor $descriptor
        Assert-TransactionContext -Journal $journal -IncludeRelease
        if ([string]$journal.state -cne 'product_committed_unconfirmed') {
            throw 'Only an unconfirmed product commit can be wrapper-confirmed.'
        }
        $activeManifest = Join-Path $descriptor.InstallRoot `
            'release-metadata\release-manifest.json'
        if (-not (Test-Path -LiteralPath $activeManifest -PathType Leaf) -or
            (Get-FileHash -LiteralPath $activeManifest -Algorithm SHA256).Hash `
                -cne $journal.expectedReleaseManifestSha256.ToUpperInvariant()) {
            throw 'Finalization refused because the active product manifest changed.'
        }
        # This is the durable cross-engine success point.  A crash after this
        # write must keep the new product; stale recovery only discards the old
        # snapshot for wrapper_succeeded transactions.
        $journal.state = 'wrapper_succeeded'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
        try {
            Remove-TransactionDirectory -Descriptor $descriptor
        } catch {
            # Cleanup is intentionally non-fatal after the durable success
            # marker.  The next Begin safely retries it.
            Write-Warning (
                'Wrapper succeeded, but retained installer cleanup is pending: ' +
                $_.Exception.Message)
        }
    }
}
