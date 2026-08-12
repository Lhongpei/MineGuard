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
    [switch] $AllowUnsignedInternalRelease,
    [ValidateSet('0', '1')]
    [string] $WrapperInstallRootPreexisted = '1',
    [ValidateSet('0', '1')]
    [string] $WrapperShortcutGroupPreexisted = '1'
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
    $rootItem = Get-Item -LiteralPath $Path -Force
    if (-not $rootItem.PSIsContainer) {
        Set-Acl -LiteralPath $Path -AclObject (New-ProtectedFileSecurity)
        return
    }
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
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($normalized, 'N', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty) {
        throw 'TransactionId must identify a non-empty GUID.'
    }
    return $normalized
}

function Get-NormalizedPathText {
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label must be an absolute local drive path."
    }
    return [IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Get-TransactionDescriptor {
    param([string] $Root, [string] $Kind, [string] $Id,
          [switch] $AllowMissingInstallRoot)
    $install = Get-SafeLocalNtfsPath -Path $Root `
        -Label 'transaction install root' `
        -MustExist:(-not $AllowMissingInstallRoot)
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
    $full = [IO.Path]::GetFullPath($Descriptor.Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($Descriptor.Parent).TrimEnd('\')
    $leafPattern = '^\.mineguard-(?:platform|agent)-inno-transaction-[a-f0-9]{32}$'
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
        try {
            $items = @(Get-ChildItem -LiteralPath $full -Force)
            $journalFiles = @()
            $payloadItems = @()
            foreach ($item in $items) {
                if (-not $item.PSIsContainer -and (
                        $item.Name -ceq 'journal.json' -or
                        $item.Name -cmatch '^journal-[0-9]{20}\.json$' -or
                        $item.Name -cmatch '^\.journal-[a-f0-9]{32}\.tmp$')) {
                    $journalFiles += @($item)
                } else {
                    $payloadItems += @($item)
                }
            }

            $validRecords = @(Get-ValidTransactionJournalRecords `
                -Descriptor $Descriptor | Sort-Object Generation -Descending)
            if ($validRecords.Count -eq 0 -and $payloadItems.Count -gt 0) {
                throw (
                    'Refusing to clean a transaction that has payload but no ' +
                    'valid durable journal.')
            }
            $authoritativeJournal = if ($validRecords.Count -gt 0) {
                [IO.Path]::GetFullPath([string]$validRecords[0].Path)
            } else {
                ''
            }

            # Snapshot/candidate/other payload is always removed before any
            # journal.  If cleanup is interrupted, the authoritative state is
            # therefore still available to the next recovery attempt.
            foreach ($item in $payloadItems) {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force `
                    -ErrorAction Stop
            }
            foreach ($journalFile in $journalFiles) {
                $journalFullName = [IO.Path]::GetFullPath($journalFile.FullName)
                if ([string]::IsNullOrWhiteSpace($authoritativeJournal) -or
                    -not $journalFullName.Equals(
                        $authoritativeJournal,
                        [StringComparison]::OrdinalIgnoreCase)) {
                    Remove-Item -LiteralPath $journalFullName -Force `
                        -ErrorAction Stop
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($authoritativeJournal) -and
                (Test-Path -LiteralPath $authoritativeJournal -PathType Leaf)) {
                # The final valid journal is deliberately the last file.
                Remove-Item -LiteralPath $authoritativeJournal -Force `
                    -ErrorAction Stop
            }
            # No recursive root deletion: reaching this line means every
            # child, including the final journal, was removed in order.
            Remove-Item -LiteralPath $full -Force -ErrorAction Stop
        } catch { $lastError = $_ }
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
    Assert-TransactionJournalIdentity -Descriptor $Descriptor -Journal $Journal
    # Each generation is immutable.  A torn highest-generation write is
    # ignored by Read-TransactionJournal, which falls back to the preceding
    # valid generation.  Reusing journal.json with Move-Item -Force would not
    # provide that guarantee across sudden power loss.
    $highestNamedGeneration = [long]0
    foreach ($file in @(Get-ChildItem -LiteralPath $Descriptor.Path `
            -File -Force)) {
        if ($file.Name -cmatch '^journal-(?<generation>[0-9]{20})\.json$') {
            try {
                $generation = [long]::Parse(
                    [string]$Matches['generation'],
                    [Globalization.CultureInfo]::InvariantCulture)
            } catch {
                throw 'Installer transaction journal generation is out of range.'
            }
            if ($generation -gt $highestNamedGeneration) {
                $highestNamedGeneration = $generation
            }
        }
    }
    if ($highestNamedGeneration -eq [long]::MaxValue) {
        throw 'Installer transaction journal generation space is exhausted.'
    }
    $generation = $highestNamedGeneration + 1

    $utf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList @($false, $true)
    $payloadJson = $Journal | ConvertTo-Json -Depth 16 -Compress
    $payloadBytes = $utf8.GetBytes($payloadJson)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $payloadSha256 = ([BitConverter]::ToString(
            $sha256.ComputeHash($payloadBytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    $envelope = [ordered]@{
        schemaVersion = 2
        generation = $generation
        payloadEncoding = 'utf-8-base64'
        payloadSha256 = $payloadSha256
        payloadBase64 = [Convert]::ToBase64String($payloadBytes)
    }
    $envelopeBytes = $utf8.GetBytes(
        ($envelope | ConvertTo-Json -Depth 4 -Compress))
    $journalName = 'journal-' + $generation.ToString(
        'D20', [Globalization.CultureInfo]::InvariantCulture) + '.json'
    $journalPath = Join-Path $Descriptor.Path $journalName
    $stream = $null
    $durableWriteCompleted = $false
    try {
        $stream = [IO.FileStream]::new(
            $journalPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        $stream.Write($envelopeBytes, 0, $envelopeBytes.Length)
        $stream.Flush($true)
        $durableWriteCompleted = $true
    } finally {
        if ($null -ne $stream) {
            if ($durableWriteCompleted) {
                # Flush(true) is the acknowledgement boundary.  The new file
                # already inherited the protected Admin/System-only DACL from
                # its transaction directory.  No post-durable ACL/readback or
                # close error may turn wrapper_succeeded into a reported
                # failure while recovery correctly treats it as committed.
                try { $stream.Dispose() } catch { }
            } else {
                $stream.Dispose()
            }
        }
    }
}

function Assert-TransactionJournalIdentity {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] $Journal)
    if ([int]$Journal.schemaVersion -ne 1 -or
        [string]$Journal.product -cne $Product -or
        [string]$Journal.transactionId -cne `
            ([IO.Path]::GetFileName($Descriptor.Path).Substring(
                $Descriptor.Prefix.Length)) -or
        -not ([string]$Journal.installRoot).Equals(
            $Descriptor.InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer transaction journal identity does not match its protected path.'
    }
}

function Read-TransactionJournalGeneration {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] [string] $Path,
          [Parameter(Mandatory = $true)] [long] $ExpectedGeneration)
    try {
        $envelopeBytes = [IO.File]::ReadAllBytes($Path)
    } catch {
        throw "Installer transaction journal generation could not be read: $Path"
    }
    try {
        $strictUtf8 = New-Object -TypeName Text.UTF8Encoding `
            -ArgumentList @($false, $true)
        $envelope = $strictUtf8.GetString($envelopeBytes) | ConvertFrom-Json
        if ([int]$envelope.schemaVersion -ne 2 -or
            [long]$envelope.generation -ne $ExpectedGeneration -or
            [string]$envelope.payloadEncoding -cne 'utf-8-base64' -or
            [string]$envelope.payloadSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$envelope.payloadBase64 -cnotmatch `
                '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$') {
            return $null
        }
        $payloadBytes = [Convert]::FromBase64String(
            [string]$envelope.payloadBase64)
        if ([Convert]::ToBase64String($payloadBytes) -cne
            [string]$envelope.payloadBase64) {
            return $null
        }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha256 = ([BitConverter]::ToString(
                $sha256.ComputeHash($payloadBytes))).Replace(
                    '-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
        if ($actualSha256 -cne [string]$envelope.payloadSha256) {
            return $null
        }
        $journal = $strictUtf8.GetString($payloadBytes) | ConvertFrom-Json
        Assert-TransactionJournalIdentity -Descriptor $Descriptor `
            -Journal $journal
        return [pscustomobject]@{
            Generation = $ExpectedGeneration
            Journal = $journal
            Path = $Path
        }
    } catch {
        return $null
    }
}

function Get-ValidTransactionJournalRecords {
    param([Parameter(Mandatory = $true)] $Descriptor)
    $records = [System.Collections.Generic.List[object]]::new()
    $unreadableGenerations = [System.Collections.Generic.List[long]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $Descriptor.Path `
            -File -Force)) {
        if ($file.Name -cmatch '^journal-(?<generation>[0-9]{20})\.json$') {
            try {
                $generation = [long]::Parse(
                    [string]$Matches['generation'],
                    [Globalization.CultureInfo]::InvariantCulture)
            } catch {
                continue
            }
            if ($generation -lt 1) { continue }
            try {
                $record = Read-TransactionJournalGeneration `
                    -Descriptor $Descriptor -Path $file.FullName `
                    -ExpectedGeneration $generation
            } catch {
                $unreadableGenerations.Add($generation)
                continue
            }
            if ($null -ne $record) { $records.Add($record) }
        }
    }

    $highestValidGeneration = if ($records.Count -eq 0) {
        [long]0
    } else {
        [long](($records | Measure-Object -Property Generation -Maximum).Maximum)
    }
    if (@($unreadableGenerations | Where-Object {
                $_ -gt $highestValidGeneration
            }).Count -gt 0) {
        throw 'A newer installer transaction journal generation is temporarily unreadable.'
    }

    # Compatibility with transactions created by the schema-1 implementation.
    # It is generation zero and therefore loses to every valid envelope.
    if ($records.Count -eq 0 -and
        (Test-Path -LiteralPath $Descriptor.JournalPath -PathType Leaf)) {
        try {
            $legacyBytes = [IO.File]::ReadAllBytes($Descriptor.JournalPath)
        } catch {
            throw 'The legacy installer transaction journal is temporarily unreadable.'
        }
        try {
            $strictUtf8 = New-Object -TypeName Text.UTF8Encoding `
                -ArgumentList @($false, $true)
            $legacy = $strictUtf8.GetString($legacyBytes) | ConvertFrom-Json
            Assert-TransactionJournalIdentity -Descriptor $Descriptor `
                -Journal $legacy
            $records.Add([pscustomobject]@{
                Generation = [long]0
                Journal = $legacy
                Path = $Descriptor.JournalPath
            })
        } catch {
            # A torn legacy journal is not authoritative.  Recovery below only
            # removes it when no snapshot/candidate or other payload exists.
        }
    }
    return $records.ToArray()
}

function Read-TransactionJournalRecord {
    param([Parameter(Mandatory = $true)] $Descriptor)
    Assert-ProtectedDirectoryAcl -Path $Descriptor.Path
    $records = @(Get-ValidTransactionJournalRecords -Descriptor $Descriptor |
        Sort-Object Generation -Descending)
    if ($records.Count -eq 0) {
        throw "Installer transaction has no valid durable journal: $($Descriptor.Path)"
    }
    return $records[0]
}

function Read-TransactionJournal {
    param([Parameter(Mandatory = $true)] $Descriptor)
    $record = Read-TransactionJournalRecord -Descriptor $Descriptor
    return $record.Journal
}

function Test-TransactionContainsOnlyJournalArtifacts {
    param([Parameter(Mandatory = $true)] $Descriptor)
    Assert-ProtectedDirectoryAcl -Path $Descriptor.Path
    Assert-NoReparseTree -Path $Descriptor.Path `
        -Label 'journal-only installer transaction'
    foreach ($item in @(Get-ChildItem -LiteralPath $Descriptor.Path -Force)) {
        if ($item.PSIsContainer) {
            # In particular, never discard snapshot or candidate content when
            # no authenticated journal survives a power interruption.
            return $false
        }
        if ($item.Name -cne 'journal.json' -and
            $item.Name -cnotmatch '^journal-[0-9]{20}\.json$' -and
            $item.Name -cnotmatch '^\.journal-[a-f0-9]{32}\.tmp$') {
            return $false
        }
    }
    return $true
}

function Test-SafeUninitializedTransactionOrphan {
    param([Parameter(Mandatory = $true)] $Descriptor)
    if (@(Get-ValidTransactionJournalRecords -Descriptor $Descriptor).Count -gt 0) {
        return $false
    }
    return Test-TransactionContainsOnlyJournalArtifacts -Descriptor $Descriptor
}

function Sync-FileTreeToDisk {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $item = Get-Item -LiteralPath $Path -Force
    $files = if ($item.PSIsContainer) {
        @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse)
    } else {
        @($item)
    }
    foreach ($file in $files) {
        $originalAttributes = [IO.File]::GetAttributes($file.FullName)
        $clearedReadOnly = ($originalAttributes -band
            [IO.FileAttributes]::ReadOnly) -ne 0
        if ($clearedReadOnly) {
            [IO.File]::SetAttributes(
                $file.FullName,
                $originalAttributes -band (-bnot [IO.FileAttributes]::ReadOnly))
        }
        $stream = $null
        try {
            $stream = [IO.FileStream]::new(
                $file.FullName,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::Read,
                4096,
                [IO.FileOptions]::WriteThrough)
            $stream.Flush($true)
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
            if ($clearedReadOnly) {
                [IO.File]::SetAttributes($file.FullName, $originalAttributes)
            }
        }
    }
}

function Get-OriginalSecuritySddl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $acl = Get-Acl -LiteralPath $Path
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    return $acl.GetSecurityDescriptorSddlForm($sections)
}

function Get-ByteArraySha256 {
    param([Parameter(Mandatory = $true)] [byte[]] $Bytes)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Set-ExactSecuritySddl {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Kind,
        [Parameter(Mandatory = $true)] [string] $Sddl
    )
    # Avoid a lossy no-op round trip. Windows may normalize control flags or
    # ACE representation when the same SDDL is loaded into a new managed ACL
    # object and written back, defeating the exact rollback comparison below.
    if ((Get-OriginalSecuritySddl -Path $Path) -ceq $Sddl) {
        return
    }
    $security = if ($Kind -eq 'directory') {
        New-Object -TypeName Security.AccessControl.DirectorySecurity
    } elseif ($Kind -eq 'file') {
        New-Object -TypeName Security.AccessControl.FileSecurity
    } else {
        throw "Unsupported security descriptor kind: $Kind"
    }
    $managedSections =
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    # Restore only the sections captured by Get-OriginalSecuritySddl.  The
    # existing Audit/SACL section is intentionally neither replaced nor cleared.
    $security.SetSecurityDescriptorSddlForm($Sddl, $managedSections)
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-ExactSecuritySddl {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedSddl
    )
    if ((Get-OriginalSecuritySddl -Path $Path) -cne $ExpectedSddl) {
        throw "Restored security descriptor does not match its snapshot: $Path"
    }
}

function Get-PlatformMutableDirectorySpecifications {
    param([Parameter(Mandatory = $true)] [string] $Root)
    return @(
        [pscustomobject]@{ name = 'config'; path = Join-Path $Root 'config' },
        [pscustomobject]@{ name = 'state'; path = Join-Path $Root 'state' },
        [pscustomobject]@{ name = 'backups'; path = Join-Path $Root 'backups' },
        [pscustomobject]@{ name = 'logs'; path = Join-Path $Root 'logs' }
    )
}

function Capture-ProductRootMetadata {
    param(
        [Parameter(Mandatory = $true)] $Descriptor,
        [Parameter(Mandatory = $true)] [bool] $InstallRootPreexisted,
        [Parameter(Mandatory = $true)] [bool] $ShortcutGroupPreexisted
    )
    $root = Get-SafeLocalNtfsPath -Path $Descriptor.InstallRoot `
        -Label 'transaction product root' -MustExist
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Transaction product root cannot be a reparse point.'
    }
    $mutableDirectories = @()
    if ($Product -eq 'Platform') {
        foreach ($specification in @(
                Get-PlatformMutableDirectorySpecifications -Root $root)) {
            $exists = Test-Path -LiteralPath $specification.path
            if ($exists -and
                -not (Test-Path -LiteralPath $specification.path `
                    -PathType Container)) {
                throw "Platform mutable directory has the wrong type: $($specification.path)"
            }
            if ($exists) {
                $item = Get-Item -LiteralPath $specification.path -Force
                if (($item.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Platform mutable directory cannot be a reparse point.'
                }
            }
            $mutableDirectories += [pscustomobject]@{
                name = [string]$specification.name
                path = [IO.Path]::GetFullPath([string]$specification.path).TrimEnd('\')
                existed = [bool]$exists
                sddl = if ($exists) {
                    Get-OriginalSecuritySddl -Path $specification.path
                } else { '' }
            }
        }
    }
    return [pscustomobject]@{
        format = 'mineguard-product-root-rollback-v1'
        product = $Product
        installRoot = $root
        installRootPreexisted = $InstallRootPreexisted
        installRootSddl = Get-OriginalSecuritySddl -Path $root
        mutableDirectories = @($mutableDirectories)
        shortcutGroup = [IO.Path]::GetFullPath(
            (Join-Path ([Environment]::GetFolderPath(
                [Environment+SpecialFolder]::CommonPrograms)) 'MineGuard')).TrimEnd('\')
        shortcutGroupPreexisted = $ShortcutGroupPreexisted
    }
}

function Get-ValidatedProductRootRollbackMetadata {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Descriptor
    )
    foreach ($propertyName in @(
            'format', 'product', 'installRoot', 'installRootPreexisted',
            'installRootSddl', 'mutableDirectories', 'shortcutGroup',
            'shortcutGroupPreexisted')) {
        if ($null -eq $Snapshot.PSObject.Properties[$propertyName]) {
            throw 'Product-root rollback metadata is incomplete.'
        }
    }
    if ([string]$Snapshot.format -cne 'mineguard-product-root-rollback-v1' -or
        [string]$Snapshot.product -cne $Product -or
        $Snapshot.installRootPreexisted -isnot [bool] -or
        $Snapshot.shortcutGroupPreexisted -isnot [bool] -or
        [string]::IsNullOrWhiteSpace([string]$Snapshot.installRootSddl) -or
        -not ([string]$Snapshot.installRoot).Equals(
            $Descriptor.InstallRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Product-root rollback metadata does not match this transaction.'
    }
    $installRootExists = Test-Path -LiteralPath $Descriptor.InstallRoot
    if ($installRootExists) {
        if (-not (Test-Path -LiteralPath $Descriptor.InstallRoot `
                -PathType Container)) {
            throw 'Rollback product root changed type.'
        }
        [void](Get-SafeLocalNtfsPath -Path $Descriptor.InstallRoot `
            -Label 'rollback product root' -MustExist)
    } elseif ([bool]$Snapshot.installRootPreexisted) {
        throw 'Pre-existing rollback product root disappeared.'
    }
    $expectedShortcutGroup = [IO.Path]::GetFullPath(
        (Join-Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonPrograms)) 'MineGuard')).TrimEnd('\')
    if (-not ([string]$Snapshot.shortcutGroup).Equals(
            $expectedShortcutGroup, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Product-root rollback shortcut group is invalid.'
    }
    if (Test-Path -LiteralPath $expectedShortcutGroup) {
        if (-not (Test-Path -LiteralPath $expectedShortcutGroup `
                -PathType Container)) {
            throw 'MineGuard shortcut group changed type.'
        }
        $groupItem = Get-Item -LiteralPath $expectedShortcutGroup -Force
        if (($groupItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'MineGuard shortcut group became a reparse point.'
        }
    } elseif ([bool]$Snapshot.shortcutGroupPreexisted) {
        throw 'Pre-existing MineGuard shortcut group disappeared.'
    }
    $expectedSpecifications = if ($Product -eq 'Platform') {
        @(Get-PlatformMutableDirectorySpecifications `
            -Root $Descriptor.InstallRoot)
    } else { @() }
    $records = @($Snapshot.mutableDirectories)
    if ($records.Count -ne $expectedSpecifications.Count) {
        throw 'Product-root rollback directory set is invalid.'
    }
    $validated = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $records.Count; $index++) {
        $record = $records[$index]
        foreach ($propertyName in @('name', 'path', 'existed', 'sddl')) {
            if ($null -eq $record.PSObject.Properties[$propertyName]) {
                throw 'Product-root rollback directory record is incomplete.'
            }
        }
        $expected = $expectedSpecifications[$index]
        $expectedPath = [IO.Path]::GetFullPath(
            [string]$expected.path).TrimEnd('\')
        if ([string]$record.name -cne [string]$expected.name -or
            -not ([string]$record.path).Equals(
                $expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
            $record.existed -isnot [bool] -or
            ([bool]$record.existed -and
                [string]::IsNullOrWhiteSpace([string]$record.sddl))) {
            throw 'Product-root rollback directory record is invalid.'
        }
        if (Test-Path -LiteralPath $expectedPath) {
            if (-not (Test-Path -LiteralPath $expectedPath -PathType Container)) {
                throw 'Platform mutable rollback path changed type.'
            }
            $item = Get-Item -LiteralPath $expectedPath -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Platform mutable rollback path became a reparse point.'
            }
            if (-not [bool]$record.existed) {
                foreach ($child in @(
                        Get-ChildItem -LiteralPath $expectedPath -Force)) {
                    $allowedSettings = [string]$record.name -ceq 'config' -and
                        $child.Name -ceq 'settings.json' -and
                        -not $child.PSIsContainer -and
                        ($child.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -eq 0
                    if (-not $allowedSettings) {
                        throw 'New Platform mutable directory contains unknown data and was preserved.'
                    }
                }
            }
        } elseif ([bool]$record.existed) {
            throw 'Existing Platform mutable directory disappeared.'
        }
        $validated.Add([pscustomobject]@{
            name = [string]$record.name
            path = $expectedPath
            existed = [bool]$record.existed
            sddl = [string]$record.sddl
        })
    }
    return [pscustomobject]@{
        installRoot = $Descriptor.InstallRoot
        installRootPreexisted = [bool]$Snapshot.installRootPreexisted
        installRootSddl = [string]$Snapshot.installRootSddl
        mutableDirectories = $validated.ToArray()
        shortcutGroup = $expectedShortcutGroup
        shortcutGroupPreexisted = [bool]$Snapshot.shortcutGroupPreexisted
    }
}

function Restore-ProductRootMetadataBeforeArtifacts {
    param([Parameter(Mandatory = $true)] $Validated)
    if (Test-Path -LiteralPath $Validated.installRoot -PathType Container) {
        Set-ExactSecuritySddl -Path $Validated.installRoot -Kind 'directory' `
            -Sddl $Validated.installRootSddl
    } elseif ([bool]$Validated.installRootPreexisted) {
        throw 'Pre-existing rollback product root disappeared.'
    }
    foreach ($record in @($Validated.mutableDirectories)) {
        if ([bool]$record.existed) {
            Set-ExactSecuritySddl -Path $record.path -Kind 'directory' `
                -Sddl $record.sddl
        }
    }
}

function Complete-ProductRootMetadataRollback {
    param([Parameter(Mandatory = $true)] $Validated)
    foreach ($record in @($Validated.mutableDirectories)) {
        if ([bool]$record.existed) {
            Assert-ExactSecuritySddl -Path $record.path `
                -ExpectedSddl $record.sddl
            continue
        }
        if (-not (Test-Path -LiteralPath $record.path)) { continue }
        if (-not (Test-Path -LiteralPath $record.path -PathType Container) -or
            @(Get-ChildItem -LiteralPath $record.path -Force).Count -ne 0) {
            throw 'New Platform mutable directory is not empty after rollback.'
        }
        Remove-Item -LiteralPath $record.path -Force
    }
    if (-not [bool]$Validated.shortcutGroupPreexisted -and
        (Test-Path -LiteralPath $Validated.shortcutGroup)) {
        if (@(Get-ChildItem -LiteralPath $Validated.shortcutGroup -Force).Count -ne 0) {
            throw 'New MineGuard shortcut group is not empty after rollback.'
        }
        Remove-Item -LiteralPath $Validated.shortcutGroup -Force
    }
    if ([bool]$Validated.installRootPreexisted) {
        Assert-ExactSecuritySddl -Path $Validated.installRoot `
            -ExpectedSddl $Validated.installRootSddl
    } elseif (Test-Path -LiteralPath $Validated.installRoot) {
        if (@(Get-ChildItem -LiteralPath $Validated.installRoot -Force).Count -ne 0) {
            throw 'New product InstallRoot is not empty after rollback.'
        }
        Remove-Item -LiteralPath $Validated.installRoot -Force
    }
}

function Get-AgentStateMarkerPath {
    param([Parameter(Mandatory = $true)] [string] $Root)
    return Join-Path $Root '.mineguard-enterprise-agent-instances.json'
}

function Assert-SafeAgentStateRootScope {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $ApplicationRoot
    )
    $normalizedRoot = Get-SafeLocalNtfsPath -Path $Root `
        -Label 'Agent transaction StateRoot'
    $normalizedApplication = Get-SafeLocalNtfsPath -Path $ApplicationRoot `
        -Label 'Agent transaction InstallRoot' -MustExist
    $protectedCandidates = @(
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
        $protectedCandidates += Join-Path $env:SystemDrive 'Users'
    }
    foreach ($candidate in @($protectedCandidates | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })) {
        $protected = [IO.Path]::GetFullPath([string]$candidate).TrimEnd('\')
        if ($normalizedRoot.Equals(
                $protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Agent StateRoot cannot be a broad Windows/system data directory.'
        }
    }
    $statePrefix = $normalizedRoot.TrimEnd('\') + '\'
    $applicationPrefix = $normalizedApplication.TrimEnd('\') + '\'
    if ($normalizedRoot.Equals(
            $normalizedApplication, [StringComparison]::OrdinalIgnoreCase) -or
        $normalizedRoot.StartsWith(
            $applicationPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $normalizedApplication.StartsWith(
            $statePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Agent InstallRoot and StateRoot must be separate, non-nested directories.'
    }
    return $normalizedRoot
}

function Assert-OrdinaryAgentStateMarkerFile {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Agent StateRoot marker is not a regular file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 1MB) {
        throw "Agent StateRoot marker is unsafe or outside its size limit: $Path"
    }
    return $item
}

function Assert-TransactionCreatedAgentStateMarker {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedRoot,
        [Parameter(Mandatory = $true)] [string] $ExpectedTransactionId
    )
    [void](Assert-OrdinaryAgentStateMarkerFile -Path $Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $strictUtf8 = New-Object -TypeName Text.UTF8Encoding `
        -ArgumentList @($false, $true)
    try {
        $marker = $strictUtf8.GetString($bytes) | ConvertFrom-Json
    } catch {
        throw "Transaction-created Agent StateRoot marker is invalid JSON: $Path"
    }
    $transactionId = Get-NormalizedTransactionId -Value $ExpectedTransactionId
    $expectedRootId = [Guid]::ParseExact($transactionId, 'N').ToString('D')
    $createdUtc = [DateTimeOffset]::MinValue
    foreach ($propertyName in @(
            'format', 'product', 'canonical_path', 'root_id', 'created_utc')) {
        if ($null -eq $marker.PSObject.Properties[$propertyName]) {
            throw 'Transaction-created Agent StateRoot marker is missing its transaction binding.'
        }
    }
    if ([string]$marker.format -cne
            'mineguard-enterprise-agent-state-root-v1' -or
        [string]$marker.product -cne 'MineGuard Enterprise Agent' -or
        -not ([string]$marker.canonical_path).Equals(
            $ExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$marker.root_id -cne $expectedRootId -or
        -not [DateTimeOffset]::TryParse(
            [string]$marker.created_utc, [ref]$createdUtc)) {
        throw 'Refusing to remove an Agent StateRoot marker not proven to be transaction-created.'
    }
}

function Get-AgentStateAclInventory {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $item = Get-Item -LiteralPath $fullRoot -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Agent StateRoot ACL snapshot root is unsafe: $fullRoot"
    }
    # The wrapper-aware child installer never rewrites ACLs below an existing
    # StateRoot.  Persist only the root descriptor; the marker has a separate
    # byte/hash/ACL record below.  This keeps a large business-data tree out of
    # every durable journal generation.
    return @([pscustomobject]@{
        path = '.'
        kind = 'directory'
        sddl = Get-OriginalSecuritySddl -Path $fullRoot
    })
}

function Get-AgentStateAclEntryPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $RelativePath
    )
    if ($RelativePath -eq '.') { return $Root }
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.StartsWith('/') -or $RelativePath.Contains('\') -or
        $RelativePath.Contains(':')) {
        throw 'Agent StateRoot ACL snapshot contains an unsafe relative path.'
    }
    $segments = $RelativePath.Split('/')
    if ($segments -contains '' -or $segments -contains '.' -or
        $segments -contains '..') {
        throw 'Agent StateRoot ACL snapshot contains an unsafe path segment.'
    }
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $fullRoot $RelativePath.Replace('/', '\')))
    if (-not $candidate.StartsWith(
            $fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Agent StateRoot ACL snapshot escaped its protected root.'
    }
    return $candidate
}

function Capture-AgentStateRootMetadata {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )
    if ($Product -ne 'EnterpriseAgent') { return $null }
    $normalizedTransactionId = Get-NormalizedTransactionId -Value $TransactionId
    $normalizedRoot = Assert-SafeAgentStateRootScope -Root $Root `
        -ApplicationRoot $InstallRoot
    $rootExisted = Test-Path -LiteralPath $normalizedRoot
    if ($rootExisted -and
        -not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        throw 'Agent transaction StateRoot exists but is not a directory.'
    }
    $aclInventory = @()
    if ($rootExisted) {
        $aclInventory = @(Get-AgentStateAclInventory -Root $normalizedRoot)
    }
    $missingAncestors = [System.Collections.Generic.List[string]]::new()
    $existingAncestor = $normalizedRoot
    if (-not $rootExisted) {
        $cursor = $normalizedRoot
        while (-not (Test-Path -LiteralPath $cursor)) {
            $missingAncestors.Add($cursor)
            $parent = Split-Path -Parent $cursor
            if ([string]::IsNullOrWhiteSpace($parent) -or
                $parent.Equals($cursor, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Agent StateRoot has no safe existing ancestor.'
            }
            $cursor = [IO.Path]::GetFullPath($parent).TrimEnd('\')
        }
        if (-not (Test-Path -LiteralPath $cursor -PathType Container)) {
            throw 'Agent StateRoot existing ancestor is not a directory.'
        }
        [void](Get-SafeLocalNtfsPath -Path $cursor `
            -Label 'Agent StateRoot existing ancestor' -MustExist)
        $existingAncestor = $cursor
    }
    $transactionTemporary = Join-Path $normalizedRoot (
        '.mineguard-enterprise-agent-instances.tmp-' +
        $normalizedTransactionId)
    if (Test-Path -LiteralPath $transactionTemporary) {
        throw 'Agent StateRoot already contains the reserved transaction marker temporary path.'
    }
    $markerPath = Get-AgentStateMarkerPath -Root $normalizedRoot
    $markerExisted = Test-Path -LiteralPath $markerPath
    $markerRecord = if ($markerExisted) {
        $markerItem = Assert-OrdinaryAgentStateMarkerFile -Path $markerPath
        $markerBytes = [IO.File]::ReadAllBytes($markerPath)
        [pscustomobject]@{
            existed = $true
            bytes = [long]$markerBytes.LongLength
            sha256 = Get-ByteArraySha256 -Bytes $markerBytes
            sddl = Get-OriginalSecuritySddl -Path $markerPath
            attributes = [int]$markerItem.Attributes
        }
    } else {
        [pscustomobject]@{
            existed = $false
            bytes = [long]0
            sha256 = ''
            sddl = ''
            attributes = [int]0
        }
    }
    return [pscustomobject]@{
        format = 'mineguard-enterprise-agent-state-root-rollback-v1'
        stateRoot = $normalizedRoot
        rootExisted = [bool]$rootExisted
        transactionId = $normalizedTransactionId
        expectedMarkerRootId = [Guid]::ParseExact(
            $normalizedTransactionId, 'N').ToString('D')
        marker = $markerRecord
        aclInventory = @($aclInventory)
        missingAncestors = $missingAncestors.ToArray()
        existingAncestor = $existingAncestor
    }
}

function Restore-AgentStateRootMetadata {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Journal
    )
    if ($Product -ne 'EnterpriseAgent') { return }
    foreach ($propertyName in @(
            'format', 'stateRoot', 'rootExisted', 'transactionId',
            'expectedMarkerRootId', 'marker', 'aclInventory',
            'missingAncestors', 'existingAncestor')) {
        if ($null -eq $Snapshot.PSObject.Properties[$propertyName]) {
            throw 'Agent StateRoot rollback metadata is incomplete.'
        }
    }
    foreach ($propertyName in @(
            'existed', 'bytes', 'sha256', 'sddl', 'attributes')) {
        if ($null -eq $Snapshot.marker.PSObject.Properties[$propertyName]) {
            throw 'Agent StateRoot marker rollback metadata is incomplete.'
        }
    }
    $transactionId = Get-NormalizedTransactionId -Value (
        [string]$Snapshot.transactionId)
    $expectedMarkerRootId = [Guid]::ParseExact(
        $transactionId, 'N').ToString('D')
    if ([string]$Snapshot.format -cne
            'mineguard-enterprise-agent-state-root-rollback-v1' -or
        [string]::IsNullOrWhiteSpace([string]$Snapshot.stateRoot) -or
        -not ([string]$Snapshot.stateRoot).Equals(
            [string]$Journal.stateRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        $transactionId -cne [string]$Journal.transactionId -or
        [string]$Snapshot.expectedMarkerRootId -cne $expectedMarkerRootId -or
        $Snapshot.rootExisted -isnot [bool] -or
        $Snapshot.marker.existed -isnot [bool]) {
        throw 'Agent StateRoot rollback metadata is invalid.'
    }
    $root = Get-SafeLocalNtfsPath -Path ([string]$Snapshot.stateRoot) `
        -Label 'Agent rollback StateRoot'
    $missingAncestors = @($Snapshot.missingAncestors)
    $existingAncestor = Get-SafeLocalNtfsPath `
        -Path ([string]$Snapshot.existingAncestor) `
        -Label 'Agent rollback existing StateRoot ancestor' -MustExist
    if ([bool]$Snapshot.rootExisted) {
        if ($missingAncestors.Count -ne 0 -or
            -not $existingAncestor.Equals(
                $root, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Existing Agent StateRoot has invalid ancestor rollback metadata.'
        }
    } else {
        if ($missingAncestors.Count -eq 0) {
            throw 'New Agent StateRoot is missing its ancestor rollback metadata.'
        }
        $expectedMissing = $root
        foreach ($missing in $missingAncestors) {
            $normalizedMissing = Get-SafeLocalNtfsPath `
                -Path ([string]$missing) `
                -Label 'Agent rollback missing ancestor'
            if (-not $normalizedMissing.Equals(
                    $expectedMissing,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Agent StateRoot ancestor rollback chain is invalid.'
            }
            $expectedMissing = [IO.Path]::GetFullPath(
                (Split-Path -Parent $expectedMissing)).TrimEnd('\')
        }
        if (-not $expectedMissing.Equals(
                $existingAncestor, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Agent StateRoot rollback chain crossed its existing ancestor.'
        }
    }
    if ((Test-Path -LiteralPath $root) -and
        -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'Agent rollback StateRoot is no longer a directory.'
    }
    if ([bool]$Snapshot.rootExisted -and
        -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'Agent rollback StateRoot disappeared; business data recovery is required.'
    }

    $markerPath = Get-AgentStateMarkerPath -Root $root
    $transactionTemporary = Join-Path $root (
        '.mineguard-enterprise-agent-instances.tmp-' + $transactionId)
    if (-not [bool]$Snapshot.rootExisted) {
        for ($index = 0; $index -lt $missingAncestors.Count; $index++) {
            $missingPath = [IO.Path]::GetFullPath(
                [string]$missingAncestors[$index]).TrimEnd('\')
            if (-not (Test-Path -LiteralPath $missingPath)) { continue }
            if (-not (Test-Path -LiteralPath $missingPath -PathType Container)) {
                throw 'Transaction-created Agent StateRoot ancestor changed type.'
            }
            $missingItem = Get-Item -LiteralPath $missingPath -Force
            if (($missingItem.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Transaction-created Agent StateRoot ancestor became a reparse point.'
            }
            foreach ($item in @(
                    Get-ChildItem -LiteralPath $missingPath -Force)) {
                $allowed = if ($index -eq 0) {
                    $item.FullName.Equals(
                        $markerPath, [StringComparison]::OrdinalIgnoreCase) -or
                    $item.FullName.Equals(
                        $transactionTemporary,
                        [StringComparison]::OrdinalIgnoreCase)
                } else {
                    $item.FullName.Equals(
                        [IO.Path]::GetFullPath(
                            [string]$missingAncestors[$index - 1]).TrimEnd('\'),
                        [StringComparison]::OrdinalIgnoreCase)
                }
                if (-not $allowed) {
                    throw 'New Agent StateRoot ancestor contains unknown data and was preserved.'
                }
            }
        }
    }

    # Existing business descendants are deliberately absent from this record:
    # the wrapper-aware child installer only validates them and never rewrites
    # their ACLs.  Validate the one root entry before the first mutation.
    $validatedEntries = [System.Collections.Generic.List[object]]::new()
    if ([bool]$Snapshot.rootExisted) {
        $seenPaths = @{}
        foreach ($entry in @($Snapshot.aclInventory)) {
            foreach ($propertyName in @('path', 'kind', 'sddl')) {
                if ($null -eq $entry.PSObject.Properties[$propertyName]) {
                    throw 'Agent StateRoot ACL snapshot entry is incomplete.'
                }
            }
            $relative = [string]$entry.path
            $key = $relative.ToLowerInvariant()
            if ($seenPaths.ContainsKey($key) -or
                [string]::IsNullOrWhiteSpace([string]$entry.sddl) -or
                [string]$entry.kind -notin @('directory', 'file')) {
                throw 'Agent StateRoot ACL snapshot entry is invalid or duplicated.'
            }
            $seenPaths[$key] = $true
            $path = Get-AgentStateAclEntryPath -Root $root `
                -RelativePath $relative
            if (-not (Test-Path -LiteralPath $path)) {
                throw "Agent StateRoot snapshot object disappeared: $path"
            }
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (([string]$entry.kind -eq 'directory') -ne
                    [bool]$item.PSIsContainer)) {
                throw "Agent StateRoot snapshot object changed type: $path"
            }
            $validatedEntries.Add([pscustomobject]@{
                path = $path
                relative = $relative
                kind = [string]$entry.kind
                sddl = [string]$entry.sddl
                depth = if ($relative -eq '.') { 0 } else {
                    $relative.Split('/').Count
                }
            })
        }
        if ($validatedEntries.Count -ne 1 -or
            -not $seenPaths.ContainsKey('.') -or
            [string]$validatedEntries[0].kind -cne 'directory') {
            throw 'Agent StateRoot ACL snapshot must contain only its root entry.'
        }
    }
    if (Test-Path -LiteralPath $transactionTemporary) {
        $temporaryItem = Get-Item -LiteralPath $transactionTemporary -Force
        if ($temporaryItem.PSIsContainer -or
            ($temporaryItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Transaction-bound Agent marker temporary path is unsafe.'
        }
    }

    if ([bool]$Snapshot.marker.existed) {
        $markerItem = Assert-OrdinaryAgentStateMarkerFile -Path $markerPath
        $markerBytes = [IO.File]::ReadAllBytes($markerPath)
        if ([long]$markerBytes.LongLength -ne [long]$Snapshot.marker.bytes -or
            [string]$Snapshot.marker.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            (Get-ByteArraySha256 -Bytes $markerBytes) -cne
                [string]$Snapshot.marker.sha256 -or
            [string]::IsNullOrWhiteSpace([string]$Snapshot.marker.sddl)) {
            throw 'Existing Agent StateRoot marker changed during installation.'
        }
        [IO.File]::SetAttributes(
            $markerPath, [IO.FileAttributes][int]$Snapshot.marker.attributes)
        Set-ExactSecuritySddl -Path $markerPath -Kind 'file' `
            -Sddl ([string]$Snapshot.marker.sddl)
    } elseif (Test-Path -LiteralPath $markerPath) {
        Assert-TransactionCreatedAgentStateMarker -Path $markerPath `
            -ExpectedRoot $root -ExpectedTransactionId $transactionId
        Remove-Item -LiteralPath $markerPath -Force
    }

    if (Test-Path -LiteralPath $transactionTemporary) {
        Remove-Item -LiteralPath $transactionTemporary -Force
    }

    if ([bool]$Snapshot.rootExisted) {
        foreach ($entry in @($validatedEntries |
                Sort-Object -Property depth, relative)) {
            Set-ExactSecuritySddl -Path $entry.path -Kind $entry.kind `
                -Sddl $entry.sddl
        }
        foreach ($entry in $validatedEntries) {
            Assert-ExactSecuritySddl -Path $entry.path `
                -ExpectedSddl $entry.sddl
        }
    } else {
        foreach ($missing in $missingAncestors) {
            $path = [IO.Path]::GetFullPath([string]$missing).TrimEnd('\')
            if (-not (Test-Path -LiteralPath $path)) { continue }
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                throw 'Transaction-created Agent StateRoot ancestor changed type.'
            }
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                @(Get-ChildItem -LiteralPath $path -Force).Count -ne 0) {
                throw 'Transaction-created Agent StateRoot ancestor contains unknown data.'
            }
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Get-TreeInventory {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootItem = Get-Item -LiteralPath $Root -Force
    $records = [System.Collections.Generic.List[object]]::new()
    $items = @($rootItem)
    if ($rootItem.PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $Root -Force -Recurse |
            Sort-Object FullName)
    }
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Managed product artifact contains a reparse point: $($item.FullName)"
        }
        $relative = if ($item.FullName.Equals(
                [IO.Path]::GetFullPath($Root),
                [StringComparison]::OrdinalIgnoreCase)) {
            '.'
        } else {
            $item.FullName.Substring($prefix.Length).Replace('\', '/')
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
    return $records.ToArray()
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
    $specifications = [System.Collections.Generic.List[object]]::new()
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
    return $specifications.ToArray()
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

function Convert-ArpRegistrationToCanonicalJson {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $canonicalKeys = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($Snapshot.keys | Sort-Object -Property @(
            @{ Expression = { [string]$_.path }; Ascending = $true }
        ))) {
        $canonicalValues = [System.Collections.Generic.List[object]]::new()
        foreach ($valueRecord in @($record.values |
                Sort-Object -CaseSensitive -Property @(
                    @{ Expression = { [string]$_.name }; Ascending = $true }
                ))) {
            $encoding = [string]$valueRecord.value.encoding
            $data = if ($encoding -eq 'string-array') {
                @($valueRecord.value.data | ForEach-Object { [string]$_ })
            } else {
                [string]$valueRecord.value.data
            }
            $canonicalValues.Add([ordered]@{
                name = [string]$valueRecord.name
                kind = [string]$valueRecord.kind
                encoding = $encoding
                data = $data
            })
        }
        $canonicalKeys.Add([ordered]@{
            path = [string]$record.path
            sddl = [string]$record.sddl
            values = $canonicalValues.ToArray()
        })
    }
    $canonical = [ordered]@{
        subKey = [string]$Snapshot.subKey
        existed = [bool]$Snapshot.existed
        keys = $canonicalKeys.ToArray()
    }
    return ($canonical | ConvertTo-Json -Depth 20 -Compress)
}

function Get-RegistrySecuritySddl {
    param([Parameter(Mandatory = $true)]
          [Microsoft.Win32.RegistryKey] $Key)
    $security = $Key.GetAccessControl()
    $managedSections =
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    return $security.GetSecurityDescriptorSddlForm($managedSections)
}

function Set-ExactRegistrySecuritySddl {
    param(
        [Parameter(Mandatory = $true)] [Microsoft.Win32.RegistryKey] $Key,
        [Parameter(Mandatory = $true)] [string] $Sddl
    )
    # A recreated key normally inherits the exact saved descriptor already.
    # Avoid an order-only SetAccessControl round trip that lets Windows
    # normalize inherited ACE/control representation.
    if ((Get-RegistrySecuritySddl -Key $Key) -ceq $Sddl) {
        return
    }
    $security = New-Object -TypeName Security.AccessControl.RegistrySecurity
    $managedSections =
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    $security.SetSecurityDescriptorSddlForm($Sddl, $managedSections)
    $Key.SetAccessControl($security)
}

function Assert-ExactRegistrySecuritySddl {
    param(
        [Parameter(Mandatory = $true)] [Microsoft.Win32.RegistryKey] $Key,
        [Parameter(Mandatory = $true)] [string] $ExpectedSddl,
        [Parameter(Mandatory = $true)] [string] $Path
    )
    if ((Get-RegistrySecuritySddl -Key $Key) -cne $ExpectedSddl) {
        throw "Restored ARP security descriptor does not match its snapshot: $Path"
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
        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue('')
        $records = [System.Collections.Generic.List[object]]::new()
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
                $values = [System.Collections.Generic.List[object]]::new()
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
                        [Security.AccessControl.AccessControlSections]::Access -bor
                        [Security.AccessControl.AccessControlSections]::Owner -bor
                        [Security.AccessControl.AccessControlSections]::Group)
                    values = $values.ToArray()
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
            keys = $records.ToArray()
        }
    } finally {
        $base.Dispose()
    }
}

function Flush-ArpRegistryParent {
    param([Parameter(Mandatory = $true)] $BaseKey,
          [Parameter(Mandatory = $true)] [string] $SubKey)
    $separator = $SubKey.LastIndexOf('\')
    if ($separator -le 0) {
        throw 'ARP registry path has no flushable parent.'
    }
    $parentPath = $SubKey.Substring(0, $separator)
    $parentKey = $BaseKey.OpenSubKey($parentPath, $true)
    if ($null -eq $parentKey) {
        throw 'ARP registry parent disappeared during durable rollback.'
    }
    try {
        # RegistryKey.Flush maps to the native RegFlushKey durability boundary.
        $parentKey.Flush()
    } finally {
        $parentKey.Dispose()
    }
}

function Restore-ArpRegistration {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $expectedSubKey = Get-ArpRegistrySubKey -Kind $Product
    if ([string]$Snapshot.subKey -cne $expectedSubKey) {
        throw 'ARP snapshot targets an unexpected registry key.'
    }
    $expectedCanonical = Convert-ArpRegistrationToCanonicalJson `
        -Snapshot $Snapshot
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        try { $base.DeleteSubKeyTree($expectedSubKey, $false) } catch { throw }
        if (-not [bool]$Snapshot.existed) {
            Flush-ArpRegistryParent -BaseKey $base -SubKey $expectedSubKey
            $actualCanonical = Convert-ArpRegistrationToCanonicalJson `
                -Snapshot (Capture-ArpRegistration)
            if ($actualCanonical -cne $expectedCanonical) {
                throw 'Absent ARP registration was not restored exactly.'
            }
            return
        }
        $records = @($Snapshot.keys | Sort-Object -Property @(
            @{ Expression = {
                if ([string]$_.path -eq '') {
                    0
                } else {
                    ([string]$_.path).Split('\').Count
                }
            }; Ascending = $true },
            @{ Expression = { [string]$_.path }; Ascending = $true }
        ))
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
                Set-ExactRegistrySecuritySddl -Key $key `
                    -Sddl ([string]$record.sddl)
                # Flush every restored key before rolledback can become
                # durable; this covers values, security and child-key state.
                $key.Flush()
            } finally {
                $key.Dispose()
            }
        }
        # Verify the final ACL tree only after every parent and child has been
        # created, so late inheritance propagation cannot escape detection.
        foreach ($record in $records) {
            $currentSubKey = if ([string]$record.path -eq '') {
                $expectedSubKey
            } else {
                $expectedSubKey + '\' + [string]$record.path
            }
            $key = $base.OpenSubKey($currentSubKey, $false)
            if ($null -eq $key) {
                throw "Restored ARP registry key disappeared: $currentSubKey"
            }
            try {
                Assert-ExactRegistrySecuritySddl -Key $key `
                    -ExpectedSddl ([string]$record.sddl) `
                    -Path $currentSubKey
            } finally {
                $key.Dispose()
            }
        }
        Flush-ArpRegistryParent -BaseKey $base -SubKey $expectedSubKey
        $actualCanonical = Convert-ArpRegistrationToCanonicalJson `
            -Snapshot (Capture-ArpRegistration)
        if ($actualCanonical -cne $expectedCanonical) {
            throw 'Restored ARP registration values, types or ACLs do not match the snapshot.'
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
            # Snapshot content must reach stable storage before a durable
            # journal generation is allowed to reference it.
            Sync-FileTreeToDisk -Path $snapshotPath
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
    # Restore parents before children so inherited descriptors can settle
    # naturally.  Set-ExactSecuritySddl skips an already-identical descriptor;
    # this is essential for inherited ACLs because a no-op Set-Acl round trip
    # may normalize Windows control flags or ACE representation.
    $ordered = @($Inventory | Sort-Object -Property @(
        @{ Expression = {
            if ([string]$_.path -eq '.') {
                0
            } else {
                ([string]$_.path).Split('/').Count
            }
        }; Ascending = $true },
        @{ Expression = { [string]$_.path }; Ascending = $true }
    ))
    foreach ($entry in $ordered) {
        $path = if ([string]$entry.path -eq '.') {
            $Root
        } else {
            Join-Path $Root ([string]$entry.path).Replace('/', '\')
        }
        Set-ExactSecuritySddl -Path $path -Kind ([string]$entry.kind) `
            -Sddl ([string]$entry.sddl)
    }
    # Validate the final tree only after every parent and child has settled;
    # a later inherited-ACL propagation must never escape detection.
    foreach ($entry in $ordered) {
        $path = if ([string]$entry.path -eq '.') {
            $Root
        } else {
            Join-Path $Root ([string]$entry.path).Replace('/', '\')
        }
        Assert-ExactSecuritySddl -Path $path `
            -ExpectedSddl ([string]$entry.sddl)
    }
}

function Restore-ManagedArtifacts {
    param([Parameter(Mandatory = $true)] $Descriptor,
          [Parameter(Mandatory = $true)] $Journal)
    $productRootProperty =
        $Journal.PSObject.Properties['productRootMetadata']
    if ($null -eq $productRootProperty -or
        $null -eq $productRootProperty.Value) {
        throw 'Transaction has no product-root rollback metadata and was preserved.'
    }
    $validatedProductRoot = Get-ValidatedProductRootRollbackMetadata `
        -Snapshot $productRootProperty.Value -Descriptor $Descriptor
    $Journal.state = 'rollingback'
    Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal

    Restore-ProductRootMetadataBeforeArtifacts -Validated $validatedProductRoot
    Restore-ArpRegistration -Snapshot $Journal.arpRegistration

    if (Test-Path -LiteralPath $Descriptor.InstallRoot -PathType Container) {
        foreach ($currentUninstaller in @(Get-ChildItem `
                -LiteralPath $Descriptor.InstallRoot -File -Force |
                Where-Object {
                    $_.Name -cmatch '^unins[0-9]{3}\.(?:exe|dat|msg)$'
                })) {
            Remove-ManagedTarget -Path $currentUninstaller.FullName
        }
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
        # The restored active tree must be on stable storage before the
        # cleanup-only rolledback generation is acknowledged.
        Sync-FileTreeToDisk -Path $target
        $index++
    }
    if ($Product -eq 'EnterpriseAgent') {
        $stateMetadataProperty =
            $Journal.PSObject.Properties['agentStateRootMetadata']
        if ($null -eq $stateMetadataProperty -or
            $null -eq $stateMetadataProperty.Value) {
            throw 'Agent transaction has no StateRoot rollback metadata and was preserved.'
        }
        Restore-AgentStateRootMetadata -Snapshot $stateMetadataProperty.Value `
            -Journal $Journal
    }
    # Restore the independent Agent StateRoot before the final fresh-product
    # directory deletion.  If power is lost after that deletion, a replay can
    # tolerate the already-absent InstallRoot and still reach the durable
    # cleanup-only terminal state.
    Complete-ProductRootMetadataRollback -Validated $validatedProductRoot
    $Journal.state = 'rolledback'
    Write-TransactionJournal -Descriptor $Descriptor -Journal $Journal
}

function Assert-TransactionContext {
    param([Parameter(Mandatory = $true)] $Journal,
          [switch] $IncludeRelease,
          [switch] $IncludeCurrentStateRoot)
    if ([string]$Journal.product -cne $Product -or
        -not ([string]$Journal.installRoot).Equals(
            [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer transaction context does not match the current product.'
    }
    if ($IncludeCurrentStateRoot) {
        $currentStateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
            ''
        } else {
            Get-NormalizedPathText -Value $StateRoot -Label 'StateRoot'
        }
        if (($Product -eq 'EnterpriseAgent' -and
                [string]::IsNullOrWhiteSpace($currentStateRoot)) -or
            ($Product -eq 'Platform' -and
                -not [string]::IsNullOrWhiteSpace($currentStateRoot)) -or
            -not ([string]$Journal.stateRoot).Equals(
                $currentStateRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Installer transaction StateRoot changed between phases.'
        }
    }
    if ($IncludeRelease) {
        $expected = ($ExpectedReleaseManifestSha256 -replace '\s', '').ToLowerInvariant()
        $rootMetadataProperty =
            $Journal.PSObject.Properties['productRootMetadata']
        if ([string]$Journal.expectedReleaseManifestSha256 -cne $expected -or
            [bool]$Journal.allowUnsignedTestMedia -ne [bool]$AllowUnsignedTestMedia -or
            [bool]$Journal.allowUnsignedInternalRelease -ne
                [bool]$AllowUnsignedInternalRelease -or
            [string]$Journal.approvedSignerThumbprint -cne
                (($ApprovedSignerThumbprint -replace '\s', '').ToUpperInvariant()) -or
            $null -eq $rootMetadataProperty -or
            [bool]$rootMetadataProperty.Value.installRootPreexisted -ne
                ($WrapperInstallRootPreexisted -ceq '1') -or
            [bool]$rootMetadataProperty.Value.shortcutGroupPreexisted -ne
                ($WrapperShortcutGroupPreexisted -ceq '1')) {
            throw 'Installer transaction release authorization changed between phases.'
        }
    }
}

function Invoke-StagedProductInstaller {
    param(
        [string] $CandidateRoot,
        [string] $InstallerPath,
        [string] $MarkerTransactionId = ''
    )
    if ($Product -eq 'Platform') {
        $arguments = @{
            SourceDirectory = $CandidateRoot
            InstallRoot = $InstallRoot
        }
        if (-not [string]::IsNullOrWhiteSpace($MarkerTransactionId)) {
            $arguments['TrustedBootstrapTransactionId'] =
                Get-NormalizedTransactionId -Value $MarkerTransactionId
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
        if (-not [string]::IsNullOrWhiteSpace($MarkerTransactionId)) {
            $arguments['TrustedBootstrapTransactionId'] =
                Get-NormalizedTransactionId -Value $MarkerTransactionId
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
    param(
        [Parameter(Mandatory = $true)] $Descriptor,
        [switch] $IncludeCurrentStateRoot
    )
    if (-not (Test-Path -LiteralPath $Descriptor.Path -PathType Container)) {
        return
    }
    try {
        $journalRecord = Read-TransactionJournalRecord -Descriptor $Descriptor
        $journal = $journalRecord.Journal
    } catch {
        if (Test-SafeUninitializedTransactionOrphan -Descriptor $Descriptor) {
            # Begin may lose power between protected-directory creation and
            # its first complete journal generation.  With no payload at all,
            # this orphan cannot represent an installed-product mutation.
            Remove-TransactionDirectory -Descriptor $Descriptor
            return
        }
        throw (
            'Installer rollback preserved a transaction with no valid journal ' +
            'because it contains snapshot, candidate, or unknown data: ' +
            $Descriptor.Path)
    }
    Assert-TransactionContext -Journal $journal `
        -IncludeCurrentStateRoot:$IncludeCurrentStateRoot
    if ([string]$journal.state -eq 'capturing') {
        if ([long]$journalRecord.Generation -eq 0 -and
            -not (Test-TransactionContainsOnlyJournalArtifacts `
                -Descriptor $Descriptor)) {
            # The legacy writer overwrote journal.json without a durable
            # generation.  Its capturing value can lag a later product
            # mutation, so payload-bearing legacy transactions are preserved
            # for manual recovery instead of being discarded.
            throw 'Legacy capturing transaction has payload and was preserved.'
        }
        Remove-TransactionDirectory -Descriptor $Descriptor
        return
    }
    if ([string]$journal.state -in @('rolledback', 'wrapper_succeeded')) {
        # These durable terminal states are cleanup-only.  Replaying rollback
        # after a partial cleanup could consume a half-removed snapshot.
        Remove-TransactionDirectory -Descriptor $Descriptor
        return
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
        try {
            $journalRecord = Read-TransactionJournalRecord -Descriptor $stale
            $journal = $journalRecord.Journal
        } catch {
            if (Test-SafeUninitializedTransactionOrphan -Descriptor $stale) {
                Remove-TransactionDirectory -Descriptor $stale
                continue
            }
            throw (
                'Stale recovery preserved a transaction with no valid journal ' +
                'because it contains snapshot, candidate, or unknown data: ' +
                $stale.Path)
        }
        Assert-TransactionContext -Journal $journal
        if ([string]$journal.state -in @('rolledback', 'wrapper_succeeded')) {
            # Durable wrapper success is the no-return point. Its retained
            # snapshot, like a rolled-back terminal snapshot, is cleanup-only
            # data even if a later uninstall or upgrade changed active files.
            Remove-TransactionDirectory -Descriptor $stale
        } elseif ([string]$journal.state -eq 'capturing') {
            if ([long]$journalRecord.Generation -eq 0 -and
                -not (Test-TransactionContainsOnlyJournalArtifacts `
                    -Descriptor $stale)) {
                throw 'Legacy capturing transaction has payload and was preserved.'
            }
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
    -Kind $Product -Id $normalizedTransactionId `
    -AllowMissingInstallRoot:($TransactionAction -eq 'Rollback')

switch ($TransactionAction) {
    'Begin' {
        $normalizedStateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
            ''
        } else {
            Get-NormalizedPathText -Value $StateRoot -Label 'StateRoot'
        }
        if (($Product -eq 'EnterpriseAgent' -and
                [string]::IsNullOrWhiteSpace($normalizedStateRoot)) -or
            ($Product -eq 'Platform' -and
                -not [string]::IsNullOrWhiteSpace($normalizedStateRoot))) {
            throw 'StateRoot is required only for the Enterprise Agent transaction.'
        }
        $normalizedExpectedHash = (
            $ExpectedReleaseManifestSha256 -replace '\s', '').ToLowerInvariant()
        if ($normalizedExpectedHash -cnotmatch '^[a-f0-9]{64}$') {
            throw 'ExpectedReleaseManifestSha256 must be exactly 64 hexadecimal characters.'
        }
        if ($Product -eq 'EnterpriseAgent') {
            $normalizedStateRoot = Assert-SafeAgentStateRootScope `
                -Root $normalizedStateRoot `
                -ApplicationRoot $descriptor.InstallRoot
        }
        Recover-StaleTransactions -CurrentDescriptor $descriptor
        $productRootMetadata = Capture-ProductRootMetadata `
            -Descriptor $descriptor `
            -InstallRootPreexisted:($WrapperInstallRootPreexisted -ceq '1') `
            -ShortcutGroupPreexisted:($WrapperShortcutGroupPreexisted -ceq '1')
        $agentStateRootMetadata = if ($Product -eq 'EnterpriseAgent') {
            Capture-AgentStateRootMetadata -Root $normalizedStateRoot `
                -TransactionId $normalizedTransactionId
        } else { $null }
        New-ProtectedTransactionDirectory -Descriptor $descriptor
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
            productRootMetadata = $productRootMetadata
            agentStateRootMetadata = $agentStateRootMetadata
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
        Assert-TransactionContext -Journal $journal -IncludeRelease `
            -IncludeCurrentStateRoot
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
        # The prepared state is recoverable only when every candidate byte was
        # flushed before its journal generation became durable.
        Sync-FileTreeToDisk -Path $candidate
        [void](Assert-TrustedReleaseTree -Root $candidate `
            -ExpectedManifestHash $ExpectedReleaseManifestSha256 -Kind $Product)
        $journal.state = 'prepared'
        Write-TransactionJournal -Descriptor $descriptor -Journal $journal
    }
    'Commit' {
        $journal = Read-TransactionJournal -Descriptor $descriptor
        Assert-TransactionContext -Journal $journal -IncludeRelease `
            -IncludeCurrentStateRoot
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
            -InstallerPath $stagedInstaller `
            -MarkerTransactionId $journal.transactionId
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
        Invoke-TransactionRollback -Descriptor $descriptor `
            -IncludeCurrentStateRoot
    }
    'Finalize' {
        if (-not (Test-Path -LiteralPath $descriptor.Path -PathType Container)) {
            return
        }
        $journal = Read-TransactionJournal -Descriptor $descriptor
        Assert-TransactionContext -Journal $journal -IncludeRelease `
            -IncludeCurrentStateRoot
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
