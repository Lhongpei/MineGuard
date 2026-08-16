[CmdletBinding()]
param(
    [string] $BootstrapPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT' -or
    $PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSVersion.Minor -lt 1) {
    throw 'This transaction test must run with Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'This transaction test requires 64-bit Windows PowerShell for HKLM64.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BootstrapPath)) {
    $BootstrapPath = Join-Path $repositoryRoot `
        'packaging\windows\assets\Invoke-MineGuardTrustedProductInstall.ps1'
}
$BootstrapPath = [IO.Path]::GetFullPath($BootstrapPath)
if (-not (Test-Path -LiteralPath $BootstrapPath -PathType Leaf)) {
    throw "Trusted bootstrap is missing: $BootstrapPath"
}
$bootstrapItem = Get-Item -LiteralPath $BootstrapPath -Force
if (($bootstrapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Trusted bootstrap test input cannot be a reparse point.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName `
    Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Trusted bootstrap transaction tests must run as Administrator.'
}

$script:bootstrapSha256 = (Get-FileHash -LiteralPath $BootstrapPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$script:utf8NoBom = New-Object -TypeName Text.UTF8Encoding `
    -ArgumentList @($false, $true)
$script:platformArpRootSddl = ''
$script:platformArpNestedSddl = ''
$script:platformArpLeafSddl = ''
$script:platformArpOwnershipToken = [Guid]::NewGuid().ToString('N')

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)] [bool] $Condition,
        [Parameter(Mandatory = $true)] [string] $Message
    )
    if (-not $Condition) { throw $Message }
}

function Format-TestFailure {
    param([Parameter(Mandatory = $true)] $ErrorRecord)
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add([string]$ErrorRecord.Exception.Message)
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$ErrorRecord.InvocationInfo.PositionMessage)) {
        $parts.Add('Original position:' + [Environment]::NewLine +
            [string]$ErrorRecord.InvocationInfo.PositionMessage)
    }
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$ErrorRecord.ScriptStackTrace)) {
        $parts.Add('Original script stack:' + [Environment]::NewLine +
            [string]$ErrorRecord.ScriptStackTrace)
    }
    return ($parts.ToArray() -join [Environment]::NewLine)
}

function Get-RelativeTestPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $FullName
    )
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($FullName)
    if (-not $full.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fixture file escaped its root: $full"
    }
    return $full.Substring($prefix.Length).Replace('\', '/')
}

function Write-Utf8NoBomText {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Text
    )
    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function Write-NewOwnedUtf8NoBomText {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Text,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $OwnedPaths
    )
    $stream = New-Object -TypeName IO.FileStream -ArgumentList @(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::WriteThrough
    )
    $failure = $null
    try {
        $bytes = $script:utf8NoBom.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } catch {
        $failure = $_
    } finally {
        $stream.Dispose()
    }
    if ($null -ne $failure) {
        try { Remove-Item -LiteralPath $Path -Force } catch { }
        throw $failure
    }
    try {
        [void]$OwnedPaths.Add([IO.Path]::GetFullPath($Path))
    } catch {
        $trackingFailure = $_
        try { Remove-Item -LiteralPath $Path -Force } catch { }
        throw $trackingFailure
    }
}

function Assert-NoLocalReparseTree {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($item in @((Get-Item -LiteralPath $Path -Force)) + @(
            Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Test cleanup target contains a reparse point: $($item.FullName)"
        }
    }
}

function New-SecureVerificationRoot {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $volumeRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($volumeRoot) -or
        $full.Equals(
            $volumeRoot.TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unsafe verification root: $full"
    }
    if (Test-Path -LiteralPath $full) {
        throw "Verification root already exists: $full"
    }
    $parent = Split-Path -Parent $full
    $parentItem = Get-Item -LiteralPath $parent -Force
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Verification-root parent is a reparse point: $parent"
    }
    $drive = New-Object -TypeName IO.DriveInfo -ArgumentList $volumeRoot
    if (-not $drive.IsReady -or
        $drive.DriveType -ne [IO.DriveType]::Fixed -or
        -not $drive.DriveFormat.Equals(
            'NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Verification root must be on a ready local fixed NTFS volume.'
    }

    $administrators = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $localSystem = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
        -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in @($administrators, $localSystem)) {
        $rule = New-Object -TypeName `
            Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    [void][IO.Directory]::CreateDirectory($full, $acl)

    $actual = [IO.Directory]::GetAccessControl($full)
    $actualOwner = $actual.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    $actualRules = @($actual.GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]))
    if (-not $actual.AreAccessRulesProtected -or
        $actualOwner -cne $administrators.Value -or
        $actualRules.Count -ne 2) {
        throw 'Secure verification root has an invalid owner or DACL.'
    }
    $expectedSids = @($administrators.Value, $localSystem.Value)
    foreach ($actualRule in $actualRules) {
        if ($expectedSids -cnotcontains $actualRule.IdentityReference.Value -or
            $actualRule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $actualRule.FileSystemRights -ne
                [Security.AccessControl.FileSystemRights]::FullControl -or
            $actualRule.InheritanceFlags -ne $inheritance -or
            $actualRule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None) {
            throw 'Secure verification root has a non-canonical DACL rule.'
        }
    }
    return $full
}

function Remove-SafeVerificationRoot {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedParent
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    if (-not ([IO.Path]::GetDirectoryName($full)).Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cnotmatch
            '^MineGuardTrustedBootstrapTest-[a-f0-9]{32}$') {
        throw "Refusing to remove an unexpected verification root: $full"
    }
    Assert-NoLocalReparseTree -Path $full
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $lastError = $null
    do {
        try {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
        } catch {
            $lastError = $_
        }
        if (-not (Test-Path -LiteralPath $full)) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $detail = if ($null -eq $lastError) {
        'the directory still exists'
    } else {
        $lastError.Exception.Message
    }
    throw "Verification-root cleanup failed: $full. $detail"
}

function Get-ArpSubKey {
    param([ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product)
    $applicationId = if ($Product -eq 'Platform') {
        '{8B391CBD-E234-46D7-9946-E9D37F2649C1}'
    } else {
        '{9B73DE95-6B38-4482-A8BC-2A4FC656D05A}'
    }
    return 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' +
        $applicationId + '_is1'
}

function Open-Registry64Base {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
}

function Test-ArpRegistrationExists {
    param([ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product)
    $base = Open-Registry64Base
    try {
        $key = $base.OpenSubKey((Get-ArpSubKey -Product $Product), $false)
        if ($null -eq $key) { return $false }
        $key.Dispose()
        return $true
    } finally {
        $base.Dispose()
    }
}

function Flush-ArpParent {
    param(
        [Parameter(Mandatory = $true)] $Base,
        [Parameter(Mandatory = $true)] [string] $SubKey
    )
    $separator = $SubKey.LastIndexOf('\')
    $parentPath = $SubKey.Substring(0, $separator)
    $parent = $Base.OpenSubKey($parentPath, $true)
    if ($null -eq $parent) { throw 'ARP parent registry key is unavailable.' }
    try { $parent.Flush() } finally { $parent.Dispose() }
}

function Get-RegistrySddl {
    param([Parameter(Mandatory = $true)] $Key)
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    return $Key.GetAccessControl().GetSecurityDescriptorSddlForm($sections)
}

function Set-RestrictedArpFixtureAcl {
    param([Parameter(Mandatory = $true)] $Key)
    $administrators = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $localSystem = New-Object -TypeName `
        Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $security = New-Object -TypeName Security.AccessControl.RegistrySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administrators)
    $systemRule = New-Object -TypeName `
        Security.AccessControl.RegistryAccessRule -ArgumentList @(
            $localSystem,
            [Security.AccessControl.RegistryRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
    )
    $administratorRights = [Security.AccessControl.RegistryRights]::ReadKey `
        -bor [Security.AccessControl.RegistryRights]::Delete `
        -bor [Security.AccessControl.RegistryRights]::ChangePermissions
    $administratorRule = New-Object -TypeName `
        Security.AccessControl.RegistryAccessRule -ArgumentList @(
            $administrators,
            $administratorRights,
            $inheritance,
            $propagation,
            $allow
    )
    [void]$security.AddAccessRule($systemRule)
    [void]$security.AddAccessRule($administratorRule)
    $Key.SetAccessControl($security)
    $Key.Flush()

    $actual = $Key.GetAccessControl()
    $administratorRules = @($actual.GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]) |
        Where-Object {
            $_.IdentityReference.Value -ceq $administrators.Value -and
            $_.AccessControlType -eq $allow
        })
    if (-not $actual.AreAccessRulesProtected -or
        $administratorRules.Count -ne 1 -or
        ($administratorRules[0].RegistryRights -band
            [Security.AccessControl.RegistryRights]::CreateSubKey) -ne 0 -or
        ($administratorRules[0].RegistryRights -band
            [Security.AccessControl.RegistryRights]::SetValue) -ne 0 -or
        ($administratorRules[0].RegistryRights -band
            [Security.AccessControl.RegistryRights]::Delete) -eq 0 -or
        ($administratorRules[0].RegistryRights -band
            [Security.AccessControl.RegistryRights]::ChangePermissions) -eq 0) {
        throw 'Restricted ARP fixture ACL did not remove administrator write access.'
    }
}

function Enable-PlatformArpFixtureCleanupAccess {
    $subKey = Get-ArpSubKey -Product Platform
    $base = Open-Registry64Base
    try {
        $root = $base.OpenSubKey($subKey, $false)
        if ($null -eq $root) { return $false }
        try {
            $token = [string]$root.GetValue(
                'MineGuardTransactionTestOwner', '',
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($token -cne $script:platformArpOwnershipToken) {
                throw 'Refusing to relax or delete an ARP key not owned by this test.'
            }
            $pending = New-Object `
                'System.Collections.Generic.Queue[string]'
            $pending.Enqueue('')
            $relativePaths = @()
            while ($pending.Count -gt 0) {
                $relative = $pending.Dequeue()
                $relativePaths += $relative
                $current = if ($relative -eq '') {
                    $root
                } else {
                    $root.OpenSubKey($relative, $false)
                }
                if ($null -eq $current) {
                    throw 'Test-owned ARP tree changed during cleanup authorization.'
                }
                try {
                    foreach ($child in @($current.GetSubKeyNames())) {
                        $pending.Enqueue($(if ($relative -eq '') {
                            $child
                        } else {
                            $relative + '\' + $child
                        }))
                    }
                } finally {
                    if ($current -ne $root) { $current.Dispose() }
                }
            }
        } finally {
            $root.Dispose()
        }

        $administrators = New-Object -TypeName `
            Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
        $localSystem = New-Object -TypeName `
            Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit
        $allow = [Security.AccessControl.AccessControlType]::Allow
        foreach ($relative in @($relativePaths | Sort-Object {
                    if ($_ -eq '') { 0 } else { $_.Split('\').Count }
                } -Descending)) {
            $currentSubKey = if ($relative -eq '') {
                $subKey
            } else {
                $subKey + '\' + $relative
            }
            $cleanupRights = `
                [Security.AccessControl.RegistryRights]::ReadKey -bor `
                [Security.AccessControl.RegistryRights]::ChangePermissions
            $key = $base.OpenSubKey(
                $currentSubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                $cleanupRights)
            if ($null -eq $key) {
                throw 'Test-owned ARP key denied cleanup ACL access.'
            }
            try {
                $security = New-Object -TypeName `
                    Security.AccessControl.RegistrySecurity
                $security.SetAccessRuleProtection($true, $false)
                foreach ($sid in @($administrators, $localSystem)) {
                    $rule = New-Object -TypeName `
                        Security.AccessControl.RegistryAccessRule -ArgumentList @(
                            $sid,
                            [Security.AccessControl.RegistryRights]::FullControl,
                            $inheritance,
                            [Security.AccessControl.PropagationFlags]::None,
                            $allow
                    )
                    [void]$security.AddAccessRule($rule)
                }
                $key.SetAccessControl($security)
                $key.Flush()
            } finally {
                $key.Dispose()
            }
        }
        return $true
    } finally {
        $base.Dispose()
    }
}

function Remove-TestOwnedPlatformArpRegistration {
    if (-not (Enable-PlatformArpFixtureCleanupAccess)) { return }
    $subKey = Get-ArpSubKey -Product Platform
    $base = Open-Registry64Base
    try {
        # Recheck ownership after the ACL transition and immediately before
        # deleting this fixed global identity.  A concurrently replaced real
        # registration must be preserved.
        $root = $base.OpenSubKey($subKey, $false)
        if ($null -eq $root) { return }
        try {
            $token = [string]$root.GetValue(
                'MineGuardTransactionTestOwner', '',
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($token -cne $script:platformArpOwnershipToken) {
                throw 'Refusing to delete an ARP key no longer owned by this test.'
            }
        } finally {
            $root.Dispose()
        }
        $base.DeleteSubKeyTree($subKey, $false)
        Flush-ArpParent -Base $base -SubKey $subKey
    } finally {
        $base.Dispose()
    }
}

function New-TestOwnedPlatformArpProviderKey {
    param([Parameter(Mandatory = $true)] [string] $ProviderPath)
    $createdKey = $null
    try {
        # RegistryProvider returns the newly opened RegistryKey.  Suppressing
        # that object with [void] leaves its native handle for GC/finalization,
        # so a later DeleteSubKeyTree can remain delete-pending indefinitely
        # within this long-lived test process.  Capture and deterministically
        # dispose the create-new handle before reopening through Registry64.
        $createdKey = New-Item -Path $ProviderPath -ErrorAction Stop
        if ($createdKey -isnot [Microsoft.Win32.RegistryKey]) {
            throw 'RegistryProvider returned an unexpected create-new object.'
        }
    } finally {
        if ($null -ne $createdKey -and
            $createdKey -is [Microsoft.Win32.RegistryKey]) {
            $createdKey.Dispose()
        }
    }
}

function New-PlatformArpFixture {
    $subKey = Get-ArpSubKey -Product Platform
    $providerPath = 'Registry::HKEY_LOCAL_MACHINE\' + $subKey
    if (Test-ArpRegistrationExists -Product Platform) {
        throw 'Refusing to overwrite a Platform ARP registration created during the test.'
    }
    # New-Item without -Force is the create-new boundary.  If another
    # installer wins the fixed-name race, it fails instead of opening and
    # overwriting that registration.  Until the ownership token is written,
    # no catch path deletes this fixed name merely because creation started.
    New-TestOwnedPlatformArpProviderKey -ProviderPath $providerPath
    $ownershipSet = $false
    $base = Open-Registry64Base
    try {
        $root = $base.OpenSubKey(
            $subKey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [Security.AccessControl.RegistryRights]::FullControl)
        if ($null -eq $root) {
            throw 'New Platform ARP fixture could not be reopened for writing.'
        }
        try {
            $root.SetValue(
                'MineGuardTransactionTestOwner',
                $script:platformArpOwnershipToken,
                [Microsoft.Win32.RegistryValueKind]::String)
            $ownershipSet = $true
            $root.SetValue('', 'fixture-default',
                [Microsoft.Win32.RegistryValueKind]::String)
            $root.SetValue('DisplayName', 'MineGuard transaction fixture',
                [Microsoft.Win32.RegistryValueKind]::String)
            $root.SetValue('Expandable', '%ProgramData%\MineGuardFixture',
                [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $root.SetValue('DwordValue', [int]123456789,
                [Microsoft.Win32.RegistryValueKind]::DWord)
            $root.SetValue('QwordValue', [long]9876543210,
                [Microsoft.Win32.RegistryValueKind]::QWord)
            $root.SetValue('MultiValue', [string[]]@('alpha', 'beta'),
                [Microsoft.Win32.RegistryValueKind]::MultiString)
            $root.SetValue('BinaryValue', [byte[]]@(0, 1, 2, 127, 128, 255),
                [Microsoft.Win32.RegistryValueKind]::Binary)
            $root.SetValue('NoneValue', [byte[]]@(9, 8, 7, 0),
                [Microsoft.Win32.RegistryValueKind]::None)
            $child = $root.CreateSubKey(
                'Nested',
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
            try {
                $child.SetValue('Channel', 'fixture-old',
                    [Microsoft.Win32.RegistryValueKind]::String)
                $leaf = $child.CreateSubKey(
                    'Leaf',
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                try {
                    $leaf.SetValue('Depth', [int]2,
                        [Microsoft.Win32.RegistryValueKind]::DWord)
                    $leaf.Flush()
                } finally {
                    $leaf.Dispose()
                }
                $child.Flush()
            } finally {
                $child.Dispose()
            }
            # The captured root intentionally denies Administrators SetValue
            # and CreateSubKey while retaining ReadKey/Delete.  The rollback
            # must therefore create the entire Nested\Leaf tree before it
            # restores this parent ACL.
            Set-RestrictedArpFixtureAcl -Key $root
            $script:platformArpRootSddl = Get-RegistrySddl -Key $root
            $nestedRead = $root.OpenSubKey('Nested', $false)
            if ($null -eq $nestedRead) {
                throw 'Restricted ARP fixture lost its Nested key.'
            }
            try {
                $script:platformArpNestedSddl = Get-RegistrySddl -Key $nestedRead
                $leafRead = $nestedRead.OpenSubKey('Leaf', $false)
                if ($null -eq $leafRead) {
                    throw 'Restricted ARP fixture lost its Nested\Leaf key.'
                }
                try {
                    $script:platformArpLeafSddl = Get-RegistrySddl -Key $leafRead
                } finally {
                    $leafRead.Dispose()
                }
            } finally {
                $nestedRead.Dispose()
            }
        } finally {
            $root.Dispose()
        }
        Flush-ArpParent -Base $base -SubKey $subKey
    } catch {
        $fixtureFailure = $_
        try {
            if ($ownershipSet) {
                Remove-TestOwnedPlatformArpRegistration
            }
        } catch {
            throw (
                $fixtureFailure.Exception.Message + [Environment]::NewLine +
                'Platform ARP fixture cleanup also failed: ' +
                $_.Exception.Message)
        }
        throw $fixtureFailure
    } finally {
        $base.Dispose()
    }
}

function Set-ChangedPlatformArpFixture {
    Remove-TestOwnedPlatformArpRegistration
    $subKey = Get-ArpSubKey -Product Platform
    $providerPath = 'Registry::HKEY_LOCAL_MACHINE\' + $subKey
    if (Test-ArpRegistrationExists -Product Platform) {
        throw 'Refusing to overwrite a Platform ARP registration created during mutation.'
    }
    New-TestOwnedPlatformArpProviderKey -ProviderPath $providerPath
    $base = Open-Registry64Base
    try {
        $root = $base.OpenSubKey($subKey, $true)
        if ($null -eq $root) {
            throw 'Changed Platform ARP fixture could not be reopened for writing.'
        }
        try {
            $root.SetValue(
                'MineGuardTransactionTestOwner',
                $script:platformArpOwnershipToken,
                [Microsoft.Win32.RegistryValueKind]::String)
            $root.SetValue('DisplayName', 'changed-after-commit',
                [Microsoft.Win32.RegistryValueKind]::String)
            $root.SetValue('DwordValue', [int]7,
                [Microsoft.Win32.RegistryValueKind]::DWord)
            $root.Flush()
        } finally {
            $root.Dispose()
        }
        Flush-ArpParent -Base $base -SubKey $subKey
    } finally {
        $base.Dispose()
    }
}

function Assert-RegistryValue {
    param(
        [Parameter(Mandatory = $true)] $Key,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Name,
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryValueKind] $Kind,
        [Parameter(Mandatory = $true)] $Expected
    )
    if ($Key.GetValueKind($Name) -ne $Kind) {
        throw "ARP registry value kind changed: $Name"
    }
    $options = if ($Kind -eq
            [Microsoft.Win32.RegistryValueKind]::ExpandString) {
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    } else {
        [Microsoft.Win32.RegistryValueOptions]::None
    }
    $actual = $Key.GetValue($Name, $null, $options)
    if ($Kind -in @(
            [Microsoft.Win32.RegistryValueKind]::Binary,
            [Microsoft.Win32.RegistryValueKind]::None)) {
        if ([Convert]::ToBase64String([byte[]]$actual) -cne
            [Convert]::ToBase64String([byte[]]$Expected)) {
            throw "ARP binary registry value changed: $Name"
        }
        return
    }
    if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
        $actualValues = [string[]]$actual
        $expectedValues = [string[]]$Expected
        if ($actualValues.Count -ne $expectedValues.Count) {
            throw "ARP multi-string registry value changed: $Name"
        }
        for ($index = 0; $index -lt $actualValues.Count; $index++) {
            if ($actualValues[$index] -cne $expectedValues[$index]) {
                throw "ARP multi-string registry value changed: $Name"
            }
        }
        return
    }
    if ([string]$actual -cne [string]$Expected) {
        throw "ARP registry value changed: $Name"
    }
}

function Assert-PlatformArpFixture {
    $base = Open-Registry64Base
    try {
        $root = $base.OpenSubKey((Get-ArpSubKey -Product Platform), $false)
        if ($null -eq $root) { throw 'Platform ARP fixture was not restored.' }
        try {
            if ([string]::IsNullOrWhiteSpace($script:platformArpRootSddl) -or
                (Get-RegistrySddl -Key $root) -cne
                    $script:platformArpRootSddl) {
                throw 'Platform ARP root ACL was not restored exactly.'
            }
            Assert-RegistryValue -Key $root `
                -Name 'MineGuardTransactionTestOwner' -Kind String `
                -Expected $script:platformArpOwnershipToken
            Assert-RegistryValue -Key $root -Name '' `
                -Kind String -Expected 'fixture-default'
            Assert-RegistryValue -Key $root -Name 'DisplayName' `
                -Kind String -Expected 'MineGuard transaction fixture'
            Assert-RegistryValue -Key $root -Name 'Expandable' `
                -Kind ExpandString -Expected '%ProgramData%\MineGuardFixture'
            Assert-RegistryValue -Key $root -Name 'DwordValue' `
                -Kind DWord -Expected ([int]123456789)
            Assert-RegistryValue -Key $root -Name 'QwordValue' `
                -Kind QWord -Expected ([long]9876543210)
            Assert-RegistryValue -Key $root -Name 'MultiValue' `
                -Kind MultiString -Expected ([string[]]@('alpha', 'beta'))
            Assert-RegistryValue -Key $root -Name 'BinaryValue' `
                -Kind Binary -Expected ([byte[]]@(0, 1, 2, 127, 128, 255))
            Assert-RegistryValue -Key $root -Name 'NoneValue' `
                -Kind None -Expected ([byte[]]@(9, 8, 7, 0))
            $child = $root.OpenSubKey('Nested', $false)
            if ($null -eq $child) { throw 'Platform ARP child key was not restored.' }
            try {
                if ([string]::IsNullOrWhiteSpace(
                        $script:platformArpNestedSddl) -or
                    (Get-RegistrySddl -Key $child) -cne
                        $script:platformArpNestedSddl) {
                    throw 'Platform ARP nested ACL was not restored exactly.'
                }
                Assert-RegistryValue -Key $child -Name 'Channel' `
                    -Kind String -Expected 'fixture-old'
                $leaf = $child.OpenSubKey('Leaf', $false)
                if ($null -eq $leaf) {
                    throw 'Platform ARP nested leaf key was not restored.'
                }
                try {
                    if ([string]::IsNullOrWhiteSpace(
                            $script:platformArpLeafSddl) -or
                        (Get-RegistrySddl -Key $leaf) -cne
                            $script:platformArpLeafSddl) {
                        throw 'Platform ARP leaf ACL was not restored exactly.'
                    }
                    Assert-RegistryValue -Key $leaf -Name 'Depth' `
                        -Kind DWord -Expected ([int]2)
                } finally {
                    $leaf.Dispose()
                }
            } finally {
                $child.Dispose()
            }
        } finally {
            $root.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}

function Get-PlatformMockInstaller {
    return @'
[CmdletBinding()]
param(
    [string] $SourceDirectory,
    [string] $InstallRoot,
    [switch] $AllowUnsignedInternalRelease,
    [string] $ExpectedReleaseManifestSha256 = '',
    [string] $TrustedBootstrapTransactionId = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($TrustedBootstrapTransactionId -cnotmatch '^[a-f0-9]{32}$') {
    throw 'Mock Platform installer did not receive the transaction binding.'
}
foreach ($name in @(
        'runtime', 'service', 'launcher', 'release-metadata', 'docs',
        'uninstall-tools')) {
    $target = Join-Path $InstallRoot $name
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
$runtime = Join-Path $InstallRoot 'runtime'
$metadata = Join-Path $InstallRoot 'release-metadata'
$config = Join-Path $InstallRoot 'config'
New-Item -ItemType Directory -Path $runtime,$metadata,$config -Force |
    Out-Null
Copy-Item -LiteralPath (Join-Path $SourceDirectory `
    'runtime\MineGuardPlatform.exe') -Destination $runtime -Force
Copy-Item -LiteralPath (Join-Path $SourceDirectory `
    'release-manifest.json') -Destination $metadata -Force
$utf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList @($false, $true)
[IO.File]::WriteAllText(
    (Join-Path $runtime 'transaction-new.txt'), 'platform-new', $utf8)
[IO.File]::WriteAllText(
    (Join-Path $config 'settings.json'), '{"fixture":"new"}', $utf8)
'@
}

function Get-AgentMockInstaller {
    return @'
[CmdletBinding()]
param(
    [string] $SourceRoot,
    [string] $InstallRoot,
    [string] $StateRoot,
    [string] $ApprovedSignerThumbprint = '',
    [switch] $AllowUnsignedTestMedia,
    [switch] $AllowUnsignedInternalRelease,
    [string] $ExpectedReleaseManifestSha256 = '',
    [string] $TrustedBootstrapTransactionId = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($TrustedBootstrapTransactionId -cnotmatch '^[a-f0-9]{32}$') {
    throw 'Mock Agent installer did not receive the transaction binding.'
}
foreach ($name in @(
        'runtime', 'deploy', 'release-metadata', 'docs', 'uninstall-tools')) {
    $target = Join-Path $InstallRoot $name
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
$runtime = Join-Path $InstallRoot 'runtime'
$metadata = Join-Path $InstallRoot 'release-metadata'
New-Item -ItemType Directory -Path $runtime,$metadata -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $SourceRoot `
    'runtime\MineGuardEnterpriseAgent.exe') -Destination $runtime -Force
Copy-Item -LiteralPath (Join-Path $SourceRoot `
    'release-manifest.json') -Destination $metadata -Force
$utf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList @($false, $true)
[IO.File]::WriteAllText(
    (Join-Path $runtime 'transaction-new.txt'), 'agent-new', $utf8)
New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
$markerPath = Join-Path $StateRoot `
    '.mineguard-enterprise-agent-instances.json'
if (-not (Test-Path -LiteralPath $markerPath)) {
    $marker = [ordered]@{
        format = 'mineguard-enterprise-agent-state-root-v1'
        product = 'MineGuard Enterprise Agent'
        canonical_path = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
        root_id = [Guid]::ParseExact(
            $TrustedBootstrapTransactionId, 'N').ToString('D')
        created_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $bytes = $utf8.GetBytes(
        (($marker | ConvertTo-Json -Depth 3) + [Environment]::NewLine))
    $temporary = Join-Path $StateRoot (
        '.mineguard-enterprise-agent-instances.tmp-' +
        $TrustedBootstrapTransactionId)
    [IO.File]::WriteAllBytes($temporary, $bytes)
    Move-Item -LiteralPath $temporary -Destination $markerPath
}
'@
}

function New-MinimalReleaseFixture {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $Root
    )
    [void](New-Item -ItemType Directory -Path $Root -Force)
    $runtimeRelative = if ($Product -eq 'Platform') {
        'runtime/MineGuardPlatform.exe'
    } else {
        'runtime/MineGuardEnterpriseAgent.exe'
    }
    $installerRelative = if ($Product -eq 'Platform') {
        'deploy/windows/Install-MineGuardPlatform.ps1'
    } else {
        'deploy/windows/Install-EnterpriseAgent.ps1'
    }
    $productName = if ($Product -eq 'Platform') {
        'MineGuard Platform'
    } else {
        'MineGuard Enterprise Agent'
    }
    $runtimePath = Join-Path $Root $runtimeRelative.Replace('/', '\')
    $installerPath = Join-Path $Root $installerRelative.Replace('/', '\')
    [void](New-Item -ItemType Directory -Path `
        (Split-Path -Parent $runtimePath),(Split-Path -Parent $installerPath) `
        -Force)
    Write-Utf8NoBomText -Path $runtimePath `
        -Text ("minimal fixture executable for $Product`r`n")
    $installerText = if ($Product -eq 'Platform') {
        Get-PlatformMockInstaller
    } else {
        Get-AgentMockInstaller
    }
    Write-Utf8NoBomText -Path $installerPath `
        -Text ($installerText + [Environment]::NewLine)

    $entries = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Sort-Object FullName)) {
        $relative = Get-RelativeTestPath -Root $Root `
            -FullName $file.FullName
        $entries += [ordered]@{
            path = $relative
            bytes = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        product = $productName
        entryPoint = $runtimeRelative
        files = $entries
    }
    $manifestPath = Join-Path $Root 'release-manifest.json'
    Write-Utf8NoBomText -Path $manifestPath -Text (
        ($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine)

    $sumLines = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Sort-Object FullName)) {
        $relative = Get-RelativeTestPath -Root $Root `
            -FullName $file.FullName
        $digest = (Get-FileHash -LiteralPath $file.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        $sumLines += $digest + '  ' + $relative
    }
    [IO.File]::WriteAllLines(
        (Join-Path $Root 'SHA256SUMS.txt'),
        [string[]]$sumLines,
        $script:utf8NoBom)
    return (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-TrustedBootstrapAction {
    param(
        [ValidateSet('Begin', 'Prepare', 'Commit', 'Rollback', 'Finalize')]
        [string] $Action,
        [Parameter(Mandatory = $true)] [string] $TransactionId,
        [Parameter(Mandatory = $true)] [hashtable] $Context
    )
    $actualHash = (Get-FileHash -LiteralPath $BootstrapPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $script:bootstrapSha256) {
        throw 'Trusted bootstrap changed while its transaction test was running.'
    }
    $bytes = [IO.File]::ReadAllBytes($BootstrapPath)
    $offset = if ($bytes.Length -ge 3 -and
        $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and
        $bytes[2] -eq 0xBF) { 3 } else { 0 }
    $text = $script:utf8NoBom.GetString(
        $bytes, $offset, $bytes.Length - $offset)
    $bootstrapBlock = [ScriptBlock]::Create($text)
    $parameters = @{
        TransactionAction = $Action
        TransactionId = $TransactionId
    }
    foreach ($entry in $Context.GetEnumerator()) {
        $parameters[[string]$entry.Key] = $entry.Value
    }
    & $bootstrapBlock @parameters | Out-Host
}

function Get-TransactionPath {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $InstallRoot,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )
    $prefix = if ($Product -eq 'Platform') {
        '.mineguard-platform-inno-transaction-'
    } else {
        '.mineguard-agent-inno-transaction-'
    }
    return Join-Path (Split-Path -Parent $InstallRoot) `
        ($prefix + $TransactionId)
}

function Assert-TransactionAbsent {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $InstallRoot,
        [Parameter(Mandatory = $true)] [string] $TransactionId
    )
    $path = Get-TransactionPath -Product $Product `
        -InstallRoot $InstallRoot -TransactionId $TransactionId
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $path)) `
        -Message "Installer transaction leaked: $path"
}

function Get-PathSddl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($sections)
}

function Test-PlatformUpgradeRecovery {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $Fixture,
        [Parameter(Mandatory = $true)] [string] $ManifestHash,
        [Parameter(Mandatory = $true)] [string] $ShortcutGroup,
        [Parameter(Mandatory = $true)] [string] $GroupShortcut,
        [Parameter(Mandatory = $true)] [string] $DesktopShortcut,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]] $CreatedShortcutPaths,
        [Parameter(Mandatory = $true)] [ref] $ShortcutGroupOwned
    )
    $scenario = Join-Path $Root 'platform-upgrade-recovery'
    $installRoot = Join-Path $scenario 'installed'
    foreach ($directory in @(
            $scenario,
            (Join-Path $installRoot 'runtime\nested'),
            (Join-Path $installRoot 'service'),
            (Join-Path $installRoot 'config'),
            (Join-Path $installRoot 'state'),
            (Join-Path $installRoot 'docs'))) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    Write-Utf8NoBomText -Path (Join-Path $installRoot `
        'runtime\nested\old-runtime.txt') -Text 'runtime-old'
    Write-Utf8NoBomText -Path (Join-Path $installRoot `
        'service\old-service.txt') -Text 'service-old'
    Write-Utf8NoBomText -Path (Join-Path $installRoot `
        'docs\old-doc.txt') -Text 'docs-old'
    Write-Utf8NoBomText -Path (Join-Path $installRoot `
        'config\settings.json') -Text '{"fixture":"old"}'
    Write-Utf8NoBomText -Path (Join-Path $installRoot `
        'state\business-data.txt') -Text 'business-state-old'
    Write-Utf8NoBomText -Path (Join-Path $installRoot 'unins000.dat') `
        -Text 'uninstaller-old'

    $context = @{
        Product = 'Platform'
        SourceRoot = $Fixture
        ExpectedReleaseManifestSha256 = $ManifestHash
        InstallRoot = $installRoot
        WrapperInstallRootPreexisted = '1'
        WrapperShortcutGroupPreexisted = '0'
    }
    $firstId = [Guid]::NewGuid().ToString('N')
    $secondId = [Guid]::NewGuid().ToString('N')
    Invoke-TrustedBootstrapAction -Action Begin `
        -TransactionId $firstId -Context $context
    Invoke-TrustedBootstrapAction -Action Prepare `
        -TransactionId $firstId -Context $context
    Invoke-TrustedBootstrapAction -Action Commit `
        -TransactionId $firstId -Context $context

    Remove-Item -LiteralPath (Join-Path $installRoot 'unins000.dat') -Force
    Write-Utf8NoBomText -Path (Join-Path $installRoot 'unins123.dat') `
        -Text 'uninstaller-new'
    Set-ChangedPlatformArpFixture

    # These paths are global product identities. Recheck immediately before
    # the first write so a concurrently-created real shortcut is never
    # overwritten or later mistaken for test-owned cleanup.
    foreach ($shortcut in @($GroupShortcut, $DesktopShortcut)) {
        if (Test-Path -LiteralPath $shortcut) {
            throw "Refusing to overwrite a shortcut created during the test: $shortcut"
        }
    }
    if (Test-Path -LiteralPath $ShortcutGroup) {
        throw 'Refusing to reuse a MineGuard shortcut group created during the test.'
    }
    [void](New-Item -ItemType Directory -Path $ShortcutGroup `
        -ErrorAction Stop)
    $ShortcutGroupOwned.Value = $true
    foreach ($shortcut in @($GroupShortcut, $DesktopShortcut)) {
        Write-NewOwnedUtf8NoBomText -Path $shortcut `
            -Text 'test-only-shortcut' -OwnedPaths $CreatedShortcutPaths
    }

    # A new Begin must first roll back the unconfirmed prior commit, then
    # capture a new clean transaction from the restored product.
    Invoke-TrustedBootstrapAction -Action Begin `
        -TransactionId $secondId -Context $context
    Assert-TransactionAbsent -Product Platform `
        -InstallRoot $installRoot -TransactionId $firstId
    Assert-Condition -Condition (Test-Path -LiteralPath (Join-Path `
        $installRoot 'runtime\nested\old-runtime.txt') -PathType Leaf) `
        -Message 'Platform stale recovery did not restore the old runtime.'
    Assert-Condition -Condition ((Get-Content -LiteralPath (Join-Path `
        $installRoot 'config\settings.json') -Raw -Encoding UTF8) -ceq
        '{"fixture":"old"}') `
        -Message 'Platform stale recovery did not restore settings.json.'
    Assert-Condition -Condition ((Get-Content -LiteralPath (Join-Path `
        $installRoot 'state\business-data.txt') -Raw -Encoding UTF8) -ceq
        'business-state-old') `
        -Message 'Platform stale recovery changed business state.'
    Assert-Condition -Condition (Test-Path -LiteralPath (Join-Path `
        $installRoot 'unins000.dat') -PathType Leaf) `
        -Message 'Platform stale recovery did not restore the old uninstaller.'
    Assert-Condition -Condition (-not (Test-Path -LiteralPath (Join-Path `
        $installRoot 'unins123.dat'))) `
        -Message 'Platform stale recovery retained the replacement uninstaller.'
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $GroupShortcut)) `
        -Message 'Platform stale recovery retained a group shortcut.'
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $DesktopShortcut)) `
        -Message 'Platform stale recovery retained a desktop shortcut.'
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $ShortcutGroup)) `
        -Message 'Platform stale recovery retained its new shortcut group.'
    # The rollback above proved that every test-created global shortcut and
    # its group are absent. Relinquish cleanup ownership now so a real
    # installer that runs later cannot have its new files removed in finally.
    $CreatedShortcutPaths.Clear()
    $ShortcutGroupOwned.Value = $false
    Assert-PlatformArpFixture

    Invoke-TrustedBootstrapAction -Action Rollback `
        -TransactionId $secondId -Context $context
    Assert-TransactionAbsent -Product Platform `
        -InstallRoot $installRoot -TransactionId $secondId
    Assert-PlatformArpFixture
    Write-Host 'Platform upgrade, stale recovery and rollback passed.'
}

function Test-PlatformFreshFinalize {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $Fixture,
        [Parameter(Mandatory = $true)] [string] $ManifestHash
    )
    $scenario = Join-Path $Root 'platform-fresh-finalize'
    $installRoot = Join-Path $scenario 'installed'
    [void](New-Item -ItemType Directory -Path $installRoot -Force)
    $context = @{
        Product = 'Platform'
        SourceRoot = $Fixture
        ExpectedReleaseManifestSha256 = $ManifestHash
        InstallRoot = $installRoot
        WrapperInstallRootPreexisted = '0'
        WrapperShortcutGroupPreexisted = '0'
    }
    $transactionId = [Guid]::NewGuid().ToString('N')
    foreach ($action in @('Begin', 'Prepare', 'Commit', 'Finalize')) {
        Invoke-TrustedBootstrapAction -Action $action `
            -TransactionId $transactionId -Context $context
    }
    $activeManifest = Join-Path $installRoot `
        'release-metadata\release-manifest.json'
    Assert-Condition -Condition (Test-Path -LiteralPath $activeManifest `
        -PathType Leaf) -Message 'Finalized Platform has no active manifest.'
    $actualHash = (Get-FileHash -LiteralPath $activeManifest `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Condition -Condition ($actualHash -ceq $ManifestHash) `
        -Message 'Finalized Platform manifest does not match its fixture.'
    Assert-TransactionAbsent -Product Platform `
        -InstallRoot $installRoot -TransactionId $transactionId
    Write-Host 'Platform fresh commit and finalize passed.'
}

function Test-AgentMissingStateRollback {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $Fixture,
        [Parameter(Mandatory = $true)] [string] $ManifestHash
    )
    $scenario = Join-Path $Root 'agent-missing-state-rollback'
    $installRoot = Join-Path $scenario 'installed'
    $missingTop = Join-Path $scenario 'missing-a'
    $stateRoot = Join-Path $missingTop 'missing-b\instances'
    [void](New-Item -ItemType Directory -Path $installRoot -Force)
    $context = @{
        Product = 'EnterpriseAgent'
        SourceRoot = $Fixture
        ExpectedReleaseManifestSha256 = $ManifestHash
        InstallRoot = $installRoot
        StateRoot = $stateRoot
        AllowUnsignedTestMedia = $true
        WrapperInstallRootPreexisted = '0'
        WrapperShortcutGroupPreexisted = '0'
    }
    $transactionId = [Guid]::NewGuid().ToString('N')
    foreach ($action in @('Begin', 'Prepare', 'Commit')) {
        Invoke-TrustedBootstrapAction -Action $action `
            -TransactionId $transactionId -Context $context
    }
    $markerPath = Join-Path $stateRoot `
        '.mineguard-enterprise-agent-instances.json'
    Assert-Condition -Condition (Test-Path -LiteralPath $markerPath `
        -PathType Leaf) -Message 'Mock Agent did not create its StateRoot marker.'
    $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $expectedRootId = [Guid]::ParseExact(
        $transactionId, 'N').ToString('D')
    Assert-Condition -Condition ([string]$marker.root_id -ceq $expectedRootId) `
        -Message 'Mock Agent StateRoot marker is not transaction-bound.'

    Invoke-TrustedBootstrapAction -Action Rollback `
        -TransactionId $transactionId -Context $context
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $installRoot)) `
        -Message 'Agent rollback retained its transaction-created InstallRoot.'
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $missingTop)) `
        -Message 'Agent rollback retained transaction-created StateRoot ancestors.'
    Assert-TransactionAbsent -Product EnterpriseAgent `
        -InstallRoot $installRoot -TransactionId $transactionId
    Assert-Condition -Condition (-not (
        Test-ArpRegistrationExists -Product EnterpriseAgent)) `
        -Message 'Agent rollback left an ARP registration.'
    Write-Host 'Agent missing StateRoot commit and rollback passed.'
}

function Test-AgentExistingStateRollback {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $Fixture,
        [Parameter(Mandatory = $true)] [string] $ManifestHash
    )
    $scenario = Join-Path $Root 'agent-existing-state-rollback'
    $installRoot = Join-Path $scenario 'installed'
    $stateRoot = Join-Path $scenario 'business-state'
    [void](New-Item -ItemType Directory -Path $installRoot,$stateRoot -Force)
    $markerPath = Join-Path $stateRoot `
        '.mineguard-enterprise-agent-instances.json'
    $businessPath = Join-Path $stateRoot 'business-records.db'
    Write-Utf8NoBomText -Path $markerPath -Text '{"owner":"existing"}'
    Write-Utf8NoBomText -Path $businessPath -Text 'business-data-must-survive'
    $markerHash = (Get-FileHash -LiteralPath $markerPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $stateSddl = Get-PathSddl -Path $stateRoot
    $context = @{
        Product = 'EnterpriseAgent'
        SourceRoot = $Fixture
        ExpectedReleaseManifestSha256 = $ManifestHash
        InstallRoot = $installRoot
        StateRoot = $stateRoot
        AllowUnsignedTestMedia = $true
        WrapperInstallRootPreexisted = '1'
        WrapperShortcutGroupPreexisted = '0'
    }
    $transactionId = [Guid]::NewGuid().ToString('N')
    Invoke-TrustedBootstrapAction -Action Begin `
        -TransactionId $transactionId -Context $context
    Invoke-TrustedBootstrapAction -Action Rollback `
        -TransactionId $transactionId -Context $context
    $actualMarkerHash = (Get-FileHash -LiteralPath $markerPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Condition -Condition ($actualMarkerHash -ceq $markerHash) `
        -Message 'Agent rollback changed the existing StateRoot marker.'
    Assert-Condition -Condition ((Get-Content -LiteralPath $businessPath `
        -Raw -Encoding UTF8) -ceq 'business-data-must-survive') `
        -Message 'Agent rollback changed existing business data.'
    Assert-Condition -Condition ((Get-PathSddl -Path $stateRoot) -ceq `
        $stateSddl) -Message 'Agent rollback changed the existing StateRoot ACL.'
    Assert-Condition -Condition (Test-Path -LiteralPath $installRoot `
        -PathType Container) -Message 'Agent rollback removed a pre-existing root.'
    Assert-TransactionAbsent -Product EnterpriseAgent `
        -InstallRoot $installRoot -TransactionId $transactionId
    Write-Host 'Agent existing StateRoot rollback passed.'
}

function Test-PrepareFailureRollback {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $Fixture
    )
    $scenario = Join-Path $Root 'prepare-failure-rollback'
    $installRoot = Join-Path $scenario 'installed'
    [void](New-Item -ItemType Directory -Path $installRoot -Force)
    $context = @{
        Product = 'Platform'
        SourceRoot = $Fixture
        ExpectedReleaseManifestSha256 = ('0' * 64)
        InstallRoot = $installRoot
        WrapperInstallRootPreexisted = '0'
        WrapperShortcutGroupPreexisted = '0'
    }
    $transactionId = [Guid]::NewGuid().ToString('N')
    Invoke-TrustedBootstrapAction -Action Begin `
        -TransactionId $transactionId -Context $context
    $expectedFailureObserved = $false
    try {
        Invoke-TrustedBootstrapAction -Action Prepare `
            -TransactionId $transactionId -Context $context
    } catch {
        if ($_.Exception.Message -notmatch 'trusted Setup anchor') { throw }
        $expectedFailureObserved = $true
    }
    Assert-Condition -Condition $expectedFailureObserved `
        -Message 'Prepare accepted a deliberately incorrect manifest anchor.'
    Invoke-TrustedBootstrapAction -Action Rollback `
        -TransactionId $transactionId -Context $context
    Assert-Condition -Condition (-not (Test-Path -LiteralPath $installRoot)) `
        -Message 'Prepare failure rollback retained a fresh InstallRoot.'
    Assert-TransactionAbsent -Product Platform `
        -InstallRoot $installRoot -TransactionId $transactionId
    Write-Host 'Prepare trust failure and rollback passed.'
}

$commonData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData)
$commonPrograms = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonPrograms)
$commonDesktop = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonDesktopDirectory)
$shortcutGroup = Join-Path $commonPrograms 'MineGuard'
$platformGroupShortcut = Join-Path $shortcutGroup `
    'MineGuard Platform 控制中心.lnk'
$platformDesktopShortcut = Join-Path $commonDesktop `
    'MineGuard Platform 控制中心.lnk'
$fixedShortcutPaths = @(
    $platformGroupShortcut,
    (Join-Path $shortcutGroup 'MineGuard 企业接入包与注册向导.lnk'),
    (Join-Path $shortcutGroup 'MineGuard Platform 使用与部署说明.lnk'),
    (Join-Path $shortcutGroup 'MineGuard 企业接入配置向导.lnk'),
    (Join-Path $shortcutGroup 'MineGuard 模型授权导入向导.lnk'),
    (Join-Path $shortcutGroup 'MineGuard 企业端使用说明.lnk'),
    $platformDesktopShortcut
)

# These are global product identities, unlike the random test root. Refuse to
# mutate any of them when the machine may contain a real MineGuard install.
foreach ($product in @('Platform', 'EnterpriseAgent')) {
    if (Test-ArpRegistrationExists -Product $product) {
        throw "Refusing transaction tests because real $product ARP data exists."
    }
}
if (Test-Path -LiteralPath $shortcutGroup) {
    throw 'Refusing transaction tests because the MineGuard shortcut group exists.'
}
foreach ($shortcut in $fixedShortcutPaths) {
    if (Test-Path -LiteralPath $shortcut) {
        throw "Refusing transaction tests because a real shortcut exists: $shortcut"
    }
}

$testRoot = Join-Path $commonData (
    'MineGuardTrustedBootstrapTest-' + [Guid]::NewGuid().ToString('N'))
$testRootOwned = $true
$platformArpOwned = $false
$shortcutGroupOwned = $false
$createdShortcutPaths = [System.Collections.Generic.List[string]]::new()
$testFailure = $null
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
try {
    $testRoot = New-SecureVerificationRoot -Path $testRoot
    $fixtureRoot = Join-Path $testRoot 'fixtures'
    $platformFixture = Join-Path $fixtureRoot 'platform'
    $agentFixture = Join-Path $fixtureRoot 'agent'
    $platformManifestHash = New-MinimalReleaseFixture `
        -Product Platform -Root $platformFixture
    $agentManifestHash = New-MinimalReleaseFixture `
        -Product EnterpriseAgent -Root $agentFixture

    New-PlatformArpFixture
    $platformArpOwned = $true
    Test-PlatformUpgradeRecovery -Root $testRoot `
        -Fixture $platformFixture -ManifestHash $platformManifestHash `
        -ShortcutGroup $shortcutGroup `
        -GroupShortcut $platformGroupShortcut `
        -DesktopShortcut $platformDesktopShortcut `
        -CreatedShortcutPaths $createdShortcutPaths `
        -ShortcutGroupOwned ([ref]$shortcutGroupOwned)
    Remove-TestOwnedPlatformArpRegistration
    $platformArpOwned = $false
    Assert-Condition -Condition (-not (
        Test-ArpRegistrationExists -Product Platform)) `
        -Message 'Platform test ARP cleanup did not complete.'

    Test-PlatformFreshFinalize -Root $testRoot `
        -Fixture $platformFixture -ManifestHash $platformManifestHash
    Test-AgentMissingStateRollback -Root $testRoot `
        -Fixture $agentFixture -ManifestHash $agentManifestHash
    Test-AgentExistingStateRollback -Root $testRoot `
        -Fixture $agentFixture -ManifestHash $agentManifestHash
    Test-PrepareFailureRollback -Root $testRoot -Fixture $platformFixture
} catch {
    $testFailure = $_
} finally {
    if ($platformArpOwned) {
        try {
            Remove-TestOwnedPlatformArpRegistration
        } catch {
            $cleanupFailures.Add(
                'Platform ARP cleanup: ' + $_.Exception.Message)
        }
    }
    foreach ($shortcut in $createdShortcutPaths.ToArray()) {
        try {
            if ($fixedShortcutPaths -cnotcontains $shortcut) {
                throw "Refusing unexpected shortcut cleanup target: $shortcut"
            }
            if (Test-Path -LiteralPath $shortcut) {
                $item = Get-Item -LiteralPath $shortcut -Force
                if ($item.PSIsContainer -or
                    ($item.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Shortcut cleanup target changed type: $shortcut"
                }
                $expectedBytes = $script:utf8NoBom.GetBytes(
                    'test-only-shortcut')
                $actualBytes = [IO.File]::ReadAllBytes($shortcut)
                if ([Convert]::ToBase64String($actualBytes) -cne
                    [Convert]::ToBase64String($expectedBytes)) {
                    throw "Shortcut cleanup target is no longer test-owned: $shortcut"
                }
                Remove-Item -LiteralPath $shortcut -Force
            }
        } catch {
            $cleanupFailures.Add(
                "Fixed shortcut cleanup ($shortcut): " + $_.Exception.Message)
        }
    }
    if ($shortcutGroupOwned -and (Test-Path -LiteralPath $shortcutGroup)) {
        try {
            $groupItem = Get-Item -LiteralPath $shortcutGroup -Force
            if (-not $groupItem.PSIsContainer -or
                ($groupItem.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                @(Get-ChildItem -LiteralPath $shortcutGroup -Force).Count -ne 0) {
                throw 'Owned shortcut group contains an unexpected object.'
            }
            Remove-Item -LiteralPath $shortcutGroup -Force
        } catch {
            $cleanupFailures.Add(
                'Shortcut-group cleanup: ' + $_.Exception.Message)
        }
    }
    if ($testRootOwned) {
        try {
            Remove-SafeVerificationRoot -Path $testRoot `
                -ExpectedParent $commonData
        } catch {
            $cleanupFailures.Add(
                'Verification-root cleanup: ' + $_.Exception.Message)
        }
    }
}

$cleanupMessages = $cleanupFailures.ToArray()
if ($null -ne $testFailure) {
    $testFailureDiagnostic = Format-TestFailure -ErrorRecord $testFailure
    if ($cleanupMessages.Count -gt 0) {
        throw (
            $testFailureDiagnostic + [Environment]::NewLine +
            'Cleanup failures: ' + ($cleanupMessages -join '; '))
    }
    throw $testFailureDiagnostic
}
if ($cleanupMessages.Count -gt 0) {
    throw ('Transaction tests passed but cleanup failed: ' +
        ($cleanupMessages -join '; '))
}
Write-Host 'Trusted bootstrap PowerShell 5.1 transaction verification passed.'
