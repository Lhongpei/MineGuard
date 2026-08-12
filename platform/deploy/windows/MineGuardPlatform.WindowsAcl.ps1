[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-MineGuardPlatformAclServiceSid {
    return New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346'
    )
}

function Test-MineGuardPlatformAclRightsEqual {
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $Actual,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $Expected
    )
    $withSynchronize = $Expected -bor `
        [Security.AccessControl.FileSystemRights]::Synchronize
    return $Actual -eq $Expected -or $Actual -eq $withSynchronize
}

function New-MineGuardPlatformAclRule {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Principal.SecurityIdentifier] $Sid,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $Rights,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.InheritanceFlags] $Inheritance
    )
    return New-Object Security.AccessControl.FileSystemAccessRule(
        $Sid,
        $Rights,
        $Inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
}

function Assert-MineGuardPlatformCanonicalAcl {
    param(
        [Parameter(Mandatory = $true)] [IO.FileSystemInfo] $Item,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $ServiceRights
    )
    $administrators = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-544'
    )
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $service = Get-MineGuardPlatformAclServiceSid
    $security = if ($Item.PSIsContainer) {
        [IO.Directory]::GetAccessControl($Item.FullName)
    } else {
        [IO.File]::GetAccessControl($Item.FullName)
    }
    $inheritance = if ($Item.PSIsContainer) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $owner = $security.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $rules = @($security.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier]
        ))
    $expected = @{}
    $expected[$system.Value] = `
        [Security.AccessControl.FileSystemRights]::FullControl
    $expected[$administrators.Value] = `
        [Security.AccessControl.FileSystemRights]::FullControl
    $expected[$service.Value] = $ServiceRights
    if (-not $security.AreAccessRulesProtected -or
        -not $security.AreAccessRulesCanonical -or
        $owner -ne $administrators.Value -or
        $rules.Count -ne $expected.Count) {
        throw "ACL is not an exact protected MineGuard DACL: $($Item.FullName)"
    }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid) -or
            $seen.ContainsKey($sid) -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or
            -not (Test-MineGuardPlatformAclRightsEqual `
                -Actual $rule.FileSystemRights -Expected $expected[$sid]) -or
            $rule.InheritanceFlags -ne $inheritance -or
            $rule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None) {
            throw "ACL contains a noncanonical MineGuard rule: $($Item.FullName)"
        }
        $seen[$sid] = $true
    }
    foreach ($sid in $expected.Keys) {
        if (-not $seen.ContainsKey($sid)) {
            throw "ACL is missing a required MineGuard trustee: $($Item.FullName)"
        }
    }
}

function Set-MineGuardPlatformCanonicalAcl {
    param(
        [Parameter(Mandatory = $true)] [IO.FileSystemInfo] $Item,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights] $ServiceRights
    )
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "ACL target cannot be a reparse point: $($Item.FullName)"
    }
    $administrators = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-544'
    )
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    # A service SID is a valid NTFS trustee before the service is registered.
    # Passing SecurityIdentifier writes the numeric SID without LSA name lookup.
    $service = Get-MineGuardPlatformAclServiceSid
    $security = if ($Item.PSIsContainer) {
        New-Object Security.AccessControl.DirectorySecurity
    } else {
        New-Object Security.AccessControl.FileSecurity
    }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administrators)
    $inheritance = if ($Item.PSIsContainer) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($definition in @(
            [pscustomobject]@{
                Sid = $system
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            [pscustomobject]@{
                Sid = $administrators
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            [pscustomobject]@{ Sid = $service; Rights = $ServiceRights }
        )) {
        [void]$security.AddAccessRule((New-MineGuardPlatformAclRule `
            -Sid $definition.Sid -Rights $definition.Rights `
            -Inheritance $inheritance))
    }
    if ($Item.PSIsContainer) {
        [IO.Directory]::SetAccessControl($Item.FullName, $security)
    } else {
        [IO.File]::SetAccessControl($Item.FullName, $security)
    }
    Assert-MineGuardPlatformCanonicalAcl -Item $Item `
        -ServiceRights $ServiceRights
}

function Set-MineGuardPlatformCanonicalTreeAcl {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('RX', 'M')] [string] $ServicePermission
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "ACL tree does not exist: $Path"
    }
    $serviceRights = if ($ServicePermission -eq 'RX') {
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    } else {
        [Security.AccessControl.FileSystemRights]::Modify
    }

    # Resolve and validate the complete target tree before the first mutation.
    # A queue is used instead of -Recurse so no junction is entered first.
    $root = Get-Item -LiteralPath $Path -Force
    $items = @($root)
    $pending = New-Object System.Collections.Queue
    $pending.Enqueue($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        if (($directory.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "ACL tree contains a reparse point: $($directory.FullName)"
        }
        foreach ($child in Get-ChildItem -LiteralPath $directory.FullName -Force) {
            if (($child.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "ACL tree contains a reparse point: $($child.FullName)"
            }
            $items += $child
            if ($items.Count -gt 100000) {
                throw 'ACL tree exceeds the 100000 object safety limit.'
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child) }
        }
    }
    foreach ($item in $items) {
        Set-MineGuardPlatformCanonicalAcl -Item $item `
            -ServiceRights $serviceRights
    }
}

function Set-MineGuardPlatformServiceReadableFileAcl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "ACL file does not exist: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    Set-MineGuardPlatformCanonicalAcl -Item $item `
        -ServiceRights ([Security.AccessControl.FileSystemRights]::Read)
}

function Grant-MineGuardPlatformBootstrapPasswordDeleteAcl {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Bootstrap password file cannot be a reparse point: $Path"
    }
    $readAndExecute = `
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    Assert-MineGuardPlatformCanonicalAcl -Item $item `
        -ServiceRights $readAndExecute

    $service = Get-MineGuardPlatformAclServiceSid
    $security = [IO.File]::GetAccessControl($Path)
    $serviceRules = @($security.GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]
        ) | Where-Object {
            $_.IdentityReference.Value -eq $service.Value
        })
    foreach ($rule in $serviceRules) {
        [void]$security.RemoveAccessRuleSpecific($rule)
    }
    $serviceRights = [Security.AccessControl.FileSystemRights]::Read -bor `
        [Security.AccessControl.FileSystemRights]::Delete
    [void]$security.AddAccessRule((New-MineGuardPlatformAclRule `
        -Sid $service -Rights $serviceRights `
        -Inheritance ([Security.AccessControl.InheritanceFlags]::None)))
    [IO.File]::SetAccessControl($Path, $security)
    Assert-MineGuardPlatformCanonicalAcl -Item $item `
        -ServiceRights $serviceRights
}
