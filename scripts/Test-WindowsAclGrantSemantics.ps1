[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The NTFS ACL grant test must run on Windows."
}

$WindowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($WindowsIdentity)
if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw "The NTFS ACL grant test requires an elevated Administrator token."
}
$CurrentUserSid = $WindowsIdentity.User.Value
if ($CurrentUserSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$') {
    throw "The current Windows user SID has an unexpected format."
}
$MineGuardPlatformServiceSid = `
    "S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346"
if ($null -ne (Get-Service -Name "MineGuardPlatform" `
        -ErrorAction SilentlyContinue)) {
    throw (
        "The raw service-SID probe requires MineGuardPlatform to remain " +
        "unregistered."
    )
}
$PlatformAclHelper = Join-Path (Split-Path -Parent $PSScriptRoot) `
    "platform\deploy\windows\MineGuardPlatform.WindowsAcl.ps1"
if (-not (Test-Path -LiteralPath $PlatformAclHelper -PathType Leaf)) {
    throw "The production Platform ACL helper is missing: $PlatformAclHelper"
}
. $PlatformAclHelper
if ((Get-MineGuardPlatformAclServiceSid).Value -ne `
        $MineGuardPlatformServiceSid) {
    throw "The production Platform ACL helper uses an unexpected service SID."
}
$AgentSafetyHelper = Join-Path (Split-Path -Parent $PSScriptRoot) `
    "agent\deploy\windows\EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $AgentSafetyHelper -PathType Leaf)) {
    throw "The production Enterprise Agent ACL helper is missing: $AgentSafetyHelper"
}
. $AgentSafetyHelper

# Windows PowerShell 5.1 exposes PSObject.Properties as an enumerable
# collection without a Count property under StrictMode. Exercise the real
# shared JSON reader so provisioning cannot regress to direct .Count access.
$JsonProbeRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ("MineGuard-PS51-JsonProbe-" + [Guid]::NewGuid().ToString("N"))
$ValidJsonPath = Join-Path $JsonProbeRoot "valid.json"
$EmptyJsonPath = Join-Path $JsonProbeRoot "empty.json"
try {
    [void](New-Item -ItemType Directory -Path $JsonProbeRoot)
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($ValidJsonPath, '{"format":"probe"}', $Utf8NoBom)
    [IO.File]::WriteAllText($EmptyJsonPath, '{}', $Utf8NoBom)

    $ValidJson = Read-EAJsonFile -Path $ValidJsonPath -Name "PS51 JSON probe"
    if ([string](Get-EARequiredProperty -Object $ValidJson -Name "format" `
            -Context "PS51 JSON probe") -ne "probe") {
        throw "The Windows PowerShell 5.1 JSON object probe returned bad data."
    }

    $EmptyObjectRejected = $false
    try {
        [void](Read-EAJsonFile -Path $EmptyJsonPath -Name "Empty JSON probe")
    }
    catch {
        if ($_.Exception.Message -notlike `
            "Empty JSON probe must contain one JSON object:*") {
            throw
        }
        $EmptyObjectRejected = $true
    }
    if (-not $EmptyObjectRejected) {
        throw "The Windows PowerShell 5.1 JSON reader accepted an empty object."
    }
}
finally {
    if (Test-Path -LiteralPath $JsonProbeRoot) {
        Remove-Item -LiteralPath $JsonProbeRoot -Recurse -Force
    }
}
Write-Host "MineGuard PowerShell 5.1 JSON collection semantics passed."

# FileSystemRights.Write and Modify are composite enums whose numeric values
# overlap ReadAndExecute. Security filters must use only atomic mutation bits.
$MutationRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
foreach ($ReadOnlyRights in @(
        [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    )) {
    if (($ReadOnlyRights -band $MutationRights) -ne 0) {
        throw "The ACL mutation mask overlaps a read-only permission."
    }
}
foreach ($WritableRights in @(
        [Security.AccessControl.FileSystemRights]::Write,
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.FileSystemRights]::FullControl
    )) {
    if (($WritableRights -band $MutationRights) -eq 0) {
        throw "The ACL mutation mask misses a writable permission."
    }
}
Write-Host "MineGuard ACL mutation-mask semantics passed."

function Invoke-IcaclsChecked {
    param([object[]]$ArgumentList, [string]$Label)
    & "$env:SystemRoot\System32\icacls.exe" @ArgumentList | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Assert-AclContract {
    param(
        [string]$Path,
        [bool]$ExpectProtected,
        [bool]$ExpectInherited
    )
    $Acl = Get-Acl -LiteralPath $Path
    if ($Acl.AreAccessRulesProtected -ne $ExpectProtected) {
        throw "ACL inheritance protection is incorrect: $Path"
    }
    if (-not $Acl.AreAccessRulesCanonical) {
        throw "ACL rule order is not canonical: $Path"
    }
    $ExpectedSids = @("S-1-5-18", "S-1-5-32-544", "S-1-5-19")
    $Seen = @{}
    foreach ($Rule in $Acl.Access) {
        if ($Rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow) {
            throw "ACL contains a deny rule: $Path"
        }
        $Sid = try {
            $Rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            [string]$Rule.IdentityReference
        }
        if ($ExpectedSids -notcontains $Sid) {
            throw "ACL contains an unexpected trustee $Sid at $Path"
        }
        if ($Seen.ContainsKey($Sid)) {
            throw "ACL contains duplicate rules for trustee $Sid at $Path"
        }
        if ($Rule.IsInherited -ne $ExpectInherited) {
            throw "ACL rule inheritance origin is incorrect for $Sid at $Path"
        }
        $ExpectedRights = if ($Sid -eq "S-1-5-19") {
            [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                [Security.AccessControl.FileSystemRights]::Synchronize
        }
        else {
            [Security.AccessControl.FileSystemRights]::FullControl
        }
        if ($Rule.FileSystemRights -ne $ExpectedRights) {
            throw "ACL rights are incorrect for $Sid at $Path"
        }
        if ($ExpectProtected) {
            $ExpectedFlags =
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            if ($Rule.InheritanceFlags -ne $ExpectedFlags -or
                $Rule.PropagationFlags -ne
                    [Security.AccessControl.PropagationFlags]::None) {
                throw "ACL propagation is incorrect for $Sid at $Path"
            }
        }
        $Seen[$Sid] = $true
    }
    foreach ($RequiredSid in $ExpectedSids) {
        if (-not $Seen.ContainsKey($RequiredSid)) {
            throw "ACL is missing trustee $RequiredSid at $Path"
        }
    }
}

function Assert-ExplicitRawSidRule {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights]$Rights,
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.InheritanceFlags]$Inheritance
    )
    $Item = Get-Item -LiteralPath $Path -Force
    $Security = if ($Item.PSIsContainer) {
        [IO.Directory]::GetAccessControl($Item.FullName)
    } else {
        [IO.File]::GetAccessControl($Item.FullName)
    }
    $Rules = @($Security.GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]
        ) | Where-Object { $_.IdentityReference.Value -eq $Sid })
    $RightsWithSynchronize = $Rights -bor `
        [Security.AccessControl.FileSystemRights]::Synchronize
    if ($Rules.Count -ne 1 -or
        $Rules[0].AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
        ($Rules[0].FileSystemRights -ne $Rights -and
            $Rules[0].FileSystemRights -ne $RightsWithSynchronize) -or
        $Rules[0].InheritanceFlags -ne $Inheritance -or
        $Rules[0].PropagationFlags -ne
            [Security.AccessControl.PropagationFlags]::None) {
        throw "Raw SID ACL rule is missing or inexact for $Sid at $Path"
    }
}

$ProbeParent = Join-Path $env:RUNNER_TEMP "mineguard-acl-grant"
$ProbeRoot = Join-Path $ProbeParent ([Guid]::NewGuid().ToString("N"))
$ChildRoot = Join-Path $ProbeRoot "child"
$EmptyChild = Join-Path $ProbeRoot "empty-child"
$EmptyTree = Join-Path $ProbeRoot "standalone-empty-tree"
$RawConfigTree = Join-Path $ProbeRoot "raw-service-sid-config"
$RawStateTree = Join-Path $ProbeRoot "raw-service-sid-state"
$RawIntegrityFile = Join-Path $ProbeRoot "winsw-integrity.json"
$AgentRoot = Join-Path $ProbeRoot "agent-instance"
$AgentWritable = Join-Path $AgentRoot "data"
$AgentBackup = Join-Path $AgentRoot "backups"
$AgentWatch = Join-Path $ProbeRoot "agent-watch"
$AgentRecoveryFile = Join-Path $AgentRoot "restore-recovery.json"
$Executable = Join-Path $ChildRoot "acl-probe.exe"
$ProbeDirectories = @(
    $ChildRoot, $EmptyChild, $EmptyTree, $RawConfigTree, $RawStateTree,
    $AgentWritable, $AgentBackup, $AgentWatch
)
New-Item -ItemType Directory -Path $ProbeDirectories `
    -Force | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" `
    -Destination $Executable
$RawConfigFile = Join-Path $RawConfigTree "clients.json"
$RawBootstrapFile = Join-Path $RawConfigTree "bootstrap-admin-password.txt"
$RawStateFile = Join-Path $RawStateTree "mineguard.db"
[IO.File]::WriteAllText($RawConfigFile, "{}")
[IO.File]::WriteAllText($RawBootstrapFile, "probe-password")
[IO.File]::WriteAllText($RawStateFile, "state-probe")
[IO.File]::WriteAllText($RawIntegrityFile, "{}")
[IO.File]::WriteAllText($AgentRecoveryFile, "{}")

try {
    Set-MineGuardPlatformCanonicalTreeAcl -Path $RawConfigTree `
        -ServicePermission "RX"
    Grant-MineGuardPlatformBootstrapPasswordDeleteAcl `
        -Path $RawBootstrapFile
    Set-MineGuardPlatformCanonicalTreeAcl -Path $RawStateTree `
        -ServicePermission "M"
    Set-MineGuardPlatformServiceReadableFileAcl -Path $RawIntegrityFile
    Write-Host (
        "MineGuard unregistered raw service-SID ACL semantics passed."
    )

    $AgentServiceId = "MineGuardEnterpriseAgent-AclProbe" + `
        ([Guid]::NewGuid().ToString("N").Substring(0, 12))
    if ($null -ne (Get-Service -Name $AgentServiceId `
            -ErrorAction SilentlyContinue)) {
        throw "The Agent raw-SID probe service unexpectedly exists."
    }
    $AgentIdentity = Get-EAServiceIdentity -ServiceId $AgentServiceId
    $ContainerAndObject = `
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    Set-EACanonicalInheritedTreeAcl -Root $AgentRoot `
        -Name "Agent production RX ACL probe" `
        -ServicePermission "RX" -ServiceSid $AgentIdentity.Sid
    Assert-ExplicitRawSidRule -Path $AgentRoot -Sid $AgentIdentity.Sid `
        -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -Inheritance $ContainerAndObject
    Set-EACanonicalInheritedTreeAcl -Root $AgentWritable `
        -Name "Agent production writable ACL probe" `
        -ServicePermission "M" -ServiceSid $AgentIdentity.Sid
    Assert-ExplicitRawSidRule -Path $AgentWritable -Sid $AgentIdentity.Sid `
        -Rights ([Security.AccessControl.FileSystemRights]::Modify) `
        -Inheritance $ContainerAndObject
    Set-EACanonicalInheritedTreeAcl -Root $AgentBackup `
        -Name "Agent production backup ACL probe" -ServicePermission "None"
    Set-EACanonicalFileAcl -Path $AgentRecoveryFile `
        -Name "Agent production recovery ACL probe" `
        -ServicePermission "RX" -ServiceSid $AgentIdentity.Sid
    Assert-ExplicitRawSidRule -Path $AgentRecoveryFile `
        -Sid $AgentIdentity.Sid `
        -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -Inheritance ([Security.AccessControl.InheritanceFlags]::None)
    Set-EACanonicalInheritedTreeAcl -Root $AgentWatch `
        -Name "Agent watch business-boundary probe" -ServicePermission "None"
    Grant-EAServiceWatchReadAcl -WatchRoot $AgentWatch `
        -ServiceSid $AgentIdentity.Sid
    Assert-EAServiceWatchReadAcl -WatchRoot $AgentWatch `
        -ServiceSid $AgentIdentity.Sid
    if ($null -ne (Get-Service -Name $AgentServiceId `
            -ErrorAction SilentlyContinue)) {
        throw "The Agent ACL helper unexpectedly registered a service."
    }
    Write-Host "Enterprise Agent unregistered service-SID ACL semantics passed."

    Invoke-IcaclsChecked -Label "Empty-tree ACL reset" -ArgumentList @(
        $EmptyTree, "/reset"
    )
    Invoke-IcaclsChecked -Label "Empty-tree ACL root grant" -ArgumentList @(
        $EmptyTree,
        "/inheritance:r",
        "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
        "/grant:r", "*S-1-5-19:(OI)(CI)RX"
    )
    Invoke-IcaclsChecked -Label "Empty-tree descendant reset" -ArgumentList @(
        (Join-Path $EmptyTree "*"), "/reset", "/T", "/C"
    )
    Assert-AclContract -Path $EmptyTree -ExpectProtected $true `
        -ExpectInherited $false

    Invoke-IcaclsChecked -Label "Stale explicit ACL fixture" -ArgumentList @(
        $ProbeRoot, "/grant", "*S-1-5-32-545:(OI)(CI)F"
    )
    # Reproduce the historical defect first: recursive inheritance removal
    # protects descendants without giving leaf files an effective ACE.
    Invoke-IcaclsChecked -Label "Empty descendant ACL fixture" -ArgumentList @(
        $ChildRoot, "/inheritance:r", "/T", "/C"
    )
    Invoke-IcaclsChecked -Label "Empty directory ACL fixture" -ArgumentList @(
        $EmptyChild, "/inheritance:r"
    )

    # Canonicalize the root itself, then reset descendants so they inherit the
    # protected root. Applying /inheritance:r with /T protects every child and
    # can leave existing files with an empty DACL.
    Invoke-IcaclsChecked -Label "Canonical ACL root reset" -ArgumentList @(
        $ProbeRoot, "/reset"
    )
    Invoke-IcaclsChecked -Label "Canonical ACL root grant" -ArgumentList @(
        $ProbeRoot,
        "/inheritance:r",
        "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
        "/grant:r", "*S-1-5-19:(OI)(CI)RX"
    )
    Invoke-IcaclsChecked -Label "Canonical ACL descendant reset" -ArgumentList @(
        (Join-Path $ProbeRoot "*"), "/reset", "/T", "/C"
    )

    & "$env:SystemRoot\System32\icacls.exe" $ProbeRoot | Out-Host
    & "$env:SystemRoot\System32\icacls.exe" $Executable | Out-Host
    Assert-AclContract -Path $ProbeRoot -ExpectProtected $true `
        -ExpectInherited $false
    Assert-AclContract -Path $Executable -ExpectProtected $false `
        -ExpectInherited $true
    Assert-AclContract -Path $EmptyChild -ExpectProtected $false `
        -ExpectInherited $true

    [IO.File]::WriteAllText(
        (Join-Path $ProbeRoot "write-probe.txt"),
        "write access verified"
    )
    & $Executable -n 1 127.0.0.1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The ACL-protected executable returned $LASTEXITCODE."
    }
    $MovedChild = Join-Path $ProbeRoot "moved-child"
    Move-Item -LiteralPath $ChildRoot -Destination $MovedChild
    Remove-Item -LiteralPath $MovedChild -Recurse -Force
    Write-Host "MineGuard canonical NTFS ACL grant semantics passed."
}
finally {
    if (Test-Path -LiteralPath $ProbeRoot) {
        # The owner can re-open this short-lived probe even when the assertion
        # under test failed before ordinary file access was demonstrated.
        & "$env:SystemRoot\System32\icacls.exe" $ProbeRoot "/grant:r" `
            ("*{0}:(OI)(CI)F" -f $CurrentUserSid) "/T" "/C" | Out-Host
        Remove-Item -LiteralPath $ProbeRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}
