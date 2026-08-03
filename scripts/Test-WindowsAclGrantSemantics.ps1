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

$ProbeParent = Join-Path $env:RUNNER_TEMP "mineguard-acl-grant"
$ProbeRoot = Join-Path $ProbeParent ([Guid]::NewGuid().ToString("N"))
$ChildRoot = Join-Path $ProbeRoot "child"
$EmptyChild = Join-Path $ProbeRoot "empty-child"
$EmptyTree = Join-Path $ProbeRoot "standalone-empty-tree"
$Executable = Join-Path $ChildRoot "acl-probe.exe"
New-Item -ItemType Directory -Path $ChildRoot,$EmptyChild,$EmptyTree `
    -Force | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" `
    -Destination $Executable

try {
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
