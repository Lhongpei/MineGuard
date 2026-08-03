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

function Get-AllowSids {
    param([string]$Path)
    $Result = @{}
    foreach ($Rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($Rule.AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $Sid = try {
            $Rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            [string]$Rule.IdentityReference
        }
        $Result[$Sid] = $true
    }
    return $Result
}

$ProbeParent = Join-Path $env:RUNNER_TEMP "mineguard-acl-grant"
$ProbeRoot = Join-Path $ProbeParent ([Guid]::NewGuid().ToString("N"))
$ChildRoot = Join-Path $ProbeRoot "child"
$Executable = Join-Path $ChildRoot "acl-probe.exe"
New-Item -ItemType Directory -Path $ChildRoot -Force | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" `
    -Destination $Executable

try {
    # Canonicalize the root itself, then reset descendants so they inherit the
    # protected root. Applying /inheritance:r with /T protects every child and
    # can leave existing files with an empty DACL.
    Invoke-IcaclsChecked -Label "Canonical ACL reset" -ArgumentList @(
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

    $RootAllowSids = Get-AllowSids -Path $ProbeRoot
    $ChildAllowSids = Get-AllowSids -Path $Executable
    Write-Host ("Root allow SIDs: " + (($RootAllowSids.Keys | Sort-Object) -join ", "))
    Write-Host ("Child allow SIDs: " + (($ChildAllowSids.Keys | Sort-Object) -join ", "))
    & "$env:SystemRoot\System32\icacls.exe" $ProbeRoot | Out-Host
    & "$env:SystemRoot\System32\icacls.exe" $Executable | Out-Host
    foreach ($RequiredSid in @("S-1-5-18", "S-1-5-32-544", "S-1-5-19")) {
        if (-not $RootAllowSids.ContainsKey($RequiredSid)) {
            throw "Canonical root ACL is missing trustee $RequiredSid."
        }
        if (-not $ChildAllowSids.ContainsKey($RequiredSid)) {
            throw "Canonical child ACL is missing trustee $RequiredSid."
        }
    }

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
