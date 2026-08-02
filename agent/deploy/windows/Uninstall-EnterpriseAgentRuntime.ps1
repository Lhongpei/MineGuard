[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallRoot,
    [switch]$InternalInnoUninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:UninstallScriptPath = [IO.Path]::GetFullPath($PSCommandPath)

if ($env:OS -ne "Windows_NT") {
    throw "MineGuard Enterprise Agent runtime removal is supported only on Windows."
}
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw "Windows PowerShell 5.1 or later is required."
}
if (-not $InternalInnoUninstall) {
    throw "This transaction may be invoked only by the MineGuard Inno uninstaller."
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal `
    -ArgumentList $Identity
if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw "The MineGuard Enterprise Agent uninstaller must run as Administrator."
}

function Get-SafeLocalFixedPath {
    param([string]$PathValue, [string]$Label)

    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue -ne $PathValue.Trim() -or
        $PathValue.Contains("/") -or
        $PathValue -notmatch '^[A-Za-z]:\\') {
        throw "$Label must be an X:\\ absolute local path."
    }
    $WithoutTrailingSlash = $PathValue.TrimEnd('\')
    if ($WithoutTrailingSlash.Length -le 2) {
        throw "$Label must not be a filesystem root."
    }
    foreach ($Part in ($WithoutTrailingSlash.Substring(3) -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($Part) -or
            $Part -in @(".", "..") -or
            $Part.Contains(":") -or
            $Part.EndsWith(" ") -or $Part.EndsWith(".")) {
            throw "$Label contains an empty, dot or ambiguous path component."
        }
    }

    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.Equals(
            $Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label must not be a filesystem root."
    }
    $Drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $Root
    if (-not $Drive.IsReady -or
        $Drive.DriveType -ne [IO.DriveType]::Fixed -or
        -not $Drive.DriveFormat.Equals(
            "NTFS", [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label must be on a ready local fixed NTFS volume."
    }

    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a symlink, junction, mount point or reparse point: $Current"
            }
        }
        if ($Current.Equals(
                $Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $Parent = [IO.Path]::GetDirectoryName($Current)
        if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent -eq $Current) {
            throw "$Label ancestry cannot be resolved safely."
        }
        $Current = $Parent.TrimEnd('\')
    }
    return $FullPath
}

function Assert-NotBroadInstallRoot {
    param([string]$PathValue)

    $Candidate = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $Protected = @(
        $env:ProgramData,
        $env:ALLUSERSPROFILE,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:CommonProgramFiles,
        ${env:CommonProgramFiles(x86)},
        $env:PUBLIC
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    foreach ($ProtectedPath in $Protected) {
        $FullProtected = [IO.Path]::GetFullPath(
            [string]$ProtectedPath
        ).TrimEnd('\')
        if ($Candidate.Equals(
                $FullProtected, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "InstallRoot cannot be a broad system or shared-data directory."
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $WindowsRoot = [IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')
        if ($Candidate.Equals(
                $WindowsRoot, [StringComparison]::OrdinalIgnoreCase
            ) -or $Candidate.StartsWith(
                $WindowsRoot + '\', [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "InstallRoot cannot be the Windows directory or one of its descendants."
        }
    }
}

function Assert-OrdinaryDirectoryTree {
    param([string]$RootPath, [string]$Label)

    $Pending = New-Object 'System.Collections.Generic.Stack[string]'
    $Pending.Push($RootPath)
    while ($Pending.Count -gt 0) {
        $CurrentPath = $Pending.Pop()
        $CurrentItem = Get-Item -LiteralPath $CurrentPath -Force
        if (($CurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a symlink, junction, mount point or reparse point: $CurrentPath"
        }
        if (-not $CurrentItem.PSIsContainer) { continue }
        foreach ($Child in Get-ChildItem -LiteralPath $CurrentPath -Force) {
            if (($Child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a symlink, junction, mount point or reparse point: $($Child.FullName)"
            }
            if ($Child.PSIsContainer) { $Pending.Push($Child.FullName) }
        }
    }
}

function Assert-AgentReleaseIdentity {
    param([string]$RootPath)

    $MetadataRoot = Join-Path $RootPath "release-metadata"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $VersionPath = Join-Path $MetadataRoot "VERSION.txt"
    foreach ($RequiredPath in @($ManifestPath, $VersionPath)) {
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "Installed Agent identity metadata is incomplete: $RequiredPath"
        }
        $RequiredItem = Get-Item -LiteralPath $RequiredPath -Force
        if (($RequiredItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $RequiredItem.Length -gt 16MB) {
            throw "Installed Agent identity metadata is unsafe: $RequiredPath"
        }
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $Version = (Get-Content -LiteralPath $VersionPath -Raw -Encoding UTF8).Trim()
    if ([string]$Manifest.product -ne "MineGuard Enterprise Agent" -or
        [string]$Manifest.architecture -ne "x64" -or
        [string]$Manifest.entrypoint -ne "runtime/MineGuardEnterpriseAgent.exe" -or
        [string]$Manifest.version -ne $Version -or
        $Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "InstallRoot does not contain an identified MineGuard Enterprise Agent release."
    }
    $ScriptEntries = @($Manifest.files | Where-Object {
        [string]$_.path -eq
            "deploy/windows/Uninstall-EnterpriseAgentRuntime.ps1"
    })
    $ScriptItem = Get-Item -LiteralPath $script:UninstallScriptPath -Force
    if ($ScriptEntries.Count -ne 1 -or
        [string]$ScriptEntries[0].sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        [long]$ScriptEntries[0].bytes -ne [long]$ScriptItem.Length -or
        -not (Get-FileHash -LiteralPath $script:UninstallScriptPath `
            -Algorithm SHA256).Hash.Equals(
                [string]$ScriptEntries[0].sha256,
                [StringComparison]::OrdinalIgnoreCase
            )) {
        throw "The protected Agent uninstall transaction runner does not match release metadata."
    }
}

function Assert-InnoInstallBoundary {
    param([string]$RootPath)

    if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        throw "InstallRoot does not exist: $RootPath"
    }
    $Uninstallers = @(Get-ChildItem -LiteralPath $RootPath -File -Force |
        Where-Object { $_.Name -match '^unins[0-9]*\.exe$' })
    if ($Uninstallers.Count -lt 1) {
        throw "InstallRoot has no MineGuard Inno uninstaller boundary marker."
    }
    foreach ($Uninstaller in $Uninstallers) {
        if (($Uninstaller.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Inno uninstaller boundary contains a reparse point."
        }
    }
}

function Assert-AgentQuiescent {
    param([string[]]$ProtectedRoots)

    $Services = @(Get-Service -Name "MineGuardEnterpriseAgent-*" `
        -ErrorAction SilentlyContinue)
    $ServiceRegistryRoot =
        "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
    $RegistryServices = @(Get-ChildItem -LiteralPath $ServiceRegistryRoot `
        -ErrorAction Stop | Where-Object {
            $_.PSChildName.StartsWith(
                "MineGuardEnterpriseAgent-", [StringComparison]::OrdinalIgnoreCase
            )
        })
    if ($Services.Count -gt 0 -or $RegistryServices.Count -gt 0) {
        throw "Remove every MineGuardEnterpriseAgent-* Windows service before uninstalling the shared runtime."
    }

    $NormalizedRoots = @($ProtectedRoots | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd('\')
    })
    $Running = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        if ([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)) {
            return $false
        }
        try { $ProcessPath = [IO.Path]::GetFullPath([string]$_.ExecutablePath) }
        catch { return $false }
        foreach ($ProtectedRoot in $NormalizedRoots) {
            if ($ProcessPath.Equals(
                    $ProtectedRoot, [StringComparison]::OrdinalIgnoreCase
                ) -or $ProcessPath.StartsWith(
                    $ProtectedRoot + '\', [StringComparison]::OrdinalIgnoreCase
                )) {
                return $true
            }
        }
        return $false
    })
    if ($Running.Count -gt 0) {
        $Details = @($Running | ForEach-Object {
            "PID=$($_.ProcessId) Name=$($_.Name) Path=$($_.ExecutablePath)"
        }) -join "; "
        throw "A process is still running from an immutable Agent directory: $Details"
    }
}

function Remove-AgentQuarantineTree {
    param([string]$QuarantinePath)

    Assert-OrdinaryDirectoryTree -RootPath $QuarantinePath `
        -Label "Agent uninstall quarantine"
    $MarkerPath = Join-Path $QuarantinePath "quarantine-marker.json"
    $Children = @(Get-ChildItem -LiteralPath $QuarantinePath -Force)
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        if ($Children.Count -eq 0) {
            [IO.Directory]::Delete($QuarantinePath, $false)
            return
        }
        throw "Refusing a non-empty unmarked Agent uninstall quarantine: $QuarantinePath"
    }
    foreach ($Child in $Children) {
        if ($Child.Name -eq "quarantine-marker.json") { continue }
        if (-not $Child.PSIsContainer -or
            $Child.Name -notin @("runtime", "deploy", "release-metadata")) {
            throw "Agent uninstall quarantine contains an unexpected item: $($Child.FullName)"
        }
        Remove-Item -LiteralPath $Child.FullName -Recurse -Force
    }
    # Keep the ownership marker until every quarantined product directory has
    # been removed, so a failed deletion remains safely retryable.
    Remove-Item -LiteralPath $MarkerPath -Force
    [IO.Directory]::Delete($QuarantinePath, $false)
}

function Remove-RecognizedQuarantines {
    param([string]$RootPath)

    $Prefix = ".mineguard-enterprise-agent-uninstall-quarantine."
    foreach ($Directory in Get-ChildItem -LiteralPath $RootPath -Directory -Force |
        Where-Object { $_.Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) }) {
        Assert-OrdinaryDirectoryTree -RootPath $Directory.FullName `
            -Label "Agent uninstall quarantine"
        $MarkerPath = Join-Path $Directory.FullName "quarantine-marker.json"
        if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
            if (@(Get-ChildItem -LiteralPath $Directory.FullName -Force).Count -eq 0) {
                [IO.Directory]::Delete($Directory.FullName, $false)
                continue
            }
            throw "Refusing an unmarked Agent uninstall quarantine: $($Directory.FullName)"
        }
        $Marker = Get-Content -LiteralPath $MarkerPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([int]$Marker.schemaVersion -ne 1 -or
            [string]$Marker.product -ne "MineGuard Enterprise Agent" -or
            -not ([IO.Path]::GetFullPath([string]$Marker.installRoot).TrimEnd('\')).Equals(
                $RootPath, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Refusing a quarantine whose ownership marker does not match InstallRoot."
        }
        Assert-AgentQuiescent -ProtectedRoots @($Directory.FullName)
        Remove-AgentQuarantineTree -QuarantinePath $Directory.FullName
    }
}

$InstallRoot = Get-SafeLocalFixedPath -PathValue $InstallRoot -Label "InstallRoot"
Assert-NotBroadInstallRoot -PathValue $InstallRoot
Assert-InnoInstallBoundary -RootPath $InstallRoot
Remove-RecognizedQuarantines -RootPath $InstallRoot

$TargetNames = @("runtime", "deploy", "release-metadata")
$Targets = @()
foreach ($TargetName in $TargetNames) {
    $TargetPath = [IO.Path]::GetFullPath((Join-Path $InstallRoot $TargetName)).TrimEnd('\')
    $ExpectedPath = $InstallRoot + '\' + $TargetName
    if (-not $TargetPath.Equals(
            $ExpectedPath, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "An immutable Agent target escaped InstallRoot: $TargetPath"
    }
    if (Test-Path -LiteralPath $TargetPath) {
        if (-not (Test-Path -LiteralPath $TargetPath -PathType Container)) {
            throw "An immutable Agent target is not a directory: $TargetPath"
        }
        Assert-OrdinaryDirectoryTree -RootPath $TargetPath `
            -Label "Immutable Agent target"
        $Targets += [pscustomobject]@{ Name = $TargetName; Source = $TargetPath }
    }
}

if ($Targets.Count -eq 0) {
    Write-Host "MineGuard Enterprise Agent immutable runtime is already absent."
    exit 0
}
Assert-AgentReleaseIdentity -RootPath $InstallRoot
Assert-AgentQuiescent -ProtectedRoots @($Targets | ForEach-Object { $_.Source })

$QuarantineName = ".mineguard-enterprise-agent-uninstall-quarantine." +
    [Guid]::NewGuid().ToString("N")
$QuarantineRoot = Join-Path $InstallRoot $QuarantineName
New-Item -ItemType Directory -Path $QuarantineRoot | Out-Null
$QuarantineRoot = Get-SafeLocalFixedPath -PathValue $QuarantineRoot `
    -Label "Agent uninstall quarantine"
$Marker = [ordered]@{
    schemaVersion = 1
    product = "MineGuard Enterprise Agent"
    installRoot = $InstallRoot
    createdUtc = [DateTime]::UtcNow.ToString("o")
}
[IO.File]::WriteAllText(
    (Join-Path $QuarantineRoot "quarantine-marker.json"),
    (($Marker | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    (New-Object Text.UTF8Encoding($false))
)

$Moved = @()
try {
    # This is intentionally the last service/process observation before the
    # first same-volume atomic directory rename.
    Assert-AgentQuiescent -ProtectedRoots @($Targets | ForEach-Object { $_.Source })
    foreach ($Target in $Targets) {
        $Destination = Join-Path $QuarantineRoot $Target.Name
        if (Test-Path -LiteralPath $Destination) {
            throw "Quarantine destination already exists: $Destination"
        }
        [IO.Directory]::Move($Target.Source, $Destination)
        $Moved += [pscustomobject]@{
            Source = $Target.Source
            Destination = $Destination
        }
    }
    Assert-AgentQuiescent -ProtectedRoots @(
        @($Targets | ForEach-Object { $_.Source }) + @($QuarantineRoot)
    )
}
catch {
    $RenameError = $_
    $RollbackErrors = @()
    for ($Index = $Moved.Count - 1; $Index -ge 0; $Index--) {
        $Move = $Moved[$Index]
        try {
            if (-not (Test-Path -LiteralPath $Move.Destination -PathType Container)) {
                throw "Rollback source is missing: $($Move.Destination)"
            }
            if (Test-Path -LiteralPath $Move.Source) {
                throw "Rollback destination already exists: $($Move.Source)"
            }
            [IO.Directory]::Move($Move.Destination, $Move.Source)
        }
        catch { $RollbackErrors += $_.Exception.Message }
    }
    if ($RollbackErrors.Count -eq 0) {
        Remove-Item -LiteralPath $QuarantineRoot -Recurse -Force
        throw $RenameError
    }
    throw ("Agent uninstall rename failed and rollback was incomplete. " +
        "Quarantine retained at {0}. Original error: {1}. Rollback errors: {2}" -f
        $QuarantineRoot, $RenameError.Exception.Message, ($RollbackErrors -join " | "))
}

try {
    Remove-AgentQuarantineTree -QuarantinePath $QuarantineRoot
}
catch {
    throw ("Agent immutable directories were quarantined, but final deletion failed. " +
        "Retry the official uninstaller; do not manually reuse this directory. " +
        "Quarantine: {0}. Error: {1}" -f $QuarantineRoot, $_.Exception.Message)
}

Write-Host "MineGuard Enterprise Agent immutable runtime was transactionally removed."
