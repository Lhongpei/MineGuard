[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string]$DestinationRoot = "",
    [string]$SnapshotAuthenticationKeyFile = "",
    [switch]$LeaveStopped
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$SafetyHelper = Join-Path $PSScriptRoot "EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $SafetyHelper -PathType Leaf)) {
    throw "Windows safety helper is missing: $SafetyHelper"
}
. $SafetyHelper
Assert-EAPowerShell51

$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

$MaximumSnapshotFiles = 10000
$MaximumSnapshotFileBytes = 32GB
$MaximumSnapshotTotalBytes = 256GB
$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
if (-not [bool]$Context.Metadata.acl_hardened) {
    throw "State backup refuses an instance created with -SkipAcl."
}
$QuarantineDirectory = Join-Path $Context.DataDirectory "five-quantity-quarantine"
if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
    $DestinationRoot = $Context.BackupDirectory
}
# Destination validation is deliberately performed on the raw caller value.
$DestinationRoot = Resolve-EASafeLocalPath -Name "Backup destination" `
    -PathValue $DestinationRoot
if ((Test-EAPathWithin -Candidate $DestinationRoot -Parent $Context.DataDirectory) -or
    (Test-EAPathWithin -Candidate $Context.DataDirectory -Parent $DestinationRoot)) {
    throw "Backup destination must not overlap the live data directory."
}
if ((Test-EAPathWithin -Candidate $DestinationRoot -Parent $Context.InstallRoot) -or
    (Test-EAPathWithin -Candidate $Context.InstallRoot -Parent $DestinationRoot)) {
    throw "Backup destination must not overlap InstallRoot."
}
if (Test-EAPathWithin -Candidate $DestinationRoot -Parent $Context.StateRoot) {
    if (-not (Test-EAPathWithin -Candidate $DestinationRoot -Parent $Context.BackupDirectory)) {
        throw "A destination inside StateRoot must be inside this instance's backups directory."
    }
}
elseif (Test-EAPathWithin -Candidate $Context.StateRoot -Parent $DestinationRoot) {
    throw "Backup destination must not be an ancestor of StateRoot."
}
New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
$DestinationRoot = Resolve-EASafeLocalPath -Name "Backup destination" `
    -PathValue $DestinationRoot -MustExist -RequiredType Container
Assert-EAProtectedDirectoryAcl -Path $DestinationRoot -Name "Backup destination"
$Timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
$SnapshotName = "$InstanceName-$Timestamp"
$FinalSnapshot = Join-Path $DestinationRoot $SnapshotName
$TemporarySnapshot = Join-Path $DestinationRoot (
    ".incomplete-" + [Guid]::NewGuid().ToString("N")
)
$EffectiveKeyPath = if ([string]::IsNullOrWhiteSpace($SnapshotAuthenticationKeyFile)) {
    Join-Path $Context.BackupDirectory "snapshot-auth.key"
} else {
    Resolve-EASafeLocalPath -Name "SnapshotAuthenticationKeyFile" `
        -PathValue $SnapshotAuthenticationKeyFile
}
foreach ($SnapshotBoundary in @($FinalSnapshot, $TemporarySnapshot)) {
    if ((Test-EAPathWithin -Candidate $EffectiveKeyPath -Parent $SnapshotBoundary) -or
        (Test-EAPathWithin -Candidate $SnapshotBoundary -Parent $EffectiveKeyPath)) {
        throw "Snapshot authentication key must remain outside the snapshot directory."
    }
}
$SnapshotAuthenticationKey = Get-EASnapshotAuthenticationKey -Context $Context `
    -KeyPath $EffectiveKeyPath -CreateIfMissing

$ServiceContext = Get-EAServiceContext -Context $Context
$WasRunning = $null -ne $ServiceContext -and
    $ServiceContext.Service.Status -ne "Stopped"
if ($WasRunning) {
    try {
        Stop-Service -Name $Context.ServiceId -Force
        (Get-Service -Name $Context.ServiceId).WaitForStatus(
            "Stopped", [TimeSpan]::FromSeconds(30)
        )
    }
    catch {
        $CurrentService = Get-Service -Name $Context.ServiceId -ErrorAction SilentlyContinue
        if ($null -ne $CurrentService -and $CurrentService.Status -eq "Stopped") {
            Start-Service -Name $Context.ServiceId
        }
        throw
    }
}

$Completed = $false
try {
    Assert-EANoInstanceProcesses -Context $Context
    if (Test-Path -LiteralPath $FinalSnapshot) {
        throw "Snapshot target already exists: $FinalSnapshot"
    }
    New-Item -ItemType Directory -Path $TemporarySnapshot | Out-Null
    $SnapshotDatabase = Join-Path $TemporarySnapshot "enterprise-agent.db"
    # Recheck immediately before SQLite backup after all path/service validation.
    Assert-EANoInstanceProcesses -Context $Context
    Invoke-NativeChecked -FilePath $Context.Executable -ArgumentList @(
        "--env-file", $Context.ConfigPath, "--db", $Context.DatabasePath,
        "database-backup", "--output", $SnapshotDatabase
    )

    $SnapshotQuarantine = Join-Path $TemporarySnapshot "five-quantity-quarantine"
    New-Item -ItemType Directory -Path $SnapshotQuarantine | Out-Null
    if (Test-Path -LiteralPath $QuarantineDirectory -PathType Container) {
        Assert-EAOrdinaryTree -Root $QuarantineDirectory -Name "Live quarantine"
        $EvidenceFiles = @(Get-ChildItem -LiteralPath $QuarantineDirectory -Force)
        if ($EvidenceFiles.Count -gt $MaximumSnapshotFiles) {
            throw "Quarantine exceeds the $MaximumSnapshotFiles file snapshot limit."
        }
        $EvidenceBytes = 0L
        foreach ($EvidenceFile in $EvidenceFiles) {
            if ($EvidenceFile.PSIsContainer) {
                throw "Quarantine must contain only ordinary evidence files: $($EvidenceFile.FullName)"
            }
            if ([long]$EvidenceFile.Length -gt $MaximumSnapshotFileBytes) {
                throw "Evidence file exceeds the snapshot size limit: $($EvidenceFile.FullName)"
            }
            $EvidenceBytes += [long]$EvidenceFile.Length
            if ($EvidenceBytes -gt $MaximumSnapshotTotalBytes) {
                throw "Quarantine exceeds the total snapshot size limit."
            }
            Copy-Item -LiteralPath $EvidenceFile.FullName -Destination $SnapshotQuarantine
        }
    }

    $Files = @()
    $TotalBytes = 0L
    $SnapshotFiles = @(Get-ChildItem -LiteralPath $TemporarySnapshot -File -Recurse | `
        Sort-Object FullName)
    if ($SnapshotFiles.Count -gt $MaximumSnapshotFiles) {
        throw "Snapshot exceeds the $MaximumSnapshotFiles file limit."
    }
    foreach ($File in $SnapshotFiles) {
        if ([long]$File.Length -gt $MaximumSnapshotFileBytes) {
            throw "Snapshot file exceeds the size limit: $($File.FullName)"
        }
        $TotalBytes += [long]$File.Length
        if ($TotalBytes -gt $MaximumSnapshotTotalBytes) {
            throw "Snapshot exceeds the total size limit."
        }
        $Relative = $File.FullName.Substring($TemporarySnapshot.Length).TrimStart('\')
        $Files += [ordered]@{
            path = $Relative
            bytes = [long]$File.Length
            sha256 = (Get-FileHash -LiteralPath $File.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $SnapshotManifest = [ordered]@{
        format = "mineguard-enterprise-agent-state-snapshot-v2"
        created_at = [DateTime]::UtcNow.ToString("o")
        instance_name = $Context.InstanceName
        service_id = $Context.ServiceId
        mine_id = $Context.MineId
        state_root_id = $Context.RootId
        files = $Files
        integrity_note = "Authenticated by the separate per-instance snapshot key."
        hmac_algorithm = "HMAC-SHA256"
        hmac_key_id = Get-EASnapshotKeyId -Key $SnapshotAuthenticationKey
    }
    $SnapshotManifest["hmac_sha256"] = Get-EASnapshotHmacSha256 `
        -Key $SnapshotAuthenticationKey -Manifest $SnapshotManifest
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        (Join-Path $TemporarySnapshot "snapshot.json"),
        (($SnapshotManifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        $Utf8NoBom
    )
    Set-EACanonicalInheritedTreeAcl -Root $TemporarySnapshot `
        -Name "Temporary Agent snapshot" -RootGrants @(
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F"
        )
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $TemporarySnapshot
    Move-Item -LiteralPath $TemporarySnapshot -Destination $FinalSnapshot
    $Completed = $true
    Write-Host "Complete Agent state snapshot created: $FinalSnapshot"
    Write-Warning "Back up snapshot-auth.key separately through the approved key escrow. The key is never included in a snapshot."
}
finally {
    if (-not $Completed -and (Test-Path -LiteralPath $TemporarySnapshot)) {
        Remove-EAOwnedTemporaryTree -Path $TemporarySnapshot `
            -ExpectedParent $DestinationRoot -RequiredPrefix ".incomplete-"
    }
    if ($WasRunning -and -not $LeaveStopped) {
        Start-Service -Name $Context.ServiceId
        (Get-Service -Name $Context.ServiceId).WaitForStatus(
            "Running", [TimeSpan]::FromSeconds(30)
        )
    }
}
