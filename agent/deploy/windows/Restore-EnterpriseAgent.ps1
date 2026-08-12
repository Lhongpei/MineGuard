[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$SnapshotPath,
    [Parameter(Mandatory = $true)][switch]$ConfirmRestore,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string]$SnapshotAuthenticationKeyFile = "",
    [switch]$AllowUnauthenticatedLegacySnapshot,
    [switch]$StartAfterRestore
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

function Write-EAProtectedRestoreRecoveryBlock {
    param([string]$PathValue, [object]$Document, [object]$Context)
    if (Test-Path -LiteralPath $PathValue) {
        throw "Restore recovery block already exists: $PathValue"
    }
    $Parent = Split-Path -Parent $PathValue
    $Temporary = Join-Path $Parent (
        ".restore-recovery-block-" + [Guid]::NewGuid().ToString("N") + ".tmp"
    )
    $Stream = $null
    try {
        $Encoding = New-Object System.Text.UTF8Encoding($false)
        $Bytes = $Encoding.GetBytes(
            (($Document | ConvertTo-Json -Depth 8) + "`n")
        )
        $Stream = [IO.File]::Open(
            $Temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
        $Stream.Dispose()
        $Stream = $null
        Invoke-EAIcaclsChecked -ArgumentList @($Temporary, "/inheritance:r")
        Invoke-EAIcaclsChecked -ArgumentList @(
            $Temporary,
            "/grant:r", "*S-1-5-18:F",
            "/grant:r", "*S-1-5-32-544:F",
            "/grant:r", "*$($Context.ServiceIdentity.Sid):RX"
        )
        Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $Temporary
        Move-Item -LiteralPath $Temporary -Destination $PathValue
        Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $PathValue
    }
    catch {
        if ($null -ne $Stream) { $Stream.Dispose() }
        foreach ($Candidate in @($Temporary, $PathValue)) {
            if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
                Remove-Item -LiteralPath $Candidate -Force -ErrorAction SilentlyContinue
            }
        }
        throw
    }
}

function Invoke-EARestoreFaultInjection {
    param([string]$Point)
    # Internal Windows transaction tests set this process-only variable. It is
    # deliberately unavailable as a user-facing restore switch.
    if ([string]$env:MINEGUARD_INTERNAL_RESTORE_FAULT_INJECTION -eq $Point) {
        throw "Injected restore transaction failure at $Point."
    }
}

if (-not $ConfirmRestore) {
    throw "Restore requires the explicit -ConfirmRestore switch."
}
$MaximumSnapshotFiles = 10000
$MaximumSnapshotFileBytes = 32GB
$MaximumSnapshotTotalBytes = 256GB
$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
if (-not [bool]$Context.Metadata.acl_hardened) {
    throw "State restore refuses an instance created with -SkipAcl."
}
# Raw caller input is validated before normalization.
$SnapshotPath = Resolve-EASafeLocalPath -Name "SnapshotPath" -PathValue $SnapshotPath `
    -MustExist -RequiredType Container
Assert-EAOrdinaryTree -Root $SnapshotPath -Name "Snapshot" `
    -MaximumEntries ($MaximumSnapshotFiles + 4)
if ((Test-EAPathWithin -Candidate $SnapshotPath -Parent $Context.DataDirectory) -or
    (Test-EAPathWithin -Candidate $Context.DataDirectory -Parent $SnapshotPath)) {
    throw "Snapshot must not overlap the live data directory."
}
if ((Test-EAPathWithin -Candidate $SnapshotPath -Parent $Context.InstallRoot) -or
    (Test-EAPathWithin -Candidate $Context.InstallRoot -Parent $SnapshotPath)) {
    throw "Snapshot must not overlap InstallRoot."
}
if ((Test-EAPathWithin -Candidate $SnapshotPath -Parent $Context.StateRoot) -and
    -not (Test-EAPathWithin -Candidate $SnapshotPath -Parent $Context.BackupDirectory)) {
    throw "A snapshot inside StateRoot must be inside this instance's backups directory."
}
$EffectiveKeyPath = if ([string]::IsNullOrWhiteSpace($SnapshotAuthenticationKeyFile)) {
    Join-Path $Context.BackupDirectory "snapshot-auth.key"
} else {
    Resolve-EASafeLocalPath -Name "SnapshotAuthenticationKeyFile" `
        -PathValue $SnapshotAuthenticationKeyFile -MustExist -RequiredType Leaf
}
if ((Test-EAPathWithin -Candidate $EffectiveKeyPath -Parent $SnapshotPath) -or
    (Test-EAPathWithin -Candidate $SnapshotPath -Parent $EffectiveKeyPath)) {
    throw "Snapshot authentication key must be delivered independently, outside SnapshotPath."
}
Assert-EAProtectedSnapshotAcl -SnapshotRoot $SnapshotPath

$SnapshotManifestPath = Join-Path $SnapshotPath "snapshot.json"
$Manifest = Read-EAJsonFile -Path $SnapshotManifestPath -Name "Snapshot manifest" `
    -MaximumBytes 8MB
$SnapshotFormat = [string](Get-EARequiredProperty -Object $Manifest -Name "format" `
    -Context "Snapshot manifest")
$IsAuthenticatedV2 = $SnapshotFormat -eq "mineguard-enterprise-agent-state-snapshot-v2"
$IsLegacyV1 = $SnapshotFormat -eq "mineguard-enterprise-agent-state-snapshot-v1"
if (-not $IsAuthenticatedV2 -and -not $IsLegacyV1) {
    throw "Unsupported snapshot format."
}
if ($IsLegacyV1 -and -not $AllowUnauthenticatedLegacySnapshot) {
    throw "Unauthenticated v1 snapshots are refused by default. Use -AllowUnauthenticatedLegacySnapshot only under an approved legacy recovery procedure."
}
$AllowedManifestProperties = @(
    "format", "created_at", "instance_name", "service_id", "mine_id",
    "state_root_id", "files", "integrity_note"
)
if ($IsAuthenticatedV2) {
    $AllowedManifestProperties += @("hmac_algorithm", "hmac_key_id", "hmac_sha256")
}
$ActualManifestProperties = @($Manifest.PSObject.Properties.Name)
$RequiredManifestProperties = @(
    "format", "created_at", "instance_name", "service_id", "mine_id", "files",
    "integrity_note"
)
if ($IsAuthenticatedV2) {
    $RequiredManifestProperties += @(
        "state_root_id", "hmac_algorithm", "hmac_key_id", "hmac_sha256"
    )
}
foreach ($RequiredName in $RequiredManifestProperties) {
    if ($ActualManifestProperties -notcontains $RequiredName) {
        throw "Snapshot manifest is missing $RequiredName."
    }
}
foreach ($ActualName in $ActualManifestProperties) {
    if ($AllowedManifestProperties -notcontains $ActualName) {
        throw "Snapshot manifest contains an unexpected property: $ActualName"
    }
}
if ([string]$Manifest.instance_name -ne $Context.InstanceName -or
    [string]$Manifest.service_id -ne $Context.ServiceId -or
    [string]$Manifest.mine_id -ne $Context.MineId) {
    throw "Snapshot identity does not match the selected Agent instance and mine."
}
if ($IsAuthenticatedV2 -and (
        [string]$Manifest.integrity_note -ne
            "Authenticated by the separate per-instance snapshot key." -or
        [string]$Manifest.hmac_algorithm -ne "HMAC-SHA256" -or
        [string]$Manifest.hmac_key_id -notmatch '^[A-Fa-f0-9]{64}$' -or
        [string]$Manifest.hmac_sha256 -notmatch '^[A-Fa-f0-9]{64}$'
    )) {
    throw "Authenticated snapshot metadata is invalid."
}
if ($IsLegacyV1 -and
    -not ([string]$Manifest.integrity_note).Contains("not an authenticity signature")) {
    throw "Legacy snapshot authenticity warning is missing."
}
$CreatedAt = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse([string]$Manifest.created_at, [ref]$CreatedAt)) {
    throw "Snapshot manifest created_at is invalid."
}
if ($ActualManifestProperties -contains "state_root_id") {
    $SnapshotRootId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$Manifest.state_root_id, [ref]$SnapshotRootId) -or
        $SnapshotRootId -eq [Guid]::Empty) {
        throw "Snapshot state_root_id is invalid."
    }
}
if ($Manifest.files -isnot [Array]) {
    throw "Snapshot manifest files must be an array."
}
$ManifestEntries = @($Manifest.files)
if ($ManifestEntries.Count -lt 2 -or $ManifestEntries.Count -gt $MaximumSnapshotFiles) {
    throw "Snapshot manifest file count is outside the safety limit."
}
$Expected = @{}
$DeclaredTotalBytes = 0L
foreach ($Entry in $ManifestEntries) {
    Assert-EAExactProperties -Object $Entry -Expected @("path", "bytes", "sha256") `
        -Context "Snapshot file entry"
    $Relative = [string]$Entry.path
    $RelativeParts = $Relative -split '[\\/]'
    if ([string]::IsNullOrWhiteSpace($Relative) -or
        [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains(":") -or
        $RelativeParts -contains "." -or $RelativeParts -contains ".." -or
        $RelativeParts -contains "") {
        throw "Snapshot manifest contains an unsafe relative path."
    }
    $DeclaredBytes = 0L
    if (-not [long]::TryParse([string]$Entry.bytes, [ref]$DeclaredBytes) -or
        $DeclaredBytes -lt 0 -or $DeclaredBytes -gt $MaximumSnapshotFileBytes) {
        throw "Snapshot manifest contains an invalid byte length: $Relative"
    }
    $DeclaredTotalBytes += $DeclaredBytes
    if ($DeclaredTotalBytes -gt $MaximumSnapshotTotalBytes) {
        throw "Snapshot exceeds the total size limit."
    }
    $DeclaredSha = [string]$Entry.sha256
    if ($DeclaredSha -notmatch '^[A-Fa-f0-9]{64}$' -or $Expected.ContainsKey($Relative)) {
        throw "Snapshot manifest contains an invalid hash or duplicate path: $Relative"
    }
    $Expected[$Relative] = $Entry
}
if ($IsAuthenticatedV2) {
    $SnapshotAuthenticationKey = Get-EASnapshotAuthenticationKey -Context $Context `
        -KeyPath $EffectiveKeyPath
    $LocalKeyId = Get-EASnapshotKeyId -Key $SnapshotAuthenticationKey
    if (-not (Test-EAFixedTimeHexEquals -Left $LocalKeyId `
            -Right ([string]$Manifest.hmac_key_id))) {
        throw "Snapshot was authenticated by a different snapshot key. Restore the escrowed key for this instance."
    }
    $ExpectedHmac = Get-EASnapshotHmacSha256 -Key $SnapshotAuthenticationKey `
        -Manifest $Manifest
    if (-not (Test-EAFixedTimeHexEquals -Left $ExpectedHmac `
            -Right ([string]$Manifest.hmac_sha256))) {
        throw "Snapshot HMAC-SHA256 authentication failed."
    }
}

$SnapshotDirectories = @(Get-ChildItem -LiteralPath $SnapshotPath -Directory -Force -Recurse)
$SnapshotQuarantine = Join-Path $SnapshotPath "five-quantity-quarantine"
foreach ($Directory in $SnapshotDirectories) {
    if (-not $Directory.FullName.Equals(
            $SnapshotQuarantine, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Snapshot contains an unexpected directory: $($Directory.FullName)"
    }
}
if (-not (Test-Path -LiteralPath $SnapshotQuarantine -PathType Container)) {
    throw "Snapshot quarantine directory is missing."
}
$Actual = @{}
foreach ($File in Get-ChildItem -LiteralPath $SnapshotPath -File -Recurse -Force) {
    $Relative = $File.FullName.Substring($SnapshotPath.Length).TrimStart('\')
    if ($Relative -eq "snapshot.json") { continue }
    if ($Actual.ContainsKey($Relative)) {
        throw "Snapshot contains a duplicate relative path: $Relative"
    }
    $Actual[$Relative] = $File
}
if ($Expected.Count -ne $Actual.Count) {
    throw "Snapshot file set does not match its manifest."
}
foreach ($Relative in $Expected.Keys) {
    if (-not $Actual.ContainsKey($Relative)) {
        throw "Snapshot file is missing: $Relative"
    }
    $File = $Actual[$Relative]
    $Entry = $Expected[$Relative]
    if ([long]$File.Length -ne [long]$Entry.bytes -or
        (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ne ([string]$Entry.sha256).ToLowerInvariant()) {
        throw "Snapshot file size or SHA-256 mismatch: $Relative"
    }
}
$SnapshotDatabase = Join-Path $SnapshotPath "enterprise-agent.db"
if (-not (Test-Path -LiteralPath $SnapshotDatabase -PathType Leaf)) {
    throw "Snapshot database is missing."
}

$ServiceContext = Get-EAServiceContext -Context $Context
if ($null -ne $ServiceContext -and $ServiceContext.Service.Status -ne "Stopped") {
    throw "Restore refuses an online service. Stop $($Context.ServiceId) first."
}
Assert-EANoInstanceProcesses -Context $Context
if ($IsLegacyV1) {
    Write-Warning "The explicit legacy override accepts checksums without cryptographic source authentication."
}
$TransactionParent = Resolve-EASafeLocalPath -Name "Restore transaction parent" `
    -PathValue (Join-Path $Context.BackupDirectory "restore-transactions")
$RollbackParent = Resolve-EASafeLocalPath -Name "Restore rollback parent" `
    -PathValue (Join-Path $Context.BackupDirectory "restore-rollbacks")

if ($PSCmdlet.ShouldProcess(
        $Context.InstanceName, "restore Agent database and quarantine evidence"
    )) {
    # No directory creation, copy, move or other mutation occurs before ShouldProcess.
    $ServiceContext = Get-EAServiceContext -Context $Context
    if ($null -ne $ServiceContext -and $ServiceContext.Service.Status -ne "Stopped") {
        throw "Service state changed during validation; restore aborted."
    }
    Assert-EANoInstanceProcesses -Context $Context
    $TransactionId = [Guid]::NewGuid().ToString("N")
    $TransactionRoot = Join-Path $TransactionParent $TransactionId
    $RollbackRoot = Join-Path $RollbackParent (
        [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ-") + $TransactionId
    )
    $StagedQuarantine = Join-Path $TransactionRoot "staged-quarantine"
    $OldQuarantine = Join-Path $TransactionRoot "pre-restore-quarantine"
    $CurrentQuarantine = Join-Path $Context.DataDirectory "five-quantity-quarantine"
    $PreRestoreDatabase = Join-Path $TransactionRoot "pre-restore-live-database.db"
    $FailedRestoredDatabase = Join-Path $TransactionRoot "failed-restored-database.db"
    $FailedRestoredQuarantine = Join-Path $TransactionRoot `
        "failed-restored-quarantine"
    $RecoveryMarkerPath = Get-EARestoreRecoveryBlockPath -Context $Context
    $RecoveryMaterialRoot = $TransactionRoot
    $OldQuarantineMoved = $false
    $NewQuarantinePublished = $false
    $DatabaseSwitchAttempted = $false
    $Committed = $false
    New-Item -ItemType Directory -Path $TransactionParent -Force | Out-Null
    [void](Resolve-EASafeLocalPath -Name "Restore transaction parent" `
        -PathValue $TransactionParent -MustExist -RequiredType Container)
    New-Item -ItemType Directory -Path $TransactionRoot | Out-Null
    New-Item -ItemType Directory -Path $StagedQuarantine | Out-Null
    Set-EACanonicalInheritedTreeAcl -Root $TransactionRoot `
        -Name "Agent restore transaction" -RootGrants @(
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F"
        )
    foreach ($EvidenceFile in Get-ChildItem -LiteralPath $SnapshotQuarantine -File -Force) {
        Copy-Item -LiteralPath $EvidenceFile.FullName -Destination $StagedQuarantine
    }
    $HadLiveDatabase = Test-Path -LiteralPath $Context.DatabasePath -PathType Leaf
    if ($HadLiveDatabase) {
        Assert-EAOrdinaryLeaf -Path $Context.DatabasePath -Name "Live Agent database" `
            -MaximumBytes 32GB
        Copy-Item -LiteralPath $Context.DatabasePath -Destination $PreRestoreDatabase
        foreach ($Suffix in @("-wal", "-shm")) {
            $LiveSidecar = "$($Context.DatabasePath)$Suffix"
            if (Test-Path -LiteralPath $LiveSidecar) {
                Assert-EAOrdinaryLeaf -Path $LiveSidecar `
                    -Name "Live Agent database sidecar" -MaximumBytes 32GB
                Copy-Item -LiteralPath $LiveSidecar `
                    -Destination "$PreRestoreDatabase$Suffix"
            }
        }
    }
    elseif (Test-Path -LiteralPath $Context.DatabasePath) {
        throw "Live Agent database path is not an ordinary file."
    }
    $HadLiveQuarantine = Test-Path -LiteralPath $CurrentQuarantine -PathType Container
    if (-not $HadLiveQuarantine -and (Test-Path -LiteralPath $CurrentQuarantine)) {
        throw "Live quarantine path is not a directory."
    }
    $RecoveryDocument = [ordered]@{
        format = "mineguard-enterprise-agent-restore-recovery-block-v1"
        created_utc = [DateTime]::UtcNow.ToString("o")
        instance_name = $Context.InstanceName
        service_id = $Context.ServiceId
        transaction_id = $TransactionId
        live_database = $Context.DatabasePath
        live_quarantine = $CurrentQuarantine
        had_live_database = [bool]$HadLiveDatabase
        had_live_quarantine = [bool]$HadLiveQuarantine
        candidate_material_roots = @($TransactionRoot, $RollbackRoot)
        pre_restore_database_relative = "pre-restore-live-database.db"
        pre_restore_quarantine_relative = "pre-restore-quarantine"
        failed_restored_database_relative = "failed-restored-database.db"
        failed_restored_quarantine_relative = "failed-restored-quarantine"
        pre_restore_database_candidates = @(
            (Join-Path $TransactionRoot "pre-restore-live-database.db"),
            (Join-Path $RollbackRoot "pre-restore-live-database.db")
        )
        pre_restore_quarantine_candidates = @(
            (Join-Path $TransactionRoot "pre-restore-quarantine"),
            (Join-Path $RollbackRoot "pre-restore-quarantine")
        )
        instructions = @(
            "Keep the Windows service stopped.",
            "Use the first existing candidate_material_roots directory.",
            "Preserve failed-restored-* evidence before replacing live paths.",
            "Restore the pre-restore database generation and quarantine paths exactly.",
            "Repair canonical instance ACLs and verify mine/database identity.",
            "Delete this marker only after administrator verification, then run health checks."
        )
    }
    # Publish a protected fail-close marker before the first live rename. A
    # process crash or power loss can therefore never make Start/Restore treat
    # a partially switched database/quarantine pair as a normal instance.
    Write-EAProtectedRestoreRecoveryBlock -PathValue $RecoveryMarkerPath `
        -Document $RecoveryDocument -Context $Context
    try {
        Assert-EANoInstanceProcesses -Context $Context
        if ($HadLiveQuarantine) {
            Assert-EAOrdinaryTree -Root $CurrentQuarantine -Name "Live quarantine"
            Move-Item -LiteralPath $CurrentQuarantine -Destination $OldQuarantine
            $OldQuarantineMoved = $true
        }
        Move-Item -LiteralPath $StagedQuarantine -Destination $CurrentQuarantine
        $NewQuarantinePublished = $true
        $DatabaseSwitchAttempted = $true
        $PreviousRestoreTransaction = $env:MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID
        try {
            $env:MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID = $TransactionId
            Invoke-NativeChecked -FilePath $Context.Executable -ArgumentList @(
                "--env-file", $Context.ConfigPath, "--authoritative-env-file",
                "--db", $Context.DatabasePath,
                "database-restore", "--input", $SnapshotDatabase,
                "--rollback-directory", (Join-Path $TransactionRoot "database"),
                "--yes-service-stopped"
            )
        }
        finally {
            if ($null -eq $PreviousRestoreTransaction) {
                Remove-Item Env:MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID `
                    -ErrorAction SilentlyContinue
            }
            else {
                $env:MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID = `
                    $PreviousRestoreTransaction
            }
        }
        Invoke-EARestoreFaultInjection -Point "after-database-restore"
        # Snapshot material is deliberately staged under an administrators-only
        # ACL. Reapply the per-instance service SID after it becomes live so no
        # restored database/evidence file retains that staging ACL.
        Set-EAInstanceCanonicalAcl -Context $Context
        Invoke-EARestoreFaultInjection -Point "after-acl-repair"
        New-Item -ItemType Directory -Path $RollbackParent -Force | Out-Null
        [void](Resolve-EASafeLocalPath -Name "Restore rollback parent" `
            -PathValue $RollbackParent -MustExist -RequiredType Container)
        Move-Item -LiteralPath $TransactionRoot -Destination $RollbackRoot
        $RecoveryMaterialRoot = $RollbackRoot
        Invoke-EARestoreFaultInjection -Point "after-rollback-publish"
        Assert-EARestoreRecoveryBlockAcl -Context $Context `
            -Path $RecoveryMarkerPath
        Remove-Item -LiteralPath $RecoveryMarkerPath -Force
        $Committed = $true
    }
    catch {
        $OriginalError = $_
        $RollbackErrors = [System.Collections.Generic.List[string]]::new()
        if ($DatabaseSwitchAttempted) {
            try {
                $FailedRestoredDatabase = Join-Path $RecoveryMaterialRoot `
                    "failed-restored-database.db"
                if (Test-Path -LiteralPath $Context.DatabasePath -PathType Leaf) {
                    Move-Item -LiteralPath $Context.DatabasePath `
                        -Destination $FailedRestoredDatabase
                }
                foreach ($Suffix in @("-wal", "-shm")) {
                    $LiveSidecar = "$($Context.DatabasePath)$Suffix"
                    if (Test-Path -LiteralPath $LiveSidecar -PathType Leaf) {
                        Move-Item -LiteralPath $LiveSidecar `
                            -Destination "$FailedRestoredDatabase$Suffix"
                    }
                }
                if ($HadLiveDatabase) {
                    $PreRestoreDatabase = Join-Path $RecoveryMaterialRoot `
                        "pre-restore-live-database.db"
                    if (-not (Test-Path -LiteralPath $PreRestoreDatabase -PathType Leaf)) {
                        throw "Pre-restore raw database is missing: $PreRestoreDatabase"
                    }
                    Copy-Item -LiteralPath $PreRestoreDatabase `
                        -Destination $Context.DatabasePath
                    foreach ($Suffix in @("-wal", "-shm")) {
                        $SavedSidecar = "$PreRestoreDatabase$Suffix"
                        if (Test-Path -LiteralPath $SavedSidecar -PathType Leaf) {
                            Copy-Item -LiteralPath $SavedSidecar `
                                -Destination "$($Context.DatabasePath)$Suffix"
                        }
                    }
                }
            }
            catch { $RollbackErrors.Add("Database rollback: $($_.Exception.Message)") }
        }
        if ($OldQuarantineMoved -or $NewQuarantinePublished) {
            try {
                $FailedRestoredQuarantine = Join-Path $RecoveryMaterialRoot `
                    "failed-restored-quarantine"
                if ($NewQuarantinePublished -and
                    (Test-Path -LiteralPath $CurrentQuarantine -PathType Container)) {
                    Move-Item -LiteralPath $CurrentQuarantine `
                        -Destination $FailedRestoredQuarantine
                }
                if ($OldQuarantineMoved) {
                    $OldQuarantine = Join-Path $RecoveryMaterialRoot `
                        "pre-restore-quarantine"
                    if (-not (Test-Path -LiteralPath $OldQuarantine -PathType Container)) {
                        throw "Pre-restore quarantine is missing: $OldQuarantine"
                    }
                    Move-Item -LiteralPath $OldQuarantine `
                        -Destination $CurrentQuarantine
                }
            }
            catch { $RollbackErrors.Add("Quarantine rollback: $($_.Exception.Message)") }
        }
        try { Set-EAInstanceCanonicalAcl -Context $Context }
        catch { $RollbackErrors.Add("Instance ACL rollback: $($_.Exception.Message)") }
        if ($RollbackErrors.Count -eq 0) {
            try {
                Assert-EARestoreRecoveryBlockAcl -Context $Context `
                    -Path $RecoveryMarkerPath
                Remove-Item -LiteralPath $RecoveryMarkerPath -Force
            }
            catch { $RollbackErrors.Add("Recovery marker removal: $($_.Exception.Message)") }
        }
        if ($RollbackErrors.Count -eq 0) {
            if ($RecoveryMaterialRoot.Equals(
                    $TransactionRoot, [StringComparison]::OrdinalIgnoreCase
                ) -and (Test-Path -LiteralPath $TransactionRoot -PathType Container)) {
                try {
                    New-Item -ItemType Directory -Path $RollbackParent -Force | Out-Null
                    $FailureRoot = "$RollbackRoot-failed"
                    Move-Item -LiteralPath $TransactionRoot -Destination $FailureRoot
                    Write-Warning "Failed restore material was preserved at $FailureRoot"
                }
                catch {
                    Write-Warning "Could not publish cleanly rolled-back restore material: $($_.Exception.Message)"
                }
            }
            throw $OriginalError
        }
        $FailureDetailsPath = Join-Path $RecoveryMaterialRoot `
            "RECOVERY-FAILURE.txt"
        try {
            $FailureText = (
                "Original restore error: " + $OriginalError.Exception.Message + "`r`n" +
                "Automatic rollback errors:`r`n- " +
                ($RollbackErrors.ToArray() -join "`r`n- ") + "`r`n"
            )
            [IO.File]::WriteAllText(
                $FailureDetailsPath, $FailureText,
                (New-Object System.Text.UTF8Encoding($false))
            )
            Invoke-EAIcaclsChecked -ArgumentList @(
                $FailureDetailsPath, "/inheritance:r"
            )
            Invoke-EAIcaclsChecked -ArgumentList @(
                $FailureDetailsPath,
                "/grant:r", "*S-1-5-18:F",
                "/grant:r", "*S-1-5-32-544:F"
            )
        }
        catch {
            Write-Warning "Could not write recovery failure details: $($_.Exception.Message)"
        }
        throw (
            "Restore failed before commit and automatic rollback was incomplete. " +
            "The instance is fail-closed by $RecoveryMarkerPath. Recovery material: " +
            "$RecoveryMaterialRoot. Errors: " +
            ($RollbackErrors.ToArray() -join "; ")
        )
    }
    if (-not $Committed) {
        throw "Restore transaction ended without an explicit commit."
    }
    Write-Host "Agent state restored. Rollback material: $RollbackRoot"
    if ($StartAfterRestore) {
        $RestartContext = Get-EAServiceContext -Context $Context
        if ($null -eq $RestartContext) {
            throw "Restore succeeded, but Windows service is not installed. Start manually."
        }
        Start-Service -Name $Context.ServiceId
        (Get-Service -Name $Context.ServiceId).WaitForStatus(
            "Running", [TimeSpan]::FromSeconds(30)
        )
        Write-Host "Windows service started: $($Context.ServiceId)"
    }
}
