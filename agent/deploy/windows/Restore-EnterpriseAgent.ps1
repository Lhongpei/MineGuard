[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$SnapshotPath,
    [Parameter(Mandatory = $true)][switch]$ConfirmRestore,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$StartAfterRestore
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function Test-AgentEndpoint {
    param([int]$Port)
    try {
        $Response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/health" -UseBasicParsing -TimeoutSec 2
        return [int]$Response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath"
    }
}

if (-not $ConfirmRestore) {
    throw "Restore requires the explicit -ConfirmRestore switch."
}
if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$SnapshotPath = [IO.Path]::GetFullPath($SnapshotPath)
$InstanceRoot = Join-Path $StateRoot $InstanceName
$MetadataPath = Join-Path $InstanceRoot "instance.json"
$ConfigPath = Join-Path (Join-Path $InstanceRoot "config") "agent.env"
$Executable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
$SnapshotManifestPath = Join-Path $SnapshotPath "snapshot.json"
foreach ($Required in @($MetadataPath, $ConfigPath, $Executable, $SnapshotManifestPath)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required file is missing: $Required"
    }
}
$SnapshotRootItem = Get-Item -LiteralPath $SnapshotPath -Force
$SnapshotManifestItem = Get-Item -LiteralPath $SnapshotManifestPath -Force
if ((($SnapshotRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (($SnapshotManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Snapshot root and manifest must not be symlinks, junctions or reparse points."
}
$SnapshotFiles = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
$PendingDirectories = New-Object 'System.Collections.Generic.Queue[System.IO.DirectoryInfo]'
$PendingDirectories.Enqueue($SnapshotRootItem)
while ($PendingDirectories.Count -gt 0) {
    $CurrentDirectory = $PendingDirectories.Dequeue()
    foreach ($Item in Get-ChildItem -LiteralPath $CurrentDirectory.FullName -Force) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Snapshot must not contain a symlink, junction or reparse point: $($Item.FullName)"
        }
        if ($Item.PSIsContainer) {
            $PendingDirectories.Enqueue($Item)
        }
        else {
            $SnapshotFiles.Add($Item)
        }
    }
}
$Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Manifest = Get-Content -LiteralPath $SnapshotManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Manifest.format -ne "mineguard-enterprise-agent-state-snapshot-v1") {
    throw "Unsupported snapshot format."
}
if ([string]$Manifest.instance_name -ne $InstanceName -or [string]$Manifest.mine_id -ne [string]$Metadata.mine_id) {
    throw "Snapshot belongs to a different Agent instance or mine."
}

$Expected = @{}
foreach ($Entry in $Manifest.files) {
    $Relative = [string]$Entry.path
    $RelativeParts = $Relative -split '[\\/]'
    if ([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative) -or
        $Relative.Contains(":") -or $RelativeParts -contains "." -or $RelativeParts -contains "..") {
        throw "Snapshot manifest contains an unsafe relative path."
    }
    $DeclaredBytes = 0L
    if (-not [long]::TryParse([string]$Entry.bytes, [ref]$DeclaredBytes) -or $DeclaredBytes -lt 0) {
        throw "Snapshot manifest contains an invalid byte length: $Relative"
    }
    $DeclaredSha = [string]$Entry.sha256
    if ($DeclaredSha -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Snapshot manifest contains an invalid SHA-256: $Relative"
    }
    if ($Expected.ContainsKey($Relative)) {
        throw "Snapshot manifest contains a duplicate path: $Relative"
    }
    $Expected[$Relative] = $Entry
}
$Actual = @{}
foreach ($File in $SnapshotFiles) {
    $Relative = $File.FullName.Substring($SnapshotPath.Length).TrimStart('\')
    if ($Relative -eq "snapshot.json") { continue }
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
    if ([long]$File.Length -ne [long]$Entry.bytes) {
        throw "Snapshot file size mismatch: $Relative"
    }
    $Digest = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Digest -ne [string]$Entry.sha256) {
        throw "Snapshot SHA-256 mismatch: $Relative"
    }
}

$ServiceId = [string]$Metadata.service_id
$Service = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if ($null -ne $Service -and $Service.Status -ne "Stopped") {
    throw "Restore refuses an online service. Stop $ServiceId first."
}
if (Test-AgentEndpoint -Port ([int]$Metadata.port)) {
    throw "Restore refuses a running foreground Agent. Stop it first."
}

$DatabasePath = [IO.Path]::GetFullPath([string]$Metadata.database_path)
$DataDirectory = Split-Path -Parent $DatabasePath
$DataPrefix = $DataDirectory.TrimEnd('\') + '\'
if ($SnapshotPath.Equals($DataDirectory, [StringComparison]::OrdinalIgnoreCase) -or
    $SnapshotPath.StartsWith($DataPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Snapshot must not be stored inside the live data directory."
}
$CurrentQuarantine = Join-Path $DataDirectory "five-quantity-quarantine"
$SnapshotDatabase = Join-Path $SnapshotPath "enterprise-agent.db"
$SnapshotQuarantine = Join-Path $SnapshotPath "five-quantity-quarantine"
if (-not (Test-Path -LiteralPath $SnapshotDatabase -PathType Leaf)) {
    throw "Snapshot database is missing."
}
if (-not (Test-Path -LiteralPath $SnapshotQuarantine -PathType Container)) {
    throw "Snapshot quarantine directory is missing."
}
$RestoreTimestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$RollbackRoot = Join-Path (Join-Path $InstanceRoot "backups\restore-rollbacks") $RestoreTimestamp
$StagedQuarantine = Join-Path $DataDirectory (".quarantine-restore-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $RollbackRoot -Force | Out-Null
Copy-Item -LiteralPath $SnapshotQuarantine -Destination $StagedQuarantine -Recurse

if ($PSCmdlet.ShouldProcess($InstanceName, "restore Agent database and quarantine evidence")) {
    $OldQuarantine = Join-Path $RollbackRoot "five-quantity-quarantine"
    $QuarantineSwitched = $false
    try {
        if (Test-Path -LiteralPath $CurrentQuarantine -PathType Container) {
            Move-Item -LiteralPath $CurrentQuarantine -Destination $OldQuarantine
        }
        Move-Item -LiteralPath $StagedQuarantine -Destination $CurrentQuarantine
        $QuarantineSwitched = $true
        Invoke-NativeChecked -FilePath $Executable -ArgumentList @(
            "--env-file", $ConfigPath, "--db", $DatabasePath,
            "database-restore", "--input", $SnapshotDatabase,
            "--rollback-directory", $RollbackRoot, "--yes-service-stopped"
        )
    }
    catch {
        if ($QuarantineSwitched -and (Test-Path -LiteralPath $CurrentQuarantine -PathType Container)) {
            Move-Item -LiteralPath $CurrentQuarantine -Destination (Join-Path $RollbackRoot "failed-restored-quarantine")
        }
        if (Test-Path -LiteralPath $OldQuarantine -PathType Container) {
            Move-Item -LiteralPath $OldQuarantine -Destination $CurrentQuarantine
        }
        throw
    }
    Write-Host "Agent state restored. Rollback material: $RollbackRoot"
    if ($StartAfterRestore) {
        if ($null -eq (Get-Service -Name $ServiceId -ErrorAction SilentlyContinue)) {
            throw "Restore succeeded, but Windows service is not installed. Start manually."
        }
        Start-Service -Name $ServiceId
        (Get-Service -Name $ServiceId).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
        Write-Host "Windows service started: $ServiceId"
    }
}
elseif (Test-Path -LiteralPath $StagedQuarantine -PathType Container) {
    Remove-Item -LiteralPath $StagedQuarantine -Recurse -Force
}
