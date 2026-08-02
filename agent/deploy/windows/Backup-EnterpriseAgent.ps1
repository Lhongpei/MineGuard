[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string]$DestinationRoot = "",
    [switch]$LeaveStopped
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

if ($InstanceName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
    throw "Invalid InstanceName."
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$InstanceRoot = Join-Path $StateRoot $InstanceName
$MetadataPath = Join-Path $InstanceRoot "instance.json"
$ConfigPath = Join-Path (Join-Path $InstanceRoot "config") "agent.env"
$Executable = Join-Path $InstallRoot "runtime\.venv\Scripts\enterprise-agent.exe"
foreach ($Required in @($MetadataPath, $ConfigPath, $Executable)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required file is missing: $Required"
    }
}
$Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$DatabasePath = [IO.Path]::GetFullPath([string]$Metadata.database_path)
$DataDirectory = Split-Path -Parent $DatabasePath
$QuarantineDirectory = Join-Path $DataDirectory "five-quantity-quarantine"
if (-not $DestinationRoot) {
    $DestinationRoot = Join-Path $InstanceRoot "backups"
}
$DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
$DataPrefix = $DataDirectory.TrimEnd('\') + '\'
if ($DestinationRoot.Equals($DataDirectory, [StringComparison]::OrdinalIgnoreCase) -or
    $DestinationRoot.StartsWith($DataPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Backup destination must not be inside the live data directory."
}
New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null

$ServiceId = [string]$Metadata.service_id
$Port = [int]$Metadata.port
$Service = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
$WasRunning = $null -ne $Service -and $Service.Status -ne "Stopped"
if ($WasRunning) {
    try {
        Stop-Service -Name $ServiceId -Force
        (Get-Service -Name $ServiceId).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    catch {
        $CurrentService = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
        if ($null -ne $CurrentService -and $CurrentService.Status -eq "Stopped") {
            Start-Service -Name $ServiceId
        }
        throw
    }
}
elseif (Test-AgentEndpoint -Port $Port) {
    throw "A foreground Agent is using this instance. Stop it before a complete state backup."
}

$Timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$SnapshotName = "$InstanceName-$Timestamp"
$FinalSnapshot = Join-Path $DestinationRoot $SnapshotName
$TemporarySnapshot = Join-Path $DestinationRoot (".incomplete-" + [Guid]::NewGuid().ToString("N"))
$Completed = $false
try {
    New-Item -ItemType Directory -Path $TemporarySnapshot | Out-Null
    $SnapshotDatabase = Join-Path $TemporarySnapshot "enterprise-agent.db"
    Invoke-NativeChecked -FilePath $Executable -ArgumentList @(
        "--env-file", $ConfigPath, "--db", $DatabasePath,
        "database-backup", "--output", $SnapshotDatabase
    )
    $SnapshotQuarantine = Join-Path $TemporarySnapshot "five-quantity-quarantine"
    if (Test-Path -LiteralPath $QuarantineDirectory -PathType Container) {
        $QuarantineItem = Get-Item -LiteralPath $QuarantineDirectory -Force
        if (($QuarantineItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Live quarantine directory cannot be a reparse point."
        }
        New-Item -ItemType Directory -Path $SnapshotQuarantine | Out-Null
        foreach ($EvidenceFile in Get-ChildItem -LiteralPath $QuarantineDirectory -Force) {
            if ($EvidenceFile.PSIsContainer -or (($EvidenceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "Quarantine must contain only ordinary evidence files: $($EvidenceFile.FullName)"
            }
            Copy-Item -LiteralPath $EvidenceFile.FullName -Destination $SnapshotQuarantine
        }
    }
    else {
        New-Item -ItemType Directory -Path $SnapshotQuarantine | Out-Null
    }

    $Files = @()
    foreach ($File in Get-ChildItem -LiteralPath $TemporarySnapshot -File -Recurse | Sort-Object FullName) {
        $Relative = $File.FullName.Substring($TemporarySnapshot.Length).TrimStart('\')
        $Files += [ordered]@{
            path = $Relative
            bytes = [long]$File.Length
            sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $SnapshotManifest = [ordered]@{
        format = "mineguard-enterprise-agent-state-snapshot-v1"
        created_at = [DateTime]::UtcNow.ToString("o")
        instance_name = $InstanceName
        service_id = $ServiceId
        mine_id = [string]$Metadata.mine_id
        files = $Files
        integrity_note = "SHA-256 detects corruption but is not an authenticity signature."
    }
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        (Join-Path $TemporarySnapshot "snapshot.json"),
        (($SnapshotManifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        $Utf8NoBom
    )
    if (Test-Path -LiteralPath $FinalSnapshot) {
        throw "Snapshot target already exists: $FinalSnapshot"
    }
    Move-Item -LiteralPath $TemporarySnapshot -Destination $FinalSnapshot
    $Completed = $true
    Write-Host "Complete Agent state snapshot created: $FinalSnapshot"
    Write-Host "Copy this snapshot to protected independent storage. SHA-256 is not proof of authenticity."
}
finally {
    if (-not $Completed -and (Test-Path -LiteralPath $TemporarySnapshot)) {
        Remove-Item -LiteralPath $TemporarySnapshot -Recurse -Force
    }
    if ($WasRunning -and -not $LeaveStopped) {
        Start-Service -Name $ServiceId
        (Get-Service -Name $ServiceId).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
    }
}
