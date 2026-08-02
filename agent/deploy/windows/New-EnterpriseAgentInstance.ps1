[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][string]$MineId,
    [Parameter(Mandatory = $true)][string]$MineName,
    [Parameter(Mandatory = $true)][string]$OperatorId,
    [Parameter(Mandatory = $true)][string]$OperatorName,
    [Parameter(Mandatory = $true)][string]$SystemId,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string[]]$WatchDirectories = @(),
    [switch]$GrantWatchReadAcl,
    [switch]$SkipAcl
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$SafetyHelper = Join-Path $PSScriptRoot "EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $SafetyHelper -PathType Leaf)) {
    throw "Windows safety helper is missing: $SafetyHelper"
}
. $SafetyHelper
Assert-EAPowerShell51

if (-not $SkipAcl) {
    $Principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )) {
        throw "Run in an elevated Administrator PowerShell, or use -SkipAcl only for local development."
    }
}

function Assert-EnvironmentValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "$Name must be non-empty and contain no control characters."
    }
}

function Assert-ContractIdentifier {
    param([string]$Name, [string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "$Name must match the V2 identifier format and be at most 128 characters."
    }
}

function Assert-DisplayName {
    param([string]$Name, [string]$Value)
    Assert-EnvironmentValue -Name $Name -Value $Value
    if ($Value.Length -gt 256) { throw "$Name must be at most 256 characters." }
}

function Assert-SafeWatchAclTarget {
    param([string]$WatchRoot, [string]$ApplicationRoot, [string]$InstancesRoot)
    foreach ($ProductRoot in @($ApplicationRoot, $InstancesRoot)) {
        if ((Test-EAPathWithin -Candidate $WatchRoot -Parent $ProductRoot) -or
            (Test-EAPathWithin -Candidate $ProductRoot -Parent $WatchRoot)) {
            throw "Custom watch ACL target must not overlap InstallRoot or StateRoot: $WatchRoot"
        }
    }
    $ProtectedRoots = @(
        $env:SystemRoot, $env:ProgramData, $env:ALLUSERSPROFILE,
        $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:PUBLIC
    )
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $ProtectedRoots += Join-Path $env:SystemDrive "Users"
    }
    foreach ($ProtectedCandidate in @($ProtectedRoots | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })) {
        $Protected = [IO.Path]::GetFullPath([string]$ProtectedCandidate).TrimEnd('\')
        if ((Test-EAPathWithin -Candidate $WatchRoot -Parent $Protected) -or
            (Test-EAPathWithin -Candidate $Protected -Parent $WatchRoot)) {
            throw "Custom watch ACL target is too broad or system-managed: $WatchRoot"
        }
    }
}

Assert-EAInstanceName -Value $InstanceName
Assert-ContractIdentifier -Name "MineId" -Value $MineId
Assert-DisplayName -Name "MineName" -Value $MineName
Assert-ContractIdentifier -Name "OperatorId" -Value $OperatorId
Assert-DisplayName -Name "OperatorName" -Value $OperatorName
Assert-ContractIdentifier -Name "SystemId" -Value $SystemId

# Raw X:\ path validation intentionally precedes GetFullPath normalization.
$InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" -PathValue $InstallRoot `
    -MustExist -RequiredType Container
$StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" -PathValue $StateRoot `
    -MustExist -RequiredType Container
[void](Assert-EAStateRootMarker -StateRoot $StateRoot)
$AgentExecutable = Get-EAAgentExecutable -InstallRoot $InstallRoot
$Template = Resolve-EASafeLocalPath -Name "Instance template" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\agent.env.template") `
    -MustExist -RequiredType Leaf
Assert-EAOrdinaryLeaf -Path $Template -Name "Instance template" -MaximumBytes 1MB

$InstanceRoot = Join-Path $StateRoot $InstanceName
if (Test-Path -LiteralPath $InstanceRoot) {
    throw "Instance already exists: $InstanceRoot"
}
foreach ($ExistingDirectory in Get-ChildItem -LiteralPath $StateRoot -Directory -Force) {
    if ($ExistingDirectory.Name.StartsWith(".instance-staging-")) { continue }
    if ($ExistingDirectory.Name -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "StateRoot contains an unrecognized instance directory: $($ExistingDirectory.FullName)"
    }
    $ExistingContext = Get-EAInstanceContext -InstanceName $ExistingDirectory.Name `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    if ($ExistingContext.Port -eq $Port) {
        throw "Port $Port is already assigned by $($ExistingContext.InstanceName)."
    }
}

$UsingDefaultInbox = $WatchDirectories.Count -eq 0
$ResolvedWatchDirectories = @()
if (-not $UsingDefaultInbox) {
    foreach ($WatchDirectory in $WatchDirectories) {
        if ([string]::IsNullOrWhiteSpace($WatchDirectory) -or
            $WatchDirectory.Contains(";")) {
            throw "Watch directory must be non-empty and cannot contain a semicolon."
        }
        $ResolvedWatch = Resolve-EASafeLocalPath -Name "Watch directory" `
            -PathValue $WatchDirectory -MustExist -RequiredType Container -CheckTree
        foreach ($ExistingWatch in $ResolvedWatchDirectories) {
            if ((Test-EAPathWithin -Candidate $ResolvedWatch -Parent $ExistingWatch) -or
                (Test-EAPathWithin -Candidate $ExistingWatch -Parent $ResolvedWatch)) {
                throw "Watch directories must be unique and non-overlapping: $ResolvedWatch"
            }
        }
        Assert-SafeWatchAclTarget -WatchRoot $ResolvedWatch `
            -ApplicationRoot $InstallRoot -InstancesRoot $StateRoot
        $ResolvedWatchDirectories += $ResolvedWatch
    }
}

$StageRoot = Join-Path $StateRoot (".instance-staging-" + [Guid]::NewGuid().ToString("N"))
$Published = $false
$ExternalAclBackups = @{}
try {
    New-Item -ItemType Directory -Path $StageRoot -ErrorAction Stop | Out-Null
    $StageConfigDirectory = Join-Path $StageRoot "config"
    $StageDataDirectory = Join-Path $StageRoot "data"
    $StageLogDirectory = Join-Path $StageRoot "logs"
    $StageBackupDirectory = Join-Path $StageRoot "backups"
    $StageInboxDirectory = Join-Path $StageRoot "inbox"
    $StageServiceDirectory = Join-Path $StageRoot "service"
    foreach ($Directory in @(
        $StageConfigDirectory, $StageDataDirectory, $StageLogDirectory,
        $StageBackupDirectory, $StageInboxDirectory, $StageServiceDirectory
    )) {
        New-Item -ItemType Directory -Path $Directory | Out-Null
    }

    $FinalConfigPath = Join-Path $InstanceRoot "config\agent.env"
    $FinalDatabasePath = Join-Path $InstanceRoot "data\enterprise-agent.db"
    if ($UsingDefaultInbox) {
        $ResolvedWatchDirectories = @(Join-Path $InstanceRoot "inbox")
    }
    $Content = [IO.File]::ReadAllText($Template)
    $Replacements = @{
        "__DATABASE_PATH__" = $FinalDatabasePath
        "__PORT__" = $Port.ToString()
        "__MINE_ID__" = $MineId
        "__MINE_NAME__" = $MineName
        "__OPERATOR_ID__" = $OperatorId
        "__OPERATOR_NAME__" = $OperatorName
        "__SYSTEM_ID__" = $SystemId
        "__WATCH_DIRECTORIES__" = ($ResolvedWatchDirectories -join ";")
    }
    foreach ($Entry in $Replacements.GetEnumerator()) {
        $Content = $Content.Replace([string]$Entry.Key, [string]$Entry.Value)
    }
    if ($Content -match '__[A-Z0-9_]+__') {
        throw "Instance template contains an unresolved placeholder."
    }
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $StageConfigPath = Join-Path $StageConfigDirectory "agent.env"
    [IO.File]::WriteAllText($StageConfigPath, $Content, $Utf8NoBom)
    [void](Read-EAEnvironmentFile -Path $StageConfigPath)

    $ServiceId = "MineGuardEnterpriseAgent-$InstanceName"
    $Metadata = [ordered]@{
        format = "mineguard-enterprise-agent-windows-instance-v1"
        instance_name = $InstanceName
        service_id = $ServiceId
        port = $Port
        mine_id = $MineId
        system_id = $SystemId
        config_path = $FinalConfigPath
        database_path = $FinalDatabasePath
        acl_hardened = (-not $SkipAcl.IsPresent)
    }
    [IO.File]::WriteAllText(
        (Join-Path $StageRoot "instance.json"),
        (($Metadata | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
        $Utf8NoBom
    )

    if (-not $SkipAcl) {
        Invoke-EAIcaclsChecked -ArgumentList @($StageRoot, "/inheritance:r")
        Invoke-EAIcaclsChecked -ArgumentList @(
            $StageRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX", "/T", "/C"
        )
        foreach ($Writable in @($StageDataDirectory, $StageLogDirectory)) {
            Invoke-EAIcaclsChecked -ArgumentList @(
                $Writable, "/grant:r", "*S-1-5-19:(OI)(CI)M", "/T", "/C"
            )
        }
        Invoke-EAIcaclsChecked -ArgumentList @($StageBackupDirectory, "/inheritance:r")
        Invoke-EAIcaclsChecked -ArgumentList @(
            $StageBackupDirectory, "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F", "/T", "/C"
        )
        if (-not $UsingDefaultInbox -and $GrantWatchReadAcl) {
            foreach ($WatchDirectory in $ResolvedWatchDirectories) {
                $ExternalAclBackups[$WatchDirectory] = Get-Acl -LiteralPath $WatchDirectory
                # Set one inheritable read ACE on the dedicated root. Do not recursively
                # rewrite vendor files or protected child ACLs.
                Invoke-EAIcaclsChecked -ArgumentList @(
                    $WatchDirectory, "/grant", "*S-1-5-19:(OI)(CI)RX"
                )
            }
        }
        elseif (-not $UsingDefaultInbox) {
            Write-Warning "Custom watch directories were not modified. Grant LocalService read access through the directory owner."
        }
    }
    else {
        Write-Warning "ACL hardening was skipped. Do not use this instance in production."
    }

    Assert-EAOrdinaryTree -Root $StageRoot -Name "Staged instance"
    Move-Item -LiteralPath $StageRoot -Destination $InstanceRoot
    $CreatedContext = Get-EAInstanceContext -InstanceName $InstanceName `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    $Published = $true
    Write-Host "Enterprise Agent instance created: $InstanceName"
    Write-Host "Config: $($CreatedContext.ConfigPath)"
    Write-Host "Database: $($CreatedContext.DatabasePath)"
    Write-Host "Port: $Port"
    Write-Host "Edit the ACL-protected config, then run Start-EnterpriseAgent.ps1."
}
catch {
    $OriginalError = $_
    if (-not $Published) {
        if ((Test-Path -LiteralPath $InstanceRoot -PathType Container) -and
            -not (Test-Path -LiteralPath $StageRoot)) {
            try { Move-Item -LiteralPath $InstanceRoot -Destination $StageRoot }
            catch { Write-Warning "Could not retract the unpublished instance: $($_.Exception.Message)" }
        }
        foreach ($WatchDirectory in $ExternalAclBackups.Keys) {
            try { Set-Acl -LiteralPath $WatchDirectory -AclObject $ExternalAclBackups[$WatchDirectory] }
            catch { Write-Warning "Could not restore watch ACL on $WatchDirectory: $($_.Exception.Message)" }
        }
        if (Test-Path -LiteralPath $StageRoot) {
            try {
                Remove-EAOwnedTemporaryTree -Path $StageRoot `
                    -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
            }
            catch { Write-Warning "Could not remove failed staging directory: $($_.Exception.Message)" }
        }
    }
    throw $OriginalError
}
