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
    [string]$ProvisionedEnvironmentFile = "",
    [string]$ProvisioningLockFile = "",
    [string]$ProvisioningSecretStoreFile = "",
    [switch]$SkipAcl,
    [switch]$DevelopmentOnly
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

if ($SkipAcl -and -not $DevelopmentOnly) {
    throw "-SkipAcl requires the explicit -DevelopmentOnly acknowledgement and can never be used for a production instance."
}
if ($DevelopmentOnly -and -not $SkipAcl) {
    throw "-DevelopmentOnly is only valid together with -SkipAcl."
}
if ($SkipAcl -and $GrantWatchReadAcl) {
    throw "-GrantWatchReadAcl cannot be combined with -SkipAcl."
}

$ProvisioningInputs = @(
    $ProvisionedEnvironmentFile,
    $ProvisioningLockFile,
    $ProvisioningSecretStoreFile
)
$ProvisioningInputCount = @($ProvisioningInputs | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_)
}).Count
if ($ProvisioningInputCount -notin @(0, 3)) {
    throw (
        "Provisioned instance creation requires all three prepared files: " +
        "environment, lock and DPAPI secret store."
    )
}
$UsingProvisioningPackage = $ProvisioningInputCount -eq 3
if ($UsingProvisioningPackage -and ($SkipAcl -or $DevelopmentOnly)) {
    throw "Provisioned access packages require the production ACL boundary."
}

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
$ServiceId = "MineGuardEnterpriseAgent-$InstanceName"
$ServiceIdentity = Get-EAServiceIdentity -ServiceId $ServiceId
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
$StateMarker = Assert-EAStateRootMarker -StateRoot $StateRoot
$AgentExecutable = Get-EAAgentExecutable -InstallRoot $InstallRoot
$Template = Resolve-EASafeLocalPath -Name "Instance template" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\agent.env.template") `
    -MustExist -RequiredType Leaf
Assert-EAOrdinaryLeaf -Path $Template -Name "Instance template" -MaximumBytes 1MB

$PreparedFiles = $null
if ($UsingProvisioningPackage) {
    $PreparedEnvironment = Resolve-EASafeLocalPath `
        -Name "Prepared provisioned environment" `
        -PathValue $ProvisionedEnvironmentFile -MustExist -RequiredType Leaf
    $PreparedLock = Resolve-EASafeLocalPath -Name "Prepared provisioning lock" `
        -PathValue $ProvisioningLockFile -MustExist -RequiredType Leaf
    $PreparedSecretStore = Resolve-EASafeLocalPath `
        -Name "Prepared provisioning secret store" `
        -PathValue $ProvisioningSecretStoreFile -MustExist -RequiredType Leaf
    $PreparedParent = [IO.Path]::GetDirectoryName($PreparedEnvironment)
    $ExpectedPreparedParent = [IO.Path]::GetDirectoryName($PreparedLock)
    foreach ($Candidate in @($PreparedSecretStore)) {
        $CandidateParent = [IO.Path]::GetDirectoryName($Candidate)
        if (-not $CandidateParent.Equals(
                $PreparedParent, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Prepared provisioning files must share one transaction directory."
        }
    }
    if (-not $ExpectedPreparedParent.Equals(
            $PreparedParent, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Prepared provisioning files must share one transaction directory."
    }
    $PreparedParentParent = [IO.Path]::GetDirectoryName($PreparedParent)
    $PreparedLeaf = [IO.Path]::GetFileName($PreparedParent)
    if (-not $PreparedParentParent.Equals(
            $StateRoot, [StringComparison]::OrdinalIgnoreCase
        ) -or $PreparedLeaf -notmatch '^\.instance-staging-[A-Fa-f0-9]{32}$') {
        throw (
            "Prepared provisioning files must be inside an owned, same-volume " +
            "StateRoot transaction directory."
        )
    }
    $ExpectedPreparedNames = @{
        $PreparedEnvironment = "provisioned-agent.env"
        $PreparedLock = "provisioning-lock.json"
        $PreparedSecretStore = "provisioning-secrets.dpapi"
    }
    foreach ($Entry in $ExpectedPreparedNames.GetEnumerator()) {
        $ActualPreparedName = [IO.Path]::GetFileName([string]$Entry.Key)
        if (-not $ActualPreparedName.Equals(
                [string]$Entry.Value, [StringComparison]::Ordinal
            )) {
            throw "Prepared provisioning file has an unexpected name: $($Entry.Key)"
        }
    }
    Assert-EAOrdinaryTree -Root $PreparedParent `
        -Name "Prepared provisioning transaction" -MaximumEntries 12
    Assert-EAOrdinaryLeaf -Path $PreparedEnvironment `
        -Name "Prepared provisioned environment" -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $PreparedLock `
        -Name "Prepared provisioning lock" -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $PreparedSecretStore `
        -Name "Prepared provisioning secret store" -MaximumBytes 1MB
    $PreparedFiles = [pscustomobject]@{
        Environment = $PreparedEnvironment
        Lock = $PreparedLock
        SecretStore = $PreparedSecretStore
        Parent = $PreparedParent
    }
}

$CreationMutexName = "Global\MineGuardEnterpriseAgent-StateRoot-$($StateMarker.root_id)"
$CreationMutex = New-Object Threading.Mutex($false, $CreationMutexName)
$CreationMutexAcquired = $false
try {
    try {
        $CreationMutexAcquired = $CreationMutex.WaitOne(
            [TimeSpan]::FromSeconds(60)
        )
    }
    catch [Threading.AbandonedMutexException] {
        # The prior creator died while holding the boundary. We own the mutex
        # now, and the staging-directory validation below remains fail-closed.
        $CreationMutexAcquired = $true
    }
    if (-not $CreationMutexAcquired) {
        throw "Timed out waiting for the StateRoot-wide instance creation mutex."
    }

$InstanceRoot = Join-Path $StateRoot $InstanceName
if (Test-Path -LiteralPath $InstanceRoot) {
    throw "Instance already exists: $InstanceRoot"
}
$ExistingContexts = @()
foreach ($ExistingDirectory in Get-ChildItem -LiteralPath $StateRoot -Directory -Force) {
    if ($ExistingDirectory.Name.StartsWith(".instance-staging-")) { continue }
    if ($ExistingDirectory.Name -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "StateRoot contains an unrecognized instance directory: $($ExistingDirectory.FullName)"
    }
    $ExistingContext = Get-EAInstanceContext -InstanceName $ExistingDirectory.Name `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    Assert-EAInstanceGlobalIsolation -Context $ExistingContext
    $ExistingContexts += $ExistingContext
    if ($ExistingContext.Port -eq $Port) {
        throw "Port $Port is already assigned by $($ExistingContext.InstanceName)."
    }
    if ($ExistingContext.MineId.Equals(
            $MineId, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "MineId $MineId is already assigned by $($ExistingContext.InstanceName)."
    }
    if ($ExistingContext.SystemId.Equals(
            $SystemId, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "SystemId $SystemId is already assigned by $($ExistingContext.InstanceName)."
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
else {
    $ResolvedWatchDirectories = @(Join-Path $InstanceRoot "inbox")
}
foreach ($ExistingContext in $ExistingContexts) {
    foreach ($NewWatch in $ResolvedWatchDirectories) {
        foreach ($ExistingWatch in @($ExistingContext.WatchDirectories)) {
            if ((Test-EAPathWithin -Candidate $NewWatch -Parent $ExistingWatch) -or
                (Test-EAPathWithin -Candidate $ExistingWatch -Parent $NewWatch)) {
                throw (
                    "Watch directory isolation violation: new instance $InstanceName " +
                    "overlaps existing instance $($ExistingContext.InstanceName): " +
                    "$NewWatch <-> $ExistingWatch"
                )
            }
        }
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
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $StageConfigPath = Join-Path $StageConfigDirectory "agent.env"
    if ($UsingProvisioningPackage) {
        [IO.File]::Copy($PreparedFiles.Environment, $StageConfigPath, $false)
        [IO.File]::Copy(
            $PreparedFiles.Lock,
            (Join-Path $StageConfigDirectory "provisioning-lock.json"),
            $false
        )
        [IO.File]::Copy(
            $PreparedFiles.SecretStore,
            (Join-Path $StageConfigDirectory "provisioning-secrets.dpapi"),
            $false
        )
    }
    else {
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
        [IO.File]::WriteAllText($StageConfigPath, $Content, $Utf8NoBom)
    }
    $PreparedValues = Read-EAEnvironmentFile -Path $StageConfigPath
    if ($UsingProvisioningPackage) {
        $ExpectedProvisioningPaths = @{
            "ENTERPRISE_PROVISIONING_LOCK_FILE" = (
                Join-Path $InstanceRoot "config\provisioning-lock.json"
            )
            "ENTERPRISE_PROVISIONING_SECRET_STORE" = (
                Join-Path $InstanceRoot "config\provisioning-secrets.dpapi"
            )
        }
        foreach ($Entry in $ExpectedProvisioningPaths.GetEnumerator()) {
            if (-not $PreparedValues.ContainsKey([string]$Entry.Key) -or
                -not ([string]$PreparedValues[[string]$Entry.Key]).Equals(
                    [string]$Entry.Value,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Provisioned environment does not bind $($Entry.Key) to this instance."
            }
        }
        foreach ($SecretName in @(
            "ENTERPRISE_EXCHANGE_HMAC_SECRET",
            "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
            "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET",
            "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
            "PLATFORM_V3_TRANSPORT_HMAC_SECRET"
        )) {
            if ($PreparedValues.ContainsKey($SecretName) -and
                -not [string]::IsNullOrEmpty([string]$PreparedValues[$SecretName])) {
                throw "Provisioned environment must not contain plaintext $SecretName."
            }
        }
        # The four prepared files have now been copied into this creator's own
        # transaction.  Consume the caller-owned same-volume staging tree
        # before publication so a failed import cannot leave a second DPAPI
        # store, password hashes or activation-derived metadata behind.
        Remove-EAOwnedTemporaryTree -Path $PreparedFiles.Parent `
            -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
    }

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
        Set-EACanonicalInheritedTreeAcl -Root $StageRoot `
            -Name "Staged Agent instance" `
            -ServiceSid $ServiceIdentity.Sid -ServicePermission 'RX'
        foreach ($Writable in @($StageDataDirectory, $StageLogDirectory)) {
            Set-EACanonicalInheritedTreeAcl -Root $Writable `
                -Name "Writable Agent instance directory" `
                -ServiceSid $ServiceIdentity.Sid -ServicePermission 'M'
        }
        Set-EACanonicalInheritedTreeAcl -Root $StageBackupDirectory `
            -Name "Agent backup directory" -ServicePermission 'None'
        if (-not $UsingDefaultInbox -and $GrantWatchReadAcl) {
            foreach ($WatchDirectory in $ResolvedWatchDirectories) {
                $ExternalAclBackups[$WatchDirectory] = Get-Acl -LiteralPath $WatchDirectory
                # Set one inheritable read ACE on the dedicated root. Do not recursively
                # rewrite vendor files or protected child ACLs.
                Grant-EAServiceWatchReadAcl -WatchRoot $WatchDirectory `
                    -ServiceSid $ServiceIdentity.Sid
                Assert-EAServiceWatchReadAcl -WatchRoot $WatchDirectory `
                    -ServiceSid $ServiceIdentity.Sid
            }
        }
        elseif (-not $UsingDefaultInbox) {
            Write-Warning (
                "Custom watch directories were not modified. Their owner must grant " +
                "inheritable read access to $($ServiceIdentity.AccountName) " +
                "(SID $($ServiceIdentity.Sid)) and narrow any Everyone, Authenticated " +
                "Users, BUILTIN Users, LocalService, NetworkService, ALL SERVICES or " +
                "different service-SID allow ACE before formal service installation."
            )
        }
    }
    else {
        Write-Warning "DEVELOPMENT ONLY: ACL hardening was skipped. This instance cannot be installed as a production service."
    }

    Assert-EAOrdinaryTree -Root $StageRoot -Name "Staged instance"
    Move-Item -LiteralPath $StageRoot -Destination $InstanceRoot
    $CreatedContext = Get-EAInstanceContext -InstanceName $InstanceName `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    if (-not $SkipAcl) {
        Assert-EAInstanceCanonicalAcl -Context $CreatedContext
    }
    Assert-EAInstanceGlobalIsolation -Context $CreatedContext
    if (-not $SkipAcl -and ($UsingDefaultInbox -or $GrantWatchReadAcl)) {
        Assert-EAInstanceWatchAcls -Context $CreatedContext
    }
    if ($UsingProvisioningPackage) {
        $PolicyNames = @(
            "MINEGUARD_SERVICE_PRODUCTION_MODE",
            "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED",
            "MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED"
        )
        $OriginalPolicies = @{}
        foreach ($PolicyName in $PolicyNames) {
            $OriginalPolicies[$PolicyName] = [Environment]::GetEnvironmentVariable(
                $PolicyName, [EnvironmentVariableTarget]::Process
            )
        }
        try {
            foreach ($PolicyName in $PolicyNames) {
                $PolicyValue = if ($PolicyName -eq `
                    "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED") { "false" } else { "true" }
                [Environment]::SetEnvironmentVariable(
                    $PolicyName, $PolicyValue, [EnvironmentVariableTarget]::Process
                )
            }
            & $CreatedContext.Executable "--env-file" $CreatedContext.ConfigPath `
                "--authoritative-env-file" "config-check" "--production"
            if ($LASTEXITCODE -ne 0) {
                throw (
                    "Provisioned instance failed the production configuration " +
                    "preflight with exit code $LASTEXITCODE."
                )
            }
        }
        finally {
            foreach ($PolicyName in $PolicyNames) {
                [Environment]::SetEnvironmentVariable(
                    $PolicyName, $OriginalPolicies[$PolicyName],
                    [EnvironmentVariableTarget]::Process
                )
            }
        }
    }
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
            catch { Write-Warning "Could not restore watch ACL on ${WatchDirectory}: $($_.Exception.Message)" }
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
}
finally {
    if ($CreationMutexAcquired) {
        $CreationMutex.ReleaseMutex()
    }
    $CreationMutex.Dispose()
}
