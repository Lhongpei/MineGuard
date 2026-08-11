[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundlePath,
    [Parameter(Mandatory = $true)][string]$ActivationCodeFile,
    [Parameter(Mandatory = $true)][string]$TrustKeyPath,
    [Parameter(Mandatory = $true)][string]$ExpectedTrustKeySha256,
    [Parameter(Mandatory = $true)][string]$ExpectedIssuerKeyId,
    [Parameter(Mandatory = $true)][string]$CaSourcePath,
    [Parameter(Mandatory = $true)][string]$ExpectedCaSha256,
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$SafetyHelper = Join-Path $PSScriptRoot "EnterpriseAgent.WindowsSafety.ps1"
if (-not (Test-Path -LiteralPath $SafetyHelper -PathType Leaf)) {
    throw "Windows 安全辅助脚本缺失。"
}
. $SafetyHelper
Assert-EAPowerShell51

$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw "请在管理员 PowerShell 或开始菜单配置向导中执行接入包更新。"
}
Assert-EAInstanceName -Value $InstanceName

function Get-NormalizedSha256 {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Fa-f0-9\s]+$') {
        throw "$Name 必须是从介质外审批材料取得的 64 位十六进制 SHA-256。"
    }
    $Normalized = ($Value -replace '\s', '').ToLowerInvariant()
    if ($Normalized -notmatch '^[a-f0-9]{64}$') {
        throw "$Name 必须是从介质外审批材料取得的 64 位十六进制 SHA-256。"
    }
    return $Normalized
}

function Resolve-ProvisioningInputFile {
    param(
        [string]$Name,
        [string]$PathValue,
        [long]$MaximumBytes,
        [string[]]$AllowedExtensions = @()
    )
    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue -ne $PathValue.Trim() -or $PathValue.Contains('/') -or
        $PathValue -notmatch '^[A-Za-z]:\\') {
        throw "$Name 必须是本机盘符上的 X:\... 完整路径。"
    }
    $WithoutTrailingSeparator = $PathValue.TrimEnd('\')
    if ($WithoutTrailingSeparator.Length -le 2) {
        throw "$Name 不能是磁盘根目录。"
    }
    foreach ($Part in ($WithoutTrailingSeparator.Substring(3) -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @('.', '..') -or
            $Part.EndsWith(' ') -or $Part.EndsWith('.')) {
            throw "$Name 路径含空、点或歧义片段。"
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    if ($FullPath -notmatch '^[A-Za-z]:\\' -or $FullPath.StartsWith('\\') -or
        $FullPath.Substring(2).Contains(':')) {
        throw "$Name 路径不安全或含 NTFS ADS。"
    }
    $DriveRoot = [IO.Path]::GetPathRoot($FullPath)
    $DeviceId = $DriveRoot.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" `
        -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -notin @(2, 3)) {
        throw "$Name 必须位于本地固定盘或现场可移动介质，不能使用网络盘。"
    }
    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name 路径不能经过链接、联接点或重解析点。"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $DriveRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) { break }
        $Parent = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($Parent)) {
            throw "$Name 路径祖先无法安全解析。"
        }
        $Current = $Parent
    }
    Assert-EAOrdinaryLeaf -Path $FullPath -Name $Name -MaximumBytes $MaximumBytes
    $Extension = [IO.Path]::GetExtension($FullPath).ToLowerInvariant()
    if ($AllowedExtensions.Count -gt 0 -and
        $AllowedExtensions -notcontains $Extension) {
        throw "$Name 文件扩展名不符合要求。"
    }
    return $FullPath
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $Builder = New-Object Text.StringBuilder
    [void]$Builder.Append([char]'"')
    $BackslashCount = 0
    foreach ($Character in $Value.ToCharArray()) {
        if ($Character -eq [char]'\') {
            $BackslashCount += 1
            continue
        }
        if ($Character -eq [char]'"') {
            [void]$Builder.Append([char]'\', (($BackslashCount * 2) + 1))
            [void]$Builder.Append([char]'"')
            $BackslashCount = 0
            continue
        }
        if ($BackslashCount -gt 0) {
            [void]$Builder.Append([char]'\', $BackslashCount)
            $BackslashCount = 0
        }
        [void]$Builder.Append($Character)
    }
    if ($BackslashCount -gt 0) {
        [void]$Builder.Append([char]'\', ($BackslashCount * 2))
    }
    [void]$Builder.Append([char]'"')
    return $Builder.ToString()
}

function Test-ConfigurationEnvironmentName {
    param([string]$Name)
    foreach ($Prefix in @(
        "ENTERPRISE_", "PLATFORM_", "REGULATORY_", "AGENT_V2_",
        "DEEPSEEK_", "COAL_NEWS_", "MINEGUARD_"
    )) {
        if ($Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Invoke-AgentJson {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [hashtable]$ExtraEnvironment = @{}
    )
    $Serialized = @($Arguments | ForEach-Object {
        if ($null -eq $_) { throw "拒绝把 null 作为 Agent 命令参数。" }
        ConvertTo-NativeArgument -Value ([string]$_)
    }) -join " "
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = $Serialized
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Name in @($StartInfo.EnvironmentVariables.Keys)) {
        if (Test-ConfigurationEnvironmentName -Name ([string]$Name)) {
            $StartInfo.EnvironmentVariables.Remove([string]$Name)
        }
    }
    $StartInfo.EnvironmentVariables["PYTHONUTF8"] = "1"
    $StartInfo.EnvironmentVariables["PYTHONUNBUFFERED"] = "1"
    foreach ($Entry in $ExtraEnvironment.GetEnumerator()) {
        $StartInfo.EnvironmentVariables[[string]$Entry.Key] = [string]$Entry.Value
    }
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) { throw "无法启动 Agent 子进程。" }
        $Stdout = $Process.StandardOutput.ReadToEnd()
        $Stderr = $Process.StandardError.ReadToEnd()
        $Process.WaitForExit()
        if ($Stdout.Length -gt 65536 -or $Stderr.Length -gt 65536) {
            throw "Agent 子进程输出超过安全上限。"
        }
        if ($Process.ExitCode -ne 0) {
            $SafeError = $Stderr.Trim()
            if ([string]::IsNullOrWhiteSpace($SafeError)) {
                $SafeError = "Agent 子进程退出码 $($Process.ExitCode)。"
            }
            throw $SafeError
        }
        try { $Result = $Stdout | ConvertFrom-Json }
        catch { throw "Agent 子进程未返回有效 JSON。" }
        if ($null -eq $Result -or $Result -is [Array]) {
            throw "Agent 子进程未返回单个 JSON 对象。"
        }
        return $Result
    }
    finally { $Process.Dispose() }
}

function Stop-SelectedService {
    param([object]$Context, [object]$ServiceContext)
    $ServiceContext.Service.Refresh()
    if ($ServiceContext.Service.Status -ne "Stopped") {
        Stop-Service -Name $Context.ServiceId -ErrorAction Stop
        $ServiceContext.Service.WaitForStatus(
            "Stopped",
            [TimeSpan]::FromSeconds(45)
        )
    }
    Assert-EANoInstanceProcesses -Context $Context
}

function Start-SelectedService {
    param([object]$Context, [object]$ServiceContext)
    $ServiceContext.Service.Refresh()
    if ($ServiceContext.Service.Status -ne "Running") {
        Start-Service -Name $Context.ServiceId -ErrorAction Stop
        $ServiceContext.Service.WaitForStatus(
            "Running",
            [TimeSpan]::FromSeconds(45)
        )
    }
}

function Write-UpdateRecoveryBlock {
    param(
        [string]$PathValue,
        [string]$TransactionId,
        [string]$StagingRoot,
        [object]$Context
    )
    if (Test-Path -LiteralPath $PathValue) {
        throw "实例已有恢复阻断标记，拒绝开始配置更新。"
    }
    $Document = [ordered]@{
        format = "mineguard-enterprise-agent-provisioning-update-block-v1"
        transaction_id = $TransactionId
        instance_name = $Context.InstanceName
        staging_root = $StagingRoot
        created_utc = [DateTime]::UtcNow.ToString("o")
    }
    $Bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(
        (($Document | ConvertTo-Json -Depth 4) + [Environment]::NewLine)
    )
    $Temporary = Join-Path $Context.InstanceRoot (
        ".provision-update-block-" + $TransactionId + ".tmp"
    )
    $Stream = $null
    try {
        $Stream = [IO.File]::Open(
            $Temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    }
    finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
    }
    try { Move-Item -LiteralPath $Temporary -Destination $PathValue }
    catch {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
        throw
    }
    Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $PathValue
}

function Remove-UpdateRecoveryBlock {
    param([string]$PathValue, [object]$Context)
    if (-not (Test-Path -LiteralPath $PathValue)) { return }
    Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $PathValue
    Remove-Item -LiteralPath $PathValue -Force
}

$ExpectedTrustKeySha256 = Get-NormalizedSha256 `
    -Name "签发公钥 SHA-256" -Value $ExpectedTrustKeySha256
$ExpectedCaSha256 = Get-NormalizedSha256 `
    -Name "政府 CA 文件 SHA-256" -Value $ExpectedCaSha256
if ($ExpectedIssuerKeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
    throw "介质外 issuer key ID 格式无效。"
}
$BundlePath = Resolve-ProvisioningInputFile -Name "企业更新接入包" `
    -PathValue $BundlePath -MaximumBytes 4MB -AllowedExtensions @('.mgprov')
$ActivationCodeFile = Resolve-ProvisioningInputFile -Name "激活码文件" `
    -PathValue $ActivationCodeFile -MaximumBytes 4KB
$TrustKeyPath = Resolve-ProvisioningInputFile -Name "签发公钥" `
    -PathValue $TrustKeyPath -MaximumBytes 64KB -AllowedExtensions @('.pem')
$CaSourcePath = Resolve-ProvisioningInputFile -Name "政府 CA 文件" `
    -PathValue $CaSourcePath -MaximumBytes 1MB -AllowedExtensions @('.pem', '.crt')
$DistinctInputs = @(@(
    $BundlePath, $ActivationCodeFile, $TrustKeyPath, $CaSourcePath
) | Select-Object -Unique)
if ($DistinctInputs.Count -ne 4) {
    throw "更新包、激活码、公钥和 CA 必须是四个不同文件。"
}
if ((Get-FileHash -LiteralPath $CaSourcePath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -ne $ExpectedCaSha256) {
    throw "政府 CA 文件与介质外审批 SHA-256 不一致。"
}

$InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" `
    -PathValue $InstallRoot -MustExist -RequiredType Container -CheckTree
$StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" `
    -PathValue $StateRoot -MustExist -RequiredType Container
$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
if (-not [bool]$Context.Metadata.acl_hardened) {
    throw "配置包更新只支持已启用正式 ACL 的实例。"
}
$ServiceContext = Get-EAServiceContext -Context $Context
if ($null -eq $ServiceContext) {
    throw "配置包更新要求实例已安装受管 Windows 服务。"
}
$ServiceContext.Service.Refresh()
if ($ServiceContext.Service.Status -notin @("Running", "Stopped")) {
    throw "Windows 服务当前处于过渡或暂停状态，请稳定后重试。"
}
$WasRunning = $ServiceContext.Service.Status -eq "Running"

$ServiceXml = Join-Path $Context.ServiceDirectory ($Context.ServiceId + ".xml")
Assert-EAOrdinaryLeaf -Path $ServiceXml -Name "WinSW instance XML" `
    -MaximumBytes 1MB
$ServiceXmlText = [IO.File]::ReadAllText($ServiceXml)
if ($ServiceXmlText -notmatch (
        '<env\s+name="MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED"' +
        '\s+value="true"\s*/>'
    )) {
    throw "现有服务未启用独立受管配置策略；请先用当前安装包重新安装该实例服务。"
}

$CurrentValues = Read-EAEnvironmentFile -Path $Context.ConfigPath
$FinalLockPath = Join-Path $Context.InstanceRoot "config\provisioning-lock.json"
$FinalStorePath = Join-Path $Context.InstanceRoot "config\provisioning-secrets.dpapi"
$FinalCaPath = Join-Path $Context.InstanceRoot "config\platform-ca.pem"
$CurrentBindings = @(
    [pscustomobject]@{ Name = "ENTERPRISE_PROVISIONING_LOCK_FILE"; Value = $FinalLockPath },
    [pscustomobject]@{ Name = "ENTERPRISE_PROVISIONING_SECRET_STORE"; Value = $FinalStorePath },
    [pscustomobject]@{ Name = "PLATFORM_V3_CA_BUNDLE"; Value = $FinalCaPath },
    [pscustomobject]@{ Name = "ENTERPRISE_PROVISIONING_MANAGED_REQUIRED"; Value = "true" }
)
foreach ($Binding in $CurrentBindings) {
    if (-not $CurrentValues.ContainsKey([string]$Binding.Name) -or
        -not ([string]$CurrentValues[[string]$Binding.Name]).Equals(
            [string]$Binding.Value, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "现有实例不是完整受管配置，字段不匹配：$($Binding.Name)"
    }
}
foreach ($PathValue in @($FinalLockPath, $FinalStorePath, $FinalCaPath)) {
    Assert-EAOrdinaryLeaf -Path $PathValue -Name "现有受管配置文件" `
        -MaximumBytes 1MB
}

$MutexName = "Global\MineGuardEnterpriseAgent-ProvisionUpdate-$($Context.RootId)-$InstanceName"
$Mutex = New-Object Threading.Mutex($false, $MutexName)
$MutexAcquired = $false
$TransactionId = [Guid]::NewGuid().ToString("N")
$StageRoot = Join-Path $StateRoot (".instance-staging-" + $TransactionId)
$RecoveryMarker = Join-Path $Context.InstanceRoot "restore-recovery-block.json"
$RecoveryMarkerWritten = $false
$Committed = $false
$RollbackComplete = $false
$ImportResult = $null
$Files = @()
try {
    try { $MutexAcquired = $Mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
    catch [Threading.AbandonedMutexException] { $MutexAcquired = $true }
    if (-not $MutexAcquired) {
        throw "等待该实例配置更新锁超时。"
    }

    New-Item -ItemType Directory -Path $StageRoot -ErrorAction Stop | Out-Null
    Invoke-EAIcaclsChecked -ArgumentList @(
        $StageRoot, "/inheritance:r",
        "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "/grant:r", "*S-1-5-32-544:(OI)(CI)F"
    )
    $RollbackRoot = Join-Path $StageRoot "rollback"
    $FailedRoot = Join-Path $StageRoot "failed-new"
    New-Item -ItemType Directory -Path $RollbackRoot | Out-Null
    New-Item -ItemType Directory -Path $FailedRoot | Out-Null
    $BaseEnvironment = Join-Path $StageRoot "base-agent.env"
    $NewEnvironment = Join-Path $StageRoot "provisioned-agent.env"
    $NewLock = Join-Path $StageRoot "provisioning-lock.json"
    $NewStore = Join-Path $StageRoot "provisioning-secrets.dpapi"
    $PreparedCa = Join-Path $StageRoot "platform-ca.pem"
    [IO.File]::Copy($Context.ConfigPath, $BaseEnvironment, $false)
    [IO.File]::Copy($CaSourcePath, $PreparedCa, $false)
    if ((Get-FileHash -LiteralPath $PreparedCa -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ne $ExpectedCaSha256) {
        throw "复制后的政府 CA 文件 SHA-256 不一致。"
    }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot

    $ImportResult = Invoke-AgentJson -Executable $Context.Executable -Arguments @(
        "provision-import", "--bundle", $BundlePath,
        "--activation-code-file", $ActivationCodeFile,
        "--issuer-public-key", $TrustKeyPath,
        "--expected-public-key-sha256", $ExpectedTrustKeySha256,
        "--expected-issuer-key-id", $ExpectedIssuerKeyId,
        "--ca-source", $PreparedCa,
        "--expected-ca-sha256", $ExpectedCaSha256,
        "--base-env", $BaseEnvironment,
        "--output-env", $NewEnvironment,
        "--lock-output", $NewLock,
        "--lock-env-path", $FinalLockPath,
        "--secret-store", $NewStore,
        "--secret-store-env-path", $FinalStorePath,
        "--secret-protection", "dpapi-local-machine",
        "--expected-mine-id", $Context.MineId,
        "--expected-system-id", $Context.SystemId,
        "--current-lock", $FinalLockPath
    )
    if (-not [bool]$ImportResult.valid -or
        [string]$ImportResult.mine_id -ne $Context.MineId -or
        [string]$ImportResult.system_id -ne $Context.SystemId) {
        throw "更新接入包未保持现有实例身份。"
    }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot
    $NewValues = Read-EAEnvironmentFile -Path $NewEnvironment
    $NewBindings = @(
        [pscustomobject]@{ Name = "ENTERPRISE_AGENT_DB"; Value = [string]$CurrentValues["ENTERPRISE_AGENT_DB"] },
        [pscustomobject]@{ Name = "ENTERPRISE_AGENT_PORT"; Value = [string]$CurrentValues["ENTERPRISE_AGENT_PORT"] },
        [pscustomobject]@{ Name = "ENTERPRISE_MINE_ID"; Value = $Context.MineId },
        [pscustomobject]@{ Name = "ENTERPRISE_SYSTEM_ID"; Value = $Context.SystemId },
        [pscustomobject]@{ Name = "ENTERPRISE_PROVISIONING_LOCK_FILE"; Value = $FinalLockPath },
        [pscustomobject]@{ Name = "ENTERPRISE_PROVISIONING_SECRET_STORE"; Value = $FinalStorePath },
        [pscustomobject]@{ Name = "PLATFORM_V3_CA_BUNDLE"; Value = $FinalCaPath }
    )
    foreach ($Binding in $NewBindings) {
        if (-not $NewValues.ContainsKey([string]$Binding.Name) -or
            -not ([string]$NewValues[[string]$Binding.Name]).Equals(
                [string]$Binding.Value, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "更新后的受管环境越过本实例边界：$($Binding.Name)"
        }
    }
    foreach ($SecretName in @(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
        "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET",
        "PLATFORM_V3_TRANSPORT_HMAC_SECRET"
    )) {
        if ($NewValues.ContainsKey($SecretName) -and
            -not [string]::IsNullOrEmpty([string]$NewValues[$SecretName])) {
            throw "更新后的 agent.env 含明文秘密：$SecretName"
        }
    }

    $Files = @(
        [pscustomobject]@{ Name = "platform-ca.pem"; Live = $FinalCaPath; New = $PreparedCa },
        [pscustomobject]@{ Name = "provisioning-secrets.dpapi"; Live = $FinalStorePath; New = $NewStore },
        [pscustomobject]@{ Name = "provisioning-lock.json"; Live = $FinalLockPath; New = $NewLock },
        [pscustomobject]@{ Name = "agent.env"; Live = $Context.ConfigPath; New = $NewEnvironment }
    )
    foreach ($File in $Files) {
        $File | Add-Member -NotePropertyName Backup `
            -NotePropertyValue (Join-Path $RollbackRoot $File.Name)
        $File | Add-Member -NotePropertyName Failed `
            -NotePropertyValue (Join-Path $FailedRoot $File.Name)
    }

    Stop-SelectedService -Context $Context -ServiceContext $ServiceContext
    Write-UpdateRecoveryBlock -PathValue $RecoveryMarker `
        -TransactionId $TransactionId -StagingRoot $StageRoot -Context $Context
    $RecoveryMarkerWritten = $true

    foreach ($File in $Files) {
        Assert-EAOrdinaryLeaf -Path $File.Live -Name "现有配置 $($File.Name)" `
            -MaximumBytes 1MB
        Move-Item -LiteralPath $File.Live -Destination $File.Backup
        Invoke-EAIcaclsChecked -ArgumentList @($File.Backup, "/reset")
    }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot
    foreach ($File in $Files) {
        Move-Item -LiteralPath $File.New -Destination $File.Live
    }
    Set-EAInstanceCanonicalAcl -Context $Context

    $Preflight = Invoke-AgentJson -Executable $Context.Executable `
        -Arguments @(
            "--env-file", $Context.ConfigPath,
            "--authoritative-env-file", "config-check", "--production"
        ) -ExtraEnvironment @{
            MINEGUARD_SERVICE_PRODUCTION_MODE = "true"
            MINEGUARD_SERVICE_FOUR_EYES_REQUIRED = "true"
            MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED = "true"
            MINEGUARD_INTERNAL_PROVISIONING_UPDATE_TRANSACTION_ID = $TransactionId
        }
    if (-not [bool]$Preflight.valid -or
        -not [bool]$Preflight.provisioning.managed -or
        [int]$Preflight.provisioning.profile_version -ne
            [int]$ImportResult.profile_version -or
        [string]$Preflight.mine_id -ne $Context.MineId) {
        throw "更新配置发布后的正式自检未保持受管身份或版本。"
    }
    Remove-UpdateRecoveryBlock -PathValue $RecoveryMarker -Context $Context
    $RecoveryMarkerWritten = $false
    if ($WasRunning) {
        Start-SelectedService -Context $Context -ServiceContext $ServiceContext
    }
    $Committed = $true
    try {
        Remove-EAOwnedTemporaryTree -Path $StageRoot `
            -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
    }
    catch {
        Write-Warning "更新已提交，但旧配置事务目录无法清理：$StageRoot"
    }
    [pscustomobject]@{
        status = "updated"
        instance_name = $InstanceName
        mine_id = $Context.MineId
        system_id = $Context.SystemId
        pair_id = [string]$ImportResult.pair_id
        profile_version = [int]$ImportResult.profile_version
        service_restored = $WasRunning
        production_preflight = "passed"
    }
}
catch {
    $OriginalError = $_
    $RollbackErrors = @()
    $HasBackup = @($Files | Where-Object {
        $null -ne $_.PSObject.Properties["Backup"] -and
        (Test-Path -LiteralPath $_.Backup)
    }).Count -gt 0
    if ($RecoveryMarkerWritten -or $HasBackup) {
        try { Stop-SelectedService -Context $Context -ServiceContext $ServiceContext }
        catch { $RollbackErrors += "停止服务：$($_.Exception.Message)" }
        if (-not (Test-Path -LiteralPath $RecoveryMarker)) {
            try {
                Write-UpdateRecoveryBlock -PathValue $RecoveryMarker `
                    -TransactionId $TransactionId -StagingRoot $StageRoot `
                    -Context $Context
                $RecoveryMarkerWritten = $true
            }
            catch { $RollbackErrors += "重建阻断标记：$($_.Exception.Message)" }
        }
        for ($FileIndex = $Files.Count - 1; $FileIndex -ge 0; $FileIndex -= 1) {
            $File = $Files[$FileIndex]
            try {
                if (Test-Path -LiteralPath $File.Backup) {
                    if (Test-Path -LiteralPath $File.Live) {
                        Move-Item -LiteralPath $File.Live -Destination $File.Failed
                        Invoke-EAIcaclsChecked -ArgumentList @(
                            $File.Failed, "/reset"
                        )
                    }
                    Move-Item -LiteralPath $File.Backup -Destination $File.Live
                }
            }
            catch { $RollbackErrors += "恢复 $($File.Name)：$($_.Exception.Message)" }
        }
        if ($RollbackErrors.Count -eq 0) {
            try { Set-EAInstanceCanonicalAcl -Context $Context }
            catch { $RollbackErrors += "恢复 ACL：$($_.Exception.Message)" }
        }
        if ($RollbackErrors.Count -eq 0) {
            try {
                [void](Invoke-AgentJson -Executable $Context.Executable `
                    -Arguments @(
                        "--env-file", $Context.ConfigPath,
                        "--authoritative-env-file", "config-check", "--production"
                    ) -ExtraEnvironment @{
                        MINEGUARD_SERVICE_PRODUCTION_MODE = "true"
                        MINEGUARD_SERVICE_FOUR_EYES_REQUIRED = "true"
                        MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED = "true"
                        MINEGUARD_INTERNAL_PROVISIONING_UPDATE_TRANSACTION_ID = $TransactionId
                    })
            }
            catch { $RollbackErrors += "旧配置回滚自检：$($_.Exception.Message)" }
        }
        if ($RollbackErrors.Count -eq 0) {
            try {
                Remove-UpdateRecoveryBlock -PathValue $RecoveryMarker -Context $Context
                $RecoveryMarkerWritten = $false
                if ($WasRunning) {
                    Start-SelectedService -Context $Context `
                        -ServiceContext $ServiceContext
                }
                $RollbackComplete = $true
            }
            catch { $RollbackErrors += "恢复服务：$($_.Exception.Message)" }
        }
    }
    else {
        try {
            if ($WasRunning) {
                Start-SelectedService -Context $Context `
                    -ServiceContext $ServiceContext
            }
            $RollbackComplete = $true
        }
        catch { $RollbackErrors += "恢复原服务状态：$($_.Exception.Message)" }
    }
    if ($RollbackComplete -and (Test-Path -LiteralPath $StageRoot)) {
        try {
            Remove-EAOwnedTemporaryTree -Path $StageRoot `
                -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
        }
        catch { Write-Warning "回滚成功，但更新事务目录无法清理：$StageRoot" }
    }
    if ($RollbackErrors.Count -ne 0) {
        throw (
            "接入配置更新失败且自动回滚不完整；服务保持停止，阻断标记和事务目录已保留。" +
            " 原始错误：$($OriginalError.Exception.Message)；回滚错误：" +
            ($RollbackErrors -join "；")
        )
    }
    throw $OriginalError
}
finally {
    if ($MutexAcquired) { $Mutex.ReleaseMutex() }
    $Mutex.Dispose()
    if (-not $Committed -and -not $RecoveryMarkerWritten -and
        (Test-Path -LiteralPath $StageRoot)) {
        try {
            Remove-EAOwnedTemporaryTree -Path $StageRoot `
                -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
        }
        catch { Write-Warning "无法清理未发布的配置更新事务目录：$StageRoot" }
    }
}
