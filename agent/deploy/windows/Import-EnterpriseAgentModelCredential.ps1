[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundlePath,
    [Parameter(Mandatory = $true)][string]$ActivationCodeFile,
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
    throw "请从管理员 PowerShell 或 MineGuard 模型凭据向导执行导入。"
}
Assert-EAInstanceName -Value $InstanceName

$PlaintextModelEnvironmentNames = @(
    "MINEGUARD_AGENT_API_KEY",
    "MINEGUARD_AGENT_BASE_URL",
    "MINEGUARD_AGENT_MODEL",
    "MINEGUARD_AGENT_TIMEOUT_SECONDS",
    "MINEGUARD_AGENT_MAX_RETRIES",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_MODEL",
    "DEEPSEEK_TIMEOUT_SECONDS",
    "DEEPSEEK_MAX_RETRIES"
)

function Resolve-ModelCredentialInputFile {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
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
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [hashtable]$ExtraEnvironment = @{},
        [int]$MaximumOutputCharacters = 131072
    )
    $Serialized = @($Arguments | ForEach-Object {
        if ($null -eq $_) { throw "拒绝把 null 作为 Agent 命令参数。" }
        ConvertTo-NativeArgument -Value ([string]$_)
    }) -join ' '
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = $Serialized
    $StartInfo.WorkingDirectory = Split-Path -Parent $Executable
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $StartInfo.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
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
        if ($Stdout.Length -gt $MaximumOutputCharacters -or
            $Stderr.Length -gt $MaximumOutputCharacters) {
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

function Set-EnvironmentRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$' -or
        $Value.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "本地环境记录不安全：$Name"
    }
    $Pattern = '(?im)^[ \t]*' + [regex]::Escape($Name) + `
        '[ \t]*=.*(?:\r?\n|$)'
    $Matches = [regex]::Matches($Content, $Pattern)
    if ($Matches.Count -gt 1) { throw "实例配置含重复配置项：$Name" }
    $Replacement = $Name + '=' + $Value + [Environment]::NewLine
    if ($Matches.Count -eq 1) {
        return [regex]::Replace(
            $Content, $Pattern, $Replacement.Replace('$', '$$')
        )
    }
    return $Content.TrimEnd(@([char]13, [char]10)) + `
        [Environment]::NewLine + $Replacement
}

function Remove-EnvironmentRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$') {
        throw "本地环境记录名称不安全：$Name"
    }
    $Pattern = '(?im)^[ \t]*' + [regex]::Escape($Name) + `
        '[ \t]*=.*(?:\r?\n|$)'
    $Matches = [regex]::Matches($Content, $Pattern)
    if ($Matches.Count -gt 1) { throw "实例配置含重复配置项：$Name" }
    return [regex]::Replace($Content, $Pattern, '')
}

function Write-NewUtf8File {
    param([string]$PathValue, [string]$Content)
    $Bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Content)
    $Stream = $null
    try {
        $Stream = [IO.File]::Open(
            $PathValue, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    }
    finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
    }
}

function Stop-SelectedService {
    param([object]$Context, [object]$ServiceContext)
    $ServiceContext.Service.Refresh()
    if ($ServiceContext.Service.Status -ne "Stopped") {
        Stop-Service -Name $Context.ServiceId -ErrorAction Stop
        $ServiceContext.Service.WaitForStatus(
            "Stopped", [TimeSpan]::FromSeconds(45)
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
            "Running", [TimeSpan]::FromSeconds(45)
        )
    }
}

function Write-ModelCredentialRecoveryBlock {
    param(
        [string]$PathValue,
        [string]$TransactionId,
        [string]$StagingRoot,
        [object]$Context
    )
    if (Test-Path -LiteralPath $PathValue) {
        throw "实例已有恢复阻断标记，拒绝开始模型凭据更新。"
    }
    $Document = [ordered]@{
        # Reuse the established guarded configuration-update format. The
        # Agent permits only this transaction's config-check while the marker
        # exists and rejects serve plus every unrelated command.
        format = "mineguard-enterprise-agent-provisioning-update-block-v1"
        transaction_id = $TransactionId
        instance_name = $Context.InstanceName
        staging_root = $StagingRoot
        created_utc = [DateTime]::UtcNow.ToString("o")
    }
    $Temporary = Join-Path $Context.InstanceRoot (
        ".model-credential-recovery-" + $TransactionId + ".tmp"
    )
    Write-NewUtf8File -PathValue $Temporary -Content (
        ($Document | ConvertTo-Json -Depth 4) + [Environment]::NewLine
    )
    try { Move-Item -LiteralPath $Temporary -Destination $PathValue }
    catch {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
        throw
    }
    Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $PathValue
}

function Remove-ModelCredentialRecoveryBlock {
    param([string]$PathValue, [object]$Context)
    if (-not (Test-Path -LiteralPath $PathValue)) { return }
    Assert-EARestoreRecoveryBlockAcl -Context $Context -Path $PathValue
    Remove-Item -LiteralPath $PathValue -Force
}

$BundlePath = Resolve-ModelCredentialInputFile -Name "模型凭据包" `
    -PathValue $BundlePath -MaximumBytes 2MB -AllowedExtensions @('.mgllm')
$ActivationCodeFile = Resolve-ModelCredentialInputFile -Name "独立激活码文件" `
    -PathValue $ActivationCodeFile -MaximumBytes 4KB
if ($BundlePath.Equals(
        $ActivationCodeFile, [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "模型凭据包和激活码必须是两个不同文件。"
}

$InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" `
    -PathValue $InstallRoot -MustExist -RequiredType Container -CheckTree
$StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" `
    -PathValue $StateRoot -MustExist -RequiredType Container
$TrustStorePath = Join-Path $InstallRoot `
    "release-metadata\model-credential-trust.json"
$TrustStorePath = Resolve-EASafeLocalPath -Name "已安装模型签发者信任库" `
    -PathValue $TrustStorePath -MustExist -RequiredType Leaf
if (-not (Test-EAPathWithin -Candidate $TrustStorePath -Parent $InstallRoot)) {
    throw "模型签发者信任库必须位于已安装程序边界内。"
}
Assert-EAOrdinaryLeaf -Path $TrustStorePath -Name "已安装模型签发者信任库" `
    -MaximumBytes 1MB

$Context = Get-EAInstanceContext -InstanceName $InstanceName `
    -InstallRoot $InstallRoot -StateRoot $StateRoot
if (-not [bool]$Context.Metadata.acl_hardened) {
    throw "模型凭据导入只支持已启用正式 ACL 的实例。"
}
$ServiceContext = Get-EAServiceContext -Context $Context
if ($null -eq $ServiceContext) {
    throw "模型凭据导入要求实例已安装受管 Windows 服务。"
}
$ServiceContext.Service.Refresh()
if ($ServiceContext.Service.Status -notin @("Running", "Stopped")) {
    throw "Windows 服务处于过渡或暂停状态，请稳定后重试。"
}
$WasRunning = $ServiceContext.Service.Status -eq "Running"

$ServiceXml = Join-Path $Context.ServiceDirectory ($Context.ServiceId + ".xml")
Assert-EAOrdinaryLeaf -Path $ServiceXml -Name "WinSW instance XML" `
    -MaximumBytes 1MB
$ServiceXmlText = [IO.File]::ReadAllText($ServiceXml)
foreach ($RequiredPolicy in @(
    "MINEGUARD_SERVICE_PRODUCTION_MODE",
    "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED",
    "MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED"
)) {
    if ($ServiceXmlText -notmatch (
            '<env\s+name="' + [regex]::Escape($RequiredPolicy) +
            '"\s+value="true"\s*/>'
        )) {
        throw "现有服务未锁定正式运行策略：$RequiredPolicy"
    }
}

$CurrentValues = Read-EAEnvironmentFile -Path $Context.ConfigPath
if (-not $CurrentValues.ContainsKey("ENTERPRISE_OPERATOR_ID") -or
    [string]::IsNullOrWhiteSpace(
        [string]$CurrentValues["ENTERPRISE_OPERATOR_ID"]
    )) {
    throw "正式实例缺少企业 party 身份，不能导入模型凭据。"
}
$ExpectedPartyId = [string]$CurrentValues["ENTERPRISE_OPERATOR_ID"]
$FinalLockPath = Join-Path $Context.InstanceRoot `
    "config\model-credential-lock.json"
$FinalAntiRollbackStatePath = [IO.Path]::ChangeExtension(
    $FinalLockPath, ".state.json"
)
$FinalSecretStorePath = Join-Path $Context.InstanceRoot `
    "config\model-credentials.dpapi"
$ManagedBindings = @(
    [pscustomobject]@{
        Name = "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE"
        Value = $FinalLockPath
    },
    [pscustomobject]@{
        Name = "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE"
        Value = $FinalSecretStorePath
    }
)
$LockEntryExists = Test-Path -LiteralPath $FinalLockPath
$StateEntryExists = Test-Path -LiteralPath $FinalAntiRollbackStatePath
$StoreEntryExists = Test-Path -LiteralPath $FinalSecretStorePath
if (($LockEntryExists -and
        -not (Test-Path -LiteralPath $FinalLockPath -PathType Leaf)) -or
    ($StateEntryExists -and
        -not (Test-Path -LiteralPath $FinalAntiRollbackStatePath -PathType Leaf)) -or
    ($StoreEntryExists -and
        -not (Test-Path -LiteralPath $FinalSecretStorePath -PathType Leaf))) {
    throw "模型凭据固定路径已被非文件对象占用，拒绝导入。"
}
$HasExistingLock = $LockEntryExists
$HasExistingState = $StateEntryExists
$HasExistingStore = $StoreEntryExists
if ($HasExistingLock -ne $HasExistingStore -or
    $HasExistingLock -ne $HasExistingState) {
    throw "现有模型凭据锁、DPAPI 密文和防回退状态不一致，拒绝覆盖。"
}
foreach ($Binding in $ManagedBindings) {
    if ($CurrentValues.ContainsKey([string]$Binding.Name) -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$CurrentValues[[string]$Binding.Name]
        ) -and
        -not ([string]$CurrentValues[[string]$Binding.Name]).Equals(
            [string]$Binding.Value, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "现有模型凭据指针越过固定实例边界：$($Binding.Name)"
    }
}
if ($HasExistingLock) {
    Assert-EAOrdinaryLeaf -Path $FinalLockPath -Name "现有模型凭据锁" `
        -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $FinalSecretStorePath `
        -Name "现有模型凭据 DPAPI 密文" -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $FinalAntiRollbackStatePath `
        -Name "现有模型凭据防回退状态" -MaximumBytes 1MB
    foreach ($Binding in $ManagedBindings) {
        if (-not $CurrentValues.ContainsKey([string]$Binding.Name) -or
            -not ([string]$CurrentValues[[string]$Binding.Name]).Equals(
                [string]$Binding.Value, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "现有模型凭据不完整，缺少固定指针：$($Binding.Name)"
        }
    }
}

$MutexName = "Global\MineGuardEnterpriseAgent-ProvisionUpdate-$($Context.RootId)-$InstanceName"
$Mutex = New-Object Threading.Mutex($false, $MutexName)
$MutexAcquired = $false
$TransactionId = [Guid]::NewGuid().ToString("N")
$StageRoot = Join-Path $StateRoot (".instance-staging-" + $TransactionId)
$RecoveryMarker = Get-EARestoreRecoveryBlockPath -Context $Context
$RecoveryMarkerWritten = $false
$Committed = $false
$RollbackComplete = $false
$Files = @()
try {
    try { $MutexAcquired = $Mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
    catch [Threading.AbandonedMutexException] { $MutexAcquired = $true }
    if (-not $MutexAcquired) {
        throw "等待该实例受管配置更新锁超时。"
    }
    # The first context check occurs before waiting for the shared update
    # mutex.  Recheck after acquisition so an abandoned concurrent transaction
    # cannot leave a recovery block in the wait window and be bypassed here.
    Assert-EANoRestoreRecoveryBlock -Context $Context

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
    $PreparedBundle = Join-Path $StageRoot "credential.mgllm"
    $PreparedActivation = Join-Path $StageRoot "activation.code"
    $ImportEnvironment = Join-Path $StageRoot "model-import.env"
    $PreparedEnvironment = Join-Path $StageRoot "agent.env"
    $NewLock = Join-Path $StageRoot "model-credential-lock.json"
    $NewAntiRollbackState = [IO.Path]::ChangeExtension(
        $NewLock, ".state.json"
    )
    $NewSecretStore = Join-Path $StageRoot "model-credentials.dpapi"
    [IO.File]::Copy($BundlePath, $PreparedBundle, $false)
    [IO.File]::Copy($ActivationCodeFile, $PreparedActivation, $false)
    foreach ($CopyPair in @(
        [pscustomobject]@{ Source = $BundlePath; Copy = $PreparedBundle },
        [pscustomobject]@{ Source = $ActivationCodeFile; Copy = $PreparedActivation }
    )) {
        $SourceHash = (Get-FileHash -LiteralPath $CopyPair.Source `
            -Algorithm SHA256).Hash
        $CopyHash = (Get-FileHash -LiteralPath $CopyPair.Copy `
            -Algorithm SHA256).Hash
        if ($SourceHash -ne $CopyHash) {
            throw "模型凭据输入复制过程中发生变化，已拒绝导入。"
        }
    }

    $EnvironmentContent = [IO.File]::ReadAllText($Context.ConfigPath)
    foreach ($PlaintextName in $PlaintextModelEnvironmentNames) {
        $EnvironmentContent = Remove-EnvironmentRecord `
            -Content $EnvironmentContent -Name $PlaintextName
    }
    $ImportEnvironmentContent = $EnvironmentContent
    # Both first import and rotation load only the signed provisioning
    # identity. Keeping an expired but cryptographically intact active model
    # credential in this staging environment would prevent the very rotation
    # intended to replace it. The CLI authenticates --current-lock separately
    # and enforces exact subject/version/key rotation against the fixed files.
    foreach ($Binding in $ManagedBindings) {
        $ImportEnvironmentContent = Remove-EnvironmentRecord `
            -Content $ImportEnvironmentContent -Name ([string]$Binding.Name)
    }
    Write-NewUtf8File -PathValue $ImportEnvironment `
        -Content $ImportEnvironmentContent
    foreach ($Binding in $ManagedBindings) {
        $EnvironmentContent = Set-EnvironmentRecord `
            -Content $EnvironmentContent -Name ([string]$Binding.Name) `
            -Value ([string]$Binding.Value)
    }
    Write-NewUtf8File -PathValue $PreparedEnvironment `
        -Content $EnvironmentContent
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot

    $ImportArguments = @(
        "--env-file", $ImportEnvironment,
        "--authoritative-env-file",
        "model-credential-import",
        "--bundle", $PreparedBundle,
        "--activation-code-file", $PreparedActivation,
        "--trust-store", $TrustStorePath,
        "--expected-mine-id", $Context.MineId,
        "--expected-system-id", $Context.SystemId,
        "--expected-party-id", $ExpectedPartyId,
        "--lock-output", $NewLock,
        "--lock-env-path", $FinalLockPath,
        "--secret-store", $NewSecretStore,
        "--secret-store-env-path", $FinalSecretStorePath,
        "--secret-protection", "dpapi-local-machine"
    )
    if ($HasExistingLock) {
        $ImportArguments += @("--current-lock", $FinalLockPath)
    }
    $ImportResult = Invoke-AgentJson -Executable $Context.Executable `
        -Arguments $ImportArguments
    if (-not [bool]$ImportResult.managed -or
        [string]$ImportResult.mine_id -ne $Context.MineId -or
        [string]$ImportResult.system_id -ne $Context.SystemId -or
        [string]$ImportResult.party_id -ne $ExpectedPartyId -or
        [string]::IsNullOrWhiteSpace([string]$ImportResult.pair_id) -or
        [int]$ImportResult.credential_version -lt 1 -or
        [string]::IsNullOrWhiteSpace(
            [string]$ImportResult.anti_rollback_state_path
        ) -or
        -not ([string]$ImportResult.anti_rollback_state_path).Equals(
            $NewAntiRollbackState, [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$ImportResult.secret_protection -ne
            "dpapi-local-machine-v1") {
        throw "模型凭据包未保持所选实例身份。"
    }
    Assert-EAOrdinaryLeaf -Path $NewLock -Name "新模型凭据锁" `
        -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $NewSecretStore -Name "新模型凭据 DPAPI 密文" `
        -MaximumBytes 1MB
    Assert-EAOrdinaryLeaf -Path $NewAntiRollbackState `
        -Name "新模型凭据防回退状态" -MaximumBytes 1MB
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot

    $PreparedValues = Read-EAEnvironmentFile -Path $PreparedEnvironment
    foreach ($PlaintextName in $PlaintextModelEnvironmentNames) {
        if ($PreparedValues.ContainsKey($PlaintextName)) {
            throw "发布前配置仍含明文模型变量：$PlaintextName"
        }
    }
    foreach ($Binding in $ManagedBindings) {
        if (-not $PreparedValues.ContainsKey([string]$Binding.Name) -or
            -not ([string]$PreparedValues[[string]$Binding.Name]).Equals(
                [string]$Binding.Value, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "发布前配置缺少固定模型凭据指针：$($Binding.Name)"
        }
    }

    $Files = @(
        [pscustomobject]@{
            Name = "model-credentials.dpapi"
            Live = $FinalSecretStorePath
            New = $NewSecretStore
            HadLive = $HasExistingStore
        },
        [pscustomobject]@{
            Name = "model-credential-lock.state.json"
            Live = $FinalAntiRollbackStatePath
            New = $NewAntiRollbackState
            HadLive = $HasExistingState
        },
        [pscustomobject]@{
            Name = "model-credential-lock.json"
            Live = $FinalLockPath
            New = $NewLock
            HadLive = $HasExistingLock
        },
        [pscustomobject]@{
            Name = "agent.env"
            Live = $Context.ConfigPath
            New = $PreparedEnvironment
            HadLive = $true
        }
    )
    foreach ($File in $Files) {
        $File | Add-Member -NotePropertyName Backup `
            -NotePropertyValue (Join-Path $RollbackRoot $File.Name)
        $File | Add-Member -NotePropertyName Failed `
            -NotePropertyValue (Join-Path $FailedRoot $File.Name)
        $File | Add-Member -NotePropertyName BackupCreated `
            -NotePropertyValue $false
        $File | Add-Member -NotePropertyName Published `
            -NotePropertyValue $false
    }

    Stop-SelectedService -Context $Context -ServiceContext $ServiceContext
    Write-ModelCredentialRecoveryBlock -PathValue $RecoveryMarker `
        -TransactionId $TransactionId -StagingRoot $StageRoot -Context $Context
    $RecoveryMarkerWritten = $true

    foreach ($File in $Files) {
        if ([bool]$File.HadLive) {
            Assert-EAOrdinaryLeaf -Path $File.Live `
                -Name "现有配置 $($File.Name)" -MaximumBytes 1MB
            Move-Item -LiteralPath $File.Live -Destination $File.Backup
            $File.BackupCreated = $true
            Invoke-EAIcaclsChecked -ArgumentList @($File.Backup, "/reset")
        }
    }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $StageRoot
    foreach ($File in $Files) {
        Move-Item -LiteralPath $File.New -Destination $File.Live
        $File.Published = $true
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
    $ModelCredentialStatus = $Preflight.PSObject.Properties["model_credential"]
    if (-not [bool]$Preflight.valid -or
        [string]$Preflight.mine_id -ne $Context.MineId -or
        [string]$Preflight.system_id -ne $Context.SystemId -or
        $null -eq $ModelCredentialStatus -or
        -not [bool]$ModelCredentialStatus.Value.managed -or
        [int]$ModelCredentialStatus.Value.credential_version -ne
            [int]$ImportResult.credential_version -or
        [string]$ModelCredentialStatus.Value.mine_id -ne $Context.MineId -or
        [string]$ModelCredentialStatus.Value.system_id -ne $Context.SystemId -or
        [string]$ModelCredentialStatus.Value.party_id -ne $ExpectedPartyId -or
        [string]$ModelCredentialStatus.Value.pair_id -ne
            [string]$ImportResult.pair_id) {
        throw "模型凭据发布后的正式配置自检失败。"
    }
    Remove-ModelCredentialRecoveryBlock -PathValue $RecoveryMarker `
        -Context $Context
    $RecoveryMarkerWritten = $false
    if ($WasRunning) {
        Start-SelectedService -Context $Context -ServiceContext $ServiceContext
        $HealthScript = Resolve-EASafeLocalPath -Name "Agent health script" `
            -PathValue (Join-Path $InstallRoot `
                "deploy\windows\Test-EnterpriseAgentHealth.ps1") `
            -MustExist -RequiredType Leaf
        $HealthDeadline = [DateTime]::UtcNow.AddSeconds(30)
        $HealthVerified = $false
        $LastHealthError = "health probe did not run"
        do {
            try {
                & $HealthScript -InstanceName $InstanceName `
                    -InstallRoot $InstallRoot -StateRoot $StateRoot `
                    -TimeoutSeconds 5
                $HealthVerified = $true
                break
            }
            catch {
                $LastHealthError = $_.Exception.Message
                Start-Sleep -Milliseconds 500
            }
        } while ([DateTime]::UtcNow -lt $HealthDeadline)
        if (-not $HealthVerified) {
            throw "模型凭据更新后服务未通过实例绑定健康检查：$LastHealthError"
        }
    }
    $Committed = $true
    try {
        Remove-EAOwnedTemporaryTree -Path $StageRoot `
            -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
    }
    catch {
        Write-Warning "模型凭据已提交，但旧事务目录无法清理：$StageRoot"
    }
    [pscustomobject]@{
        status = if ($HasExistingLock) { "updated" } else { "imported" }
        instance_name = $InstanceName
        mine_id = $Context.MineId
        system_id = $Context.SystemId
        bundle_id = [string]$ImportResult.bundle_id
        credential_version = [int]$ImportResult.credential_version
        anti_rollback_state_path = $FinalAntiRollbackStatePath
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
                Write-ModelCredentialRecoveryBlock -PathValue $RecoveryMarker `
                    -TransactionId $TransactionId -StagingRoot $StageRoot `
                    -Context $Context
                $RecoveryMarkerWritten = $true
            }
            catch { $RollbackErrors += "重建阻断标记：$($_.Exception.Message)" }
        }
        for ($Index = $Files.Count - 1; $Index -ge 0; $Index -= 1) {
            $File = $Files[$Index]
            try {
                # A backup failure can leave later live files completely
                # untouched.  Move aside only files that this transaction
                # actually published; otherwise rollback would destroy an
                # unchanged live file merely because an earlier move failed.
                if ([bool]$File.Published -and
                    (Test-Path -LiteralPath $File.Live)) {
                    Move-Item -LiteralPath $File.Live -Destination $File.Failed
                    Invoke-EAIcaclsChecked -ArgumentList @($File.Failed, "/reset")
                }
                if ([bool]$File.BackupCreated -and
                    (Test-Path -LiteralPath $File.Backup)) {
                    if (Test-Path -LiteralPath $File.Live) {
                        throw "回滚目标仍被占用：$($File.Name)"
                    }
                    Move-Item -LiteralPath $File.Backup -Destination $File.Live
                }
            }
            catch { $RollbackErrors += "恢复 $($File.Name)：$($_.Exception.Message)" }
        }
        foreach ($File in $Files) {
            if ([bool]$File.HadLive -ne
                (Test-Path -LiteralPath $File.Live -PathType Leaf)) {
                $RollbackErrors += "恢复 $($File.Name)：回滚后的文件存在状态不正确"
            }
            if ([bool]$File.BackupCreated -and
                (Test-Path -LiteralPath $File.Backup)) {
                $RollbackErrors += "恢复 $($File.Name)：旧文件仍滞留在回滚目录"
            }
        }
        if ($RollbackErrors.Count -eq 0) {
            try { Set-EAInstanceCanonicalAcl -Context $Context }
            catch { $RollbackErrors += "恢复 ACL：$($_.Exception.Message)" }
        }
        if ($RollbackErrors.Count -eq 0) {
            try {
                $OldPreflight = Invoke-AgentJson -Executable $Context.Executable `
                    -Arguments @(
                        "--env-file", $Context.ConfigPath,
                        "--authoritative-env-file", "config-check", "--production"
                    ) -ExtraEnvironment @{
                        MINEGUARD_SERVICE_PRODUCTION_MODE = "true"
                        MINEGUARD_SERVICE_FOUR_EYES_REQUIRED = "true"
                        MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED = "true"
                        MINEGUARD_INTERNAL_PROVISIONING_UPDATE_TRANSACTION_ID = $TransactionId
                    }
                if (-not [bool]$OldPreflight.valid) {
                    throw "旧配置未通过正式自检。"
                }
            }
            catch { $RollbackErrors += "旧配置回滚自检：$($_.Exception.Message)" }
        }
        if ($RollbackErrors.Count -eq 0) {
            try {
                Remove-ModelCredentialRecoveryBlock -PathValue $RecoveryMarker `
                    -Context $Context
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
        catch { Write-Warning "回滚成功，但模型凭据事务目录无法清理：$StageRoot" }
    }
    if ($RollbackErrors.Count -ne 0) {
        throw (
            "模型凭据导入失败且自动回滚不完整；服务保持停止，阻断标记和事务目录已保留。" +
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
        catch { Write-Warning "无法清理未发布的模型凭据事务目录：$StageRoot" }
    }
}
