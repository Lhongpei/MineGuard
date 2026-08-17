[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundlePath,
    [Parameter(Mandatory = $true)][string]$InstanceName,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
    [Parameter(Mandatory = $true)][string]$BusinessAdminActorId,
    [Parameter(Mandatory = $true)][string]$BusinessAdminName,
    [Parameter(Mandatory = $true)][Security.SecureString]$BusinessAdminPassword,
    [Parameter(Mandatory = $true)][Security.SecureString]$BusinessAdminPasswordConfirmation,
    [Parameter(Mandatory = $true)][Security.SecureString]$ApiAdminPassword,
    [Parameter(Mandatory = $true)][Security.SecureString]$ApiAdminPasswordConfirmation,
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
    throw "请在管理员 PowerShell 或开始菜单配置向导中执行接入包导入。"
}

function Assert-ActorInput {
    param([string]$Label, [string]$ActorId, [string]$DisplayName)
    if ($ActorId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$') {
        throw "$Label 登录名格式不正确。"
    }
    if ([string]::IsNullOrWhiteSpace($DisplayName) -or
        $DisplayName.Length -gt 128 -or
        $DisplayName.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "$Label 姓名必须为 1-128 个字符且不能换行。"
    }
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
    $Extension = [IO.Path]::GetExtension($FullPath)
    $Extension = $Extension.ToLowerInvariant()
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

function Invoke-AgentProcess {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [Security.SecureString[]]$SecureInputLines = @(),
        [int]$MaximumOutputCharacters = 131072
    )
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = (@($Arguments | ForEach-Object {
        if ($null -eq $_) { throw "拒绝把 null 作为 Agent 参数。" }
        ConvertTo-NativeArgument -Value ([string]$_)
    }) -join ' ')
    $StartInfo.WorkingDirectory = Split-Path -Parent $Executable
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardInput = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $StartInfo.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) { throw "Agent 子进程启动失败。" }
        foreach ($SecureLine in $SecureInputLines) {
            $Pointer = [IntPtr]::Zero
            $Plaintext = $null
            try {
                $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                    $SecureLine
                )
                $Plaintext = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                    $Pointer
                )
                if ($Plaintext.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
                    throw "安全输入不能包含 NUL 或换行。"
                }
                $Process.StandardInput.WriteLine($Plaintext)
                $Process.StandardInput.Flush()
            }
            finally {
                $Plaintext = $null
                if ($Pointer -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
                }
            }
        }
        $Process.StandardInput.Close()
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
        return $Stdout.Trim()
    }
    finally {
        $Process.Dispose()
    }
}

function Convert-SecureStringForComparison {
    param([Security.SecureString]$Value)
    $Pointer = [IntPtr]::Zero
    try {
        $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
    }
    finally {
        if ($Pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
        }
    }
}

function Test-SecureStringEqual {
    param([Security.SecureString]$Left, [Security.SecureString]$Right)
    $LeftText = $null
    $RightText = $null
    try {
        $LeftText = Convert-SecureStringForComparison -Value $Left
        $RightText = Convert-SecureStringForComparison -Value $Right
        return [string]::Equals(
            $LeftText, $RightText, [StringComparison]::Ordinal
        )
    }
    finally {
        $LeftText = $null
        $RightText = $null
    }
}

function Get-ProductionPasswordRecord {
    param([string]$Executable, [Security.SecureString]$Password)
    $Output = Invoke-AgentProcess -Executable $Executable -Arguments @(
        "hash-password", "--password-stdin", "--production", "--json"
    ) -SecureInputLines @($Password) -MaximumOutputCharacters 16384
    try { $Record = $Output | ConvertFrom-Json }
    catch { throw "Agent 密码摘要命令未返回有效 JSON。" }
    if ($null -eq $Record -or
        [string]$Record.password_hash -notmatch '^pbkdf2_sha256\$[0-9]+\$' -or
        [string]$Record.credential_provenance -ne "production_hash_command" -or
        [bool]$Record.must_change_password) {
        throw "Agent 密码摘要命令返回了不受支持的正式凭据记录。"
    }
    return $Record
}

function Set-EnvironmentRecord {
    param([string]$Content, [string]$Name, [string]$Value)
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$' -or
        $Value.IndexOfAny(@([char]0, [char]10, [char]13)) -ge 0) {
        throw "本地环境记录不安全：$Name"
    }
    $Pattern = '(?m)^' + [regex]::Escape($Name) + '=.*$'
    $Matches = [regex]::Matches($Content, $Pattern)
    if ($Matches.Count -gt 1) { throw "实例模板含重复配置项：$Name" }
    $Replacement = $Name + '=' + $Value
    if ($Matches.Count -eq 1) {
        # Password hashes contain '$'.  Escape it for the .NET regex
        # replacement grammar so no hash segment can be interpreted as a
        # capture-group reference.
        $LiteralReplacement = $Replacement.Replace('$', '$$')
        return [regex]::Replace($Content, $Pattern, $LiteralReplacement)
    }
    $TrimCharacters = [char[]]@([char]13, [char]10)
    return $Content.TrimEnd($TrimCharacters) + [Environment]::NewLine + `
        $Replacement + [Environment]::NewLine
}

Assert-EAInstanceName -Value $InstanceName
if ($InstanceName -notmatch '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$') {
    throw "正式接入实例名只允许 1-64 位英文小写字母、数字和中间短横线。"
}
Assert-ActorInput -Label "企业管理员" -ActorId $BusinessAdminActorId `
    -DisplayName $BusinessAdminName
if ($BusinessAdminActorId.Equals(
        'api_admin', [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "企业管理员登录名不能使用保留账号 api_admin。"
}
if (-not (Test-SecureStringEqual $BusinessAdminPassword `
        $BusinessAdminPasswordConfirmation)) {
    throw "企业管理员两次输入的密码不一致。"
}
if (-not (Test-SecureStringEqual $ApiAdminPassword `
        $ApiAdminPasswordConfirmation)) {
    throw "api_admin 两次输入的密码不一致。"
}
if (Test-SecureStringEqual $BusinessAdminPassword $ApiAdminPassword) {
    throw "企业管理员与 api_admin 不能使用相同密码。"
}

$BundlePath = Resolve-ProvisioningInputFile -Name "企业接入包" `
    -PathValue $BundlePath -MaximumBytes 4MB -AllowedExtensions @('.mgprov')

$InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" `
    -PathValue $InstallRoot -MustExist -RequiredType Container -CheckTree
$StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" -PathValue $StateRoot `
    -MustExist -RequiredType Container
[void](Assert-EAStateRootMarker -StateRoot $StateRoot)
$AgentExecutable = Get-EAAgentExecutable -InstallRoot $InstallRoot
$Template = Resolve-EASafeLocalPath -Name "Agent instance template" `
    -PathValue (Join-Path $InstallRoot "deploy\windows\agent.env.template") `
    -MustExist -RequiredType Leaf
$NewInstanceScript = Resolve-EASafeLocalPath -Name "Instance creator" `
    -PathValue (Join-Path $InstallRoot `
        "deploy\windows\New-EnterpriseAgentInstance.ps1") `
    -MustExist -RequiredType Leaf
$InstanceRoot = Join-Path $StateRoot $InstanceName
if (Test-Path -LiteralPath $InstanceRoot) {
    throw "实例已存在，接入包导入绝不会覆盖：$InstanceRoot"
}

$FinalDatabasePath = Join-Path $InstanceRoot "data\enterprise-agent.db"
$FinalInboxPath = Join-Path $InstanceRoot "inbox"
$FinalConfigDirectory = Join-Path $InstanceRoot "config"
$FinalLockPath = Join-Path $FinalConfigDirectory "provisioning-lock.json"
$FinalSecretStorePath = Join-Path $FinalConfigDirectory `
    "provisioning-secrets.dpapi"
$FinalModelConfigPath = Join-Path $FinalConfigDirectory "model-api.json"

$TransactionRoot = Join-Path $StateRoot `
    (".instance-staging-" + [Guid]::NewGuid().ToString("N"))
$TransactionCreated = $false
try {
    New-Item -ItemType Directory -Path $TransactionRoot -ErrorAction Stop | `
        Out-Null
    $TransactionCreated = $true
    # The transaction is still empty.  Harden its root in one native ACL
    # operation before writing hashes, password records or DPAPI material;
    # every subsequently created file inherits this administrative boundary.
    Invoke-EAIcaclsChecked -ArgumentList @(
        $TransactionRoot,
        "/inheritance:r",
        "/grant:r", "*S-1-5-18:(OI)(CI)F",
        "/grant:r", "*S-1-5-32-544:(OI)(CI)F"
    )

    $BusinessAdminRecord = Get-ProductionPasswordRecord `
        -Executable $AgentExecutable -Password $BusinessAdminPassword
    $ApiAdminRecord = Get-ProductionPasswordRecord `
        -Executable $AgentExecutable -Password $ApiAdminPassword
    $Users = @(
        [ordered]@{
            actor_id = $BusinessAdminActorId
            name = $BusinessAdminName.Trim()
            role = "企业管理员"
            password_hash = [string]$BusinessAdminRecord.password_hash
            permissions = @("read", "write", "confirm", "submit")
            must_change_password = $false
            credential_provenance = "production_hash_command"
        },
        [ordered]@{
            actor_id = "api_admin"
            name = "API 配置管理员"
            role = "API 配置管理员"
            password_hash = [string]$ApiAdminRecord.password_hash
            permissions = @("model_api_admin")
            must_change_password = $false
            credential_provenance = "production_hash_command"
        }
    )
    $UsersJson = $Users | ConvertTo-Json -Compress -Depth 8

    $BaseEnvironment = [IO.File]::ReadAllText($Template)
    $TemplateReplacements = @{
        "__DATABASE_PATH__" = $FinalDatabasePath
        "__PORT__" = $Port.ToString()
        "__MINE_ID__" = "pending-signed-mine"
        "__MINE_NAME__" = "pending-signed-mine"
        "__OPERATOR_ID__" = "pending-signed-operator"
        "__OPERATOR_NAME__" = "pending-signed-operator"
        "__SYSTEM_ID__" = "pending-signed-system"
        "__WATCH_DIRECTORIES__" = $FinalInboxPath
    }
    foreach ($Entry in $TemplateReplacements.GetEnumerator()) {
        $BaseEnvironment = $BaseEnvironment.Replace(
            [string]$Entry.Key, [string]$Entry.Value
        )
    }
    if ($BaseEnvironment -match '__[A-Z0-9_]+__') {
        throw "Agent 实例模板含未解析占位符。"
    }
    $BaseEnvironment = Set-EnvironmentRecord -Content $BaseEnvironment `
        -Name "ENTERPRISE_AGENT_USERS_JSON" -Value $UsersJson
    $BaseEnvironment = Set-EnvironmentRecord -Content $BaseEnvironment `
        -Name "ENTERPRISE_PROVISIONING_LOCK_FILE" -Value $FinalLockPath
    $BaseEnvironment = Set-EnvironmentRecord -Content $BaseEnvironment `
        -Name "ENTERPRISE_PROVISIONING_SECRET_STORE" -Value $FinalSecretStorePath
    $BaseEnvironment = Set-EnvironmentRecord -Content $BaseEnvironment `
        -Name "ENTERPRISE_AGENT_MODEL_CONFIG_FILE" -Value $FinalModelConfigPath
    # The signed bundle owns every exchange-secret namespace.  Even the
    # harmless-looking JSON literal [] is truthy to the fail-closed importer,
    # so the local base must leave this key empty rather than inherit it.
    $BaseEnvironment = Set-EnvironmentRecord -Content $BaseEnvironment `
        -Name "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON" -Value ""

    $BaseEnvironmentPath = Join-Path $TransactionRoot "base-agent.env"
    $ProvisionedEnvironmentPath = Join-Path $TransactionRoot `
        "provisioned-agent.env"
    $ProvisioningLockPath = Join-Path $TransactionRoot `
        "provisioning-lock.json"
    $SecretStorePath = Join-Path $TransactionRoot `
        "provisioning-secrets.dpapi"
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    $Stream = New-Object IO.FileStream(
        $BaseEnvironmentPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $Bytes = $Utf8NoBom.GetBytes($BaseEnvironment)
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    }
    finally { $Stream.Dispose() }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $TransactionRoot

    # The self-contained .mgprov package carries its signed encrypted payload,
    # activation material and issuer public key.  The importer validates all
    # bindings before DPAPI LocalMachine protection and CreateNew writes.
    $ImportOutput = Invoke-AgentProcess -Executable $AgentExecutable `
        -Arguments @(
            "provision-import", "--bundle", $BundlePath,
            "--base-env", $BaseEnvironmentPath,
            "--output-env", $ProvisionedEnvironmentPath,
            "--lock-output", $ProvisioningLockPath,
            "--secret-store", $SecretStorePath,
            "--secret-protection", "dpapi-local-machine",
            "--lock-env-path", $FinalLockPath,
            "--secret-store-env-path", $FinalSecretStorePath
        )
    try { $ImportResult = $ImportOutput | ConvertFrom-Json }
    catch { throw "接入包导入器未返回有效 JSON。" }
    if ($null -eq $ImportResult -or -not [bool]$ImportResult.valid) {
        throw "接入包未通过正式验签和解密检查。"
    }
    Assert-EAProtectedSnapshotAcl -SnapshotRoot $TransactionRoot

    $ProvisionedValues = Read-EAEnvironmentFile `
        -Path $ProvisionedEnvironmentPath
    foreach ($Required in @(
        "ENTERPRISE_MINE_ID", "ENTERPRISE_MINE_NAME",
        "ENTERPRISE_OPERATOR_ID", "ENTERPRISE_OPERATOR_NAME",
        "ENTERPRISE_SYSTEM_ID", "PLATFORM_V3_SENDER_ID"
    )) {
        if (-not $ProvisionedValues.ContainsKey($Required) -or
            [string]::IsNullOrWhiteSpace([string]$ProvisionedValues[$Required])) {
            throw "接入包导入结果缺少锁定身份：$Required"
        }
    }
    if ([string]$ProvisionedValues["ENTERPRISE_AGENT_DB"] -ne
            $FinalDatabasePath -or
        [string]$ProvisionedValues["ENTERPRISE_AGENT_HOST"] -ne "127.0.0.1" -or
        [string]$ProvisionedValues["ENTERPRISE_AGENT_PORT"] -ne
            $Port.ToString() -or
        [string]$ProvisionedValues["ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS"] -ne
            $FinalInboxPath -or
        [string]$ProvisionedValues["ENTERPRISE_SYSTEM_ID"] -ne
            [string]$ProvisionedValues["PLATFORM_V3_SENDER_ID"]) {
        throw "签名配置与本机实例边界不一致。"
    }

    $NewInstanceOutput = & $NewInstanceScript `
        -InstanceName $InstanceName `
        -MineId ([string]$ProvisionedValues["ENTERPRISE_MINE_ID"]) `
        -MineName ([string]$ProvisionedValues["ENTERPRISE_MINE_NAME"]) `
        -OperatorId ([string]$ProvisionedValues["ENTERPRISE_OPERATOR_ID"]) `
        -OperatorName ([string]$ProvisionedValues["ENTERPRISE_OPERATOR_NAME"]) `
        -SystemId ([string]$ProvisionedValues["ENTERPRISE_SYSTEM_ID"]) `
        -Port $Port `
        -InstallRoot $InstallRoot `
        -StateRoot $StateRoot `
        -ProvisionedEnvironmentFile $ProvisionedEnvironmentPath `
        -ProvisioningLockFile $ProvisioningLockPath `
        -ProvisioningSecretStoreFile $SecretStorePath | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "实例创建事务失败，退出码 $LASTEXITCODE。"
    }
    $TransactionCreated = $false
    [pscustomobject]@{
        status = "configured"
        instance_name = $InstanceName
        mine_id = [string]$ProvisionedValues["ENTERPRISE_MINE_ID"]
        mine_name = [string]$ProvisionedValues["ENTERPRISE_MINE_NAME"]
        system_id = [string]$ProvisionedValues["ENTERPRISE_SYSTEM_ID"]
        port = $Port
        platform_origin = [string]$ProvisionedValues["PLATFORM_V3_BASE_URL"]
        profile_version = $ImportResult.profile_version
        bundle_id = $ImportResult.bundle_id
        package_sha256 = (Get-FileHash -LiteralPath $BundlePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        tls_trust = "operating-system"
        production_preflight = "passed"
    }
}
catch {
    $OriginalError = $_
    if ($TransactionCreated -and (Test-Path -LiteralPath $TransactionRoot)) {
        try {
            Remove-EAOwnedTemporaryTree -Path $TransactionRoot `
                -ExpectedParent $StateRoot -RequiredPrefix ".instance-staging-"
        }
        catch {
            Write-Warning (
                "导入失败后的受保护事务目录无法清理，请保持管理员隔离并人工处理：" +
                $TransactionRoot
            )
        }
    }
    throw $OriginalError
}
