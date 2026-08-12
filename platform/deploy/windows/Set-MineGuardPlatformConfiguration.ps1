[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
    [string] $ClientsFile,
    [switch] $DemoWithoutClientRegistry,
    [string] $StateDirectory,
    [ValidateRange(1, 65535)] [int] $Port = 8080,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformSystemId = 'mineguard-qinyuan',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformPartyId = 'regulator-qinyuan',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformKeyId = 'regulator-key-v2',
    [string] $AdminUsername = 'admin',
    [Security.SecureString] $AdminPassword,
    [switch] $ManagedProvisioningRequired,
    [string] $ProvisioningTrustedPublicKeySource,
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ProvisioningExpectedPublicKeySha256,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $ProvisioningExpectedIssuerKeyId,
    [switch] $AllowDemoDefaultPassword,
    [switch] $HttpOnlyDemo,
    [switch] $NonInteractive,
    [switch] $ClearBootstrapPassword,
    [switch] $AuditFailAfterFirstMutation
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $identity
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) { throw '配置和保护秘密文件必须以管理员身份运行 Windows PowerShell。' }
}

function Throw-ConfigurationValidationFailure {
    param(
        [Parameter(Mandatory = $true)] [string] $Summary,
        [AllowNull()] [object] $CheckOutput
    )
    $detail = $null
    try {
        $failure = $CheckOutput | Out-String | ConvertFrom-Json
        if ($null -ne $failure.error -and
            $null -ne $failure.error.message) {
            $detail = [string]$failure.error.message
        }
    } catch {
        $detail = $null
    }
    if (-not [string]::IsNullOrWhiteSpace($detail)) {
        $detail = ($detail -replace '[\r\n\x00]+', ' ').Trim()
        if ($detail.Length -gt 512) {
            $detail = $detail.Substring(0, 512)
        }
        throw ("{0} 详情：{1}" -f $Summary, $detail)
    }
    throw $Summary
}

function Write-ConfigurationBlockMarker {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $TransactionDirectory,
        [Parameter(Mandatory = $true)]
        [ValidateSet('in_progress', 'rollback_incomplete')]
        [string] $Phase
    )
    $document = [ordered]@{
        schemaVersion = 1
        product = 'MineGuard Platform Configuration Guard'
        phase = $Phase
        transactionDirectory = $TransactionDirectory
        createdUtc = [DateTime]::UtcNow.ToString('o')
        recovery = '停止 MineGuardPlatform；管理员核验并清理上述精确事务目录；最后删除本阻断标记并重新配置。'
    }
    $temporary = $Path + ('.{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($document | ConvertTo-Json -Depth 4),
            $utf8NoBom
        )
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $null)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-ConfigAcl {
    param([string] $Path)
    Set-MineGuardPlatformCanonicalTreeAcl -Path $Path `
        -ServicePermission 'RX'
}

function Grant-BootstrapPasswordDeleteToService {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Grant-MineGuardPlatformBootstrapPasswordDeleteAcl -Path $Path
}

function Set-StateAcl {
    param([string] $Path)
    Set-MineGuardPlatformCanonicalTreeAcl -Path $Path `
        -ServicePermission 'M'
}

function Test-PathEqualOrChild {
    param([string] $Candidate, [string] $Parent)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith(
            $parentFull + '\', [StringComparison]::OrdinalIgnoreCase
        )
}

function Get-SafeLocalPath {
    param(
        [string] $Path,
        [string] $Label,
        [switch] $RequireFixedNtfs
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\')) {
        throw "$Label 不能使用 UNC/SMB 网络路径。"
    }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    if ($RequireFixedNtfs) {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
            throw "$Label 必须位于本机固定磁盘，不能使用映射盘或移动盘。"
        }
        if (-not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS') {
            throw "$Label 必须位于已就绪的 NTFS 磁盘。"
        }
    }
    $current = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 及其现有祖先目录不能包含符号链接、junction 或挂载点：$current"
            }
        }
        if ($current.TrimEnd('\') -eq $root.TrimEnd('\')) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $fullPath
}

function Assert-NoReparseTree {
    param([string] $Path, [string] $Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $pending = New-Object System.Collections.Queue
    $pending.Enqueue((Get-Item -LiteralPath $Path -Force))
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label 不能包含符号链接、junction 或挂载点：$($directory.FullName)"
        }
        foreach ($child in Get-ChildItem -LiteralPath $directory.FullName -Force) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 不能包含 reparse point：$($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child) }
        }
    }
}

function Assert-NoResidualConfigurationTransaction {
    param([Parameter(Mandatory = $true)] [string] $ConfigurationDirectory)
    $inspected = 0
    foreach ($child in Get-ChildItem -LiteralPath $ConfigurationDirectory -Force) {
        $inspected++
        if ($inspected -gt 256) {
            throw '配置目录直系子项超过 256 个安全上限；无法证明不存在残留配置事务。'
        }
        if ($child.PSIsContainer -and
            $child.Name -match '^\.configuration-transaction\.[A-Fa-f0-9]{32}$') {
            throw (
                '检测到残留配置事务目录，已拒绝继续：' + $child.FullName +
                '。请保持服务停止，由管理员核验并清理该精确目录后重新配置。'
            )
        }
    }
}

function Assert-StateBoundary {
    param([string] $Candidate, [string] $Root)
    $defaultState = Join-Path $Root 'state'
    if (Test-PathEqualOrChild -Candidate $Candidate -Parent $Root) {
        if (-not (Test-PathEqualOrChild -Candidate $Candidate -Parent $defaultState)) {
            throw '状态目录位于安装目录内时，只允许使用 Platform\state 或其专用子目录。'
        }
    } elseif (Test-PathEqualOrChild -Candidate $Root -Parent $Candidate) {
        throw '状态目录不能等于安装目录，也不能是安装目录的祖先。'
    }
}

function Initialize-StateOwnership {
    param([string] $Path, [string] $Root)
    $markerPath = Join-Path $Path '.mineguard-platform-state.json'
    $insideDefaultState = Test-PathEqualOrChild `
        -Candidate $Path -Parent (Join-Path $Root 'state')
    if (-not $insideDefaultState) {
        $entries = @(Get-ChildItem -LiteralPath $Path -Force)
        if ($entries.Count -gt 0 -and
            -not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            $allowedLegacyNames = @(
                'mineguard.db', 'mineguard.db-wal', 'mineguard.db-shm',
                'auth.db', 'auth.db-wal', 'auth.db-shm', 'backup.key',
                'backups', '.mineguard-platform.instance.lock',
                '.mineguard-v2-synthetic-owner.json'
            )
            $unexpected = @($entries | Where-Object {
                    $allowedLegacyNames -notcontains $_.Name
                })
            if ($unexpected.Count -gt 0 -or
                -not ((Test-Path -LiteralPath (Join-Path $Path 'mineguard.db') `
                        -PathType Leaf) -or
                    (Test-Path -LiteralPath (Join-Path $Path 'auth.db') `
                        -PathType Leaf))) {
                throw '外部状态目录必须为空、带 MineGuard 所有权标记，或是可识别的既有 MineGuard 状态根；拒绝对宽泛目录递归授权。'
            }
        }
    }
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        try {
            $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 |
                ConvertFrom-Json
        } catch {
            throw "状态目录所有权标记无效：$($_.Exception.Message)"
        }
        if ([int]$marker.schemaVersion -ne 1 -or
            [string]$marker.product -ne 'MineGuard Platform State') {
            throw '状态目录所有权标记不属于 MineGuard Platform。'
        }
    } else {
        $marker = [ordered]@{
            schemaVersion = 1
            product = 'MineGuard Platform State'
            initializedFor = $Root
        }
        [System.IO.File]::WriteAllText(
            $markerPath,
            ($marker | ConvertTo-Json -Depth 3),
            $utf8NoBom
        )
    }
}

Assert-Administrator
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$configurationMutex = New-Object -TypeName System.Threading.Mutex `
    -ArgumentList @($false, 'Global\MineGuardPlatform.Configuration')
$configurationMutexHeld = $false
$savedProvisioningEnvironment = @{}
foreach ($environmentName in @(
        'MINEGUARD_PROVISIONING_MANAGED_REQUIRED',
        'MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE',
        'MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256',
        'MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID'
    )) {
    $existingEnvironment = Get-Item -LiteralPath ('Env:' + $environmentName) `
        -ErrorAction SilentlyContinue
    $savedProvisioningEnvironment[$environmentName] = if (
        $null -eq $existingEnvironment
    ) { $null } else { [string]$existingEnvironment.Value }
}
try {
    try {
        $configurationMutexHeld = $configurationMutex.WaitOne(
            [TimeSpan]::FromSeconds(30)
        )
    } catch [System.Threading.AbandonedMutexException] {
        $configurationMutexHeld = $true
    }
    if (-not $configurationMutexHeld) {
        throw '另一项 MineGuard Platform 配置事务仍在运行；30 秒内未获得机器级配置锁。'
    }

$InstallRoot = Get-SafeLocalPath -Path $InstallRoot -Label '安装目录' `
    -RequireFixedNtfs
$configDirectory = Join-Path $InstallRoot 'config'
$settingsPath = Join-Path $configDirectory 'settings.json'
$bootstrapPath = Join-Path $configDirectory 'bootstrap-admin-password.txt'
$targetClientsPath = Join-Path $configDirectory 'clients.json'
$targetProvisioningPublicKeyPath = Join-Path $configDirectory `
    'provisioning-issuer-public.pem'
$configurationBlockMarker = Join-Path $configDirectory `
    '.mineguard-configuration-blocked.json'
$resolverPath = Join-Path $PSScriptRoot 'Resolve-MineGuardPlatformExecutable.ps1'
$aclHelperPath = Join-Path $PSScriptRoot 'MineGuardPlatform.WindowsAcl.ps1'
foreach ($requiredHelper in @($resolverPath, $aclHelperPath)) {
    if (-not (Test-Path -LiteralPath $requiredHelper -PathType Leaf)) {
        throw "找不到受信 helper：$requiredHelper。请重新安装 MineGuard Platform。"
    }
}
if (-not (Test-Path -LiteralPath $configDirectory -PathType Container)) {
    throw "找不到配置目录：$configDirectory。请先运行安装脚本。"
}
Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
Assert-NoResidualConfigurationTransaction `
    -ConfigurationDirectory $configDirectory
if (Test-Path -LiteralPath $configurationBlockMarker) {
    throw (
        '检测到上次配置事务未安全收尾，已拒绝继续。请停止 MineGuardPlatform，' +
        '由管理员查看 config\.mineguard-configuration-blocked.json 中的精确 transactionDirectory，' +
        '核验并清理该目录后，再删除该精确阻断标记并重新运行配置。'
    )
}
. $resolverPath
. $aclHelperPath
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot

$managedProvisioning = [bool]$ManagedProvisioningRequired
$trustedPublicKeySource = $null
$trustedPublicKeyPath = ''
$trustedPublicKeySha256 = ''
$trustedIssuerKeyId = ''
$existingSettings = $null
if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
    try {
        $existingSettings = Get-Content -LiteralPath $settingsPath -Raw `
            -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "现有 settings.json 无法解析；拒绝改写签发信任：$($_.Exception.Message)"
    }
    $existingManagedProperty = $existingSettings.PSObject.Properties[
        'managedProvisioningRequired'
    ]
    if ($null -ne $existingManagedProperty) {
        if ($existingManagedProperty.Value -isnot [bool]) {
            throw 'settings.json 的 managedProvisioningRequired 必须是 JSON 布尔值。'
        }
        if ([bool]$existingManagedProperty.Value) {
            # Once a managed registry is installed this script may preserve or
            # rotate its trust anchor, but it must never silently downgrade it.
            $managedProvisioning = $true
            if (-not $ManagedProvisioningRequired) {
                foreach ($requiredName in @(
                        'provisioningTrustedPublicKeyFile',
                        'provisioningExpectedPublicKeySha256',
                        'provisioningExpectedIssuerKeyId'
                    )) {
                    if ($null -eq $existingSettings.PSObject.Properties[$requiredName]) {
                        throw "受管配置缺少 $requiredName；拒绝降级覆盖。"
                    }
                }
                $trustedPublicKeyPath = [string](
                    $existingSettings.provisioningTrustedPublicKeyFile
                )
                $trustedPublicKeySha256 = [string](
                    $existingSettings.provisioningExpectedPublicKeySha256
                )
                $trustedIssuerKeyId = [string](
                    $existingSettings.provisioningExpectedIssuerKeyId
                )
            }
        }
    }
}
if ($ManagedProvisioningRequired) {
    if ([string]::IsNullOrWhiteSpace($ProvisioningTrustedPublicKeySource) -or
        [string]::IsNullOrWhiteSpace($ProvisioningExpectedPublicKeySha256) -or
        [string]::IsNullOrWhiteSpace($ProvisioningExpectedIssuerKeyId)) {
        throw '启用受管接入必须同时提供签发公钥、介质外 SPKI SHA-256 和 issuer key ID。'
    }
    $trustedPublicKeySource = Get-SafeLocalPath `
        -Path $ProvisioningTrustedPublicKeySource -Label '签发公钥来源'
    if (-not (Test-Path -LiteralPath $trustedPublicKeySource -PathType Leaf)) {
        throw "签发公钥来源不存在：$trustedPublicKeySource"
    }
    $trustedPublicKeyItem = Get-Item -LiteralPath $trustedPublicKeySource -Force
    if (($trustedPublicKeyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $trustedPublicKeyItem.Length -le 0 -or $trustedPublicKeyItem.Length -gt 65536) {
        throw '签发公钥来源必须是 1-65536 字节的普通 PEM 文件。'
    }
    $trustedPublicKeyPath = $targetProvisioningPublicKeyPath
    $trustedPublicKeySha256 = $ProvisioningExpectedPublicKeySha256
    $trustedIssuerKeyId = $ProvisioningExpectedIssuerKeyId
}
if ($managedProvisioning) {
    $trustedPublicKeyPath = Get-SafeLocalPath -Path $trustedPublicKeyPath `
        -Label '受信签发公钥路径' -RequireFixedNtfs
    if (-not $trustedPublicKeyPath.Equals(
            $targetProvisioningPublicKeyPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw '受信签发公钥必须固定为 config\provisioning-issuer-public.pem。'
    }
    if ($trustedPublicKeySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $trustedIssuerKeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw '受管签发公钥指纹或 issuer key ID 格式无效。'
    }
    $env:MINEGUARD_PROVISIONING_MANAGED_REQUIRED = 'true'
    $env:MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE = if (
        $null -ne $trustedPublicKeySource
    ) { $trustedPublicKeySource } else { $trustedPublicKeyPath }
    $env:MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256 = `
        $trustedPublicKeySha256
    $env:MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID = $trustedIssuerKeyId
} else {
    foreach ($environmentName in $savedProvisioningEnvironment.Keys) {
        Remove-Item -LiteralPath ('Env:' + $environmentName) `
            -ErrorAction SilentlyContinue
    }
}

if ($ClearBootstrapPassword) {
    if ($AuditFailAfterFirstMutation) {
        throw '-AuditFailAfterFirstMutation 不能用于 ClearBootstrapPassword。'
    }
    if ($null -ne $AdminPassword) {
        throw '-ClearBootstrapPassword 不能与 -AdminPassword 同时使用。'
    }
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw 'settings.json 尚不存在；拒绝删除首次管理员密码。'
    }
    $currentSettings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $currentState = Get-SafeLocalPath -Path ([string]$currentSettings.stateDirectory) `
        -Label 'settings.json 状态目录' -RequireFixedNtfs
    Assert-StateBoundary -Candidate $currentState -Root $InstallRoot
    Assert-NoReparseTree -Path $currentState -Label '状态目录'
    $authDatabase = Join-Path $currentState 'auth.db'
    if (-not (Test-Path -LiteralPath $authDatabase -PathType Leaf)) {
        throw 'auth.db 尚不存在；拒绝删除首次管理员密码，以免服务无法完成首启。'
    }
    $authCheck = @('config-check', '--auth-database', $authDatabase)
    $currentDemoProperty = $currentSettings.PSObject.Properties[
        'allowDemoDefaultPassword'
    ]
    if ($null -eq $currentDemoProperty -or
        $currentDemoProperty.Value -isnot [bool]) {
        throw 'settings.json 的 allowDemoDefaultPassword 必须是 JSON 布尔值。'
    }
    $currentClientsFile = [string]$currentSettings.clientsFile
    $currentSecureCookie = $currentSettings.secureCookie
    if ($currentSecureCookie -isnot [bool]) {
        throw 'settings.json 的 secureCookie 必须是 JSON 布尔值。'
    }
    $currentIsFormal = -not [string]::IsNullOrWhiteSpace($currentClientsFile)
    if ($currentIsFormal -and
        ([bool]$currentDemoProperty.Value -or -not [bool]$currentSecureCookie)) {
        throw '正式配置安全开关不一致；拒绝清除首启密码。'
    }
    if (-not $currentIsFormal -and
        (-not [bool]$currentDemoProperty.Value -or [bool]$currentSecureCookie)) {
        throw '演示配置安全开关不一致；拒绝清除首启密码。'
    }
    if ($currentIsFormal) { $authCheck += '--production' }
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments $authCheck
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝删除首次管理员密码。'
    }
    $check = $checkText | Out-String | ConvertFrom-Json
    if ([int]$check.auth_ready_admin_count -lt 1 -and
        $currentIsFormal) {
        throw 'auth.db 中尚无已完成改密的正式管理员；拒绝删除首次管理员密码。'
    }
    if ([int]$check.auth_user_count -lt 1) {
        throw 'auth.db 中尚无账号；拒绝删除首次管理员密码。'
    }
    Set-ConfigAcl -Path $configDirectory
    if (Test-Path -LiteralPath $bootstrapPath -PathType Leaf) {
        Remove-Item -LiteralPath $bootstrapPath -Force
        Write-Host '首次管理员明文密码文件已删除；auth.db 中仅保留密码摘要。'
    } else {
        Write-Host '首次管理员明文密码文件已经不存在。'
    }
    return
}

$service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne 'Stopped') {
    throw '修改 Platform 配置或状态目录前必须停止 MineGuardPlatform 服务。'
}
if ($AuditFailAfterFirstMutation -and
    $env:MINEGUARD_RELEASE_AUDIT_MODE -ne 'configuration-rollback-test') {
    throw 'AuditFailAfterFirstMutation 仅允许 Windows 发布流水线的配置回滚测试使用。'
}
if ($DemoWithoutClientRegistry -and -not [string]::IsNullOrWhiteSpace($ClientsFile)) {
    throw '-DemoWithoutClientRegistry 不能与 -ClientsFile 同时使用。'
}
if ($DemoWithoutClientRegistry -and $managedProvisioning) {
    throw '已启用受管企业接入后禁止降级为无客户端注册表的演示配置。'
}
if (-not $DemoWithoutClientRegistry -and [string]::IsNullOrWhiteSpace($ClientsFile)) {
    throw '正式配置必须提供 -ClientsFile；仅合成演示可显式使用 -DemoWithoutClientRegistry。'
}
if ($AllowDemoDefaultPassword -and -not $DemoWithoutClientRegistry) {
    throw '-AllowDemoDefaultPassword 只允许与 -DemoWithoutClientRegistry 一起使用。'
}
if ($HttpOnlyDemo -and -not $DemoWithoutClientRegistry) {
    throw '-HttpOnlyDemo 仅允许与 -DemoWithoutClientRegistry 一起使用；正式配置必须通过 HTTPS。'
}
if ($DemoWithoutClientRegistry -and
    (-not $AllowDemoDefaultPassword -or -not $HttpOnlyDemo)) {
    throw '演示配置必须同时显式启用 -AllowDemoDefaultPassword 和 -HttpOnlyDemo。'
}
if ([string]::IsNullOrWhiteSpace($AdminUsername) -or $AdminUsername.Length -gt 128) {
    throw '管理员用户名必须包含 1-128 个字符。'
}

$sourceClientsPath = $null
$validatedCount = 0
if (-not $DemoWithoutClientRegistry) {
    $sourceClientsPath = Get-SafeLocalPath -Path $ClientsFile `
        -Label '客户端注册表'
    if (-not (Test-Path -LiteralPath $sourceClientsPath -PathType Leaf)) {
        throw "客户端注册表不存在：$sourceClientsPath"
    }
    $sourceItem = Get-Item -LiteralPath $sourceClientsPath -Force
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw '客户端注册表不能是符号链接、junction 或其他 reparse point。'
    }
    if ($sourceItem.Length -gt (4 * 1024 * 1024)) {
        throw '客户端注册表超过 4 MiB 安全上限。'
    }
    $sourceText = Get-Content -LiteralPath $sourceClientsPath -Raw -Encoding UTF8
    if ($sourceText -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        throw '客户端注册表仍含示例/占位秘密；请生成独立随机密钥后再配置。'
    }
    $sourceText = $null
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--clients-file', $sourceClientsPath, '--production',
            '--platform-system-id', $PlatformSystemId,
            '--platform-party-id', $PlatformPartyId,
            '--platform-key-id', $PlatformKeyId
        )
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        Throw-ConfigurationValidationFailure `
            -Summary '客户端注册表未通过 MineGuard 完整校验。' `
            -CheckOutput $checkText
    }
    $validated = $checkText | Out-String | ConvertFrom-Json
    $validatedCount = [int]$validated.client_count
}

$defaultStateDirectory = Join-Path $InstallRoot 'state'
if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
    $stateDirectory = $defaultStateDirectory
} else {
    $stateDirectory = $StateDirectory
}
$stateDirectory = Get-SafeLocalPath -Path $stateDirectory -Label '状态目录' `
    -RequireFixedNtfs
Assert-StateBoundary -Candidate $stateDirectory -Root $InstallRoot
Assert-NoReparseTree -Path $stateDirectory -Label '状态目录'

if (-not $DemoWithoutClientRegistry) {
    $stateCheckArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--state-directory', $stateDirectory, '--production'
        )
    & $runtime.filePath @stateCheckArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '状态目录包含演示/合成数据或无法通过正式用途核验；请改用独立空目录。'
    }
}

$authDatabase = Join-Path $stateDirectory 'auth.db'
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--auth-database', $authDatabase)
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝覆盖管理员首启配置。'
    }
    $check = $checkText | Out-String | ConvertFrom-Json
    $hasAuthUser = ([int]$check.auth_user_count -ge 1)
    if (-not $DemoWithoutClientRegistry -and $hasAuthUser) {
        $productionCheckArguments = Join-MineGuardPlatformArguments `
            -Runtime $runtime -Arguments @(
                'config-check', '--auth-database', $authDatabase, '--production'
            )
        & $runtime.filePath @productionCheckArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw '现有 auth.db 没有已完成改密的正式管理员，或仍有启用的演示凭据账号。'
        }
    }
}
if ($null -eq $AdminPassword -and -not $hasAuthUser -and
    -not $AllowDemoDefaultPassword) {
    if ($NonInteractive) {
        throw '全新状态库需要 -AdminPassword；非交互模式不会回退到演示默认密码。'
    }
    $AdminPassword = Read-Host (
        '请输入正式管理员密码（至少 12 位，大小写字母、数字、符号至少三类）'
    ) -AsSecureString
}

$plainPassword = $null
if ($null -ne $AdminPassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
    try {
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($null -ne $bstr) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    if ($plainPassword.Length -lt 8 -or
        $plainPassword.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        $plainPassword = $null
        throw '首次管理员密码至少 8 个字符，且不得包含换行或 NUL。'
    }
    if ($plainPassword -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        $plainPassword = $null
        throw '首次管理员密码不能使用示例或占位文本。'
    }
    if (-not $DemoWithoutClientRegistry) {
        if ($plainPassword -ceq '123123123') {
            $plainPassword = $null
            throw '正式配置禁止使用演示默认密码 123123123。'
        }
        $categoryCount = 0
        if ($plainPassword -cmatch '[a-z]') { $categoryCount++ }
        if ($plainPassword -cmatch '[A-Z]') { $categoryCount++ }
        if ($plainPassword -match '[0-9]') { $categoryCount++ }
        if ($plainPassword -match '[^A-Za-z0-9]') { $categoryCount++ }
        if ($plainPassword.Length -lt 12 -or $categoryCount -lt 3) {
            $plainPassword = $null
            throw '正式管理员密码至少 12 个字符，并包含大小写字母、数字、符号中的至少三类。'
        }
        if ($plainPassword.ToLowerInvariant() -in @(
                'password123', 'admin123456', 'qwerty123'
            )) {
            $plainPassword = $null
            throw '正式管理员密码不能使用常见弱口令。'
        }
    }
}

if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $stateDirectory | Out-Null
}
$stateDirectory = Get-SafeLocalPath -Path $stateDirectory -Label '状态目录' `
    -RequireFixedNtfs
Assert-NoReparseTree -Path $stateDirectory -Label '状态目录'
Initialize-StateOwnership -Path $stateDirectory -Root $InstallRoot
Assert-NoReparseTree -Path $stateDirectory -Label '状态目录'

Set-ConfigAcl -Path $configDirectory
Set-StateAcl -Path $stateDirectory

$installedClientsPath = if ($DemoWithoutClientRegistry) { '' } else {
    $targetClientsPath
}
$settings = [ordered]@{
    schemaVersion = 1
    host = '127.0.0.1'
    port = $Port
    stateDirectory = $stateDirectory
    clientsFile = $installedClientsPath
    adminUsername = $AdminUsername
    secureCookie = (-not $HttpOnlyDemo)
    allowDemoDefaultPassword = [bool]$AllowDemoDefaultPassword
    platformSystemId = $PlatformSystemId
    platformPartyId = $PlatformPartyId
    platformKeyId = $PlatformKeyId
    managedProvisioningRequired = [bool]$managedProvisioning
    provisioningTrustedPublicKeyFile = $trustedPublicKeyPath
    provisioningExpectedPublicKeySha256 = $trustedPublicKeySha256
    provisioningExpectedIssuerKeyId = $trustedIssuerKeyId
}

$transactionRoot = Join-Path $configDirectory (
    '.configuration-transaction.{0}' -f [Guid]::NewGuid().ToString('N')
)
$stagedRoot = Join-Path $transactionRoot 'staged'
$rollbackRoot = Join-Path $transactionRoot 'rollback'
$operations = @()
$transactionComplete = $false
$rollbackComplete = $false
$mutationCount = 0
Write-ConfigurationBlockMarker -Path $configurationBlockMarker `
    -TransactionDirectory $transactionRoot -Phase 'in_progress'
try {
    New-Item -ItemType Directory -Path $stagedRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $rollbackRoot -Force | Out-Null

    if ($null -ne $trustedPublicKeySource) {
        $stagedProvisioningPublicKey = Join-Path $stagedRoot `
            'provisioning-issuer-public.pem'
        [System.IO.File]::WriteAllBytes(
            $stagedProvisioningPublicKey,
            [System.IO.File]::ReadAllBytes($trustedPublicKeySource)
        )
        $operations += [pscustomobject]@{
            Name = 'provisioning-public-key'
            Target = $targetProvisioningPublicKeyPath
            Stage = $stagedProvisioningPublicKey
            Backup = (Join-Path $rollbackRoot 'provisioning-issuer-public.pem')
            Action = 'write'; Started = $false; HadOriginal = $false
        }
    }

    if ($DemoWithoutClientRegistry) {
        $operations += [pscustomobject]@{
            Name = 'clients'; Target = $targetClientsPath; Stage = ''
            Backup = (Join-Path $rollbackRoot 'clients.json')
            Action = 'remove'; Started = $false; HadOriginal = $false
        }
    } else {
        $stagedClients = Join-Path $stagedRoot 'clients.json'
        [System.IO.File]::WriteAllBytes(
            $stagedClients,
            [System.IO.File]::ReadAllBytes($sourceClientsPath)
        )
        $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
            -Arguments @(
                'config-check', '--clients-file', $stagedClients, '--production',
                '--platform-system-id', $PlatformSystemId,
                '--platform-party-id', $PlatformPartyId,
                '--platform-key-id', $PlatformKeyId
            )
        $stagedCheckText = & $runtime.filePath @checkArguments
        if ($LASTEXITCODE -ne 0) {
            Throw-ConfigurationValidationFailure `
                -Summary '事务暂存的客户端注册表未通过 MineGuard 完整校验。' `
                -CheckOutput $stagedCheckText
        }
        $operations += [pscustomobject]@{
            Name = 'clients'; Target = $targetClientsPath; Stage = $stagedClients
            Backup = (Join-Path $rollbackRoot 'clients.json')
            Action = 'write'; Started = $false; HadOriginal = $false
        }
    }

    if ($null -ne $plainPassword) {
        $stagedPassword = Join-Path $stagedRoot 'bootstrap-admin-password.txt'
        [System.IO.File]::WriteAllText($stagedPassword, $plainPassword, $utf8NoBom)
        $plainPassword = $null
        $operations += [pscustomobject]@{
            Name = 'bootstrap-password'; Target = $bootstrapPath
            Stage = $stagedPassword
            Backup = (Join-Path $rollbackRoot 'bootstrap-admin-password.txt')
            Action = 'write'; Started = $false; HadOriginal = $false
        }
    }

    $stagedSettings = Join-Path $stagedRoot 'settings.json'
    [System.IO.File]::WriteAllText(
        $stagedSettings,
        ($settings | ConvertTo-Json -Depth 5),
        $utf8NoBom
    )
    $operations += [pscustomobject]@{
        Name = 'settings'; Target = $settingsPath; Stage = $stagedSettings
        Backup = (Join-Path $rollbackRoot 'settings.json')
        Action = 'write'; Started = $false; HadOriginal = $false
    }

    foreach ($operation in $operations) {
        $operation.Started = $true
        if (Test-Path -LiteralPath $operation.Target -PathType Leaf) {
            Move-Item -LiteralPath $operation.Target -Destination $operation.Backup
            $operation.HadOriginal = $true
        }
        if ($operation.Action -eq 'write') {
            Move-Item -LiteralPath $operation.Stage -Destination $operation.Target
        }
        $mutationCount++
        if ($AuditFailAfterFirstMutation -and $mutationCount -eq 1) {
            throw '发布审计故障注入：验证 clients/password/settings 配置事务回滚。'
        }
    }
    Set-ConfigAcl -Path $configDirectory
    Grant-BootstrapPasswordDeleteToService -Path $bootstrapPath
    $transactionComplete = $true
} catch {
    $configurationError = $_
    $rollbackErrors = @()
    for ($index = $operations.Count - 1; $index -ge 0; $index--) {
        $operation = $operations[$index]
        if (-not $operation.Started) { continue }
        try {
            if (Test-Path -LiteralPath $operation.Target -PathType Leaf) {
                Remove-Item -LiteralPath $operation.Target -Force
            }
            if ($operation.HadOriginal -and
                (Test-Path -LiteralPath $operation.Backup -PathType Leaf)) {
                Move-Item -LiteralPath $operation.Backup -Destination $operation.Target
            }
        } catch {
            $rollbackErrors += ('{0}: {1}' -f `
                $operation.Name, $_.Exception.Message)
        }
    }
    if ($rollbackErrors.Count -gt 0) {
        try {
            Write-ConfigurationBlockMarker -Path $configurationBlockMarker `
                -TransactionDirectory $transactionRoot `
                -Phase 'rollback_incomplete'
        } catch {
            $rollbackErrors += ('blocking-marker: {0}' -f $_.Exception.Message)
        }
        throw ((
            'Platform 配置失败且自动回滚不完整；为避免丢失旧配置，已保留事务目录 {0}。' +
            '请停止操作并由管理员恢复 rollback 子目录。原始错误：{1}；回滚错误：{2}'
        ) -f `
                $transactionRoot, $configurationError.Exception.Message,
                ($rollbackErrors -join ' | ')
        )
    }
    $rollbackComplete = $true
    throw $configurationError
} finally {
    $plainPassword = $null
    if (($transactionComplete -or $rollbackComplete) -and
        (Test-Path -LiteralPath $transactionRoot)) {
        Remove-Item -LiteralPath $transactionRoot -Recurse -Force
    }
    if (($transactionComplete -or $rollbackComplete) -and
        (Test-Path -LiteralPath $configurationBlockMarker -PathType Leaf)) {
        Remove-Item -LiteralPath $configurationBlockMarker -Force -ErrorAction Stop
    }
}
if (-not $transactionComplete) { throw 'Platform 配置事务未完成。' }

if (-not $DemoWithoutClientRegistry) {
    Write-Host "客户端注册表已校验：$validatedCount 座煤矿。"
}
Write-Host 'MineGuard Platform 配置已原子保存；秘密未写入 WinSW XML 或命令行。'
if (-not $HttpOnlyDemo) {
    Write-Host '会话 Cookie 已启用 Secure；必须通过 HTTPS 反向代理访问。'
} else {
    Write-Warning '当前为 HTTP 本机演示模式，不能用于正式内网。'
}
if ($null -ne $AdminPassword) {
    Write-Host '首次正式启动会由短生命周期 helper 建立密码摘要，并在成功后自动删除首启明文文件。'
    Write-Host '若摘要建立或删除失败，长运行服务会拒绝启动；请按错误核验 auth.db 后再使用受控清理选项。'
}
Write-Host '配置修改需重启 MineGuardPlatform 服务后生效。'
} finally {
    foreach ($environmentName in $savedProvisioningEnvironment.Keys) {
        $savedValue = $savedProvisioningEnvironment[$environmentName]
        if ($null -eq $savedValue) {
            Remove-Item -LiteralPath ('Env:' + $environmentName) `
                -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath ('Env:' + $environmentName) `
                -Value ([string]$savedValue)
        }
    }
    if ($configurationMutexHeld) {
        try { $configurationMutex.ReleaseMutex() }
        catch { }
    }
    if ($null -ne $configurationMutex) { $configurationMutex.Dispose() }
}
