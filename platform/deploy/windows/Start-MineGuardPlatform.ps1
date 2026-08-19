[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "settings.json 缺少必填项：$Name"
    }
    return $property.Value
}

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Value)
    if ($Value.IndexOf([char]0) -ge 0) {
        throw '拒绝把 NUL 传给 Platform 长运行进程。'
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object -TypeName System.Text.StringBuilder
    [void]$builder.Append([char]'"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashes++
            continue
        }
        if ($character -eq [char]'"') {
            [void]$builder.Append([char]'\', (($backslashes * 2) + 1))
            [void]$builder.Append([char]'"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]'\', $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]'\', ($backslashes * 2))
    }
    [void]$builder.Append([char]'"')
    return $builder.ToString()
}

function Join-WindowsCommandLineArguments {
    param([Parameter(Mandatory = $true)] [object[]] $Arguments)
    return (@(foreach ($argument in $Arguments) {
                if ($null -eq $argument) {
                    throw '拒绝把 null 作为 Platform 长运行进程参数。'
                }
                ConvertTo-WindowsCommandLineArgument -Value ([string]$argument)
            }) -join ' ')
}

function Get-SafeFixedNtfsPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    try {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or
            -not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS') {
            throw "$Label 必须位于已就绪的本机固定 NTFS 磁盘。"
        }
    } catch [System.ArgumentException] {
        throw "$Label 所在磁盘无法识别。"
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

function Test-PathEqualOrChild {
    param([string] $Candidate, [string] $Parent)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith(
            $parentFull + '\', [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-NoReparseTree {
    param([string] $Path, [string] $Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $rootItem = Get-Item -LiteralPath $Path -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label 不能是符号链接、junction 或挂载点：$Path"
    }
    if (-not $rootItem.PSIsContainer) { return }
    $pending = New-Object System.Collections.Queue
    $pending.Enqueue($rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($child in Get-ChildItem -LiteralPath $directory.FullName -Force) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 不能包含 reparse point：$($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child) }
        }
    }
}

function Assert-InternalUnsignedPlatformReleaseTree {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [object] $Manifest,
        [Parameter(Mandatory = $true)] [string] $ExpectedManifestSha256
    )
    $metadataRoot = Join-Path $Root 'release-metadata'
    $runtimeRoot = Join-Path $Root 'runtime'
    $serviceRoot = Join-Path $Root 'service'
    $manifestPath = Join-Path $metadataRoot 'release-manifest.json'
    foreach ($tree in @($metadataRoot, $runtimeRoot, $serviceRoot)) {
        Assert-NoReparseTree -Path $tree -Label 'INTERNAL-UNSIGNED 发行目录'
    }
    $actualManifestSha256 = (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash
    if (-not $actualManifestSha256.Equals(
            $ExpectedManifestSha256,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'INTERNAL-UNSIGNED 发行清单与安装时持久化的信任锚不一致。'
    }
    $expected = @{}
    foreach ($entry in @($Manifest.files)) {
        $relative = [string]$entry.path
        $parts = $relative.Split('/')
        if ([string]::IsNullOrWhiteSpace($relative) -or
            [IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or
            $relative.Contains('\') -or $parts -contains '' -or
            $parts -contains '.' -or $parts -contains '..' -or
            $expected.ContainsKey($relative) -or
            [string]$entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            [long]$entry.bytes -lt 0) {
            throw "INTERNAL-UNSIGNED 发行清单文件证据无效：$relative"
        }
        $installedPath = if ($relative.StartsWith(
                'runtime/', [StringComparison]::Ordinal
            )) {
            Join-Path $runtimeRoot $relative.Substring('runtime/'.Length).Replace('/', '\')
        }
        elseif ($relative.StartsWith(
                'deploy/windows/', [StringComparison]::Ordinal
            )) {
            Join-Path $serviceRoot $relative.Substring('deploy/windows/'.Length).Replace('/', '\')
        }
        elseif ($relative -in @('VERSION.txt', 'build-metadata.json')) {
            Join-Path $metadataRoot $relative
        }
        else {
            throw "INTERNAL-UNSIGNED 发行清单包含无法映射的文件：$relative"
        }
        if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
            throw "INTERNAL-UNSIGNED 发行文件缺失：$relative"
        }
        $item = Get-Item -LiteralPath $installedPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [long]$item.Length -ne [long]$entry.bytes -or
            -not (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash.Equals(
                [string]$entry.sha256, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "INTERNAL-UNSIGNED 发行文件与受信清单不一致：$relative"
        }
        $expected[$relative] = $true
    }
    if (-not $expected.ContainsKey('runtime/MineGuardPlatform.exe')) {
        throw 'INTERNAL-UNSIGNED 发行清单缺少 Platform 主程序。'
    }

    $actual = @{}
    foreach ($file in Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse -Force) {
        $relative = 'runtime/' + $file.FullName.Substring(
            $runtimeRoot.Length
        ).TrimStart('\').Replace('\', '/')
        $actual[$relative] = $true
    }
    foreach ($file in Get-ChildItem -LiteralPath $serviceRoot -File -Recurse -Force) {
        $serviceRelative = $file.FullName.Substring(
            $serviceRoot.Length
        ).TrimStart('\').Replace('\', '/')
        if ($serviceRelative -in @(
                'MineGuard.Platform.exe', 'MineGuard.Platform.exe.config',
                'winsw-integrity.json'
            )) {
            continue
        }
        $actual['deploy/windows/' + $serviceRelative] = $true
    }
    foreach ($file in Get-ChildItem -LiteralPath $metadataRoot -File -Recurse -Force) {
        $relative = $file.FullName.Substring($metadataRoot.Length).TrimStart('\').Replace('\', '/')
        if ($relative -in @(
                'release-manifest.json', 'SHA256SUMS.txt',
                'release-trust-anchor.json'
            )) {
            continue
        }
        if ($relative -notin @('VERSION.txt', 'build-metadata.json')) {
            throw "INTERNAL-UNSIGNED release-metadata 包含清单外文件：$relative"
        }
        $actual[$relative] = $true
    }
    if ($actual.Count -ne $expected.Count) {
        throw 'INTERNAL-UNSIGNED 实际文件集合与受信发行清单不一致。'
    }
    foreach ($relative in $actual.Keys) {
        if (-not $expected.ContainsKey($relative)) {
            throw "INTERNAL-UNSIGNED 运行树包含清单外文件：$relative"
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
                '检测到残留配置事务目录，已拒绝启动：' + $child.FullName +
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

function Assert-StateOwnership {
    param([string] $Path)
    $markerPath = Get-SafeFixedNtfsPath `
        -Value (Join-Path $Path '.mineguard-platform-state.json') `
        -Label '状态目录所有权标记'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw '状态目录缺少 MineGuard 所有权标记；请先运行 Set-MineGuardPlatformConfiguration.ps1。'
    }
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
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$InstallRoot = Get-SafeFixedNtfsPath -Value $InstallRoot -Label '安装目录'
$configDirectory = Get-SafeFixedNtfsPath `
    -Value (Join-Path $InstallRoot 'config') -Label '配置目录'
$configurationMutex = New-Object -TypeName System.Threading.Mutex `
    -ArgumentList @($false, 'Global\MineGuardPlatform.Configuration')
$configurationMutexHeld = $false
$serverProcess = $null
$localControlToken = $null
try {
    try {
        $configurationMutexHeld = $configurationMutex.WaitOne(
            [TimeSpan]::FromSeconds(30)
        )
    } catch [System.Threading.AbandonedMutexException] {
        $configurationMutexHeld = $true
    }
    if (-not $configurationMutexHeld) {
        throw '配置事务仍在运行；30 秒内未获得机器级配置锁，已拒绝启动。'
    }
Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
Assert-NoResidualConfigurationTransaction `
    -ConfigurationDirectory $configDirectory
$configurationBlockMarker = Get-SafeFixedNtfsPath `
    -Value (Join-Path $configDirectory '.mineguard-configuration-blocked.json') `
    -Label '配置事务阻断标记'
if (Test-Path -LiteralPath $configurationBlockMarker) {
    throw (
        '检测到未安全收尾的配置事务，已拒绝启动。请保持服务停止，由管理员查看 ' +
        'config\.mineguard-configuration-blocked.json 中的精确 transactionDirectory，' +
        '核验并清理该目录后，再删除该精确阻断标记并重新配置。'
    )
}
$settingsPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $configDirectory 'settings.json') -Label 'settings.json'
if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "找不到配置文件：$settingsPath。请先运行 Set-MineGuardPlatformConfiguration.ps1。"
}

try {
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
} catch {
    throw "settings.json 不是有效 JSON：$($_.Exception.Message)"
}
if ([int](Get-RequiredProperty -Object $settings -Name 'schemaVersion') -ne 1) {
    throw '不支持的 settings.json 版本。'
}

$hostAddress = [string](Get-RequiredProperty -Object $settings -Name 'host')
if ($hostAddress -ne '127.0.0.1') {
    throw 'Windows 正式运行只允许监听 127.0.0.1；请由 HTTPS 反向代理对外服务。'
}
$port = [int](Get-RequiredProperty -Object $settings -Name 'port')
if ($port -lt 1 -or $port -gt 65535) {
    throw '监听端口必须在 1-65535 之间。'
}
$stateDirectory = Get-SafeFixedNtfsPath `
    -Value ([string](Get-RequiredProperty -Object $settings -Name 'stateDirectory')) `
    -Label '状态目录'
Assert-StateBoundary -Candidate $stateDirectory -Root $InstallRoot
$clientsFile = [string](Get-RequiredProperty -Object $settings -Name 'clientsFile')
$isFormalConfiguration = -not [string]::IsNullOrWhiteSpace($clientsFile)
if ($isFormalConfiguration) {
    $releaseMetadataRoot = Get-SafeFixedNtfsPath `
        -Value (Join-Path $InstallRoot 'release-metadata') `
        -Label 'Platform 发行元数据目录'
    Assert-NoReparseTree -Path $releaseMetadataRoot -Label 'Platform 发行元数据目录'
    $releaseManifestPath = Join-Path $releaseMetadataRoot 'release-manifest.json'
    $buildMetadataPath = Join-Path $releaseMetadataRoot 'build-metadata.json'
    foreach ($releaseMetadataPath in @($releaseManifestPath, $buildMetadataPath)) {
        if (-not (Test-Path -LiteralPath $releaseMetadataPath -PathType Leaf)) {
            throw '正式配置只允许从完整二进制正式发行版启动；当前缺少发行分类元数据。'
        }
    }
    try {
        $releaseManifest = Get-Content -LiteralPath $releaseManifestPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        $buildMetadata = Get-Content -LiteralPath $buildMetadataPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw '正式配置的发行分类元数据不是有效 JSON；已拒绝启动。'
    }
    $releaseClassification = [string]$releaseManifest.releaseClassification
    if ([string]$releaseManifest.product -ne 'MineGuard Platform' -or
        [string]$buildMetadata.product -ne 'MineGuard Platform' -or
        $releaseManifest.codeSigned -isnot [bool] -or
        $buildMetadata.codeSigned -isnot [bool] -or
        [bool]$releaseManifest.codeSigned -ne [bool]$buildMetadata.codeSigned -or
        [string]$buildMetadata.releaseClassification -ne $releaseClassification -or
        $releaseClassification -notin @(
            'signed-production-candidate', 'unsigned-internal-release'
        ) -or
        ([bool]$releaseManifest.codeSigned) -ne
            ($releaseClassification -eq 'signed-production-candidate')) {
        throw 'UNSIGNED-TEST-ONLY、开发版或分类异常的 Platform 禁止启动正式配置。'
    }
    if ($releaseClassification -eq 'unsigned-internal-release') {
        $releaseTrustAnchorPath = Join-Path $releaseMetadataRoot `
            'release-trust-anchor.json'
        if (-not (Test-Path -LiteralPath $releaseTrustAnchorPath -PathType Leaf)) {
            throw 'INTERNAL-UNSIGNED 正式启动缺少安装事务持久化的发行信任锚。'
        }
        try {
            $releaseTrustAnchor = Get-Content -LiteralPath $releaseTrustAnchorPath `
                -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            throw 'INTERNAL-UNSIGNED 持久化发行信任锚不是有效 JSON。'
        }
        $anchorProperties = @(
            $releaseTrustAnchor.PSObject.Properties | ForEach-Object { $_.Name }
        )
        $approvedManifestSha256 = [string](
            $releaseTrustAnchor.childReleaseManifestSha256
        )
        if ($anchorProperties.Count -ne 4 -or
            [int]$releaseTrustAnchor.schemaVersion -ne 1 -or
            [string]$releaseTrustAnchor.product -ne
                'MineGuard Platform release trust anchor' -or
            [string]$releaseTrustAnchor.releaseClassification -ne
                'unsigned-internal-release' -or
            $approvedManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            throw 'INTERNAL-UNSIGNED 持久化发行信任锚格式或身份无效。'
        }
        Assert-InternalUnsignedPlatformReleaseTree -Root $InstallRoot `
            -Manifest $releaseManifest `
            -ExpectedManifestSha256 $approvedManifestSha256
    }
}
$adminUsername = [string](Get-RequiredProperty -Object $settings -Name 'adminUsername')
if ([string]::IsNullOrWhiteSpace($adminUsername)) {
    throw '管理员用户名不能为空。'
}
$secureCookieValue = Get-RequiredProperty -Object $settings -Name 'secureCookie'
if ($secureCookieValue -isnot [bool]) {
    throw 'settings.json 的 secureCookie 必须是 JSON 布尔值。'
}
$managedProvisioningRequired = $false
$managedProperty = $settings.PSObject.Properties['managedProvisioningRequired']
if ($null -ne $managedProperty) {
    if ($managedProperty.Value -isnot [bool]) {
        throw 'settings.json 的 managedProvisioningRequired 必须是 JSON 布尔值。'
    }
    $managedProvisioningRequired = [bool]$managedProperty.Value
}
$provisioningTrustedPublicKeyFile = ''
$provisioningExpectedPublicKeySha256 = ''
$provisioningExpectedIssuerKeyId = ''
if ($managedProvisioningRequired) {
    $provisioningTrustedPublicKeyFile = [string](
        Get-RequiredProperty -Object $settings `
            -Name 'provisioningTrustedPublicKeyFile'
    )
    $provisioningExpectedPublicKeySha256 = [string](
        Get-RequiredProperty -Object $settings `
            -Name 'provisioningExpectedPublicKeySha256'
    )
    $provisioningExpectedIssuerKeyId = [string](
        Get-RequiredProperty -Object $settings `
            -Name 'provisioningExpectedIssuerKeyId'
    )
}

$resolverPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $PSScriptRoot 'Resolve-MineGuardPlatformExecutable.ps1') `
    -Label '运行时解析器'
if (-not (Test-Path -LiteralPath $resolverPath -PathType Leaf)) {
    throw "找不到运行时解析器：$resolverPath。请重新安装 MineGuard Platform。"
}
. $resolverPath
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
$runtime.filePath = Get-SafeFixedNtfsPath `
    -Value ([string]$runtime.filePath) -Label 'MineGuard Platform 运行时'
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    throw '状态目录不存在；请先运行 Set-MineGuardPlatformConfiguration.ps1。'
}
Assert-NoReparseTree -Path $stateDirectory -Label '状态目录'
Assert-StateOwnership -Path $stateDirectory

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$localControlEnvironment = Get-Item `
    -LiteralPath 'Env:MINEGUARD_LOCAL_CONTROL_TOKEN' `
    -ErrorAction SilentlyContinue
if ($null -ne $localControlEnvironment) {
    $localControlToken = [string]$localControlEnvironment.Value
    if ($localControlToken -cnotmatch '^[0-9a-f]{64}$') {
        throw '本机控制令牌格式无效；已拒绝启动。'
    }
}
$inheritedMineGuardEnvironment = @(
    Get-ChildItem Env: | Where-Object {
        $_.Name.StartsWith(
            'MINEGUARD_', [StringComparison]::OrdinalIgnoreCase
        )
    }
)
foreach ($environmentEntry in $inheritedMineGuardEnvironment) {
    Remove-Item -LiteralPath ('Env:' + $environmentEntry.Name) `
        -ErrorAction SilentlyContinue
}
$inheritedMineGuardEnvironment = $null

if ($managedProvisioningRequired) {
    $provisioningTrustedPublicKeyFile = Get-SafeFixedNtfsPath `
        -Value $provisioningTrustedPublicKeyFile -Label '签发信任公钥'
    $expectedTrustPath = Get-SafeFixedNtfsPath `
        -Value (Join-Path $configDirectory 'provisioning-issuer-public.pem') `
        -Label '固定签发信任公钥路径'
    if (-not $provisioningTrustedPublicKeyFile.Equals(
            $expectedTrustPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $provisioningTrustedPublicKeyFile `
            -PathType Leaf)) {
        throw '受管签发公钥必须是 config\provisioning-issuer-public.pem 普通文件。'
    }
    $trustItem = Get-Item -LiteralPath $provisioningTrustedPublicKeyFile -Force
    if (($trustItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $trustItem.Length -le 0 -or $trustItem.Length -gt 65536) {
        throw '受管签发公钥大小或文件类型无效。'
    }
    if ($provisioningExpectedPublicKeySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $provisioningExpectedIssuerKeyId -notmatch `
            '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw '受管签发公钥 SPKI SHA-256 或 issuer key ID 格式无效。'
    }
    # The short-lived config-check below validates a managed clients.json too,
    # so it needs the same trust boundary as the long-running process.
    $env:MINEGUARD_PROVISIONING_MANAGED_REQUIRED = 'true'
    $env:MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE = `
        $provisioningTrustedPublicKeyFile
    $env:MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256 = `
        $provisioningExpectedPublicKeySha256
    $env:MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID = `
        $provisioningExpectedIssuerKeyId
}

if (-not [string]::IsNullOrWhiteSpace($clientsFile)) {
    $clientsFile = Get-SafeFixedNtfsPath -Value $clientsFile -Label '煤矿客户端注册表'
    if (-not (Test-Path -LiteralPath $clientsFile -PathType Leaf)) {
        throw "煤矿客户端注册表不存在：$clientsFile"
    }
    $clientItem = Get-Item -LiteralPath $clientsFile -Force
    if (($clientItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $clientItem.Length -le 0 -or $clientItem.Length -gt 4194304) {
        throw '煤矿客户端注册表必须是 1-4 MiB 范围内的普通文件。'
    }
    $registryProbeArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'config-check', '--clients-file', $clientsFile
        )
    $registryProbeText = & $runtime.filePath @registryProbeArguments
    if ($LASTEXITCODE -ne 0) {
        throw '煤矿客户端注册表无法通过短生命周期只读核验。'
    }
    try {
        $registryProbe = $registryProbeText | Out-String | ConvertFrom-Json
    } catch { throw '客户端注册表只读核验未返回有效 JSON。' }
    $registryProbeText = $null
    $hasManagedRegistryLock = [bool]$registryProbe.client_registry_managed
    $registryProbe = $null
    if ($hasManagedRegistryLock -and -not $managedProvisioningRequired) {
        throw 'clients.json 已包含受管注册锁，但 settings.json 未启用强制受管校验；拒绝降级启动。'
    }
}

$env:MINEGUARD_V2_PLATFORM_SYSTEM_ID = [string](
    Get-RequiredProperty -Object $settings -Name 'platformSystemId'
)
$env:MINEGUARD_V2_PLATFORM_PARTY_ID = [string](
    Get-RequiredProperty -Object $settings -Name 'platformPartyId'
)
$env:MINEGUARD_V2_PLATFORM_KEY_ID = [string](
    Get-RequiredProperty -Object $settings -Name 'platformKeyId'
)

$authDatabase = Join-Path $stateDirectory 'auth.db'
$bootstrapSecret = Get-SafeFixedNtfsPath -Value (
    Join-Path (Join-Path $InstallRoot 'config') 'bootstrap-admin-password.txt'
) -Label '首次管理员密码文件'
$allowDemoDefault = $false
$demoProperty = $settings.PSObject.Properties['allowDemoDefaultPassword']
if ($null -eq $demoProperty -or $demoProperty.Value -isnot [bool]) {
    throw 'settings.json 的 allowDemoDefaultPassword 必须是 JSON 布尔值。'
}
$allowDemoDefault = [bool]$demoProperty.Value
$isFormalConfiguration = -not [string]::IsNullOrWhiteSpace($clientsFile)
$isDemoConfiguration = -not $isFormalConfiguration
if ($isFormalConfiguration) {
    if ($allowDemoDefault) {
        throw '正式配置绝不允许 allowDemoDefaultPassword=true；拒绝降级为演示模式。'
    }
    if (-not [bool]$secureCookieValue) {
        throw '正式运行必须启用 Secure Cookie 并通过 HTTPS 反向代理访问。'
    }
} elseif (-not $allowDemoDefault -or [bool]$secureCookieValue) {
    throw '无客户端注册表时只允许明确的本机 HTTP 演示配置；安全开关组合不一致。'
}
if ($isFormalConfiguration) {
    $clientCheckArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--clients-file', $clientsFile, '--production'
        )
    & $runtime.filePath @clientCheckArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '煤矿客户端注册表未通过短生命周期 MineGuard 完整校验；拒绝启动。'
    }
    $env:MINEGUARD_V2_CLIENTS_FILE = $clientsFile
    $stateCheckArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--state-directory', $stateDirectory, '--production'
        )
    & $runtime.filePath @stateCheckArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '状态目录包含演示/合成数据或无法通过正式用途核验；拒绝启动。'
    }
}
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--auth-database', $authDatabase)
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝在不确定管理员状态时启动。'
    }
    $check = $checkText | Out-String | ConvertFrom-Json
    $hasAuthUser = ([int]$check.auth_user_count -ge 1)
    if ($isFormalConfiguration -and $hasAuthUser) {
        $productionAuthArguments = Join-MineGuardPlatformArguments `
            -Runtime $runtime -Arguments @(
                'config-check', '--auth-database', $authDatabase, '--production'
            )
        & $runtime.filePath @productionAuthArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'auth.db 没有正式可用管理员，或仍有启用的演示凭据账号；拒绝启动。'
        }
    }
}
if (-not $hasAuthUser -and $isFormalConfiguration) {
    Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
    if (-not (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf)) {
        throw '全新状态库缺少首次管理员密码。请重新运行配置脚本并安全输入密码。'
    }
    $bootstrapItem = Get-Item -LiteralPath $bootstrapSecret -Force
    if ($bootstrapItem.PSIsContainer -or
        ($bootstrapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw '首次管理员密码必须是配置目录中的普通文件。'
    }
    $bootstrapArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'bootstrap-admin', '--state-directory', $stateDirectory,
            '--admin-username', $adminUsername,
            '--password-file', $bootstrapSecret, '--production'
        )
    $bootstrapOutput = & $runtime.filePath @bootstrapArguments
    $bootstrapExitCode = $LASTEXITCODE
    if ($bootstrapExitCode -ne 0) {
        $bootstrapMessage = ($bootstrapOutput | Out-String).Trim()
        $bootstrapOutput = $null
        throw (
            "首次管理员摘要建立失败（退出码 $bootstrapExitCode）。" +
            "明文文件已保留，请按错误信息修正后重试：$bootstrapMessage"
        )
    }
    $bootstrapOutput = $null
    if (Test-Path -LiteralPath $bootstrapSecret) {
        throw '短首启进程未删除明文密码文件；已拒绝启动长运行服务。请检查 config 目录 ACL 后重试。'
    }
    $hasAuthUser = $true
}

if ($isFormalConfiguration) {
    $postBootstrapAuthArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'config-check', '--auth-database', $authDatabase, '--production'
        )
    & $runtime.filePath @postBootstrapAuthArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '管理员摘要未通过正式凭据核验；已拒绝启动长运行服务。请在服务器本机安全改密后重试。'
    }
    Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
    if (Test-Path -LiteralPath $bootstrapSecret) {
        throw 'auth.db 已存在但首启明文密码文件仍在；为避免误删，已拒绝启动。请以管理员身份核验账号库后运行 Set-MineGuardPlatformConfiguration.ps1 -ClearBootstrapPassword。'
    }
}

if ($isDemoConfiguration) {
    $demoStateArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--state-directory', $stateDirectory)
    $demoStateText = & $runtime.filePath @demoStateArguments
    if ($LASTEXITCODE -ne 0) {
        throw '演示状态目录无法核验；拒绝启动。'
    }
    $demoStateCheck = $demoStateText | Out-String | ConvertFrom-Json
    if ([int]$demoStateCheck.state_demo_evidence_count -lt 1) {
        throw '演示配置缺少受控合成数据标记；拒绝用演示开关启动正式状态目录。'
    }
}

$arguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'serve',
    '--host', $hostAddress,
    '--port', [string]$port,
    '--state-directory', $stateDirectory,
    '--admin-username', $adminUsername
)
if ([bool]$secureCookieValue) {
    $arguments += '--secure-cookie'
}
if ($isFormalConfiguration) {
    $arguments += '--production'
}

Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue
if (Test-Path Env:MINEGUARD_ADMIN_PASSWORD) {
    throw '无法清除首启管理员环境变量；已拒绝启动长运行服务。'
}

$exitCode = 1
try {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $runtime.filePath
    $startInfo.Arguments = Join-WindowsCommandLineArguments -Arguments $arguments
    $startInfo.WorkingDirectory = $InstallRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $false
    if ($null -ne $localControlToken) {
        $startInfo.EnvironmentVariables['MINEGUARD_LOCAL_CONTROL_TOKEN'] = (
            $localControlToken
        )
    }
    try {
        $serverProcess = [Diagnostics.Process]::Start($startInfo)
    } finally {
        [void]$startInfo.EnvironmentVariables.Remove(
            'MINEGUARD_LOCAL_CONTROL_TOKEN'
        )
        $localControlToken = $null
    }
    if ($null -eq $serverProcess) {
        throw '操作系统未能创建 Platform 长运行进程。'
    }
    $serverProcess.WaitForExit()
    $exitCode = $serverProcess.ExitCode
} finally {
    Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
} finally {
    if ($configurationMutexHeld) {
        try { $configurationMutex.ReleaseMutex() }
        catch { }
    }
    $localControlToken = $null
    foreach ($environmentEntry in @(Get-ChildItem Env:)) {
        if ($environmentEntry.Name.StartsWith(
                'MINEGUARD_', [StringComparison]::OrdinalIgnoreCase
            )) {
            Remove-Item -LiteralPath ('Env:' + $environmentEntry.Name) `
                -ErrorAction SilentlyContinue
        }
    }
    if ($null -ne $configurationMutex) { $configurationMutex.Dispose() }
    if ($null -ne $serverProcess) { $serverProcess.Dispose() }
}
if ($null -eq $exitCode) { $exitCode = 1 }
exit $exitCode
