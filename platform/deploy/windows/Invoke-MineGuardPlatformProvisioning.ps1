[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('IssuerInit', 'CreatePair', 'ImportRegistration')]
    [string] $Action,
    [string] $InstallRoot = (Join-Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData
        )) 'MineGuard\Platform'),

    [string] $PrivateKeyPath,
    [string] $PublicKeyPath,
    [Security.SecureString] $Passphrase,
    [Security.SecureString] $PassphraseConfirmation,

    [string] $IssuerId,
    [string] $IssuerKeyId,
    [string] $MineId,
    [string] $MineName,
    [string] $EnterprisePartyId,
    [string] $EnterprisePartyName,
    [string] $EnterpriseSystemId,
    [string] $CapacityBand,
    [string] $MiningMethod,
    [string] $ShiftSystem,
    [string] $CoalType,
    [string] $OperatingRegime,
    [string] $PlatformBaseUrl,
    [string] $AgentInstanceName,
    [string] $PlatformSystemId,
    [string] $PlatformPartyId,
    [string] $PlatformKeyId,
    [ValidateRange(1, 90)] [int] $InstallWindowDays = 14,
    [string] $BundleOutputDirectory,
    [string] $PlatformRegistrationDirectory,
    [string] $ActivationDirectory,
    [ValidateRange(1, 1000000)] [int] $ProfileVersion = 1,
    [string] $PreviousRegistrationBundle,
    [string] $PreviousRegistrationActivationFile,

    [string] $RegistrationBundle,
    [string] $RegistrationActivationFile,
    [string] $ExpectedPublicKeySha256,
    [string] $ExpectedIssuerKeyId,
    [switch] $AllowUpdate,
    [switch] $ManageServiceLifecycle,
    [string] $StateDirectory,
    [ValidateRange(0, 65535)] [int] $Port = 0,
    [string] $AdminUsername,
    [Security.SecureString] $AdminPassword
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '企业接入配置必须以管理员身份运行。'
    }
}

function Get-SafeLocalPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Label,
        [switch] $RequireFixedNtfs,
        [switch] $AllowMissingLeaf
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -ne $Value.Trim() -or
        $Value.IndexOf([char]0) -ge 0 -or $Value.Contains('/') -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $full = [IO.Path]::GetFullPath($Value)
    $root = [IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\') -or
        $full.Substring(2).Contains(':')) {
        throw "$Label 不能是磁盘根目录，也不能包含 NTFS ADS。"
    }
    foreach ($part in ($full.Substring(3).TrimEnd('\') -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -in @('.', '..') -or
            $part.Contains(':') -or $part.EndsWith(' ') -or
            $part.EndsWith('.')) {
            throw "$Label 包含空、点或其他歧义路径段。"
        }
    }
    $drive = New-Object IO.DriveInfo $root
    if (-not $drive.IsReady -or $drive.DriveType -notin @(
            [IO.DriveType]::Fixed, [IO.DriveType]::Removable)) {
        throw "$Label 必须位于已就绪的本机固定磁盘或可移动介质。"
    }
    if ($RequireFixedNtfs -and
        ($drive.DriveType -ne [IO.DriveType]::Fixed -or
            -not $drive.DriveFormat.Equals(
                'NTFS', [StringComparison]::OrdinalIgnoreCase))) {
        throw "$Label 必须位于本机固定 NTFS 磁盘。"
    }
    $current = if (Test-Path -LiteralPath $full) {
        $full
    } elseif ($AllowMissingLeaf) {
        Split-Path -Parent $full
    } else { $full }
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 及其现有祖先不能包含符号链接、junction 或挂载点。"
            }
        }
        if ($current.TrimEnd('\') -eq $root.TrimEnd('\')) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
    return $full
}

function Assert-RegularFile {
    param(
        [string] $Path, [string] $Label,
        [long] $MaximumBytes = 4194304
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 不存在：$Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label 必须是 1-$MaximumBytes 字节的普通文件。"
    }
}

function Set-AdministratorOnlyAcl {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [switch] $Recurse
    )
    & "$env:SystemRoot\System32\icacls.exe" $Path '/inheritance:r' `
        '/grant:r' '*S-1-5-18:(OI)(CI)F' `
        '/grant:r' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "无法把秘密目录 ACL 限制为 SYSTEM 和 Administrators：$Path"
    }
    if ($Recurse -and @(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
        Assert-NoReparseTree -Path $Path -Label 'MineGuard 专用受控目录'
        & "$env:SystemRoot\System32\icacls.exe" (Join-Path $Path '*') `
            '/inheritance:r' '/grant:r' '*S-1-5-18:F' `
            '/grant:r' '*S-1-5-32-544:F' '/T' '/C' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "无法保护本次专用秘密目录中的文件：$Path"
        }
    }
}

function Assert-NoReparseTree {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $inspected = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        $inspected++
        if ($inspected -gt 4096) {
            throw "$Label 项目过多，拒绝递归修改 ACL。"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label 不能包含符号链接、junction 或其他重解析点。"
        }
    }
}

function Assert-SeparateDirectoryTrees {
    param([Parameter(Mandatory = $true)] [string[]] $Paths)
    for ($firstIndex = 0; $firstIndex -lt $Paths.Count; $firstIndex++) {
        $first = [IO.Path]::GetFullPath($Paths[$firstIndex]).TrimEnd('\')
        for ($secondIndex = $firstIndex + 1;
            $secondIndex -lt $Paths.Count; $secondIndex++) {
            $second = [IO.Path]::GetFullPath(
                $Paths[$secondIndex]
            ).TrimEnd('\')
            if ($first.Equals($second, [StringComparison]::OrdinalIgnoreCase) -or
                $first.StartsWith(
                    $second + '\', [StringComparison]::OrdinalIgnoreCase
                ) -or
                $second.StartsWith(
                    $first + '\', [StringComparison]::OrdinalIgnoreCase
                )) {
                throw '企业包、监管注册包和两类激活码必须位于四个互不包含的目录树。'
            }
        }
    }
}

function Initialize-OwnedProtectedRoot {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedPath,
        [Parameter(Mandatory = $true)] [string] $Purpose
    )
    if (-not $Path.Equals(
            $ExpectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose 必须使用安装目录下的固定专用路径：$ExpectedPath"
    }
    $markerName = '.mineguard-provisioning-root.json'
    $markerPath = Join-Path $Path $markerName
    $created = $false
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        $created = $true
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose 不是目录。"
    }
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        Assert-RegularFile -Path $markerPath -Label "$Purpose 所有权标记" `
            -MaximumBytes 65536
        try {
            $marker = Get-Content -LiteralPath $markerPath -Raw `
                -Encoding UTF8 | ConvertFrom-Json
        } catch { throw "$Purpose 所有权标记无效。" }
        if ([string]$marker.schema_version -ne
                'mineguard-provisioning-root-v1' -or
            -not [string]::Equals(
                [string]$marker.install_root, $InstallRoot,
                [StringComparison]::OrdinalIgnoreCase) -or
            [string]$marker.purpose -ne $Purpose) {
            throw "$Purpose 所有权标记不属于当前安装。"
        }
    } else {
        $children = @(Get-ChildItem -LiteralPath $Path -Force)
        if (-not $created -and $children.Count -ne 0) {
            throw "$Purpose 已存在且非空，但缺少 MineGuard 所有权标记；拒绝递归改 ACL。"
        }
        Set-AdministratorOnlyAcl -Path $Path
        $marker = [ordered]@{
            schema_version = 'mineguard-provisioning-root-v1'
            install_root = $InstallRoot
            purpose = $Purpose
            created_utc = [DateTime]::UtcNow.ToString('o')
        }
        $stream = New-Object IO.FileStream(
            $markerPath, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        try {
            $payload = $utf8NoBom.GetBytes(
                ($marker | ConvertTo-Json -Depth 3)
            )
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
    }
    Set-AdministratorOnlyAcl -Path $Path
    return $Path
}

function ConvertFrom-SecureStringPrivate {
    param([Security.SecureString] $Value, [string] $Label)
    if ($null -eq $Value) { throw "$Label 不能为空。" }
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Write-PassphraseFile {
    param(
        [Security.SecureString] $Value,
        [Security.SecureString] $Confirmation,
        [string] $Path,
        [switch] $RequireConfirmation
    )
    $plain = $null
    $confirmed = $null
    try {
        $plain = ConvertFrom-SecureStringPrivate -Value $Value -Label '签发私钥口令'
        if ($RequireConfirmation) {
            $confirmed = ConvertFrom-SecureStringPrivate -Value $Confirmation `
                -Label '签发私钥确认口令'
            if (-not [string]::Equals(
                    $plain, $confirmed, [StringComparison]::Ordinal)) {
                throw '两次输入的签发私钥口令不一致。'
            }
        }
        $categories = 0
        if ($plain -cmatch '[a-z]') { $categories++ }
        if ($plain -cmatch '[A-Z]') { $categories++ }
        if ($plain -match '[0-9]') { $categories++ }
        if ($plain -match '[^A-Za-z0-9]') { $categories++ }
        if ($plain.Length -lt 14 -or $categories -lt 3 -or
            $plain.IndexOfAny([char[]]"`r`n`0") -ge 0) {
            throw '签发私钥口令至少 14 位，且大小写字母、数字、符号至少三类。'
        }
        [IO.File]::WriteAllText($Path, $plain, $utf8NoBom)
    } finally {
        $plain = $null
        $confirmed = $null
    }
}

function Invoke-PlatformJson {
    param([object] $Runtime, [string[]] $Arguments, [string] $Label)
    $nativeArguments = Join-MineGuardPlatformArguments -Runtime $Runtime `
        -Arguments $Arguments
    $output = & $Runtime.filePath @nativeArguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    $output = $null
    if ($exitCode -ne 0) {
        throw "$Label 失败（退出码 $exitCode）：$text"
    }
    try { return $text | ConvertFrom-Json }
    catch { throw "$Label 未返回有效 JSON。" }
}

function Assert-Identifier {
    param([string] $Value, [string] $Label)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "$Label 只能包含字母、数字、点、下划线、冒号和连字符。"
    }
    if ($Value -match '(?i)(?:^|[._:-])(demo|example|test|unknown)(?:$|[._:-])') {
        throw "$Label 不能使用演示或占位标识。"
    }
}

function Get-SpkiSha256FromPem {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $pem = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $match = [Text.RegularExpressions.Regex]::Match(
        $pem,
        '^\s*-----BEGIN PUBLIC KEY-----\s*(?<body>[A-Za-z0-9+/=\s]+)' +
        '-----END PUBLIC KEY-----\s*$',
        [Text.RegularExpressions.RegexOptions]::Singleline
    )
    $pem = $null
    if (-not $match.Success) {
        throw '签发公钥必须是单一 SubjectPublicKeyInfo PEM 公钥。'
    }
    try {
        $der = [Convert]::FromBase64String(
            ($match.Groups['body'].Value -replace '\s', '')
        )
    } catch { throw '签发公钥 PEM 的 base64 内容无效。' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($der))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $der = $null
    }
}

function Set-ReadOnlyOrdinaryFile {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [string] $Label = '交付文件'
    )
    Assert-RegularFile -Path $Path -Label $Label -MaximumBytes 4194304
    $attributes = [IO.File]::GetAttributes($Path)
    [IO.File]::SetAttributes($Path, ($attributes -bor [IO.FileAttributes]::ReadOnly))
}

function New-ProtectedWorkDirectory {
    $path = Join-Path $InstallRoot (
        '.provisioning-work-' + [Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $path | Out-Null
    Set-AdministratorOnlyAcl -Path $path
    return $path
}

function Remove-ProtectedWorkDirectory {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or
        (Split-Path -Parent $Path) -ne $InstallRoot -or
        (Split-Path -Leaf $Path) -notmatch
            '^\.provisioning-work-[0-9a-f]{32}$') {
        throw '拒绝清理不属于本次操作的目录。'
    }
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

if ($env:OS -ne 'Windows_NT') { throw '本向导只支持 Windows。' }
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
Assert-Administrator
$InstallRoot = Get-SafeLocalPath -Value $InstallRoot -Label '安装目录' `
    -RequireFixedNtfs
$resolver = Join-Path $PSScriptRoot 'Resolve-MineGuardPlatformExecutable.ps1'
if (-not (Test-Path -LiteralPath $resolver -PathType Leaf)) {
    throw '安装不完整：缺少 Platform 运行时解析器。'
}
. $resolver
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
$workDirectory = $null
$operationError = $null
$serviceWasRunning = $false
$configurationMutex = $null
$configurationMutexHeld = $false
try {
    $workDirectory = New-ProtectedWorkDirectory

    if ($Action -eq 'IssuerInit') {
        $PrivateKeyPath = Get-SafeLocalPath -Value $PrivateKeyPath `
            -Label '签发私钥路径' -RequireFixedNtfs -AllowMissingLeaf
        $PublicKeyPath = Get-SafeLocalPath -Value $PublicKeyPath `
            -Label '签发公钥路径' -RequireFixedNtfs -AllowMissingLeaf
        if ($PrivateKeyPath.Equals(
                $PublicKeyPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw '签发私钥和公钥必须使用不同文件。'
        }
        if ((Test-Path -LiteralPath $PrivateKeyPath) -or
            (Test-Path -LiteralPath $PublicKeyPath)) {
            throw '签发密钥文件已存在；为防止覆盖，请选择新的专用目录。'
        }
        $authorityDirectory = Split-Path -Parent $PrivateKeyPath
        if (-not $authorityDirectory.Equals(
                (Split-Path -Parent $PublicKeyPath),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw '签发私钥和公钥必须放在同一个管理员专用目录。'
        }
        $expectedAuthorityDirectory = Join-Path $InstallRoot `
            'provisioning-authority'
        $null = Initialize-OwnedProtectedRoot -Path $authorityDirectory `
            -ExpectedPath $expectedAuthorityDirectory `
            -Purpose 'MineGuard Platform Provisioning Authority'
        $passphraseFile = Join-Path $workDirectory 'issuer-passphrase.txt'
        Write-PassphraseFile -Value $Passphrase `
            -Confirmation $PassphraseConfirmation -Path $passphraseFile `
            -RequireConfirmation
        $result = Invoke-PlatformJson -Runtime $runtime `
            -Arguments @(
                'provision', 'issuer-init', '--private-key', $PrivateKeyPath,
                '--public-key', $PublicKeyPath, '--passphrase-file',
                $passphraseFile
            ) -Label '初始化签发密钥'
        Set-AdministratorOnlyAcl -Path $authorityDirectory -Recurse
        return $result
    }

    if ($Action -eq 'CreatePair') {
        foreach ($entry in @(
                @($IssuerId, '签发机构 ID'), @($IssuerKeyId, '签发 key ID'),
                @($MineId, '煤矿 ID'), @($EnterprisePartyId, '企业主体 ID'),
                @($EnterpriseSystemId, '企业系统 ID'),
                @($PlatformSystemId, '监管系统 ID'),
                @($PlatformPartyId, '监管主体 ID'),
                @($PlatformKeyId, '监管应用 key ID')
            )) { Assert-Identifier -Value $entry[0] -Label $entry[1] }
        if ($AgentInstanceName -notmatch '^[a-z0-9][a-z0-9-]{0,47}$') {
            throw '企业实例名只能使用 1-48 位小写字母、数字和连字符。'
        }
        foreach ($displayEntry in @(
                @($MineName, '煤矿名称'),
                @($EnterprisePartyName, '企业名称'),
                @($CapacityBand, '产能区间'), @($MiningMethod, '开采方式'),
                @($ShiftSystem, '班次制度'), @($CoalType, '煤种'),
                @($OperatingRegime, '生产制度')
            )) {
            if ([string]::IsNullOrWhiteSpace([string]$displayEntry[0]) -or
                ([string]$displayEntry[0]).Length -gt 64) {
                throw "$($displayEntry[1]) 必须填写，且不能超过 64 个字符。"
            }
        }
        $PrivateKeyPath = Get-SafeLocalPath -Value $PrivateKeyPath `
            -Label '签发私钥' -RequireFixedNtfs
        Assert-RegularFile -Path $PrivateKeyPath -Label '签发私钥' `
            -MaximumBytes 65536
        $PublicKeyPath = Get-SafeLocalPath -Value $PublicKeyPath `
            -Label '签发公钥'
        Assert-RegularFile -Path $PublicKeyPath -Label '签发公钥' `
            -MaximumBytes 65536
        $expectedAuthorityDirectory = Join-Path $InstallRoot `
            'provisioning-authority'
        foreach ($authorityMaterial in @($PrivateKeyPath, $PublicKeyPath)) {
            if (-not (Split-Path -Parent $authorityMaterial).Equals(
                    $expectedAuthorityDirectory,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "签发密钥必须位于固定管理员专用目录：$expectedAuthorityDirectory"
            }
        }
        $null = Initialize-OwnedProtectedRoot `
            -Path $expectedAuthorityDirectory `
            -ExpectedPath $expectedAuthorityDirectory `
            -Purpose 'MineGuard Platform Provisioning Authority'
        foreach ($otherKeyMaterial in @($PublicKeyPath)) {
            if ($PrivateKeyPath.Equals(
                    $otherKeyMaterial, [StringComparison]::OrdinalIgnoreCase)) {
                throw '签发私钥不能同时作为签发公钥。'
            }
        }
        $BundleOutputDirectory = Get-SafeLocalPath `
            -Value $BundleOutputDirectory -Label '企业交付根目录' `
            -AllowMissingLeaf
        $PlatformRegistrationDirectory = Get-SafeLocalPath `
            -Value $PlatformRegistrationDirectory -Label '政府注册包根目录' `
            -RequireFixedNtfs -AllowMissingLeaf
        $ActivationDirectory = Get-SafeLocalPath -Value $ActivationDirectory `
            -Label '激活码保管目录' -RequireFixedNtfs -AllowMissingLeaf
        if (-not (Test-Path -LiteralPath $BundleOutputDirectory)) {
            New-Item -ItemType Directory -Path $BundleOutputDirectory | Out-Null
        }
        $null = Initialize-OwnedProtectedRoot -Path $ActivationDirectory `
            -ExpectedPath (Join-Path $InstallRoot 'provisioning-activations') `
            -Purpose 'MineGuard Platform Provisioning Activations'
        $null = Initialize-OwnedProtectedRoot `
            -Path $PlatformRegistrationDirectory `
            -ExpectedPath (Join-Path $InstallRoot 'provisioning-registrations') `
            -Purpose 'MineGuard Platform Registration Bundles'
        $deliveryStem = ($MineId -replace '[^A-Za-z0-9._-]+', '-').Trim('-')
        $deliveryLeaf = '{0}-v{1}' -f $deliveryStem, $ProfileVersion
        $enterpriseDeliveryDirectory = Join-Path $BundleOutputDirectory `
            $deliveryLeaf
        $platformRegistrationOutput = Join-Path `
            $PlatformRegistrationDirectory $deliveryLeaf
        $enterpriseActivationOutput = Join-Path (Join-Path `
                $ActivationDirectory 'enterprise') $deliveryLeaf
        $platformActivationOutput = Join-Path (Join-Path `
                $ActivationDirectory 'platform') $deliveryLeaf
        foreach ($newOutputTree in @(
                $enterpriseDeliveryDirectory, $platformRegistrationOutput,
                $enterpriseActivationOutput, $platformActivationOutput
            )) {
            if (Test-Path -LiteralPath $newOutputTree) {
                throw "该矿该版本的四区输出目录已存在；拒绝覆盖：$newOutputTree"
            }
        }
        Assert-SeparateDirectoryTrees -Paths @(
            $enterpriseDeliveryDirectory, $platformRegistrationOutput,
            $enterpriseActivationOutput, $platformActivationOutput
        )
        $snapshotPublicKey = Join-Path $workDirectory 'issuer-public.pem'
        [IO.File]::WriteAllBytes(
            $snapshotPublicKey, [IO.File]::ReadAllBytes($PublicKeyPath)
        )
        $snapshotPublicKeyFingerprint = Get-SpkiSha256FromPem `
            -Path $snapshotPublicKey
        $expiresAt = [DateTime]::UtcNow.AddDays($InstallWindowDays)
        $profile = [ordered]@{
            profile_version = $ProfileVersion
            expires_at = $expiresAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
            issuer_id = $IssuerId
            issuer_key_id = $IssuerKeyId
            subject = [ordered]@{
                mine_id = $MineId; mine_name = $MineName
                party_id = $EnterprisePartyId
                party_name = $EnterprisePartyName
                system_id = $EnterpriseSystemId
            }
            comparison_context = [ordered]@{
                capacity_band = $CapacityBand; mining_method = $MiningMethod
                shift_system = $ShiftSystem; coal_type = $CoalType
                operating_regime = $OperatingRegime
            }
            agent = [ordered]@{
                platform_base_url = $PlatformBaseUrl
                reporting_timezone = 'Asia/Shanghai'
            }
            platform_identity = [ordered]@{
                system_id = $PlatformSystemId; party_id = $PlatformPartyId
                key_id = $PlatformKeyId
            }
        }
        $profilePath = Join-Path $workDirectory 'approved-profile.json'
        [IO.File]::WriteAllText(
            $profilePath, ($profile | ConvertTo-Json -Depth 8), $utf8NoBom
        )
        $passphraseFile = Join-Path $workDirectory 'issuer-passphrase.txt'
        Write-PassphraseFile -Value $Passphrase -Path $passphraseFile
        $arguments = @(
            'provision', 'create-pair', '--profile', $profilePath,
            '--issuer-private-key', $PrivateKeyPath,
            '--issuer-passphrase-file', $passphraseFile,
            '--enterprise-bundle-directory', $enterpriseDeliveryDirectory,
            '--platform-registration-directory',
            $platformRegistrationOutput,
            '--enterprise-activation-directory',
            $enterpriseActivationOutput,
            '--platform-activation-directory', $platformActivationOutput
        )
        $previousRequested = (
            -not [string]::IsNullOrWhiteSpace($PreviousRegistrationBundle) -or
            -not [string]::IsNullOrWhiteSpace(
                $PreviousRegistrationActivationFile
            )
        )
        if ($previousRequested) {
            if ([string]::IsNullOrWhiteSpace($PreviousRegistrationBundle) -or
                [string]::IsNullOrWhiteSpace(
                    $PreviousRegistrationActivationFile)) {
                throw '更新接入包必须同时选择上一版 .mgreg 和 Platform 激活码。'
            }
            $previousBundlePath = Get-SafeLocalPath `
                -Value $PreviousRegistrationBundle -Label '上一版注册包'
            $previousActivationPath = Get-SafeLocalPath `
                -Value $PreviousRegistrationActivationFile `
                -Label '上一版 Platform 激活码'
            Assert-RegularFile -Path $previousBundlePath -Label '上一版注册包'
            Assert-RegularFile -Path $previousActivationPath `
                -Label '上一版 Platform 激活码' -MaximumBytes 4096
            $arguments += @(
                '--previous-registration-bundle', $previousBundlePath,
                '--previous-registration-activation-code-file',
                $previousActivationPath
            )
        } elseif ($ProfileVersion -ne 1) {
            throw '首次生成必须使用 profile_version=1；升级必须提供上一版资料。'
        }
        $result = Invoke-PlatformJson -Runtime $runtime `
            -Arguments $arguments -Label '生成企业接入包'
        $deliveryAgentBundle = [string]$result.agent_bundle
        $deliveryPublicKey = [string]$result.issuer_public_key_file
        try {
            if ([string]$result.layout -ne 'split-delivery-v1' -or
                [bool]$result.legacy_shared_layout) {
                throw 'Platform core 未返回强制四区隔离布局。'
            }
            Assert-RegularFile -Path $deliveryAgentBundle `
                -Label 'core 生成的企业接入包'
            Assert-RegularFile -Path $deliveryPublicKey `
                -Label 'core 派生的签发公钥' -MaximumBytes 65536
            $derivedPublicKeyFingerprint = Get-SpkiSha256FromPem `
                -Path $deliveryPublicKey
            if (-not [string]::Equals(
                    [string]$result.issuer_public_key_sha256,
                    $snapshotPublicKeyFingerprint,
                    [StringComparison]::Ordinal) -or
                -not [string]::Equals(
                    $derivedPublicKeyFingerprint,
                    $snapshotPublicKeyFingerprint,
                    [StringComparison]::Ordinal)) {
                throw '所选签发公钥与解密后的签发私钥不属于同一密钥对。'
            }
            $enterpriseFiles = @(Get-ChildItem -LiteralPath `
                    $enterpriseDeliveryDirectory -Force)
            if ($enterpriseFiles.Count -ne 1 -or
                -not $enterpriseFiles[0].FullName.Equals(
                    $deliveryAgentBundle,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw '企业交付目录必须且只能包含一个 .mgprov 文件。'
            }
            Set-ReadOnlyOrdinaryFile -Path $deliveryAgentBundle `
                -Label '企业接入包'
            Set-AdministratorOnlyAcl -Path $enterpriseActivationOutput `
                -Recurse
            Set-AdministratorOnlyAcl -Path $platformActivationOutput `
                -Recurse
            Set-AdministratorOnlyAcl -Path $platformRegistrationOutput `
                -Recurse
        } catch {
            $handoffError = $_
            foreach ($generatedPath in @(
                    [string]$result.agent_bundle,
                    [string]$result.platform_registration_bundle,
                    [string]$result.provisioning_manifest,
                    [string]$result.issuer_public_key_file,
                    [string]$result.agent_activation_file,
                    [string]$result.platform_activation_file
                )) {
                if (-not [string]::IsNullOrWhiteSpace($generatedPath) -and
                    (Test-Path -LiteralPath $generatedPath -PathType Leaf)) {
                    [IO.File]::SetAttributes(
                        $generatedPath, [IO.FileAttributes]::Normal
                    )
                    Remove-Item -LiteralPath $generatedPath -Force
                }
            }
            foreach ($generatedDirectory in @(
                    $enterpriseDeliveryDirectory,
                    $platformRegistrationOutput,
                    $enterpriseActivationOutput,
                    $platformActivationOutput
                )) {
                if ((Test-Path -LiteralPath $generatedDirectory `
                        -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $generatedDirectory `
                        -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $generatedDirectory -Force
                }
            }
            throw $handoffError
        }
        $result | Add-Member -NotePropertyName enterprise_delivery_directory `
            -NotePropertyValue $enterpriseDeliveryDirectory
        $result | Add-Member -NotePropertyName enterprise_agent_bundle `
            -NotePropertyValue $deliveryAgentBundle
        $result | Add-Member -NotePropertyName enterprise_package_sha256 `
            -NotePropertyValue ((Get-FileHash -LiteralPath `
                    $deliveryAgentBundle -Algorithm SHA256).Hash.ToLowerInvariant())
        $result | Add-Member -NotePropertyName agent_instance_name `
            -NotePropertyValue $AgentInstanceName
        $result | Add-Member -NotePropertyName expires_at `
            -NotePropertyValue $expiresAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
        return $result
    }

    # ImportRegistration: stage every removable-medium input before validation,
    # then delegate the final clients/settings/key transaction to the audited
    # configuration script. No activation value enters arguments or logs.
    if ($ExpectedPublicKeySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw '介质外 SPKI SHA-256 必须是 64 位小写十六进制。'
    }
    Assert-Identifier -Value $ExpectedIssuerKeyId `
        -Label '介质外 issuer key ID'
    $registrationSource = Get-SafeLocalPath -Value $RegistrationBundle `
        -Label '监管注册包'
    $activationSource = Get-SafeLocalPath `
        -Value $RegistrationActivationFile -Label 'Platform 激活码文件'
    $publicKeySource = Get-SafeLocalPath -Value $PublicKeyPath `
        -Label '签发公钥'
    Assert-RegularFile -Path $registrationSource -Label '监管注册包'
    Assert-RegularFile -Path $activationSource -Label 'Platform 激活码文件' `
        -MaximumBytes 4096
    Assert-RegularFile -Path $publicKeySource -Label '签发公钥' `
        -MaximumBytes 65536
    $stagedRegistration = Join-Path $workDirectory 'registration.mgreg'
    $stagedActivation = Join-Path $workDirectory 'platform.activation'
    $stagedPublicKey = Join-Path $workDirectory 'issuer-public.pem'
    [IO.File]::WriteAllBytes(
        $stagedRegistration, [IO.File]::ReadAllBytes($registrationSource)
    )
    [IO.File]::WriteAllBytes(
        $stagedActivation, [IO.File]::ReadAllBytes($activationSource)
    )
    [IO.File]::WriteAllBytes(
        $stagedPublicKey, [IO.File]::ReadAllBytes($publicKeySource)
    )
    Set-AdministratorOnlyAcl -Path $workDirectory

    $configurationScript = Join-Path $PSScriptRoot `
        'Set-MineGuardPlatformConfiguration.ps1'
    if (-not (Test-Path -LiteralPath $configurationScript -PathType Leaf)) {
        throw '安装不完整：缺少 Platform 配置事务脚本。'
    }
    # Fail closed for CLI callers. The GUI sets this switch only after showing
    # an explicit outage warning and receiving a Yes decision.
    $service = Get-Service -Name 'MineGuardPlatform' `
        -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $service.Refresh()
        if ($service.Status -ne `
                [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            if (-not $ManageServiceLifecycle) {
                throw 'MineGuardPlatform 服务正在运行；请在图形向导中确认短暂停服并自动恢复，或先手工停止服务。'
            }
            if ($service.Status -ne `
                    [System.ServiceProcess.ServiceControllerStatus]::Running) {
                throw "MineGuardPlatform 服务处于 $($service.Status)；请先由管理员恢复为 Running 或 Stopped。"
            }
            $serviceWasRunning = $true
            Stop-Service -Name 'MineGuardPlatform' -ErrorAction Stop
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(45)
            )
            $service.Refresh()
            if ($service.Status -ne `
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                throw 'MineGuardPlatform 未能在 45 秒内安全停止。'
            }
        }
    }
    # Hold the same machine-wide configuration mutex while taking the current
    # registry snapshot and importing it. The nested configuration script is
    # executed on this same thread; System.Threading.Mutex is re-entrant and it
    # releases its own acquisition before returning.
    $configurationMutex = New-Object -TypeName System.Threading.Mutex `
        -ArgumentList @($false, 'Global\MineGuardPlatform.Configuration')
    try {
        $configurationMutexHeld = $configurationMutex.WaitOne(
            [TimeSpan]::FromSeconds(30)
        )
    } catch [System.Threading.AbandonedMutexException] {
        $configurationMutexHeld = $true
    }
    if (-not $configurationMutexHeld) {
        throw '另一项 MineGuard Platform 配置或启动事务仍在运行；30 秒内未获得机器级配置锁。'
    }

    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw '找不到 settings.json；请先完成 Platform 安装。'
    }
    try {
        $settings = Get-Content -LiteralPath $settingsPath -Raw `
            -Encoding UTF8 | ConvertFrom-Json
    } catch { throw 'settings.json 无法解析；拒绝导入。' }
    $existingClients = [string]$settings.clientsFile
    if ([string]::IsNullOrWhiteSpace($existingClients)) {
        $existingClients = Join-Path (Join-Path $InstallRoot 'config') `
            'clients.json'
    }
    $stagedClients = Join-Path $workDirectory 'clients.json'
    if (Test-Path -LiteralPath $existingClients -PathType Leaf) {
        Assert-RegularFile -Path $existingClients -Label '现有客户端注册表'
        [IO.File]::WriteAllBytes(
            $stagedClients, [IO.File]::ReadAllBytes($existingClients)
        )
    }
    $importArguments = @(
        'provision', 'import-registration', '--bundle', $stagedRegistration,
        '--activation-code-file', $stagedActivation,
        '--issuer-public-key', $stagedPublicKey,
        '--expected-public-key-sha256', $ExpectedPublicKeySha256,
        '--expected-issuer-key-id', $ExpectedIssuerKeyId,
        '--clients-file', $stagedClients
    )
    if ($AllowUpdate) { $importArguments += '--allow-update' }
    $result = Invoke-PlatformJson -Runtime $runtime `
        -Arguments $importArguments -Label '验签并导入监管注册包'

    $existingFormalConfiguration = -not [string]::IsNullOrWhiteSpace(
        [string]$settings.clientsFile
    )
    if ($existingFormalConfiguration) {
        # Adding another mine is a registry operation, never an opportunity to
        # silently move state, change the listening port/admin or replace the
        # already-established bootstrap credential.
        $effectiveState = [string]$settings.stateDirectory
        $effectivePort = [int]$settings.port
        $effectiveAdmin = [string]$settings.adminUsername
        if ($null -ne $AdminPassword) {
            throw '已有正式 Platform 时新增煤矿不得重设管理员密码；请将密码栏留空。'
        }
    } else {
        $effectiveState = if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
            [string]$settings.stateDirectory
        } else { $StateDirectory }
        $effectivePort = if ($Port -eq 0) { [int]$settings.port } else { $Port }
        $effectiveAdmin = if ([string]::IsNullOrWhiteSpace($AdminUsername)) {
            [string]$settings.adminUsername
        } else { $AdminUsername }
    }
    $configurationArguments = @{
        InstallRoot = $InstallRoot
        ClientsFile = $stagedClients
        StateDirectory = $effectiveState
        Port = $effectivePort
        AdminUsername = $effectiveAdmin
        PlatformSystemId = [string]$result.platform_identity.system_id
        PlatformPartyId = [string]$result.platform_identity.party_id
        PlatformKeyId = [string]$result.platform_identity.key_id
        ManagedProvisioningRequired = $true
        ProvisioningTrustedPublicKeySource = $stagedPublicKey
        ProvisioningExpectedPublicKeySha256 = $ExpectedPublicKeySha256
        ProvisioningExpectedIssuerKeyId = $ExpectedIssuerKeyId
        NonInteractive = $true
    }
    if ($null -ne $AdminPassword) {
        $configurationArguments.AdminPassword = $AdminPassword
    }
    & $configurationScript @configurationArguments
    return [pscustomobject][ordered]@{
        status = [string]$result.status
        idempotent = [bool]$result.idempotent
        mine_id = [string]$result.subject.mine_id
        enterprise_system_id = [string]$result.subject.system_id
        profile_version = [int]$result.profile_version
        client_count = [int]$result.client_count
        platform_system_id = [string]$result.platform_identity.system_id
        platform_party_id = [string]$result.platform_identity.party_id
        platform_key_id = [string]$result.platform_identity.key_id
        issuer_public_key_sha256 = $ExpectedPublicKeySha256
        issuer_key_id = $ExpectedIssuerKeyId
        managed_provisioning_required = $true
        clients_file = (Join-Path (Join-Path $InstallRoot 'config') 'clients.json')
        secrets_disclosed = $false
    }
} catch {
    $operationError = $_
    throw
} finally {
    $cleanupFailure = $null
    if ($null -ne $workDirectory) {
        try { Remove-ProtectedWorkDirectory -Path $workDirectory }
        catch { $cleanupFailure = $_ }
    }
    if ($configurationMutexHeld -and $null -ne $configurationMutex) {
        try { $configurationMutex.ReleaseMutex() }
        catch {
            if ($null -eq $cleanupFailure) { $cleanupFailure = $_ }
        }
        $configurationMutexHeld = $false
    }
    if ($null -ne $configurationMutex) {
        try { $configurationMutex.Dispose() }
        catch {
            if ($null -eq $cleanupFailure) { $cleanupFailure = $_ }
        }
        $configurationMutex = $null
    }
    $restartFailure = $null
    if ($serviceWasRunning) {
        try {
            $restoreService = Get-Service -Name 'MineGuardPlatform' `
                -ErrorAction Stop
            $restoreService.Refresh()
            if ($restoreService.Status -eq `
                    [System.ServiceProcess.ServiceControllerStatus]::StopPending) {
                $restoreService.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds(20)
                )
                $restoreService.Refresh()
            }
            if ($restoreService.Status -eq `
                    [System.ServiceProcess.ServiceControllerStatus]::StartPending) {
                $restoreService.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Running,
                    [TimeSpan]::FromSeconds(45)
                )
                $restoreService.Refresh()
            } elseif ($restoreService.Status -eq `
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Start-Service -Name 'MineGuardPlatform' -ErrorAction Stop
                $restoreService.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Running,
                    [TimeSpan]::FromSeconds(45)
                )
                $restoreService.Refresh()
            }
            if ($restoreService.Status -ne `
                    [System.ServiceProcess.ServiceControllerStatus]::Running) {
                throw "恢复后的服务状态为 $($restoreService.Status)"
            }
        } catch { $restartFailure = $_ }
    }
    if ($null -ne $restartFailure) {
        $original = if ($null -eq $operationError) {
            '注册导入事务已执行。'
        } else {
            '注册导入事务同时失败：' + $operationError.Exception.Message
        }
        throw ($original + ' MineGuardPlatform 自动恢复失败，服务可能仍处于停止状态；' +
            '请立即由管理员检查服务与 Platform 日志。恢复错误：' +
            $restartFailure.Exception.Message)
    }
    if ($null -ne $cleanupFailure) {
        $original = if ($null -eq $operationError) { '' } else {
            '原操作失败：' + $operationError.Exception.Message + ' '
        }
        throw ($original + '受控临时目录清理失败，请保持现场并由管理员处理：' +
            $cleanupFailure.Exception.Message)
    }
}
