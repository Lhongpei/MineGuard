[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $WinSWExecutable,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')] [string] $ExpectedSha256,
    [string] $ExpectedConfigSha256,
    [switch] $Production,
    [string] $ExpectedSignerThumbprint = '',
    [switch] $AllowUnsignedInternalRelease,
    [string] $ExpectedRuntimeSha256 = '',
    [string] $ExpectedReleaseManifestSha256 = '',
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
    [switch] $StartService
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }
$script:ServiceInstallScriptPath = [IO.Path]::GetFullPath($PSCommandPath)
$ServiceAccount = 'NT SERVICE\MineGuardPlatform'
$ServiceSid = 'S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346'

if ($env:OS -ne 'Windows_NT') {
    throw 'MineGuard Platform Windows 服务只能在 Windows 上安装。'
}
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $identity
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) { throw '安装 Windows 服务必须以管理员身份运行 Windows PowerShell。' }
}

function Get-SafeLocalPath {
    param(
        [string] $Path,
        [string] $Label,
        [switch] $RequireFixedNtfs
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -ne $Path.Trim() -or $Path.IndexOf([char]0) -ge 0 -or
        $Path.Contains('/') -or $Path -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $withoutTrailingSlash = $Path.TrimEnd('\\')
    if ($withoutTrailingSlash.Length -le 2) {
        throw "$Label 不能是磁盘根目录。"
    }
    foreach ($part in ($withoutTrailingSlash.Substring(3) -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -in @('.', '..') -or
            $part.Contains(':') -or $part.EndsWith(' ') -or $part.EndsWith('.')) {
            throw "$Label 包含空、点、ADS 或其他歧义路径段。"
        }
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.Substring(2).Contains(':')) {
        throw "$Label 不能包含 NTFS alternate data stream (ADS)。"
    }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
    if ($RequireFixedNtfs -and
        ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or
            -not $drive.IsReady -or
            -not $drive.DriveFormat.Equals('NTFS', [StringComparison]::OrdinalIgnoreCase))) {
        throw "$Label 必须位于已就绪的本机固定 NTFS 磁盘。"
    }
    $current = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 及其祖先不能包含符号链接、junction 或挂载点：$current"
            }
        }
        if ($current.TrimEnd('\') -eq $root.TrimEnd('\')) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $fullPath
}

function Assert-NotBroadOrSystemInstallRoot {
    param([string] $Path)
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\\')
    foreach ($protectedValue in @(
            $env:ProgramData, $env:ALLUSERSPROFILE, $env:ProgramFiles,
            ${env:ProgramFiles(x86)}, $env:CommonProgramFiles,
            ${env:CommonProgramFiles(x86)}, $env:PUBLIC
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) {
        $protected = [IO.Path]::GetFullPath([string]$protectedValue).TrimEnd('\\')
        if ($candidate.Equals($protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能是 ProgramData、Program Files、Public 等宽泛系统目录本身。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $windowsRoot = [IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\\')
        if ($candidate.Equals($windowsRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($windowsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能位于 Windows 系统目录内。'
        }
    }
}

function Assert-OrdinaryFile {
    param([string] $Path, [string] $Label, [long] $MaximumBytes = 0)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 不存在：$Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label 不能是符号链接或 reparse point：$Path"
    }
    if ($MaximumBytes -gt 0 -and ($item.Length -le 0 -or $item.Length -gt $MaximumBytes)) {
        throw "$Label 大小超出安全范围：$Path"
    }
    return $item
}

function Assert-PathBelowRoot {
    param([string] $Path, [string] $Root, [string] $Label)
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\\')
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd('\\')
    if (-not $candidate.StartsWith($parent + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label 必须严格位于批准目录内。"
    }
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

function Read-JsonObject {
    param([string] $Path, [string] $Label, [long] $MaximumBytes = 16777216)
    $null = Assert-OrdinaryFile -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try { $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "$Label 不是有效 JSON：$($_.Exception.Message)" }
    if ($null -eq $value -or $value -is [Array]) { throw "$Label 必须只包含一个 JSON 对象。" }
    return $value
}

function Assert-SafeReleaseRelativePath {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains('\') -or
        [IO.Path]::IsPathRooted($Value) -or $Value.Contains(':')) {
        throw "release-manifest.json 包含不安全路径：$Value"
    }
    $parts = $Value.Split('/')
    if ($parts -contains '' -or $parts -contains '.' -or $parts -contains '..') {
        throw "release-manifest.json 包含歧义路径：$Value"
    }
}

function Assert-PlatformReleaseIdentity {
    param([string] $Root)
    $metadataRoot = Join-Path $Root 'release-metadata'
    $manifestPath = Join-Path $metadataRoot 'release-manifest.json'
    $versionPath = Join-Path $metadataRoot 'VERSION.txt'
    $buildMetadataPath = Join-Path $metadataRoot 'build-metadata.json'
    $checksumsPath = Join-Path $metadataRoot 'SHA256SUMS.txt'
    $trustAnchorPath = Join-Path $metadataRoot 'release-trust-anchor.json'
    Assert-NoReparseTree -Path (Join-Path $Root 'runtime') -Label 'runtime 目录'
    Assert-NoReparseTree -Path (Join-Path $Root 'service') -Label 'service 目录'
    Assert-NoReparseTree -Path $metadataRoot -Label 'release-metadata 目录'
    $manifest = Read-JsonObject -Path $manifestPath -Label 'Platform release manifest'
    $build = Read-JsonObject -Path $buildMetadataPath -Label 'Platform build metadata'
    $null = Assert-OrdinaryFile -Path $versionPath -Label 'Platform VERSION.txt' -MaximumBytes 128
    $null = Assert-OrdinaryFile -Path $checksumsPath -Label 'Platform SHA256SUMS.txt' -MaximumBytes 16777216
    $version = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.product -ne 'MineGuard Platform' -or
        [string]$manifest.architecture -ne 'x64' -or
        [string]$manifest.runtime -ne 'nuitka-standalone' -or
        [string]$manifest.entryPoint -ne 'runtime/MineGuardPlatform.exe' -or
        [string]$manifest.operations -ne 'deploy/windows' -or
        [string]$manifest.version -ne $version -or
        $version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw '安装目录不包含身份一致的 MineGuard Platform x64 standalone 发布。'
    }
    if ([string]$build.product -ne 'MineGuard Platform' -or
        [string]$build.version -ne $version -or
        [string]$build.architecture -ne 'x64' -or
        [string]$build.operatingSystem -ne 'Windows') {
        throw 'Platform build-metadata 与 release manifest 身份不一致。'
    }
    if ($manifest.codeSigned -isnot [bool] -or
        $manifest.authenticodeVerified -isnot [bool] -or
        [bool]$manifest.authenticodeVerified -ne [bool]$manifest.codeSigned -or
        $build.codeSigned -isnot [bool] -or
        [bool]$build.codeSigned -ne [bool]$manifest.codeSigned) {
        throw 'Platform 发布的代码签名声明无效或彼此不一致。'
    }
    $declaredClassification = [string]$manifest.releaseClassification
    $expectedClassification = if ([bool]$manifest.codeSigned) {
        'signed-production-candidate'
    } elseif ($declaredClassification -eq 'unsigned-internal-release') {
        'unsigned-internal-release'
    } else {
        'unsigned-test-artifacts'
    }
    if ([string]$manifest.releaseClassification -ne $expectedClassification -or
        [string]$build.releaseClassification -ne $expectedClassification) {
        throw 'Platform 发布分类与代码签名状态不一致。'
    }
    if ($expectedClassification -eq 'unsigned-internal-release') {
        $null = Assert-OrdinaryFile -Path $trustAnchorPath `
            -Label 'Platform 发行信任锚' -MaximumBytes 65536
    } elseif (Test-Path -LiteralPath $trustAnchorPath) {
        throw '只有 unsigned-internal-release 可以携带持久化发行信任锚。'
    }
    $checksumMap = @{}
    foreach ($line in Get-Content -LiteralPath $checksumsPath -Encoding UTF8) {
        if ($line -notmatch '^(?<hash>[A-Fa-f0-9]{64})  (?<path>[^\r\n]+)$') {
            throw 'SHA256SUMS.txt 格式无效。'
        }
        $relative = [string]$Matches['path']
        Assert-SafeReleaseRelativePath -Value $relative
        $key = $relative.ToLowerInvariant()
        if ($checksumMap.ContainsKey($key)) { throw "SHA256SUMS.txt 重复列出：$relative" }
        $checksumMap[$key] = ([string]$Matches['hash']).ToUpperInvariant()
    }
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    if (-not $checksumMap.ContainsKey('release-manifest.json') -or
        $checksumMap['release-manifest.json'] -ne $manifestHash) {
        throw 'release-manifest.json 未被已安装 SHA256SUMS.txt 正确认证。'
    }
    $seen = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        Assert-SafeReleaseRelativePath -Value $relative
        if ([string]$entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or [long]$entry.bytes -lt 0) {
            throw "release manifest 文件元数据无效：$relative"
        }
        $key = $relative.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { throw "release manifest 重复列出：$relative" }
        $seen[$key] = $true
        if (-not $checksumMap.ContainsKey($key) -or
            $checksumMap[$key] -ne ([string]$entry.sha256).ToUpperInvariant()) {
            throw "release manifest 与 SHA256SUMS.txt 不一致：$relative"
        }
        if ($relative.StartsWith('runtime/', [StringComparison]::Ordinal)) {
            $installedPath = Join-Path $Root $relative.Replace('/', '\')
        } elseif ($relative.StartsWith('deploy/windows/', [StringComparison]::Ordinal)) {
            $installedPath = Join-Path (Join-Path $Root 'service') `
                $relative.Substring('deploy/windows/'.Length).Replace('/', '\')
        } elseif ($relative -in @('VERSION.txt', 'build-metadata.json')) {
            $installedPath = Join-Path $metadataRoot $relative
        } else {
            throw "Platform release manifest 包含无法映射的安装文件：$relative"
        }
        $item = Assert-OrdinaryFile -Path $installedPath -Label "已安装发布文件 $relative"
        if ([long]$item.Length -ne [long]$entry.bytes -or
            (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash -ne
                ([string]$entry.sha256).ToUpperInvariant()) {
            throw "已安装发布文件与 release manifest 不一致：$relative"
        }
    }
    $actualReleaseFiles = @{}
    $runtimeRoot = Join-Path $Root 'runtime'
    $serviceRoot = Join-Path $Root 'service'
    foreach ($file in Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse -Force) {
        $relative = 'runtime/' + $file.FullName.Substring(
            $runtimeRoot.Length
        ).TrimStart('\').Replace('\', '/')
        $key = $relative.ToLowerInvariant()
        if ($actualReleaseFiles.ContainsKey($key)) {
            throw "已安装 Platform 发布包含重复路径：$relative"
        }
        $actualReleaseFiles[$key] = $true
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
        $relative = 'deploy/windows/' + $serviceRelative
        $key = $relative.ToLowerInvariant()
        if ($actualReleaseFiles.ContainsKey($key)) {
            throw "已安装 Platform 发布包含重复路径：$relative"
        }
        $actualReleaseFiles[$key] = $true
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
            throw "release-metadata 包含未批准文件：$relative"
        }
        $key = $relative.ToLowerInvariant()
        if ($actualReleaseFiles.ContainsKey($key)) {
            throw "已安装 Platform 发布包含重复路径：$relative"
        }
        $actualReleaseFiles[$key] = $true
    }
    if ($actualReleaseFiles.Count -ne $seen.Count) {
        throw '已安装 Platform 实际文件集合与 release manifest 不一致。'
    }
    foreach ($key in $actualReleaseFiles.Keys) {
        if (-not $seen.ContainsKey($key)) {
            throw "已安装 Platform 包含清单外文件：$key"
        }
    }
    foreach ($required in @(
            'runtime/MineGuardPlatform.exe',
            'deploy/windows/Install-MineGuardPlatformService.ps1',
            'deploy/windows/MineGuardPlatform.WindowsAcl.ps1',
            'deploy/windows/Resolve-MineGuardPlatformExecutable.ps1',
            'deploy/windows/MineGuard.Platform.xml',
            'deploy/windows/Start-MineGuardPlatform.ps1',
            'deploy/windows/Configure-MineGuardPlatformFormal.ps1',
            'deploy/windows/Test-MineGuardPlatform.ps1'
        )) {
        if (-not $seen.ContainsKey($required.ToLowerInvariant())) {
            throw "Platform release manifest 缺少服务链文件：$required"
        }
    }
    $expectedScript = Join-Path (Join-Path $Root 'service') 'Install-MineGuardPlatformService.ps1'
    if (-not $script:ServiceInstallScriptPath.Equals(
            $expectedScript, [StringComparison]::OrdinalIgnoreCase)) {
        throw '必须从已安装且经 release manifest 校验的 service 目录运行服务安装脚本。'
    }
    return [pscustomobject]@{
        Version = $version
        ManifestSha256 = $manifestHash
        CodeSigned = [bool]$manifest.codeSigned
        ReleaseClassification = $expectedClassification
        RecordedSignerThumbprint = [string]$build.signingCertificateThumbprint
        TrustAnchorPath = $trustAnchorPath
    }
}

function Assert-ProductionRuntimeSignature {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object] $ReleaseIdentity,
        [Parameter(Mandatory = $true)] [string] $ApprovedThumbprint
    )
    $approved = ($ApprovedThumbprint -replace '\s', '').ToUpperInvariant()
    if ($approved -notmatch '^[A-F0-9]{40}$') {
        throw '-ExpectedSignerThumbprint 必须是从独立审批渠道取得的 40 位证书 SHA-1 指纹。'
    }
    if (-not [bool]$ReleaseIdentity.CodeSigned -or
        [string]$ReleaseIdentity.ReleaseClassification -ne
            'signed-production-candidate') {
        throw '正式服务只接受标记为 signed-production-candidate 的已签名 Platform 发布。'
    }
    $recorded = (([string]$ReleaseIdentity.RecordedSignerThumbprint) `
        -replace '\s', '').ToUpperInvariant()
    if ($recorded -notmatch '^[A-F0-9]{40}$') {
        throw '已安装构建元数据没有有效的签名证书指纹。'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $null -eq $signature.SignerCertificate) {
        throw "Platform 主程序 Authenticode 签名无效：$($signature.Status)"
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'Platform 主程序缺少可验证的 Authenticode 时间戳。'
    }
    $actual = ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($actual -ne $approved) {
        throw 'Platform 主程序签名者与外部批准的证书指纹不一致。'
    }
    if ($actual -ne $recorded) {
        throw 'Platform 主程序签名者与构建元数据不一致。'
    }
}

function Assert-InternalUnsignedRuntimeIntegrity {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object] $ReleaseIdentity,
        [Parameter(Mandatory = $true)] [string] $ApprovedManifestSha256,
        [string] $ApprovedRuntimeSha256 = ''
    )
    $approvedManifest = ($ApprovedManifestSha256 -replace '\s', '').ToUpperInvariant()
    if ($approvedManifest -notmatch '^[A-F0-9]{64}$') {
        throw '-ExpectedReleaseManifestSha256 必须是从介质外独立审批渠道取得的 64 位 SHA-256。'
    }
    if (-not ([string]$ReleaseIdentity.ManifestSha256).Equals(
            $approvedManifest, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Platform 子发行清单 SHA-256 与介质外独立批准值不一致。'
    }
    $trustAnchor = Read-JsonObject -Path ([string]$ReleaseIdentity.TrustAnchorPath) `
        -Label 'Platform 持久化发行信任锚' -MaximumBytes 65536
    $anchorProperties = @($trustAnchor.PSObject.Properties | ForEach-Object { $_.Name })
    if ($anchorProperties.Count -ne 4 -or
        [int]$trustAnchor.schemaVersion -ne 1 -or
        [string]$trustAnchor.product -ne 'MineGuard Platform release trust anchor' -or
        [string]$trustAnchor.releaseClassification -ne 'unsigned-internal-release' -or
        -not ([string]$trustAnchor.childReleaseManifestSha256).Equals(
            $approvedManifest, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Platform 持久化发行信任锚与介质外批准值不一致。'
    }
    if ([bool]$ReleaseIdentity.CodeSigned -or
        [string]$ReleaseIdentity.ReleaseClassification -ne
            'unsigned-internal-release') {
        throw 'AllowUnsignedInternalRelease 只接受标记为 unsigned-internal-release 的未签名 Platform 发布。'
    }
    if (-not [string]::IsNullOrWhiteSpace(
            [string]$ReleaseIdentity.RecordedSignerThumbprint
        )) {
        throw '无签名内网发布不得在构建元数据中声明签名者指纹。'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'NotSigned') {
        throw "Platform 主程序与无签名内网发布声明不一致：$($signature.Status)"
    }
    $approvedRuntime = ($ApprovedRuntimeSha256 -replace '\s', '').ToUpperInvariant()
    if (-not [string]::IsNullOrWhiteSpace($approvedRuntime)) {
        if ($approvedRuntime -notmatch '^[A-F0-9]{64}$') {
            throw '-ExpectedRuntimeSha256 必须是 64 位十六进制 SHA-256。'
        }
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        if (-not $actual.Equals(
                $approvedRuntime, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'Platform 主程序 SHA-256 与附加批准值不一致。'
        }
    }
}

function Get-RegisteredService {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='MineGuardPlatform'" -ErrorAction Stop)
    if ($services.Count -gt 1) { throw '同一名称出现多个 Win32_Service 记录。' }
    if ($services.Count -eq 0) { return $null }
    return $services[0]
}

function Assert-ServiceSidTypeUnrestricted {
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\MineGuardPlatform'
    try {
        $properties = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
    } catch {
        throw '无法读取 MineGuardPlatform 的 ServiceSidType；拒绝继续。'
    }
    $property = $properties.PSObject.Properties['ServiceSidType']
    if ($null -eq $property -or [int]$property.Value -ne 1) {
        throw 'MineGuardPlatform 未启用 unrestricted 专属服务 SID；拒绝继续。'
    }
    $sidOutput = (& "$env:SystemRoot\System32\sc.exe" `
        'showsid' 'MineGuardPlatform' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe showsid 无法计算 MineGuardPlatform 服务 SID，退出码 $LASTEXITCODE。"
    }
    $sidMatches = @([regex]::Matches(
        $sidOutput,
        '(?<![0-9])S-1-5-80(?:-[0-9]+){5}(?![0-9])',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    ) | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
    if ($sidMatches.Count -ne 1 -or
        -not $sidMatches[0].Equals(
            $ServiceSid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Windows 计算的 MineGuardPlatform 服务 SID 与固定 ACL SID 不一致。'
    }
    try {
        $account = New-Object -TypeName Security.Principal.NTAccount `
            -ArgumentList $ServiceAccount
        $translated = $account.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "无法把专属虚拟账号 $ServiceAccount 解析为 Windows SID。"
    }
    if (-not $translated.Equals(
            $ServiceSid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw '专属虚拟账号解析所得 SID 与固定 ACL SID 不一致。'
    }
}

function Get-ServiceExecutablePath {
    param([object] $Service)
    $pathName = ([string]$Service.PathName).Trim()
    if ($pathName -match '^"([^"\r\n]+)"\s*$') { return $Matches[1] }
    if ($pathName -match '^[^"\r\n]+$') { return $pathName }
    throw 'MineGuardPlatform 服务 PathName 不安全或携带参数。'
}

function Assert-ServiceIdentity {
    param([object] $Service, [string] $ExpectedWrapper, [switch] $PathOnly)
    $registered = Get-SafeLocalPath -Path (Get-ServiceExecutablePath -Service $Service) `
        -Label 'Win32_Service PathName' -RequireFixedNtfs
    if (-not $registered.Equals($ExpectedWrapper, [StringComparison]::OrdinalIgnoreCase)) {
        throw '同名 MineGuardPlatform 服务未精确指向批准的无参数 wrapper；拒绝继续。'
    }
    if (-not $PathOnly -and
        -not ([string]$Service.StartName).Equals(
            $ServiceAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw "MineGuardPlatform 服务账号不是批准的专属虚拟账号 $ServiceAccount。"
    }
}

function Wait-ServiceRecordAbsent {
    param([int] $Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 200
        $service = Get-RegisteredService
    } while ($null -ne $service -and [DateTime]::UtcNow -lt $deadline)
    if ($null -ne $service) { throw 'MineGuardPlatform 服务注册未在期限内删除。' }
}

function Remove-ServiceRegistrationChecked {
    param([string] $ExpectedWrapper)
    $service = Get-RegisteredService
    if ($null -eq $service) { return }
    Assert-ServiceIdentity -Service $service -ExpectedWrapper $ExpectedWrapper -PathOnly
    if (-not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase)) {
        Stop-Service -Name 'MineGuardPlatform' -Force -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 200
            $service = Get-RegisteredService
            if ($null -eq $service) { return }
            Assert-ServiceIdentity -Service $service -ExpectedWrapper $ExpectedWrapper -PathOnly
        } while (-not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase) -and
            [DateTime]::UtcNow -lt $deadline)
        if (-not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MineGuardPlatform 服务未能在 30 秒内停止。'
        }
    }
    $service = Get-RegisteredService
    if ($null -eq $service) { return }
    Assert-ServiceIdentity -Service $service -ExpectedWrapper $ExpectedWrapper -PathOnly
    & "$env:SystemRoot\System32\sc.exe" 'delete' 'MineGuardPlatform' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete 失败，退出码 $LASTEXITCODE。" }
    Wait-ServiceRecordAbsent
}

function Write-NewFileDurably {
    param([string] $Path, [byte[]] $Bytes)
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

Assert-Administrator
$InstallRoot = Get-SafeLocalPath -Path $InstallRoot -Label '安装目录' `
    -RequireFixedNtfs
$WinSWExecutable = Get-SafeLocalPath -Path $WinSWExecutable -Label 'WinSW 输入文件' `
    -RequireFixedNtfs
Assert-NotBroadOrSystemInstallRoot -Path $InstallRoot
$serviceDirectory = Get-SafeLocalPath -Path (Join-Path $InstallRoot 'service') `
    -Label '服务目录' -RequireFixedNtfs
$configDirectory = Get-SafeLocalPath -Path (Join-Path $InstallRoot 'config') `
    -Label '配置目录' -RequireFixedNtfs
$configurationMutex = New-Object -TypeName System.Threading.Mutex `
    -ArgumentList @($false, 'Global\MineGuardPlatform.Configuration')
$configurationMutexHeld = $false
try {
    try {
        $configurationMutexHeld = $configurationMutex.WaitOne(
            [TimeSpan]::FromSeconds(30)
        )
    } catch [System.Threading.AbandonedMutexException] {
        $configurationMutexHeld = $true
    }
    if (-not $configurationMutexHeld) {
        throw '前台/服务运行或配置事务仍占用机器级配置锁；30 秒内未取得，已拒绝安装服务。'
    }
Assert-NoReparseTree -Path $serviceDirectory -Label '服务目录'
Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
$releaseIdentity = Assert-PlatformReleaseIdentity -Root $InstallRoot
$resolverPath = Join-Path $serviceDirectory 'Resolve-MineGuardPlatformExecutable.ps1'
$aclHelperPath = Join-Path $serviceDirectory 'MineGuardPlatform.WindowsAcl.ps1'
$template = Join-Path $serviceDirectory 'MineGuard.Platform.xml'
$settings = Join-Path $configDirectory 'settings.json'
$bootstrapSecret = Join-Path $configDirectory 'bootstrap-admin-password.txt'
$null = Assert-OrdinaryFile -Path $WinSWExecutable -Label 'WinSW 输入文件' `
    -MaximumBytes 134217728
if (-not (Test-Path -LiteralPath $template -PathType Leaf)) {
    throw "WinSW XML 模板不存在：$template。请重新运行平台安装脚本。"
}
if (-not (Test-Path -LiteralPath $settings -PathType Leaf)) {
    throw '缺少 settings.json；请先运行配置脚本。'
}
if (-not (Test-Path -LiteralPath $resolverPath -PathType Leaf)) {
    throw "找不到运行时解析器：$resolverPath"
}
$null = Assert-OrdinaryFile -Path $aclHelperPath `
    -Label 'Platform ACL helper' -MaximumBytes 262144
. $resolverPath
. $aclHelperPath
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
$runtimePath = Get-SafeLocalPath -Path ([string]$runtime.filePath) `
    -Label 'Platform runtime' -RequireFixedNtfs
$expectedRuntimePath = Join-Path $InstallRoot 'runtime\MineGuardPlatform.exe'
if (-not $runtimePath.Equals($expectedRuntimePath, [StringComparison]::OrdinalIgnoreCase) -or
    [string]$runtime.runtimeKind -ne 'standalone') {
    throw 'Windows 服务只接受经 release manifest 认证的 standalone Platform runtime。'
}
$actualHash = (Get-FileHash -LiteralPath $WinSWExecutable -Algorithm SHA256).Hash
if (-not $actualHash.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "WinSW SHA-256 不匹配。实际值：$actualHash"
}
try { [xml]$xml = Get-Content -LiteralPath $template -Raw -Encoding UTF8 } catch {
    throw "WinSW XML 无效：$($_.Exception.Message)"
}
if ($xml.service.id -ne 'MineGuardPlatform' -or
    $xml.service.serviceaccount.username -ne $ServiceAccount -or
    $xml.service.executable -ne '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe' -or
    $xml.service.workingdirectory -ne '%BASE%' -or
    $xml.service.startmode -ne 'Automatic' -or
    $null -ne $xml.service.serviceaccount.password) {
    throw 'WinSW XML 的服务 ID、可执行入口、工作目录或专属虚拟服务账号不符合固定契约。'
}
$xmlText = Get-Content -LiteralPath $template -Raw -Encoding UTF8
if ($xmlText -match '(?i)REPLACE[_-]|CHANGE[_-]ME|<password>|MINEGUARD_ADMIN_PASSWORD') {
    throw 'WinSW XML 包含秘密/占位符；拒绝安装服务。'
}

$configuration = Read-JsonObject -Path $settings -Label 'Platform settings.json' `
    -MaximumBytes 1048576
if ([int]$configuration.schemaVersion -ne 1) {
    throw 'settings.json 版本不受支持。'
}
if ([string]$configuration.host -ne '127.0.0.1') {
    throw '服务只允许监听 127.0.0.1。'
}
$configuredPort = [int]$configuration.port
if ($configuredPort -lt 1 -or $configuredPort -gt 65535) {
    throw 'settings.json 端口必须在 1-65535 之间。'
}
if ($configuration.secureCookie -isnot [bool] -or
    $configuration.allowDemoDefaultPassword -isnot [bool]) {
    throw 'settings.json 的安全开关必须是 JSON 布尔值。'
}
foreach ($identityName in @('platformSystemId', 'platformPartyId', 'platformKeyId')) {
    if ([string]$configuration.$identityName -notmatch
        '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "settings.json 的 $identityName 不是有效 Platform 身份。"
    }
}
if ([string]::IsNullOrWhiteSpace([string]$configuration.adminUsername) -or
    ([string]$configuration.adminUsername).Length -gt 128) {
    throw 'settings.json 的管理员身份无效。'
}
$configuredClientsFile = [string]$configuration.clientsFile
$managedProvisioningRequired = $false
$managedProvisioningProperty = $configuration.PSObject.Properties[
    'managedProvisioningRequired'
]
if ($null -ne $managedProvisioningProperty) {
    if ($managedProvisioningProperty.Value -isnot [bool]) {
        throw 'settings.json 的 managedProvisioningRequired 必须是 JSON 布尔值。'
    }
    $managedProvisioningRequired = [bool]$managedProvisioningProperty.Value
}
$isFormalConfiguration = -not [string]::IsNullOrWhiteSpace(
    $configuredClientsFile
)
$isDemoConfiguration = -not $isFormalConfiguration
if ($isFormalConfiguration) {
    if ([bool]$configuration.allowDemoDefaultPassword) {
        throw '正式配置绝不允许 allowDemoDefaultPassword=true；拒绝安装降级服务。'
    }
    if (-not [bool]$configuration.secureCookie) {
        throw '正式 Windows 服务必须启用 Secure Cookie 并通过 HTTPS 反向代理访问。'
    }
    if (-not $Production) {
        throw '正式配置安装服务必须显式使用 -Production。'
    }
    if ($AllowUnsignedInternalRelease) {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
            throw '无签名内网模式不接受 ExpectedSignerThumbprint；必须使用独立批准的 ExpectedReleaseManifestSha256。'
        }
        Assert-InternalUnsignedRuntimeIntegrity -Path $runtimePath `
            -ReleaseIdentity $releaseIdentity `
            -ApprovedManifestSha256 $ExpectedReleaseManifestSha256 `
            -ApprovedRuntimeSha256 $ExpectedRuntimeSha256
        Write-Warning (
            '正在以内网无签名正式发行模式安装正式服务：生产配置与安全门禁全部保留，' +
            '但 Windows 无法验证软件发布者；信任来自介质外独立批准的子发行清单 SHA-256，' +
            '并覆盖完整 standalone 文件树。'
        )
    } else {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedRuntimeSha256) -or
            -not [string]::IsNullOrWhiteSpace($ExpectedReleaseManifestSha256)) {
            throw '运行时/发行清单 SHA-256 只能与 -AllowUnsignedInternalRelease 同时使用。'
        }
        Assert-ProductionRuntimeSignature -Path $runtimePath `
            -ReleaseIdentity $releaseIdentity `
            -ApprovedThumbprint $ExpectedSignerThumbprint
    }
} elseif (-not [bool]$configuration.allowDemoDefaultPassword -or
    [bool]$configuration.secureCookie) {
    throw '无客户端注册表时只允许明确的本机 HTTP 演示配置；安全开关组合不一致。'
}
if ($isDemoConfiguration -and
    ($Production -or $AllowUnsignedInternalRelease -or
        -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedRuntimeSha256) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedReleaseManifestSha256))) {
    throw '演示配置不得声明 -Production、内网未签名授权或正式信任锚。'
}
if (-not [string]::IsNullOrWhiteSpace($configuredClientsFile)) {
    $configuredClientsFile = Get-SafeLocalPath -Path $configuredClientsFile `
        -Label 'settings.json 客户端注册表'
    if (-not (Test-Path -LiteralPath $configuredClientsFile -PathType Leaf)) {
        throw 'settings.json 指向的客户端注册表不存在。'
    }
    $expectedClientsFile = Join-Path $configDirectory 'clients.json'
    if (-not $configuredClientsFile.Equals(
            $expectedClientsFile, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'settings.json 客户端注册表必须是安装目录内经配置事务发布的 config\clients.json。'
    }
    $null = Assert-OrdinaryFile -Path $configuredClientsFile `
        -Label 'settings.json 客户端注册表' -MaximumBytes 4194304
    $registryProbeArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'config-check', '--clients-file', $configuredClientsFile
        )
    $registryProbeText = & $runtime.filePath @registryProbeArguments
    if ($LASTEXITCODE -ne 0) {
        throw '客户端注册表无法通过短生命周期只读核验。'
    }
    try {
        $registryProbe = $registryProbeText | Out-String | ConvertFrom-Json
    } catch { throw '客户端注册表只读核验未返回有效 JSON。' }
    $registryProbeText = $null
    $hasManagedRegistryLock = [bool]$registryProbe.client_registry_managed
    $registryProbe = $null
    if ($hasManagedRegistryLock -and -not $managedProvisioningRequired) {
        throw 'clients.json 已包含受管注册锁，但 settings.json 未启用强制受管校验。'
    }
    if ($managedProvisioningRequired) {
        foreach ($requiredTrustName in @(
                'provisioningTrustedPublicKeyFile',
                'provisioningExpectedPublicKeySha256',
                'provisioningExpectedIssuerKeyId'
            )) {
            if ($null -eq $configuration.PSObject.Properties[$requiredTrustName]) {
                throw "受管 settings.json 缺少 $requiredTrustName。"
            }
        }
        $trustedPublicKeyPath = Get-SafeLocalPath `
            -Path ([string]$configuration.provisioningTrustedPublicKeyFile) `
            -Label 'settings.json 签发信任公钥' -RequireFixedNtfs
        $expectedTrustedPublicKeyPath = Join-Path $configDirectory `
            'provisioning-issuer-public.pem'
        if (-not $trustedPublicKeyPath.Equals(
                $expectedTrustedPublicKeyPath,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw '受管签发公钥必须固定为 config\provisioning-issuer-public.pem。'
        }
        $null = Assert-OrdinaryFile -Path $trustedPublicKeyPath `
            -Label 'settings.json 签发信任公钥' -MaximumBytes 65536
        $expectedProvisioningHash = [string](
            $configuration.provisioningExpectedPublicKeySha256
        )
        $expectedProvisioningIssuerKeyId = [string](
            $configuration.provisioningExpectedIssuerKeyId
        )
        if ($expectedProvisioningHash -cnotmatch '^[0-9a-f]{64}$' -or
            $expectedProvisioningIssuerKeyId -notmatch `
                '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
            throw '受管签发公钥 SPKI SHA-256 或 issuer key ID 格式无效。'
        }
        $env:MINEGUARD_PROVISIONING_MANAGED_REQUIRED = 'true'
        $env:MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE = `
            $trustedPublicKeyPath
        $env:MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256 = `
            $expectedProvisioningHash
        $env:MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID = `
            $expectedProvisioningIssuerKeyId
    }
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--clients-file', $configuredClientsFile, '--production',
            '--platform-system-id', ([string]$configuration.platformSystemId),
            '--platform-party-id', ([string]$configuration.platformPartyId),
            '--platform-key-id', ([string]$configuration.platformKeyId)
        )
    & $runtime.filePath @checkArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '客户端注册表未通过 MineGuard 完整校验。' }
}
$configuredStateDirectory = Get-SafeLocalPath `
    -Path ([string]$configuration.stateDirectory) `
    -Label 'settings.json 状态目录' -RequireFixedNtfs
$defaultStateDirectory = Get-SafeLocalPath `
    -Path (Join-Path $InstallRoot 'state') -Label '默认状态目录' `
    -RequireFixedNtfs
if (Test-PathEqualOrChild -Candidate $configuredStateDirectory -Parent $InstallRoot) {
    if (-not (Test-PathEqualOrChild -Candidate $configuredStateDirectory `
            -Parent $defaultStateDirectory)) {
        throw 'settings.json 状态目录不能指向 runtime、config、service 或其他程序目录。'
    }
} elseif (Test-PathEqualOrChild -Candidate $InstallRoot `
    -Parent $configuredStateDirectory) {
    throw 'settings.json 状态目录不能是安装目录的祖先。'
}
if (-not (Test-Path -LiteralPath $configuredStateDirectory -PathType Container)) {
    throw 'settings.json 状态目录不存在；请先重新运行配置脚本。'
}
Assert-NoReparseTree -Path $configuredStateDirectory -Label 'settings.json 状态目录'
$stateMarkerPath = Join-Path $configuredStateDirectory '.mineguard-platform-state.json'
if (-not (Test-Path -LiteralPath $stateMarkerPath -PathType Leaf)) {
    throw '状态目录缺少 MineGuard 所有权标记；请先重新运行配置脚本。'
}
$stateMarker = Read-JsonObject -Path $stateMarkerPath `
    -Label '状态目录所有权标记' -MaximumBytes 65536
if ([int]$stateMarker.schemaVersion -ne 1 -or
    [string]$stateMarker.product -ne 'MineGuard Platform State' -or
    [string]::IsNullOrWhiteSpace([string]$stateMarker.initializedFor)) {
    throw '状态目录所有权标记不属于 MineGuard Platform。'
}
$markerInstallRoot = Get-SafeLocalPath -Path ([string]$stateMarker.initializedFor) `
    -Label '状态目录标记 initializedFor' -RequireFixedNtfs
if (-not $markerInstallRoot.Equals($InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw '状态目录所有权标记不属于当前 Platform 安装目录。'
}
if ($isFormalConfiguration) {
    $stateCheckArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @(
            'config-check', '--state-directory', $configuredStateDirectory,
            '--production'
        )
    & $runtime.filePath @stateCheckArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '状态目录包含演示/合成数据或无法通过正式用途核验；拒绝安装服务。'
    }
}
$authDatabase = Join-Path $configuredStateDirectory 'auth.db'
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--auth-database', $authDatabase)
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝安装服务。'
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
            throw 'auth.db 没有正式可用管理员，或仍有启用的演示凭据账号；拒绝安装服务。'
        }
    }
}
if (-not $hasAuthUser -and
    -not (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf) -and
    $isFormalConfiguration) {
    throw '首次启动缺少受保护的管理员密码文件；拒绝安装会回退演示口令的服务。'
}
if (-not $hasAuthUser -and
    (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf) -and
    $isFormalConfiguration) {
    $null = Assert-OrdinaryFile -Path $bootstrapSecret `
        -Label '首次管理员密码文件' -MaximumBytes 4096
    $bootstrapArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'bootstrap-admin', '--state-directory', $configuredStateDirectory,
            '--admin-username', ([string]$configuration.adminUsername),
            '--password-file', $bootstrapSecret, '--production'
        )
    & $runtime.filePath @bootstrapArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '短生命周期 bootstrap-admin 未能建立正式管理员摘要；拒绝安装服务。'
    }
    if (Test-Path -LiteralPath $bootstrapSecret) {
        throw 'bootstrap-admin 成功返回但未删除首启密码文件；拒绝安装长运行服务。'
    }
    $productionAuthArguments = Join-MineGuardPlatformArguments `
        -Runtime $runtime -Arguments @(
            'config-check', '--auth-database', $authDatabase, '--production'
        )
    & $runtime.filePath @productionAuthArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '短首启 helper 建立的管理员摘要未通过正式凭据核验。'
    }
    $hasAuthUser = $true
}
if ($hasAuthUser -and $isFormalConfiguration -and
    (Test-Path -LiteralPath $bootstrapSecret)) {
    throw 'auth.db 已有账号但首启密码文件仍在；请先按受控清理流程处理，拒绝安装服务。'
}
if ($isDemoConfiguration -and
    (Test-Path -LiteralPath $bootstrapSecret)) {
    throw '演示服务不使用首启密码文件；请先按受控流程清理异常残留。'
}
if ($isDemoConfiguration) {
    $demoStateArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--state-directory', $configuredStateDirectory)
    $demoStateText = & $runtime.filePath @demoStateArguments
    if ($LASTEXITCODE -ne 0) { throw '演示状态目录无法核验；拒绝安装服务。' }
    $demoStateCheck = $demoStateText | Out-String | ConvertFrom-Json
    if ([int]$demoStateCheck.state_demo_evidence_count -lt 1) {
        throw '演示配置缺少受控合成数据标记；拒绝用演示开关安装正式状态目录。'
    }
    Write-Warning '配置允许演示默认密码；不得把该服务接入正式内网。'
}

$destination = Join-Path $serviceDirectory 'MineGuard.Platform.exe'
$destinationConfig = $destination + '.config'
$sourceConfig = $WinSWExecutable + '.config'
$integrityPath = Join-Path $serviceDirectory 'winsw-integrity.json'
$destination = Get-SafeLocalPath -Path $destination -Label 'WinSW 目标 wrapper' -RequireFixedNtfs
$destinationConfig = Get-SafeLocalPath -Path $destinationConfig `
    -Label 'WinSW 目标 .config' -RequireFixedNtfs
$integrityPath = Get-SafeLocalPath -Path $integrityPath `
    -Label 'WinSW 完整性记录' -RequireFixedNtfs
foreach ($path in @($destination, $destinationConfig, $integrityPath)) {
    Assert-PathBelowRoot -Path $path -Root $serviceDirectory -Label 'WinSW 服务文件'
    if (Test-Path -LiteralPath $path) {
        throw "服务安装拒绝覆盖已有 WinSW 文件：$path。请先安全移除旧服务和 wrapper。"
    }
}
if ($null -ne (Get-RegisteredService)) {
    throw 'MineGuardPlatform 服务已经安装；本脚本不会隐式覆盖或重装现有服务。'
}
$configHash = ''
if (Test-Path -LiteralPath $sourceConfig -PathType Leaf) {
    $sourceConfig = Get-SafeLocalPath -Path $sourceConfig `
        -Label 'WinSW .config 输入文件' -RequireFixedNtfs
    $null = Assert-OrdinaryFile -Path $sourceConfig -Label 'WinSW .config 输入文件' `
        -MaximumBytes 4194304
    if ([string]$ExpectedConfigSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'WinSW 输入带 .config 时必须显式提供外部批准的 ExpectedConfigSha256。'
    }
    $configHash = (Get-FileHash -LiteralPath $sourceConfig -Algorithm SHA256).Hash
    if (-not $configHash.Equals(
            $ExpectedConfigSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WinSW .config SHA-256 与外部批准值不一致。'
    }
} elseif (-not [string]::IsNullOrWhiteSpace($ExpectedConfigSha256)) {
    throw '提供了 ExpectedConfigSha256，但 WinSW 输入没有 companion .config。'
}
$integrity = [ordered]@{
    schemaVersion = 1
    product = 'MineGuard Platform WinSW Service'
    serviceId = 'MineGuardPlatform'
    serviceAccount = $ServiceAccount
    serviceSid = $ServiceSid
    serviceSidType = 'unrestricted'
    canonicalWrapperPath = $destination
    wrapperSha256 = $actualHash
    wrapperConfigSha256 = $configHash
}
$transactionId = [Guid]::NewGuid().ToString('N')
$temporaryWrapper = Join-Path $serviceDirectory ('.winsw-{0}.exe.tmp' -f $transactionId)
$temporaryConfig = Join-Path $serviceDirectory ('.winsw-{0}.config.tmp' -f $transactionId)
$temporaryIntegrity = Join-Path $serviceDirectory ('.winsw-{0}.integrity.tmp' -f $transactionId)
$publishedWrapper = $false
$publishedConfig = $false
$publishedIntegrity = $false
try {
    # 最后一次复核全部外部信任锚和产品身份，然后才开始写入服务目录。
    $lateReleaseIdentity = Assert-PlatformReleaseIdentity -Root $InstallRoot
    if ($isFormalConfiguration) {
        if ($AllowUnsignedInternalRelease) {
            Assert-InternalUnsignedRuntimeIntegrity -Path $runtimePath `
                -ReleaseIdentity $lateReleaseIdentity `
                -ApprovedManifestSha256 $ExpectedReleaseManifestSha256 `
                -ApprovedRuntimeSha256 $ExpectedRuntimeSha256
        } else {
            Assert-ProductionRuntimeSignature -Path $runtimePath `
                -ReleaseIdentity $lateReleaseIdentity `
                -ApprovedThumbprint $ExpectedSignerThumbprint
        }
    }
    $null = Assert-OrdinaryFile -Path $WinSWExecutable -Label 'WinSW 输入文件' `
        -MaximumBytes 134217728
    $actualHash = (Get-FileHash -LiteralPath $WinSWExecutable -Algorithm SHA256).Hash
    if (-not $actualHash.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WinSW SHA-256 在服务安装前发生变化。'
    }
    if ($null -ne (Get-RegisteredService)) { throw '服务安装期间出现了同名服务。' }
    foreach ($path in @($destination, $destinationConfig, $integrityPath)) {
        if (Test-Path -LiteralPath $path) { throw "服务安装期间目标文件被占用：$path" }
    }

    Write-NewFileDurably -Path $temporaryWrapper -Bytes ([IO.File]::ReadAllBytes($WinSWExecutable))
    if ((Get-FileHash -LiteralPath $temporaryWrapper -Algorithm SHA256).Hash -ne
        $ExpectedSha256.ToUpperInvariant()) {
        throw '暂存 WinSW wrapper 未通过批准 SHA-256。'
    }
    if (-not [string]::IsNullOrWhiteSpace($configHash)) {
        $lateConfigHash = (Get-FileHash -LiteralPath $sourceConfig -Algorithm SHA256).Hash
        if (-not $lateConfigHash.Equals(
                $ExpectedConfigSha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'WinSW .config 在暂存前发生变化。'
        }
        Write-NewFileDurably -Path $temporaryConfig -Bytes ([IO.File]::ReadAllBytes($sourceConfig))
        if ((Get-FileHash -LiteralPath $temporaryConfig -Algorithm SHA256).Hash -ne
            $ExpectedConfigSha256.ToUpperInvariant()) {
            throw '暂存 WinSW .config 未通过批准 SHA-256。'
        }
    }
    Write-NewFileDurably -Path $temporaryIntegrity `
        -Bytes $utf8NoBom.GetBytes(($integrity | ConvertTo-Json -Depth 4))

    [IO.File]::Move($temporaryWrapper, $destination)
    $publishedWrapper = $true
    if (-not [string]::IsNullOrWhiteSpace($configHash)) {
        [IO.File]::Move($temporaryConfig, $destinationConfig)
        $publishedConfig = $true
    }
    [IO.File]::Move($temporaryIntegrity, $integrityPath)
    $publishedIntegrity = $true
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne
        $ExpectedSha256.ToUpperInvariant()) {
        throw '已发布 WinSW wrapper 未通过批准 SHA-256。'
    }
    if ($publishedConfig -and
        (Get-FileHash -LiteralPath $destinationConfig -Algorithm SHA256).Hash -ne
            $ExpectedConfigSha256.ToUpperInvariant()) {
        throw '已发布 WinSW .config 未通过批准 SHA-256。'
    }
    try {
        Set-MineGuardPlatformServiceReadableFileAcl -Path $integrityPath
    } catch {
        throw (
            '保护 WinSW 完整性记录失败；拒绝安装服务。详情：' +
            $_.Exception.Message
        )
    }

    if ($null -ne (Get-RegisteredService)) { throw '注册服务前出现了同名服务。' }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne
        $ExpectedSha256.ToUpperInvariant()) {
        throw 'WinSW wrapper 在关键注册操作前发生变化。'
    }
    if ($publishedConfig -and
        (Get-FileHash -LiteralPath $destinationConfig -Algorithm SHA256).Hash -ne
            $ExpectedConfigSha256.ToUpperInvariant()) {
        throw 'WinSW .config 在关键注册操作前发生变化。'
    }
    & $destination 'install'
    if ($LASTEXITCODE -ne 0) { throw "WinSW 安装服务失败，退出码 $LASTEXITCODE。" }
    $registeredService = Get-RegisteredService
    if ($null -eq $registeredService) { throw 'WinSW 返回成功但未注册 MineGuardPlatform 服务。' }
    & "$env:SystemRoot\System32\sc.exe" 'sidtype' 'MineGuardPlatform' `
        'unrestricted' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "设置 MineGuardPlatform 专属服务 SID 失败，sc.exe 退出码 $LASTEXITCODE。"
    }
    Assert-ServiceSidTypeUnrestricted
    Assert-ServiceIdentity -Service $registeredService -ExpectedWrapper $destination
    if ($StartService) {
        $registeredService = Get-RegisteredService
        Assert-ServiceSidTypeUnrestricted
        Assert-ServiceIdentity -Service $registeredService -ExpectedWrapper $destination
        # Start-MineGuardPlatform.ps1 必须持有同一把锁贯穿运行期。
        # 此时配置、bootstrap 和服务注册已完整提交，先释放再启动，
        # 避免新服务等待本安装进程而死锁。
        $configurationMutex.ReleaseMutex()
        $configurationMutexHeld = $false
        Start-Service -Name 'MineGuardPlatform' -ErrorAction Stop
        $serviceController = Get-Service -Name 'MineGuardPlatform' -ErrorAction Stop
        $serviceController.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(30)
        )
        $healthScript = Join-Path $serviceDirectory 'Test-MineGuardPlatform.ps1'
        $healthArguments = @{
            BaseUri = ('http://127.0.0.1:{0}' -f $configuredPort)
            TimeoutSeconds = 2
        }
        if ($isDemoConfiguration) {
            $healthArguments['HealthOnly'] = $true
        }
        $ready = $false
        for ($attempt = 1; $attempt -le 15; $attempt++) {
            try {
                & $healthScript @healthArguments | Out-Null
                $ready = $true
                break
            } catch {
                Start-Sleep -Seconds 2
            }
        }
        if (-not $ready) {
            throw '服务已启动，但 30 秒内未通过健康检查。'
        }
        $registeredService = Get-RegisteredService
        Assert-ServiceSidTypeUnrestricted
        Assert-ServiceIdentity -Service $registeredService -ExpectedWrapper $destination
    }
} catch {
    $originalError = $_
    $rollbackErrors = New-Object System.Collections.Generic.List[string]
    try { Remove-ServiceRegistrationChecked -ExpectedWrapper $destination }
    catch { $rollbackErrors.Add($_.Exception.Message) }
    $remainingService = $null
    $serviceStateKnown = $false
    try { $remainingService = Get-RegisteredService; $serviceStateKnown = $true }
    catch { $rollbackErrors.Add($_.Exception.Message) }
    if ($serviceStateKnown -and $null -eq $remainingService) {
        foreach ($published in @(
                [pscustomobject]@{ Path = $integrityPath; Created = $publishedIntegrity },
                [pscustomobject]@{ Path = $destinationConfig; Created = $publishedConfig },
                [pscustomobject]@{ Path = $destination; Created = $publishedWrapper }
            )) {
            if ($published.Created -and (Test-Path -LiteralPath $published.Path)) {
                try { Remove-Item -LiteralPath $published.Path -Force -ErrorAction Stop }
                catch { $rollbackErrors.Add($_.Exception.Message) }
            }
        }
    } else {
        $rollbackErrors.Add('服务状态或归属无法证明为已删除；为避免破坏仍注册的服务，已保留 wrapper 文件。')
    }
    if ($rollbackErrors.Count -gt 0) {
        throw ('Platform 服务安装失败：' + $originalError.Exception.Message +
            '；rollback incomplete：' + ($rollbackErrors -join '；'))
    }
    throw $originalError
} finally {
    foreach ($temporaryPath in @($temporaryIntegrity, $temporaryConfig, $temporaryWrapper)) {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}
} finally {
    if ($configurationMutexHeld) {
        try { $configurationMutex.ReleaseMutex() }
        catch { }
    }
    if ($null -ne $configurationMutex) { $configurationMutex.Dispose() }
}

Write-Host 'MineGuardPlatform Windows 服务安装完成。'
Write-Host "WinSW SHA-256：$actualHash"
if (-not $StartService) {
    Write-Host '检查 HTTPS 反向代理和配置后，运行 Start-Service MineGuardPlatform。'
}
