[CmdletBinding()]
param(
    [string] $SourceDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
    [string] $PythonExecutable,
    [string] $Wheelhouse,
    [ValidateRange(1, 65535)] [int] $Port = 8080,
    [switch] $AuditFailAfterRuntimeSwitch
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ServiceSid = 'S-1-5-19'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $identity
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw '安装和设置 NTFS ACL 必须在“以管理员身份运行”的 Windows PowerShell 5.1 中执行。'
    }
}

function Get-LocalAbsolutePath {
    param(
        [string] $Value,
        [string] $Label,
        [switch] $RequireFixedNtfs
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ($fullPath.StartsWith('\\')) { throw "$Label 不能使用 UNC/SMB 网络路径。" }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    if ($RequireFixedNtfs) {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
            throw "$Label 必须位于本机固定磁盘。"
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
        if ($current.TrimEnd('\\') -eq $root.TrimEnd('\\')) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $fullPath
}

function Test-PathEqualOrChild {
    param([string] $Candidate, [string] $Parent)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\\')
    return $candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith(
            $parentFull + '\\', [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-NotBroadOrSystemInstallRoot {
    param([string] $Path)
    $candidate = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $protectedExact = @(
        $env:ProgramData,
        $env:ALLUSERSPROFILE,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:CommonProgramFiles,
        ${env:CommonProgramFiles(x86)},
        $env:PUBLIC
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    foreach ($protectedValue in $protectedExact) {
        $protected = [System.IO.Path]::GetFullPath(
            [string]$protectedValue
        ).TrimEnd('\')
        if ($candidate.Equals($protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能是 ProgramData、Program Files、Public 等宽泛系统目录本身。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $windowsRoot = [System.IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')
        if ($candidate.Equals($windowsRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith(
                $windowsRoot + '\', [StringComparison]::OrdinalIgnoreCase
            )) {
            throw '安装目录不能位于 Windows 系统目录内。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $usersRoot = [System.IO.Path]::GetFullPath(
            (Join-Path $env:SystemDrive 'Users')
        ).TrimEnd('\')
        if ($candidate.Equals($usersRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能是整个 Users 目录。'
        }
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)] [string] $Command,
        [Parameter(Mandatory = $true)] [object[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label 失败，退出码 $LASTEXITCODE。"
    }
}

function Set-MineGuardDirectoryAcl {
    param(
        [string] $Path,
        [string] $ServicePermission,
        [switch] $Recurse
    )
    $serviceGrant = ('*{0}:(OI)(CI){1}' -f $ServiceSid, $ServicePermission)
    $aclArguments = @(
        $Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F', $serviceGrant
    )
    if ($Recurse) { $aclArguments += @('/T', '/C') }
    & "$env:SystemRoot\System32\icacls.exe" @aclArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "设置 NTFS ACL 失败：$Path" }
}

function Test-MineGuardPlatformRuntimeProcess {
    param([string] $RuntimeRoot)
    $runtimePrefix = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\\') + '\\'
    $running = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            if ([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)) {
                return $false
            }
            try {
                $processPath = [System.IO.Path]::GetFullPath(
                    [string]$_.ExecutablePath
                )
                return $processPath.StartsWith(
                    $runtimePrefix, [StringComparison]::OrdinalIgnoreCase
                )
            } catch {
                return $false
            }
        })
    return $running.Count -gt 0
}

Assert-Administrator
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$SourceDirectory = Get-LocalAbsolutePath -Value $SourceDirectory -Label '发布源目录'
$InstallRoot = Get-LocalAbsolutePath -Value $InstallRoot -Label '安装目录' `
    -RequireFixedNtfs
Assert-NotBroadOrSystemInstallRoot -Path $InstallRoot
$binarySource = Join-Path $SourceDirectory 'runtime\MineGuardPlatform.exe'
$sourceProject = Join-Path $SourceDirectory 'pyproject.toml'
$binaryMode = Test-Path -LiteralPath $binarySource -PathType Leaf
$sourceMode = Test-Path -LiteralPath $sourceProject -PathType Leaf
if (-not $binaryMode -and -not $sourceMode) {
    throw "源目录既不是 Platform 二进制发布包，也不是开发源码目录：$SourceDirectory"
}
if ((Test-PathEqualOrChild -Candidate $InstallRoot -Parent $SourceDirectory) -or
    (Test-PathEqualOrChild -Candidate $SourceDirectory -Parent $InstallRoot)) {
    throw '发布源目录与安装目录不得相同或互相嵌套。'
}

$launcherArguments = @()
$venvPython = $null
if ($binaryMode) {
    if (-not [string]::IsNullOrWhiteSpace($PythonExecutable) -or
        -not [string]::IsNullOrWhiteSpace($Wheelhouse)) {
        throw '二进制发布包不接受 PythonExecutable 或 Wheelhouse；客户机无需 Python。'
    }
    $hashFile = Join-Path $SourceDirectory 'SHA256SUMS.txt'
    $releaseManifest = Join-Path $SourceDirectory 'release-manifest.json'
    foreach ($releaseFile in @($hashFile, $releaseManifest)) {
        if (-not (Test-Path -LiteralPath $releaseFile -PathType Leaf)) {
            throw "二进制发布包缺少完整性文件：$releaseFile"
        }
    }
    $releaseRootPrefix = $SourceDirectory.TrimEnd('\') + '\'
    $expectedFiles = @{}
    foreach ($line in Get-Content -LiteralPath $hashFile -Encoding UTF8) {
        if ($line -notmatch '^(?<hash>[A-Fa-f0-9]{64})  (?<path>[^\r\n]+)$') {
            throw 'SHA256SUMS.txt 格式不合法。'
        }
        $relative = [string]$Matches['path']
        $segments = $relative.Replace('\', '/').Split('/')
        if ([System.IO.Path]::IsPathRooted($relative) -or
            $relative.Contains(':') -or $segments -contains '..' -or
            $segments -contains '.' -or $segments -contains '') {
            throw "SHA256SUMS.txt 包含不安全路径：$relative"
        }
        $candidate = [System.IO.Path]::GetFullPath(
            (Join-Path $SourceDirectory $relative.Replace('/', '\'))
        )
        if (-not $candidate.StartsWith(
            $releaseRootPrefix, [StringComparison]::OrdinalIgnoreCase
        ) -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "发布清单文件不存在或越界：$relative"
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "发布包不能包含 reparse point：$relative"
        }
        $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
        if ($actual -ne ([string]$Matches['hash']).ToUpperInvariant()) {
            throw "发布文件 SHA-256 不匹配：$relative"
        }
        if ($expectedFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "SHA256SUMS.txt 重复列出文件：$relative"
        }
        $expectedFiles[$candidate.ToLowerInvariant()] = $true
    }
    foreach ($item in Get-ChildItem -LiteralPath $SourceDirectory -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "发布包不能包含 reparse point：$($item.FullName)"
        }
        if (-not $item.PSIsContainer -and $item.FullName -ne $hashFile -and
            -not $expectedFiles.ContainsKey($item.FullName.ToLowerInvariant())) {
            throw "发布包包含未列入 SHA256SUMS.txt 的文件：$($item.FullName)"
        }
    }
    try {
        $manifest = Get-Content -LiteralPath $releaseManifest -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw "release-manifest.json 无效：$($_.Exception.Message)"
    }
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.product -ne 'MineGuard Platform' -or
        [string]$manifest.architecture -ne 'x64' -or
        [string]$manifest.runtime -ne 'nuitka-standalone' -or
        [string]$manifest.entryPoint -ne 'runtime/MineGuardPlatform.exe') {
        throw '二进制发布清单与 MineGuard Platform x64 standalone 契约不符。'
    }
    $candidateVersionText = (Get-Content -LiteralPath (
        Join-Path $SourceDirectory 'VERSION.txt'
    ) -Raw -Encoding UTF8).Trim()
    if ($candidateVersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        [string]$manifest.version -ne $candidateVersionText) {
        throw '二进制发布包的 VERSION.txt 与 release-manifest.json 版本不一致。'
    }
    if ($manifest.codeSigned -isnot [bool]) {
        throw 'release-manifest.json 的 codeSigned 必须是 JSON 布尔值。'
    }
    if ($manifest.authenticodeVerified -isnot [bool] -or
        [bool]$manifest.authenticodeVerified -ne [bool]$manifest.codeSigned) {
        throw 'release-manifest.json 的 Authenticode 验证状态无效。'
    }
    $manifestFiles = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        $segments = $relative.Replace('\', '/').Split('/')
        if ([System.IO.Path]::IsPathRooted($relative) -or
            $relative.Contains(':') -or $segments -contains '..' -or
            $segments -contains '.' -or $segments -contains '' -or
            $relative -in @('release-manifest.json', 'SHA256SUMS.txt')) {
            throw "release-manifest.json 包含不安全或自引用路径：$relative"
        }
        if ([string]$entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            [long]$entry.bytes -lt 0) {
            throw "release-manifest.json 文件元数据无效：$relative"
        }
        $candidate = [System.IO.Path]::GetFullPath(
            (Join-Path $SourceDirectory $relative.Replace('/', '\'))
        )
        if (-not $expectedFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "release-manifest.json 引用了未认证文件：$relative"
        }
        $candidateItem = Get-Item -LiteralPath $candidate -Force
        $candidateHash = (Get-FileHash -LiteralPath $candidate `
            -Algorithm SHA256).Hash
        if ([long]$candidateItem.Length -ne [long]$entry.bytes -or
            $candidateHash -ne ([string]$entry.sha256).ToUpperInvariant()) {
            throw "release-manifest.json 文件摘要不匹配：$relative"
        }
        if ($manifestFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "release-manifest.json 重复列出文件：$relative"
        }
        $manifestFiles[$candidate.ToLowerInvariant()] = $true
    }
    foreach ($authenticatedPath in $expectedFiles.Keys) {
        if ($authenticatedPath -ne $releaseManifest.ToLowerInvariant() -and
            -not $manifestFiles.ContainsKey($authenticatedPath)) {
            throw "release-manifest.json 未覆盖发布文件：$authenticatedPath"
        }
    }
    $buildMetadataPath = Join-Path $SourceDirectory 'build-metadata.json'
    try {
        $buildMetadata = Get-Content -LiteralPath $buildMetadataPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "build-metadata.json 无效：$($_.Exception.Message)"
    }
    if ($buildMetadata.codeSigned -isnot [bool] -or
        [bool]$buildMetadata.codeSigned -ne [bool]$manifest.codeSigned) {
        throw '发布清单与构建元数据的代码签名状态不一致。'
    }
    if ([string]$buildMetadata.version -ne $candidateVersionText) {
        throw '构建元数据与候选发布版本不一致。'
    }
    if ([bool]$manifest.codeSigned) {
        $signature = Get-AuthenticodeSignature -LiteralPath $binarySource
        if ($signature.Status -ne 'Valid' -or
            $null -eq $signature.SignerCertificate) {
            throw "Platform 主程序 Authenticode 签名无效：$($signature.Status)"
        }
        $expectedSigner = [string]$buildMetadata.signingCertificateThumbprint
        $actualSigner = ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
        if ($expectedSigner -notmatch '^[A-Fa-f0-9]{40}$' -or
            $actualSigner -ne $expectedSigner.ToUpperInvariant()) {
            throw 'Platform 主程序签名证书与构建元数据不一致。'
        }
        if ($null -eq $signature.TimeStamperCertificate) {
            throw 'Platform 主程序缺少可验证的 Authenticode 时间戳。'
        }
    } else {
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$buildMetadata.signingCertificateThumbprint
            )) {
            throw '未签名发布的构建元数据不得声明签名证书指纹。'
        }
        $unsignedSignature = Get-AuthenticodeSignature -LiteralPath $binarySource
        if ($unsignedSignature.Status -ne 'NotSigned') {
            throw '发布清单声明未签名，但 Platform 主程序实际带有签名或签名状态异常。'
        }
        Write-Warning '当前为未签名内部测试版，不是生产可信发布。'
    }
    Invoke-CheckedNative -Command $binarySource -Arguments @('self-check') `
        -Label '校验发布包冻结运行时'

    $installedExecutablePath = Join-Path $InstallRoot 'runtime\MineGuardPlatform.exe'
    $installedMetadataRoot = Join-Path $InstallRoot 'release-metadata'
    $installedVersionPath = Join-Path $installedMetadataRoot 'VERSION.txt'
    if ((Test-Path -LiteralPath $installedExecutablePath -PathType Leaf) -and
        -not (Test-Path -LiteralPath $installedVersionPath -PathType Leaf)) {
        throw '检测到已安装的编译运行时但缺少 VERSION.txt；拒绝覆盖，请先核查安装完整性。'
    }
    if (Test-Path -LiteralPath $installedVersionPath -PathType Leaf) {
        $installedVersionText = (Get-Content -LiteralPath $installedVersionPath `
            -Raw -Encoding UTF8).Trim()
        if ($installedVersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
            throw '已安装 VERSION.txt 无法识别；拒绝覆盖，请先核查 release-metadata。'
        }
        if (Test-Path -LiteralPath $installedExecutablePath -PathType Leaf) {
            foreach ($requiredInstalledMetadata in @(
                'release-manifest.json', 'build-metadata.json', 'SHA256SUMS.txt'
            )) {
                if (-not (Test-Path -LiteralPath (
                        Join-Path $installedMetadataRoot $requiredInstalledMetadata
                    ) -PathType Leaf)) {
                    throw "已安装编译运行时缺少 $requiredInstalledMetadata；拒绝覆盖。"
                }
            }
            $installedVersionOutput = & $installedExecutablePath '--version'
            if ($LASTEXITCODE -ne 0 -or
                ([string]($installedVersionOutput | Out-String)) -notmatch (
                    '(?<![0-9.])' + [regex]::Escape($installedVersionText) + '(?![0-9.])'
                )) {
                throw '已安装运行时版本与 release-metadata 不一致；拒绝覆盖。'
            }
            try {
                $installedManifest = Get-Content -LiteralPath (
                    Join-Path $installedMetadataRoot 'release-manifest.json'
                ) -Raw -Encoding UTF8 | ConvertFrom-Json
                $installedBuildMetadata = Get-Content -LiteralPath (
                    Join-Path $installedMetadataRoot 'build-metadata.json'
                ) -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                throw "已安装发布元数据无法解析；拒绝覆盖：$($_.Exception.Message)"
            }
            if ([string]$installedManifest.version -ne $installedVersionText -or
                [string]$installedBuildMetadata.version -ne $installedVersionText) {
                throw '已安装 VERSION、发布清单与构建元数据不一致；拒绝覆盖。'
            }
        }
        if ([version]$candidateVersionText -lt [version]$installedVersionText) {
            throw (
                '默认拒绝将 MineGuard Platform 从 {0} 降级到 {1}。' -f `
                    $installedVersionText, $candidateVersionText
            )
        }
    }
} else {
    if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
        $py = Get-Command 'py.exe' -ErrorAction SilentlyContinue
        if ($null -ne $py) {
            $PythonExecutable = $py.Source
            $launcherArguments = @('-3.12')
        } else {
            $pythonCommand = Get-Command 'python.exe' -ErrorAction SilentlyContinue
            if ($null -eq $pythonCommand) {
                throw '找不到 Python。请安装 CPython 3.12 x64，或用 -PythonExecutable 指定 python.exe。'
            }
            $PythonExecutable = $pythonCommand.Source
        }
    } else {
        $PythonExecutable = [System.IO.Path]::GetFullPath($PythonExecutable)
        if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
            throw "Python 可执行文件不存在：$PythonExecutable"
        }
    }

    $probeCode = @'
import json, platform, struct, sys
print(json.dumps({'version': list(sys.version_info[:3]), 'bits': struct.calcsize('P') * 8, 'implementation': platform.python_implementation()}))
'@
    $probeText = & $PythonExecutable @launcherArguments '-c' $probeCode
    if ($LASTEXITCODE -ne 0) { throw '无法执行指定的 Python。' }
    try { $probe = $probeText | ConvertFrom-Json } catch { throw '无法解析 Python 版本信息。' }
    if ([string]$probe.implementation -ne 'CPython' -or [int]$probe.bits -ne 64) {
        throw '需要 64 位 CPython。'
    }
    if ([int]$probe.version[0] -ne 3 -or [int]$probe.version[1] -ne 12) {
        throw '当前 Windows 发布约束只完成 CPython 3.12 x64 验证；请安装 Python 3.12。'
    }

    if (-not [string]::IsNullOrWhiteSpace($Wheelhouse)) {
        $Wheelhouse = Get-LocalAbsolutePath -Value $Wheelhouse -Label '离线 wheelhouse'
        if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
            throw "离线 wheelhouse 不存在：$Wheelhouse"
        }
    }
}

$directories = @(
    $InstallRoot,
    (Join-Path $InstallRoot 'runtime'),
    (Join-Path $InstallRoot 'config'),
    (Join-Path $InstallRoot 'state'),
    (Join-Path $InstallRoot 'backups'),
    (Join-Path $InstallRoot 'logs'),
    (Join-Path $InstallRoot 'service'),
    (Join-Path $InstallRoot 'release-metadata')
)
foreach ($directory in $directories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [void](Get-LocalAbsolutePath -Value $directory -Label '安装目录树' `
        -RequireFixedNtfs)
}

if ($binaryMode) {
    $runtimeTarget = Join-Path $InstallRoot 'runtime'
    $serviceTarget = Join-Path $InstallRoot 'service'
    $metadataTarget = Join-Path $InstallRoot 'release-metadata'
    $serviceSource = $PSScriptRoot
    $service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        throw '切换 Platform 二进制运行时前必须停止 MineGuardPlatform 服务。'
    }
    if ((Test-Path -LiteralPath $runtimeTarget -PathType Container) -and
        (Test-MineGuardPlatformRuntimeProcess -RuntimeRoot $runtimeTarget)) {
        throw '切换 Platform 运行时前必须停止 runtime 目录中的全部前台进程（含旧 Python/venv）。'
    }
    if ($AuditFailAfterRuntimeSwitch -and
        $env:MINEGUARD_RELEASE_AUDIT_MODE -ne 'installer-rollback-test') {
        throw 'AuditFailAfterRuntimeSwitch 仅允许发布流水线回滚测试使用。'
    }
    $runtimeIncoming = Join-Path $InstallRoot (
        '.runtime.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $runtimePrevious = Join-Path $InstallRoot (
        '.runtime.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $serviceIncoming = Join-Path $InstallRoot (
        '.service.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $servicePrevious = Join-Path $InstallRoot (
        '.service.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $metadataIncoming = Join-Path $InstallRoot (
        '.release-metadata.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $metadataPrevious = Join-Path $InstallRoot (
        '.release-metadata.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $runtimePreviousMoved = $false
    $servicePreviousMoved = $false
    $metadataPreviousMoved = $false
    $runtimeActivated = $false
    $serviceActivated = $false
    $metadataActivated = $false
    $transactionComplete = $false
    $settingsCreated = $false
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    try {
        New-Item -ItemType Directory -Path $runtimeIncoming | Out-Null
        New-Item -ItemType Directory -Path $serviceIncoming | Out-Null
        New-Item -ItemType Directory -Path $metadataIncoming | Out-Null
        foreach ($item in Get-ChildItem `
            -LiteralPath (Join-Path $SourceDirectory 'runtime') -Force) {
            Copy-Item -LiteralPath $item.FullName -Destination $runtimeIncoming `
                -Recurse -Force
        }
        $incomingExecutable = Join-Path $runtimeIncoming 'MineGuardPlatform.exe'
        Invoke-CheckedNative -Command $incomingExecutable -Arguments @('self-check') `
            -Label '验证待切换冻结运行时'
        foreach ($file in Get-ChildItem -LiteralPath $serviceSource -File) {
            if ($file.Extension -in @('.ps1', '.xml', '.example')) {
                Copy-Item -LiteralPath $file.FullName -Destination $serviceIncoming
            }
        }
        $existingWrapper = Join-Path $serviceTarget 'MineGuard.Platform.exe'
        $existingWrapperConfig = $existingWrapper + '.config'
        $wrapperIntegrityPath = Join-Path $serviceTarget 'winsw-integrity.json'
        if (Test-Path -LiteralPath $existingWrapper -PathType Leaf) {
            if (-not (Test-Path -LiteralPath $wrapperIntegrityPath -PathType Leaf)) {
                throw '已有 WinSW 服务包装器但缺少受保护的 winsw-integrity.json；拒绝在升级中继承。'
            }
            try {
                $wrapperIntegrity = Get-Content -LiteralPath $wrapperIntegrityPath `
                    -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                throw "winsw-integrity.json 无法解析；拒绝继承服务包装器：$($_.Exception.Message)"
            }
            $expectedWrapperHash = [string]$wrapperIntegrity.wrapperSha256
            $actualWrapperHash = (Get-FileHash -LiteralPath $existingWrapper `
                -Algorithm SHA256).Hash
            if ([int]$wrapperIntegrity.schemaVersion -ne 1 -or
                $expectedWrapperHash -notmatch '^[A-Fa-f0-9]{64}$' -or
                $actualWrapperHash -ne $expectedWrapperHash.ToUpperInvariant()) {
                throw '已有 WinSW 服务包装器与批准的 SHA-256 记录不一致；拒绝继承。'
            }
            $expectedConfigHash = [string]$wrapperIntegrity.wrapperConfigSha256
            if ([string]::IsNullOrWhiteSpace($expectedConfigHash)) {
                if (Test-Path -LiteralPath $existingWrapperConfig -PathType Leaf) {
                    throw '发现未登记的 WinSW .config 文件；拒绝在升级中继承。'
                }
            } else {
                if ($expectedConfigHash -notmatch '^[A-Fa-f0-9]{64}$' -or
                    -not (Test-Path -LiteralPath $existingWrapperConfig -PathType Leaf) -or
                    (Get-FileHash -LiteralPath $existingWrapperConfig `
                        -Algorithm SHA256).Hash -ne $expectedConfigHash.ToUpperInvariant()) {
                    throw 'WinSW .config 与批准的 SHA-256 记录不一致；拒绝继承。'
                }
                Copy-Item -LiteralPath $existingWrapperConfig `
                    -Destination $serviceIncoming
            }
            Copy-Item -LiteralPath $existingWrapper -Destination $serviceIncoming
            Copy-Item -LiteralPath $wrapperIntegrityPath -Destination $serviceIncoming
        } elseif ((Test-Path -LiteralPath $wrapperIntegrityPath) -or
            (Test-Path -LiteralPath $existingWrapperConfig)) {
            throw 'WinSW 完整性记录不完整；拒绝在升级中继承服务文件。'
        }
        foreach ($metadataName in @(
            'VERSION.txt', 'build-metadata.json', 'release-manifest.json',
            'SHA256SUMS.txt'
        )) {
            Copy-Item -LiteralPath (Join-Path $SourceDirectory $metadataName) `
                -Destination (Join-Path $metadataIncoming $metadataName)
        }
        foreach ($requiredScript in @(
            'Start-MineGuardPlatform.ps1',
            'Resolve-MineGuardPlatformExecutable.ps1',
            'Install-MineGuardPlatformService.ps1'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $serviceIncoming $requiredScript) `
                    -PathType Leaf)) {
                throw "待切换 service 目录缺少：$requiredScript"
            }
        }
        if ((Get-Item -LiteralPath $runtimeTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 runtime 不能是符号链接、junction 或其他 reparse point。'
        }
        if ((Get-Item -LiteralPath $serviceTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 service 不能是符号链接、junction 或其他 reparse point。'
        }
        if ((Get-Item -LiteralPath $metadataTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 release-metadata 不能是 reparse point。'
        }
        Set-MineGuardDirectoryAcl -Path $runtimeIncoming `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $serviceIncoming `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $metadataIncoming `
            -ServicePermission 'RX' -Recurse

        if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            $settings = [ordered]@{
                schemaVersion = 1
                host = '127.0.0.1'
                port = $Port
                stateDirectory = (Join-Path $InstallRoot 'state')
                clientsFile = ''
                adminUsername = 'admin'
                secureCookie = $true
                allowDemoDefaultPassword = $false
                platformSystemId = 'mineguard-government'
                platformPartyId = 'regulator-government'
                platformKeyId = 'regulator-key-v2'
            }
            [System.IO.File]::WriteAllText(
                $settingsPath,
                ($settings | ConvertTo-Json -Depth 5),
                $utf8NoBom
            )
            $settingsCreated = $true
        }
        Set-MineGuardDirectoryAcl -Path $InstallRoot -ServicePermission 'RX'
        Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'config') `
            -ServicePermission 'RX' -Recurse
        foreach ($writableDirectory in @(
            (Join-Path $InstallRoot 'state'),
            (Join-Path $InstallRoot 'backups'),
            (Join-Path $InstallRoot 'logs')
        )) {
            Set-MineGuardDirectoryAcl -Path $writableDirectory `
                -ServicePermission 'M' -Recurse
        }

        $service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            throw '运行时切换前复检发现 MineGuardPlatform 服务未停止。'
        }
        if (Test-MineGuardPlatformRuntimeProcess -RuntimeRoot $runtimeTarget) {
            throw '运行时切换前复检发现 runtime 目录中仍有前台进程。'
        }
        Move-Item -LiteralPath $runtimeTarget -Destination $runtimePrevious
        $runtimePreviousMoved = $true
        Move-Item -LiteralPath $runtimeIncoming -Destination $runtimeTarget
        $runtimeActivated = $true
        Move-Item -LiteralPath $serviceTarget -Destination $servicePrevious
        $servicePreviousMoved = $true
        Move-Item -LiteralPath $serviceIncoming -Destination $serviceTarget
        $serviceActivated = $true
        Move-Item -LiteralPath $metadataTarget -Destination $metadataPrevious
        $metadataPreviousMoved = $true
        Move-Item -LiteralPath $metadataIncoming -Destination $metadataTarget
        $metadataActivated = $true

        $installedExecutable = Join-Path $runtimeTarget 'MineGuardPlatform.exe'
        Invoke-CheckedNative -Command $installedExecutable -Arguments @('self-check') `
            -Label '验证已安装冻结运行时'
        foreach ($requiredScript in @(
            'Start-MineGuardPlatform.ps1',
            'Resolve-MineGuardPlatformExecutable.ps1',
            'Install-MineGuardPlatformService.ps1'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $serviceTarget $requiredScript) `
                    -PathType Leaf)) {
                throw "切换后的 service 目录缺少：$requiredScript"
            }
        }
        if (-not (Test-Path -LiteralPath (
                Join-Path $metadataTarget 'release-manifest.json'
            ) -PathType Leaf)) {
            throw '切换后的 release-metadata 缺少发布清单。'
        }
        if ($AuditFailAfterRuntimeSwitch) {
            throw '发布审计故障注入：验证二进制切换后的完整回滚。'
        }
        $transactionComplete = $true
    } catch {
        if ($metadataActivated -and (Test-Path -LiteralPath $metadataTarget)) {
            Remove-Item -LiteralPath $metadataTarget -Recurse -Force
            $metadataActivated = $false
        }
        if ($serviceActivated -and (Test-Path -LiteralPath $serviceTarget)) {
            Remove-Item -LiteralPath $serviceTarget -Recurse -Force
            $serviceActivated = $false
        }
        if ($runtimeActivated -and (Test-Path -LiteralPath $runtimeTarget)) {
            Remove-Item -LiteralPath $runtimeTarget -Recurse -Force
            $runtimeActivated = $false
        }
        if ($metadataPreviousMoved -and (Test-Path -LiteralPath $metadataPrevious)) {
            Move-Item -LiteralPath $metadataPrevious -Destination $metadataTarget
            $metadataPreviousMoved = $false
        }
        if ($servicePreviousMoved -and (Test-Path -LiteralPath $servicePrevious)) {
            Move-Item -LiteralPath $servicePrevious -Destination $serviceTarget
            $servicePreviousMoved = $false
        }
        if ($runtimePreviousMoved -and (Test-Path -LiteralPath $runtimePrevious)) {
            Move-Item -LiteralPath $runtimePrevious -Destination $runtimeTarget
            $runtimePreviousMoved = $false
        }
        if ($settingsCreated -and (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            Remove-Item -LiteralPath $settingsPath -Force
            $settingsCreated = $false
        }
        throw
    } finally {
        foreach ($incomingPath in @(
            $runtimeIncoming, $serviceIncoming, $metadataIncoming
        )) {
            if (Test-Path -LiteralPath $incomingPath) {
                Remove-Item -LiteralPath $incomingPath -Recurse -Force
            }
        }
    }
    if (-not $transactionComplete) {
        throw 'Platform 二进制切换未完成。'
    }
    foreach ($oldPath in @(
        $runtimePrevious, $servicePrevious, $metadataPrevious
    )) {
        try {
            Remove-Item -LiteralPath $oldPath -Recurse -Force
        } catch {
            Write-Warning "新版本已完整生效，但旧目录待人工清理：$oldPath"
        }
    }
} else {
    $venvPython = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        Invoke-CheckedNative -Command $PythonExecutable `
            -Arguments ($launcherArguments + @('-m', 'venv', (Join-Path $InstallRoot 'runtime'))) `
            -Label '创建隔离 Python 运行时'
    }
    $constraints = Join-Path $SourceDirectory 'constraints.txt'
    if ([string]::IsNullOrWhiteSpace($Wheelhouse)) {
        Invoke-CheckedNative -Command $venvPython `
            -Arguments @('-m', 'pip', 'install', 'setuptools>=68') `
            -Label '安装构建工具'
        Invoke-CheckedNative -Command $venvPython `
            -Arguments @('-m', 'pip', 'install', '-c', $constraints, $SourceDirectory) `
            -Label '安装 MineGuard Platform'
    } else {
        $offline = @('--no-index', '--find-links', $Wheelhouse)
        Invoke-CheckedNative -Command $venvPython `
            -Arguments (@('-m', 'pip', 'install') + $offline + @('setuptools>=68')) `
            -Label '从 wheelhouse 安装构建工具'
        Invoke-CheckedNative -Command $venvPython `
            -Arguments (@('-m', 'pip', 'install') + $offline + @(
                '--no-build-isolation', '-c', $constraints, $SourceDirectory
            )) `
            -Label '从 wheelhouse 安装 MineGuard Platform'
    }
    $verifyCode = @'
from importlib.metadata import version
from zoneinfo import ZoneInfo
import mineguard, numpy, scipy
assert ZoneInfo("Asia/Shanghai").key == "Asia/Shanghai"
print("MineGuard", mineguard.__version__, "numpy", numpy.__version__, "scipy", scipy.__version__, "tzdata", version("tzdata"))
'@
    Invoke-CheckedNative -Command $venvPython -Arguments @('-c', $verifyCode) `
        -Label '验证算法和 Windows 时区运行时'
}

$serviceTarget = Join-Path $InstallRoot 'service'
if (-not $binaryMode) {
    $serviceSource = $PSScriptRoot
    foreach ($file in Get-ChildItem -LiteralPath $serviceSource -File) {
        if ($file.Extension -in @('.ps1', '.xml', '.example')) {
            Copy-Item -LiteralPath $file.FullName -Destination $serviceTarget -Force
        }
    }
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        $settings = [ordered]@{
            schemaVersion = 1
            host = '127.0.0.1'
            port = $Port
            stateDirectory = (Join-Path $InstallRoot 'state')
            clientsFile = ''
            adminUsername = 'admin'
            secureCookie = $true
            allowDemoDefaultPassword = $false
            platformSystemId = 'mineguard-government'
            platformPartyId = 'regulator-government'
            platformKeyId = 'regulator-key-v2'
        }
        [System.IO.File]::WriteAllText(
            $settingsPath,
            ($settings | ConvertTo-Json -Depth 5),
            $utf8NoBom
        )
    }

    Set-MineGuardDirectoryAcl -Path $InstallRoot `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'runtime') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'config') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'service') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'release-metadata') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'state') `
        -ServicePermission 'M' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'backups') `
        -ServicePermission 'M' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'logs') `
        -ServicePermission 'M' -Recurse
}

Write-Host ''
Write-Host 'MineGuard Platform Windows 运行时安装完成。'
Write-Host "安装目录：$InstallRoot"
Write-Host '下一步（不会在命令行记录秘密）：'
Write-Host ("  & '{0}' -InstallRoot '{1}' -ClientsFile 'C:\安全交付\clients.json'" -f `
    (Join-Path $serviceTarget 'Set-MineGuardPlatformConfiguration.ps1'), $InstallRoot)
