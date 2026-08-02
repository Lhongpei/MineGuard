[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [string] $SourceDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $PythonExecutable,
    [string] $ExpectedPythonPatchVersion,
    [string] $ExpectedPythonExecutableSha256,
    [string] $Wheelhouse,
    [switch] $AllowNuitkaToolDownloads,
    [string] $SignToolPath,
    [string] $ExpectedSignToolSha256,
    [string] $SigningCertificateThumbprint,
    [uri] $TimestampUrl,
    [switch] $RequireSignedBinary,
    [switch] $AllowDirtySource,
    [switch] $Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Get-LocalAbsolutePath {
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -ne $Value.Trim() -or
        $Value -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Label 必须是形如 C:\\path 的本机完全限定绝对路径。"
    }
    foreach ($segment in $Value.Substring(3).Split(@('\', '/'))) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -in @('.', '..') -or $segment.Contains(':') -or
            $segment.EndsWith(' ') -or $segment.EndsWith('.')) {
            throw "$Label 含空、点、备用数据流或歧义路径片段。"
        }
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ($fullPath.StartsWith('\\')) { throw "$Label 不能使用 UNC/SMB 网络路径。" }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or
        -not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS') {
        throw "$Label 必须位于已就绪的本机固定 NTFS 磁盘。"
    }
    $currentPath = $root
    foreach ($segment in $fullPath.Substring($root.Length).Split(
        @('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries
    )) {
        $currentPath = Join-Path $currentPath $segment
        if (-not (Test-Path -LiteralPath $currentPath)) { break }
        $item = Get-Item -LiteralPath $currentPath -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label 不能位于 reparse point（符号链接、junction 或挂载点）之下：$currentPath"
        }
    }
    return $fullPath
}

function Assert-NoReparseTree {
    param([string] $Path, [string] $Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($item in @((Get-Item -LiteralPath $Path -Force)) + @(
        Get-ChildItem -LiteralPath $Path -Force -Recurse
    )) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label 不能包含符号链接、junction 或挂载点：$($item.FullName)"
        }
    }
}

function Test-ReleaseDirectoryIntegrity {
    param([Parameter(Mandatory = $true)] [string] $ReleaseDirectory)

    $reparsePoints = @(Get-ChildItem -LiteralPath $ReleaseDirectory -Recurse -Force |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        })
    if ($reparsePoints.Count -gt 0) {
        throw '发布目录自验发现 reparse point；拒绝发布可能越界的目录树。'
    }
    $manifestPath = Join-Path $ReleaseDirectory 'release-manifest.json'
    $checksumsPath = Join-Path $ReleaseDirectory 'SHA256SUMS.txt'
    foreach ($requiredPath in @($manifestPath, $checksumsPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "发布目录自验缺少文件：$requiredPath"
        }
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw '发布目录自验无法解析 release-manifest.json。'
    }
    if ([string]$manifest.entryPoint -ne 'runtime/MineGuardPlatform.exe' -or
        [string]$manifest.runtime -ne 'nuitka-standalone') {
        throw '发布目录自验发现清单入口或运行时类型不正确。'
    }

    $manifestExpected = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($relative) -or
            $relative.StartsWith('/') -or $relative.StartsWith('\\') -or
            $relative -match '(^|/)\.\.(/|$)' -or $relative.Contains('\\') -or
            $manifestExpected.ContainsKey($relative)) {
            throw "发布目录自验发现不安全或重复的清单路径：$relative"
        }
        $manifestExpected[$relative] = $entry
    }
    $manifestActual = @(Get-ChildItem -LiteralPath $ReleaseDirectory -Recurse -File |
        Where-Object { $_.Name -notin @('release-manifest.json', 'SHA256SUMS.txt') })
    if ($manifestExpected.Count -ne $manifestActual.Count) {
        throw '发布目录自验发现 release-manifest.json 文件覆盖范围不完整。'
    }
    foreach ($file in $manifestActual) {
        $relative = $file.FullName.Substring($ReleaseDirectory.Length).TrimStart('\')
        $relative = $relative.Replace('\', '/')
        if (-not $manifestExpected.ContainsKey($relative)) {
            throw "发布目录自验发现清单外文件：$relative"
        }
        $entry = $manifestExpected[$relative]
        $actualHash = (Get-FileHash -LiteralPath $file.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([long]$entry.bytes -ne [long]$file.Length -or
            [string]$entry.sha256 -ne $actualHash) {
            throw "发布目录自验发现清单摘要不匹配：$relative"
        }
    }

    $checksumExpected = @{}
    foreach ($line in Get-Content -LiteralPath $checksumsPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $checksumMatch = [regex]::Match(
            $line, '^(?<hash>[A-Fa-f0-9]{64})  (?<path>.+)$'
        )
        if (-not $checksumMatch.Success) {
            throw '发布目录自验发现 SHA256SUMS.txt 格式不正确。'
        }
        $relative = [string]$checksumMatch.Groups['path'].Value
        if ($relative.StartsWith('/') -or $relative.StartsWith('\\') -or
            $relative -match '(^|/)\.\.(/|$)' -or $relative.Contains('\\') -or
            $checksumExpected.ContainsKey($relative)) {
            throw "发布目录自验发现不安全或重复的摘要路径：$relative"
        }
        $checksumExpected[$relative] = [string](
            $checksumMatch.Groups['hash'].Value.ToLowerInvariant()
        )
    }
    $checksumActual = @(Get-ChildItem -LiteralPath $ReleaseDirectory -Recurse -File |
        Where-Object { $_.Name -ne 'SHA256SUMS.txt' })
    if ($checksumExpected.Count -ne $checksumActual.Count) {
        throw '发布目录自验发现 SHA256SUMS.txt 文件覆盖范围不完整。'
    }
    foreach ($file in $checksumActual) {
        $relative = $file.FullName.Substring($ReleaseDirectory.Length).TrimStart('\')
        $relative = $relative.Replace('\', '/')
        if (-not $checksumExpected.ContainsKey($relative)) {
            throw "发布目录自验发现摘要清单外文件：$relative"
        }
        $actualHash = (Get-FileHash -LiteralPath $file.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($checksumExpected[$relative] -ne $actualHash) {
            throw "发布目录自验发现 SHA-256 不匹配：$relative"
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

if ($env:OS -ne 'Windows_NT') {
    throw 'MineGuard Platform 的 Windows EXE 必须在 64 位 Windows 上构建。'
}
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$SourceDirectory = Get-LocalAbsolutePath -Value $SourceDirectory -Label 'Platform 源目录'
$OutputDirectory = Get-LocalAbsolutePath -Value $OutputDirectory -Label '交付输出目录'
Assert-NoReparseTree -Path $SourceDirectory -Label 'Platform 源目录'
$projectFile = Join-Path $SourceDirectory 'pyproject.toml'
$constraintsFile = Join-Path $SourceDirectory 'constraints.txt'
$entryPoint = Join-Path $PSScriptRoot 'MineGuardPlatform.py'
$buildRequirements = Join-Path $PSScriptRoot 'requirements-build.txt'
foreach ($requiredFile in @(
    $projectFile, $constraintsFile, $entryPoint, $buildRequirements,
    (Join-Path $SourceDirectory 'src\mineguard\regulatory_web\index.html'),
    (Join-Path $SourceDirectory 'src\mineguard\web\index.html')
)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "构建输入不完整：$requiredFile"
    }
}
if (Test-Path -LiteralPath $OutputDirectory) {
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        throw '交付输出路径已经存在且不是目录。'
    }
} else {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}
$OutputDirectory = Get-LocalAbsolutePath -Value $OutputDirectory -Label '交付输出目录'

$launcherArguments = @()
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $py = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        $PythonExecutable = $py.Source
        $launcherArguments = @('-3.12')
    } else {
        $pythonCommand = Get-Command 'python.exe' -ErrorAction SilentlyContinue
        if ($null -eq $pythonCommand) {
            throw '找不到 Python。请安装 CPython 3.12 x64。'
        }
        $PythonExecutable = $pythonCommand.Source
    }
}
$PythonExecutable = Get-LocalAbsolutePath `
    -Value $PythonExecutable -Label 'Python 可执行文件'
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Python 可执行文件不存在：$PythonExecutable"
}
if ($ExpectedPythonExecutableSha256) {
    if ($ExpectedPythonExecutableSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'ExpectedPythonExecutableSha256 必须是 64 位十六进制散列。'
    }
    $actualPythonSha256 = (Get-FileHash -LiteralPath $PythonExecutable `
        -Algorithm SHA256).Hash
    if ($actualPythonSha256 -ne $ExpectedPythonExecutableSha256) {
        throw 'Python 可执行文件与根构建传入的预期 SHA-256 不一致。'
    }
}
$ExpectedPythonPatchVersion = ([string]$ExpectedPythonPatchVersion).Trim()
if ($ExpectedPythonPatchVersion -and
    $ExpectedPythonPatchVersion -notmatch '^3\.12\.\d+$') {
    throw 'ExpectedPythonPatchVersion 必须是精确 CPython 3.12 patch。'
}
if ($RequireSignedBinary -and
    (-not $ExpectedPythonPatchVersion -or -not $ExpectedPythonExecutableSha256)) {
    throw '正式签名子构建必须接收已核验 Python patch 和可执行文件 SHA-256。'
}
$probeCode = @'
import json, platform, struct, sys
print(json.dumps({'version': list(sys.version_info[:3]), 'bits': struct.calcsize('P') * 8, 'implementation': platform.python_implementation()}))
'@
$probeText = & $PythonExecutable @launcherArguments '-c' $probeCode
if ($LASTEXITCODE -ne 0) { throw '无法执行指定的 Python。' }
try { $probe = $probeText | ConvertFrom-Json } catch { throw '无法解析 Python 版本信息。' }
if ([string]$probe.implementation -ne 'CPython' -or [int]$probe.bits -ne 64 -or
    [int]$probe.version[0] -ne 3 -or [int]$probe.version[1] -ne 12) {
    throw '发布构建只允许 64 位 CPython 3.12。'
}
$actualPythonPatchVersion = ('{0}.{1}.{2}' -f
    $probe.version[0], $probe.version[1], $probe.version[2])
if ($ExpectedPythonPatchVersion -and
    $actualPythonPatchVersion -ne $ExpectedPythonPatchVersion) {
    throw 'Python patch 与根构建传入的精确版本不一致。'
}

if (-not [string]::IsNullOrWhiteSpace($Wheelhouse)) {
    $Wheelhouse = Get-LocalAbsolutePath -Value $Wheelhouse -Label '离线 wheelhouse'
    if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
        throw "离线 wheelhouse 不存在：$Wheelhouse"
    }
    Assert-NoReparseTree -Path $Wheelhouse -Label '离线 wheelhouse'
}
$hasSignTool = -not [string]::IsNullOrWhiteSpace($SignToolPath)
$hasThumbprint = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
$hasTimestamp = $null -ne $TimestampUrl
$signingValueCount = @($hasSignTool, $hasThumbprint, $hasTimestamp) |
    Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($signingValueCount -notin @(0, 3)) {
    throw 'SignToolPath、SigningCertificateThumbprint 和 TimestampUrl 必须同时提供。'
}
$signingEnabled = $signingValueCount -eq 3
if ($signingEnabled -and -not $RequireSignedBinary) {
    throw '提供签名参数时必须同时使用 -RequireSignedBinary，禁止绕过正式发布门禁。'
}
if ($RequireSignedBinary -and -not $signingEnabled) {
    throw 'RequireSignedBinary 要求同时提供签名工具、证书指纹和可信时间戳 URL。'
}
if ($RequireSignedBinary -and $AllowNuitkaToolDownloads) {
    throw '正式签名构建禁止下载 Nuitka 工具；必须预置并审批构建缓存。'
}
if ($RequireSignedBinary -and [string]::IsNullOrWhiteSpace($Wheelhouse)) {
    throw '正式签名构建必须使用已审批的离线 wheelhouse。'
}
if ($RequireSignedBinary -and [string]::IsNullOrWhiteSpace($ExpectedSignToolSha256)) {
    throw '正式签名子构建必须接收 SignTool 的预期 SHA-256。'
}
if ($signingEnabled) {
    $SignToolPath = Get-LocalAbsolutePath -Value $SignToolPath -Label 'SignTool'
    if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
        throw "SignTool 不存在：$SignToolPath"
    }
    $actualSignToolSha256 = (Get-FileHash -LiteralPath $SignToolPath `
        -Algorithm SHA256).Hash
    if ($ExpectedSignToolSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $actualSignToolSha256 -ne $ExpectedSignToolSha256) {
        throw 'SignTool 与根构建传入的预期 SHA-256 不一致。'
    }
    if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw '代码签名证书指纹必须是 40 位十六进制 SHA-1 thumbprint。'
    }
    $SigningCertificateThumbprint = $SigningCertificateThumbprint.ToUpperInvariant()
    $signingHelper = Join-Path (
        [System.IO.Path]::GetFullPath((Join-Path $SourceDirectory '..'))
    ) 'scripts\Invoke-WindowsAuthenticodeSign.ps1'
    if (-not (Test-Path -LiteralPath $signingHelper -PathType Leaf)) {
        throw "找不到统一 Authenticode 签名助手：$signingHelper"
    }
}

$sourceRevision = 'unknown'
$sourceTreeDirty = $null
$gitCommand = Get-Command 'git.exe' -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) {
    $gitCommand = Get-Command 'git' -ErrorAction SilentlyContinue
}
if ($null -ne $gitCommand) {
    $revisionText = & $gitCommand.Source '-C' $SourceDirectory `
        'rev-parse' '--verify' 'HEAD' 2>$null
    if ($LASTEXITCODE -eq 0 -and
        [string]($revisionText | Select-Object -First 1) -match '^[A-Fa-f0-9]{40,64}$') {
        $sourceRevision = [string]($revisionText | Select-Object -First 1)
        $statusText = & $gitCommand.Source '-C' $SourceDirectory `
            'status' '--porcelain' '--untracked-files=normal'
        if ($LASTEXITCODE -ne 0) { throw '无法读取 Git 工作树状态。' }
        $sourceTreeDirty = -not [string]::IsNullOrWhiteSpace(
            [string]($statusText | Out-String)
        )
        if ($sourceTreeDirty -and -not $AllowDirtySource) {
            throw '源码工作树存在未提交改动；正式发布拒绝构建。调试可显式使用 -AllowDirtySource。'
        }
    }
}
if ($RequireSignedBinary -and
    ($sourceRevision -eq 'unknown' -or $sourceTreeDirty -ne $false)) {
    throw '正式签名构建必须来自可识别且干净的 Git revision。'
}

$projectText = Get-Content -LiteralPath $projectFile -Raw -Encoding UTF8
$versionMatch = [regex]::Match(
    $projectText,
    '(?m)^version\s*=\s*"(?<version>[0-9]+\.[0-9]+\.[0-9]+)"\s*$'
)
if (-not $versionMatch.Success) { throw '无法从 pyproject.toml 读取三段式版本号。' }
$productVersion = $versionMatch.Groups['version'].Value
$windowsVersion = $productVersion + '.0'
$releaseName = 'MineGuardPlatform-{0}-windows-x64' -f $productVersion
$releaseDirectory = Get-LocalAbsolutePath `
    -Value (Join-Path $OutputDirectory $releaseName) -Label 'Platform 最终交付目录'
$publishToken = [Guid]::NewGuid().ToString('N')
$publishIncoming = Get-LocalAbsolutePath `
    -Value (Join-Path $OutputDirectory ('.{0}.incoming.{1}' -f $releaseName, $publishToken)) `
    -Label 'Platform 同级发布暂存目录'
$publishPrevious = Get-LocalAbsolutePath `
    -Value (Join-Path $OutputDirectory ('.{0}.previous.{1}' -f $releaseName, $publishToken)) `
    -Label 'Platform 旧版本备份目录'
if ((Test-Path -LiteralPath $releaseDirectory) -and
    -not (Test-Path -LiteralPath $releaseDirectory -PathType Container)) {
    throw 'Platform 最终交付路径已经存在且不是目录。'
}
if ((Test-Path -LiteralPath $releaseDirectory -PathType Container) -and
    -not $Force) {
    throw 'Platform 最终交付目录已经存在；拒绝隐式覆盖。确需替换同版本构建时显式使用 -Force。'
}
foreach ($reservedPath in @($publishIncoming, $publishPrevious)) {
    if (Test-Path -LiteralPath $reservedPath) {
        throw "随机发布事务路径已存在，拒绝覆盖：$reservedPath"
    }
}

$stageRoot = Get-LocalAbsolutePath -Value (
    Join-Path ([System.IO.Path]::GetTempPath()) (
        'mineguard-platform-build-' + [Guid]::NewGuid().ToString('N')
    )
) -Label 'Platform 一次性构建目录'
New-Item -ItemType Directory -Path $stageRoot | Out-Null
try {
    $buildEnvironment = Join-Path $stageRoot 'build-env'
    if ($ExpectedPythonExecutableSha256) {
        $criticalPythonSha256 = (Get-FileHash -LiteralPath $PythonExecutable `
            -Algorithm SHA256).Hash
        if ($criticalPythonSha256 -ne $ExpectedPythonExecutableSha256) {
            throw 'Python 可执行文件在创建构建环境前发生变化。'
        }
    }
    Invoke-CheckedNative -Command $PythonExecutable `
        -Arguments ($launcherArguments + @('-m', 'venv', $buildEnvironment)) `
        -Label '创建一次性构建环境'
    $buildPython = Join-Path $buildEnvironment 'Scripts\python.exe'
    if ([string]::IsNullOrWhiteSpace($Wheelhouse)) {
        Invoke-CheckedNative -Command $buildPython -Arguments @(
            '-m', 'pip', 'install', '-r', $buildRequirements
        ) -Label '安装锁定的 Nuitka 构建工具'
        Invoke-CheckedNative -Command $buildPython -Arguments @(
            '-m', 'pip', 'install', '--no-build-isolation',
            '-c', $constraintsFile, $SourceDirectory
        ) -Label '安装锁定的 Platform 构建输入'
    } else {
        $offline = @('--no-index', '--find-links', $Wheelhouse)
        Invoke-CheckedNative -Command $buildPython -Arguments (
            @('-m', 'pip', 'install') + $offline + @('-r', $buildRequirements)
        ) -Label '从 wheelhouse 安装 Nuitka 构建工具'
        Invoke-CheckedNative -Command $buildPython -Arguments (
            @('-m', 'pip', 'install') + $offline + @(
                '--no-build-isolation', '-c', $constraintsFile, $SourceDirectory
            )
        ) -Label '从 wheelhouse 安装 Platform 构建输入'
    }

    $compileRoot = Join-Path $stageRoot 'compiled'
    New-Item -ItemType Directory -Path $compileRoot | Out-Null
    $nuitkaArguments = @(
        '-m', 'nuitka',
        '--mode=standalone',
        '--deployment',
        '--msvc=latest',
        '--output-dir=' + $compileRoot,
        '--output-filename=MineGuardPlatform.exe',
        '--windows-console-mode=force',
        '--company-name=MineGuard',
        '--product-name=MineGuard Platform',
        '--file-description=MineGuard Government Regulatory Platform',
        '--file-version=' + $windowsVersion,
        '--product-version=' + $windowsVersion,
        '--include-data-dir=' + (Join-Path $SourceDirectory 'src\mineguard\regulatory_web') + '=mineguard/regulatory_web',
        '--include-data-dir=' + (Join-Path $SourceDirectory 'src\mineguard\web') + '=mineguard/web',
        '--include-package=tzdata',
        '--include-package-data=tzdata',
        '--include-distribution-metadata=numpy',
        '--include-distribution-metadata=scipy',
        '--include-distribution-metadata=pydantic',
        '--include-distribution-metadata=PyYAML',
        '--include-distribution-metadata=tzdata',
        '--include-distribution-metadata=olefile',
        '--include-distribution-metadata=xlrd',
        '--remove-output'
    )
    if ($AllowNuitkaToolDownloads) {
        $nuitkaArguments += '--assume-yes-for-downloads'
    }
    $nuitkaArguments += $entryPoint
    Invoke-CheckedNative -Command $buildPython -Arguments $nuitkaArguments `
        -Label 'Nuitka standalone 编译'

    $compiledDirectory = Join-Path $compileRoot 'MineGuardPlatform.dist'
    $compiledExecutable = Join-Path $compiledDirectory 'MineGuardPlatform.exe'
    if (-not (Test-Path -LiteralPath $compiledExecutable -PathType Leaf)) {
        throw "Nuitka 未生成预期程序：$compiledExecutable"
    }
    $codeSigned = $false
    if ($signingEnabled) {
        $criticalSignToolSha256 = (Get-FileHash -LiteralPath $SignToolPath `
            -Algorithm SHA256).Hash
        if ($criticalSignToolSha256 -ne $ExpectedSignToolSha256) {
            throw 'SignTool 在关键签名操作前发生变化。'
        }
        & $signingHelper -Files @($compiledExecutable) `
            -SignToolPath $SignToolPath `
            -CertificateThumbprint $SigningCertificateThumbprint `
            -TimestampUrl $TimestampUrl
        $codeSigned = $true
    }
    if ($RequireSignedBinary -and -not $codeSigned) {
        throw 'Platform 主程序未通过 Authenticode 签名验证。'
    }
    if (-not $codeSigned) {
        Write-Warning '正在生成未签名内部测试版；该产物不是生产可信发布。'
    }
    $versionText = & $compiledExecutable '--version'
    if ($LASTEXITCODE -ne 0 -or $versionText -notmatch [regex]::Escape($productVersion)) {
        throw '冻结 EXE 版本检查失败。'
    }
    $selfCheckText = & $compiledExecutable 'self-check'
    if ($LASTEXITCODE -ne 0) { throw '冻结 EXE 完整自检失败。' }
    $selfCheck = $selfCheckText | Out-String | ConvertFrom-Json
    if ([string]$selfCheck.status -ne 'ok' -or
        [string]$selfCheck.timezone -ne 'Asia/Shanghai' -or
        [string]$selfCheck.solver -ne 'scipy.optimize.linprog/highs') {
        throw '冻结 EXE 自检结果缺少时区或 HiGHS 求解器。'
    }
    foreach ($asset in @(
        'regulatory_web/index.html', 'regulatory_web/app.js',
        'web/index.html', 'web/app.js'
    )) {
        if ($null -eq $selfCheck.assets.PSObject.Properties[$asset]) {
            throw "冻结 EXE 自检缺少前端资源：$asset"
        }
    }
    $sourceLeaks = @(Get-ChildItem -LiteralPath $compiledDirectory -Recurse -File |
        Where-Object {
            $relative = $_.FullName.Substring($compiledDirectory.Length).Replace('\', '/')
            $_.Extension.ToLowerInvariant() -in @(
                '.py', '.pyc', '.pyo', '.pyi', '.c', '.cc', '.cpp', '.cxx',
                '.h', '.hh', '.hpp', '.hxx', '.pxd', '.pxi', '.ipynb',
                '.f', '.f90', '.rs', '.pdb'
            ) -or
            ('/' + $relative + '/') -match '(?i)/(tests?|\.git)/' -or
            $_.Name -match '(?i)(^|[._-])(\.env|secret|private[-_]?key|api[-_]?key)([._-]|$)' -or
            $_.Name -match '(?i)^(pyproject\.toml|setup\.cfg|tox\.ini|requirements[^\\/]*\.txt)$'
        })
    if ($sourceLeaks.Count -gt 0) {
        throw 'standalone 目录出现源码、调试符号、测试或疑似秘密文件；拒绝生成交付物。'
    }

    $destinationDirectory = Join-Path $publishIncoming 'runtime'
    $deployDirectory = Join-Path $publishIncoming 'deploy\windows'
    New-Item -ItemType Directory -Path $publishIncoming | Out-Null
    New-Item -ItemType Directory -Path $destinationDirectory | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $compiledDirectory -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $destinationDirectory `
            -Recurse -Force
    }
    New-Item -ItemType Directory -Path $deployDirectory -Force | Out-Null
    foreach ($item in Get-ChildItem `
        -LiteralPath (Join-Path $SourceDirectory 'deploy\windows') -File) {
        Copy-Item -LiteralPath $item.FullName -Destination $deployDirectory -Force
    }

    $nuitkaVersionText = & $buildPython '-m' 'nuitka' '--version'
    if ($LASTEXITCODE -ne 0) { throw '无法读取 Nuitka 构建版本。' }
    $nuitkaVersion = [string]($nuitkaVersionText | Select-Object -First 1)
    [System.IO.File]::WriteAllText(
        (Join-Path $publishIncoming 'VERSION.txt'),
        ($productVersion + "`n"),
        $utf8NoBom
    )
    $buildMetadata = [ordered]@{
        schemaVersion = 1
        product = 'MineGuard Platform'
        version = $productVersion
        architecture = 'x64'
        operatingSystem = 'Windows'
        python = ('{0}.{1}.{2}' -f $probe.version[0], $probe.version[1], $probe.version[2])
        nuitka = $nuitkaVersion
        sourceRevision = $sourceRevision
        sourceTreeDirty = $sourceTreeDirty
        builtUtc = [DateTime]::UtcNow.ToString('o')
        codeSigned = $codeSigned
        authenticodeVerified = $codeSigned
        signingCertificateThumbprint = $(
            if ($codeSigned) { $SigningCertificateThumbprint } else { $null }
        )
        dependencies = $selfCheck.runtime.dependencies
        constraintsSha256 = (Get-FileHash -LiteralPath $constraintsFile `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        buildRequirementsSha256 = (Get-FileHash -LiteralPath $buildRequirements `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $publishIncoming 'build-metadata.json'),
        ($buildMetadata | ConvertTo-Json -Depth 10),
        $utf8NoBom
    )

    $manifestFiles = @()
    foreach ($file in Get-ChildItem -LiteralPath $publishIncoming -Recurse -File |
        Sort-Object FullName) {
        $relative = $file.FullName.Substring($publishIncoming.Length).TrimStart('\')
        $relative = $relative.Replace('\', '/')
        $manifestFiles += [ordered]@{
            path = $relative
            bytes = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        product = 'MineGuard Platform'
        version = $productVersion
        architecture = 'x64'
        runtime = 'nuitka-standalone'
        entryPoint = 'runtime/MineGuardPlatform.exe'
        operations = 'deploy/windows'
        codeSigned = $codeSigned
        authenticodeVerified = $codeSigned
        files = $manifestFiles
        selfCheck = $selfCheck
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $publishIncoming 'release-manifest.json'),
        ($manifest | ConvertTo-Json -Depth 20),
        $utf8NoBom
    )
    $hashLines = @()
    foreach ($file in Get-ChildItem -LiteralPath $publishIncoming -Recurse -File |
        Sort-Object FullName) {
        $relative = $file.FullName.Substring($publishIncoming.Length).TrimStart('\')
        $relative = $relative.Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $hashLines += ('{0}  {1}' -f $hash, $relative)
    }
    [System.IO.File]::WriteAllLines(
        (Join-Path $publishIncoming 'SHA256SUMS.txt'),
        $hashLines,
        $utf8NoBom
    )
    Test-ReleaseDirectoryIntegrity -ReleaseDirectory $publishIncoming

    # Both directories are direct children of OutputDirectory, so Directory.Move is
    # a same-volume rename.  The final path never contains a partially copied build.
    $previousMoved = $false
    try {
        $OutputDirectory = Get-LocalAbsolutePath `
            -Value $OutputDirectory -Label '发布时交付输出目录'
        $publishIncoming = Get-LocalAbsolutePath `
            -Value $publishIncoming -Label '发布时同级暂存目录'
        $releaseDirectory = Get-LocalAbsolutePath `
            -Value $releaseDirectory -Label '发布时 Platform 最终交付目录'
        if (Test-Path -LiteralPath $releaseDirectory) {
            if (-not (Test-Path -LiteralPath $releaseDirectory -PathType Container)) {
                throw 'Platform 最终交付路径已经存在且不是目录。'
            }
            [System.IO.Directory]::Move($releaseDirectory, $publishPrevious)
            $previousMoved = $true
        }
        [System.IO.Directory]::Move($publishIncoming, $releaseDirectory)
    } catch {
        $publishFailure = $_
        if ($previousMoved -and
            (Test-Path -LiteralPath $publishPrevious -PathType Container)) {
            try {
                if (Test-Path -LiteralPath $releaseDirectory) {
                    $failedPath = Join-Path $OutputDirectory (
                        '.{0}.failed.{1}' -f $releaseName, [Guid]::NewGuid().ToString('N')
                    )
                    if (Test-Path -LiteralPath $releaseDirectory -PathType Container) {
                        [System.IO.Directory]::Move($releaseDirectory, $failedPath)
                    } else {
                        [System.IO.File]::Move($releaseDirectory, $failedPath)
                    }
                    Write-Warning "发布失败时目标路径被占用；占用目录已保留在 $failedPath。"
                }
                [System.IO.Directory]::Move($publishPrevious, $releaseDirectory)
            } catch {
                throw "发布新目录失败，且旧版本自动恢复失败。旧版本保留在 $publishPrevious。原始错误：$publishFailure；恢复错误：$_"
            }
        }
        throw $publishFailure
    }
    if ($previousMoved -and (Test-Path -LiteralPath $publishPrevious)) {
        try {
            Remove-Item -LiteralPath $publishPrevious -Recurse -Force
        } catch {
            Write-Warning "新版本已原子发布，但旧版本备份清理失败：$publishPrevious。$_"
        }
    }
} finally {
    if (Test-Path -LiteralPath $stageRoot) {
        try {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force
        } catch {
            Write-Warning "一次性构建目录清理失败：$stageRoot。$_"
        }
    }
    if (Test-Path -LiteralPath $publishIncoming) {
        try {
            Remove-Item -LiteralPath $publishIncoming -Recurse -Force
        } catch {
            Write-Warning "未发布暂存目录清理失败：$publishIncoming。$_"
        }
    }
}

Write-Host 'MineGuard Platform standalone 构建完成。'
Write-Host ("交付目录：{0}" -f (Join-Path $OutputDirectory (
    'MineGuardPlatform-{0}-windows-x64' -f $productVersion
)))
Write-Host ("主程序：{0}" -f (
    Join-Path $OutputDirectory (
        'MineGuardPlatform-{0}-windows-x64\runtime\MineGuardPlatform.exe' -f `
            $productVersion
    )
))
