[CmdletBinding()]
param(
    [string] $SourceDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
    [string] $PythonExecutable,
    [string] $Wheelhouse,
    [ValidateRange(1, 65535)] [int] $Port = 8080
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
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or
        -not [System.IO.Path]::IsPathRooted($Value)) {
        throw "$Label 必须是本机绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ($fullPath.StartsWith('\\')) { throw "$Label 不能使用 UNC/SMB 网络路径。" }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    return $fullPath
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
    param([string] $Path, [string] $ServicePermission)
    $serviceGrant = ('*{0}:(OI)(CI){1}' -f $ServiceSid, $ServicePermission)
    & "$env:SystemRoot\System32\icacls.exe" $Path '/inheritance:r' `
        '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        $serviceGrant '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "设置 NTFS ACL 失败：$Path" }
}

Assert-Administrator
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$SourceDirectory = [System.IO.Path]::GetFullPath($SourceDirectory)
$InstallRoot = Get-LocalAbsolutePath -Value $InstallRoot -Label '安装目录'
if (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory 'pyproject.toml') -PathType Leaf)) {
    throw "源目录不是 platform 发布目录：$SourceDirectory"
}
if ($InstallRoot.StartsWith($SourceDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw '安装目录不能位于源码目录内部。'
}

$launcherArguments = @()
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
print(json.dumps({"version": list(sys.version_info[:3]), "bits": struct.calcsize("P") * 8, "implementation": platform.python_implementation()}))
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

$directories = @(
    $InstallRoot,
    (Join-Path $InstallRoot 'runtime'),
    (Join-Path $InstallRoot 'config'),
    (Join-Path $InstallRoot 'state'),
    (Join-Path $InstallRoot 'backups'),
    (Join-Path $InstallRoot 'logs'),
    (Join-Path $InstallRoot 'service')
)
foreach ($directory in $directories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

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

$serviceSource = $PSScriptRoot
$serviceTarget = Join-Path $InstallRoot 'service'
foreach ($file in Get-ChildItem -LiteralPath $serviceSource -File) {
    if ($file.Extension -in @('.ps1', '.xml')) {
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

Set-MineGuardDirectoryAcl -Path $InstallRoot -ServicePermission 'RX'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'runtime') -ServicePermission 'RX'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'config') -ServicePermission 'RX'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'service') -ServicePermission 'RX'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'state') -ServicePermission 'M'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'backups') -ServicePermission 'M'
Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'logs') -ServicePermission 'M'

Write-Host ''
Write-Host 'MineGuard Platform Windows 运行时安装完成。'
Write-Host "安装目录：$InstallRoot"
Write-Host '下一步（不会在命令行记录秘密）：'
Write-Host ("  & '{0}' -InstallRoot '{1}' -ClientsFile 'C:\安全交付\clients.json'" -f `
    (Join-Path $serviceTarget 'Set-MineGuardPlatformConfiguration.ps1'), $InstallRoot)
