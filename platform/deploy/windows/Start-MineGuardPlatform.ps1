[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform')
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

function Get-LocalAbsolutePath {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        -not [System.IO.Path]::IsPathRooted($Value)) {
        throw "$Label 必须是本机绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ($fullPath.StartsWith('\\')) {
        throw "$Label 不能使用 UNC/SMB 网络路径。"
    }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    try {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($drive.DriveType -eq [System.IO.DriveType]::Network) {
            throw "$Label 不能位于映射网络盘。"
        }
    } catch [System.ArgumentException] {
        throw "$Label 所在磁盘无法识别。"
    }
    return $fullPath
}

$InstallRoot = Get-LocalAbsolutePath -Value $InstallRoot -Label '安装目录'
$settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
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
$stateDirectory = Get-LocalAbsolutePath `
    -Value ([string](Get-RequiredProperty -Object $settings -Name 'stateDirectory')) `
    -Label '状态目录'
$clientsFile = [string](Get-RequiredProperty -Object $settings -Name 'clientsFile')
$adminUsername = [string](Get-RequiredProperty -Object $settings -Name 'adminUsername')
if ([string]::IsNullOrWhiteSpace($adminUsername)) {
    throw '管理员用户名不能为空。'
}
$secureCookieValue = Get-RequiredProperty -Object $settings -Name 'secureCookie'
if ($secureCookieValue -isnot [bool]) {
    throw 'settings.json 的 secureCookie 必须是 JSON 布尔值。'
}

$python = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "找不到隔离运行时：$python。请重新运行安装脚本。"
}
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
}

$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
Remove-Item Env:MINEGUARD_V2_CLIENTS_JSON -ErrorAction SilentlyContinue
Remove-Item Env:MINEGUARD_V2_CLIENTS_FILE -ErrorAction SilentlyContinue
Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue

if (-not [string]::IsNullOrWhiteSpace($clientsFile)) {
    $clientsFile = Get-LocalAbsolutePath -Value $clientsFile -Label '煤矿客户端注册表'
    if (-not (Test-Path -LiteralPath $clientsFile -PathType Leaf)) {
        throw "煤矿客户端注册表不存在：$clientsFile"
    }
    $clientsText = Get-Content -LiteralPath $clientsFile -Raw -Encoding UTF8
    if ($clientsText -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        throw '煤矿客户端注册表仍含示例/占位秘密；拒绝启动。'
    }
    $clientsText = $null
    $env:MINEGUARD_V2_CLIENTS_FILE = $clientsFile
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
$bootstrapSecret = Join-Path (Join-Path $InstallRoot 'config') 'bootstrap-admin-password.txt'
$allowDemoDefault = $false
$demoProperty = $settings.PSObject.Properties['allowDemoDefaultPassword']
if ($null -eq $demoProperty -or $demoProperty.Value -isnot [bool]) {
    throw 'settings.json 的 allowDemoDefaultPassword 必须是 JSON 布尔值。'
}
$allowDemoDefault = [bool]$demoProperty.Value
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $authUserCountCode = @'
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=5) as connection:
    print(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
'@
    $authUserCount = & $python '-c' $authUserCountCode $authDatabase
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝在不确定管理员状态时启动。'
    }
    $hasAuthUser = ([int]$authUserCount -ge 1)
}
if (-not $hasAuthUser) {
    if (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf) {
        $strictUtf8 = New-Object -TypeName System.Text.UTF8Encoding `
            -ArgumentList @($false, $true)
        $reader = New-Object -TypeName System.IO.StreamReader `
            -ArgumentList @($bootstrapSecret, $strictUtf8, $true)
        try { $password = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($password.Length -lt 8 -or $password.IndexOfAny([char[]]"`r`n`0") -ge 0) {
            throw '首次管理员密码文件无效：至少 8 个字符且不得包含换行或 NUL。'
        }
        if ($password -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
            throw '首次管理员密码仍含示例/占位文本；拒绝启动。'
        }
        $env:MINEGUARD_ADMIN_PASSWORD = $password
        $password = $null
    } elseif (-not $allowDemoDefault) {
        throw '全新状态库缺少首次管理员密码。请重新运行配置脚本并安全输入密码。'
    }
}

$arguments = @(
    '-m', 'mineguard', 'serve',
    '--host', $hostAddress,
    '--port', [string]$port,
    '--state-directory', $stateDirectory,
    '--admin-username', $adminUsername
)
if ([bool]$secureCookieValue) {
    $arguments += '--secure-cookie'
}

$exitCode = 1
Push-Location $InstallRoot
try {
    & $python @arguments
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
    Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
if ($null -eq $exitCode) { $exitCode = 1 }
exit $exitCode
