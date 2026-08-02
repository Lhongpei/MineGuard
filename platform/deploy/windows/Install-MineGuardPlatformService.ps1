[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $WinSWExecutable,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')] [string] $ExpectedSha256,
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
    [switch] $StartService
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
    )) { throw '安装 Windows 服务必须以管理员身份运行 Windows PowerShell。' }
}

Assert-Administrator
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$WinSWExecutable = [System.IO.Path]::GetFullPath($WinSWExecutable)
$serviceDirectory = Join-Path $InstallRoot 'service'
$python = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
$template = Join-Path $serviceDirectory 'MineGuard.Platform.xml'
$settings = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
$bootstrapSecret = Join-Path (Join-Path $InstallRoot 'config') 'bootstrap-admin-password.txt'
if (-not (Test-Path -LiteralPath $WinSWExecutable -PathType Leaf)) {
    throw "WinSW 可执行文件不存在：$WinSWExecutable"
}
if (-not (Test-Path -LiteralPath $template -PathType Leaf)) {
    throw "WinSW XML 模板不存在：$template。请重新运行平台安装脚本。"
}
if (-not (Test-Path -LiteralPath $settings -PathType Leaf)) {
    throw '缺少 settings.json；请先运行配置脚本。'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "找不到已安装平台运行时：$python"
}
$actualHash = (Get-FileHash -LiteralPath $WinSWExecutable -Algorithm SHA256).Hash
if ($actualHash -ne $ExpectedSha256.ToUpperInvariant()) {
    throw "WinSW SHA-256 不匹配。实际值：$actualHash"
}
try { [xml]$xml = Get-Content -LiteralPath $template -Raw -Encoding UTF8 } catch {
    throw "WinSW XML 无效：$($_.Exception.Message)"
}
if ($xml.service.id -ne 'MineGuardPlatform' -or
    $xml.service.serviceaccount.username -ne 'NT AUTHORITY\LocalService') {
    throw 'WinSW XML 必须使用固定服务 ID 和低权限 LocalService 账号。'
}
$xmlText = Get-Content -LiteralPath $template -Raw -Encoding UTF8
if ($xmlText -match '(?i)REPLACE[_-]|CHANGE[_-]ME|<password>|MINEGUARD_ADMIN_PASSWORD') {
    throw 'WinSW XML 包含秘密/占位符；拒绝安装服务。'
}

$configuration = Get-Content -LiteralPath $settings -Raw -Encoding UTF8 |
    ConvertFrom-Json
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
$configuredClientsFile = [string]$configuration.clientsFile
if (-not [string]::IsNullOrWhiteSpace($configuredClientsFile)) {
    if (-not (Test-Path -LiteralPath $configuredClientsFile -PathType Leaf)) {
        throw 'settings.json 指向的客户端注册表不存在。'
    }
    $configuredClientsText = Get-Content -LiteralPath $configuredClientsFile -Raw -Encoding UTF8
    if ($configuredClientsText -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        throw '客户端注册表仍含示例/占位秘密；拒绝安装服务。'
    }
    $configuredClientsText = $null
    $validateCode = @'
import sys
from mineguard.exchange_v2 import load_exchange_clients
clients = load_exchange_clients(None, sys.argv[1])
if not clients:
    raise SystemExit("客户端注册表至少需要一座煤矿")
print(len(clients))
'@
    & $python '-c' $validateCode $configuredClientsFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '客户端注册表未通过 MineGuard 完整校验。' }
} elseif (-not [bool]$configuration.allowDemoDefaultPassword) {
    throw '正式服务至少需要一座煤矿客户端注册；拒绝安装空注册表服务。'
}
if (-not [bool]$configuration.secureCookie -and
    -not [bool]$configuration.allowDemoDefaultPassword) {
    throw '正式 Windows 服务必须启用 Secure Cookie 并通过 HTTPS 反向代理访问。'
}
$configuredStateDirectory = [System.IO.Path]::GetFullPath(
    [string]$configuration.stateDirectory
)
if ($configuredStateDirectory.StartsWith('\\')) {
    throw 'settings.json 状态目录不能使用 UNC/SMB 网络路径。'
}
$configuredStateRoot = [System.IO.Path]::GetPathRoot($configuredStateDirectory)
if ($configuredStateDirectory.TrimEnd('\') -eq $configuredStateRoot.TrimEnd('\')) {
    throw 'settings.json 状态目录不能是磁盘根目录。'
}
$configuredStateDrive = New-Object -TypeName System.IO.DriveInfo `
    -ArgumentList $configuredStateRoot
if ($configuredStateDrive.DriveType -eq [System.IO.DriveType]::Network) {
    throw 'settings.json 状态目录不能位于映射网络盘。'
}
$authDatabase = Join-Path $configuredStateDirectory 'auth.db'
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $authUserCountCode = @'
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=5) as connection:
    print(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
'@
    $authUserCount = & $python '-c' $authUserCountCode $authDatabase
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝安装服务。'
    }
    $hasAuthUser = ([int]$authUserCount -ge 1)
}
if (-not $hasAuthUser -and
    -not (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf) -and
    -not [bool]$configuration.allowDemoDefaultPassword) {
    throw '首次启动缺少受保护的管理员密码文件；拒绝安装会回退演示口令的服务。'
}
if (-not $hasAuthUser -and
    (Test-Path -LiteralPath $bootstrapSecret -PathType Leaf)) {
    $bootstrapText = Get-Content -LiteralPath $bootstrapSecret -Raw -Encoding UTF8
    if ($bootstrapText.Length -lt 8 -or
        $bootstrapText.IndexOfAny([char[]]"`r`n`0") -ge 0 -or
        $bootstrapText -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        throw '首次管理员密码文件无效或仍含占位文本；拒绝安装服务。'
    }
    $bootstrapText = $null
}
if ([bool]$configuration.allowDemoDefaultPassword) {
    Write-Warning '配置允许演示默认密码；不得把该服务接入正式内网。'
}

$destination = Join-Path $serviceDirectory 'MineGuard.Platform.exe'
if (Test-Path -LiteralPath $destination -PathType Leaf) {
    $existingHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($existingHash -ne $actualHash) {
        throw '服务目录已有不同的 WinSW 可执行文件；请先按变更流程处理旧服务。'
    }
} else {
    Copy-Item -LiteralPath $WinSWExecutable -Destination $destination
}

$existingService = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
    throw 'MineGuardPlatform 服务已经安装；本脚本不会隐式覆盖或重装现有服务。'
}
& $destination 'install'
if ($LASTEXITCODE -ne 0) { throw "WinSW 安装服务失败，退出码 $LASTEXITCODE。" }
try {
    if ($StartService) {
        & $destination 'start'
        if ($LASTEXITCODE -ne 0) { throw "WinSW 启动服务失败，退出码 $LASTEXITCODE。" }
        $healthScript = Join-Path $serviceDirectory 'Test-MineGuardPlatform.ps1'
        $healthArguments = @{
            BaseUri = ('http://127.0.0.1:{0}' -f $configuredPort)
            TimeoutSeconds = 2
        }
        if ([bool]$configuration.allowDemoDefaultPassword) {
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
    }
} catch {
    Write-Warning '服务已安装但未成功启动；请查看 logs 目录和 Windows 事件日志。'
    throw
}

Write-Host 'MineGuardPlatform Windows 服务安装完成。'
Write-Host "WinSW SHA-256：$actualHash"
if (-not $StartService) {
    Write-Host '检查 HTTPS 反向代理和配置后，运行 Start-Service MineGuardPlatform。'
}
