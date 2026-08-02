[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
    [string] $ClientsFile,
    [switch] $DemoWithoutClientRegistry,
    [string] $StateDirectory,
    [ValidateRange(1, 65535)] [int] $Port = 8080,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformSystemId = 'mineguard-government',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformPartyId = 'regulator-government',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformKeyId = 'regulator-key-v2',
    [string] $AdminUsername = 'admin',
    [Security.SecureString] $AdminPassword,
    [switch] $AllowDemoDefaultPassword,
    [switch] $HttpOnlyDemo,
    [switch] $NonInteractive,
    [switch] $ClearBootstrapPassword
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
    )) { throw '配置和保护秘密文件必须以管理员身份运行 Windows PowerShell。' }
}

function Set-ConfigAcl {
    param([string] $Path)
    $serviceGrant = ('*{0}:(OI)(CI)RX' -f $ServiceSid)
    & "$env:SystemRoot\System32\icacls.exe" $Path '/inheritance:r' `
        '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        $serviceGrant '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "设置配置目录 NTFS ACL 失败：$Path" }
}

function Set-StateAcl {
    param([string] $Path)
    $serviceGrant = ('*{0}:(OI)(CI)M' -f $ServiceSid)
    & "$env:SystemRoot\System32\icacls.exe" $Path '/inheritance:r' `
        '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        $serviceGrant '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "设置状态目录 NTFS ACL 失败：$Path" }
}

function Test-ReparsePoint {
    param([string] $Path)
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

Assert-Administrator
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
if ($InstallRoot.StartsWith('\\')) { throw '安装目录不能使用 UNC/SMB 网络路径。' }
$configDirectory = Join-Path $InstallRoot 'config'
$python = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
$settingsPath = Join-Path $configDirectory 'settings.json'
$bootstrapPath = Join-Path $configDirectory 'bootstrap-admin-password.txt'
$targetClientsPath = Join-Path $configDirectory 'clients.json'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "找不到已安装运行时：$python。请先运行 Install-MineGuardPlatform.ps1。"
}
if (-not (Test-Path -LiteralPath $configDirectory -PathType Container)) {
    throw "找不到配置目录：$configDirectory。请先运行安装脚本。"
}

if ($ClearBootstrapPassword) {
    if ($null -ne $AdminPassword) {
        throw '-ClearBootstrapPassword 不能与 -AdminPassword 同时使用。'
    }
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw 'settings.json 尚不存在；拒绝删除首次管理员密码。'
    }
    $currentSettings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $authDatabase = Join-Path ([string]$currentSettings.stateDirectory) 'auth.db'
    if (-not (Test-Path -LiteralPath $authDatabase -PathType Leaf)) {
        throw 'auth.db 尚不存在；拒绝删除首次管理员密码，以免服务无法完成首启。'
    }
    $userCountCode = @'
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=5) as connection:
    print(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
'@
    $userCount = & $python '-c' $userCountCode $authDatabase
    if ($LASTEXITCODE -ne 0 -or [int]$userCount -lt 1) {
        throw 'auth.db 中尚无管理员账号；拒绝删除首次管理员密码。'
    }
    if (Test-Path -LiteralPath $bootstrapPath -PathType Leaf) {
        Remove-Item -LiteralPath $bootstrapPath -Force
        Write-Host '首次管理员明文密码文件已删除；auth.db 中仅保留密码摘要。'
    } else {
        Write-Host '首次管理员明文密码文件已经不存在。'
    }
    exit 0
}

if ($DemoWithoutClientRegistry -and -not [string]::IsNullOrWhiteSpace($ClientsFile)) {
    throw '-DemoWithoutClientRegistry 不能与 -ClientsFile 同时使用。'
}
if (-not $DemoWithoutClientRegistry -and [string]::IsNullOrWhiteSpace($ClientsFile)) {
    throw '正式配置必须提供 -ClientsFile；仅合成演示可显式使用 -DemoWithoutClientRegistry。'
}
if ($AllowDemoDefaultPassword -and -not $DemoWithoutClientRegistry) {
    throw '-AllowDemoDefaultPassword 只允许与 -DemoWithoutClientRegistry 一起使用。'
}
if ([string]::IsNullOrWhiteSpace($AdminUsername) -or $AdminUsername.Length -gt 128) {
    throw '管理员用户名必须包含 1-128 个字符。'
}

$installedClientsPath = ''
if (-not $DemoWithoutClientRegistry) {
    $sourceClientsPath = [System.IO.Path]::GetFullPath($ClientsFile)
    if ($sourceClientsPath.StartsWith('\\')) {
        throw '客户端注册表不能从 UNC/SMB 网络路径读取。'
    }
    if (-not (Test-Path -LiteralPath $sourceClientsPath -PathType Leaf)) {
        throw "客户端注册表不存在：$sourceClientsPath"
    }
    if (Test-ReparsePoint -Path $sourceClientsPath) {
        throw '客户端注册表不能是符号链接、junction 或其他 reparse point。'
    }
    $length = (Get-Item -LiteralPath $sourceClientsPath).Length
    if ($length -gt (4 * 1024 * 1024)) {
        throw '客户端注册表超过 4 MiB 安全上限。'
    }
    $sourceText = Get-Content -LiteralPath $sourceClientsPath -Raw -Encoding UTF8
    if ($sourceText -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
        throw '客户端注册表仍含示例/占位秘密；请生成独立随机密钥后再配置。'
    }
    $sourceText = $null

    $validateCode = @'
import sys
from mineguard.exchange_v2 import load_exchange_clients
clients = load_exchange_clients(None, sys.argv[1])
if not clients:
    raise SystemExit("客户端注册表至少需要一座煤矿")
print(len(clients))
'@
    $temporaryClients = Join-Path $configDirectory (
        '.clients.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
    )
    try {
        [System.IO.File]::WriteAllBytes(
            $temporaryClients,
            [System.IO.File]::ReadAllBytes($sourceClientsPath)
        )
        $validatedCount = & $python '-c' $validateCode $temporaryClients
        if ($LASTEXITCODE -ne 0) {
            throw '复制后的客户端注册表未通过 MineGuard 完整校验。'
        }
        if (Test-Path -LiteralPath $targetClientsPath -PathType Leaf) {
            [System.IO.File]::Replace($temporaryClients, $targetClientsPath, $null)
        } else {
            Move-Item -LiteralPath $temporaryClients -Destination $targetClientsPath
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryClients) {
            Remove-Item -LiteralPath $temporaryClients -Force
        }
    }
    $installedClientsPath = $targetClientsPath
    Write-Host "客户端注册表已校验：$validatedCount 座煤矿。"
} elseif (Test-Path -LiteralPath $targetClientsPath -PathType Leaf) {
    Remove-Item -LiteralPath $targetClientsPath -Force
}

if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
    $stateDirectory = Join-Path $InstallRoot 'state'
} else {
    $stateDirectory = [System.IO.Path]::GetFullPath($StateDirectory)
    if ($stateDirectory.StartsWith('\\')) {
        throw '状态目录不能使用 UNC/SMB 网络路径。'
    }
    $stateRoot = [System.IO.Path]::GetPathRoot($stateDirectory)
    if ($stateDirectory.TrimEnd('\') -eq $stateRoot.TrimEnd('\')) {
        throw '状态目录不能是磁盘根目录。'
    }
    $stateDrive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $stateRoot
    if ($stateDrive.DriveType -eq [System.IO.DriveType]::Network) {
        throw '状态目录不能位于映射网络盘。'
    }
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    }
}
$authDatabase = Join-Path $stateDirectory 'auth.db'
$hasAuthUser = $false
if (Test-Path -LiteralPath $authDatabase -PathType Leaf) {
    $authUserCountCode = @'
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=5) as connection:
    print(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
'@
    $authUserCount = & $python '-c' $authUserCountCode $authDatabase
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝覆盖管理员首启配置。'
    }
    $hasAuthUser = ([int]$authUserCount -ge 1)
}
if ($null -eq $AdminPassword -and
    -not $hasAuthUser -and
    -not $AllowDemoDefaultPassword) {
    if ($NonInteractive) {
        throw '全新状态库需要 -AdminPassword；非交互模式不会回退到演示默认密码。'
    }
    $AdminPassword = Read-Host '请输入首次管理员密码（至少 8 个字符）' -AsSecureString
}
if ($null -ne $AdminPassword) {
    $temporaryPassword = $null
    $plainPassword = $null
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
    try {
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($plainPassword.Length -lt 8 -or
            $plainPassword.IndexOfAny([char[]]"`r`n`0") -ge 0) {
            throw '首次管理员密码至少 8 个字符，且不得包含换行或 NUL。'
        }
        if ($plainPassword -match '(?i)REPLACE(?:[_-]|\b)|CHANGE[_-]?ME|DEMO[_-]?ONLY|NOT[_-]?FOR[_-]?PRODUCTION') {
            throw '首次管理员密码不能使用示例或占位文本。'
        }
        $temporaryPassword = Join-Path $configDirectory (
            '.bootstrap-password.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
        )
        [System.IO.File]::WriteAllText($temporaryPassword, $plainPassword, $utf8NoBom)
        if (Test-Path -LiteralPath $bootstrapPath -PathType Leaf) {
            [System.IO.File]::Replace($temporaryPassword, $bootstrapPath, $null)
        } else {
            Move-Item -LiteralPath $temporaryPassword -Destination $bootstrapPath
        }
    } finally {
        if ($null -ne $bstr) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainPassword = $null
        if ($null -ne $temporaryPassword -and
            (Test-Path -LiteralPath $temporaryPassword)) {
            Remove-Item -LiteralPath $temporaryPassword -Force
        }
    }
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
}
$temporarySettings = Join-Path $configDirectory (
    '.settings.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
)
try {
    [System.IO.File]::WriteAllText(
        $temporarySettings,
        ($settings | ConvertTo-Json -Depth 5),
        $utf8NoBom
    )
    if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        [System.IO.File]::Replace($temporarySettings, $settingsPath, $null)
    } else {
        Move-Item -LiteralPath $temporarySettings -Destination $settingsPath
    }
} finally {
    if (Test-Path -LiteralPath $temporarySettings) {
        Remove-Item -LiteralPath $temporarySettings -Force
    }
}
Set-ConfigAcl -Path $configDirectory
Set-StateAcl -Path $stateDirectory

Write-Host 'MineGuard Platform 配置已保存；秘密未写入 WinSW XML 或命令行。'
if (-not $HttpOnlyDemo) {
    Write-Host '会话 Cookie 已启用 Secure；必须通过 HTTPS 反向代理访问。'
} else {
    Write-Warning '当前为 HTTP 本机演示模式，不能用于正式内网。'
}
if ($null -ne $AdminPassword) {
    Write-Host '首次启动并通过健康检查后，请运行：'
    Write-Host ("  & '{0}' -InstallRoot '{1}' -ClearBootstrapPassword" -f `
        (Join-Path (Join-Path $InstallRoot 'service') 'Set-MineGuardPlatformConfiguration.ps1'), `
        $InstallRoot)
}
Write-Host '配置修改需重启 MineGuardPlatform 服务后生效。'
