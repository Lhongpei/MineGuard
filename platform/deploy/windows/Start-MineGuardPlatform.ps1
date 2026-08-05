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
Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
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
$adminUsername = [string](Get-RequiredProperty -Object $settings -Name 'adminUsername')
if ([string]::IsNullOrWhiteSpace($adminUsername)) {
    throw '管理员用户名不能为空。'
}
$secureCookieValue = Get-RequiredProperty -Object $settings -Name 'secureCookie'
if ($secureCookieValue -isnot [bool]) {
    throw 'settings.json 的 secureCookie 必须是 JSON 布尔值。'
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
Remove-Item Env:MINEGUARD_V2_CLIENTS_JSON -ErrorAction SilentlyContinue
Remove-Item Env:MINEGUARD_V2_CLIENTS_FILE -ErrorAction SilentlyContinue
Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue

if (-not [string]::IsNullOrWhiteSpace($clientsFile)) {
    $clientsFile = Get-SafeFixedNtfsPath -Value $clientsFile -Label '煤矿客户端注册表'
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
    $checkArguments = Join-MineGuardPlatformArguments -Runtime $runtime `
        -Arguments @('config-check', '--auth-database', $authDatabase)
    $checkText = & $runtime.filePath @checkArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'auth.db 无法只读核验；拒绝在不确定管理员状态时启动。'
    }
    $check = $checkText | Out-String | ConvertFrom-Json
    $hasAuthUser = ([int]$check.auth_user_count -ge 1)
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

$exitCode = 1
Push-Location $InstallRoot
try {
    & $runtime.filePath @arguments
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
    Remove-Item Env:MINEGUARD_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
if ($null -eq $exitCode) { $exitCode = 1 }
exit $exitCode
