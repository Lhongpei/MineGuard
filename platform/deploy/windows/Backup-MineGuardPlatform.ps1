[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
    [string] $BackupId,
    [string] $BackupDirectory,
    [string] $KeyFile,
    [string] $KeyId = 'mineguard-v2-backup-key'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Get-SafeFixedNtfsPath {
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or
        -not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS') {
        throw "$Label 必须位于已就绪的本机固定 NTFS 磁盘。"
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
$resolverPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $PSScriptRoot 'Resolve-MineGuardPlatformExecutable.ps1') `
    -Label '运行时解析器'
if (-not (Test-Path -LiteralPath $resolverPath -PathType Leaf)) {
    throw "找不到运行时解析器：$resolverPath"
}
. $resolverPath
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
$runtime.filePath = Get-SafeFixedNtfsPath `
    -Value ([string]$runtime.filePath) -Label 'MineGuard Platform 运行时'
$settingsPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $configDirectory 'settings.json') -Label 'settings.json'
if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "找不到当前运行配置：$settingsPath"
}
try {
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
} catch {
    throw "settings.json 不是有效 JSON：$($_.Exception.Message)"
}
if ([int]$settings.schemaVersion -ne 1) { throw 'settings.json 版本不受支持。' }
$stateDirectory = Get-SafeFixedNtfsPath `
    -Value ([string]$settings.stateDirectory) -Label '当前配置状态目录'
Assert-StateBoundary -Candidate $stateDirectory -Root $InstallRoot
if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
    throw "当前配置状态目录不存在：$stateDirectory"
}
Assert-NoReparseTree -Path $stateDirectory -Label '当前配置状态目录'
Assert-StateOwnership -Path $stateDirectory
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $InstallRoot 'backups'
}
if ([string]::IsNullOrWhiteSpace($KeyFile)) {
    $KeyFile = Join-Path $stateDirectory 'backup.key'
}
$BackupDirectory = Get-SafeFixedNtfsPath `
    -Value $BackupDirectory -Label '备份目录'
$KeyFile = Get-SafeFixedNtfsPath -Value $KeyFile -Label '备份认证密钥'
if ([string]::IsNullOrWhiteSpace($BackupId)) {
    $BackupId = '{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $PID
}
if ($BackupId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw 'BackupId 只能包含字母、数字、点、下划线和连字符。'
}
$mineguardDatabase = Get-SafeFixedNtfsPath `
    -Value (Join-Path $stateDirectory 'mineguard.db') -Label 'mineguard.db'
if (-not (Test-Path -LiteralPath $mineguardDatabase -PathType Leaf)) {
    throw "状态目录中没有 mineguard.db：$stateDirectory"
}
if (-not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) {
    throw "备份认证密钥不存在：$KeyFile。先至少成功启动一次服务，并离线保存该密钥。"
}
if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
}
$BackupDirectory = Get-SafeFixedNtfsPath `
    -Value $BackupDirectory -Label '备份目录'
Assert-NoReparseTree -Path $BackupDirectory -Label '备份目录'

$createArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'backup', $BackupId,
    '--state-directory', $stateDirectory,
    '--backup-directory', $BackupDirectory,
    '--key-file', $KeyFile, '--key-id', $KeyId
)
$createdText = & $runtime.filePath @createArguments
if ($LASTEXITCODE -ne 0) { throw "创建备份失败，退出码 $LASTEXITCODE。" }
$verifyArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'verify-backup', $BackupId,
    '--state-directory', $stateDirectory,
    '--backup-directory', $BackupDirectory,
    '--key-file', $KeyFile, '--key-id', $KeyId
)
$verifiedText = & $runtime.filePath @verifyArguments
if ($LASTEXITCODE -ne 0) { throw "备份已创建但核验失败，退出码 $LASTEXITCODE。" }

[pscustomobject]@{
    status = 'created_and_verified'
    backupId = $BackupId
    backupDirectory = $BackupDirectory
    created = ($createdText | Out-String | ConvertFrom-Json)
    verified = ($verifiedText | Out-String | ConvertFrom-Json)
    reminder = 'backup.key 不包含在备份中，必须另行离线保管。'
}
