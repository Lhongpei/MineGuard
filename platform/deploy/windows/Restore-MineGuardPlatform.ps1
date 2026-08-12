[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BackupId,
    [Parameter(Mandatory = $true)] [string] $TargetStateDirectory,
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
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

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $identity
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) { throw '恢复和设置 NTFS ACL 必须以管理员身份运行 Windows PowerShell。' }
}

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

function Assert-PathsDoNotOverlap {
    param(
        [string] $First,
        [string] $Second,
        [string] $Message
    )
    if ((Test-PathEqualOrChild -Candidate $First -Parent $Second) -or
        (Test-PathEqualOrChild -Candidate $Second -Parent $First)) {
        throw $Message
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
        throw '当前状态目录缺少 MineGuard 所有权标记；请先运行配置脚本。'
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

function Initialize-StateOwnership {
    param([string] $Path, [string] $Root)
    $markerPath = Get-SafeFixedNtfsPath `
        -Value (Join-Path $Path '.mineguard-platform-state.json') `
        -Label '恢复状态所有权标记'
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        Assert-StateOwnership -Path $Path
        return
    }
    $marker = [ordered]@{
        schemaVersion = 1
        product = 'MineGuard Platform State'
        initializedFor = $Root
    }
    [System.IO.File]::WriteAllText(
        $markerPath,
        ($marker | ConvertTo-Json -Depth 3),
        $utf8NoBom
    )
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
Assert-Administrator
if ($BackupId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw 'BackupId 格式不合法。'
}
$InstallRoot = Get-SafeFixedNtfsPath -Value $InstallRoot -Label '安装目录'
$configDirectory = Get-SafeFixedNtfsPath `
    -Value (Join-Path $InstallRoot 'config') -Label '配置目录'
Assert-NoReparseTree -Path $configDirectory -Label '配置目录'
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
$currentStateDirectory = Get-SafeFixedNtfsPath `
    -Value ([string]$settings.stateDirectory) -Label '当前配置状态目录'
Assert-StateBoundary -Candidate $currentStateDirectory -Root $InstallRoot
if (-not (Test-Path -LiteralPath $currentStateDirectory -PathType Container)) {
    throw "当前配置状态目录不存在：$currentStateDirectory"
}
Assert-NoReparseTree -Path $currentStateDirectory -Label '当前配置状态目录'
Assert-StateOwnership -Path $currentStateDirectory
$TargetStateDirectory = Get-SafeFixedNtfsPath `
    -Value $TargetStateDirectory -Label '恢复目标'
Assert-StateBoundary -Candidate $TargetStateDirectory -Root $InstallRoot
Assert-PathsDoNotOverlap `
    -First $TargetStateDirectory -Second $currentStateDirectory `
    -Message '恢复目标不能等于当前状态目录，也不能与其互为父子目录。'
if (Test-Path -LiteralPath $TargetStateDirectory) {
    if (-not (Test-Path -LiteralPath $TargetStateDirectory -PathType Container)) {
        throw '恢复目标已经存在且不是目录。'
    }
    if ($null -ne (Get-ChildItem -LiteralPath $TargetStateDirectory -Force | Select-Object -First 1)) {
        throw '恢复目标必须不存在或为空；脚本绝不覆盖当前状态目录。'
    }
}
$resolverPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $PSScriptRoot 'Resolve-MineGuardPlatformExecutable.ps1') `
    -Label '运行时解析器'
$aclHelperPath = Get-SafeFixedNtfsPath `
    -Value (Join-Path $PSScriptRoot 'MineGuardPlatform.WindowsAcl.ps1') `
    -Label 'Platform ACL helper'
foreach ($requiredHelper in @($resolverPath, $aclHelperPath)) {
    if (-not (Test-Path -LiteralPath $requiredHelper -PathType Leaf)) {
        throw "恢复工具缺少受信 helper：$requiredHelper"
    }
}
. $resolverPath
. $aclHelperPath
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
$runtime.filePath = Get-SafeFixedNtfsPath `
    -Value ([string]$runtime.filePath) -Label 'MineGuard Platform 运行时'
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $InstallRoot 'backups'
}
if ([string]::IsNullOrWhiteSpace($KeyFile)) {
    $KeyFile = Join-Path $currentStateDirectory 'backup.key'
}
$BackupDirectory = Get-SafeFixedNtfsPath `
    -Value $BackupDirectory -Label '备份目录'
$KeyFile = Get-SafeFixedNtfsPath -Value $KeyFile -Label '备份认证密钥'
if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
    throw "备份目录不存在：$BackupDirectory"
}
Assert-NoReparseTree -Path $BackupDirectory -Label '备份目录'
Assert-PathsDoNotOverlap `
    -First $TargetStateDirectory -Second $BackupDirectory `
    -Message '恢复目标不能与备份目录互为父子目录。'
if (-not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) { throw "备份认证密钥不存在：$KeyFile" }

$verifyArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'verify-backup', $BackupId,
    '--state-directory', $currentStateDirectory,
    '--backup-directory', $BackupDirectory,
    '--key-file', $KeyFile, '--key-id', $KeyId
)
$verified = & $runtime.filePath @verifyArguments
if ($LASTEXITCODE -ne 0) { throw '恢复前备份核验失败。' }
$restoreArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'restore-backup', $BackupId,
    '--state-directory', $TargetStateDirectory,
    '--backup-directory', $BackupDirectory,
    '--key-file', $KeyFile, '--key-id', $KeyId
)
$restored = & $runtime.filePath @restoreArguments
if ($LASTEXITCODE -ne 0) { throw '恢复失败；当前运行状态目录未被修改。' }

$TargetStateDirectory = Get-SafeFixedNtfsPath `
    -Value $TargetStateDirectory -Label '恢复目标'
if (-not (Test-Path -LiteralPath $TargetStateDirectory -PathType Container)) {
    throw '恢复命令成功返回，但恢复目标目录不存在。'
}
Assert-NoReparseTree -Path $TargetStateDirectory -Label '恢复目标'
Initialize-StateOwnership -Path $TargetStateDirectory -Root $InstallRoot
Assert-NoReparseTree -Path $TargetStateDirectory -Label '恢复目标'

Set-MineGuardPlatformCanonicalTreeAcl -Path $TargetStateDirectory `
    -ServicePermission 'M'

[pscustomobject]@{
    status = 'restored_to_new_directory'
    backupId = $BackupId
    targetStateDirectory = $TargetStateDirectory
    verification = ($verified | Out-String | ConvertFrom-Json)
    restore = ($restored | Out-String | ConvertFrom-Json)
    nextStep = "先在隔离端口验收；确认后停止服务，并运行 Set-MineGuardPlatformConfiguration.ps1 -StateDirectory '$TargetStateDirectory' 通过配置事务原子切换。禁止手工编辑 settings.json。"
}
