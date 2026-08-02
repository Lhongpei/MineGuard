[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BackupId,
    [Parameter(Mandatory = $true)] [string] $TargetStateDirectory,
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
    [string] $BackupDirectory,
    [string] $KeyFile,
    [string] $KeyId = 'mineguard-v2-backup-key'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ServiceSid = 'S-1-5-19'
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

Assert-Administrator
if ($BackupId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw 'BackupId 格式不合法。'
}
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
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
$currentStateDirectory = [System.IO.Path]::GetFullPath(
    [string]$settings.stateDirectory
)
if ($currentStateDirectory.StartsWith('\\')) {
    throw '当前配置状态目录不能是 UNC/SMB 网络路径。'
}
$currentStateRoot = [System.IO.Path]::GetPathRoot($currentStateDirectory)
if ($currentStateDirectory.TrimEnd('\') -eq $currentStateRoot.TrimEnd('\')) {
    throw '当前配置状态目录不能是磁盘根目录。'
}
$currentStateDrive = New-Object -TypeName System.IO.DriveInfo `
    -ArgumentList $currentStateRoot
if ($currentStateDrive.DriveType -eq [System.IO.DriveType]::Network) {
    throw '当前配置状态目录不能位于映射网络盘。'
}
$TargetStateDirectory = [System.IO.Path]::GetFullPath($TargetStateDirectory)
if ($TargetStateDirectory.StartsWith('\\')) {
    throw '恢复目标不能位于 UNC/SMB 网络路径。'
}
$targetRoot = [System.IO.Path]::GetPathRoot($TargetStateDirectory)
if ($TargetStateDirectory.TrimEnd('\') -eq $targetRoot.TrimEnd('\')) {
    throw '恢复目标不能是磁盘根目录。'
}
$targetDrive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $targetRoot
if ($targetDrive.DriveType -eq [System.IO.DriveType]::Network) {
    throw '恢复目标不能位于映射网络盘。'
}
if (Test-Path -LiteralPath $TargetStateDirectory) {
    if (-not (Test-Path -LiteralPath $TargetStateDirectory -PathType Container)) {
        throw '恢复目标已经存在且不是目录。'
    }
    if ($null -ne (Get-ChildItem -LiteralPath $TargetStateDirectory -Force | Select-Object -First 1)) {
        throw '恢复目标必须不存在或为空；脚本绝不覆盖当前状态目录。'
    }
}
$python = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $InstallRoot 'backups'
}
if ([string]::IsNullOrWhiteSpace($KeyFile)) {
    $KeyFile = Join-Path $currentStateDirectory 'backup.key'
}
$BackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
$KeyFile = [System.IO.Path]::GetFullPath($KeyFile)
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "找不到运行时：$python" }
if (-not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) { throw "备份认证密钥不存在：$KeyFile" }

$verified = & $python '-m' 'mineguard' 'verify-backup' $BackupId `
    '--state-directory' $currentStateDirectory `
    '--backup-directory' $BackupDirectory '--key-file' $KeyFile '--key-id' $KeyId
if ($LASTEXITCODE -ne 0) { throw '恢复前备份核验失败。' }
$restored = & $python '-m' 'mineguard' 'restore-backup' $BackupId `
    '--state-directory' $TargetStateDirectory `
    '--backup-directory' $BackupDirectory '--key-file' $KeyFile '--key-id' $KeyId
if ($LASTEXITCODE -ne 0) { throw '恢复失败；当前运行状态目录未被修改。' }

$serviceGrant = ('*{0}:(OI)(CI)M' -f $ServiceSid)
& "$env:SystemRoot\System32\icacls.exe" $TargetStateDirectory '/inheritance:r' `
    '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
    $serviceGrant '/T' '/C' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '恢复成功，但设置恢复目录 NTFS ACL 失败。' }

[pscustomobject]@{
    status = 'restored_to_new_directory'
    backupId = $BackupId
    targetStateDirectory = $TargetStateDirectory
    verification = ($verified | Out-String | ConvertFrom-Json)
    restore = ($restored | Out-String | ConvertFrom-Json)
    nextStep = '先在隔离端口验收；确认后再人工修改 settings.json 的 stateDirectory 并重启。'
}
