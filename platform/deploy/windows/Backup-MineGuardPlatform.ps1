[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform'),
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

$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$python = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
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
$stateDirectory = [System.IO.Path]::GetFullPath([string]$settings.stateDirectory)
if ($stateDirectory.StartsWith('\\')) {
    throw '当前配置状态目录不能是 UNC/SMB 网络路径。'
}
$stateRoot = [System.IO.Path]::GetPathRoot($stateDirectory)
if ($stateDirectory.TrimEnd('\') -eq $stateRoot.TrimEnd('\')) {
    throw '当前配置状态目录不能是磁盘根目录。'
}
$stateDrive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $stateRoot
if ($stateDrive.DriveType -eq [System.IO.DriveType]::Network) {
    throw '当前配置状态目录不能位于映射网络盘。'
}
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $InstallRoot 'backups'
}
if ([string]::IsNullOrWhiteSpace($KeyFile)) {
    $KeyFile = Join-Path $stateDirectory 'backup.key'
}
$BackupDirectory = [System.IO.Path]::GetFullPath($BackupDirectory)
$KeyFile = [System.IO.Path]::GetFullPath($KeyFile)
if ([string]::IsNullOrWhiteSpace($BackupId)) {
    $BackupId = '{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $PID
}
if ($BackupId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
    throw 'BackupId 只能包含字母、数字、点、下划线和连字符。'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "找不到运行时：$python"
}
if (-not (Test-Path -LiteralPath (Join-Path $stateDirectory 'mineguard.db') -PathType Leaf)) {
    throw "状态目录中没有 mineguard.db：$stateDirectory"
}
if (-not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) {
    throw "备份认证密钥不存在：$KeyFile。先至少成功启动一次服务，并离线保存该密钥。"
}
if (-not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
}

$createdText = & $python '-m' 'mineguard' 'backup' $BackupId `
    '--state-directory' $stateDirectory `
    '--backup-directory' $BackupDirectory `
    '--key-file' $KeyFile '--key-id' $KeyId
if ($LASTEXITCODE -ne 0) { throw "创建备份失败，退出码 $LASTEXITCODE。" }
$verifiedText = & $python '-m' 'mineguard' 'verify-backup' $BackupId `
    '--state-directory' $stateDirectory `
    '--backup-directory' $BackupDirectory `
    '--key-file' $KeyFile '--key-id' $KeyId
if ($LASTEXITCODE -ne 0) { throw "备份已创建但核验失败，退出码 $LASTEXITCODE。" }

[pscustomobject]@{
    status = 'created_and_verified'
    backupId = $BackupId
    backupDirectory = $BackupDirectory
    created = ($createdText | Out-String | ConvertFrom-Json)
    verified = ($verifiedText | Out-String | ConvertFrom-Json)
    reminder = 'backup.key 不包含在备份中，必须另行离线保管。'
}
