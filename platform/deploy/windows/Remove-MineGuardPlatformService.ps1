[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramData 'MineGuard\Platform')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
    -ArgumentList $identity
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) { throw '卸载 Windows 服务必须以管理员身份运行 Windows PowerShell。' }

$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$expectedWrapper = Join-Path (Join-Path $InstallRoot 'service') 'MineGuard.Platform.exe'
$service = Get-CimInstance -ClassName Win32_Service `
    -Filter "Name='MineGuardPlatform'" -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host 'MineGuardPlatform 服务未安装；状态、配置和备份均未修改。'
    exit 0
}
if ([string]$service.PathName -notlike ('*' + $expectedWrapper + '*')) {
    throw '同名服务的可执行路径不属于指定安装目录；拒绝卸载。'
}

if ($PSCmdlet.ShouldProcess(
    'MineGuardPlatform',
    '停止并删除固定 Windows 服务注册（保留 runtime/config/state/backups/logs）'
)) {
    $serviceController = Get-Service -Name 'MineGuardPlatform'
    if ($serviceController.Status -ne 'Stopped') {
        Stop-Service -Name 'MineGuardPlatform' -Force
        $serviceController.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
    }
    & "$env:SystemRoot\System32\sc.exe" 'delete' 'MineGuardPlatform' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "删除服务注册失败，sc.exe 退出码 $LASTEXITCODE。" }
    Write-Host 'MineGuardPlatform 服务注册已删除。'
    Write-Host "数据未删除，可恢复目录：$InstallRoot"
}
