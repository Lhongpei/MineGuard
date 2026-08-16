[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,
    [switch] $ModelCredentials,
    [switch] $Elevated
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:LauncherTitle = if ($ModelCredentials) {
    'MineGuard 模型授权导入向导'
} else {
    'MineGuard 企业接入配置向导'
}

function Show-LauncherError {
    param([string] $Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message,
            $script:LauncherTitle,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    } catch {
        Write-Error $Message
    }
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 5 -or
        ($PSVersionTable.PSVersion.Major -eq 5 -and
            $PSVersionTable.PSVersion.Minor -lt 1)) {
        throw '需要 Windows PowerShell 5.1。'
    }
    if ([string]::IsNullOrWhiteSpace($InstallRoot) -or
        $InstallRoot -notmatch '^[A-Za-z]:\\') {
        throw '安装目录无效，请重新安装 MineGuard Enterprise Agent。'
    }
    if ($InstallRoot.IndexOf([char]0) -ge 0 -or
        $InstallRoot.IndexOf([char]10) -ge 0 -or
        $InstallRoot.IndexOf([char]13) -ge 0 -or
        $InstallRoot.IndexOf([char]34) -ge 0) {
        throw '安装目录包含不允许的字符。'
    }

    $resolvedRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $launcherPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
    $wizardName = if ($ModelCredentials) {
        'Start-EnterpriseAgentModelCredentialWizard.ps1'
    } else {
        'Start-EnterpriseAgentProvisioningWizard.ps1'
    }
    $wizardPath = Join-Path $resolvedRoot ('deploy\windows\' + $wizardName)
    $powershellPath = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        throw '找不到 Windows PowerShell。'
    }

    if ($Elevated) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        if (-not $principal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "$script:LauncherTitle 没有获得管理员权限。"
        }
        if (-not (Test-Path -LiteralPath $wizardPath -PathType Leaf)) {
            throw "安装不完整：找不到 $script:LauncherTitle。请重新安装。"
        }
        & $wizardPath -InstallRoot $resolvedRoot
        return
    }

    # Ordinary users can read only this tiny launcher. Request UAC before
    # inspecting the protected deploy tree so a clean installation opens
    # reliably without leaking deployment scripts to desktop users.
    $modeArgument = if ($ModelCredentials) { ' -ModelCredentials' } else { '' }
    $arguments = (
        '-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}"{2} -Elevated' -f
            $launcherPath, $resolvedRoot, $modeArgument
    )
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershellPath
    $startInfo.Arguments = $arguments
    $startInfo.UseShellExecute = $true
    $startInfo.Verb = 'runas'
    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw "$script:LauncherTitle 未能启动。"
    }
} catch {
    $message = $_.Exception.Message
    if ($_.Exception -is [ComponentModel.Win32Exception] -and
        $_.Exception.NativeErrorCode -eq 1223) {
        $message = "管理员授权已取消，$script:LauncherTitle 没有启动。"
    }
    Show-LauncherError -Message $message
    exit 1
}
