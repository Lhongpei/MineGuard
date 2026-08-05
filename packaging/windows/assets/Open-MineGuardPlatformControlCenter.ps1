[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,
    [switch] $Elevated
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Show-LauncherError {
    param([string] $Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message,
            'MineGuard Platform 控制中心',
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
        throw '需要 Windows PowerShell 5.1。请先安装 WMF 5.1 并重启服务器。'
    }
    if ([string]::IsNullOrWhiteSpace($InstallRoot) -or
        $InstallRoot -notmatch '^[A-Za-z]:\\') {
        throw '安装目录无效，请重新安装 MineGuard Platform。'
    }
    if ($InstallRoot.IndexOf([char]0) -ge 0 -or
        $InstallRoot.IndexOf([char]10) -ge 0 -or
        $InstallRoot.IndexOf([char]13) -ge 0 -or
        $InstallRoot.IndexOf([char]34) -ge 0) {
        throw '安装目录包含不允许的字符。'
    }

    $resolvedRoot = [System.IO.Path]::GetFullPath($InstallRoot)
    $launcherPath = [System.IO.Path]::GetFullPath(
        $MyInvocation.MyCommand.Path
    )
    $wizardPath = Join-Path $resolvedRoot `
        'service\Start-MineGuardPlatformWizard.ps1'
    $powershellPath = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        throw '找不到 Windows PowerShell。'
    }

    if ($Elevated) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object `
            -TypeName Security.Principal.WindowsPrincipal `
            -ArgumentList $identity
        if (-not $principal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator
            )) {
            throw '控制中心没有获得管理员权限。'
        }
        if (-not (Test-Path -LiteralPath $wizardPath -PathType Leaf)) {
            throw '安装不完整：找不到 MineGuard Platform 中文控制中心。请重新安装。'
        }
        & $wizardPath -InstallRoot $resolvedRoot
        return
    }

    # The protected Platform tree is intentionally unreadable to an ordinary
    # desktop token. Ask UAC first by elevating this tiny public launcher; the
    # elevated branch can then verify the protected wizard and show any error
    # in a message box. Windows paths cannot contain a double quote, so quoting
    # these normalized absolute paths is unambiguous.
    $arguments = (
        '-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -Elevated' -f
            $launcherPath, $resolvedRoot
    )
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershellPath
    $startInfo.Arguments = $arguments
    $startInfo.UseShellExecute = $true
    $startInfo.Verb = 'runas'
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw '控制中心未能启动。'
    }
} catch {
    $message = $_.Exception.Message
    if ($_.Exception -is [System.ComponentModel.Win32Exception] -and
        $_.Exception.NativeErrorCode -eq 1223) {
        $message = '管理员授权已取消，控制中心没有启动。'
    }
    Show-LauncherError -Message $message
    exit 1
}
