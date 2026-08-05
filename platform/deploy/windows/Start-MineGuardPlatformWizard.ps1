[CmdletBinding()]
param(
    [string] $InstallRoot,
    [switch] $SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-WindowsCommandLineArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object -TypeName System.Text.StringBuilder
    [void]$builder.Append([char]'"')
    $backslashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashCount += 1
            continue
        }
        if ($character -eq [char]'"') {
            [void]$builder.Append([char]'\', (($backslashCount * 2) + 1))
            [void]$builder.Append([char]'"')
            $backslashCount = 0
            continue
        }
        if ($backslashCount -gt 0) {
            [void]$builder.Append([char]'\', $backslashCount)
            $backslashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashCount -gt 0) {
        [void]$builder.Append([char]'\', ($backslashCount * 2))
    }
    [void]$builder.Append([char]'"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param([Parameter(Mandatory = $true)] [object[]] $Arguments)
    return (@(foreach ($argument in $Arguments) {
                if ($null -eq $argument) {
                    throw '拒绝把 null 作为原生命令参数。'
                }
                ConvertTo-WindowsCommandLineArgument -Value ([string]$argument)
            }) -join ' ')
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-FatalMessage {
    param([string] $Message)
    [void][System.Windows.Forms.MessageBox]::Show(
        $Message,
        'MineGuard Platform 启动向导',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    $versionMessage = (
        '当前是 Windows PowerShell {0}。MineGuard 需要 Windows PowerShell 5.1。' +
        "`r`n请先离线安装 WMF 5.1、重启服务器，再运行本向导。"
    ) -f $PSVersionTable.PSVersion.ToString()
    Show-FatalMessage $versionMessage
    exit 1
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    Show-FatalMessage '无法确定向导脚本路径；请从已安装的 service 目录运行。'
    exit 1
}
$scriptPath = [System.IO.Path]::GetFullPath($scriptPath)
$scriptDirectory = Split-Path -Parent $scriptPath
if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Split-Path -Parent $scriptDirectory
}
try {
    $InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
} catch {
    Show-FatalMessage "安装目录无效：$($_.Exception.Message)"
    exit 1
}
if ($InstallRoot -notmatch '^[A-Za-z]:\\' -or
    [System.IO.Path]::GetPathRoot($InstallRoot).TrimEnd('\') -eq
        $InstallRoot.TrimEnd('\')) {
    Show-FatalMessage '安装目录必须是本机磁盘上的 X:\... 完整路径，且不能是磁盘根目录。'
    exit 1
}

$windowsPowerShell = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($SelfTest) {
    $requiredNames = @(
        'Set-MineGuardPlatformConfiguration.ps1',
        'Start-MineGuardPlatform.ps1',
        'Resolve-MineGuardPlatformExecutable.ps1'
    )
    $missingNames = @($requiredNames | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path $scriptDirectory $_) `
                -PathType Leaf)
        })
    if ($missingNames.Count -gt 0) {
        throw ('控制中心自检缺少文件：' + ($missingNames -join '、'))
    }
    [ordered]@{
        status = 'ok'
        component = 'mineguard-platform-control-center'
        powershell = $PSVersionTable.PSVersion.ToString()
        installRoot = $InstallRoot
        guiMode = 'windows-forms-ps51'
    } | ConvertTo-Json -Compress | Write-Output
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
    -ArgumentList $identity
$isAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdministrator) {
    try {
        $elevationArguments = Join-NativeArguments -Arguments @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA',
            '-File', $scriptPath, '-InstallRoot', $InstallRoot
        )
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $windowsPowerShell
        $startInfo.Arguments = $elevationArguments
        $startInfo.UseShellExecute = $true
        $startInfo.Verb = 'runas'
        [void][System.Diagnostics.Process]::Start($startInfo)
    } catch {
        Show-FatalMessage (
            '首次配置需要管理员权限。UAC 提权未完成：' +
            $_.Exception.Message
        )
        exit 1
    }
    exit 0
}

$configScript = Join-Path $scriptDirectory `
    'Set-MineGuardPlatformConfiguration.ps1'
$startScript = Join-Path $scriptDirectory 'Start-MineGuardPlatform.ps1'
$resolverScript = Join-Path $scriptDirectory `
    'Resolve-MineGuardPlatformExecutable.ps1'
foreach ($requiredPath in @($configScript, $startScript, $resolverScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Show-FatalMessage "安装不完整，缺少文件：$requiredPath"
        exit 1
    }
}

if (-not ('MineGuardGuiProcessCapture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;

public sealed class MineGuardGuiProcessCapture : IDisposable
{
    public readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
    public Process Process { get; private set; }

    public void Start(ProcessStartInfo startInfo)
    {
        Process = new Process();
        Process.StartInfo = startInfo;
        Process.OutputDataReceived += OnOutput;
        Process.ErrorDataReceived += OnError;
        if (!Process.Start())
            throw new InvalidOperationException("process start returned false");
        Process.BeginOutputReadLine();
        Process.BeginErrorReadLine();
    }

    private void OnOutput(object sender, DataReceivedEventArgs args)
    {
        if (args.Data != null) Lines.Enqueue(args.Data);
    }

    private void OnError(object sender, DataReceivedEventArgs args)
    {
        if (args.Data != null) Lines.Enqueue("[错误] " + args.Data);
    }

    public void Dispose()
    {
        if (Process == null) return;
        Process.OutputDataReceived -= OnOutput;
        Process.ErrorDataReceived -= OnError;
        Process.Dispose();
        Process = null;
    }
}
'@
}

[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$normalFont = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
$smallFont = New-Object System.Drawing.Font('Microsoft YaHei UI', 8)
$titleFont = New-Object System.Drawing.Font(
    'Microsoft YaHei UI', 17, [System.Drawing.FontStyle]::Bold
)
$sectionFont = New-Object System.Drawing.Font(
    'Microsoft YaHei UI', 10, [System.Drawing.FontStyle]::Bold
)
$monoFont = New-Object System.Drawing.Font('Consolas', 9)
$green = [System.Drawing.Color]::FromArgb(24, 128, 72)
$amber = [System.Drawing.Color]::FromArgb(176, 104, 0)
$red = [System.Drawing.Color]::FromArgb(190, 45, 45)
$muted = [System.Drawing.Color]::FromArgb(90, 98, 108)

$form = New-Object System.Windows.Forms.Form
$form.Text = 'MineGuard Platform 首次配置与启动'
$form.ClientSize = New-Object System.Drawing.Size(870, 690)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(886, 728)
$form.Font = $normalFont
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

$title = New-Object System.Windows.Forms.Label
$title.Text = 'MineGuard Platform'
$title.Font = $titleFont
$title.Location = New-Object System.Drawing.Point(22, 14)
$title.Size = New-Object System.Drawing.Size(430, 37)
$form.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = '离线首次配置与启动向导（不会联网，不在命令行传递密码）'
$subtitle.ForeColor = $muted
$subtitle.Location = New-Object System.Drawing.Point(25, 51)
$subtitle.Size = New-Object System.Drawing.Size(650, 24)
$form.Controls.Add($subtitle)

$configurationBanner = New-Object System.Windows.Forms.Label
$configurationBanner.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$configurationBanner.Location = New-Object System.Drawing.Point(22, 78)
$configurationBanner.Size = New-Object System.Drawing.Size(826, 42)
$configurationBanner.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$configurationBanner.Padding = New-Object System.Windows.Forms.Padding(9, 0, 9, 0)
$form.Controls.Add($configurationBanner)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(22, 130)
$tabs.Size = New-Object System.Drawing.Size(826, 310)
$form.Controls.Add($tabs)

$demoTab = New-Object System.Windows.Forms.TabPage
$demoTab.Text = '本机展示（推荐先看）'
$demoTab.BackColor = [System.Drawing.Color]::White
$tabs.TabPages.Add($demoTab)

$demoHeading = New-Object System.Windows.Forms.Label
$demoHeading.Text = '一键生成演示数据、配置并启动'
$demoHeading.Font = $sectionFont
$demoHeading.Location = New-Object System.Drawing.Point(20, 18)
$demoHeading.Size = New-Object System.Drawing.Size(500, 24)
$demoTab.Controls.Add($demoHeading)

$demoDescription = New-Object System.Windows.Forms.Label
$demoDescription.Text = (
    '包含合成教学场景及太岳矿、梗阳矿 2026 年 7 月样表映射值。' +
    '数据只用于功能展示，不是企业报送或监管认定。'
)
$demoDescription.ForeColor = $muted
$demoDescription.Location = New-Object System.Drawing.Point(20, 48)
$demoDescription.Size = New-Object System.Drawing.Size(770, 42)
$demoTab.Controls.Add($demoDescription)

$monthLabel = New-Object System.Windows.Forms.Label
$monthLabel.Text = '演示截止月份'
$monthLabel.Location = New-Object System.Drawing.Point(20, 101)
$monthLabel.Size = New-Object System.Drawing.Size(105, 25)
$monthLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$demoTab.Controls.Add($monthLabel)

$monthPicker = New-Object System.Windows.Forms.DateTimePicker
$monthPicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
$monthPicker.CustomFormat = 'yyyy 年 MM 月'
$monthPicker.ShowUpDown = $true
$monthPicker.MinDate = [DateTime]'2026-07-01'
$monthPicker.MaxDate = [DateTime]'2100-12-01'
$monthPicker.Value = [DateTime]'2026-07-01'
$monthPicker.Location = New-Object System.Drawing.Point(132, 101)
$monthPicker.Size = New-Object System.Drawing.Size(155, 25)
$demoTab.Controls.Add($monthPicker)

$demoPortLabel = New-Object System.Windows.Forms.Label
$demoPortLabel.Text = '本机端口'
$demoPortLabel.Location = New-Object System.Drawing.Point(330, 101)
$demoPortLabel.Size = New-Object System.Drawing.Size(80, 25)
$demoPortLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$demoTab.Controls.Add($demoPortLabel)

$demoPort = New-Object System.Windows.Forms.NumericUpDown
$demoPort.Minimum = 1
$demoPort.Maximum = 65535
$demoPort.Value = 8080
$demoPort.Location = New-Object System.Drawing.Point(412, 101)
$demoPort.Size = New-Object System.Drawing.Size(105, 25)
$demoTab.Controls.Add($demoPort)

$demoPathLabel = New-Object System.Windows.Forms.Label
$demoPathLabel.Text = '独立数据目录'
$demoPathLabel.Location = New-Object System.Drawing.Point(20, 139)
$demoPathLabel.Size = New-Object System.Drawing.Size(105, 25)
$demoPathLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$demoTab.Controls.Add($demoPathLabel)

$demoPath = New-Object System.Windows.Forms.TextBox
$demoPath.Text = Join-Path (Join-Path $InstallRoot 'state') 'local-demo'
$demoPath.ReadOnly = $true
$demoPath.BackColor = [System.Drawing.Color]::WhiteSmoke
$demoPath.Location = New-Object System.Drawing.Point(132, 139)
$demoPath.Size = New-Object System.Drawing.Size(650, 25)
$demoTab.Controls.Add($demoPath)

$demoWarning = New-Object System.Windows.Forms.CheckBox
$demoWarning.Text = '我知道这是本机 HTTP 演示，默认账号 admin、默认密码 123123123，不能用于正式运行。'
$demoWarning.ForeColor = $red
$demoWarning.Location = New-Object System.Drawing.Point(20, 178)
$demoWarning.Size = New-Object System.Drawing.Size(770, 28)
$demoTab.Controls.Add($demoWarning)

$demoButton = New-Object System.Windows.Forms.Button
$demoButton.Text = '一键准备并启动展示'
$demoButton.Location = New-Object System.Drawing.Point(20, 220)
$demoButton.Size = New-Object System.Drawing.Size(205, 42)
$demoButton.BackColor = $green
$demoButton.ForeColor = [System.Drawing.Color]::White
$demoButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$demoTab.Controls.Add($demoButton)

$demoHint = New-Object System.Windows.Forms.Label
$demoHint.Text = '完成后自动用 Edge/Chrome 打开；无需 clients.json。'
$demoHint.ForeColor = $muted
$demoHint.Location = New-Object System.Drawing.Point(242, 230)
$demoHint.Size = New-Object System.Drawing.Size(500, 25)
$demoTab.Controls.Add($demoHint)

$formalTab = New-Object System.Windows.Forms.TabPage
$formalTab.Text = '正式内网配置'
$formalTab.BackColor = [System.Drawing.Color]::White
$tabs.TabPages.Add($formalTab)

function Add-FormalLabel {
    param([string] $Text, [int] $Y)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point(18, $Y)
    $label.Size = New-Object System.Drawing.Size(112, 25)
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $formalTab.Controls.Add($label)
}

Add-FormalLabel -Text 'clients.json' -Y 18
$clientsText = New-Object System.Windows.Forms.TextBox
$clientsText.Location = New-Object System.Drawing.Point(132, 18)
$clientsText.Size = New-Object System.Drawing.Size(558, 25)
$formalTab.Controls.Add($clientsText)
$clientsBrowse = New-Object System.Windows.Forms.Button
$clientsBrowse.Text = '选择...'
$clientsBrowse.Location = New-Object System.Drawing.Point(700, 16)
$clientsBrowse.Size = New-Object System.Drawing.Size(88, 29)
$formalTab.Controls.Add($clientsBrowse)

Add-FormalLabel -Text '状态数据目录' -Y 57
$formalState = New-Object System.Windows.Forms.TextBox
$formalState.Text = Join-Path $InstallRoot 'state'
$formalState.Location = New-Object System.Drawing.Point(132, 57)
$formalState.Size = New-Object System.Drawing.Size(558, 25)
$formalTab.Controls.Add($formalState)
$stateBrowse = New-Object System.Windows.Forms.Button
$stateBrowse.Text = '选择...'
$stateBrowse.Location = New-Object System.Drawing.Point(700, 55)
$stateBrowse.Size = New-Object System.Drawing.Size(88, 29)
$formalTab.Controls.Add($stateBrowse)

Add-FormalLabel -Text '本机端口' -Y 96
$portInput = New-Object System.Windows.Forms.NumericUpDown
$portInput.Minimum = 1
$portInput.Maximum = 65535
$portInput.Value = 8080
$portInput.Location = New-Object System.Drawing.Point(132, 96)
$portInput.Size = New-Object System.Drawing.Size(105, 25)
$formalTab.Controls.Add($portInput)

$adminLabel = New-Object System.Windows.Forms.Label
$adminLabel.Text = '管理员用户名'
$adminLabel.Location = New-Object System.Drawing.Point(273, 96)
$adminLabel.Size = New-Object System.Drawing.Size(105, 25)
$adminLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$formalTab.Controls.Add($adminLabel)
$adminInput = New-Object System.Windows.Forms.TextBox
$adminInput.Text = 'admin'
$adminInput.Location = New-Object System.Drawing.Point(382, 96)
$adminInput.Size = New-Object System.Drawing.Size(210, 25)
$formalTab.Controls.Add($adminInput)

Add-FormalLabel -Text '管理员密码' -Y 135
$passwordInput = New-Object System.Windows.Forms.TextBox
$passwordInput.UseSystemPasswordChar = $true
$passwordInput.Location = New-Object System.Drawing.Point(132, 135)
$passwordInput.Size = New-Object System.Drawing.Size(230, 25)
$formalTab.Controls.Add($passwordInput)

$confirmLabel = New-Object System.Windows.Forms.Label
$confirmLabel.Text = '再次输入'
$confirmLabel.Location = New-Object System.Drawing.Point(382, 135)
$confirmLabel.Size = New-Object System.Drawing.Size(75, 25)
$confirmLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$formalTab.Controls.Add($confirmLabel)
$confirmInput = New-Object System.Windows.Forms.TextBox
$confirmInput.UseSystemPasswordChar = $true
$confirmInput.Location = New-Object System.Drawing.Point(460, 135)
$confirmInput.Size = New-Object System.Drawing.Size(230, 25)
$formalTab.Controls.Add($confirmInput)

$passwordHint = New-Object System.Windows.Forms.Label
$passwordHint.Text = '至少 12 位，并同时包含字母和数字；正式模式禁止使用 123123123。'
$passwordHint.ForeColor = $muted
$passwordHint.Location = New-Object System.Drawing.Point(132, 166)
$passwordHint.Size = New-Object System.Drawing.Size(560, 23)
$formalTab.Controls.Add($passwordHint)

Add-FormalLabel -Text '单位 HTTPS 地址' -Y 190
$formalAccessUrl = New-Object System.Windows.Forms.TextBox
$formalAccessUrl.Location = New-Object System.Drawing.Point(132, 190)
$formalAccessUrl.Size = New-Object System.Drawing.Size(558, 25)
$formalAccessUrl.Text = ''
$formalTab.Controls.Add($formalAccessUrl)

$formalAccessHint = New-Object System.Windows.Forms.Label
$formalAccessHint.Text = '可暂不填写；配置好 HTTPS 反向代理后再粘贴领导端地址。'
$formalAccessHint.ForeColor = $muted
$formalAccessHint.Location = New-Object System.Drawing.Point(700, 187)
$formalAccessHint.Size = New-Object System.Drawing.Size(90, 44)
$formalTab.Controls.Add($formalAccessHint)

$formalButton = New-Object System.Windows.Forms.Button
$formalButton.Text = '保存正式配置并启动'
$formalButton.Location = New-Object System.Drawing.Point(20, 232)
$formalButton.Size = New-Object System.Drawing.Size(205, 42)
$formalButton.BackColor = [System.Drawing.Color]::FromArgb(34, 91, 158)
$formalButton.ForeColor = [System.Drawing.Color]::White
$formalButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$formalTab.Controls.Add($formalButton)

$formalHint = New-Object System.Windows.Forms.Label
$formalHint.Text = (
    '正式配置启用 Secure Cookie，只监听 127.0.0.1；请通过单位批准的 HTTPS 反向代理访问。'
)
$formalHint.ForeColor = $amber
$formalHint.Location = New-Object System.Drawing.Point(242, 229)
$formalHint.Size = New-Object System.Drawing.Size(545, 48)
$formalTab.Controls.Add($formalHint)

$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(22, 450)
$buttonPanel.Size = New-Object System.Drawing.Size(826, 42)
$form.Controls.Add($buttonPanel)

$startCurrentButton = New-Object System.Windows.Forms.Button
$startCurrentButton.Text = '启动当前配置'
$startCurrentButton.Location = New-Object System.Drawing.Point(0, 0)
$startCurrentButton.Size = New-Object System.Drawing.Size(145, 34)
$buttonPanel.Controls.Add($startCurrentButton)

$openButton = New-Object System.Windows.Forms.Button
$openButton.Text = '打开领导端页面'
$openButton.Location = New-Object System.Drawing.Point(154, 0)
$openButton.Size = New-Object System.Drawing.Size(145, 34)
$buttonPanel.Controls.Add($openButton)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = '停止本次启动'
$stopButton.Location = New-Object System.Drawing.Point(308, 0)
$stopButton.Size = New-Object System.Drawing.Size(145, 34)
$stopButton.Enabled = $false
$buttonPanel.Controls.Add($stopButton)

$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = '刷新检测'
$refreshButton.Location = New-Object System.Drawing.Point(462, 0)
$refreshButton.Size = New-Object System.Drawing.Size(115, 34)
$buttonPanel.Controls.Add($refreshButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = '正在检测安装状态...'
$statusLabel.Location = New-Object System.Drawing.Point(585, 3)
$statusLabel.Size = New-Object System.Drawing.Size(238, 29)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$buttonPanel.Controls.Add($statusLabel)

$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = '运行状态（出错时可拍照这一栏）'
$logLabel.Font = $sectionFont
$logLabel.Location = New-Object System.Drawing.Point(22, 496)
$logLabel.Size = New-Object System.Drawing.Size(400, 24)
$form.Controls.Add($logLabel)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Location = New-Object System.Drawing.Point(22, 523)
$logBox.Size = New-Object System.Drawing.Size(826, 140)
$logBox.ReadOnly = $true
$logBox.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 251)
$logBox.Font = $monoFont
$logBox.DetectUrls = $false
$form.Controls.Add($logBox)

$script:ConfigurationState = $null
$script:OperationPowerShell = $null
$script:OperationAsync = $null
$script:OperationPurpose = ''
$script:OperationStreamOffsets = @{}
$script:OperationSecureString = $null
$script:ServerCapture = $null
$script:ServerProcess = $null
$script:ServerPort = 8080
$script:ServerMode = ''
$script:BrowserOpened = $false
$script:HealthConfirmed = $false
$script:ClearBootstrapAttempted = $false
$script:LastHealthCheck = [DateTime]::MinValue
$script:ServerStartedAt = [DateTime]::MinValue
$script:HealthDelayReported = $false
$script:StopRequested = $false
$script:ClosingApproved = $false
$script:LogFilePath = Join-Path (Join-Path $InstallRoot 'logs') (
    'control-center-{0:yyyyMMdd-HHmmss}-{1}.log' -f `
        (Get-Date), [Guid]::NewGuid().ToString('N').Substring(0, 8)
)
$script:LogEncoding = New-Object System.Text.UTF8Encoding($false)

function Add-Log {
    param([string] $Message, [string] $Level = 'info')
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $color = [System.Drawing.Color]::FromArgb(42, 48, 56)
    if ($Level -eq 'error') { $color = $red }
    elseif ($Level -eq 'warning') { $color = $amber }
    elseif ($Level -eq 'success') { $color = $green }
    $logBox.SelectionStart = $logBox.TextLength
    $logBox.SelectionLength = 0
    $logBox.SelectionColor = $color
    $renderedLine = '[{0:yyyy-MM-dd HH:mm:ss}] {1}' -f (Get-Date), $Message
    $logBox.AppendText($renderedLine + "`r`n")
    $logBox.SelectionColor = $logBox.ForeColor
    $logBox.ScrollToCaret()
    try {
        $logDirectory = Split-Path -Parent $script:LogFilePath
        if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
            [void][IO.Directory]::CreateDirectory($logDirectory)
        }
        [IO.File]::AppendAllText(
            $script:LogFilePath,
            $renderedLine + [Environment]::NewLine,
            $script:LogEncoding
        )
    } catch {
        # Logging must never conceal the actionable message already visible in
        # the control center.  The protected setup/ACL scripts remain the
        # authority for whether an operation may proceed.
    }
}

function Set-BusyState {
    param([bool] $Busy)
    $demoButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'pristine')
    $formalButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'pristine')
    $startCurrentButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -in @('demo', 'formal'))
    $openButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -in @('demo', 'formal'))
    $clientsBrowse.Enabled = -not $Busy
    $stateBrowse.Enabled = -not $Busy
    $monthPicker.Enabled = -not $Busy
    $demoPort.Enabled = -not $Busy
    $clientsText.Enabled = -not $Busy
    $formalState.Enabled = -not $Busy
    $portInput.Enabled = -not $Busy
    $adminInput.Enabled = -not $Busy
    $passwordInput.Enabled = -not $Busy
    $confirmInput.Enabled = -not $Busy
    $refreshButton.Enabled = -not $Busy
}

function Test-StateDirectoryHasContent {
    param([string] $StateDirectory)
    try {
        if ([string]::IsNullOrWhiteSpace($StateDirectory) -or
            -not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
            return $false
        }
        return $null -ne (Get-ChildItem -LiteralPath $StateDirectory -Force |
            Select-Object -First 1)
    } catch {
        # An unreadable or malformed existing path must never be treated as a
        # blank installation that the first-run wizard may overwrite.
        return $true
    }
}

function Get-ConfigurationState {
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    $clientsPath = Join-Path (Join-Path $InstallRoot 'config') 'clients.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '未找到 settings.json；安装可能不完整，已禁止写入。'
            port = 8080
            stateDirectory = ''
        }
    }
    try {
        $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $expectedNames = @(
            'schemaVersion', 'host', 'port', 'stateDirectory', 'clientsFile',
            'adminUsername', 'secureCookie', 'allowDemoDefaultPassword',
            'platformSystemId', 'platformPartyId', 'platformKeyId'
        )
        $actualNames = @($settings.PSObject.Properties.Name)
        if ($actualNames.Count -ne $expectedNames.Count -or
            @($actualNames | Where-Object { $expectedNames -notcontains $_ }).Count -gt 0) {
            throw '配置字段集合不符合已知格式'
        }
        foreach ($requiredName in $expectedNames) {
            $property = $settings.PSObject.Properties[$requiredName]
            if ($null -eq $property -or $null -eq $property.Value) {
                throw "缺少字段 $requiredName"
            }
        }
        $integerTypeNames = @(
            'Int16', 'Int32', 'Int64', 'UInt16', 'UInt32', 'UInt64'
        )
        if ($settings.schemaVersion.GetType().Name -notin $integerTypeNames -or
            [int]$settings.schemaVersion -ne 1 -or
            [string]$settings.host -ne '127.0.0.1' -or
            $settings.port.GetType().Name -notin $integerTypeNames -or
            $settings.stateDirectory -isnot [string] -or
            $settings.clientsFile -isnot [string] -or
            $settings.adminUsername -isnot [string] -or
            $settings.platformSystemId -isnot [string] -or
            $settings.platformPartyId -isnot [string] -or
            $settings.platformKeyId -isnot [string] -or
            $settings.secureCookie -isnot [bool] -or
            $settings.allowDemoDefaultPassword -isnot [bool] -or
            [string]::IsNullOrWhiteSpace([string]$settings.adminUsername) -or
            [string]$settings.platformSystemId -notmatch `
                '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
            [string]$settings.platformPartyId -notmatch `
                '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
            [string]$settings.platformKeyId -notmatch `
                '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
            [string]$settings.stateDirectory -notmatch '^[A-Za-z]:\\') {
            throw '配置版本、监听地址或安全开关不符合已知格式'
        }
        $port = [int]$settings.port
        $stateDirectory = [string]$settings.stateDirectory
        $clientsFile = [string]$settings.clientsFile
        $allowDemo = [bool]$settings.allowDemoDefaultPassword
        $secureCookie = [bool]$settings.secureCookie
    } catch {
        return [pscustomobject]@{
            kind = 'blocked'
            message = 'settings.json 无法安全读取；已禁止覆盖，请由管理员检查。'
            port = 8080
            stateDirectory = ''
        }
    }
    if ($port -lt 1 -or $port -gt 65535) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '现有配置端口无效；已禁止覆盖。'
            port = 8080
            stateDirectory = $stateDirectory
        }
    }
    $hasState = Test-StateDirectoryHasContent -StateDirectory $stateDirectory
    if (-not [string]::IsNullOrWhiteSpace($clientsFile) -or
        (Test-Path -LiteralPath $clientsPath -PathType Leaf)) {
        return [pscustomobject]@{
            kind = 'formal'
            message = '已检测到正式配置。为防止误覆盖，只允许启动或打开页面。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    if ($allowDemo -or -not $secureCookie) {
        return [pscustomobject]@{
            kind = 'demo'
            message = '已检测到本机演示配置。可直接启动，不会重复改写配置。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    if ($hasState) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '发现状态数据，但配置既不是正式模式也不是演示模式；已禁止覆盖。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    $defaultStateDirectory = Join-Path $InstallRoot 'state'
    $isInstallerPlaceholder = (
        [string]$settings.adminUsername -eq 'admin' -and
        $stateDirectory.Equals(
            $defaultStateDirectory,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        [string]$settings.platformSystemId -eq 'mineguard-government' -and
        [string]$settings.platformPartyId -eq 'regulator-government' -and
        [string]$settings.platformKeyId -eq 'regulator-key-v2'
    )
    if (-not $isInstallerPlaceholder) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '现有 settings.json 不是安装器的完整首次配置占位值；已禁止覆盖。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    return [pscustomobject]@{
        kind = 'pristine'
        message = '尚未首次配置：可选择“本机展示”或“正式内网配置”。'
        port = $port
        stateDirectory = $stateDirectory
    }
}

function Refresh-ConfigurationState {
    $script:ConfigurationState = Get-ConfigurationState
    $script:ServerPort = [int]$script:ConfigurationState.port
    $configurationBanner.Text = '  ' + $script:ConfigurationState.message
    switch ($script:ConfigurationState.kind) {
        'pristine' {
            $configurationBanner.BackColor = [System.Drawing.Color]::FromArgb(235, 246, 239)
            $configurationBanner.ForeColor = $green
        }
        'demo' {
            $tabs.SelectedTab = $demoTab
            $configurationBanner.BackColor = [System.Drawing.Color]::FromArgb(255, 246, 226)
            $configurationBanner.ForeColor = $amber
        }
        'formal' {
            $tabs.SelectedTab = $formalTab
            $configurationBanner.BackColor = [System.Drawing.Color]::FromArgb(232, 241, 252)
            $configurationBanner.ForeColor = [System.Drawing.Color]::FromArgb(34, 91, 158)
        }
        default {
            $configurationBanner.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 235)
            $configurationBanner.ForeColor = $red
        }
    }
    Set-BusyState -Busy ($null -ne $script:OperationPowerShell)
}

function Get-ModernBrowserPath {
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $candidates += Join-Path ${env:ProgramFiles(x86)} `
            'Microsoft\Edge\Application\msedge.exe'
        $candidates += Join-Path ${env:ProgramFiles(x86)} `
            'Google\Chrome\Application\chrome.exe'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates += Join-Path $env:ProgramFiles `
            'Microsoft\Edge\Application\msedge.exe'
        $candidates += Join-Path $env:ProgramFiles `
            'Google\Chrome\Application\chrome.exe'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates += Join-Path $env:LOCALAPPDATA `
            'Microsoft\Edge\Application\msedge.exe'
        $candidates += Join-Path $env:LOCALAPPDATA `
            'Google\Chrome\Application\chrome.exe'
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

function Open-LeaderPage {
    $localUrl = 'http://127.0.0.1:{0}/' -f $script:ServerPort
    $url = $localUrl
    if ($script:ConfigurationState.kind -eq 'formal') {
        $candidate = $formalAccessUrl.Text.Trim()
        $parsed = $null
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            Add-Log '正式模式不会打开本机 HTTP。请先配置单位 HTTPS 反向代理，再填写访问地址。' 'warning'
            [void][System.Windows.Forms.MessageBox]::Show(
                '正式模式启用了安全 Cookie，不能直接用本机 HTTP 登录。' +
                "`r`n`r`n请先配置单位批准的 HTTPS 反向代理，再在“单位 HTTPS 地址”中粘贴领导端地址。",
                '需要 HTTPS 地址',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$parsed) -or
            $parsed.Scheme -ne 'https' -or
            [string]::IsNullOrWhiteSpace($parsed.Host) -or
            -not [string]::IsNullOrWhiteSpace($parsed.UserInfo) -or
            -not [string]::IsNullOrWhiteSpace($parsed.Query) -or
            -not [string]::IsNullOrWhiteSpace($parsed.Fragment)) {
            Add-Log '单位 HTTPS 地址无效；必须是无账号口令、查询参数或片段的 https:// 完整地址。' 'error'
            return
        }
        $url = $parsed.AbsoluteUri
    }
    if (-not (Test-MineGuardHealth -Port $script:ServerPort)) {
        Add-Log "Platform 尚未通过健康检查，暂不打开页面：$localUrl" 'warning'
        [void][System.Windows.Forms.MessageBox]::Show(
            'Platform 还没有正常启动。请先点击“启动当前配置”，并等待右下角显示“服务正常”。',
            '服务尚未就绪',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }
    $browser = Get-ModernBrowserPath
    if ($null -eq $browser) {
        Add-Log (
            "未找到 Edge 或 Chrome。服务地址是 $url；请离线安装现代浏览器后再打开。"
        ) 'warning'
        [void][System.Windows.Forms.MessageBox]::Show(
            "服务已启动，但没有找到 Edge 或 Chrome。`r`n`r`n地址：$url`r`n`r`n请不要使用 Internet Explorer。",
            '需要现代浏览器',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    try {
        $browserStart = New-Object System.Diagnostics.ProcessStartInfo
        $browserStart.FileName = $browser
        $browserStart.Arguments = ConvertTo-WindowsCommandLineArgument -Value $url
        $browserStart.UseShellExecute = $false
        [void][System.Diagnostics.Process]::Start($browserStart)
        $script:BrowserOpened = $true
        Add-Log "已用现代浏览器打开 $url" 'success'
    } catch {
        Add-Log "浏览器启动失败：$($_.Exception.Message)" 'error'
    }
}

function Test-MineGuardHealth {
    param([int] $Port)
    $response = $null
    $reader = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create(
            ('http://127.0.0.1:{0}/healthz' -f $Port)
        )
        $request.Proxy = $null
        $request.Timeout = 900
        $request.ReadWriteTimeout = 900
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        return ([int]$response.StatusCode -eq 200 -and
            $body -match '"service"\s*:\s*"mineguard-v2"' -and
            $body -match '"status"\s*:\s*"ok"')
    } catch {
        return $false
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

function New-SecureStringFromTextBox {
    param([System.Windows.Forms.TextBox] $TextBox)
    $secure = New-Object Security.SecureString
    foreach ($character in $TextBox.Text.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    return $secure
}

function Start-ConfigurationOperation {
    param(
        [ValidateSet('demo', 'formal')] [string] $Mode,
        [string] $StateDirectory,
        [int] $Port,
        [string] $ClientsFile,
        [string] $AdminUsername,
        [Security.SecureString] $AdminPassword,
        [string] $ThroughMonth
    )
    if ($null -ne $script:OperationPowerShell) {
        Add-Log '另一项配置操作仍在进行，请稍候。' 'warning'
        if ($null -ne $AdminPassword) { $AdminPassword.Dispose() }
        return
    }
    Refresh-ConfigurationState
    if ($script:ConfigurationState.kind -ne 'pristine') {
        Add-Log '检测到已有配置或状态数据；为防止覆盖，已取消首次配置。' 'error'
        if ($null -ne $AdminPassword) { $AdminPassword.Dispose() }
        return
    }

    $worker = @'
param(
    [string] $Mode,
    [string] $InstallRoot,
    [string] $ResolverScript,
    [string] $ConfigScript,
    [string] $StateDirectory,
    [int] $Port,
    [string] $ClientsFile,
    [string] $AdminUsername,
    [Security.SecureString] $AdminPassword,
    [string] $ThroughMonth
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. $ResolverScript
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
if ($Mode -eq 'demo') {
    Write-Information '正在生成或核验演示数据，请稍候...' -InformationAction Continue
    $seedArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
        'seed-v2-demo', '--state-directory', $StateDirectory,
        '--through-month', $ThroughMonth
    )
    & $runtime.filePath @seedArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "演示数据生成失败，运行时退出码：$LASTEXITCODE"
    }
    Write-Information '演示数据准备完成，正在应用受保护的本机配置...' -InformationAction Continue
    $parameters = @{
        InstallRoot = $InstallRoot
        StateDirectory = $StateDirectory
        Port = $Port
        AdminUsername = 'admin'
        DemoWithoutClientRegistry = $true
        AllowDemoDefaultPassword = $true
        HttpOnlyDemo = $true
        NonInteractive = $true
    }
    & $ConfigScript @parameters
} else {
    Write-Information '正在校验 clients.json 并原子保存正式配置...' -InformationAction Continue
    $parameters = @{
        InstallRoot = $InstallRoot
        StateDirectory = $StateDirectory
        Port = $Port
        ClientsFile = $ClientsFile
        AdminUsername = $AdminUsername
        AdminPassword = $AdminPassword
        NonInteractive = $true
    }
    & $ConfigScript @parameters
}
Write-Information '受保护的配置事务已完成。' -InformationAction Continue
'@

    $script:OperationPowerShell = [System.Management.Automation.PowerShell]::Create()
    [void]$script:OperationPowerShell.AddScript($worker)
    foreach ($argument in @(
        $Mode, $InstallRoot, $resolverScript, $configScript, $StateDirectory,
        $Port, $ClientsFile, $AdminUsername, $AdminPassword, $ThroughMonth
    )) {
        [void]$script:OperationPowerShell.AddArgument($argument)
    }
    $script:OperationPurpose = $Mode
    $script:OperationSecureString = $AdminPassword
    $script:OperationStreamOffsets = @{
        Error = 0; Warning = 0; Information = 0; Verbose = 0
    }
    try {
        $script:OperationAsync = $script:OperationPowerShell.BeginInvoke()
        Set-BusyState -Busy $true
        $statusLabel.Text = '正在配置...'
        $operationMessage = if ($Mode -eq 'demo') {
            '开始一键准备本机展示。'
        } else {
            '开始正式首次配置；密码不会显示在日志或命令行。'
        }
        Add-Log $operationMessage
    } catch {
        $script:OperationPowerShell.Dispose()
        $script:OperationPowerShell = $null
        $script:OperationAsync = $null
        if ($null -ne $script:OperationSecureString) {
            $script:OperationSecureString.Dispose()
            $script:OperationSecureString = $null
        }
        Set-BusyState -Busy $false
        Add-Log "无法启动配置操作：$($_.Exception.Message)" 'error'
    }
}

function Copy-OperationStreams {
    if ($null -eq $script:OperationPowerShell) { return }
    foreach ($streamName in @('Information', 'Warning', 'Verbose', 'Error')) {
        $stream = $script:OperationPowerShell.Streams.$streamName
        $offset = [int]$script:OperationStreamOffsets[$streamName]
        while ($offset -lt $stream.Count) {
            $record = $stream[$offset]
            $text = if ($streamName -eq 'Information') {
                [string]$record.MessageData
            } elseif ($streamName -eq 'Error') {
                [string]$record.Exception.Message
            } else {
                [string]$record.Message
            }
            $level = if ($streamName -eq 'Error') { 'error' }
            elseif ($streamName -eq 'Warning') { 'warning' }
            else { 'info' }
            Add-Log $text $level
            $offset++
        }
        $script:OperationStreamOffsets[$streamName] = $offset
    }
}

function Get-CurrentSettings {
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw '当前没有 settings.json。请先完成首次配置。'
    }
    try {
        return Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw "settings.json 无法解析：$($_.Exception.Message)"
    }
}

function Start-ConfiguredServer {
    param([ValidateSet('demo', 'formal', 'existing')] [string] $Mode)
    if ($null -ne $script:ServerProcess -and
        -not $script:ServerProcess.HasExited) {
        Add-Log '本向导已经启动了 Platform，无需重复启动。' 'warning'
        return
    }
    $service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Add-Log '检测到 MineGuardPlatform Windows 服务正在运行；请直接打开页面，不再启动第二份前台进程。' 'warning'
        Refresh-ConfigurationState
        return
    }
    try {
        $settings = Get-CurrentSettings
        $script:ServerPort = [int]$settings.port
        if ($script:ServerPort -lt 1 -or $script:ServerPort -gt 65535) {
            throw '配置中的端口不在 1-65535 范围。'
        }
        $arguments = Join-NativeArguments -Arguments @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $startScript, '-InstallRoot', $InstallRoot
        )
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $windowsPowerShell
        $startInfo.Arguments = $arguments
        $startInfo.WorkingDirectory = $InstallRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        try {
            $encoding = New-Object System.Text.UTF8Encoding($false)
            $startInfo.StandardOutputEncoding = $encoding
            $startInfo.StandardErrorEncoding = $encoding
        } catch { }
        $capture = New-Object MineGuardGuiProcessCapture
        $capture.Start($startInfo)
        $script:ServerCapture = $capture
        $script:ServerProcess = $capture.Process
        $script:ServerMode = if ($Mode -eq 'existing') {
            [string]$script:ConfigurationState.kind
        } else { $Mode }
        $script:BrowserOpened = $false
        $script:HealthConfirmed = $false
        $script:ClearBootstrapAttempted = $false
        $script:LastHealthCheck = [DateTime]::MinValue
        $script:ServerStartedAt = Get-Date
        $script:HealthDelayReported = $false
        $script:StopRequested = $false
        $stopButton.Enabled = $true
        $statusLabel.Text = '正在启动服务...'
        Add-Log (
            'Platform 前台服务已启动（进程号 {0}），正在等待健康检查。' -f
            $script:ServerProcess.Id
        )
    } catch {
        Add-Log "启动失败：$($_.Exception.Message)" 'error'
        $statusLabel.Text = '启动失败'
        $statusLabel.ForeColor = $red
    }
}

function Clear-BootstrapPasswordIfPresent {
    if ($script:ClearBootstrapAttempted) { return }
    $script:ClearBootstrapAttempted = $true
    $bootstrapPath = Join-Path (Join-Path $InstallRoot 'config') `
        'bootstrap-admin-password.txt'
    if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) { return }
    $clearPowerShell = $null
    try {
        $clearPowerShell = [System.Management.Automation.PowerShell]::Create()
        [void]$clearPowerShell.AddCommand($configScript)
        [void]$clearPowerShell.AddParameter('InstallRoot', $InstallRoot)
        [void]$clearPowerShell.AddParameter('ClearBootstrapPassword')
        $result = $clearPowerShell.Invoke()
        if ($clearPowerShell.HadErrors) {
            throw [string]$clearPowerShell.Streams.Error[0]
        }
        Add-Log '首次管理员明文密码文件已由受保护脚本清除。' 'success'
    } catch {
        Add-Log (
            '服务已启动，但首次密码文件自动清除失败。请不要关闭本窗口，并联系管理员处理：' +
            $_.Exception.Message
        ) 'error'
    } finally {
        if ($null -ne $clearPowerShell) { $clearPowerShell.Dispose() }
    }
}

function Stop-StartedServer {
    if ($null -eq $script:ServerProcess -or $script:ServerProcess.HasExited) {
        Add-Log '本向导没有正在运行的 Platform 前台服务。' 'warning'
        $stopButton.Enabled = $false
        return $true
    }
    try {
        $script:StopRequested = $true
        if ($script:ServerProcess.CloseMainWindow() -and
            $script:ServerProcess.WaitForExit(5000)) {
            Add-Log 'Platform 已响应正常关闭请求。' 'success'
            $statusLabel.Text = '已停止'
            $statusLabel.ForeColor = $muted
            return $true
        }
        $pidText = [string]$script:ServerProcess.Id
        $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
        foreach ($force in @($false, $true)) {
            if ($script:ServerProcess.HasExited) { break }
            if ($force) {
                Add-Log '正常停止未在限定时间内完成，正在执行强制兜底；下次启动会自动核验数据库。' 'warning'
            }
            $arguments = @('/PID', $pidText, '/T')
            if ($force) { $arguments += '/F' }
            $stopInfo = New-Object System.Diagnostics.ProcessStartInfo
            $stopInfo.FileName = $taskKill
            $stopInfo.Arguments = Join-NativeArguments -Arguments $arguments
            $stopInfo.UseShellExecute = $false
            $stopInfo.CreateNoWindow = $true
            $stopInfo.RedirectStandardOutput = $true
            $stopInfo.RedirectStandardError = $true
            $stopProcess = [System.Diagnostics.Process]::Start($stopInfo)
            if ($null -eq $stopProcess -or -not $stopProcess.WaitForExit(10000)) {
                if ($null -ne $stopProcess) {
                    try { $stopProcess.Kill() } catch { }
                    $stopProcess.Dispose()
                }
                throw 'Windows 停止命令在 10 秒内没有返回。'
            }
            $taskKillExitCode = $stopProcess.ExitCode
            $taskKillError = $stopProcess.StandardError.ReadToEnd().Trim()
            $stopProcess.Dispose()
            [void]$script:ServerProcess.WaitForExit(5000)
            if (-not $script:ServerProcess.HasExited -and
                $taskKillExitCode -ne 0 -and -not $force) {
                Add-Log "正常停止命令未成功（退出码 $taskKillExitCode）：$taskKillError" 'warning'
            }
        }
        if (-not $script:ServerProcess.HasExited) {
            throw 'Platform 进程仍在运行；请不要重复启动，并联系管理员查看任务管理器。'
        }
        Add-Log '已确认本向导启动的 Platform 进程树停止。' 'success'
        $statusLabel.Text = '已停止'
        $statusLabel.ForeColor = $muted
        return $true
    } catch {
        $script:StopRequested = $false
        Add-Log "停止失败：$($_.Exception.Message)" 'error'
        $statusLabel.Text = '停止失败'
        $statusLabel.ForeColor = $red
        return $false
    }
}

$clientsBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = '选择单位批准的 clients.json'
        $dialog.Filter = 'JSON 文件 (clients.json)|*.json|所有文件|*.*'
        $dialog.CheckFileExists = $true
        $dialog.Multiselect = $false
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $clientsText.Text = $dialog.FileName
        }
        $dialog.Dispose()
    })

$stateBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = '选择 MineGuard 状态数据专用目录（本机固定 NTFS 磁盘）'
        $dialog.SelectedPath = $formalState.Text
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $formalState.Text = $dialog.SelectedPath
        }
        $dialog.Dispose()
    })

$demoButton.Add_Click({
        if (-not $demoWarning.Checked) {
            [void][System.Windows.Forms.MessageBox]::Show(
                '请先勾选红色确认项，明确本机演示的默认密码和使用边界。',
                '需要确认',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        $emptyPassword = New-Object Security.SecureString
        $emptyPassword.MakeReadOnly()
        $throughMonth = '{0:yyyy-MM-dd}' -f
            $monthPicker.Value.Date.AddMonths(1).AddDays(-1)
        Start-ConfigurationOperation -Mode demo `
            -StateDirectory $demoPath.Text -Port ([int]$demoPort.Value) `
            -ClientsFile '' `
            -AdminUsername 'admin' -AdminPassword $emptyPassword `
            -ThroughMonth $throughMonth
    })

$formalButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($clientsText.Text) -or
            -not (Test-Path -LiteralPath $clientsText.Text -PathType Leaf)) {
            Add-Log '请先选择实际存在、经批准的 clients.json。' 'error'
            return
        }
        if ([string]::IsNullOrWhiteSpace($formalState.Text)) {
            Add-Log '状态数据目录不能为空。' 'error'
            return
        }
        if ([string]::IsNullOrWhiteSpace($adminInput.Text) -or
            $adminInput.Text.Length -gt 128) {
            Add-Log '管理员用户名必须包含 1-128 个字符。' 'error'
            return
        }
        $passwordText = $passwordInput.Text
        $confirmText = $confirmInput.Text
        if ($passwordText -ne $confirmText) {
            Add-Log '两次输入的管理员密码不一致。' 'error'
            $passwordText = $null
            $confirmText = $null
            return
        }
        if ($passwordText.Length -lt 12 -or
            $passwordText -notmatch '[A-Za-z]' -or
            $passwordText -notmatch '[0-9]' -or
            $passwordText -eq '123123123') {
            Add-Log '正式管理员密码至少 12 位，并同时包含字母和数字，且不能使用演示默认密码。' 'error'
            $passwordText = $null
            $confirmText = $null
            return
        }
        $securePassword = New-SecureStringFromTextBox -TextBox $passwordInput
        $passwordInput.Clear()
        $confirmInput.Clear()
        $passwordText = $null
        $confirmText = $null
        Start-ConfigurationOperation -Mode formal `
            -StateDirectory $formalState.Text -Port ([int]$portInput.Value) `
            -ClientsFile $clientsText.Text -AdminUsername $adminInput.Text `
            -AdminPassword $securePassword -ThroughMonth '2026-07-31'
    })

$startCurrentButton.Add_Click({ Start-ConfiguredServer -Mode existing })
$openButton.Add_Click({ Open-LeaderPage })
$stopButton.Add_Click({ [void](Stop-StartedServer) })
$refreshButton.Add_Click({
        Refresh-ConfigurationState
        Add-Log $script:ConfigurationState.message
    })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
        if ($null -ne $script:OperationPowerShell) {
            Copy-OperationStreams
            if ($script:OperationAsync.IsCompleted) {
                $purpose = $script:OperationPurpose
                $operationFailed = $script:OperationPowerShell.HadErrors
                try {
                    $result = $script:OperationPowerShell.EndInvoke(
                        $script:OperationAsync
                    )
                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
                                Add-Log ([string]$item)
                            }
                        }
                    }
                } catch {
                    $operationFailed = $true
                    Add-Log $_.Exception.Message 'error'
                }
                Copy-OperationStreams
                $script:OperationPowerShell.Dispose()
                $script:OperationPowerShell = $null
                $script:OperationAsync = $null
                if ($null -ne $script:OperationSecureString) {
                    $script:OperationSecureString.Dispose()
                    $script:OperationSecureString = $null
                }
                $script:OperationPurpose = ''
                Refresh-ConfigurationState
                if ($operationFailed) {
                    $statusLabel.Text = '配置失败'
                    $statusLabel.ForeColor = $red
                    Add-Log '配置未完成。旧配置事务已由受保护脚本回滚；请按上方错误检查。' 'error'
                } else {
                    $statusLabel.Text = '配置完成，正在启动'
                    $statusLabel.ForeColor = $green
                    Add-Log '配置完成，准备启动 Platform。' 'success'
                    Start-ConfiguredServer -Mode $purpose
                }
            }
        }

        if ($null -ne $script:ServerCapture) {
            $line = $null
            while ($script:ServerCapture.Lines.TryDequeue([ref]$line)) {
                $level = if ($line.StartsWith('[错误]')) { 'error' } else { 'info' }
                Add-Log $line $level
                $line = $null
            }
        }

        if ($null -ne $script:ServerProcess) {
            if ($script:ServerProcess.HasExited) {
                $exitCode = $script:ServerProcess.ExitCode
                if ($script:StopRequested) {
                    $statusLabel.Text = '已停止'
                    $statusLabel.ForeColor = $muted
                } elseif ($exitCode -ne 0) {
                    Add-Log "Platform 已异常退出，退出码：$exitCode。请拍照保存上方错误。" 'error'
                    $statusLabel.Text = '服务已退出'
                    $statusLabel.ForeColor = $red
                } elseif (-not $script:HealthConfirmed) {
                    Add-Log 'Platform 在健康检查完成前退出。' 'error'
                    $statusLabel.Text = '服务未启动'
                    $statusLabel.ForeColor = $red
                }
                $stopButton.Enabled = $false
                $script:ServerProcess = $null
                $script:ServerCapture.Dispose()
                $script:ServerCapture = $null
                $script:StopRequested = $false
            } elseif (((Get-Date) - $script:LastHealthCheck).TotalSeconds -ge 2) {
                $script:LastHealthCheck = Get-Date
                if (Test-MineGuardHealth -Port $script:ServerPort) {
                    if (-not $script:HealthConfirmed) {
                        $script:HealthConfirmed = $true
                        $statusLabel.Text = '服务正常'
                        $statusLabel.ForeColor = $green
                        Add-Log (
                            '健康检查通过：http://127.0.0.1:{0}/' -f
                            $script:ServerPort
                        ) 'success'
                        Clear-BootstrapPasswordIfPresent
                    }
                    if ($script:ServerMode -eq 'demo' -and
                        -not $script:BrowserOpened) {
                        Open-LeaderPage
                    }
                } elseif (-not $script:HealthDelayReported -and
                    ((Get-Date) - $script:ServerStartedAt).TotalSeconds -ge 45) {
                    $script:HealthDelayReported = $true
                    $statusLabel.Text = '启动时间过长'
                    $statusLabel.ForeColor = $amber
                    Add-Log '服务进程仍在运行，但 45 秒内未通过健康检查；请查看上方运行输出。' 'warning'
                }
            }
        }
    })

$form.Add_FormClosing({
        param($sender, $eventArgs)
        if ($script:ClosingApproved) { return }
        if ($null -ne $script:OperationPowerShell) {
            [void][System.Windows.Forms.MessageBox]::Show(
                '配置事务正在执行，请等待完成后再关闭。',
                '请稍候',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            $eventArgs.Cancel = $true
            return
        }
        if ($null -ne $script:ServerProcess -and
            -not $script:ServerProcess.HasExited) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                '关闭向导会同时停止本次启动的 Platform。是否继续？',
                '确认关闭',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
                $eventArgs.Cancel = $true
                return
            }
            if (-not (Stop-StartedServer)) {
                $eventArgs.Cancel = $true
                return
            }
        }
        $script:ClosingApproved = $true
    })

$form.Add_FormClosed({
        $timer.Stop()
        if ($null -ne $script:OperationPowerShell) {
            try { $script:OperationPowerShell.Stop() } catch { }
            $script:OperationPowerShell.Dispose()
        }
        if ($null -ne $script:OperationSecureString) {
            $script:OperationSecureString.Dispose()
        }
        if ($null -ne $script:ServerCapture) {
            $script:ServerCapture.Dispose()
        }
        foreach ($font in @($normalFont, $smallFont, $titleFont, $sectionFont, $monoFont)) {
            $font.Dispose()
        }
    })

Refresh-ConfigurationState
$portInput.Value = [decimal]$script:ConfigurationState.port
Add-Log ('安装目录：' + $InstallRoot)
Add-Log ('本次诊断日志：' + $script:LogFilePath)
Add-Log $script:ConfigurationState.message
$timer.Start()
[void]$form.ShowDialog()
