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
        'MineGuardPlatform.WindowsAcl.ps1',
        'Start-MineGuardPlatform.ps1',
        'Resolve-MineGuardPlatformExecutable.ps1',
        'Install-MineGuardPlatformService.ps1',
        'Configure-MineGuardPlatformFormal.ps1'
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
$platformAclHelper = Join-Path $scriptDirectory `
    'MineGuardPlatform.WindowsAcl.ps1'
$startScript = Join-Path $scriptDirectory 'Start-MineGuardPlatform.ps1'
$resolverScript = Join-Path $scriptDirectory `
    'Resolve-MineGuardPlatformExecutable.ps1'
$serviceInstallScript = Join-Path $scriptDirectory `
    'Install-MineGuardPlatformService.ps1'
$formalConfigHelper = Join-Path $scriptDirectory `
    'Configure-MineGuardPlatformFormal.ps1'
foreach ($requiredPath in @(
        $configScript, $platformAclHelper, $startScript, $resolverScript,
        $serviceInstallScript, $formalConfigHelper
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Show-FatalMessage "安装不完整，缺少文件：$requiredPath"
        exit 1
    }
}

function Get-InstalledPlatformReleaseClassification {
    $metadataRoot = Join-Path $InstallRoot 'release-metadata'
    $manifestPath = Join-Path $metadataRoot 'release-manifest.json'
    $buildMetadataPath = Join-Path $metadataRoot 'build-metadata.json'
    try {
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $buildMetadataPath -PathType Leaf)) {
            return 'invalid-or-development'
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $build = Get-Content -LiteralPath $buildMetadataPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([string]$manifest.product -ne 'MineGuard Platform' -or
            [string]$build.product -ne 'MineGuard Platform' -or
            $manifest.codeSigned -isnot [bool] -or
            $build.codeSigned -isnot [bool] -or
            [bool]$manifest.codeSigned -ne [bool]$build.codeSigned -or
            [string]$manifest.releaseClassification -ne
                [string]$build.releaseClassification) {
            return 'invalid-or-development'
        }
        $classification = [string]$manifest.releaseClassification
        if ($classification -notin @(
                'signed-production-candidate',
                'unsigned-internal-release',
                'unsigned-test-artifacts'
            )) {
            return 'invalid-or-development'
        }
        if (([bool]$manifest.codeSigned) -ne
            ($classification -eq 'signed-production-candidate')) {
            return 'invalid-or-development'
        }
        return $classification
    } catch {
        return 'invalid-or-development'
    }
}

$script:InstalledReleaseClassification = `
    Get-InstalledPlatformReleaseClassification

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
        if (args.Data != null) Lines.Enqueue("[STDOUT] " + args.Data);
    }

    private void OnError(object sender, DataReceivedEventArgs args)
    {
        if (args.Data != null) Lines.Enqueue("[STDERR] " + args.Data);
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
$form.ClientSize = New-Object System.Drawing.Size(870, 710)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(886, 748)
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
$tabs.Size = New-Object System.Drawing.Size(826, 330)
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

Add-FormalLabel -Text 'Platform 系统 ID' -Y 135
$platformSystemInput = New-Object System.Windows.Forms.TextBox
$platformSystemInput.Text = 'mineguard-qinyuan'
$platformSystemInput.Location = New-Object System.Drawing.Point(132, 135)
$platformSystemInput.Size = New-Object System.Drawing.Size(250, 25)
$platformSystemInput.Font = $monoFont
$formalTab.Controls.Add($platformSystemInput)

$platformPartyLabel = New-Object System.Windows.Forms.Label
$platformPartyLabel.Text = '监管主体 ID'
$platformPartyLabel.Location = New-Object System.Drawing.Point(400, 135)
$platformPartyLabel.Size = New-Object System.Drawing.Size(105, 25)
$platformPartyLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$formalTab.Controls.Add($platformPartyLabel)
$platformPartyInput = New-Object System.Windows.Forms.TextBox
$platformPartyInput.Text = 'regulator-qinyuan'
$platformPartyInput.Location = New-Object System.Drawing.Point(510, 135)
$platformPartyInput.Size = New-Object System.Drawing.Size(278, 25)
$platformPartyInput.Font = $monoFont
$formalTab.Controls.Add($platformPartyInput)

Add-FormalLabel -Text '政府签名 key ID' -Y 174
$platformKeyInput = New-Object System.Windows.Forms.TextBox
$platformKeyInput.Text = 'regulator-key-v2'
$platformKeyInput.Location = New-Object System.Drawing.Point(132, 174)
$platformKeyInput.Size = New-Object System.Drawing.Size(250, 25)
$platformKeyInput.Font = $monoFont
$formalTab.Controls.Add($platformKeyInput)

$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = '管理员密码'
$passwordLabel.Location = New-Object System.Drawing.Point(400, 174)
$passwordLabel.Size = New-Object System.Drawing.Size(105, 25)
$passwordLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$formalTab.Controls.Add($passwordLabel)
$passwordHint = New-Object System.Windows.Forms.Label
$passwordHint.Text = '安全窗输入；请同时核对左侧政府签名 key ID。'
$passwordHint.ForeColor = $muted
$passwordHint.Location = New-Object System.Drawing.Point(510, 174)
$passwordHint.Size = New-Object System.Drawing.Size(278, 38)
$formalTab.Controls.Add($passwordHint)

Add-FormalLabel -Text '单位 HTTPS 地址' -Y 213
$formalAccessUrl = New-Object System.Windows.Forms.TextBox
$formalAccessUrl.Location = New-Object System.Drawing.Point(132, 213)
$formalAccessUrl.Size = New-Object System.Drawing.Size(558, 25)
$formalAccessUrl.Text = ''
$formalTab.Controls.Add($formalAccessUrl)

$formalAccessHint = New-Object System.Windows.Forms.Label
$formalAccessHint.Text = '可暂不填写；配置好 HTTPS 反向代理后再粘贴领导端地址。'
$formalAccessHint.ForeColor = $muted
$formalAccessHint.Location = New-Object System.Drawing.Point(700, 210)
$formalAccessHint.Size = New-Object System.Drawing.Size(90, 44)
$formalTab.Controls.Add($formalAccessHint)

$formalButton = New-Object System.Windows.Forms.Button
$formalButton.Text = '打开安全密码窗并配置'
$formalButton.Location = New-Object System.Drawing.Point(20, 252)
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
$formalHint.Location = New-Object System.Drawing.Point(242, 249)
$formalHint.Size = New-Object System.Drawing.Size(545, 48)
$formalTab.Controls.Add($formalHint)

$serviceTab = New-Object System.Windows.Forms.TabPage
$serviceTab.Text = '正式服务安装'
$serviceTab.BackColor = [System.Drawing.Color]::White
$tabs.TabPages.Add($serviceTab)

function Add-ServiceInstallLabel {
    param([string] $Text, [int] $Y)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point(18, $Y)
    $label.Size = New-Object System.Drawing.Size(112, 25)
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $serviceTab.Controls.Add($label)
}

Add-ServiceInstallLabel -Text '批准的 WinSW' -Y 18
$winSWText = New-Object System.Windows.Forms.TextBox
$winSWText.Location = New-Object System.Drawing.Point(132, 18)
$winSWText.Size = New-Object System.Drawing.Size(558, 25)
$serviceTab.Controls.Add($winSWText)
$winSWBrowse = New-Object System.Windows.Forms.Button
$winSWBrowse.Text = '选择...'
$winSWBrowse.Location = New-Object System.Drawing.Point(700, 16)
$winSWBrowse.Size = New-Object System.Drawing.Size(88, 29)
$serviceTab.Controls.Add($winSWBrowse)

Add-ServiceInstallLabel -Text 'WinSW SHA-256' -Y 57
$winSWSha256Text = New-Object System.Windows.Forms.TextBox
$winSWSha256Text.Location = New-Object System.Drawing.Point(132, 57)
$winSWSha256Text.Size = New-Object System.Drawing.Size(656, 25)
$winSWSha256Text.Font = $monoFont
$serviceTab.Controls.Add($winSWSha256Text)

Add-ServiceInstallLabel -Text '.config SHA-256' -Y 96
$winSWConfigSha256Text = New-Object System.Windows.Forms.TextBox
$winSWConfigSha256Text.Location = New-Object System.Drawing.Point(132, 96)
$winSWConfigSha256Text.Size = New-Object System.Drawing.Size(656, 25)
$winSWConfigSha256Text.Font = $monoFont
$serviceTab.Controls.Add($winSWConfigSha256Text)

$releaseApprovalLabel = New-Object System.Windows.Forms.Label
$releaseApprovalLabel.Location = New-Object System.Drawing.Point(18, 135)
$releaseApprovalLabel.Size = New-Object System.Drawing.Size(112, 25)
$releaseApprovalLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$releaseApprovalLabel.Text = if (
    $script:InstalledReleaseClassification -eq 'unsigned-internal-release'
    ) { '发行清单 SHA-256' } else { '签名者指纹' }
$serviceTab.Controls.Add($releaseApprovalLabel)
$releaseTrustText = New-Object System.Windows.Forms.TextBox
$releaseTrustText.Location = New-Object System.Drawing.Point(132, 135)
$releaseTrustText.Size = New-Object System.Drawing.Size(656, 25)
$releaseTrustText.Font = $monoFont
$serviceTab.Controls.Add($releaseTrustText)

$independentRuntimeShaCheck = New-Object System.Windows.Forms.CheckBox
$independentRuntimeShaCheck.Text = (
    '我已通过待安装介质之外的独立渠道核对上述 Platform 发行清单 SHA-256'
)
$independentRuntimeShaCheck.Location = New-Object System.Drawing.Point(132, 166)
$independentRuntimeShaCheck.Size = New-Object System.Drawing.Size(656, 34)
$independentRuntimeShaCheck.ForeColor = $red
$independentRuntimeShaCheck.Checked = $false
$independentRuntimeShaCheck.Visible = (
    $script:InstalledReleaseClassification -eq 'unsigned-internal-release'
)
$serviceTab.Controls.Add($independentRuntimeShaCheck)

$serviceInstallButton = New-Object System.Windows.Forms.Button
$serviceInstallButton.Text = '核验并安装正式服务'
$serviceInstallButton.Location = New-Object System.Drawing.Point(20, 214)
$serviceInstallButton.Size = New-Object System.Drawing.Size(205, 42)
$serviceInstallButton.BackColor = [System.Drawing.Color]::FromArgb(34, 91, 158)
$serviceInstallButton.ForeColor = [System.Drawing.Color]::White
$serviceInstallButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$serviceTab.Controls.Add($serviceInstallButton)

$serviceInstallHint = New-Object System.Windows.Forms.Label
$serviceInstallHint.Text = if (
    $script:InstalledReleaseClassification -eq 'unsigned-internal-release'
) {
    '内网无签名正式发行没有 Windows 发布者身份。子发行清单和 WinSW SHA-256 必须从介质外独立批准记录手工填写并显式确认；仅用于受控内网。'
} elseif ($script:InstalledReleaseClassification -eq
    'signed-production-candidate') {
    '先完成正式配置和前台验收。WinSW 摘要和签名者指纹必须从介质外的单位审批记录手工填写。'
} else {
    '当前是未签名测试介质或发布元数据无法识别；禁止安装正式 Windows 服务。'
}
$serviceInstallHint.ForeColor = $amber
$serviceInstallHint.Location = New-Object System.Drawing.Point(242, 207)
$serviceInstallHint.Size = New-Object System.Drawing.Size(545, 76)
$serviceTab.Controls.Add($serviceInstallHint)
if ($script:InstalledReleaseClassification -notin @(
        'signed-production-candidate', 'unsigned-internal-release'
    )) {
    $serviceInstallButton.Enabled = $false
}

$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(22, 470)
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
$logLabel.Location = New-Object System.Drawing.Point(22, 516)
$logLabel.Size = New-Object System.Drawing.Size(400, 24)
$form.Controls.Add($logLabel)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Location = New-Object System.Drawing.Point(22, 543)
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
$script:FormalConfigCapture = $null
$script:FormalConfigProcess = $null
$script:ServerCapture = $null
$script:ServerProcess = $null
$script:ServerPort = 8080
$script:ServerMode = ''
$script:BrowserOpened = $false
$script:BrowserAutoAttempted = $false
$script:HealthConfirmed = $false
$script:LastHealthCheck = [DateTime]::MinValue
$script:ServerStartedAt = [DateTime]::MinValue
$script:HealthDelayReported = $false
$script:StopRequested = $false
$script:ServerControlToken = $null
$script:ClosingApproved = $false
$script:FormalAccessSettingsPath = Join-Path (Join-Path $InstallRoot 'config') `
    'control-center.json'
$script:LogFilePath = Join-Path (Join-Path $InstallRoot 'logs') (
    'control-center-{0:yyyyMMdd-HHmmss}-{1}.log' -f `
        (Get-Date), [Guid]::NewGuid().ToString('N').Substring(0, 8)
)
$script:LogEncoding = New-Object System.Text.UTF8Encoding($true)

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
    $managedServerRunning = (
        $null -ne $script:ServerProcess -and
        -not $script:ServerProcess.HasExited
    )
    $demoButton.Enabled = (-not $Busy) -and
        (-not $managedServerRunning) -and
        ($script:ConfigurationState.kind -in @('pristine', 'demo'))
    $formalReleaseEligible = $script:InstalledReleaseClassification -in @(
        'signed-production-candidate', 'unsigned-internal-release'
    )
    $formalButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'pristine') -and
        $formalReleaseEligible
    $startCurrentButton.Enabled = (-not $Busy) -and (
        ($script:ConfigurationState.kind -eq 'demo') -or
        (($script:ConfigurationState.kind -eq 'formal') -and
            $formalReleaseEligible)
    )
    $openButton.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -in @('demo', 'formal'))
    $monthPicker.Enabled = (-not $Busy) -and (-not $managedServerRunning)
    $demoPort.Enabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'pristine')
    $formalInputsEnabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'pristine') -and
        $formalReleaseEligible
    $clientsBrowse.Enabled = $formalInputsEnabled
    $stateBrowse.Enabled = $formalInputsEnabled
    $clientsText.Enabled = $formalInputsEnabled
    $formalState.Enabled = $formalInputsEnabled
    $portInput.Enabled = $formalInputsEnabled
    $adminInput.Enabled = $formalInputsEnabled
    $platformSystemInput.Enabled = $formalInputsEnabled
    $platformPartyInput.Enabled = $formalInputsEnabled
    $platformKeyInput.Enabled = $formalInputsEnabled
    $formalAccessUrl.Enabled = -not $Busy
    $serviceReleaseEligible = $formalReleaseEligible
    $serviceInstallEnabled = (-not $Busy) -and
        ($script:ConfigurationState.kind -eq 'formal') -and
        $serviceReleaseEligible
    $winSWBrowse.Enabled = $serviceInstallEnabled
    $winSWText.Enabled = $serviceInstallEnabled
    $winSWSha256Text.Enabled = $serviceInstallEnabled
    $winSWConfigSha256Text.Enabled = $serviceInstallEnabled
    $releaseTrustText.Enabled = $serviceInstallEnabled
    $independentRuntimeShaCheck.Enabled = $serviceInstallEnabled -and
        ($script:InstalledReleaseClassification -eq 'unsigned-internal-release')
    $serviceInstallButton.Enabled = $serviceInstallEnabled
    $refreshButton.Enabled = -not $Busy
}

function Test-StateDirectoryHasContent {
    param([string] $StateDirectory)
    try {
        if ([string]::IsNullOrWhiteSpace($StateDirectory) -or
            -not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
            return $false
        }
        $pending = New-Object System.Collections.Queue
        $pending.Enqueue((Get-Item -LiteralPath $StateDirectory -Force))
        while ($pending.Count -gt 0) {
            $directory = $pending.Dequeue()
            foreach ($child in Get-ChildItem -LiteralPath $directory.FullName -Force) {
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return $true
                }
                if ($child.PSIsContainer) {
                    $pending.Enqueue($child)
                } elseif ($child.Name -ne '.mineguard-platform-state.json') {
                    return $true
                }
            }
        }
        # A failed first-run transaction may leave only the product ownership
        # marker and empty directories.  Those contain no business state and
        # are safe for the guarded configuration script to validate and reuse.
        return $false
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
        $coreExpectedNames = @(
            'schemaVersion', 'host', 'port', 'stateDirectory', 'clientsFile',
            'adminUsername', 'secureCookie', 'allowDemoDefaultPassword',
            'platformSystemId', 'platformPartyId', 'platformKeyId'
        )
        $provisioningExpectedNames = @(
            'managedProvisioningRequired',
            'provisioningTrustedPublicKeyFile',
            'provisioningExpectedPublicKeySha256',
            'provisioningExpectedIssuerKeyId'
        )
        $expectedNames = @($coreExpectedNames + $provisioningExpectedNames)
        $actualNames = @($settings.PSObject.Properties.Name)
        $isLegacyFieldSet = (
            $actualNames.Count -eq $coreExpectedNames.Count -and
            @($actualNames | Where-Object {
                    $coreExpectedNames -notcontains $_
                }).Count -eq 0
        )
        $isCurrentFieldSet = (
            $actualNames.Count -eq $expectedNames.Count -and
            @($actualNames | Where-Object {
                    $expectedNames -notcontains $_
                }).Count -eq 0
        )
        if (-not $isLegacyFieldSet -and -not $isCurrentFieldSet) {
            throw '配置字段集合不符合已知格式'
        }
        foreach ($requiredName in $coreExpectedNames) {
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
            [string]$settings.stateDirectory -notmatch '^[A-Za-z]:\\' -or
            ($isCurrentFieldSet -and
                $settings.managedProvisioningRequired -isnot [bool])) {
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
    $hasFormalRegistry = (
        -not [string]::IsNullOrWhiteSpace($clientsFile) -or
        (Test-Path -LiteralPath $clientsPath -PathType Leaf)
    )
    if ($hasFormalRegistry -and ($allowDemo -or -not $secureCookie)) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '正式配置的演示口令或 Secure Cookie 开关被改动；已拒绝降级启动。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    if ($hasFormalRegistry) {
        return [pscustomobject]@{
            kind = 'formal'
            message = '已检测到正式配置。为防止误覆盖，只允许启动或打开页面。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    if ($allowDemo -and -not $secureCookie) {
        return [pscustomobject]@{
            kind = 'demo'
            message = '已检测到本机演示配置。可直接启动，不会重复改写配置。'
            port = $port
            stateDirectory = $stateDirectory
        }
    }
    if ($allowDemo -or -not $secureCookie) {
        return [pscustomobject]@{
            kind = 'blocked'
            message = '演示配置安全开关组合不一致；已禁止启动或覆盖。'
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
        [string]$settings.platformSystemId -eq 'mineguard-qinyuan' -and
        [string]$settings.platformPartyId -eq 'regulator-qinyuan' -and
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
        message = '尚未首次配置：可选择【本机展示】或【正式内网配置】。'
        port = $port
        stateDirectory = $stateDirectory
    }
}

function Refresh-ConfigurationState {
    $script:ConfigurationState = Get-ConfigurationState
    $script:ServerPort = [int]$script:ConfigurationState.port
    if ($script:ConfigurationState.kind -eq 'demo') {
        $demoButton.Text = '补齐数据并启动展示'
        $demoPath.Text = [string]$script:ConfigurationState.stateDirectory
        $demoPort.Value = [decimal]$script:ConfigurationState.port
    } else {
        $demoButton.Text = '一键准备并启动展示'
    }
    if ($script:ConfigurationState.kind -eq 'formal') {
        $formalState.Text = [string]$script:ConfigurationState.stateDirectory
        $portInput.Value = [decimal]$script:ConfigurationState.port
    }
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
    Set-BusyState -Busy (
        $null -ne $script:OperationPowerShell -or
        $null -ne $script:FormalConfigProcess
    )
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

function Test-LocalPortAvailable {
    param([ValidateRange(1, 65535)] [int] $Port)
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @(
            [System.Net.IPAddress]::Loopback,
            $Port
        )
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) {
            try { $listener.Stop() } catch { }
        }
    }
}

function Test-LocalPortListening {
    param([ValidateRange(1, 65535)] [int] $Port)
    try {
        $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::`
            GetIPGlobalProperties().GetActiveTcpListeners()
        return @($listeners | Where-Object { $_.Port -eq $Port }).Count -gt 0
    } catch {
        # If listener enumeration is unavailable, binding remains a conservative
        # fallback.  Never infer a PID from the port or terminate an unknown owner.
        return -not (Test-LocalPortAvailable -Port $Port)
    }
}

function Resolve-FormalAccessUri {
    param([string] $Value)
    $candidate = $Value.Trim()
    $parsed = $null
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw '单位 HTTPS 地址为空。'
    }
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or
        [string]::IsNullOrWhiteSpace($parsed.Host) -or
        -not [string]::IsNullOrWhiteSpace($parsed.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($parsed.Query) -or
        -not [string]::IsNullOrWhiteSpace($parsed.Fragment) -or
        $parsed.AbsolutePath -ne '/') {
        throw (
            '单位 HTTPS 地址必须是 https://主机名/ 根地址，' +
            '不能带账号口令、子路径、查询参数或片段。'
        )
    }
    return $parsed
}

function Read-SavedFormalAccessUrl {
    $path = $script:FormalAccessSettingsPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    try {
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -gt 16384) {
            throw '文件类型或大小不符合安全规则'
        }
        $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $names = @($document.PSObject.Properties.Name)
        if ($names.Count -ne 2 -or
            $names -notcontains 'schemaVersion' -or
            $names -notcontains 'formalAccessUrl' -or
            [int]$document.schemaVersion -ne 1 -or
            $document.formalAccessUrl -isnot [string]) {
            throw '字段集合不符合已知格式'
        }
        $uri = Resolve-FormalAccessUri -Value ([string]$document.formalAccessUrl)
        return $uri.AbsoluteUri
    } catch {
        Add-Log "已保存的单位 HTTPS 地址无法安全读取：$($_.Exception.Message)" 'warning'
        return ''
    }
}

function Save-FormalAccessUrl {
    param([Parameter(Mandatory = $true)] [Uri] $Uri)
    $path = $script:FormalAccessSettingsPath
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw '找不到受保护的 config 目录。'
    }
    if (Test-Path -LiteralPath $path) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw '控制中心配置路径已被非文件对象占用。'
        }
        $existing = Get-Item -LiteralPath $path -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw '拒绝覆盖 reparse point 形式的控制中心配置。'
        }
    }
    $temporaryPath = Join-Path $directory (
        '.control-center.{0}.tmp' -f [Guid]::NewGuid().ToString('N')
    )
    $document = [ordered]@{
        schemaVersion = 1
        formalAccessUrl = $Uri.AbsoluteUri
    }
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($document | ConvertTo-Json -Depth 3),
            $script:LogEncoding
        )
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $path, $null)
        } else {
            Move-Item -LiteralPath $temporaryPath -Destination $path
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Open-LeaderPage {
    $localUrl = 'http://127.0.0.1:{0}/' -f $script:ServerPort
    $url = $localUrl
    if ($script:ConfigurationState.kind -eq 'formal') {
        $candidate = $formalAccessUrl.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            Add-Log '正式模式不会打开本机 HTTP。请先配置单位 HTTPS 反向代理，再填写访问地址。' 'warning'
            $httpsMessage = @(
                '正式模式启用了安全 Cookie，不能直接用本机 HTTP 登录。'
                ''
                '请先配置单位批准的 HTTPS 反向代理，再在【单位 HTTPS 地址】中粘贴领导端地址。'
            ) -join [Environment]::NewLine
            [void][System.Windows.Forms.MessageBox]::Show(
                $httpsMessage,
                '需要 HTTPS 地址',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        try {
            $parsed = Resolve-FormalAccessUri -Value $candidate
        } catch {
            Add-Log $_.Exception.Message 'error'
            return
        }
        $url = $parsed.AbsoluteUri
    }
    $requireReady = ($script:ConfigurationState.kind -eq 'formal')
    if (-not (Test-MineGuardHealth -Port $script:ServerPort `
            -RequireReady:$requireReady)) {
        Add-Log "Platform 尚未通过健康检查，暂不打开页面：$localUrl" 'warning'
        [void][System.Windows.Forms.MessageBox]::Show(
            'Platform 还没有正常启动。请先点击【启动当前配置】，并等待右下角显示【服务正常】。',
            '服务尚未就绪',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }
    if ($script:ConfigurationState.kind -eq 'formal') {
        $formalHealthUrl = New-Object System.Uri -ArgumentList @(
            $parsed,
            'readyz'
        )
        if (-not (Test-MineGuardHealthUrl -Url $formalHealthUrl.AbsoluteUri `
                -TimeoutMilliseconds 5000 -ExpectedStatus 'ready')) {
            Add-Log (
                '本机服务正常，但单位 HTTPS 地址未能访问 /readyz。' +
                '请检查 DNS、证书和反向代理根路径。'
            ) 'error'
            [void][System.Windows.Forms.MessageBox]::Show(
                '单位 HTTPS 地址还没有连通本平台。请让运维检查 DNS、HTTPS 证书和反向代理后重试。',
                'HTTPS 访问尚未就绪',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        try {
            Save-FormalAccessUrl -Uri $parsed
        } catch {
            Add-Log "页面可访问，但 HTTPS 地址保存失败：$($_.Exception.Message)" 'warning'
        }
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

function Test-MineGuardHealthUrl {
    param(
        [Parameter(Mandatory = $true)] [string] $Url,
        [ValidateRange(100, 30000)] [int] $TimeoutMilliseconds = 900,
        [ValidateSet('ok', 'ready')] [string] $ExpectedStatus = 'ok'
    )
    $response = $null
    $reader = $null
    $originalSecurityProtocol = $null
    $securityProtocolChanged = $false
    try {
        $healthUri = New-Object System.Uri -ArgumentList $Url
        if ($healthUri.Scheme -eq 'https') {
            $originalSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
            $tls12 = [Net.SecurityProtocolType]::Tls12
            $enabledProtocols = $originalSecurityProtocol -bor $tls12
            if ($enabledProtocols -ne $originalSecurityProtocol) {
                [Net.ServicePointManager]::SecurityProtocol = $enabledProtocols
                $securityProtocolChanged = $true
            }
        }
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Proxy = $null
        $request.Timeout = $TimeoutMilliseconds
        $request.ReadWriteTimeout = $TimeoutMilliseconds
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        $statusPattern = '"status"\s*:\s*"{0}"' -f [regex]::Escape(
            $ExpectedStatus
        )
        return ([int]$response.StatusCode -eq 200 -and
            $body -match '"service"\s*:\s*"mineguard-v2"' -and
            $body -match $statusPattern)
    } catch {
        return $false
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        if ($securityProtocolChanged) {
            [Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
        }
    }
}

function Test-MineGuardHealth {
    param([int] $Port, [switch] $RequireReady)
    $endpoint = if ($RequireReady) { 'readyz' } else { 'healthz' }
    $expectedStatus = if ($RequireReady) { 'ready' } else { 'ok' }
    return Test-MineGuardHealthUrl -Url (
        'http://127.0.0.1:{0}/{1}' -f $Port, $endpoint
    ) -ExpectedStatus $expectedStatus
}

function Request-MineGuardGracefulShutdown {
    param(
        [ValidateRange(1, 65535)] [int] $Port,
        [Parameter(Mandatory = $true)] [string] $ControlToken
    )
    if ($ControlToken -notmatch '^[0-9a-f]{64}$') { return $false }
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create(
            ('http://127.0.0.1:{0}/_mineguard/local-control/shutdown' -f $Port)
        )
        $request.Method = 'POST'
        $request.Proxy = $null
        $request.KeepAlive = $false
        $request.ContentLength = 0
        $request.Timeout = 3000
        $request.ReadWriteTimeout = 3000
        $request.Headers.Add(
            'X-MineGuard-Local-Control-Token', $ControlToken
        )
        $response = $request.GetResponse()
        return ([int]$response.StatusCode -eq 202)
    } catch {
        return $false
    } finally {
        if ($null -ne $response) { $response.Dispose() }
    }
}

function New-MineGuardLocalControlToken {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Start-DemoConfigurationOperation {
    param(
        [string] $StateDirectory,
        [int] $Port,
        [string] $ThroughMonth
    )
    if ($null -ne $script:OperationPowerShell -or
        $null -ne $script:FormalConfigProcess) {
        Add-Log '另一项配置操作仍在进行，请稍候。' 'warning'
        return
    }
    Refresh-ConfigurationState
    $configureFirst = ($script:ConfigurationState.kind -eq 'pristine')
    $canResumeDemo = ($script:ConfigurationState.kind -eq 'demo')
    if (-not $configureFirst -and -not $canResumeDemo) {
        Add-Log '检测到已有配置或状态数据；为防止覆盖，已取消首次配置。' 'error'
        return
    }

    $worker = @'
param(
    [string] $InstallRoot,
    [string] $ResolverScript,
    [string] $ConfigScript,
    [string] $StateDirectory,
    [int] $Port,
    [string] $ThroughMonth,
    [bool] $ConfigureFirst
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. $ResolverScript
$runtime = Resolve-MineGuardPlatformExecutable -InstallRoot $InstallRoot
if ($ConfigureFirst) {
    Write-Information '正在应用受保护的本机配置...' -InformationAction Continue
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
    Write-Information '受保护的本机配置已完成。' -InformationAction Continue
} else {
    Write-Information '已有演示配置；本次只补齐或核验演示数据，不改写配置。' -InformationAction Continue
}
Write-Information '正在生成或核验演示数据，请稍候...' -InformationAction Continue
$seedArguments = Join-MineGuardPlatformArguments -Runtime $runtime -Arguments @(
    'seed-v2-demo', '--state-directory', $StateDirectory,
    '--through-month', $ThroughMonth
)
$seedOutput = & $runtime.filePath @seedArguments
$seedExitCode = $LASTEXITCODE
if ($seedExitCode -ne 0) {
    throw "演示数据生成失败，运行时退出码：$seedExitCode"
}
try {
    $seedResult = $seedOutput | Out-String | ConvertFrom-Json
    $mineCount = [int]$seedResult.mine_count
    $submissionCount = [int]$seedResult.submission_count
} catch {
    throw "演示数据生成结果无法核验：$($_.Exception.Message)"
}
if ([string]$seedResult.schema_version -ne
        'mineguard-regulatory-v2-demo-v3' -or
    $mineCount -ne 10 -or $submissionCount -ne 26 -or
    $seedResult.demo_dataset -ne $true -or
    $seedResult.contains_workbook_examples -ne $true) {
    throw '演示数据未达到受控样例的 10 座煤矿、26 期报送，已拒绝启动不完整页面。'
}
Write-Information (
    '演示数据已准备完成：{0} 座煤矿、{1} 期报送。' -f
    $mineCount, $submissionCount
) -InformationAction Continue
Write-Information '一键准备操作已完成。' -InformationAction Continue
'@

    $script:OperationPowerShell = [System.Management.Automation.PowerShell]::Create()
    [void]$script:OperationPowerShell.AddScript($worker)
    foreach ($argument in @(
        $InstallRoot, $resolverScript, $configScript, $StateDirectory,
        $Port, $ThroughMonth, $configureFirst
    )) {
        [void]$script:OperationPowerShell.AddArgument($argument)
    }
    $script:OperationPurpose = 'demo'
    $script:OperationStreamOffsets = @{
        Error = 0; Warning = 0; Information = 0; Verbose = 0
    }
    try {
        $script:OperationAsync = $script:OperationPowerShell.BeginInvoke()
        Set-BusyState -Busy $true
        $statusLabel.Text = '正在配置...'
        Add-Log '开始一键准备本机展示。'
    } catch {
        $script:OperationPowerShell.Dispose()
        $script:OperationPowerShell = $null
        $script:OperationAsync = $null
        Set-BusyState -Busy $false
        Add-Log "无法启动配置操作：$($_.Exception.Message)" 'error'
    }
}

function Start-FormalConfigurationProcess {
    param(
        [string] $StateDirectory,
        [int] $Port,
        [string] $ClientsFile,
        [string] $AdminUsername,
        [string] $PlatformSystemId,
        [string] $PlatformPartyId,
        [string] $PlatformKeyId
    )
    if ($null -ne $script:OperationPowerShell -or
        $null -ne $script:FormalConfigProcess) {
        Add-Log '另一项配置或服务操作仍在进行，请稍候。' 'warning'
        return
    }
    Refresh-ConfigurationState
    if ($script:ConfigurationState.kind -ne 'pristine') {
        Add-Log '检测到已有配置或状态数据；为防止覆盖，已取消正式首次配置。' 'error'
        return
    }
    try {
        $arguments = Join-NativeArguments -Arguments @(
            '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass',
            '-File', $formalConfigHelper,
            '-InstallRoot', $InstallRoot,
            '-ClientsFile', $ClientsFile,
            '-StateDirectory', $StateDirectory,
            '-Port', [string]$Port,
            '-AdminUsername', $AdminUsername,
            '-PlatformSystemId', $PlatformSystemId,
            '-PlatformPartyId', $PlatformPartyId,
            '-PlatformKeyId', $PlatformKeyId
        )
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $windowsPowerShell
        $startInfo.Arguments = $arguments
        $startInfo.WorkingDirectory = $InstallRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables.Remove('MINEGUARD_ADMIN_PASSWORD')
        try {
            $encoding = New-Object System.Text.UTF8Encoding($false)
            $startInfo.StandardOutputEncoding = $encoding
            $startInfo.StandardErrorEncoding = $encoding
        } catch { }
        $capture = New-Object MineGuardGuiProcessCapture
        $capture.Start($startInfo)
        $script:FormalConfigCapture = $capture
        $script:FormalConfigProcess = $capture.Process
        Set-BusyState -Busy $true
        $statusLabel.Text = '等待独立安全密码窗口...'
        Add-Log '已启动独立短生命周期正式配置 helper；主控制中心未接收密码。'
    } catch {
        if ($null -ne $script:FormalConfigCapture) {
            $script:FormalConfigCapture.Dispose()
        }
        $script:FormalConfigCapture = $null
        $script:FormalConfigProcess = $null
        Set-BusyState -Busy $false
        Add-Log "无法启动正式配置 helper：$($_.Exception.Message)" 'error'
    }
}

function Start-ServiceInstallOperation {
    param(
        [string] $WinSWExecutable,
        [string] $ExpectedSha256,
        [string] $ExpectedConfigSha256,
        [string] $ExpectedSignerThumbprint,
        [string] $ExpectedReleaseManifestSha256,
        [bool] $UseInternalUnsigned
    )
    if ($null -ne $script:OperationPowerShell -or
        $null -ne $script:FormalConfigProcess) {
        Add-Log '另一项配置或服务操作仍在进行，请稍候。' 'warning'
        return
    }
    $worker = @'
param(
    [string] $ServiceInstallScript,
    [string] $InstallRoot,
    [string] $WinSWExecutable,
    [string] $ExpectedSha256,
    [string] $ExpectedConfigSha256,
    [string] $ExpectedSignerThumbprint,
    [string] $ExpectedReleaseManifestSha256,
    [bool] $UseInternalUnsigned
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$parameters = @{
    WinSWExecutable = $WinSWExecutable
    ExpectedSha256 = $ExpectedSha256
    InstallRoot = $InstallRoot
    Production = $true
    StartService = $true
}
if ($UseInternalUnsigned) {
    $parameters['AllowUnsignedInternalRelease'] = $true
    $parameters['ExpectedReleaseManifestSha256'] = $ExpectedReleaseManifestSha256
} else {
    $parameters['ExpectedSignerThumbprint'] = $ExpectedSignerThumbprint
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedConfigSha256)) {
    $parameters['ExpectedConfigSha256'] = $ExpectedConfigSha256
}
& $ServiceInstallScript @parameters
'@
    $script:OperationPowerShell = [System.Management.Automation.PowerShell]::Create()
    [void]$script:OperationPowerShell.AddScript($worker)
    foreach ($argument in @(
        $serviceInstallScript, $InstallRoot, $WinSWExecutable,
        $ExpectedSha256, $ExpectedConfigSha256, $ExpectedSignerThumbprint,
        $ExpectedReleaseManifestSha256, $UseInternalUnsigned
    )) {
        [void]$script:OperationPowerShell.AddArgument($argument)
    }
    $script:OperationPurpose = 'service-install'
    $script:OperationStreamOffsets = @{
        Error = 0; Warning = 0; Information = 0; Verbose = 0
    }
    try {
        $script:OperationAsync = $script:OperationPowerShell.BeginInvoke()
        Set-BusyState -Busy $true
        $statusLabel.Text = '正在核验并安装服务...'
        if ($UseInternalUnsigned) {
            Add-Log '开始内网无签名正式发行服务安装；发行清单 SHA-256 来自用户显式确认的介质外独立批准记录，并将覆盖完整 standalone 文件树。' 'warning'
        } else {
            Add-Log '开始正式服务安装；签名者指纹来自用户填写的线下审批记录。'
        }
    } catch {
        $script:OperationPowerShell.Dispose()
        $script:OperationPowerShell = $null
        $script:OperationAsync = $null
        $script:OperationPurpose = ''
        Set-BusyState -Busy $false
        Add-Log "无法启动服务安装操作：$($_.Exception.Message)" 'error'
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
        if (-not (Test-LocalPortAvailable -Port $script:ServerPort)) {
            throw ((
                '本机端口 {0} 已被其他程序占用。' +
                '请先关闭占用程序，或在首次配置时换一个端口。'
            ) -f $script:ServerPort)
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
        $controlToken = New-MineGuardLocalControlToken
        $startInfo.EnvironmentVariables['MINEGUARD_LOCAL_CONTROL_TOKEN'] = (
            $controlToken
        )
        $capture = New-Object MineGuardGuiProcessCapture
        $capture.Start($startInfo)
        $script:ServerCapture = $capture
        $script:ServerProcess = $capture.Process
        $script:ServerControlToken = $controlToken
        $controlToken = $null
        $script:ServerMode = if ($Mode -eq 'existing') {
            [string]$script:ConfigurationState.kind
        } else { $Mode }
        $script:BrowserOpened = $false
        $script:BrowserAutoAttempted = $false
        $script:HealthConfirmed = $false
        $script:LastHealthCheck = [DateTime]::MinValue
        $script:ServerStartedAt = Get-Date
        $script:HealthDelayReported = $false
        $script:StopRequested = $false
        $stopButton.Enabled = $true
        Set-BusyState -Busy $false
        $statusLabel.Text = '正在启动服务...'
        Add-Log (
            'Platform 前台服务已启动（进程号 {0}），正在等待健康检查。' -f
            $script:ServerProcess.Id
        )
    } catch {
        $script:ServerControlToken = $null
        Add-Log "启动失败：$($_.Exception.Message)" 'error'
        $statusLabel.Text = '启动失败'
        $statusLabel.ForeColor = $red
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
        $graceful = $false
        if (-not [string]::IsNullOrWhiteSpace($script:ServerControlToken)) {
            Add-Log '正在安全停止 Platform，并等待数据库完成收尾。'
            $graceful = Request-MineGuardGracefulShutdown `
                -Port $script:ServerPort `
                -ControlToken $script:ServerControlToken
        }
        $script:ServerControlToken = $null
        if ($graceful) {
            [void]$script:ServerProcess.WaitForExit(30000)
        } else {
            # The service may have accepted the single-use request even if the
            # control center did not receive its 202 response. Give it a short
            # natural-exit window before using the process-tree fallback.
            [void]$script:ServerProcess.WaitForExit(5000)
        }
        $usedForcedFallback = $false
        if (-not $script:ServerProcess.HasExited) {
            $usedForcedFallback = $true
            Add-Log '安全停止未在限定时间内完成，正在停止本向导启动的进程树。' 'warning'
            $pidText = [string]$script:ServerProcess.Id
            $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
            $arguments = @('/PID', $pidText, '/T', '/F')
            $stopInfo = New-Object System.Diagnostics.ProcessStartInfo
            $stopInfo.FileName = $taskKill
            $stopInfo.Arguments = Join-NativeArguments -Arguments $arguments
            $stopInfo.UseShellExecute = $false
            $stopInfo.CreateNoWindow = $true
            $stopProcess = [System.Diagnostics.Process]::Start($stopInfo)
            if ($null -eq $stopProcess -or -not $stopProcess.WaitForExit(10000)) {
                if ($null -ne $stopProcess) {
                    try { $stopProcess.Kill() } catch { }
                    $stopProcess.Dispose()
                }
                throw 'Windows 停止命令在 10 秒内没有返回。'
            }
            $taskKillExitCode = $stopProcess.ExitCode
            $stopProcess.Dispose()
            [void]$script:ServerProcess.WaitForExit(5000)
            if (-not $script:ServerProcess.HasExited -and $taskKillExitCode -ne 0) {
                throw "Windows 进程树停止失败（退出码 $taskKillExitCode）。"
            }
        }
        if (-not $script:ServerProcess.HasExited) {
            throw 'Platform 进程仍在运行；请不要重复启动，并联系管理员查看任务管理器。'
        }
        $portReleased = $false
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if (-not (Test-LocalPortListening -Port $script:ServerPort)) {
                $portReleased = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $portReleased) {
            throw "Platform 包装进程已退出，但端口 $($script:ServerPort) 仍被占用；请勿重复启动。"
        }
        if ($usedForcedFallback) {
            Add-Log '已确认本向导启动的 Platform 进程树停止，端口已经释放。' 'success'
        } else {
            Add-Log 'Platform 已安全停止，数据库已完成收尾，端口已经释放。' 'success'
        }
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

function Stop-FormalConfigurationProcess {
    if ($null -eq $script:FormalConfigProcess) { return $true }
    try {
        $processId = [string]$script:FormalConfigProcess.Id
        if (-not $script:FormalConfigProcess.HasExited) {
            try { [void]$script:FormalConfigProcess.CloseMainWindow() }
            catch { }
            [void]$script:FormalConfigProcess.WaitForExit(3000)
        }
        if (-not $script:FormalConfigProcess.HasExited) {
            $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
            $stopInfo = New-Object System.Diagnostics.ProcessStartInfo
            $stopInfo.FileName = $taskKill
            $stopInfo.Arguments = Join-NativeArguments -Arguments @(
                '/PID', $processId, '/T', '/F'
            )
            $stopInfo.UseShellExecute = $false
            $stopInfo.CreateNoWindow = $true
            $stopProcess = [Diagnostics.Process]::Start($stopInfo)
            if ($null -eq $stopProcess -or
                -not $stopProcess.WaitForExit(10000)) {
                if ($null -ne $stopProcess) { $stopProcess.Dispose() }
                throw '独立正式配置 helper 未能在限定时间内停止。'
            }
            $taskKillExitCode = $stopProcess.ExitCode
            $stopProcess.Dispose()
            [void]$script:FormalConfigProcess.WaitForExit(5000)
            if (-not $script:FormalConfigProcess.HasExited) {
                throw "精确终止正式配置 helper 后进程仍在运行，taskkill 退出码 $taskKillExitCode。"
            }
        }
        if ($null -ne $script:FormalConfigCapture) {
            $script:FormalConfigCapture.Dispose()
        }
        $script:FormalConfigCapture = $null
        $script:FormalConfigProcess = $null
        return $true
    } catch {
        Add-Log "停止正式配置 helper 失败：$($_.Exception.Message)" 'error'
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

$winSWBrowse.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = '选择单位批准的 WinSW x64 可执行文件'
        $dialog.Filter = '可执行文件 (*.exe)|*.exe|所有文件|*.*'
        $dialog.CheckFileExists = $true
        $dialog.Multiselect = $false
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $winSWText.Text = $dialog.FileName
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
        Refresh-ConfigurationState
        if (-not $demoWarning.Checked) {
            [void][System.Windows.Forms.MessageBox]::Show(
                '请先勾选红色确认项，明确本机演示的默认密码和使用边界。',
                '需要确认',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        if ($script:ConfigurationState.kind -eq 'demo' -and
            (Test-MineGuardHealth -Port $script:ConfigurationState.port)) {
            Add-Log '演示服务已经正常运行，直接打开页面。' 'success'
            Open-LeaderPage
            return
        }
        $requestedDemoPort = if ($script:ConfigurationState.kind -eq 'demo') {
            [int]$script:ConfigurationState.port
        } else {
            [int]$demoPort.Value
        }
        if (-not (Test-LocalPortAvailable -Port $requestedDemoPort)) {
            Add-Log (
                ('端口 {0} 已被占用；本次未继续，现有配置没有被改写。' -f
                    $requestedDemoPort)
            ) 'error'
            return
        }
        $throughMonth = '{0:yyyy-MM-dd}' -f
            $monthPicker.Value.Date.AddMonths(1).AddDays(-1)
        Start-DemoConfigurationOperation `
            -StateDirectory $demoPath.Text -Port $requestedDemoPort `
            -ThroughMonth $throughMonth
    })

$formalButton.Add_Click({
        Refresh-ConfigurationState
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
        $identityPattern = '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        $selectedPlatformSystemId = $platformSystemInput.Text.Trim()
        $selectedPlatformPartyId = $platformPartyInput.Text.Trim()
        $selectedPlatformKeyId = $platformKeyInput.Text.Trim()
        $identityValues = @(
            [pscustomobject]@{
                Label = 'Platform 系统 ID'; Value = $selectedPlatformSystemId
            },
            [pscustomobject]@{
                Label = '监管主体 ID'; Value = $selectedPlatformPartyId
            },
            [pscustomobject]@{
                Label = '政府签名 key ID'; Value = $selectedPlatformKeyId
            }
        )
        foreach ($identityValue in $identityValues) {
            if ($identityValue.Value -cnotmatch $identityPattern) {
                Add-Log ($identityValue.Label + '格式无效；请核对后重试。') 'error'
                return
            }
        }
        if ($selectedPlatformSystemId -ceq $selectedPlatformPartyId) {
            Add-Log 'Platform 系统 ID 与监管主体 ID 不能相同。' 'error'
            return
        }
        $requestedFormalPort = [int]$portInput.Value
        if (-not (Test-LocalPortAvailable -Port $requestedFormalPort)) {
            Add-Log (
                ('端口 {0} 已被占用；未写入配置。请换一个端口后重试。' -f
                    $requestedFormalPort)
            ) 'error'
            return
        }
        if (-not [string]::IsNullOrWhiteSpace($formalAccessUrl.Text)) {
            try {
                $formalUri = Resolve-FormalAccessUri -Value $formalAccessUrl.Text
                $formalAccessUrl.Text = $formalUri.AbsoluteUri
            } catch {
                Add-Log $_.Exception.Message 'error'
                return
            }
        }
        Start-FormalConfigurationProcess `
            -StateDirectory $formalState.Text -Port $requestedFormalPort `
            -ClientsFile $clientsText.Text -AdminUsername $adminInput.Text `
            -PlatformSystemId $selectedPlatformSystemId `
            -PlatformPartyId $selectedPlatformPartyId `
            -PlatformKeyId $selectedPlatformKeyId
    })

$serviceInstallButton.Add_Click({
        $currentReleaseClassification = `
            Get-InstalledPlatformReleaseClassification
        if ($currentReleaseClassification -ne
            $script:InstalledReleaseClassification) {
            Add-Log '发布元数据在控制中心打开后发生变化；请关闭并重新打开控制中心后再操作。' 'error'
            return
        }
        if ($currentReleaseClassification -notin @(
                'signed-production-candidate',
                'unsigned-internal-release'
            )) {
            Add-Log '当前未签名测试介质或无效发布不得安装正式 Windows 服务。' 'error'
            return
        }
        Refresh-ConfigurationState
        if ($script:ConfigurationState.kind -ne 'formal') {
            Add-Log '请先完成正式内网配置和前台验收，再安装正式服务。' 'error'
            return
        }
        if ($null -ne $script:ServerProcess -and
            -not $script:ServerProcess.HasExited) {
            Add-Log '请先点击【停止本次启动】，释放端口后再安装 Windows 服务。' 'error'
            return
        }
        if ($null -ne (Get-Service -Name 'MineGuardPlatform' `
                -ErrorAction SilentlyContinue)) {
            Add-Log 'MineGuardPlatform 服务已经存在；向导不会隐式覆盖或重装。' 'error'
            return
        }
        $winSWPathValue = $winSWText.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($winSWPathValue) -or
            $winSWPathValue -notmatch '^[A-Za-z]:\\' -or
            -not (Test-Path -LiteralPath $winSWPathValue -PathType Leaf)) {
            Add-Log '请选择本机磁盘上实际存在、经单位批准的 WinSW x64 文件。' 'error'
            return
        }
        $approvedWinSW = $winSWSha256Text.Text.Trim()
        if ($approvedWinSW -notmatch '^[A-Fa-f0-9]{64}$') {
            Add-Log 'WinSW SHA-256 必须是线下审批记录中的 64 位十六进制值。' 'error'
            return
        }
        $approvedConfig = $winSWConfigSha256Text.Text.Trim()
        $companionConfig = $winSWPathValue + '.config'
        if (Test-Path -LiteralPath $companionConfig -PathType Leaf) {
            if ($approvedConfig -notmatch '^[A-Fa-f0-9]{64}$') {
                Add-Log '所选 WinSW 带 .config；必须填写其线下批准的 64 位 SHA-256。' 'error'
                return
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($approvedConfig)) {
            Add-Log '所选 WinSW 不带 companion .config；对应 SHA-256 必须留空。' 'error'
            return
        }
        $approvedReleaseAnchor = (
            $releaseTrustText.Text -replace '\s', ''
        ).ToUpperInvariant()
        $useInternalUnsigned = $currentReleaseClassification -eq
            'unsigned-internal-release'
        $approvedSigner = ''
        $approvedManifest = ''
        if ($useInternalUnsigned) {
            if ($approvedReleaseAnchor -notmatch '^[A-F0-9]{64}$') {
                Add-Log '发行清单 SHA-256 必须是从安装介质之外的独立批准记录取得的 64 位十六进制值。' 'error'
                return
            }
            if (-not $independentRuntimeShaCheck.Checked) {
                Add-Log '必须显式勾选确认：已通过待安装介质之外的独立渠道核对 Platform 发行清单 SHA-256。' 'error'
                return
            }
            $approvedManifest = $approvedReleaseAnchor
            $confirmationText = (
                '该 INTERNAL-UNSIGNED 介质没有 Authenticode，Windows 无法验证发布者身份。' +
                '你已勾选确认 Platform 发行清单 SHA-256 来自安装介质之外的独立渠道；' +
                'WinSW SHA-256 也必须来自独立批准记录，' +
                '且本机位于受控内网。继续后仍会启用全部正式配置和 Secure Cookie 门禁。'
            )
            $confirmationTitle = '确认 INTERNAL-UNSIGNED 风险与外部摘要'
        } else {
            if ($approvedReleaseAnchor -notmatch '^[A-F0-9]{40}$') {
                Add-Log '签名者指纹必须是从介质外审批记录取得的 40 位证书 SHA-1 指纹。' 'error'
                return
            }
            $approvedSigner = $approvedReleaseAnchor
            $confirmationText = '请确认 WinSW 摘要和 Platform 签名者指纹均来自待安装介质之外的单位审批记录。继续后将安装并启动正式 Windows 服务。'
            $confirmationTitle = '确认外部信任锚'
        }
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $confirmationText,
            $confirmationTitle,
            [System.Windows.Forms.MessageBoxButtons]::OKCancel,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::OK) { return }
        Start-ServiceInstallOperation -WinSWExecutable $winSWPathValue `
            -ExpectedSha256 $approvedWinSW.ToUpperInvariant() `
            -ExpectedConfigSha256 $approvedConfig.ToUpperInvariant() `
            -ExpectedSignerThumbprint $approvedSigner `
            -ExpectedReleaseManifestSha256 $approvedManifest `
            -UseInternalUnsigned $useInternalUnsigned
    })

$startCurrentButton.Add_Click({ Start-ConfiguredServer -Mode existing })
$openButton.Add_Click({ Open-LeaderPage })
$stopButton.Add_Click({ [void](Stop-StartedServer) })
$refreshButton.Add_Click({
        Refresh-ConfigurationState
        Add-Log $script:ConfigurationState.message
    })

function Write-ServerCaptureLine {
    param([string] $Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return }
    $isStandardError = $Line.StartsWith('[STDERR] ')
    $text = if ($isStandardError -or $Line.StartsWith('[STDOUT] ')) {
        $Line.Substring(9)
    } else {
        $Line
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    # The GUI itself probes health every two seconds.  These successful access
    # lines are not useful to an operator and previously filled the pane with
    # misleading red "errors" because BaseHTTPRequestHandler logs to stderr.
    if ($text -match '"GET /(?:healthz|readyz) HTTP/1\.1" 200 (?:-|[0-9]+)$') { return }
    $level = 'info'
    if ($isStandardError) {
        if ($text -match '" [23][0-9]{2} (?:-|[0-9]+)$' -or
            $text -match '^(首次管理员账号|本机演示默认密码|MineGuard ·|状态目录：|业务前端只读)') {
            $level = 'info'
        } elseif ($text -match '" 4[0-9]{2} (?:-|[0-9]+)$') {
            $level = 'warning'
        } else {
            $level = 'error'
        }
    } elseif ($text -match '^\s*\{\s*"error"\s*:') {
        $level = 'error'
    }
    Add-Log $text $level
}

function Write-ShortProcessCaptureLine {
    param([string] $Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return }
    $isStandardError = $Line.StartsWith('[STDERR] ')
    $text = if ($isStandardError -or $Line.StartsWith('[STDOUT] ')) {
        $Line.Substring(9)
    } else { $Line }
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    if ($text -match '(?i)(MINEGUARD_ADMIN_PASSWORD|AdminPassword\s*[:=])') {
        Add-Log '独立 helper 返回了疑似敏感字段标签；该行已隐藏，请查看受控事件记录。' 'warning'
        return
    }
    if ($text.Length -gt 2048) {
        $text = $text.Substring(0, 2048) + '…[已截断]'
    }
    Add-Log $text $(if ($isStandardError) { 'error' } else { 'info' })
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
        if ($null -ne $script:FormalConfigCapture) {
            $formalLine = $null
            while ($script:FormalConfigCapture.Lines.TryDequeue(
                    [ref]$formalLine
                )) {
                Write-ShortProcessCaptureLine -Line $formalLine
                $formalLine = $null
            }
            if ($script:FormalConfigProcess.HasExited) {
                [void]$script:FormalConfigProcess.WaitForExit()
                while ($script:FormalConfigCapture.Lines.TryDequeue(
                        [ref]$formalLine
                    )) {
                    Write-ShortProcessCaptureLine -Line $formalLine
                    $formalLine = $null
                }
                $formalExitCode = $script:FormalConfigProcess.ExitCode
                $script:FormalConfigCapture.Dispose()
                $script:FormalConfigCapture = $null
                $script:FormalConfigProcess = $null
                Refresh-ConfigurationState
                if ($formalExitCode -eq 0 -and
                    $script:ConfigurationState.kind -eq 'formal') {
                    $statusLabel.Text = '正式配置完成，正在启动'
                    $statusLabel.ForeColor = $green
                    Add-Log '独立短生命周期 helper 已退出；主控制中心从未接收管理员密码。' 'success'
                    Start-ConfiguredServer -Mode formal
                } elseif ($formalExitCode -eq 3) {
                    $statusLabel.Text = '已取消正式配置'
                    $statusLabel.ForeColor = $muted
                    Add-Log '正式配置已取消，未写入密码或配置。' 'warning'
                    Set-BusyState -Busy $false
                } else {
                    $statusLabel.Text = '正式配置失败'
                    $statusLabel.ForeColor = $red
                    Add-Log "独立正式配置 helper 失败，退出码：$formalExitCode。" 'error'
                    Set-BusyState -Busy $false
                }
            }
        }
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
                $script:OperationPurpose = ''
                Refresh-ConfigurationState
                if ($operationFailed) {
                    $statusLabel.Text = if ($purpose -eq 'service-install') {
                        '服务安装失败'
                    } else { '配置失败' }
                    $statusLabel.ForeColor = $red
                    if ($purpose -eq 'service-install') {
                        Add-Log '正式服务未安装或已安全回滚；请按上方错误核对审批值后重试。' 'error'
                    } elseif ($purpose -eq 'demo' -and
                        $script:ConfigurationState.kind -eq 'demo') {
                        Add-Log '安全配置已保存，但演示数据未准备完成。修正上方问题后，再点击【补齐数据并启动展示】。' 'error'
                    } else {
                        Add-Log '准备未完成。配置文件事务已自动回滚；请按上方错误检查后重试。' 'error'
                    }
                } elseif ($purpose -eq 'service-install') {
                    $statusLabel.Text = '正式服务已安装并启动'
                    $statusLabel.ForeColor = $green
                    Add-Log 'MineGuardPlatform 正式 Windows 服务已安装并通过健康检查。' 'success'
                    Set-BusyState -Busy $false
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
                Write-ServerCaptureLine -Line $line
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
                $script:ServerControlToken = $null
                Set-BusyState -Busy $false
            } elseif (((Get-Date) - $script:LastHealthCheck).TotalSeconds -ge 2) {
                $script:LastHealthCheck = Get-Date
                $requireReady = ($script:ServerMode -eq 'formal')
                if (Test-MineGuardHealth -Port $script:ServerPort `
                        -RequireReady:$requireReady) {
                    if (-not $script:HealthConfirmed) {
                        $script:HealthConfirmed = $true
                        $statusLabel.Text = '服务正常'
                        $statusLabel.ForeColor = $green
                        Add-Log (
                            '{0}检查通过：http://127.0.0.1:{1}/' -f
                            $(if ($requireReady) { '正式就绪' } else { '健康' }),
                            $script:ServerPort
                        ) 'success'
                    }
                    $shouldOpenDemo = ($script:ServerMode -eq 'demo')
                    $shouldOpenFormal = (
                        $script:ServerMode -eq 'formal' -and
                        -not [string]::IsNullOrWhiteSpace($formalAccessUrl.Text)
                    )
                    if (($shouldOpenDemo -or $shouldOpenFormal) -and
                        -not $script:BrowserAutoAttempted) {
                        $script:BrowserAutoAttempted = $true
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
                '配置或服务事务正在执行，请等待操作退出后再关闭。',
                '请稍候',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            $eventArgs.Cancel = $true
            return
        }
        if ($null -ne $script:FormalConfigProcess) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                '关闭会精确终止独立正式配置 helper。若配置事务已开始，下次启动将按阻断标记拒绝并要求管理员恢复。是否继续？',
                '确认终止安全配置窗口',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes -or
                -not (Stop-FormalConfigurationProcess)) {
                $eventArgs.Cancel = $true
                return
            }
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
        if ($null -ne $script:FormalConfigCapture -or
            $null -ne $script:FormalConfigProcess) {
            [void](Stop-FormalConfigurationProcess)
        }
        if ($null -ne $script:ServerCapture) {
            $script:ServerCapture.Dispose()
        }
        foreach ($font in @($normalFont, $smallFont, $titleFont, $sectionFont, $monoFont)) {
            $font.Dispose()
        }
    })

$savedFormalAccessUrl = Read-SavedFormalAccessUrl
if (-not [string]::IsNullOrWhiteSpace($savedFormalAccessUrl)) {
    $formalAccessUrl.Text = $savedFormalAccessUrl
}
Refresh-ConfigurationState
$portInput.Value = [decimal]$script:ConfigurationState.port
Add-Log ('安装目录：' + $InstallRoot)
Add-Log ('本次诊断日志：' + $script:LogFilePath)
Add-Log $script:ConfigurationState.message
$timer.Start()
[void]$form.ShowDialog()
