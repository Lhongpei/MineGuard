[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-FatalMessage {
    param([string]$Message)
    [void][Windows.Forms.MessageBox]::Show(
        $Message,
        "MineGuard 模型授权导入向导",
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    )
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    Show-FatalMessage "本向导需要 Windows PowerShell 5.1。"
    exit 1
}

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $Builder = New-Object Text.StringBuilder
    [void]$Builder.Append([char]'"')
    $BackslashCount = 0
    foreach ($Character in $Value.ToCharArray()) {
        if ($Character -eq [char]'\') {
            $BackslashCount += 1
            continue
        }
        if ($Character -eq [char]'"') {
            [void]$Builder.Append([char]'\', (($BackslashCount * 2) + 1))
            [void]$Builder.Append([char]'"')
            $BackslashCount = 0
            continue
        }
        if ($BackslashCount -gt 0) {
            [void]$Builder.Append([char]'\', $BackslashCount)
            $BackslashCount = 0
        }
        [void]$Builder.Append($Character)
    }
    if ($BackslashCount -gt 0) {
        [void]$Builder.Append([char]'\', ($BackslashCount * 2))
    }
    [void]$Builder.Append([char]'"')
    return $Builder.ToString()
}

function Join-NativeArguments {
    param([Parameter(Mandatory = $true)][object[]]$Arguments)
    return (@($Arguments | ForEach-Object {
        if ($null -eq $_) { throw "拒绝把 null 作为原生命令参数。" }
        ConvertTo-WindowsCommandLineArgument -Value ([string]$_)
    }) -join " ")
}

$ScriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    Show-FatalMessage "无法确定向导脚本路径。"
    exit 1
}
$ScriptPath = [IO.Path]::GetFullPath($ScriptPath)
$ScriptDirectory = Split-Path -Parent $ScriptPath
if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Split-Path -Parent (Split-Path -Parent $ScriptDirectory)
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$ImportScript = Join-Path $ScriptDirectory `
    "Import-EnterpriseAgentModelCredential.ps1"
$SafetyHelper = Join-Path $ScriptDirectory `
    "EnterpriseAgent.WindowsSafety.ps1"
$FixedTrustStore = Join-Path $InstallRoot `
    "release-metadata\model-credential-trust.json"

if ($SelfTest) {
    foreach ($RequiredFile in @($ImportScript, $SafetyHelper, $FixedTrustStore)) {
        if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
            throw "模型授权向导缺少正式导入、安全组件或固定签发信任库。"
        }
    }
    $SelfTestResult = [ordered]@{
        status = "ok"
        component = "enterprise-agent-model-credential-wizard"
        powershell = $PSVersionTable.PSVersion.ToString()
        gui_mode = "windows-forms-ps51"
        trust_store = $FixedTrustStore
        trust_store_present = $true
        trust_store_editable = $false
        api_configuration_editable = $false
        secrets_on_command_line = $false
        controls_constructed = $true
    }
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $SelfTest -and -not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    try {
        $PowerShellPath = Join-Path $env:SystemRoot `
            "System32\WindowsPowerShell\v1.0\powershell.exe"
        $Arguments = Join-NativeArguments -Arguments @(
            "-NoProfile", "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass", "-STA",
            "-File", $ScriptPath,
            "-InstallRoot", $InstallRoot,
            "-StateRoot", $StateRoot
        )
        $StartInfo = New-Object Diagnostics.ProcessStartInfo
        $StartInfo.FileName = $PowerShellPath
        $StartInfo.Arguments = $Arguments
        $StartInfo.UseShellExecute = $true
        $StartInfo.Verb = "runas"
        [void][Diagnostics.Process]::Start($StartInfo)
    }
    catch {
        Show-FatalMessage ("导入模型授权需要管理员权限：" + $_.Exception.Message)
        exit 1
    }
    exit 0
}

foreach ($RequiredScript in @($ImportScript, $SafetyHelper)) {
    if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
        Show-FatalMessage "安装不完整，缺少模型凭据导入或安全组件。"
        exit 1
    }
}
. $SafetyHelper

if (-not $SelfTest) {
    try {
        $InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" `
            -PathValue $InstallRoot -MustExist -RequiredType Container -CheckTree
        $StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" `
            -PathValue $StateRoot -MustExist -RequiredType Container
        [void](Assert-EAStateRootMarker -StateRoot $StateRoot)
        $FixedTrustStore = Resolve-EASafeLocalPath -Name "已安装模型签发者信任库" `
            -PathValue (Join-Path $InstallRoot `
                "release-metadata\model-credential-trust.json") `
            -MustExist -RequiredType Leaf
        Assert-EAOrdinaryLeaf -Path $FixedTrustStore `
            -Name "已安装模型签发者信任库" -MaximumBytes 1MB
    }
    catch {
        Show-FatalMessage ("安装或信任库校验失败：" + $_.Exception.Message)
        exit 1
    }
}

[Windows.Forms.Application]::EnableVisualStyles()
[Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$NormalFont = New-Object Drawing.Font("Microsoft YaHei UI", 9)
$TitleFont = New-Object Drawing.Font(
    "Microsoft YaHei UI", 16, [Drawing.FontStyle]::Bold
)
$Muted = [Drawing.Color]::FromArgb(88, 96, 106)
$Green = [Drawing.Color]::FromArgb(24, 128, 72)
$Red = [Drawing.Color]::FromArgb(188, 45, 45)

$Form = New-Object Windows.Forms.Form
$Form.Text = "MineGuard 模型授权导入向导"
$Form.ClientSize = New-Object Drawing.Size(760, 475)
$Form.StartPosition = "CenterScreen"
$Form.MinimumSize = New-Object Drawing.Size(776, 514)
$Form.Font = $NormalFont
$Form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi

$Title = New-Object Windows.Forms.Label
$Title.Text = "为企业 Agent 导入模型授权"
$Title.Font = $TitleFont
$Title.Location = New-Object Drawing.Point(24, 17)
$Title.Size = New-Object Drawing.Size(520, 38)
$Form.Controls.Add($Title)

$Subtitle = New-Object Windows.Forms.Label
$Subtitle.Text = (
    "只需选择矿井实例、签发的 .mgllm 文件和独立激活码。" +
    "API 地址、模型、密钥和签发信任均由受管文件锁定。"
)
$Subtitle.ForeColor = $Muted
$Subtitle.Location = New-Object Drawing.Point(27, 57)
$Subtitle.Size = New-Object Drawing.Size(700, 42)
$Form.Controls.Add($Subtitle)

function Add-Label {
    param([string]$Text, [int]$Y)
    $Label = New-Object Windows.Forms.Label
    $Label.Text = $Text
    $Label.Location = New-Object Drawing.Point(28, ($Y + 4))
    $Label.Size = New-Object Drawing.Size(145, 24)
    $Form.Controls.Add($Label)
}

function Add-FileField {
    param([string]$LabelText, [int]$Y, [string]$Filter)
    Add-Label -Text $LabelText -Y $Y
    $Box = New-Object Windows.Forms.TextBox
    $Box.Location = New-Object Drawing.Point(176, $Y)
    $Box.Size = New-Object Drawing.Size(470, 25)
    $Box.ReadOnly = $true
    $Form.Controls.Add($Box)
    $Button = New-Object Windows.Forms.Button
    $Button.Text = "选择..."
    $Button.Location = New-Object Drawing.Point(654, ($Y - 1))
    $Button.Size = New-Object Drawing.Size(78, 28)
    $Button.Add_Click({
        $Dialog = New-Object Windows.Forms.OpenFileDialog
        $Dialog.Filter = $Filter
        $Dialog.CheckFileExists = $true
        $Dialog.Multiselect = $false
        if ($Dialog.ShowDialog($Form) -eq [Windows.Forms.DialogResult]::OK) {
            $Box.Text = $Dialog.FileName
        }
        $Dialog.Dispose()
    }.GetNewClosure())
    $Form.Controls.Add($Button)
    return [pscustomobject]@{ Box = $Box; Button = $Button }
}

Add-Label -Text "矿井实例" -Y 112
$InstanceBox = New-Object Windows.Forms.ComboBox
$InstanceBox.Location = New-Object Drawing.Point(176, 112)
$InstanceBox.Size = New-Object Drawing.Size(470, 25)
$InstanceBox.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
$Form.Controls.Add($InstanceBox)
$RefreshButton = New-Object Windows.Forms.Button
$RefreshButton.Text = "刷新"
$RefreshButton.Location = New-Object Drawing.Point(654, 111)
$RefreshButton.Size = New-Object Drawing.Size(78, 28)
$Form.Controls.Add($RefreshButton)

$BundleField = Add-FileField -LabelText "模型授权包（.mgllm）" -Y 153 `
    -Filter "MineGuard 模型授权包 (*.mgllm)|*.mgllm|所有文件 (*.*)|*.*"
$ActivationField = Add-FileField -LabelText "独立交付的激活码文件" -Y 194 `
    -Filter "MineGuard 激活码 (*.activation)|*.activation|文本文件 (*.txt;*.code)|*.txt;*.code|所有文件 (*.*)|*.*"

$TrustLabel = New-Object Windows.Forms.Label
$TrustLabel.Text = "签发信任库：已随正式软件安装并锁定，现场不可选择或替换。"
$TrustLabel.ForeColor = $Muted
$TrustLabel.Location = New-Object Drawing.Point(176, 231)
$TrustLabel.Size = New-Object Drawing.Size(556, 23)
$Form.Controls.Add($TrustLabel)

$ImportButton = New-Object Windows.Forms.Button
$ImportButton.Text = "验证并安全导入"
$ImportButton.Location = New-Object Drawing.Point(176, 267)
$ImportButton.Size = New-Object Drawing.Size(175, 36)
$Form.Controls.Add($ImportButton)

$CloseButton = New-Object Windows.Forms.Button
$CloseButton.Text = "关闭"
$CloseButton.Location = New-Object Drawing.Point(360, 267)
$CloseButton.Size = New-Object Drawing.Size(100, 36)
$CloseButton.Add_Click({ $Form.Close() })
$Form.Controls.Add($CloseButton)

$StatusLabel = New-Object Windows.Forms.Label
$StatusLabel.Text = "请选择材料。导入期间服务可能短暂停止，完成后恢复原运行状态。"
$StatusLabel.ForeColor = $Muted
$StatusLabel.Location = New-Object Drawing.Point(28, 319)
$StatusLabel.Size = New-Object Drawing.Size(704, 25)
$Form.Controls.Add($StatusLabel)

$ResultBox = New-Object Windows.Forms.TextBox
$ResultBox.Location = New-Object Drawing.Point(28, 350)
$ResultBox.Size = New-Object Drawing.Size(704, 92)
$ResultBox.Multiline = $true
$ResultBox.ReadOnly = $true
$ResultBox.ScrollBars = [Windows.Forms.ScrollBars]::Vertical
$Form.Controls.Add($ResultBox)

function Load-Instances {
    $Selected = [string]$InstanceBox.SelectedItem
    $InstanceBox.Items.Clear()
    foreach ($Directory in @(Get-ChildItem -LiteralPath $StateRoot `
            -Directory -Force | Sort-Object Name)) {
        if ($Directory.Name.StartsWith(".instance-staging-")) { continue }
        try {
            $Context = Get-EAInstanceContext -InstanceName $Directory.Name `
                -InstallRoot $InstallRoot -StateRoot $StateRoot
            if ([bool]$Context.Metadata.acl_hardened -and
                $null -ne (Get-EAServiceContext -Context $Context)) {
                [void]$InstanceBox.Items.Add($Directory.Name)
            }
        }
        catch {
            # An unsafe or incomplete directory is never offered as a target.
        }
    }
    if ($InstanceBox.Items.Count -eq 0) {
        $StatusLabel.Text = "没有发现已安装正式 Windows 服务的企业实例。"
        $StatusLabel.ForeColor = $Red
        return
    }
    $SelectionIndex = if ($Selected) {
        $InstanceBox.Items.IndexOf($Selected)
    } else { -1 }
    $InstanceBox.SelectedIndex = if ($SelectionIndex -ge 0) {
        $SelectionIndex
    } else { 0 }
    $StatusLabel.Text = "请选择材料。导入期间服务可能短暂停止，完成后恢复原运行状态。"
    $StatusLabel.ForeColor = $Muted
}

$RefreshButton.Add_Click({
    try { Load-Instances }
    catch {
        $StatusLabel.Text = "实例刷新失败：" + $_.Exception.Message
        $StatusLabel.ForeColor = $Red
    }
})

$ImportButton.Add_Click({
    if ($null -eq $InstanceBox.SelectedItem -or
        [string]::IsNullOrWhiteSpace($BundleField.Box.Text) -or
        [string]::IsNullOrWhiteSpace($ActivationField.Box.Text)) {
        $StatusLabel.Text = "请先选择实例、.mgllm 模型授权包和独立激活码文件。"
        $StatusLabel.ForeColor = $Red
        return
    }
    $Controls = @(
        $InstanceBox, $RefreshButton, $BundleField.Box, $BundleField.Button,
        $ActivationField.Box, $ActivationField.Button, $ImportButton,
        $CloseButton
    )
    foreach ($Control in $Controls) { $Control.Enabled = $false }
    $Form.UseWaitCursor = $true
    $StatusLabel.Text = "正在验签、加密保存并执行服务事务，请勿关闭窗口..."
    $StatusLabel.ForeColor = $Muted
    $ResultBox.Clear()
    [Windows.Forms.Application]::DoEvents()
    try {
        $Output = & $ImportScript `
            -BundlePath $BundleField.Box.Text `
            -ActivationCodeFile $ActivationField.Box.Text `
            -InstanceName ([string]$InstanceBox.SelectedItem) `
            -InstallRoot $InstallRoot `
            -StateRoot $StateRoot 2>&1 | Out-String
        $ResultBox.Text = $Output.Trim()
        $StatusLabel.Text = "模型授权已安全导入，正式配置自检通过。"
        $StatusLabel.ForeColor = $Green
        $BundleField.Box.Clear()
        $ActivationField.Box.Clear()
        [void][Windows.Forms.MessageBox]::Show(
            "模型授权导入成功。企业端无需也不能手工填写模型 API 配置。",
            "MineGuard 模型授权导入向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        $ResultBox.Text = $_.Exception.Message
        $StatusLabel.Text = "导入失败；若自动回滚完整，原服务状态已恢复。"
        $StatusLabel.ForeColor = $Red
    }
    finally {
        $Form.UseWaitCursor = $false
        foreach ($Control in $Controls) { $Control.Enabled = $true }
    }
})

if ($SelfTest) {
    try {
        $SelfTestResult | ConvertTo-Json -Compress | Write-Output
    }
    finally { $Form.Dispose() }
    return
}
try {
    Load-Instances
}
catch {
    $Form.Dispose()
    Show-FatalMessage ("无法读取实例列表：" + $_.Exception.Message)
    exit 1
}
try { [void]$Form.ShowDialog() }
finally { $Form.Dispose() }
