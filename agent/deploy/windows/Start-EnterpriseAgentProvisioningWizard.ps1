[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
$script:ExpectedHandoverCheckCode = ""

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-FatalMessage {
    param([string]$Message)
    [void][Windows.Forms.MessageBox]::Show(
        $Message,
        "MineGuard 企业接入配置向导",
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
    Show-FatalMessage "无法确定配置向导脚本路径。"
    exit 1
}
$ScriptPath = [IO.Path]::GetFullPath($ScriptPath)
$ScriptDirectory = Split-Path -Parent $ScriptPath
if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Split-Path -Parent (Split-Path -Parent $ScriptDirectory)
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$ImportScript = Join-Path $ScriptDirectory `
    "Import-EnterpriseAgentAccessPackage.ps1"
$UpdateScript = Join-Path $ScriptDirectory `
    "Update-EnterpriseAgentAccessPackage.ps1"
$ServiceInstallScript = Join-Path $ScriptDirectory `
    "Install-EnterpriseAgentService.ps1"
$SafetyHelper = Join-Path $ScriptDirectory `
    "EnterpriseAgent.WindowsSafety.ps1"
if ($SelfTest) {
    foreach ($RequiredScript in @(
            $ImportScript, $UpdateScript, $ServiceInstallScript, $SafetyHelper
        )) {
        if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
            throw "配置向导缺少接入、更新或正式服务安装组件。"
        }
    }
    [ordered]@{
        status = "ok"
        component = "enterprise-agent-provisioning-wizard"
        powershell = $PSVersionTable.PSVersion.ToString()
        gui_mode = "windows-forms-ps51"
        secrets_on_command_line = $false
    } | ConvertTo-Json -Compress | Write-Output
    return
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole(
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
        Show-FatalMessage ("首次配置需要管理员权限：" + $_.Exception.Message)
        exit 1
    }
    exit 0
}

foreach ($RequiredScript in @(
        $ImportScript, $UpdateScript, $ServiceInstallScript, $SafetyHelper
    )) {
    if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
        Show-FatalMessage "安装不完整，缺少接入、更新或正式服务安装组件。"
        exit 1
    }
}
. $SafetyHelper

[Windows.Forms.Application]::EnableVisualStyles()
[Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$NormalFont = New-Object Drawing.Font("Microsoft YaHei UI", 9)
$TitleFont = New-Object Drawing.Font(
    "Microsoft YaHei UI", 16, [Drawing.FontStyle]::Bold
)
$SectionFont = New-Object Drawing.Font(
    "Microsoft YaHei UI", 9, [Drawing.FontStyle]::Bold
)
$Muted = [Drawing.Color]::FromArgb(88, 96, 106)
$Green = [Drawing.Color]::FromArgb(24, 128, 72)
$Red = [Drawing.Color]::FromArgb(188, 45, 45)

$Form = New-Object Windows.Forms.Form
$Form.Text = "MineGuard 企业接入配置向导"
$Form.ClientSize = New-Object Drawing.Size(900, 750)
$Form.StartPosition = "CenterScreen"
$Form.MinimumSize = New-Object Drawing.Size(916, 788)
$Form.Font = $NormalFont
$Form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi

$Title = New-Object Windows.Forms.Label
$Title.Text = "导入本矿企业接入包"
$Title.Font = $TitleFont
$Title.Location = New-Object Drawing.Point(24, 16)
$Title.Size = New-Object Drawing.Size(500, 38)
$Form.Controls.Add($Title)

$Subtitle = New-Object Windows.Forms.Label
$Subtitle.Text = (
    "只需选择获批材料并设置两个本地账号。矿井身份、政府接口和逐矿密钥由签名包锁定。"
)
$Subtitle.ForeColor = $Muted
$Subtitle.Location = New-Object Drawing.Point(27, 56)
$Subtitle.Size = New-Object Drawing.Size(840, 24)
$Form.Controls.Add($Subtitle)

$LoadHandoverButton = New-Object Windows.Forms.Button
$LoadHandoverButton.Text = "加载企业交付目录"
$LoadHandoverButton.Location = New-Object Drawing.Point(584, 17)
$LoadHandoverButton.Size = New-Object Drawing.Size(184, 32)
$Form.Controls.Add($LoadHandoverButton)
$ManualEntryButton = New-Object Windows.Forms.Button
$ManualEntryButton.Text = "手工填写"
$ManualEntryButton.Location = New-Object Drawing.Point(778, 17)
$ManualEntryButton.Size = New-Object Drawing.Size(92, 32)
$Form.Controls.Add($ManualEntryButton)

function Add-SectionLabel {
    param([string]$Text, [int]$Y)
    $Label = New-Object Windows.Forms.Label
    $Label.Text = $Text
    $Label.Font = $SectionFont
    $Label.Location = New-Object Drawing.Point(26, $Y)
    $Label.Size = New-Object Drawing.Size(820, 22)
    $Form.Controls.Add($Label)
}

function Add-TextField {
    param(
        [string]$LabelText,
        [int]$Y,
        [int]$X = 188,
        [int]$Width = 600,
        [switch]$Password
    )
    $Label = New-Object Windows.Forms.Label
    $Label.Text = $LabelText
    $Label.Location = New-Object Drawing.Point(28, ($Y + 4))
    $Label.Size = New-Object Drawing.Size(155, 24)
    $Form.Controls.Add($Label)
    $Box = New-Object Windows.Forms.TextBox
    $Box.Location = New-Object Drawing.Point($X, $Y)
    $Box.Size = New-Object Drawing.Size($Width, 25)
    if ($Password) { $Box.UseSystemPasswordChar = $true }
    $Form.Controls.Add($Box)
    return $Box
}

function Add-FileField {
    param([string]$LabelText, [int]$Y, [string]$Filter)
    $Box = Add-TextField -LabelText $LabelText -Y $Y -Width 600
    $Button = New-Object Windows.Forms.Button
    $Button.Text = "选择..."
    $Button.Location = New-Object Drawing.Point(798, ($Y - 1))
    $Button.Size = New-Object Drawing.Size(72, 27)
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
    $Box.Tag = $Button
    $Form.Controls.Add($Button)
    return $Box
}

Add-SectionLabel -Text "一、选择离线审批材料" -Y 88
$BundleBox = Add-FileField -LabelText "企业接入包（.mgprov）" -Y 115 `
    -Filter "MineGuard 接入包 (*.mgprov)|*.mgprov|所有文件 (*.*)|*.*"
$ActivationBox = Add-FileField -LabelText "独立交付的激活码文件" -Y 148 `
    -Filter "MineGuard 激活码 (*.activation)|*.activation|文本文件 (*.txt;*.code)|*.txt;*.code|所有文件 (*.*)|*.*"
$TrustKeyBox = Add-FileField -LabelText "签发公钥 PEM" -Y 181 `
    -Filter "PEM 公钥 (*.pem)|*.pem|所有文件 (*.*)|*.*"
$TrustHashBox = Add-TextField -LabelText "介质外公钥 SHA-256" -Y 214 -Width 330
$IssuerKeyIdLabel = New-Object Windows.Forms.Label
$IssuerKeyIdLabel.Text = "issuer key ID"
$IssuerKeyIdLabel.Location = New-Object Drawing.Point(526, 218)
$IssuerKeyIdLabel.Size = New-Object Drawing.Size(100, 24)
$Form.Controls.Add($IssuerKeyIdLabel)
$IssuerKeyIdBox = New-Object Windows.Forms.TextBox
$IssuerKeyIdBox.Location = New-Object Drawing.Point(630, 214)
$IssuerKeyIdBox.Size = New-Object Drawing.Size(240, 25)
$Form.Controls.Add($IssuerKeyIdBox)
$CaBox = Add-FileField -LabelText "政府 HTTPS CA PEM" -Y 247 `
    -Filter "PEM 证书 (*.pem;*.crt)|*.pem;*.crt|所有文件 (*.*)|*.*"
$CaHashBox = Add-TextField -LabelText "介质外 CA 文件 SHA-256" -Y 280 -Width 682

Add-SectionLabel -Text "二、设置本机实例" -Y 320
$InstanceBox = Add-TextField -LabelText "实例名（英文小写）" -Y 347 -Width 250
$InstanceBox.Text = "mine-001"
$PortBox = Add-TextField -LabelText "本机端口" -Y 380 -Width 120
$PortBox.Text = "8090"

$ModeLabel = New-Object Windows.Forms.Label
$ModeLabel.Text = "操作模式"
$ModeLabel.Location = New-Object Drawing.Point(468, 351)
$ModeLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ModeLabel)
$ModeBox = New-Object Windows.Forms.ComboBox
$ModeBox.Location = New-Object Drawing.Point(585, 347)
$ModeBox.Size = New-Object Drawing.Size(285, 25)
$ModeBox.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
[void]$ModeBox.Items.Add("首次创建新实例")
[void]$ModeBox.Items.Add("安全更新现有实例")
$ModeBox.SelectedIndex = 0
$Form.Controls.Add($ModeBox)

Add-SectionLabel -Text "三、设置四眼复核账号" -Y 420
$PreparerIdBox = Add-TextField -LabelText "经办人登录名" -Y 447 -Width 250
$PreparerIdBox.Text = "preparer"
$PreparerNameBox = Add-TextField -LabelText "经办人姓名" -Y 480 -Width 250
$PreparerPasswordBox = Add-TextField -LabelText "经办人密码" -Y 513 `
    -Width 250 -Password
$PreparerConfirmBox = Add-TextField -LabelText "再次输入" -Y 546 `
    -Width 250 -Password

$ReviewerIdLabel = New-Object Windows.Forms.Label
$ReviewerIdLabel.Text = "复核人登录名"
$ReviewerIdLabel.Location = New-Object Drawing.Point(468, 451)
$ReviewerIdLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ReviewerIdLabel)
$ReviewerIdBox = New-Object Windows.Forms.TextBox
$ReviewerIdBox.Location = New-Object Drawing.Point(585, 447)
$ReviewerIdBox.Size = New-Object Drawing.Size(285, 25)
$ReviewerIdBox.Text = "reviewer"
$Form.Controls.Add($ReviewerIdBox)

$ReviewerNameLabel = New-Object Windows.Forms.Label
$ReviewerNameLabel.Text = "复核人姓名"
$ReviewerNameLabel.Location = New-Object Drawing.Point(468, 484)
$ReviewerNameLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ReviewerNameLabel)
$ReviewerNameBox = New-Object Windows.Forms.TextBox
$ReviewerNameBox.Location = New-Object Drawing.Point(585, 480)
$ReviewerNameBox.Size = New-Object Drawing.Size(285, 25)
$Form.Controls.Add($ReviewerNameBox)

$ReviewerPasswordLabel = New-Object Windows.Forms.Label
$ReviewerPasswordLabel.Text = "复核人密码"
$ReviewerPasswordLabel.Location = New-Object Drawing.Point(468, 517)
$ReviewerPasswordLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ReviewerPasswordLabel)
$ReviewerPasswordBox = New-Object Windows.Forms.TextBox
$ReviewerPasswordBox.Location = New-Object Drawing.Point(585, 513)
$ReviewerPasswordBox.Size = New-Object Drawing.Size(285, 25)
$ReviewerPasswordBox.UseSystemPasswordChar = $true
$Form.Controls.Add($ReviewerPasswordBox)

$ReviewerConfirmLabel = New-Object Windows.Forms.Label
$ReviewerConfirmLabel.Text = "再次输入"
$ReviewerConfirmLabel.Location = New-Object Drawing.Point(468, 550)
$ReviewerConfirmLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ReviewerConfirmLabel)
$ReviewerConfirmBox = New-Object Windows.Forms.TextBox
$ReviewerConfirmBox.Location = New-Object Drawing.Point(585, 546)
$ReviewerConfirmBox.Size = New-Object Drawing.Size(285, 25)
$ReviewerConfirmBox.UseSystemPasswordChar = $true
$Form.Controls.Add($ReviewerConfirmBox)

$PasswordHint = New-Object Windows.Forms.Label
$PasswordHint.Text = "正式密码至少 12 位，并至少包含大写、小写、数字、符号中的三类；两人密码必须不同。"
$PasswordHint.ForeColor = $Muted
$PasswordHint.Location = New-Object Drawing.Point(28, 580)
$PasswordHint.Size = New-Object Drawing.Size(840, 24)
$Form.Controls.Add($PasswordHint)

$VerificationCodeLabel = New-Object Windows.Forms.Label
$VerificationCodeLabel.Text = "独立核验码"
$VerificationCodeLabel.Location = New-Object Drawing.Point(28, 608)
$VerificationCodeLabel.Size = New-Object Drawing.Size(90, 24)
$Form.Controls.Add($VerificationCodeLabel)
$VerificationCodeBox = New-Object Windows.Forms.TextBox
$VerificationCodeBox.Location = New-Object Drawing.Point(122, 604)
$VerificationCodeBox.Size = New-Object Drawing.Size(125, 25)
$VerificationCodeBox.MaxLength = 12
$Form.Controls.Add($VerificationCodeBox)
$IndependentApprovalCheck = New-Object Windows.Forms.CheckBox
$IndependentApprovalCheck.Text = "核验码来自企业交付介质之外的监管方渠道"
$IndependentApprovalCheck.Location = New-Object Drawing.Point(260, 604)
$IndependentApprovalCheck.Size = New-Object Drawing.Size(610, 27)
$IndependentApprovalCheck.ForeColor = $Red
$Form.Controls.Add($IndependentApprovalCheck)

$StatusBox = New-Object Windows.Forms.TextBox
$StatusBox.Location = New-Object Drawing.Point(28, 632)
$StatusBox.Size = New-Object Drawing.Size(842, 45)
$StatusBox.Multiline = $true
$StatusBox.ReadOnly = $true
$StatusBox.ScrollBars = "Vertical"
$StatusBox.Text = "尚未导入。首次创建不覆盖实例；已有实例只能在显式更新模式中事务更新。"
$Form.Controls.Add($StatusBox)

$ImportButton = New-Object Windows.Forms.Button
$ImportButton.Text = "导入、锁定配置并执行正式预检"
$ImportButton.Location = New-Object Drawing.Point(568, 690)
$ImportButton.Size = New-Object Drawing.Size(302, 38)
$ImportButton.BackColor = $Green
$ImportButton.ForeColor = [Drawing.Color]::White
$ImportButton.FlatStyle = "Flat"
$Form.Controls.Add($ImportButton)

$ServiceInstallButton = New-Object Windows.Forms.Button
$ServiceInstallButton.Text = "安装并启动正式服务…"
$ServiceInstallButton.Location = New-Object Drawing.Point(28, 690)
$ServiceInstallButton.Size = New-Object Drawing.Size(410, 38)
$ServiceInstallButton.BackColor = [Drawing.Color]::FromArgb(43, 93, 152)
$ServiceInstallButton.ForeColor = [Drawing.Color]::White
$ServiceInstallButton.FlatStyle = "Flat"
$Form.Controls.Add($ServiceInstallButton)

$CloseButton = New-Object Windows.Forms.Button
$CloseButton.Text = "关闭"
$CloseButton.Location = New-Object Drawing.Point(455, 690)
$CloseButton.Size = New-Object Drawing.Size(100, 38)
$CloseButton.Add_Click({ $Form.Close() })
$Form.Controls.Add($CloseButton)

function Update-OperationModeUi {
    $IsUpdate = $ModeBox.SelectedIndex -eq 1
    foreach ($Control in @(
            $PortBox, $PreparerIdBox, $PreparerNameBox,
            $PreparerPasswordBox, $PreparerConfirmBox,
            $ReviewerIdBox, $ReviewerNameBox,
            $ReviewerPasswordBox, $ReviewerConfirmBox
        )) { $Control.Enabled = -not $IsUpdate }
    if ($IsUpdate) {
        $PreparerPasswordBox.Clear()
        $PreparerConfirmBox.Clear()
        $ReviewerPasswordBox.Clear()
        $ReviewerConfirmBox.Clear()
        $ImportButton.Text = "安全更新实例并执行正式预检"
        $PasswordHint.Text = "更新只替换受管通信配置和 CA，不重建账号、数据库、端口或业务数据；失败自动回滚。"
    }
    else {
        $ImportButton.Text = "导入、锁定配置并执行正式预检"
        $PasswordHint.Text = "正式密码至少 12 位，并至少包含大写、小写、数字、符号中的三类；两人密码必须不同。"
    }
}
$ModeBox.Add_SelectedIndexChanged({ Update-OperationModeUi })
Update-OperationModeUi

function Set-HandoverFieldsReadOnly {
    param([bool]$Locked)
    foreach ($Box in @(
            $BundleBox, $TrustKeyBox, $TrustHashBox, $IssuerKeyIdBox,
            $CaBox, $CaHashBox, $InstanceBox
        )) {
        $Box.ReadOnly = $Locked
        if ($Box.Tag -is [Windows.Forms.Button]) {
            $Box.Tag.Enabled = -not $Locked
        }
    }
}

function Resolve-HandoverArtifact {
    param([string]$Directory, [string]$FileName, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($FileName) -or
        [IO.Path]::IsPathRooted($FileName) -or $FileName.Contains('/') -or
        $FileName.Contains('\') -or $FileName.Contains(':') -or
        [IO.Path]::GetFileName($FileName) -ne $FileName -or
        $FileName -in @('.', '..')) {
        throw "$Label 在交接清单中不是安全的单一文件名。"
    }
    $Path = [IO.Path]::GetFullPath((Join-Path $Directory $FileName))
    if (-not (Split-Path -Parent $Path).Equals(
            $Directory, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label 不在所选企业交付目录中。"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 不存在：$FileName"
    }
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $Item.Length -le 0 -or $Item.Length -gt 4194304) {
        throw "$Label 必须是交付目录中的普通文件。"
    }
    return $Path
}

function Get-HandoverCheckCode {
    param(
        [string]$PairId,
        [string]$IssuerKeyId,
        [string]$SpkiSha256,
        [string]$CaSha256
    )
    $NormalizedSpki = ($SpkiSha256 -replace '\s', '').ToLowerInvariant()
    $NormalizedCa = ($CaSha256 -replace '\s', '').ToLowerInvariant()
    if ($PairId -notmatch `
        '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        $IssuerKeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $NormalizedSpki -notmatch '^[a-f0-9]{64}$' -or
        $NormalizedCa -notmatch '^[a-f0-9]{64}$') {
        throw "无法从当前材料计算独立核验码。"
    }
    $Material = "mineguard-handover-check-v1`n$PairId`n" +
        "$IssuerKeyId`n$NormalizedSpki`n$NormalizedCa"
    $Sha = [Security.Cryptography.SHA256]::Create()
    try {
        $Digest = $Sha.ComputeHash($Utf8NoBom.GetBytes($Material))
        return ([BitConverter]::ToString($Digest)).Replace(
            '-', ''
        ).ToLowerInvariant().Substring(0, 12)
    }
    finally { $Sha.Dispose(); $Material = $null }
}

function Test-FixedTimeCode {
    param([string]$Actual, [string]$Expected)
    $ActualBytes = [Text.Encoding]::ASCII.GetBytes($Actual)
    $ExpectedBytes = [Text.Encoding]::ASCII.GetBytes($Expected)
    $Difference = $ActualBytes.Length -bxor $ExpectedBytes.Length
    $Count = [Math]::Max($ActualBytes.Length, $ExpectedBytes.Length)
    for ($Index = 0; $Index -lt $Count; $Index++) {
        $Left = if ($Index -lt $ActualBytes.Length) {
            [int]$ActualBytes[$Index]
        } else { 0 }
        $Right = if ($Index -lt $ExpectedBytes.Length) {
            [int]$ExpectedBytes[$Index]
        } else { 0 }
        $Difference = $Difference -bor ($Left -bxor $Right)
    }
    return $Difference -eq 0
}

function Get-ManualHandoverCheckCode {
    if (-not (Test-Path -LiteralPath $BundleBox.Text -PathType Leaf)) {
        throw "企业接入包不存在，无法核验独立码。"
    }
    $Item = Get-Item -LiteralPath $BundleBox.Text -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $Item.Length -le 0 -or $Item.Length -gt 4194304) {
        throw "企业接入包必须是 1-4 MiB 的普通文件。"
    }
    try {
        $Bundle = Get-Content -LiteralPath $BundleBox.Text -Raw `
            -Encoding UTF8 | ConvertFrom-Json
    }
    catch { throw "企业接入包不是有效 JSON，无法核验独立码。" }
    $PairId = [string]$Bundle.protected.pair_id
    $BundleIssuerKeyId = [string]$Bundle.protected.issuer_key_id
    if (-not [string]::Equals(
            $BundleIssuerKeyId, $IssuerKeyIdBox.Text,
            [StringComparison]::Ordinal)) {
        throw "接入包 issuer key ID 与输入值不一致。"
    }
    return Get-HandoverCheckCode -PairId $PairId `
        -IssuerKeyId $BundleIssuerKeyId -SpkiSha256 $TrustHashBox.Text `
        -CaSha256 $CaHashBox.Text
}

function Import-EnterpriseHandoverDirectory {
    param([string]$Directory)
    if ([string]::IsNullOrWhiteSpace($Directory) -or
        $Directory -notmatch '^[A-Za-z]:\\') {
        throw "企业交付目录必须是 X:\\... 形式的本机完整路径。"
    }
    $Directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "企业交付目录不存在。"
    }
    $DirectoryItem = Get-Item -LiteralPath $Directory -Force
    if (($DirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "企业交付目录不能是符号链接或 junction。"
    }
    $ManifestPath = Join-Path $Directory `
        'enterprise-install-manifest.json'
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "目录缺少 enterprise-install-manifest.json；请使用监管端接入包向导生成的完整企业交付目录。"
    }
    $ManifestItem = Get-Item -LiteralPath $ManifestPath -Force
    if (($ManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $ManifestItem.Length -le 0 -or $ManifestItem.Length -gt 65536) {
        throw "企业安装交接清单必须是 1-65536 字节的普通文件。"
    }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw `
            -Encoding UTF8 | ConvertFrom-Json
    }
    catch { throw "企业安装交接清单不是有效 JSON。" }
    if ([string]$Manifest.schema_version -ne
        'mineguard-enterprise-install-manifest-v1' -or
        $Manifest.activation_included -isnot [bool] -or
        [bool]$Manifest.activation_included -or
        $Manifest.secrets_disclosed -isnot [bool] -or
        [bool]$Manifest.secrets_disclosed) {
        throw "企业安装交接清单版本或无秘密声明无效。"
    }
    $TrustHash = ([string]$Manifest.issuer_public_key_sha256).ToLowerInvariant()
    $CaHash = ([string]$Manifest.platform_ca_sha256).ToLowerInvariant()
    $IssuerKeyId = [string]$Manifest.issuer_key_id
    $InstanceName = [string]$Manifest.agent_instance_name
    if ($TrustHash -notmatch '^[a-f0-9]{64}$' -or
        $CaHash -notmatch '^[a-f0-9]{64}$' -or
        $IssuerKeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $InstanceName -notmatch '^[a-z0-9][a-z0-9-]{0,47}$') {
        throw "企业安装交接清单中的指纹、issuer key ID 或实例名格式无效。"
    }
    $BundlePath = Resolve-HandoverArtifact -Directory $Directory `
        -FileName ([string]$Manifest.agent_bundle_file) `
        -Label "企业接入包"
    $PublicKeyPath = Resolve-HandoverArtifact -Directory $Directory `
        -FileName ([string]$Manifest.issuer_public_key_file) `
        -Label "签发公钥"
    $CaPath = Resolve-HandoverArtifact -Directory $Directory `
        -FileName ([string]$Manifest.platform_ca_file) `
        -Label "政府 HTTPS CA"
    $BundleBox.Text = $BundlePath
    $TrustKeyBox.Text = $PublicKeyPath
    $TrustHashBox.Text = $TrustHash
    $IssuerKeyIdBox.Text = $IssuerKeyId
    $CaBox.Text = $CaPath
    $CaHashBox.Text = $CaHash
    $InstanceBox.Text = $InstanceName
    $script:ExpectedHandoverCheckCode = Get-HandoverCheckCode `
        -PairId ([string]$Manifest.pair_id) -IssuerKeyId $IssuerKeyId `
        -SpkiSha256 $TrustHash -CaSha256 $CaHash
    $ExistingInstancePath = Join-Path $StateRoot $InstanceName
    if ([int]$Manifest.profile_version -gt 1 -or
        (Test-Path -LiteralPath $ExistingInstancePath -PathType Container)) {
        $ModeBox.SelectedIndex = 1
    }
    else { $ModeBox.SelectedIndex = 0 }
    Set-HandoverFieldsReadOnly -Locked $true
    $IndependentApprovalCheck.Checked = $false
    $StatusBox.ForeColor = $Muted
    $StatusBox.Text = (
        "已自动加载企业交付清单：$ManifestPath`r`n" +
        "pair_id=$($Manifest.pair_id)，profile_version=$($Manifest.profile_version)。" +
        "仍须从交付介质之外取得监管方 12 位独立核验码；激活码也必须从另一渠道另选。"
    )
}

$LoadHandoverButton.Add_Click({
    $Dialog = New-Object Windows.Forms.FolderBrowserDialog
    $Dialog.Description = "选择监管端生成的企业交付目录"
    $Dialog.ShowNewFolderButton = $false
    try {
        if ($Dialog.ShowDialog($Form) -eq [Windows.Forms.DialogResult]::OK) {
            Import-EnterpriseHandoverDirectory -Directory $Dialog.SelectedPath
        }
    }
    catch {
        $StatusBox.ForeColor = $Red
        $StatusBox.Text = "交接清单加载失败：`r`n" + $_.Exception.Message
        [void][Windows.Forms.MessageBox]::Show(
            $StatusBox.Text, "MineGuard 企业接入配置向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally { $Dialog.Dispose() }
})
$ManualEntryButton.Add_Click({
    Set-HandoverFieldsReadOnly -Locked $false
    $script:ExpectedHandoverCheckCode = ""
    $IndependentApprovalCheck.Checked = $false
    $StatusBox.ForeColor = $Muted
    $StatusBox.Text = "已切换为手工填写。仍须从交付介质之外取得监管方独立核验码；激活码另渠道选择。"
})

function Get-InstalledAgentServiceTrustMode {
    $MetadataRoot = Join-Path $InstallRoot "release-metadata"
    $ManifestPath = Join-Path $MetadataRoot "release-manifest.json"
    $BuildMetadataPath = Join-Path $MetadataRoot "build-metadata.json"
    foreach ($PathValue in @($ManifestPath, $BuildMetadataPath)) {
        if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
            throw "已安装程序缺少发行分类信息，不能打开正式服务安装。"
        }
    }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        $BuildMetadata = Get-Content -LiteralPath $BuildMetadataPath -Raw `
            -Encoding UTF8 | ConvertFrom-Json
    }
    catch { throw "已安装程序的发行分类信息无法读取。" }
    $ManifestClassificationProperty = `
        $Manifest.PSObject.Properties["release_classification"]
    $BuildClassificationProperty = `
        $BuildMetadata.PSObject.Properties["release_classification"]
    $ManifestClassification = if ($null -eq $ManifestClassificationProperty) {
        ""
    } else {
        [string]$ManifestClassificationProperty.Value
    }
    $BuildClassification = if ($null -eq $BuildClassificationProperty) {
        ""
    } else {
        [string]$BuildClassificationProperty.Value
    }
    if ($ManifestClassification -eq "unsigned-internal-release" -and
        $BuildClassification -eq "unsigned-internal-release" -and
        $Manifest.authenticode_signed -is [bool] -and
        $BuildMetadata.authenticode_signed -is [bool] -and
        -not [bool]$Manifest.authenticode_signed -and
        -not [bool]$BuildMetadata.authenticode_signed) {
        return "internal-unsigned"
    }
    if ($Manifest.authenticode_signed -is [bool] -and
        $BuildMetadata.authenticode_signed -is [bool] -and
        [bool]$Manifest.authenticode_signed -and
        [bool]$BuildMetadata.authenticode_signed -and
        ($ManifestClassification -in @("", "signed-production-candidate")) -and
        ($BuildClassification -in @("", "signed-production-candidate"))) {
        return "signed"
    }
    throw "当前安装介质不是签名正式版或明确分类的内网无证书正式发行版，不能安装正式服务。"
}

function Show-FormalServiceInstallDialog {
    param([Parameter(Mandatory = $true)][string]$InstanceName)

    # This is a GUI-side preflight only. The service installer repeats the full
    # path, ownership, metadata, ACL, signer, hash and runtime checks immediately
    # before it changes Windows service state.
    $InstanceContext = Get-EAInstanceContext -InstanceName $InstanceName `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    $InstanceContext = $null
    $ServiceTrustMode = Get-InstalledAgentServiceTrustMode
    $InternalUnsignedMode = $ServiceTrustMode -eq "internal-unsigned"

    $ServiceDialog = New-Object Windows.Forms.Form
    $ServiceDialog.Text = "安装并启动 MineGuard 正式服务"
    $ServiceDialog.ClientSize = New-Object Drawing.Size(720, 370)
    $ServiceDialog.StartPosition = "CenterParent"
    $ServiceDialog.FormBorderStyle = `
        [Windows.Forms.FormBorderStyle]::FixedDialog
    $ServiceDialog.MaximizeBox = $false
    $ServiceDialog.MinimizeBox = $false
    $ServiceDialog.ShowInTaskbar = $false
    $ServiceDialog.Font = $NormalFont

    $ServiceTitle = New-Object Windows.Forms.Label
    $ServiceTitle.Text = "正式 Windows 服务安装"
    $ServiceTitle.Font = $SectionFont
    $ServiceTitle.Location = New-Object Drawing.Point(22, 18)
    $ServiceTitle.Size = New-Object Drawing.Size(660, 26)
    $ServiceDialog.Controls.Add($ServiceTitle)

    $InstanceLabel = New-Object Windows.Forms.Label
    $InstanceLabel.Text = "已验证实例"
    $InstanceLabel.Location = New-Object Drawing.Point(22, 58)
    $InstanceLabel.Size = New-Object Drawing.Size(145, 24)
    $ServiceDialog.Controls.Add($InstanceLabel)
    $SelectedInstanceBox = New-Object Windows.Forms.TextBox
    $SelectedInstanceBox.Text = $InstanceName
    $SelectedInstanceBox.Location = New-Object Drawing.Point(174, 54)
    $SelectedInstanceBox.Size = New-Object Drawing.Size(510, 25)
    $SelectedInstanceBox.ReadOnly = $true
    $ServiceDialog.Controls.Add($SelectedInstanceBox)

    $WinSWLabel = New-Object Windows.Forms.Label
    $WinSWLabel.Text = "批准的 WinSW 文件"
    $WinSWLabel.Location = New-Object Drawing.Point(22, 98)
    $WinSWLabel.Size = New-Object Drawing.Size(145, 24)
    $ServiceDialog.Controls.Add($WinSWLabel)
    $WinSWBox = New-Object Windows.Forms.TextBox
    $WinSWBox.Location = New-Object Drawing.Point(174, 94)
    $WinSWBox.Size = New-Object Drawing.Size(420, 25)
    $ServiceDialog.Controls.Add($WinSWBox)
    $WinSWSelectButton = New-Object Windows.Forms.Button
    $WinSWSelectButton.Text = "选择…"
    $WinSWSelectButton.Location = New-Object Drawing.Point(604, 92)
    $WinSWSelectButton.Size = New-Object Drawing.Size(80, 29)
    $ServiceDialog.Controls.Add($WinSWSelectButton)

    $WinSWHashLabel = New-Object Windows.Forms.Label
    $WinSWHashLabel.Text = "介质外 WinSW SHA-256"
    $WinSWHashLabel.Location = New-Object Drawing.Point(22, 138)
    $WinSWHashLabel.Size = New-Object Drawing.Size(150, 24)
    $ServiceDialog.Controls.Add($WinSWHashLabel)
    $WinSWHashBox = New-Object Windows.Forms.TextBox
    $WinSWHashBox.Location = New-Object Drawing.Point(174, 134)
    $WinSWHashBox.Size = New-Object Drawing.Size(510, 25)
    $WinSWHashBox.MaxLength = 96
    $ServiceDialog.Controls.Add($WinSWHashBox)

    $SignerLabel = New-Object Windows.Forms.Label
    $SignerLabel.Text = if ($InternalUnsignedMode) {
        "Agent 发行清单 SHA-256"
    } else {
        "Agent runtime 签名者 SHA-1"
    }
    $SignerLabel.Location = New-Object Drawing.Point(22, 178)
    $SignerLabel.Size = New-Object Drawing.Size(170, 24)
    $ServiceDialog.Controls.Add($SignerLabel)
    $SignerBox = New-Object Windows.Forms.TextBox
    $SignerBox.Location = New-Object Drawing.Point(194, 174)
    $SignerBox.Size = New-Object Drawing.Size(490, 25)
    $SignerBox.MaxLength = if ($InternalUnsignedMode) { 96 } else { 72 }
    $ServiceDialog.Controls.Add($SignerBox)

    $ServiceNote = New-Object Windows.Forms.Label
    $ServiceNote.Text = if ($InternalUnsignedMode) {
        "警告：该版本没有 Windows 发布者签名。WinSW 和 Agent 子发行清单的 SHA-256 " +
        "都必须从安装介质之外的审批记录手工输入；本窗口不会自动计算或替你信任包内数值。"
    } else {
        "WinSW 必须先复制到本机固定 NTFS 目录。本窗口不会下载、捆绑或自动计算批准值；" +
        "两个核验值必须由操作员从所选文件之外的审批记录手工输入。"
    }
    $ServiceNote.ForeColor = if ($InternalUnsignedMode) { $Red } else { $Muted }
    $ServiceNote.Location = New-Object Drawing.Point(24, 216)
    $ServiceNote.Size = New-Object Drawing.Size(660, 48)
    $ServiceDialog.Controls.Add($ServiceNote)

    $ServiceApprovalCheck = New-Object Windows.Forms.CheckBox
    $ServiceApprovalCheck.Text = if ($InternalUnsignedMode) {
        "确认两个 SHA-256 已通过独立渠道核对，理解无发布者签名风险，并立即启动和健康检查"
    } else {
        "确认两个核验值来自介质外审批记录，并同意安装后立即启动和健康检查"
    }
    $ServiceApprovalCheck.ForeColor = $Red
    $ServiceApprovalCheck.Location = New-Object Drawing.Point(26, 270)
    $ServiceApprovalCheck.Size = New-Object Drawing.Size(658, 27)
    $ServiceDialog.Controls.Add($ServiceApprovalCheck)

    $ServiceCancelButton = New-Object Windows.Forms.Button
    $ServiceCancelButton.Text = "取消"
    $ServiceCancelButton.Location = New-Object Drawing.Point(400, 316)
    $ServiceCancelButton.Size = New-Object Drawing.Size(90, 34)
    $ServiceCancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $ServiceDialog.Controls.Add($ServiceCancelButton)
    $InstallServiceNowButton = New-Object Windows.Forms.Button
    $InstallServiceNowButton.Text = "安装、启动并健康检查"
    $InstallServiceNowButton.Location = New-Object Drawing.Point(502, 316)
    $InstallServiceNowButton.Size = New-Object Drawing.Size(182, 34)
    $InstallServiceNowButton.BackColor = $Green
    $InstallServiceNowButton.ForeColor = [Drawing.Color]::White
    $InstallServiceNowButton.FlatStyle = "Flat"
    $ServiceDialog.Controls.Add($InstallServiceNowButton)
    $ServiceDialog.CancelButton = $ServiceCancelButton

    $WinSWSelectButton.Add_Click({
        $Picker = New-Object Windows.Forms.OpenFileDialog
        $Picker.Title = "选择单位批准的 WinSW x64 可执行文件"
        $Picker.Filter = "WinSW 可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
        $Picker.CheckFileExists = $true
        $Picker.Multiselect = $false
        try {
            if ($Picker.ShowDialog($ServiceDialog) -eq `
                    [Windows.Forms.DialogResult]::OK) {
                $WinSWBox.Text = $Picker.FileName
            }
        }
        finally { $Picker.Dispose() }
    })

    $InstallServiceNowButton.Add_Click({
        $ExpectedWinSWHash = $null
        $ApprovedRuntimeValue = $null
        $InstallServiceNowButton.Enabled = $false
        $ServiceDialog.UseWaitCursor = $true
        try {
            if (-not $ServiceApprovalCheck.Checked) {
                throw "必须确认两个核验值来自介质外审批记录并接受当前发行模式。"
            }
            if (-not (Test-Path -LiteralPath $WinSWBox.Text -PathType Leaf)) {
                throw "请选择已复制到本机固定 NTFS 目录的 WinSW 可执行文件。"
            }
            $ExpectedWinSWHash = (
                $WinSWHashBox.Text -replace '\s', ''
            ).ToUpperInvariant()
            $ApprovedRuntimeValue = (
                $SignerBox.Text -replace '\s', ''
            ).ToUpperInvariant()
            $WinSWHashBox.Clear()
            $SignerBox.Clear()
            if ($ExpectedWinSWHash -cnotmatch '^[A-F0-9]{64}$') {
                throw "介质外 WinSW SHA-256 必须是 64 位十六进制。"
            }
            if ($InternalUnsignedMode) {
                if ($ApprovedRuntimeValue -cnotmatch '^[A-F0-9]{64}$') {
                    throw "介质外 Agent 发行清单 SHA-256 必须是 64 位十六进制。"
                }
            }
            elseif ($ApprovedRuntimeValue -cnotmatch '^[A-F0-9]{40}$') {
                throw "Agent runtime 签名者 SHA-1 指纹必须是 40 位十六进制。"
            }
            # Re-resolve the instance immediately before the mutating script to
            # close the GUI validation/use interval as far as practical.
            $ValidatedContext = Get-EAInstanceContext `
                -InstanceName $InstanceName -InstallRoot $InstallRoot `
                -StateRoot $StateRoot
            $ValidatedContext = $null
            if ($InternalUnsignedMode) {
                & $ServiceInstallScript `
                    -InstanceName $InstanceName `
                    -WinSWPath $WinSWBox.Text `
                    -WinSWExpectedSha256 $ExpectedWinSWHash `
                    -AllowUnsignedInternalRelease `
                    -ExpectedReleaseManifestSha256 $ApprovedRuntimeValue `
                    -InstallRoot $InstallRoot `
                    -StateRoot $StateRoot `
                    -Start `
                    1>$null 3>$null 4>$null 5>$null 6>$null
            }
            else {
                & $ServiceInstallScript `
                    -InstanceName $InstanceName `
                    -WinSWPath $WinSWBox.Text `
                    -WinSWExpectedSha256 $ExpectedWinSWHash `
                    -ApprovedSignerThumbprint $ApprovedRuntimeValue `
                    -InstallRoot $InstallRoot `
                    -StateRoot $StateRoot `
                    -Start `
                    1>$null 3>$null 4>$null 5>$null 6>$null
            }
            $StatusBox.ForeColor = $Green
            $StatusBox.Text = (
                "正式服务已安装、启动并通过绑定当前实例的健康检查：" +
                $InstanceName
            )
            [void][Windows.Forms.MessageBox]::Show(
                $StatusBox.Text,
                "MineGuard 企业接入配置向导",
                [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Information
            )
            $ServiceDialog.DialogResult = [Windows.Forms.DialogResult]::OK
            $ServiceDialog.Close()
        }
        catch {
            $Message = "正式服务安装未完成：`r`n" + $_.Exception.Message
            [void][Windows.Forms.MessageBox]::Show(
                $Message,
                "MineGuard 企业接入配置向导",
                [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Error
            )
        }
        finally {
            $ExpectedWinSWHash = $null
            $ApprovedRuntimeValue = $null
            $WinSWHashBox.Clear()
            $SignerBox.Clear()
            $ServiceDialog.UseWaitCursor = $false
            $InstallServiceNowButton.Enabled = $true
        }
    })

    $ServiceDialog.Add_FormClosed({
        $WinSWHashBox.Clear()
        $SignerBox.Clear()
    })
    try { [void]$ServiceDialog.ShowDialog($Form) }
    finally { $ServiceDialog.Dispose() }
}

$ServiceInstallButton.Add_Click({
    $ServiceInstallButton.Enabled = $false
    try {
        $SelectedInstance = $InstanceBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($SelectedInstance)) {
            throw "请先在主界面填写或加载要安装服务的实例名。"
        }
        Show-FormalServiceInstallDialog -InstanceName $SelectedInstance
    }
    catch {
        $StatusBox.ForeColor = $Red
        $StatusBox.Text = "无法打开正式服务安装：`r`n" + `
            $_.Exception.Message
        [void][Windows.Forms.MessageBox]::Show(
            $StatusBox.Text,
            "MineGuard 企业接入配置向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally { $ServiceInstallButton.Enabled = $true }
})

$ImportButton.Add_Click({
    $ImportButton.Enabled = $false
    $Form.UseWaitCursor = $true
    $StatusBox.ForeColor = $Muted
    $IsUpdate = $ModeBox.SelectedIndex -eq 1
    $StatusBox.Text = if ($IsUpdate) {
        "正在离线验签、停止本实例服务并执行可回滚配置更新，请稍候..."
    } else {
        "正在离线验签、解密、创建实例并执行正式配置预检，请稍候..."
    }
    $Form.Refresh()
    $PreparerSecure = $null
    $PreparerConfirmSecure = $null
    $ReviewerSecure = $null
    $ReviewerConfirmSecure = $null
    try {
        if (-not $IndependentApprovalCheck.Checked) {
            throw "必须确认独立核验码来自企业交付介质之外的监管方渠道。"
        }
        $ActualCheckCode = $VerificationCodeBox.Text.Trim().ToLowerInvariant()
        $VerificationCodeBox.Clear()
        if ($ActualCheckCode -notmatch '^[a-f0-9]{12}$') {
            throw "独立核验码必须是监管方另行告知的 12 位小写十六进制。"
        }
        $ExpectedCheckCode = if (
            [string]::IsNullOrWhiteSpace($script:ExpectedHandoverCheckCode)
        ) { Get-ManualHandoverCheckCode } else {
            $script:ExpectedHandoverCheckCode
        }
        if (-not (Test-FixedTimeCode -Actual $ActualCheckCode `
                -Expected $ExpectedCheckCode)) {
            $ActualCheckCode = $null
            throw "独立核验码不匹配；请停止导入并联系监管方重新核对交付材料。"
        }
        $ActualCheckCode = $null
        if ($IsUpdate) {
            $Result = & $UpdateScript `
                -BundlePath $BundleBox.Text `
                -ActivationCodeFile $ActivationBox.Text `
                -TrustKeyPath $TrustKeyBox.Text `
                -ExpectedTrustKeySha256 $TrustHashBox.Text `
                -ExpectedIssuerKeyId $IssuerKeyIdBox.Text `
                -CaSourcePath $CaBox.Text `
                -ExpectedCaSha256 $CaHashBox.Text `
                -InstanceName $InstanceBox.Text `
                -InstallRoot $InstallRoot `
                -StateRoot $StateRoot
        }
        else {
            if ([string]::IsNullOrWhiteSpace($PreparerPasswordBox.Text) -or
                [string]::IsNullOrWhiteSpace($ReviewerPasswordBox.Text)) {
                throw "请填写经办人和复核人密码。"
            }
            $PreparerSecure = ConvertTo-SecureString $PreparerPasswordBox.Text `
                -AsPlainText -Force
            $PreparerConfirmSecure = ConvertTo-SecureString $PreparerConfirmBox.Text `
                -AsPlainText -Force
            $ReviewerSecure = ConvertTo-SecureString $ReviewerPasswordBox.Text `
                -AsPlainText -Force
            $ReviewerConfirmSecure = ConvertTo-SecureString $ReviewerConfirmBox.Text `
                -AsPlainText -Force
            $PreparerPasswordBox.Clear()
            $PreparerConfirmBox.Clear()
            $ReviewerPasswordBox.Clear()
            $ReviewerConfirmBox.Clear()
            $Result = & $ImportScript `
                -BundlePath $BundleBox.Text `
                -ActivationCodeFile $ActivationBox.Text `
                -TrustKeyPath $TrustKeyBox.Text `
                -ExpectedTrustKeySha256 $TrustHashBox.Text `
                -ExpectedIssuerKeyId $IssuerKeyIdBox.Text `
                -CaSourcePath $CaBox.Text `
                -ExpectedCaSha256 $CaHashBox.Text `
                -InstanceName $InstanceBox.Text `
                -Port ([int]$PortBox.Text) `
                -PreparerActorId $PreparerIdBox.Text `
                -PreparerName $PreparerNameBox.Text `
                -PreparerPassword $PreparerSecure `
                -PreparerPasswordConfirmation $PreparerConfirmSecure `
                -ReviewerActorId $ReviewerIdBox.Text `
                -ReviewerName $ReviewerNameBox.Text `
                -ReviewerPassword $ReviewerSecure `
                -ReviewerPasswordConfirmation $ReviewerConfirmSecure `
                -InstallRoot $InstallRoot `
                -StateRoot $StateRoot
        }
        $Summary = @($Result | ForEach-Object { [string]$_ }) -join `
            [Environment]::NewLine
        $StatusBox.Text = if ([string]::IsNullOrWhiteSpace($Summary)) {
            if ($IsUpdate) {
                "现有实例已安全更新，账号、数据库和业务数据未改动。"
            } else { "企业接入包已导入并通过正式预检。" }
        } else { $Summary }
        if (-not $IsUpdate) {
            $StatusBox.Text += (
                "`r`n当前只完成实例配置和正式预检，尚未启动或安装 Windows 服务。" +
                "准备好批准材料后，可点击左下角安装并启动正式服务。"
            )
        }
        $StatusBox.ForeColor = $Green
        $SuccessMessage = if ($IsUpdate) {
            "更新完成。受管配置已事务切换并通过正式预检；原服务状态已恢复。"
        } else {
            "配置完成，接入包身份已锁定且正式预检通过；当前尚未启动。准备好批准材料后，可点击左下角安装并启动正式服务。"
        }
        [void][Windows.Forms.MessageBox]::Show(
            $SuccessMessage,
            "MineGuard 企业接入配置向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        $VerificationCodeBox.Clear()
        $IndependentApprovalCheck.Checked = $false
        $PreparerPasswordBox.Clear()
        $PreparerConfirmBox.Clear()
        $ReviewerPasswordBox.Clear()
        $ReviewerConfirmBox.Clear()
        $StatusBox.Text = if ($IsUpdate) {
            "更新失败；安全脚本已尝试回滚并恢复原服务状态。`r`n" +
                $_.Exception.Message
        } else {
            "导入失败，未覆盖任何现有实例。`r`n" + $_.Exception.Message
        }
        $StatusBox.ForeColor = $Red
        [void][Windows.Forms.MessageBox]::Show(
            $StatusBox.Text,
            "MineGuard 企业接入配置向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally {
        foreach ($SecureValue in @(
                $PreparerSecure, $PreparerConfirmSecure,
                $ReviewerSecure, $ReviewerConfirmSecure
            )) {
            if ($null -ne $SecureValue) { $SecureValue.Dispose() }
        }
        $PreparerSecure = $null; $PreparerConfirmSecure = $null
        $ReviewerSecure = $null; $ReviewerConfirmSecure = $null
        $PreparerPasswordBox.Clear()
        $PreparerConfirmBox.Clear()
        $ReviewerPasswordBox.Clear()
        $ReviewerConfirmBox.Clear()
        $Form.UseWaitCursor = $false
        $ImportButton.Enabled = $true
    }
})

$Form.Add_FormClosed({
    $VerificationCodeBox.Clear()
    $PreparerPasswordBox.Clear(); $PreparerConfirmBox.Clear()
    $ReviewerPasswordBox.Clear(); $ReviewerConfirmBox.Clear()
})
[void]$Form.ShowDialog()
