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
$ServiceInstallScript = Join-Path $ScriptDirectory `
    "Install-EnterpriseAgentService.ps1"
$SafetyHelper = Join-Path $ScriptDirectory `
    "EnterpriseAgent.WindowsSafety.ps1"
if ($SelfTest) {
    foreach ($RequiredScript in @(
            $ImportScript, $ServiceInstallScript, $SafetyHelper
        )) {
        if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
            throw "配置向导缺少接入或正式服务安装组件。"
        }
    }
    $SelfTestResult = [ordered]@{
        status = "ok"
        component = "enterprise-agent-provisioning-wizard"
        powershell = $PSVersionTable.PSVersion.ToString()
        gui_mode = "windows-forms-ps51"
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
        Show-FatalMessage ("首次配置需要管理员权限：" + $_.Exception.Message)
        exit 1
    }
    exit 0
}

foreach ($RequiredScript in @(
        $ImportScript, $ServiceInstallScript, $SafetyHelper
    )) {
    if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
        Show-FatalMessage "安装不完整，缺少接入或正式服务安装组件。"
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
$Form.ClientSize = New-Object Drawing.Size(900, 680)
$Form.StartPosition = "CenterScreen"
$Form.MinimumSize = New-Object Drawing.Size(916, 718)
$Form.Font = $NormalFont
$Form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi

$Title = New-Object Windows.Forms.Label
$Title.Text = "企业端一次配置并启动"
$Title.Font = $TitleFont
$Title.Location = New-Object Drawing.Point(24, 16)
$Title.Size = New-Object Drawing.Size(500, 38)
$Form.Controls.Add($Title)

$Subtitle = New-Object Windows.Forms.Label
$Subtitle.Text = (
    "选择监管端交付的一个 .mgprov 文件，设置业务管理员和 api_admin；其余参数自动完成。"
)
$Subtitle.ForeColor = $Muted
$Subtitle.Location = New-Object Drawing.Point(27, 56)
$Subtitle.Size = New-Object Drawing.Size(840, 24)
$Form.Controls.Add($Subtitle)

$LoadHandoverButton = New-Object Windows.Forms.Button
$LoadHandoverButton.Text = "选择..."
$LoadHandoverButton.Location = New-Object Drawing.Point(798, 114)
$LoadHandoverButton.Size = New-Object Drawing.Size(72, 29)
$Form.Controls.Add($LoadHandoverButton)

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

Add-SectionLabel -Text "一、选择企业接入包" -Y 88
$BundleBox = Add-TextField -LabelText "企业接入包 (.mgprov)" -Y 115 `
    -Width 600
$BundleBox.ReadOnly = $true
$PackageSummaryBox = New-Object Windows.Forms.TextBox
$PackageSummaryBox.Location = New-Object Drawing.Point(28, 151)
$PackageSummaryBox.Size = New-Object Drawing.Size(842, 46)
$PackageSummaryBox.Multiline = $true
$PackageSummaryBox.ReadOnly = $true
$PackageSummaryBox.Text = "尚未选择 .mgprov 文件。"
$Form.Controls.Add($PackageSummaryBox)

Add-SectionLabel -Text "二、确认本机实例" -Y 215
$InstanceBox = Add-TextField -LabelText "实例名" -Y 242 -Width 250
$InstanceBox.Text = "enterprise"
$PortBox = Add-TextField -LabelText "本机端口" -Y 275 -Width 120
$PortBox.Text = "8090"

Add-SectionLabel -Text "三、设置业务管理员和 API 管理员" -Y 315
$BusinessAdminIdBox = Add-TextField -LabelText "业务管理员登录名" -Y 342 -Width 250
$BusinessAdminIdBox.Text = "admin"
$BusinessAdminNameBox = Add-TextField -LabelText "业务管理员姓名" -Y 375 -Width 250
$BusinessAdminPasswordBox = Add-TextField -LabelText "业务管理员密码" -Y 408 `
    -Width 250 -Password
$BusinessAdminConfirmBox = Add-TextField -LabelText "再次输入" -Y 441 `
    -Width 250 -Password

$ApiAdminIdLabel = New-Object Windows.Forms.Label
$ApiAdminIdLabel.Text = "API 管理员登录名"
$ApiAdminIdLabel.Location = New-Object Drawing.Point(468, 346)
$ApiAdminIdLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ApiAdminIdLabel)
$ApiAdminIdBox = New-Object Windows.Forms.TextBox
$ApiAdminIdBox.Location = New-Object Drawing.Point(585, 342)
$ApiAdminIdBox.Size = New-Object Drawing.Size(285, 25)
$ApiAdminIdBox.Text = "api_admin"
$ApiAdminIdBox.ReadOnly = $true
$Form.Controls.Add($ApiAdminIdBox)

$ApiAdminNameLabel = New-Object Windows.Forms.Label
$ApiAdminNameLabel.Text = "API 管理员姓名"
$ApiAdminNameLabel.Location = New-Object Drawing.Point(468, 379)
$ApiAdminNameLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ApiAdminNameLabel)
$ApiAdminNameBox = New-Object Windows.Forms.TextBox
$ApiAdminNameBox.Location = New-Object Drawing.Point(585, 375)
$ApiAdminNameBox.Size = New-Object Drawing.Size(285, 25)
$ApiAdminNameBox.Text = "API 配置管理员"
$ApiAdminNameBox.ReadOnly = $true
$Form.Controls.Add($ApiAdminNameBox)

$ApiAdminPasswordLabel = New-Object Windows.Forms.Label
$ApiAdminPasswordLabel.Text = "API 管理员密码"
$ApiAdminPasswordLabel.Location = New-Object Drawing.Point(468, 412)
$ApiAdminPasswordLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ApiAdminPasswordLabel)
$ApiAdminPasswordBox = New-Object Windows.Forms.TextBox
$ApiAdminPasswordBox.Location = New-Object Drawing.Point(585, 408)
$ApiAdminPasswordBox.Size = New-Object Drawing.Size(285, 25)
$ApiAdminPasswordBox.UseSystemPasswordChar = $true
$Form.Controls.Add($ApiAdminPasswordBox)

$ApiAdminConfirmLabel = New-Object Windows.Forms.Label
$ApiAdminConfirmLabel.Text = "再次输入"
$ApiAdminConfirmLabel.Location = New-Object Drawing.Point(468, 445)
$ApiAdminConfirmLabel.Size = New-Object Drawing.Size(110, 24)
$Form.Controls.Add($ApiAdminConfirmLabel)
$ApiAdminConfirmBox = New-Object Windows.Forms.TextBox
$ApiAdminConfirmBox.Location = New-Object Drawing.Point(585, 441)
$ApiAdminConfirmBox.Size = New-Object Drawing.Size(285, 25)
$ApiAdminConfirmBox.UseSystemPasswordChar = $true
$Form.Controls.Add($ApiAdminConfirmBox)

$PasswordHint = New-Object Windows.Forms.Label
$PasswordHint.Text = "正式密码至少 12 位，并至少包含大写、小写、数字、符号中的三类；两个账号密码必须不同。api_admin 只能配置模型 API。"
$PasswordHint.ForeColor = $Muted
$PasswordHint.Location = New-Object Drawing.Point(28, 475)
$PasswordHint.Size = New-Object Drawing.Size(840, 24)
$Form.Controls.Add($PasswordHint)

$StatusBox = New-Object Windows.Forms.TextBox
$StatusBox.Location = New-Object Drawing.Point(28, 510)
$StatusBox.Size = New-Object Drawing.Size(842, 58)
$StatusBox.Multiline = $true
$StatusBox.ReadOnly = $true
$StatusBox.ScrollBars = "Vertical"
$StatusBox.Text = "选择一个 .mgprov 文件并设置两个账号，即可创建全新实例。"
$Form.Controls.Add($StatusBox)

$ImportButton = New-Object Windows.Forms.Button
$ImportButton.Text = "导入配置并继续安装服务"
$ImportButton.Location = New-Object Drawing.Point(452, 624)
$ImportButton.Size = New-Object Drawing.Size(418, 38)
$ImportButton.BackColor = $Green
$ImportButton.ForeColor = [Drawing.Color]::White
$ImportButton.FlatStyle = "Flat"
$Form.Controls.Add($ImportButton)

$ServiceInstallButton = New-Object Windows.Forms.Button
$ServiceInstallButton.Text = "已有实例：安装或修复服务…"
$ServiceInstallButton.Location = New-Object Drawing.Point(28, 624)
$ServiceInstallButton.Size = New-Object Drawing.Size(300, 38)
$ServiceInstallButton.BackColor = [Drawing.Color]::FromArgb(43, 93, 152)
$ServiceInstallButton.ForeColor = [Drawing.Color]::White
$ServiceInstallButton.FlatStyle = "Flat"
$Form.Controls.Add($ServiceInstallButton)

$CloseButton = New-Object Windows.Forms.Button
$CloseButton.Text = "关闭"
$CloseButton.Location = New-Object Drawing.Point(340, 624)
$CloseButton.Size = New-Object Drawing.Size(100, 38)
$CloseButton.Add_Click({ $Form.Close() })
$Form.Controls.Add($CloseButton)

$LoadHandoverButton.Add_Click({
    $Dialog = New-Object Windows.Forms.OpenFileDialog
    $Dialog.Title = "选择监管端生成的企业接入包"
    $Dialog.Filter = "MineGuard 企业接入包 (*.mgprov)|*.mgprov"
    $Dialog.CheckFileExists = $true
    $Dialog.Multiselect = $false
    try {
        if ($Dialog.ShowDialog($Form) -eq [Windows.Forms.DialogResult]::OK) {
            $Item = Get-Item -LiteralPath $Dialog.FileName -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $Item.Length -le 0 -or $Item.Length -gt 4194304) {
                throw "企业接入包必须是 1-4194304 字节的普通文件。"
            }
            $BundleBox.Text = $Item.FullName
            $PackageSummaryBox.Text = (
                "已选择：$($Item.Name)`r`n" +
                "文件 SHA-256：" +
                (Get-FileHash -LiteralPath $Item.FullName `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
            )
            $StatusBox.ForeColor = $Muted
            $StatusBox.Text = "接入包已加载。填写实例和两个账号后即可导入。"
        }
    }
    catch {
        $StatusBox.ForeColor = $Red
        $StatusBox.Text = "接入包加载失败：`r`n" + $_.Exception.Message
        [void][Windows.Forms.MessageBox]::Show(
            $StatusBox.Text, "MineGuard 企业接入配置向导",
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally { $Dialog.Dispose() }
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

    $ValidatedContext = Get-EAInstanceContext -InstanceName $InstanceName `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    $ValidatedContext = $null
    $ServiceTrustMode = Get-InstalledAgentServiceTrustMode
    $InternalUnsignedMode = $ServiceTrustMode -eq "internal-unsigned"
    $confirmation = (
        "将为实例 [$InstanceName] 安装并启动正式 Windows 服务。`r`n`r`n" +
        "服务包装器和完整性摘要已内置在安装包中，将自动核验，无需选择 " +
        "WinSW 或填写 SHA。是否继续？"
    )
    $choice = [Windows.Forms.MessageBox]::Show(
        $confirmation, "安装并启动 MineGuard 正式服务",
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Question
    )
    if ($choice -ne [Windows.Forms.DialogResult]::Yes) { return }

    $ValidatedContext = Get-EAInstanceContext -InstanceName $InstanceName `
        -InstallRoot $InstallRoot -StateRoot $StateRoot
    $ValidatedContext = $null
    if ($InternalUnsignedMode) {
        & $ServiceInstallScript -InstanceName $InstanceName `
            -AllowUnsignedInternalRelease -InstallRoot $InstallRoot `
            -StateRoot $StateRoot -Start `
            1>$null 3>$null 4>$null 5>$null 6>$null
    }
    else {
        & $ServiceInstallScript -InstanceName $InstanceName `
            -InstallRoot $InstallRoot -StateRoot $StateRoot -Start `
            1>$null 3>$null 4>$null 5>$null 6>$null
    }
    $StatusBox.ForeColor = $Green
    $StatusBox.Text = (
        "正式服务已安装、启动并通过绑定当前实例的健康检查：" +
        $InstanceName
    )
    [void][Windows.Forms.MessageBox]::Show(
        $StatusBox.Text, "MineGuard 企业接入配置向导",
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information
    )
}

$ServiceInstallButton.Add_Click({
    $ServiceInstallButton.Enabled = $false
    try {
        $SelectedInstance = $InstanceBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($SelectedInstance)) {
            throw "请先在主界面填写或加载要安装服务的实例名。"
        }
        $SelectedInstanceRoot = Join-Path $StateRoot $SelectedInstance
        if (-not (Test-Path -LiteralPath $SelectedInstanceRoot `
                -PathType Container)) {
            throw (
                "尚未创建实例 [$SelectedInstance]。首次部署请先选择监管端生成的 " +
                ".mgprov，填写企业管理员和 api_admin 密码，然后点击右侧绿色" +
                "[导入配置并继续安装服务]。"
            )
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
    $StatusBox.Text = "正在离线验签、解密、创建实例并执行正式配置预检，请稍候..."
    $Form.Refresh()
    $BusinessAdminSecure = $null
    $BusinessAdminConfirmSecure = $null
    $ApiAdminSecure = $null
    $ApiAdminConfirmSecure = $null
    try {
        if ([string]::IsNullOrWhiteSpace($BundleBox.Text)) {
            throw "请先选择监管端生成的 .mgprov 企业接入包。"
        }
        if ([string]::IsNullOrWhiteSpace($BusinessAdminPasswordBox.Text) -or
            [string]::IsNullOrWhiteSpace($ApiAdminPasswordBox.Text)) {
            throw "请填写业务管理员和 api_admin 密码。"
        }
        $Port = 0
        if (-not [int]::TryParse($PortBox.Text, [ref]$Port) -or
            $Port -lt 1 -or $Port -gt 65535) {
            throw "本机端口必须是 1-65535 的整数。"
        }
        $BusinessAdminSecure = ConvertTo-SecureString $BusinessAdminPasswordBox.Text `
            -AsPlainText -Force
        $BusinessAdminConfirmSecure = ConvertTo-SecureString $BusinessAdminConfirmBox.Text `
            -AsPlainText -Force
        $ApiAdminSecure = ConvertTo-SecureString $ApiAdminPasswordBox.Text `
            -AsPlainText -Force
        $ApiAdminConfirmSecure = ConvertTo-SecureString $ApiAdminConfirmBox.Text `
            -AsPlainText -Force
        $BusinessAdminPasswordBox.Clear()
        $BusinessAdminConfirmBox.Clear()
        $ApiAdminPasswordBox.Clear()
        $ApiAdminConfirmBox.Clear()
        $Result = & $ImportScript `
            -BundlePath $BundleBox.Text `
            -InstanceName $InstanceBox.Text `
            -Port $Port `
            -BusinessAdminActorId $BusinessAdminIdBox.Text `
            -BusinessAdminName $BusinessAdminNameBox.Text `
            -BusinessAdminPassword $BusinessAdminSecure `
            -BusinessAdminPasswordConfirmation $BusinessAdminConfirmSecure `
            -ApiAdminPassword $ApiAdminSecure `
            -ApiAdminPasswordConfirmation $ApiAdminConfirmSecure `
            -InstallRoot $InstallRoot `
            -StateRoot $StateRoot
        $Summary = @($Result | ForEach-Object { [string]$_ }) -join `
            [Environment]::NewLine
        $StatusBox.Text = if ([string]::IsNullOrWhiteSpace($Summary)) {
            "企业接入包已导入并通过正式预检。"
        } else { $Summary }
        $StatusBox.Text += "`r`n配置完成；正在继续打开正式服务安装。"
        $StatusBox.ForeColor = $Green
        $Form.UseWaitCursor = $false
        try {
            Show-FormalServiceInstallDialog -InstanceName $InstanceBox.Text
        }
        catch {
            $StatusBox.Text += (
                "`r`n配置已完成，但正式服务安装窗口未能打开：" +
                $_.Exception.Message
            )
            $StatusBox.ForeColor = $Red
        }
    }
    catch {
        $BusinessAdminPasswordBox.Clear()
        $BusinessAdminConfirmBox.Clear()
        $ApiAdminPasswordBox.Clear()
        $ApiAdminConfirmBox.Clear()
        $StatusBox.Text = "导入失败，未覆盖任何现有实例。`r`n" + `
            $_.Exception.Message
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
                $BusinessAdminSecure, $BusinessAdminConfirmSecure,
                $ApiAdminSecure, $ApiAdminConfirmSecure
            )) {
            if ($null -ne $SecureValue) { $SecureValue.Dispose() }
        }
        $BusinessAdminSecure = $null; $BusinessAdminConfirmSecure = $null
        $ApiAdminSecure = $null; $ApiAdminConfirmSecure = $null
        $BusinessAdminPasswordBox.Clear()
        $BusinessAdminConfirmBox.Clear()
        $ApiAdminPasswordBox.Clear()
        $ApiAdminConfirmBox.Clear()
        $Form.UseWaitCursor = $false
        $ImportButton.Enabled = $true
    }
})

$Form.Add_FormClosed({
    $BusinessAdminPasswordBox.Clear(); $BusinessAdminConfirmBox.Clear()
    $ApiAdminPasswordBox.Clear(); $ApiAdminConfirmBox.Clear()
})
try {
    if ($SelfTest) {
        $SelfTestResult | ConvertTo-Json -Compress | Write-Output
        return
    }
    [void]$Form.ShowDialog()
}
finally { $Form.Dispose() }
