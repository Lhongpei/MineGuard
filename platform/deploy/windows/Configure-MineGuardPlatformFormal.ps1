[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InstallRoot,
    [Parameter(Mandatory = $true)] [string] $ClientsFile,
    [Parameter(Mandatory = $true)] [string] $StateDirectory,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)] [int] $Port,
    [Parameter(Mandatory = $true)] [string] $AdminUsername,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformSystemId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformPartyId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string] $PlatformKeyId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
    -ArgumentList $identity
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw '正式配置密码 helper 必须在管理员上下文中运行。'
}

$scriptDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($PSCommandPath))
$configurationScript = Join-Path $scriptDirectory `
    'Set-MineGuardPlatformConfiguration.ps1'
if (-not (Test-Path -LiteralPath $configurationScript -PathType Leaf)) {
    throw "安装不完整，缺少配置脚本：$configurationScript"
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
$dialog = New-Object System.Windows.Forms.Form
$dialog.Text = 'MineGuard 正式管理员密码'
$dialog.ClientSize = New-Object System.Drawing.Size(520, 252)
$dialog.StartPosition = 'CenterScreen'
$dialog.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$dialog.MaximizeBox = $false
$dialog.MinimizeBox = $false
$dialog.Font = $font
$dialog.TopMost = $true

$heading = New-Object System.Windows.Forms.Label
$heading.Text = '密码仅存在于本独立短生命周期进程'
$heading.Font = New-Object System.Drawing.Font(
    'Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold
)
$heading.Location = New-Object System.Drawing.Point(22, 18)
$heading.Size = New-Object System.Drawing.Size(470, 28)
$dialog.Controls.Add($heading)

$description = New-Object System.Windows.Forms.Label
$description.Text = '至少 12 位；大小写字母、数字、符号四类中至少三类。配置结束后本进程立即退出。'
$description.Location = New-Object System.Drawing.Point(22, 50)
$description.Size = New-Object System.Drawing.Size(470, 42)
$dialog.Controls.Add($description)

$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = '管理员密码'
$passwordLabel.Location = New-Object System.Drawing.Point(22, 101)
$passwordLabel.Size = New-Object System.Drawing.Size(95, 25)
$dialog.Controls.Add($passwordLabel)
$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.UseSystemPasswordChar = $true
$passwordBox.Location = New-Object System.Drawing.Point(124, 99)
$passwordBox.Size = New-Object System.Drawing.Size(360, 25)
$dialog.Controls.Add($passwordBox)

$confirmationLabel = New-Object System.Windows.Forms.Label
$confirmationLabel.Text = '再次输入'
$confirmationLabel.Location = New-Object System.Drawing.Point(22, 138)
$confirmationLabel.Size = New-Object System.Drawing.Size(95, 25)
$dialog.Controls.Add($confirmationLabel)
$confirmationBox = New-Object System.Windows.Forms.TextBox
$confirmationBox.UseSystemPasswordChar = $true
$confirmationBox.Location = New-Object System.Drawing.Point(124, 136)
$confirmationBox.Size = New-Object System.Drawing.Size(360, 25)
$dialog.Controls.Add($confirmationBox)

$status = New-Object System.Windows.Forms.Label
$status.ForeColor = [Drawing.Color]::FromArgb(190, 45, 45)
$status.Location = New-Object System.Drawing.Point(22, 170)
$status.Size = New-Object System.Drawing.Size(462, 30)
$dialog.Controls.Add($status)

$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = '确认并配置'
$okButton.Location = New-Object System.Drawing.Point(278, 207)
$okButton.Size = New-Object System.Drawing.Size(100, 32)
$dialog.Controls.Add($okButton)
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = '取消'
$cancelButton.Location = New-Object System.Drawing.Point(384, 207)
$cancelButton.Size = New-Object System.Drawing.Size(100, 32)
$dialog.Controls.Add($cancelButton)
$dialog.AcceptButton = $okButton
$dialog.CancelButton = $cancelButton

$script:formalPassword = $null
$okButton.Add_Click({
        if (-not [string]::Equals(
                $passwordBox.Text, $confirmationBox.Text,
                [StringComparison]::Ordinal
            )) {
            $status.Text = '两次输入的密码不一致。'
            $passwordBox.Clear()
            $confirmationBox.Clear()
            $passwordBox.Focus()
            return
        }
        $categoryCount = 0
        if ($passwordBox.Text -cmatch '[a-z]') { $categoryCount++ }
        if ($passwordBox.Text -cmatch '[A-Z]') { $categoryCount++ }
        if ($passwordBox.Text -match '[0-9]') { $categoryCount++ }
        if ($passwordBox.Text -match '[^A-Za-z0-9]') { $categoryCount++ }
        if ($passwordBox.Text.Length -lt 12 -or $categoryCount -lt 3 -or
            $passwordBox.Text -ceq '123123123' -or
            $passwordBox.Text.ToLowerInvariant() -in @(
                'password123', 'admin123456', 'qwerty123'
            )) {
            $status.Text = '密码长度、复杂度或弱口令检查未通过。'
            $passwordBox.Clear()
            $confirmationBox.Clear()
            $passwordBox.Focus()
            return
        }
        $secure = New-Object Security.SecureString
        foreach ($character in $passwordBox.Text.ToCharArray()) {
            $secure.AppendChar($character)
        }
        $secure.MakeReadOnly()
        $passwordBox.Clear()
        $confirmationBox.Clear()
        $script:formalPassword = $secure
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    })
$cancelButton.Add_Click({
        $passwordBox.Clear()
        $confirmationBox.Clear()
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $dialog.Close()
    })

try {
    $result = $dialog.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or
        $null -eq $script:formalPassword) {
        Write-Output '正式配置已由用户取消，未写入密码或配置。'
        exit 3
    }
    & $configurationScript -InstallRoot $InstallRoot `
        -ClientsFile $ClientsFile -StateDirectory $StateDirectory `
        -Port $Port -AdminUsername $AdminUsername `
        -PlatformSystemId $PlatformSystemId `
        -PlatformPartyId $PlatformPartyId -PlatformKeyId $PlatformKeyId `
        -AdminPassword $script:formalPassword -NonInteractive
    Write-Output '正式配置 helper 已完成，正在退出短生命周期进程。'
} finally {
    $passwordBox.Clear()
    $confirmationBox.Clear()
    if ($null -ne $script:formalPassword) {
        $script:formalPassword.Dispose()
        $script:formalPassword = $null
    }
    $dialog.Dispose()
    $heading.Font.Dispose()
    $font.Dispose()
}
