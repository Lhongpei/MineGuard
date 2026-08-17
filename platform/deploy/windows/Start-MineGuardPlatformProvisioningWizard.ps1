[CmdletBinding()]
param(
    [string] $InstallRoot,
    [switch] $SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false

function Quote-NativeArgument {
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append([char]'"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') { $slashes++; continue }
        if ($character -eq [char]'"') {
            [void]$builder.Append([char]'\', (($slashes * 2) + 1))
            [void]$builder.Append([char]'"'); $slashes = 0; continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append([char]'\', $slashes); $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append([char]'\', ($slashes * 2)) }
    [void]$builder.Append([char]'"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param([object[]] $Arguments)
    return (@($Arguments | ForEach-Object {
                if ($null -eq $_) { throw '拒绝把 null 作为提权参数。' }
                Quote-NativeArgument -Value ([string]$_)
            }) -join ' ')
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
[Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

function Show-Fatal {
    param([string] $Message)
    [void][Windows.Forms.MessageBox]::Show(
        $Message, 'MineGuard 企业接入配置',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    )
}

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    Show-Fatal '需要 Windows PowerShell 5.1 或更高版本。'
    exit 1
}
$scriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$scriptDirectory = Split-Path -Parent $scriptPath
if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = Split-Path -Parent $scriptDirectory
}
try { $InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') }
catch { Show-Fatal '安装目录无效。'; exit 1 }
$coreScript = Join-Path $scriptDirectory `
    'Invoke-MineGuardPlatformProvisioning.ps1'
$configurationScript = Join-Path $scriptDirectory `
    'Set-MineGuardPlatformConfiguration.ps1'
$platformAclHelper = Join-Path $scriptDirectory `
    'MineGuardPlatform.WindowsAcl.ps1'
$resolverScript = Join-Path $scriptDirectory `
    'Resolve-MineGuardPlatformExecutable.ps1'
if ($SelfTest) {
    foreach ($required in @(
            $coreScript, $configurationScript, $platformAclHelper, $resolverScript
        )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "安装不完整，缺少文件：$required"
        }
    }
    $selfTestResult = [ordered]@{
        status = 'ok'
        component = 'mineguard-platform-provisioning-wizard'
        gui = 'windows-forms-ps51'
        install_root = $InstallRoot
        secret_transport = 'protected-files-only'
        controls_constructed = $true
    }
}

if (-not $SelfTest) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        try {
            $powerShell = Join-Path $env:SystemRoot `
                'System32\WindowsPowerShell\v1.0\powershell.exe'
            $start = New-Object Diagnostics.ProcessStartInfo
            $start.FileName = $powerShell
            $start.Arguments = Join-NativeArguments @(
                '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File',
                $scriptPath, '-InstallRoot', $InstallRoot
            )
            $start.UseShellExecute = $true
            $start.Verb = 'runas'
            [void][Diagnostics.Process]::Start($start)
        } catch { Show-Fatal ('UAC 提权未完成：' + $_.Exception.Message); exit 1 }
        exit 0
    }
}

# The installed service tree is intentionally unreadable to a normal desktop
# token. Validate its protected components only after UAC elevation; otherwise
# the wizard would fail before it ever had a chance to request elevation.
foreach ($required in @(
        $coreScript, $configurationScript, $platformAclHelper, $resolverScript
    )) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Show-Fatal "安装不完整，缺少文件：$required"
        exit 1
    }
}

function New-SecureValue {
    param([Windows.Forms.TextBox] $TextBox)
    $secure = New-Object Security.SecureString
    foreach ($character in $TextBox.Text.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    return $secure
}

function Select-Folder {
    param([Windows.Forms.TextBox] $Target, [string] $Description)
    $dialog = New-Object Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if (-not [string]::IsNullOrWhiteSpace($Target.Text) -and
        (Test-Path -LiteralPath $Target.Text -PathType Container)) {
        $dialog.SelectedPath = $Target.Text
    }
    try {
        if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
            $Target.Text = $dialog.SelectedPath
        }
    } finally { $dialog.Dispose() }
}

function Select-File {
    param(
        [Windows.Forms.TextBox] $Target,
        [string] $Filter,
        [string] $Title
    )
    $dialog = New-Object Windows.Forms.OpenFileDialog
    $dialog.Filter = $Filter
    $dialog.Title = $Title
    $dialog.CheckFileExists = $true
    $dialog.Multiselect = $false
    try {
        if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
            $Target.Text = $dialog.FileName
        }
    } finally { $dialog.Dispose() }
}

function New-InputTable {
    $table = New-Object Windows.Forms.TableLayoutPanel
    $table.AutoSize = $true
    $table.AutoSizeMode = [Windows.Forms.AutoSizeMode]::GrowAndShrink
    $table.ColumnCount = 3
    $table.RowCount = 0
    $table.Dock = [Windows.Forms.DockStyle]::Top
    $table.Padding = New-Object Windows.Forms.Padding(12)
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle(
                [Windows.Forms.SizeType]::Absolute, 178)))
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle(
                [Windows.Forms.SizeType]::Percent, 100)))
    [void]$table.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle(
                [Windows.Forms.SizeType]::Absolute, 88)))
    return $table
}

function Add-InputRow {
    param(
        [Windows.Forms.TableLayoutPanel] $Table,
        [hashtable] $Store,
        [string] $Key,
        [string] $Label,
        [string] $Default = '',
        [switch] $Password,
        [ValidateSet('', 'file', 'folder')] [string] $Browse = '',
        [string] $Filter = '全部文件 (*.*)|*.*'
    )
    $row = $Table.RowCount
    $Table.RowCount++
    [void]$Table.RowStyles.Add((New-Object Windows.Forms.RowStyle(
                [Windows.Forms.SizeType]::Absolute, 35)))
    $caption = New-Object Windows.Forms.Label
    $caption.Text = $Label
    $caption.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $caption.Dock = [Windows.Forms.DockStyle]::Fill
    $box = New-Object Windows.Forms.TextBox
    $box.Text = $Default
    $box.Dock = [Windows.Forms.DockStyle]::Fill
    $box.Margin = New-Object Windows.Forms.Padding(4, 5, 4, 4)
    if ($Password) { $box.UseSystemPasswordChar = $true }
    $Table.Controls.Add($caption, 0, $row)
    $Table.Controls.Add($box, 1, $row)
    if ($Browse) {
        $button = New-Object Windows.Forms.Button
        $button.Text = '选择…'
        $button.Dock = [Windows.Forms.DockStyle]::Fill
        $button.Tag = [pscustomobject]@{
            target = $box; mode = $Browse; filter = $Filter; title = $Label
        }
        $box.Tag = $button
        $button.Add_Click({
                $browseContext = $this.Tag
                if ($browseContext.mode -eq 'folder') {
                    Select-Folder -Target $browseContext.target `
                        -Description $browseContext.title
                } else {
                    Select-File -Target $browseContext.target `
                        -Filter $browseContext.filter `
                        -Title $browseContext.title
                }
            })
        $Table.Controls.Add($button, 2, $row)
    }
    $Store[$Key] = $box
    return $box
}

function Add-NoteRow {
    param([Windows.Forms.TableLayoutPanel] $Table, [string] $Text)
    $row = $Table.RowCount
    $Table.RowCount++
    [void]$Table.RowStyles.Add((New-Object Windows.Forms.RowStyle(
                [Windows.Forms.SizeType]::Absolute, 45)))
    $label = New-Object Windows.Forms.Label
    $label.Text = $Text
    $label.ForeColor = [Drawing.Color]::FromArgb(90, 98, 108)
    $label.Dock = [Windows.Forms.DockStyle]::Fill
    $label.TextAlign = [Drawing.ContentAlignment]::MiddleLeft
    $Table.Controls.Add($label, 1, $row)
    $Table.SetColumnSpan($label, 2)
}

function Add-ActionRow {
    param(
        [Windows.Forms.TableLayoutPanel] $Table,
        [string] $Text,
        [scriptblock] $Handler
    )
    $row = $Table.RowCount
    $Table.RowCount++
    [void]$Table.RowStyles.Add((New-Object Windows.Forms.RowStyle(
                [Windows.Forms.SizeType]::Absolute, 52)))
    $button = New-Object Windows.Forms.Button
    $button.Text = $Text
    $button.Height = 38
    $button.Dock = [Windows.Forms.DockStyle]::Fill
    $button.BackColor = [Drawing.Color]::FromArgb(24, 128, 72)
    $button.ForeColor = [Drawing.Color]::White
    $button.FlatStyle = [Windows.Forms.FlatStyle]::Flat
    $button.Add_Click($Handler)
    $Table.Controls.Add($button, 1, $row)
    $Table.SetColumnSpan($button, 2)
    return $button
}

$font = New-Object Drawing.Font('Microsoft YaHei UI', 9)
$titleFont = New-Object Drawing.Font(
    'Microsoft YaHei UI', 16, [Drawing.FontStyle]::Bold
)
$monoFont = New-Object Drawing.Font('Consolas', 9)
$form = New-Object Windows.Forms.Form
$form.Text = 'MineGuard 企业接入包与注册向导'
$form.ClientSize = New-Object Drawing.Size(1020, 790)
$form.MinimumSize = New-Object Drawing.Size(930, 700)
$form.StartPosition = 'CenterScreen'
$form.Font = $font
$form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi

$header = New-Object Windows.Forms.Label
$header.Text = '企业专属接入配置'
$header.Font = $titleFont
$header.Location = New-Object Drawing.Point(18, 12)
$header.Size = New-Object Drawing.Size(500, 36)
$form.Controls.Add($header)
$subHeader = New-Object Windows.Forms.Label
$subHeader.Text = '监管端一次生成配对材料；企业只接收 .mgprov，政府留存 .mgreg 并在本机导入。密钥与激活码不进入命令行或日志。'
$subHeader.ForeColor = [Drawing.Color]::FromArgb(85, 94, 104)
$subHeader.Location = New-Object Drawing.Point(20, 49)
$subHeader.Size = New-Object Drawing.Size(970, 26)
$form.Controls.Add($subHeader)

$tabs = New-Object Windows.Forms.TabControl
$tabs.Location = New-Object Drawing.Point(18, 78)
$tabs.Size = New-Object Drawing.Size(984, 525)
$tabs.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($tabs)
$statusBox = New-Object Windows.Forms.TextBox
$statusBox.Location = New-Object Drawing.Point(18, 614)
$statusBox.Size = New-Object Drawing.Size(984, 142)
$statusBox.Anchor = 'Bottom,Left,Right'
$statusBox.Multiline = $true
$statusBox.ScrollBars = [Windows.Forms.ScrollBars]::Vertical
$statusBox.ReadOnly = $true
$statusBox.Font = $monoFont
$statusBox.BackColor = [Drawing.Color]::White
$form.Controls.Add($statusBox)
$statusLabel = New-Object Windows.Forms.Label
$statusLabel.Text = '非秘密结果与操作提示'
$statusLabel.Location = New-Object Drawing.Point(20, 590)
$statusLabel.Size = New-Object Drawing.Size(220, 24)
$statusLabel.Anchor = 'Bottom,Left'
$form.Controls.Add($statusLabel)

function Set-Status {
    param([string] $Text)
    $statusBox.Text = $Text
    $statusBox.SelectionStart = $statusBox.TextLength
    $statusBox.ScrollToCaret()
    [Windows.Forms.Application]::DoEvents()
}
function Show-OperationError {
    param([string] $Label, [object] $ErrorRecord)
    $message = "$Label 失败：$($ErrorRecord.Exception.Message)"
    Set-Status $message
    [void][Windows.Forms.MessageBox]::Show(
        $message, 'MineGuard 企业接入配置',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    )
}

# Page 1: create the offline signing authority.
$issuerPage = New-Object Windows.Forms.TabPage
$issuerPage.Text = '1. 初始化签发密钥'
$issuerPage.AutoScroll = $true
$tabs.TabPages.Add($issuerPage)
$issuerTable = New-InputTable
$issuerPage.Controls.Add($issuerTable)
$issuerFields = @{}
$authorityDefault = Join-Path $InstallRoot 'provisioning-authority'
$authorityBox = New-Object Windows.Forms.TextBox
$authorityBox.Text = $authorityDefault
$privateBox = New-Object Windows.Forms.TextBox
$privateBox.Text = Join-Path $authorityDefault 'issuer-private.pem'
$publicBox = New-Object Windows.Forms.TextBox
$publicBox.Text = Join-Path $authorityDefault 'issuer-public.pem'
$issuerPass = Add-InputRow $issuerTable $issuerFields 'passphrase' `
    '私钥口令（至少14位）' '' -Password
$issuerConfirm = Add-InputRow $issuerTable $issuerFields 'confirmation' `
    '再次输入私钥口令' '' -Password
Add-NoteRow $issuerTable '私钥目录只授权 SYSTEM/Administrators。请另做离线加密备份；私钥绝不能交给企业。'
$null = Add-ActionRow $issuerTable '初始化签发密钥' {
    $secure = $null; $confirm = $null
    try {
        $secure = New-SecureValue $issuerPass
        $confirm = New-SecureValue $issuerConfirm
        $issuerPass.Clear(); $issuerConfirm.Clear()
        Set-Status '正在本机生成口令加密的 Ed25519 签发密钥…'
        $result = & $coreScript -Action IssuerInit -InstallRoot $InstallRoot `
            -PrivateKeyPath $privateBox.Text -PublicKeyPath $publicBox.Text `
            -Passphrase $secure -PassphraseConfirmation $confirm
        Set-Status ((
                "签发密钥已建立。`r`n公钥：{0}`r`n" +
                "SPKI-DER SHA-256：{1}`r`n`r`n" +
                '请把该指纹通过独立审批渠道登记；不要只从接入 U 盘抄录。'
            ) -f $result.public_key, $result.public_key_sha256)
        $tabs.SelectedTab = $createPage
    } catch { Show-OperationError '初始化签发密钥' $_ }
    finally {
        if ($null -ne $secure) { $secure.Dispose() }
        if ($null -ne $confirm) { $confirm.Dispose() }
    }
}

# Page 2: create a new current-version package. Fixed authority identity,
# protected government storage paths and profile version are not operator
# choices, so the GUI does not expose them.
$createPage = New-Object Windows.Forms.TabPage
$createPage.Text = '2. 生成企业接入包'
$createPage.AutoScroll = $true
$tabs.TabPages.Add($createPage)
$createTable = New-InputTable
$createPage.Controls.Add($createTable)
$create = @{}
$create.private = New-Object Windows.Forms.TextBox
$create.private.Text = Join-Path $authorityDefault 'issuer-private.pem'
$create.public = New-Object Windows.Forms.TextBox
$create.public.Text = Join-Path $authorityDefault 'issuer-public.pem'
$create.issuer_id = New-Object Windows.Forms.TextBox
$create.issuer_id.Text = 'qinyuan-regulator'
$create.issuer_key_id = New-Object Windows.Forms.TextBox
$create.issuer_key_id.Text = 'qinyuan-provisioning-key-v1'
$create.party_id = New-Object Windows.Forms.TextBox
$create.system_id = New-Object Windows.Forms.TextBox
$create.platform_system = New-Object Windows.Forms.TextBox
$create.platform_system.Text = 'mineguard-qinyuan'
$create.platform_party = New-Object Windows.Forms.TextBox
$create.platform_party.Text = 'regulator-qinyuan'
$create.platform_key = New-Object Windows.Forms.TextBox
$create.platform_key.Text = 'regulator-key-v3'
$create.instance = New-Object Windows.Forms.TextBox
$create.registration_output = New-Object Windows.Forms.TextBox
$create.registration_output.Text = Join-Path $InstallRoot `
    'provisioning-registrations'
$create.activations = New-Object Windows.Forms.TextBox
$create.activations.Text = Join-Path $InstallRoot 'provisioning-activations'
Add-InputRow $createTable $create 'ca_source' '政府 HTTPS CA PEM' '' `
    -Browse file -Filter 'PEM/CRT 证书 (*.pem;*.crt)|*.pem;*.crt|全部文件 (*.*)|*.*' | Out-Null
Add-InputRow $createTable $create 'passphrase' '签发私钥口令' '' -Password | Out-Null
Add-InputRow $createTable $create 'mine_id' '煤矿 ID' '' | Out-Null
Add-InputRow $createTable $create 'mine_name' '煤矿名称' '' | Out-Null
Add-InputRow $createTable $create 'party_name' '企业名称' '' | Out-Null
Add-InputRow $createTable $create 'capacity' '核定产能区间' '' | Out-Null
Add-InputRow $createTable $create 'method' '开采方式' '' | Out-Null
Add-InputRow $createTable $create 'shift' '班次制度' '' | Out-Null
Add-InputRow $createTable $create 'coal' '主要煤种' '' | Out-Null
Add-InputRow $createTable $create 'regime' '生产制度' '' | Out-Null
Add-InputRow $createTable $create 'agent_origin' '企业端 HTTPS 地址' '' | Out-Null
Add-InputRow $createTable $create 'platform_url' '监管端 HTTPS 地址' '' | Out-Null
Add-InputRow $createTable $create 'output' '企业交付根目录（可选U盘）' '' -Browse folder | Out-Null

function Set-AuthorityPolicyFieldsLocked {
    param([bool] $Locked)
    foreach ($field in @(
            $create.private, $create.public, $create.issuer_id,
            $create.issuer_key_id, $create.ca_source,
            $create.platform_url, $create.platform_system,
            $create.platform_party, $create.platform_key
        )) {
        $field.ReadOnly = $Locked
        if ($field.Tag -is [Windows.Forms.Button]) {
            $field.Tag.Enabled = -not $Locked
        }
    }
}

function Get-AuthorityPolicyPath {
    if ([string]::IsNullOrWhiteSpace($create.private.Text)) { return '' }
    return Join-Path (Split-Path -Parent $create.private.Text) `
        'authority-policy.json'
}

function Get-AuthorityPolicyPendingPath {
    $policyPath = Get-AuthorityPolicyPath
    if ([string]::IsNullOrWhiteSpace($policyPath)) { return '' }
    return Join-Path (Split-Path -Parent $policyPath) `
        'authority-policy.pending.json'
}

function Get-AuthorityPolicyFixedCaPath {
    return Join-Path $authorityDefault 'platform-ca.pem'
}

function Get-AuthorityPolicyValues {
    return [ordered]@{
        issuer_private_key_file = $create.private.Text
        issuer_public_key_file = $create.public.Text
        issuer_id = $create.issuer_id.Text
        issuer_key_id = $create.issuer_key_id.Text
        platform_ca_source_file = $create.ca_source.Text
        platform_base_url = $create.platform_url.Text
        platform_system_id = $create.platform_system.Text
        platform_party_id = $create.platform_party.Text
        platform_key_id = $create.platform_key.Text
    }
}

function Assert-GuiOrdinaryFile {
    param([string] $Path, [string] $Label, [long] $MaximumBytes = 1048576)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 不存在：$Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label 必须是普通小文件，且不能是链接或重解析点。"
    }
}

function Get-GuiSpkiSha256FromPem {
    param([string] $Path)
    Assert-GuiOrdinaryFile -Path $Path -Label '签发公钥' `
        -MaximumBytes 65536
    $pem = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $match = [Text.RegularExpressions.Regex]::Match(
        $pem,
        '^\s*-----BEGIN PUBLIC KEY-----\s*(?<body>[A-Za-z0-9+/=\s]+)' +
        '-----END PUBLIC KEY-----\s*$',
        [Text.RegularExpressions.RegexOptions]::Singleline
    )
    $pem = $null
    if (-not $match.Success) {
        throw '签发公钥必须是单一 SubjectPublicKeyInfo PEM 公钥。'
    }
    try {
        $der = [Convert]::FromBase64String(
            ($match.Groups['body'].Value -replace '\s', '')
        )
    } catch { throw '签发公钥 PEM 内容无效。' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($der))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $sha.Dispose(); $der = $null }
}

function Test-FixedTimeText {
    param([string] $Left, [string] $Right)
    if ($null -eq $Left -or $null -eq $Right -or
        $Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor (
            ([int][char]$Left[$index]) -bxor ([int][char]$Right[$index])
        )
    }
    return $difference -eq 0
}

function Assert-NoAuthorityPolicyPending {
    $pendingPath = Get-AuthorityPolicyPendingPath
    if (-not [string]::IsNullOrWhiteSpace($pendingPath) -and
        (Test-Path -LiteralPath $pendingPath)) {
        throw (
            '检测到未完成的监管固定策略事务 authority-policy.pending.json；' +
            '后续签发已闭锁。请停止签发，核对固定 CA、四区输出和审计记录，' +
            '再按批准的恢复或迁移流程处理；本向导不会自动删除或覆盖该标记。'
        )
    }
}

function New-AuthorityPolicyPending {
    $policyPath = Get-AuthorityPolicyPath
    $pendingPath = Get-AuthorityPolicyPendingPath
    $fixedCaPath = Get-AuthorityPolicyFixedCaPath
    $expectedPolicyPath = Join-Path $authorityDefault 'authority-policy.json'
    if ([string]::IsNullOrWhiteSpace($policyPath) -or
        [string]::IsNullOrWhiteSpace($pendingPath)) {
        throw '无法确定监管固定策略事务路径。'
    }
    if (-not [string]::Equals(
            $policyPath, $expectedPolicyPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw '监管固定策略必须位于安装目录的 provisioning-authority 专用目录。'
    }
    if (Test-Path -LiteralPath $policyPath) {
        throw 'authority-policy.json 已存在，不能创建首次策略事务。'
    }
    Assert-NoAuthorityPolicyPending
    if (Test-Path -LiteralPath $fixedCaPath) {
        throw (
            '固定 CA 已存在但 authority-policy.json 缺失，可能是上次事务残留；' +
            '拒绝静默接管。请核验备份和审计记录后执行显式恢复或迁移。'
        )
    }
    $transactionId = [Guid]::NewGuid().ToString('N')
    $document = [ordered]@{
        schema_version = 'mineguard-authority-policy-pending-v1'
        transaction_id = $transactionId
        created_utc = [DateTime]::UtcNow.ToString('o')
        authority_policy_file = $policyPath
        platform_ca_file = $fixedCaPath
        contains_secrets = $false
    }
    $bytes = $utf8NoBom.GetBytes(($document | ConvertTo-Json -Depth 3))
    $stream = New-Object IO.FileStream(
        $pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    & "$env:SystemRoot\System32\icacls.exe" $pendingPath '/inheritance:r' `
        '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '无法保护 authority-policy pending 标记 ACL；后续签发保持闭锁。'
    }
    return $transactionId
}

function Read-AuthorityPolicyPending {
    param([string] $ExpectedTransactionId)
    $pendingPath = Get-AuthorityPolicyPendingPath
    Assert-GuiOrdinaryFile -Path $pendingPath `
        -Label 'authority-policy pending 标记' -MaximumBytes 65536
    try {
        $pending = Get-Content -LiteralPath $pendingPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch { throw 'authority-policy pending 标记无法解析。' }
    $containsSecrets = $pending.PSObject.Properties['contains_secrets']
    if ([string]$pending.schema_version -ne
            'mineguard-authority-policy-pending-v1' -or
        [string]$pending.transaction_id -ne $ExpectedTransactionId -or
        $null -eq $containsSecrets -or
        $containsSecrets.Value -isnot [bool] -or
        [bool]$containsSecrets.Value -or
        -not [string]::Equals(
            [string]$pending.authority_policy_file,
            (Get-AuthorityPolicyPath),
            [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            [string]$pending.platform_ca_file,
            (Get-AuthorityPolicyFixedCaPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'authority-policy pending 标记身份或边界不匹配。'
    }
    return $pending
}

function Assert-AuthorityPolicyMaterial {
    param([object] $Policy)
    $containsSecretsProperty = $Policy.PSObject.Properties['contains_secrets']
    if ($null -eq $containsSecretsProperty -or
        $containsSecretsProperty.Value -isnot [bool] -or
        [bool]$containsSecretsProperty.Value) {
        throw 'authority-policy.json 必须明确标记 contains_secrets=false。'
    }
    $storedSpki = [string]$Policy.issuer_public_key_sha256
    $storedCa = [string]$Policy.platform_ca_sha256
    if ($storedSpki -cnotmatch '^[0-9a-f]{64}$' -or
        $storedCa -cnotmatch '^[0-9a-f]{64}$') {
        throw 'authority-policy.json 中的公钥/CA SHA-256 格式无效。'
    }
    $fixedCaPath = Get-AuthorityPolicyFixedCaPath
    if (-not [string]::Equals(
            [string]$Policy.platform_ca_source_file, $fixedCaPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw (
            '现有 authority-policy.json 引用了外部或可移动路径的旧版 CA；' +
            '当前版本拒绝静默替换。请停止签发，核对旧策略摘要和审批记录，' +
            '再执行显式 CA 策略迁移到固定路径：' + $fixedCaPath
        )
    }
    $actualSpki = Get-GuiSpkiSha256FromPem `
        -Path ([string]$Policy.issuer_public_key_file)
    Assert-GuiOrdinaryFile -Path ([string]$Policy.platform_ca_source_file) `
        -Label '固定政府 HTTPS CA' -MaximumBytes 1048576
    $actualCa = (Get-FileHash `
        -LiteralPath ([string]$Policy.platform_ca_source_file) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not (Test-FixedTimeText -Left $actualSpki -Right $storedSpki)) {
        throw '固定签发公钥已变化；拒绝继续批量签发，请走显式签发机构迁移。'
    }
    if (-not (Test-FixedTimeText -Left $actualCa -Right $storedCa)) {
        throw '固定政府 HTTPS CA 已变化；拒绝继续批量签发，请走显式 CA 迁移。'
    }
}

function Import-AuthorityPolicy {
    param(
        [string] $Path,
        [switch] $LoadFields,
        [switch] $AllowMatchingPending
    )
    if (-not $AllowMatchingPending) { Assert-NoAuthorityPolicyPending }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 65536) {
        throw 'authority-policy.json 必须是管理员密钥目录中的普通小文件。'
    }
    try {
        $policy = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch { throw 'authority-policy.json 无法解析。' }
    if ([string]$policy.schema_version -ne 'mineguard-authority-policy-v1') {
        throw 'authority-policy.json 版本不受支持。'
    }
    $mapping = [ordered]@{
        issuer_private_key_file = $create.private
        issuer_public_key_file = $create.public
        issuer_id = $create.issuer_id
        issuer_key_id = $create.issuer_key_id
        platform_ca_source_file = $create.ca_source
        platform_base_url = $create.platform_url
        platform_system_id = $create.platform_system
        platform_party_id = $create.platform_party
        platform_key_id = $create.platform_key
    }
    foreach ($entry in $mapping.GetEnumerator()) {
        $value = [string]$policy.($entry.Key)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "authority-policy.json 缺少 $($entry.Key)。"
        }
        if ($LoadFields) {
            $entry.Value.Text = $value
        } else {
            $comparison = if ($entry.Key -in @(
                    'issuer_private_key_file',
                    'issuer_public_key_file',
                    'platform_ca_source_file'
                )) {
                [StringComparison]::OrdinalIgnoreCase
            } else { [StringComparison]::Ordinal }
            if (-not [string]::Equals(
                    $entry.Value.Text, $value, $comparison)) {
                throw "监管固定项 $($entry.Key) 与 authority-policy.json 不一致。"
            }
        }
    }
    Assert-AuthorityPolicyMaterial -Policy $policy
    if ($LoadFields) { Set-AuthorityPolicyFieldsLocked -Locked $true }
    return $policy
}

function Save-AuthorityPolicy {
    param([object] $Result, [string] $PendingTransactionId)
    $path = Get-AuthorityPolicyPath
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw '无法确定 authority-policy.json 保存位置。'
    }
    $expectedPolicyPath = Join-Path $authorityDefault 'authority-policy.json'
    if (-not [string]::Equals(
            $path, $expectedPolicyPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'authority-policy.json 只能发布到安装目录的签发机构专用目录。'
    }
    if ([string]::IsNullOrWhiteSpace($PendingTransactionId)) {
        Assert-NoAuthorityPolicyPending
    }
    if (Test-Path -LiteralPath $path) {
        $null = Import-AuthorityPolicy -Path $path
        Set-AuthorityPolicyFieldsLocked -Locked $true
        return
    }
    if ([string]::IsNullOrWhiteSpace($PendingTransactionId)) {
        throw '首次保存 authority-policy.json 必须绑定预先建立的 pending 事务。'
    }
    $null = Read-AuthorityPolicyPending `
        -ExpectedTransactionId $PendingTransactionId
    $values = Get-AuthorityPolicyValues
    $fixedCaPath = Get-AuthorityPolicyFixedCaPath
    if (-not [string]::Equals(
            [string]$Result.authority_platform_ca_file, $fixedCaPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw '生成器未返回安装目录中的固定政府 HTTPS CA，策略拒绝发布。'
    }
    $document = [ordered]@{
        schema_version = 'mineguard-authority-policy-v1'
        created_utc = [DateTime]::UtcNow.ToString('o')
        issuer_private_key_file = $values.issuer_private_key_file
        issuer_public_key_file = $values.issuer_public_key_file
        issuer_id = $values.issuer_id
        issuer_key_id = $values.issuer_key_id
        issuer_public_key_sha256 = [string]$Result.issuer_public_key_sha256
        platform_ca_source_file = $fixedCaPath
        platform_ca_sha256 = [string]$Result.platform_ca_sha256
        platform_base_url = $values.platform_base_url
        platform_system_id = $values.platform_system_id
        platform_party_id = $values.platform_party_id
        platform_key_id = $values.platform_key_id
        contains_secrets = $false
    }
    $bytes = $utf8NoBom.GetBytes(($document | ConvertTo-Json -Depth 4))
    $temporaryPath = Join-Path (Split-Path -Parent $path) (
        '.authority-policy.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    $stream = New-Object IO.FileStream(
        $temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    try {
        & "$env:SystemRoot\System32\icacls.exe" $temporaryPath `
            '/inheritance:r' '/grant:r' '*S-1-5-18:F' `
            '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw '无法保护 authority-policy.json 候选文件 ACL。'
        }
        Move-Item -LiteralPath $temporaryPath -Destination $path
        $create.ca_source.Text = $fixedCaPath
        $published = Import-AuthorityPolicy -Path $path `
            -AllowMatchingPending
        if ($null -eq $published) {
            throw 'authority-policy.json 原子发布后无法重新验证。'
        }
        $pendingPath = Get-AuthorityPolicyPendingPath
        Remove-Item -LiteralPath $pendingPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
    Set-AuthorityPolicyFieldsLocked -Locked $true
}

$defaultAuthorityPolicy = Join-Path $authorityDefault 'authority-policy.json'
$defaultAuthorityPolicyPending = Join-Path $authorityDefault `
    'authority-policy.pending.json'
if (Test-Path -LiteralPath $defaultAuthorityPolicyPending) {
    Set-Status (
        '检测到未完成的 authority-policy pending 事务；后续签发已闭锁。' +
        '请核对固定 CA、四区输出和审计记录后执行批准的恢复流程。'
    )
} elseif (Test-Path -LiteralPath $defaultAuthorityPolicy -PathType Leaf) {
    try {
        $null = Import-AuthorityPolicy -Path $defaultAuthorityPolicy -LoadFields
        Set-Status '已加载并锁定监管固定项 authority-policy.json；本页只需逐矿填写矿企字段。'
        $tabs.SelectedTab = $createPage
    } catch {
        Set-Status ('监管固定项加载失败：' + $_.Exception.Message)
    }
} elseif ((Test-Path -LiteralPath $privateBox.Text -PathType Leaf) -and
    (Test-Path -LiteralPath $publicBox.Text -PathType Leaf)) {
    Set-Status '已检测到本机签发密钥；请继续生成第一家企业的专属接入包。'
    $tabs.SelectedTab = $createPage
}

function Set-CurrentEnterpriseIdentifiers {
    $mineId = $create.mine_id.Text.Trim()
    $stem = ($mineId.ToLowerInvariant() -replace
        '[^a-z0-9-]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($stem)) {
        throw '煤矿 ID 必须至少包含一个字母或数字。'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $suffix = ([BitConverter]::ToString(
                $sha.ComputeHash($utf8NoBom.GetBytes($mineId))
            )).Replace('-', '').ToLowerInvariant().Substring(0, 8)
    } finally { $sha.Dispose() }
    if ($stem.Length -gt 39) { $stem = $stem.Substring(0, 39).TrimEnd('-') }
    $stem = $stem + '-' + $suffix
    $create.instance.Text = $stem
    $create.party_id.Text = 'enterprise-' + $stem
    $create.system_id.Text = 'agent-' + $stem
}

Add-NoteRow $createTable '当前版只生成全新配置（版本 1）。企业交付目录可选 U 盘；政府注册包和两端激活码自动保存到监管机受保护目录。'
$null = Add-ActionRow $createTable '生成这一家企业的专属接入包' {
    $secure = $null
    $pendingTransactionId = $null
    try {
        $days = 14
        Set-CurrentEnterpriseIdentifiers
        $secure = New-SecureValue $create.passphrase
        $create.passphrase.Clear()
        $policyPath = Get-AuthorityPolicyPath
        if (-not [string]::IsNullOrWhiteSpace($policyPath) -and
            (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
            $null = Import-AuthorityPolicy -Path $policyPath
        } else {
            $pendingTransactionId = New-AuthorityPolicyPending
        }
        Set-Status '正在验签发资料并生成一矿一包；激活码不会显示在窗口中…'
        $parameters = @{
            Action = 'CreatePair'; InstallRoot = $InstallRoot
            PrivateKeyPath = $create.private.Text
            PublicKeyPath = $create.public.Text
            PlatformCaSourcePath = $create.ca_source.Text
            Passphrase = $secure
            IssuerId = $create.issuer_id.Text
            IssuerKeyId = $create.issuer_key_id.Text
            MineId = $create.mine_id.Text; MineName = $create.mine_name.Text
            EnterprisePartyId = $create.party_id.Text
            EnterprisePartyName = $create.party_name.Text
            EnterpriseSystemId = $create.system_id.Text
            CapacityBand = $create.capacity.Text
            MiningMethod = $create.method.Text
            ShiftSystem = $create.shift.Text; CoalType = $create.coal.Text
            OperatingRegime = $create.regime.Text
            AgentPublicOrigin = $create.agent_origin.Text
            PlatformBaseUrl = $create.platform_url.Text
            AgentInstanceName = $create.instance.Text
            PlatformSystemId = $create.platform_system.Text
            PlatformPartyId = $create.platform_party.Text
            PlatformKeyId = $create.platform_key.Text
            InstallWindowDays = $days
            BundleOutputDirectory = $create.output.Text
            PlatformRegistrationDirectory = $create.registration_output.Text
            ActivationDirectory = $create.activations.Text
            ProfileVersion = 1
        }
        $result = & $coreScript @parameters
        Save-AuthorityPolicy -Result $result `
            -PendingTransactionId $pendingTransactionId
        $import.bundle.Text = [string]$result.platform_registration_bundle
        $import.activation.Text = [string]$result.platform_activation_file
        $import.public.Text = $create.public.Text
        $import.hash.Text = [string]$result.issuer_public_key_sha256
        $import.issuer_key.Text = $create.issuer_key_id.Text
        Set-Status ((
                "生成成功（{0}，版本 {1}；企业实例名 {8}）。`r`n企业交付目录：{2}`r`n" +
                "政府注册包：{3}`r`n企业激活码：{4}`r`n" +
                "政府激活码：{5}`r`n公钥 SPKI SHA-256：{6}`r`n" +
                "CA 文件 SHA-256：{9}`r`n签发 key ID：{7}`r`n" +
                "独立核验码（另渠道告知企业）：{10}`r`n" +
                "监管核验记录：{11}`r`n`r`n" +
                '交付要求：.mgprov 与企业激活码不要长期同盘保存，' +
                '应使用两个独立渠道交付。政府 .mgreg 与 Platform 激活码留在监管机；' +
                '私钥和 .mgreg 不得交给企业。监管固定策略和 CA 固定副本已原子发布。'
            ) -f $result.pair_id, $result.profile_version,
                $result.enterprise_delivery_directory,
                $result.platform_registration_bundle,
                $result.agent_activation_file,
                $result.platform_activation_file,
                $result.issuer_public_key_sha256, $create.issuer_key_id.Text,
                $result.agent_instance_name, $result.platform_ca_sha256,
                $result.independent_handover_check_code,
                $result.independent_handover_record)
        $tabs.SelectedTab = $importPage
    } catch { Show-OperationError '生成企业接入包' $_ }
    finally { if ($null -ne $secure) { $secure.Dispose() } }
}

# Page 3: import the matching registration retained by government and atomically make
# the Platform formal configuration managed by the issuer trust anchor.
$importPage = New-Object Windows.Forms.TabPage
$importPage.Text = '3. 完成监管端配置'
$importPage.AutoScroll = $true
$tabs.TabPages.Add($importPage)
$importTable = New-InputTable
$importPage.Controls.Add($importTable)
$import = @{}
Add-InputRow $importTable $import 'bundle' '政府本机留存 .mgreg' '' -Browse file `
    -Filter 'MineGuard 注册包 (*.mgreg)|*.mgreg|全部文件 (*.*)|*.*' | Out-Null
Add-InputRow $importTable $import 'activation' 'Platform 激活码' '' -Browse file `
    -Filter 'MineGuard 激活码 (*.activation)|*.activation|全部文件 (*.*)|*.*' | Out-Null
$import.public = New-Object Windows.Forms.TextBox
$import.public.Text = Join-Path $authorityDefault 'issuer-public.pem'
$import.hash = New-Object Windows.Forms.TextBox
$import.issuer_key = New-Object Windows.Forms.TextBox
$import.issuer_key.Text = 'qinyuan-provisioning-key-v1'
$import.state = New-Object Windows.Forms.TextBox
$import.state.Text = Join-Path $InstallRoot 'state'
Add-InputRow $importTable $import 'port' '本机监听端口' '8080' | Out-Null
Add-InputRow $importTable $import 'admin' '领导端管理员账号' 'admin' | Out-Null
Add-InputRow $importTable $import 'admin_password' '首次管理员密码' '' -Password | Out-Null
Add-InputRow $importTable $import 'admin_confirm' '再次输入管理员密码' '' -Password | Out-Null
Add-NoteRow $importTable '生成成功后，本页会自动带入政府注册包、Platform 激活码和签发信任。第一次配置只需设置强密码；以后新增煤矿无需重设密码。'
$script:ExistingFormalImportConfiguration = $false
$installedSettingsPath = Join-Path (Join-Path $InstallRoot 'config') `
    'settings.json'
if (Test-Path -LiteralPath $installedSettingsPath -PathType Leaf) {
    try {
        $installedSettings = Get-Content -LiteralPath $installedSettingsPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
        $import.state.Text = [string]$installedSettings.stateDirectory
        $import.port.Text = [string]$installedSettings.port
        $import.admin.Text = [string]$installedSettings.adminUsername
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$installedSettings.clientsFile)) {
            $script:ExistingFormalImportConfiguration = $true
            foreach ($fixedField in @(
                    $import.state, $import.port, $import.admin
                )) { $fixedField.ReadOnly = $true }
            if ($import.state.Tag -is [Windows.Forms.Button]) {
                $import.state.Tag.Enabled = $false
            }
            $import.admin_password.Enabled = $false
            $import.admin_confirm.Enabled = $false
            $managedProperty = $installedSettings.PSObject.Properties[
                'managedProvisioningRequired'
            ]
            if ($null -ne $managedProperty -and
                [bool]$managedProperty.Value) {
                $import.public.Text = [string](
                    $installedSettings.provisioningTrustedPublicKeyFile
                )
                $import.hash.Text = [string](
                    $installedSettings.provisioningExpectedPublicKeySha256
                )
                $import.issuer_key.Text = [string](
                    $installedSettings.provisioningExpectedIssuerKeyId
                )
                foreach ($trustField in @(
                        $import.public, $import.hash, $import.issuer_key
                    )) { $trustField.ReadOnly = $true }
                if ($import.public.Tag -is [Windows.Forms.Button]) {
                    $import.public.Tag.Enabled = $false
                }
            }
        }
    } catch {
        Set-Status ('现有 settings.json 无法安全预填：' + $_.Exception.Message)
    }
}
$null = Add-ActionRow $importTable '验签、导入并完成正式配置' {
    $adminSecure = $null
    try {
        $port = 0
        if (-not [int]::TryParse($import.port.Text, [ref]$port) -or
            $port -lt 1 -or $port -gt 65535) { throw '监听端口必须为 1-65535。' }
        if ([string]::IsNullOrWhiteSpace($import.hash.Text)) {
            $import.hash.Text = Get-GuiSpkiSha256FromPem `
                -Path $import.public.Text
        }
        $passwordSupplied = -not [string]::IsNullOrEmpty(
            $import.admin_password.Text
        ) -or -not [string]::IsNullOrEmpty($import.admin_confirm.Text)
        if ($script:ExistingFormalImportConfiguration -and $passwordSupplied) {
            throw '已有正式 Platform 时新增煤矿不能重设管理员密码。'
        }
        if ($passwordSupplied) {
            if (-not [string]::Equals(
                    $import.admin_password.Text, $import.admin_confirm.Text,
                    [StringComparison]::Ordinal)) {
                throw '两次输入的管理员密码不一致。'
            }
            $adminSecure = New-SecureValue $import.admin_password
        }
        $import.admin_password.Clear(); $import.admin_confirm.Clear()
        $manageService = $false
        $runningService = Get-Service -Name 'MineGuardPlatform' `
            -ErrorAction SilentlyContinue
        if ($null -ne $runningService) {
            $runningService.Refresh()
            if ($runningService.Status -ne `
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                if ($runningService.Status -ne `
                        [System.ServiceProcess.ServiceControllerStatus]::Running) {
                    throw "MineGuardPlatform 服务处于 $($runningService.Status)，请先由管理员恢复为 Running 或 Stopped。"
                }
                $decision = [Windows.Forms.MessageBox]::Show(
                    '导入注册会短暂停止 MineGuardPlatform，期间领导端与企业报送暂不可用；事务完成或失败后向导都会自动恢复服务。是否现在继续？',
                    '确认短暂停服',
                    [Windows.Forms.MessageBoxButtons]::YesNo,
                    [Windows.Forms.MessageBoxIcon]::Warning,
                    [Windows.Forms.MessageBoxDefaultButton]::Button2
                )
                if ($decision -ne [Windows.Forms.DialogResult]::Yes) {
                    throw '用户取消了短暂停服，注册未导入。'
                }
                $manageService = $true
            }
        }
        Set-Status '正在验签本机留存的监管注册包，并事务写入企业注册与签发信任…'
        $parameters = @{
            Action = 'ImportRegistration'; InstallRoot = $InstallRoot
            RegistrationBundle = $import.bundle.Text
            RegistrationActivationFile = $import.activation.Text
            PublicKeyPath = $import.public.Text
            ExpectedPublicKeySha256 = $import.hash.Text.Trim()
            ExpectedIssuerKeyId = $import.issuer_key.Text.Trim()
            StateDirectory = $import.state.Text; Port = $port
            AdminUsername = $import.admin.Text
        }
        if ($manageService) { $parameters.ManageServiceLifecycle = $true }
        if ($null -ne $adminSecure) { $parameters.AdminPassword = $adminSecure }
        $result = & $coreScript @parameters
        $serviceResultNote = if ($manageService) {
            '原先运行的 Platform 服务已自动恢复。'
        } else {
            '现在可回到 Platform 控制中心安装/启动正式服务。'
        }
        Set-Status ((
                "注册导入完成：{0}`r`n煤矿 ID：{1}`r`n" +
                "企业系统 ID：{2}`r`n配置版本：{3}`r`n" +
                "当前企业数：{4}`r`n监管身份：{5} / {6} / {7}`r`n" +
                "签发 SPKI SHA-256：{8}`r`n`r`n" +
                'clients.json、监管身份和信任锚已同时保存。' +
                $serviceResultNote
            ) -f $result.status, $result.mine_id,
                $result.enterprise_system_id, $result.profile_version,
                $result.client_count, $result.platform_system_id,
                $result.platform_party_id, $result.platform_key_id,
                $result.issuer_public_key_sha256)
    } catch { Show-OperationError '导入监管注册包' $_ }
    finally { if ($null -ne $adminSecure) { $adminSecure.Dispose() } }
}

$form.Add_FormClosed({
        foreach ($box in @(
                $issuerPass, $issuerConfirm, $create.passphrase,
                $import.admin_password, $import.admin_confirm
            )) { if ($null -ne $box) { $box.Clear() } }
})
try {
    if ($script:ExistingFormalImportConfiguration) {
        Set-Status '已检测到正式 Platform：新增煤矿时将强制沿用现有 state、端口、管理员和签发信任，不会重配领导端。'
    } else {
        Set-Status '请按 1 → 2 → 3 操作。已存在签发密钥时可直接从第 2 步开始。'
    }
    if ($SelfTest) {
        $selfTestResult | ConvertTo-Json -Compress | Write-Output
        return
    }
    [void]$form.ShowDialog()
} finally {
    $form.Dispose()
    $titleFont.Dispose(); $monoFont.Dispose(); $font.Dispose()
}
