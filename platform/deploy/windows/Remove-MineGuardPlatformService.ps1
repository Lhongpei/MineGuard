[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
    [switch] $RemoveWrapperFiles
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }
$script:ServiceRemovalScriptPath = [IO.Path]::GetFullPath($PSCommandPath)
$ServiceAccount = 'NT SERVICE\MineGuardPlatform'
$ServiceSid = 'S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346'

if ($env:OS -ne 'Windows_NT') { throw '服务移除脚本只能在 Windows 上运行。' }
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) { throw '移除 Windows 服务必须以管理员身份运行 Windows PowerShell。' }

function Get-SafeFixedNtfsPath {
    param([string] $Value, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -ne $Value.Trim() -or
        $Value.IndexOf([char]0) -ge 0 -or $Value.Contains('/') -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $withoutTrailingSlash = $Value.TrimEnd('\\')
    if ($withoutTrailingSlash.Length -le 2) { throw "$Label 不能是磁盘根目录。" }
    foreach ($part in ($withoutTrailingSlash.Substring(3) -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -in @('.', '..') -or
            $part.Contains(':') -or $part.EndsWith(' ') -or $part.EndsWith('.')) {
            throw "$Label 包含空、点、ADS 或其他歧义路径段。"
        }
    }
    $fullPath = [IO.Path]::GetFullPath($Value).TrimEnd('\\')
    if ($fullPath.Substring(2).Contains(':')) { throw "$Label 不能包含 ADS。" }
    $root = [IO.Path]::GetPathRoot($fullPath)
    $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or -not $drive.IsReady -or
        -not $drive.DriveFormat.Equals('NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label 必须位于已就绪的本机固定 NTFS 磁盘。"
    }
    $current = $fullPath
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 及其现有祖先不能包含符号链接、junction 或 reparse point：$current"
            }
        }
        if ($current.Equals($root.TrimEnd('\\'), [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            throw "$Label 无法安全解析祖先目录。"
        }
        $current = $parent.TrimEnd('\\')
    }
    return $fullPath
}

function Assert-NotBroadInstallRoot {
    param([string] $Path)
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\\')
    foreach ($protectedValue in @(
            $env:ProgramData, $env:ALLUSERSPROFILE, $env:ProgramFiles,
            ${env:ProgramFiles(x86)}, $env:CommonProgramFiles,
            ${env:CommonProgramFiles(x86)}, $env:PUBLIC
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) {
        $protected = [IO.Path]::GetFullPath([string]$protectedValue).TrimEnd('\\')
        if ($candidate.Equals($protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'InstallRoot 不能是宽泛系统或共享数据目录。'
        }
    }
    $windowsRoot = [IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\\')
    if ($candidate.Equals($windowsRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($windowsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'InstallRoot 不能位于 Windows 系统目录内。'
    }
}

function Assert-OrdinaryFile {
    param([string] $Path, [string] $Label, [long] $MaximumBytes = 0)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label 不存在：$Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label 不能是 reparse point：$Path"
    }
    if ($MaximumBytes -gt 0 -and ($item.Length -le 0 -or $item.Length -gt $MaximumBytes)) {
        throw "$Label 大小无效：$Path"
    }
    return $item
}

function Assert-NoReparseTree {
    param([string] $Path, [string] $Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Label 不存在：$Path" }
    foreach ($item in @((Get-Item -LiteralPath $Path -Force)) + @(
            Get-ChildItem -LiteralPath $Path -Recurse -Force
        )) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label 包含 reparse point：$($item.FullName)"
        }
    }
}

function Read-JsonObject {
    param([string] $Path, [string] $Label, [long] $MaximumBytes = 16777216)
    $null = Assert-OrdinaryFile -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try { $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "$Label 不是有效 JSON：$($_.Exception.Message)" }
    if ($null -eq $value -or $value -is [Array]) { throw "$Label 必须是一个 JSON 对象。" }
    return $value
}

function Assert-PlatformReleaseAndConfigurationIdentity {
    param([string] $Root)
    $serviceRoot = Join-Path $Root 'service'
    $metadataRoot = Join-Path $Root 'release-metadata'
    $manifestPath = Join-Path $metadataRoot 'release-manifest.json'
    $versionPath = Join-Path $metadataRoot 'VERSION.txt'
    $checksumsPath = Join-Path $metadataRoot 'SHA256SUMS.txt'
    Assert-NoReparseTree -Path $serviceRoot -Label 'service 目录'
    Assert-NoReparseTree -Path $metadataRoot -Label 'release-metadata 目录'
    $manifest = Read-JsonObject -Path $manifestPath -Label 'Platform release manifest'
    $null = Assert-OrdinaryFile -Path $versionPath -Label 'VERSION.txt' -MaximumBytes 128
    $null = Assert-OrdinaryFile -Path $checksumsPath -Label 'SHA256SUMS.txt' -MaximumBytes 16777216
    $version = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.product -ne 'MineGuard Platform' -or
        [string]$manifest.architecture -ne 'x64' -or
        [string]$manifest.runtime -ne 'nuitka-standalone' -or
        [string]$manifest.entryPoint -ne 'runtime/MineGuardPlatform.exe' -or
        [string]$manifest.version -ne $version -or
        $version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'InstallRoot 不包含身份一致的 MineGuard Platform 发布。'
    }
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    $manifestChecksumCount = 0
    foreach ($line in Get-Content -LiteralPath $checksumsPath -Encoding UTF8) {
        if ($line -match '^(?<hash>[A-Fa-f0-9]{64})  release-manifest\.json$') {
            $manifestChecksumCount++
            if (-not $manifestHash.Equals(
                    [string]$Matches['hash'], [StringComparison]::OrdinalIgnoreCase)) {
                throw 'release-manifest.json 与 SHA256SUMS.txt 不一致。'
            }
        }
    }
    if ($manifestChecksumCount -ne 1) { throw 'SHA256SUMS.txt 未唯一认证 release manifest。' }
    $scriptEntries = @($manifest.files | Where-Object {
            [string]$_.path -eq 'deploy/windows/Remove-MineGuardPlatformService.ps1'
        })
    $scriptItem = Get-Item -LiteralPath $script:ServiceRemovalScriptPath -Force
    $expectedScriptPath = Join-Path $serviceRoot 'Remove-MineGuardPlatformService.ps1'
    if (-not $script:ServiceRemovalScriptPath.Equals(
            $expectedScriptPath, [StringComparison]::OrdinalIgnoreCase) -or
        $scriptEntries.Count -ne 1 -or
        [string]$scriptEntries[0].sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        [long]$scriptEntries[0].bytes -ne [long]$scriptItem.Length -or
        -not (Get-FileHash -LiteralPath $script:ServiceRemovalScriptPath `
            -Algorithm SHA256).Hash.Equals(
                [string]$scriptEntries[0].sha256,
                [StringComparison]::OrdinalIgnoreCase
            )) {
        throw '服务移除脚本不属于当前受保护的 Platform release manifest。'
    }

    $settingsPath = Join-Path (Join-Path $Root 'config') 'settings.json'
    $settings = Read-JsonObject -Path $settingsPath -Label 'Platform settings.json' -MaximumBytes 1048576
    if ([int]$settings.schemaVersion -ne 1 -or [string]$settings.host -ne '127.0.0.1' -or
        [string]$settings.platformSystemId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        [string]$settings.platformPartyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        [string]$settings.platformKeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw 'Platform settings.json 产品/监管身份无效。'
    }
    $stateRoot = Get-SafeFixedNtfsPath -Value ([string]$settings.stateDirectory) `
        -Label 'settings.json 状态目录'
    $marker = Read-JsonObject -Path (Join-Path $stateRoot '.mineguard-platform-state.json') `
        -Label 'Platform 状态所有权标记' -MaximumBytes 65536
    $markerRoot = Get-SafeFixedNtfsPath -Value ([string]$marker.initializedFor) `
        -Label '状态标记 initializedFor'
    if ([int]$marker.schemaVersion -ne 1 -or
        [string]$marker.product -ne 'MineGuard Platform State' -or
        -not $markerRoot.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) {
        throw '状态目录所有权标记不属于当前 Platform 安装。'
    }
}

function Get-RegisteredService {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='MineGuardPlatform'" -ErrorAction Stop)
    if ($services.Count -gt 1) { throw '同一名称出现多个 Win32_Service 记录。' }
    if ($services.Count -eq 0) { return $null }
    return $services[0]
}

function Assert-ServiceSidTypeUnrestricted {
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\MineGuardPlatform'
    try {
        $properties = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
    } catch {
        throw '无法读取 MineGuardPlatform 的 ServiceSidType；拒绝移除。'
    }
    $property = $properties.PSObject.Properties['ServiceSidType']
    if ($null -eq $property -or [int]$property.Value -ne 1) {
        throw '同名服务未启用 unrestricted 专属服务 SID；拒绝移除。'
    }
    $sidOutput = (& "$env:SystemRoot\System32\sc.exe" `
        'showsid' 'MineGuardPlatform' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe showsid 无法计算 MineGuardPlatform 服务 SID，退出码 $LASTEXITCODE。"
    }
    $sidMatches = @([regex]::Matches(
        $sidOutput,
        '(?<![0-9])S-1-5-80(?:-[0-9]+){5}(?![0-9])',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    ) | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
    if ($sidMatches.Count -ne 1 -or
        -not $sidMatches[0].Equals(
            $ServiceSid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Windows 计算的 MineGuardPlatform 服务 SID 与固定 ACL SID 不一致；拒绝移除。'
    }
    try {
        $account = New-Object -TypeName Security.Principal.NTAccount `
            -ArgumentList $ServiceAccount
        $translated = $account.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "无法把专属虚拟账号 $ServiceAccount 解析为 Windows SID；拒绝移除。"
    }
    if (-not $translated.Equals(
            $ServiceSid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw '专属虚拟账号解析所得 SID 与固定 ACL SID 不一致；拒绝移除。'
    }
}

function Get-ServiceExecutablePath {
    param([object] $Service)
    $pathName = ([string]$Service.PathName).Trim()
    if ($pathName -match '^"([^"\r\n]+)"\s*$') { return $Matches[1] }
    if ($pathName -match '^[^"\r\n]+$') { return $pathName }
    throw '同名服务 PathName 不安全或携带参数；拒绝移除。'
}

function Assert-ServiceTargetsWrapper {
    param([object] $Service, [string] $ExpectedWrapper)
    $registered = Get-SafeFixedNtfsPath -Value (Get-ServiceExecutablePath -Service $Service) `
        -Label 'Win32_Service PathName'
    if (-not $registered.Equals($ExpectedWrapper, [StringComparison]::OrdinalIgnoreCase)) {
        throw '同名服务未精确指向批准的无参数 wrapper；拒绝同名服务劫持。'
    }
    if (-not ([string]$Service.StartName).Equals(
            $ServiceAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw "同名服务账号不是批准的专属虚拟账号 $ServiceAccount；拒绝移除。"
    }
    Assert-ServiceSidTypeUnrestricted
}

function Wait-ServiceRecordAbsent {
    param([int] $Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 200
        $service = Get-RegisteredService
    } while ($null -ne $service -and [DateTime]::UtcNow -lt $deadline)
    if ($null -ne $service) { throw 'MineGuardPlatform 服务注册未在期限内删除。' }
}

function Assert-WrapperIntegrity {
    param([string] $Wrapper, [string] $Config, [string] $IntegrityPath)
    $integrity = Read-JsonObject -Path $IntegrityPath -Label 'WinSW 完整性记录' -MaximumBytes 1048576
    $null = Assert-OrdinaryFile -Path $Wrapper -Label 'WinSW wrapper' -MaximumBytes 134217728
    if ([int]$integrity.schemaVersion -ne 1 -or
        [string]$integrity.wrapperSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        -not (Get-FileHash -LiteralPath $Wrapper -Algorithm SHA256).Hash.Equals(
            [string]$integrity.wrapperSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WinSW wrapper 与受保护的完整性记录不一致。'
    }
    if ([string]$integrity.product -ne 'MineGuard Platform WinSW Service' -or
        [string]$integrity.serviceId -ne 'MineGuardPlatform' -or
        [string]$integrity.serviceAccount -ne $ServiceAccount -or
        [string]$integrity.serviceSid -ne $ServiceSid -or
        [string]$integrity.serviceSidType -ne 'unrestricted' -or
        -not ([string]$integrity.canonicalWrapperPath).Equals(
            $Wrapper, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WinSW 完整性记录的产品或服务身份不一致。'
    }
    $configHash = [string]$integrity.wrapperConfigSha256
    if ([string]::IsNullOrWhiteSpace($configHash)) {
        if (Test-Path -LiteralPath $Config) { throw '发现未登记的 WinSW .config。' }
    } else {
        $null = Assert-OrdinaryFile -Path $Config -Label 'WinSW .config' -MaximumBytes 4194304
        if ($configHash -notmatch '^[A-Fa-f0-9]{64}$' -or
            -not (Get-FileHash -LiteralPath $Config -Algorithm SHA256).Hash.Equals(
                $configHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'WinSW .config 与受保护的完整性记录不一致。'
        }
    }
}

$InstallRoot = Get-SafeFixedNtfsPath -Value $InstallRoot -Label '安装目录'
Assert-NotBroadInstallRoot -Path $InstallRoot
Assert-PlatformReleaseAndConfigurationIdentity -Root $InstallRoot
$serviceDirectory = Get-SafeFixedNtfsPath -Value (Join-Path $InstallRoot 'service') `
    -Label 'Platform service 目录'
$expectedWrapper = Get-SafeFixedNtfsPath `
    -Value (Join-Path $serviceDirectory 'MineGuard.Platform.exe') `
    -Label 'MineGuard Platform 服务 wrapper'
$wrapperConfig = Get-SafeFixedNtfsPath -Value ($expectedWrapper + '.config') `
    -Label 'MineGuard Platform wrapper .config'
$integrityPath = Get-SafeFixedNtfsPath -Value (Join-Path $serviceDirectory 'winsw-integrity.json') `
    -Label 'MineGuard Platform WinSW 完整性记录'

$service = Get-RegisteredService
if ($null -ne $service) {
    Assert-ServiceTargetsWrapper -Service $service -ExpectedWrapper $expectedWrapper
    Assert-WrapperIntegrity -Wrapper $expectedWrapper -Config $wrapperConfig `
        -IntegrityPath $integrityPath
} elseif (-not $RemoveWrapperFiles) {
    Write-Host 'MineGuardPlatform 服务未安装；runtime、config、state、backups 和 logs 均未修改。'
    exit 0
}

if ($PSCmdlet.ShouldProcess(
        'MineGuardPlatform',
        '停止并删除精确绑定的 Windows 服务注册（保留业务状态）'
    )) {
    $service = Get-RegisteredService
    if ($null -ne $service) {
        Assert-ServiceTargetsWrapper -Service $service -ExpectedWrapper $expectedWrapper
        Assert-WrapperIntegrity -Wrapper $expectedWrapper -Config $wrapperConfig `
            -IntegrityPath $integrityPath
        if (-not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Service -Name 'MineGuardPlatform' -Force -ErrorAction Stop
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 200
                $service = Get-RegisteredService
                if ($null -eq $service) { break }
                Assert-ServiceTargetsWrapper -Service $service -ExpectedWrapper $expectedWrapper
            } while (-not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase) -and
                [DateTime]::UtcNow -lt $deadline)
            if ($null -ne $service -and
                -not ([string]$service.State).Equals('Stopped', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'MineGuardPlatform 服务未在 30 秒内停止。'
            }
        }
        # 最后一次 sc.exe delete 之前重新读取并精确校验完整、无参数 PathName 和账号。
        $service = Get-RegisteredService
        if ($null -ne $service) {
            Assert-ServiceTargetsWrapper -Service $service -ExpectedWrapper $expectedWrapper
            & "$env:SystemRoot\System32\sc.exe" 'delete' 'MineGuardPlatform' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "删除服务注册失败，sc.exe 退出码 $LASTEXITCODE。" }
            Wait-ServiceRecordAbsent
        }
    }

    if ($RemoveWrapperFiles) {
        if ($null -ne (Get-RegisteredService)) { throw '服务仍注册，拒绝删除 wrapper 文件。' }
        Assert-WrapperIntegrity -Wrapper $expectedWrapper -Config $wrapperConfig `
            -IntegrityPath $integrityPath
        foreach ($exactPath in @($wrapperConfig, $expectedWrapper, $integrityPath)) {
            if ($null -ne (Get-RegisteredService)) {
                throw 'wrapper 清理期间服务重新出现；停止清理。'
            }
            if (Test-Path -LiteralPath $exactPath -PathType Leaf) {
                $null = Assert-OrdinaryFile -Path $exactPath -Label '精确 WinSW 服务文件'
                Remove-Item -LiteralPath $exactPath -Force -ErrorAction Stop
            }
        }
    }
    Write-Host 'MineGuardPlatform 服务注册已删除。'
    Write-Host "业务 runtime/config/state/backups/logs 未删除：$InstallRoot"
}
