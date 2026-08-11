[CmdletBinding()]
param(
    [string] $SourceDirectory = '',
    [string] $InstallRoot = (Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) 'MineGuard\Platform'),
    [string] $PythonExecutable,
    [string] $Wheelhouse,
    [ValidateRange(1, 65535)] [int] $Port = 8080,
    [switch] $AllowUnsignedInternalRelease,
    [string] $ExpectedReleaseManifestSha256 = '',
    [switch] $AuditFailAfterRuntimeSwitch
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ServiceSid = 'S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346'
$ServiceAccount = 'NT SERVICE\MineGuardPlatform'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }
if ([string]::IsNullOrWhiteSpace($SourceDirectory)) {
    $SourceDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $identity
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw '安装和设置 NTFS ACL 必须在【以管理员身份运行】的 Windows PowerShell 5.1 中执行。'
    }
}

function Assert-InstalledServiceSecurityBoundary {
    $records = @(Get-CimInstance Win32_Service `
        -Filter "Name='MineGuardPlatform'" -ErrorAction Stop)
    if ($records.Count -ne 1 -or
        -not ([string]$records[0].StartName).Equals(
            $ServiceAccount, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw '现有 MineGuardPlatform 服务不是专属虚拟账号；请先用当前版本安全移除服务，再重新安装。'
    }
    $properties = Get-ItemProperty -LiteralPath `
        'HKLM:\SYSTEM\CurrentControlSet\Services\MineGuardPlatform' `
        -ErrorAction Stop
    $sidType = $properties.PSObject.Properties['ServiceSidType']
    if ($null -eq $sidType -or [int]$sidType.Value -ne 1) {
        throw '现有 MineGuardPlatform 服务未启用 unrestricted 专属服务 SID；拒绝继承。'
    }
    $sidOutput = (& "$env:SystemRoot\System32\sc.exe" `
        'showsid' 'MineGuardPlatform' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $sidOutput -notmatch '(?<![0-9])S-1-5-80(?:-[0-9]+){5}(?![0-9])' -or
        -not $Matches[0].Equals(
            $ServiceSid, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Windows 计算的 MineGuardPlatform 服务 SID 与固定 ACL SID 不一致；拒绝继承。'
    }
}

function Get-LocalAbsolutePath {
    param(
        [string] $Value,
        [string] $Label,
        [switch] $RequireFixedNtfs
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Za-z]:\\') {
        throw "$Label 必须是 X:\\... 形式的本机完整绝对路径。"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if ($fullPath.StartsWith('\\')) { throw "$Label 不能使用 UNC/SMB 网络路径。" }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label 不能是磁盘根目录。"
    }
    if ($RequireFixedNtfs) {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
            throw "$Label 必须位于本机固定磁盘。"
        }
        if (-not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS') {
            throw "$Label 必须位于已就绪的 NTFS 磁盘。"
        }
    }
    $current = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label 及其现有祖先目录不能包含符号链接、junction 或挂载点：$current"
            }
        }
        if ($current.TrimEnd('\\') -eq $root.TrimEnd('\\')) { break }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $fullPath
}

function Test-PathEqualOrChild {
    param([string] $Candidate, [string] $Parent)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\\')
    return $candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith(
            $parentFull + '\', [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-MineGuardNoReparseTree {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($item in @((Get-Item -LiteralPath $Path -Force)) + @(
            Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "安装目录树不能包含 reparse point：$($item.FullName)"
        }
    }
}

function Assert-NotBroadOrSystemInstallRoot {
    param([string] $Path)
    $candidate = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $protectedExact = @(
        $env:ProgramData,
        $env:ALLUSERSPROFILE,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:CommonProgramFiles,
        ${env:CommonProgramFiles(x86)},
        $env:PUBLIC
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    foreach ($protectedValue in $protectedExact) {
        $protected = [System.IO.Path]::GetFullPath(
            [string]$protectedValue
        ).TrimEnd('\')
        if ($candidate.Equals($protected, [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能是 ProgramData、Program Files、Public 等宽泛系统目录本身。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $windowsRoot = [System.IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')
        if ($candidate.Equals($windowsRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith(
                $windowsRoot + '\', [StringComparison]::OrdinalIgnoreCase
            )) {
            throw '安装目录不能位于 Windows 系统目录内。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $usersRoot = [System.IO.Path]::GetFullPath(
            (Join-Path $env:SystemDrive 'Users')
        ).TrimEnd('\')
        if ($candidate.Equals($usersRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw '安装目录不能是整个 Users 目录。'
        }
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)] [string] $Command,
        [Parameter(Mandatory = $true)] [object[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label 失败，退出码 $LASTEXITCODE。"
    }
}

function Assert-MineGuardOwnedPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedParent,
        [Parameter(Mandatory = $true)] [string] $AllowedLeafPattern
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullParent = [System.IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $actualParent = [System.IO.Path]::GetDirectoryName($fullPath)
    $leaf = [System.IO.Path]::GetFileName($fullPath)
    if (-not $actualParent.Equals(
            $fullParent, [StringComparison]::OrdinalIgnoreCase
        ) -or -not [regex]::IsMatch(
            $leaf,
            $AllowedLeafPattern,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )) {
        throw "拒绝操作非本事务拥有的路径：$fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        $item = Get-Item -LiteralPath $fullPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "拒绝操作 reparse point：$fullPath"
        }
    }
}

function Remove-MineGuardOwnedPathWithRetry {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedParent,
        [Parameter(Mandatory = $true)] [string] $AllowedLeafPattern,
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 60
    )
    Assert-MineGuardOwnedPath -Path $Path -ExpectedParent $ExpectedParent `
        -AllowedLeafPattern $AllowedLeafPattern
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ($true) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try {
            $item = Get-Item -LiteralPath $Path -Force
            if ($item.PSIsContainer) {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
        } catch {
            $lastError = $_
        }
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $detail = if ($null -eq $lastError) {
        '路径仍然存在'
    } else {
        $lastError.Exception.Message
    }
    throw "在 $TimeoutSeconds 秒内无法清理事务路径 $Path。最后错误：$detail"
}

function Move-MineGuardOwnedPathWithRetry {
    param(
        [Parameter(Mandatory = $true)] [string] $SourcePath,
        [Parameter(Mandatory = $true)] [string] $SourceParent,
        [Parameter(Mandatory = $true)] [string] $SourceLeafPattern,
        [Parameter(Mandatory = $true)] [string] $DestinationPath,
        [Parameter(Mandatory = $true)] [string] $DestinationParent,
        [Parameter(Mandatory = $true)] [string] $DestinationLeafPattern,
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 60
    )
    Assert-MineGuardOwnedPath -Path $SourcePath -ExpectedParent $SourceParent `
        -AllowedLeafPattern $SourceLeafPattern
    Assert-MineGuardOwnedPath -Path $DestinationPath `
        -ExpectedParent $DestinationParent `
        -AllowedLeafPattern $DestinationLeafPattern
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "事务源路径不存在：$SourcePath"
    }
    if (Test-Path -LiteralPath $DestinationPath) {
        throw "事务目标路径已存在，拒绝覆盖：$DestinationPath"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = $null
    $moveAttempted = $false
    while ($true) {
        if (-not (Test-Path -LiteralPath $SourcePath)) {
            if ($moveAttempted -and
                (Test-Path -LiteralPath $DestinationPath)) { return }
            throw "事务源路径和目标路径均不存在：$SourcePath -> $DestinationPath"
        }
        if (Test-Path -LiteralPath $DestinationPath) {
            throw "事务目标路径已存在，拒绝覆盖：$DestinationPath"
        }
        try {
            $moveAttempted = $true
            Move-Item -LiteralPath $SourcePath -Destination $DestinationPath `
                -ErrorAction Stop
        } catch {
            $lastError = $_
        }
        if (-not (Test-Path -LiteralPath $SourcePath) -and
            (Test-Path -LiteralPath $DestinationPath)) {
            return
        }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $detail = if ($null -eq $lastError) {
        '移动未完成'
    } else {
        $lastError.Exception.Message
    }
    throw "在 $TimeoutSeconds 秒内无法移动事务路径 $SourcePath。最后错误：$detail"
}

function Assert-MineGuardBinaryInstallPathBudget {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [object] $Manifest,
        [ValidateRange(200, 259)] [int] $MaximumPathLength = 240
    )
    $syntheticGuid = 'f' * 32
    $longestPath = $Root
    foreach ($entry in @($Manifest.files)) {
        $relative = ([string]$entry.path).Replace('\', '/')
        $transactionLeaf = $null
        $transactionRelative = $null
        if ($relative.StartsWith(
                'runtime/', [StringComparison]::OrdinalIgnoreCase
            )) {
            $transactionLeaf = '.runtime.incoming.' + $syntheticGuid
            $transactionRelative = $relative.Substring('runtime/'.Length)
        } elseif ($relative.StartsWith(
                'deploy/windows/', [StringComparison]::OrdinalIgnoreCase
            )) {
            $transactionLeaf = '.service.incoming.' + $syntheticGuid
            $transactionRelative = $relative.Substring('deploy/windows/'.Length)
        } elseif ($relative -in @(
                'VERSION.txt', 'build-metadata.json', 'release-manifest.json',
                'SHA256SUMS.txt'
            )) {
            $transactionLeaf = '.release-metadata.incoming.' + $syntheticGuid
            $transactionRelative = $relative
        }
        if ($null -eq $transactionLeaf) { continue }
        $projected = Join-Path (Join-Path $Root $transactionLeaf) `
            $transactionRelative.Replace('/', '\')
        if ($projected.Length -gt $longestPath.Length) {
            $longestPath = $projected
        }
    }
    if ($longestPath.Length -gt $MaximumPathLength) {
        throw (
            '安装目录过深：当前发布包的事务暂存路径最长将达到 {0} 个字符，' +
            '安全上限为 {1}。请改用更短的安装目录。' -f `
                $longestPath.Length, $MaximumPathLength
        )
    }
}

function Set-MineGuardDirectoryAcl {
    param(
        [string] $Path,
        [string] $ServicePermission,
        [switch] $Recurse,
        [switch] $UsersReadExecute
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "ACL 目标不存在：$Path"
    }
    $rootItem = Get-Item -LiteralPath $Path -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "ACL 根必须是普通目录：$Path"
    }
    $serviceRights = switch ($ServicePermission) {
        'RX' { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
        'M' { [Security.AccessControl.FileSystemRights]::Modify }
        default { throw "不支持的 Platform 服务 ACL 权限：$ServicePermission" }
    }
    $administrators = New-Object Security.Principal.SecurityIdentifier(
        'S-1-5-32-544'
    )
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $service = New-Object Security.Principal.SecurityIdentifier($ServiceSid)
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $none = [Security.AccessControl.PropagationFlags]::None
    $containerAndObject = `
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit

    function Set-OneMineGuardAcl {
        param([IO.FileSystemInfo] $Item)
        $isDirectory = $Item.PSIsContainer
        $security = if ($isDirectory) {
            New-Object Security.AccessControl.DirectorySecurity
        }
        else {
            New-Object Security.AccessControl.FileSecurity
        }
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($administrators)
        $inheritance = if ($isDirectory) {
            $containerAndObject
        }
        else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        foreach ($definition in @(
            [pscustomobject]@{
                Sid = $system
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            [pscustomobject]@{
                Sid = $administrators
                Rights = [Security.AccessControl.FileSystemRights]::FullControl
            },
            [pscustomobject]@{
                Sid = $service
                Rights = $serviceRights
            }
        )) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $definition.Sid,
                $definition.Rights,
                $inheritance,
                $none,
                $allow
            )
            [void]$security.AddAccessRule($rule)
        }
        if ($UsersReadExecute) {
            $usersRule = New-Object Security.AccessControl.FileSystemAccessRule(
                $users,
                [Security.AccessControl.FileSystemRights]::ReadAndExecute,
                $inheritance,
                $none,
                $allow
            )
            [void]$security.AddAccessRule($usersRule)
        }
        if ($isDirectory) {
            [IO.Directory]::SetAccessControl($Item.FullName, $security)
            $applied = [IO.Directory]::GetAccessControl($Item.FullName)
        }
        else {
            [IO.File]::SetAccessControl($Item.FullName, $security)
            $applied = [IO.File]::GetAccessControl($Item.FullName)
        }
        if (-not $applied.AreAccessRulesProtected) {
            throw "ACL 意外保留了继承：$($Item.FullName)"
        }
    }

    # 每个对象只执行一次完整 protected DACL 写入；禁止先 /reset 再收紧所
    # 产生的短暂父目录继承窗口。
    Set-OneMineGuardAcl -Item $rootItem
    if ($Recurse) {
        foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Platform 产品树不能包含 reparse point：$($item.FullName)"
            }
            Set-OneMineGuardAcl -Item $item
        }
    }
}

function Test-MineGuardPlatformRuntimeProcess {
    param([string] $RuntimeRoot)
    $runtimePrefix = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\\') + '\'
    $running = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            if ([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)) {
                return $false
            }
            try {
                $processPath = [System.IO.Path]::GetFullPath(
                    [string]$_.ExecutablePath
                )
                return $processPath.StartsWith(
                    $runtimePrefix, [StringComparison]::OrdinalIgnoreCase
                )
            } catch {
                return $false
            }
        })
    return $running.Count -gt 0
}

Assert-Administrator
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw '需要 Windows PowerShell 5.1 或更高版本。'
}
$SourceDirectory = Get-LocalAbsolutePath -Value $SourceDirectory -Label '发布源目录'
$InstallRoot = Get-LocalAbsolutePath -Value $InstallRoot -Label '安装目录' `
    -RequireFixedNtfs
Assert-NotBroadOrSystemInstallRoot -Path $InstallRoot
$binarySource = Join-Path $SourceDirectory 'runtime\MineGuardPlatform.exe'
$sourceProject = Join-Path $SourceDirectory 'pyproject.toml'
$binaryMode = Test-Path -LiteralPath $binarySource -PathType Leaf
$sourceMode = Test-Path -LiteralPath $sourceProject -PathType Leaf
if (-not $binaryMode -and -not $sourceMode) {
    throw "源目录既不是 Platform 二进制发布包，也不是开发源码目录：$SourceDirectory"
}
if ($AllowUnsignedInternalRelease -and -not $binaryMode) {
    throw 'AllowUnsignedInternalRelease 只能授权安装标记为 unsigned-internal-release 的二进制发布包。'
}
if ((Test-PathEqualOrChild -Candidate $InstallRoot -Parent $SourceDirectory) -or
    (Test-PathEqualOrChild -Candidate $SourceDirectory -Parent $InstallRoot)) {
    throw '发布源目录与安装目录不得相同或互相嵌套。'
}

$launcherArguments = @()
$venvPython = $null
if ($binaryMode) {
    if (-not [string]::IsNullOrWhiteSpace($PythonExecutable) -or
        -not [string]::IsNullOrWhiteSpace($Wheelhouse)) {
        throw '二进制发布包不接受 PythonExecutable 或 Wheelhouse；客户机无需 Python。'
    }
    $hashFile = Join-Path $SourceDirectory 'SHA256SUMS.txt'
    $releaseManifest = Join-Path $SourceDirectory 'release-manifest.json'
    foreach ($releaseFile in @($hashFile, $releaseManifest)) {
        if (-not (Test-Path -LiteralPath $releaseFile -PathType Leaf)) {
            throw "二进制发布包缺少完整性文件：$releaseFile"
        }
    }
    $releaseRootPrefix = $SourceDirectory.TrimEnd('\') + '\'
    $expectedFiles = @{}
    foreach ($line in Get-Content -LiteralPath $hashFile -Encoding UTF8) {
        if ($line -notmatch '^(?<hash>[A-Fa-f0-9]{64})  (?<path>[^\r\n]+)$') {
            throw 'SHA256SUMS.txt 格式不合法。'
        }
        $relative = [string]$Matches['path']
        $segments = $relative.Replace('\', '/').Split('/')
        if ([System.IO.Path]::IsPathRooted($relative) -or
            $relative.Contains(':') -or $segments -contains '..' -or
            $segments -contains '.' -or $segments -contains '') {
            throw "SHA256SUMS.txt 包含不安全路径：$relative"
        }
        $candidate = [System.IO.Path]::GetFullPath(
            (Join-Path $SourceDirectory $relative.Replace('/', '\'))
        )
        if (-not $candidate.StartsWith(
            $releaseRootPrefix, [StringComparison]::OrdinalIgnoreCase
        ) -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "发布清单文件不存在或越界：$relative"
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "发布包不能包含 reparse point：$relative"
        }
        $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
        if ($actual -ne ([string]$Matches['hash']).ToUpperInvariant()) {
            throw "发布文件 SHA-256 不匹配：$relative"
        }
        if ($expectedFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "SHA256SUMS.txt 重复列出文件：$relative"
        }
        $expectedFiles[$candidate.ToLowerInvariant()] = $true
    }
    foreach ($item in Get-ChildItem -LiteralPath $SourceDirectory -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "发布包不能包含 reparse point：$($item.FullName)"
        }
        if (-not $item.PSIsContainer -and $item.FullName -ne $hashFile -and
            -not $expectedFiles.ContainsKey($item.FullName.ToLowerInvariant())) {
            throw "发布包包含未列入 SHA256SUMS.txt 的文件：$($item.FullName)"
        }
    }
    $normalizedExpectedManifestSha256 = (
        $ExpectedReleaseManifestSha256 -replace '\s', ''
    ).ToUpperInvariant()
    if ($AllowUnsignedInternalRelease) {
        if ($normalizedExpectedManifestSha256 -cnotmatch '^[A-F0-9]{64}$') {
            throw 'INTERNAL-UNSIGNED 产品安装要求由已核验 Setup 传入 64 位 ExpectedReleaseManifestSha256。'
        }
        $actualReleaseManifestSha256 = (Get-FileHash -LiteralPath `
            $releaseManifest -Algorithm SHA256).Hash
        if (-not $actualReleaseManifestSha256.Equals(
                $normalizedExpectedManifestSha256,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Platform 子发行清单与已核验 Setup 固化的 SHA-256 不一致；禁止执行候选程序。'
        }
    } elseif (-not [string]::IsNullOrWhiteSpace(
            $normalizedExpectedManifestSha256
        )) {
        throw 'ExpectedReleaseManifestSha256 只能与 -AllowUnsignedInternalRelease 同时使用。'
    }
    try {
        $manifest = Get-Content -LiteralPath $releaseManifest -Raw -Encoding UTF8 |
            ConvertFrom-Json
    } catch {
        throw "release-manifest.json 无效：$($_.Exception.Message)"
    }
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.product -ne 'MineGuard Platform' -or
        [string]$manifest.architecture -ne 'x64' -or
        [string]$manifest.runtime -ne 'nuitka-standalone' -or
        [string]$manifest.entryPoint -ne 'runtime/MineGuardPlatform.exe') {
        throw '二进制发布清单与 MineGuard Platform x64 standalone 契约不符。'
    }
    $candidateVersionText = (Get-Content -LiteralPath (
        Join-Path $SourceDirectory 'VERSION.txt'
    ) -Raw -Encoding UTF8).Trim()
    if ($candidateVersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        [string]$manifest.version -ne $candidateVersionText) {
        throw '二进制发布包的 VERSION.txt 与 release-manifest.json 版本不一致。'
    }
    if ($manifest.codeSigned -isnot [bool]) {
        throw 'release-manifest.json 的 codeSigned 必须是 JSON 布尔值。'
    }
    if ($manifest.authenticodeVerified -isnot [bool] -or
        [bool]$manifest.authenticodeVerified -ne [bool]$manifest.codeSigned) {
        throw 'release-manifest.json 的 Authenticode 验证状态无效。'
    }
    $declaredClassification = [string]$manifest.releaseClassification
    $expectedClassification = if ([bool]$manifest.codeSigned) {
        'signed-production-candidate'
    } elseif ($declaredClassification -eq 'unsigned-internal-release') {
        'unsigned-internal-release'
    } else {
        'unsigned-test-artifacts'
    }
    if ([string]$manifest.releaseClassification -ne $expectedClassification) {
        throw 'release-manifest.json 的发布分类与代码签名状态不一致。'
    }
    if ($expectedClassification -eq 'unsigned-internal-release' -and
        -not $AllowUnsignedInternalRelease) {
        throw (
            '检测到 INTERNAL-UNSIGNED 内网无签名正式发行介质；必须由 Setup 显式传入 ' +
            '-AllowUnsignedInternalRelease，并在执行 Setup 前根据介质外审批记录核对其 SHA-256。'
        )
    }
    if ($expectedClassification -ne 'unsigned-internal-release' -and
        $AllowUnsignedInternalRelease) {
        throw 'AllowUnsignedInternalRelease 与当前发布分类不匹配；拒绝扩大未签名授权范围。'
    }
    $manifestFiles = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        $segments = $relative.Replace('\', '/').Split('/')
        if ([System.IO.Path]::IsPathRooted($relative) -or
            $relative.Contains(':') -or $segments -contains '..' -or
            $segments -contains '.' -or $segments -contains '' -or
            $relative -in @('release-manifest.json', 'SHA256SUMS.txt')) {
            throw "release-manifest.json 包含不安全或自引用路径：$relative"
        }
        if ([string]$entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            [long]$entry.bytes -lt 0) {
            throw "release-manifest.json 文件元数据无效：$relative"
        }
        $candidate = [System.IO.Path]::GetFullPath(
            (Join-Path $SourceDirectory $relative.Replace('/', '\'))
        )
        if (-not $expectedFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "release-manifest.json 引用了未认证文件：$relative"
        }
        $candidateItem = Get-Item -LiteralPath $candidate -Force
        $candidateHash = (Get-FileHash -LiteralPath $candidate `
            -Algorithm SHA256).Hash
        if ([long]$candidateItem.Length -ne [long]$entry.bytes -or
            $candidateHash -ne ([string]$entry.sha256).ToUpperInvariant()) {
            throw "release-manifest.json 文件摘要不匹配：$relative"
        }
        if ($manifestFiles.ContainsKey($candidate.ToLowerInvariant())) {
            throw "release-manifest.json 重复列出文件：$relative"
        }
        $manifestFiles[$candidate.ToLowerInvariant()] = $true
    }
    foreach ($authenticatedPath in $expectedFiles.Keys) {
        if ($authenticatedPath -ne $releaseManifest.ToLowerInvariant() -and
            -not $manifestFiles.ContainsKey($authenticatedPath)) {
            throw "release-manifest.json 未覆盖发布文件：$authenticatedPath"
        }
    }
    $trustedLauncherRelative = `
        'deploy/windows/Open-MineGuardPlatformControlCenter.ps1'
    $trustedLauncherEntries = @($manifest.files | Where-Object {
        [string]$_.path -ceq $trustedLauncherRelative
    })
    if ($trustedLauncherEntries.Count -ne 1) {
        throw 'Platform 子发行清单必须唯一认证桌面 launcher 原字节。'
    }
    $trustedLauncherSource = Join-Path $SourceDirectory `
        $trustedLauncherRelative.Replace('/', '\')
    $trustedLauncherSha256 = `
        ([string]$trustedLauncherEntries[0].sha256).ToUpperInvariant()
    if (-not (Test-Path -LiteralPath $trustedLauncherSource -PathType Leaf) -or
        $trustedLauncherSha256 -cnotmatch '^[A-F0-9]{64}$' -or
        (Get-FileHash -LiteralPath $trustedLauncherSource -Algorithm SHA256).Hash `
            -cne $trustedLauncherSha256) {
        throw 'Platform 桌面 launcher 与子发行清单固定 SHA-256 不一致。'
    }
    $buildMetadataPath = Join-Path $SourceDirectory 'build-metadata.json'
    try {
        $buildMetadata = Get-Content -LiteralPath $buildMetadataPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "build-metadata.json 无效：$($_.Exception.Message)"
    }
    if ($buildMetadata.codeSigned -isnot [bool] -or
        [bool]$buildMetadata.codeSigned -ne [bool]$manifest.codeSigned) {
        throw '发布清单与构建元数据的代码签名状态不一致。'
    }
    if ([string]$buildMetadata.releaseClassification -ne $expectedClassification) {
        throw '构建元数据的发布分类与发布清单不一致。'
    }
    if ([string]$buildMetadata.version -ne $candidateVersionText) {
        throw '构建元数据与候选发布版本不一致。'
    }
    if ([bool]$manifest.codeSigned) {
        $signature = Get-AuthenticodeSignature -LiteralPath $binarySource
        if ($signature.Status -ne 'Valid' -or
            $null -eq $signature.SignerCertificate) {
            throw "Platform 主程序 Authenticode 签名无效：$($signature.Status)"
        }
        $expectedSigner = [string]$buildMetadata.signingCertificateThumbprint
        $actualSigner = ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
        if ($expectedSigner -notmatch '^[A-Fa-f0-9]{40}$' -or
            $actualSigner -ne $expectedSigner.ToUpperInvariant()) {
            throw 'Platform 主程序签名证书与构建元数据不一致。'
        }
        if ($null -eq $signature.TimeStamperCertificate) {
            throw 'Platform 主程序缺少可验证的 Authenticode 时间戳。'
        }
    } else {
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$buildMetadata.signingCertificateThumbprint
            )) {
            throw '未签名发布的构建元数据不得声明签名证书指纹。'
        }
        $unsignedSignature = Get-AuthenticodeSignature -LiteralPath $binarySource
        if ($unsignedSignature.Status -ne 'NotSigned') {
            throw '发布清单声明未签名，但 Platform 主程序实际带有签名或签名状态异常。'
        }
        if ($expectedClassification -eq 'unsigned-internal-release') {
            Write-Warning (
                '当前为 INTERNAL-UNSIGNED 内网无签名正式发行，没有 Windows 发布者身份。' +
                '只能在受控内网中使用，后续安装正式服务必须再输入介质外独立批准的子发行清单 SHA-256。'
            )
        } else {
            Write-Warning '当前为未签名内部测试版，不是生产可信发布。'
        }
    }
    Assert-MineGuardBinaryInstallPathBudget -Root $InstallRoot `
        -Manifest $manifest
    Invoke-CheckedNative -Command $binarySource -Arguments @('self-check') `
        -Label '校验发布包冻结运行时'

    $installedExecutablePath = Join-Path $InstallRoot 'runtime\MineGuardPlatform.exe'
    $installedMetadataRoot = Join-Path $InstallRoot 'release-metadata'
    $installedVersionPath = Join-Path $installedMetadataRoot 'VERSION.txt'
    if ((Test-Path -LiteralPath $installedExecutablePath -PathType Leaf) -and
        -not (Test-Path -LiteralPath $installedVersionPath -PathType Leaf)) {
        if ($env:MINEGUARD_RELEASE_AUDIT_MODE -eq 'installer-guard-test') {
            Write-Host 'MINEGUARD_RELEASE_AUDIT_MARKER=platform-missing-metadata'
        }
        throw '检测到已安装的编译运行时但缺少 VERSION.txt；拒绝覆盖，请先核查安装完整性。'
    }
    if (Test-Path -LiteralPath $installedVersionPath -PathType Leaf) {
        $installedVersionText = (Get-Content -LiteralPath $installedVersionPath `
            -Raw -Encoding UTF8).Trim()
        if ($installedVersionText -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
            throw '已安装 VERSION.txt 无法识别；拒绝覆盖，请先核查 release-metadata。'
        }
        if (Test-Path -LiteralPath $installedExecutablePath -PathType Leaf) {
            foreach ($requiredInstalledMetadata in @(
                'release-manifest.json', 'build-metadata.json', 'SHA256SUMS.txt'
            )) {
                if (-not (Test-Path -LiteralPath (
                        Join-Path $installedMetadataRoot $requiredInstalledMetadata
                    ) -PathType Leaf)) {
                    throw "已安装编译运行时缺少 $requiredInstalledMetadata；拒绝覆盖。"
                }
            }
            $installedVersionOutput = & $installedExecutablePath '--version'
            if ($LASTEXITCODE -ne 0 -or
                ([string]($installedVersionOutput | Out-String)) -notmatch (
                    '(?<![0-9.])' + [regex]::Escape($installedVersionText) + '(?![0-9.])'
                )) {
                throw '已安装运行时版本与 release-metadata 不一致；拒绝覆盖。'
            }
            try {
                $installedManifest = Get-Content -LiteralPath (
                    Join-Path $installedMetadataRoot 'release-manifest.json'
                ) -Raw -Encoding UTF8 | ConvertFrom-Json
                $installedBuildMetadata = Get-Content -LiteralPath (
                    Join-Path $installedMetadataRoot 'build-metadata.json'
                ) -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                throw "已安装发布元数据无法解析；拒绝覆盖：$($_.Exception.Message)"
            }
            if ([string]$installedManifest.version -ne $installedVersionText -or
                [string]$installedBuildMetadata.version -ne $installedVersionText) {
                throw '已安装 VERSION、发布清单与构建元数据不一致；拒绝覆盖。'
            }
        }
        if ([version]$candidateVersionText -lt [version]$installedVersionText) {
            if ($env:MINEGUARD_RELEASE_AUDIT_MODE -eq 'installer-guard-test') {
                Write-Host 'MINEGUARD_RELEASE_AUDIT_MARKER=platform-downgrade'
            }
            throw (
                '默认拒绝将 MineGuard Platform 从 {0} 降级到 {1}。' -f `
                    $installedVersionText, $candidateVersionText
            )
        }
    }
} else {
    if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
        $py = Get-Command 'py.exe' -ErrorAction SilentlyContinue
        if ($null -ne $py) {
            $PythonExecutable = $py.Source
            $launcherArguments = @('-3.12')
        } else {
            $pythonCommand = Get-Command 'python.exe' -ErrorAction SilentlyContinue
            if ($null -eq $pythonCommand) {
                throw '找不到 Python。请安装 CPython 3.12 x64，或用 -PythonExecutable 指定 python.exe。'
            }
            $PythonExecutable = $pythonCommand.Source
        }
    } else {
        $PythonExecutable = [System.IO.Path]::GetFullPath($PythonExecutable)
        if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
            throw "Python 可执行文件不存在：$PythonExecutable"
        }
    }

    $probeCode = @'
import json, platform, struct, sys
print(json.dumps({'version': list(sys.version_info[:3]), 'bits': struct.calcsize('P') * 8, 'implementation': platform.python_implementation()}))
'@
    $probeText = & $PythonExecutable @launcherArguments '-c' $probeCode
    if ($LASTEXITCODE -ne 0) { throw '无法执行指定的 Python。' }
    try { $probe = $probeText | ConvertFrom-Json } catch { throw '无法解析 Python 版本信息。' }
    if ([string]$probe.implementation -ne 'CPython' -or [int]$probe.bits -ne 64) {
        throw '需要 64 位 CPython。'
    }
    if ([int]$probe.version[0] -ne 3 -or [int]$probe.version[1] -ne 12) {
        throw '当前 Windows 发布约束只完成 CPython 3.12 x64 验证；请安装 Python 3.12。'
    }

    if (-not [string]::IsNullOrWhiteSpace($Wheelhouse)) {
        $Wheelhouse = Get-LocalAbsolutePath -Value $Wheelhouse -Label '离线 wheelhouse'
        if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
            throw "离线 wheelhouse 不存在：$Wheelhouse"
        }
    }
}

$directories = @(
    $InstallRoot,
    (Join-Path $InstallRoot 'runtime'),
    (Join-Path $InstallRoot 'config'),
    (Join-Path $InstallRoot 'state'),
    (Join-Path $InstallRoot 'backups'),
    (Join-Path $InstallRoot 'logs'),
    (Join-Path $InstallRoot 'service'),
    (Join-Path $InstallRoot 'launcher'),
    (Join-Path $InstallRoot 'release-metadata')
)
foreach ($directory in $directories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [void](Get-LocalAbsolutePath -Value $directory -Label '安装目录树' `
        -RequireFixedNtfs)
}

if ($binaryMode) {
    $runtimeTarget = Join-Path $InstallRoot 'runtime'
    $serviceTarget = Join-Path $InstallRoot 'service'
    $launcherTarget = Join-Path $InstallRoot 'launcher'
    $metadataTarget = Join-Path $InstallRoot 'release-metadata'
    $serviceSource = $PSScriptRoot
    $service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        Assert-InstalledServiceSecurityBoundary
    }
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        throw '切换 Platform 二进制运行时前必须停止 MineGuardPlatform 服务。'
    }
    if ((Test-Path -LiteralPath $runtimeTarget -PathType Container) -and
        (Test-MineGuardPlatformRuntimeProcess -RuntimeRoot $runtimeTarget)) {
        if ($env:MINEGUARD_RELEASE_AUDIT_MODE -eq 'installer-guard-test') {
            Write-Host 'MINEGUARD_RELEASE_AUDIT_MARKER=platform-runtime-process'
        }
        throw '切换 Platform 运行时前必须停止 runtime 目录中的全部前台进程（含旧 Python/venv）。'
    }
    if ($AuditFailAfterRuntimeSwitch -and
        $env:MINEGUARD_RELEASE_AUDIT_MODE -ne 'installer-rollback-test') {
        throw 'AuditFailAfterRuntimeSwitch 仅允许发布流水线回滚测试使用。'
    }
    # The trusted Setup bootstrap has already authenticated the staged source.
    # Protect the destination parent before creating any executable incoming
    # directory so an unprivileged local process cannot win a copy/use race.
    Set-MineGuardDirectoryAcl -Path $InstallRoot -ServicePermission 'RX'
    $runtimeIncoming = Join-Path $InstallRoot (
        '.runtime.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $runtimePrevious = Join-Path $InstallRoot (
        '.runtime.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $serviceIncoming = Join-Path $InstallRoot (
        '.service.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $servicePrevious = Join-Path $InstallRoot (
        '.service.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $launcherIncoming = Join-Path $InstallRoot (
        '.launcher.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $launcherPrevious = Join-Path $InstallRoot (
        '.launcher.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $metadataIncoming = Join-Path $InstallRoot (
        '.release-metadata.incoming.' + [Guid]::NewGuid().ToString('N')
    )
    $metadataPrevious = Join-Path $InstallRoot (
        '.release-metadata.previous.' + [Guid]::NewGuid().ToString('N')
    )
    $runtimePreviousMoved = $false
    $servicePreviousMoved = $false
    $launcherPreviousMoved = $false
    $metadataPreviousMoved = $false
    $runtimeActivated = $false
    $serviceActivated = $false
    $launcherActivated = $false
    $metadataActivated = $false
    $transactionComplete = $false
    $settingsCreated = $false
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    $incomingLeafPattern = `
        '^\.(?:runtime|service|launcher|release-metadata)\.incoming\.[a-f0-9]{32}$'
    $previousLeafPattern = `
        '^\.(?:runtime|service|launcher|release-metadata)\.previous\.[a-f0-9]{32}$'
    $transactionError = $null
    $rollbackErrors = New-Object System.Collections.Generic.List[string]
    $cleanupErrors = New-Object System.Collections.Generic.List[string]
    try {
        New-Item -ItemType Directory -Path $runtimeIncoming | Out-Null
        New-Item -ItemType Directory -Path $serviceIncoming | Out-Null
        New-Item -ItemType Directory -Path $launcherIncoming | Out-Null
        New-Item -ItemType Directory -Path $metadataIncoming | Out-Null
        foreach ($item in Get-ChildItem `
            -LiteralPath (Join-Path $SourceDirectory 'runtime') -Force) {
            Copy-Item -LiteralPath $item.FullName -Destination $runtimeIncoming `
                -Recurse -Force
        }
        $incomingExecutable = Join-Path $runtimeIncoming 'MineGuardPlatform.exe'
        Invoke-CheckedNative -Command $incomingExecutable -Arguments @('self-check') `
            -Label '验证待切换冻结运行时'
        foreach ($file in Get-ChildItem -LiteralPath $serviceSource -File) {
            if ($file.Extension -in @('.ps1', '.xml', '.example')) {
                Copy-Item -LiteralPath $file.FullName -Destination $serviceIncoming
            }
        }
        $incomingLauncher = Join-Path $launcherIncoming `
            'Open-MineGuardPlatformControlCenter.ps1'
        Copy-Item -LiteralPath $trustedLauncherSource `
            -Destination $incomingLauncher
        if ((Get-FileHash -LiteralPath $incomingLauncher -Algorithm SHA256).Hash `
                -cne $trustedLauncherSha256) {
            throw '候选 launcher 未保持子发行清单认证的原字节。'
        }
        $existingWrapper = Join-Path $serviceTarget 'MineGuard.Platform.exe'
        $existingWrapperConfig = $existingWrapper + '.config'
        $wrapperIntegrityPath = Join-Path $serviceTarget 'winsw-integrity.json'
        if (Test-Path -LiteralPath $existingWrapper -PathType Leaf) {
            if (-not (Test-Path -LiteralPath $wrapperIntegrityPath -PathType Leaf)) {
                throw '已有 WinSW 服务包装器但缺少受保护的 winsw-integrity.json；拒绝在升级中继承。'
            }
            try {
                $wrapperIntegrity = Get-Content -LiteralPath $wrapperIntegrityPath `
                    -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                throw "winsw-integrity.json 无法解析；拒绝继承服务包装器：$($_.Exception.Message)"
            }
            $expectedWrapperHash = [string]$wrapperIntegrity.wrapperSha256
            $actualWrapperHash = (Get-FileHash -LiteralPath $existingWrapper `
                -Algorithm SHA256).Hash
            if ([int]$wrapperIntegrity.schemaVersion -ne 1 -or
                [string]$wrapperIntegrity.serviceAccount -ne $ServiceAccount -or
                [string]$wrapperIntegrity.serviceSid -ne $ServiceSid -or
                [string]$wrapperIntegrity.serviceSidType -ne 'unrestricted' -or
                $expectedWrapperHash -notmatch '^[A-Fa-f0-9]{64}$' -or
                $actualWrapperHash -ne $expectedWrapperHash.ToUpperInvariant()) {
                throw '已有 WinSW 服务包装器与批准的 SHA-256 记录不一致；拒绝继承。'
            }
            $expectedConfigHash = [string]$wrapperIntegrity.wrapperConfigSha256
            if ([string]::IsNullOrWhiteSpace($expectedConfigHash)) {
                if (Test-Path -LiteralPath $existingWrapperConfig -PathType Leaf) {
                    throw '发现未登记的 WinSW .config 文件；拒绝在升级中继承。'
                }
            } else {
                if ($expectedConfigHash -notmatch '^[A-Fa-f0-9]{64}$' -or
                    -not (Test-Path -LiteralPath $existingWrapperConfig -PathType Leaf) -or
                    (Get-FileHash -LiteralPath $existingWrapperConfig `
                        -Algorithm SHA256).Hash -ne $expectedConfigHash.ToUpperInvariant()) {
                    throw 'WinSW .config 与批准的 SHA-256 记录不一致；拒绝继承。'
                }
                Copy-Item -LiteralPath $existingWrapperConfig `
                    -Destination $serviceIncoming
            }
            Copy-Item -LiteralPath $existingWrapper -Destination $serviceIncoming
            Copy-Item -LiteralPath $wrapperIntegrityPath -Destination $serviceIncoming
        } elseif ((Test-Path -LiteralPath $wrapperIntegrityPath) -or
            (Test-Path -LiteralPath $existingWrapperConfig)) {
            throw 'WinSW 完整性记录不完整；拒绝在升级中继承服务文件。'
        }
        foreach ($metadataName in @(
            'VERSION.txt', 'build-metadata.json', 'release-manifest.json',
            'SHA256SUMS.txt'
        )) {
            Copy-Item -LiteralPath (Join-Path $SourceDirectory $metadataName) `
                -Destination (Join-Path $metadataIncoming $metadataName)
        }
        if ($AllowUnsignedInternalRelease) {
            $releaseTrustAnchor = [ordered]@{
                schemaVersion = 1
                product = 'MineGuard Platform release trust anchor'
                releaseClassification = 'unsigned-internal-release'
                childReleaseManifestSha256 = `
                    $normalizedExpectedManifestSha256.ToLowerInvariant()
            }
            [IO.File]::WriteAllText(
                (Join-Path $metadataIncoming 'release-trust-anchor.json'),
                (($releaseTrustAnchor | ConvertTo-Json -Depth 3) +
                    [Environment]::NewLine),
                $utf8NoBom
            )
        }
        foreach ($requiredScript in @(
            'Start-MineGuardPlatform.ps1',
            'Start-MineGuardPlatformWizard.ps1',
            'Configure-MineGuardPlatformFormal.ps1',
            'Resolve-MineGuardPlatformExecutable.ps1',
            'Install-MineGuardPlatformService.ps1'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $serviceIncoming $requiredScript) `
                    -PathType Leaf)) {
                throw "待切换 service 目录缺少：$requiredScript"
            }
        }
        if ((Get-Item -LiteralPath $runtimeTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 runtime 不能是符号链接、junction 或其他 reparse point。'
        }
        if ((Get-Item -LiteralPath $serviceTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 service 不能是符号链接、junction 或其他 reparse point。'
        }
        if ((Get-Item -LiteralPath $launcherTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 launcher 不能是符号链接、junction 或其他 reparse point。'
        }
        if ((Get-Item -LiteralPath $metadataTarget -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw '目标 release-metadata 不能是 reparse point。'
        }
        if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            $settings = [ordered]@{
                schemaVersion = 1
                host = '127.0.0.1'
                port = $Port
                stateDirectory = (Join-Path $InstallRoot 'state')
                clientsFile = ''
                adminUsername = 'admin'
                secureCookie = $true
                allowDemoDefaultPassword = $false
                platformSystemId = 'mineguard-qinyuan'
                platformPartyId = 'regulator-qinyuan'
                platformKeyId = 'regulator-key-v2'
                managedProvisioningRequired = $false
                provisioningTrustedPublicKeyFile = ''
                provisioningExpectedPublicKeySha256 = ''
                provisioningExpectedIssuerKeyId = ''
            }
            [System.IO.File]::WriteAllText(
                $settingsPath,
                ($settings | ConvertTo-Json -Depth 5),
                $utf8NoBom
            )
            $settingsCreated = $true
        }
        # Canonicalize the entire Inno-created tree before the first directory
        # switch. This removes stale writable ACEs and makes any ACL failure a
        # pre-commit failure instead of leaving a committed runtime half-frozen.
        Assert-MineGuardNoReparseTree -Path $InstallRoot
        Set-MineGuardDirectoryAcl -Path $InstallRoot `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $runtimeIncoming `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $serviceIncoming `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $metadataIncoming `
            -ServicePermission 'RX' -Recurse
        Set-MineGuardDirectoryAcl -Path $launcherIncoming `
            -ServicePermission 'RX' -UsersReadExecute -Recurse
        Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'config') `
            -ServicePermission 'RX' -Recurse
        foreach ($writableDirectory in @(
            (Join-Path $InstallRoot 'state'),
            (Join-Path $InstallRoot 'backups'),
            (Join-Path $InstallRoot 'logs')
        )) {
            Set-MineGuardDirectoryAcl -Path $writableDirectory `
                -ServicePermission 'M' -Recurse
        }
        $docsDirectory = Join-Path $InstallRoot 'docs'
        if (Test-Path -LiteralPath $docsDirectory -PathType Container) {
            Set-MineGuardDirectoryAcl -Path $docsDirectory `
                -ServicePermission 'RX' -UsersReadExecute -Recurse
        }

        $service = Get-Service -Name 'MineGuardPlatform' -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            throw '运行时切换前复检发现 MineGuardPlatform 服务未停止。'
        }
        if (Test-MineGuardPlatformRuntimeProcess -RuntimeRoot $runtimeTarget) {
            throw '运行时切换前复检发现 runtime 目录中仍有前台进程。'
        }
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $runtimeTarget -SourceParent $InstallRoot `
            -SourceLeafPattern '^runtime$' `
            -DestinationPath $runtimePrevious -DestinationParent $InstallRoot `
            -DestinationLeafPattern $previousLeafPattern
        $runtimePreviousMoved = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $runtimeIncoming -SourceParent $InstallRoot `
            -SourceLeafPattern $incomingLeafPattern `
            -DestinationPath $runtimeTarget -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^runtime$'
        $runtimeActivated = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $serviceTarget -SourceParent $InstallRoot `
            -SourceLeafPattern '^service$' `
            -DestinationPath $servicePrevious -DestinationParent $InstallRoot `
            -DestinationLeafPattern $previousLeafPattern
        $servicePreviousMoved = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $serviceIncoming -SourceParent $InstallRoot `
            -SourceLeafPattern $incomingLeafPattern `
            -DestinationPath $serviceTarget -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^service$'
        $serviceActivated = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $metadataTarget -SourceParent $InstallRoot `
            -SourceLeafPattern '^release-metadata$' `
            -DestinationPath $metadataPrevious -DestinationParent $InstallRoot `
            -DestinationLeafPattern $previousLeafPattern
        $metadataPreviousMoved = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $metadataIncoming -SourceParent $InstallRoot `
            -SourceLeafPattern $incomingLeafPattern `
            -DestinationPath $metadataTarget -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^release-metadata$'
        $metadataActivated = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $launcherTarget -SourceParent $InstallRoot `
            -SourceLeafPattern '^launcher$' `
            -DestinationPath $launcherPrevious -DestinationParent $InstallRoot `
            -DestinationLeafPattern $previousLeafPattern
        $launcherPreviousMoved = $true
        Move-MineGuardOwnedPathWithRetry `
            -SourcePath $launcherIncoming -SourceParent $InstallRoot `
            -SourceLeafPattern $incomingLeafPattern `
            -DestinationPath $launcherTarget -DestinationParent $InstallRoot `
            -DestinationLeafPattern '^launcher$'
        $launcherActivated = $true

        $installedExecutable = Join-Path $runtimeTarget 'MineGuardPlatform.exe'
        Invoke-CheckedNative -Command $installedExecutable -Arguments @('self-check') `
            -Label '验证已安装冻结运行时'
        foreach ($requiredScript in @(
            'Start-MineGuardPlatform.ps1',
            'Start-MineGuardPlatformWizard.ps1',
            'Configure-MineGuardPlatformFormal.ps1',
            'Resolve-MineGuardPlatformExecutable.ps1',
            'Install-MineGuardPlatformService.ps1'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $serviceTarget $requiredScript) `
                    -PathType Leaf)) {
                throw "切换后的 service 目录缺少：$requiredScript"
            }
        }
        if (-not (Test-Path -LiteralPath (
                Join-Path $metadataTarget 'release-manifest.json'
            ) -PathType Leaf)) {
            throw '切换后的 release-metadata 缺少发布清单。'
        }
        $installedLauncherFiles = @(Get-ChildItem -LiteralPath $launcherTarget `
            -File -Force -Recurse)
        $installedLauncher = Join-Path $launcherTarget `
            'Open-MineGuardPlatformControlCenter.ps1'
        if ($installedLauncherFiles.Count -ne 1 -or
            -not (Test-Path -LiteralPath $installedLauncher -PathType Leaf) -or
            (Get-FileHash -LiteralPath $installedLauncher -Algorithm SHA256).Hash `
                -cne $trustedLauncherSha256) {
            throw '切换后的公开 launcher 不是子发行清单认证的唯一原字节文件。'
        }
        if ($AuditFailAfterRuntimeSwitch) {
            Write-Host 'MINEGUARD_RELEASE_AUDIT_MARKER=platform-post-switch'
            throw '发布审计故障注入：验证二进制切换后的完整回滚。'
        }
        $transactionComplete = $true
    } catch {
        $transactionError = $_
        if ($settingsCreated) {
            try {
                Remove-MineGuardOwnedPathWithRetry -Path $settingsPath `
                    -ExpectedParent (Join-Path $InstallRoot 'config') `
                    -AllowedLeafPattern '^settings\.json$'
                $settingsCreated = $false
            } catch {
                $rollbackErrors.Add(
                    "清理本次新建 settings.json 失败：$($_.Exception.Message)"
                )
            }
        }

        if ($launcherActivated) {
            try {
                Move-MineGuardOwnedPathWithRetry `
                    -SourcePath $launcherTarget -SourceParent $InstallRoot `
                    -SourceLeafPattern '^launcher$' `
                    -DestinationPath $launcherIncoming `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $incomingLeafPattern
                $launcherActivated = $false
            } catch {
                $rollbackErrors.Add(
                    "隔离候选 launcher 失败：$($_.Exception.Message)"
                )
            }
        }
        if ($launcherPreviousMoved) {
            if ($launcherActivated) {
                $rollbackErrors.Add('候选 launcher 未能隔离，无法恢复原目录。')
            } else {
                try {
                    Move-MineGuardOwnedPathWithRetry `
                        -SourcePath $launcherPrevious `
                        -SourceParent $InstallRoot `
                        -SourceLeafPattern $previousLeafPattern `
                        -DestinationPath $launcherTarget `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^launcher$'
                    $launcherPreviousMoved = $false
                } catch {
                    $rollbackErrors.Add(
                        "恢复原 launcher 失败：$($_.Exception.Message)"
                    )
                }
            }
        }

        if ($metadataActivated) {
            try {
                Move-MineGuardOwnedPathWithRetry `
                    -SourcePath $metadataTarget -SourceParent $InstallRoot `
                    -SourceLeafPattern '^release-metadata$' `
                    -DestinationPath $metadataIncoming `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $incomingLeafPattern
                $metadataActivated = $false
            } catch {
                $rollbackErrors.Add(
                    "隔离候选 release-metadata 失败：$($_.Exception.Message)"
                )
            }
        }
        if ($metadataPreviousMoved) {
            if ($metadataActivated) {
                $rollbackErrors.Add(
                    '候选 release-metadata 未能隔离，无法恢复原目录。'
                )
            } else {
                try {
                    Move-MineGuardOwnedPathWithRetry `
                        -SourcePath $metadataPrevious `
                        -SourceParent $InstallRoot `
                        -SourceLeafPattern $previousLeafPattern `
                        -DestinationPath $metadataTarget `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^release-metadata$'
                    $metadataPreviousMoved = $false
                } catch {
                    $rollbackErrors.Add(
                        "恢复原 release-metadata 失败：$($_.Exception.Message)"
                    )
                }
            }
        }

        if ($serviceActivated) {
            try {
                Move-MineGuardOwnedPathWithRetry `
                    -SourcePath $serviceTarget -SourceParent $InstallRoot `
                    -SourceLeafPattern '^service$' `
                    -DestinationPath $serviceIncoming `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $incomingLeafPattern
                $serviceActivated = $false
            } catch {
                $rollbackErrors.Add(
                    "隔离候选 service 失败：$($_.Exception.Message)"
                )
            }
        }
        if ($servicePreviousMoved) {
            if ($serviceActivated) {
                $rollbackErrors.Add('候选 service 未能隔离，无法恢复原目录。')
            } else {
                try {
                    Move-MineGuardOwnedPathWithRetry `
                        -SourcePath $servicePrevious -SourceParent $InstallRoot `
                        -SourceLeafPattern $previousLeafPattern `
                        -DestinationPath $serviceTarget `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^service$'
                    $servicePreviousMoved = $false
                } catch {
                    $rollbackErrors.Add(
                        "恢复原 service 失败：$($_.Exception.Message)"
                    )
                }
            }
        }

        if ($runtimeActivated) {
            try {
                Move-MineGuardOwnedPathWithRetry `
                    -SourcePath $runtimeTarget -SourceParent $InstallRoot `
                    -SourceLeafPattern '^runtime$' `
                    -DestinationPath $runtimeIncoming `
                    -DestinationParent $InstallRoot `
                    -DestinationLeafPattern $incomingLeafPattern
                $runtimeActivated = $false
            } catch {
                $rollbackErrors.Add(
                    "隔离候选 runtime 失败：$($_.Exception.Message)"
                )
            }
        }
        if ($runtimePreviousMoved) {
            if ($runtimeActivated) {
                $rollbackErrors.Add('候选 runtime 未能隔离，无法恢复原目录。')
            } else {
                try {
                    Move-MineGuardOwnedPathWithRetry `
                        -SourcePath $runtimePrevious -SourceParent $InstallRoot `
                        -SourceLeafPattern $previousLeafPattern `
                        -DestinationPath $runtimeTarget `
                        -DestinationParent $InstallRoot `
                        -DestinationLeafPattern '^runtime$'
                    $runtimePreviousMoved = $false
                } catch {
                    $rollbackErrors.Add(
                        "恢复原 runtime 失败：$($_.Exception.Message)"
                    )
                }
            }
        }
    } finally {
        foreach ($incomingPath in @(
            $runtimeIncoming, $serviceIncoming, $launcherIncoming,
            $metadataIncoming
        )) {
            try {
                Remove-MineGuardOwnedPathWithRetry -Path $incomingPath `
                    -ExpectedParent $InstallRoot `
                    -AllowedLeafPattern $incomingLeafPattern
            } catch {
                $cleanupErrors.Add(
                    "清理候选事务目录 $incomingPath 失败：$($_.Exception.Message)"
                )
            }
        }
    }
    if ($null -ne $transactionError) {
        $allRecoveryErrors = @($rollbackErrors) + @($cleanupErrors)
        if ($allRecoveryErrors.Count -gt 0) {
            $message = (
                'Platform 安装失败且回滚不完整。原始错误：{0}；回滚错误：{1}' -f `
                    $transactionError.Exception.Message,
                    ($allRecoveryErrors -join ' | ')
            )
            throw [System.Exception]::new(
                $message, $transactionError.Exception
            )
        }
        $PSCmdlet.ThrowTerminatingError($transactionError)
    }
    if ($cleanupErrors.Count -gt 0) {
        throw ('Platform 事务清理未完成：' + ($cleanupErrors -join ' | '))
    }
    if (-not $transactionComplete) {
        throw 'Platform 二进制切换未完成。'
    }
    foreach ($oldPath in @(
        $runtimePrevious, $servicePrevious, $launcherPrevious,
        $metadataPrevious
    )) {
        try {
            Remove-MineGuardOwnedPathWithRetry -Path $oldPath `
                -ExpectedParent $InstallRoot `
                -AllowedLeafPattern $previousLeafPattern
        } catch {
            Write-Warning "新版本已完整生效，但旧目录待人工清理：$oldPath"
        }
    }
} else {
    $venvPython = Join-Path (Join-Path $InstallRoot 'runtime') 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        Invoke-CheckedNative -Command $PythonExecutable `
            -Arguments ($launcherArguments + @('-m', 'venv', (Join-Path $InstallRoot 'runtime'))) `
            -Label '创建隔离 Python 运行时'
    }
    $constraints = Join-Path $SourceDirectory 'constraints.txt'
    if ([string]::IsNullOrWhiteSpace($Wheelhouse)) {
        Invoke-CheckedNative -Command $venvPython `
            -Arguments @('-m', 'pip', 'install', 'setuptools>=68') `
            -Label '安装构建工具'
        Invoke-CheckedNative -Command $venvPython `
            -Arguments @('-m', 'pip', 'install', '-c', $constraints, $SourceDirectory) `
            -Label '安装 MineGuard Platform'
    } else {
        $offline = @('--no-index', '--find-links', $Wheelhouse)
        Invoke-CheckedNative -Command $venvPython `
            -Arguments (@('-m', 'pip', 'install') + $offline + @('setuptools>=68')) `
            -Label '从 wheelhouse 安装构建工具'
        Invoke-CheckedNative -Command $venvPython `
            -Arguments (@('-m', 'pip', 'install') + $offline + @(
                '--no-build-isolation', '-c', $constraints, $SourceDirectory
            )) `
            -Label '从 wheelhouse 安装 MineGuard Platform'
    }
    $verifyCode = @'
from importlib.metadata import version
from zoneinfo import ZoneInfo
import mineguard, numpy, scipy
assert ZoneInfo("Asia/Shanghai").key == "Asia/Shanghai"
print("MineGuard", mineguard.__version__, "numpy", numpy.__version__, "scipy", scipy.__version__, "tzdata", version("tzdata"))
'@
    Invoke-CheckedNative -Command $venvPython -Arguments @('-c', $verifyCode) `
        -Label '验证算法和 Windows 时区运行时'
}

$serviceTarget = Join-Path $InstallRoot 'service'
if (-not $binaryMode) {
    $serviceSource = $PSScriptRoot
    foreach ($file in Get-ChildItem -LiteralPath $serviceSource -File) {
        if ($file.Extension -in @('.ps1', '.xml', '.example')) {
            Copy-Item -LiteralPath $file.FullName -Destination $serviceTarget -Force
        }
    }
    $settingsPath = Join-Path (Join-Path $InstallRoot 'config') 'settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        $settings = [ordered]@{
            schemaVersion = 1
            host = '127.0.0.1'
            port = $Port
            stateDirectory = (Join-Path $InstallRoot 'state')
            clientsFile = ''
            adminUsername = 'admin'
            secureCookie = $true
            allowDemoDefaultPassword = $false
            platformSystemId = 'mineguard-qinyuan'
            platformPartyId = 'regulator-qinyuan'
            platformKeyId = 'regulator-key-v2'
            managedProvisioningRequired = $false
            provisioningTrustedPublicKeyFile = ''
            provisioningExpectedPublicKeySha256 = ''
            provisioningExpectedIssuerKeyId = ''
        }
        [System.IO.File]::WriteAllText(
            $settingsPath,
            ($settings | ConvertTo-Json -Depth 5),
            $utf8NoBom
        )
    }

    Set-MineGuardDirectoryAcl -Path $InstallRoot `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'runtime') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'config') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'service') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'release-metadata') `
        -ServicePermission 'RX' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'state') `
        -ServicePermission 'M' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'backups') `
        -ServicePermission 'M' -Recurse
    Set-MineGuardDirectoryAcl -Path (Join-Path $InstallRoot 'logs') `
        -ServicePermission 'M' -Recurse
}

Write-Host ''
Write-Host 'MineGuard Platform Windows 运行时安装完成。'
Write-Host "安装目录：$InstallRoot"
Write-Host '下一步（不会在命令行记录秘密）：'
Write-Host ("  & '{0}' -InstallRoot '{1}' -ClientsFile 'C:\安全交付\clients.json'" -f `
    (Join-Path $serviceTarget 'Set-MineGuardPlatformConfiguration.ps1'), $InstallRoot)
