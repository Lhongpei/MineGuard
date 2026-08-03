[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Wheelhouse = "",
    [string]$WheelhouseManifest = "",
    [string]$ExpectedWheelhouseManifestSha256 = "",
    [string]$PythonExecutable = "",
    [string]$ExpectedPythonPatchVersion = "",
    [string]$ExpectedPythonExecutableSha256 = "",
    [string]$InnoCompiler = "",
    [string]$ExpectedInnoCompilerSha256 = "",
    [switch]$AllowNuitkaToolDownloads,
    [string]$UnsignedCompilerCacheReadyMarker = "",
    [switch]$AllowDirtySource,
    [string]$SignToolPath = "",
    [string]$ExpectedSignToolSha256 = "",
    [string]$SigningCertificateThumbprint = "",
    [uri]$TimestampUrl,
    [switch]$RequireSigned,
    [switch]$TestInstallerFailurePropagation,
    [switch]$TestInstallerLifecycle
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}

if ($env:OS -ne "Windows_NT") {
    throw "The root Windows binary release must be built on native Windows x64."
}
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and
        $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw "Windows PowerShell 5.1 or later is required."
}

function Invoke-NativeChecked {
    param([string]$FilePath, [object[]]$ArgumentList, [string]$Label)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Assert-CleanGitSnapshot {
    param([string]$GitPath, [string]$Root, [string]$ExpectedRevision)
    $ActualRevision = (& $GitPath -C $Root rev-parse HEAD |
        Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $ActualRevision -ne $ExpectedRevision) {
        throw "The source revision changed during the signed release build."
    }
    & $GitPath -C $Root diff --quiet
    $WorkingTreeDirty = $LASTEXITCODE -ne 0
    & $GitPath -C $Root diff --cached --quiet
    $IndexDirty = $LASTEXITCODE -ne 0
    $Untracked = @(& $GitPath -C $Root ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0 -or $WorkingTreeDirty -or $IndexDirty -or
        $Untracked.Count -ne 0) {
        throw "The source tree changed during the signed release build."
    }
}

function Get-SafeLocalNtfsPath {
    param([string]$Name, [string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue -ne $PathValue.Trim() -or
        $PathValue -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Name must be supplied as an X:\\ absolute local path: $PathValue"
    }
    foreach ($Part in $PathValue.Substring(3) -split '[\\/]') {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @('.', '..') -or
            $Part.Contains(':') -or $Part.EndsWith(' ') -or $Part.EndsWith('.')) {
            throw "$Name contains an empty, dot, alternate-stream or ambiguous path component: $PathValue"
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrWhiteSpace($Root) -or
        $FullPath.Equals($Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must not be a filesystem root: $PathValue"
    }
    $DeviceId = $Root.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3 -or
        -not ([string]$Disk.FileSystem).Equals('NTFS', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name must use a local fixed NTFS disk: $FullPath"
    }
    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a symlink, junction or reparse-point component: $Current"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $Root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $Parent = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($Parent)) {
            throw "$Name path ancestry cannot be resolved safely: $FullPath"
        }
        $Current = $Parent
    }
    return $FullPath
}

function Get-NewOutputDirectoryPath {
    param([string]$PathValue)
    $FullPath = Get-SafeLocalNtfsPath -Name 'OutputDirectory' -PathValue $PathValue
    if (Test-Path -LiteralPath $FullPath) {
        throw "OutputDirectory must not exist before atomic publication: $FullPath"
    }
    return $FullPath.TrimEnd('\')
}

function Test-PathAtOrBelow {
    param([string]$Candidate, [string]$Root)
    $CandidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $RootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $CandidatePath.Equals($RootPath, [StringComparison]::OrdinalIgnoreCase) -or
        $CandidatePath.StartsWith($RootPath + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-PathsDoNotOverlap {
    param(
        [string]$FirstName,
        [string]$FirstPath,
        [string]$SecondName,
        [string]$SecondPath
    )
    if ((Test-PathAtOrBelow -Candidate $FirstPath -Root $SecondPath) -or
        (Test-PathAtOrBelow -Candidate $SecondPath -Root $FirstPath)) {
        throw "$FirstName and $SecondName must not equal, contain, or be contained by one another."
    }
}

function Assert-Sha256Text {
    param([string]$Name, [string]$Value)
    if ($Value -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "$Name must be exactly 64 hexadecimal digits."
    }
}

function Assert-ApprovedFileSha256 {
    param([string]$Name, [string]$PathValue, [string]$ExpectedSha256)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
        throw "$Name does not exist as a file: $PathValue"
    }
    $Item = Get-Item -LiteralPath $PathValue -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Name cannot be a symlink or reparse point: $PathValue"
    }
    $ActualSha256 = (Get-FileHash -LiteralPath $PathValue -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and
        $ActualSha256 -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "$Name does not match its protected expected SHA-256."
    }
    return $ActualSha256
}

function Find-PythonExecutable {
    param([string]$RequestedPath)
    if ($RequestedPath) {
        $Candidate = Get-SafeLocalNtfsPath -Name 'PythonExecutable' -PathValue $RequestedPath
        if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            throw "The explicitly configured python.exe does not exist: $Candidate"
        }
        return $Candidate
    }
    $PythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($null -ne $PythonCommand) {
        return Get-SafeLocalNtfsPath -Name 'PythonExecutable' -PathValue $PythonCommand.Source
    }
    $PythonLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($null -ne $PythonLauncher) {
        $Candidate = (& $PythonLauncher.Source -3.12 -c "import sys; print(sys.executable)" |
            Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($Candidate)) {
            return Get-SafeLocalNtfsPath -Name 'PythonExecutable' -PathValue $Candidate
        }
    }
    throw "A native x64 CPython 3.12 python.exe could not be resolved."
}

function Get-PythonIdentity {
    param([string]$PathValue)
    $ProbeCode = @'
import json, platform, struct, sys
print(json.dumps({'implementation': platform.python_implementation(), 'version': platform.python_version(), 'bits': struct.calcsize('P') * 8, 'executable': sys.executable}))
'@
    $ProbeText = (& $PathValue -c $ProbeCode | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ProbeText)) {
        throw "Unable to execute the resolved Python interpreter."
    }
    try { $Probe = $ProbeText | ConvertFrom-Json } catch {
        throw "Unable to parse the resolved Python interpreter identity."
    }
    if ([string]$Probe.implementation -ne "CPython" -or
        [int]$Probe.bits -ne 64 -or
        [string]$Probe.version -notmatch '^3\.12\.\d+$') {
        throw "The Windows release requires native x64 CPython 3.12."
    }
    $ReportedExecutable = Get-SafeLocalNtfsPath -Name 'Python sys.executable' `
        -PathValue ([string]$Probe.executable)
    if (-not $ReportedExecutable.Equals($PathValue, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The resolved python.exe does not match its own sys.executable identity."
    }
    return [pscustomobject]@{
        version = [string]$Probe.version
        executable = $ReportedExecutable
    }
}

function Find-InnoCompiler {
    param([string]$RequestedPath)
    if ($RequestedPath) {
        $Candidate = Get-SafeLocalNtfsPath -Name 'InnoCompiler' -PathValue $RequestedPath
        if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            throw "The explicitly configured ISCC.exe does not exist: $Candidate"
        }
        return $Candidate
    }
    $Candidates = @()
    $Command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($null -ne $Command) { $Candidates += $Command.Source }
    $Candidates += @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    )
    foreach ($Candidate in $Candidates) {
        if ($Candidate -and (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            return Get-SafeLocalNtfsPath -Name 'InnoCompiler' -PathValue $Candidate
        }
    }
    throw "ISCC.exe was not found. Install an organization-approved Inno Setup 6.7.1 build before running this script; the release build never downloads it ad hoc."
}

function Get-InnoCompilerVersion {
    param([string]$PathValue)
    $VersionProbeSource = @'
[Setup]
AppName=MineGuard Inno Version Probe
AppVersion=0.0.0
DefaultDirName={tmp}\MineGuardInnoVersionProbe
PrivilegesRequired=lowest
Uninstallable=no
'@
    $VersionProbeOutput = @(
        $VersionProbeSource | & $PathValue "/O-" "-" 2>&1
    )
    $VersionProbeExitCode = $LASTEXITCODE
    $VersionProbeText = @(
        $VersionProbeOutput | ForEach-Object { [string]$_ }
    ) -join [Environment]::NewLine
    if ($VersionProbeExitCode -ne 0) {
        throw "Unable to execute the Inno Setup compiler version probe."
    }
    $VersionMatch = [regex]::Match(
        $VersionProbeText,
        'Compiler engine version:\s+Inno Setup\s+(\d+\.\d+\.\d+(?:\.\d+)?)',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $VersionMatch.Success) {
        throw "Unable to identify the Inno Setup compiler engine version from ISCC output."
    }
    return [version]$VersionMatch.Groups[1].Value
}

function Get-SemanticVersionFromStage {
    param([string]$StageRoot)
    $Version = (Get-Content -LiteralPath (Join-Path $StageRoot "VERSION.txt") -Raw -Encoding UTF8).Trim()
    if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "Invalid stage version: $Version"
    }
    return $Version
}

function Test-WheelhouseSupplyChainManifest {
    param(
        [string]$WheelhouseRoot,
        [string]$ManifestPath,
        [string]$ExpectedManifestSha256 = ""
    )
    $WheelhouseRoot = Get-SafeLocalNtfsPath -Name 'Wheelhouse' -PathValue $WheelhouseRoot
    $ManifestPath = Get-SafeLocalNtfsPath -Name 'WheelhouseManifest' -PathValue $ManifestPath
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "WheelhouseManifest does not exist: $ManifestPath"
    }
    $WheelhousePrefix = $WheelhouseRoot + '\'
    if ($ManifestPath.StartsWith($WheelhousePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "WheelhouseManifest must be stored outside the wheelhouse to avoid a circular file-set hash."
    }
    foreach ($Item in @((Get-Item -LiteralPath $WheelhouseRoot -Force)) + @(
        Get-ChildItem -LiteralPath $WheelhouseRoot -Force -Recurse
    )) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Wheelhouse contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
    $ManifestItem = Get-Item -LiteralPath $ManifestPath -Force
    if (($ManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "WheelhouseManifest cannot be a symlink or reparse point."
    }
    $ActualManifestSha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedManifestSha256 -and
        $ActualManifestSha256 -ne $ExpectedManifestSha256.ToLowerInvariant()) {
        throw "WheelhouseManifest does not match ExpectedWheelhouseManifestSha256."
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$Manifest.format -ne "mineguard-wheelhouse-manifest-v1" -or
        [string]$Manifest.python -notmatch '^3\.12(?:\.|$)' -or
        [string]$Manifest.architecture -ne "x64") {
        throw "WheelhouseManifest has an unsupported format, Python version or architecture."
    }
    $Expected = @{}
    foreach ($Entry in @($Manifest.files)) {
        $Relative = [string]$Entry.path
        $Parts = $Relative -split '/'
        if ([string]::IsNullOrWhiteSpace($Relative) -or
            [IO.Path]::IsPathRooted($Relative) -or
            $Relative.Contains("\") -or $Relative.Contains(":") -or
            $Parts -contains "." -or $Parts -contains ".." -or
            [IO.Path]::GetExtension($Relative).ToLowerInvariant() -ne ".whl") {
            throw "WheelhouseManifest contains an unsafe or non-wheel path: $Relative"
        }
        if ($Expected.ContainsKey($Relative) -or [string]$Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "WheelhouseManifest contains a duplicate path or invalid hash: $Relative"
        }
        $Expected[$Relative] = $Entry
    }
    $Actual = @{}
    foreach ($File in Get-ChildItem -LiteralPath $WheelhouseRoot -File -Force -Recurse) {
        $Relative = $File.FullName.Substring($WheelhouseRoot.Length + 1).Replace('\', '/')
        if ($File.Extension.ToLowerInvariant() -ne ".whl") {
            throw "Wheelhouse contains a non-wheel file: $Relative"
        }
        $Actual[$Relative] = $File
    }
    if ($Expected.Count -eq 0 -or $Expected.Count -ne $Actual.Count) {
        throw "Wheelhouse file set does not exactly match WheelhouseManifest."
    }
    foreach ($Relative in $Expected.Keys) {
        if (-not $Actual.ContainsKey($Relative)) {
            throw "Wheelhouse is missing a declared file: $Relative"
        }
        $File = $Actual[$Relative]
        $Entry = $Expected[$Relative]
        if ([long]$File.Length -ne [long]$Entry.bytes) {
            throw "Wheelhouse file size mismatch: $Relative"
        }
        $Hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
        if (-not $Hash.Equals([string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Wheelhouse SHA-256 mismatch: $Relative"
        }
    }
    return [pscustomobject]@{
        format = [string]$Manifest.format
        python = [string]$Manifest.python
        architecture = [string]$Manifest.architecture
        file_count = $Actual.Count
        manifest_sha256 = $ActualManifestSha256
        expected_manifest_sha256 = if ($ExpectedManifestSha256) {
            $ExpectedManifestSha256.ToLowerInvariant()
        } else { $null }
        external_trust_anchor_verified = [bool]$ExpectedManifestSha256
    }
}

function Invoke-InnoCompile {
    param(
        [string]$ScriptPath,
        [string]$StageRoot,
        [string]$AssetsRoot,
        [string]$ArtifactsRoot,
        [string]$Version,
        [string]$ArtifactBaseName,
        [bool]$SigningEnabled,
        [string]$SigningCommand
    )
    $Arguments = @(
        "/Qp",
        "/DStageRoot=$StageRoot",
        "/DAssetsRoot=$AssetsRoot",
        "/DOutputDir=$ArtifactsRoot",
        "/DAppVersion=$Version",
        "/DNumericVersion=$Version.0",
        "/DArtifactFileName=$ArtifactBaseName"
    )
    if ($SigningEnabled) {
        if ($script:ExpectedSignToolSha256) {
            [void](Assert-ApprovedFileSha256 -Name 'SignToolPath' `
                -PathValue $script:ResolvedSignToolPath `
                -ExpectedSha256 $script:ExpectedSignToolSha256)
        }
        $Arguments += @("/DEnableSigning=1", "/Srelease_signer=$SigningCommand")
    }
    $Arguments += $ScriptPath
    if ($script:ExpectedInnoCompilerSha256) {
        [void](Assert-ApprovedFileSha256 -Name 'InnoCompiler' `
            -PathValue $script:ResolvedInnoCompiler `
            -ExpectedSha256 $script:ExpectedInnoCompilerSha256)
    }
    Invoke-NativeChecked -FilePath $script:ResolvedInnoCompiler -ArgumentList $Arguments -Label "Inno Setup compilation"
    $InstallerPath = Join-Path $ArtifactsRoot ($ArtifactBaseName + ".exe")
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw "Inno Setup did not create the expected installer: $InstallerPath"
    }
    return $InstallerPath
}

$RepositoryRoot = Get-SafeLocalNtfsPath -Name 'RepositoryRoot' -PathValue $RepositoryRoot
$OutputDirectory = Get-NewOutputDirectoryPath -PathValue $OutputDirectory
foreach ($Required in @(
    (Join-Path $RepositoryRoot "platform\packaging\windows\Build-MineGuardPlatform.ps1"),
    (Join-Path $RepositoryRoot "agent\packaging\windows\Build-EnterpriseAgentBinary.ps1"),
    (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardPlatform.iss"),
    (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardEnterpriseAgent.iss"),
    (Join-Path $RepositoryRoot "packaging\windows\inno\languages\ChineseSimplified.isl"),
    (Join-Path $RepositoryRoot "scripts\Test-WindowsBinaryRelease.ps1")
)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Release build input is missing: $Required"
    }
}
$InnoChineseLanguagePath = Join-Path $RepositoryRoot `
    "packaging\windows\inno\languages\ChineseSimplified.isl"
$ExpectedInnoChineseLanguageSha256 = `
    "7d544b9bb1d142cfa11f2e5d3cc8abe2e55f8e066c5124e3772675aa236e1278"
$ActualInnoChineseLanguageSha256 = Assert-ApprovedFileSha256 `
    -Name 'Inno Simplified Chinese language input' `
    -PathValue $InnoChineseLanguagePath `
    -ExpectedSha256 $ExpectedInnoChineseLanguageSha256

$Git = Get-Command "git.exe" -ErrorAction SilentlyContinue
$SourceRevision = $null
$SourceDirty = $null
if ($null -ne $Git -and (Test-Path -LiteralPath (Join-Path $RepositoryRoot ".git"))) {
    $SourceRevision = (& $Git.Source -C $RepositoryRoot rev-parse HEAD | Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Unable to determine the Git source revision." }
    & $Git.Source -C $RepositoryRoot diff --quiet
    $WorkingTreeDirty = $LASTEXITCODE -ne 0
    & $Git.Source -C $RepositoryRoot diff --cached --quiet
    $IndexDirty = $LASTEXITCODE -ne 0
    $Untracked = @(& $Git.Source -C $RepositoryRoot ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect untracked files." }
    $SourceDirty = $WorkingTreeDirty -or $IndexDirty -or $Untracked.Count -gt 0
    if ($SourceDirty -and -not $AllowDirtySource) {
        throw "The source tree is dirty. Commit/review the exact release source or pass -AllowDirtySource for a clearly marked internal build."
    }
}

$SigningValues = @(@(
    $SignToolPath,
    $SigningCertificateThumbprint,
    [string]$TimestampUrl
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$SigningEnabled = $SigningValues.Count -ne 0
$SigningCertificateStore = $null
$ActualSignToolSha256 = $null
if ($SigningEnabled -and $SigningValues.Count -ne 3) {
    throw "SignToolPath, SigningCertificateThumbprint and TimestampUrl must be provided together."
}
if ($SigningEnabled -and -not $RequireSigned) {
    throw "Authenticode parameters are accepted only with -RequireSigned so signed media cannot bypass production-candidate release gates."
}
if ($RequireSigned -and -not $SigningEnabled) {
    throw "RequireSigned requires the complete Authenticode signing configuration."
}
if ($RequireSigned) {
    if ($AllowDirtySource -or $SourceDirty -ne $false -or [string]::IsNullOrWhiteSpace($SourceRevision)) {
        throw "A signed production candidate requires a clean, revision-controlled source tree."
    }
    if ($AllowNuitkaToolDownloads) {
        throw "A signed production candidate cannot allow Nuitka tool downloads; pre-stage the approved cache."
    }
    if (-not $Wheelhouse -or -not $WheelhouseManifest -or
        -not $ExpectedWheelhouseManifestSha256) {
        throw "A signed production candidate requires an approved offline Wheelhouse, WheelhouseManifest and its external expected SHA-256."
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedPythonPatchVersion) -or
        [string]::IsNullOrWhiteSpace($ExpectedPythonExecutableSha256) -or
        [string]::IsNullOrWhiteSpace($ExpectedInnoCompilerSha256) -or
        [string]::IsNullOrWhiteSpace($ExpectedSignToolSha256)) {
        throw "A signed production candidate requires protected expected Python patch, Python executable SHA-256, Inno SHA-256 and SignTool SHA-256 values."
    }
    $TestInstallerFailurePropagation = $true
    $TestInstallerLifecycle = $true
}
$ExpectedPythonPatchVersion = $ExpectedPythonPatchVersion.Trim()
if ($ExpectedPythonPatchVersion -and
    $ExpectedPythonPatchVersion -notmatch '^3\.12\.\d+$') {
    throw "ExpectedPythonPatchVersion must be an exact CPython 3.12 patch version."
}
foreach ($ExpectedHashDefinition in @(
    [pscustomobject]@{ name = "ExpectedPythonExecutableSha256"; value = $ExpectedPythonExecutableSha256 },
    [pscustomobject]@{ name = "ExpectedInnoCompilerSha256"; value = $ExpectedInnoCompilerSha256 },
    [pscustomobject]@{ name = "ExpectedSignToolSha256"; value = $ExpectedSignToolSha256 }
)) {
    if (-not [string]::IsNullOrWhiteSpace($ExpectedHashDefinition.value)) {
        $ExpectedHashDefinition.value = ([string]$ExpectedHashDefinition.value).Trim()
        Assert-Sha256Text -Name $ExpectedHashDefinition.name -Value $ExpectedHashDefinition.value
    }
}
$ExpectedPythonExecutableSha256 = $ExpectedPythonExecutableSha256.Trim()
$ExpectedInnoCompilerSha256 = $ExpectedInnoCompilerSha256.Trim()
$ExpectedSignToolSha256 = $ExpectedSignToolSha256.Trim()
if ($ExpectedWheelhouseManifestSha256) {
    $ExpectedWheelhouseManifestSha256 = $ExpectedWheelhouseManifestSha256.Trim()
    if ($ExpectedWheelhouseManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "ExpectedWheelhouseManifestSha256 must be exactly 64 hexadecimal digits."
    }
    if (-not $WheelhouseManifest) {
        throw "ExpectedWheelhouseManifestSha256 cannot be used without WheelhouseManifest."
    }
}
if ($SigningEnabled) {
    $SignToolPath = Get-SafeLocalNtfsPath -Name 'SignToolPath' -PathValue $SignToolPath
    $script:ResolvedSignToolPath = $SignToolPath
    $script:ExpectedSignToolSha256 = $ExpectedSignToolSha256
    if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "SigningCertificateThumbprint must be a 40-digit certificate thumbprint."
    }
    if (-not $TimestampUrl.IsAbsoluteUri -or
        $TimestampUrl.Scheme -ne "https" -or
        [string]::IsNullOrWhiteSpace($TimestampUrl.DnsSafeHost) -or
        -not [string]::IsNullOrWhiteSpace($TimestampUrl.UserInfo)) {
        throw "TimestampUrl must be absolute HTTPS, include a host and contain no user information."
    }
    if ($TimestampUrl.AbsoluteUri -match '[\s"$]' -or $SignToolPath -match '\$') {
        throw "SignToolPath/TimestampUrl contains characters that cannot be represented safely in the Inno SignTool command."
    }
    $NormalizedThumbprint = ($SigningCertificateThumbprint -replace '\s', '').ToUpperInvariant()
    $CertificateMatches = @()
    foreach ($StoreDefinition in @(
        [pscustomobject]@{ path = "Cert:\CurrentUser\My"; location = "CurrentUser" },
        [pscustomobject]@{ path = "Cert:\LocalMachine\My"; location = "LocalMachine" }
    )) {
        if (Test-Path -LiteralPath $StoreDefinition.path) {
            foreach ($Certificate in Get-ChildItem -LiteralPath $StoreDefinition.path) {
                if (($Certificate.Thumbprint -replace '\s', '').ToUpperInvariant() -eq $NormalizedThumbprint) {
                    $CertificateMatches += [pscustomobject]@{
                        certificate = $Certificate
                        location = $StoreDefinition.location
                    }
                }
            }
        }
    }
    if ($CertificateMatches.Count -ne 1) {
        throw "Exactly one signing certificate must match in CurrentUser/My or LocalMachine/My. Found: $($CertificateMatches.Count)"
    }
    $SigningCertificateStore = [string]$CertificateMatches[0].location
    $ActualSignToolSha256 = Assert-ApprovedFileSha256 -Name 'SignToolPath' `
        -PathValue $SignToolPath -ExpectedSha256 $ExpectedSignToolSha256
}
elseif ($ExpectedSignToolSha256) {
    throw "ExpectedSignToolSha256 cannot be used without a complete signing configuration."
}

$WheelhouseEvidence = $null
if ($Wheelhouse) {
    $Wheelhouse = Get-SafeLocalNtfsPath -Name 'Wheelhouse' -PathValue $Wheelhouse
    if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
        throw "Wheelhouse does not exist: $Wheelhouse"
    }
    if ($WheelhouseManifest) {
        $WheelhouseManifest = Get-SafeLocalNtfsPath `
            -Name 'WheelhouseManifest' -PathValue $WheelhouseManifest
        $WheelhouseEvidence = Test-WheelhouseSupplyChainManifest `
            -WheelhouseRoot $Wheelhouse `
            -ManifestPath $WheelhouseManifest `
            -ExpectedManifestSha256 $ExpectedWheelhouseManifestSha256
    }
    elseif ($RequireSigned) {
        throw "WheelhouseManifest is mandatory for signed production candidates."
    }
    else {
        Write-Warning "Wheelhouse was not accompanied by a verified manifest; this is allowed only for unsigned test builds."
    }
}
elseif ($WheelhouseManifest -or $ExpectedWheelhouseManifestSha256) {
    throw "WheelhouseManifest and ExpectedWheelhouseManifestSha256 cannot be used without Wheelhouse."
}

if ($Wheelhouse) {
    Assert-PathsDoNotOverlap -FirstName 'OutputDirectory' -FirstPath $OutputDirectory `
        -SecondName 'Wheelhouse' -SecondPath $Wheelhouse
}
if ($WheelhouseManifest) {
    Assert-PathsDoNotOverlap -FirstName 'OutputDirectory' -FirstPath $OutputDirectory `
        -SecondName 'WheelhouseManifest' -SecondPath $WheelhouseManifest
}
if ($Wheelhouse -and $WheelhouseManifest) {
    Assert-PathsDoNotOverlap -FirstName 'Wheelhouse' -FirstPath $Wheelhouse `
        -SecondName 'WheelhouseManifest' -SecondPath $WheelhouseManifest
}

$script:ResolvedInnoCompiler = Find-InnoCompiler -RequestedPath $InnoCompiler
$script:ExpectedInnoCompilerSha256 = $ExpectedInnoCompilerSha256
$ActualInnoCompilerSha256 = Assert-ApprovedFileSha256 -Name 'InnoCompiler' `
    -PathValue $script:ResolvedInnoCompiler `
    -ExpectedSha256 $ExpectedInnoCompilerSha256
$InnoVersion = Get-InnoCompilerVersion -PathValue $script:ResolvedInnoCompiler
if ($InnoVersion.Major -ne 6 -or $InnoVersion -lt [version]"6.7.1") {
    throw "The verified compiler baseline is Inno Setup 6.7.1 or newer within major version 6. Found: $InnoVersion"
}
Write-Host "Using preinstalled Inno Setup $InnoVersion at $script:ResolvedInnoCompiler"

$ResolvedPythonExecutable = Find-PythonExecutable -RequestedPath $PythonExecutable
$ActualPythonExecutableSha256 = Assert-ApprovedFileSha256 `
    -Name 'PythonExecutable' -PathValue $ResolvedPythonExecutable `
    -ExpectedSha256 $ExpectedPythonExecutableSha256
$PythonIdentity = Get-PythonIdentity -PathValue $ResolvedPythonExecutable
if ($ExpectedPythonPatchVersion -and
    $PythonIdentity.version -ne $ExpectedPythonPatchVersion) {
    throw "Resolved Python patch does not match ExpectedPythonPatchVersion."
}
Write-Host "Using x64 CPython $($PythonIdentity.version) at $ResolvedPythonExecutable"

$SafeTempRoot = Get-SafeLocalNtfsPath -Name 'TemporaryDirectory' `
    -PathValue ([IO.Path]::GetTempPath().TrimEnd('\'))
$ResolvedCompilerCacheReadyMarker = $null
if ($UnsignedCompilerCacheReadyMarker) {
    if ($SigningEnabled -or $RequireSigned) {
        throw "UnsignedCompilerCacheReadyMarker is forbidden for signed production candidates."
    }
    $ResolvedCompilerCacheReadyMarker = Get-SafeLocalNtfsPath `
        -Name 'UnsignedCompilerCacheReadyMarker' `
        -PathValue $UnsignedCompilerCacheReadyMarker
    if (-not (Test-PathAtOrBelow `
            -Candidate $ResolvedCompilerCacheReadyMarker -Root $SafeTempRoot)) {
        throw "UnsignedCompilerCacheReadyMarker must be located under the process temporary directory."
    }
    if (Test-Path -LiteralPath $ResolvedCompilerCacheReadyMarker) {
        throw "UnsignedCompilerCacheReadyMarker must not exist before compilation."
    }
}
$WorkParent = Join-Path $SafeTempRoot "MineGuardWindowsReleaseBuild"
$WorkRoot = Join-Path $WorkParent ([Guid]::NewGuid().ToString("N"))
$PlatformOutput = Join-Path $WorkRoot "platform-output"
$AgentOutput = Join-Path $WorkRoot "agent-output"
$ArtifactStage = Join-Path $WorkRoot "artifact-stage"
$PublishStage = $null
New-Item -ItemType Directory -Path $PlatformOutput -Force | Out-Null
New-Item -ItemType Directory -Path $AgentOutput -Force | Out-Null
New-Item -ItemType Directory -Path $ArtifactStage -Force | Out-Null
try {
    $PlatformBuild = Join-Path $RepositoryRoot "platform\packaging\windows\Build-MineGuardPlatform.ps1"
    [void](Assert-ApprovedFileSha256 -Name 'PythonExecutable' `
        -PathValue $ResolvedPythonExecutable `
        -ExpectedSha256 $ActualPythonExecutableSha256)
    if ($SigningEnabled) {
        [void](Assert-ApprovedFileSha256 -Name 'SignToolPath' `
            -PathValue $SignToolPath -ExpectedSha256 $ActualSignToolSha256)
    }
    $PlatformArguments = @(
        "-OutputDirectory", $PlatformOutput,
        "-PythonExecutable", $ResolvedPythonExecutable,
        "-ExpectedPythonPatchVersion", $PythonIdentity.version,
        "-ExpectedPythonExecutableSha256", $ActualPythonExecutableSha256
    )
    if ($Wheelhouse) { $PlatformArguments += @("-Wheelhouse", $Wheelhouse) }
    if ($AllowNuitkaToolDownloads) { $PlatformArguments += "-AllowNuitkaToolDownloads" }
    if ($AllowDirtySource) { $PlatformArguments += "-AllowDirtySource" }
    if ($SigningEnabled) {
        $PlatformArguments += @(
            "-SignToolPath", $SignToolPath,
            "-ExpectedSignToolSha256", $ActualSignToolSha256,
            "-SigningCertificateThumbprint", $SigningCertificateThumbprint,
            "-TimestampUrl", $TimestampUrl.AbsoluteUri,
            "-RequireSignedBinary"
        )
    }
    Invoke-NativeChecked -FilePath "powershell.exe" -ArgumentList (@(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PlatformBuild
    ) + $PlatformArguments) -Label "Platform standalone build"

    $AgentBuild = Join-Path $RepositoryRoot "agent\packaging\windows\Build-EnterpriseAgentBinary.ps1"
    [void](Assert-ApprovedFileSha256 -Name 'PythonExecutable' `
        -PathValue $ResolvedPythonExecutable `
        -ExpectedSha256 $ActualPythonExecutableSha256)
    if ($SigningEnabled) {
        [void](Assert-ApprovedFileSha256 -Name 'SignToolPath' `
            -PathValue $SignToolPath -ExpectedSha256 $ActualSignToolSha256)
    }
    $AgentArguments = @(
        "-ArtifactsRoot", $AgentOutput,
        "-PythonExecutable", $ResolvedPythonExecutable,
        "-ExpectedPythonPatchVersion", $PythonIdentity.version,
        "-ExpectedPythonExecutableSha256", $ActualPythonExecutableSha256
    )
    if ($Wheelhouse) { $AgentArguments += @("-Wheelhouse", $Wheelhouse) }
    if ($AllowNuitkaToolDownloads) { $AgentArguments += "-AllowNuitkaToolDownloads" }
    if ($SigningEnabled) {
        $AgentArguments += @(
            "-SignToolPath", $SignToolPath,
            "-ExpectedSignToolSha256", $ActualSignToolSha256,
            "-SigningCertificateThumbprint", $SigningCertificateThumbprint,
            "-TimestampUrl", $TimestampUrl.AbsoluteUri,
            "-RequireSignedBinary"
        )
    }
    Invoke-NativeChecked -FilePath "powershell.exe" -ArgumentList (@(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $AgentBuild
    ) + $AgentArguments) -Label "Enterprise Agent standalone build"

    if ($ResolvedCompilerCacheReadyMarker) {
        $MarkerText = "Both child compilers completed for source $SourceRevision."
        [IO.File]::WriteAllText(
            $ResolvedCompilerCacheReadyMarker,
            ($MarkerText + [Environment]::NewLine),
            (New-Object Text.UTF8Encoding($false))
        )
    }

    if ($null -ne $WheelhouseEvidence) {
        $WheelhouseEvidence = Test-WheelhouseSupplyChainManifest `
            -WheelhouseRoot $Wheelhouse `
            -ManifestPath $WheelhouseManifest `
            -ExpectedManifestSha256 $ExpectedWheelhouseManifestSha256
    }
    if ($RequireSigned) {
        Assert-CleanGitSnapshot -GitPath $Git.Source -Root $RepositoryRoot `
            -ExpectedRevision $SourceRevision
    }

    $PlatformStages = @(Get-ChildItem -LiteralPath $PlatformOutput -Directory -Filter "MineGuardPlatform-*-windows-x64")
    $AgentStages = @(Get-ChildItem -LiteralPath $AgentOutput -Directory -Filter "MineGuardEnterpriseAgent-*-windows-x64")
    if ($PlatformStages.Count -ne 1 -or $AgentStages.Count -ne 1) {
        throw "Each child build must create exactly one versioned Windows x64 release staging directory."
    }
    $PlatformStage = $PlatformStages[0].FullName
    $AgentStage = $AgentStages[0].FullName
    $PlatformVersion = Get-SemanticVersionFromStage -StageRoot $PlatformStage
    $AgentVersion = Get-SemanticVersionFromStage -StageRoot $AgentStage

    $AuditScript = Join-Path $RepositoryRoot "scripts\Test-WindowsBinaryRelease.ps1"
    $AuditArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $AuditScript,
        "-PlatformStage", $PlatformStage,
        "-AgentStage", $AgentStage
    )
    if ($SigningEnabled) { $AuditArguments += "-RequireSigned" }
    else { $AuditArguments += "-ExpectUnsignedTestOnly" }
    Invoke-NativeChecked -FilePath "powershell.exe" -ArgumentList $AuditArguments -Label "Pre-installer binary audit"

    if ($TestInstallerFailurePropagation) {
        $FailureProbe = Join-Path $RepositoryRoot "scripts\Test-WindowsInstallerFailurePropagation.ps1"
        [void](Assert-ApprovedFileSha256 -Name 'InnoCompiler' `
            -PathValue $script:ResolvedInnoCompiler `
            -ExpectedSha256 $ActualInnoCompilerSha256)
        Invoke-NativeChecked -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $FailureProbe,
            "-InnoCompiler", $script:ResolvedInnoCompiler,
            "-PlatformStage", $PlatformStage,
            "-AgentStage", $AgentStage,
            "-AssetsRoot", (Join-Path $RepositoryRoot "packaging\windows\assets")
        ) -Label "Installer failure-propagation audit"
    }

    $ClassificationSuffix = if ($SigningEnabled) { "" } else { "-UNSIGNED-TEST-ONLY" }
    $PlatformArtifactBase = "MineGuard-Platform-$PlatformVersion-windows-x64$ClassificationSuffix"
    $AgentArtifactBase = "MineGuard-EnterpriseAgent-$AgentVersion-windows-x64$ClassificationSuffix"
    $SignToolCommand = ""
    if ($SigningEnabled) {
        $StoreSwitch = if ($SigningCertificateStore -eq "LocalMachine") { " /sm" } else { "" }
        $SignToolCommand = '$q' + $SignToolPath + '$q sign /fd SHA256' + $StoreSwitch + ' /sha1 ' +
            $SigningCertificateThumbprint.ToUpperInvariant() + ' /tr $q' +
            $TimestampUrl.AbsoluteUri + '$q /td SHA256 $f'
    }
    $AssetsRoot = Join-Path $RepositoryRoot "packaging\windows\assets"
    $PlatformInstaller = Invoke-InnoCompile `
        -ScriptPath (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardPlatform.iss") `
        -StageRoot $PlatformStage -AssetsRoot $AssetsRoot -ArtifactsRoot $ArtifactStage `
        -Version $PlatformVersion -ArtifactBaseName $PlatformArtifactBase `
        -SigningEnabled $SigningEnabled -SigningCommand $SignToolCommand
    $AgentInstaller = Invoke-InnoCompile `
        -ScriptPath (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardEnterpriseAgent.iss") `
        -StageRoot $AgentStage -AssetsRoot $AssetsRoot -ArtifactsRoot $ArtifactStage `
        -Version $AgentVersion -ArtifactBaseName $AgentArtifactBase `
        -SigningEnabled $SigningEnabled -SigningCommand $SignToolCommand

    $PlatformMetadata = Get-Content -LiteralPath (Join-Path $PlatformStage "build-metadata.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $AgentMetadata = Get-Content -LiteralPath (Join-Path $AgentStage "build-metadata.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$PlatformMetadata.python -ne $PythonIdentity.version -or
        [string]$AgentMetadata.python -ne $PythonIdentity.version) {
        throw "Both child builders must use the same resolved root python.exe patch version."
    }
    if ($RequireSigned) {
        if ([string]$PlatformMetadata.python -ne $ExpectedPythonPatchVersion -or
            [string]$AgentMetadata.python -ne $ExpectedPythonPatchVersion) {
            throw "Signed child metadata does not match ExpectedPythonPatchVersion."
        }
        if ([string]$PlatformMetadata.sourceRevision -ne $SourceRevision -or
            $PlatformMetadata.sourceTreeDirty -ne $false -or
            [string]$AgentMetadata.source_revision -ne $SourceRevision -or
            $AgentMetadata.source_dirty -ne $false) {
            throw "A signed child binary does not identify the clean root source revision."
        }
    }
    $Installers = @()
    foreach ($InstallerDefinition in @(
        [pscustomobject]@{ product = "MineGuard Platform"; id = "platform"; version = $PlatformVersion; path = $PlatformInstaller },
        [pscustomobject]@{ product = "MineGuard Enterprise Agent"; id = "enterprise-agent"; version = $AgentVersion; path = $AgentInstaller }
    )) {
        $Signature = Get-AuthenticodeSignature -LiteralPath $InstallerDefinition.path
        if ($SigningEnabled -and ($Signature.Status -ne "Valid" -or $null -eq $Signature.TimeStamperCertificate)) {
            throw "Signed installer verification failed: $($InstallerDefinition.path)"
        }
        if ($SigningEnabled) {
            [void](Assert-ApprovedFileSha256 -Name 'SignToolPath' `
                -PathValue $SignToolPath -ExpectedSha256 $ActualSignToolSha256)
            Invoke-NativeChecked -FilePath $SignToolPath -ArgumentList @(
                "verify", "/pa", "/all", "/v", $InstallerDefinition.path
            ) -Label "Installer Authenticode verification"
        }
        $ActualSignerThumbprint = if ($null -ne $Signature.SignerCertificate) {
            ($Signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
        } else { $null }
        if ($SigningEnabled -and $ActualSignerThumbprint -ne $NormalizedThumbprint) {
            throw "Installer signer thumbprint does not match the configured certificate: $($InstallerDefinition.path)"
        }
        if (-not $SigningEnabled -and $Signature.Status -ne "NotSigned") {
            throw "Unsigned-test installer has unexpected Authenticode status: $($Signature.Status)"
        }
        $Installers += [ordered]@{
            product = $InstallerDefinition.product
            product_id = $InstallerDefinition.id
            version = $InstallerDefinition.version
            file = [IO.Path]::GetFileName($InstallerDefinition.path)
            bytes = [long](Get-Item -LiteralPath $InstallerDefinition.path).Length
            sha256 = (Get-FileHash -LiteralPath $InstallerDefinition.path -Algorithm SHA256).Hash.ToLowerInvariant()
            authenticode_status = [string]$Signature.Status
            signer_thumbprint = $ActualSignerThumbprint
            timestamped = $null -ne $Signature.TimeStamperCertificate
        }
    }
    $ReleaseManifest = [ordered]@{
        format = "mineguard-windows-installers-v1"
        classification = if ($SigningEnabled) { "signed-production-candidate" } else { "unsigned-test-artifacts" }
        generated_utc = [DateTime]::UtcNow.ToString("o")
        source_revision = $SourceRevision
        source_dirty = $SourceDirty
        architecture = "native-windows-x64"
        minimum_windows = "Windows 10 1809 / Windows Server 2019 x64"
        arm64_status = "not-validated-and-blocked"
        process_statement = "Constrained, traceable and repeatable build; byte-for-byte identical output is not promised."
        contents_statement = "No MineGuard backend Python source, Python bytecode, tests, Git history or real secrets. Browser HTML/JavaScript/CSS and operations PowerShell remain visible plaintext."
        toolchain = [ordered]@{
            inno_setup = [string]$InnoVersion
            inno_setup_path_sha256 = $ActualInnoCompilerSha256
            inno_chinese_language_sha256 = $ActualInnoChineseLanguageSha256
            expected_inno_setup_path_sha256 = if ($ExpectedInnoCompilerSha256) {
                $ExpectedInnoCompilerSha256.ToLowerInvariant()
            } else { $null }
            inno_external_anchor_verified = [bool]($ExpectedInnoCompilerSha256 -and
                $ActualInnoCompilerSha256 -eq $ExpectedInnoCompilerSha256.ToLowerInvariant())
            root_python = $PythonIdentity.version
            python_executable_sha256 = $ActualPythonExecutableSha256
            expected_python_patch = if ($ExpectedPythonPatchVersion) {
                $ExpectedPythonPatchVersion
            } else { $null }
            expected_python_executable_sha256 = if ($ExpectedPythonExecutableSha256) {
                $ExpectedPythonExecutableSha256.ToLowerInvariant()
            } else { $null }
            python_external_anchor_verified = [bool](
                $ExpectedPythonPatchVersion -and
                $ExpectedPythonExecutableSha256 -and
                $PythonIdentity.version -eq $ExpectedPythonPatchVersion -and
                $ActualPythonExecutableSha256 -eq $ExpectedPythonExecutableSha256.ToLowerInvariant()
            )
            signtool_sha256 = $ActualSignToolSha256
            expected_signtool_sha256 = if ($ExpectedSignToolSha256) {
                $ExpectedSignToolSha256.ToLowerInvariant()
            } else { $null }
            signtool_external_anchor_verified = [bool]($ExpectedSignToolSha256 -and
                $ActualSignToolSha256 -eq $ExpectedSignToolSha256.ToLowerInvariant())
            platform_python = [string]$PlatformMetadata.python
            platform_nuitka = [string]$PlatformMetadata.nuitka
            platform_dependencies = $PlatformMetadata.dependencies
            agent_python = [string]$AgentMetadata.python
            agent_nuitka = [string]$AgentMetadata.nuitka
            agent_build_dependencies = $AgentMetadata.build_dependencies
            agent_runtime_dependencies = $AgentMetadata.runtime_dependencies
        }
        third_party_review = "Delivery organization must review the Nuitka builder/runtime exception, Inno Setup commercial-use terms and bundled dependency licenses before redistribution."
        authenticode_signing = [ordered]@{
            enabled = $SigningEnabled
            certificate_store_location = $SigningCertificateStore
            normalized_signer_thumbprint = if ($SigningEnabled) { $NormalizedThumbprint } else { $null }
            timestamp_url = if ($SigningEnabled) { $TimestampUrl.AbsoluteUri } else { $null }
        }
        wheelhouse_supply_chain = if ($null -ne $WheelhouseEvidence) {
            [ordered]@{
                verified = $true
                format = $WheelhouseEvidence.format
                python = $WheelhouseEvidence.python
                architecture = $WheelhouseEvidence.architecture
                file_count = $WheelhouseEvidence.file_count
                manifest_sha256 = $WheelhouseEvidence.manifest_sha256
                expected_manifest_sha256 = $WheelhouseEvidence.expected_manifest_sha256
                external_trust_anchor_verified = $WheelhouseEvidence.external_trust_anchor_verified
            }
        } else {
            [ordered]@{ verified = $false }
        }
        installers = $Installers
    }
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    $ManifestPath = Join-Path $ArtifactStage "release-manifest.json"
    [IO.File]::WriteAllText(
        $ManifestPath,
        (($ReleaseManifest | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
        $Utf8NoBom
    )
    $SumLines = @()
    foreach ($File in @($PlatformInstaller, $AgentInstaller, $ManifestPath)) {
        $Hash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
        $SumLines += "$Hash *$([IO.Path]::GetFileName($File))"
    }
    [IO.File]::WriteAllLines((Join-Path $ArtifactStage "SHA256SUMS.txt"), $SumLines, $Utf8NoBom)

    $FinalAuditArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $AuditScript,
        "-PlatformStage", $PlatformStage,
        "-AgentStage", $AgentStage,
        "-ArtifactDirectory", $ArtifactStage,
        "-SkipRuntimeSmoke"
    )
    if ($SigningEnabled) { $FinalAuditArguments += "-RequireSigned" }
    else { $FinalAuditArguments += "-ExpectUnsignedTestOnly" }
    if ($TestInstallerLifecycle) { $FinalAuditArguments += "-TestInstallerLifecycle" }
    Invoke-NativeChecked -FilePath "powershell.exe" -ArgumentList $FinalAuditArguments -Label "Final installer audit"
    if ($RequireSigned) {
        Assert-CleanGitSnapshot -GitPath $Git.Source -Root $RepositoryRoot `
            -ExpectedRevision $SourceRevision
    }

    $FilesToPublish = @(
        [IO.Path]::GetFileName($PlatformInstaller),
        [IO.Path]::GetFileName($AgentInstaller),
        "release-manifest.json",
        "SHA256SUMS.txt"
    )
    $OutputParent = [IO.Path]::GetDirectoryName($OutputDirectory)
    if (-not (Test-Path -LiteralPath $OutputParent)) {
        New-Item -ItemType Directory -Path $OutputParent -Force | Out-Null
    }
    $OutputParent = Get-SafeLocalNtfsPath -Name 'OutputDirectory parent' `
        -PathValue $OutputParent
    if (Test-Path -LiteralPath $OutputDirectory) {
        throw "OutputDirectory appeared before atomic publication: $OutputDirectory"
    }
    $OutputLeaf = [IO.Path]::GetFileName($OutputDirectory)
    $PublishStage = Join-Path $OutputParent (
        "." + $OutputLeaf + ".incoming-" + [Guid]::NewGuid().ToString("N")
    )
    $PublishStage = Get-SafeLocalNtfsPath -Name 'Publication staging directory' `
        -PathValue $PublishStage
    if (Test-Path -LiteralPath $PublishStage) {
        throw "Random publication staging directory unexpectedly exists: $PublishStage"
    }
    New-Item -ItemType Directory -Path $PublishStage | Out-Null
    foreach ($FileName in $FilesToPublish) {
        $SourcePath = Join-Path $ArtifactStage $FileName
        $StagedPublishPath = Join-Path $PublishStage $FileName
        Copy-Item -LiteralPath $SourcePath -Destination $StagedPublishPath
    }
    $PublishedAuditArguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $AuditScript,
        "-PlatformStage", $PlatformStage,
        "-AgentStage", $AgentStage,
        "-ArtifactDirectory", $PublishStage,
        "-SkipRuntimeSmoke"
    )
    if ($SigningEnabled) { $PublishedAuditArguments += "-RequireSigned" }
    else { $PublishedAuditArguments += "-ExpectUnsignedTestOnly" }
    Invoke-NativeChecked -FilePath "powershell.exe" `
        -ArgumentList $PublishedAuditArguments `
        -Label "Published artifact audit (pre-rename staging)"
    if ($RequireSigned) {
        Assert-CleanGitSnapshot -GitPath $Git.Source -Root $RepositoryRoot `
            -ExpectedRevision $SourceRevision
    }
    if (Test-Path -LiteralPath $OutputDirectory) {
        throw "OutputDirectory appeared before the final atomic rename: $OutputDirectory"
    }
    [IO.Directory]::Move($PublishStage, $OutputDirectory)

    Write-Host "MineGuard independent Windows installers created: $OutputDirectory"
    if (-not $SigningEnabled) {
        Write-Warning "These are UNSIGNED-TEST-ONLY artifacts. They are not production-trusted release media."
    }
}
finally {
    if ($null -ne $PublishStage -and (Test-Path -LiteralPath $PublishStage)) {
        $FullPublishStage = [IO.Path]::GetFullPath($PublishStage)
        $FullOutputParent = [IO.Path]::GetFullPath(
            [IO.Path]::GetDirectoryName($OutputDirectory)
        ).TrimEnd('\') + '\'
        if (-not $FullPublishStage.StartsWith(
                $FullOutputParent, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Refusing unsafe publication staging cleanup path: $FullPublishStage"
        }
        Remove-Item -LiteralPath $FullPublishStage -Recurse -Force
    }
    if (Test-Path -LiteralPath $WorkRoot) {
        $FullWorkRoot = [IO.Path]::GetFullPath($WorkRoot)
        $FullWorkParent = [IO.Path]::GetFullPath($WorkParent).TrimEnd('\') + '\'
        if (-not $FullWorkRoot.StartsWith($FullWorkParent, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing unsafe build cleanup path: $FullWorkRoot"
        }
        Remove-Item -LiteralPath $FullWorkRoot -Recurse -Force
    }
}
