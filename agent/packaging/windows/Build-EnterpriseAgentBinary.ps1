[CmdletBinding()]
param(
    [string]$SourceRoot = "",
    [string]$ArtifactsRoot = "",
    [string]$PythonExecutable = "",
    [string]$ExpectedPythonPatchVersion = "",
    [string]$ExpectedPythonExecutableSha256 = "",
    [string]$PythonCommand = "py",
    [string[]]$PythonArguments = @("-3.12"),
    [string]$Wheelhouse = "",
    [switch]$AllowNuitkaToolDownloads,
    [string]$SignToolPath = "",
    [string]$ExpectedSignToolSha256 = "",
    [string]$SigningCertificateThumbprint = "",
    [string]$TimestampUrl = "",
    [switch]$RequireSignedBinary,
    [switch]$SkipSmokeTest,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

if ($env:OS -ne "Windows_NT") {
    throw "The Enterprise Agent Windows binary must be built on native Windows."
}
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    throw "Windows PowerShell 5.1 or later is required."
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Assert-SafeLocalFixedPath {
    param([string]$Name, [string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { throw "$Name cannot be empty." }
    if ($PathValue -ne $PathValue.Trim() -or $PathValue.Contains("/") -or
        $PathValue -notmatch '^[A-Za-z]:\\') {
        throw "$Name must be supplied as an X:\ absolute local path: $PathValue"
    }
    $PathWithoutTrailingSeparator = $PathValue.TrimEnd('\')
    if ($PathWithoutTrailingSeparator.Length -le 2) {
        throw "$Name must not be a filesystem root."
    }
    $PathParts = $PathWithoutTrailingSeparator.Substring(3) -split '\\'
    foreach ($Part in $PathParts) {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @(".", "..") -or
            $Part.EndsWith(" ") -or $Part.EndsWith(".")) {
            throw "$Name contains an empty, dot or ambiguous path component: $PathValue"
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if ($FullPath -notmatch '^[A-Za-z]:\\' -or
        $FullPath.StartsWith("\\") -or $FullPath.Substring(2).Contains(":")) {
        throw "$Name must use an X:\ absolute local path without alternate data streams: $FullPath"
    }
    $Root = [IO.Path]::GetPathRoot($FullPath)
    $DeviceId = $Root.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" `
        -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3) {
        throw "$Name must use a local fixed disk: $FullPath"
    }
    if (-not ([string]$Disk.FileSystem).Equals(
            "NTFS", [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Name must use an NTFS filesystem: $FullPath"
    }

    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $CurrentItem = Get-Item -LiteralPath $Current -Force
            if (($CurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
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
}

function Get-DistributionVersion {
    param([string]$PythonExecutable, [string]$DistributionName)
    $VersionText = (& $PythonExecutable -c "import importlib.metadata as m,sys; print(m.version(sys.argv[1]))" $DistributionName |
        Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($VersionText)) {
        throw "Cannot determine installed distribution version: $DistributionName"
    }
    return $VersionText
}

function Assert-OrdinaryDirectoryTree {
    param([string]$Root)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release input cannot be a symlink, junction or reparse point: $Root"
    }
    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release input contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
}

Assert-SafeLocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
Assert-SafeLocalFixedPath -Name "SourceRoot" -PathValue $SourceRoot
$RepositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$AuthenticodeHelper = Join-Path $RepositoryRoot "scripts\Invoke-WindowsAuthenticodeSign.ps1"
$WindowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
Assert-SafeLocalFixedPath -Name "WindowsPowerShell" -PathValue $WindowsPowerShell
if (-not $ArtifactsRoot) {
    $ArtifactsRoot = Join-Path $SourceRoot "artifacts"
}
Assert-SafeLocalFixedPath -Name "ArtifactsRoot" -PathValue $ArtifactsRoot
$ArtifactsRoot = [IO.Path]::GetFullPath($ArtifactsRoot)
$ExplicitPythonExecutable = -not [string]::IsNullOrWhiteSpace($PythonExecutable)
if ($ExplicitPythonExecutable) {
    if ($PSBoundParameters.ContainsKey("PythonCommand") -or
        $PSBoundParameters.ContainsKey("PythonArguments")) {
        throw "PythonExecutable cannot be combined with PythonCommand or PythonArguments."
    }
    Assert-SafeLocalFixedPath -Name "PythonExecutable" -PathValue $PythonExecutable
    $PythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)
    Assert-SafeLocalFixedPath -Name "PythonExecutable" -PathValue $PythonExecutable
    if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
        throw "PythonExecutable does not exist: $PythonExecutable"
    }
    $PythonCommand = $PythonExecutable
    $PythonArguments = @()
}
$ExpectedPythonPatchVersion = $ExpectedPythonPatchVersion.Trim()
if ($ExpectedPythonPatchVersion -and
    $ExpectedPythonPatchVersion -notmatch '^3\.12\.\d+$') {
    throw "ExpectedPythonPatchVersion must be an exact CPython 3.12 patch."
}
if ($ExpectedPythonExecutableSha256 -and
    $ExpectedPythonExecutableSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "ExpectedPythonExecutableSha256 must be exactly 64 hexadecimal digits."
}
if ($RequireSignedBinary -and
    (-not $ExplicitPythonExecutable -or -not $ExpectedPythonPatchVersion -or
        -not $ExpectedPythonExecutableSha256)) {
    throw "A signed child build requires the resolved Python executable, exact patch and approved SHA-256."
}
if ($ExpectedPythonExecutableSha256) {
    if (-not $ExplicitPythonExecutable) {
        throw "ExpectedPythonExecutableSha256 requires PythonExecutable."
    }
    $ActualPythonExecutableSha256 = (Get-FileHash -LiteralPath $PythonExecutable `
        -Algorithm SHA256).Hash
    if ($ActualPythonExecutableSha256 -ne $ExpectedPythonExecutableSha256) {
        throw "PythonExecutable does not match ExpectedPythonExecutableSha256."
    }
}
$SigningValues = @(@($SignToolPath, $SigningCertificateThumbprint, $TimestampUrl) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$SigningEnabled = $SigningValues.Count -ne 0
$SigningVerified = $false
$TimestampVerified = $false
$VerifiedSigningThumbprint = $null
if ($SigningEnabled -and $SigningValues.Count -ne 3) {
    throw "SignToolPath, SigningCertificateThumbprint and TimestampUrl must be provided together."
}
if ($SigningEnabled -and -not $RequireSignedBinary) {
    throw "Signing parameters require -RequireSignedBinary so formal release gates cannot be bypassed."
}
if ($RequireSignedBinary -and -not $SigningEnabled) {
    throw "RequireSignedBinary requires the complete Authenticode signing configuration."
}
if ($RequireSignedBinary -and $AllowNuitkaToolDownloads) {
    throw "A signed formal binary cannot download Nuitka tools; pre-stage the approved cache."
}
if ($RequireSignedBinary -and [string]::IsNullOrWhiteSpace($Wheelhouse)) {
    throw "A signed formal binary requires an approved offline Wheelhouse."
}
if ($RequireSignedBinary -and [string]::IsNullOrWhiteSpace($ExpectedSignToolSha256)) {
    throw "A signed child build requires ExpectedSignToolSha256."
}
if ($SigningEnabled) {
    Assert-SafeLocalFixedPath -Name "SignToolPath" -PathValue $SignToolPath
    $SignToolPath = [IO.Path]::GetFullPath($SignToolPath)
    Assert-SafeLocalFixedPath -Name "SignToolPath" -PathValue $SignToolPath
    if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
        throw "signtool.exe does not exist: $SignToolPath"
    }
    if ($ExpectedSignToolSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $SignToolPath -Algorithm SHA256).Hash -ne
            $ExpectedSignToolSha256) {
        throw "SignToolPath does not match ExpectedSignToolSha256."
    }
    if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "SigningCertificateThumbprint must be a 40-character SHA-1 certificate thumbprint."
    }
    $ParsedTimestampUri = $null
    if (-not [uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$ParsedTimestampUri) -or
        $ParsedTimestampUri.Scheme -ne "https" -or
        [string]::IsNullOrWhiteSpace($ParsedTimestampUri.DnsSafeHost) -or
        -not [string]::IsNullOrWhiteSpace($ParsedTimestampUri.UserInfo)) {
        throw "TimestampUrl must be an absolute HTTPS URL with a host and no user information."
    }
    $TimestampUrl = $ParsedTimestampUri.AbsoluteUri
}
$SourceRevision = $null
$SourceDirty = $null
$GitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
if ($null -ne $GitCommand) {
    $SourceRevision = (& $GitCommand.Source -C $SourceRoot rev-parse HEAD 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -eq 0 -and $SourceRevision -match '^[A-Fa-f0-9]{40,64}$') {
        $DirtyLines = @(& $GitCommand.Source -C $SourceRoot status --porcelain --untracked-files=normal 2>$null)
        if ($LASTEXITCODE -ne 0) {
            $SourceRevision = $null
        }
        else {
            $SourceDirty = $DirtyLines.Count -ne 0
        }
    }
    else {
        $SourceRevision = $null
    }
}
if ($RequireSignedBinary -and ($null -eq $SourceRevision -or $SourceDirty -ne $false)) {
    throw "A signed formal binary must be built from a clean Git revision."
}
$ProjectFile = Join-Path $SourceRoot "pyproject.toml"
$ConstraintsFile = Join-Path $SourceRoot "constraints.txt"
$WebRoot = Join-Path $SourceRoot "web"
$EntryPoint = Join-Path $PSScriptRoot "enterprise_agent_entry.py"
$BuildRequirements = Join-Path $PSScriptRoot "build-requirements.txt"
$SmokeTest = Join-Path $PSScriptRoot "Test-EnterpriseAgentBinary.ps1"
foreach ($Required in @($ProjectFile, $ConstraintsFile, $WebRoot, $EntryPoint, $BuildRequirements, $SmokeTest)) {
    if (-not (Test-Path -LiteralPath $Required)) {
        throw "Build input is missing: $Required"
    }
}
Assert-OrdinaryDirectoryTree -Root $SourceRoot

New-Item -ItemType Directory -Path $ArtifactsRoot -Force | Out-Null
Assert-SafeLocalFixedPath -Name "ArtifactsRoot" -PathValue $ArtifactsRoot
$WorkRoot = Join-Path $ArtifactsRoot (".agent-binary-work-" + [Guid]::NewGuid().ToString("N"))
$StageRoot = Join-Path $ArtifactsRoot (".agent-binary-stage-" + [Guid]::NewGuid().ToString("N"))
$BuildEnvironment = Join-Path $WorkRoot ".venv"
$CompilerOutput = Join-Path $WorkRoot "compiler-output"
$Completed = $false
try {
    New-Item -ItemType Directory -Path $WorkRoot | Out-Null
    New-Item -ItemType Directory -Path $StageRoot | Out-Null
    Assert-SafeLocalFixedPath -Name "WorkRoot" -PathValue $WorkRoot
    Assert-SafeLocalFixedPath -Name "StageRoot" -PathValue $StageRoot
    if ($ExpectedPythonExecutableSha256) {
        $CriticalPythonSha256 = (Get-FileHash -LiteralPath $PythonExecutable `
            -Algorithm SHA256).Hash
        if ($CriticalPythonSha256 -ne $ExpectedPythonExecutableSha256) {
            throw "PythonExecutable changed before build environment creation."
        }
    }
    $VersionCheck = "import struct,sys; assert sys.version_info[:2] == (3,12) and struct.calcsize('P') == 8, sys.version"
    Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-c", $VersionCheck))
    Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-m", "venv", $BuildEnvironment))
    $BuildPython = Join-Path $BuildEnvironment "Scripts\python.exe"
    Invoke-NativeChecked -FilePath $BuildPython -ArgumentList @("-c", $VersionCheck)
    $PythonPatchVersion = (& $BuildPython -c "import platform; print(platform.python_version())" |
        Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $PythonPatchVersion -notmatch '^3\.12\.\d+$') {
        throw "Cannot determine the exact CPython 3.12 patch version."
    }
    if ($ExpectedPythonPatchVersion -and
        $PythonPatchVersion -ne $ExpectedPythonPatchVersion) {
        throw "Build Python patch does not match ExpectedPythonPatchVersion."
    }

    $PipCommon = @("-m", "pip", "install", "--disable-pip-version-check")
    if ($Wheelhouse) {
        Assert-SafeLocalFixedPath -Name "Wheelhouse" -PathValue $Wheelhouse
        $Wheelhouse = [IO.Path]::GetFullPath($Wheelhouse)
        Assert-SafeLocalFixedPath -Name "Wheelhouse" -PathValue $Wheelhouse
        if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
            throw "Wheelhouse directory does not exist: $Wheelhouse"
        }
        Assert-OrdinaryDirectoryTree -Root $Wheelhouse
        $PipCommon += @("--no-index", "--find-links", $Wheelhouse)
    }
    Invoke-NativeChecked -FilePath $BuildPython -ArgumentList ($PipCommon + @("-r", $BuildRequirements))
    Invoke-NativeChecked -FilePath $BuildPython -ArgumentList (
        $PipCommon + @("--no-build-isolation", "--constraint", $ConstraintsFile, $SourceRoot)
    )

    $Version = (& $BuildPython -c "import enterprise_agent; print(enterprise_agent.__version__)" | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "Enterprise Agent version must use numeric major.minor.patch form."
    }
    $FileVersion = $Version + ".0"
    New-Item -ItemType Directory -Path $CompilerOutput | Out-Null
    $NuitkaArguments = @(
        "-m", "nuitka",
        "--mode=standalone",
        "--deployment",
        "--python-flag=isolated",
        "--python-flag=safe_path",
        "--python-flag=no_docstrings",
        "--python-flag=dont_write_bytecode",
        "--msvc=latest",
        "--output-dir=$CompilerOutput",
        "--output-filename=MineGuardEnterpriseAgent.exe",
        "--windows-console-mode=force",
        "--company-name=MineGuard",
        "--product-name=MineGuard Enterprise Agent",
        "--file-description=MineGuard Enterprise Agent",
        "--file-version=$FileVersion",
        "--product-version=$FileVersion",
        "--include-package=enterprise_agent",
        "--include-package=openpyxl",
        "--include-package=xlrd",
        "--include-package=tzdata",
        "--include-package-data=tzdata",
        "--include-data-dir=$WebRoot=web",
        "--remove-output"
    )
    if ($AllowNuitkaToolDownloads) {
        $NuitkaArguments += "--assume-yes-for-downloads"
    }
    $NuitkaArguments += $EntryPoint
    Invoke-NativeChecked -FilePath $BuildPython -ArgumentList $NuitkaArguments

    $Executables = @(Get-ChildItem -LiteralPath $CompilerOutput -Filter "MineGuardEnterpriseAgent.exe" -File -Recurse)
    if ($Executables.Count -ne 1) {
        throw "Nuitka output must contain exactly one MineGuardEnterpriseAgent.exe."
    }
    $CompiledRuntime = $Executables[0].Directory.FullName
    Assert-OrdinaryDirectoryTree -Root $CompiledRuntime
    $RuntimeStage = Join-Path $StageRoot "runtime"
    New-Item -ItemType Directory -Path $RuntimeStage | Out-Null
    foreach ($Item in Get-ChildItem -LiteralPath $CompiledRuntime -Force) {
        Copy-Item -LiteralPath $Item.FullName -Destination $RuntimeStage -Recurse
    }
    $StagedExecutable = Join-Path $RuntimeStage "MineGuardEnterpriseAgent.exe"
    if ($SigningEnabled) {
        Assert-SafeLocalFixedPath -Name "AuthenticodeHelper" -PathValue $AuthenticodeHelper
        if (-not (Test-Path -LiteralPath $AuthenticodeHelper -PathType Leaf)) {
            throw "The repository Authenticode signing helper is missing: $AuthenticodeHelper"
        }
        if (-not (Test-Path -LiteralPath $WindowsPowerShell -PathType Leaf)) {
            throw "Windows PowerShell 5.1 was not found: $WindowsPowerShell"
        }
        $CriticalSignToolSha256 = (Get-FileHash -LiteralPath $SignToolPath `
            -Algorithm SHA256).Hash
        if ($CriticalSignToolSha256 -ne $ExpectedSignToolSha256) {
            throw "SignToolPath changed before the critical signing operation."
        }
        Invoke-NativeChecked -FilePath $WindowsPowerShell -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $AuthenticodeHelper,
            "-Files", $StagedExecutable,
            "-SignToolPath", $SignToolPath,
            "-CertificateThumbprint", $SigningCertificateThumbprint,
            "-TimestampUrl", $TimestampUrl
        )
        $StagedSignature = Get-AuthenticodeSignature -LiteralPath $StagedExecutable
        $VerifiedSigningThumbprint = if ($null -ne $StagedSignature.SignerCertificate) {
            ($StagedSignature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
        } else { $null }
        if ($StagedSignature.Status.ToString() -ne "Valid" -or
            $VerifiedSigningThumbprint -ne
                ($SigningCertificateThumbprint -replace '\s', '').ToUpperInvariant() -or
            $null -eq $StagedSignature.TimeStamperCertificate) {
            throw "The signed Agent executable failed the post-sign Authenticode contract."
        }
        $SigningVerified = $true
        $TimestampVerified = $true
    }
    else {
        $StagedSignature = Get-AuthenticodeSignature -LiteralPath $StagedExecutable
        if ($StagedSignature.Status.ToString() -ne "NotSigned" -or
            $null -ne $StagedSignature.SignerCertificate -or
            $null -ne $StagedSignature.TimeStamperCertificate) {
            throw "Unsigned build mode requires an actually unsigned Agent executable."
        }
        Write-Warning "Creating an unsigned internal-test binary. Formal releases must use -RequireSignedBinary and the controlled certificate store."
    }

    $DeployStage = Join-Path $StageRoot "deploy\windows"
    New-Item -ItemType Directory -Path $DeployStage -Force | Out-Null
    foreach ($Item in Get-ChildItem -LiteralPath (Join-Path $SourceRoot "deploy\windows") -Force) {
        Copy-Item -LiteralPath $Item.FullName -Destination $DeployStage -Recurse
    }
    [IO.File]::WriteAllText(
        (Join-Path $StageRoot "VERSION.txt"),
        ($Version + [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false))
    )
    $BuildMetadata = [ordered]@{
        format = "mineguard-enterprise-agent-build-metadata-v1"
        product = "MineGuard Enterprise Agent"
        version = $Version
        architecture = "x64"
        python = $PythonPatchVersion
        nuitka = (& $BuildPython -m nuitka --version | Select-Object -First 1).Trim()
        build_dependencies = [ordered]@{
            setuptools = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "setuptools")
            wheel = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "wheel")
            ordered_set = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "ordered-set")
            zstandard = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "zstandard")
        }
        runtime_dependencies = [ordered]@{
            openpyxl = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "openpyxl")
            et_xmlfile = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "et-xmlfile")
            xlrd = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "xlrd")
            tzdata = $(Get-DistributionVersion -PythonExecutable $BuildPython -DistributionName "tzdata")
        }
        authenticode_signed = $SigningVerified
        signing_certificate_thumbprint = if ($SigningVerified) {
            $VerifiedSigningThumbprint
        } else { $null }
        timestamp_verified = $TimestampVerified
        timestamp_url = if ($TimestampVerified) { $TimestampUrl } else { $null }
        built_utc = [DateTime]::UtcNow.ToString("o")
        source_revision = $SourceRevision
        source_dirty = $SourceDirty
        nuitka_tool_downloads_allowed = $AllowNuitkaToolDownloads.IsPresent
    }
    [IO.File]::WriteAllText(
        (Join-Path $StageRoot "build-metadata.json"),
        (($BuildMetadata | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false))
    )

    if (-not $SkipSmokeTest) {
        & $WindowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $SmokeTest -RuntimeRoot $RuntimeStage
        if ($LASTEXITCODE -ne 0) {
            throw "Standalone smoke test failed with exit code $LASTEXITCODE."
        }
    }

    $ForbiddenRuntimeFiles = @(Get-ChildItem -LiteralPath $RuntimeStage -File -Recurse -Force |
        Where-Object { $_.Extension -in @(".py", ".pyw", ".pyc", ".pyo", ".pyi", ".pyx", ".pxd", ".ipynb", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".pdb", ".ilk", ".map") })
    if ($ForbiddenRuntimeFiles.Count -ne 0) {
        throw "Binary runtime contains forbidden source: $($ForbiddenRuntimeFiles[0].FullName)"
    }
    $ForbiddenReleaseNames = @("pyproject.toml", ".git", "tests")
    foreach ($Name in $ForbiddenReleaseNames) {
        if (Get-ChildItem -LiteralPath $StageRoot -Force -Recurse | Where-Object { $_.Name -eq $Name }) {
            throw "Binary release contains a forbidden development item: $Name"
        }
    }

    $ManifestEntries = @()
    foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse -Force | Sort-Object FullName) {
        $RelativePath = $File.FullName.Substring($StageRoot.Length + 1).Replace('\', '/')
        $ManifestEntries += [ordered]@{
            path = $RelativePath
            bytes = [long]$File.Length
            sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $ReleaseManifest = [ordered]@{
        format = "mineguard-enterprise-agent-windows-binary-v1"
        product = "MineGuard Enterprise Agent"
        version = $Version
        architecture = "x64"
        entrypoint = "runtime/MineGuardEnterpriseAgent.exe"
        authenticode_signed = $SigningVerified
        signing_certificate_thumbprint = if ($SigningVerified) {
            $VerifiedSigningThumbprint
        } else { $null }
        timestamp_verified = $TimestampVerified
        timestamp_url = if ($TimestampVerified) { $TimestampUrl } else { $null }
        files = $ManifestEntries
    }
    $ManifestPath = Join-Path $StageRoot "release-manifest.json"
    [IO.File]::WriteAllText(
        $ManifestPath,
        (($ReleaseManifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false))
    )
    $ChecksumLines = @()
    foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse -Force | Sort-Object FullName) {
        $RelativePath = $File.FullName.Substring($StageRoot.Length + 1).Replace('\', '/')
        $Digest = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $ChecksumLines += "$Digest *$RelativePath"
    }
    [IO.File]::WriteAllLines(
        (Join-Path $StageRoot "SHA256SUMS.txt"),
        $ChecksumLines,
        (New-Object System.Text.UTF8Encoding($false))
    )

    $ReleaseName = "MineGuardEnterpriseAgent-$Version-windows-x64"
    $ReleaseRoot = Join-Path $ArtifactsRoot $ReleaseName
    $ReplacedReleaseRoot = Join-Path $ArtifactsRoot (
        ".agent-binary-replaced-" + [Guid]::NewGuid().ToString("N")
    )
    if (Test-Path -LiteralPath $ReleaseRoot) {
        if (-not $Force) {
            throw "Release already exists; pass -Force to replace this exact version: $ReleaseRoot"
        }
        Move-Item -LiteralPath $ReleaseRoot -Destination $ReplacedReleaseRoot
    }
    try {
        Move-Item -LiteralPath $StageRoot -Destination $ReleaseRoot
    }
    catch {
        if ((Test-Path -LiteralPath $ReplacedReleaseRoot) -and
            -not (Test-Path -LiteralPath $ReleaseRoot)) {
            Move-Item -LiteralPath $ReplacedReleaseRoot -Destination $ReleaseRoot
        }
        throw
    }
    $Completed = $true
    if (Test-Path -LiteralPath $ReplacedReleaseRoot) {
        try {
            Remove-Item -LiteralPath $ReplacedReleaseRoot -Recurse -Force
        }
        catch {
            Write-Warning "Release was published, but the replaced release remains at $ReplacedReleaseRoot."
        }
    }
    Write-Host "Enterprise Agent Windows binary release created."
    Write-Host "Release: $ReleaseRoot"
    Write-Host "Executable: $(Join-Path $ReleaseRoot 'runtime\MineGuardEnterpriseAgent.exe')"
}
finally {
    if (Test-Path -LiteralPath $WorkRoot) {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force
    }
    if (-not $Completed -and (Test-Path -LiteralPath $StageRoot)) {
        Remove-Item -LiteralPath $StageRoot -Recurse -Force
    }
}
