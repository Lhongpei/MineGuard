[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InnoCompiler,
    [Parameter(Mandatory = $true)][string]$PlatformStage,
    [Parameter(Mandatory = $true)][string]$AgentStage,
    [string]$AssetsRoot = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
if ([string]::IsNullOrWhiteSpace($AssetsRoot)) {
    $AssetsRoot = Join-Path (Split-Path -Parent $PSScriptRoot) `
        "packaging\windows\assets"
}

if ($env:OS -ne "Windows_NT") {
    throw "Installer failure-propagation verification must run on Windows."
}
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$InnoCompiler = [IO.Path]::GetFullPath($InnoCompiler)
foreach ($PathValue in @($InnoCompiler, $PlatformStage, $AgentStage, $AssetsRoot)) {
    if (-not (Test-Path -LiteralPath $PathValue)) {
        throw "Failure-propagation test input is missing: $PathValue"
    }
}

function Invoke-NativeChecked {
    param([string]$FilePath, [object[]]$ArgumentList, [string]$Label)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function ConvertTo-WindowsCommandLineArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $Builder = New-Object -TypeName System.Text.StringBuilder
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

function Test-IsTransientAccessDenied {
    param([Exception]$Exception)
    $CurrentException = $Exception
    while ($null -ne $CurrentException) {
        if ($CurrentException -is [UnauthorizedAccessException] -or
            ($CurrentException -is [ComponentModel.Win32Exception] -and
                $CurrentException.NativeErrorCode -eq 5) -or
            $CurrentException.HResult -eq -2147024891) {
            return $true
        }
        $CurrentException = $CurrentException.InnerException
    }
    return $Exception.Message -match '(?i)access (?:is )?denied'
}

function Invoke-ProcessTreeWithTransientAccessRetry {
    param(
        [string]$FilePath,
        [object[]]$ArgumentList,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )
    $SerializedArguments = @(foreach ($Argument in $ArgumentList) {
        if ($null -eq $Argument) {
            throw "Native process contains a null argument: $FilePath"
        }
        ConvertTo-WindowsCommandLineArgument -Value ([string]$Argument)
    }) -join " "
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        $Process = $null
        try {
            $Process = Start-Process -FilePath $FilePath `
                -ArgumentList $SerializedArguments -Wait -PassThru `
                -ErrorAction Stop
            return [int]$Process.ExitCode
        }
        catch {
            if (-not (Test-IsTransientAccessDenied -Exception $_.Exception) -or
                [DateTime]::UtcNow -ge $Deadline) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
        finally {
            if ($null -ne $Process) { $Process.Dispose() }
        }
    }
}

function Remove-DirectoryWithRetry {
    param(
        [string]$PathValue,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $LastCleanupError = $null
    while ($true) {
        if (-not (Test-Path -LiteralPath $PathValue)) { return }
        try {
            Remove-Item -LiteralPath $PathValue -Recurse -Force -ErrorAction Stop
        }
        catch {
            $LastCleanupError = $_
        }
        if (-not (Test-Path -LiteralPath $PathValue)) { return }
        if ([DateTime]::UtcNow -ge $Deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $FailureDetail = if ($null -eq $LastCleanupError) {
        "the directory still exists"
    }
    else {
        $LastCleanupError.Exception.Message
    }
    throw (
        "Failure-probe cleanup did not finish within $TimeoutSeconds seconds: " +
        "$PathValue. Last error: $FailureDetail"
    )
}

function Remove-FileWithRetry {
    param(
        [string]$PathValue,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $LastCleanupError = $null
    while ($true) {
        if (-not (Test-Path -LiteralPath $PathValue)) { return }
        try {
            Remove-Item -LiteralPath $PathValue -Force -ErrorAction Stop
        }
        catch {
            $LastCleanupError = $_
        }
        if (-not (Test-Path -LiteralPath $PathValue)) { return }
        if ([DateTime]::UtcNow -ge $Deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $FailureDetail = if ($null -eq $LastCleanupError) {
        "the file still exists"
    }
    else {
        $LastCleanupError.Exception.Message
    }
    throw (
        "Failure-probe file cleanup did not finish within $TimeoutSeconds " +
        "seconds: $PathValue. Last error: $FailureDetail"
    )
}

function Wait-ProcessExecutableVisible {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
    )
    $ExpectedPath = [IO.Path]::GetFullPath($ExecutablePath)
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Process = Get-CimInstance Win32_Process `
            -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if ($null -ne $Process -and
            -not [string]::IsNullOrWhiteSpace([string]$Process.ExecutablePath)) {
            $ActualPath = [IO.Path]::GetFullPath([string]$Process.ExecutablePath)
            if ($ActualPath.Equals(
                    $ExpectedPath, [StringComparison]::OrdinalIgnoreCase
                )) {
                return
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Process $ProcessId was not visible through CIM at $ExpectedPath."
}

function Write-FailureProbeLog {
    param([string]$Product, [string]$LogPath)
    if (-not (Test-Path -LiteralPath $LogPath)) {
        Write-Warning "$Product failure-probe Inno log was not created: $LogPath"
        return
    }
    Write-Host "--- $Product failure-probe Inno log (diagnostic only) ---"
    Get-Content -LiteralPath $LogPath | ForEach-Object { Write-Host $_ }
    Write-Host "--- end $Product failure-probe Inno log ---"
}

function Write-FailureProbeReleaseIntegrity {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$StageRoot,
        [string]$OriginalManifestPath
    )
    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    $ManifestPath = Join-Path $StageRoot "release-manifest.json"
    $ChecksumsPath = Join-Path $StageRoot "SHA256SUMS.txt"
    $Manifest = Get-Content -LiteralPath $OriginalManifestPath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    $ManifestEntries = @()
    foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse -Force |
        Where-Object {
            $Relative = $_.FullName.Substring($StageRoot.Length + 1).Replace('\', '/')
            $Relative -notin @("release-manifest.json", "SHA256SUMS.txt")
        } | Sort-Object FullName) {
        $Relative = $File.FullName.Substring($StageRoot.Length + 1).Replace('\', '/')
        $ManifestEntries += [ordered]@{
            path = $Relative
            bytes = [long]$File.Length
            sha256 = (Get-FileHash -LiteralPath $File.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $Manifest.files = $ManifestEntries
    [IO.File]::WriteAllText(
        $ManifestPath,
        (($Manifest | ConvertTo-Json -Depth 50) + [Environment]::NewLine),
        $Utf8NoBom
    )

    $ChecksumLines = @()
    foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse -Force |
        Where-Object {
            $_.FullName.Substring($StageRoot.Length + 1).Replace('\', '/') -ne
                "SHA256SUMS.txt"
        } | Sort-Object FullName) {
        $Relative = $File.FullName.Substring($StageRoot.Length + 1).Replace('\', '/')
        $Digest = (Get-FileHash -LiteralPath $File.FullName `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        $Separator = if ($Product -eq "agent") { " *" } else { "  " }
        $ChecksumLines += "$Digest$Separator$Relative"
    }
    [IO.File]::WriteAllLines($ChecksumsPath, $ChecksumLines, $Utf8NoBom)
    return (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
}

function Test-OneFailureProbe {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$OriginalStage,
        [string]$InnoScript,
        [string]$Version,
        [string]$ProbeRoot
    )
    $CorruptStage = Join-Path $ProbeRoot "c"
    $ProbeOutput = Join-Path $ProbeRoot "o"
    $InstallRoot = Join-Path $ProbeRoot "i"
    $ProbeLog = Join-Path $ProbeRoot "f.log"
    New-Item -ItemType Directory -Path $ProbeRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $CorruptStage | Out-Null
    New-Item -ItemType Directory -Path $ProbeOutput | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $CorruptStage "runtime") | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $CorruptStage "deploy\windows") -Force | Out-Null
    foreach ($MetadataName in @("VERSION.txt", "build-metadata.json", "release-manifest.json", "SHA256SUMS.txt")) {
        Copy-Item -LiteralPath (Join-Path $OriginalStage $MetadataName) -Destination $CorruptStage
    }
    if ($Product -eq "agent") {
        Copy-Item -LiteralPath (Join-Path $OriginalStage `
            "model-credential-trust.json") -Destination $CorruptStage
    }
    foreach ($DeployFile in Get-ChildItem -LiteralPath (Join-Path $OriginalStage "deploy\windows") -Force) {
        Copy-Item -LiteralPath $DeployFile.FullName -Destination (Join-Path $CorruptStage "deploy\windows") -Recurse
    }
    $PlaceholderName = if ($Product -eq "platform") { "MineGuardPlatform.exe" } else { "MineGuardEnterpriseAgent.exe" }
    [IO.File]::WriteAllText(
        (Join-Path (Join-Path $CorruptStage "runtime") $PlaceholderName),
        "not-an-executable; the guarded manifest check must reject this tiny failure probe"
    )
    [IO.File]::WriteAllText(
        (Join-Path $CorruptStage "VERSION.txt"),
        ($Version + "-deliberately-tampered" + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    $ChildReleaseManifestSha256 = Write-FailureProbeReleaseIntegrity `
        -Product $Product -StageRoot $CorruptStage `
        -OriginalManifestPath (Join-Path $OriginalStage "release-manifest.json")
    $TrustedBootstrapSha256 = (Get-FileHash -LiteralPath (Join-Path $AssetsRoot `
        "Invoke-MineGuardTrustedProductInstall.ps1") -Algorithm SHA256).Hash
    $ArtifactBase = "MineGuard-$Product-FailurePropagationProbe"
    $CompileArguments = @(
        "/Qp",
        "/DStageRoot=$CorruptStage",
        "/DAssetsRoot=$AssetsRoot",
        "/DOutputDir=$ProbeOutput",
        "/DAppVersion=$Version",
        "/DNumericVersion=$Version.0",
        "/DArtifactFileName=$ArtifactBase",
        "/DChildReleaseManifestSha256=$ChildReleaseManifestSha256",
        "/DTrustedBootstrapSha256=$TrustedBootstrapSha256",
        $InnoScript
    )
    Invoke-NativeChecked -FilePath $InnoCompiler -ArgumentList $CompileArguments -Label "$Product negative-probe compilation"
    $ProbeInstaller = Join-Path $ProbeOutput ($ArtifactBase + ".exe")
    $InstallArguments = @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
        "/DIR=$InstallRoot", "/LOG=$ProbeLog"
    )
    # Both fixture installers are intentionally compiled without signing. The
    # explicit flag keeps this negative test on the unsigned-test path.
    $InstallArguments += "/ALLOW_UNSIGNED_TEST_MEDIA=1"
    if ($Product -eq "agent") {
        $InstallArguments += "/STATE_ROOT=$(Join-Path $ProbeRoot 's')"
    }
    $ProbeExitCode = Invoke-ProcessTreeWithTransientAccessRetry `
        -FilePath $ProbeInstaller -ArgumentList $InstallArguments `
        -TimeoutSeconds 30
    if ($ProbeExitCode -eq 0) {
        Write-FailureProbeLog -Product $Product -LogPath $ProbeLog
        throw "$Product corrupted staging was incorrectly accepted by the installer."
    }
    if ($ProbeExitCode -ne 1001) {
        Write-FailureProbeLog -Product $Product -LogPath $ProbeLog
        throw (
            "$Product corrupted staging returned unexpected installer exit code " +
            "$ProbeExitCode instead of guarded product failure code 1001."
        )
    }
    foreach ($ImmutableDirectory in @("runtime", "release-metadata", "deploy", "service")) {
        if (Test-Path -LiteralPath (Join-Path $InstallRoot $ImmutableDirectory)) {
            Write-FailureProbeLog -Product $Product -LogPath $ProbeLog
            throw (
                "$Product failed setup left installed product directory " +
                "$ImmutableDirectory after manifest rejection."
            )
        }
    }
    Write-Host "$Product installer propagated the guarded product-installer failure (exit $ProbeExitCode)."
}

function Invoke-ProductInstallerExpectFailure {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$InstallScript,
        [string]$OriginalStage,
        [string]$InstallRoot,
        [string]$StateRoot,
        [switch]$InjectAfterSwitch,
        [string]$FailureKind = "guarded failure",
        [string]$ExpectedOutputPattern = ""
    )
    $Arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $InstallScript
    )
    if ($Product -eq "platform") {
        $Arguments += @("-SourceDirectory", $OriginalStage, "-InstallRoot", $InstallRoot)
    }
    else {
        $Arguments += @(
            "-SourceRoot", $OriginalStage,
            "-InstallRoot", $InstallRoot,
            "-StateRoot", $StateRoot
        )
    }
    $BuildMetadata = Get-Content -LiteralPath (Join-Path $OriginalStage `
        "build-metadata.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $ReleaseClassification = if ($Product -eq "platform") {
        [string]$BuildMetadata.releaseClassification
    }
    else {
        [string]$BuildMetadata.release_classification
    }
    switch ($ReleaseClassification) {
        "signed-production-candidate" {
            if ($Product -eq "agent") {
                $ApprovedSignerThumbprint = [string](
                    $BuildMetadata.signing_certificate_thumbprint
                )
                if ($ApprovedSignerThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
                    throw "Agent signed failure probe has no valid approved signer thumbprint."
                }
                $Arguments += @(
                    "-ApprovedSignerThumbprint", $ApprovedSignerThumbprint
                )
            }
        }
        "unsigned-internal-release" {
            $ReleaseManifestSha256 = (Get-FileHash -LiteralPath (Join-Path `
                $OriginalStage "release-manifest.json") -Algorithm SHA256).Hash
            $Arguments += @(
                "-AllowUnsignedInternalRelease",
                "-ExpectedReleaseManifestSha256", $ReleaseManifestSha256
            )
        }
        "unsigned-test-artifacts" {
            if ($Product -ne "platform") {
                throw "Only the Platform uses unsigned-test-artifacts classification."
            }
        }
        "unsigned-test-only" {
            if ($Product -ne "agent") {
                throw "Only the Agent uses unsigned-test-only classification."
            }
            $Arguments += "-AllowUnsignedTestMedia"
        }
        default {
            throw "$Product failure probe found unsupported release classification: $ReleaseClassification"
        }
    }
    if ($InjectAfterSwitch) {
        $Arguments += "-AuditFailAfterRuntimeSwitch"
    }
    $PreviousAuditMode = $env:MINEGUARD_RELEASE_AUDIT_MODE
    $ChildOutput = @()
    $ExitCode = $null
    try {
        if ($InjectAfterSwitch) {
            $env:MINEGUARD_RELEASE_AUDIT_MODE = "installer-rollback-test"
        }
        else {
            $env:MINEGUARD_RELEASE_AUDIT_MODE = "installer-guard-test"
        }
        $PreviousNativeErrorActionPreference = $ErrorActionPreference
        try {
            # Windows PowerShell 5.1 can promote redirected native stderr when
            # ErrorActionPreference is Stop. Capture this expected failing child
            # under Continue, then make the decision solely from its exit code.
            $ErrorActionPreference = "Continue"
            $ChildOutput = @(& powershell.exe @Arguments 2>&1)
            $ExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $PreviousNativeErrorActionPreference
        }
    }
    finally {
        if ($null -eq $PreviousAuditMode) {
            Remove-Item Env:MINEGUARD_RELEASE_AUDIT_MODE -ErrorAction SilentlyContinue
        }
        else {
            $env:MINEGUARD_RELEASE_AUDIT_MODE = $PreviousAuditMode
        }
    }
    foreach ($Line in $ChildOutput) {
        Write-Host ([string]$Line)
    }
    if ($null -eq $ExitCode) {
        throw "$Product product installer did not produce an exit code for the $FailureKind probe."
    }
    if ($ExitCode -eq 0) {
        throw "$Product product installer incorrectly accepted the $FailureKind probe."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedOutputPattern)) {
        $ChildOutputText = ($ChildOutput | Out-String)
        if ($ChildOutputText -notmatch $ExpectedOutputPattern) {
            throw (
                "$Product product installer failed before reaching the expected " +
                "$FailureKind checkpoint. Required output pattern: " +
                $ExpectedOutputPattern
            )
        }
    }
    return $ExitCode
}

function Get-ProductTreeSnapshot {
    param([string]$RuntimeRoot, [string]$OperationsRoot, [string]$MetadataRoot)
    $Snapshot = @{}
    foreach ($Definition in @(
        [pscustomobject]@{ Prefix = "runtime"; Root = $RuntimeRoot },
        [pscustomobject]@{ Prefix = "operations"; Root = $OperationsRoot },
        [pscustomobject]@{ Prefix = "metadata"; Root = $MetadataRoot }
    )) {
        foreach ($Directory in Get-ChildItem -LiteralPath $Definition.Root `
            -Directory -Recurse -Force) {
            $Relative = ($Directory.FullName.Substring(
                $Definition.Root.Length
            )).TrimStart('\').Replace('\', '/')
            $Key = "$($Definition.Prefix)/$Relative/"
            if ($Snapshot.ContainsKey($Key)) {
                throw "Duplicate rollback snapshot path: $Key"
            }
            $Snapshot[$Key] = "<directory>"
        }
        foreach ($File in Get-ChildItem -LiteralPath $Definition.Root `
            -File -Recurse -Force) {
            $Relative = ($File.FullName.Substring(
                $Definition.Root.Length
            )).TrimStart('\').Replace('\', '/')
            $Key = "$($Definition.Prefix)/$Relative"
            if ($Snapshot.ContainsKey($Key)) {
                throw "Duplicate rollback snapshot path: $Key"
            }
            $Snapshot[$Key] = (Get-FileHash -LiteralPath $File.FullName `
                -Algorithm SHA256).Hash
        }
    }
    return $Snapshot
}

function Assert-ProductTreeSnapshot {
    param(
        [hashtable]$Expected,
        [string]$RuntimeRoot,
        [string]$OperationsRoot,
        [string]$MetadataRoot,
        [string]$Label
    )
    $Actual = Get-ProductTreeSnapshot -RuntimeRoot $RuntimeRoot `
        -OperationsRoot $OperationsRoot -MetadataRoot $MetadataRoot
    if ($Expected.Count -ne $Actual.Count) {
        throw "$Label changed the prior file set. Expected $($Expected.Count), found $($Actual.Count)."
    }
    foreach ($Key in $Expected.Keys) {
        if (-not $Actual.ContainsKey($Key) -or $Actual[$Key] -ne $Expected[$Key]) {
            throw "$Label failed to restore the prior file and hash: $Key"
        }
    }
}

function Test-OneTransactionalRollbackAndDowngrade {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$OriginalStage,
        [string]$Version,
        [string]$ProbeRoot
    )
    $InstallRoot = Join-Path $ProbeRoot "i"
    $StateRoot = Join-Path $ProbeRoot "s"
    $RuntimeRoot = Join-Path $InstallRoot "runtime"
    $MetadataRoot = Join-Path $InstallRoot "release-metadata"
    $OperationsRoot = if ($Product -eq "platform") {
        Join-Path $InstallRoot "service"
    }
    else {
        Join-Path $InstallRoot "deploy\windows"
    }
    foreach ($Directory in @($RuntimeRoot, $MetadataRoot, $OperationsRoot, $StateRoot)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }
    if ($Product -eq "platform") {
        foreach ($Name in @("config", "state", "backups", "logs")) {
            $Directory = Join-Path $InstallRoot $Name
            New-Item -ItemType Directory -Path $Directory -Force | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $Directory "prior-$Name-sentinel.txt"),
                "preserve-$Product-$Name"
            )
        }
    }
    $InstalledVersion = Join-Path $MetadataRoot "VERSION.txt"
    $PriorSnapshot = $null
    $Sentinels = @()
    if ($Product -eq "agent") {
        foreach ($Item in Get-ChildItem -LiteralPath (
            Join-Path $OriginalStage "runtime"
        ) -Force) {
            Copy-Item -LiteralPath $Item.FullName -Destination $RuntimeRoot -Recurse
        }
        foreach ($Item in Get-ChildItem -LiteralPath (
            Join-Path $OriginalStage "deploy\windows"
        ) -Force) {
            Copy-Item -LiteralPath $Item.FullName -Destination $OperationsRoot -Recurse
        }
        foreach ($MetadataName in @(
            "VERSION.txt", "build-metadata.json", "release-manifest.json",
            "SHA256SUMS.txt", "model-credential-trust.json"
        )) {
            Copy-Item -LiteralPath (Join-Path $OriginalStage $MetadataName) `
                -Destination $MetadataRoot
        }
        New-Item -ItemType Directory `
            -Path (Join-Path $RuntimeRoot ".prior-install-identity") | Out-Null
        $PriorSnapshot = Get-ProductTreeSnapshot -RuntimeRoot $RuntimeRoot `
            -OperationsRoot $OperationsRoot -MetadataRoot $MetadataRoot
    }
    else {
        $Sentinels = @(
            (Join-Path $RuntimeRoot "prior-runtime-sentinel.txt"),
            (Join-Path $OperationsRoot "prior-operations-sentinel.txt"),
            (Join-Path $MetadataRoot "prior-metadata-sentinel.txt")
        )
        foreach ($Sentinel in $Sentinels) {
            [IO.File]::WriteAllText($Sentinel, "preserve-$Product")
        }
        [IO.File]::WriteAllText(
            $InstalledVersion,
            ($Version + [Environment]::NewLine),
            (New-Object Text.UTF8Encoding($false))
        )
        $PriorSnapshot = Get-ProductTreeSnapshot -RuntimeRoot $RuntimeRoot `
            -OperationsRoot $OperationsRoot -MetadataRoot $MetadataRoot
    }
    $InstallScriptName = if ($Product -eq "platform") {
        "Install-MineGuardPlatform.ps1"
    }
    else {
        "Install-EnterpriseAgent.ps1"
    }
    $InstallScript = Join-Path $OriginalStage "deploy\windows\$InstallScriptName"
    $PostSwitchExit = Invoke-ProductInstallerExpectFailure `
        -Product $Product -InstallScript $InstallScript `
        -OriginalStage $OriginalStage -InstallRoot $InstallRoot `
        -StateRoot $StateRoot -InjectAfterSwitch `
        -FailureKind "post-switch audit fault" `
        -ExpectedOutputPattern ([regex]::Escape(
            "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-post-switch"
        ))

    $NewExecutable = if ($Product -eq "platform") {
        Join-Path $RuntimeRoot "MineGuardPlatform.exe"
    }
    else {
        Join-Path $RuntimeRoot "MineGuardEnterpriseAgent.exe"
    }
    if ($Product -eq "platform") {
        Assert-ProductTreeSnapshot -Expected $PriorSnapshot `
            -RuntimeRoot $RuntimeRoot -OperationsRoot $OperationsRoot `
            -MetadataRoot $MetadataRoot -Label "Platform post-switch rollback"
        foreach ($Sentinel in $Sentinels) {
            if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
                throw "$Product post-switch rollback did not restore prior content: $Sentinel"
            }
        }
        if (Test-Path -LiteralPath $NewExecutable -PathType Leaf) {
            throw "$Product post-switch failure left the candidate executable active."
        }
        if (Test-Path -LiteralPath (Join-Path $InstallRoot "config\settings.json")) {
            throw "Platform post-switch rollback left a newly created settings.json."
        }
        foreach ($Name in @("config", "state", "backups", "logs")) {
            $Sentinel = Join-Path $InstallRoot "$Name\prior-$Name-sentinel.txt"
            if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
                throw "Platform rollback removed preserved operational state: $Sentinel"
            }
        }
    }
    else {
        Assert-ProductTreeSnapshot -Expected $PriorSnapshot `
            -RuntimeRoot $RuntimeRoot -OperationsRoot $OperationsRoot `
            -MetadataRoot $MetadataRoot -Label "Agent post-switch rollback"
    }
    $LeakedTransactionDirectory = Get-ChildItem -LiteralPath $InstallRoot -Directory -Force |
        Where-Object {
            $_.Name -match '^\.(?:runtime|service|deploy|release-metadata)[.-](?:incoming|previous|stage|rollback)'
        } | Select-Object -First 1
    if ($null -ne $LeakedTransactionDirectory) {
        throw "$Product rollback leaked a transaction directory: $($LeakedTransactionDirectory.FullName)"
    }

    $LegacyProcessExecutable = Join-Path $RuntimeRoot "legacy-python.exe"
    Copy-Item -LiteralPath "$env:SystemRoot\System32\PING.EXE" `
        -Destination $LegacyProcessExecutable
    $LegacyProcess = $null
    try {
        $LegacyProcess = Start-Process -FilePath $LegacyProcessExecutable `
            -ArgumentList @("-t", "127.0.0.1") -WindowStyle Hidden -PassThru
        if ($LegacyProcess.HasExited) {
            throw "$Product legacy-runtime process probe exited before the installer check."
        }
        Wait-ProcessExecutableVisible -ProcessId $LegacyProcess.Id `
            -ExecutablePath $LegacyProcessExecutable
        [void](Invoke-ProductInstallerExpectFailure `
            -Product $Product -InstallScript $InstallScript `
            -OriginalStage $OriginalStage -InstallRoot $InstallRoot `
            -StateRoot $StateRoot `
            -FailureKind "running legacy runtime process" `
            -ExpectedOutputPattern ([regex]::Escape(
                "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-runtime-process"
            )))
    }
    finally {
        if ($null -ne $LegacyProcess -and -not $LegacyProcess.HasExited) {
            Stop-Process -Id $LegacyProcess.Id -Force
            $LegacyProcess.WaitForExit()
        }
        Remove-FileWithRetry -PathValue $LegacyProcessExecutable
    }

    $CandidateExecutable = if ($Product -eq "platform") {
        Join-Path $OriginalStage "runtime\MineGuardPlatform.exe"
    }
    else {
        Join-Path $OriginalStage "runtime\MineGuardEnterpriseAgent.exe"
    }
    if ($Product -eq "platform") {
        Copy-Item -LiteralPath $CandidateExecutable -Destination $NewExecutable
    }
    Remove-Item -LiteralPath $InstalledVersion -Force
    try {
        [void](Invoke-ProductInstallerExpectFailure `
            -Product $Product -InstallScript $InstallScript `
            -OriginalStage $OriginalStage -InstallRoot $InstallRoot `
            -StateRoot $StateRoot `
            -FailureKind "active binary with missing release metadata" `
            -ExpectedOutputPattern ([regex]::Escape(
                "MINEGUARD_RELEASE_AUDIT_MARKER=$Product-missing-metadata"
            )))
    }
    finally {
        if ($Product -eq "platform") {
            Remove-Item -LiteralPath $NewExecutable -Force -ErrorAction SilentlyContinue
        }
        else {
            Copy-Item -LiteralPath (Join-Path $OriginalStage "VERSION.txt") `
                -Destination $InstalledVersion
        }
    }

    if ($Product -eq "platform") {
        [IO.File]::WriteAllText(
            $InstalledVersion,
            "999.0.0$([Environment]::NewLine)",
            (New-Object Text.UTF8Encoding($false))
        )
        $DowngradeExit = Invoke-ProductInstallerExpectFailure `
            -Product $Product -InstallScript $InstallScript `
            -OriginalStage $OriginalStage -InstallRoot $InstallRoot `
            -StateRoot $StateRoot -FailureKind "downgrade" `
            -ExpectedOutputPattern ([regex]::Escape(
                "MINEGUARD_RELEASE_AUDIT_MARKER=platform-downgrade"
            ))
        foreach ($Sentinel in $Sentinels) {
            if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
                throw "$Product downgrade rejection changed prior content: $Sentinel"
            }
        }
        if (Test-Path -LiteralPath $NewExecutable -PathType Leaf) {
            throw "$Product downgrade rejection installed the older candidate executable."
        }
        Write-Host (
            "$Product post-switch rollback (exit $PostSwitchExit) and downgrade rejection " +
            "(exit $DowngradeExit) passed."
        )
    }
    else {
        Assert-ProductTreeSnapshot -Expected $PriorSnapshot `
            -RuntimeRoot $RuntimeRoot -OperationsRoot $OperationsRoot `
            -MetadataRoot $MetadataRoot -Label "Agent missing-metadata rejection"
        Write-Host (
            "$Product post-switch rollback (exit $PostSwitchExit), legacy-process " +
            "rejection and missing-metadata rejection passed."
        )
    }
}

$ProbeParent = Join-Path ([IO.Path]::GetTempPath()) "mgfp"
New-Item -ItemType Directory -Path $ProbeParent -Force | Out-Null
$ProbeRoot = Join-Path $ProbeParent (
    "p-" + [Guid]::NewGuid().ToString("N").Substring(0, 16)
)
New-Item -ItemType Directory -Path $ProbeRoot | Out-Null
$FailurePropagationCompleted = $false
try {
    $PlatformVersion = (Get-Content -LiteralPath (Join-Path $PlatformStage "VERSION.txt") -Raw -Encoding UTF8).Trim()
    $AgentVersion = (Get-Content -LiteralPath (Join-Path $AgentStage "VERSION.txt") -Raw -Encoding UTF8).Trim()
    Test-OneFailureProbe `
        -Product platform -OriginalStage $PlatformStage `
        -InnoScript (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardPlatform.iss") `
        -Version $PlatformVersion -ProbeRoot (Join-Path $ProbeRoot "pf")
    Test-OneFailureProbe `
        -Product agent -OriginalStage $AgentStage `
        -InnoScript (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardEnterpriseAgent.iss") `
        -Version $AgentVersion -ProbeRoot (Join-Path $ProbeRoot "af")
    Test-OneTransactionalRollbackAndDowngrade `
        -Product platform -OriginalStage $PlatformStage `
        -Version $PlatformVersion -ProbeRoot (Join-Path $ProbeRoot "pt")
    Test-OneTransactionalRollbackAndDowngrade `
        -Product agent -OriginalStage $AgentStage `
        -Version $AgentVersion -ProbeRoot (Join-Path $ProbeRoot "at")
    $FailurePropagationCompleted = $true
}
finally {
    try {
        if (Test-Path -LiteralPath $ProbeRoot) {
            $FullProbeRoot = [IO.Path]::GetFullPath($ProbeRoot)
            $FullProbeParent = [IO.Path]::GetFullPath($ProbeParent).TrimEnd('\') + '\'
            if (-not $FullProbeRoot.StartsWith($FullProbeParent, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing unsafe failure-probe cleanup path: $FullProbeRoot"
            }
            Remove-DirectoryWithRetry `
                -PathValue $FullProbeRoot -TimeoutSeconds 30
        }
    }
    catch {
        if ($FailurePropagationCompleted) { throw }
        Write-Warning (
            "Failure-probe cleanup also failed after the primary audit failure: " +
            $_.Exception.Message
        )
    }
}

Write-Host "MineGuard installer failure propagation verification passed."
