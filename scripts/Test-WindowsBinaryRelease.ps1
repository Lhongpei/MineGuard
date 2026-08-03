[CmdletBinding(DefaultParameterSetName = "Release")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Release")][string]$PlatformStage,
    [Parameter(Mandatory = $true, ParameterSetName = "Release")][string]$AgentStage,
    [Parameter(ParameterSetName = "Release")][string]$ArtifactDirectory = "",
    [Parameter(ParameterSetName = "Release")][switch]$RequireSigned,
    [Parameter(ParameterSetName = "Release")][switch]$ExpectUnsignedTestOnly,
    [Parameter(ParameterSetName = "Release")][switch]$SkipRuntimeSmoke,
    [Parameter(ParameterSetName = "Release")][switch]$TestInstallerLifecycle,
    [Parameter(Mandatory = $true, ParameterSetName = "SecretAudit")]
    [ValidateNotNullOrEmpty()][string[]]$SecretAuditRoots
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PYTHONUTF8 = "1"

if ($env:OS -ne "Windows_NT") {
    throw "Windows binary release verification must run on native Windows."
}
if ($RequireSigned -and $ExpectUnsignedTestOnly) {
    throw "RequireSigned and ExpectUnsignedTestOnly are mutually exclusive."
}
if ($TestInstallerLifecycle -and -not $ArtifactDirectory) {
    throw "TestInstallerLifecycle requires ArtifactDirectory."
}

function Get-FullExistingDirectory {
    param([string]$PathValue, [string]$Label)
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if (-not (Test-Path -LiteralPath $FullPath -PathType Container)) {
        throw "$Label does not exist: $FullPath"
    }
    return $FullPath.TrimEnd('\')
}

function Assert-OrdinaryTree {
    param([string]$Root)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release root cannot be a symlink, junction or reparse point: $Root"
    }
    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
}

function Get-RelativeReleasePath {
    param([string]$Root, [string]$FullName)
    return $FullName.Substring($Root.Length + 1).Replace('\', '/')
}

function Assert-SafeRelativePath {
    param([string]$RelativePath)
    $Parts = $RelativePath -split '/'
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.Contains("\") -or $RelativePath.Contains(":") -or
        $Parts -contains "." -or $Parts -contains "..") {
        throw "Unsafe release path: $RelativePath"
    }
}

function Assert-NoDevelopmentOrSecretMaterial {
    param([string]$Root)
    $ForbiddenDirectoryNames = @(".git", "test", "tests", "__pycache__", ".pytest_cache")
    $ForbiddenExtensions = @(
        ".py", ".pyw", ".pyc", ".pyo", ".pyi", ".pyx", ".pxd", ".ipynb",
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".pdb", ".ilk", ".map", ".pfx", ".p12", ".jks", ".key", ".pem"
    )
    $ForbiddenFileNames = @(".env", "id_rsa", "id_ed25519")
    $TextExtensions = @(
        ".txt", ".md", ".json", ".yml", ".yaml", ".ini", ".config",
        ".ps1", ".psm1", ".xml", ".html", ".js", ".css", ".template", ".example"
    )

    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        $Relative = Get-RelativeReleasePath -Root $Root -FullName $Item.FullName
        $Segments = $Relative -split '/'
        if ($Item.PSIsContainer) {
            foreach ($Segment in $Segments) {
                if ($ForbiddenDirectoryNames -contains $Segment.ToLowerInvariant()) {
                    throw "Release contains a forbidden development directory: $Relative"
                }
            }
            continue
        }
        $LowerExtension = $Item.Extension.ToLowerInvariant()
        $LowerName = $Item.Name.ToLowerInvariant()
        if ($ForbiddenExtensions -contains $LowerExtension -or
            $ForbiddenFileNames -contains $LowerName) {
            throw "Release contains forbidden source, debug or secret material: $Relative"
        }
        if ($TextExtensions -contains $LowerExtension -and $Item.Length -le (4 * 1024 * 1024)) {
            $Text = Get-Content -LiteralPath $Item.FullName -Raw -Encoding UTF8
            if ($Text -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----') {
                throw "Release contains a private key block: $Relative"
            }
            if ($Text -match '(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}') {
                throw "Release contains a likely live model API key: $Relative"
            }
            foreach ($Line in ($Text -split "`r?`n")) {
                if ($Line -match '(?i)^\s*["'']?([A-Z0-9_]*(?:API_KEY|PASSWORD|HMAC_SECRET|PRIVATE_KEY)[A-Z0-9_]*)["'']?\s*[:=]\s*["'']?([^"''#,}\s][^"''#,}]*)') {
                    $SensitiveName = [string]$Matches[1]
                    $Value = $Matches[2].Trim()
                    $IsKnownBooleanSwitchExpression = (
                        $SensitiveName.Equals(
                            "allowDemoDefaultPassword",
                            [StringComparison]::OrdinalIgnoreCase
                        ) -and
                        ($LowerExtension -eq ".ps1" -or $LowerExtension -eq ".psm1") -and
                        [regex]::IsMatch(
                            $Value,
                            '^\[(?i:bool)\]\s*\$[A-Za-z_][A-Za-z0-9_]*$'
                        )
                    )
                    $IsPlaceholder = (
                        $Value.StartsWith("<") -or $Value.StartsWith("__") -or
                        $Value.StartsWith("$") -or $Value.StartsWith("%") -or
                        $IsKnownBooleanSwitchExpression -or
                        $Value -match '^(?i:REPLACE|CHANGE[_-]?ME|NOT[_-]?CONFIGURED|NULL|NONE|FALSE|TRUE)'
                    )
                    if (-not $IsPlaceholder) {
                        throw "Release contains a non-placeholder value for ${SensitiveName}: $Relative"
                    }
                }
            }
        }
    }
}

function Test-ChildReleaseManifest {
    param(
        [string]$StageRoot,
        [string]$ExpectedProduct,
        [string]$ExpectedEntrypoint
    )
    Assert-OrdinaryTree -Root $StageRoot
    Assert-NoDevelopmentOrSecretMaterial -Root $StageRoot
    $ManifestPath = Join-Path $StageRoot "release-manifest.json"
    $ChecksumsPath = Join-Path $StageRoot "SHA256SUMS.txt"
    $VersionPath = Join-Path $StageRoot "VERSION.txt"
    $MetadataPath = Join-Path $StageRoot "build-metadata.json"
    foreach ($RequiredPath in @($ManifestPath, $ChecksumsPath, $VersionPath, $MetadataPath)) {
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "Release is missing required trace metadata: $RequiredPath"
        }
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Version = (Get-Content -LiteralPath $VersionPath -Raw -Encoding UTF8).Trim()
    if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "Invalid product version in VERSION.txt: $Version"
    }
    if ([string]$Manifest.product -ne $ExpectedProduct -or
        [string]$Manifest.version -ne $Version -or
        [string]$Manifest.architecture -ne "x64" -or
        [string]$Manifest.entrypoint -ne $ExpectedEntrypoint) {
        throw "Child release manifest identity does not match $ExpectedProduct."
    }

    $ExpectedFiles = @{}
    foreach ($Entry in @($Manifest.files)) {
        $Relative = [string]$Entry.path
        Assert-SafeRelativePath -RelativePath $Relative
        if ($ExpectedFiles.ContainsKey($Relative)) {
            throw "Duplicate path in release manifest: $Relative"
        }
        if ([string]$Entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "Invalid SHA-256 in release manifest: $Relative"
        }
        $ExpectedFiles[$Relative] = $Entry
    }
    $ActualFiles = @{}
    foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Force -Recurse) {
        $Relative = Get-RelativeReleasePath -Root $StageRoot -FullName $File.FullName
        if ($Relative -in @("release-manifest.json", "SHA256SUMS.txt")) {
            continue
        }
        $ActualFiles[$Relative] = $File
    }
    if ($ExpectedFiles.Count -ne $ActualFiles.Count) {
        throw "Release file set does not match release-manifest.json for $ExpectedProduct."
    }
    foreach ($Relative in $ExpectedFiles.Keys) {
        if (-not $ActualFiles.ContainsKey($Relative)) {
            throw "Manifest file is missing: $Relative"
        }
        $File = $ActualFiles[$Relative]
        $Entry = $ExpectedFiles[$Relative]
        if ([long]$Entry.bytes -ne [long]$File.Length) {
            throw "Manifest size mismatch: $Relative"
        }
        $Hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
        if (-not $Hash.Equals([string]$Entry.sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Manifest SHA-256 mismatch: $Relative"
        }
    }

    $ChecksumEntries = @{}
    foreach ($Line in Get-Content -LiteralPath $ChecksumsPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        if ($Line -notmatch '^([A-Fa-f0-9]{64}) [ *](.+)$') {
            throw "Malformed SHA256SUMS.txt line: $Line"
        }
        $Relative = $Matches[2]
        Assert-SafeRelativePath -RelativePath $Relative
        if ($ChecksumEntries.ContainsKey($Relative)) {
            throw "Duplicate checksum path: $Relative"
        }
        $ChecksumEntries[$Relative] = $Matches[1]
    }
    $ChecksumFiles = @(Get-ChildItem -LiteralPath $StageRoot -File -Force -Recurse |
        Where-Object { (Get-RelativeReleasePath -Root $StageRoot -FullName $_.FullName) -ne "SHA256SUMS.txt" })
    if ($ChecksumEntries.Count -ne $ChecksumFiles.Count) {
        throw "SHA256SUMS.txt does not cover the exact release file set."
    }
    foreach ($File in $ChecksumFiles) {
        $Relative = Get-RelativeReleasePath -Root $StageRoot -FullName $File.FullName
        if (-not $ChecksumEntries.ContainsKey($Relative)) {
            throw "SHA256SUMS.txt is missing: $Relative"
        }
        $Hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
        if (-not $Hash.Equals([string]$ChecksumEntries[$Relative], [StringComparison]::OrdinalIgnoreCase)) {
            throw "SHA256SUMS.txt mismatch: $Relative"
        }
    }

    $Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$Metadata.python -notmatch '^3\.12(?:\.|$)' -or
        [string]$Metadata.nuitka -notmatch '^4\.1\.3(?:\b|$)') {
        throw "$ExpectedProduct was not built with the approved CPython 3.12 / Nuitka 4.1.3 toolchain."
    }
    $Entrypoint = Join-Path $StageRoot ($ExpectedEntrypoint.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $Entrypoint -PathType Leaf)) {
        throw "Release entrypoint is missing: $Entrypoint"
    }
    return [pscustomobject]@{
        root = $StageRoot
        version = $Version
        executable = $Entrypoint
        metadata = $Metadata
    }
}

function Assert-AuthenticodeClassification {
    param([string]$PathValue)
    $Signature = Get-AuthenticodeSignature -LiteralPath $PathValue
    if ($RequireSigned) {
        if ($Signature.Status -ne "Valid" -or $null -eq $Signature.TimeStamperCertificate) {
            throw "A valid timestamped Authenticode signature is required: $PathValue"
        }
    }
    elseif ($ExpectUnsignedTestOnly) {
        if ($Signature.Status -ne "NotSigned") {
            throw "Unsigned test input unexpectedly has Authenticode status $($Signature.Status): $PathValue"
        }
    }
    return [string]$Signature.Status
}

function Get-FreeLoopbackPort {
    $Listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $Listener.Start()
    try { return ([Net.IPEndPoint]$Listener.LocalEndpoint).Port }
    finally { $Listener.Stop() }
}

function ConvertTo-QuotedNativeArgument {
    param([string]$Value)
    if ($Value.Length -eq 0) { return '""' }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-ExecutableChecked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Executable returned ${LASTEXITCODE}: $Executable $($Arguments -join ' ')"
    }
}

function Invoke-ExecutableJsonChecked {
    param([string]$Executable, [string[]]$Arguments)
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = (($Arguments | ForEach-Object {
        ConvertTo-QuotedNativeArgument -Value ([string]$_)
    }) -join " ")
    $StartInfo.WorkingDirectory = Split-Path -Parent $Executable
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $Utf8 = New-Object Text.UTF8Encoding($false)
    $StartInfo.StandardOutputEncoding = $Utf8
    $StartInfo.StandardErrorEncoding = $Utf8
    foreach ($EnvironmentName in @($StartInfo.EnvironmentVariables.Keys)) {
        if ([string]$EnvironmentName -match '(?i)(API[_-]?KEY|PASSWORD|HMAC[_-]?SECRET|ACCESS[_-]?TOKEN)') {
            $StartInfo.EnvironmentVariables.Remove([string]$EnvironmentName)
        }
    }
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        if (-not $Process.Start()) {
            throw "Failed to start JSON command: $Executable"
        }
        $StandardOutputTask = $Process.StandardOutput.ReadToEndAsync()
        $StandardErrorTask = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit(240000)) {
            $Process.Kill()
            $Process.WaitForExit()
            $TimedOutError = $StandardErrorTask.Result
            throw "Executable did not finish within 240 seconds: $Executable $($Arguments -join ' ')`n$TimedOutError"
        }
        $StandardOutput = $StandardOutputTask.Result
        $StandardError = $StandardErrorTask.Result
        if ($Process.ExitCode -ne 0) {
            throw "Executable returned $($Process.ExitCode): $Executable $($Arguments -join ' ')`n$StandardError"
        }
        if ([string]::IsNullOrWhiteSpace($StandardOutput)) {
            throw "Executable returned no JSON: $Executable $($Arguments -join ' ')"
        }
        try {
            return $StandardOutput | ConvertFrom-Json
        }
        catch {
            throw "Executable returned invalid JSON: $Executable $($Arguments -join ' ')`n$StandardOutput"
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Assert-PlatformDemoSeed {
    param([string]$Executable, [string]$StatePath, [string]$EvidencePath)
    $Seed = Invoke-ExecutableJsonChecked -Executable $Executable -Arguments @(
        "seed-v2-demo", "--state-directory", $StatePath,
        "--through-month", "2026-07-31"
    )
    [IO.File]::WriteAllText(
        $EvidencePath,
        ($Seed | ConvertTo-Json -Depth 20),
        (New-Object Text.UTF8Encoding($false))
    )
    if ([string]$Seed.status -ne "seeded" -or
        -not [bool]$Seed.synthetic_demo -or
        [int]$Seed.mine_count -ne 8 -or
        [int]$Seed.submission_count -ne 24 -or
        [int]$Seed.created_submission_count -ne 24 -or
        [int]$Seed.replayed_submission_count -ne 0 -or
        [string]$Seed.period_start -ne "2026-05-01" -or
        [string]$Seed.period_end -ne "2026-07-31") {
        throw "Platform frozen runtime did not create the exact fresh 8-mine/24-submission V2 demo dataset."
    }
    $ExpectedDecisionCounts = @{
        insufficient_data = 1
        normal_candidate = 19
        risk = 4
    }
    $ActualDecisionProperties = @($Seed.decision_counts.PSObject.Properties)
    if ($ActualDecisionProperties.Count -ne $ExpectedDecisionCounts.Count) {
        throw "Platform V2 demo returned an unexpected decision category set."
    }
    foreach ($Decision in $ExpectedDecisionCounts.Keys) {
        $Property = $Seed.decision_counts.PSObject.Properties[$Decision]
        if ($null -eq $Property -or [int]$Property.Value -ne $ExpectedDecisionCounts[$Decision]) {
            throw "Platform V2 demo decision count mismatch for $Decision."
        }
    }
    $Scenarios = @($Seed.scenarios)
    $MineIds = @($Scenarios | ForEach-Object { [string]$_.mine_id } | Sort-Object -Unique)
    $ScenarioSubmissionCount = ($Scenarios | Measure-Object -Property submission_count -Sum).Sum
    if ($Scenarios.Count -ne 8 -or $MineIds.Count -ne 8 -or [int]$ScenarioSubmissionCount -ne 24) {
        throw "Platform V2 demo did not persist three real submissions for each of eight distinct mines."
    }
    foreach ($Scenario in $Scenarios) {
        $DecisionTotal = (@($Scenario.decisions.PSObject.Properties) |
            Measure-Object -Property Value -Sum).Sum
        if ([int]$Scenario.submission_count -ne 3 -or [int]$DecisionTotal -ne 3) {
            throw "Platform V2 demo scenario $($Scenario.mine_id) is not backed by three analyzed submissions."
        }
    }
    $LatestDecisions = @($Scenarios | ForEach-Object {
        [string]$_.latest_decision
    } | Sort-Object -Unique)
    foreach ($RequiredDecision in @("normal_candidate", "risk", "insufficient_data")) {
        if ($RequiredDecision -notin $LatestDecisions) {
            throw "Platform V2 demo lacks a latest $RequiredDecision teaching scenario."
        }
    }
    $SignalCodes = @($Scenarios | ForEach-Object {
        @($_.signal_codes) | ForEach-Object { [string]$_ }
    } | Sort-Object -Unique)
    foreach ($RequiredSignal in @(
        "daily_shift_arithmetic_mismatch",
        "sustained_ratio_drift",
        "retrospective_change_point"
    )) {
        if ($RequiredSignal -notin $SignalCodes) {
            throw "Platform V2 demo did not exercise required engine signal $RequiredSignal."
        }
    }
    $ReferenceBases = @($Scenarios | ForEach-Object {
        @($_.reference_bases) | ForEach-Object { [string]$_ }
    } | Sort-Object -Unique)
    if ("anonymous_peer" -notin $ReferenceBases) {
        throw "Platform V2 demo did not exercise the anonymous peer comparison path."
    }
    $ExpectedDatabase = [IO.Path]::GetFullPath((Join-Path $StatePath "mineguard.db"))
    if (-not (Test-Path -LiteralPath $ExpectedDatabase -PathType Leaf) -or
        [IO.Path]::GetFullPath([string]$Seed.database_path) -ne $ExpectedDatabase) {
        throw "Platform V2 demo JSON does not point to the persisted SQLite state."
    }
}

function Invoke-RuntimeSmoke {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$Executable,
        [string]$WorkingStateRoot = ""
    )
    Invoke-ExecutableChecked -Executable $Executable -Arguments @("--version")
    Invoke-ExecutableChecked -Executable $Executable -Arguments @("--help")
    $RuntimeRoot = Split-Path -Parent $Executable
    $CreatedTemporaryRoot = $false
    if (-not $WorkingStateRoot) {
        $UnicodeLeaf = "MineGuard release " + [char]0x5BA1 + [char]0x8BA1 + " " + [Guid]::NewGuid().ToString("N")
        $WorkingStateRoot = Join-Path ([IO.Path]::GetTempPath()) $UnicodeLeaf
        $CreatedTemporaryRoot = $true
    }
    $WorkingStateRoot = [IO.Path]::GetFullPath($WorkingStateRoot)
    New-Item -ItemType Directory -Path $WorkingStateRoot -Force | Out-Null
    $SmokeRoot = Join-Path $WorkingStateRoot ("runtime-smoke-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $SmokeRoot -Force | Out-Null
    $StdoutPath = Join-Path $SmokeRoot "$Product-stdout.log"
    $StderrPath = Join-Path $SmokeRoot "$Product-stderr.log"
    $Port = Get-FreeLoopbackPort
    if ($Product -eq "platform") {
        $StatePath = Join-Path $SmokeRoot "platform state"
        $Arguments = @(
            "serve", "--host", "127.0.0.1", "--port", [string]$Port,
            "--state-directory", $StatePath, "--admin-username", "release-audit", "--no-auth"
        )
        $HealthUrl = "http://127.0.0.1:$Port/healthz"
    }
    else {
        $DatabasePath = Join-Path $SmokeRoot "enterprise agent.db"
        $Arguments = @("--db", $DatabasePath, "serve", "--host", "127.0.0.1", "--port", [string]$Port)
        $HealthUrl = "http://127.0.0.1:$Port/api/v1/health"
    }
    $ArgumentLine = (($Arguments | ForEach-Object { ConvertTo-QuotedNativeArgument -Value ([string]$_) }) -join " ")
    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Executable
    $StartInfo.Arguments = $ArgumentLine
    $StartInfo.WorkingDirectory = $RuntimeRoot
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($EnvironmentName in @($StartInfo.EnvironmentVariables.Keys)) {
        if ([string]$EnvironmentName -match '(?i)(API[_-]?KEY|PASSWORD|HMAC[_-]?SECRET|ACCESS[_-]?TOKEN)') {
            $StartInfo.EnvironmentVariables.Remove([string]$EnvironmentName)
        }
    }
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    $ProcessStarted = $false
    $RuntimeStandardOutputTask = $null
    $RuntimeStandardErrorTask = $null
    try {
        if ($Product -eq "platform") {
            Assert-PlatformDemoSeed `
                -Executable $Executable `
                -StatePath $StatePath `
                -EvidencePath (Join-Path $SmokeRoot "platform-seed-evidence.json")
        }
        if (-not $Process.Start()) {
            throw "Failed to start $Product runtime."
        }
        $ProcessStarted = $true
        $RuntimeStandardOutputTask = $Process.StandardOutput.ReadToEndAsync()
        $RuntimeStandardErrorTask = $Process.StandardError.ReadToEndAsync()
        $Deadline = [DateTime]::UtcNow.AddSeconds(45)
        $Healthy = $false
        while ([DateTime]::UtcNow -lt $Deadline) {
            if ($Process.HasExited) {
                $ErrorOutput = $RuntimeStandardErrorTask.Result
                throw "$Product runtime exited with $($Process.ExitCode): $ErrorOutput"
            }
            try {
                $Response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2
                if ([int]$Response.StatusCode -eq 200) {
                    $Healthy = $true
                    break
                }
            }
            catch { Start-Sleep -Milliseconds 250 }
        }
        if (-not $Healthy) {
            throw "$Product runtime did not become healthy within 45 seconds."
        }
    }
    finally {
        if ($ProcessStarted -and -not $Process.HasExited) {
            $Process.Kill()
            $Process.WaitForExit(5000) | Out-Null
        }
        if ($ProcessStarted) {
            $StandardOutput = $RuntimeStandardOutputTask.Result
            $StandardError = $RuntimeStandardErrorTask.Result
            [IO.File]::WriteAllText($StdoutPath, $StandardOutput)
            [IO.File]::WriteAllText($StderrPath, $StandardError)
        }
        $Process.Dispose()
        if ($CreatedTemporaryRoot -and (Test-Path -LiteralPath $WorkingStateRoot)) {
            Remove-Item -LiteralPath $WorkingStateRoot -Recurse -Force
        }
    }
    Write-Host "$Product standalone runtime smoke test passed."
}

function Test-RootArtifactManifest {
    param([string]$ArtifactsRoot)
    Assert-OrdinaryTree -Root $ArtifactsRoot
    Assert-NoDevelopmentOrSecretMaterial -Root $ArtifactsRoot
    $ManifestPath = Join-Path $ArtifactsRoot "release-manifest.json"
    $SumsPath = Join-Path $ArtifactsRoot "SHA256SUMS.txt"
    foreach ($Required in @($ManifestPath, $SumsPath)) {
        if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
            throw "Installer release is missing: $Required"
        }
    }
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$Manifest.format -ne "mineguard-windows-installers-v1") {
        throw "Unsupported root Windows release manifest."
    }
    $ExpectedClassification = if ($RequireSigned) { "signed-production-candidate" } else { "unsigned-test-artifacts" }
    if (($RequireSigned -or $ExpectUnsignedTestOnly) -and [string]$Manifest.classification -ne $ExpectedClassification) {
        throw "Root release classification mismatch."
    }
    if ($RequireSigned) {
        $WheelhouseEvidence = $Manifest.wheelhouse_supply_chain
        $ActualManifestSha256 = [string]$WheelhouseEvidence.manifest_sha256
        $ExpectedManifestSha256 = [string]$WheelhouseEvidence.expected_manifest_sha256
        if (-not [bool]$WheelhouseEvidence.verified -or
            -not [bool]$WheelhouseEvidence.external_trust_anchor_verified -or
            $ActualManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            $ExpectedManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            -not $ActualManifestSha256.Equals($ExpectedManifestSha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Signed root release lacks a verified external wheelhouse-manifest trust anchor."
        }
    }
    $Installers = @($Manifest.installers)
    if ($Installers.Count -ne 2) {
        throw "Root release must contain exactly two independent installers."
    }
    $SeenProducts = @{}
    foreach ($Entry in $Installers) {
        $Relative = [string]$Entry.file
        Assert-SafeRelativePath -RelativePath $Relative
        $InstallerPath = Join-Path $ArtifactsRoot $Relative
        if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
            throw "Installer listed in root manifest is missing: $Relative"
        }
        if ([IO.Path]::GetExtension($InstallerPath) -ne ".exe") {
            throw "Installer artifact must be an EXE: $Relative"
        }
        if ($ExpectUnsignedTestOnly -and $Relative -notmatch 'UNSIGNED-TEST-ONLY') {
            throw "Unsigned installer filename lacks the required UNSIGNED-TEST-ONLY marker: $Relative"
        }
        if ($RequireSigned -and $Relative -match 'UNSIGNED-TEST-ONLY') {
            throw "A signed production candidate uses an unsigned-test filename: $Relative"
        }
        $Hash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Hash -ne ([string]$Entry.sha256).ToLowerInvariant()) {
            throw "Root manifest installer SHA-256 mismatch: $Relative"
        }
        $SignatureStatus = Assert-AuthenticodeClassification -PathValue $InstallerPath
        if ([string]$Entry.authenticode_status -ne $SignatureStatus) {
            throw "Recorded Authenticode status does not match the installer: $Relative"
        }
        $ActualSignerThumbprint = if ($null -ne (Get-AuthenticodeSignature -LiteralPath $InstallerPath).SignerCertificate) {
            (((Get-AuthenticodeSignature -LiteralPath $InstallerPath).SignerCertificate.Thumbprint) -replace '\s', '').ToUpperInvariant()
        } else { "" }
        $RecordedSignerThumbprint = (([string]$Entry.signer_thumbprint) -replace '\s', '').ToUpperInvariant()
        if ($ActualSignerThumbprint -ne $RecordedSignerThumbprint) {
            throw "Recorded signer thumbprint does not match the installer: $Relative"
        }
        if ($RequireSigned) {
            $RootSignerThumbprint = (([string]$Manifest.authenticode_signing.normalized_signer_thumbprint) -replace '\s', '').ToUpperInvariant()
            if ($RootSignerThumbprint -notmatch '^[A-F0-9]{40}$' -or $ActualSignerThumbprint -ne $RootSignerThumbprint) {
                throw "Signed installer does not match the root manifest signer thumbprint: $Relative"
            }
        }
        $ProductId = [string]$Entry.product_id
        if ($ProductId -notin @("platform", "enterprise-agent") -or $SeenProducts.ContainsKey($ProductId)) {
            throw "Root manifest has an invalid or duplicate product_id: $ProductId"
        }
        $SeenProducts[$ProductId] = $InstallerPath
    }
    $SumEntries = @{}
    foreach ($Line in Get-Content -LiteralPath $SumsPath -Encoding UTF8) {
        if ($Line -notmatch '^([A-Fa-f0-9]{64}) [ *](.+)$') {
            throw "Malformed root SHA256SUMS.txt line: $Line"
        }
        $SumEntries[$Matches[2]] = $Matches[1]
    }
    $ExpectedSumFiles = @($Installers | ForEach-Object { [string]$_.file }) + @("release-manifest.json")
    if ($SumEntries.Count -ne $ExpectedSumFiles.Count) {
        throw "Root SHA256SUMS.txt must cover exactly both installers and release-manifest.json."
    }
    foreach ($Relative in $ExpectedSumFiles) {
        if (-not $SumEntries.ContainsKey($Relative)) {
            throw "Root SHA256SUMS.txt is missing $Relative"
        }
        $Hash = (Get-FileHash -LiteralPath (Join-Path $ArtifactsRoot $Relative) -Algorithm SHA256).Hash
        if (-not $Hash.Equals([string]$SumEntries[$Relative], [StringComparison]::OrdinalIgnoreCase)) {
            throw "Root SHA256SUMS.txt mismatch: $Relative"
        }
    }
    $ExpectedArtifactFiles = @($ExpectedSumFiles) + @("SHA256SUMS.txt")
    $ActualArtifactFiles = @(Get-ChildItem -LiteralPath $ArtifactsRoot -File -Force -Recurse |
        ForEach-Object { Get-RelativeReleasePath -Root $ArtifactsRoot -FullName $_.FullName })
    if ($ActualArtifactFiles.Count -ne $ExpectedArtifactFiles.Count) {
        throw "Installer artifact directory contains an extra or missing file."
    }
    foreach ($Relative in $ActualArtifactFiles) {
        if ($Relative -notin $ExpectedArtifactFiles) {
            throw "Installer artifact directory contains an undeclared file: $Relative"
        }
    }
    return [pscustomobject]@{ manifest = $Manifest; installers = $SeenProducts }
}

function New-ServiceStateProbe {
    param([string]$ServiceName, [string]$ProbeRoot)
    if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        throw "Release lifecycle runner is not isolated; probe service name already exists: $ServiceName"
    }
    $ProbeExecutable = Join-Path $ProbeRoot "MineGuardServiceStateProbe.exe"
    if (-not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) {
        $TypeName = "MineGuardServiceStateProbe" + [Guid]::NewGuid().ToString("N")
        $Source = @'
using System;
using System.ServiceProcess;

public sealed class __TYPE_NAME__ : ServiceBase
{
    private __TYPE_NAME__(string serviceName)
    {
        ServiceName = serviceName;
        CanStop = true;
        AutoLog = false;
    }

    public static void Main(string[] args)
    {
        if (args.Length != 1) Environment.Exit(2);
        ServiceBase.Run(new __TYPE_NAME__(args[0]));
    }
}
'@
        $Source = $Source.Replace("__TYPE_NAME__", $TypeName)
        Add-Type `
            -TypeDefinition $Source `
            -ReferencedAssemblies "System.ServiceProcess.dll" `
            -OutputAssembly $ProbeExecutable `
            -OutputType ConsoleApplication
    }
    $BinaryPath = '"' + $ProbeExecutable + '" ' + $ServiceName
    & sc.exe create $ServiceName "binPath=" $BinaryPath "start=" "demand" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create the exact lifecycle probe service: $ServiceName"
    }
    $Service = Get-Service -Name $ServiceName
    if ($Service.Status -ne "Stopped") {
        throw "New lifecycle probe service was not Stopped."
    }
    return $Service
}

function Remove-ServiceStateProbe {
    param([string]$ServiceName)
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $Service) { return }
    if ($Service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $Service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    $Service.Dispose()
    & sc.exe delete $ServiceName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to delete lifecycle probe service: $ServiceName"
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "Lifecycle probe service registration did not disappear: $ServiceName"
}

function Invoke-InstallerLifecycleTest {
    param([string]$Product, [string]$Installer)
    $Identity = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $Identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Installer lifecycle verification requires an elevated Administrator runner."
    }
    $VerificationParent = Join-Path $env:ProgramData "MineGuardReleaseVerification"
    $VerificationRoot = Join-Path $VerificationParent ([Guid]::NewGuid().ToString("N"))
    $InstallLeaf = if ($Product -eq "platform") { "Platform" } else { "EnterpriseAgent" }
    $InstallRoot = Join-Path $VerificationRoot $InstallLeaf
    $AgentStateRoot = Join-Path $VerificationRoot "EnterpriseAgentInstances"
    $ServiceName = if ($Product -eq "platform") {
        "MineGuardPlatform"
    } else {
        "MineGuardEnterpriseAgent-ci-" + [Guid]::NewGuid().ToString("N").Substring(0, 10)
    }
    New-Item -ItemType Directory -Path $VerificationRoot -Force | Out-Null
    try {
        $ProbeService = New-ServiceStateProbe -ServiceName $ServiceName -ProbeRoot $VerificationRoot
        $InstallArguments = @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/DIR=$InstallRoot", "/LOG=$(Join-Path $VerificationRoot 'install.log')")
        if ($Product -eq "agent") {
            $InstallArguments += "/STATE_ROOT=$AgentStateRoot"
        }
        & $Installer @InstallArguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Product installer rejected a registered but Stopped service with exit code $LASTEXITCODE."
        }
        $RuntimeExecutable = if ($Product -eq "platform") {
            Join-Path $InstallRoot "runtime\MineGuardPlatform.exe"
        } else {
            Join-Path $InstallRoot "runtime\MineGuardEnterpriseAgent.exe"
        }
        $OperationsDirectory = if ($Product -eq "platform") {
            Join-Path $InstallRoot "service"
        } else {
            Join-Path $InstallRoot "deploy\windows"
        }
        foreach ($Required in @($RuntimeExecutable, $OperationsDirectory, (Join-Path $InstallRoot "release-metadata"))) {
            if (-not (Test-Path -LiteralPath $Required)) {
                throw "$Product install is missing required runtime/operations/trace content: $Required"
            }
        }
        $PreservationRoot = if ($Product -eq "platform") { $InstallRoot } else { Join-Path $AgentStateRoot "ci-preservation" }
        foreach ($DirectoryName in @("config", "state", "backups", "logs")) {
            $Directory = Join-Path $PreservationRoot $DirectoryName
            New-Item -ItemType Directory -Path $Directory -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $Directory "ci-state-sentinel.txt"), "preserve-$Product")
        }
        if ($Product -eq "platform") {
            $ConfigurationScript = Join-Path $OperationsDirectory `
                "Set-MineGuardPlatformConfiguration.ps1"
            $InitialClients = Join-Path $VerificationRoot "clients-initial.json"
            $ChangedClients = Join-Path $VerificationRoot "clients-changed.json"
            $InitialRegistry = [ordered]@{
                clients = @([ordered]@{
                    sender_id = "agent-ci-mine-001"
                    party_id = "operator-ci-mine-001"
                    mine_id = "MINE-CI-001"
                    mine_name = "Windows release audit mine"
                    active_message_key_id = "ci-key-v1"
                    message_keys = [ordered]@{
                        "ci-key-v1" = "ci-message-secret-material-000000000001"
                    }
                    transport_secrets = @(
                        "ci-transport-secret-material-0000000001"
                    )
                })
            }
            $ChangedRegistry = [ordered]@{
                clients = @([ordered]@{
                    sender_id = "agent-ci-mine-001"
                    party_id = "operator-ci-mine-001"
                    mine_id = "MINE-CI-001"
                    mine_name = "Windows release audit mine changed"
                    active_message_key_id = "ci-key-v2"
                    message_keys = [ordered]@{
                        "ci-key-v2" = "changed-message-secret-material-000000001"
                    }
                    transport_secrets = @(
                        "changed-transport-secret-material-0000001"
                    )
                })
            }
            $NoBom = New-Object Text.UTF8Encoding($false)
            [IO.File]::WriteAllText(
                $InitialClients,
                ($InitialRegistry | ConvertTo-Json -Depth 8),
                $NoBom
            )
            [IO.File]::WriteAllText(
                $ChangedClients,
                ($ChangedRegistry | ConvertTo-Json -Depth 8),
                $NoBom
            )
            $InitialPassword = ConvertTo-SecureString `
                "MineGuard-CI-Initial-123!" -AsPlainText -Force
            & $ConfigurationScript -InstallRoot $InstallRoot `
                -ClientsFile $InitialClients -AdminPassword $InitialPassword `
                -NonInteractive
            $ConfigRoot = Join-Path $InstallRoot "config"
            $ProtectedConfiguration = @(
                (Join-Path $ConfigRoot "clients.json"),
                (Join-Path $ConfigRoot "bootstrap-admin-password.txt"),
                (Join-Path $ConfigRoot "settings.json")
            )
            $BeforeConfigurationHashes = @{}
            foreach ($ConfigFile in $ProtectedConfiguration) {
                if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
                    throw "Platform initial configuration did not create: $ConfigFile"
                }
                $BeforeConfigurationHashes[$ConfigFile] = (
                    Get-FileHash -LiteralPath $ConfigFile -Algorithm SHA256
                ).Hash
            }
            $ChangedPassword = ConvertTo-SecureString `
                "MineGuard-CI-Changed-456!" -AsPlainText -Force
            $PreviousAuditMode = $env:MINEGUARD_RELEASE_AUDIT_MODE
            $ConfigurationFailureObserved = $false
            try {
                $env:MINEGUARD_RELEASE_AUDIT_MODE = "configuration-rollback-test"
                & $ConfigurationScript -InstallRoot $InstallRoot `
                    -ClientsFile $ChangedClients -AdminPassword $ChangedPassword `
                    -NonInteractive -AuditFailAfterFirstMutation
            }
            catch {
                $ConfigurationFailureObserved = $true
            }
            finally {
                if ($null -eq $PreviousAuditMode) {
                    Remove-Item Env:MINEGUARD_RELEASE_AUDIT_MODE `
                        -ErrorAction SilentlyContinue
                }
                else {
                    $env:MINEGUARD_RELEASE_AUDIT_MODE = $PreviousAuditMode
                }
            }
            if (-not $ConfigurationFailureObserved) {
                throw "Platform configuration fault injection did not fail."
            }
            foreach ($ConfigFile in $ProtectedConfiguration) {
                $AfterHash = (Get-FileHash -LiteralPath $ConfigFile `
                    -Algorithm SHA256).Hash
                if ($AfterHash -ne $BeforeConfigurationHashes[$ConfigFile]) {
                    throw "Platform configuration rollback changed protected content: $ConfigFile"
                }
            }
            $LeakedConfigurationTransaction = Get-ChildItem `
                -LiteralPath $ConfigRoot -Directory -Force | Where-Object {
                    $_.Name -like ".configuration-transaction.*"
                } | Select-Object -First 1
            if ($null -ne $LeakedConfigurationTransaction) {
                throw "Platform configuration rollback leaked: $($LeakedConfigurationTransaction.FullName)"
            }
        }
        Invoke-RuntimeSmoke -Product $Product -Executable $RuntimeExecutable -WorkingStateRoot (Join-Path $PreservationRoot "state")
        $Uninstallers = @(Get-ChildItem -LiteralPath $InstallRoot -Filter "unins*.exe" -File)
        if ($Uninstallers.Count -ne 1) {
            throw "$Product install must contain exactly one Inno uninstaller."
        }

        Start-Service -Name $ServiceName
        $ProbeService.WaitForStatus("Running", [TimeSpan]::FromSeconds(20))
        $RunningUpgradeArguments = @($InstallArguments | Where-Object { $_ -notlike "/LOG=*" })
        $RunningUpgradeArguments += "/LOG=$(Join-Path $VerificationRoot 'running-upgrade-rejection.log')"
        & $Installer @RunningUpgradeArguments
        if ($LASTEXITCODE -eq 0) {
            throw "$Product installer accepted an upgrade while its service was Running."
        }
        Stop-Service -Name $ServiceName -Force
        $ProbeService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
        $ProbeService.Dispose()

        & $Uninstallers[0].FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
        if ($LASTEXITCODE -eq 0) {
            throw "$Product uninstaller accepted a still-registered service."
        }
        if (-not (Test-Path -LiteralPath $RuntimeExecutable -PathType Leaf)) {
            throw "$Product refused uninstall removed runtime despite the registered service."
        }
        Remove-ServiceStateProbe -ServiceName $ServiceName

        $ForegroundPort = Get-FreeLoopbackPort
        $ForegroundState = Join-Path $PreservationRoot "state\foreground-blocking-test"
        New-Item -ItemType Directory -Path $ForegroundState -Force | Out-Null
        if ($Product -eq "platform") {
            $ForegroundArguments = @(
                "serve", "--host", "127.0.0.1", "--port", [string]$ForegroundPort,
                "--state-directory", $ForegroundState, "--admin-username", "release-audit", "--no-auth"
            )
            $ForegroundHealth = "http://127.0.0.1:$ForegroundPort/healthz"
        } else {
            $ForegroundArguments = @(
                "--db", (Join-Path $ForegroundState "enterprise-agent.db"),
                "serve", "--host", "127.0.0.1", "--port", [string]$ForegroundPort
            )
            $ForegroundHealth = "http://127.0.0.1:$ForegroundPort/api/v1/health"
        }
        $ForegroundInfo = New-Object Diagnostics.ProcessStartInfo
        $ForegroundInfo.FileName = $RuntimeExecutable
        $ForegroundInfo.Arguments = (($ForegroundArguments | ForEach-Object {
            ConvertTo-QuotedNativeArgument -Value ([string]$_)
        }) -join " ")
        $ForegroundInfo.WorkingDirectory = Split-Path -Parent $RuntimeExecutable
        $ForegroundInfo.UseShellExecute = $false
        $ForegroundInfo.CreateNoWindow = $true
        $ForegroundInfo.RedirectStandardOutput = $true
        $ForegroundInfo.RedirectStandardError = $true
        foreach ($EnvironmentName in @($ForegroundInfo.EnvironmentVariables.Keys)) {
            if ([string]$EnvironmentName -match '(?i)(API[_-]?KEY|PASSWORD|HMAC[_-]?SECRET|ACCESS[_-]?TOKEN)') {
                $ForegroundInfo.EnvironmentVariables.Remove([string]$EnvironmentName)
            }
        }
        $ForegroundProcess = New-Object Diagnostics.Process
        $ForegroundProcess.StartInfo = $ForegroundInfo
        $ForegroundStarted = $false
        $ForegroundStandardOutputTask = $null
        $ForegroundStandardErrorTask = $null
        try {
            if (-not $ForegroundProcess.Start()) { throw "Unable to start foreground runtime probe." }
            $ForegroundStarted = $true
            $ForegroundStandardOutputTask = $ForegroundProcess.StandardOutput.ReadToEndAsync()
            $ForegroundStandardErrorTask = $ForegroundProcess.StandardError.ReadToEndAsync()
            $ForegroundDeadline = [DateTime]::UtcNow.AddSeconds(45)
            $ForegroundHealthy = $false
            while ([DateTime]::UtcNow -lt $ForegroundDeadline) {
                if ($ForegroundProcess.HasExited) {
                    throw "$Product foreground runtime probe exited unexpectedly: $($ForegroundStandardErrorTask.Result)"
                }
                try {
                    $Response = Invoke-WebRequest -Uri $ForegroundHealth -UseBasicParsing -TimeoutSec 2
                    if ([int]$Response.StatusCode -eq 200) { $ForegroundHealthy = $true; break }
                } catch { Start-Sleep -Milliseconds 250 }
            }
            if (-not $ForegroundHealthy) { throw "$Product foreground runtime probe was not healthy." }

            $ForegroundUpgradeArguments = @($InstallArguments | Where-Object { $_ -notlike "/LOG=*" })
            $ForegroundUpgradeArguments += "/LOG=$(Join-Path $VerificationRoot 'foreground-upgrade-rejection.log')"
            & $Installer @ForegroundUpgradeArguments
            if ($LASTEXITCODE -eq 0) {
                throw "$Product installer accepted an upgrade while its exact foreground runtime was active."
            }
            & $Uninstallers[0].FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
            if ($LASTEXITCODE -eq 0) {
                throw "$Product uninstaller accepted an active foreground runtime."
            }
            if (-not (Test-Path -LiteralPath $RuntimeExecutable -PathType Leaf)) {
                throw "$Product refused foreground uninstall removed the active runtime."
            }
        }
        finally {
            if ($ForegroundStarted -and -not $ForegroundProcess.HasExited) {
                $ForegroundProcess.Kill()
                $ForegroundProcess.WaitForExit(5000) | Out-Null
            }
            if ($ForegroundStarted) {
                $ForegroundStandardOutputTask.Wait(5000) | Out-Null
                $ForegroundStandardErrorTask.Wait(5000) | Out-Null
            }
            $ForegroundProcess.Dispose()
        }
        & $Uninstallers[0].FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
        if ($LASTEXITCODE -ne 0) {
            throw "$Product uninstaller returned $LASTEXITCODE."
        }
        $PathsExpectedRemoved = @(
            (Join-Path $InstallRoot "runtime"),
            (Join-Path $InstallRoot "deploy"),
            (Join-Path $InstallRoot "service"),
            (Join-Path $InstallRoot "release-metadata")
        )
        $RemovalDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $RemainingPaths = @($PathsExpectedRemoved | Where-Object { Test-Path -LiteralPath $_ })
            if ($RemainingPaths.Count -eq 0) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $RemovalDeadline)
        foreach ($RemovedPath in $PathsExpectedRemoved) {
            if (Test-Path -LiteralPath $RemovedPath) {
                throw "$Product uninstall left immutable runtime/deployment content: $RemovedPath"
            }
        }
        foreach ($DirectoryName in @("config", "state", "backups", "logs")) {
            $Sentinel = Join-Path (Join-Path $PreservationRoot $DirectoryName) "ci-state-sentinel.txt"
            if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
                throw "$Product uninstall removed preserved operational state: $Sentinel"
            }
        }
        Write-Host "$Product silent install, health and state-preserving uninstall passed."
    }
    finally {
        Remove-ServiceStateProbe -ServiceName $ServiceName
        if (Test-Path -LiteralPath $VerificationRoot) {
            $FullVerificationRoot = [IO.Path]::GetFullPath($VerificationRoot)
            $FullParent = [IO.Path]::GetFullPath($VerificationParent).TrimEnd('\') + '\'
            if (-not $FullVerificationRoot.StartsWith($FullParent, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing unsafe lifecycle cleanup path: $FullVerificationRoot"
            }
            Remove-Item -LiteralPath $FullVerificationRoot -Recurse -Force
        }
    }
}

if ($PSCmdlet.ParameterSetName -eq "SecretAudit") {
    foreach ($SecretAuditRoot in $SecretAuditRoots) {
        $ResolvedAuditRoot = Get-FullExistingDirectory `
            -PathValue $SecretAuditRoot -Label "SecretAuditRoot"
        Assert-OrdinaryTree -Root $ResolvedAuditRoot
        Assert-NoDevelopmentOrSecretMaterial -Root $ResolvedAuditRoot
    }
    Write-Host "MineGuard Windows release text safety preflight passed."
    return
}

$PlatformStage = Get-FullExistingDirectory -PathValue $PlatformStage -Label "PlatformStage"
$AgentStage = Get-FullExistingDirectory -PathValue $AgentStage -Label "AgentStage"
$PlatformRelease = Test-ChildReleaseManifest `
    -StageRoot $PlatformStage `
    -ExpectedProduct "MineGuard Platform" `
    -ExpectedEntrypoint "runtime/MineGuardPlatform.exe"
$AgentRelease = Test-ChildReleaseManifest `
    -StageRoot $AgentStage `
    -ExpectedProduct "MineGuard Enterprise Agent" `
    -ExpectedEntrypoint "runtime/MineGuardEnterpriseAgent.exe"

Assert-AuthenticodeClassification -PathValue $PlatformRelease.executable | Out-Null
Assert-AuthenticodeClassification -PathValue $AgentRelease.executable | Out-Null
if (-not $SkipRuntimeSmoke) {
    Invoke-RuntimeSmoke -Product platform -Executable $PlatformRelease.executable
    Invoke-RuntimeSmoke -Product agent -Executable $AgentRelease.executable
}

if ($ArtifactDirectory) {
    $ArtifactDirectory = Get-FullExistingDirectory -PathValue $ArtifactDirectory -Label "ArtifactDirectory"
    $RootRelease = Test-RootArtifactManifest -ArtifactsRoot $ArtifactDirectory
    if ($TestInstallerLifecycle) {
        Invoke-InstallerLifecycleTest -Product platform -Installer $RootRelease.installers["platform"]
        Invoke-InstallerLifecycleTest -Product agent -Installer $RootRelease.installers["enterprise-agent"]
    }
}

Write-Host "MineGuard Windows binary release verification passed."
