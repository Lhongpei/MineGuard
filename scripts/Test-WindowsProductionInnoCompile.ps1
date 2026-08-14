[CmdletBinding()]
param(
    [string] $InnoCompiler = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT' -or
    $PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSVersion.Minor -lt 1) {
    throw 'The production Inno compile gate requires Windows PowerShell 5.1.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'The production Inno compile gate requires a 64-bit process.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InnoCompiler)) {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $InnoCompiler = $candidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($InnoCompiler) -or
    -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw 'The preinstalled Inno Setup 6 compiler is unavailable.'
}
$InnoCompiler = [IO.Path]::GetFullPath($InnoCompiler)

$assetsRoot = Join-Path $repositoryRoot 'packaging\windows\assets'
$bootstrapPath = Join-Path $assetsRoot `
    'Invoke-MineGuardTrustedProductInstall.ps1'
$platformScript = Join-Path $repositoryRoot `
    'packaging\windows\inno\MineGuardPlatform.iss'
$agentScript = Join-Path $repositoryRoot `
    'packaging\windows\inno\MineGuardEnterpriseAgent.iss'
$auditScript = Join-Path $repositoryRoot `
    'scripts\Test-WindowsBinaryRelease.ps1'
foreach ($required in @(
        $bootstrapPath,
        $platformScript,
        $agentScript,
        $auditScript,
        (Join-Path $assetsRoot 'Windows-binary-release-guide.html'),
        (Join-Path $assetsRoot 'RELEASE-NOTICE.txt'),
        (Join-Path $assetsRoot 'Open-MineGuardPlatformControlCenter.ps1'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Production Inno compile input is missing: $required"
    }
}

$auditTokens = $null
$auditParseErrors = $null
$auditAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $auditScript,
    [ref]$auditTokens,
    [ref]$auditParseErrors
)
if ($auditParseErrors.Count -ne 0) {
    throw 'The release audit cannot be parsed for the production Inno gate.'
}
foreach ($functionName in @(
        'ConvertTo-QuotedNativeArgument',
        'Get-WindowsDiagnosticLogTail',
        'Stop-WindowsProcessTree',
        'Invoke-WindowsGuiProcessAndWait')) {
    $matches = @($auditAst.FindAll({
        param($node)
        $node -is `
            [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
    }, $true))
    if ($matches.Count -ne 1) {
        throw "Expected one $functionName definition, found $($matches.Count)."
    }
    . ([scriptblock]::Create($matches[0].Extent.Text))
}

function New-MinimalStage {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $Root
    )
    $uninstallName = if ($Product -eq 'Platform') {
        'Uninstall-MineGuardPlatformRuntime.ps1'
    } else {
        'Uninstall-EnterpriseAgentRuntime.ps1'
    }
    $sourceUninstaller = if ($Product -eq 'Platform') {
        Join-Path $repositoryRoot `
            'platform\deploy\windows\Uninstall-MineGuardPlatformRuntime.ps1'
    } else {
        Join-Path $repositoryRoot `
            'agent\deploy\windows\Uninstall-EnterpriseAgentRuntime.ps1'
    }
    if (-not (Test-Path -LiteralPath $sourceUninstaller -PathType Leaf)) {
        throw "Production uninstall runner is missing: $sourceUninstaller"
    }
    $deploy = Join-Path $Root 'deploy\windows'
    $runtime = Join-Path $Root 'runtime'
    [void](New-Item -ItemType Directory -Path $deploy,$runtime -Force)
    Copy-Item -LiteralPath $sourceUninstaller `
        -Destination (Join-Path $deploy $uninstallName)
    $runtimeName = if ($Product -eq 'Platform') {
        'MineGuardPlatform.exe'
    } else {
        'MineGuardEnterpriseAgent.exe'
    }
    [IO.File]::WriteAllBytes(
        (Join-Path $runtime $runtimeName), [byte[]]@(77, 90, 0, 0))
    $manifest = Join-Path $Root 'release-manifest.json'
    [IO.File]::WriteAllText(
        $manifest,
        '{"compile_gate":true}',
        (New-Object Text.UTF8Encoding($false)))
    return (Get-FileHash -LiteralPath $manifest `
        -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-ProductionInnoCompile {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $StageRoot,
        [Parameter(Mandatory = $true)] [string] $OutputRoot,
        [Parameter(Mandatory = $true)] [string] $ManifestSha256,
        [switch] $InternalUnsignedRelease
    )
    $scriptPath = if ($Product -eq 'Platform') {
        $platformScript
    } else {
        $agentScript
    }
    $classification = if ($InternalUnsignedRelease) {
        'InternalUnsigned'
    } else {
        'UnsignedTest'
    }
    $artifactName = (
        'MineGuard-' + $Product + '-Production-Iss-Compile-Gate-' +
        $classification
    )
    $bootstrapSha256 = (Get-FileHash -LiteralPath $bootstrapPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $arguments = @(
        '/Qp',
        "/DStageRoot=$StageRoot",
        "/DAssetsRoot=$assetsRoot",
        "/DOutputDir=$OutputRoot",
        '/DAppVersion=0.0.0',
        '/DNumericVersion=0.0.0.0',
        "/DArtifactFileName=$artifactName",
        '/DMinimumWindowsVersion=10.0.17763',
        "/DChildReleaseManifestSha256=$ManifestSha256",
        "/DTrustedBootstrapSha256=$bootstrapSha256"
    )
    if ($InternalUnsignedRelease) {
        $arguments += '/DInternalUnsignedRelease=1'
    }
    $arguments += $scriptPath
    & $InnoCompiler @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Product production Inno script failed with exit code $LASTEXITCODE."
    }
    $artifact = Join-Path $OutputRoot ($artifactName + '.exe')
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf) -or
        (Get-Item -LiteralPath $artifact).Length -le 0) {
        throw "$Product production Inno script created no installer."
    }
    Write-Host (
        "$Product $classification production Inno script compiled successfully."
    )
    return $artifact
}

function Test-InternalUnsignedAuthorizationRejection {
    param(
        [ValidateSet('Platform', 'EnterpriseAgent')] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $Installer,
        [Parameter(Mandatory = $true)] [string] $ProbeRoot
    )
    $installRoot = Join-Path $ProbeRoot ('negative-install-' + $Product)
    $logPath = Join-Path $ProbeRoot ('negative-authorization-' + $Product + '.log')
    $exitCode = Invoke-WindowsGuiProcessAndWait `
        -FilePath $Installer `
        -ArgumentList @(
            '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
            "/DIR=$installRoot", "/LOG=$logPath"
        ) -TimeoutSeconds 30 `
        -OperationLabel "$Product production Inno missing-authorization gate" `
        -DiagnosticLogPath $logPath
    if ($exitCode -ne 7) {
        throw (
            "$Product INTERNAL-UNSIGNED missing-authorization Setup returned " +
            "$exitCode instead of deterministic PrepareToInstall exit code 7."
        )
    }
    if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
        throw "$Product missing-authorization probe created no Inno log."
    }
    $logText = Get-Content -LiteralPath $logPath -Raw
    if ($logText -notmatch 'ALLOWUNSIGNEDINTERNALRELEASE=1') {
        throw (
            "$Product missing-authorization Setup did not reach its " +
            'deterministic PrepareToInstall rejection.'
        )
    }
    if (Test-Path -LiteralPath $installRoot) {
        throw "$Product missing-authorization probe created the install root."
    }
    Write-Host (
        "$Product INTERNAL-UNSIGNED missing-authorization Setup exited " +
        "non-interactively with deterministic code $exitCode."
    )
}

$temporaryParent = [Environment]::GetEnvironmentVariable('RUNNER_TEMP')
if ([string]::IsNullOrWhiteSpace($temporaryParent)) {
    $temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
} else {
    $temporaryParent = [IO.Path]::GetFullPath($temporaryParent).TrimEnd('\')
}
if (-not (Test-Path -LiteralPath $temporaryParent -PathType Container)) {
    throw "Inno compile temporary parent is unavailable: $temporaryParent"
}
$temporaryRoot = Join-Path $temporaryParent (
    'MineGuardProductionInnoCompile-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporaryRoot)
try {
    $outputRoot = Join-Path $temporaryRoot 'out'
    [void](New-Item -ItemType Directory -Path $outputRoot)
    foreach ($product in @('Platform', 'EnterpriseAgent')) {
        $stageRoot = Join-Path $temporaryRoot ('stage-' + $product)
        $manifestSha256 = New-MinimalStage `
            -Product $product -Root $stageRoot
        [void](Invoke-ProductionInnoCompile -Product $product `
            -StageRoot $stageRoot -OutputRoot $outputRoot `
            -ManifestSha256 $manifestSha256)
        $internalInstaller = Invoke-ProductionInnoCompile -Product $product `
            -StageRoot $stageRoot -OutputRoot $outputRoot `
            -ManifestSha256 $manifestSha256 -InternalUnsignedRelease
        Test-InternalUnsignedAuthorizationRejection -Product $product `
            -Installer $internalInstaller -ProbeRoot $temporaryRoot
    }
} finally {
    $full = [IO.Path]::GetFullPath($temporaryRoot).TrimEnd('\')
    $expectedParent = [IO.Path]::GetFullPath($temporaryParent).TrimEnd('\')
    if (-not ([IO.Path]::GetDirectoryName($full)).Equals(
            $expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cnotmatch
            '^MineGuardProductionInnoCompile-[a-f0-9]{32}$') {
        throw "Refusing unsafe Inno compile cleanup: $full"
    }
    if (Test-Path -LiteralPath $full) {
        foreach ($item in @((Get-Item -LiteralPath $full -Force)) + @(
                Get-ChildItem -LiteralPath $full -Force -Recurse)) {
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Inno compile cleanup contains a reparse point: $($item.FullName)"
            }
        }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

Write-Host (
    'Both production Inno scripts passed unsigned-test compilation and ' +
    'INTERNAL-UNSIGNED noninteractive authorization gates.'
)
