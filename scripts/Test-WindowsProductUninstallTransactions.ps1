[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:OS -ne "Windows_NT") {
    throw "The product uninstall transaction probe must run on Windows."
}
if ($PSVersionTable.PSEdition -ne "Desktop" -or
    $PSVersionTable.PSVersion -lt [version]"5.1" -or
    $PSVersionTable.PSVersion.Major -ge 6) {
    throw "The product uninstall transaction probe requires Windows PowerShell 5.1."
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
    throw "The product uninstall transaction probe requires an elevated token."
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "RUNNER_TEMP is required for the isolated uninstall probe."
}

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$PlatformRunner = Join-Path $RepositoryRoot `
    "platform\deploy\windows\Uninstall-MineGuardPlatformRuntime.ps1"
$AgentRunner = Join-Path $RepositoryRoot `
    "agent\deploy\windows\Uninstall-EnterpriseAgentRuntime.ps1"
foreach ($Runner in @($PlatformRunner, $AgentRunner)) {
    if (-not (Test-Path -LiteralPath $Runner -PathType Leaf)) {
        throw "A production uninstall transaction runner is missing: $Runner"
    }
}

$ProbeParent = Join-Path $env:RUNNER_TEMP `
    "MineGuardProductUninstallTransactionProbe"
$ProbeRoot = Join-Path $ProbeParent ([Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $ProbeRoot -Force | Out-Null
$ProbeRoot = [IO.Path]::GetFullPath($ProbeRoot).TrimEnd('\')
$ExpectedParent = [IO.Path]::GetFullPath($ProbeParent).TrimEnd('\')
if (-not ([IO.Path]::GetDirectoryName($ProbeRoot)).Equals(
        $ExpectedParent, [StringComparison]::OrdinalIgnoreCase
    ) -or [IO.Path]::GetFileName($ProbeRoot) -cnotmatch '^[a-f0-9]{32}$') {
    throw "The isolated uninstall probe root escaped its owned parent."
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Value
    )
    [IO.File]::WriteAllText(
        $Path,
        $Value,
        (New-Object Text.UTF8Encoding($false))
    )
}

function New-UninstallFixture {
    param(
        [Parameter(Mandatory = $true)] [string] $InstallRoot,
        [Parameter(Mandatory = $true)] [string] $Product,
        [Parameter(Mandatory = $true)] [string] $EntryPoint,
        [Parameter(Mandatory = $true)] [string] $RunnerPath,
        [Parameter(Mandatory = $true)] [string] $RunnerManifestPath,
        [Parameter(Mandatory = $true)] [string[]] $RemovedDirectories,
        [Parameter(Mandatory = $true)] [string[]] $PreservedDirectories
    )
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($DirectoryName in @($RemovedDirectories + $PreservedDirectories)) {
        $Directory = Join-Path $InstallRoot $DirectoryName
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        Write-Utf8File -Path (Join-Path $Directory "probe-sentinel.txt") `
            -Value "$Product/$DirectoryName"
    }
    Write-Utf8File -Path (Join-Path $InstallRoot "unins000.exe") `
        -Value "MineGuard isolated Inno boundary marker"

    $MetadataRoot = Join-Path $InstallRoot "release-metadata"
    Write-Utf8File -Path (Join-Path $MetadataRoot "VERSION.txt") `
        -Value "0.0.0`n"
    $RunnerItem = Get-Item -LiteralPath $RunnerPath -Force
    $Manifest = [ordered]@{
        product = $Product
        architecture = "x64"
        entrypoint = $EntryPoint
        version = "0.0.0"
        files = @(
            [ordered]@{
                path = $RunnerManifestPath
                bytes = [long]$RunnerItem.Length
                sha256 = (Get-FileHash -LiteralPath $RunnerPath `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        )
    }
    Write-Utf8File -Path (Join-Path $MetadataRoot "release-manifest.json") `
        -Value (($Manifest | ConvertTo-Json -Depth 6) + "`n")
}

function Assert-UninstallResult {
    param(
        [Parameter(Mandatory = $true)] [string] $InstallRoot,
        [Parameter(Mandatory = $true)] [string] $Product,
        [Parameter(Mandatory = $true)] [string[]] $RemovedDirectories,
        [Parameter(Mandatory = $true)] [string[]] $PreservedDirectories,
        [Parameter(Mandatory = $true)] [string] $QuarantinePrefix
    )
    foreach ($DirectoryName in $RemovedDirectories) {
        $Path = Join-Path $InstallRoot $DirectoryName
        if (Test-Path -LiteralPath $Path) {
            throw "$Product uninstall transaction left a managed directory: $Path"
        }
    }
    foreach ($DirectoryName in $PreservedDirectories) {
        $Sentinel = Join-Path (Join-Path $InstallRoot $DirectoryName) `
            "probe-sentinel.txt"
        if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
            throw "$Product uninstall transaction removed preserved content: $Sentinel"
        }
    }
    $LeakedQuarantine = Get-ChildItem -LiteralPath $InstallRoot `
        -Directory -Force | Where-Object {
            $_.Name.StartsWith(
                $QuarantinePrefix, [StringComparison]::OrdinalIgnoreCase
            )
        } | Select-Object -First 1
    if ($null -ne $LeakedQuarantine) {
        throw "$Product uninstall transaction leaked quarantine: $($LeakedQuarantine.FullName)"
    }
}

try {
    if ($null -ne (Get-Service -Name "MineGuardPlatform" `
            -ErrorAction SilentlyContinue)) {
        throw "The Platform uninstall fixture requires an unregistered service."
    }
    if (@(Get-Service -Name "MineGuardEnterpriseAgent-*" `
            -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "The Agent uninstall fixture requires all Agent services to be absent."
    }

    $PlatformRoot = Join-Path $ProbeRoot "Platform"
    $PlatformRemoved = @(
        "runtime", "deploy", "service", "release-metadata", "launcher"
    )
    $PlatformPreserved = @(
        "config", "state", "backups", "logs", "docs", "uninstall-tools"
    )
    New-UninstallFixture -InstallRoot $PlatformRoot `
        -Product "MineGuard Platform" `
        -EntryPoint "runtime/MineGuardPlatform.exe" `
        -RunnerPath $PlatformRunner `
        -RunnerManifestPath `
            "deploy/windows/Uninstall-MineGuardPlatformRuntime.ps1" `
        -RemovedDirectories $PlatformRemoved `
        -PreservedDirectories $PlatformPreserved
    & $PlatformRunner -InstallRoot $PlatformRoot -InternalInnoUninstall
    Assert-UninstallResult -InstallRoot $PlatformRoot -Product "Platform" `
        -RemovedDirectories $PlatformRemoved `
        -PreservedDirectories $PlatformPreserved `
        -QuarantinePrefix ".mineguard-platform-uninstall-quarantine."

    $AgentRoot = Join-Path $ProbeRoot "EnterpriseAgent"
    $AgentRemoved = @("runtime", "deploy", "release-metadata")
    $AgentPreserved = @("docs", "uninstall-tools", "operator-state")
    New-UninstallFixture -InstallRoot $AgentRoot `
        -Product "MineGuard Enterprise Agent" `
        -EntryPoint "runtime/MineGuardEnterpriseAgent.exe" `
        -RunnerPath $AgentRunner `
        -RunnerManifestPath `
            "deploy/windows/Uninstall-EnterpriseAgentRuntime.ps1" `
        -RemovedDirectories $AgentRemoved `
        -PreservedDirectories $AgentPreserved
    & $AgentRunner -InstallRoot $AgentRoot -InternalInnoUninstall
    Assert-UninstallResult -InstallRoot $AgentRoot `
        -Product "Enterprise Agent" `
        -RemovedDirectories $AgentRemoved `
        -PreservedDirectories $AgentPreserved `
        -QuarantinePrefix `
            ".mineguard-enterprise-agent-uninstall-quarantine."

    Write-Host (
        "MineGuard production uninstall transactions removed every managed " +
        "directory and preserved operator data."
    )
}
finally {
    if (Test-Path -LiteralPath $ProbeRoot) {
        Remove-Item -LiteralPath $ProbeRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}
