[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The Windows wizard construction probe requires native Windows."
}
if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    throw "The Windows wizard construction probe requires PowerShell 5.1 or later."
}

function Invoke-WizardConstructionProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][object[]]$ScriptArguments,
        [Parameter(Mandatory = $true)][string]$ExpectedComponent
    )

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "$Name script is missing: $ScriptPath"
    }
    $OutputLines = @(& $WindowsPowerShell -NoProfile -STA `
        -ExecutionPolicy Bypass -File $ScriptPath @ScriptArguments 2>&1)
    $OutputText = @($OutputLines | ForEach-Object { [string]$_ }) -join `
        [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) {
        throw "$Name exited with code $LASTEXITCODE`: $OutputText"
    }
    try {
        $Result = $OutputText | ConvertFrom-Json
    }
    catch {
        throw "$Name did not emit exactly one valid JSON self-test result: $OutputText"
    }
    if ([string]$Result.status -ne "ok" -or
        [string]$Result.component -ne $ExpectedComponent -or
        -not [bool]$Result.controls_constructed) {
        throw "$Name did not construct all of its top-level Windows Forms controls."
    }
    Write-Host "$Name GUI construction probe passed."
}

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$WindowsPowerShell = Join-Path $env:SystemRoot `
    "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $WindowsPowerShell -PathType Leaf)) {
    throw "Windows PowerShell is missing: $WindowsPowerShell"
}
$PlatformRoot = Join-Path $RepositoryRoot "platform"
$AgentRoot = Join-Path $RepositoryRoot "agent"
$PlatformWizard = Join-Path $PlatformRoot `
    "deploy\windows\Start-MineGuardPlatformProvisioningWizard.ps1"
$AgentWizard = Join-Path $AgentRoot `
    "deploy\windows\Start-EnterpriseAgentProvisioningWizard.ps1"

$TemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$ProbeRoot = Join-Path $TemporaryParent (
    "MineGuardWizardConstruction-" + [Guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $ProbeRoot | Out-Null
try {
    Invoke-WizardConstructionProbe -Name "Platform provisioning wizard" `
        -ScriptPath $PlatformWizard -ExpectedComponent `
        "mineguard-platform-provisioning-wizard" -ScriptArguments @(
            "-InstallRoot", $PlatformRoot, "-SelfTest"
        )
    Invoke-WizardConstructionProbe -Name "Agent provisioning wizard" `
        -ScriptPath $AgentWizard -ExpectedComponent `
        "enterprise-agent-provisioning-wizard" -ScriptArguments @(
            "-InstallRoot", $AgentRoot,
            "-StateRoot", (Join-Path $ProbeRoot "agent-state"),
            "-SelfTest"
        )
}
finally {
    $ResolvedProbeRoot = [IO.Path]::GetFullPath($ProbeRoot)
    $ExpectedPrefix = $TemporaryParent + '\'
    if (-not $ResolvedProbeRoot.StartsWith(
            $ExpectedPrefix,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Split-Path -Leaf $ResolvedProbeRoot) -notmatch `
            '^MineGuardWizardConstruction-[a-f0-9]{32}$') {
        throw "Refusing unsafe wizard probe cleanup path: $ResolvedProbeRoot"
    }
    Remove-Item -LiteralPath $ResolvedProbeRoot -Recurse -Force
}

Write-Host "All Windows onboarding wizard GUI construction probes passed."
