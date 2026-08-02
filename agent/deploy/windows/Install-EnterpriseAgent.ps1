[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "MineGuard\EnterpriseAgent"),
    [string]$StateRoot = (Join-Path $env:ProgramData "MineGuard\EnterpriseAgent\instances"),
    [string]$SourceRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$PythonCommand = "py",
    [string[]]$PythonArguments = @("-3.12"),
    [string]$Wheelhouse = ""
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated Administrator PowerShell."
}

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $FilePath"
    }
}

function Assert-LocalFixedPath {
    param([string]$Name, [string]$PathValue)
    if (-not [IO.Path]::IsPathRooted($PathValue)) {
        throw "$Name must be an absolute local path."
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue)
    if ($FullPath.StartsWith("\\")) {
        throw "$Name must not use a UNC/network path: $FullPath"
    }
    $Root = [IO.Path]::GetPathRoot($FullPath)
    if ($FullPath.TrimEnd('\') -eq $Root.TrimEnd('\')) {
        throw "$Name must not be a filesystem root."
    }
    if ($Root -match '^([A-Za-z]):\\$') {
        $DeviceId = $Matches[1] + ":"
        $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction SilentlyContinue
        if ($null -ne $Disk -and [int]$Disk.DriveType -ne 3) {
            throw "$Name must use a local fixed disk: $FullPath"
        }
    }
}

function Invoke-IcaclsChecked {
    param([string[]]$ArgumentList)
    & icacls.exe @ArgumentList | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
}

$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
Assert-LocalFixedPath -Name "InstallRoot" -PathValue $InstallRoot
Assert-LocalFixedPath -Name "StateRoot" -PathValue $StateRoot
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$InstallPrefix = $InstallRoot.TrimEnd('\') + '\'
$StatePrefix = $StateRoot.TrimEnd('\') + '\'
if ($InstallRoot.Equals($StateRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $InstallRoot.StartsWith($StatePrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $StateRoot.StartsWith($InstallPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot and StateRoot must be separate, non-nested directories."
}
$ProjectFile = Join-Path $SourceRoot "pyproject.toml"
$Constraints = Join-Path $SourceRoot "constraints.txt"
if (-not (Test-Path -LiteralPath $ProjectFile -PathType Leaf)) {
    throw "Agent source root is invalid: $SourceRoot"
}
if (-not (Test-Path -LiteralPath $Constraints -PathType Leaf)) {
    throw "Pinned constraints file is missing: $Constraints"
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
$RunningServices = Get-Service -Name "MineGuardEnterpriseAgent-*" -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -ne "Stopped" }
if ($null -ne $RunningServices) {
    throw "Stop all MineGuardEnterpriseAgent-* services before installing or upgrading the shared runtime."
}
$RuntimeRoot = Join-Path $InstallRoot "runtime"
$VirtualEnvironment = Join-Path $RuntimeRoot ".venv"
New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null

$VersionCheck = "import struct,sys; assert sys.version_info[:2] == (3,12) and struct.calcsize('P') == 8, sys.version"
Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-c", $VersionCheck))
if (-not (Test-Path -LiteralPath (Join-Path $VirtualEnvironment "Scripts\python.exe") -PathType Leaf)) {
    Invoke-NativeChecked -FilePath $PythonCommand -ArgumentList ($PythonArguments + @("-m", "venv", $VirtualEnvironment))
}

$VenvPython = Join-Path $VirtualEnvironment "Scripts\python.exe"
Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @("-c", $VersionCheck)
if ($Wheelhouse) {
    $Wheelhouse = [IO.Path]::GetFullPath($Wheelhouse)
    if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
        throw "Wheelhouse directory does not exist: $Wheelhouse"
    }
    $AgentWheel = Get-ChildItem -LiteralPath $Wheelhouse -Filter "enterprise_reporting_agent-*.whl" -File |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $AgentWheel) {
        throw "Wheelhouse must contain enterprise_reporting_agent-*.whl and all dependency wheels."
    }
    Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @(
        "-m", "pip", "install", "--disable-pip-version-check",
        "--no-index", "--find-links", $Wheelhouse,
        "--constraint", $Constraints, $AgentWheel.FullName
    )
}
else {
    Invoke-NativeChecked -FilePath $VenvPython -ArgumentList @(
        "-m", "pip", "install", "--disable-pip-version-check",
        "--constraint", $Constraints, $SourceRoot
    )
}

$DeployTarget = Join-Path $InstallRoot "deploy\windows"
New-Item -ItemType Directory -Path $DeployTarget -Force | Out-Null
foreach ($DeployFile in Get-ChildItem -LiteralPath $PSScriptRoot) {
    Copy-Item -LiteralPath $DeployFile.FullName -Destination $DeployTarget -Recurse -Force
}
Copy-Item -LiteralPath $Constraints -Destination (Join-Path $InstallRoot "constraints.txt") -Force
Invoke-IcaclsChecked -ArgumentList @($InstallRoot, "/grant", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX", "/T", "/C")
Invoke-IcaclsChecked -ArgumentList @($StateRoot, "/inheritance:r")
Invoke-IcaclsChecked -ArgumentList @($StateRoot, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-19:(OI)(CI)RX")

$AgentExecutable = Join-Path $VirtualEnvironment "Scripts\enterprise-agent.exe"
Invoke-NativeChecked -FilePath $AgentExecutable -ArgumentList @("--version")
Write-Host "Enterprise Agent runtime installed."
Write-Host "Runtime: $VirtualEnvironment"
Write-Host "Instances: $StateRoot"
Write-Host "Next: run New-EnterpriseAgentInstance.ps1 once for each mine."
