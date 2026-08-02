[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Resolve-MineGuardPlatformExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $InstallRoot
    )

    $runtimeDirectory = Join-Path ([System.IO.Path]::GetFullPath($InstallRoot)) 'runtime'
    $standaloneExecutable = Join-Path $runtimeDirectory 'MineGuardPlatform.exe'
    if (Test-Path -LiteralPath $standaloneExecutable -PathType Leaf) {
        return [pscustomobject]@{
            filePath = $standaloneExecutable
            prefixArguments = [string[]]@()
            runtimeKind = 'standalone'
        }
    }

    # Keep the source/venv deployment as an explicitly supported development
    # fallback.  External installer builds contain only the standalone branch.
    $pythonExecutable = Join-Path $runtimeDirectory 'Scripts\python.exe'
    if (Test-Path -LiteralPath $pythonExecutable -PathType Leaf) {
        return [pscustomobject]@{
            filePath = $pythonExecutable
            prefixArguments = [string[]]@('-m', 'mineguard')
            runtimeKind = 'python-venv'
        }
    }

    throw (
        '找不到 MineGuard Platform 运行时。需要 runtime\MineGuardPlatform.exe，' +
        '开发安装也可使用 runtime\Scripts\python.exe。'
    )
}

function Join-MineGuardPlatformArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Runtime,
        [Parameter(Mandatory = $true)] [string[]] $Arguments
    )

    return [string[]](@($Runtime.prefixArguments) + @($Arguments))
}
