[CmdletBinding()]
param(
    [uri] $BaseUri = 'http://127.0.0.1:8080',
    [ValidateRange(1, 60)] [int] $TimeoutSeconds = 5,
    [switch] $HealthOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$OutputEncoding = $utf8NoBom
try { [Console]::OutputEncoding = $utf8NoBom } catch { }

function Invoke-HealthEndpoint {
    param([string] $Name, [string] $RelativePath)
    $uri = New-Object -TypeName System.Uri -ArgumentList @($BaseUri, $RelativePath)
    try {
        $response = Invoke-WebRequest -Uri $uri.AbsoluteUri -UseBasicParsing `
            -TimeoutSec $TimeoutSeconds -Headers @{ 'Cache-Control' = 'no-cache' }
        $body = $response.Content | ConvertFrom-Json
        $configuredMines = $null
        $configuredProperty = $body.PSObject.Properties['configured_mines']
        if ($null -ne $configuredProperty) {
            $configuredMines = $configuredProperty.Value
        }
        return [pscustomobject]@{
            name = $Name
            uri = $uri.AbsoluteUri
            httpStatus = [int]$response.StatusCode
            status = [string]$body.status
            configuredMines = $configuredMines
            ok = ([int]$response.StatusCode -eq 200)
        }
    } catch {
        $statusCode = $null
        $responseProperty = $_.Exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
            try { $statusCode = [int]$responseProperty.Value.StatusCode } catch { }
        }
        throw "$Name 检查失败（$($uri.AbsoluteUri)，HTTP $statusCode）：$($_.Exception.Message)"
    }
}

$results = @()
$results += Invoke-HealthEndpoint -Name 'healthz' -RelativePath '/healthz'
if (-not $HealthOnly) {
    $results += Invoke-HealthEndpoint -Name 'readyz' -RelativePath '/readyz'
}
$results
Write-Host 'MineGuard Platform 健康检查通过。'
