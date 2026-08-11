[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RuntimeRoot
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUNBUFFERED = "1"

$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$Executable = Join-Path $RuntimeRoot "MineGuardEnterpriseAgent.exe"
$WebRoot = Join-Path $RuntimeRoot "web"
foreach ($Required in @(
    $Executable,
    (Join-Path $WebRoot "index.html"),
    (Join-Path $WebRoot "app.js"),
    (Join-Path $WebRoot "v2-app.js"),
    (Join-Path $WebRoot "styles.css")
)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Standalone runtime is missing a required file: $Required"
    }
}

$Forbidden = Get-ChildItem -LiteralPath $RuntimeRoot -File -Recurse -Force |
    Where-Object { $_.Extension -in @(".py", ".pyw", ".pyc", ".pyo", ".pyi", ".pyx", ".pxd", ".ipynb", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".pdb", ".ilk", ".map") }
if ($null -ne $Forbidden) {
    throw "Standalone runtime contains source or compiler intermediate files: $($Forbidden[0].FullName)"
}

$VersionOutput = (& $Executable --version | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or $VersionOutput -notmatch '^enterprise-agent [0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Standalone executable did not report a valid Enterprise Agent version."
}

foreach ($RequiredEnvironment in @(
    [pscustomobject]@{ Name = "SystemRoot"; PathType = "Container" },
    [pscustomobject]@{ Name = "windir"; PathType = "Container" },
    [pscustomobject]@{ Name = "ComSpec"; PathType = "Leaf" }
)) {
    $EnvironmentValue = [Environment]::GetEnvironmentVariable(
        $RequiredEnvironment.Name,
        [EnvironmentVariableTarget]::Process
    )
    if ([string]::IsNullOrWhiteSpace($EnvironmentValue) -or
        -not (Test-Path -LiteralPath $EnvironmentValue `
            -PathType $RequiredEnvironment.PathType)) {
        throw "Windows smoke-test environment is missing $($RequiredEnvironment.Name)."
    }
}

$Listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$Listener.Start()
$Port = ([Net.IPEndPoint]$Listener.LocalEndpoint).Port
$Listener.Stop()

$TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("MineGuard binary smoke " + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
$DatabasePath = Join-Path $TemporaryRoot "enterprise-agent.db"
$StdoutPath = Join-Path $TemporaryRoot "stdout.log"
$StderrPath = Join-Path $TemporaryRoot "stderr.log"
$QuotedDatabase = '"' + $DatabasePath.Replace('"', '\"') + '"'
$Arguments = "--db $QuotedDatabase serve --host 127.0.0.1 --port $Port"
$Process = $null
try {
    # Start-Process must inherit the live Windows process environment.
    # Starting from a freshly reconstructed environment drops process/user-
    # scoped values on Windows and can leave Winsock unable to expand or load
    # a catalog provider DLL.
    # Remove only application credentials and Python host-environment hints
    # while the child process is created, then restore the build process.
    $SavedEnvironment = @{}
    $EnvironmentVariablesToClear = @(
        Get-ChildItem Env: |
            Where-Object {
                $_.Name -in @(
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "VIRTUAL_ENV",
                    "VIRTUAL_ENV_PROMPT"
                ) -or
                $_.Name -match `
                    '^(ENTERPRISE_|PLATFORM_|DEEPSEEK_|OPENAI_|COAL_NEWS_|MINEGUARD_AGENT_)' -or
                $_.Name -match '(?i)(API_KEY|SECRET|TOKEN|PASSWORD)$'
            } |
            ForEach-Object { $_.Name } |
            Sort-Object -Unique
    )
    try {
        foreach ($Name in $EnvironmentVariablesToClear) {
            $SavedEnvironment[$Name] = [Environment]::GetEnvironmentVariable(
                $Name,
                [EnvironmentVariableTarget]::Process
            )
            [Environment]::SetEnvironmentVariable(
                $Name,
                $null,
                [EnvironmentVariableTarget]::Process
            )
        }
        $Process = Start-Process `
            -FilePath $Executable `
            -ArgumentList $Arguments `
            -WorkingDirectory $RuntimeRoot `
            -RedirectStandardOutput $StdoutPath `
            -RedirectStandardError $StderrPath `
            -PassThru
    }
    finally {
        foreach ($Name in $EnvironmentVariablesToClear) {
            [Environment]::SetEnvironmentVariable(
                $Name,
                $SavedEnvironment[$Name],
                [EnvironmentVariableTarget]::Process
            )
        }
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    $Healthy = $false
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Process.Refresh()
        if ($Process.HasExited) {
            $Process.WaitForExit()
            $ExitCode = [int]$Process.ExitCode
            $ErrorText = if (Test-Path -LiteralPath $StderrPath -PathType Leaf) {
                [IO.File]::ReadAllText($StderrPath, [Text.Encoding]::UTF8)
            } else { "" }
            throw "Standalone Agent exited during smoke test with code ${ExitCode}: $ErrorText"
        }
        try {
            $Health = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/api/v1/health" `
                -UseBasicParsing `
                -TimeoutSec 2
            if ([int]$Health.StatusCode -eq 200) {
                $Healthy = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $Healthy) {
        throw "Standalone Agent did not become healthy within 30 seconds."
    }
    $Frontend = Invoke-WebRequest `
        -Uri "http://127.0.0.1:$Port/" `
        -UseBasicParsing `
        -TimeoutSec 5
    if ([int]$Frontend.StatusCode -ne 200 -or $Frontend.Content -notmatch '<!doctype html') {
        throw "Standalone Agent did not serve the bundled frontend."
    }
}
finally {
    if ($null -ne $Process) {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            $Process.WaitForExit(5000) | Out-Null
        }
    }
    if (Test-Path -LiteralPath $TemporaryRoot) {
        Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force
    }
}

Write-Host "MineGuard Enterprise Agent standalone smoke test passed."
