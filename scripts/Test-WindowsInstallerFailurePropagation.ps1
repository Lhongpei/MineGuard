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

function Get-SecurityAccessFingerprint {
    param([Parameter(Mandatory = $true)] [string] $Sddl)
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $owner = if ($null -eq $descriptor.Owner) { '' } else { $descriptor.Owner.Value }
    $group = if ($null -eq $descriptor.Group) { '' } else { $descriptor.Group.Value }
    $daclPresent = (($descriptor.ControlFlags -band
        [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0)
    $daclProtected = (($descriptor.ControlFlags -band
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)
    $aces = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $descriptor.DiscretionaryAcl) {
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            $bytes = [byte[]]::new($ace.BinaryLength)
            $ace.GetBinaryForm($bytes, 0)
            $aces.Add([BitConverter]::ToString($bytes).Replace('-', ''))
        }
    }
    return "$owner|$group|$daclPresent|$daclProtected|$($aces -join ',')"
}

function Invoke-RegExeForExitCode {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
    $PreviousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can surface native stderr as an error record
        # when the script-wide preference is Stop. Missing-key probes are an
        # expected nonzero result, so retain only reg.exe's native exit code.
        $ErrorActionPreference = "Continue"
        & "$env:SystemRoot\System32\reg.exe" @ArgumentList 2>&1 | Out-Null
        return [int]$LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
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

function New-SecureVerificationRoot {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    $VolumeRoot = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrWhiteSpace($VolumeRoot) -or
        $FullPath.Equals(
            $VolumeRoot.TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing unsafe verification root: $FullPath"
    }
    if (Test-Path -LiteralPath $FullPath) {
        throw "Verification root already exists: $FullPath"
    }
    $ParentPath = Split-Path -Parent $FullPath
    $ParentItem = Get-Item -LiteralPath $ParentPath -Force
    if (($ParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Verification-root parent is a reparse point: $ParentPath"
    }
    $Drive = [IO.DriveInfo]::new($VolumeRoot)
    if (-not $Drive.IsReady -or
        $Drive.DriveType -ne [IO.DriveType]::Fixed -or
        -not $Drive.DriveFormat.Equals(
            "NTFS", [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Verification root must be on a ready local fixed NTFS volume."
    }

    $Administrators = [Security.Principal.SecurityIdentifier]::new(
        "S-1-5-32-544"
    )
    $LocalSystem = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $Inheritance = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $Acl = [Security.AccessControl.DirectorySecurity]::new()
    $Acl.SetAccessRuleProtection($true, $false)
    $Acl.SetOwner($Administrators)
    foreach ($Sid in @($Administrators, $LocalSystem)) {
        $Rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    [void][IO.Directory]::CreateDirectory($FullPath, $Acl)

    $CreatedItem = Get-Item -LiteralPath $FullPath -Force
    if (($CreatedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Secure verification root became a reparse point: $FullPath"
    }
    $ActualAcl = [IO.Directory]::GetAccessControl($FullPath)
    $ActualOwner = $ActualAcl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $ActualRules = @($ActualAcl.GetAccessRules(
            $true,
            $false,
            [Security.Principal.SecurityIdentifier]
        ))
    if (-not $ActualAcl.AreAccessRulesProtected -or
        $ActualOwner -cne $Administrators.Value -or
        $ActualRules.Count -ne 2) {
        throw "Secure verification root owner or DACL protection is invalid."
    }
    $ExpectedSidValues = @($Administrators.Value, $LocalSystem.Value)
    foreach ($ActualRule in $ActualRules) {
        if (-not ($ExpectedSidValues -ccontains
                $ActualRule.IdentityReference.Value) -or
            $ActualRule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $ActualRule.FileSystemRights -ne
                [Security.AccessControl.FileSystemRights]::FullControl -or
            $ActualRule.InheritanceFlags -ne $Inheritance -or
            $ActualRule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None) {
            throw "Secure verification root has a non-canonical ACL rule."
        }
    }
    return $FullPath
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

function Remove-TestAuthenticodeCertificate {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)
    $Signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($Signature.Status.ToString() -eq "NotSigned") { return }
    $Bytes = [IO.File]::ReadAllBytes($ExecutablePath)
    if ($Bytes.Length -lt 256) {
        throw "Signed probe executable is too small to be a valid PE image."
    }
    $PeOffset = [BitConverter]::ToInt32($Bytes, 0x3c)
    if ($PeOffset -lt 0x40 -or $PeOffset + 256 -gt $Bytes.Length -or
        [BitConverter]::ToUInt32($Bytes, $PeOffset) -ne 0x00004550) {
        throw "Signed probe executable has an invalid PE header."
    }
    $OptionalHeader = $PeOffset + 24
    $Magic = [BitConverter]::ToUInt16($Bytes, $OptionalHeader)
    $DataDirectoryOffset = switch ($Magic) {
        0x10b { $OptionalHeader + 96; break }
        0x20b { $OptionalHeader + 112; break }
        default { throw "Signed probe executable has an unsupported PE format." }
    }
    $SecurityDirectory = $DataDirectoryOffset + (8 * 4)
    $CertificateOffset = [BitConverter]::ToUInt32($Bytes, $SecurityDirectory)
    $CertificateSize = [BitConverter]::ToUInt32($Bytes, $SecurityDirectory + 4)
    if ($CertificateOffset -eq 0 -or $CertificateSize -eq 0 -or
        [long]$CertificateOffset + [long]$CertificateSize -gt $Bytes.LongLength) {
        throw "Signed probe executable has an invalid Authenticode directory."
    }
    # The PE security directory is a file offset, not an RVA. Zeroing the
    # directory removes the signature without changing executable code or
    # depending on a certificate/private key; the orphaned certificate bytes
    # remain inert overlay data for this test-only copy.
    for ($Index = 0; $Index -lt 8; $Index++) {
        $Bytes[$SecurityDirectory + $Index] = 0
    }
    [IO.File]::WriteAllBytes($ExecutablePath, $Bytes)
    $Unsigned = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($Unsigned.Status.ToString() -ne "NotSigned" -or
        $null -ne $Unsigned.SignerCertificate) {
        throw "Could not create an unsigned test-only copy of the probe executable."
    }
}

function New-UnsignedWrapperProbeStage {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$OriginalStage,
        [string]$Destination
    )
    New-Item -ItemType Directory -Path $Destination | Out-Null
    foreach ($Item in Get-ChildItem -LiteralPath $OriginalStage -Force) {
        Copy-Item -LiteralPath $Item.FullName -Destination $Destination -Recurse
    }
    $ExecutableName = if ($Product -eq "platform") {
        "MineGuardPlatform.exe"
    }
    else {
        "MineGuardEnterpriseAgent.exe"
    }
    $Executable = Join-Path $Destination "runtime\$ExecutableName"
    Remove-TestAuthenticodeCertificate -ExecutablePath $Executable

    $Utf8NoBom = New-Object Text.UTF8Encoding($false)
    $ManifestPath = Join-Path $Destination "release-manifest.json"
    $MetadataPath = Join-Path $Destination "build-metadata.json"
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $Metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ($Product -eq "platform") {
        $Manifest.codeSigned = $false
        $Manifest.authenticodeVerified = $false
        $Manifest.releaseClassification = "unsigned-test-artifacts"
        $Metadata.codeSigned = $false
        $Metadata.authenticodeVerified = $false
        $Metadata.releaseClassification = "unsigned-test-artifacts"
        $Metadata.signingCertificateThumbprint = $null
    }
    else {
        $Manifest.authenticode_signed = $false
        $Manifest.signing_certificate_thumbprint = $null
        $Manifest.timestamp_verified = $false
        $Manifest.timestamp_url = $null
        $Manifest.release_classification = "unsigned-test-only"
        $Metadata.authenticode_signed = $false
        $Metadata.signing_certificate_thumbprint = $null
        $Metadata.timestamp_verified = $false
        $Metadata.timestamp_url = $null
        $Metadata.release_classification = "unsigned-test-only"
    }
    [IO.File]::WriteAllText(
        $MetadataPath,
        (($Metadata | ConvertTo-Json -Depth 50) + [Environment]::NewLine),
        $Utf8NoBom
    )
    [IO.File]::WriteAllText(
        $ManifestPath,
        (($Manifest | ConvertTo-Json -Depth 50) + [Environment]::NewLine),
        $Utf8NoBom
    )
    return Write-FailureProbeReleaseIntegrity `
        -Product $Product -StageRoot $Destination `
        -OriginalManifestPath $ManifestPath
}

function Get-WrapperShortcutPaths {
    param([ValidateSet("platform", "agent")][string]$Product)
    $Group = Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonPrograms)) "MineGuard"
    $Names = if ($Product -eq "platform") {
        @(
            "MineGuard Platform 控制中心.lnk",
            "MineGuard 企业接入包与注册向导.lnk",
            "MineGuard Platform 使用与部署说明.lnk"
        )
    }
    else {
        @(
            "MineGuard 企业接入配置向导.lnk",
            "MineGuard 企业端使用说明.lnk"
        )
    }
    $Paths = @($Names | ForEach-Object { Join-Path $Group $_ })
    if ($Product -eq "platform") {
        $Paths += Join-Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonDesktopDirectory)) `
            "MineGuard Platform 控制中心.lnk"
    }
    return $Paths
}

function Get-ExactArtifactSnapshot {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $Snapshot = @{}
    foreach ($PathValue in $Paths) {
        $Full = [IO.Path]::GetFullPath($PathValue)
        $RootKey = $Full.ToLowerInvariant()
        if (-not (Test-Path -LiteralPath $Full)) {
            $Snapshot[$RootKey] = "<missing>"
            continue
        }
        $RootItem = Get-Item -LiteralPath $Full -Force
        $Items = @($RootItem)
        if ($RootItem.PSIsContainer) {
            $Items += @(Get-ChildItem -LiteralPath $Full -Force -Recurse |
                Sort-Object FullName)
        }
        $Prefix = $Full.TrimEnd('\') + '\'
        foreach ($Item in $Items) {
            $Relative = if ($Item.FullName.Equals(
                    $Full, [StringComparison]::OrdinalIgnoreCase)) {
                "."
            }
            else {
                $Item.FullName.Substring($Prefix.Length).Replace('\', '/')
            }
            $Key = "$RootKey|$Relative"
            $Acl = Get-Acl -LiteralPath $Item.FullName
            $Security = Get-SecurityAccessFingerprint -Sddl $Acl.Sddl
            if ($Item.PSIsContainer) {
                $Snapshot[$Key] = "directory|$Security"
            }
            else {
                $Snapshot[$Key] = (
                    "file|$($Item.Length)|" +
                    (Get-FileHash -LiteralPath $Item.FullName `
                        -Algorithm SHA256).Hash + "|$Security"
                )
            }
        }
    }
    return $Snapshot
}

function Assert-ExactArtifactSnapshot {
    param([hashtable]$Expected, [string[]]$Paths, [string]$Label)
    $Actual = Get-ExactArtifactSnapshot -Paths $Paths
    if ($Expected.Count -ne $Actual.Count) {
        throw "$Label changed the managed artifact set."
    }
    foreach ($Key in $Expected.Keys) {
        if (-not $Actual.ContainsKey($Key) -or $Actual[$Key] -cne $Expected[$Key]) {
            throw "$Label failed exact content/ACL restoration: $Key"
        }
    }
}

function Convert-ArpRegistryValueToCanonicalRecord {
    param($Value, [Microsoft.Win32.RegistryValueKind]$Kind)
    if ($Kind -in @(
            [Microsoft.Win32.RegistryValueKind]::Binary,
            [Microsoft.Win32.RegistryValueKind]::None)) {
        return [ordered]@{
            encoding = "base64"
            data = [Convert]::ToBase64String([byte[]]$Value)
        }
    }
    if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
        return [ordered]@{
            encoding = "string-array"
            data = @([string[]]$Value)
        }
    }
    $Data = if ($Kind -in @(
            [Microsoft.Win32.RegistryValueKind]::DWord,
            [Microsoft.Win32.RegistryValueKind]::QWord)) {
        $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    else {
        [string]$Value
    }
    return [ordered]@{
        encoding = "scalar"
        data = $Data
    }
}

function Get-ArpRegistrationSnapshot {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$ScratchRoot
    )
    # Registry values and subkeys have no defined enumeration order.  Compare
    # a canonical Registry64 semantic snapshot instead of hashing reg.exe's
    # order-dependent export text. ScratchRoot remains in the signature so all
    # existing native probes retain one uniform call shape.
    [void]$ScratchRoot
    $ApplicationId = if ($Product -eq "platform") {
        "{8B391CBD-E234-46D7-9946-E9D37F2649C1}"
    }
    else {
        "{9B73DE95-6B38-4482-A8BC-2A4FC656D05A}"
    }
    $SubKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${ApplicationId}_is1"
    $Base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $Root = $Base.OpenSubKey($SubKey, $false)
        if ($null -eq $Root) {
            throw "$Product ARP registration is missing after baseline install."
        }
        $Root.Dispose()
        $Pending = [System.Collections.Generic.Queue[string]]::new()
        $Pending.Enqueue("")
        $Keys = [System.Collections.Generic.List[object]]::new()
        while ($Pending.Count -gt 0) {
            $Relative = $Pending.Dequeue()
            $CurrentSubKey = if ($Relative -eq "") {
                $SubKey
            }
            else {
                $SubKey + "\" + $Relative
            }
            $Key = $Base.OpenSubKey($CurrentSubKey, $false)
            if ($null -eq $Key) {
                throw "$Product ARP key changed during snapshot: $CurrentSubKey"
            }
            try {
                $Values = [System.Collections.Generic.List[object]]::new()
                foreach ($Name in @($Key.GetValueNames() |
                        Sort-Object -CaseSensitive)) {
                    $Kind = $Key.GetValueKind($Name)
                    $Option = if ($Kind -eq
                            [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    }
                    else {
                        [Microsoft.Win32.RegistryValueOptions]::None
                    }
                    $Value = $Key.GetValue($Name, $null, $Option)
                    $Values.Add([ordered]@{
                        name = [string]$Name
                        kind = [string]$Kind
                        value = Convert-ArpRegistryValueToCanonicalRecord `
                            -Value $Value -Kind $Kind
                    })
                }
                $Security = $Key.GetAccessControl()
                $Sections =
                    [Security.AccessControl.AccessControlSections]::Access -bor
                    [Security.AccessControl.AccessControlSections]::Owner -bor
                    [Security.AccessControl.AccessControlSections]::Group
                $Keys.Add([ordered]@{
                    path = [string]$Relative
                    owner = $Security.GetOwner(
                        [Security.Principal.SecurityIdentifier]).Value
                    group = $Security.GetGroup(
                        [Security.Principal.SecurityIdentifier]).Value
                    accessRulesProtected = [bool]$Security.AreAccessRulesProtected
                    sddl = $Security.GetSecurityDescriptorSddlForm($Sections)
                    values = $Values.ToArray()
                })
                foreach ($Child in @($Key.GetSubKeyNames() |
                        Sort-Object -CaseSensitive)) {
                    $ChildRelative = if ($Relative -eq "") {
                        $Child
                    }
                    else {
                        $Relative + "\" + $Child
                    }
                    $Pending.Enqueue($ChildRelative)
                }
            }
            finally {
                $Key.Dispose()
            }
        }
        $Snapshot = [ordered]@{
            subKey = $SubKey
            keys = $Keys.ToArray()
        }
        return ($Snapshot | ConvertTo-Json -Depth 20 -Compress)
    }
    finally {
        $Base.Dispose()
    }
}

function Assert-ExactArpRegistrationSnapshot {
    param([string]$Expected, [string]$Actual, [string]$Label)
    if ($Actual -ceq $Expected) { return }
    # This fixture runs on an isolated release runner and ARP records contain
    # no credentials. Emit both canonical structures so a genuine
    # value/type/ACL regression is diagnosable without relying on registry
    # enumeration order.
    Write-Host "$Label expected ARP: $Expected"
    Write-Host "$Label actual ARP: $Actual"
    throw "$Label did not restore HKLM64 ARP exactly."
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

function Test-OneSetupMutexExclusion {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$InstallerPath,
        [object[]]$InstallArguments,
        [string]$InstallRoot,
        [string]$StateRoot,
        [string]$ArpKey,
        [string[]]$ShortcutPaths,
        [string]$TransactionPrefix,
        [string]$ProbeRoot
    )
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
    if (-not $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The SetupMutex native probe must run in an elevated administrator process."
    }
    $UnexpectedRoots = @($InstallRoot)
    if ($Product -eq "agent") { $UnexpectedRoots += $StateRoot }
    foreach ($UnexpectedRoot in $UnexpectedRoots) {
        if (-not [string]::IsNullOrWhiteSpace([string]$UnexpectedRoot) -and
            (Test-Path -LiteralPath $UnexpectedRoot)) {
            throw "$Product SetupMutex probe precondition already exists: $UnexpectedRoot"
        }
    }
    $ExistingTransaction = Get-ChildItem -LiteralPath (
        Split-Path -Parent $InstallRoot) -Directory -Force |
        Where-Object { $_.Name.StartsWith($TransactionPrefix) } |
        Select-Object -First 1
    if ($null -ne $ExistingTransaction) {
        throw "$Product SetupMutex probe found a pre-existing transaction: $($ExistingTransaction.FullName)"
    }

    $MutexName = "Global\MineGuard-Setup-Transaction-v1"
    $CreatedNew = $false
    $Mutex = $null
    $MutexLog = Join-Path $ProbeRoot "setup-mutex-blocked.log"
    $BlockedExit = $null
    try {
        $Mutex = [Threading.Mutex]::new(
            $true, $MutexName, [ref]$CreatedNew)
        if (-not $CreatedNew) {
            throw "The stable global MineGuard SetupMutex already exists."
        }
        $BlockedArguments = @($InstallArguments) + "/LOG=$MutexLog"
        $BlockedExit = Invoke-ProcessTreeWithTransientAccessRetry `
            -FilePath $InstallerPath -ArgumentList $BlockedArguments `
            -TimeoutSeconds 30
    }
    finally {
        if ($null -ne $Mutex) {
            try {
                if ($CreatedNew) { [void]$Mutex.ReleaseMutex() }
            }
            finally {
                $Mutex.Dispose()
            }
        }
    }
    if ($null -eq $BlockedExit -or [int]$BlockedExit -eq 0) {
        Write-FailureProbeLog -Product $Product -LogPath $MutexLog
        throw "$Product Setup incorrectly ran while the stable global SetupMutex was held."
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        Write-FailureProbeLog -Product $Product -LogPath $MutexLog
        throw "$Product SetupMutex rejection created InstallRoot."
    }
    if ($Product -eq "agent" -and (Test-Path -LiteralPath $StateRoot)) {
        Write-FailureProbeLog -Product $Product -LogPath $MutexLog
        throw "$Product SetupMutex rejection created StateRoot."
    }
    if ((Invoke-RegExeForExitCode -ArgumentList @(
            "query", $ArpKey, "/reg:64")) -eq 0) {
        throw "$Product SetupMutex rejection created an HKLM64 ARP registration."
    }
    foreach ($Shortcut in $ShortcutPaths) {
        if (Test-Path -LiteralPath $Shortcut) {
            throw "$Product SetupMutex rejection created a shortcut: $Shortcut"
        }
    }
    $LeakedTransaction = Get-ChildItem -LiteralPath (
        Split-Path -Parent $InstallRoot) -Directory -Force |
        Where-Object { $_.Name.StartsWith($TransactionPrefix) } |
        Select-Object -First 1
    if ($null -ne $LeakedTransaction) {
        throw "$Product SetupMutex rejection created a retained transaction: $($LeakedTransaction.FullName)"
    }
    Write-Host (
        "$Product SetupMutex rejected the competing Setup with exit " +
        "$BlockedExit before any persistent product artifact was created."
    )
}

function Test-OneUninstallMutexExclusion {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$UninstallerPath,
        [string]$InstallRoot,
        [string]$StateRoot,
        [string]$ArpKey,
        [string[]]$ShortcutPaths,
        [string]$ProbeRoot
    )
    if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $UninstallerPath -PathType Leaf)) {
        throw "$Product uninstall SetupMutex probe requires a complete baseline install."
    }
    $SnapshotPaths = @($InstallRoot) + @($ShortcutPaths)
    if ($Product -eq "agent") {
        if (-not (Test-Path -LiteralPath $StateRoot -PathType Container)) {
            throw "$Product uninstall SetupMutex probe is missing StateRoot."
        }
        $SnapshotPaths += $StateRoot
    }
    $BeforeArtifacts = Get-ExactArtifactSnapshot -Paths $SnapshotPaths
    $BeforeArp = Get-ArpRegistrationSnapshot `
        -Product $Product -ScratchRoot $ProbeRoot

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
    if (-not $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The uninstall SetupMutex probe must run in an elevated administrator process."
    }
    $MutexName = "Global\MineGuard-Setup-Transaction-v1"
    $CreatedNew = $false
    $Mutex = $null
    $MutexLog = Join-Path $ProbeRoot "uninstall-mutex-blocked.log"
    $BlockedExit = $null
    try {
        $Mutex = [Threading.Mutex]::new(
            $true, $MutexName, [ref]$CreatedNew)
        if (-not $CreatedNew) {
            throw "The stable global MineGuard SetupMutex already exists."
        }
        $BlockedExit = Invoke-ProcessTreeWithTransientAccessRetry `
            -FilePath $UninstallerPath `
            -ArgumentList @(
                "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                "/LOG=$MutexLog"
            ) -TimeoutSeconds 30
    }
    finally {
        if ($null -ne $Mutex) {
            try {
                if ($CreatedNew) { [void]$Mutex.ReleaseMutex() }
            }
            finally {
                $Mutex.Dispose()
            }
        }
    }

    $Failures = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $BlockedExit -or [int]$BlockedExit -eq 0) {
        $Failures.Add("the blocked uninstaller did not return a nonzero exit code")
    }
    try {
        Assert-ExactArtifactSnapshot -Expected $BeforeArtifacts `
            -Paths $SnapshotPaths -Label "$Product blocked uninstall"
    }
    catch {
        $Failures.Add($_.Exception.Message)
    }
    try {
        $AfterArp = Get-ArpRegistrationSnapshot `
            -Product $Product -ScratchRoot $ProbeRoot
        Assert-ExactArpRegistrationSnapshot -Expected $BeforeArp `
            -Actual $AfterArp -Label "$Product blocked uninstaller"
    }
    catch {
        $Failures.Add($_.Exception.Message)
    }
    if ($Failures.Count -ne 0) {
        Write-FailureProbeLog -Product $Product -LogPath $MutexLog
        throw (
            "$Product uninstall SetupMutex exclusion failed: " +
            ($Failures.ToArray() -join "; ")
        )
    }
    Write-Host (
        "$Product uninstall SetupMutex rejected the competing uninstaller " +
        "with exit $BlockedExit and preserved InstallRoot/StateRoot, " +
        "shortcuts and HKLM64 ARP exactly."
    )
}

function Test-AgentStateRootMarkerRollback {
    param(
        [string]$FailureInstaller,
        [string]$ProbeRoot,
        [string]$ArpKey,
        [string[]]$ShortcutPaths,
        [string]$TransactionPrefix
    )
    $MarkerLeaf = ".mineguard-enterprise-agent-instances.json"
    $ShortcutGroup = Split-Path -Parent $ShortcutPaths[0]
    $Scenarios = @(
        [pscustomobject]@{
            Name = "preexisting-empty-unmarked"
            RootExisted = $true
            StateRelative = "state"
            MissingAncestorRelative = ""
        },
        [pscustomobject]@{
            Name = "new-state-root"
            RootExisted = $false
            StateRelative = "missing-parent-a\missing-parent-b\state"
            MissingAncestorRelative = "missing-parent-a"
        }
    )
    foreach ($Scenario in $Scenarios) {
        $ScenarioRoot = Join-Path $ProbeRoot ("state-" + $Scenario.Name)
        $InstallRoot = Join-Path $ScenarioRoot "installed"
        $StateRoot = Join-Path $ScenarioRoot ([string]$Scenario.StateRelative)
        $MissingAncestorRoot = if ([string]::IsNullOrWhiteSpace(
                [string]$Scenario.MissingAncestorRelative)) {
            ""
        }
        else {
            Join-Path $ScenarioRoot ([string]$Scenario.MissingAncestorRelative)
        }
        $FailureLog = Join-Path $ScenarioRoot "failure.log"
        New-Item -ItemType Directory -Path $ScenarioRoot | Out-Null
        if ([bool]$Scenario.RootExisted) {
            New-Item -ItemType Directory -Path $StateRoot | Out-Null
            if (@(Get-ChildItem -LiteralPath $StateRoot -Force).Count -ne 0) {
                throw "Agent StateRoot rollback fixture must start empty and unmarked."
            }
        }
        $BeforeState = Get-ExactArtifactSnapshot `
            -Paths @($InstallRoot, $StateRoot, $ShortcutGroup)
        $InstallArguments = @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/ALLOW_UNSIGNED_TEST_MEDIA=1", "/DIR=$InstallRoot",
            "/STATE_ROOT=$StateRoot", "/LOG=$FailureLog"
        )
        $FailureExit = Invoke-ProcessTreeWithTransientAccessRetry `
            -FilePath $FailureInstaller -ArgumentList $InstallArguments `
            -TimeoutSeconds 120

        $Failures = [System.Collections.Generic.List[string]]::new()
        if ($FailureExit -ne 1001) {
            $Failures.Add(
                "wrapper fault returned $FailureExit instead of exit code 1001")
        }
        if (-not (Test-Path -LiteralPath $FailureLog -PathType Leaf)) {
            $Failures.Add("wrapper fault did not create its Inno diagnostic log")
        }
        else {
            $FailureLogText = Get-Content -LiteralPath $FailureLog -Raw
            if ($FailureLogText -notmatch
                "Release audit fault injection after wrapper persistence") {
                $Failures.Add("wrapper fault did not reach ssPostInstall")
            }
        }
        try {
            Assert-ExactArtifactSnapshot -Expected $BeforeState `
                -Paths @($InstallRoot, $StateRoot, $ShortcutGroup) `
                -Label "Agent $($Scenario.Name) StateRoot rollback"
        }
        catch {
            $Failures.Add($_.Exception.Message)
        }
        $MarkerPath = Join-Path $StateRoot $MarkerLeaf
        if (Test-Path -LiteralPath $MarkerPath) {
            $Failures.Add("transaction-created StateRoot marker was retained")
        }
        if ([bool]$Scenario.RootExisted) {
            if (-not (Test-Path -LiteralPath $StateRoot -PathType Container) -or
                @(Get-ChildItem -LiteralPath $StateRoot -Force).Count -ne 0) {
                $Failures.Add(
                    "the pre-existing empty unmarked StateRoot was not restored")
            }
        }
        elseif (Test-Path -LiteralPath $StateRoot) {
            $Failures.Add("the transaction-created StateRoot was not removed")
        }
        if (Test-Path -LiteralPath $InstallRoot) {
            $Failures.Add("the transaction-created InstallRoot was not removed")
        }
        if (-not [string]::IsNullOrWhiteSpace($MissingAncestorRoot) -and
            (Test-Path -LiteralPath $MissingAncestorRoot)) {
            $Failures.Add(
                "transaction-created StateRoot ancestor directories were not removed")
        }
        if ((Invoke-RegExeForExitCode -ArgumentList @(
                "query", $ArpKey, "/reg:64")) -eq 0) {
            $Failures.Add("StateRoot rollback left an HKLM64 ARP registration")
        }
        foreach ($Shortcut in $ShortcutPaths) {
            if (Test-Path -LiteralPath $Shortcut) {
                $Failures.Add("StateRoot rollback left a shortcut: $Shortcut")
            }
        }
        $LeakedTransaction = Get-ChildItem -LiteralPath $ScenarioRoot `
            -Directory -Force |
            Where-Object { $_.Name.StartsWith($TransactionPrefix) } |
            Select-Object -First 1
        if ($null -ne $LeakedTransaction) {
            $Failures.Add(
                "StateRoot rollback leaked transaction $($LeakedTransaction.FullName)")
        }
        if ($Failures.Count -ne 0) {
            Write-FailureProbeLog -Product "agent $($Scenario.Name)" `
                -LogPath $FailureLog
            throw (
                "Agent StateRoot marker rollback probe failed: " +
                ($Failures.ToArray() -join "; ")
            )
        }
        Write-Host (
            "Agent $($Scenario.Name) failure restored the StateRoot path, " +
            "root ACL and marker absence exactly."
        )
    }
}

function Test-OneWrapperPersistenceRollback {
    param(
        [ValidateSet("platform", "agent")][string]$Product,
        [string]$OriginalStage,
        [string]$InnoScript,
        [string]$Version,
        [string]$ProbeRoot
    )
    $Stage = Join-Path $ProbeRoot "stage"
    $BaselineOutput = Join-Path $ProbeRoot "baseline-output"
    $FailureOutput = Join-Path $ProbeRoot "failure-output"
    $InstallRoot = Join-Path $ProbeRoot "installed"
    $StateRoot = Join-Path $ProbeRoot "state"
    $FailureLog = Join-Path $ProbeRoot "wrapper-failure.log"
    New-Item -ItemType Directory -Path $ProbeRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $BaselineOutput | Out-Null
    New-Item -ItemType Directory -Path $FailureOutput | Out-Null
    $ChildManifestHash = New-UnsignedWrapperProbeStage `
        -Product $Product -OriginalStage $OriginalStage -Destination $Stage
    $TrustedBootstrapHash = (Get-FileHash -LiteralPath (Join-Path $AssetsRoot `
        "Invoke-MineGuardTrustedProductInstall.ps1") -Algorithm SHA256).Hash
    $ShortcutPaths = @(Get-WrapperShortcutPaths -Product $Product)
    foreach ($Shortcut in $ShortcutPaths) {
        if (Test-Path -LiteralPath $Shortcut) {
            throw "$Product wrapper probe refuses to overwrite an existing shortcut: $Shortcut"
        }
    }
    $ApplicationId = if ($Product -eq "platform") {
        "{8B391CBD-E234-46D7-9946-E9D37F2649C1}"
    }
    else {
        "{9B73DE95-6B38-4482-A8BC-2A4FC656D05A}"
    }
    $ArpKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${ApplicationId}_is1"
    if ((Invoke-RegExeForExitCode -ArgumentList @(
            "query", $ArpKey, "/reg:64")) -eq 0) {
        throw "$Product wrapper probe refuses to overwrite an existing ARP registration."
    }
    $TransactionPrefix = if ($Product -eq "platform") {
        ".mineguard-platform-inno-transaction-"
    }
    else {
        ".mineguard-agent-inno-transaction-"
    }

    $CommonCompileArguments = @(
        "/Qp",
        "/DStageRoot=$Stage",
        "/DAssetsRoot=$AssetsRoot",
        "/DAppVersion=$Version",
        "/DNumericVersion=$Version.0",
        "/DChildReleaseManifestSha256=$ChildManifestHash",
        "/DTrustedBootstrapSha256=$TrustedBootstrapHash"
    )
    $BaselineArtifact = "MineGuard-$Product-WrapperBaseline"
    $FailureArtifact = "MineGuard-$Product-WrapperPersistenceFailure"
    Invoke-NativeChecked -FilePath $InnoCompiler -ArgumentList (
        $CommonCompileArguments + @(
            "/DOutputDir=$BaselineOutput",
            "/DArtifactFileName=$BaselineArtifact",
            $InnoScript
        )) -Label "$Product wrapper baseline compilation"
    Invoke-NativeChecked -FilePath $InnoCompiler -ArgumentList (
        $CommonCompileArguments + @(
            "/DOutputDir=$FailureOutput",
            "/DArtifactFileName=$FailureArtifact",
            "/DFailureAfterWrapperPersistenceProbe=1",
            $InnoScript
        )) -Label "$Product wrapper persistence-failure compilation"

    $InstallArguments = @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
        "/ALLOW_UNSIGNED_TEST_MEDIA=1", "/DIR=$InstallRoot"
    )
    if ($Product -eq "agent") {
        $InstallArguments += "/STATE_ROOT=$StateRoot"
    }
    $BaselineInstaller = Join-Path $BaselineOutput ($BaselineArtifact + ".exe")
    $FailureInstaller = Join-Path $FailureOutput ($FailureArtifact + ".exe")
    try {
        Test-OneSetupMutexExclusion `
            -Product $Product -InstallerPath $BaselineInstaller `
            -InstallArguments $InstallArguments -InstallRoot $InstallRoot `
            -StateRoot $StateRoot -ArpKey $ArpKey `
            -ShortcutPaths $ShortcutPaths `
            -TransactionPrefix $TransactionPrefix -ProbeRoot $ProbeRoot
        if ($Product -eq "agent") {
            Test-AgentStateRootMarkerRollback `
                -FailureInstaller $FailureInstaller `
                -ProbeRoot $ProbeRoot -ArpKey $ArpKey `
                -ShortcutPaths $ShortcutPaths `
                -TransactionPrefix $TransactionPrefix
        }
        else {
            $ShortcutGroup = Split-Path -Parent $ShortcutPaths[0]
            $FreshPaths = @($InstallRoot, $ShortcutGroup) + $ShortcutPaths
            $BeforeFreshArtifacts = Get-ExactArtifactSnapshot `
                -Paths $FreshPaths
            if ((Invoke-RegExeForExitCode -ArgumentList @(
                    "query", $ArpKey, "/reg:64")) -eq 0) {
                throw "Platform fresh wrapper fixture unexpectedly has HKLM64 ARP."
            }
            $FreshFailureLog = Join-Path $ProbeRoot `
                "fresh-wrapper-failure.log"
            $FreshFailureExit = Invoke-ProcessTreeWithTransientAccessRetry `
                -FilePath $FailureInstaller `
                -ArgumentList (@($InstallArguments) + "/LOG=$FreshFailureLog") `
                -TimeoutSeconds 120
            if ($FreshFailureExit -ne 1001) {
                Write-FailureProbeLog -Product "platform fresh wrapper" `
                    -LogPath $FreshFailureLog
                throw (
                    "Platform fresh wrapper persistence probe returned " +
                    "$FreshFailureExit instead of exit code 1001."
                )
            }
            Assert-ExactArtifactSnapshot -Expected $BeforeFreshArtifacts `
                -Paths $FreshPaths `
                -Label "platform fresh wrapper persistence rollback"
            if ((Invoke-RegExeForExitCode -ArgumentList @(
                    "query", $ArpKey, "/reg:64")) -eq 0) {
                throw "Platform fresh wrapper rollback left HKLM64 ARP."
            }
            $FreshLeakedTransaction = Get-ChildItem -LiteralPath (
                Split-Path -Parent $InstallRoot) -Directory -Force |
                Where-Object { $_.Name.StartsWith($TransactionPrefix) } |
                Select-Object -First 1
            if ($null -ne $FreshLeakedTransaction) {
                throw (
                    "Platform fresh wrapper rollback leaked transaction " +
                    $FreshLeakedTransaction.FullName
                )
            }
        }
        $BaselineExit = Invoke-ProcessTreeWithTransientAccessRetry `
            -FilePath $BaselineInstaller -ArgumentList $InstallArguments `
            -TimeoutSeconds 120
        if ($BaselineExit -ne 0) {
            throw "$Product wrapper baseline install failed with exit code $BaselineExit."
        }
        $RequiredDirectories = if ($Product -eq "platform") {
            @("runtime", "service", "launcher", "release-metadata", "docs",
              "uninstall-tools")
        }
        else {
            @("runtime", "deploy", "release-metadata", "docs", "uninstall-tools")
        }
        foreach ($Name in $RequiredDirectories) {
            if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot $Name) `
                    -PathType Container)) {
                throw "$Product baseline is missing managed wrapper directory: $Name"
            }
        }
        if ($Product -eq "platform") {
            $BaselineDocsAcl = Get-Acl -LiteralPath (
                Join-Path $InstallRoot "docs")
            if (-not $BaselineDocsAcl.AreAccessRulesProtected) {
                throw "Platform baseline docs retained inherited ACLs."
            }
        }
        $UninstallerParts = @(Get-ChildItem -LiteralPath $InstallRoot -File -Force |
            Where-Object {
                $_.Name -cmatch '^unins[0-9]{3}\.(?:exe|dat|msg)$'
            })
        if (@($UninstallerParts | Where-Object {
                    $_.Extension -eq ".exe"
                }).Count -ne 1 -or
            @($UninstallerParts | Where-Object {
                    $_.Extension -eq ".dat"
                }).Count -ne 1) {
            throw "$Product baseline does not have one complete Inno uninstaller."
        }
        foreach ($Shortcut in $ShortcutPaths) {
            if (-not (Test-Path -LiteralPath $Shortcut -PathType Leaf)) {
                throw "$Product baseline shortcut was not created: $Shortcut"
            }
        }
        $BaselineUninstaller = $UninstallerParts | Where-Object {
            $_.Extension -eq ".exe"
        } | Select-Object -First 1
        Test-OneUninstallMutexExclusion `
            -Product $Product `
            -UninstallerPath $BaselineUninstaller.FullName `
            -InstallRoot $InstallRoot -StateRoot $StateRoot `
            -ArpKey $ArpKey -ShortcutPaths $ShortcutPaths `
            -ProbeRoot $ProbeRoot
        $ManagedPaths = @($InstallRoot) + $ShortcutPaths
        if ($Product -eq "agent") { $ManagedPaths += $StateRoot }
        $BeforeArtifacts = Get-ExactArtifactSnapshot -Paths $ManagedPaths
        $BeforeArp = Get-ArpRegistrationSnapshot `
            -Product $Product -ScratchRoot $ProbeRoot

        $FaultArguments = @($InstallArguments) + "/LOG=$FailureLog"
        $FailureExit = Invoke-ProcessTreeWithTransientAccessRetry `
            -FilePath $FailureInstaller -ArgumentList $FaultArguments `
            -TimeoutSeconds 120
        if ($FailureExit -ne 1001) {
            Write-FailureProbeLog -Product $Product -LogPath $FailureLog
            throw (
                "$Product wrapper persistence probe returned $FailureExit " +
                "instead of deterministic exit code 1001."
            )
        }
        $FailureLogText = Get-Content -LiteralPath $FailureLog -Raw
        if ($FailureLogText -notmatch
            "Release audit fault injection after wrapper persistence") {
            Write-FailureProbeLog -Product $Product -LogPath $FailureLog
            throw "$Product wrapper probe failed before its ssPostInstall checkpoint."
        }
        Assert-ExactArtifactSnapshot -Expected $BeforeArtifacts `
            -Paths $ManagedPaths `
            -Label "$Product wrapper persistence rollback"
        $AfterArp = Get-ArpRegistrationSnapshot `
            -Product $Product -ScratchRoot $ProbeRoot
        Assert-ExactArpRegistrationSnapshot -Expected $BeforeArp `
            -Actual $AfterArp `
            -Label "$Product wrapper persistence rollback"
        $LeakedTransaction = Get-ChildItem -LiteralPath (
            Split-Path -Parent $InstallRoot) -Directory -Force |
            Where-Object { $_.Name.StartsWith($TransactionPrefix) } |
            Select-Object -First 1
        if ($null -ne $LeakedTransaction) {
            throw "$Product wrapper rollback leaked: $($LeakedTransaction.FullName)"
        }
        Write-Host (
            "$Product wrapper persistence failure restored product tree, docs, " +
            "launcher/deploy, uninstall-tools, uninstaller, shortcuts and HKLM64 ARP."
        )
    }
    finally {
        if (Test-Path -LiteralPath $InstallRoot) {
            try {
                $Uninstaller = Get-ChildItem -LiteralPath $InstallRoot `
                    -Filter "unins*.exe" -File | Select-Object -First 1
                if ($null -ne $Uninstaller) {
                    [void](Invoke-ProcessTreeWithTransientAccessRetry `
                        -FilePath $Uninstaller.FullName `
                        -ArgumentList @(
                            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
                        ) -TimeoutSeconds 120)
                }
            }
            catch {
                Write-Warning "$Product wrapper baseline uninstall cleanup failed: $($_.Exception.Message)"
            }
        }
        [void](Invoke-RegExeForExitCode -ArgumentList @(
            "delete", $ArpKey, "/f", "/reg:64"))
        foreach ($Shortcut in $ShortcutPaths) {
            Remove-Item -LiteralPath $Shortcut -Force -ErrorAction SilentlyContinue
        }
    }
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
    New-Item -ItemType Directory -Path $ProbeRoot -Force | Out-Null
    $PriorStage = $OriginalStage
    if ($Product -eq "agent") {
        # Seed a valid unsigned-test installation, then install the current
        # candidate classification over it.  This catches accidental reuse of
        # incoming trust switches while inspecting the existing runtime.
        $PriorStage = Join-Path $ProbeRoot "prior-agent-unsigned-test"
        [void](New-UnsignedWrapperProbeStage -Product agent `
            -OriginalStage $OriginalStage -Destination $PriorStage)
    }
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
            Join-Path $PriorStage "runtime"
        ) -Force) {
            Copy-Item -LiteralPath $Item.FullName -Destination $RuntimeRoot -Recurse
        }
        foreach ($Item in Get-ChildItem -LiteralPath (
            Join-Path $PriorStage "deploy\windows"
        ) -Force) {
            Copy-Item -LiteralPath $Item.FullName -Destination $OperationsRoot -Recurse
        }
        foreach ($MetadataName in @(
            "VERSION.txt", "build-metadata.json", "release-manifest.json",
            "SHA256SUMS.txt", "model-credential-trust.json"
        )) {
            Copy-Item -LiteralPath (Join-Path $PriorStage $MetadataName) `
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
            "$Product unsigned-test classification transition, post-switch " +
            "rollback (exit $PostSwitchExit), legacy-process rejection and " +
            "missing-metadata rejection passed."
        )
    }
}

# Wrapper install-root preflight intentionally rejects user-writable ancestors.
# A normal child created beneath ProgramData inherits permissive creator rights,
# so create a per-run direct child with a protected Administrators/SYSTEM DACL.
$ProbeParent = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData
)
if ([string]::IsNullOrWhiteSpace($ProbeParent)) {
    throw "Windows CommonApplicationData is unavailable."
}
$ProbeParent = [IO.Path]::GetFullPath($ProbeParent).TrimEnd('\')
$ProbeRoot = Join-Path $ProbeParent ([Guid]::NewGuid().ToString("N"))
$ProbeRoot = New-SecureVerificationRoot -PathValue $ProbeRoot
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
    Test-OneWrapperPersistenceRollback `
        -Product platform -OriginalStage $PlatformStage `
        -InnoScript (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardPlatform.iss") `
        -Version $PlatformVersion -ProbeRoot (Join-Path $ProbeRoot "pw")
    Test-OneWrapperPersistenceRollback `
        -Product agent -OriginalStage $AgentStage `
        -InnoScript (Join-Path $RepositoryRoot "packaging\windows\inno\MineGuardEnterpriseAgent.iss") `
        -Version $AgentVersion -ProbeRoot (Join-Path $ProbeRoot "aw")
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
            $RelativeProbeRoot = if ($FullProbeRoot.StartsWith(
                    $FullProbeParent,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $FullProbeRoot.Substring($FullProbeParent.Length)
            }
            else {
                ""
            }
            $ParsedProbeId = [Guid]::Empty
            $IsDirectGuidChild = (
                -not [string]::IsNullOrWhiteSpace($RelativeProbeRoot) -and
                -not $RelativeProbeRoot.Contains('\') -and
                [Guid]::TryParseExact(
                    $RelativeProbeRoot, "N", [ref]$ParsedProbeId
                )
            )
            if (-not $IsDirectGuidChild) {
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
