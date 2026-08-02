# Shared safety helpers for MineGuard Enterprise Agent operations.
# This file intentionally supports Windows PowerShell 5.1.

function Assert-EAPowerShell51 {
    if ($PSVersionTable.PSVersion.Major -lt 5 -or
        ($PSVersionTable.PSVersion.Major -eq 5 -and
            $PSVersionTable.PSVersion.Minor -lt 1)) {
        throw "Windows PowerShell 5.1 or later is required."
    }
}

function Assert-EAInstanceName {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$') {
        throw "Invalid InstanceName."
    }
    $BaseName = ($Value.Split('.')[0]).ToUpperInvariant()
    $Reserved = @(
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
        "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
        "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    )
    if ($Reserved -contains $BaseName) {
        throw "InstanceName is a reserved Windows device name."
    }
}

function Assert-EAOrdinaryTree {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$Name = "Directory",
        [int]$MaximumEntries = 0
    )
    $RootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $RootItem.PSIsContainer -or
        ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Name must be an ordinary directory: $Root"
    }
    $EntryCount = 0
    foreach ($Item in Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop) {
        $EntryCount += 1
        if ($MaximumEntries -gt 0 -and $EntryCount -gt $MaximumEntries) {
            throw "$Name exceeds the $MaximumEntries entry traversal limit."
        }
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Name contains a symlink, junction or reparse point: $($Item.FullName)"
        }
    }
}

function Resolve-EASafeLocalPath {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PathValue,
        [ValidateSet("Any", "Container", "Leaf")][string]$RequiredType = "Any",
        [switch]$MustExist,
        [switch]$CheckTree
    )
    if ([string]::IsNullOrWhiteSpace($PathValue) -or
        $PathValue -ne $PathValue.Trim() -or $PathValue.Contains("/") -or
        $PathValue -notmatch '^[A-Za-z]:\\') {
        throw "$Name must be supplied as an X:\ absolute local path: $PathValue"
    }
    $WithoutTrailingSeparator = $PathValue.TrimEnd('\')
    if ($WithoutTrailingSeparator.Length -le 2) {
        throw "$Name must not be a filesystem root."
    }
    foreach ($Part in ($WithoutTrailingSeparator.Substring(3) -split '\\')) {
        if ([string]::IsNullOrWhiteSpace($Part) -or $Part -in @(".", "..") -or
            $Part.EndsWith(" ") -or $Part.EndsWith(".")) {
            throw "$Name contains an empty, dot or ambiguous path component: $PathValue"
        }
    }
    $FullPath = [IO.Path]::GetFullPath($PathValue).TrimEnd('\')
    if ($FullPath -notmatch '^[A-Za-z]:\\' -or $FullPath.StartsWith("\\") -or
        $FullPath.Substring(2).Contains(":")) {
        throw "$Name must use an X:\ absolute local path without alternate data streams."
    }
    $DriveRoot = [IO.Path]::GetPathRoot($FullPath)
    $DeviceId = $DriveRoot.Substring(0, 2)
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'" -ErrorAction Stop
    if ($null -eq $Disk -or [int]$Disk.DriveType -ne 3) {
        throw "$Name must use a local fixed disk: $FullPath"
    }
    if (-not ([string]$Disk.FileSystem).Equals(
            "NTFS", [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Name must use an NTFS filesystem: $FullPath"
    }
    $Current = $FullPath
    while ($true) {
        if (Test-Path -LiteralPath $Current) {
            $CurrentItem = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            if (($CurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name contains a symlink, junction or reparse-point component: $Current"
            }
        }
        if ($Current.TrimEnd('\').Equals(
                $DriveRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
            )) { break }
        $Parent = [IO.Path]::GetDirectoryName($Current.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($Parent)) {
            throw "$Name ancestry cannot be resolved safely: $FullPath"
        }
        $Current = $Parent
    }
    if ($MustExist -and -not (Test-Path -LiteralPath $FullPath)) {
        throw "$Name does not exist: $FullPath"
    }
    if ($RequiredType -eq "Container" -and
        -not (Test-Path -LiteralPath $FullPath -PathType Container)) {
        throw "$Name must be a directory: $FullPath"
    }
    if ($RequiredType -eq "Leaf" -and
        -not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "$Name must be a file: $FullPath"
    }
    if ($CheckTree) {
        Assert-EAOrdinaryTree -Root $FullPath -Name $Name
    }
    return $FullPath
}

function Test-EAPathWithin {
    param([string]$Candidate, [string]$Parent)
    $NormalizedCandidate = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $NormalizedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $NormalizedCandidate.Equals(
        $NormalizedParent, [StringComparison]::OrdinalIgnoreCase
    ) -or $NormalizedCandidate.StartsWith(
        $NormalizedParent + '\', [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-EAWatchDirectoryBoundary {
    param(
        [string]$WatchRoot,
        [string]$InstallRoot,
        [string]$StateRoot,
        [string]$ExpectedInbox
    )
    if ($WatchRoot.Equals($ExpectedInbox, [StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    foreach ($ProductRoot in @($InstallRoot, $StateRoot)) {
        if ((Test-EAPathWithin -Candidate $WatchRoot -Parent $ProductRoot) -or
            (Test-EAPathWithin -Candidate $ProductRoot -Parent $WatchRoot)) {
            throw "Configured watch directory overlaps a protected Agent program/state boundary."
        }
    }
    $ProtectedRoots = @(
        $env:SystemRoot, $env:ProgramData, $env:ALLUSERSPROFILE,
        $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:PUBLIC
    )
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $ProtectedRoots += Join-Path $env:SystemDrive "Users"
    }
    foreach ($ProtectedCandidate in @($ProtectedRoots | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })) {
        $Protected = [IO.Path]::GetFullPath([string]$ProtectedCandidate).TrimEnd('\')
        if ((Test-EAPathWithin -Candidate $WatchRoot -Parent $Protected) -or
            (Test-EAPathWithin -Candidate $Protected -Parent $WatchRoot)) {
            throw "Configured watch directory is too broad or system-managed: $WatchRoot"
        }
    }
}

function Assert-EAOrdinaryLeaf {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [long]$MaximumBytes = 1MB
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name is missing: $Path"
    }
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $Item.Length -lt 0 -or $Item.Length -gt $MaximumBytes) {
        throw "$Name is unsafe or exceeds its size limit: $Path"
    }
}

function Get-EARequiredProperty {
    param([object]$Object, [string]$Name, [string]$Context)
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw "$Context is missing $Name." }
        return $Object[$Name]
    }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { throw "$Context is missing $Name." }
    return $Property.Value
}

function Read-EAJsonFile {
    param([string]$Path, [string]$Name, [long]$MaximumBytes = 1MB)
    Assert-EAOrdinaryLeaf -Path $Path -Name $Name -MaximumBytes $MaximumBytes
    try { $Result = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "$Name is not valid JSON: $Path" }
    if ($null -eq $Result -or $Result -is [Array] -or
        $Result.PSObject.Properties.Count -eq 0) {
        throw "$Name must contain one JSON object: $Path"
    }
    return $Result
}

function Assert-EAExactProperties {
    param([object]$Object, [string[]]$Expected, [string]$Context)
    $Actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $Wanted = @($Expected | Sort-Object)
    if ($Actual.Count -ne $Wanted.Count) {
        throw "$Context contains missing or unexpected properties."
    }
    for ($Index = 0; $Index -lt $Wanted.Count; $Index += 1) {
        if (-not $Actual[$Index].Equals($Wanted[$Index], [StringComparison]::Ordinal)) {
            throw "$Context contains missing or unexpected properties."
        }
    }
}

function Read-EAEnvironmentFile {
    param([string]$Path)
    Assert-EAOrdinaryLeaf -Path $Path -Name "Instance configuration" -MaximumBytes 1MB
    $Values = @{}
    $LineNumber = 0
    foreach ($Original in ((Get-Content -LiteralPath $Path -Raw -Encoding UTF8) -split "`r?`n")) {
        $LineNumber += 1
        $Line = $Original.Trim()
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith("#")) { continue }
        if ($Line.StartsWith("export ")) { $Line = $Line.Substring(7).TrimStart() }
        $Separator = $Line.IndexOf("=")
        if ($Separator -lt 1) { throw "Invalid KEY=VALUE record at config line $LineNumber." }
        $Key = $Line.Substring(0, $Separator).Trim()
        if ($Key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $Values.ContainsKey($Key)) {
            throw "Invalid or duplicate config key at line $LineNumber."
        }
        $Value = $Line.Substring($Separator + 1).Trim()
        if ($Value.Length -ge 1 -and $Value[0] -in @([char]34, [char]39)) {
            if ($Value.Length -lt 2 -or $Value[$Value.Length - 1] -ne $Value[0]) {
                throw "Unterminated quoted config value at line $LineNumber."
            }
            $Value = $Value.Substring(1, $Value.Length - 2)
        }
        if ($Value.IndexOf([char]0) -ge 0) {
            throw "Config value contains a forbidden control character at line $LineNumber."
        }
        $Values[$Key] = $Value
    }
    return $Values
}

function Assert-EAStateRootMarker {
    param([string]$StateRoot)
    $MarkerPath = Join-Path $StateRoot ".mineguard-enterprise-agent-instances.json"
    $Marker = Read-EAJsonFile -Path $MarkerPath -Name "StateRoot ownership marker" `
        -MaximumBytes 64KB
    $MarkerProperties = @("format", "product", "canonical_path", "root_id", "created_utc")
    Assert-EAExactProperties -Object $Marker -Expected $MarkerProperties `
        -Context "StateRoot marker"
    foreach ($Name in $MarkerProperties) {
        [void](Get-EARequiredProperty -Object $Marker -Name $Name -Context "StateRoot marker")
    }
    $RootId = [Guid]::Empty
    $CreatedUtc = [DateTimeOffset]::MinValue
    if ([string]$Marker.format -ne "mineguard-enterprise-agent-state-root-v1" -or
        [string]$Marker.product -ne "MineGuard Enterprise Agent" -or
        -not ([string]$Marker.canonical_path).TrimEnd('\').Equals(
            $StateRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase
        ) -or -not [Guid]::TryParse([string]$Marker.root_id, [ref]$RootId) -or
        $RootId -eq [Guid]::Empty -or
        -not [DateTimeOffset]::TryParse([string]$Marker.created_utc, [ref]$CreatedUtc)) {
        throw "StateRoot ownership marker does not identify this Agent state directory."
    }
    return $Marker
}

function Get-EAAgentExecutable {
    param([string]$InstallRoot)
    $RuntimeRoot = Join-Path $InstallRoot "runtime"
    $RuntimeRoot = Resolve-EASafeLocalPath -Name "Agent runtime" -PathValue $RuntimeRoot `
        -MustExist -RequiredType Container -CheckTree
    $Executable = Join-Path $RuntimeRoot "MineGuardEnterpriseAgent.exe"
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        $DevelopmentExecutable = Join-Path $RuntimeRoot ".venv\Scripts\enterprise-agent.exe"
        if (-not (Test-Path -LiteralPath $DevelopmentExecutable -PathType Leaf)) {
            throw "Installed Agent executable is missing: $Executable"
        }
        Write-Warning "Using the source-development Python runtime. Production media must use MineGuardEnterpriseAgent.exe."
        $Executable = $DevelopmentExecutable
    }
    Assert-EAOrdinaryLeaf -Path $Executable -Name "Agent executable" -MaximumBytes 2GB
    return $Executable
}

function Get-EAInstanceContext {
    param(
        [Parameter(Mandatory = $true)][string]$InstanceName,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )
    Assert-EAInstanceName -Value $InstanceName
    $InstallRoot = Resolve-EASafeLocalPath -Name "InstallRoot" -PathValue $InstallRoot `
        -MustExist -RequiredType Container
    $StateRoot = Resolve-EASafeLocalPath -Name "StateRoot" -PathValue $StateRoot `
        -MustExist -RequiredType Container
    $RootMarker = Assert-EAStateRootMarker -StateRoot $StateRoot
    $InstanceRoot = Join-Path $StateRoot $InstanceName
    $InstanceRoot = Resolve-EASafeLocalPath -Name "Instance root" -PathValue $InstanceRoot `
        -MustExist -RequiredType Container
    if (-not (Test-EAPathWithin -Candidate $InstanceRoot -Parent $StateRoot)) {
        throw "Instance root escapes StateRoot."
    }
    $MetadataPath = Join-Path $InstanceRoot "instance.json"
    $Metadata = Read-EAJsonFile -Path $MetadataPath -Name "Instance metadata" `
        -MaximumBytes 1MB
    $MetadataProperties = @(
        "format", "instance_name", "service_id", "port", "mine_id", "system_id",
        "config_path", "database_path", "acl_hardened"
    )
    Assert-EAExactProperties -Object $Metadata -Expected $MetadataProperties `
        -Context "Instance metadata"
    foreach ($Name in $MetadataProperties) {
        [void](Get-EARequiredProperty -Object $Metadata -Name $Name -Context "Instance metadata")
    }
    $ServiceId = "MineGuardEnterpriseAgent-$InstanceName"
    $ConfigPath = Join-Path $InstanceRoot "config\agent.env"
    $DatabasePath = Join-Path $InstanceRoot "data\enterprise-agent.db"
    $Port = 0
    if ([string]$Metadata.format -ne "mineguard-enterprise-agent-windows-instance-v1" -or
        -not ([string]$Metadata.instance_name).Equals(
            $InstanceName, [StringComparison]::Ordinal
        ) -or -not ([string]$Metadata.service_id).Equals(
            $ServiceId, [StringComparison]::Ordinal
        ) -or -not [int]::TryParse([string]$Metadata.port, [ref]$Port) -or
        $Port -lt 1 -or $Port -gt 65535 -or
        [string]$Metadata.mine_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        [string]$Metadata.system_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        -not ([string]$Metadata.config_path).Equals(
            $ConfigPath, [StringComparison]::OrdinalIgnoreCase
        ) -or -not ([string]$Metadata.database_path).Equals(
            $DatabasePath, [StringComparison]::OrdinalIgnoreCase
        ) -or $Metadata.acl_hardened -isnot [bool]) {
        throw "Instance metadata does not match the selected instance boundary."
    }
    foreach ($DirectoryName in @("config", "data", "logs", "backups", "inbox", "service")) {
        $DirectoryPath = Join-Path $InstanceRoot $DirectoryName
        [void](Resolve-EASafeLocalPath -Name "Instance $DirectoryName directory" `
            -PathValue $DirectoryPath -MustExist -RequiredType Container)
    }
    $Values = Read-EAEnvironmentFile -Path $ConfigPath
    foreach ($RequiredKey in @(
        "ENTERPRISE_AGENT_DB", "ENTERPRISE_AGENT_HOST", "ENTERPRISE_AGENT_PORT",
        "ENTERPRISE_MINE_ID", "ENTERPRISE_SYSTEM_ID", "PLATFORM_V2_SENDER_ID",
        "ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS"
    )) {
        if (-not $Values.ContainsKey($RequiredKey)) {
            throw "Instance configuration is missing $RequiredKey."
        }
    }
    $ConfigPort = 0
    if (-not ([string]$Values["ENTERPRISE_AGENT_DB"]).Equals(
            $DatabasePath, [StringComparison]::OrdinalIgnoreCase
        ) -or [string]$Values["ENTERPRISE_AGENT_HOST"] -ne "127.0.0.1" -or
        -not [int]::TryParse([string]$Values["ENTERPRISE_AGENT_PORT"], [ref]$ConfigPort) -or
        $ConfigPort -ne $Port -or
        [string]$Values["ENTERPRISE_MINE_ID"] -ne [string]$Metadata.mine_id -or
        [string]$Values["ENTERPRISE_SYSTEM_ID"] -ne [string]$Metadata.system_id -or
        [string]$Values["PLATFORM_V2_SENDER_ID"] -ne [string]$Metadata.system_id) {
        throw "Instance configuration identity does not match instance.json."
    }
    $WatchPaths = @(([string]$Values["ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS"]) -split ';')
    if ($WatchPaths.Count -eq 0) { throw "Instance configuration has no watch directory." }
    $ResolvedWatches = @()
    $ExpectedInbox = Join-Path $InstanceRoot "inbox"
    foreach ($WatchPath in $WatchPaths) {
        $ResolvedWatch = Resolve-EASafeLocalPath -Name "Configured watch directory" `
            -PathValue $WatchPath -MustExist -RequiredType Container
        Assert-EAWatchDirectoryBoundary -WatchRoot $ResolvedWatch `
            -InstallRoot $InstallRoot -StateRoot $StateRoot `
            -ExpectedInbox $ExpectedInbox
        foreach ($ExistingWatch in $ResolvedWatches) {
            if ((Test-EAPathWithin -Candidate $ResolvedWatch -Parent $ExistingWatch) -or
                (Test-EAPathWithin -Candidate $ExistingWatch -Parent $ResolvedWatch)) {
                throw "Configured watch directories must be unique and non-overlapping."
            }
        }
        $ResolvedWatches += $ResolvedWatch
    }
    $Executable = Get-EAAgentExecutable -InstallRoot $InstallRoot
    return [pscustomobject]@{
        InstallRoot = $InstallRoot
        StateRoot = $StateRoot
        RootId = [string]$RootMarker.root_id
        InstanceName = $InstanceName
        InstanceRoot = $InstanceRoot
        Metadata = $Metadata
        MetadataPath = $MetadataPath
        ConfigPath = $ConfigPath
        DatabasePath = $DatabasePath
        DataDirectory = (Join-Path $InstanceRoot "data")
        BackupDirectory = (Join-Path $InstanceRoot "backups")
        ServiceDirectory = (Join-Path $InstanceRoot "service")
        ServiceId = $ServiceId
        WrapperPath = (Join-Path (Join-Path $InstanceRoot "service") "$ServiceId.exe")
        Executable = $Executable
        Port = $Port
        MineId = [string]$Metadata.mine_id
        SystemId = [string]$Metadata.system_id
    }
}

function Get-EAServiceContext {
    param([Parameter(Mandatory = $true)][object]$Context)
    $Service = Get-Service -Name $Context.ServiceId -ErrorAction SilentlyContinue
    if ($null -eq $Service) { return $null }
    $CimService = Get-CimInstance Win32_Service -Filter (
        "Name='{0}'" -f $Context.ServiceId
    ) -ErrorAction Stop
    if ($null -eq $CimService) {
        throw "Windows service metadata is missing for $($Context.ServiceId)."
    }
    $RawPath = ([string]$CimService.PathName).Trim()
    $Match = if ($RawPath.StartsWith('"')) {
        [regex]::Match($RawPath, '^"(?<path>[^"]+)"$')
    } else {
        [regex]::Match($RawPath, '^(?<path>\S+)$')
    }
    if (-not $Match.Success) { throw "Windows service executable path is malformed." }
    $ServiceExecutable = Resolve-EASafeLocalPath -Name "Service wrapper" `
        -PathValue $Match.Groups["path"].Value -MustExist -RequiredType Leaf
    if (-not $ServiceExecutable.Equals(
            $Context.WrapperPath, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Windows service points outside the selected Agent instance: $ServiceExecutable"
    }
    Assert-EAOrdinaryLeaf -Path $Context.WrapperPath -Name "Service wrapper" `
        -MaximumBytes 512MB
    $Service.Refresh()
    return [pscustomobject]@{ Service = $Service; CimService = $CimService }
}

function Get-EAInstanceProcesses {
    param([Parameter(Mandatory = $true)][object]$Context)
    $Matches = @()
    foreach ($Process in Get-CimInstance Win32_Process -ErrorAction Stop) {
        $ExecutablePath = [string]$Process.ExecutablePath
        $CommandLine = [string]$Process.CommandLine
        if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { continue }
        try { $NormalizedExecutable = [IO.Path]::GetFullPath($ExecutablePath) }
        catch { continue }
        $IsWrapper = $NormalizedExecutable.Equals(
            $Context.WrapperPath, [StringComparison]::OrdinalIgnoreCase
        )
        $IsAgent = $NormalizedExecutable.Equals(
            $Context.Executable, [StringComparison]::OrdinalIgnoreCase
        )
        $BindsInstance = -not [string]::IsNullOrWhiteSpace($CommandLine) -and (
            $CommandLine.IndexOf(
                $Context.ConfigPath, [StringComparison]::OrdinalIgnoreCase
            ) -ge 0 -or $CommandLine.IndexOf(
                $Context.DatabasePath, [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        )
        if ($IsWrapper -or ($IsAgent -and $BindsInstance)) { $Matches += $Process }
    }
    return $Matches
}

function Assert-EANoInstanceProcesses {
    param([Parameter(Mandatory = $true)][object]$Context)
    $Running = @(Get-EAInstanceProcesses -Context $Context)
    if ($Running.Count -ne 0) {
        $Descriptions = @($Running | ForEach-Object {
            "PID=$($_.ProcessId) Name=$($_.Name)"
        }) -join "; "
        throw "The selected Agent instance still has running processes: $Descriptions"
    }
}

function Assert-EAInstanceIsRunning {
    param([Parameter(Mandatory = $true)][object]$Context)
    # Resolve and validate a registered wrapper if present, but never accept the
    # wrapper alone: the concrete Agent child must bind this instance config.
    [void](Get-EAServiceContext -Context $Context)
    $Running = @(Get-EAInstanceProcesses -Context $Context | Where-Object {
        -not ([IO.Path]::GetFullPath([string]$_.ExecutablePath)).Equals(
            $Context.WrapperPath, [StringComparison]::OrdinalIgnoreCase
        )
    })
    if ($Running.Count -eq 0) {
        throw "No running process is bound to the selected Agent instance."
    }
}

function Invoke-EAIcaclsChecked {
    param([string[]]$ArgumentList)
    & icacls.exe @ArgumentList | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }
}

function Remove-EAOwnedTemporaryTree {
    param(
        [string]$Path,
        [string]$ExpectedParent,
        [string]$RequiredPrefix
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $FullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $FullParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $ActualParent = [IO.Path]::GetDirectoryName($FullPath)
    $ExpectedNamePattern = '^' + [regex]::Escape($RequiredPrefix) + '[A-Fa-f0-9]{32}$'
    if (-not $ActualParent.Equals(
            $FullParent, [StringComparison]::OrdinalIgnoreCase
        ) -or [IO.Path]::GetFileName($FullPath) -notmatch $ExpectedNamePattern) {
        throw "Temporary cleanup target is outside its exact owned boundary: $FullPath"
    }
    Assert-EAOrdinaryTree -Root $FullPath -Name "Temporary cleanup target" `
        -MaximumEntries 20000
    Remove-Item -LiteralPath $FullPath -Recurse -Force
}

function Assert-EAProtectedSnapshotAcl {
    param([string]$SnapshotRoot)
    foreach ($Item in @((Get-Item -LiteralPath $SnapshotRoot -Force)) + @(
        Get-ChildItem -LiteralPath $SnapshotRoot -Force -Recurse
    )) {
        $Acl = Get-Acl -LiteralPath $Item.FullName
        foreach ($Rule in $Acl.Access) {
            $Sid = try { $Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
                catch { [string]$Rule.IdentityReference }
            $UnsafeRights = [Security.AccessControl.FileSystemRights]::Write -bor
                [Security.AccessControl.FileSystemRights]::Modify -bor
                [Security.AccessControl.FileSystemRights]::FullControl -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $Sid -in @("S-1-1-0", "S-1-5-11", "S-1-5-32-545") -and
                (($Rule.FileSystemRights -band $UnsafeRights) -ne 0)) {
                throw "Snapshot ACL permits broad modification: $($Item.FullName)"
            }
        }
    }
}

function Assert-EAExclusiveAdministrativeAcl {
    param([string]$Path, [string]$Name)
    $Acl = Get-Acl -LiteralPath $Path
    if (-not $Acl.AreAccessRulesProtected) {
        throw "$Name ACL must disable inherited access rules."
    }
    $AllowedSids = @("S-1-5-18", "S-1-5-32-544")
    $FullControlSids = @{}
    foreach ($Rule in $Acl.Access) {
        $Sid = try {
            $Rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        } catch { [string]$Rule.IdentityReference }
        if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) {
            if ($AllowedSids -notcontains $Sid) {
                throw "$Name ACL grants access to an identity other than SYSTEM/Administrators: $Sid"
            }
            $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
            if (($Rule.FileSystemRights -band $FullControl) -eq $FullControl) {
                $FullControlSids[$Sid] = $true
            }
        }
    }
    foreach ($RequiredSid in $AllowedSids) {
        if (-not $FullControlSids.ContainsKey($RequiredSid)) {
            throw "$Name ACL must grant FullControl to SYSTEM and Administrators."
        }
    }
}

function Assert-EAProtectedFileAcl {
    param([string]$Path, [string]$Name)
    Assert-EAOrdinaryLeaf -Path $Path -Name $Name -MaximumBytes 1MB
    Assert-EAExclusiveAdministrativeAcl -Path $Path -Name $Name
}

function Assert-EAProtectedDirectoryAcl {
    param([string]$Path, [string]$Name)
    $Path = Resolve-EASafeLocalPath -Name $Name -PathValue $Path `
        -MustExist -RequiredType Container
    Assert-EAExclusiveAdministrativeAcl -Path $Path -Name $Name
}

function Get-EASnapshotAuthenticationKey {
    param(
        [object]$Context,
        [string]$KeyPath = "",
        [switch]$CreateIfMissing
    )
    if ([string]::IsNullOrWhiteSpace($KeyPath)) {
        $KeyPath = Join-Path $Context.BackupDirectory "snapshot-auth.key"
    }
    # Resolve the raw explicit value before any normalization. For a new key,
    # this validates the existing parent ancestry and fixed NTFS volume.
    $KeyPath = Resolve-EASafeLocalPath -Name "Snapshot authentication key" `
        -PathValue $KeyPath
    if ((Test-EAPathWithin -Candidate $KeyPath -Parent $Context.InstallRoot) -or
        (Test-EAPathWithin -Candidate $Context.InstallRoot -Parent $KeyPath) -or
        (Test-EAPathWithin -Candidate $KeyPath -Parent $Context.DataDirectory) -or
        (Test-EAPathWithin -Candidate $Context.DataDirectory -Parent $KeyPath)) {
        throw "Snapshot authentication key must not overlap Agent program/live data."
    }
    if ((Test-EAPathWithin -Candidate $KeyPath -Parent $Context.StateRoot) -and
        -not (Test-EAPathWithin -Candidate $KeyPath -Parent $Context.BackupDirectory)) {
        throw "A snapshot key inside StateRoot must be inside this instance's backups directory."
    }
    $KeyParent = Resolve-EASafeLocalPath -Name "Snapshot key directory" `
        -PathValue (Split-Path -Parent $KeyPath) -MustExist -RequiredType Container
    Assert-EAProtectedDirectoryAcl -Path $KeyParent -Name "Snapshot key directory"
    if (-not (Test-Path -LiteralPath $KeyPath)) {
        if (-not $CreateIfMissing) {
            throw "Snapshot authentication key is missing: $KeyPath"
        }
        $KeyBytes = New-Object byte[] 32
        $Generator = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $Stream = $null
        try {
            $Generator.GetBytes($KeyBytes)
            $Stream = [IO.File]::Open(
                $KeyPath, [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write, [IO.FileShare]::None
            )
            $Stream.Write($KeyBytes, 0, $KeyBytes.Length)
            $Stream.Flush($true)
        }
        finally {
            if ($null -ne $Stream) { $Stream.Dispose() }
            $Generator.Dispose()
        }
        try {
            Invoke-EAIcaclsChecked -ArgumentList @($KeyPath, "/inheritance:r")
            Invoke-EAIcaclsChecked -ArgumentList @(
                $KeyPath, "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"
            )
        }
        catch {
            if (Test-Path -LiteralPath $KeyPath) {
                Remove-Item -LiteralPath $KeyPath -Force
            }
            throw
        }
    }
    $KeyPath = Resolve-EASafeLocalPath -Name "Snapshot authentication key" `
        -PathValue $KeyPath -MustExist -RequiredType Leaf
    Assert-EAProtectedFileAcl -Path $KeyPath -Name "Snapshot authentication key"
    $Key = [IO.File]::ReadAllBytes($KeyPath)
    if ($Key.Length -ne 32) {
        throw "Snapshot authentication key must contain exactly 32 random bytes."
    }
    return ,$Key
}

function ConvertTo-EACanonicalBase64 {
    param([string]$Value)
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    return [Convert]::ToBase64String($Encoding.GetBytes($Value))
}

function Get-EASnapshotKeyId {
    param([byte[]]$Key)
    $Sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Sha256.ComputeHash($Key))).Replace(
            "-", ""
        ).ToLowerInvariant()
    }
    finally { $Sha256.Dispose() }
}

function Get-EASnapshotCanonicalBytes {
    param([object]$Manifest)
    $Lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($FieldName in @(
        "format", "created_at", "instance_name", "service_id", "mine_id",
        "state_root_id", "integrity_note", "hmac_algorithm", "hmac_key_id"
    )) {
        $Value = [string](Get-EARequiredProperty -Object $Manifest `
            -Name $FieldName -Context "Snapshot manifest")
        $Lines.Add($FieldName + "=" + (ConvertTo-EACanonicalBase64 -Value $Value))
    }
    $ManifestFiles = Get-EARequiredProperty -Object $Manifest -Name "files" `
        -Context "Snapshot manifest"
    $FileLines = [string[]]@($ManifestFiles | ForEach-Object {
        $EntryPath = Get-EARequiredProperty -Object $_ -Name "path" `
            -Context "Snapshot file entry"
        $EntryBytes = Get-EARequiredProperty -Object $_ -Name "bytes" `
            -Context "Snapshot file entry"
        $EntrySha = Get-EARequiredProperty -Object $_ -Name "sha256" `
            -Context "Snapshot file entry"
        $Path = ConvertTo-EACanonicalBase64 -Value ([string]$EntryPath)
        $Bytes = ([long]$EntryBytes).ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
        "file=$Path`:$Bytes`:$(([string]$EntrySha).ToLowerInvariant())"
    })
    [Array]::Sort($FileLines, [StringComparer]::Ordinal)
    foreach ($FileLine in $FileLines) { $Lines.Add($FileLine) }
    $Canonical = ($Lines -join "`n") + "`n"
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    return ,$Encoding.GetBytes($Canonical)
}

function Get-EASnapshotHmacSha256 {
    param([byte[]]$Key, [object]$Manifest)
    $Hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $Hmac.Key = $Key
        $Bytes = Get-EASnapshotCanonicalBytes -Manifest $Manifest
        return ([BitConverter]::ToString($Hmac.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally { $Hmac.Dispose() }
}

function Test-EAFixedTimeHexEquals {
    param([string]$Left, [string]$Right)
    if ($Left -notmatch '^[A-Fa-f0-9]{64}$' -or
        $Right -notmatch '^[A-Fa-f0-9]{64}$') { return $false }
    $Difference = 0
    $NormalizedLeft = $Left.ToLowerInvariant()
    $NormalizedRight = $Right.ToLowerInvariant()
    for ($Index = 0; $Index -lt 64; $Index += 1) {
        $Difference = $Difference -bor (
            [int][char]$NormalizedLeft[$Index] -bxor
            [int][char]$NormalizedRight[$Index]
        )
    }
    return $Difference -eq 0
}
