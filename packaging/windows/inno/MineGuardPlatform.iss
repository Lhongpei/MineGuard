#ifndef StageRoot
  #error StageRoot must point to the audited Platform binary release.
#endif
#ifndef AssetsRoot
  #error AssetsRoot is required.
#endif
#ifndef OutputDir
  #error OutputDir is required.
#endif
#ifndef AppVersion
  #error AppVersion is required.
#endif
#ifndef NumericVersion
  #error NumericVersion is required.
#endif
#ifndef ArtifactFileName
  #error ArtifactFileName is required.
#endif

#define ProductName "MineGuard Platform"
#define ProductPublisher "MineGuard Delivery Team"

[Setup]
AppId={{8B391CBD-E234-46D7-9946-E9D37F2649C1}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher={#ProductPublisher}
DefaultDirName={commonappdata}\MineGuard\Platform
DefaultGroupName=MineGuard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible and not arm64
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename={#ArtifactFileName}
VersionInfoVersion={#NumericVersion}
VersionInfoProductVersion={#NumericVersion}
VersionInfoCompany={#ProductPublisher}
VersionInfoDescription=MineGuard government regulatory platform installer
UninstallDisplayIcon={app}\runtime\MineGuardPlatform.exe
SetupLogging=yes
RestartIfNeededByRun=no
CloseApplications=no
#ifdef EnableSigning
SignTool=release_signer
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Files]
; Consume the exact audited Platform staging layout. The root installer does not
; carry a second Python entry point or a second Nuitka build definition. The
; product installer validates the temporary media, switches runtime atomically
; and applies the Platform ACLs.
Source: "{#StageRoot}\runtime\*"; DestDir: "{tmp}\MineGuardPlatformRelease\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs deleteafterinstall
Source: "{#StageRoot}\deploy\windows\*"; DestDir: "{tmp}\MineGuardPlatformRelease\deploy\windows"; Flags: ignoreversion recursesubdirs createallsubdirs deleteafterinstall
Source: "{#StageRoot}\VERSION.txt"; DestDir: "{tmp}\MineGuardPlatformRelease"; Flags: ignoreversion deleteafterinstall
Source: "{#StageRoot}\build-metadata.json"; DestDir: "{tmp}\MineGuardPlatformRelease"; Flags: ignoreversion deleteafterinstall
Source: "{#StageRoot}\release-manifest.json"; DestDir: "{tmp}\MineGuardPlatformRelease"; Flags: ignoreversion deleteafterinstall
; Keep the uninstall transaction runner outside every product-owned directory
; that it atomically quarantines. Inno owns and removes this protected copy.
Source: "{#StageRoot}\deploy\windows\Uninstall-MineGuardPlatformRuntime.ps1"; DestDir: "{app}\uninstall-tools"; Flags: ignoreversion
Source: "{#AssetsRoot}\Windows-binary-release-guide.html"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#AssetsRoot}\RELEASE-NOTICE.txt"; DestDir: "{app}\docs"; Flags: ignoreversion
; Keep the guarded product transaction as the final [Files] action. If any
; ordinary payload copy fails, the product runtime has not been switched yet.
Source: "{#StageRoot}\SHA256SUMS.txt"; DestDir: "{tmp}\MineGuardPlatformRelease"; Flags: ignoreversion deleteafterinstall; AfterInstall: InstallProductRuntime

[Icons]
Name: "{group}\MineGuard Platform deployment guide"; Filename: "{app}\docs\Windows-binary-release-guide.html"
Name: "{group}\Configure MineGuard Platform"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoExit -NoProfile -ExecutionPolicy Bypass -Command ""Write-Host 'Read the deployment guide, prepare clients.json and an administrator password, then run:' -ForegroundColor Cyan; Write-Host '& .\Set-MineGuardPlatformConfiguration.ps1 -InstallRoot ''{app}'' -ClientsFile ''C:\approved\clients.json'''; Set-Location -LiteralPath '{app}\service'"""; WorkingDir: "{app}\service"
Name: "{group}\MineGuard Platform operations console"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoExit -NoProfile -Command ""Set-Location -LiteralPath '{app}\service'; Get-ChildItem -Filter '*.ps1' | Select-Object Name"""; WorkingDir: "{app}\service"

[Run]
Filename: "{app}\docs\Windows-binary-release-guide.html"; Description: "Open the deployment guide"; Flags: postinstall shellexec skipifsilent nowait

[UninstallDelete]
; Product-owned immutable directories are removed only by the guarded
; same-volume quarantine transaction in [Code]. Never list runtime, deploy,
; service, release-metadata, config, state, backups or logs here.
Type: filesandordirs; Name: "{app}\uninstall-tools"

[Code]
var
  RuntimeRemovalCompleted: Boolean;

function HasMineGuardPlatformService(): Boolean;
begin
  Result := RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\MineGuardPlatform');
end;

function HasRunningMineGuardPlatformService(): Boolean;
var
  ResultCode: Integer;
  PowerShellPath: String;
  Parameters: String;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoProfile -NonInteractive -Command "$service = Get-Service -Name ''MineGuardPlatform'' -ErrorAction SilentlyContinue; if (($null -ne $service) -and ($service.Status -ne ''Stopped'')) { exit 42 }; exit 0"';
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Failed to inspect MineGuardPlatform service state.');
  if (ResultCode <> 0) and (ResultCode <> 42) then
    RaiseException(Format('MineGuardPlatform service-state inspection failed with exit code %d.', [ResultCode]));
  Result := ResultCode = 42;
end;

function PowerShellSingleQuoted(const Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '''', '''''', True);
  Result := '''' + Result + '''';
end;

function HasActiveMineGuardPlatformRuntime(): Boolean;
var
  ResultCode: Integer;
  PowerShellPath: String;
  RuntimeRoot: String;
  Parameters: String;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  RuntimeRoot := ExpandConstant('{app}\runtime');
  Parameters := '-NoProfile -NonInteractive -Command "$root = [IO.Path]::GetFullPath(' +
    PowerShellSingleQuoted(RuntimeRoot) +
    '); $root = $root.TrimEnd([char]92) + [char]92; $active = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { if (-not $_.ExecutablePath) { $false } else { try { $candidate = [IO.Path]::GetFullPath([string]$_.ExecutablePath); $candidate.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) } catch { $false } } }); if ($active.Count -gt 0) { exit 43 }; exit 0"';
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Failed to inspect active MineGuardPlatform processes.');
  if (ResultCode <> 0) and (ResultCode <> 43) then
    RaiseException(Format('MineGuardPlatform process inspection failed with exit code %d.', [ResultCode]));
  Result := ResultCode = 43;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if HasRunningMineGuardPlatformService() then
    Result := 'The MineGuardPlatform service is running. Stop it before installing or upgrading the runtime. A registered but stopped service is preserved.'
  else if HasActiveMineGuardPlatformRuntime() then
    Result := 'A foreground process is executing from the MineGuard Platform runtime directory. Stop it before installing or upgrading.';
end;

procedure InstallProductRuntime();
var
  ResultCode: Integer;
  PowerShellPath: String;
  Parameters: String;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := ExpandConstant('-NoProfile -ExecutionPolicy Bypass -File "{tmp}\MineGuardPlatformRelease\deploy\windows\Install-MineGuardPlatform.ps1" -SourceDirectory "{tmp}\MineGuardPlatformRelease" -InstallRoot "{app}"');
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode, nil) then
    RaiseException('Failed to launch the guarded MineGuard Platform product installer.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded MineGuard Platform product installer failed with exit code %d. Setup has been aborted.', [ResultCode]));
end;

procedure RemoveProductRuntimeTransactionally();
var
  ResultCode: Integer;
  PowerShellPath: String;
  ScriptPath: String;
  Parameters: String;
begin
  if RuntimeRemovalCompleted then
    Exit;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  ScriptPath := ExpandConstant('{app}\uninstall-tools\Uninstall-MineGuardPlatformRuntime.ps1');
  if not FileExists(ScriptPath) then
    RaiseException('The guarded MineGuard Platform runtime-removal script is missing. Uninstall has been aborted before product data was touched.');
  Parameters := ExpandConstant('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{app}\uninstall-tools\Uninstall-MineGuardPlatformRuntime.ps1" -InstallRoot "{app}" -InternalInnoUninstall');
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode, nil) then
    RaiseException('Failed to launch the guarded MineGuard Platform runtime-removal transaction.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded MineGuard Platform runtime-removal transaction failed with exit code %d. Uninstall has been aborted.', [ResultCode]));
  RuntimeRemovalCompleted := True;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  if HasMineGuardPlatformService() then
  begin
    SuppressibleMsgBox('The MineGuardPlatform Windows service is still registered.' + #13#10 +
      'Run Remove-MineGuardPlatformService.ps1 before uninstalling the runtime.' + #13#10 +
      'Government configuration, state, backups and logs will be preserved.', mbError, MB_OK, IDOK);
    Result := False;
  end;
  if Result and HasActiveMineGuardPlatformRuntime() then
  begin
    SuppressibleMsgBox('A foreground process is executing from the MineGuard Platform runtime directory.' + #13#10 +
      'Stop the process before uninstalling. Government configuration, state, backups and logs will be preserved.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveProductRuntimeTransactionally();
end;
