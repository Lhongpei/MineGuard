#ifndef StageRoot
  #error StageRoot must point to the audited Enterprise Agent binary release.
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

#define ProductName "MineGuard Enterprise Agent"
#define ProductPublisher "MineGuard Delivery Team"

[Setup]
AppId={{9B73DE95-6B38-4482-A8BC-2A4FC656D05A}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher={#ProductPublisher}
DefaultDirName={autopf}\MineGuard\EnterpriseAgent
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
VersionInfoDescription=MineGuard enterprise-side Agent installer
UninstallDisplayIcon={app}\runtime\MineGuardEnterpriseAgent.exe
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
Name: "chinesesimplified"; MessagesFile: "languages\ChineseSimplified.isl"

[Files]
; This is the exact audited child-product staging layout. The installer never
; rebuilds the Agent and never imports a root-level duplicate entry point. It
; is unpacked only long enough for the product installer to verify its manifest
; and perform the guarded runtime switch and ACL setup.
Source: "{#StageRoot}\runtime\*"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs deleteafterinstall
Source: "{#StageRoot}\deploy\windows\*"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease\deploy\windows"; Flags: ignoreversion recursesubdirs createallsubdirs deleteafterinstall
Source: "{#StageRoot}\VERSION.txt"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease"; Flags: ignoreversion deleteafterinstall
Source: "{#StageRoot}\build-metadata.json"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease"; Flags: ignoreversion deleteafterinstall
Source: "{#StageRoot}\release-manifest.json"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease"; Flags: ignoreversion deleteafterinstall
; Keep the uninstall transaction runner outside every product-owned directory
; that it atomically quarantines. Inno owns and removes this protected copy.
Source: "{#StageRoot}\deploy\windows\Uninstall-EnterpriseAgentRuntime.ps1"; DestDir: "{app}\uninstall-tools"; Flags: ignoreversion
Source: "{#AssetsRoot}\Windows-binary-release-guide.html"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#AssetsRoot}\RELEASE-NOTICE.txt"; DestDir: "{app}\docs"; Flags: ignoreversion
; Keep the guarded product transaction as the final [Files] action. If any
; ordinary payload copy fails, the product runtime has not been switched yet.
Source: "{#StageRoot}\SHA256SUMS.txt"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease"; Flags: ignoreversion deleteafterinstall; AfterInstall: InstallProductRuntime

[Icons]
Name: "{group}\MineGuard Enterprise Agent deployment guide"; Filename: "{app}\docs\Windows-binary-release-guide.html"
Name: "{group}\Create an enterprise mine instance"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\deploy\windows\New-EnterpriseAgentInstance.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\deploy\windows"
Name: "{group}\Enterprise Agent operations console"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoExit -NoProfile -Command ""Set-Location -LiteralPath '{app}\deploy\windows'; Get-Content -LiteralPath '.\README.md' -TotalCount 45"""; WorkingDir: "{app}\deploy\windows"

[Run]
Filename: "{app}\docs\Windows-binary-release-guide.html"; Description: "Open the deployment guide"; Flags: postinstall shellexec skipifsilent nowait

[UninstallDelete]
; Product-owned immutable directories are removed only by the guarded
; same-volume quarantine transaction in [Code]. Never list runtime, deploy,
; release-metadata or any ProgramData instance/state directory here.
Type: filesandordirs; Name: "{app}\uninstall-tools"

[Code]
var
  RuntimeRemovalCompleted: Boolean;

function HasEnterpriseAgentService(): Boolean;
var
  ServiceNames: TArrayOfString;
  I: Integer;
begin
  Result := False;
  if RegGetSubkeyNames(HKLM64, 'SYSTEM\CurrentControlSet\Services', ServiceNames) then
  begin
    for I := 0 to GetArrayLength(ServiceNames) - 1 do
    begin
      if CompareText(Copy(ServiceNames[I], 1, 25), 'MineGuardEnterpriseAgent-') = 0 then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
end;

function HasRunningEnterpriseAgentService(): Boolean;
var
  ResultCode: Integer;
  PowerShellPath: String;
  Parameters: String;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoProfile -NonInteractive -Command "$running = @(Get-Service -Name ''MineGuardEnterpriseAgent-*'' -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne ''Stopped'' }); if ($running.Count -gt 0) { exit 42 }; exit 0"';
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Failed to inspect MineGuard Enterprise Agent service state.');
  if (ResultCode <> 0) and (ResultCode <> 42) then
    RaiseException(Format('Enterprise Agent service-state inspection failed with exit code %d.', [ResultCode]));
  Result := ResultCode = 42;
end;

function PowerShellSingleQuoted(const Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '''', '''''', True);
  Result := '''' + Result + '''';
end;

function HasActiveEnterpriseAgentRuntime(): Boolean;
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
    RaiseException('Failed to inspect active MineGuard Enterprise Agent processes.');
  if (ResultCode <> 0) and (ResultCode <> 43) then
    RaiseException(Format('Enterprise Agent process inspection failed with exit code %d.', [ResultCode]));
  Result := ResultCode = 43;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if HasRunningEnterpriseAgentService() then
    Result := 'A MineGuard Enterprise Agent service is running. Stop every MineGuardEnterpriseAgent-* service before installing or upgrading the shared runtime. Registered but stopped services are preserved.'
  else if HasActiveEnterpriseAgentRuntime() then
    Result := 'A foreground process is executing from the MineGuard Enterprise Agent runtime directory. Stop it before installing or upgrading.';
end;

procedure InstallProductRuntime();
var
  ResultCode: Integer;
  PowerShellPath: String;
  Parameters: String;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := ExpandConstant('-NoProfile -ExecutionPolicy Bypass -File "{tmp}\MineGuardEnterpriseAgentRelease\deploy\windows\Install-EnterpriseAgent.ps1" -SourceRoot "{tmp}\MineGuardEnterpriseAgentRelease" -InstallRoot "{app}" -StateRoot "{param:STATE_ROOT|{commonappdata}\MineGuard\EnterpriseAgent\instances}"');
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode, nil) then
    RaiseException('Failed to launch the guarded Enterprise Agent product installer.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded Enterprise Agent product installer failed with exit code %d. Setup has been aborted.', [ResultCode]));
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
  ScriptPath := ExpandConstant('{app}\uninstall-tools\Uninstall-EnterpriseAgentRuntime.ps1');
  if not FileExists(ScriptPath) then
    RaiseException('The guarded Enterprise Agent runtime-removal script is missing. Uninstall has been aborted before enterprise data was touched.');
  Parameters := ExpandConstant('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{app}\uninstall-tools\Uninstall-EnterpriseAgentRuntime.ps1" -InstallRoot "{app}" -InternalInnoUninstall');
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode, nil) then
    RaiseException('Failed to launch the guarded Enterprise Agent runtime-removal transaction.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded Enterprise Agent runtime-removal transaction failed with exit code %d. Uninstall has been aborted.', [ResultCode]));
  RuntimeRemovalCompleted := True;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  if HasEnterpriseAgentService() then
  begin
    SuppressibleMsgBox('A MineGuard Enterprise Agent Windows service is still registered.' + #13#10 +
      'Use Uninstall-EnterpriseAgentService.ps1 for every mine instance before uninstalling the runtime.' + #13#10 +
      'Enterprise instance data in ProgramData will be preserved.', mbError, MB_OK, IDOK);
    Result := False;
  end;
  if Result and HasActiveEnterpriseAgentRuntime() then
  begin
    SuppressibleMsgBox('A foreground process is executing from the MineGuard Enterprise Agent runtime directory.' + #13#10 +
      'Stop the process before uninstalling. Enterprise instance data in ProgramData will be preserved.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveProductRuntimeTransactionally();
end;
