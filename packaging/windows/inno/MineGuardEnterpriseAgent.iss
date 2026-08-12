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
#ifndef MinimumWindowsVersion
  #define MinimumWindowsVersion "10.0.17763"
#endif
#ifdef EnableSigning
#ifdef InternalUnsignedRelease
  #error EnableSigning and InternalUnsignedRelease are mutually exclusive.
#endif
#endif
#ifndef ChildReleaseManifestSha256
  #error The audited child release-manifest SHA-256 is required for every release classification.
#endif
#ifndef TrustedBootstrapSha256
  #error The reviewed trusted product bootstrap SHA-256 is required.
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
MinVersion={#MinimumWindowsVersion}
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
; Serialize both products across Windows sessions. Their retained transaction
; directories share one MineGuard parent and must never recover a live peer.
SetupMutex=MineGuard-Setup-Transaction-v1,Global\MineGuard-Setup-Transaction-v1
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
; These temporary transaction inputs are deliberately first for solid-compression
; extraction. CurStepChanged(ssInstall) extracts them before Inno writes any
; persistent Files/Icons/ARP/uninstaller state. They are never copied normally.
Source: "{#AssetsRoot}\Invoke-MineGuardTrustedProductInstall.ps1"; Flags: dontcopy noencryption
Source: "{#StageRoot}\*"; DestDir: "{tmp}\MineGuardEnterpriseAgentRelease"; Flags: ignoreversion recursesubdirs createallsubdirs dontcopy noencryption
; Keep the uninstall transaction runner outside every product-owned directory
; that it atomically quarantines. Inno owns and removes this protected copy.
Source: "{#StageRoot}\deploy\windows\Uninstall-EnterpriseAgentRuntime.ps1"; DestDir: "{app}\uninstall-tools"; Flags: ignoreversion
Source: "{#AssetsRoot}\Windows-binary-release-guide.html"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#AssetsRoot}\RELEASE-NOTICE.txt"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{commonprograms}\MineGuard\MineGuard Enterprise Agent deployment guide"; Filename: "{app}\docs\Windows-binary-release-guide.html"
Name: "{commonprograms}\MineGuard\MineGuard 企业接入配置向导"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File ""{app}\deploy\windows\Start-EnterpriseAgentProvisioningWizard.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\deploy\windows"
Name: "{commonprograms}\MineGuard\MineGuard 模型授权导入向导"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File ""{app}\deploy\windows\Start-EnterpriseAgentModelCredentialWizard.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\deploy\windows"
Name: "{commonprograms}\MineGuard\Enterprise Agent operations console"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoExit -NoProfile -Command ""Set-Location -LiteralPath '{app}\deploy\windows'; Get-Content -LiteralPath '.\README.md' -TotalCount 45"""; WorkingDir: "{app}\deploy\windows"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File ""{app}\deploy\windows\Start-EnterpriseAgentProvisioningWizard.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\deploy\windows"; Description: "立即打开 MineGuard 企业接入配置向导"; Flags: postinstall skipifsilent nowait; Check: IsWrapperTransactionConfirmed
Filename: "{app}\docs\Windows-binary-release-guide.html"; Description: "Open the deployment guide"; Flags: postinstall shellexec skipifsilent nowait; Check: IsWrapperTransactionConfirmed

[UninstallDelete]
; Product-owned immutable directories are removed only by the guarded
; same-volume quarantine transaction in [Code]. Never list runtime, deploy,
; release-metadata or any ProgramData instance/state directory here.
Type: filesandordirs; Name: "{app}\uninstall-tools"

[Code]
const
  ProductInstallFailureExitCode = 1001;
  ProductTransactionMutexes =
    'MineGuard-Setup-Transaction-v1,Global\MineGuard-Setup-Transaction-v1';
  ProductTransactionLocalMutex = 'MineGuard-Setup-Transaction-v1';
  ProductTransactionGlobalMutex = 'Global\MineGuard-Setup-Transaction-v1';

var
  RuntimeRemovalCompleted: Boolean;
  ProductInstallFailed: Boolean;
  ProductTransactionStarted: Boolean;
  ProductTransactionPrepared: Boolean;
  WrapperTransactionSucceeded: Boolean;
  ProductTransactionId: String;
  ReleaseAuthorizationCaptured: Boolean;
  WrapperOriginalStateCaptured: Boolean;
  WrapperInstallRootPreexisted: Boolean;
  WrapperShortcutGroupPreexisted: Boolean;
  WrapperOriginalInstallRoot: String;
  WrapperOriginalExistingInstallAncestor: String;
#ifdef EnableSigning
  SignerInputPage: TInputQueryWizardPage;
  SignerFilePage: TInputFileWizardPage;
  ApprovedSignerThumbprint: String;
#else
#ifdef InternalUnsignedRelease
  InternalUnsignedHashPage: TInputQueryWizardPage;
  InternalUnsignedConfirmationPage: TInputOptionWizardPage;
  ApprovedInstallerSha256: String;
#else
  UnsignedTestPage: TInputOptionWizardPage;
#endif
#endif

function IsWrapperTransactionConfirmed(): Boolean;
begin
  Result := WrapperTransactionSucceeded and (not ProductInstallFailed);
end;

function NormalizeSignerThumbprint(const Value: String; var Normalized: String): Boolean;
var
  I: Integer;
  Ch: String;
begin
  Normalized := '';
  for I := 1 to Length(Value) do
  begin
    Ch := Copy(Value, I, 1);
    if (Ch = ' ') or (Ch = #9) or (Ch = #10) or (Ch = #13) then
    begin
      { Offline approval sheets often group a SHA-1 thumbprint with spaces. }
    end
    else if Pos(UpperCase(Ch), '0123456789ABCDEF') > 0 then
      Normalized := Normalized + UpperCase(Ch)
    else
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := Length(Normalized) = 40;
end;

#ifdef EnableSigning
function MergeApprovedSignerSource(const RawValue: String; const SourceName: String;
  var MergedValue: String; var ErrorText: String): Boolean;
var
  Candidate: String;
begin
  Result := False;
  if Trim(RawValue) = '' then
  begin
    Result := True;
    Exit;
  end;
  if not NormalizeSignerThumbprint(RawValue, Candidate) then
  begin
    ErrorText := SourceName + ' must contain exactly 40 hexadecimal SHA-1 characters.';
    Exit;
  end;
  if (MergedValue <> '') and (CompareText(MergedValue, Candidate) <> 0) then
  begin
    ErrorText := 'The approved signer thumbprints supplied by different offline sources do not match.';
    Exit;
  end;
  MergedValue := Candidate;
  Result := True;
end;

function TryResolveApprovedSigner(var ResolvedValue: String;
  var ErrorText: String): Boolean;
var
  CommandLineValue: String;
  ImportedText: AnsiString;
begin
  Result := False;
  ResolvedValue := '';
  ErrorText := '';
  CommandLineValue := ExpandConstant('{param:APPROVED_SIGNER_THUMBPRINT|}');
  if not MergeApprovedSignerSource(CommandLineValue, 'Command-line approval',
      ResolvedValue, ErrorText) then
    Exit;
  if not MergeApprovedSignerSource(SignerInputPage.Values[0], 'Pasted approval',
      ResolvedValue, ErrorText) then
    Exit;
  if Trim(SignerFilePage.Values[0]) <> '' then
  begin
    if not LoadStringFromFile(SignerFilePage.Values[0], ImportedText) then
    begin
      ErrorText := 'The selected offline approval file could not be read.';
      Exit;
    end;
    if not MergeApprovedSignerSource(String(ImportedText), 'Imported approval file',
        ResolvedValue, ErrorText) then
      Exit;
  end;
  if ResolvedValue = '' then
  begin
    ErrorText := 'Formal installation requires the approved signer thumbprint from independently delivered offline approval material.';
    Exit;
  end;
  Result := True;
end;
#else
#ifdef InternalUnsignedRelease
function NormalizeSha256(const Value: String; var Normalized: String): Boolean;
var
  I: Integer;
  Ch: String;
begin
  Normalized := '';
  for I := 1 to Length(Value) do
  begin
    Ch := Copy(Value, I, 1);
    if (Ch = ' ') or (Ch = #9) or (Ch = #10) or (Ch = #13) then
    begin
      { Permit grouped hashes copied from an independently delivered sheet. }
    end
    else if Pos(UpperCase(Ch), '0123456789ABCDEF') > 0 then
      Normalized := Normalized + UpperCase(Ch)
    else
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := Length(Normalized) = 64;
end;

function TryAuthorizeUnsignedInternalRelease(var ResolvedHash: String;
  var ErrorText: String): Boolean;
var
  RawHash: String;
  ActualHash: String;
  CommandAuthorization: String;
begin
  Result := False;
  ResolvedHash := '';
  ErrorText := '';
  CommandAuthorization := Trim(ExpandConstant('{param:ALLOWUNSIGNEDINTERNALRELEASE|}'));
  if WizardSilent then
  begin
    if CommandAuthorization <> '1' then
    begin
      ErrorText := 'Silent INTERNAL-UNSIGNED installation requires /ALLOWUNSIGNEDINTERNALRELEASE=1.';
      Exit;
    end;
    RawHash := ExpandConstant('{param:EXPECTEDINSTALLERSHA256|}');
    if Trim(RawHash) = '' then
    begin
      ErrorText := 'Silent INTERNAL-UNSIGNED installation requires /EXPECTEDINSTALLERSHA256=<64 hex>.';
      Exit;
    end;
  end
  else
  begin
    RawHash := InternalUnsignedHashPage.Values[0];
    if not InternalUnsignedConfirmationPage.Values[0] then
    begin
      ErrorText := 'Confirm that the expected SHA-256 came from a channel separate from this installer.';
      Exit;
    end;
  end;
  if not NormalizeSha256(RawHash, ResolvedHash) then
  begin
    ErrorText := 'Expected installer SHA-256 must contain exactly 64 hexadecimal characters.';
    Exit;
  end;
  ActualHash := UpperCase(GetSHA256OfFile(ExpandConstant('{srcexe}')));
  if (Length(ActualHash) <> 64) or (CompareText(ActualHash, ResolvedHash) <> 0) then
  begin
    ErrorText := 'This Setup file does not match the independently supplied SHA-256. Installation is blocked.';
    Exit;
  end;
  Result := True;
end;
#else
function IsUnsignedTestMediaAuthorized(): Boolean;
var
  CommandLineValue: String;
begin
  CommandLineValue := Trim(ExpandConstant('{param:ALLOW_UNSIGNED_TEST_MEDIA|}'));
  Result := (CommandLineValue = '1') or UnsignedTestPage.Values[0];
end;
#endif
#endif

procedure InitializeWizard();
begin
#ifdef EnableSigning
  SignerInputPage := CreateInputQueryPage(wpSelectDir,
    'Independent signer approval',
    'Paste the approved Agent signer SHA-1 thumbprint',
    'Use the value from independently delivered offline approval material. The installer never trusts or prefills a value from its own media metadata.');
  SignerInputPage.Add('Approved signer thumbprint (40 hexadecimal characters):', False);
  SignerInputPage.Values[0] := ExpandConstant('{param:APPROVED_SIGNER_THUMBPRINT|}');
  SignerFilePage := CreateInputFilePage(SignerInputPage.ID,
    'Import offline signer approval',
    'Optionally select a text file containing only the approved thumbprint',
    'If both pasted and imported values are supplied, they must match exactly.');
  SignerFilePage.Add('Offline approval text file:',
    'Text files (*.txt)|*.txt|All files (*.*)|*.*', '.txt');
#else
#ifdef InternalUnsignedRelease
  InternalUnsignedHashPage := CreateInputQueryPage(wpSelectDir,
    'INTERNAL-UNSIGNED 介质核验',
    '粘贴通过另一渠道取得的本安装包 SHA-256',
    '此版本未做 Authenticode 签名。请从电话、纸质交接单或独立审批系统取得 64 位 SHA-256；不要从本安装包所在 U 盘读取该值。');
  InternalUnsignedHashPage.Add('介质外 Setup SHA-256：', False);
  InternalUnsignedHashPage.Values[0] := ExpandConstant('{param:EXPECTEDINSTALLERSHA256|}');
  InternalUnsignedConfirmationPage := CreateInputOptionPage(InternalUnsignedHashPage.ID,
    '确认独立核验渠道',
    '确认摘要不是从当前安装介质取得',
    '只有摘要与当前 Setup 文件完全一致，安装才能继续。INTERNAL-UNSIGNED 仍不提供 Authenticode 发布者身份签名。',
    False, False);
  InternalUnsignedConfirmationPage.Add('我确认上述 SHA-256 来自当前安装介质之外的独立渠道。');
#else
  UnsignedTestPage := CreateInputOptionPage(wpSelectDir,
    'Unsigned internal test media',
    'This build cannot be used as a formal installation',
    'Continue only on an isolated test machine. It cannot install a production-trusted service.',
    False, False);
  UnsignedTestPage.Add('I explicitly authorize this unsigned internal-test installation.');
#endif
#endif
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  ErrorText: String;
  ResolvedValue: String;
begin
  Result := True;
#ifdef EnableSigning
  if CurPageID = SignerFilePage.ID then
  begin
    if not TryResolveApprovedSigner(ResolvedValue, ErrorText) then
    begin
      MsgBox(ErrorText, mbError, MB_OK);
      Result := False;
    end
    else
    begin
      ApprovedSignerThumbprint := ResolvedValue;
      ReleaseAuthorizationCaptured := True;
    end;
  end;
#else
#ifdef InternalUnsignedRelease
  if (CurPageID = InternalUnsignedConfirmationPage.ID) and
      (not TryAuthorizeUnsignedInternalRelease(ResolvedValue, ErrorText)) then
  begin
    MsgBox(ErrorText, mbError, MB_OK);
    Result := False;
  end
  else if CurPageID = InternalUnsignedConfirmationPage.ID then
  begin
    ApprovedInstallerSha256 := ResolvedValue;
    ReleaseAuthorizationCaptured := True;
  end;
#else
  if (CurPageID = UnsignedTestPage.ID) and
      (not IsUnsignedTestMediaAuthorized()) then
  begin
    MsgBox('Unsigned test media requires explicit test authorization.', mbError, MB_OK);
    Result := False;
  end;
#endif
#endif
end;

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

procedure CaptureWrapperOriginalState();
var
  Cursor: String;
  Parent: String;
begin
  if WrapperOriginalStateCaptured then
  begin
    if CompareText(ExpandConstant('{app}'), WrapperOriginalInstallRoot) <> 0 then
      RaiseException(
        'The install directory changed after its original state was captured. Close Setup and restart it to use a different directory.');
    Exit;
  end;
  WrapperOriginalInstallRoot := ExpandConstant('{app}');
  WrapperInstallRootPreexisted := DirExists(ExpandConstant('{app}'));
  WrapperShortcutGroupPreexisted := DirExists(
    ExpandConstant('{commonprograms}\MineGuard'));
  Cursor := WrapperOriginalInstallRoot;
  while not DirExists(Cursor) do
  begin
    Parent := ExtractFileDir(Cursor);
    if (Parent = '') or (CompareText(Parent, Cursor) = 0) then
      Break;
    Cursor := Parent;
  end;
  WrapperOriginalExistingInstallAncestor := Cursor;
  WrapperOriginalStateCaptured := True;
end;

procedure CleanupWrapperCreatedEmptyInstallChain();
var
  Cursor: String;
  Parent: String;
begin
  if (not WrapperOriginalStateCaptured) or
      WrapperInstallRootPreexisted then
    Exit;
  Cursor := WrapperOriginalInstallRoot;
  while CompareText(Cursor, WrapperOriginalExistingInstallAncestor) <> 0 do
  begin
    if DirExists(Cursor) then
    begin
      if not RemoveDir(Cursor) then
        Exit;
    end
    else if FileExists(Cursor) then
      Exit;
    Parent := ExtractFileDir(Cursor);
    if (Parent = '') or (CompareText(Parent, Cursor) = 0) then
      Exit;
    Cursor := Parent;
  end;
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

function PreflightEnterpriseAgentInstallRoot(var ErrorText: String): Boolean;
var
  ResultCode: Integer;
  PowerShellPath: String;
  CommandText: String;
  Parameters: String;
begin
  Result := False;
  ErrorText := '';
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  CommandText :=
    'Set-StrictMode -Version 2.0;$ErrorActionPreference=''Stop'';' +
    '$target=[IO.Path]::GetFullPath(' +
      PowerShellSingleQuoted(ExpandConstant('{app}')) + ').TrimEnd([char]92);' +
    '$root=[IO.Path]::GetPathRoot($target);' +
    'if([string]::IsNullOrWhiteSpace($root)-or($root.Length-ne 3)-or' +
      '($root[1]-ne[char]58)-or($root[2]-ne[char]92)){' +
      'throw ''Install root must be an absolute local drive path.''};' +
    'if($target.Equals($root.TrimEnd([char]92),' +
      '[StringComparison]::OrdinalIgnoreCase)){' +
      'throw ''Install root cannot be a drive root.''};' +
    '$drive=[IO.DriveInfo]::new($root);' +
    'if((-not $drive.IsReady)-or($drive.DriveType-ne[IO.DriveType]::Fixed)-or' +
      '(-not $drive.DriveFormat.Equals(''NTFS'',' +
      '[StringComparison]::OrdinalIgnoreCase))){' +
      'throw ''Install root must be on a ready local fixed NTFS volume.''};' +
    'function Assert-Ancestors([string]$p){$cursor=$p;while($true){' +
      'if([IO.File]::Exists($cursor)-and(-not[IO.Directory]::Exists($cursor))){' +
      'throw ''Install path component is a file: ''+$cursor};' +
      'if([IO.Directory]::Exists($cursor)){' +
      '$a=[IO.File]::GetAttributes($cursor);' +
      'if(($a-band[IO.FileAttributes]::ReparsePoint)-ne 0){' +
      'throw ''Install path contains a reparse point: ''+$cursor}};' +
      'if($cursor.TrimEnd([char]92).Equals($root.TrimEnd([char]92),' +
      '[StringComparison]::OrdinalIgnoreCase)){break};' +
      '$next=[IO.Path]::GetDirectoryName($cursor);' +
      'if([string]::IsNullOrWhiteSpace($next)-or($next-eq$cursor)){break};' +
      '$cursor=$next}};' +
    'function Assert-Tree([string]$p){' +
      '$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($p);' +
      'while($q.Count-gt 0){$d=$q.Dequeue();' +
      'foreach($child in [IO.Directory]::GetFileSystemEntries($d)){' +
      '$a=[IO.File]::GetAttributes($child);' +
      'if(($a-band[IO.FileAttributes]::ReparsePoint)-ne 0){' +
      'throw ''Install tree contains a reparse point: ''+$child};' +
      'if(($a-band[IO.FileAttributes]::Directory)-ne 0){$q.Enqueue($child)}}}};' +
    'function Get-Sha256([string]$p){$s=[IO.File]::OpenRead($p);' +
      '$h=[Security.Cryptography.SHA256]::Create();try{' +
      'return [BitConverter]::ToString($h.ComputeHash($s)).Replace(''-'','''').' +
      'ToLowerInvariant()}finally{$h.Dispose();$s.Dispose()}};' +
    'function Assert-ExistingProduct([string]$p){' +
      '$meta=[IO.Path]::Combine($p,''release-metadata'');' +
      '$mp=[IO.Path]::Combine($meta,''release-manifest.json'');' +
      '$bp=[IO.Path]::Combine($meta,''build-metadata.json'');' +
      '$vp=[IO.Path]::Combine($meta,''VERSION.txt'');' +
      '$exe=[IO.Path]::Combine($p,''runtime'',''MineGuardEnterpriseAgent.exe'');' +
      'foreach($required in @($mp,$bp,$vp,$exe)){' +
      'if(-not[IO.File]::Exists($required)){' +
      'throw ''Pre-existing non-empty directory is not a verified MineGuard Enterprise Agent installation.''}};' +
      '$m=[IO.File]::ReadAllText($mp,[Text.Encoding]::UTF8)|ConvertFrom-Json;' +
      '$b=[IO.File]::ReadAllText($bp,[Text.Encoding]::UTF8)|ConvertFrom-Json;' +
      '$v=[IO.File]::ReadAllText($vp,[Text.Encoding]::UTF8).Trim();' +
      'if(([string]$m.product-cne''MineGuard Enterprise Agent'')-or' +
      '([string]$m.entrypoint-cne''runtime/MineGuardEnterpriseAgent.exe'')-or' +
      '([string]$b.product-cne''MineGuard Enterprise Agent'')-or' +
      '([string]$m.version-cne$v)-or([string]$b.version-cne$v)){' +
      'throw ''Existing installation identity does not match MineGuard Enterprise Agent.''};' +
      '$entries=@($m.files|Where-Object{' +
      '[string]$_.path-ceq''runtime/MineGuardEnterpriseAgent.exe''});' +
      'if($entries.Count-ne 1){throw ''Existing Agent manifest has no unique executable entry.''};' +
      '$fi=[IO.FileInfo]::new($exe);$entry=$entries[0];' +
      'if(([long]$fi.Length-ne[long]$entry.bytes)-or' +
      '((Get-Sha256 $exe)-cne([string]$entry.sha256).ToLowerInvariant())){' +
      'throw ''Existing Agent executable does not match its release manifest.''}};' +
    '$admin=[Security.Principal.SecurityIdentifier]::new(''S-1-5-32-544'');' +
    '$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit-bor' +
      '[Security.AccessControl.InheritanceFlags]::ObjectInherit;' +
    '$none=[Security.AccessControl.PropagationFlags]::None;' +
    '$allow=[Security.AccessControl.AccessControlType]::Allow;' +
    '$rights=@{''S-1-5-32-544''=[Security.AccessControl.FileSystemRights]::FullControl;' +
      '''S-1-5-18''=[Security.AccessControl.FileSystemRights]::FullControl;' +
      '''S-1-5-80-0''=[Security.AccessControl.FileSystemRights]::ReadAndExecute};' +
    '$trusted=@{''S-1-5-32-544''=$true;''S-1-5-18''=$true;' +
      '''S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464''=$true};' +
    '$identity=[Security.Principal.WindowsIdentity]::GetCurrent();' +
      '$principal=[Security.Principal.WindowsPrincipal]::new($identity);' +
      'if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){' +
      '$trusted[$identity.User.Value]=$true};' +
    '$danger=[Security.AccessControl.FileSystemRights]::Write-bor' +
      '[Security.AccessControl.FileSystemRights]::Modify-bor' +
      '[Security.AccessControl.FileSystemRights]::Delete-bor' +
      '[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles-bor' +
      '[Security.AccessControl.FileSystemRights]::ChangePermissions-bor' +
      '[Security.AccessControl.FileSystemRights]::TakeOwnership;' +
    'function Assert-SafeSecurity([string]$p){' +
      '$s=if([IO.Directory]::Exists($p)){' +
      '[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)};' +
      '$owner=$s.GetOwner([Security.Principal.SecurityIdentifier]).Value;' +
      'if(-not$trusted.ContainsKey($owner)){' +
      'throw ''Unsafe owner on existing install path: ''+$p};' +
      'foreach($r in $s.GetAccessRules($true,$true,' +
      '[Security.Principal.SecurityIdentifier])){' +
      'if(($r.AccessControlType-eq$allow)-and' +
      '(-not$trusted.ContainsKey($r.IdentityReference.Value))-and' +
      '(($r.FileSystemRights-band$danger)-ne 0)){' +
      'throw ''Ordinary principal has write/delete control of install path: ''+$p}}};' +
    'function Assert-AncestorSecurity([string]$p){' +
      '$standard=@([Environment]::GetFolderPath(' +
      '[Environment+SpecialFolder]::CommonApplicationData),' +
      '[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),' +
      '[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86))|' +
      'Where-Object{-not[string]::IsNullOrWhiteSpace($_)}|' +
      'ForEach-Object{[IO.Path]::GetFullPath($_).TrimEnd([char]92)};' +
      '$cursor=[IO.Path]::GetDirectoryName($p);while($cursor){' +
      'if(@($standard|Where-Object{$cursor.Equals($_,' +
      '[StringComparison]::OrdinalIgnoreCase)}).Count-gt 0){break};' +
      'if([IO.Directory]::Exists($cursor)){Assert-SafeSecurity $cursor};' +
      'if($cursor.TrimEnd([char]92).Equals($root.TrimEnd([char]92),' +
      '[StringComparison]::OrdinalIgnoreCase)){break};' +
      '$next=[IO.Path]::GetDirectoryName($cursor);' +
      'if([string]::IsNullOrWhiteSpace($next)-or($next-eq$cursor)){break};' +
      '$cursor=$next}};' +
    'function Assert-CodeSecurity([string]$p){' +
      '$roots=@(''runtime'',''deploy'',''release-metadata'',''uninstall-tools'');' +
      'foreach($leaf in $roots){$cr=[IO.Path]::Combine($p,$leaf);' +
      'if([IO.Directory]::Exists($cr)){$q=[Collections.Generic.Queue[string]]::new();' +
      '$q.Enqueue($cr);while($q.Count-gt 0){$d=$q.Dequeue();' +
      'Assert-SafeSecurity $d;foreach($child in [IO.Directory]::GetFileSystemEntries($d)){' +
      'Assert-SafeSecurity $child;if([IO.Directory]::Exists($child)){$q.Enqueue($child)}}}}};' +
      'foreach($pattern in @(''unins*.exe'',''unins*.dat'')){' +
      'foreach($f in [IO.Directory]::GetFiles($p,$pattern)){' +
      'Assert-SafeSecurity $f}}};' +
    'function Assert-CanonicalRoot([string]$p){' +
      '$actual=[IO.Directory]::GetAccessControl($p);' +
      '$owner=$actual.GetOwner([Security.Principal.SecurityIdentifier]).Value;' +
      'if((-not $actual.AreAccessRulesProtected)-or' +
      '($owner-cne''S-1-5-32-544'')){' +
      'throw ''Install root owner or DACL protection is not canonical.''};' +
      '$rules=@($actual.GetAccessRules($true,$false,' +
      '[Security.Principal.SecurityIdentifier]));' +
      'if($rules.Count-ne$rights.Count){throw ''Install root DACL rule count is not canonical.''};' +
      'foreach($r in $rules){$sid=$r.IdentityReference.Value;' +
      '$expectedRights=$rights[$sid];$actualRights=$r.FileSystemRights;' +
      'if((-not$rights.ContainsKey($sid))-or($r.AccessControlType-ne$allow)-or' +
      '($r.InheritanceFlags-ne$inherit)-or($r.PropagationFlags-ne$none)-or' +
      '(($actualRights-ne$expectedRights)-and' +
      '($actualRights-ne($expectedRights-bor' +
      '[Security.AccessControl.FileSystemRights]::Synchronize)))){' +
      'throw ''Install root DACL contains a non-canonical rule.''}}};' +
    '$acl=[Security.AccessControl.DirectorySecurity]::new();' +
    '$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admin);' +
    'foreach($pair in $rights.GetEnumerator()){' +
      '$sid=[Security.Principal.SecurityIdentifier]::new([string]$pair.Key);' +
      '$rule=[Security.AccessControl.FileSystemAccessRule]::new(' +
      '$sid,[Security.AccessControl.FileSystemRights]$pair.Value,' +
      '$inherit,$none,$allow);[void]$acl.AddAccessRule($rule)};' +
    'Assert-Ancestors $target;Assert-AncestorSecurity $target;' +
    '$existed=[IO.Directory]::Exists($target);$wasEmpty=$false;' +
    'if($existed){Assert-Tree $target;' +
      '$wasEmpty=([IO.Directory]::GetFileSystemEntries($target).Count-eq 0);' +
      'if(-not $wasEmpty){Assert-ExistingProduct $target};' +
      'Assert-CanonicalRoot $target;if(-not $wasEmpty){Assert-CodeSecurity $target}' +
      '}else{[void][IO.Directory]::CreateDirectory($target,$acl)};' +
    'Assert-Ancestors $target;Assert-AncestorSecurity $target;Assert-Tree $target;' +
    'if(((-not $existed)-or $wasEmpty)-and' +
      '([IO.Directory]::GetFileSystemEntries($target).Count-ne 0)){' +
      'throw ''Install root changed during secure creation.''};' +
    'Assert-CanonicalRoot $target';
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    CommandText + '"';
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode, nil) then
  begin
    ErrorText := 'Failed to start the trusted Enterprise Agent install-root preflight.';
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    ErrorText := Format(
      'Enterprise Agent install-root preflight rejected the target directory ' +
      '(exit %d). See Setup log for details.', [ResultCode]);
    Exit;
  end;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ApprovalError: String;
  ResolvedApproval: String;
  PreflightError: String;
begin
  Result := '';
  CaptureWrapperOriginalState();
#ifdef EnableSigning
  if not ReleaseAuthorizationCaptured then
  begin
    if not TryResolveApprovedSigner(ResolvedApproval, ApprovalError) then
      Result := ApprovalError
    else
    begin
      ApprovedSignerThumbprint := ResolvedApproval;
      ReleaseAuthorizationCaptured := True;
    end;
  end;
#else
#ifdef InternalUnsignedRelease
  if not ReleaseAuthorizationCaptured then
  begin
    if not TryAuthorizeUnsignedInternalRelease(ResolvedApproval, ApprovalError) then
      Result := ApprovalError
    else
    begin
      ApprovedInstallerSha256 := ResolvedApproval;
      ReleaseAuthorizationCaptured := True;
    end;
  end;
#else
  if not IsUnsignedTestMediaAuthorized() then
    Result := 'Unsigned internal-test media was not explicitly authorized. Formal installation is unavailable for this build.';
#endif
#endif
  if Result <> '' then
    Exit;
  if HasRunningEnterpriseAgentService() then
    Result := 'A MineGuard Enterprise Agent service is running. Stop every MineGuardEnterpriseAgent-* service before installing or upgrading the shared runtime. Registered but stopped services are preserved.'
  else if HasActiveEnterpriseAgentRuntime() then
    Result := 'A foreground process is executing from the MineGuard Enterprise Agent runtime directory. Stop it before installing or upgrading.';
  if Result <> '' then
    Exit;
  if not PreflightEnterpriseAgentInstallRoot(PreflightError) then
    Result := PreflightError;
end;

function GetProductTransactionId(): String;
var
  UniqueSeed: String;
begin
  if ProductTransactionId = '' then
  begin
    UniqueSeed := GenerateUniqueName(ExpandConstant('{tmp}'), '.tmp');
    ProductTransactionId := LowerCase(Copy(GetSHA256OfString(
      UniqueSeed + '|' + ExpandConstant('{app}')), 1, 32));
  end;
  Result := ProductTransactionId;
end;

function BooleanFlag(const Value: Boolean): String;
begin
  if Value then
    Result := '1'
  else
    Result := '0';
end;

function GetExtractedAgentReleaseRoot(): String;
begin
  { ExtractTemporaryFiles preserves the unexpanded destination below Setup's
    private temporary root. }
  Result := AddBackslash(ExpandConstant('{tmp}')) +
    '{tmp}\MineGuardEnterpriseAgentRelease';
end;

function InvokeProductTransactionAction(const ActionName: String;
  const Visible: Boolean; var ResultCode: Integer): Boolean;
var
  PowerShellPath: String;
  BootstrapPath: String;
  ActualBootstrapSha256: String;
  BootstrapArguments: String;
  LoaderCommand: String;
  Parameters: String;
  WindowStyle: Integer;
#ifdef InternalUnsignedRelease
  ApprovalError: String;
#endif
begin
  Result := False;
  ResultCode := -1;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  BootstrapPath := ExpandConstant(
    '{tmp}\Invoke-MineGuardTrustedProductInstall.ps1');
  if not FileExists(BootstrapPath) then
  begin
    Log('Trusted product bootstrap is not extracted: ' + BootstrapPath);
    Exit;
  end;
  ActualBootstrapSha256 := UpperCase(GetSHA256OfFile(BootstrapPath));
  if CompareText(ActualBootstrapSha256, '{#TrustedBootstrapSha256}') <> 0 then
  begin
    Log('Trusted product bootstrap failed its embedded SHA-256 check.');
    Exit;
  end;
  BootstrapArguments :=
    ' -TransactionAction ' + PowerShellSingleQuoted(ActionName) +
    ' -TransactionId ' + PowerShellSingleQuoted(GetProductTransactionId()) +
    ' -Product ' +
    PowerShellSingleQuoted('EnterpriseAgent') +
    ' -SourceRoot ' + PowerShellSingleQuoted(
      GetExtractedAgentReleaseRoot()) +
    ' -ExpectedReleaseManifestSha256 ' +
      PowerShellSingleQuoted('{#ChildReleaseManifestSha256}') +
    ' -InstallRoot ' + PowerShellSingleQuoted(ExpandConstant('{app}')) +
    ' -StateRoot ' + PowerShellSingleQuoted(ExpandConstant(
      '{param:STATE_ROOT|{commonappdata}\MineGuard\EnterpriseAgent\instances}')) +
    ' -WrapperInstallRootPreexisted ' + PowerShellSingleQuoted(
      BooleanFlag(WrapperInstallRootPreexisted)) +
    ' -WrapperShortcutGroupPreexisted ' + PowerShellSingleQuoted(
      BooleanFlag(WrapperShortcutGroupPreexisted));
#ifdef EnableSigning
  if (not ReleaseAuthorizationCaptured) or
      (Length(ApprovedSignerThumbprint) <> 40) then
  begin
    Log('The independently approved signer thumbprint was not resolved.');
    Exit;
  end;
  BootstrapArguments := BootstrapArguments +
    ' -ApprovedSignerThumbprint ' +
    PowerShellSingleQuoted(ApprovedSignerThumbprint);
#else
#ifdef InternalUnsignedRelease
  if (not ReleaseAuthorizationCaptured) or
      (Length(ApprovedInstallerSha256) <> 64) then
  begin
    Log('The locked INTERNAL-UNSIGNED authorization is unavailable.');
    Exit;
  end;
  BootstrapArguments := BootstrapArguments +
    ' -AllowUnsignedInternalRelease';
#else
  if not IsUnsignedTestMediaAuthorized() then
  begin
    Log('Unsigned test media was not explicitly authorized.');
    Exit;
  end;
  BootstrapArguments := BootstrapArguments + ' -AllowUnsignedTestMedia';
#endif
#endif
  { Hash the exact bytes that are executed, so a writable inherited ACL or a
    pre-created parent cannot win a GetSHA256OfFile-to-Exec replacement race. }
  LoaderCommand :=
    'Set-StrictMode -Version 2.0;$ErrorActionPreference=''Stop'';' +
    '$p=' + PowerShellSingleQuoted(BootstrapPath) +
    ';$bytes=[IO.File]::ReadAllBytes($p);' +
    '$sha=[Security.Cryptography.SHA256]::Create();try{' +
    '$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace([string][char]45,[string]::Empty).ToLowerInvariant()' +
    '}finally{$sha.Dispose()};' +
    'if($digest -cne (''{#TrustedBootstrapSha256}'').ToLowerInvariant()){' +
    'throw ''Trusted bootstrap changed after Setup verification.''};' +
    '$offset=0;if(($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ' +
    '($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)){$offset=3};' +
    '$utf8=[System.Text.UTF8Encoding]::new($false,$true);' +
    '$text=$utf8.GetString($bytes,$offset,$bytes.Length-$offset);' +
    '& ([ScriptBlock]::Create($text))' +
    BootstrapArguments;
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    LoaderCommand + '"';
  if Visible then
    WindowStyle := SW_SHOWNORMAL
  else
    WindowStyle := SW_HIDE;
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', WindowStyle,
      ewWaitUntilTerminated, ResultCode, nil) then
  begin
    Log('Failed to launch Agent transaction action ' + ActionName + '.');
    Exit;
  end;
  Result := ResultCode = 0;
end;

procedure RequireProductTransactionAction(const ActionName: String);
var
  ResultCode: Integer;
begin
  if not InvokeProductTransactionAction(ActionName, True, ResultCode) then
  begin
    ProductInstallFailed := True;
    RaiseException(Format(
      'Enterprise Agent transaction action %s failed with exit code %d.', [
      ActionName, ResultCode]));
  end;
end;

procedure PrepareAndCommitProductRuntime();
begin
  { ssInstall runs before Inno makes persistent Files, Icons, ARP or uninstaller
    changes. The retained child transaction is therefore the only state that
    needs explicit rollback until ssPostInstall. }
  ExtractTemporaryFiles(
    '{tmp}\Invoke-MineGuardTrustedProductInstall.ps1');
  ExtractTemporaryFiles('{tmp}\MineGuardEnterpriseAgentRelease\*');
  ProductTransactionStarted := True;
  RequireProductTransactionAction('Begin');
  RequireProductTransactionAction('Prepare');
  RequireProductTransactionAction('Commit');
  ProductTransactionPrepared := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
    PrepareAndCommitProductRuntime()
  else if CurStep = ssPostInstall then
  begin
#ifdef FailureAfterWrapperPersistenceProbe
    { Compile-only release audit: PerformInstall has completed Files, Icons,
      ARP and uninstaller persistence, but the wrapper success marker is
      deliberately withheld so DeinitializeSetup must restore both engines. }
    ProductInstallFailed := True;
    Log('Release audit fault injection after wrapper persistence.');
    Exit;
#endif
    if not ProductTransactionPrepared then
    begin
      ProductInstallFailed := True;
      Log('Agent wrapper reached ssPostInstall without a retained product commit.');
      Exit;
    end;
    if InvokeProductTransactionAction('Finalize', False, ResultCode) then
      WrapperTransactionSucceeded := True
    else
    begin
      ProductInstallFailed := True;
      Log(Format(
        'Agent wrapper success marker/finalization failed with exit code %d.', [
        ResultCode]));
    end;
  end;
end;

procedure DeinitializeSetup();
var
  ResultCode: Integer;
begin
  if ProductTransactionStarted and not WrapperTransactionSucceeded then
  begin
    if not InvokeProductTransactionAction('Rollback', False, ResultCode) then
      Log(Format(
        'ERROR: Agent retained transaction rollback failed with exit code %d.', [
        ResultCode]));
  end;
  if not WrapperTransactionSucceeded then
    CleanupWrapperCreatedEmptyInstallChain();
end;

function GetCustomSetupExitCode: Integer;
begin
  { Inno deliberately catches exceptions raised by BeforeInstall/AfterInstall.
    Preserve the visible error above while still returning a deterministic
    non-zero code to deployment automation and parent processes. }
  if ProductInstallFailed then
    Result := ProductInstallFailureExitCode
  else
    Result := 0;
end;

procedure RemoveProductRuntimeTransactionally();
var
  ResultCode: Integer;
  PowerShellPath: String;
  ScriptPath: String;
  ManifestPath: String;
  LoaderCommand: String;
  Parameters: String;
begin
  if RuntimeRemovalCompleted then
    Exit;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  ScriptPath := ExpandConstant('{app}\uninstall-tools\Uninstall-EnterpriseAgentRuntime.ps1');
  if not FileExists(ScriptPath) then
    RaiseException('The guarded Enterprise Agent runtime-removal script is missing. Uninstall has been aborted before enterprise data was touched.');
  ManifestPath := ExpandConstant('{app}\release-metadata\release-manifest.json');
  if not FileExists(ManifestPath) then
    RaiseException('The guarded Enterprise Agent release manifest is missing. Uninstall has been aborted before enterprise data was touched.');
  LoaderCommand :=
    'Set-StrictMode -Version 2.0;$ErrorActionPreference=''Stop'';' +
    '$mp=' + PowerShellSingleQuoted(ManifestPath) +
    ';$sp=' + PowerShellSingleQuoted(ScriptPath) +
    ';$expectedPath=' + PowerShellSingleQuoted(
      'deploy/windows/Uninstall-EnterpriseAgentRuntime.ps1') +
    ';$mb=[IO.File]::ReadAllBytes($mp);' +
    '$sha=[Security.Cryptography.SHA256]::Create();try{' +
    '$mh=[BitConverter]::ToString($sha.ComputeHash($mb)).Replace([string][char]45,[string]::Empty).ToLowerInvariant()' +
    '}finally{$sha.Dispose()};' +
    'if($mh -cne (''{#ChildReleaseManifestSha256}'').ToLowerInvariant()){' +
    'throw ''Installed Agent manifest does not match this uninstaller.''};' +
    '$utf8=[System.Text.UTF8Encoding]::new($false,$true);' +
    '$mo=0;if(($mb.Length -ge 3) -and ($mb[0] -eq 0xEF) -and ' +
    '($mb[1] -eq 0xBB) -and ($mb[2] -eq 0xBF)){$mo=3};' +
    '$m=$utf8.GetString($mb,$mo,$mb.Length-$mo)|ConvertFrom-Json;' +
    '$e=@($m.files|Where-Object{[string]$_.path -ceq $expectedPath});' +
    'if($e.Count -ne 1){throw ''Agent uninstall runner manifest entry is invalid.''};' +
    '$expected=[string]$e[0].sha256;' +
    'if($expected -cnotmatch ''^[A-Fa-f0-9]{64}$''){' +
    'throw ''Agent uninstall runner digest is invalid.''};' +
    '$bytes=[IO.File]::ReadAllBytes($sp);' +
    '$sha=[Security.Cryptography.SHA256]::Create();try{' +
    '$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace([string][char]45,[string]::Empty).ToLowerInvariant()' +
    '}finally{$sha.Dispose()};' +
    'if(($digest -cne $expected.ToLowerInvariant()) -or ' +
    '([long]$bytes.LongLength -ne [long]$e[0].bytes)){' +
    'throw ''Agent uninstall runner failed release-manifest validation.''};' +
    '$offset=0;if(($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ' +
    '($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)){$offset=3};' +
    '$text=$utf8.GetString($bytes,$offset,$bytes.Length-$offset);' +
    '& ([ScriptBlock]::Create($text))' +
    ' -InstallRoot ' + PowerShellSingleQuoted(ExpandConstant('{app}')) +
    ' -InternalInnoUninstall -TrustedScriptPath $sp' +
    ' -TrustedScriptSha256 $digest -TrustedScriptBytes $bytes.LongLength';
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    LoaderCommand + '"';
  if not ExecAndLogOutput(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode, nil) then
    RaiseException('Failed to launch the guarded Enterprise Agent runtime-removal transaction.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded Enterprise Agent runtime-removal transaction failed with exit code %d. Uninstall has been aborted.', [ResultCode]));
  RuntimeRemovalCompleted := True;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  if CheckForMutexes(ProductTransactionMutexes) then
  begin
    SuppressibleMsgBox(
      'Another MineGuard installation or uninstall transaction is running. ' +
      'Wait for it to finish before uninstalling.', mbError, MB_OK, IDOK);
    Result := False;
    Exit;
  end;
  { SetupMutex is a Setup-only directive. Hold the same two names throughout
    uninstall so Platform and Agent cannot mutate their shared parent at once. }
  CreateMutex(ProductTransactionLocalMutex);
  CreateMutex(ProductTransactionGlobalMutex);
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
