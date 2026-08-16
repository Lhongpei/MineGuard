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
#ifndef MinimumWindowsVersion
  #define MinimumWindowsVersion "10.0.17763"
#endif
#ifndef ApplicationId
  #define ApplicationId "{{8B391CBD-E234-46D7-9946-E9D37F2649C1}"
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

#define ProductName "MineGuard Platform"
#define ProductPublisher "MineGuard Delivery Team"

[Setup]
AppId={#ApplicationId}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher={#ProductPublisher}
DefaultDirName={commonappdata}\MineGuard\Platform
DisableDirPage=no
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
VersionInfoDescription=MineGuard government regulatory platform installer
UninstallDisplayIcon={app}\runtime\MineGuardPlatform.exe
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

[Tasks]
Name: "desktopicon"; Description: "创建 MineGuard Platform 控制中心桌面快捷方式"; GroupDescription: "快捷方式："; Flags: checkedonce

[Dirs]
; The launcher and product documentation are readable by desktop users. They
; can predate Inno's file phase, so remove them on uninstall only when empty;
; runtime, configuration, state and logs keep their stricter service ACLs.
Name: "{app}\launcher"; Permissions: users-readexec; Flags: uninsalwaysuninstall
Name: "{app}\docs"; Permissions: users-readexec; Flags: uninsalwaysuninstall

[Files]
; These temporary transaction inputs are deliberately first for solid-compression
; extraction. CurStepChanged(ssInstall) extracts them before Inno writes any
; persistent Files/Icons/ARP/uninstaller state. They are never copied normally.
Source: "{#AssetsRoot}\Invoke-MineGuardTrustedProductInstall.ps1"; Flags: dontcopy noencryption
Source: "{#StageRoot}\*"; DestDir: "{tmp}\MineGuardPlatformRelease"; Flags: ignoreversion recursesubdirs createallsubdirs dontcopy noencryption
; Keep the uninstall transaction runner outside every product-owned directory
; that it atomically quarantines. Inno owns and removes this protected copy.
Source: "{#StageRoot}\deploy\windows\Uninstall-MineGuardPlatformRuntime.ps1"; DestDir: "{app}\uninstall-tools"; Flags: ignoreversion
Source: "{#AssetsRoot}\Windows-binary-release-guide.html"; DestDir: "{app}\docs"; Flags: ignoreversion; Permissions: users-readexec
Source: "{#AssetsRoot}\RELEASE-NOTICE.txt"; DestDir: "{app}\docs"; Flags: ignoreversion; Permissions: users-readexec
; Keep a tiny, explicitly read-only launcher separate from the protected
; runtime/config/state trees.  A desktop token can request UAC before opening
; the administrator control center.  It contains no configuration or secret.
Source: "{#AssetsRoot}\Open-MineGuardPlatformControlCenter.ps1"; DestDir: "{app}\launcher"; Flags: ignoreversion; Permissions: users-readexec

[Icons]
Name: "{commonprograms}\MineGuard\MineGuard Platform 控制中心"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\launcher\Open-MineGuardPlatformControlCenter.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\launcher"; IconFilename: "{app}\runtime\MineGuardPlatform.exe"
Name: "{commonprograms}\MineGuard\MineGuard 企业接入包与注册向导"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\launcher\Open-MineGuardPlatformControlCenter.ps1"" -InstallRoot ""{app}"" -Provisioning"; WorkingDir: "{app}\launcher"; IconFilename: "{app}\runtime\MineGuardPlatform.exe"
Name: "{commondesktop}\MineGuard Platform 控制中心"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\launcher\Open-MineGuardPlatformControlCenter.ps1"" -InstallRoot ""{app}"""; WorkingDir: "{app}\launcher"; IconFilename: "{app}\runtime\MineGuardPlatform.exe"; Tasks: desktopicon
Name: "{commonprograms}\MineGuard\MineGuard Platform 使用与部署说明"; Filename: "{app}\docs\Windows-binary-release-guide.html"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\service\Start-MineGuardPlatformWizard.ps1"" -InstallRoot ""{app}"""; Description: "打开 MineGuard Platform 中文配置向导"; Flags: postinstall skipifsilent nowait; Check: IsWrapperTransactionConfirmed

[UninstallDelete]
; Product-owned immutable directories are removed only by the guarded
; same-volume quarantine transaction in [Code]. Never list runtime, deploy,
; service, release-metadata, launcher, config, state, backups or logs here.
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
#ifndef EnableSigning
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

#ifndef EnableSigning
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
#ifndef EnableSigning
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
    'This Platform build cannot be used as a formal installation',
    'Continue only on an isolated test machine. This unsigned build is not a production trust root and cannot be treated as formally delivered software.',
    False, False);
  UnsignedTestPage.Add('I explicitly authorize this unsigned internal-test Platform installation.');
#endif
#endif
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  ErrorText: String;
  ResolvedHash: String;
begin
  Result := True;
  { Silent installs have no operator who can correct a custom wizard page.
    Defer their authorization decision to PrepareToInstall, which returns a
    deterministic Setup error instead of leaving the hidden wizard on a page. }
  if WizardSilent then
    Exit;
#ifndef EnableSigning
#ifdef InternalUnsignedRelease
  if (CurPageID = InternalUnsignedConfirmationPage.ID) and
      (not TryAuthorizeUnsignedInternalRelease(ResolvedHash, ErrorText)) then
  begin
    SuppressibleMsgBox(ErrorText, mbError, MB_OK, IDOK);
    Result := False;
  end
  else if CurPageID = InternalUnsignedConfirmationPage.ID then
  begin
    ApprovedInstallerSha256 := ResolvedHash;
    ReleaseAuthorizationCaptured := True;
  end;
#else
  if (CurPageID = UnsignedTestPage.ID) and
      (not IsUnsignedTestMediaAuthorized()) then
  begin
    SuppressibleMsgBox(
      'Unsigned Platform test media requires explicit test authorization.',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
#endif
#endif
end;

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

function PreflightMineGuardPlatformInstallRoot(var ErrorText: String): Boolean;
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
      '$exe=[IO.Path]::Combine($p,''runtime'',''MineGuardPlatform.exe'');' +
      'foreach($required in @($mp,$bp,$vp,$exe)){' +
      'if(-not[IO.File]::Exists($required)){' +
      'throw ''Pre-existing non-empty directory is not a verified MineGuard Platform installation.''}};' +
      '$m=[IO.File]::ReadAllText($mp,[Text.Encoding]::UTF8)|ConvertFrom-Json;' +
      '$b=[IO.File]::ReadAllText($bp,[Text.Encoding]::UTF8)|ConvertFrom-Json;' +
      '$v=[IO.File]::ReadAllText($vp,[Text.Encoding]::UTF8).Trim();' +
      'if(([string]$m.product-cne''MineGuard Platform'')-or' +
      '([string]$m.entryPoint-cne''runtime/MineGuardPlatform.exe'')-or' +
      '([string]$b.product-cne''MineGuard Platform'')-or' +
      '([string]$m.version-cne$v)-or([string]$b.version-cne$v)){' +
      'throw ''Existing installation identity does not match MineGuard Platform.''};' +
      '$entries=@($m.files|Where-Object{' +
      '[string]$_.path-ceq''runtime/MineGuardPlatform.exe''});' +
      'if($entries.Count-ne 1){throw ''Existing Platform manifest has no unique executable entry.''};' +
      '$fi=[IO.FileInfo]::new($exe);$entry=$entries[0];' +
      'if(([long]$fi.Length-ne[long]$entry.bytes)-or' +
      '((Get-Sha256 $exe)-cne([string]$entry.sha256).ToLowerInvariant())){' +
      'throw ''Existing Platform executable does not match its release manifest.''}};' +
    '$admin=[Security.Principal.SecurityIdentifier]::new(''S-1-5-32-544'');' +
    '$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit-bor' +
      '[Security.AccessControl.InheritanceFlags]::ObjectInherit;' +
    '$none=[Security.AccessControl.PropagationFlags]::None;' +
    '$allow=[Security.AccessControl.AccessControlType]::Allow;' +
    '$rights=@{''S-1-5-32-544''=[Security.AccessControl.FileSystemRights]::FullControl;' +
      '''S-1-5-18''=[Security.AccessControl.FileSystemRights]::FullControl;' +
      '''S-1-5-80-4217648432-3698953252-1345452052-477395953-3006768346''=' +
      '[Security.AccessControl.FileSystemRights]::ReadAndExecute};' +
    '$trusted=@{''S-1-5-32-544''=$true;''S-1-5-18''=$true;' +
      '''S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464''=$true};' +
    '$identity=[Security.Principal.WindowsIdentity]::GetCurrent();' +
      '$principal=[Security.Principal.WindowsPrincipal]::new($identity);' +
      'if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){' +
      '$trusted[$identity.User.Value]=$true};' +
    '$danger=[Security.AccessControl.FileSystemRights]::WriteData-bor' +
      '[Security.AccessControl.FileSystemRights]::AppendData-bor' +
      '[Security.AccessControl.FileSystemRights]::WriteExtendedAttributes-bor' +
      '[Security.AccessControl.FileSystemRights]::WriteAttributes-bor' +
      '[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles-bor' +
      '[Security.AccessControl.FileSystemRights]::Delete-bor' +
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
      '$roots=@(''runtime'',''service'',''release-metadata'',''uninstall-tools'',''launcher'');' +
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
    ErrorText := 'Failed to start the trusted MineGuard Platform install-root preflight.';
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    ErrorText := Format(
      'MineGuard Platform install-root preflight rejected the target directory ' +
      '(exit %d). See Setup log for details.', [ResultCode]);
    Exit;
  end;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResolvedHash: String;
  ApprovalError: String;
  PreflightError: String;
begin
  Result := '';
  CaptureWrapperOriginalState();
#ifndef EnableSigning
#ifdef InternalUnsignedRelease
  if not ReleaseAuthorizationCaptured then
  begin
    if not TryAuthorizeUnsignedInternalRelease(ResolvedHash, ApprovalError) then
      Result := ApprovalError
    else
    begin
      ApprovedInstallerSha256 := ResolvedHash;
      ReleaseAuthorizationCaptured := True;
    end;
  end;
#else
  if not IsUnsignedTestMediaAuthorized() then
    Result := 'Unsigned Platform internal-test media was not explicitly authorized. Formal installation is unavailable for this build.';
#endif
  if Result <> '' then
    Exit;
#endif
  if HasRunningMineGuardPlatformService() then
    Result := 'The MineGuardPlatform service is running. Stop it before installing or upgrading the runtime. A registered but stopped service is preserved.'
  else if HasActiveMineGuardPlatformRuntime() then
    Result := 'A foreground process is executing from the MineGuard Platform runtime directory. Stop it before installing or upgrading.';
  if Result <> '' then
    Exit;
  if not PreflightMineGuardPlatformInstallRoot(PreflightError) then
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

function GetExtractedPlatformReleaseRoot(): String;
begin
  // ExtractTemporaryFiles maps a leading {tmp}\ DestDir to Setup's private
  // temporary root instead of preserving that token as a literal subfolder.
  Result := ExpandConstant('{tmp}\MineGuardPlatformRelease');
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
    ' -Product ' + PowerShellSingleQuoted('Platform') +
    ' -SourceRoot ' + PowerShellSingleQuoted(
      GetExtractedPlatformReleaseRoot()) +
    ' -ExpectedReleaseManifestSha256 ' +
      PowerShellSingleQuoted('{#ChildReleaseManifestSha256}') +
    ' -InstallRoot ' + PowerShellSingleQuoted(ExpandConstant('{app}')) +
    ' -WrapperInstallRootPreexisted ' + PowerShellSingleQuoted(
      BooleanFlag(WrapperInstallRootPreexisted)) +
    ' -WrapperShortcutGroupPreexisted ' + PowerShellSingleQuoted(
      BooleanFlag(WrapperShortcutGroupPreexisted));
#ifndef EnableSigning
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
    Log('Unsigned Platform test media was not explicitly authorized.');
    Exit;
  end;
#endif
#endif
  { Read the bootstrap once, hash those exact bytes, then execute the same
    in-memory bytes. This closes the hash-to-Exec race even if an inherited ACL
    or hostile pre-created parent made the random extraction directory writable. }
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
    Log('Failed to launch Platform transaction action ' + ActionName + '.');
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
      'MineGuard Platform transaction action %s failed with exit code %d.', [
      ActionName, ResultCode]));
  end;
end;

procedure PrepareAndCommitProductRuntime();
begin
  { ssInstall is dispatched with HandleExceptions=False immediately before
    PerformInstall. A failure here is fatal while Inno still has no persistent
    Files/Icons/ARP/uninstaller changes to unwind. }
  ExtractTemporaryFiles(
    '{tmp}\Invoke-MineGuardTrustedProductInstall.ps1');
  ExtractTemporaryFiles('{tmp}\MineGuardPlatformRelease\*');
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
      Log('Platform wrapper reached ssPostInstall without a retained product commit.');
      Exit;
    end;
    if InvokeProductTransactionAction('Finalize', False, ResultCode) then
      WrapperTransactionSucceeded := True
    else
    begin
      ProductInstallFailed := True;
      Log(Format(
        'Platform wrapper success marker/finalization failed with exit code %d.', [
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
        'ERROR: Platform retained transaction rollback failed with exit code %d.', [
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
  ScriptPath := ExpandConstant('{app}\uninstall-tools\Uninstall-MineGuardPlatformRuntime.ps1');
  if not FileExists(ScriptPath) then
    RaiseException('The guarded MineGuard Platform runtime-removal script is missing. Uninstall has been aborted before product data was touched.');
  ManifestPath := ExpandConstant('{app}\release-metadata\release-manifest.json');
  if not FileExists(ManifestPath) then
    RaiseException('The guarded MineGuard Platform release manifest is missing. Uninstall has been aborted before product data was touched.');
  { The uninstaller executable embeds the child-manifest anchor. Read the
    manifest and runner once, validate those byte arrays, and execute only the
    validated in-memory runner. This also protects unsigned internal media from
    a writable uninstall-tools pre-creation or later hash-to-Exec race. }
  LoaderCommand :=
    'Set-StrictMode -Version 2.0;$ErrorActionPreference=''Stop'';' +
    '$mp=' + PowerShellSingleQuoted(ManifestPath) +
    ';$sp=' + PowerShellSingleQuoted(ScriptPath) +
    ';$expectedPath=' + PowerShellSingleQuoted(
      'deploy/windows/Uninstall-MineGuardPlatformRuntime.ps1') +
    ';$mb=[IO.File]::ReadAllBytes($mp);' +
    '$sha=[Security.Cryptography.SHA256]::Create();try{' +
    '$mh=[BitConverter]::ToString($sha.ComputeHash($mb)).Replace([string][char]45,[string]::Empty).ToLowerInvariant()' +
    '}finally{$sha.Dispose()};' +
    'if($mh -cne (''{#ChildReleaseManifestSha256}'').ToLowerInvariant()){' +
    'throw ''Installed Platform manifest does not match this uninstaller.''};' +
    '$utf8=[System.Text.UTF8Encoding]::new($false,$true);' +
    '$mo=0;if(($mb.Length -ge 3) -and ($mb[0] -eq 0xEF) -and ' +
    '($mb[1] -eq 0xBB) -and ($mb[2] -eq 0xBF)){$mo=3};' +
    '$m=$utf8.GetString($mb,$mo,$mb.Length-$mo)|ConvertFrom-Json;' +
    '$e=@($m.files|Where-Object{[string]$_.path -ceq $expectedPath});' +
    'if($e.Count -ne 1){throw ''Platform uninstall runner manifest entry is invalid.''};' +
    '$expected=[string]$e[0].sha256;' +
    'if($expected -cnotmatch ''^[A-Fa-f0-9]{64}$''){' +
    'throw ''Platform uninstall runner digest is invalid.''};' +
    '$bytes=[IO.File]::ReadAllBytes($sp);' +
    '$sha=[Security.Cryptography.SHA256]::Create();try{' +
    '$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace([string][char]45,[string]::Empty).ToLowerInvariant()' +
    '}finally{$sha.Dispose()};' +
    'if(($digest -cne $expected.ToLowerInvariant()) -or ' +
    '([long]$bytes.LongLength -ne [long]$e[0].bytes)){' +
    'throw ''Platform uninstall runner failed release-manifest validation.''};' +
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
    RaiseException('Failed to launch the guarded MineGuard Platform runtime-removal transaction.');
  if ResultCode <> 0 then
    RaiseException(Format('The guarded MineGuard Platform runtime-removal transaction failed with exit code %d. Uninstall has been aborted.', [ResultCode]));
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
