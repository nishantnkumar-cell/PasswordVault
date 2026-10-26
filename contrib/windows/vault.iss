; Inno Setup script for the Windows installer (docs/user-guide/windows-install.md).
;
; Build the programs, then compile this script with Inno Setup 7 (6.x also works):
;
;     cargo build --release --locked
;     iscc contrib\windows\vault.iss /DAppVersion=0.2.0
;
; CI passes the build's version (contrib/version.sh --build), e.g. 0.2.0 for a
; release or 0.2.0-dev.1a2b3c4 otherwise, and NumVersion, its numeric part.
;
; Running a newer installer over an existing install upgrades it in place: same
; folder, same install mode, same tasks; vaultd and the app are stopped first
; and the vault itself is never touched. An older installer asks first.
; The installer asks "for me only" (the default, no administrator rights:
; %LOCALAPPDATA%\Programs, HKCU) or "for all users" (one administrator prompt
; during setup: Program Files, HKLM). Either way vaultd runs as each signed-in
; user, never elevated: the installer starts it with the original user's
; rights, and at sign-in it starts from the Run key through vaultw.exe.

#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef NumVersion
  #define NumVersion AppVersion
#endif
#ifndef BinDir
  #define BinDir "..\..\target\release"
#endif
#ifndef OutDir
  #define OutDir "..\..\target\installer"
#endif

[Setup]
AppId={{B15F8027-096D-4CCA-B21D-F856FEDF70E6}
AppName=Secret Vault
AppVersion={#AppVersion}
; Shown in Settings > Apps and in the file's properties (numbers only there).
VersionInfoVersion={#NumVersion}
VersionInfoProductTextVersion={#AppVersion}
AppVerName=Secret Vault {#AppVersion}
; Upgrades keep the previous folder, install mode and task choices.
UsePreviousAppDir=yes
UsePreviousPrivileges=yes
UsePreviousTasks=yes
AppPublisher=PasswordVault project
AppPublisherURL=https://github.com/nishantnkumar-cell/PasswordVault
DefaultDirName={autopf}\Secret Vault
DefaultGroupName=Secret Vault
DisableProgramGroupPage=yes
; No administrator rights unless the user picks "all users".
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1903 is the first with webauthn.dll.
MinVersion=10.0.18362
LicenseFile=..\..\LICENSE.md
OutputDir={#OutDir}
OutputBaseFilename=SecretVault-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
; vaultd is stopped in PrepareToInstall instead.
CloseApplications=no
UninstallDisplayIcon={app}\vault-gui.exe
SetupIconFile=..\icons\secret-vault.ico
UninstallDisplayName=Secret Vault

[Tasks]
Name: "autostart"; Description: "Start the vault daemon at sign-in"
Name: "path"; Description: "Add the vault command to PATH"

[Files]
Source: "{#BinDir}\vaultd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vaultw.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vault-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vault-prompt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vault-native-host.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\vault-gpg.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Secret Vault"; Filename: "{app}\vault-gui.exe"

[Registry]
; HKA is HKCU for "me only" and HKLM for "all users" (each user's own vaultd).
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Secret Vault daemon"; ValueData: """{app}\vaultw.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; As the user who started setup, not the administrator account it may run as.
Filename: "{app}\vaultw.exe"; Flags: nowait runasoriginaluser; Tasks: autostart
Filename: "{app}\vault-gui.exe"; Description: "Open Secret Vault"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM vaultd.exe /IM vault-gui.exe"; Flags: runhidden; RunOnceId: "StopVaultd"

[Code]
function EnvRoot: Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvKey: String;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

procedure AddToPath(Dir: String);
var
  Path: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Path) then
    Path := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0 then
    exit;
  if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then
    Path := Path + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Path + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Path: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Path) then
    exit;
  Path := ';' + Path + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Path));
  if P = 0 then
    exit;
  Delete(Path, P, Length(Dir) + 1);
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Copy(Path, 2, Length(Path) - 2));
end;

const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{B15F8027-096D-4CCA-B21D-F856FEDF70E6}_is1';

var
  OldVersion: String;

// The installed version, from either install mode, or '' when none.
function InstalledVersion: String;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, UninstallKey, 'DisplayVersion', Result) then
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstallKey, 'DisplayVersion', Result) then
      Result := '';
end;

// "0.2.0-dev.1a2b3c4" -> "0.2.0".
function NumericPart(V: String): String;
begin
  Result := V;
  if Pos('-', Result) > 0 then
    Result := Copy(Result, 1, Pos('-', Result) - 1);
end;

// An older installer over a newer install asks first (default: no), since an
// older vaultd may not read a vault the newer one has saved.
function InitializeSetup: Boolean;
var
  Old, New: Int64;
begin
  Result := True;
  OldVersion := InstalledVersion;
  if OldVersion = '' then
    exit;
  if StrToVersion(NumericPart(OldVersion), Old) and StrToVersion('{#NumVersion}', New) then
    if ComparePackedVersion(New, Old) < 0 then
      Result := SuppressibleMsgBox(
        'Secret Vault ' + OldVersion + ' is installed, which is newer than this installer ({#AppVersion}).'
        + #13#10#13#10 + 'An older version may not be able to open a vault that a newer one has saved. '
        + 'Install the older version anyway?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  if OldVersion = '' then
    Result := 'Install Secret Vault {#AppVersion}'
  else if OldVersion = '{#AppVersion}' then
    Result := 'Reinstall Secret Vault {#AppVersion}'
  else
    Result := 'Upgrade Secret Vault from ' + OldVersion + ' to {#AppVersion}' + NewLine
      + Space + 'Your vault, settings and paired apps are kept.';
  Result := Result + NewLine + NewLine + MemoDirInfo;
  if MemoTasksInfo <> '' then
    Result := Result + NewLine + NewLine + MemoTasksInfo;
end;

// An upgrade replaces the programs, so stop the running ones. The vault locks;
// its file is saved on every change, so nothing is lost.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM vaultd.exe /IM vault-gui.exe /IM vault-prompt.exe',
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('path') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
