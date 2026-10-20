; Inno Setup script for the Windows installer (docs/user-guide/windows-install.md).
;
; Build the programs, then compile this script with Inno Setup 6:
;
;     cargo build --release --locked
;     iscc contrib\windows\vault.iss /DAppVersion=0.1.0
;
; The installer asks "for me only" (the default, no administrator rights:
; %LOCALAPPDATA%\Programs, HKCU) or "for all users" (one administrator prompt
; during setup: Program Files, HKLM). Either way vaultd runs as each signed-in
; user, never elevated: the installer starts it with the original user's
; rights, and at sign-in it starts from the Run key through vaultw.exe.

#ifndef AppVersion
  #define AppVersion "0.1.0"
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
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM vaultd.exe"; Flags: runhidden; RunOnceId: "StopVaultd"

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

// An upgrade replaces vaultd.exe, so stop the running one. The vault locks;
// its file is saved on every change, so nothing is lost.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM vaultd.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
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
