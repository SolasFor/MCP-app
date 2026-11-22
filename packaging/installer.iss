; MCP app - Inno Setup 6 script. Built by packaging\build.ps1:
;   ISCC.exe /DAppVersion=0.4.0 packaging\installer.iss
;
; * Per-user install, no admin rights: %LOCALAPPDATA%\Programs\MCP app
; * Start menu shortcut, optional desktop shortcut
; * AppMutex: setup/uninstall asks to quit a running MCP app first
; * Uninstall removes the autostart value (HKCU\...\Run\MCPApp)
; * User data (%APPDATA%\MCPApp: settings, token, audit log) is kept on uninstall
;
; This file is ASCII on purpose (Inno Setup reads BOM-less files as ANSI).
; Russian wizard texts come from compiler:Languages\Russian.isl.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "MCP app"
#define AppExe "MCPApp.exe"

[Setup]
AppId={{8F3C2A71-4D5E-4B9A-9C61-2E7A1D0B5F43}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
AppMutex=MCPApp-Running
CloseApplications=yes
OutputDir=..\dist
OutputBaseFilename=MCPApp-Setup-{#AppVersion}
SetupIconFile=..\build\MCPApp.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\MCPApp\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Old _internal from a previous version must not mix with the new one.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Autostart is turned on from inside the app; here we only make sure uninstall removes it.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "MCPApp"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
