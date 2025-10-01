;----------------------------
; OSAV Installer Script 
;----------------------------

#define MyAppName "OSAV - Open Source Anti-Virus"
#define MyAppVersion "1.1"
#define MyAppPublisher "sourcecode347"
#define MyAppExeName "osav.exe"
#define SourcePath "{SOURCE_PATH}"   ; <-- Placeholder, replaced by Python
#define MyAppIcon ".\assets\osav.ico"
#define MyLicense ".\LICENSE"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppId={{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=Output
OutputBaseFilename=OSAV_SETUP
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile={#MyLicense}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourcePath}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\database\*"; DestDir: "{app}\database"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: ".\virus_hashes.pkl"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppIcon}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
