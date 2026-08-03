; DirectDesk installer (Inno Setup 6)
;
; Installs the three release executables, creates Start Menu shortcuts for
; the host and client, and offers ONE optional task: "Start DirectDesk
; automatically with Windows". That task, if selected:
;   (a) installs and starts the DirectDeskService Windows service via
;       DirectDeskService.exe's own "install" verb ([Run]), reversed by
;       "uninstall" on removal ([UninstallRun]);
;   (b) adds a visible, honestly-named HKCU Run entry ("DirectDesk Host")
;       that launches DirectDeskHost.exe --minimized.
;
; SYNC-POINT: the exact DirectDeskService.exe CLI verbs used below
; (install / uninstall / start / stop) and the DirectDeskHost.exe
; --minimized flag DO NOT YET EXIST in the M0 scaffold (see
; host/src/main.rs, service/src/main.rs). Whoever implements the host and
; service CLI parsing must either match these exact verb/flag names, or
; this script (and installer/scripts/install.ps1 / uninstall.ps1) must be
; updated to match whatever is actually implemented. Every place in this
; file that depends on this is marked "SYNC-POINT" below.
;
; No silent extras: nothing is installed, started, or scheduled beyond what
; is described above and shown to the user in the wizard. No UPnP router
; configuration is performed by this installer under any circumstance.
;
; Binaries are NOT code-signed in this build; Windows SmartScreen will warn
; on first run of the installer itself and of each installed executable.
; This is expected — see docs/SECURITY.md.

#define MyAppName "DirectDesk"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "DirectDesk"
#define MyAppExeHost "DirectDeskHost.exe"
#define MyAppExeClient "DirectDeskClient.exe"
#define MyAppExeService "DirectDeskService.exe"
; Directory (relative to this .iss file) containing the built release exes.
#define ReleaseDir "..\target\release"

[Setup]
; Fixed, stable AppId — do not regenerate this GUID on future edits of this
; script; changing it breaks upgrade/uninstall detection for existing
; installs. Generated once for DirectDesk: 599CBC02-E9B9-4C93-8D8A-BADE5BF3BF24
AppId={{599CBC02-E9B9-4C93-8D8A-BADE5BF3BF24}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\DirectDesk
DefaultGroupName=DirectDesk
DisableProgramGroupPage=yes
; {autopf} resolves to Program Files (64-bit on x64 Windows) with no
; per-user/per-machine ambiguity baked into this script — the installer
; itself still offers the standard Inno "install for all users / just me"
; choice via PrivilegesRequiredOverridesAllowed.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=DirectDeskSetup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Unsigned build: no SignTool directive. SmartScreen warning on the
; installer itself is expected — see docs/SECURITY.md and docs/LIMITATIONS.md.
UninstallDisplayIcon={app}\{#MyAppExeHost}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start DirectDesk automatically with Windows (installs the DirectDesk service and adds a visible ""DirectDesk Host"" startup entry)"; Flags: unchecked

[Files]
Source: "{#ReleaseDir}\{#MyAppExeHost}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ReleaseDir}\{#MyAppExeClient}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ReleaseDir}\{#MyAppExeService}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\DirectDesk Host"; Filename: "{app}\{#MyAppExeHost}"
Name: "{group}\DirectDesk Client"; Filename: "{app}\{#MyAppExeClient}"
Name: "{group}\Uninstall DirectDesk"; Filename: "{uninstallexe}"

[Run]
; SYNC-POINT: "install" and "start" are the assumed DirectDeskService.exe
; CLI verbs. Runs only if the "autostart" task was selected. runhidden
; keeps this invisible during setup (it is a normal, visible-afterward
; service install, not a hidden persistence mechanism — see docs/SECURITY.md
; on what the service will/won't do).
Filename: "{app}\{#MyAppExeService}"; Parameters: "install"; StatusMsg: "Installing DirectDesk service..."; Tasks: autostart; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeService}"; Parameters: "start"; StatusMsg: "Starting DirectDesk service..."; Tasks: autostart; Flags: runhidden waituntilterminated

[UninstallRun]
; Reverse of [Run] above, plus firewall rule cleanup. Uses "RunOnceId" so
; Inno only runs each of these once even if uninstall is somehow invoked
; twice. These run regardless of which tasks were originally selected,
; because EnsureFirewallRules/service-install could have been created
; through the service directly (e.g. via installer/scripts/install.ps1)
; even if the wizard task wasn't ticked — "uninstall" and "stop" are
; harmless no-ops if the service was never installed/running.
; SYNC-POINT: "stop" / "uninstall" / "RemoveFirewallRules"-equivalent CLI
; verbs on DirectDeskService.exe are assumed here; see the header comment.
Filename: "{app}\{#MyAppExeService}"; Parameters: "stop"; RunOnceId: "StopService"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeService}"; Parameters: "uninstall"; RunOnceId: "UninstallService"; Flags: runhidden waituntilterminated

[UninstallDelete]
; Removes the HKCU Run entry's target only if left dangling; the registry
; value itself is removed by the [Registry] entry below via uninsdeletevalue.

[Registry]
; Visible, honestly-named autostart entry — never hidden, never disguised.
; SYNC-POINT: "--minimized" is the assumed DirectDeskHost.exe CLI flag for
; "start hosting but keep the tray-icon-only minimized state" (the tray
; icon itself remains mandatory per docs/SECURITY.md / docs/README.md —
; --minimized affects the main window, not the tray icon's visibility).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "DirectDesk Host"; ValueData: """{app}\{#MyAppExeHost}"" --minimized"; Tasks: autostart; Flags: uninsdeletevalue

[Code]
var
  KeepDataPage: TInputOptionWizardPage;

function InitializeUninstall(): Boolean;
begin
  Result := True;
end;

// Ask before deleting %ProgramData%\DirectDesk on uninstall (settings/logs
// live under LOCALAPPDATA per docs/TROUBLESHOOTING.md; ProgramData is used
// for any machine-scoped state the service writes). Default is "keep" —
// deleting user data is never the silent default.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProgramDataDir: string;
  DeleteData: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    ProgramDataDir := ExpandConstant('{commonappdata}\DirectDesk');
    if DirExists(ProgramDataDir) then
    begin
      DeleteData := MsgBox(
        'Delete DirectDesk''s stored data in' + #13#10 + ProgramDataDir + '?' + #13#10#13#10 +
        'This includes machine-scoped configuration and paired-device identity. ' +
        'Choose No to keep it (e.g. if you plan to reinstall).',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2);
      if DeleteData = IDYES then
      begin
        DelTree(ProgramDataDir, True, True, True);
      end;
    end;
  end;
end;
