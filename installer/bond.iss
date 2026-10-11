; Inno Setup script for Bond. Build with build.ps1, which stages the files in
; dist\app and passes /DAppVersion.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6E2B9C1D-4F3A-4E8B-9C57-2A1D0B7E5F31}
AppName=Bond
AppVersion={#AppVersion}
AppVerName=Bond {#AppVersion}
AppPublisher=rdbuff
AppCopyright=Copyright (c) 2026 rdbuff
AppPublisherURL=https://github.com/rdbuff
DefaultDirName={autopf}\Bond
DefaultGroupName=Bond
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableReadyPage=yes
DisableWelcomePage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=Bond-Setup-{#AppVersion}
SetupIconFile=bond.ico
UninstallDisplayIcon={app}\Bond.exe
UninstallDisplayName=Bond
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"
Name: "autostart"; Description: "&Start Bond when I sign in to Windows (opens in the system tray)"; Flags: unchecked

[Files]
Source: "..\dist\app\Bond.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\bond-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\app\wintun-LICENSE.txt"; DestDir: "{app}\licenses"
Source: "..\LICENSE"; DestDir: "{app}\licenses"; DestName: "Bond-LICENSE.txt"
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}\licenses"
Source: "..\README.md"; DestDir: "{app}"; Flags: isreadme

[Icons]
Name: "{autoprograms}\Bond"; Filename: "{app}\Bond.exe"; Comment: "Combine WiFi and Ethernet, block ads"
Name: "{autodesktop}\Bond"; Filename: "{app}\Bond.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Bond.exe"; Parameters: "--set-autostart on"; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Setting up start with Windows..."
Filename: "{app}\Bond.exe"; Description: "Launch Bond"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM Bond.exe"; Flags: runhidden; RunOnceId: "StopBond"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM bond-client.exe"; Flags: runhidden; RunOnceId: "StopBondClient"
Filename: "{app}\Bond.exe"; Parameters: "--cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "Cleanup"

[Code]
const
  WebView2Guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2Url = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703';

var
  DownloadPage: TDownloadWizardPage;

function WebView2Installed: Boolean;
var
  Version: String;
begin
  Result :=
    (RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\' + WebView2Guid, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0')) or
    (RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\' + WebView2Guid, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0'));
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), 'Downloading the Microsoft Edge WebView2 Runtime, which Bond''s window needs...', nil);
end;

procedure EnsureWebView2;
var
  ResultCode: Integer;
begin
  if not WebView2Installed then
  begin
    DownloadPage.Clear;
    DownloadPage.Add(WebView2Url, 'MicrosoftEdgeWebview2Setup.exe', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
        DownloadPage.SetText('Installing the Microsoft Edge WebView2 Runtime...', '');
        if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or not WebView2Installed then
          MsgBox('The WebView2 Runtime could not be installed (code ' + IntToStr(ResultCode) + '). Bond''s window needs it; you can install it later from https://developer.microsoft.com/microsoft-edge/webview2/', mbError, MB_OK);
      except
        MsgBox('Downloading the WebView2 Runtime failed: ' + GetExceptionMessage + #13#10 + 'You can install it later from https://developer.microsoft.com/microsoft-edge/webview2/', mbError, MB_OK);
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

// Runs right before files are copied: get WebView2 if missing, and stop a
// running copy so its files can be replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  EnsureWebView2;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Bond.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM bond-client.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and DirExists(ExpandConstant('{userappdata}\Bond')) then
    if MsgBox('Also delete your Bond settings and server key?' + #13#10 + ExpandConstant('{userappdata}\Bond'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{userappdata}\Bond'), True, True, True);
end;
