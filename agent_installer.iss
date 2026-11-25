
[Setup]
AppName=Insider Threat Agent
AppVersion=1.0
DefaultDirName={pf}\InsiderThreatAgent
DefaultGroupName=Insider Threat Agent
OutputDir=dist
OutputBaseFilename=Setup_Agent
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
CloseApplications=no

[Tasks]
Name: "allusers"; Description: "Install Agent for ALL users on this machine"; GroupDescription: "Installation Scope:"; Flags: exclusive unchecked
Name: "currentuser"; Description: "Install Agent for CURRENT user only"; GroupDescription: "Installation Scope:"; Flags: exclusive

[Files]
Source: "dist\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "deploy\setup_sacl.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Grant all users access to read Event Logs (needed for standard users to read Security Log)
Filename: "{sys}\net.exe"; Parameters: "localgroup ""Event Log Readers"" ""Authenticated Users"" /add"; Flags: runhidden waituntilterminated

; 1. Enable Event 4688 tracking
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:""Process Creation"" /success:enable /failure:enable"; Flags: runhidden waituntilterminated

; 1b. Enable File System object access auditing (needed for RBAC file monitor)
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:""File System"" /success:enable /failure:enable"; Flags: runhidden waituntilterminated

; 2. Enable Command Line arguments in Event 4688 via Registry
Filename: "{sys}\reg.exe"; Parameters: "add ""HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"; Flags: runhidden waituntilterminated

; 2b. Force Windows to respect the granular auditpol setting above
Filename: "{sys}\reg.exe"; Parameters: "add ""HKLM\SYSTEM\CurrentControlSet\Control\Lsa"" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f"; Flags: runhidden waituntilterminated

; 3a. Setup persistence (Current User Only)
Filename: "{sys}\schtasks.exe"; Parameters: "/create /tn ""InsiderThreatAgent"" /tr ""'{app}\agent.exe'"" /sc onlogon /ru ""{%USERDOMAIN}\{%USERNAME}"" /rl HIGHEST /it /f"; Tasks: currentuser; Flags: runhidden waituntilterminated

; 3b. Setup persistence (All Users)
Filename: "{sys}\schtasks.exe"; Parameters: "/create /tn ""InsiderThreatAgent"" /tr ""'{app}\agent.exe'"" /sc onlogon /ru ""BUILTIN\Users"" /rl HIGHEST /it /f"; Tasks: allusers; Flags: runhidden waituntilterminated

; 3b. Apply SACLs to restricted folders based on access_policy.json
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\setup_sacl.ps1"" -InstallDir ""{app}"""; Flags: runhidden waituntilterminated


; 4. Start the agent immediately after installation in the current interactive session
Filename: "{app}\agent.exe"; Flags: runhidden nowait

[UninstallRun]
; Remove scheduled task on uninstall
Filename: "{sys}\schtasks.exe"; Parameters: "/delete /tn ""InsiderThreatAgent"" /f"; Flags: runhidden waituntilterminated

; Optionally kill the agent process if it's running
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im agent.exe"; Flags: runhidden waituntilterminated

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM agent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
