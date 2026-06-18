' =====================================================================
'  Launch-SharedAccountAuth.vbs <EventType>
'  Self-locating hidden launcher for the sign-on audit prompt.
'
'  Purpose: start SharedAccountAuth.ps1 with NO visible PowerShell console
'  window. wscript.exe runs this VBS, and we spawn powershell.exe with
'  window style 0 (hidden) so the user never sees a flashing console.
'
'  Self-locating: we derive our own folder from WScript.ScriptFullName
'  via FileSystemObject (GetParentFolderName). This means the script
'  works no matter where the install directory lives -- no hard-coded
'  paths -- so the scheduled task only needs the absolute path to THIS
'  file and SharedAccountAuth.ps1 is always found as a sibling.
'
'  ---------------------------------------------------------------
'  EXECUTION POLICY NOTE -- the scripts are NOT signed:
'  ---------------------------------------------------------------
'  The "-ExecutionPolicy Bypass" token below lets PowerShell run
'  SharedAccountAuth.ps1 WITHOUT an Authenticode signature. By project
'  policy these scripts are not code-signed. Bypass (rather than
'  RemoteSigned) also avoids the "Mark of the Web" block that can
'  otherwise stop a .ps1 copied in from a ZIP or removable media -- a
'  blocked script would mean no audit prompt, i.e. a SILENT failure.
'  The token applies only to THIS launched powershell.exe process.
'
'  Neither this .vbs nor the .ps1 is gated by a signature. Both are
'  instead governed by AppLocker (Script / path rules) -- see README for
'  the AppLocker policy that whitelists the install directory and blocks
'  arbitrary scripts elsewhere. So: AppLocker is the integrity control;
'  code signing is not used.
'
'  If a site DOES mandate signing, set this single token to "AllSigned"
'  (or "RemoteSigned") and sign the .ps1/.psd1 yourself -- but note that a
'  MACHINE-LEVEL GPO execution policy, if set, OVERRIDES this process-scope
'  token, so signing may be required regardless of what is written here.
' =====================================================================

Option Explicit
Dim sh, fso, here, ps1, evt, cmd

Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Derive our own folder (the src\ directory) at runtime.
here = fso.GetParentFolderName(WScript.ScriptFullName)   ' the src\ folder
ps1  = here & "\SharedAccountAuth.ps1"

' EventType argument: default to "Logon" when none is supplied.
evt = "Logon"
If WScript.Arguments.Count > 0 Then evt = WScript.Arguments(0)

' Build the PowerShell invocation.
'   -NoProfile        : ignore user/host profiles (fast, deterministic)
'   -ExecutionPolicy  : Bypass -- run the unsigned .ps1 (see NOTE above)
'   -WindowStyle Hidden : belt-and-suspenders; sh.Run 0 already hides it
'   -File "<ps1>"     : run the audit prompt script
'   -EventType <evt>  : pass through Logon / Unlock / etc.
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """ -EventType " & evt

' sh.Run cmd, intWindowStyle, bWaitOnReturn
'   0     = hidden window (no console flash)
'   False = do not wait for the process to finish (non-blocking)
sh.Run cmd, 0, False
