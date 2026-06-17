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
'  SECURITY NOTE -- what AllSigned gates (and what it does NOT):
'  ---------------------------------------------------------------
'  The "-ExecutionPolicy AllSigned" token below applies to the
'  POWERSHELL script (SharedAccountAuth.ps1). It forces PowerShell to refuse
'  to run that .ps1 unless it carries a trusted Authenticode signature.
'
'  It does NOT gate THIS .vbs file. VBScript is executed by the Windows
'  Script Host (wscript.exe), which ignores PowerShell execution policy
'  entirely. The VBS launcher is instead covered by AppLocker (Script
'  rules) -- see README for the AppLocker policy that whitelists this
'  launcher and blocks arbitrary scripts. So: AppLocker -> VBS,
'  AllSigned -> PS1. Two different gates, by design.
'
'  To switch the PowerShell gate to RemoteSigned (e.g. during dev when
'  the .ps1 is not yet signed), change the single token "AllSigned" to
'  "RemoteSigned" in the cmd string below -- nothing else needs to
'  change. (RemoteSigned only requires a signature on scripts that came
'  from the internet zone; locally-authored .ps1 files run unsigned.)
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
'   -ExecutionPolicy  : AllSigned -- gates the .ps1 (see SECURITY NOTE)
'   -WindowStyle Hidden : belt-and-suspenders; sh.Run 0 already hides it
'   -File "<ps1>"     : run the audit prompt script
'   -EventType <evt>  : pass through Logon / Unlock / etc.
cmd = "powershell.exe -NoProfile -ExecutionPolicy AllSigned -WindowStyle Hidden -File """ & ps1 & """ -EventType " & evt

' sh.Run cmd, intWindowStyle, bWaitOnReturn
'   0     = hidden window (no console flash)
'   False = do not wait for the process to finish (non-blocking)
sh.Run cmd, 0, False
