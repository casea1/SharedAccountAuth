<#
=======================================================================
 Register-AuditTasks.ps1 - Sign-On Audit Logger task registration
 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules.
 Built-in modules used: Microsoft.PowerShell.* and ScheduledTasks.
 Fully offline. No network calls.

 PURPOSE (spec section 11)
 -----------------------------------------------------------------------
 Registers the two scheduled tasks that drive the audit prompt:

   SharedAccountAuth-Logon   LogonTrigger scoped to the shared account.
   SharedAccountAuth-Unlock  SessionStateChangeTrigger / SessionUnlock,
                       scoped to the shared account.

 Both tasks are SCOPED TO THE SHARED ACCOUNT so that personal logins
 never trigger them:
   - Principal : UserId = resolved SharedAccount (local account; see
                 RESOLUTION below), LogonType=InteractiveToken,
                 RunLevel=LeastPrivilege. The task therefore runs in the
                 shared user's INTERACTIVE desktop session (session != 0),
                 NOT as SYSTEM / session 0, and WITHOUT elevation. The
                 interactive session is required for the WPF window to be
                 visible.
   - Action    : wscript.exe "<install>\src\Launch-SharedAccountAuth.vbs" <EventType>
                 using the ABSOLUTE install path resolved at registration.
                 wscript runs the VBS with window style 0 (no console flash),
                 which in turn launches SharedAccountAuth.ps1 -EventType <EventType>.
   - Settings  : MultipleInstancesPolicy=IgnoreNew,
                 DisallowStartIfOnBatteries=false, StopIfGoingOnBatteries=false,
                 AllowHardTerminate=true, ExecutionTimeLimit=PT0S (no limit),
                 RunOnlyIfNetworkAvailable=false (run even if the share is
                 down -> the prompt spools locally), Enabled=true.

 SHARED-ACCOUNT RESOLUTION (spec section 11)
 -----------------------------------------------------------------------
 Task Scheduler requires a concrete account in <UserId>; a relative form
 such as '.\name' or a bare 'name' is NOT acceptable for a LOCAL account.
 So at registration we resolve the configured SharedAccount as follows:
   MACHINE\name  -> kept as-is (already fully qualified).
   .\name        -> $env:COMPUTERNAME\name  (this machine's local SAM).
   name          -> $env:COMPUTERNAME\name  (bare name == local account).
 The same resolved value is used for BOTH the principal UserId and the
 trigger UserId (the trigger UserId is the PRIMARY scope control; the
 prompt's own self-check, spec section 9.2, is the backstop).

 The SessionStateChange unlock trigger is NOT exposed by
 New-ScheduledTaskTrigger, so the task XML is authored by hand and
 registered with Register-ScheduledTask -Xml -Force.

 This script:
   1. Loads config via Get-AuditConfig (AuditCommon.ps1).
   2. Requires admin (self-check; friendly message + diag if not elevated).
   3. Resolves the absolute install root and the local SharedAccount.
   4. Generates the Logon + Unlock task XML.
   5. Writes the generated XML to tasks\ for reference/audit.
   6. Registers both with Register-ScheduledTask -Xml -Force, logging each
      step to the local diag log.

 -----------------------------------------------------------------------
 Inline config block (mirrors config\AuditConfig.psd1 - the single source
 of truth). Keys relevant to this script (loaded at runtime via
 Get-AuditConfig from src\AuditCommon.ps1):
   SharedAccount   REQUIRED. MACHINE\name | .\name | bare name. Resolved
                   to MACHINE\name (see RESOLUTION) and used for BOTH the
                   principal and the trigger UserId of each task.
   DiagLogPath     '' -> C:\ProgramData\SharedAccountAuth\diag\audit-diag.log
=======================================================================
#>

[CmdletBinding()]
param(
    # Optional override of the config file path; defaults to ..\config\AuditConfig.psd1.
    [string] $ConfigPath,

    # Optional override of the shared account (MACHINE\name, .\name, or bare
    # name). Blank => use config SharedAccount. Whatever is chosen is resolved
    # to a fully-qualified local account (MACHINE\name) before use.
    [string] $SharedAccount
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Resolve paths and dot-source the shared library. $PSScriptRoot is deploy\;
# the library lives in ..\src\AuditCommon.ps1, the VBS in ..\src\, and the
# reference task XML in ..\tasks\.
# ---------------------------------------------------------------------
$InstallRoot = Split-Path -Parent $PSScriptRoot                       # repo / install root
$SrcDir      = Join-Path $InstallRoot 'src'
$TasksDir    = Join-Path $InstallRoot 'tasks'
$CommonPath  = Join-Path $SrcDir 'AuditCommon.ps1'
$VbsPath     = Join-Path $SrcDir 'Launch-SharedAccountAuth.vbs'

if (-not (Test-Path -LiteralPath $CommonPath)) {
    throw "AuditCommon.ps1 not found at $CommonPath"
}
. $CommonPath

# Task names registered in the root Task Scheduler folder.
$LogonTaskName  = 'SharedAccountAuth-Logon'
$UnlockTaskName = 'SharedAccountAuth-Unlock'


function Test-IsAdministrator {
<#
.SYNOPSIS
    Returns $true if the current process is running elevated (member of the
    local Administrators role).
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param()
    try {
        $id        = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}


function Resolve-AuditTaskAccount {
<#
.SYNOPSIS
    Resolves the configured shared account to a fully-qualified LOCAL account
    (MACHINE\name) suitable for a Task Scheduler <UserId>.
.DESCRIPTION
    Per spec section 11, a LOCAL account must be fully qualified for the
    scheduled-task principal / trigger UserId. Resolution:
        MACHINE\name -> kept as-is (already qualified; backslash present and
                        the prefix is not '.' so we treat it as MACHINE\name).
        .\name       -> $env:COMPUTERNAME\name
        name         -> $env:COMPUTERNAME\name
    The machine name comes from Get-AuditComputerName (never blank:
    COMPUTERNAME -> DNS -> UNKNOWN-HOST), so the result is never blank.
.PARAMETER Account
    The configured/overridden account string (MACHINE\name, .\name, or name).
.OUTPUTS
    [string] MACHINE\name (never blank).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Account
    )

    $machine = Get-AuditComputerName            # never blank (spec hard constraint)
    $value   = $Account.Trim()

    $bs = $value.IndexOf('\')
    if ($bs -lt 0) {
        # Bare 'name' -> this machine's local account.
        return '{0}\{1}' -f $machine, $value
    }

    $prefix = $value.Substring(0, $bs)
    $leaf   = $value.Substring($bs + 1)

    if ($prefix -eq '.' -or [string]::IsNullOrWhiteSpace($prefix)) {
        # '.\name' (or '\name') -> this machine's local account.
        return '{0}\{1}' -f $machine, $leaf
    }

    # Already MACHINE\name (or DOMAIN\name) - keep as supplied.
    return $value
}


function ConvertTo-AuditXmlText {
<#
.SYNOPSIS
    XML-escapes a string for safe insertion into element text or attribute
    values (&, <, >, ", ').
.PARAMETER Value
    Raw text (e.g. MACHINE\User, a file path).
.OUTPUTS
    [string] XML-escaped text.
#>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()] [string] $Value
    )
    if ($null -eq $Value) { return '' }
    $t = $Value
    # & MUST be replaced first or it would double-escape the entities below.
    $t = $t.Replace('&', '&amp;')
    $t = $t.Replace('<', '&lt;')
    $t = $t.Replace('>', '&gt;')
    $t = $t.Replace('"', '&quot;')
    $t = $t.Replace("'", '&apos;')
    return $t
}


function New-AuditTaskXml {
<#
.SYNOPSIS
    Builds the Task Scheduler 1.2 XML for one audit task (Logon or Unlock).
.DESCRIPTION
    Produces a complete, registerable Task 1.2 XML string honoring spec
    section 11:
      - InteractiveToken principal, LeastPrivilege, scoped to the shared
        account (UserId) so personal logins never trigger it.
      - The matching trigger:
          Logon  -> <LogonTrigger><UserId>...</UserId></LogonTrigger>
          Unlock -> <SessionStateChangeTrigger>
                      <StateChange>SessionUnlock</StateChange>
                      <UserId>...</UserId>
                    </SessionStateChangeTrigger>
        both scoped to the shared account.
      - A wscript.exe action launching the VBS with the matching EventType
        using the absolute install path.
      - The fixed Settings block (IgnoreNew, battery flags false,
        AllowHardTerminate=true, ExecutionTimeLimit=PT0S,
        RunOnlyIfNetworkAvailable=false, Enabled=true).
    All interpolated values are XML-escaped.
.PARAMETER EventType
    'Logon' or 'Unlock'. Selects the trigger shape and the VBS argument.
.PARAMETER UserId
    The resolved shared account (MACHINE\User) for the principal and trigger.
.PARAMETER ActionExec
    The action command (wscript.exe, full path if resolvable).
.PARAMETER ActionArgs
    The action arguments ("<install>\src\Launch-SharedAccountAuth.vbs" <EventType>).
.PARAMETER Description
    RegistrationInfo description text.
.PARAMETER Uri
    Task URI (e.g. \SharedAccountAuth-Logon).
.OUTPUTS
    [string] the task XML.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Logon', 'Unlock')] [string] $EventType,
        [Parameter(Mandatory = $true)] [string] $UserId,
        [Parameter(Mandatory = $true)] [string] $ActionExec,
        [Parameter(Mandatory = $true)] [string] $ActionArgs,
        [Parameter(Mandatory = $true)] [string] $Description,
        [Parameter(Mandatory = $true)] [string] $Uri
    )

    $userXml = ConvertTo-AuditXmlText -Value $UserId
    $execXml = ConvertTo-AuditXmlText -Value $ActionExec
    $argsXml = ConvertTo-AuditXmlText -Value $ActionArgs
    $descXml = ConvertTo-AuditXmlText -Value $Description
    $uriXml  = ConvertTo-AuditXmlText -Value $Uri

    # Trigger XML differs by event type. Both are scoped to the shared account
    # via <UserId>. The unlock trigger is the native SessionStateChangeTrigger
    # with StateChange=SessionUnlock (no Security audit-policy dependency).
    if ($EventType -eq 'Logon') {
        $triggerXml = @"
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$userXml</UserId>
    </LogonTrigger>
"@
    } else {
        $triggerXml = @"
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <StateChange>SessionUnlock</StateChange>
      <UserId>$userXml</UserId>
    </SessionStateChangeTrigger>
"@
    }

    # NOTE: Register-ScheduledTask -Xml and Task Scheduler exports both use a
    # UTF-16-declared document. We keep the standard <?xml ... encoding="UTF-16"?>
    # header so the on-disk reference is interchangeable with a real export.
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$descXml</Description>
    <URI>$uriXml</URI>
  </RegistrationInfo>
  <Triggers>
$triggerXml
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$userXml</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$execXml</Command>
      <Arguments>$argsXml</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    return $xml
}


# =====================================================================
# Main
# =====================================================================
$cfg = $null
try {
    # Load config first so we can diag-log everything, even failures below.
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $cfg = Get-AuditConfig
    } else {
        $cfg = Get-AuditConfig -ConfigPath $ConfigPath
    }
} catch {
    Write-Warning "Failed to load audit config: $($_.Exception.Message)"
    throw
}

Write-AuditDiag -Config $cfg -Level Info -Message 'Register-AuditTasks started.'

# ---- Admin self-check (friendly message + diag if not elevated). ----
if (-not (Test-IsAdministrator)) {
    $msg = 'Register-AuditTasks must be run as Administrator (elevated). Right-click PowerShell -> Run as administrator, then re-run.'
    Write-AuditDiag -Config $cfg -Level Error -Message $msg
    Write-Warning $msg
    return
}

try {
    # ---- Resolve the shared account to a fully-qualified local account. ----
    # SharedAccount is REQUIRED by Get-AuditConfig (it throws if missing), so by
    # here $cfg.SharedAccount is guaranteed non-blank unless overridden.
    $accountInput = if (-not [string]::IsNullOrWhiteSpace($SharedAccount)) { $SharedAccount } else { [string]$cfg.SharedAccount }
    if ([string]::IsNullOrWhiteSpace($accountInput)) {
        throw "No SharedAccount available to scope the tasks (config SharedAccount is blank and no -SharedAccount override was given)."
    }
    $resolvedUser = Resolve-AuditTaskAccount -Account $accountInput
    Write-AuditDiag -Config $cfg -Level Info -Message ("Resolved shared task account: {0} (from '{1}')" -f $resolvedUser, $accountInput)

    # ---- Resolve the absolute action exec + args. ----
    # wscript.exe is on PATH; resolve its absolute path for robustness, falling
    # back to %WINDIR%\System32\wscript.exe, then the bare name.
    $wscript = $null
    try {
        $cmd = Get-Command -Name 'wscript.exe' -ErrorAction Stop
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
            $wscript = $cmd.Source
        }
    } catch { }
    if ([string]::IsNullOrWhiteSpace($wscript)) {
        $candidate = Join-Path $env:WINDIR 'System32\wscript.exe'
        if (Test-Path -LiteralPath $candidate) { $wscript = $candidate } else { $wscript = 'wscript.exe' }
    }

    if (-not (Test-Path -LiteralPath $VbsPath)) {
        # Not fatal to registration, but warn loudly: the tasks would do nothing.
        Write-AuditDiag -Config $cfg -Level Warn -Message ("Launcher VBS not found at {0}; tasks will be registered but will fail to launch until it exists." -f $VbsPath)
        Write-Warning "Launcher not found at $VbsPath (registering anyway)."
    }

    # Action arguments: the ABSOLUTE VBS path (quoted) + the EventType token.
    $logonArgs  = '"{0}" Logon'  -f $VbsPath
    $unlockArgs = '"{0}" Unlock' -f $VbsPath

    # ---- Generate the task XML. ----
    $logonXml = New-AuditTaskXml -EventType 'Logon' -UserId $resolvedUser `
        -ActionExec $wscript -ActionArgs $logonArgs `
        -Description 'Shared-Account Sign-On Audit Logger - shows the identify-yourself prompt at interactive logon and records the access to the central append-only CSV.' `
        -Uri ('\{0}' -f $LogonTaskName)

    $unlockXml = New-AuditTaskXml -EventType 'Unlock' -UserId $resolvedUser `
        -ActionExec $wscript -ActionArgs $unlockArgs `
        -Description 'Shared-Account Sign-On Audit Logger - shows the identify-yourself prompt when the workstation is unlocked and records the access to the central append-only CSV.' `
        -Uri ('\{0}' -f $UnlockTaskName)

    # ---- Write the generated XML to tasks\ for reference/audit. ----
    # Task Scheduler XML is conventionally UTF-16 (matches the <?xml?> header);
    # write a Unicode (UTF-16 LE w/ BOM) file so the on-disk reference matches.
    if (-not (Test-Path -LiteralPath $TasksDir)) {
        New-Item -ItemType Directory -Path $TasksDir -Force | Out-Null
    }
    $logonRefPath  = Join-Path $TasksDir 'SharedAccountAuth-Logon.xml'
    $unlockRefPath = Join-Path $TasksDir 'SharedAccountAuth-Unlock.xml'
    Set-Content -LiteralPath $logonRefPath  -Value $logonXml  -Encoding Unicode
    Set-Content -LiteralPath $unlockRefPath -Value $unlockXml -Encoding Unicode
    Write-AuditDiag -Config $cfg -Level Info -Message ("Wrote reference task XML to {0} and {1}" -f $logonRefPath, $unlockRefPath)

    # ---- Register both tasks via -Xml -Force. ----
    # -Force overwrites an existing task of the same name (idempotent re-deploy).
    # -Xml carries the InteractiveToken principal + SessionStateChange trigger
    # that the cmdlet trigger builders cannot express.
    Register-ScheduledTask -TaskName $LogonTaskName -Xml $logonXml -Force -ErrorAction Stop | Out-Null
    Write-AuditDiag -Config $cfg -Level Info -Message ("Registered task {0} scoped to {1}" -f $LogonTaskName, $resolvedUser)
    Write-Host ("Registered task '{0}' (scoped to {1})." -f $LogonTaskName, $resolvedUser)

    Register-ScheduledTask -TaskName $UnlockTaskName -Xml $unlockXml -Force -ErrorAction Stop | Out-Null
    Write-AuditDiag -Config $cfg -Level Info -Message ("Registered task {0} scoped to {1}" -f $UnlockTaskName, $resolvedUser)
    Write-Host ("Registered task '{0}' (scoped to {1})." -f $UnlockTaskName, $resolvedUser)

    Write-AuditDiag -Config $cfg -Level Info -Message 'Register-AuditTasks completed successfully.'
    Write-Host 'Audit tasks registered successfully.'
}
catch {
    $err = $_.Exception.Message
    Write-AuditDiag -Config $cfg -Level Error -Message ("Register-AuditTasks failed: {0}" -f $err)
    Write-Warning ("Registration failed: {0}" -f $err)
    throw
}
