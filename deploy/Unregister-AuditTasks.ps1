<#
=======================================================================
 Unregister-AuditTasks.ps1 - Sign-On Audit Logger task removal
 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules.
 Built-in modules used: Microsoft.PowerShell.* and ScheduledTasks.
 Fully offline. No network calls.

 PURPOSE (spec section 11)
 -----------------------------------------------------------------------
 Removes the two scheduled tasks created by Register-AuditTasks.ps1:

   SharedAccountAuth-Logon
   SharedAccountAuth-Unlock

 Each is removed via Unregister-ScheduledTask -Confirm:$false. The script
 is TOLERANT if a task is absent (already removed / never installed): it
 logs the fact and continues rather than failing.

 This script:
   1. Loads config via Get-AuditConfig (AuditCommon.ps1).
   2. Requires admin (self-check; friendly message + diag if not elevated).
   3. Unregisters each task if present (no error if missing).
   4. Logs every step to the local diag log.

 -----------------------------------------------------------------------
 Inline config block (mirrors config\AuditConfig.psd1 - the single source
 of truth). Key relevant to this script (loaded at runtime via
 Get-AuditConfig from src\AuditCommon.ps1):
   DiagLogPath     '' -> C:\ProgramData\SharedAccountAuth\diag\audit-diag.log
=======================================================================
#>

[CmdletBinding()]
param(
    # Optional override of the config file path; defaults to ..\config\AuditConfig.psd1.
    [string] $ConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Resolve paths and dot-source the shared library. $PSScriptRoot is deploy\;
# the library lives in ..\src\AuditCommon.ps1.
# ---------------------------------------------------------------------
$InstallRoot = Split-Path -Parent $PSScriptRoot
$SrcDir      = Join-Path $InstallRoot 'src'
$CommonPath  = Join-Path $SrcDir 'AuditCommon.ps1'

if (-not (Test-Path -LiteralPath $CommonPath)) {
    throw "AuditCommon.ps1 not found at $CommonPath"
}
. $CommonPath

# The two tasks registered by Register-AuditTasks.ps1 (root TS folder).
$TaskNames = @('SharedAccountAuth-Logon', 'SharedAccountAuth-Unlock')


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


function Remove-AuditTask {
<#
.SYNOPSIS
    Unregisters one scheduled task if it exists. Tolerant if absent.
.DESCRIPTION
    Looks the task up with Get-ScheduledTask (-ErrorAction SilentlyContinue,
    which yields $null when the task is missing). If found, removes it with
    Unregister-ScheduledTask -Confirm:$false. A missing task is logged and
    skipped - never an error. Each outcome is diag-logged.
.PARAMETER Name
    Task name in the root Task Scheduler folder.
.PARAMETER Config
    Resolved config hashtable (for diag logging).
.OUTPUTS
    [bool] $true if a task was removed, $false if it was absent or failed.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]    $Name,
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    # Get-ScheduledTask errors when the task does not exist; SilentlyContinue
    # turns that into $null so we can branch tolerantly.
    $existing = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Write-AuditDiag -Config $Config -Level Info -Message ("Task {0} not present; nothing to remove." -f $Name)
        Write-Host ("Task '{0}' not present (skipped)." -f $Name)
        return $false
    }

    try {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop | Out-Null
        Write-AuditDiag -Config $Config -Level Info -Message ("Unregistered task {0}." -f $Name)
        Write-Host ("Unregistered task '{0}'." -f $Name)
        return $true
    }
    catch {
        # Tolerant: log the failure but do NOT abort the whole script - the
        # other task should still be attempted.
        Write-AuditDiag -Config $Config -Level Warn -Message ("Failed to unregister task {0}: {1}" -f $Name, $_.Exception.Message)
        Write-Warning ("Failed to unregister '{0}': {1}" -f $Name, $_.Exception.Message)
        return $false
    }
}


# =====================================================================
# Main
# =====================================================================
$cfg = $null
try {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $cfg = Get-AuditConfig
    } else {
        $cfg = Get-AuditConfig -ConfigPath $ConfigPath
    }
} catch {
    Write-Warning "Failed to load audit config: $($_.Exception.Message)"
    throw
}

Write-AuditDiag -Config $cfg -Level Info -Message 'Unregister-AuditTasks started.'

# ---- Admin self-check (friendly message + diag if not elevated). ----
if (-not (Test-IsAdministrator)) {
    $msg = 'Unregister-AuditTasks must be run as Administrator (elevated). Right-click PowerShell -> Run as administrator, then re-run.'
    Write-AuditDiag -Config $cfg -Level Error -Message $msg
    Write-Warning $msg
    return
}

try {
    $removed = 0
    foreach ($name in $TaskNames) {
        if (Remove-AuditTask -Name $name -Config $cfg) {
            $removed++
        }
    }

    Write-AuditDiag -Config $cfg -Level Info -Message ("Unregister-AuditTasks completed. {0} task(s) removed." -f $removed)
    Write-Host ("Done. {0} task(s) removed." -f $removed)
}
catch {
    # Should be rare since Remove-AuditTask swallows per-task errors, but keep a
    # top-level guard so the script still diag-logs any unexpected failure.
    $err = $_.Exception.Message
    Write-AuditDiag -Config $cfg -Level Error -Message ("Unregister-AuditTasks failed: {0}" -f $err)
    Write-Warning ("Unregister failed: {0}" -f $err)
    throw
}
