<#
=======================================================================
 Install-Audit.ps1 - one-command per-PC installer + preflight validator
 for the Shared-Account Sign-On Audit Logger.

 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules
 (built-ins only: Microsoft.PowerShell.*, ScheduledTasks, and the ADSI
 WinNT provider via [ADSI] for offline local-account enumeration). Fully
 offline; the only network touch is Test-Path against the configured UNC
 share/roster to check reachability -- which is the whole point of the
 preflight.

 WHAT IT DOES
 -----------------------------------------------------------------------
 Run this ONCE per workstation after copying the tree into place and
 editing config\AuditConfig.psd1. It:
   1. SELF-ELEVATES (relaunches itself through UAC in a new window) if not
      already admin, so the operator need not remember "Run as administrator".
   2. Registers the Logon + Unlock scheduled tasks by invoking the existing
      deploy\Register-AuditTasks.ps1 (NO duplicated task XML).
   3. Runs a PREFLIGHT VALIDATION that surfaces -- at install time -- the
      failure modes that are otherwise SILENT at runtime:
         * config invalid / SharedAccount blank
         * install files missing
         * SharedAccount has no matching local account (if it is local)
         * central LogPath UNC unreachable (runtime would spool locally)
         * roster unreadable, or roster usernames with NO matching local
           account on THIS PC (those people could never authenticate here)
         * tasks not registered / not enabled
      and prints an OK / WARN / FAIL report.

 MODES
   (default)        register the tasks, then run the preflight report.
   -ValidateOnly    run ONLY the preflight report; change nothing on disk.
   -SkipValidation  register the tasks without the preflight report.

 NOTE ON SIGNING: the scripts are NOT code-signed. The launcher runs the
 .ps1 with -ExecutionPolicy Bypass and AppLocker governs the install
 directory (see README / spec section 14). This installer is therefore
 not signed either.
=======================================================================
#>
[CmdletBinding()]
param(
    # Optional override of the config file path; passed through to
    # Register-AuditTasks.ps1 and Get-AuditConfig. Blank => default
    # ..\config\AuditConfig.psd1.
    [string] $ConfigPath,

    # Optional override of the shared account to scope the tasks to
    # (MACHINE\name, .\name, or bare name). Blank => config SharedAccount.
    [string] $SharedAccount,

    # Run ONLY the preflight validation; do not register anything.
    [switch] $ValidateOnly,

    # Register the tasks but skip the preflight validation report.
    [switch] $SkipValidation
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Resolve paths. $PSScriptRoot is deploy\; the library lives in
# ..\src\AuditCommon.ps1 and the registration helper alongside us.
# ---------------------------------------------------------------------
$DeployDir    = $PSScriptRoot
$InstallRoot  = Split-Path -Parent $DeployDir
$SrcDir       = Join-Path $InstallRoot 'src'
$CommonPath   = Join-Path $SrcDir 'AuditCommon.ps1'
$RegisterPath = Join-Path $DeployDir 'Register-AuditTasks.ps1'
$InstallCommonPath = Join-Path $DeployDir 'AuditInstallCommon.ps1'

function Test-IsAdministrator {
<#
.SYNOPSIS
    Returns $true if the current process is running elevated.
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}


function Invoke-SelfElevate {
<#
.SYNOPSIS
    Relaunch this script elevated (UAC), forwarding the original parameters,
    in a NEW window kept open with -NoExit so the operator can read the
    report. The caller should return after this.
.DESCRIPTION
    Uses Start-Process -Verb RunAs (the standard offline self-elevation
    pattern). Forwards -ConfigPath / -SharedAccount / -ValidateOnly /
    -SkipValidation as supplied. -ExecutionPolicy Bypass mirrors the runtime
    posture (scripts are unsigned).
#>
    [CmdletBinding()]
    param()

    # Build a single argument string with quoted paths (robust against spaces).
    $inner = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath))    { $inner += " -ConfigPath `"$ConfigPath`"" }
    if (-not [string]::IsNullOrWhiteSpace($SharedAccount)) { $inner += " -SharedAccount `"$SharedAccount`"" }
    if ($ValidateOnly)   { $inner += ' -ValidateOnly' }
    if ($SkipValidation) { $inner += ' -SkipValidation' }

    Start-Process -FilePath 'powershell.exe' -ArgumentList $inner -Verb RunAs | Out-Null
}


function Write-AuditPreflightReport {
<#
.SYNOPSIS
    Pretty-prints the preflight results and a tally.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Results)

    Write-Host ''
    Write-Host '=== Preflight validation ===' -ForegroundColor Cyan
    foreach ($r in $Results) {
        $color = 'Green'
        if ($r.Status -eq 'WARN') { $color = 'Yellow' }
        elseif ($r.Status -eq 'FAIL') { $color = 'Red' }
        Write-Host ('  [{0,-4}] {1,-30} {2}' -f $r.Status, $r.Check, $r.Detail) -ForegroundColor $color
    }

    $fail = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    Write-Host ''
    if ($fail -gt 0) {
        Write-Host ("Preflight: {0} FAIL, {1} WARN - resolve the FAILs before relying on the prompt." -f $fail, $warn) -ForegroundColor Red
    } elseif ($warn -gt 0) {
        Write-Host ("Preflight: 0 FAIL, {0} WARN - review the warnings above." -f $warn) -ForegroundColor Yellow
    } else {
        Write-Host 'Preflight: all checks OK.' -ForegroundColor Green
    }
}


# =====================================================================
#  MAIN
# =====================================================================

# Self-elevate FIRST (before touching anything) unless already admin.
if (-not (Test-IsAdministrator)) {
    Write-Host 'Not elevated - relaunching with administrator rights (UAC prompt)...' -ForegroundColor Yellow
    try {
        Invoke-SelfElevate
        Write-Host 'Elevated installer launched in a new window. This window can be closed.'
        return
    } catch {
        Write-Warning ("Self-elevation failed: {0}" -f $_.Exception.Message)
        Write-Warning 'Re-run this script from an elevated PowerShell (Run as administrator).'
        return
    }
}

# Load the shared library + config.
if (-not (Test-Path -LiteralPath $CommonPath)) {
    throw "AuditCommon.ps1 not found at $CommonPath"
}
. $CommonPath
if (-not (Test-Path -LiteralPath $InstallCommonPath)) { throw "AuditInstallCommon.ps1 not found at $InstallCommonPath" }
. $InstallCommonPath

$cfg = $null
try {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $cfg = Get-AuditConfig
    } else {
        $cfg = Get-AuditConfig -ConfigPath $ConfigPath
    }
} catch {
    Write-Warning ("Failed to load audit config: {0}" -f $_.Exception.Message)
    throw
}

Write-AuditDiag -Config $cfg -Level Info -Message 'Install-Audit started.'

Write-Host ''
Write-Host 'Shared-Account Sign-On Audit Logger - install' -ForegroundColor Cyan
Write-Host '---------------------------------------------' -ForegroundColor Cyan

# Register the tasks (unless validate-only) by delegating to the existing
# helper so the task XML lives in exactly one place.
if (-not $ValidateOnly) {
    if (-not (Test-Path -LiteralPath $RegisterPath)) {
        throw "Register-AuditTasks.ps1 not found at $RegisterPath"
    }
    Write-Host 'Registering scheduled tasks...' -ForegroundColor Cyan
    $regParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath))    { $regParams['ConfigPath']    = $ConfigPath }
    if (-not [string]::IsNullOrWhiteSpace($SharedAccount)) { $regParams['SharedAccount'] = $SharedAccount }
    & $RegisterPath @regParams
    Write-AuditDiag -Config $cfg -Level Info -Message 'Install-Audit: tasks registered via Register-AuditTasks.'
} else {
    Write-Host 'Validate-only mode: not registering tasks.' -ForegroundColor Yellow
}

# Preflight validation (unless skipped).
if (-not $SkipValidation) {
    $results = Invoke-AuditPreflight -Config $cfg -SrcDir $SrcDir
    Write-AuditPreflightReport -Results $results
    $failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
    Write-AuditDiag -Config $cfg -Level Info -Message ("Install-Audit preflight: {0} checks, {1} FAIL." -f $results.Count, $failCount)
} else {
    Write-Host 'Skip-validation mode: preflight not run.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Next: sign in as the shared account (or Win+L then unlock) to confirm the prompt appears.'
Write-Host 'If it does not, inspect C:\ProgramData\SharedAccountAuth\diag\audit-diag.log on this PC.'
Write-AuditDiag -Config $cfg -Level Info -Message 'Install-Audit completed.'
