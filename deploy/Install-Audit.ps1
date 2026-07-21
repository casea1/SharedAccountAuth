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


function Set-AuditLocalStateAcl {
<#
.SYNOPSIS
    Grant the shared account Modify on the local state root (LocalRoot) so the
    prompt (which runs as that account) can write ALL of its state files.
.DESCRIPTION
    The prompt writes to C:\ProgramData\SharedAccountAuth\ (cache, diag, spool,
    state). Because this installer creates those dirs while ELEVATED, a standard
    shared user can otherwise only create NEW files there (spool) but cannot
    update EXISTING ones (the diag log and the roster cache) — which silently
    breaks diagnostics and the roster cache fallback. This grants the shared
    account Modify (inherited to subfolders + files, applied to existing
    children) so its whole state tree is writable. NEVER throws (a failure here
    must not abort the install); logs a warning instead.
.PARAMETER Config
    Resolved config hashtable (LocalRoot, SharedAccount).
.PARAMETER SharedAccountOverride
    Optional explicit shared account (else uses config SharedAccount).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable] $Config,
        [string] $SharedAccountOverride
    )
    try {
        $localRoot = [string]$Config.LocalRoot
        if ([string]::IsNullOrWhiteSpace($localRoot)) { return }
        if (-not (Test-Path -LiteralPath $localRoot)) {
            New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
        }

        # Resolve the shared account to a grantable identity (MACHINE\name for a
        # local account; keep MACHINE\ or DOMAIN\ prefixes as supplied).
        $acct = if (-not [string]::IsNullOrWhiteSpace($SharedAccountOverride)) { $SharedAccountOverride } else { [string]$Config.SharedAccount }
        $leaf = Get-AuditLeafName -Name $acct
        if ([string]::IsNullOrWhiteSpace($leaf)) { return }
        $bs = $acct.IndexOf('\')
        if ($bs -ge 0 -and $acct.Substring(0, $bs) -ne '.' -and -not [string]::IsNullOrWhiteSpace($acct.Substring(0, $bs))) {
            $grantee = $acct
        } else {
            $grantee = '{0}\{1}' -f $env:COMPUTERNAME, $leaf
        }

        # icacls: grant Modify, (OI)(CI) inherit to files+subfolders, /T to apply
        # to existing children, /C to continue past any per-file error.
        $icaclsOut = & icacls "$localRoot" /grant ("{0}:(OI)(CI)M" -f $grantee) /T /C 2>&1
        if ($LASTEXITCODE -ne 0) { throw ("icacls returned {0}: {1}" -f $LASTEXITCODE, ($icaclsOut -join '; ')) }

        Write-Host ("Granted '{0}' write access to local state: {1}" -f $grantee, $localRoot) -ForegroundColor Cyan
        Write-AuditDiag -Config $Config -Level Info -Message ("Install-Audit: granted {0} Modify on {1}" -f $grantee, $localRoot)
    } catch {
        Write-Warning ("Could not set local-state ACL (non-fatal): {0}" -f $_.Exception.Message)
        try { Write-AuditDiag -Config $Config -Level Warn -Message ("Install-Audit: could not set local-state ACL: {0}" -f $_.Exception.Message) } catch { }
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

    # Grant the shared account write access to its own local state tree so the
    # prompt (running as that account) can update the diag log + roster cache,
    # not just create spool files. Without this, diagnostics go silently blind.
    Set-AuditLocalStateAcl -Config $cfg -SharedAccountOverride $SharedAccount
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
