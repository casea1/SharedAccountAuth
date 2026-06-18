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

$LogonTaskName  = 'SharedAccountAuth-Logon'
$UnlockTaskName = 'SharedAccountAuth-Unlock'


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


function Get-LocalUserNameSet {
<#
.SYNOPSIS
    Returns a HashSet[string] (lower-cased) of LOCAL user account names.
.DESCRIPTION
    Enumerates local users via the ADSI WinNT provider -- fully offline and
    with no dependency on the Microsoft.PowerShell.LocalAccounts module
    (which is absent on some SKUs). Never throws; returns an empty set on
    failure (the cross-checks then just WARN that they could not verify).
.OUTPUTS
    [System.Collections.Generic.HashSet[string]]
#>
    [CmdletBinding()]
    param()

    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    try {
        $root = [ADSI]("WinNT://" + $env:COMPUTERNAME)
        foreach ($child in $root.Children) {
            try {
                if ($child.SchemaClassName -eq 'User') {
                    [void]$set.Add(([string]$child.Name).ToLowerInvariant())
                }
            } catch {
                # Skip a child we cannot classify; keep going.
            }
        }
    } catch {
        # ADSI unavailable -> empty set (cross-checks degrade to "could not verify").
    }
    # Unary comma prevents the pipeline from enumerating the set's elements.
    return ,$set
}


function Get-AuditLeafName {
<#
.SYNOPSIS
    Returns the leaf account name (after the last backslash), trimmed.
.PARAMETER Name
    MACHINE\user, .\user, DOMAIN\user, or bare user.
.OUTPUTS
    [string]
#>
    [CmdletBinding()]
    param([string] $Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $i = $Name.LastIndexOf('\')
    if ($i -lt 0) { return $Name.Trim() }
    return $Name.Substring($i + 1).Trim()
}


function New-AuditCheckResult {
<#
.SYNOPSIS
    Builds one preflight result row.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Check,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL')] [string] $Status,
        [Parameter(Mandatory = $true)] [string] $Detail
    )
    [pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail }
}


function Invoke-AuditPreflight {
<#
.SYNOPSIS
    Runs the install-time validation checks. Best-effort: NEVER throws and
    NEVER writes to the append-only central log (it only reads/Test-Paths).
.PARAMETER Config
    Resolved config hashtable from Get-AuditConfig.
.OUTPUTS
    [object[]] of @{ Check; Status; Detail } rows.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable] $Config)

    $results = New-Object System.Collections.Generic.List[object]

    # Local users, enumerated once (offline, ADSI).
    $localUsers = Get-LocalUserNameSet

    # 1. SharedAccount present. Get-AuditConfig throws if blank, so by here it
    #    is non-blank, but assert explicitly for a clear report row.
    $shared = [string]$Config.SharedAccount
    if ([string]::IsNullOrWhiteSpace($shared)) {
        $results.Add((New-AuditCheckResult -Check 'Config: SharedAccount' -Status 'FAIL' -Detail 'blank - the prompt self-check would exit and nothing would ever log'))
    } else {
        $results.Add((New-AuditCheckResult -Check 'Config: SharedAccount' -Status 'OK' -Detail $shared))
    }

    # 2. Install files present.
    foreach ($f in @(
            (Join-Path $SrcDir 'SharedAccountAuth.ps1'),
            (Join-Path $SrcDir 'AuditCommon.ps1'),
            (Join-Path $SrcDir 'Launch-SharedAccountAuth.vbs'))) {
        $leaf = Split-Path -Leaf $f
        if (Test-Path -LiteralPath $f) {
            $results.Add((New-AuditCheckResult -Check ("Install file: $leaf") -Status 'OK' -Detail $f))
        } else {
            $results.Add((New-AuditCheckResult -Check ("Install file: $leaf") -Status 'FAIL' -Detail ("missing: $f")))
        }
    }

    # 2b. Execution-policy GPO override. The scripts are UNSIGNED and the
    #     launcher runs them with -ExecutionPolicy Bypass (process scope). A
    #     MachinePolicy/UserPolicy (GPO) execution policy OVERRIDES that token:
    #       AllSigned    -> blocks ALL unsigned scripts (hard FAIL here)
    #       RemoteSigned -> blocks only files carrying "Mark of the Web" (WARN)
    #     MachinePolicy outranks UserPolicy; if neither is set, Bypass governs.
    try {
        $mp = [string](Get-ExecutionPolicy -Scope MachinePolicy)
        $up = [string](Get-ExecutionPolicy -Scope UserPolicy)
        $effPol = ''
        $effScope = ''
        if ($mp -ne 'Undefined') { $effPol = $mp; $effScope = 'MachinePolicy' }
        elseif ($up -ne 'Undefined') { $effPol = $up; $effScope = 'UserPolicy' }

        if ([string]::IsNullOrEmpty($effPol)) {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'OK' -Detail 'no GPO override; launcher Bypass runs the unsigned scripts'))
        } elseif ($effPol -eq 'AllSigned') {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'FAIL' -Detail ("$effScope=AllSigned overrides Bypass - UNSIGNED scripts are BLOCKED; sign them or relax the GPO")))
        } elseif ($effPol -eq 'RemoteSigned') {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'WARN' -Detail ("$effScope=RemoteSigned blocks only Mark-of-the-Web files; Unblock-File the install dir if scripts came via ZIP/USB")))
        } else {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'OK' -Detail ("$effScope=$effPol does not block unsigned scripts")))
        }
    } catch {
        $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'WARN' -Detail ("could not read execution policy: {0}" -f $_.Exception.Message)))
    }

    # 3. SharedAccount local-account existence (only meaningful if local).
    $sharedLeaf = (Get-AuditLeafName -Name $shared).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($sharedLeaf)) {
        if ($localUsers.Count -eq 0) {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'WARN' -Detail 'could not enumerate local accounts to verify'))
        } elseif ($localUsers.Contains($sharedLeaf)) {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'OK' -Detail $sharedLeaf))
        } else {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'WARN' -Detail ("no local account '$sharedLeaf' (fine if it is a domain account)")))
        }
    }

    # 4. Central LogPath reachability (parent dir only). We do NOT probe-write:
    #    the dir is append-only / no-read / no-delete to the shared account, so
    #    a probe file would litter and could not be cleaned. If unreachable,
    #    runtime spools locally -> WARN, not FAIL.
    $logPath = [string]$Config.LogPath
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        $results.Add((New-AuditCheckResult -Check 'Central LogPath' -Status 'FAIL' -Detail 'blank in config'))
    } else {
        $logDir = Split-Path -Parent $logPath
        if (-not [string]::IsNullOrWhiteSpace($logDir) -and (Test-Path -LiteralPath $logDir)) {
            $results.Add((New-AuditCheckResult -Check 'Central LogPath reachable' -Status 'OK' -Detail $logDir))
        } else {
            $results.Add((New-AuditCheckResult -Check 'Central LogPath reachable' -Status 'WARN' -Detail ("$logDir unreachable now - runtime will SPOOL locally until it returns")))
        }
    }

    # 5. Roster load + per-username local-account cross-check.
    try {
        $roster  = Get-AuditRosterEntries -Config $Config
        $entries = @($roster.Entries)
        switch ([string]$roster.Source) {
            'central' { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'OK'   -Detail ("central ({0} entries)" -f $entries.Count))) }
            'cache'   { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'WARN' -Detail ("central unreadable; using local cache ({0} entries)" -f $entries.Count))) }
            default   { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'FAIL' -Detail 'unavailable from central AND cache - Confirm stays disabled')) }
        }

        if ($entries.Count -gt 0) {
            if ($localUsers.Count -eq 0) {
                $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'WARN' -Detail 'could not enumerate local accounts to verify'))
            } else {
                $missing = @()
                foreach ($e in $entries) {
                    $u = (Get-AuditLeafName -Name ([string]$e.Username)).ToLowerInvariant()
                    if (-not [string]::IsNullOrWhiteSpace($u) -and -not $localUsers.Contains($u)) {
                        $missing += [string]$e.Username
                    }
                }
                if ($missing.Count -eq 0) {
                    $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'OK' -Detail 'every roster Username has a local account on this PC'))
                } else {
                    $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'WARN' -Detail ("{0} cannot authenticate here (no local account): {1}" -f $missing.Count, ($missing -join ', '))))
                }
            }
        }
    } catch {
        $results.Add((New-AuditCheckResult -Check 'Roster check' -Status 'WARN' -Detail ("could not evaluate roster: {0}" -f $_.Exception.Message)))
    }

    # 6. Local state root present/writable (Get-AuditConfig creates it).
    $localRoot = [string]$Config.LocalRoot
    if (-not [string]::IsNullOrWhiteSpace($localRoot) -and (Test-Path -LiteralPath $localRoot)) {
        $results.Add((New-AuditCheckResult -Check 'Local state root' -Status 'OK' -Detail $localRoot))
    } else {
        $results.Add((New-AuditCheckResult -Check 'Local state root' -Status 'WARN' -Detail ("not present yet: $localRoot")))
    }

    # 7. Tasks registered + enabled.
    foreach ($tn in @($LogonTaskName, $UnlockTaskName)) {
        $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($null -eq $t) {
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'FAIL' -Detail 'not registered'))
        } elseif ([string]$t.State -eq 'Disabled') {
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'WARN' -Detail 'registered but DISABLED'))
        } else {
            $uid = ''
            try { $uid = [string]$t.Principal.UserId } catch { }
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'OK' -Detail ("state=$($t.State), UserId=$uid")))
        }
    }

    return $results.ToArray()
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
    $results = Invoke-AuditPreflight -Config $cfg
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
