<#
=======================================================================
 Shared-Auth-Update.ps1 - one-command in-place UPGRADE of an existing
 Shared-Account Sign-On Audit Logger install.
 PS 5.1 / built-ins only; fully offline. Self-elevates.

 Run the copy that ships INSIDE the new version's tree:
     <new-version>\deploy\Shared-Auth-Update.ps1
 It treats its own tree as the SOURCE and the installed copy as the
 TARGET, then:
   1. backs up the site config to ProgramData\...\config-backups\
   2. clean-replaces the program folder (old tree deleted, new copied in)
   3. restores the site config over the shipped template
   4. Unblock-Files the tree (clears Mark-of-the-Web)
   5. re-registers both scheduled tasks (idempotent)
   6. re-applies the local-state ACL (insurance; only needs SharedAccount)
   7. runs the preflight and reports.

 NEVER touches: C:\ProgramData\SharedAccountAuth\ local state
 (spool/cache/diag), the central log + roster share and its server-side
 ACL, or the log-folder ACL (it persists across a code refresh, and the
 auditors group is not stored in config). Use Shared-Auth-Setup.ps1 to
 change any of those.

 Flags:
   -InstallDir <path>  target install (default C:\Program Files\SharedAccountAuth)
   -Configure          after replacing files, open Shared-Auth-Setup.ps1
                       so you can change settings (it does 5-7 via Install)
   -WhatIf             preview every step without changing anything

 Scripts are unsigned (launched via Bypass).
=======================================================================
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $InstallDir = 'C:\Program Files\SharedAccountAuth',
    [switch] $Configure
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Pure helpers - DEFINED ON DOT-SOURCE (above the startup guard) so the
# test suite can exercise the safety guards without running MAIN.
# ---------------------------------------------------------------------
function Test-IsElevated {
<#
.SYNOPSIS Returns $true if the current process is elevated (admin). Offline-safe.
#>
    [CmdletBinding()] param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-AuditIsInstallDir {
<#
.SYNOPSIS $true if $Path looks like a real, configured install (has the site
          config AND the prompt script). Guards the destructive delete.
#>
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $cfg    = Join-Path $Path 'config\AuditConfig.psd1'
    $prompt = Join-Path $Path 'src\SharedAccountAuth.ps1'
    return ((Test-Path -LiteralPath $cfg) -and (Test-Path -LiteralPath $prompt))
}

function Test-AuditIsSourceTree {
<#
.SYNOPSIS $true if $Path looks like a valid new-version SOURCE tree (has the
          prompt AND the task-register engine). Guards against deploying junk.
#>
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $prompt   = Join-Path $Path 'src\SharedAccountAuth.ps1'
    $register = Join-Path $Path 'deploy\Register-AuditTasks.ps1'
    return ((Test-Path -LiteralPath $prompt) -and (Test-Path -LiteralPath $register))
}

function Get-AuditPathRelation {
<#
.SYNOPSIS Classify how SOURCE and DEST relate: 'same', 'nested' (one contains
          the other), or 'ok'. Case-insensitive, trailing-separator safe.
          Refusing 'same'/'nested' stops the delete from eating the source.
.OUTPUTS [string] 'same' | 'nested' | 'ok'
#>
    [CmdletBinding()] param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Dest
    )
    $s = ([System.IO.Path]::GetFullPath($Source)).TrimEnd('\')
    $d = ([System.IO.Path]::GetFullPath($Dest)).TrimEnd('\')
    if ($s -ieq $d) { return 'same' }
    $cmp = [System.StringComparison]::OrdinalIgnoreCase
    if ($d.StartsWith($s + '\', $cmp)) { return 'nested' }   # dest inside source
    if ($s.StartsWith($d + '\', $cmp)) { return 'nested' }   # source inside dest
    return 'ok'
}

# Step reporter + running FAIL/WARN tally (script scope so the helper updates it).
$script:UpdFail = 0
$script:UpdWarn = 0
function Write-Step {
    [CmdletBinding()] param(
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string] $Status,
        [Parameter(Mandatory = $true)][string] $Message
    )
    switch ($Status) {
        'OK'   { $c = 'Green' }
        'WARN' { $c = 'Yellow'; $script:UpdWarn++ }
        'FAIL' { $c = 'Red';    $script:UpdFail++ }
        default { $c = 'Gray' }
    }
    Write-Host ("  [{0,-4}] {1}" -f $Status, $Message) -ForegroundColor $c
}

# =====================================================================
# STARTUP GUARD: when DOT-SOURCED (InvocationName -eq '.'), define the
# helpers above and run NOTHING below. When invoked normally, run MAIN.
# =====================================================================
if ($MyInvocation.InvocationName -ne '.') {

    $DeployDir  = $PSScriptRoot
    $SourceRoot = Split-Path -Parent $DeployDir

    # 1. Self-elevate (delete/copy under Program Files + task register need admin).
    #    Relaunch with -NoExit so the elevated window stays up to read the report.
    if (-not (Test-IsElevated)) {
        $inner = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallDir `"$InstallDir`""
        if ($Configure)        { $inner += ' -Configure' }
        if ($WhatIfPreference) { $inner += ' -WhatIf' }
        try {
            Start-Process -FilePath 'powershell.exe' -ArgumentList $inner -Verb RunAs | Out-Null
            Write-Host 'Re-launching elevated (accept the UAC prompt); this window can be closed.'
        } catch {
            Write-Warning ("Self-elevation failed: {0}. Re-run from an elevated prompt." -f $_.Exception.Message)
        }
        return
    }

    Write-Host ''
    Write-Host '=== Shared-Account Audit - in-place update ===' -ForegroundColor Cyan

    # ---- Resolve + validate SOURCE and TARGET before touching anything. ----
    $SrcFull  = [System.IO.Path]::GetFullPath($SourceRoot)
    $DestFull = [System.IO.Path]::GetFullPath($InstallDir)
    Write-Host ("  Source : {0}" -f $SrcFull)
    Write-Host ("  Target : {0}" -f $DestFull)
    Write-Host ''

    if (-not (Test-AuditIsSourceTree $SrcFull)) {
        Write-Step FAIL ("This script's tree is not a valid source (missing src\SharedAccountAuth.ps1 or deploy\Register-AuditTasks.ps1): {0}" -f $SrcFull)
        exit 1
    }
    if (-not (Test-Path -LiteralPath $DestFull)) {
        Write-Step FAIL ("No install found at {0}. For a FIRST install, run deploy\Shared-Auth-Setup.ps1 instead." -f $DestFull)
        exit 1
    }
    if (-not (Test-AuditIsInstallDir $DestFull)) {
        Write-Step FAIL ("{0} is not a valid install (missing config\AuditConfig.psd1 or src\SharedAccountAuth.ps1). Refusing to delete it." -f $DestFull)
        exit 1
    }
    $relation = Get-AuditPathRelation -Source $SrcFull -Dest $DestFull
    if ($relation -eq 'same') {
        Write-Step FAIL 'Source and target are the same folder - nothing to update. Run this from the NEW version tree.'
        exit 1
    }
    if ($relation -eq 'nested') {
        Write-Step FAIL 'Source and target overlap (one contains the other). Stage the new version in a separate folder and re-run.'
        exit 1
    }

    $destConfig   = Join-Path $DestFull 'config\AuditConfig.psd1'
    $destSrc      = Join-Path $DestFull 'src'
    $destCommon   = Join-Path $destSrc  'AuditCommon.ps1'
    $destInstall  = Join-Path $DestFull 'deploy\AuditInstallCommon.ps1'
    $destRegister = Join-Path $DestFull 'deploy\Register-AuditTasks.ps1'
    $destSetup    = Join-Path $DestFull 'deploy\Shared-Auth-Setup.ps1'

    # ---- Step 1: back up the site config (in-memory + a timestamped file). ----
    # Read the bytes NOW so the config survives the delete even if the file
    # backup fails. The stamp is UTC; no Get-Date format that could localize badly.
    $configBytes = [System.IO.File]::ReadAllBytes($destConfig)
    $backupDir   = 'C:\ProgramData\SharedAccountAuth\config-backups'
    $stamp       = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
    $backupPath  = Join-Path $backupDir ("AuditConfig-{0}.psd1" -f $stamp)
    if ($PSCmdlet.ShouldProcess($destConfig, ("Back up to {0}" -f $backupPath))) {
        try {
            if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Force -Path $backupDir | Out-Null }
            Copy-Item -LiteralPath $destConfig -Destination $backupPath -Force
            Write-Step OK ("Config backed up: {0}" -f $backupPath)
        } catch {
            Write-Step WARN ("Config file-backup failed ({0}); continuing with the in-memory copy." -f $_.Exception.Message)
        }
    }

    # ---- Step 2: clean-replace the program folder. ----
    # Delete the whole target tree (so renamed/removed files do not linger),
    # then copy the source tree in, excluding VCS/scratch dirs.
    $exclude = @('.git', '.superpowers')
    if ($PSCmdlet.ShouldProcess($DestFull, 'Replace program files (delete old tree, copy new version)')) {
        try {
            Remove-Item -LiteralPath $DestFull -Recurse -Force
            New-Item -ItemType Directory -Force -Path $DestFull | Out-Null
            Get-ChildItem -LiteralPath $SrcFull -Force |
                Where-Object { $exclude -notcontains $_.Name } |
                ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $DestFull -Recurse -Force }
            Write-Step OK 'Program files replaced with the new version.'
        } catch {
            Write-Step FAIL ("File replace failed ({0}). If files are in use, close the shared-account session/prompt and re-run." -f $_.Exception.Message)
            exit 1
        }
    }

    # ---- Step 3: restore the site config over the shipped template. ----
    if ($PSCmdlet.ShouldProcess($destConfig, 'Restore site config over the shipped template')) {
        try {
            $destConfigDir = Split-Path -Parent $destConfig
            if (-not (Test-Path -LiteralPath $destConfigDir)) { New-Item -ItemType Directory -Force -Path $destConfigDir | Out-Null }
            [System.IO.File]::WriteAllBytes($destConfig, $configBytes)
            Write-Step OK 'Site config restored (your settings preserved).'
        } catch {
            Write-Step FAIL ("Could not restore the site config ({0}). Restore it manually from {1}." -f $_.Exception.Message, $backupPath)
            exit 1
        }
    }

    # ---- Step 4: clear Mark-of-the-Web across the tree. ----
    if ($PSCmdlet.ShouldProcess($DestFull, 'Unblock files (clear Mark-of-the-Web)')) {
        try {
            Get-ChildItem -LiteralPath $DestFull -Recurse -Force | Unblock-File -ErrorAction SilentlyContinue
            Write-Step OK 'Files unblocked.'
        } catch {
            Write-Step WARN ("Unblock-File pass hit an issue ({0}); GPO exec-policy may still allow the scripts." -f $_.Exception.Message)
        }
    }

    # ---- -WhatIf short-circuit: nothing was actually copied, so do not run
    #      the config-driven steps against a half-old tree; describe them. ----
    if ($WhatIfPreference) {
        Write-Step INFO 'Would re-register both scheduled tasks, re-apply the local-state ACL, and run the preflight.'
        Write-Host ''
        Write-Host 'What-if complete: no changes were made.' -ForegroundColor Cyan
        return
    }

    # ---- -Configure: hand off to the GUI for a settings review + Install. ----
    if ($Configure) {
        Write-Step INFO 'Opening Shared-Auth-Setup.ps1 to review/change settings (its Install does the rest)...'
        try { & $destSetup -ConfigPath $destConfig }
        catch { Write-Step WARN ("Could not launch the setup GUI ({0}). Run {1} manually." -f $_.Exception.Message, $destSetup) }
        Write-Host ''
        Write-Host 'Update: files replaced; finish configuration in the setup window.' -ForegroundColor Cyan
        return
    }

    # ---- Load the NEW libraries from the target (validates the copy loads). ----
    try {
        . $destCommon
        . $destInstall
    } catch {
        Write-Step FAIL ("The new libraries failed to load ({0}). The copy may be corrupt - re-run the update." -f $_.Exception.Message)
        exit 1
    }

    # ---- Step 5: re-register both scheduled tasks (idempotent -Force). ----
    if ($PSCmdlet.ShouldProcess('scheduled tasks', 'Re-register SharedAccountAuth-Logon + -Unlock')) {
        try {
            & $destRegister -ConfigPath $destConfig
            Write-Step OK 'Scheduled tasks re-registered.'
        } catch {
            Write-Step FAIL ("Task re-registration failed ({0}). Run deploy\Register-AuditTasks.ps1 elevated." -f $_.Exception.Message)
        }
    }

    # ---- Load config once for the ACL + preflight steps. ----
    $cfg = $null
    try {
        $cfg = Get-AuditConfig -ConfigPath $destConfig
    } catch {
        Write-Step WARN ("Could not load config for the ACL/preflight steps ({0}). Check SharedAccount in {1}." -f $_.Exception.Message, $destConfig)
    }

    # ---- Step 6: re-apply the local-state ACL (insurance; needs SharedAccount only). ----
    if ($null -ne $cfg -and $PSCmdlet.ShouldProcess('local-state ACL', 'Re-grant the shared account Modify on the ProgramData state dir')) {
        try {
            Set-AuditLocalStateAcl -Config $cfg
            Write-Step OK 'Local-state ACL re-applied.'
        } catch {
            Write-Step WARN ("Local-state ACL step hit an issue ({0}); diagnostics may not be writable by the shared account." -f $_.Exception.Message)
        }
    }

    # ---- Step 7: preflight. Read-only; reports OK/WARN/FAIL per check. ----
    if ($null -ne $cfg) {
        try {
            $results = Invoke-AuditPreflight -Config $cfg -SrcDir $destSrc
            Write-Host ''
            Write-Host '--- Preflight ---'
            foreach ($r in @($results)) {
                Write-Step ([string]$r.Status) ("{0}: {1}" -f $r.Check, $r.Detail)
            }
        } catch {
            Write-Step WARN ("Preflight did not complete ({0})." -f $_.Exception.Message)
        }
    }

    # ---- Summary. ----
    Write-Host ''
    if ($script:UpdFail -gt 0) {
        Write-Host ("Update finished with {0} FAIL, {1} WARN. Config backup: {2}" -f $script:UpdFail, $script:UpdWarn, $backupPath) -ForegroundColor Red
        exit 1
    } else {
        Write-Host ("Update complete ({0} WARN). Config backup: {1}" -f $script:UpdWarn, $backupPath) -ForegroundColor Green
        Write-Host 'Sign out and back in as the shared account to confirm the new prompt.'
        exit 0
    }
}   # end startup guard
