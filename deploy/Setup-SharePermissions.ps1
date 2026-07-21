<#
=======================================================================
 Setup-SharePermissions.ps1 - admin-once NTFS ACL hardening for the
 central audit log directory.
 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules.
 Fully offline. Run ONCE, ELEVATED, on the file server that hosts the
 share (operate on the local NTFS path, e.g. D:\audit - not the UNC).

 ---------------------------------------------------------------------
 WHAT THIS SCRIPT GUARANTEES (spec section 12)
 ---------------------------------------------------------------------
 The shared local account / group can:
   * CREATE the central log file (access_log.csv) in this folder, and
   * APPEND rows to it,
 but can NEVER:
   * READ the log back (no listing of contents, no header check, no
     dedup against it), nor
   * DELETE or truncate it (no overwrite of existing rows).
 The Auditors group gets Read (+Execute) inherited to files.
 The Admin / service principal gets FullControl.

 ---------------------------------------------------------------------
 WHY APPEND-ONLY DICTATES THE ENTIRE WRITE/DEDUP ALGORITHM
 ---------------------------------------------------------------------
 Because the shared account is *denied* ReadData on the log, NOTHING in
 the runtime logic may ever read the central CSV. That single ACL fact
 forces every design choice in src\AuditCommon.ps1:

   * Header is written ONLY inside the FileMode.CreateNew "create-race"
     winner - we cannot open the file and look for a header line,
     because opening it for read is denied. Exactly one machine wins the
     create race and writes the header; everyone else opens in Append
     mode and writes a data line only. The header is therefore never
     duplicated and never read.
   * Appends use FILE_APPEND_DATA semantics (FileMode.Append +
     FileAccess.Write) - never WriteData - so a writer can only add to
     the end and can never seek back to overwrite a prior row. This is
     mirrored in the ACL: we grant AppendData but explicitly do NOT
     grant WriteData on files.
   * The spool flush (Invoke-AuditSpoolFlush) is at-least-once and does
     NO dedup against the central log, because it cannot read the
     central log to know what is already there. Rare duplicates are
     accepted and are visible to the Auditors (who CAN read it).
   * Cross-machine write safety relies on open-mode (FileShare.Read) +
     retry/backoff, not on reading the file's state.

 In short: "deny ReadData on the shared account" is the load-bearing
 security control; the append-only, never-read-the-log algorithm is the
 direct consequence, not an arbitrary stylistic choice. If this ACL were
 relaxed to allow reads, a malicious shared-session user could exfiltrate
 every other user's access history, or tamper with prior rows - exactly
 what this design exists to prevent.

 ---------------------------------------------------------------------
 NTFS RIGHTS PRIMER (the bits we use, and their dual dir/file meaning)
 ---------------------------------------------------------------------
 A single NTFS access mask bit has TWO names depending on whether the
 object is a directory or a file:

   bit     FileSystemRights name   on a DIRECTORY        on a FILE
   ----    ---------------------    -----------------     ----------------
   0x0001  ReadData                 ListDirectory         ReadData (read bytes)
   0x0002  CreateFiles              CreateFiles(AddFile)  WriteData (overwrite)
   0x0004  AppendData               AppendDir(AddSubdir)  AppendData (append)
   0x0008  ReadExtendedAttributes   ReadEA                ReadEA
   0x0010  WriteExtendedAttributes  WriteEA               WriteEA
   0x0020  ExecuteFile              Traverse              ExecuteFile
   0x0040  DeleteSubdirectoriesAndFiles (dirs only)
   0x0080  ReadAttributes           ReadAttributes        ReadAttributes
   0x0100  WriteAttributes          WriteAttributes       WriteAttributes
   0x10000 Delete                   Delete                Delete
   0x20000 ReadPermissions          ReadControl           ReadControl
   0x100000 Synchronize             Synchronize           Synchronize

 KEY INSIGHT used below: on a directory, CreateFiles (0x2) lets the
 account create a new file (access_log.csv); but the SAME 0x2 bit is
 WriteData on a FILE, which would permit overwriting existing rows.
 So we grant CreateFiles on the DIRECTORY (this-folder-only, no file
 inheritance) and we DO NOT let it inherit to files - files get only
 AppendData. This is the crux of "create yes, overwrite no".

 ---------------------------------------------------------------------
 Config block (mirrors config\AuditConfig.psd1 - single source of
 truth). This deploy script targets the local NTFS folder that BACKS
 the UNC LogPath; only LogPath is conceptually related:
 ---------------------------------------------------------------------
   LogPath  \\server\share\audit\access_log.csv   (the file that lives
            in -LogDir; this script secures its parent directory)
 The other AuditConfig keys (RosterPath, LocalRoot, tunables, etc.) are
 not used here - ACLs are a server-side, one-time concern. Pass the
 LOCAL directory that backs that UNC path via -LogDir.

 ---------------------------------------------------------------------
 USAGE
 ---------------------------------------------------------------------
   # Preview only (no changes made):
   .\Setup-SharePermissions.ps1 -LogDir 'D:\audit' `
       -SharedPrincipal 'DOMAIN\LabShared' `
       -AuditorsPrincipal 'DOMAIN\Auditors' -WhatIf

   # Apply for real (elevated console required):
   .\Setup-SharePermissions.ps1 -LogDir 'D:\audit' `
       -SharedPrincipal 'DOMAIN\LabShared' `
       -AuditorsPrincipal 'DOMAIN\Auditors'
=======================================================================
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Local NTFS directory that holds (or will hold) access_log.csv.
    # Use the LOCAL path on the file server (e.g. D:\audit), NOT the UNC -
    # NTFS ACLs are set on the local volume; the SMB share ACL is separate.
    [Parameter(Mandatory = $true)]
    [string] $LogDir,

    # The shared account or group that runs the prompt on the workstations.
    # Format: 'DOMAIN\Shared', '.\LocalGroup', or 'MACHINE\User'.
    # This principal gets APPEND+CREATE but is DENIED read/delete.
    [Parameter(Mandatory = $true)]
    [string] $SharedPrincipal,

    # The group whose members read/audit the log (read-only).
    [Parameter(Mandatory = $true)]
    [string] $AuditorsPrincipal,

    # Admin / service principal that gets FullControl. Defaults to the
    # local Administrators group. Pass a service account if preferred.
    [Parameter(Mandatory = $false)]
    [string] $AdminPrincipal = 'BUILTIN\Administrators',

    # OPTIONAL, WORKSTATION-SIDE: the local state root the prompt writes to
    # (cache/diag/spool/state), normally C:\ProgramData\SharedAccountAuth.
    # When supplied, grant the SharedPrincipal MODIFY on it so the shared
    # account can update its own diag log + roster cache (not just create spool
    # files). Leave blank to skip. NOTE: this is a per-WORKSTATION grant (run it
    # on the workstation) - separate from the central append-only log ACL above.
    # deploy\Shared-Auth-Setup.ps1 does this automatically per-PC; this is the manual
    # equivalent for when you only run Setup-SharePermissions.
    [Parameter(Mandatory = $false)]
    [string] $LocalStateDir = ''
)

# Tighten errors so a failed ACL step never "half applies" silently.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ACE builders (New-SharedDirCreateAce, New-SharedFileAppendAce, New-SharedDenyAce,
# New-AuditorsReadAce, New-AdminFullControlAce) now live in the shared install lib.
. (Join-Path $PSScriptRoot 'AuditInstallCommon.ps1')

# =====================================================================
#  icacls QUICK-REFERENCE (documented alternative; NOT executed here)
# =====================================================================
#  The Set-Acl path below is AUTHORITATIVE. The following icacls commands
#  produce an equivalent result and are handy for spot-checks / one-liners.
#  (We only INVOKE icacls read-only at the end to print the resulting ACL.)
#
#  icacls letter meanings (simple rights):
#    WD = WriteData / AddFile        (0x2 on a file = overwrite; on a dir = create file)
#    AD = AppendData / AddSubdir     (0x4: append to a file; add subdir to a dir)
#    RD = ReadData / ListDirectory   (0x1: read file bytes; list a dir)
#    S  = Synchronize                (0x100000: required for normal synchronous I/O)
#    RA = ReadAttributes             (0x80: read size/timestamps - NOT content)
#    WA = WriteAttributes            (0x100: update attrs the OS touches on write)
#    X  = ExecuteFile / Traverse     (0x20: pass through a dir to a named child)
#    D  = Delete                     (0x10000: delete THIS object)
#    DC = DeleteSubdirectoriesAndFiles (0x40: delete children, dir-only)
#    RX = ReadAndExecute (RD + X + RA + ReadEA + ReadControl + S)
#
#  icacls inheritance/propagation flags:
#    (CI) = ContainerInherit  - ACE inherits to SUBDIRECTORIES
#    (OI) = ObjectInherit     - ACE inherits to FILES
#    (IO) = InheritOnly       - ACE applies to children ONLY, not this object
#    (NP) = NoPropagate       - inherit to immediate children only (do not cascade)
#  Absence of (CI)/(OI) on a grant => "this folder only" (no inheritance).
#
#  Equivalent commands (run elevated on the server; substitute path/principals):
#
#    :: 1) Shared: create the file + traverse, THIS FOLDER ONLY (no inherit flags).
#    ::    On a DIRECTORY, the WD letter = AddFile = "create access_log.csv".
#    ::    AD (=AddSubdirectory) is intentionally omitted so the account cannot
#    ::    create subfolders. No (CI)/(OI) => does not reach files, so WD can
#    ::    never land on a file as WriteData (=overwrite).
#    icacls "D:\audit" /grant:r "DOMAIN\Shared:(WD,S,RA,X)"
#
#    :: 2) Shared: append rows on FILES ONLY (OI)(IO) = object-inherit, inherit-only,
#    ::    so the directory itself is unaffected and only files get AppendData.
#    ::    Note: NO WD here - files must never be overwritable; WA only touches attrs.
#    icacls "D:\audit" /grant:r "DOMAIN\Shared:(OI)(IO)(AD,S,RA,WA)"
#
#    :: 3) Shared: DENY read of contents + delete. (OI) deny so files can't be read;
#    ::    a non-inherited deny so this folder's own listing (RD=ListDirectory) is
#    ::    denied too. DC denies delete-of-children via the parent's right.
#    icacls "D:\audit" /deny "DOMAIN\Shared:(OI)(RD)"
#    icacls "D:\audit" /deny "DOMAIN\Shared:(RD)"
#    icacls "D:\audit" /deny "DOMAIN\Shared:(D,DC)"
#
#    :: 4) Auditors: read+execute, inherited to subfolders AND files.
#    icacls "D:\audit" /grant:r "DOMAIN\Auditors:(CI)(OI)(RX)"
#
#    :: 5) Admin/service: full control, inherited to subfolders AND files.
#    icacls "D:\audit" /grant:r "BUILTIN\Administrators:(CI)(OI)(F)"
#
#    :: Also remove inheritance from the parent so a broad "Users:Read" can't
#    :: leak a read of the log to the shared account, then verify:
#    icacls "D:\audit" /inheritance:r
#    icacls "D:\audit"
# =====================================================================


function Test-IsElevated {
<#
.SYNOPSIS
    Returns $true if the current process is running elevated (admin).
.DESCRIPTION
    Setting NTFS ACLs (especially on a server volume) requires
    administrative rights / ownership. Offline-safe: uses only the
    built-in WindowsPrincipal check, no network or module dependency.
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param()
    try {
        $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $wp  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}


# =====================================================================
#  MAIN
# =====================================================================

if (-not (Test-IsElevated)) {
    Write-Warning 'This script must be run ELEVATED (Run as administrator).'
    throw 'Not elevated - aborting before touching any ACLs.'
}

Write-Host ''
Write-Host '=== Audit log ACL hardening (append-only) ==='
Write-Host ("  Directory : {0}" -f $LogDir)
Write-Host ("  Shared    : {0}   (create + append; DENY read/delete)" -f $SharedPrincipal)
Write-Host ("  Auditors  : {0}   (read-only)" -f $AuditorsPrincipal)
Write-Host ("  Admin     : {0}   (full control)" -f $AdminPrincipal)

$applied = Set-AuditLogAcl -LogDir $LogDir -SharedPrincipal $SharedPrincipal `
                           -AuditorsPrincipal $AuditorsPrincipal -AdminPrincipal $AdminPrincipal
if ($applied) { Write-Host 'ACL applied.' } else { Write-Host 'ACL not applied (WhatIf or failure - see warnings).' }

# Verification: print the resulting ACL.
if (Test-Path -LiteralPath $LogDir) {
    Write-Host ''
    Write-Host '=== Resulting ACL (verification) ==='
    & icacls "$LogDir" | Out-Host
}

# =====================================================================
#  OPTIONAL: local state dir (workstation ProgramData) - grant the shared
#  account MODIFY so the prompt can update its own cache/diag/spool/state.
#  Unlike the append-only central log, the shared account needs full write
#  here (it owns this state). Per-workstation; skipped unless -LocalStateDir.
# =====================================================================
if (-not [string]::IsNullOrWhiteSpace($LocalStateDir)) {
    Write-Host ''
    Write-Host '=== Local state ACL (shared account write access) ==='
    if ($PSCmdlet.ShouldProcess($LocalStateDir, ("Grant '{0}' Modify on the local state dir" -f $SharedPrincipal))) {
        if (-not (Test-Path -LiteralPath $LocalStateDir)) {
            New-Item -ItemType Directory -Path $LocalStateDir -Force | Out-Null
            Write-Host "Created local state dir: $LocalStateDir"
        }
        # icacls: Modify, (OI)(CI) inherit to files+subfolders, /T existing children, /C continue.
        $localOut = & icacls "$LocalStateDir" /grant ("{0}:(OI)(CI)M" -f $SharedPrincipal) /T /C 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning ("icacls returned {0} granting local-state access: {1}" -f $LASTEXITCODE, ($localOut -join '; '))
        } else {
            Write-Host ("Granted '{0}' Modify on local state dir: {1}" -f $SharedPrincipal, $LocalStateDir)
        }
    } else {
        Write-Host ("[WhatIf] Would grant '{0}' Modify on local state dir: {1}" -f $SharedPrincipal, $LocalStateDir)
    }
}

Write-Host ''
Write-Host 'Done. Reminder: the shared account can CREATE + APPEND but can NEVER READ or DELETE the log.'
Write-Host 'This is why the runtime logic must never read the central CSV (no header check, no dedup).'
