<#
=======================================================================
 AuditCommon.ps1 — shared library for the Sign-On Audit Logger
 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules.
 Fully offline. Append-only to the central CSV (it is NEVER read by the
 shared account — no header check, no dedup against it, ever).

 This file is dot-sourced by SharedAccountAuth.ps1 and the deploy scripts.

 SECURITY: personal passwords are SecureString from the WPF PasswordBox.
 They are converted to plaintext ONLY inside Test-AuditCredential, at the
 P/Invoke boundary, and zeroed immediately (Marshal::ZeroFreeBSTR in a
 finally). A password is NEVER written to the diag log, the CSV, a spool
 file, or any variable that outlives the Test-AuditCredential call.

 ---------------------------------------------------------------------
 Config block (mirrors config\AuditConfig.psd1 — the single source of
 truth). Keys, with derived-path rules filled by Get-AuditConfig:
 ---------------------------------------------------------------------
   LogPath          \\server\share\audit\access_log.csv  (append-only)
   RosterPath       \\server\share\audit\roster.csv      (read-only)
   LocalRoot        C:\ProgramData\SharedAccountAuth
   RosterCachePath  '' -> $LocalRoot\cache\roster.csv
   SpoolDir         '' -> $LocalRoot\spool
   DiagLogPath      '' -> $LocalRoot\diag\audit-diag.log
   StateDir         '' -> $LocalRoot\state
   SharedAccount    REQUIRED — MACHINE\name | .\name | name
   AuthDomain       '.'  (LogonUser domain; '.' = local SAM)
   RetryDelayMs     1000 (delay after a failed attempt)
   DebounceSeconds  5
   WriteRetryCount  10
   WriteRetryBaseMs 50
   AppName / WindowTitle / WindowSubtitle  (UI text)
=======================================================================
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------
# Module-private helper: a single BOM-less UTF-8 encoder reused for all
# central-CSV writes. A BOM written mid-file by a concurrent append would
# corrupt rows, so we MUST use UTF8Encoding($false) everywhere.
# ---------------------------------------------------------------------
$script:AuditUtf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ---------------------------------------------------------------------
# Canonical CSV header. EXACT column order (spec §8) — used by the
# create-header-race winner only. Never read back from the central log.
# ---------------------------------------------------------------------
$script:AuditHeaderLine = 'TimestampUTC,TimestampLocal,Username,LastName,FirstName,ComputerName,EventType,AuthResult'


function Get-AuditConfig {
<#
.SYNOPSIS
    Loads config\AuditConfig.psd1, fills derived paths, ensures the local
    directory tree (cache/spool/diag/state) exists, and validates that the
    required SharedAccount key is present.
.DESCRIPTION
    Reads the data file with Import-PowerShellDataFile. Any blank derived
    path (RosterCachePath/SpoolDir/DiagLogPath/StateDir) is filled from
    LocalRoot. The local directories are created if missing. The central
    share is NOT touched here. SharedAccount is REQUIRED — a missing/blank
    value throws (the prompt's self-check depends on it).
.PARAMETER ConfigPath
    Path to the psd1. Defaults to config\AuditConfig.psd1 resolved relative
    to this script's location (..\config\AuditConfig.psd1 from src\).
.OUTPUTS
    [hashtable] the fully-resolved configuration.
#>
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        # $PSScriptRoot is src\ ; the config lives in ..\config\
        $ConfigPath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'config\AuditConfig.psd1'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Audit config not found: $ConfigPath"
    }

    $cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath

    # Establish LocalRoot before deriving the rest.
    if ([string]::IsNullOrWhiteSpace($cfg.LocalRoot)) {
        $cfg.LocalRoot = 'C:\ProgramData\SharedAccountAuth'
    }

    # Fill blank derived paths from LocalRoot.
    if ([string]::IsNullOrWhiteSpace($cfg.RosterCachePath)) {
        $cfg.RosterCachePath = Join-Path $cfg.LocalRoot 'cache\roster.csv'
    }
    if ([string]::IsNullOrWhiteSpace($cfg.SpoolDir)) {
        $cfg.SpoolDir = Join-Path $cfg.LocalRoot 'spool'
    }
    if ([string]::IsNullOrWhiteSpace($cfg.DiagLogPath)) {
        $cfg.DiagLogPath = Join-Path $cfg.LocalRoot 'diag\audit-diag.log'
    }
    if ([string]::IsNullOrWhiteSpace($cfg.StateDir)) {
        $cfg.StateDir = Join-Path $cfg.LocalRoot 'state'
    }

    # Default authentication tunables if absent (local SAM, 1s delay).
    if (-not $cfg.ContainsKey('AuthDomain') -or [string]::IsNullOrWhiteSpace($cfg.AuthDomain)) {
        $cfg.AuthDomain = '.'
    }
    if (-not $cfg.ContainsKey('RetryDelayMs')) {
        $cfg.RetryDelayMs = 1000
    }

    # Ensure local dirs exist (best-effort; these are local, so creation
    # should succeed for the shared user under ProgramData).
    $dirsToEnsure = @(
        (Split-Path -Parent $cfg.RosterCachePath),
        $cfg.SpoolDir,
        (Split-Path -Parent $cfg.DiagLogPath),
        $cfg.StateDir
    )
    foreach ($d in $dirsToEnsure) {
        if (-not [string]::IsNullOrWhiteSpace($d) -and -not (Test-Path -LiteralPath $d)) {
            try {
                New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null
            } catch {
                # Non-fatal: diag logging itself tolerates a missing dir.
            }
        }
    }

    # SharedAccount is REQUIRED (spec §5). Validate AFTER dirs exist so we
    # can write a diag breadcrumb before throwing.
    if (-not $cfg.ContainsKey('SharedAccount') -or [string]::IsNullOrWhiteSpace($cfg.SharedAccount)) {
        Write-AuditDiag -Config $cfg -Level Error -Message 'Config error: SharedAccount is required but missing/blank.'
        throw "Audit config error: 'SharedAccount' is required (set it in $ConfigPath)."
    }

    # New optional keys: ensure present so the prompt can read them under StrictMode.
    foreach ($kv in @(
        @{ K = 'ClassificationLevel';      V = '' },
        @{ K = 'ClassificationText';       V = '' },
        @{ K = 'ClassificationForeground'; V = '' },
        @{ K = 'ClassificationBackground'; V = '' },
        @{ K = 'LogoPath';                 V = '' })) {
        if (-not $cfg.ContainsKey($kv.K)) { $cfg[$kv.K] = $kv.V }
    }

    return $cfg
}


function Write-AuditDiag {
<#
.SYNOPSIS
    Appends a diagnostic line to the local diag log. NEVER throws and NEVER
    receives or writes a password.
.DESCRIPTION
    Format: 'yyyy-MM-dd HH:mm:ss [LEVEL] [PID] message'. All errors are
    swallowed — diagnostics must never break the prompt. The diag log is
    LOCAL because the central CSV is unreadable; this is how an admin
    troubleshoots a single PC. Callers MUST NOT pass credential material.
.PARAMETER Config
    The resolved config hashtable (provides DiagLogPath).
.PARAMETER Message
    The message text (never a password).
.PARAMETER Level
    Info | Warn | Error. Default Info.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config,
        [Parameter(Mandatory = $true)] [string]    $Message,
        [ValidateSet('Info', 'Warn', 'Error')] [string] $Level = 'Info'
    )

    try {
        $path = $Config.DiagLogPath
        if ([string]::IsNullOrWhiteSpace($path)) { return }

        $dir = Split-Path -Parent $path
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
        }

        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line  = '{0} [{1}] [{2}] {3}' -f $stamp, $Level.ToUpper(), $PID, $Message

        # Append; local file so a simple .NET append is fine. Use UTF-8.
        [System.IO.File]::AppendAllText($path, $line + "`r`n", $script:AuditUtf8NoBom)
    } catch {
        # Swallow — diagnostics never throw.
    }
}


function Get-AuditComputerName {
<#
.SYNOPSIS
    Returns this machine's name. NEVER blank.
.DESCRIPTION
    Resolution order: $env:COMPUTERNAME -> [System.Net.Dns]::GetHostName()
    -> the literal 'UNKNOWN-HOST'. Any failure falls through to the next.
.OUTPUTS
    [string] non-empty host name.
#>
    [CmdletBinding()]
    param()

    try {
        $name = $env:COMPUTERNAME
        if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
    } catch { }

    try {
        $dns = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($dns)) { return $dns }
    } catch { }

    return 'UNKNOWN-HOST'
}


function Get-AuditCurrentUser {
<#
.SYNOPSIS
    Returns the current Windows identity as DOMAIN\user or MACHINE\user.
.DESCRIPTION
    Uses [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.
    On any failure returns an empty string (the caller treats an empty
    result as "not the shared account" and fails safe).
.OUTPUTS
    [string] e.g. 'LAB-PC01\LabShared'.
#>
    [CmdletBinding()]
    param()

    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch {
        return ''
    }
}


function Test-AuditIsSharedAccount {
<#
.SYNOPSIS
    $true if the current user's LEAF account name equals the configured
    SharedAccount's leaf name (case-insensitive).
.DESCRIPTION
    Both the current identity (Get-AuditCurrentUser) and the configured
    SharedAccount may be MACHINE\name, DOMAIN\name, .\name, or a bare name.
    Only the LEAF (the portion after the LAST backslash) is compared, so
    'LAB-PC01\LabShared' matches a configured '.\LabShared' or 'LabShared'.
    This is the prompt's self-check backstop (the task UserId scoping is the
    primary control).
.PARAMETER Config
    Resolved config hashtable (provides SharedAccount).
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    # Local helper: take the substring after the last backslash (or the whole
    # string if there is none).
    $leaf = {
        param($v)
        if ([string]::IsNullOrWhiteSpace($v)) { return '' }
        $i = $v.LastIndexOf('\')
        if ($i -ge 0) { return $v.Substring($i + 1) }
        return $v
    }

    $currentLeaf = (& $leaf (Get-AuditCurrentUser)).Trim()
    $sharedLeaf  = (& $leaf ([string]$Config.SharedAccount)).Trim()

    if ([string]::IsNullOrWhiteSpace($currentLeaf) -or [string]::IsNullOrWhiteSpace($sharedLeaf)) {
        return $false
    }

    return [string]::Equals($currentLeaf, $sharedLeaf, [System.StringComparison]::OrdinalIgnoreCase)
}


function ConvertTo-AuditCsvField {
<#
.SYNOPSIS
    CSV-escapes a single field: wraps in double quotes and doubles any
    embedded double quotes.
.DESCRIPTION
    Null/empty -> "". This unconditional quoting keeps commas, quotes,
    apostrophes and newlines safe (e.g. O'Brien, "Smith, Jr").
.PARAMETER Value
    The raw string value.
.OUTPUTS
    [string] the quoted/escaped field.
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($null -eq $Value) { return '""' }
    # Double every embedded quote, then wrap the whole thing in quotes.
    $escaped = $Value.Replace('"', '""')
    return '"' + $escaped + '"'
}


function Format-AuditRow {
<#
.SYNOPSIS
    Builds one CSV line (no trailing newline) from the eight audit fields,
    each escaped via ConvertTo-AuditCsvField and comma-joined.
.DESCRIPTION
    Column order is EXACTLY (spec §8):
    TimestampUTC,TimestampLocal,Username,LastName,FirstName,ComputerName,EventType,AuthResult
.PARAMETER TimestampUtc
    UTC timestamp string (yyyy-MM-ddTHH:mm:ssZ).
.PARAMETER TimestampLocal
    Local timestamp string (yyyy-MM-dd HH:mm:ss).
.PARAMETER Username
    Verified local username (or selected roster username on a failure).
.PARAMETER LastName
    Roster last name.
.PARAMETER FirstName
    Roster first name.
.PARAMETER ComputerName
    Machine name (never blank).
.PARAMETER EventType
    Logon | Unlock.
.PARAMETER AuthResult
    Success | Failure.
.OUTPUTS
    [string] one CSV row.
#>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $TimestampUtc,
        [AllowNull()][AllowEmptyString()][string] $TimestampLocal,
        [AllowNull()][AllowEmptyString()][string] $Username,
        [AllowNull()][AllowEmptyString()][string] $LastName,
        [AllowNull()][AllowEmptyString()][string] $FirstName,
        [AllowNull()][AllowEmptyString()][string] $ComputerName,
        [AllowNull()][AllowEmptyString()][string] $EventType,
        [AllowNull()][AllowEmptyString()][string] $AuthResult
    )

    $fields = @(
        (ConvertTo-AuditCsvField -Value $TimestampUtc),
        (ConvertTo-AuditCsvField -Value $TimestampLocal),
        (ConvertTo-AuditCsvField -Value $Username),
        (ConvertTo-AuditCsvField -Value $LastName),
        (ConvertTo-AuditCsvField -Value $FirstName),
        (ConvertTo-AuditCsvField -Value $ComputerName),
        (ConvertTo-AuditCsvField -Value $EventType),
        (ConvertTo-AuditCsvField -Value $AuthResult)
    )
    return ($fields -join ',')
}


function Test-AuditShouldTryNextLogonType {
<#
.SYNOPSIS After a failed LogonUser, decide whether to try the next logon type.
.DESCRIPTION ERROR_LOGON_FAILURE (1326) means the password is genuinely wrong - stop, so a
             wrong password costs ONE bad-password strike instead of one per logon type
             (the cause of lockout after 1-2 attempts). Any other error (notably 1385
             ERROR_LOGON_TYPE_NOT_GRANTED, the STIG "deny network logon" case) means the
             credential may be valid for a different logon type - keep trying.
.OUTPUTS [bool] $true to try the next logon type, $false to stop.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int] $Win32Error)
    return ($Win32Error -ne 1326)
}

function Test-AuditCredential {
<#
.SYNOPSIS
    Validates a LOCAL (SAM) credential via Win32 LogonUser. Returns $bool.
    NEVER logs the password.
.DESCRIPTION
    Uses Add-Type P/Invoke into advapi32::LogonUser and kernel32::CloseHandle.

    The supplied username may arrive as 'MACHINE\user', '.\user', or 'user';
    any prefix up to and including the last backslash is stripped and the
    bare username is passed with -Domain (default '.', the local SAM).

    The SecureString is converted to plaintext ONLY at the P/Invoke boundary
    via Marshal::SecureStringToBSTR / PtrToStringBSTR, and the BSTR is zeroed
    and freed with Marshal::ZeroFreeBSTR in a finally. The plaintext lives
    only inside this call.

    Logon types are tried IN ORDER:
        NETWORK(3) -> NETWORK_CLEARTEXT(8) -> INTERACTIVE(2)
    Rationale: the STIG-hardened "Deny access to this computer from the
    network" / "deny network logon for local accounts" can make a perfectly
    valid local credential fail LOGON32_LOGON_NETWORK(3); falling back to
    NETWORK_CLEARTEXT(8) and then INTERACTIVE(2) still verifies the password
    without requiring the heavier interactive right first. Success on ANY
    type -> CloseHandle(token) and return $true. If all three fail -> $false.

    NOTE: each failed LogonUser may emit a Security 4625 and increment the
    local account's bad-password count (local lockout policy may apply). This
    is acceptable/auditable under the chosen "log failures, no cap" policy;
    the caller's inter-attempt delay (RetryDelayMs) slows brute force.
.PARAMETER Username
    The account name (MACHINE\user, .\user, or bare user).
.PARAMETER Password
    SecureString from the WPF PasswordBox.
.PARAMETER Domain
    LogonUser domain. Default '.' (local machine SAM).
.OUTPUTS
    [bool] $true on a successful logon of any tried type, else $false.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]       $Username,
        [Parameter(Mandatory = $true)] [System.Security.SecureString] $Password,
        [string] $Domain = '.'
    )

    # Compile the P/Invoke shim once (idempotent across dot-source / calls).
    if (-not ([System.Management.Automation.PSTypeName]'SharedAccountAuth.NativeLogon').Type) {
        Add-Type -Namespace 'SharedAccountAuth' -Name 'NativeLogon' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool LogonUser(
    string lpszUsername,
    string lpszDomain,
    string lpszPassword,
    int dwLogonType,
    int dwLogonProvider,
    out System.IntPtr phToken);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@
    }

    # Logon type constants.
    $LOGON32_LOGON_INTERACTIVE       = 2
    $LOGON32_LOGON_NETWORK           = 3
    $LOGON32_LOGON_NETWORK_CLEARTEXT = 8
    $LOGON32_PROVIDER_DEFAULT        = 0

    # Strip any MACHINE\ or .\ prefix -> bare username; default domain '.'.
    $bareUser = $Username
    $bs = $bareUser.LastIndexOf('\')
    if ($bs -ge 0) { $bareUser = $bareUser.Substring($bs + 1) }
    if ([string]::IsNullOrWhiteSpace($Domain)) { $Domain = '.' }

    $bstr      = [System.IntPtr]::Zero
    $plainPwd  = $null
    $token     = [System.IntPtr]::Zero
    $result    = $false

    try {
        # ---- Convert SecureString -> plaintext ONLY at the P/Invoke boundary. ----
        $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        # Try the logon types in the required order; success on ANY wins.
        foreach ($logonType in @($LOGON32_LOGON_NETWORK, $LOGON32_LOGON_NETWORK_CLEARTEXT, $LOGON32_LOGON_INTERACTIVE)) {
            $token = [System.IntPtr]::Zero
            $ok = [SharedAccountAuth.NativeLogon]::LogonUser(
                $bareUser, $Domain, $plainPwd,
                $logonType, $LOGON32_PROVIDER_DEFAULT, [ref]$token)

            if ($ok) {
                # Close the token handle immediately; we only needed the check.
                [void][SharedAccountAuth.NativeLogon]::CloseHandle($token)
                $token  = [System.IntPtr]::Zero
                $result = $true
                break
            }
            else {
                # Capture the failure reason IMMEDIATELY (SetLastError=true on the P/Invoke).
                $lastErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                # Failure: LogonUser may have emitted a 4625 and bumped the bad-password
                # count. Do NOT log the password. Close any dangling token.
                if ($token -ne [System.IntPtr]::Zero) {
                    [void][SharedAccountAuth.NativeLogon]::CloseHandle($token)
                    $token = [System.IntPtr]::Zero
                }
                # If the password is simply wrong (1326), STOP - trying the other logon
                # types only burns more bad-password strikes (this caused lockout after
                # 1-2 attempts). Only fall through for other errors (e.g. 1385 type-not-granted).
                if (-not (Test-AuditShouldTryNextLogonType -Win32Error $lastErr)) {
                    break
                }
            }
        }
    }
    finally {
        # ---- Zero + free the plaintext/BSTR no matter what. ----
        if ($bstr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $bstr = [System.IntPtr]::Zero
        }
        # PtrToStringBSTR copied the password into an immutable managed System.String,
        # which cannot be zeroed in pure .NET Framework — setting it to $null only drops
        # the reference; the GC reclaims the buffer later. This is an accepted, documented
        # limitation; the plaintext never leaves this function's scope.
        $plainPwd = $null
        # Defensive: close any dangling token.
        if ($token -ne [System.IntPtr]::Zero) {
            try { [void][SharedAccountAuth.NativeLogon]::CloseHandle($token) } catch { }
            $token = [System.IntPtr]::Zero
        }
    }

    return $result
}


function Get-AuditIOExceptionKind {
<#
.SYNOPSIS
    Classifies an IOException so the appender knows whether to APPEND (file
    already exists), RETRY (transient sharing/lock violation), or FAIL FAST to
    the spool (unreachable share / denied / path gone).
.DESCRIPTION
    Inspects the exception HResult. Windows wraps Win32 error codes as
    0x8007xxxx, where the low 16 bits are the Win32 error. We deliberately
    treat ONLY sharing/lock violations as transient; everything that is not
    "already exists" and not a sharing violation is terminal, so a down SMB
    server short-circuits straight to the spool instead of burning the full
    retry budget (which would freeze the full-screen lockdown UI for seconds
    on every sign-on). Classification is purely by exception — we never probe
    the share (no Test-Path), which on an unreachable UNC could itself block
    for the full SMB/TCP timeout.
.OUTPUTS
    [string] 'Exists' | 'Transient' | 'Terminal'
#>
    param([System.Exception] $Ex)

    # A failing `New-Object System.IO.FileStream(...)` surfaces as a
    # MethodInvocationException whose InnerException is the real IOException.
    # Unwrap so the type tests and HResult below inspect the ACTUAL error,
    # not the PowerShell wrapper (whose HResult is 0x80131501).
    while (($Ex -is [System.Management.Automation.MethodInvocationException]) -and ($null -ne $Ex.InnerException)) {
        $Ex = $Ex.InnerException
    }

    if ($Ex -is [System.IO.DirectoryNotFoundException]) { return 'Terminal' }
    if ($Ex -is [System.UnauthorizedAccessException])   { return 'Terminal' }

    $hr = 0
    try { $hr = [int]$Ex.HResult } catch { $hr = 0 }
    # Reinterpret the signed HResult as an unsigned 32-bit value for range tests.
    $u = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($hr), 0)

    # NOTE: an 8-digit hex literal with the high bit set (0x80070000) parses as a
    # NEGATIVE Int32 under PS 5.1, which would make this range test always false.
    # The L (Int64) suffix keeps the bounds positive so the comparison is valid.
    if ($u -ge 0x80070000L -and $u -le 0x8007FFFFL) {
        $code = [int]($u -band 0xFFFF)
        switch ($code) {
            0x50    { return 'Exists' }     # ERROR_FILE_EXISTS    — lost the create race
            0xB7    { return 'Exists' }     # ERROR_ALREADY_EXISTS — lost the create race
            0x20    { return 'Transient' }  # ERROR_SHARING_VIOLATION
            0x21    { return 'Transient' }  # ERROR_LOCK_VIOLATION
            default { return 'Terminal' }   # bad netpath / path not found / netname deleted / access / ...
        }
    }

    # Unknown / non-Win32-wrapped IOException: retry a bounded number of times
    # rather than fail outright — the WriteRetryCount cap still bounds any stall.
    return 'Transient'
}


function Add-AuditLineToFile {
<#
.SYNOPSIS
    INTERNAL core appender. Appends $Line to $Path, writing $HeaderLine
    exactly once via a create-header-race. Throws on unreachable/denied
    paths so the caller can spool.
.DESCRIPTION
    Concurrency model (see spec §7):
      1. A LOCAL named Mutex (Global\SharedAccountAuth_Write) serializes writers
         ON THE SAME MACHINE. NOTE: a named mutex does NOT coordinate
         across machines over SMB — cross-machine safety relies entirely on
         the open-mode (FileShare.Read) + retry/backoff below.
      2. Loop up to WriteRetryCount:
         - Try FileMode.CreateNew (FileAccess.Write, FileShare.Read). If we
           win the create race, write HeaderLine then Line and return. The
           header is written ONLY here — we never read the file to check for
           a header (the account cannot read it). Exactly one machine wins
           the race; everyone else appends with no header.
         - If CreateNew fails because the file already exists, fall through
           to FileMode.Append and write just Line.
         - On a sharing-violation / transient IOException, sleep
           min(BaseMs * 2^attempt, 2000) ms + jitter (Get-Random) and retry.
         - On DirectoryNotFound / UnauthorizedAccess / unreachable path,
           THROW so the caller spools.
    Stream is always flushed/disposed in finally; mutex always released.
    All writes are BOM-less UTF-8.
.PARAMETER Path
    Target central CSV path.
.PARAMETER Line
    The data line to append (no trailing newline).
.PARAMETER HeaderLine
    Header to write if (and only if) this call wins the create race.
.PARAMETER Config
    Resolved config (provides WriteRetryCount, WriteRetryBaseMs).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]    $Path,
        [Parameter(Mandatory = $true)] [string]    $Line,
        [Parameter(Mandatory = $true)] [string]    $HeaderLine,
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    $retryCount = [int]$Config.WriteRetryCount
    if ($retryCount -lt 1) { $retryCount = 1 }
    $baseMs = [int]$Config.WriteRetryBaseMs
    if ($baseMs -lt 1) { $baseMs = 1 }

    $mutex          = $null
    $haveMutex      = $false
    $newlineBytes   = $script:AuditUtf8NoBom.GetBytes("`r`n")

    try {
        # ---- Step 1: same-machine mutex. Does NOT span machines over SMB. ----
        try {
            $mutex = New-Object System.Threading.Mutex($false, 'Global\SharedAccountAuth_Write')
        } catch {
            # Global\ may be denied without SeCreateGlobalPrivilege; fall back to
            # a session-local mutex which still serializes this machine's sessions
            # well enough for our purposes.
            $mutex = New-Object System.Threading.Mutex($false, 'Local\SharedAccountAuth_Write')
        }

        try {
            # WaitOne returns $false on timeout (and on an abandoned mutex it
            # throws AbandonedMutexException but still grants ownership).
            $haveMutex = $mutex.WaitOne(5000)
        } catch [System.Threading.AbandonedMutexException] {
            # A prior holder died without releasing; we now own it.
            $haveMutex = $true
        }
        # If we did not get the mutex we still proceed — the FileShare.Read
        # open-mode + retry loop is the real cross-process guard.

        # ---- Step 2: create-race + append with retry/backoff. ----
        $attempt = 0
        while ($true) {
            $stream = $null
            try {
                $wroteHeader = $false
                try {
                    # Create-header-race: only one machine/process wins CreateNew.
                    $stream = New-Object System.IO.FileStream(
                        $Path,
                        [System.IO.FileMode]::CreateNew,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::Read)
                    $wroteHeader = $true
                } catch [System.IO.IOException] {
                    # CreateNew throws an IOException when the file already exists
                    # AND on transient/terminal I/O errors. Classify by HResult,
                    # NOT by probing the share with Test-Path (that probe could
                    # block for the full SMB timeout on an unreachable UNC and
                    # also couples us to the directory ACL). If we merely lost the
                    # create race, append (no header). Anything else propagates to
                    # the outer handler, which decides retry-vs-spool.
                    if ((Get-AuditIOExceptionKind $_.Exception) -eq 'Exists') {
                        $stream = New-Object System.IO.FileStream(
                            $Path,
                            [System.IO.FileMode]::Append,
                            [System.IO.FileAccess]::Write,
                            [System.IO.FileShare]::Read)
                    } else {
                        throw
                    }
                }

                if ($wroteHeader) {
                    # Header ONLY in the create path. BOM-less UTF-8.
                    $headerBytes = $script:AuditUtf8NoBom.GetBytes($HeaderLine)
                    $stream.Write($headerBytes, 0, $headerBytes.Length)
                    $stream.Write($newlineBytes, 0, $newlineBytes.Length)
                }

                $lineBytes = $script:AuditUtf8NoBom.GetBytes($Line)
                $stream.Write($lineBytes, 0, $lineBytes.Length)
                $stream.Write($newlineBytes, 0, $newlineBytes.Length)
                $stream.Flush()
                return  # success
            }
            catch [System.IO.DirectoryNotFoundException] {
                # Path/share unreachable — caller must spool.
                throw
            }
            catch [System.UnauthorizedAccessException] {
                # Denied — caller must spool.
                throw
            }
            catch [System.IO.IOException] {
                # Only a genuine sharing/lock violation is worth retrying. An
                # unreachable share (ERROR_BAD_NETPATH, path-not-found, netname
                # deleted, ...) is terminal: fail fast to the caller so it spools
                # immediately and the lockdown UI never stalls on a dead server.
                if ((Get-AuditIOExceptionKind $_.Exception) -ne 'Transient') { throw }

                # Back off and retry until we exhaust WriteRetryCount, then rethrow
                # to spool. Exponent ($attempt-1) => first retry waits BaseMs*1.
                $attempt++
                if ($attempt -ge $retryCount) { throw }

                $delay = [Math]::Min($baseMs * [Math]::Pow(2, ($attempt - 1)), 2000)
                $jitter = Get-Random -Minimum 0 -Maximum 50
                Start-Sleep -Milliseconds ([int]$delay + $jitter)
            }
            finally {
                if ($null -ne $stream) {
                    $stream.Dispose()
                }
            }
        }
    }
    finally {
        # Always release/dispose the mutex.
        if ($null -ne $mutex) {
            if ($haveMutex) {
                try { $mutex.ReleaseMutex() } catch { }
            }
            $mutex.Dispose()
        }
    }
}


function Write-AuditRow {
<#
.SYNOPSIS
    Builds an audit row and appends it to the central CSV; spools it
    locally on share failure.
.DESCRIPTION
    Computes TimestampUtc (yyyy-MM-ddTHH:mm:ssZ) and TimestampLocal
    (yyyy-MM-dd HH:mm:ss). ComputerName defaults to Get-AuditComputerName
    (never blank). On a successful central append, opportunistically flushes
    the spool. On any throw from the appender, writes the same line to a new
    spool file spool\<host>-<utcTicks>-<rand>.csv (BOM-less, NO header).

    EventType is Logon | Unlock. AuthResult is Success | Failure. The
    password NEVER reaches this function — only the (already verified or
    rejected) Username plus the roster name fields.
.PARAMETER Config
    Resolved config hashtable.
.PARAMETER Username
    Verified local username (or the selected roster username on a failure).
.PARAMETER LastName
    Roster last name.
.PARAMETER FirstName
    Roster first name.
.PARAMETER EventType
    Logon | Unlock.
.PARAMETER AuthResult
    Success | Failure.
.PARAMETER TimestampUtc
    Optional override of the UTC instant (defaults to now).
.PARAMETER ComputerName
    Optional override of the machine name.
.OUTPUTS
    [pscustomobject] @{ Written = [bool]; Spooled = [bool]; Target = [string] }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config,
        [Parameter(Mandatory = $true)] [string]    $Username,
        [Parameter(Mandatory = $true)] [string]    $LastName,
        [Parameter(Mandatory = $true)] [string]    $FirstName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Logon', 'Unlock')] [string]  $EventType,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Failure')] [string] $AuthResult,
        [datetime] $TimestampUtc,
        [string]   $ComputerName
    )

    # Default the timestamp to now (UTC) if not supplied.
    if (-not $PSBoundParameters.ContainsKey('TimestampUtc')) {
        $TimestampUtc = [DateTime]::UtcNow
    } else {
        $TimestampUtc = $TimestampUtc.ToUniversalTime()
    }

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $ComputerName = Get-AuditComputerName
    }

    $utcStr   = $TimestampUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $localStr = $TimestampUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')

    $line   = Format-AuditRow -TimestampUtc $utcStr -TimestampLocal $localStr `
                              -Username $Username -LastName $LastName -FirstName $FirstName `
                              -ComputerName $ComputerName -EventType $EventType -AuthResult $AuthResult
    $header = $script:AuditHeaderLine

    $result = [pscustomobject]@{
        Written = $false
        Spooled = $false
        Target  = $null
    }

    try {
        Add-AuditLineToFile -Path $Config.LogPath -Line $line -HeaderLine $header -Config $Config
        $result.Written = $true
        $result.Target  = $Config.LogPath
        Write-AuditDiag -Config $Config -Level Info -Message ("Wrote row to central log: {0}/{1} ({2})" -f $EventType, $AuthResult, $ComputerName)

        # Opportunistic: try to drain any previously-spooled rows.
        try { Invoke-AuditSpoolFlush -Config $Config | Out-Null } catch { }
    }
    catch {
        # Central append failed (unreachable/denied/exhausted retries). Spool.
        Write-AuditDiag -Config $Config -Level Warn -Message ("Central append failed; spooling. {0}" -f $_.Exception.Message)
        try {
            if (-not (Test-Path -LiteralPath $Config.SpoolDir)) {
                New-Item -ItemType Directory -Path $Config.SpoolDir -Force -ErrorAction Stop | Out-Null
            }
            $rand      = Get-Random -Minimum 0 -Maximum 1000000
            $spoolName = '{0}-{1}-{2}.csv' -f $ComputerName, $TimestampUtc.Ticks, $rand
            $spoolPath = Join-Path $Config.SpoolDir $spoolName
            # NO header in spool files — only the data line. BOM-less UTF-8.
            [System.IO.File]::WriteAllText($spoolPath, $line + "`r`n", $script:AuditUtf8NoBom)
            $result.Spooled = $true
            $result.Target  = $spoolPath
            Write-AuditDiag -Config $Config -Level Info -Message ("Spooled row to {0}" -f $spoolPath)
        }
        catch {
            # Could not even spool. Log and surface nothing further — the caller
            # decides; we do not rethrow so the UI never traps the user forever.
            Write-AuditDiag -Config $Config -Level Error -Message ("Spool write failed: {0}" -f $_.Exception.Message)
        }
    }

    return $result
}


function Invoke-AuditSpoolFlush {
<#
.SYNOPSIS
    Best-effort drain of the local spool into the central CSV. NEVER throws.
.DESCRIPTION
    For each *.csv in the spool (oldest first), append its line(s) to the
    central log via Add-AuditLineToFile. APPEND-ONLY: we never read the
    central log and never dedup against it (it is unreadable). The standard
    HeaderLine is passed so a brand-new central file still gets its header
    from the create-race. A spool file is deleted ONLY after every one of
    its lines was confirmed appended; on any failure it is left in place for
    the next run (at-least-once delivery; rare duplicates are acceptable and
    visible to auditors).
.PARAMETER Config
    Resolved config hashtable.
.OUTPUTS
    [int] number of spool files successfully flushed and deleted.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    $flushed = 0
    $header  = $script:AuditHeaderLine

    try {
        if ([string]::IsNullOrWhiteSpace($Config.SpoolDir) -or -not (Test-Path -LiteralPath $Config.SpoolDir)) {
            return 0
        }

        # Oldest first so rows land in roughly chronological order.
        $files = Get-ChildItem -LiteralPath $Config.SpoolDir -Filter '*.csv' -File -ErrorAction SilentlyContinue |
                 Sort-Object -Property LastWriteTimeUtc

        foreach ($f in $files) {
            try {
                # Read the spool file's data line(s) (local file — reading our
                # OWN spool is fine; only the CENTRAL log is unreadable).
                $lines = Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop |
                         Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

                $allOk = $true
                foreach ($ln in $lines) {
                    try {
                        Add-AuditLineToFile -Path $Config.LogPath -Line $ln -HeaderLine $header -Config $Config
                    } catch {
                        # Central still unreachable — stop, leave the file.
                        $allOk = $false
                        break
                    }
                }

                if ($allOk) {
                    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                    $flushed++
                    Write-AuditDiag -Config $Config -Level Info -Message ("Flushed spool file {0}" -f $f.Name)
                }
            }
            catch {
                # Leave this file; try the rest. Never throw out of the flush.
                Write-AuditDiag -Config $Config -Level Warn -Message ("Spool flush skipped {0}: {1}" -f $f.Name, $_.Exception.Message)
            }
        }
    }
    catch {
        # Swallow — flush never throws.
        Write-AuditDiag -Config $Config -Level Warn -Message ("Spool flush error: {0}" -f $_.Exception.Message)
    }

    return $flushed
}


function ConvertFrom-AuditRoster {
<#
.SYNOPSIS Pure: turn parsed roster rows (Import-Csv output) into validated, sorted, deduped entries.
.DESCRIPTION Requires ONLY a Username column. LastName/FirstName are used if present, else blank.
             Display = "LastName, FirstName" when names exist, else the Username. Sorted by Username
             (case-insensitive), deduped by Username. Blank-username rows are skipped. Returns
             Valid=$false if the rows have no Username column (only determinable when rows exist).
.OUTPUTS [pscustomobject] @{ Entries = @(@{LastName;FirstName;Username;Display}); Valid }
#>
    [CmdletBinding()]
    param([AllowNull()][object[]] $Rows)

    $rowsArr = @($Rows)
    if ($rowsArr.Count -eq 0) {
        return [pscustomobject]@{ Entries = @(); Valid = $true }   # empty roster, nothing to validate
    }

    $props = @($rowsArr[0].PSObject.Properties.Name)
    $hasUser = $false
    foreach ($p in $props) { if ($p -ieq 'Username') { $hasUser = $true; break } }
    if (-not $hasUser) {
        return [pscustomobject]@{ Entries = @(); Valid = $false }
    }
    $hasLast  = $false; foreach ($p in $props) { if ($p -ieq 'LastName')  { $hasLast  = $true; break } }
    $hasFirst = $false; foreach ($p in $props) { if ($p -ieq 'FirstName') { $hasFirst = $true; break } }

    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $built = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rowsArr) {
        $user = if ($null -ne $row.Username) { ([string]$row.Username).Trim() } else { '' }
        if ([string]::IsNullOrWhiteSpace($user)) { continue }
        if (-not $seen.Add($user)) { continue }
        $last  = if ($hasLast  -and $null -ne $row.LastName)  { ([string]$row.LastName).Trim() }  else { '' }
        $first = if ($hasFirst -and $null -ne $row.FirstName) { ([string]$row.FirstName).Trim() } else { '' }
        $display = if (-not [string]::IsNullOrWhiteSpace($last) -or -not [string]::IsNullOrWhiteSpace($first)) {
            ("{0}, {1}" -f $last, $first)
        } else { $user }
        $built.Add([pscustomobject]@{ LastName = $last; FirstName = $first; Username = $user; Display = $display })
    }

    $sorted = @($built | Sort-Object -Property Username)
    return [pscustomobject]@{ Entries = $sorted; Valid = $true }
}


function Get-AuditRosterEntries {
<#
.SYNOPSIS
    Loads the roster from the central share with a last-known-good local
    cache fallback. Refreshes the cache on every successful central read.
.DESCRIPTION
    Tries Import-Csv on RosterPath. On success: refresh the local cache
    (best-effort copy) and return Source='central'. On failure: read the
    cache and return Source='cache'. If neither is available: Source='none'.
    Requires only a Username column; LastName/FirstName optional. Ignores
    blank-username rows; builds Display via ConvertFrom-AuditRoster; sorts
    by Username and dedupes by Username.
.PARAMETER Config
    Resolved config hashtable (RosterPath, RosterCachePath).
.OUTPUTS
    [pscustomobject] @{
        Entries = array of @{ LastName; FirstName; Username; Display }
        Source  = 'central' | 'cache' | 'none'
    }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    $source = 'none'
    $raw    = $null

    # --- Attempt 1: central share. ---
    try {
        if (-not [string]::IsNullOrWhiteSpace($Config.RosterPath) -and (Test-Path -LiteralPath $Config.RosterPath)) {
            $raw = Import-Csv -LiteralPath $Config.RosterPath -ErrorAction Stop
            $source = 'central'

            # Refresh the local cache (best-effort copy of the source file).
            try {
                $cacheDir = Split-Path -Parent $Config.RosterCachePath
                if (-not [string]::IsNullOrWhiteSpace($cacheDir) -and -not (Test-Path -LiteralPath $cacheDir)) {
                    New-Item -ItemType Directory -Path $cacheDir -Force -ErrorAction Stop | Out-Null
                }
                Copy-Item -LiteralPath $Config.RosterPath -Destination $Config.RosterCachePath -Force -ErrorAction Stop
            } catch {
                Write-AuditDiag -Config $Config -Level Warn -Message ("Roster cache refresh failed: {0}" -f $_.Exception.Message)
            }
        }
    }
    catch {
        Write-AuditDiag -Config $Config -Level Warn -Message ("Central roster read failed: {0}" -f $_.Exception.Message)
        $raw = $null
    }

    # --- Attempt 2: local cache fallback. ---
    if ($null -eq $raw) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($Config.RosterCachePath) -and (Test-Path -LiteralPath $Config.RosterCachePath)) {
                $raw = Import-Csv -LiteralPath $Config.RosterCachePath -ErrorAction Stop
                $source = 'cache'
            }
        }
        catch {
            Write-AuditDiag -Config $Config -Level Warn -Message ("Cache roster read failed: {0}" -f $_.Exception.Message)
            $raw = $null
        }
    }

    if ($null -eq $raw) {
        Write-AuditDiag -Config $Config -Level Error -Message 'Roster unavailable from central and cache.'
        return [pscustomobject]@{ Entries = @(); Source = 'none' }
    }

    # --- Validate columns and build/sort/dedupe via pure helper. ---
    $parsed = ConvertFrom-AuditRoster -Rows $raw
    if (-not $parsed.Valid) {
        Write-AuditDiag -Config $Config -Level Error -Message ("Roster missing Username column (source={0})." -f $source)
        return [pscustomobject]@{ Entries = @(); Source = 'none' }
    }
    $built = $parsed.Entries

    return [pscustomobject]@{
        Entries = @($built)
        Source  = $source
    }
}


function Test-AuditDebounce {
<#
.SYNOPSIS
    Returns $true if a prompt was shown within DebounceSeconds. Global
    across event types (logon + unlock can fire together at sign-in).
.DESCRIPTION
    The marker file state\last-prompt.txt holds the UTC Ticks of the last
    shown prompt. If now - last < DebounceSeconds, returns $true (suppress).
    Otherwise returns $false AND updates the marker to "now" (because a
    prompt is about to be shown). A missing/unparsable marker => not
    debounced (and the marker is set to now).
.PARAMETER Config
    Resolved config hashtable (StateDir, DebounceSeconds).
.OUTPUTS
    [bool] $true to suppress this prompt, $false to show it.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Config
    )

    $debounceSeconds = [int]$Config.DebounceSeconds
    if ($debounceSeconds -lt 0) { $debounceSeconds = 0 }

    $markerPath = Join-Path $Config.StateDir 'last-prompt.txt'
    $nowUtc     = [DateTime]::UtcNow

    try {
        if (-not (Test-Path -LiteralPath $Config.StateDir)) {
            New-Item -ItemType Directory -Path $Config.StateDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { }

    # Read the last marker (UTC ticks).
    $lastTicks = $null
    try {
        if (Test-Path -LiteralPath $markerPath) {
            $text = (Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop)
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $parsed = 0L
                if ([Int64]::TryParse($text.Trim(), [ref]$parsed)) {
                    $lastTicks = $parsed
                }
            }
        }
    } catch {
        $lastTicks = $null
    }

    if ($null -ne $lastTicks) {
        try {
            $lastUtc  = New-Object DateTime($lastTicks, [System.DateTimeKind]::Utc)
            $elapsed  = ($nowUtc - $lastUtc).TotalSeconds
            # Guard against a clock-skew negative elapsed treating as fresh.
            if ($elapsed -ge 0 -and $elapsed -lt $debounceSeconds) {
                # Within the window — suppress. Do NOT update the marker.
                return $true
            }
        } catch {
            # Fall through to show + update.
        }
    }

    # Not debounced: a prompt will be shown -> update the marker to now.
    try {
        [System.IO.File]::WriteAllText($markerPath, $nowUtc.Ticks.ToString(), $script:AuditUtf8NoBom)
    } catch {
        Write-AuditDiag -Config $Config -Level Warn -Message ("Debounce marker update failed: {0}" -f $_.Exception.Message)
    }

    return $false
}


function Get-AuditClassification {
<#
.SYNOPSIS Resolve a classification banner's text + colors from a level, with optional overrides.
.DESCRIPTION Maps a US classification level (case-insensitive) to standard banner colors.
             Non-blank -Text/-Foreground/-Background override the defaults. Show=$false when
             the level is blank or unknown (banner hidden). Colors are WPF ARGB hex (#AARRGGBB).
.OUTPUTS [pscustomobject] @{ Text; Foreground; Background; Show }
#>
    [CmdletBinding()]
    param(
        [string] $Level,
        [string] $Text,
        [string] $Foreground,
        [string] $Background
    )
    $table = @{
        'UNCLASSIFIED' = @{ Bg = '#FF007A33'; Fg = '#FFFFFFFF' }   # green
        'CUI'          = @{ Bg = '#FF512B85'; Fg = '#FFFFFFFF' }   # purple
        'CONFIDENTIAL' = @{ Bg = '#FF0033A0'; Fg = '#FFFFFFFF' }   # blue
        'SECRET'       = @{ Bg = '#FFC8102E'; Fg = '#FFFFFFFF' }   # red
        'TOP SECRET'   = @{ Bg = '#FFFF8C00'; Fg = '#FF000000' }   # orange, black text
    }
    $key = ''
    if (-not [string]::IsNullOrWhiteSpace($Level)) { $key = $Level.Trim().ToUpperInvariant() }

    if ([string]::IsNullOrEmpty($key) -or -not $table.ContainsKey($key)) {
        return [pscustomobject]@{ Text = ''; Foreground = '#FFFFFFFF'; Background = '#FF000000'; Show = $false }
    }

    $def = $table[$key]
    $fg = if (-not [string]::IsNullOrWhiteSpace($Foreground)) { $Foreground } else { $def.Fg }
    $bg = if (-not [string]::IsNullOrWhiteSpace($Background)) { $Background } else { $def.Bg }
    $tx = if (-not [string]::IsNullOrWhiteSpace($Text))       { $Text }       else { $key }
    return [pscustomobject]@{ Text = $tx; Foreground = $fg; Background = $bg; Show = $true }
}
