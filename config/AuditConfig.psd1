@{
    # =====================================================================
    #  AuditConfig.psd1 — single source of truth for the Sign-On Audit Logger
    #  Loaded via Import-PowerShellDataFile by Get-AuditConfig (src\AuditCommon.ps1).
    #  Windows PowerShell 5.1 data file. No executable expressions allowed here.
    #  See spec section 5. Edit per site; SharedAccount is REQUIRED.
    # =====================================================================

    # --- Central share paths (UNC). Shared account: append-only on LogPath dir; read-only on RosterPath. ---
    LogPath          = '\\server\share\audit\access_log.csv'   # central append-only CSV
    RosterPath       = '\\server\share\audit\roster.csv'       # central read-only roster

    # --- Local state root (writable by the shared user; under ProgramData for AppLocker pathing) ---
    LocalRoot        = 'C:\ProgramData\SharedAccountAuth'
    RosterCachePath  = ''      # blank => $LocalRoot\cache\roster.csv
    SpoolDir         = ''      # blank => $LocalRoot\spool
    DiagLogPath      = ''      # blank => $LocalRoot\diag\audit-diag.log
    StateDir         = ''      # blank => $LocalRoot\state

    # --- Shared-account scoping (REQUIRED) ---
    # The ONE shared account this prompt applies to. MACHINE\name, .\name, or bare name.
    # Test-AuditIsSharedAccount compares only the LEAF (after the last backslash), case-insensitive.
    # RECOMMENDED: use '.\name' or bare 'name' so registration auto-resolves to the running
    # machine. A hardcoded 'MACHINE\name' will NOT match if this config is deployed to an
    # imaged/renamed clone with a different hostname (the task would never fire).
    SharedAccount    = '.\LabShared'

    # --- Authentication (local accounts) ---
    AuthDomain       = '.'     # passed to LogonUser; '.' = local machine SAM
    RetryDelayMs     = 1000    # delay after a failed attempt (slows brute force; no cap on attempts)

    # --- Behaviour tunables ---
    DebounceSeconds  = 5       # suppress a second prompt within this many seconds of the last (any event type)
    WriteRetryCount  = 10      # central-append attempts before giving up to spool
    WriteRetryBaseMs = 50      # exponential backoff base (ms): delay = min(BaseMs * 2^attempt, 2000) + jitter

    # --- UI text ---
    AppName          = 'SharedAccountAuth'
    WindowTitle      = 'Shared Account — Authenticate to Continue'
    WindowSubtitle   = 'Select your name and enter your personal account password. This window cannot be dismissed.'
}
