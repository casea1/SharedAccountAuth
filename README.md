# Shared-Account Sign-On Audit Logger

A fully **offline**, built-ins-only audit prompt for Windows 11. On a single **shared local Windows account**, every **logon** and every **workstation unlock** raises a hard-enforced, full-screen, topmost, un-closable window. The person at the keyboard must:

1. pick their name from an approved roster (an allow-list — no free text), and
2. authenticate with **their own personal local-account password**.

Only on a **successful credential check** does the window release. Every attempt — success *or* failure — is appended to a **central, append-only CSV** on a locked-down network share. Many PCs append to the same file; each row records the verified username, the person's name, **which machine** the access happened on, the event type, and the auth result.

The prompt appears **only under the one designated shared account** — never on individuals' personal logins.

- **Platform:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF). No internet at build or runtime. No external modules.
- **Append-only:** the shared account can create + append to the central log but **cannot read or delete** it. Because of that, no part of this tool ever reads the central log (no header check, no dedup against it).
- **No passwords on disk:** personal passwords are handled as `SecureString`, converted to plaintext only at the Win32 `LogonUser` boundary, zeroed immediately, and **never** written to the CSV, the spool, or the diagnostics log.

---

## 1. What it is + data-flow

### File tree

```
SharedAccountAuth/
├─ src/
│  ├─ SharedAccountAuth.ps1            # WPF lockdown prompt (entry point): self-check, name+password auth
│  ├─ AuditCommon.ps1            # shared library: config, diag, csv, append, spool, roster, debounce, credential check
│  └─ Launch-SharedAccountAuth.vbs     # hidden-console launcher (self-locating)
├─ config/
│  └─ AuditConfig.psd1           # single source of truth for paths/tunables + SharedAccount
├─ deploy/
│  ├─ Install-Audit.ps1          # one-command per-PC install: self-elevate, register tasks, preflight-validate
│  ├─ Install-Audit-GUI.ps1      # WPF single-pane front-end over Install-Audit (collect paths, preview roster, install)
│  ├─ AuditInstallCommon.ps1     # shared install-time library (preflight, local-account check, config writer)
│  ├─ Register-AuditTasks.ps1    # registers Logon + SessionUnlock tasks SCOPED to the shared account
│  ├─ Unregister-AuditTasks.ps1  # removes both tasks
│  └─ Setup-SharePermissions.ps1 # admin-once: append-only ACLs on the log dir (run on the server)
├─ assets/
│  └─ GE-Aerospace-Emblem.png    # logo displayed in the classification banner
├─ sample/
│  └─ roster.csv                 # Username (required); LastName, FirstName optional
├─ tasks/
│  ├─ SharedAccountAuth-Logon.xml      # reference export of the Logon task
│  └─ SharedAccountAuth-Unlock.xml     # reference export of the Unlock task
├─ docs/superpowers/specs/2026-06-17-sign-on-audit-logger-design.md
└─ README.md
```

### Data flow (including authentication + shared-account scoping)

```
Logon  ──┐  (tasks scoped to SharedAccount only, via trigger UserId)
         ├─► Task Scheduler  (runs as the shared INTERACTIVE user, session ≠ 0, LeastPrivilege)
Unlock ──┘        │
                  ▼
        Launch-SharedAccountAuth.vbs <EventType>   (hides the PowerShell console; wscript run-style 0)
                  │
                  ▼
        SharedAccountAuth.ps1 -EventType <Logon|Unlock>
                  │  dot-sources src\AuditCommon.ps1, then Get-AuditConfig
                  ▼
   0. SHARED-ACCOUNT SELF-CHECK:  Test-AuditIsSharedAccount -Config
        if current user's leaf name != SharedAccount leaf  →  Write-AuditDiag + EXIT (no window)
   1. DEBOUNCE:  Test-AuditDebounce -Config   (suppress a duplicate prompt within DebounceSeconds)
   2. Get-AuditComputerName   (env → DNS → 'UNKNOWN-HOST'; never blank)
   3. Get-AuditRosterEntries -Config   (central → cache fallback; refreshes cache on central success)
   4. Show fullscreen lockdown WPF window: type-to-filter name ComboBox + PasswordBox
   5. On Confirm → Test-AuditCredential -Username <roster username> -Password <SecureString> -Domain <AuthDomain>
        success → Write-AuditRow -AuthResult Success → window releases
        failure → Write-AuditRow -AuthResult Failure → clear password, wait RetryDelayMs, STAY LOCKED, retry
                  │
                  ▼
   Write-AuditRow -Config ...  →  Add-AuditLineToFile (central CSV append: create-header-race +
                  │                retry/backoff + Global\SharedAccountAuth_Write mutex + BOM-less UTF-8)
                  │  on share failure ▼
   Spool to  C:\ProgramData\SharedAccountAuth\spool\<host>-<utcTicks>-<rand>.csv  (no header)
                  │
                  ▼
   Invoke-AuditSpoolFlush -Config  drains the spool opportunistically on the next successful write
```

**Library entry points** (all in `src/AuditCommon.ps1`, dot-sourced — `Verb-Noun`, comment-help-documented):

| Function | Key params | Returns / behaviour |
|---|---|---|
| `Get-AuditConfig` | `[-ConfigPath <string>]` | `[hashtable]` resolved config. Loads the psd1, fills derived cache/spool/diag/state paths from `LocalRoot`, creates the local dirs, and **validates `SharedAccount` is present (throws if missing)**. |
| `Write-AuditDiag` | `-Config <hashtable> -Message <string> [-Level Info\|Warn\|Error]` | `void`. Appends `yyyy-MM-dd HH:mm:ss [LEVEL] [PID] message` to the local diag log. **Never throws; never receives/writes a password.** |
| `Get-AuditComputerName` | *(none)* | `[string]` non-blank host: `$env:COMPUTERNAME` → `[Net.Dns]::GetHostName()` → `'UNKNOWN-HOST'`. |
| `Get-AuditCurrentUser` | *(none)* | `[string]` `DOMAIN\user` / `MACHINE\user` via `[Security.Principal.WindowsIdentity]::GetCurrent().Name` (empty string on failure). |
| `Test-AuditIsSharedAccount` | `-Config <hashtable>` | `[bool]` `$true` if the current user's leaf name equals the `SharedAccount` leaf name (case-insensitive). |
| `ConvertTo-AuditCsvField` | `-Value <string>` | `[string]` CSV-escaped field (quoted, embedded quotes doubled); `null` → `""`. |
| `Format-AuditRow` | `-TimestampUtc -TimestampLocal -Username -LastName -FirstName -ComputerName -EventType -AuthResult` | `[string]` one escaped 8-column CSV line in exact header order. |
| `Get-AuditRosterEntries` | `-Config <hashtable>` | `[pscustomobject]` `@{ Entries = @(@{LastName;FirstName;Username;Display}) sorted+deduped; Source = 'central'\|'cache'\|'none' }`. Requires only `Username` column; `LastName`/`FirstName` are optional. Refreshes the cache on a central read. |
| `Test-AuditCredential` | `-Username <string> -Password <SecureString> [-Domain <string>=.]` | `[bool]` `LogonUser` via P/Invoke trying NETWORK(3) → NETWORK_CLEARTEXT(8) → INTERACTIVE(2); stops early on `ERROR_LOGON_FAILURE` (1326) so a wrong password costs one bad-password strike; falls through to the next type only on `ERROR_LOGON_TYPE_NOT_GRANTED` (1385); strips `MACHINE\`/`.\` prefix; BSTR zeroed in `finally`; never logs the password. |
| `Write-AuditRow` | `-Config -Username -LastName -FirstName -EventType(Logon\|Unlock) -AuthResult(Success\|Failure) [-TimestampUtc <datetime>] [-ComputerName <string>]` | `[pscustomobject]` `@{ Written=[bool]; Spooled=[bool]; Target=[string] }`. Appends to central, spools on failure, flushes the spool on success. |
| `Invoke-AuditSpoolFlush` | `-Config <hashtable>` | `[int]` count of spool files flushed. Append-only, no dedup, never reads central, deletes only on confirmed success, never throws. |
| `Test-AuditDebounce` | `-Config <hashtable>` | `[bool]` `$true` to suppress (a prompt was shown within `DebounceSeconds` per `state\last-prompt.txt` UTC ticks); updates the marker to now when returning `$false`. Global across event types. |
| `Add-AuditLineToFile` *(internal)* | `-Path -Line -HeaderLine -Config` | `void` core appender: `Global\SharedAccountAuth_Write` mutex + `CreateNew` header-race (header written only in the create path) else `Append`, `FileShare.Read`, BOM-less UTF-8, retry/backoff + jitter; **throws** on unreachable/denied so the caller spools. |

---

## 2. Install steps

Carried out offline. The repository is one self-contained tree; copy it whole.

### A. On the file server (admin, once)

1. **Create the audit directory** on a local volume, e.g. `D:\audit`, and share it (e.g. `\\server\share\audit`).
2. **Apply append-only ACLs** with `deploy/Setup-SharePermissions.ps1`. Use the **local** path on the server, not the UNC:

   ```powershell
   # Dry run first
   .\deploy\Setup-SharePermissions.ps1 -LogDir 'D:\audit' `
       -SharedPrincipal 'LAB\LabSharedGroup' `
       -AuditorsPrincipal 'LAB\Auditors' -WhatIf

   # Apply
   .\deploy\Setup-SharePermissions.ps1 -LogDir 'D:\audit' `
       -SharedPrincipal 'LAB\LabSharedGroup' `
       -AuditorsPrincipal 'LAB\Auditors'
   ```

   This grants the shared principal **CreateFiles + AppendData** but **DENIES ReadData + Delete**, grants `Auditors` Read, and grants the admin principal (default `BUILTIN\Administrators`) FullControl. The script prints the resulting ACL. `-AdminPrincipal` overrides the FullControl principal.

3. **Place the roster** at `\\server\share\audit\roster.csv` (see [section 9](#9-auditor-review) and the roster format below). The shared account needs **read-only** access to it.

### B. On each workstation (admin, per PC)

4. **Copy the whole tree** to a fixed, protected location — recommended `C:\Program Files\SharedAccountAuth\` (or any AppLocker-allowed dir; see [STIG](#6-stig-considerations)). Keep the `src/`, `config/`, `deploy/`, `tasks/`, `sample/`, `assets/` layout intact — scripts locate siblings via `$PSScriptRoot`.

5. **Edit `config\AuditConfig.psd1`** for the site. At minimum:
   - `LogPath` → the central CSV UNC, e.g. `\\server\share\audit\access_log.csv`
   - `RosterPath` → the central roster UNC, e.g. `\\server\share\audit\roster.csv`
   - **`SharedAccount`** → the one shared account this prompt applies to (e.g. `.\LabShared`). **Required** — `Get-AuditConfig` throws if it is blank.
   - Optionally `AuthDomain` (default `.` = local SAM), `RetryDelayMs`, `DebounceSeconds`, retry tunables, and UI text.
   - **Classification banner:** `ClassificationLevel` sets the banner color tier; `ClassificationText` overrides the displayed string (defaults to the level name); `ClassificationForeground` / `ClassificationBackground` override individual colors. Built-in level→color defaults:

     | `ClassificationLevel` | Foreground | Background |
     |---|---|---|
     | `UNCLASSIFIED` | Black | `#007A33` (green) |
     | `CUI` | White | `#512888` (purple) |
     | `CONFIDENTIAL` | White | `#003087` (blue) |
     | `SECRET` | White | `#C8102E` (red) |
     | `TOP SECRET` | Black | `#FF8C00` (orange) |

   - **Logo:** `LogoPath` — absolute or `$PSScriptRoot`-relative path to a PNG/BMP displayed in the banner (e.g. `assets\GE-Aerospace-Emblem.png` relative to the install root). Leave blank to hide the logo image.

   Leave `RosterCachePath`, `SpoolDir`, `DiagLogPath`, `StateDir` blank to derive them under `LocalRoot` (`C:\ProgramData\SharedAccountAuth`).

6. **Run the installer.** It self-elevates (UAC prompt), registers both scheduled tasks scoped to the shared account, then runs a preflight that surfaces the otherwise-silent runtime failure modes:

   ```powershell
   .\deploy\Install-Audit.ps1
   # or pin the scoped account / a non-default config:
   .\deploy\Install-Audit.ps1 -SharedAccount '.\LabShared'
   # validate an existing install without changing anything:
   .\deploy\Install-Audit.ps1 -ValidateOnly
   ```

   Registration creates `SharedAccountAuth-Logon` (LogonTrigger) and `SharedAccountAuth-Unlock` (SessionStateChange → SessionUnlock), both with `UserId` = the resolved shared account, an `InteractiveToken` / `LeastPrivilege` principal, and writes reference XML to `tasks/`.

   The **preflight** reports OK/WARN/FAIL for: config valid + `SharedAccount` set; install files present; the central `LogPath` UNC is reachable (else runtime spools locally); the roster loads and **every roster `Username` has a matching local account on this PC** — the username is what `LogonUser` validates against the local SAM, so anyone missing is listed and could never authenticate here; and both tasks are registered + enabled. Resolve any `FAIL` before relying on the prompt.

   > **No signing.** The scripts are not Authenticode-signed — the launcher runs the `.ps1` with `-ExecutionPolicy Bypass` and AppLocker governs the install directory (see [STIG](#6-stig-considerations)). `Install-Audit.ps1` just orchestrates `deploy\Register-AuditTasks.ps1`, which you can still run directly (elevated) to register without the installer. To remove the tasks: `.\deploy\Unregister-AuditTasks.ps1`.

   **Prefer a GUI?** Run `.\deploy\Install-Audit-GUI.ps1` instead — a single-pane window that self-elevates, prefills from the current config, lets you Test each path and preview the roster (read-only, with a "has a local account here?" column), then writes the config (backing up the prior file to `AuditConfig.psd1.bak`) and registers the tasks. It runs the same preflight as the CLI. The CLI remains for scripted/silent installs.

7. **Test** as described in [section 7](#7-testing) before relying on it (the installer's preflight is a fast first check; the sign-out/in + unlock test confirms the end-to-end flow).

---

## 3. Authentication model

Identity is proven by **picking a name from the allow-list roster and entering that person's own local-account password**. The selected roster row maps to a local `Username`, which is validated against the **local SAM** — no domain controller is required.

### Local-SAM validation via `LogonUser`

`Test-AuditCredential` (`src/AuditCommon.ps1`) P/Invokes `advapi32::LogonUser` (and `kernel32::CloseHandle`) via `Add-Type`. The username may arrive as `MACHINE\user`, `.\user`, or bare `user`; any prefix up to the last backslash is stripped and the **bare username** is passed with `-Domain` (default `.`, the local machine SAM). Success on a logon of *any* tried type → `CloseHandle(token)` → `$true`. All types fail → `$false`.

### The NETWORK → CLEARTEXT → INTERACTIVE fallback (and the STIG reason)

Logon types are tried strictly in this order:

```
LOGON32_LOGON_NETWORK (3)  →  LOGON32_LOGON_NETWORK_CLEARTEXT (8)  →  LOGON32_LOGON_INTERACTIVE (2)
```

A STIG-hardened machine commonly sets **"Deny access to this computer from the network"** for local accounts, which makes a perfectly valid local credential **fail** `LOGON32_LOGON_NETWORK(3)`. Falling back to `NETWORK_CLEARTEXT(8)` and then `INTERACTIVE(2)` still verifies the password without depending on the network-logon right. Trying the lighter types first avoids needlessly exercising the interactive-logon right when network logon is allowed.

### SecureString handling (never logged)

The WPF `PasswordBox` yields a `SecureString`. `Test-AuditCredential` converts it to plaintext **only at the P/Invoke boundary** via `Marshal::SecureStringToBSTR` / `PtrToStringBSTR`, and **zeroes and frees** the BSTR with `Marshal::ZeroFreeBSTR` in a `finally`. The plaintext lives only inside that one call. A password is **never** placed in a variable that outlives the call, and **never** written to the diag log, the CSV, or any spool file. `Write-AuditDiag` is documented to never receive credential material.

### Local lockout-policy note (attempts are uncapped)

By design, **failed attempts are logged (`AuthResult=Failure`) with no cap** — the lock holds until a valid credential is entered. Each failed `LogonUser` may emit a Security **4625** and **increment the local account's bad-password count**, so if the machine has a **local account lockout policy**, repeated wrong passwords can lock out that personal account per policy. The configurable inter-attempt delay (`RetryDelayMs`, default 1000 ms) slows brute force. Tune `RetryDelayMs` and the local lockout threshold together for your environment.

---

## 4. Credential-provider vs modal tradeoff (honest)

This tool is a **post-logon, in-session modal lockdown**, **not** a pre-logon credential provider.

- **Post-logon, not pre-logon:** the shared session is already logged in when the window appears. The auth step verifies **who is using the already-logged-in shared session**, not who may log on. It is an in-session accountability gate, not a logon gate.
- **Known bypass:** even with password auth, a determined user can reach **Ctrl+Alt+Del → Task Manager** and kill the PowerShell/`wscript` process, or use other OS-level escapes, to reach the desktop without authenticating. The window re-asserts `Topmost` on deactivation and swallows `Esc`/Alt+F4/close, but it cannot stop a Secure-Attention-Sequence escape. This is documented honestly rather than hidden.
- **Why a credential provider is out of scope:** true *pre-logon* enforcement (no desktop until authenticated, with SAS handled) requires a custom **Credential Provider** — a compiled COM component. That cannot be built or installed in this fully offline, built-ins-only, no-external-modules environment, so it is out of scope here.

Treat this as a strong deterrent and a reliable **audit record of who claimed the session**, not as an unbypassable lock.

---

## 5. Shared-account-only behavior

The prompt is guaranteed to appear **only** under the one configured shared account through **two independent controls**:

1. **Primary: trigger `UserId` scoping.** `Register-AuditTasks.ps1` registers both tasks with the trigger scoped to the shared account:
   - `SharedAccountAuth-Logon`: `<LogonTrigger><UserId>SharedAccount</UserId></LogonTrigger>` — fires only for the shared account's logon.
   - `SharedAccountAuth-Unlock`: `<SessionStateChangeTrigger><StateChange>SessionUnlock</StateChange><UserId>SharedAccount</UserId></SessionStateChangeTrigger>` — fires only on the shared account's unlock.

   So an individual logging on with their **personal** account does not trigger the task at all.

2. **Backstop: the prompt self-check.** At startup, `SharedAccountAuth.ps1` calls `Test-AuditIsSharedAccount -Config`. If the current user's **leaf** account name (after the last backslash) does not match the `SharedAccount` leaf (case-insensitive), it writes a diag breadcrumb (`Get-AuditCurrentUser`) and **exits without ever creating the window**. This catches a mis-registered or stray task and ensures personal logins never see the prompt.

### How to set `SharedAccount`

Edit `config\AuditConfig.psd1`:

```powershell
SharedAccount = '.\LabShared'   # MACHINE\name, .\name, or bare name — only the leaf is compared
```

The value can be `MACHINE\name`, `.\name`, or a bare `name`; `Test-AuditIsSharedAccount` compares **only the leaf** name (case-insensitive), so `LAB-PC01\LabShared` matches `.\LabShared` or `LabShared`. `SharedAccount` is **required** — `Get-AuditConfig` throws if it is blank, and the self-check refuses to show a window without it. When registering tasks you may also pass `-SharedAccount` to `Register-AuditTasks.ps1` to override the config value for the trigger `UserId`.

---

## 6. STIG considerations

- **Execution policy + no signing.** The scripts are **not** Authenticode-signed. The launcher runs the prompt with `-ExecutionPolicy Bypass` ([`Launch-SharedAccountAuth.vbs`](src/Launch-SharedAccountAuth.vbs)), which also avoids the "Mark of the Web" block on a `.ps1` copied in from a ZIP/removable media (a blocked script = no prompt = silent failure). Because nothing is signed, **AppLocker is the integrity control** (next bullet), not execution policy. A machine-level GPO execution policy, if set, **overrides** the launcher's process-scope `Bypass`; if a site mandates signing, set the launcher token to `AllSigned`/`RemoteSigned` and sign the `*.ps1`/`*.psd1` yourself (re-signing after every edit, including the psd1).
- **AppLocker pathing.** Two locations matter and should be covered by AppLocker rules:
  - the **local state root** `C:\ProgramData\SharedAccountAuth\` (cache/spool/diag/state) — chosen deliberately under ProgramData so it is path-addressable for AppLocker while being writable by the shared user;
  - the **install/script directory** (e.g. `C:\Program Files\SharedAccountAuth\`) holding `src\`, including the `.ps1` scripts and `Launch-SharedAccountAuth.vbs`. Nothing here is Authenticode-signed, so AppLocker (script/path rules) is the integrity control — whitelist this directory and block arbitrary scripts elsewhere.
- **Least-privilege task principal.** Both tasks run with `<LogonType>InteractiveToken</LogonType>` and `<RunLevel>LeastPrivilege</RunLevel>` — an interactive session (≠ 0), **no elevation**.
- **No audit-policy dependency for unlock.** Unlock detection uses the native Task Scheduler `SessionStateChangeTrigger`/`SessionUnlock`, so it does **not** depend on enabling Security audit policy or on event 4801. (4801 is documented only as an alternative.)
- **4625 from failed validations.** Each wrong-password attempt calls `LogonUser` and so can generate a Security **4625** and bump the local bad-password count (see [section 3](#3-authentication-model)). This is expected and auditable under the "log failures, no cap" policy; correlate 4625s with the CSV's `AuthResult=Failure` rows.
- **Keyboard hook (shell-hotkey suppression).** While the prompt is displayed, a low-level `WH_KEYBOARD_LL` hook (`SetWindowsHookEx`) swallows the following key combinations: Win, Win+R, Alt+Tab, Ctrl+Esc, and Ctrl+Shift+Esc. This closes the user-mode routes to the Start menu, Run dialog, task switcher, and Task Manager via keyboard. The hook is installed on `Loaded` and removed on `Closed`.
- **Temporary Task Manager disable.** Alongside the keyboard hook, the prompt sets `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr=1` on `Loaded` and removes the value on `Closed`, preventing Task Manager from opening via any user-mode route while the prompt is up.
- **Credential-lockout fix (one strike per attempt).** `Test-AuditCredential` now stops trying further logon types as soon as `LogonUser` returns `ERROR_LOGON_FAILURE` (1326 — wrong password). Previously it tried NETWORK(3) → NETWORK_CLEARTEXT(8) → INTERACTIVE(2) on every attempt, so a single wrong password incremented the account's bad-password count up to three times — locking the account after only 1–2 tries. Now a wrong password costs one strike, so the operator gets their full lockout-threshold of attempts. The STIG network-logon-denied fallback is preserved: on `ERROR_LOGON_TYPE_NOT_GRANTED` (1385) it still falls through to the next logon type.
- **Raised task priority.** The scheduled tasks' XML `<Priority>` was changed from 7 to 4 (Task Scheduler priority is 0–10, lower = higher), so the tasks fire earlier in session init and the desktop-visible interval before the prompt is reduced (not eliminated).
- **Honest ceiling.** The hook + `DisableTaskMgr` close the user-mode shell routes. They do **not** suppress **Ctrl+Alt+Del** (the kernel Secure Attention Sequence — SAS — cannot be intercepted by user-mode code). The Sign-out option on the Ctrl+Alt+Del screen remains reachable; choosing it ends the shared session (the session terminates — it is **not** an authentication bypass, and the next logon will re-trigger the prompt). Some desktop flash before the window appears is intrinsic and reduced but not fully eliminated; true pre-desktop enforcement requires a credential provider or a GPO synchronous logon script (both out of scope for this offline, built-ins-only tool).

---

## 7. Testing

Perform these on a representative workstation after install. Inspect `C:\ProgramData\SharedAccountAuth\diag\audit-diag.log` and the central CSV (read it from an Auditors account, since the shared account cannot).

1. **Logon trigger — fires for the shared account.** Sign out and sign back in **as the shared account** (`SharedAccount`). The full-screen prompt must appear. Confirm a `Logon` row is written.
2. **Logon trigger — does NOT fire for a personal account.** Sign in with a **personal** account. The prompt must **not** appear (trigger `UserId` scoping; the self-check is the backstop). The diag log will show `not shared account ... exiting` only if a task somehow fired.
3. **Unlock trigger.** As the shared account, press **Win+L**, then unlock. The prompt must appear; confirm an `Unlock` row.
4. **Correct password.** Pick your name, enter the **correct** local password, Confirm. The window must release and a row with `AuthResult=Success` must appear.
5. **Wrong password.** Pick your name, enter a **wrong** password, Confirm. The status line must show "incorrect password", the field clears, there is a brief delay (`RetryDelayMs`), and the window **stays locked** and lets you retry. A row with `AuthResult=Failure` must appear, and the lock must hold until a correct password is entered.
6. **Share down → spool + flush.** Make `LogPath` unreachable (e.g. disconnect the share or rename the target). Authenticate: the window still releases and the row is **spooled** to `C:\ProgramData\SharedAccountAuth\spool\*.csv` (diag shows "Spooled row"). Restore the share and trigger another successful write — `Invoke-AuditSpoolFlush` runs opportunistically and the spooled rows are appended and the spool files deleted (diag shows "Flushed spool file").

---

## 8. Multi-PC deployment

Many workstations append to the **same** central CSV.

- **Identical config and paths everywhere.** Deploy the same `AuditConfig.psd1` (same `LogPath`, `RosterPath`, `LocalRoot`, `SharedAccount`) to every PC. The same install path and `C:\ProgramData\SharedAccountAuth\` layout everywhere keeps AppLocker rules and troubleshooting uniform.
- **`ComputerName` differentiates rows.** There is no per-PC config divergence needed: each row's `ComputerName` column (from `Get-AuditComputerName`, never blank) identifies the machine. Auditors filter/sort by it to see per-PC activity.
- **Concurrency is safe.** `Add-AuditLineToFile` uses a `CreateNew` header-race (the header is written exactly once, by whichever machine wins the create), `FileShare.Read` + retry/backoff + jitter for cross-machine appends, and BOM-less UTF-8 (a mid-file BOM from a concurrent append would corrupt rows). The `Global\SharedAccountAuth_Write` mutex only serializes writers on the **same** machine — it does not coordinate across machines over SMB; that is handled by the open-mode + retry loop. Spool flush is **append-only with no dedup** (at-least-once delivery; rare duplicate rows are acceptable and visible to auditors).
- **Roster usernames must exist locally on every PC.** Because authentication is against each machine's **local SAM**, every roster `Username` that should be able to authenticate on a given PC must exist as a **local account** on that PC. A person can only sign in on machines where their local account exists.

---

## 9. Auditor review

The central CSV is **read-only** to the `Auditors` group (the shared account cannot read it). Open it from an account in `Auditors`:

```
\\server\share\audit\access_log.csv
```

Header (written once, by the create-race winner):

```
TimestampUTC,TimestampLocal,Username,LastName,FirstName,ComputerName,EventType,AuthResult
```

Column meanings:

| Column | Meaning |
|---|---|
| `TimestampUTC` | UTC instant, `yyyy-MM-ddTHH:mm:ssZ`. |
| `TimestampLocal` | Local time of the writing PC, `yyyy-MM-dd HH:mm:ss`. |
| `Username` | The **verified** local username on a success — or the **selected roster username** on a failed attempt. |
| `LastName` / `FirstName` | The roster name fields for the selected person. |
| `ComputerName` | Which machine the access occurred on (never blank; `UNKNOWN-HOST` if unresolved). |
| `EventType` | `Logon` or `Unlock`. |
| `AuthResult` | `Success` or `Failure`. |

**Passwords never appear in any column.** All fields are CSV-escaped (quoted, embedded quotes doubled), so names like `O'Brien`, `Garcia-Lopez`, and `"Smith, Jr"` are stored safely.

Typical review actions: open in Excel / `Import-Csv`; filter by `ComputerName` for per-PC activity; filter `AuthResult=Failure` to spot repeated failed attempts (correlate with Security 4625s); sort by `TimestampUTC` for a timeline; group by `Username`/`EventType`. Rare duplicate rows from at-least-once spool delivery are expected; dedupe on `(TimestampUTC, Username, ComputerName, EventType, AuthResult)` if needed.

### Roster format (`sample/roster.csv`)

Lives at `RosterPath` (readable by the shared account). The header row is required. **Only `Username` is required** — it is the person's **local** account name validated against the SAM and the value logged in the CSV. `LastName` and `FirstName` are optional; if present they are stored in the log and shown in the name drop-down (as `LastName, FirstName (username)`); if absent the drop-down shows the username. Extra columns are ignored, blank rows skipped.

Minimal (username-only) format — matches `sample/roster.csv`:

```csv
Username
asmith
bnguyen
cobrien
dgarcia
```

Full format with optional name columns:

```csv
LastName,FirstName,Username
Smith,Alice,asmith
Nguyen,Bao,bnguyen
O'Brien,Connor,cobrien
Garcia-Lopez,Diego,dgarcia
```

Mixed rows (some with names, some without) are accepted — any row missing `LastName`/`FirstName` simply shows the username in the drop-down.

Whoever owns access control edits this file at `RosterPath`. Remember: **every `Username` here must exist as a local account on each PC** where that person should be able to authenticate.

---

## 10. Troubleshooting

The **local diagnostics log** is the first stop — the central CSV is unreadable to the shared account, so per-PC troubleshooting happens here:

```
C:\ProgramData\SharedAccountAuth\diag\audit-diag.log
```

Each line is `yyyy-MM-dd HH:mm:ss [LEVEL] [PID] message`. `Write-AuditDiag` never throws and never logs credentials.

| Symptom | Likely cause / what to check |
|---|---|
| Prompt never appears for the shared account | Tasks not registered or disabled — re-run `Register-AuditTasks.ps1`, check `SharedAccountAuth-Logon`/`SharedAccountAuth-Unlock` exist and are enabled. Diag may show the self-check exit if the running user's leaf name ≠ `SharedAccount`. |
| Prompt appears on a personal login | Trigger `UserId` not scoped — re-register with the correct `-SharedAccount`. The self-check should still exit it; verify `SharedAccount` in the psd1. |
| Task does not fire / "session 0" | The principal must be `InteractiveToken` in a real interactive session (≠ 0). A task running in session 0 cannot show a window — confirm the registered principal and `RunLevel=LeastPrivilege`. |
| `Get-AuditConfig` throws | `SharedAccount` missing/blank in `AuditConfig.psd1`, or the psd1 path is wrong. The diag log records the config error before the throw. |
| Rows are spooling, not landing centrally | Share unreachable or denied — diag shows "Central append failed; spooling". Restore `LogPath`; the next successful write flushes the spool (`Invoke-AuditSpoolFlush`, "Flushed spool file"). Inspect `C:\ProgramData\SharedAccountAuth\spool\`. |
| "Roster unavailable" / Confirm stays disabled | Central `RosterPath` unreadable **and** no local cache yet (`Source=none`) — diag shows "Roster unavailable from central and cache". Fix share read access; once a central read succeeds the cache refreshes. Also verify the roster has at minimum a `Username` column in its header. |
| Correct password rejected | Likely STIG network-logon denial interacting with logon types, or the roster `Username` has no matching **local** account on this PC. `Test-AuditCredential` already falls back NETWORK→CLEARTEXT→INTERACTIVE; confirm the local account exists and the password is the **local** account's password (`AuthDomain` should be `.`). |
| Scripts won't run / blocked | A machine GPO execution policy can override the launcher's `Bypass`, or files copied from a ZIP carry "Mark of the Web". Check `Get-ExecutionPolicy -List`; clear MOTW with `Get-ChildItem -Recurse <install> \| Unblock-File`. |
| Personal account getting locked out | Repeated wrong passwords increment the local bad-password count (4625). Expected under "no cap" policy; tune `RetryDelayMs` and the local lockout threshold. |

---

## 11. Known limitations / bypasses

Documented honestly — do not assume more than the design provides.

- **Not an unbypassable lock.** This is a post-logon modal, not a credential provider. A low-level keyboard hook blocks Win / Win+R / Alt+Tab / Ctrl+Esc / Ctrl+Shift+Esc, and Task Manager is temporarily disabled while the prompt is up — closing the user-mode shell-escape routes. However, **Ctrl+Alt+Del (the kernel SAS) cannot be intercepted by user-mode code**. The Sign-out option on the Ctrl+Alt+Del screen remains reachable; using it ends the shared session (the session terminates — this is **not** an authentication bypass, and the next logon will re-trigger the prompt). True pre-logon enforcement (no desktop until authenticated, with SAS handled) requires a credential provider (out of scope offline).
- **Verifies session use, not logon.** Auth confirms **who is using the already-logged-in shared session**, not who may log on. The shared account is already signed in when the window appears.
- **Local accounts only.** Personal passwords are validated against each machine's **local SAM**. A person can only authenticate on PCs where their local account exists; there is no domain validation.
- **Uncapped attempts + lockout side effects.** Failed attempts are logged with no cap; each may emit a 4625 and increment the local bad-password count, so a local lockout policy can lock out a personal account. The `RetryDelayMs` delay only slows brute force.
- **Multi-monitor coverage is rectangular.** The window spans the virtual screen bounds (`SystemParameters.VirtualScreen*`), which covers standard rectangular layouts; exotic non-rectangular monitor arrangements may leave gaps (the design notes per-monitor blocker windows as the alternative).
- **At-least-once delivery, rare duplicates.** Spool flush is append-only and never reads the central log, so a crash between append and spool-delete can produce a **duplicate row**. Acceptable and visible to auditors; dedupe on review if needed.
- **Roster trust.** Anyone who can write the central `roster.csv` controls the allow-list. Protect `RosterPath` write access; the shared account only needs read.
- **Diag log is local.** Troubleshooting evidence lives on each PC under `C:\ProgramData\SharedAccountAuth\diag\`; it is not centralized.
