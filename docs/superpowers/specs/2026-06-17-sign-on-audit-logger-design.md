# Shared-Account Sign-On Audit Logger — Design Spec

**Date:** 2026-06-17
**Status:** Approved (rev 3 — 2026-06-18: dropped script signing — scripts run unsigned via `-ExecutionPolicy Bypass`, AppLocker is the integrity control; replaced `Sign-Scripts.ps1` with `deploy/Install-Audit.ps1`, a self-elevating one-command installer + preflight validator. rev 2 — adds local-credential authentication + shared-account scoping)
**Target:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF/WinForms). **No internet** at build or runtime. **No external modules**. Built-in components only.

---

## 1. Purpose

On a **shared local Windows account**, every **sign-on (logon)** and every **workstation unlock** must present a hard-enforced, full-screen, topmost, un-closable prompt. The user **selects their name from an approved roster and authenticates with their own personal (local) account password**; only on a successful credential check is access granted and the event appended to a **central append-only CSV** on a locked-down network share (the shared account can **write/append but not read or modify** it). Many PCs append to the same central CSV; each row records the **verified username**, the person's name, **which machine** the access occurred on, the event type, and the auth result. The prompt appears **only under the designated shared account** — never on individuals' personal logins.

## 2. Locked Decisions

| Decision | Choice |
|---|---|
| Unlock trigger | **Native Task Scheduler `SessionStateChangeTrigger` → `SessionUnlock`** (no Security audit-policy dependency). 4801 documented as alternative only. |
| Lockdown level | **Baseline modal**: Topmost / `WindowStyle=None` / spans all monitors / no close-minimize / Alt+F4·Esc·close disabled / re-assert topmost on deactivate. No hooks, no policy edits. Known bypasses documented. |
| Roster source | **Central read-only share, with last-known-good local cache fallback.** Refresh cache on every successful central read. |
| Signing posture | **Unsigned** (rev 3): scripts run via `-ExecutionPolicy Bypass`; **AppLocker** over the install dir is the integrity control, not code signing. Sites that mandate signing can switch the launcher token to AllSigned/RemoteSigned and sign the `.ps1`/`.psd1`. |
| **Personal account type** | **Local accounts** (`.\user`, validated against the local SAM). No domain controller required. |
| **Identity proof** | **Pick name from roster (allow-list) + personal password.** `roster.csv` gains a `Username` column; the selected name maps to a local username that is authenticated. No free text. |
| **Failed attempts** | **Logged** (`AuthResult=Failure`), **no cap**, with a short configurable inter-attempt delay. Lock holds until a valid credential. |
| **Scope** | **Shared account only** — tasks scoped to the shared account via trigger `UserId`, **plus** a self-check guard in the prompt that exits if the current user isn't the configured shared account. |

## 3. Architecture & Data Flow

```
Logon  ──┐  (triggers scoped to SharedAccount only)
         ├─► Task Scheduler (runs as the shared INTERACTIVE user, session ≠ 0)
Unlock ──┘        │
                  ▼
        Launch-SharedAccountAuth.vbs <EventType>   (hides the PowerShell console; wscript run-style 0)
                  │
                  ▼
        SharedAccountAuth.ps1 -EventType <Logon|Unlock>
                  │  dot-sources src\AuditCommon.ps1
                  ▼
   0. SHARED-ACCOUNT SELF-CHECK: if current user != config SharedAccount → log diag + EXIT (no window).
   1. Load config (config\AuditConfig.psd1)
   2. Debounce check (suppress duplicate prompt within DebounceSeconds)
   3. Resolve ComputerName  (env → DNS → UNKNOWN-HOST)
   4. Load roster (central → cache fallback; refresh cache on success)  [LastName,FirstName,Username]
   5. Show fullscreen lockdown WPF window: type-to-filter name ComboBox + PasswordBox
   6. On Confirm → authenticate selected username + password (Test-AuditCredential, local SAM):
        success → Write-AuditRow(AuthResult=Success) → close
        failure → Write-AuditRow(AuthResult=Failure) → clear password, brief delay, stay locked, retry
                  │
                  ▼
   Write-AuditRow → central CSV append (create-header-race + retry/backoff + local mutex)
                  │  on share failure ▼
   Spool to C:\ProgramData\SharedAccountAuth\spool\*.csv  (flushed opportunistically next run)
```

## 4. Repository Layout

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
│  ├─ Register-AuditTasks.ps1    # registers Logon + SessionUnlock tasks SCOPED to the shared account
│  ├─ Unregister-AuditTasks.ps1  # removes both tasks
│  └─ Setup-SharePermissions.ps1 # admin-once: append-only ACLs on the log dir
├─ sample/
│  └─ roster.csv                 # LastName,FirstName,Username sample
├─ tasks/
│  ├─ SharedAccountAuth-Logon.xml      # reference export of the Logon task
│  └─ SharedAccountAuth-Unlock.xml     # reference export of the Unlock task
├─ docs/superpowers/specs/2026-06-17-sign-on-audit-logger-design.md
└─ README.md
```

## 5. Configuration Schema — `config/AuditConfig.psd1`

`Import-PowerShellDataFile`-compatible hashtable:

```powershell
@{
    # --- Central share paths (UNC). Shared account: append-only on LogPath dir; read-only on RosterPath. ---
    LogPath          = '\\server\share\audit\access_log.csv'
    RosterPath       = '\\server\share\audit\roster.csv'

    # --- Local state root (writable by the shared user; under ProgramData for AppLocker pathing) ---
    LocalRoot        = 'C:\ProgramData\SharedAccountAuth'
    RosterCachePath  = ''      # blank => $LocalRoot\cache\roster.csv
    SpoolDir         = ''      # blank => $LocalRoot\spool
    DiagLogPath      = ''      # blank => $LocalRoot\diag\audit-diag.log
    StateDir         = ''      # blank => $LocalRoot\state

    # --- Shared-account scoping (REQUIRED) ---
    SharedAccount    = '.\LabShared'   # the ONE shared account this prompt applies to (MACHINE\name, .\name, or name)

    # --- Authentication (local accounts) ---
    AuthDomain       = '.'     # passed to LogonUser; '.' = local machine SAM
    RetryDelayMs     = 1000    # delay after a failed attempt (slows brute force; no cap on attempts)

    # --- Behaviour tunables ---
    DebounceSeconds  = 5
    WriteRetryCount  = 10
    WriteRetryBaseMs = 50

    # --- UI text ---
    AppName          = 'SharedAccountAuth'
    WindowTitle      = 'Shared Account — Authenticate to Continue'
    WindowSubtitle   = 'Select your name and enter your personal account password. This window cannot be dismissed.'
}
```

`Get-AuditConfig` fills blank derived paths, ensures local dirs exist, returns the hashtable. `SharedAccount` is required (a clear error/diag if missing).

## 6. `src/AuditCommon.ps1` — Public API (the contract)

`Verb-Noun`, comment-help-documented, no external modules, diagnostics never throw. **Diagnostics MUST NEVER log a password or any credential material.**

| Function | Signature (params) | Returns / behaviour |
|---|---|---|
| `Get-AuditConfig` | `[-ConfigPath <string>]` | Hashtable. Loads psd1, fills derived paths, creates `cache/spool/diag/state` dirs. Validates `SharedAccount` present. |
| `Write-AuditDiag` | `-Config -Message [-Level Info\|Warn\|Error]` | Appends `yyyy-MM-dd HH:mm:ss [LEVEL] [PID] message` to diag log. **Never throws. Never receives/writes passwords.** |
| `Get-AuditComputerName` | none | `$env:COMPUTERNAME` → `[Net.Dns]::GetHostName()` → `UNKNOWN-HOST`. **Never blank.** |
| `Get-AuditCurrentUser` | none | Current identity as `DOMAIN\user` / `MACHINE\user` via `[Security.Principal.WindowsIdentity]::GetCurrent().Name`. |
| `Test-AuditIsSharedAccount` | `-Config` | `$true` if the current user's **leaf account name** equals `SharedAccount`'s leaf name (case-insensitive). Used by the prompt's self-check. |
| `ConvertTo-AuditCsvField` | `-Value <string>` | CSV-escaped (quote, double embedded quotes). Null → `""`. |
| `Format-AuditRow` | `-TimestampUtc -TimestampLocal -Username -LastName -FirstName -ComputerName -EventType -AuthResult` | One escaped CSV line. |
| `Get-AuditRosterEntries` | `-Config` | `.Entries` (array of `@{LastName;FirstName;Username;Display}`, sorted, deduped) + `.Source` (`central`\|`cache`\|`none`). Validates `LastName,FirstName,Username`; central success refreshes cache. |
| `Test-AuditCredential` | `-Username <string> -Password <SecureString> [-Domain <string>]` | `$bool`. Validates a **local** credential via Win32 `LogonUser` trying logon types **NETWORK(3) → NETWORK_CLEARTEXT(8) → INTERACTIVE(2)** in order (covers STIG "deny network logon for local accounts"). Converts the SecureString to plaintext only at the P/Invoke boundary and **zeroes it immediately**. Never logs the password. |
| `Write-AuditRow` | `-Config -Username -LastName -FirstName -EventType -AuthResult [-TimestampUtc <datetime>] [-ComputerName <string>]` | Builds the row, appends to central; on share failure spools. Returns `@{ Written; Spooled; Target }`. |
| `Invoke-AuditSpoolFlush` | `-Config` | Append-only flush of spool files; delete on confirmed success; never read central; never throw. |
| `Test-AuditDebounce` | `-Config` | `$true` if a prompt was shown within `DebounceSeconds` (`state\last-prompt.txt`, UTC ticks); updates marker to now when returning `$false`. Global across event types. |
| `Add-AuditLineToFile` *(internal)* | `-Path -Line -HeaderLine -Config` | Core appender (see §7). Throws on unreachable/denied so callers spool. |

### Encoding rule (critical)
All central-CSV writes use **`New-Object System.Text.UTF8Encoding($false)`** (UTF-8 **without BOM**) — a mid-file BOM from concurrent appends would corrupt rows.

### Credential-validation detail (`Test-AuditCredential`)
- `Add-Type` P/Invoke `advapi32::LogonUser` + `kernel32::CloseHandle`.
- Domain default `.` (local SAM). Username may arrive as `MACHINE\user`, `.\user`, or `user` — strip any prefix; pass bare username + domain `.`.
- Convert `SecureString` → BSTR via `Marshal::SecureStringToBSTR`, read with `PtrToStringBSTR`, and **`Marshal::ZeroFreeBSTR`** in `finally`. Plaintext lives only inside the call.
- Try logon types in order; **success on any** → `CloseHandle(token)`, return `$true`. All fail → `$false`.
- Comment: each failed `LogonUser` may emit a Security 4625 and increment the local account's bad-password count (local lockout policy may apply). This is acceptable/auditable per the chosen "log failures, no cap" policy; the inter-attempt delay (`RetryDelayMs`) slows abuse.

## 7. Concurrency, Header, Spool — Precise Algorithm

### `Add-AuditLineToFile`
1. **Local mutex (same-machine only):** named `System.Threading.Mutex` `Global\SharedAccountAuth_Write`, short timeout, acquire/release in try/finally. *(Comment: a mutex does NOT coordinate across machines over SMB.)*
2. **Cross-machine = open-mode + retry.** Loop up to `WriteRetryCount`:
   - **Create-header-race:** `FileStream(Path, CreateNew, Write, Read)` → success ⇒ this machine created it ⇒ write `HeaderLine` then `Line` (BOM-less UTF-8) ⇒ done.
   - `CreateNew` throws because file exists ⇒ fall to append.
   - **Append:** `FileStream(Path, Append, Write, Read)` → write `Line` ⇒ done.
   - sharing-violation/transient `IOException` ⇒ sleep `min(WriteRetryBaseMs*2^attempt, 2000)` + jitter (`Get-Random`), retry.
   - `DirectoryNotFound`/`UnauthorizedAccess`/unreachable ⇒ **throw** (caller spools).
   - dispose stream in `finally`.

**Header without reading:** header written **only** in the `CreateNew` success path. Exactly one machine wins the create race; all others append headerless. Never duplicated, never requires a read.

### `Write-AuditRow`
- `TimestampUtc` = `[DateTime]::UtcNow` → `yyyy-MM-ddTHH:mm:ssZ`; `TimestampLocal` → `yyyy-MM-dd HH:mm:ss`.
- `ComputerName` defaults to `Get-AuditComputerName` (never blank).
- `HeaderLine = 'TimestampUTC,TimestampLocal,Username,LastName,FirstName,ComputerName,EventType,AuthResult'`.
- Append via `Add-AuditLineToFile`; on success `Written=$true` + opportunistic `Invoke-AuditSpoolFlush`; on throw spool to `spool\<ComputerName>-<utcTicks>-<rand>.csv` (no header) → `Spooled=$true`.

### Spool flush
Append each spooled line to central (append-only, **no dedup**, never read central); delete on confirmed success, else leave for next run. At-least-once delivery; rare duplicates acceptable. Never throws.

## 8. CSV Format

Header (written once, by the create-race winner):
```
TimestampUTC,TimestampLocal,Username,LastName,FirstName,ComputerName,EventType,AuthResult
```
- `TimestampUTC` `yyyy-MM-ddTHH:mm:ssZ` · `TimestampLocal` `yyyy-MM-dd HH:mm:ss`
- `Username` = verified local username (or the selected roster username on a failed attempt)
- `EventType` = `Logon` | `Unlock` · `AuthResult` = `Success` | `Failure`
- All fields CSV-escaped (quoted, embedded quotes doubled). **Passwords never appear in any column.**

## 9. `src/SharedAccountAuth.ps1` — Lockdown Prompt Spec

**Params:** `-EventType` (`Logon`|`Unlock`, required), `[-ConfigPath]`.

**Startup (in order):**
1. Dot-source `AuditCommon.ps1` (via `$PSScriptRoot`); `Get-AuditConfig`. Wrap all in try/catch → on fatal error `Write-AuditDiag Error` and degrade safely.
2. **Shared-account self-check:** if `-not (Test-AuditIsSharedAccount -Config)` → `Write-AuditDiag Info "not shared account ($(Get-AuditCurrentUser)); exiting"` and **exit without showing the window.** *(This guarantees the prompt never appears on individuals' personal logins, even if a task misfires.)*
3. **Debounce:** if `Test-AuditDebounce` → diag "debounced" and exit silently.
4. Resolve ComputerName; load roster.

**Window (WPF via `Add-Type PresentationFramework,PresentationCore,WindowsBase` + XAML through `XamlReader`):**
- `WindowStyle=None`, `ResizeMode=NoResize`, `Topmost=True`, `ShowInTaskbar=False`, dark bg, large fonts.
- **Cover all monitors:** `WindowStartupLocation=Manual`, `WindowState=Normal`, bounds = virtual screen (`SystemParameters.VirtualScreenLeft/Top/Width/Height`). *(NOT `Maximized` — it snaps to one monitor. Comment notes per-monitor blocker windows as the alternative for non-rectangular layouts.)*
- **Content:** title/subtitle, event type, computer name, an **editable type-to-filter ComboBox** (names), a **PasswordBox**, a **Confirm** button (disabled until valid), and a status line for messages (e.g., "Incorrect password — try again"). If roster `Source=none`: show "roster unavailable — contact admin", keep Confirm disabled, log a diag row; window still locks the desktop.

**Name ComboBox:** `IsEditable=True`, `IsTextSearchEnabled=True`, `StaysOpenOnEdit=True`; `ItemsSource` = roster `Display` strings; type-to-filter (case-insensitive substring). **No free text** — a name is "valid" only on an exact roster match.

**PasswordBox:** WPF `PasswordBox`; read `.SecurePassword` (SecureString) in code-behind (never bind/expose plaintext). Enabled once a valid name is selected.

**Confirm enabled when:** a valid roster name is selected **AND** the PasswordBox is non-empty.

**Lockdown handlers:** `Closing` → `e.Cancel=$true` unless `$script:AllowClose`; `KeyDown`/`PreviewKeyDown` → swallow `Esc` and Alt+F4, `Enter` invokes Confirm only when enabled; `Deactivated` → `Topmost=$false; Topmost=$true; Activate()`; `Loaded` → `Activate()` + focus the ComboBox.

**Confirm handler (authentication flow):**
1. Resolve selected entry → `Username`. Read `PasswordBox.SecurePassword`.
2. `$ok = Test-AuditCredential -Username $Username -Password $secure -Domain $cfg.AuthDomain`.
3. **Success:** `Write-AuditRow -EventType $EventType -AuthResult Success -Username $Username -LastName -FirstName`; on `Written`/`Spooled` set `$script:AllowClose=$true`, diag Info (no password), `Close()`.
4. **Failure:** `Write-AuditRow -AuthResult Failure ...`; show "Incorrect password — try again"; clear the PasswordBox; `Start-Sleep -Milliseconds RetryDelayMs`; **stay locked**, allow retry (no cap). Never log the password.
5. Dispose the SecureString after use.

**Tradeoff comment block (required):** modal-lockdown (post-logon desktop block), **not** a credential provider (pre-logon). Even with password auth, a determined user can reach Ctrl+Alt+Del → Task Manager and kill the process; document honestly. True pre-logon enforcement needs a credential provider (out of scope offline). Note that auth here verifies *who is using the already-logged-in shared session*, not a logon gate.

## 10. `src/Launch-SharedAccountAuth.vbs`
Self-locating hidden launcher (per prior design): derive own folder, accept EventType arg (default `Logon`), run `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<dir>\SharedAccountAuth.ps1" -EventType <evt>` via `sh.Run cmd, 0, False`. Comment the no-signing/Bypass + AppLocker note (Bypass also avoids "Mark of the Web"; a machine-level GPO execution policy overrides the process-scope token, so signing may be mandated regardless).

## 11. Triggering — `deploy/Register-AuditTasks.ps1` / `Unregister-AuditTasks.ps1`

Two tasks via **`Register-ScheduledTask -Xml`** (SessionStateChange not exposed by the trigger cmdlet). Both **scoped to the shared account**:
- **Principal:** `<UserId>` = resolved `SharedAccount` (local: `MACHINE\name`; resolve `.\name`/bare to `$env:COMPUTERNAME\name` at registration), `<LogonType>InteractiveToken</LogonType>`, `<RunLevel>LeastPrivilege</RunLevel>` — interactive session (≠ 0), no elevation.
- **Action:** `wscript.exe "<install>\src\Launch-SharedAccountAuth.vbs" <EventType>` (absolute path resolved at registration).
- **Settings:** `MultipleInstancesPolicy=IgnoreNew`, `DisallowStartIfOnBatteries=false`, `StopIfGoingOnBatteries=false`, `AllowHardTerminate=true`, `ExecutionTimeLimit=PT0S`, `RunOnlyIfNetworkAvailable=false`, `Enabled=true`.
- **Logon task** (`SharedAccountAuth-Logon`): `<LogonTrigger><UserId>SharedAccount</UserId></LogonTrigger>` — fires only for the shared account.
- **Unlock task** (`SharedAccountAuth-Unlock`): `<SessionStateChangeTrigger><StateChange>SessionUnlock</StateChange><UserId>SharedAccount</UserId></SessionStateChangeTrigger>` — fires only for the shared account.

`Register-AuditTasks.ps1`: generate XML, write reference copies to `tasks/`, register both with `-Force`, check admin, diag-log. `Unregister-AuditTasks.ps1`: remove both via `Unregister-ScheduledTask -Confirm:$false`, tolerant if absent. **The trigger `UserId` scoping is the primary scope control; the prompt's self-check (§9.2) is the backstop.**

## 12. Permissions — `deploy/Setup-SharePermissions.ps1` (admin, run once on the file server)

Unchanged from rev 1. NTFS ACLs on the **log directory**: shared account/group gets **CreateFiles + AppendData** (create + append) but is **DENIED ReadData + Delete**; `WriteData` NOT granted on files; `Auditors` group gets Read; admin/service FullControl. Provide both an authoritative `Set-Acl` implementation (explicit `FileSystemAccessRule` + `FileSystemRights` + inheritance flags, each bit commented) and an `icacls` quick-reference (WD/AD/RD/S/RA/D/(CI)/(OI)/(IO)/(NP) documented). Params `-LogDir -SharedPrincipal -AuditorsPrincipal`, `-WhatIf`, print resulting ACL. Header comment explains why append-only forces all dedup/spool logic to never read the central log.

## 13. Roster Management — `sample/roster.csv`

Lives at `RosterPath` (readable by the shared account). Format **now includes the local username**:
```csv
LastName,FirstName,Username
Smith,Alice,asmith
Nguyen,Bao,bnguyen
O'Brien,Connor,cobrien
Garcia-Lopez,Diego,dgarcia
St. James,Evelyn,ejames
```
- `Username` = the person's **local** account name (validated against the local SAM). Header row required; extra columns ignored; blank rows skipped; apostrophes/commas/spaces in names handled (CSV-quoted). README documents format, location, who edits it, and that every roster `Username` must exist as a local account on each shared PC.

## 14. Execution policy & install — `deploy/Install-Audit.ps1` (rev 3)
Scripts are **not signed**. `src/Launch-SharedAccountAuth.vbs` runs the prompt with `-ExecutionPolicy Bypass` (also avoids the "Mark of the Web" block on a copied `.ps1`); AppLocker path rules over the install directory are the integrity control. The former `Sign-Scripts.ps1` helper and the AllSigned posture are removed. (A site that mandates signing flips the launcher token to AllSigned/RemoteSigned and signs the `.ps1`/`.psd1`; a machine-level GPO execution policy overrides the process-scope token regardless.)

`deploy/Install-Audit.ps1` is the one-command per-PC installer: it **self-elevates** (UAC, relaunch in a `-NoExit` window), registers the tasks by invoking `Register-AuditTasks.ps1` (no duplicated XML), then runs a **preflight validator**. Modes: default (register + preflight), `-ValidateOnly` (preflight only, changes nothing), `-SkipValidation` (register only). The preflight is best-effort/never-throws, **never writes to the append-only central log**, and reports OK/WARN/FAIL for: config valid + `SharedAccount` set; install files present; `SharedAccount` and every roster `Username` cross-checked against local accounts (enumerated offline via the ADSI WinNT provider); central `LogPath` UNC reachability; roster load + source; local state root; and both tasks registered + enabled.

## 15. Diagnostics, Security & Error Handling

- Every script: top-level try/catch; meaningful steps logged via `Write-AuditDiag` to `C:\ProgramData\SharedAccountAuth\diag\audit-diag.log` (local — the central log is unreadable).
- **Passwords:** read as `SecureString` from the PasswordBox; converted to plaintext only inside `Test-AuditCredential` and zeroed immediately; **never** stored in a variable longer than the call, **never** written to the diag log, the CSV, or any spool file.
- The prompt **never** crashes to an unlocked desktop: failures still show the window, spool the row, or log diag — degrade safely.
- The shared-account self-check and roster-unavailable path both fail safe (exit cleanly / keep Confirm disabled).

## 16. README.md — required contents
1. What it is + data-flow diagram (incl. authentication + shared-account scoping).
2. **Install steps** (copy tree, edit `AuditConfig.psd1` incl. `SharedAccount`, run `Setup-SharePermissions.ps1` on the server, then `Install-Audit.ps1` per PC — self-elevates, registers the tasks via `Register-AuditTasks.ps1`, and preflight-validates incl. that each roster `Username` exists locally).
3. **Authentication model** — local-SAM password validation via `LogonUser`; the NETWORK→CLEARTEXT→INTERACTIVE fallback and the STIG "deny network logon for local accounts" reason; secure password handling (SecureString, zeroed, never logged); local account lockout-policy note (no cap + delay).
4. **Credential-provider vs modal tradeoff** — honest: post-logon desktop lock vs pre-logon gating; Ctrl+Alt+Del/Task-Manager bypass; auth verifies *who is using the shared session*, not a logon gate; why a credential provider is out of scope offline.
5. **Shared-account-only behavior** — how trigger `UserId` scoping + the prompt self-check ensure individuals' personal logins never see the prompt; how to set `SharedAccount`.
6. **STIG considerations** — unsigned scripts via `-ExecutionPolicy Bypass` (GPO-policy override caveat, Mark-of-the-Web note); AppLocker pathing for `C:\ProgramData\SharedAccountAuth\` and the script dir as the integrity control; least-privilege task principal; no audit-policy dependency for unlock; 4625 generation from failed validations.
7. **Testing** — logon trigger (sign out/in **as the shared account**, and confirm it does NOT pop on a personal account); unlock trigger (Win+L then unlock); a correct-password run and a wrong-password run (verify `AuthResult` rows + that the lock holds); share-down → spool + flush.
8. **Multi-PC deployment** — identical config/paths everywhere; `ComputerName` differentiates; roster usernames must exist locally on every PC.
9. **Auditor review** — open the CSV read-only as `Auditors`; columns (incl. `Username`, `AuthResult`) explained; sort/filter by `ComputerName`/`EventType`/`AuthResult`.
10. **Troubleshooting** — the diag log; share unreachable → spool; roster unavailable; task not firing in session 0; credential validation failing under STIG network-logon denial.
11. **Known limitations / bypasses** — documented honestly.

## 17. Hard Constraints (every file must honor)
- **Windows PowerShell 5.1** syntax only (no PS7-only `??`/`?.`/ternary/`&&`/`||`/`ForEach-Object -Parallel`/`Clean{}`).
- **.NET Framework 4.x** WPF/WinForms only (no .NET Core/5+).
- **No external modules**; built-ins only (`Microsoft.PowerShell.*`, `ScheduledTasks`, `PKI`, `PresentationFramework`, and Win32 P/Invoke via `Add-Type`).
- **Fully offline** at build and runtime.
- **Hostname never blank** (`UNKNOWN-HOST`).
- **Append-only** — never read the central log.
- **No password ever** written to disk/log/CSV; SecureString + zeroed.
- Inline comments + comment-based help; config block at top of each script.

## 18. Test / Verification Checklist (post-build)
- All `.ps1` parse under PS 5.1 (tokenizer, no errors); no PS7-only syntax; no external modules; no network calls.
- `Format-AuditRow` escapes quotes/commas (`O'Brien`, `Smith, Jr`); new 8-column order correct everywhere.
- `Add-AuditLineToFile` create-race writes header once; concurrent appends add no BOM.
- Spool on unreachable `LogPath`; flush appends + deletes.
- Roster falls back to cache; refreshes on success; `Username` column parsed.
- `Test-AuditCredential`: SecureString zeroed in `finally`; tries NETWORK→CLEARTEXT→INTERACTIVE; never logs the password.
- Window can't close via Alt+F4/Esc/close; re-asserts topmost; spans virtual screen; PasswordBox uses SecurePassword.
- **Self-check:** prompt exits immediately when current user ≠ `SharedAccount` (no window).
- Tasks register with `InteractiveToken` principal **scoped to the shared account**; unlock uses `SessionStateChangeTrigger/SessionUnlock`; logon `LogonTrigger` with `UserId`.
- ACL grants append+create, denies read+delete, grants Auditors read.
- Failed auth ⇒ `AuthResult=Failure` row + lock holds + retry allowed; success ⇒ `AuthResult=Success` row + lock releases.
