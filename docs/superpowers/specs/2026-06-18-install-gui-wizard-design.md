# Install GUI Wizard — Design Spec

**Date:** 2026-06-18
**Status:** Proposed
**Parent:** [2026-06-17-sign-on-audit-logger-design.md](2026-06-17-sign-on-audit-logger-design.md) (rev 3 — unsigned scripts via `-ExecutionPolicy Bypass`; `deploy/Install-Audit.ps1` CLI installer + preflight)
**Target:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF). **No internet, no external modules** — same stack as the runtime prompt.

---

## 1. Purpose

Provide a single-pane **WPF GUI front-end** over the existing per-PC install so an operator can set the three required values (central log path, roster path, shared account), see them validated, and register the tasks — without hand-editing `config\AuditConfig.psd1` or running the CLI. It is a convenience layer over the **same** install mechanism (`Register-AuditTasks.ps1`) and the **same** preflight as the CLI `Install-Audit.ps1`; it changes no runtime behavior and adds no new deployment architecture.

**Not** a replacement for the CLI — `Install-Audit.ps1` stays for scripted/silent use. The GUI is for interactive, small-scale / pilot installs.

## 2. Locked decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Layout | **Single-pane form** (all fields + per-field Test + preflight results + roster preview on one window). Not a multi-step wizard. |
| Roster handling | **Path + read-only preview.** Collect the roster UNC; load and show names with a per-row "local account on this PC? YES/NO" column. **No editing** of the central roster from here. |
| Config | The GUI **writes `AuditConfig.psd1`** from the collected values, **backing up** the prior file to `AuditConfig.psd1.bak` first. (This is the only genuinely new logic.) |
| Elevation | **Self-elevate the whole GUI at launch** (UAC relaunch), mirroring `Install-Audit.ps1` — registering tasks needs admin. |
| File staging | **Out of scope.** The GUI assumes the tree is already copied into place (run from `deploy\`), exactly like the CLI. It does not copy files. |
| Code reuse | **Extract** the preflight engine + helpers from `Install-Audit.ps1` into a new shared `deploy\AuditInstallCommon.ps1`, dot-sourced by **both** the CLI and the GUI. No duplicated validation. |

## 3. Architecture & components

```
deploy/
├─ Install-Audit.ps1          # CLI installer (refactored: dot-sources AuditInstallCommon.ps1)
├─ Install-Audit-GUI.ps1      # NEW: WPF single-pane front-end (self-elevate, collect, validate, install)
├─ AuditInstallCommon.ps1     # NEW: shared install-time lib (preflight + helpers + config writer)
├─ Register-AuditTasks.ps1    # unchanged — invoked to register the two tasks
├─ Unregister-AuditTasks.ps1  # unchanged
└─ Setup-SharePermissions.ps1 # unchanged
```

Both installers dot-source `..\src\AuditCommon.ps1` (runtime library) for `Get-AuditConfig`, `Get-AuditRosterEntries`, `Write-AuditDiag`, and `deploy\AuditInstallCommon.ps1` (install-time library) for the preflight + config writer.

### 3.1 `deploy\AuditInstallCommon.ps1` (new shared library)

Dot-sourced, `Verb-Noun`, comment-help-documented, never-throws diagnostics, built-ins only. Functions **moved verbatim** out of `Install-Audit.ps1` (logic unchanged):

| Function | Signature | Returns / behaviour |
|---|---|---|
| `Get-AuditLeafName` | `-Name <string>` | `[string]` leaf after the last `\`, trimmed (`''` if blank). |
| `Get-LocalUserNameSet` | *(none)* | `[HashSet[string]]` lower-cased LOCAL usernames via the ADSI `WinNT://<computer>` provider (offline; empty set on failure). |
| `New-AuditCheckResult` | `-Check <string> -Status <OK\|WARN\|FAIL> -Detail <string>` | `[pscustomobject]` one result row. |
| `Invoke-AuditPreflight` | `-Config <hashtable>` | `[object[]]` of result rows. Best-effort, never throws, **never writes to the central log**. Checks (unchanged from the current CLI): SharedAccount set; install files present; **GPO execution-policy override** (Machine/UserPolicy `AllSigned` ⇒ FAIL, `RemoteSigned` ⇒ WARN — the scripts are unsigned); SharedAccount exists locally; central `LogPath` reachable; roster source + every roster `Username` cross-checked against local accounts; local state root; both tasks registered + enabled. |

New function:

| Function | Signature | Returns / behaviour |
|---|---|---|
| `Write-AuditConfigFile` | `-ConfigPath <string> -Settings <hashtable> [-NoBackup]` | Renders a fully-commented `AuditConfig.psd1` from `$Settings` and writes it to `$ConfigPath`. If the target exists and `-NoBackup` is not set, copies it to `<ConfigPath>.bak` first (overwriting any prior `.bak`). Returns `[string]` the backup path (or `$null`). |

`Install-Audit.ps1` is refactored to **remove** those four moved functions and instead dot-source `AuditInstallCommon.ps1`; its CLI behavior and output are unchanged.

### 3.2 `Write-AuditConfigFile` algorithm

1. Known keys (in `AuditConfig.psd1` order): `LogPath, RosterPath, LocalRoot, RosterCachePath, SpoolDir, DiagLogPath, StateDir, SharedAccount, AuthDomain, RetryDelayMs, DebounceSeconds, WriteRetryCount, WriteRetryBaseMs, AppName, WindowTitle, WindowSubtitle`.
2. Numeric keys (written bare): `RetryDelayMs, DebounceSeconds, WriteRetryCount, WriteRetryBaseMs`. All others are strings, written **single-quoted with embedded `'` doubled** (psd1 escaping).
3. For each known key, emit `Key = <value>` using `$Settings[Key]` when present, else the project default. Group + comment exactly like the current file (central paths / local state / shared-account / auth / tunables / UI text).
4. Any extra keys in `$Settings` not in the known list are appended under a `# --- additional keys ---` block (string-quoted) so nothing is silently dropped.
5. Back up the existing file to `<ConfigPath>.bak`, then write UTF-8 (preserves the em-dash UI text). The result must re-parse via `Import-PowerShellDataFile` to the same values (the round-trip test).

### 3.3 `deploy\Install-Audit-GUI.ps1` (new entry point)

- `param([string] $ConfigPath)`; `Set-StrictMode -Version 2.0`; `$ErrorActionPreference = 'Stop'`.
- **Self-elevate** first (before loading anything): if not admin, relaunch `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <self> [-ConfigPath ...]` via `Start-Process -Verb RunAs`, then return. The elevated instance shows the window (`ShowDialog` keeps the process alive; no `-NoExit` needed). On failure, message + advise running elevated.
- Dot-source `..\src\AuditCommon.ps1` and `.\AuditInstallCommon.ps1`.
- **Prefill:** load the current `AuditConfig.psd1` *tolerantly* via `Import-PowerShellDataFile` (NOT `Get-AuditConfig`, which throws on a blank `SharedAccount`) to populate the three text fields; fall back to the documented defaults if the file is missing.
- Build the WPF window from a XAML string via `Add-Type PresentationFramework,PresentationCore,WindowsBase` + `XamlReader::Load`, retrieving controls with `$window.FindName(...)` — the same approach as `src\SharedAccountAuth.ps1`.

## 4. Window layout & controls (single pane)

- **Title:** "Shared-Account Sign-On Audit — Setup".
- **Three labeled text boxes**, prefilled: `Central log (UNC)`, `Roster (UNC)`, `Shared account`, each with a **Test** button:
  - Test log → `Test-Path` the parent dir of `LogPath`; OK / "unreachable (runtime will spool)".
  - Test roster → load via `Get-AuditRosterEntries` against the config resolved from the current fields (see §4.2); populate the **roster preview grid** and report source (central/cache/none) + entry count.
  - Check account → `Get-AuditLeafName` vs `Get-LocalUserNameSet`; OK / "no local account (fine if domain)".
- **Install dir** (read-only label): the resolved `$InstallRoot` (tree assumed already in place).
- **Roster preview grid** (`ListView`/`DataGrid`, read-only): columns `LastName, FirstName, Username, Local acct?` (YES/NO). Rows with `NO` highlighted (those users can't authenticate on this PC).
- **Preflight results panel** (`ListView`/`DataGrid` bound to `Invoke-AuditPreflight` output): columns `Status, Check, Detail`; rows colored by `Status` (OK green / WARN amber / FAIL red) via a XAML `DataTrigger`.
- **Buttons:** `Validate`, `Install`, `Close`. A status line at the bottom for one-line messages.

### 4.1 Behaviour

- **Validate** (no changes on disk): resolve the current field values via the §4.2 helper, run `Invoke-AuditPreflight`, fill the results + roster grids. Reuses the authoritative resolver/preflight so the report matches what the CLI would show.
- **Install:** confirm; then `Write-AuditConfigFile` to the real `AuditConfig.psd1` (with `.bak` backup); call `& Register-AuditTasks.ps1 -ConfigPath <real>` (the shared account is already in the written config, so no `-SharedAccount` is needed); re-run `Invoke-AuditPreflight` against the now-saved resolved config; show the result. A remaining **FAIL** (e.g. GPO `AllSigned`, or `SharedAccount` blank) is shown red with guidance; Install warns prominently if any FAIL remains.

### 4.2 Field resolution helper

A single internal helper turns the current field values into a resolved config hashtable without committing anything: it renders the three fields (overlaid on the tolerantly-loaded current psd1) to a **temporary** psd1 in `$env:TEMP`, calls `Get-AuditConfig -ConfigPath <temp>`, deletes the temp file, and returns the resolved hashtable. Both the per-field **Test** buttons and **Validate** use it, so every in-GUI check runs through the same authoritative `Get-AuditConfig` resolution the runtime uses.
- **Close** exits. If Install wrote config but registration failed, the `.bak` and the diag log let the operator recover.

## 5. Error handling & diagnostics

- Top-level `try/catch`; the WPF event handlers each wrap their work in `try/catch` and surface failures to the status line / a `MessageBox`, never an unhandled crash.
- Every meaningful step is diag-logged via the existing `Write-AuditDiag` to `C:\ProgramData\SharedAccountAuth\diag\audit-diag.log` (e.g. "GUI: wrote config (backup=...)", "GUI: registered tasks", "GUI: preflight N checks, M FAIL").
- **Backup-before-write** protects the prior config. No secrets are involved (this tool never handles passwords).

## 6. Verification

- **Parse-check** `Install-Audit-GUI.ps1`, `AuditInstallCommon.ps1`, and the refactored `Install-Audit.ps1` under the real PS 5.1 parser (as done for the CLI).
- **Round-trip test** for `Write-AuditConfigFile`: build a `$Settings` hashtable (incl. an apostrophe in UI text and a UNC path), write to a temp file, `Import-PowerShellDataFile` it back, assert every key matches and numeric keys are numeric.
- **Smoke test** (manual, documented): launch the GUI, confirm self-elevation, run Validate against the sample config, confirm the roster grid + preflight populate; do not require a live share.
- No claim of an automated test for the WPF window itself; the extracted logic it depends on (`Write-AuditConfigFile`, `Invoke-AuditPreflight`) is what carries the tests.

## 7. Out of scope (YAGNI)

- File copying / staging the tree (assumes in-place, like the CLI).
- Editing or writing the **central roster** (read-only preview only; a roster editor, if ever wanted, is a separate tool).
- MSI/EXE packaging; compiling anything (this is a `.ps1`, run the same way as the rest of the project).
- Changing the runtime prompt, the tasks, the ACL script, or `AuditCommon.ps1` (other than nothing — the runtime library is untouched).
- Adding param-driven config to the **CLI** `Install-Audit.ps1` (the GUI covers the interactive case; the CLI stays as-is).

## 8. Impact on existing files

| File | Change |
|---|---|
| `deploy/AuditInstallCommon.ps1` | **New.** Moved preflight/helpers + new `Write-AuditConfigFile`. |
| `deploy/Install-Audit-GUI.ps1` | **New.** WPF single-pane front-end. |
| `deploy/Install-Audit.ps1` | **Refactor.** Remove the four now-shared functions; dot-source `AuditInstallCommon.ps1`. Behavior unchanged. |
| `README.md` | Add the GUI as an alternative to step 6 (interactive install); note the CLI remains for scripted use. |
| `docs/.../2026-06-17-...-design.md` | Cross-reference rev note pointing at this spec (optional). |
