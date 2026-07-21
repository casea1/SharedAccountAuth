# Unified Setup Tool (`Shared-Auth-Setup.ps1`) — Design Spec

**Date:** 2026-07-21
**Status:** Proposed
**Parent:** [2026-06-18-install-gui-wizard-design.md](2026-06-18-install-gui-wizard-design.md)
**Target:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF). No internet, no external modules.

---

## 1. Purpose

Collapse the whole per-PC install into **one** obviously-named tool. Today setup is spread across `Install-Audit.ps1` (CLI), `Install-Audit-GUI.ps1`, `Register-AuditTasks.ps1`, and `Setup-SharePermissions.ps1`, and the README's install section is a multi-step A/B (server + per-PC) dance. The redesign: rename the GUI to **`Shared-Auth-Setup.ps1`** and make it the single entry point that configures **everything** — config, folder ACLs/permissions, scheduled tasks, and validation — and drastically shorten the README.

This is driven by real pain: the ProgramData ACL gap (the shared account couldn't write its own diag/cache) silently broke diagnostics, and the log-folder ACL is a separate manual step today. The tool should just handle both.

## 2. Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Log location model | **Both.** Local log path ⇒ the tool sets the append-only log ACL itself. UNC share ⇒ it sets the local-state ACL + verifies reachability and flags the server-side ACL step. |
| Consolidation | **GUI only.** `Shared-Auth-Setup.ps1` is the single entry point. **Delete `Install-Audit.ps1`.** Keep `Register-AuditTasks.ps1` / `Unregister-AuditTasks.ps1` / `Setup-SharePermissions.ps1` as engine + advanced tools. |
| Auditors default | Default the Auditors (read-only reviewers) field to the **`Audit`** group. |
| Classification | **In the GUI** — a level dropdown that writes `ClassificationLevel` to config. |

## 3. The tool — `deploy/Shared-Auth-Setup.ps1`

Renamed from `Install-Audit-GUI.ps1` (via `git mv`, preserving history). Self-elevates (unchanged). Single WPF pane, prefilled from any existing `AuditConfig.psd1`.

### 3.1 Fields
- **Central log path** (UNC or local) → `LogPath`
- **Roster path** (UNC) → `RosterPath`
- **Shared account** → `SharedAccount`
- **Auditors** (read-only reviewers group) → default `Audit`; used only to set the log ACL (not stored in config)
- **Classification** → dropdown: `(none)`, `UNCLASSIFIED`, `CUI`, `CONFIDENTIAL`, `SECRET`, `TOP SECRET` → writes `ClassificationLevel` (empty for `(none)`)
- **Install dir** (read-only label) — the tree is assumed already copied.

### 3.2 Install flow (each step shows ✓ / ⚠ / ✗ + a one-line detail)
1. **Write config** — `Write-AuditConfigFile` to `AuditConfig.psd1` with a `.bak` backup (incl. `ClassificationLevel` from the dropdown). Unchanged mechanism.
2. **Permissions:**
   - **Local state** — `Set-AuditLocalStateAcl`: grant the shared account Modify on `LocalRoot` (`C:\ProgramData\SharedAccountAuth\`). Always.
   - **Log folder** — if `LogPath` is **local** (not `\\…`) → `Set-AuditLogAcl` applies the append-only model on its parent dir (shared account create+append, **deny** read+delete; auditors read; admins full). If `LogPath` is a **UNC share** → skip with `⚠ set on the server via Setup-SharePermissions.ps1`, and report whether the share dir is reachable.
3. **Scheduled tasks** — register/repair both tasks via `Register-AuditTasks.ps1` (idempotent `-Force`). Preflight then reports registered/enabled state.
4. **Preflight** — `Invoke-AuditPreflight` (config valid, GPO exec-policy, roster-vs-local-accounts, LogPath reachability, task state) + the read-only **roster preview** grid.

Keeps **Validate** (dry-run, no disk changes — resolves config from the fields and runs preflight) and the per-field **Test** buttons.

## 4. Architecture — shared logic, no duplication

Move the reusable ACL/task logic into `deploy/AuditInstallCommon.ps1` so the GUI, `Setup-SharePermissions.ps1`, and any tool call one implementation:

| Function (in `AuditInstallCommon.ps1`) | Signature | Behaviour |
|---|---|---|
| `Set-AuditLogAcl` | `-LogDir <string> -SharedPrincipal <string> -AuditorsPrincipal <string> [-AdminPrincipal <string>='BUILTIN\Administrators'] [-WhatIf]` → `[bool]` | Applies the **append-only** NTFS model on `-LogDir` (create+append for shared, **deny** read+delete; auditors read; admin full; protected DACL). This is the logic **extracted from `Setup-SharePermissions.ps1`** (its `New-*Ace` builders + `Set-Acl`). Returns success. Never throws — logs + returns `$false` on failure. |
| `Set-AuditLocalStateAcl` | `-Config <hashtable> [-SharedAccountOverride <string>]` → `void` | **Moved** from `Install-Audit.ps1`. Grants the shared account Modify on `LocalRoot`. Never throws. |

- **`Setup-SharePermissions.ps1`** becomes a thin CLI wrapper: parse `-LogDir/-SharedPrincipal/-AuditorsPrincipal/-AdminPrincipal/-LocalStateDir`, call `Set-AuditLogAcl` (+ the optional local-state grant), print the resulting ACL. Same behaviour, one implementation. Stays as the **server-side** tool for a central share.
- **`Register-AuditTasks.ps1` / `Unregister-AuditTasks.ps1`** — unchanged; the GUI invokes register as today.
- **Delete `Install-Audit.ps1`** — its behaviour (self-elevate, register, preflight, local-state ACL) is fully covered by the GUI + shared lib.

**Principal resolution:** the GUI resolves the Shared account and Auditors fields to grantable identities (`MACHINE\name` for a bare/`.\` name; keep `MACHINE\`/`DOMAIN\` prefixes) using the existing `Get-AuditLeafName` + `$env:COMPUTERNAME`.

## 5. Config schema
No new persisted keys. `ClassificationLevel` (already exists) is written from the dropdown. **Auditors is transient** (an install-time ACL input, not stored). `Write-AuditConfigFile`'s known-keys are unchanged.

## 6. README — simplified install section
Replace the multi-step §2 A/B install with:

- **Every workstation:** copy the tree to `C:\Program Files\SharedAccountAuth\` → run `.\deploy\Shared-Auth-Setup.ps1` → fill the fields → **Install**. It writes config, sets folder permissions, registers the tasks, and validates. Done.
- **Only if the log is a central *server* share:** one note — run `Setup-SharePermissions.ps1` on the server once to set the append-only ACL there (a workstation can't set a remote server's NTFS ACLs).
- Remove the per-PC "sign the scripts / register tasks / ensure local accounts / set ACLs" step list — the tool does it and the preflight reports it.

The `deploy/` file-tree entry updates: `Shared-Auth-Setup.ps1` (the one you run) replaces `Install-Audit.ps1` + `Install-Audit-GUI.ps1`; the engine scripts get a one-line "advanced/engine" note.

## 7. Constraints (parent §17)
PS 5.1 only; .NET 4.x WPF; no external modules; fully offline; ACL/task helpers **never throw** (a failed step reports ⚠/✗ but must not crash the tool); no password path touched. `icacls`/`Set-Acl` are built-ins.

## 8. Out of scope (YAGNI)
Headless/silent install (GUI only, per the decision); remote server ACL-setting from the workstation (UNC case is flagged, not automated); changing the runtime prompt, roster format, or task XML.

## 9. Testing
- **Unit (automated):** the config/preflight/roster/classification helpers keep their existing tests (`Test-AuditInstall.ps1`, `Test-AuditLockdown.ps1`). Add a `Set-AuditLogAcl` **parameter/shape** smoke where feasible (it builds ACEs before touching disk — a `-WhatIf` path can be asserted to not throw). `Set-AuditLocalStateAcl` move keeps behaviour.
- **Parse/XAML:** parse-check `Shared-Auth-Setup.ps1`, `AuditInstallCommon.ps1`, `Setup-SharePermissions.ps1`; load the GUI XAML and assert named controls resolve, now including `AuditorsBox` and `ClassificationCombo`.
- **Task XML:** unchanged priority test still passes.
- **Manual smoke (required):** on a target PC, run `Shared-Auth-Setup.ps1` against a **local** log path → confirm config written, log-folder append-only ACL applied (shared can append, not read/delete), local-state ACL applied, tasks registered, preflight green; then a real logon writes a row. Real ACL application isn't safely unit-testable.

## 10. Impact on existing files
| File | Change |
|---|---|
| `deploy/Shared-Auth-Setup.ps1` | **Renamed** from `Install-Audit-GUI.ps1`; add Auditors + Classification fields; add the Permissions install step (log ACL if local + local-state); status per step. |
| `deploy/AuditInstallCommon.ps1` | Add `Set-AuditLogAcl` (extracted from Setup-SharePermissions); add `Set-AuditLocalStateAcl` (moved from Install-Audit). |
| `deploy/Setup-SharePermissions.ps1` | Refactor to a thin wrapper over `Set-AuditLogAcl` (+ its existing `-LocalStateDir`); same behaviour. |
| `deploy/Install-Audit.ps1` | **Deleted.** |
| `deploy/Register-AuditTasks.ps1` / `Unregister-AuditTasks.ps1` | Unchanged. |
| `tests/Test-AuditInstall.ps1` | Update any `Install-Audit`/GUI references; add `Set-AuditLogAcl -WhatIf` smoke; GUI XAML test → new control names. |
| `README.md` | Simplify the install section + `deploy/` tree per §6. |
| `docs/.../2026-06-18-install-gui-wizard-design.md` | Add a rev note pointing here (GUI renamed + expanded; CLI retired). |
