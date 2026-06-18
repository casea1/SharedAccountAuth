# Runtime Prompt — Hardening + UX Fixes Design Spec

**Date:** 2026-06-18
**Status:** Proposed
**Parent:** [2026-06-17-sign-on-audit-logger-design.md](2026-06-17-sign-on-audit-logger-design.md)
**Target:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF). No internet, no external modules, no compiled components.

---

## 1. Purpose

Five issues found while testing the runtime lockdown prompt ([src/SharedAccountAuth.ps1](../../../src/SharedAccountAuth.ps1)):

1. **Keyboard backdoor** — Win+R, the Win key (Start search) → type `cmd`, Alt+Tab, and Ctrl+Shift+Esc (Task Manager) all reach a shell past the lock. The window only swallows Esc/Alt+F4/Enter; OS shell hotkeys are handled by Windows, not the focused window.
2. **Name dropdown shows `LastName, FirstName`** — should show the **Username**.
3. **Name dropdown affordance is weak** — make the editable combo box and its drop arrow obviously a dropdown.
4. **Desktop flashes for ~1–2 s before the prompt** at first logon — the logon-triggered task only fires after session/desktop init.
5. **Disabled Confirm button renders near-white** (WPF's default disabled template overrides the blue), so it looks like another text box.

This revises the parent spec's locked decision **"Baseline modal … No hooks, no policy edits"** to permit a **low-level keyboard hook** and a **temporary `DisableTaskMgr` policy** while the prompt is up.

## 2. Scope decisions (from brainstorming)

| Item | Decision |
|---|---|
| #4 desktop flash | **Minimize in-scope** (raise task priority + paint the cover before the roster fetch). The GPO "Run logon scripts synchronously" route for *true* pre-desktop is **documented as a future option, not built**. |
| #1 Task Manager | **Keyboard hook + temporary `DisableTaskMgr`** (restored on exit) — defense-in-depth against the Ctrl+Alt+Del → Task Manager path. |

## 3. Honest ceiling (restated)

A low-level keyboard hook + `DisableTaskMgr` closes **every route found in testing** and the Ctrl+Alt+Del → Task Manager path. It does **not** suppress the **Ctrl+Alt+Del Secure Attention Sequence** itself (kernel-level; only a Credential Provider or Winlogon can). From that secure screen a user can still **Sign out** — which *ends the shared session* rather than bypassing the audit, so it is not an authentication bypass. True pre-logon enforcement, and fully eliminating the desktop flash, remain out of scope for this offline/no-compiler design (would need a signed Credential Provider or GPO logon-script changes).

## 4. New component — `src/AuditLockdown.ps1`

A new dot-sourced module isolating the hardening logic (one responsibility, keeps the prompt file focused, exposes a pure testable predicate). Dot-sourced by `SharedAccountAuth.ps1` after `AuditCommon.ps1`. PS 5.1 / built-ins / offline.

| Function | Signature | Behaviour |
|---|---|---|
| `Test-AuditShouldSwallowKey` | `-VkCode <int> -AltDown <bool> -CtrlDown <bool> -ShiftDown <bool>` → `[bool]` | **Pure / no side effects / unit-tested.** Returns `$true` to swallow: VK 0x5B/0x5C (Left/Right Win, always); VK 0x09 (Tab) when `AltDown` (Alt+Tab); VK 0x1B (Esc) when `AltDown` (Alt+Esc) **or** `CtrlDown` (Ctrl+Esc Start, and Ctrl+Shift+Esc Task Manager — both have CtrlDown). Returns `$false` for everything else (plain typing, bare Tab field-nav, backspace, Enter, Esc-alone — the WPF handler owns Esc/Alt+F4/Enter). |
| `Install-AuditKeyboardHook` | *(none)* → `[bool]` | Installs a `WH_KEYBOARD_LL` hook via `Add-Type` P/Invoke (`SetWindowsHookEx`/`UnhookWindowsHookEx`/`CallNextHookEx`). The callback tracks Alt/Ctrl/Shift down-state from the event stream and calls `Test-AuditShouldSwallowKey`; swallows by returning `(IntPtr)1` instead of `CallNextHookEx`. The delegate is stored in a module-scope variable so it is **not GC'd**; the hook handle is stored for removal. The callback is wrapped in try/catch and **falls through to `CallNextHookEx` on any error** (never breaks input, never throws). Returns success. |
| `Remove-AuditKeyboardHook` | *(none)* → `void` | `UnhookWindowsHookEx` if installed; idempotent; never throws. (The hook also dies with the process.) |
| `Set-AuditTaskMgrPolicy` | `-Config <hashtable>` → `void` | Captures the current `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` (absent vs value) to a state file under `LocalRoot\state`, then sets it to `1`. Idempotent; never throws. |
| `Restore-AuditTaskMgrPolicy` | `-Config <hashtable>` → `void` | Restores `DisableTaskMgr` to the captured prior state (delete if it was absent, else set back), clears the state marker. Idempotent; never throws. |

### 4.1 Hook lifecycle in `SharedAccountAuth.ps1`
- Dot-source `AuditLockdown.ps1` alongside `AuditCommon.ps1`.
- In the window **`Loaded`** handler (UI thread, after the cover is visible): `Set-AuditTaskMgrPolicy`, then `Install-AuditKeyboardHook`.
- In the **`Closing`** handler **and** the outer `finally`/`catch`: `Remove-AuditKeyboardHook` + `Restore-AuditTaskMgrPolicy` (both idempotent, so double-invocation is safe).
- The WPF `Dispatcher` (running under `ShowDialog`) pumps messages, so the LL hook callback fires.
- **Crash safety:** because the prompt runs at every logon/unlock and `Set`/`Restore` are idempotent with a captured-state marker, a hard-kill that skips `finally` self-heals on the next run (which restores from the marker before re-setting). A shared account with Task Manager briefly disabled is acceptable.

## 5. Prompt UX changes — `src/SharedAccountAuth.ps1` (XAML + code-behind)

### 5.1 Username dropdown (#2)
Build the `ComboBox` items and the `displayToEntry` lookup from **`Username`** instead of `Display`. Sort the displayed usernames alphabetically (case-insensitive). Selection still resolves to the same roster entry; `Write-AuditRow` still logs `Username`/`LastName`/`FirstName` unchanged. The substring filter operates on the username text.

### 5.2 Dropdown affordance (#3)
Style `NameCombo`: explicit `BorderBrush="#FF3A4656"`, `BorderThickness="1"`, dark editable background with light foreground, a larger high-contrast drop-arrow glyph, and a **watermark** "— select your name —" shown via an overlay `TextBlock` that is visible only when the edit text is empty. Keep `IsEditable`/type-to-filter behavior.

### 5.3 Confirm button (#5)
Replace the bare `<Button Background=…>` with a `Style` + `ControlTemplate`: a rounded `Border` (`CornerRadius="6"`) whose fill is driven by `IsEnabled` triggers — **enabled** `#FF2D6CDF` white text; **disabled** `#FF33404F` fill with `#FF8A97A6` text and a `#FF3A4656` border. It now reads unambiguously as a button in both states. (No behavioural change to the enable logic in `$updateState`.)

### 5.4 Cover-before-roster (#4, prompt half)
Reorder startup so the **full-screen opaque cover window is shown first**, then the (possibly slow, central-UNC) roster fetch + control population happen in the `Loaded` handler with a transient "Loading…" status and Confirm disabled. This shrinks the time-to-cover. The roster-unavailable path and self-check/debounce ordering are preserved (self-check + debounce still run *before* the window is created).

## 6. Task priority — `deploy/Register-AuditTasks.ps1` (#4, launch half)
In `New-AuditTaskXml`, change `<Priority>7</Priority>` → `<Priority>4</Priority>` for both tasks so they fire as early in session init as the scheduler allows. Regenerate the reference XML in `tasks/`. No other task settings change (no `<Delay>` was ever set). This reduces, but does not eliminate, the flash — §3 applies.

## 7. Out of scope (YAGNI)
- A Credential Provider (compiled COM) — impossible offline; the only true pre-logon gate.
- GPO "Run logon scripts synchronously" — the documented path to fully eliminate the flash; not built now.
- Suppressing Ctrl+Alt+Del / the Secure Desktop — not possible from user mode.
- Per-monitor blocker windows, AppLocker/GPO authoring — environment-managed, unchanged.

## 8. Constraints honoured (parent §17)
PS 5.1 only; .NET 4.x WPF + Win32 P/Invoke via `Add-Type`; no external modules; fully offline; **no password ever** read/copied/logged (these changes touch UI chrome + input blocking only, never the credential path); **degrade safely** — the hook and policy helpers never throw and the prompt still never crashes to an unlocked desktop.

## 9. Testing
- **Unit (automated):** `Test-AuditShouldSwallowKey` truth table — Win keys swallowed; Alt+Tab swallowed; Ctrl+Esc and Ctrl+Shift+Esc swallowed; bare Tab / letters / digits / Enter / lone Esc **not** swallowed. In a new no-Pester harness `tests/Test-AuditLockdown.ps1` (dot-sources `src/AuditLockdown.ps1`), modelled on the existing `tests/Test-AuditInstall.ps1` (same `Assert-True`/`Assert-Eq` style, exits 1 on failure).
- **Parse/XAML:** parse-check `SharedAccountAuth.ps1`, `AuditLockdown.ps1`, `Register-AuditTasks.ps1`; load the prompt XAML via `XamlReader` and assert the named controls still resolve (`NameCombo`, `PwBox`, `ConfirmButton`, `StatusText`, …).
- **Task XML:** assert the generated Logon/Unlock XML contains `<Priority>4</Priority>`.
- **Manual smoke (documented, required before field use):** on a target shared session, confirm Win/Win+R/Alt+Tab/Ctrl+Shift+Esc are all swallowed while the prompt is up; Task Manager is disabled during and restored after; a correct/incorrect password still works; the disabled Confirm button reads as a button; the dropdown shows usernames with a clear arrow + watermark; and the desktop-visible interval is reduced. The live keyboard hook and `DisableTaskMgr` are not automatable here.

## 10. Impact on existing files
| File | Change |
|---|---|
| `src/AuditLockdown.ps1` | **New** — keyboard-hook predicate + install/remove + TaskMgr policy set/restore. |
| `src/SharedAccountAuth.ps1` | Dot-source lockdown module; install/remove hook + policy in Loaded/Closing/finally; username dropdown; combo + button styling; cover-before-roster reorder. |
| `deploy/Register-AuditTasks.ps1` | `<Priority>7</Priority>` → `<Priority>4</Priority>`; regenerate `tasks/*.xml`. |
| `tests/Test-AuditLockdown.ps1` | **New** — `Test-AuditShouldSwallowKey` truth-table tests (no-Pester, mirrors Test-AuditInstall.ps1). |
| `docs/.../2026-06-17-…-design.md` | Revise the "no hooks/no policy edits" locked decision + restate the honest ceiling (rev note). |
| `README.md` | Update §6 STIG / §11 limitations: new keyboard-hook + TaskMgr hardening, and the remaining Ctrl+Alt+Del / pre-desktop limits. |
