# Runtime Prompt — Hardening + UX Fixes Design Spec

**Date:** 2026-06-18
**Status:** Proposed (rev 2 — adds the credential-lockout fix, classification banner, and GE logo)
**Parent:** [2026-06-17-sign-on-audit-logger-design.md](2026-06-17-sign-on-audit-logger-design.md)
**Target:** Windows 11 Enterprise, air-gapped / offline. Windows PowerShell **5.1** + **.NET Framework 4.x** (WPF). No internet, no external modules, no compiled components.

---

## 1. Purpose

Eight changes to the runtime lockdown prompt found while testing:

1. **Keyboard backdoor** — Win+R, Win-key Start search → `cmd`, Alt+Tab, Ctrl+Shift+Esc (Task Manager) all reach a shell past the lock. The window only swallows Esc/Alt+F4/Enter; OS shell hotkeys aren't seen by the focused window.
2. **Name dropdown shows `LastName, FirstName`** — should show the **Username**.
3. **Name dropdown affordance is weak** — make the editable combo + drop arrow obviously a dropdown.
4. **Desktop flashes ~1–2 s before the prompt** at logon — the logon-triggered task fires only after session/desktop init.
5. **Disabled Confirm button renders near-white** (WPF default disabled template) — looks like a text box.
6. **Account lockout after 1–2 wrong passwords** — `Test-AuditCredential` tries three logon types per attempt, so one wrong password = ~3 bad-password strikes.
7. **Classification banner** — a config-driven `SECRET` bar (white-on-red) at the top and bottom of the screen.
8. **GE logo** — display `assets/GE-Aerospace-Emblem.png` on the auth card.

This revises the parent's locked decision **"Baseline modal … No hooks, no policy edits"** to permit a low-level keyboard hook + temporary `DisableTaskMgr` while the prompt is up.

## 2. Scope decisions (from brainstorming)

| Item | Decision |
|---|---|
| #4 desktop flash | **Minimize in-scope** (task priority + paint cover before roster fetch). GPO "Run logon scripts synchronously" for true pre-desktop is **documented, not built**. |
| #1 Task Manager | **Keyboard hook + temporary `DisableTaskMgr`** (restored on exit). |
| #6 lockout | **Bundled into this effort** (not a separate hotfix). |
| #7 banner | **Config-driven**: text + fg/bg colors in config; **top and bottom** bars; default `SECRET` white-on-red; blank text hides the bars. |
| #8 logo | Config-driven `LogoPath` (blank ⇒ default `assets/GE-Aerospace-Emblem.png`); missing file degrades gracefully (no logo, no crash). |

## 3. Honest ceiling (unchanged)

The keyboard hook + `DisableTaskMgr` close every route found in testing and the Ctrl+Alt+Del → Task Manager path. They do **not** suppress the **Ctrl+Alt+Del Secure Attention Sequence** itself (kernel-level). Sign-out from that screen remains, but it *ends the shared session* rather than bypassing the audit. True pre-logon enforcement and full elimination of the desktop flash need a signed Credential Provider or GPO logon-script changes — out of scope offline.

## 4. Credential-lockout fix — `src/AuditCommon.ps1` (#6)

**Root cause:** `Test-AuditCredential` ([AuditCommon.ps1:445-466](../../../src/AuditCommon.ps1#L445-L466)) loops `NETWORK(3) → NETWORK_CLEARTEXT(8) → INTERACTIVE(2)` and calls `LogonUser` for each; on a wrong password all three fail, each incrementing the account's bad-password count → ~3 strikes per attempt → lockout after 1–2 tries when the threshold is ≤ 5.

**Fix:** after each failed `LogonUser`, read `[System.Runtime.InteropServices.Marshal]::GetLastWin32Error()` immediately (the P/Invoke already sets `SetLastError=true`). Decide whether to try the next logon type via a new **pure, unit-tested** helper:

| Function | Signature | Behaviour |
|---|---|---|
| `Test-AuditShouldTryNextLogonType` | `-Win32Error <int>` → `[bool]` | `$false` for `1326` (`ERROR_LOGON_FAILURE` — password genuinely wrong; stop, don't burn more strikes). `$true` otherwise — notably `1385` (`ERROR_LOGON_TYPE_NOT_GRANTED`, the STIG "deny network logon" case the fallback exists for), so a valid credential still falls through to a permitted logon type. |

In the loop: on failure, if `-not (Test-AuditShouldTryNextLogonType -Win32Error $err)` → `break` (return `$false`). Net effect: a wrong password costs **one** strike, so the operator gets their full lockout threshold of attempts; the STIG network-logon fallback is preserved. No change to the password-handling/zeroing path.

## 5. Lockdown hardening — `src/AuditLockdown.ps1` (#1, new module)

New dot-sourced module isolating the hardening logic (one responsibility; exposes a pure testable predicate). Dot-sourced by `SharedAccountAuth.ps1` after `AuditCommon.ps1`. PS 5.1 / built-ins / offline.

| Function | Signature | Behaviour |
|---|---|---|
| `Test-AuditShouldSwallowKey` | `-VkCode <int> -AltDown <bool> -CtrlDown <bool> -ShiftDown <bool>` → `[bool]` | **Pure / unit-tested.** `$true` to swallow: VK `0x5B`/`0x5C` (Left/Right Win, always); VK `0x09` (Tab) when `AltDown` (Alt+Tab); VK `0x1B` (Esc) when `AltDown` (Alt+Esc) **or** `CtrlDown` (Ctrl+Esc Start; Ctrl+Shift+Esc Task Manager — both CtrlDown). `$false` otherwise (plain typing, bare Tab, backspace, Enter, lone Esc — WPF owns those). |
| `Install-AuditKeyboardHook` | *(none)* → `[bool]` | `WH_KEYBOARD_LL` hook via `Add-Type` P/Invoke. Callback tracks Alt/Ctrl/Shift down-state and calls `Test-AuditShouldSwallowKey`; swallows by returning `(IntPtr)1`. Delegate stored module-scope (not GC'd); callback try/catch → falls through to `CallNextHookEx` on error (never throws/breaks input). |
| `Remove-AuditKeyboardHook` | *(none)* → `void` | `UnhookWindowsHookEx`; idempotent; never throws. |
| `Set-AuditTaskMgrPolicy` | `-Config <hashtable>` → `void` | Captures current `HKCU:\…\Policies\System\DisableTaskMgr` (absent vs value) to `LocalRoot\state`, then sets it `1`. Idempotent; never throws. |
| `Restore-AuditTaskMgrPolicy` | `-Config <hashtable>` → `void` | Restores from the captured marker (delete if it was absent), clears marker. Idempotent; never throws. |

**Lifecycle in `SharedAccountAuth.ps1`:** dot-source the module; in the window `Loaded` handler `Set-AuditTaskMgrPolicy` + `Install-AuditKeyboardHook`; in `Closing` **and** the outer `finally`/`catch` `Remove-AuditKeyboardHook` + `Restore-AuditTaskMgrPolicy` (idempotent ⇒ safe to call twice). The WPF `Dispatcher` (`ShowDialog`) pumps messages so the hook fires. A hard-kill that skips `finally` self-heals on the next run (idempotent set/restore via the marker).

## 6. Prompt UI changes — `src/SharedAccountAuth.ps1` (XAML + code-behind)

### 6.1 Username dropdown (#2)
Build the `ComboBox` items and `displayToEntry` lookup from **`Username`** (sorted case-insensitively); the substring filter operates on usernames. Selection resolves to the same roster entry; `Write-AuditRow` still logs `Username`/`LastName`/`FirstName` — CSV unchanged.

### 6.2 Dropdown affordance (#3)
Style `NameCombo`: explicit border (`#FF3A4656`), dark editable background + light foreground, a larger high-contrast drop-arrow glyph, and a "— select your name —" watermark (overlay `TextBlock` visible only when empty). Keep `IsEditable`/type-to-filter.

### 6.3 Confirm button (#5)
`Style` + `ControlTemplate`: rounded `Border` (`CornerRadius="6"`) whose fill is driven by `IsEnabled` triggers — **enabled** `#FF2D6CDF`/white; **disabled** `#FF33404F` fill, `#FF8A97A6` text, `#FF3A4656` border. Reads unambiguously as a button in both states. No change to `$updateState` enable logic.

### 6.4 Classification banner (#7)
Two full-width bars docked to the **top and bottom edges** of the root full-screen `Grid` (outside the centered card), each showing `ClassificationText` centered, bold, `ClassificationForeground` on `ClassificationBackground`. If `ClassificationText` is blank, both bars are collapsed (`Visibility=Collapsed`) — non-classified sites show nothing.

### 6.5 GE logo (#8)
A WPF `Image` at the top of the card's `StackPanel`, max height ~56 px, `Stretch=Uniform`. Source resolved from `LogoPath` (blank ⇒ `<InstallRoot>\assets\GE-Aerospace-Emblem.png`, where `InstallRoot = Split-Path -Parent $PSScriptRoot`), loaded as a `BitmapImage` with `CacheOption=OnLoad` from an absolute path (offline). If the file is missing/unreadable, the `Image` stays collapsed — no crash.

### 6.6 Cover-before-roster (#4, prompt half)
Show the full-screen opaque cover window **first**, then do the (possibly slow, central-UNC) roster fetch + control population in the `Loaded` handler with a transient "Loading…" status and Confirm disabled. Self-check + debounce still run **before** the window is created. Shrinks time-to-cover.

## 7. Config schema additions — `config/AuditConfig.psd1`
New keys (all optional; `Get-AuditConfig` fills defaults if absent, so older configs and StrictMode stay safe):

```powershell
ClassificationText       = 'SECRET'          # blank => no banner
ClassificationForeground = '#FFFFFFFF'       # white
ClassificationBackground = '#FFCE2029'       # SECRET red (configurable)
LogoPath                 = ''                # blank => <InstallRoot>\assets\GE-Aerospace-Emblem.png
```

`Get-AuditConfig` adds these defaults when missing. The installer's `Write-AuditConfigFile` (`deploy/AuditInstallCommon.ps1`) known-keys list gains the four keys so the GUI/CLI preserve them on write.

## 8. Task priority — `deploy/Register-AuditTasks.ps1` (#4, launch half)
`<Priority>7</Priority>` → `<Priority>4</Priority>` for both tasks; regenerate `tasks/*.xml`. Reduces but does not eliminate the flash (§3).

## 9. Out of scope (YAGNI)
Credential Provider (compiled COM); GPO synchronous logon script; suppressing Ctrl+Alt+Del; per-monitor blocker windows; AppLocker/GPO authoring.

## 10. Constraints honoured (parent §17)
PS 5.1 only; .NET 4.x WPF + Win32 P/Invoke via `Add-Type`; no external modules; fully offline; **no password ever** read/copied/logged (none of these changes touch the credential path except the lockout fix, which only reads an error code — never the password); **degrade safely** — hook/policy/logo/banner helpers never throw; the prompt never crashes to an unlocked desktop.

## 11. Testing
- **Unit (automated), new `tests/Test-AuditLockdown.ps1`** (no-Pester, mirrors `Test-AuditInstall.ps1`; dot-sources `src/AuditLockdown.ps1` + `src/AuditCommon.ps1`):
  - `Test-AuditShouldSwallowKey` truth table — Win keys / Alt+Tab / Ctrl+Esc / Ctrl+Shift+Esc swallowed; bare Tab / letters / digits / Enter / lone Esc not.
  - `Test-AuditShouldTryNextLogonType` — `1326` ⇒ `$false`; `1385` and others ⇒ `$true`.
- **Parse/XAML:** parse-check `SharedAccountAuth.ps1`, `AuditLockdown.ps1`, `AuditCommon.ps1`, `Register-AuditTasks.ps1`; load the prompt XAML via `XamlReader` and assert named controls resolve (`NameCombo`, `PwBox`, `ConfirmButton`, `StatusText`, `TopBanner`, `BottomBanner`, `LogoImage`).
- **Task XML:** assert generated Logon/Unlock XML contains `<Priority>4</Priority>`.
- **Manual smoke (required before field use):** on a target shared session — Win/Win+R/Alt+Tab/Ctrl+Shift+Esc all swallowed; Task Manager disabled during, restored after; **wrong password no longer locks the account in 1–2 tries**; disabled Confirm reads as a button; dropdown shows usernames with clear arrow + watermark; SECRET bars top+bottom; GE logo renders; reduced desktop-visible interval. The live hook, `DisableTaskMgr`, and real `LogonUser` lockout behavior aren't automatable here.

## 12. Impact on existing files
| File | Change |
|---|---|
| `src/AuditLockdown.ps1` | **New** — keyboard hook + swallow predicate + TaskMgr policy set/restore. |
| `src/AuditCommon.ps1` | `Test-AuditCredential` error-code-aware fallback; new `Test-AuditShouldTryNextLogonType`; `Get-AuditConfig` fills the 4 new config defaults. |
| `src/SharedAccountAuth.ps1` | Dot-source lockdown module; hook/policy lifecycle; username dropdown; combo/button styling; classification bars; logo Image; cover-before-roster. |
| `config/AuditConfig.psd1` | Add `ClassificationText/Foreground/Background`, `LogoPath`. |
| `deploy/AuditInstallCommon.ps1` | Add the 4 new keys to `Write-AuditConfigFile` known-keys (preserve on write). |
| `deploy/Register-AuditTasks.ps1` | `<Priority>7</Priority>` → `4`; regenerate `tasks/*.xml`. |
| `assets/GE-Aerospace-Emblem.png` | **New** (moved from repo root). |
| `tests/Test-AuditLockdown.ps1` | **New** — predicate truth-table tests. |
| `docs/.../2026-06-17-…-design.md` | Revise "no hooks/no policy edits" + restate the honest ceiling (rev note). |
| `README.md` | §6 STIG / §11 limitations: new hardening + lockout fix + remaining ceiling; note `assets/` in the deploy tree. |
