# Runtime Prompt Hardening + UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the keyboard bypass, fix the credential lockout, switch the name dropdown to usernames (username-only roster), restyle the combo box + Confirm button, add a config-driven classification banner + GE logo, and minimize the logon desktop flash — all in the runtime prompt.

**Architecture:** Four **pure, unit-tested** decision helpers carry the automated coverage (`Test-AuditShouldSwallowKey`, `Test-AuditShouldTryNextLogonType`, `Get-AuditClassification`, `ConvertFrom-AuditRoster`). A new `src/AuditLockdown.ps1` isolates the Win32 keyboard hook + Task-Manager-policy plumbing (parse-checked + manual smoke). The prompt (`src/SharedAccountAuth.ps1`) wires them into its WPF window. Config/installer/task/docs follow.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework 4.x WPF (XAML via `XamlReader`), Win32 P/Invoke via `Add-Type` (`SetWindowsHookEx`, `LogonUser`), ADSI, ScheduledTasks. No external modules. Tests are plain built-in PowerShell (no Pester).

## Global Constraints

- **Windows PowerShell 5.1 syntax only** — no PS7-only constructs (`??`, `?.`, ternary, `&&`, `||`, `ForEach-Object -Parallel`, `Clean{}`).
- **.NET Framework 4.x WPF** + Win32 P/Invoke via `Add-Type`. No external modules. Fully offline.
- **No password ever** read into a string, copied, or logged. The lockout fix reads only `GetLastWin32Error()`, never the password.
- **Degrade safely:** hook, policy, classification, roster, and logo helpers **never throw**; the prompt never crashes to an unlocked desktop.
- **Diagnostics** via `Write-AuditDiag` never throw.
- **Style:** `Verb-Noun`, comment-based help on each function, header block on each script; match the heavy-comment density of the surrounding files.
- Tests run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\<file>.ps1` (exit 0 = pass).
- **Spec:** [docs/superpowers/specs/2026-06-18-prompt-hardening-ux-design.md](../specs/2026-06-18-prompt-hardening-ux-design.md).
- **Honest ceiling:** Ctrl+Alt+Del Secure Attention Sequence cannot be suppressed; some desktop flash is intrinsic to the scheduled-task approach. Do not claim otherwise.

---

### Task 1: `src/AuditLockdown.ps1` module + test harness

Create the hardening module (pure swallow predicate + keyboard hook + Task-Manager policy) and the new test harness covering the predicate.

**Files:**
- Create: `src/AuditLockdown.ps1`
- Create: `tests/Test-AuditLockdown.ps1`

**Interfaces:**
- Produces:
  - `Test-AuditShouldSwallowKey -VkCode <int> [-AltDown <bool>] [-CtrlDown <bool>] [-ShiftDown <bool>]` → `[bool]`
  - `Install-AuditKeyboardHook` → `[bool]`; `Remove-AuditKeyboardHook` → `void`
  - `Set-AuditTaskMgrPolicy -Config <hashtable>` → `void`; `Restore-AuditTaskMgrPolicy -Config <hashtable>` → `void`

- [ ] **Step 1: Write the failing harness**

Create `tests/Test-AuditLockdown.ps1`:

```powershell
# Built-in test runner (no Pester) for the lockdown/hardening + helper logic.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$RepoRoot       = Split-Path -Parent $PSScriptRoot
$LockdownPath   = Join-Path $RepoRoot 'src\AuditLockdown.ps1'
$CommonPath     = Join-Path $RepoRoot 'src\AuditCommon.ps1'

$script:Failures = 0
function Assert-True($cond, $msg) {
    if ($cond) { Write-Host "  PASS  $msg" -ForegroundColor Green }
    else { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++ }
}
function Assert-Eq($actual, $expected, $msg) {
    Assert-True ($actual -eq $expected) ("{0} (expected '{1}', got '{2}')" -f $msg, $expected, $actual)
}

. $LockdownPath
. $CommonPath

Write-Host 'Task 1: Test-AuditShouldSwallowKey'
Assert-True  (Test-AuditShouldSwallowKey -VkCode 0x5B) 'LWin swallowed'
Assert-True  (Test-AuditShouldSwallowKey -VkCode 0x5C) 'RWin swallowed'
Assert-True  (Test-AuditShouldSwallowKey -VkCode 0x09 -AltDown $true)  'Alt+Tab swallowed'
Assert-True  (-not (Test-AuditShouldSwallowKey -VkCode 0x09))          'bare Tab NOT swallowed'
Assert-True  (Test-AuditShouldSwallowKey -VkCode 0x1B -CtrlDown $true) 'Ctrl+Esc swallowed'
Assert-True  (Test-AuditShouldSwallowKey -VkCode 0x1B -AltDown $true)  'Alt+Esc swallowed'
Assert-True  (-not (Test-AuditShouldSwallowKey -VkCode 0x1B))          'lone Esc NOT swallowed'
Assert-True  (-not (Test-AuditShouldSwallowKey -VkCode 0x41 -ShiftDown $true)) 'Shift+A (typing) NOT swallowed'
Assert-True  (-not (Test-AuditShouldSwallowKey -VkCode 0x0D))          'Enter NOT swallowed'

Write-Host ''
if ($script:Failures -gt 0) { Write-Host ("$($script:Failures) failure(s)") -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: FAIL — `src\AuditLockdown.ps1` does not exist (dot-source throws).

- [ ] **Step 3: Create `src/AuditLockdown.ps1`**

```powershell
<#
=======================================================================
 AuditLockdown.ps1 - desktop-lockdown hardening for the sign-on prompt.
 PS 5.1 / .NET 4.x / built-ins only; fully offline. Dot-sourced by
 SharedAccountAuth.ps1. Provides: a PURE key-swallow predicate (unit
 tested), a WH_KEYBOARD_LL keyboard hook that blocks shell hotkeys
 (Win, Win+R, Alt+Tab, Ctrl+Esc, Ctrl+Shift+Esc) while the prompt is up,
 and a temporary DisableTaskMgr policy (captured + restored).

 HONEST CEILING: this cannot suppress Ctrl+Alt+Del (the kernel Secure
 Attention Sequence). It closes user-mode shell-hotkey routes only.
 Every function NEVER throws (a hardening helper must not crash the
 prompt to an unlocked desktop).
=======================================================================
#>
Set-StrictMode -Version 2.0

# Module-scope hook state. The delegate MUST be kept alive in a variable
# or the GC collects it and the callback crashes. The handle is needed to
# unhook. Modifier down-state is tracked from the event stream.
$script:AuditHookHandle    = [System.IntPtr]::Zero
$script:AuditHookProc      = $null
$script:AuditHookAltDown   = $false
$script:AuditHookCtrlDown  = $false
$script:AuditHookShiftDown = $false

function Test-AuditShouldSwallowKey {
<#
.SYNOPSIS Pure predicate: should this key (with modifiers) be blocked while the prompt is up?
.DESCRIPTION Blocks the shell hotkeys that escape the lock: Win keys (Start/Win+R/Win+X),
             Alt+Tab, and Esc with Ctrl/Alt (Ctrl+Esc Start, Ctrl+Shift+Esc Task Manager,
             Alt+Esc). Leaves plain typing, bare Tab, backspace, Enter, and lone Esc alone
             (the WPF window owns Esc/Alt+F4/Enter).
.OUTPUTS [bool]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int] $VkCode,
        [bool] $AltDown,
        [bool] $CtrlDown,
        [bool] $ShiftDown
    )
    if ($VkCode -eq 0x5B -or $VkCode -eq 0x5C) { return $true }          # Left/Right Win
    if ($VkCode -eq 0x09 -and $AltDown) { return $true }                # Alt+Tab
    if ($VkCode -eq 0x1B -and ($AltDown -or $CtrlDown)) { return $true }# Alt+Esc / Ctrl+Esc / Ctrl+Shift+Esc
    return $false
}

function Install-AuditKeyboardHook {
<#
.SYNOPSIS Install a WH_KEYBOARD_LL hook that swallows shell hotkeys per Test-AuditShouldSwallowKey.
.OUTPUTS [bool] $true if installed (or already installed). Never throws.
#>
    [CmdletBinding()]
    param()
    try {
        if ($script:AuditHookHandle -ne [System.IntPtr]::Zero) { return $true }

        if (-not ([System.Management.Automation.PSTypeName]'SharedAccountAuth.NativeHook').Type) {
            Add-Type -Namespace 'SharedAccountAuth' -Name 'NativeHook' -MemberDefinition @'
public delegate System.IntPtr LowLevelKeyboardProc(int nCode, System.IntPtr wParam, System.IntPtr lParam);

[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern System.IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, System.IntPtr hMod, uint dwThreadId);

[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern bool UnhookWindowsHookEx(System.IntPtr hhk);

[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern System.IntPtr CallNextHookEx(System.IntPtr hhk, int nCode, System.IntPtr wParam, System.IntPtr lParam);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr GetModuleHandle(string lpModuleName);
'@
        }

        $WH_KEYBOARD_LL = 13
        $WM_KEYDOWN = 0x0100; $WM_KEYUP = 0x0101; $WM_SYSKEYDOWN = 0x0104; $WM_SYSKEYUP = 0x0105

        $script:AuditHookProc = [SharedAccountAuth.NativeHook+LowLevelKeyboardProc]{
            param([int] $nCode, [System.IntPtr] $wParam, [System.IntPtr] $lParam)
            try {
                if ($nCode -ge 0) {
                    $msg = $wParam.ToInt32()
                    $vk  = [System.Runtime.InteropServices.Marshal]::ReadInt32($lParam)   # KBDLLHOOKSTRUCT.vkCode (first DWORD)
                    $isDown = ($msg -eq $WM_KEYDOWN -or $msg -eq $WM_SYSKEYDOWN)

                    # Track modifier down-state (generic + L/R specific VKs).
                    if ($vk -eq 0x12 -or $vk -eq 0xA4 -or $vk -eq 0xA5) { $script:AuditHookAltDown   = $isDown }
                    if ($vk -eq 0x11 -or $vk -eq 0xA2 -or $vk -eq 0xA3) { $script:AuditHookCtrlDown  = $isDown }
                    if ($vk -eq 0x10 -or $vk -eq 0xA0 -or $vk -eq 0xA1) { $script:AuditHookShiftDown = $isDown }

                    if (Test-AuditShouldSwallowKey -VkCode $vk `
                            -AltDown $script:AuditHookAltDown `
                            -CtrlDown $script:AuditHookCtrlDown `
                            -ShiftDown $script:AuditHookShiftDown) {
                        return [System.IntPtr]1   # swallow (both down and up of the blocked key)
                    }
                }
            } catch {
                # Never break input on an error - fall through to the next hook.
            }
            return [SharedAccountAuth.NativeHook]::CallNextHookEx([System.IntPtr]::Zero, $nCode, $wParam, $lParam)
        }

        $hMod = [SharedAccountAuth.NativeHook]::GetModuleHandle($null)
        $script:AuditHookHandle = [SharedAccountAuth.NativeHook]::SetWindowsHookEx($WH_KEYBOARD_LL, $script:AuditHookProc, $hMod, 0)
        return ($script:AuditHookHandle -ne [System.IntPtr]::Zero)
    } catch {
        return $false
    }
}

function Remove-AuditKeyboardHook {
<#
.SYNOPSIS Remove the keyboard hook if installed. Idempotent; never throws.
#>
    [CmdletBinding()]
    param()
    try {
        if ($script:AuditHookHandle -ne [System.IntPtr]::Zero) {
            [void][SharedAccountAuth.NativeHook]::UnhookWindowsHookEx($script:AuditHookHandle)
            $script:AuditHookHandle = [System.IntPtr]::Zero
        }
    } catch { }
    $script:AuditHookProc = $null
}

function Get-AuditTaskMgrMarkerPath {
<# Internal: path of the file that records DisableTaskMgr's pre-change state. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable] $Config)
    $stateDir = [string]$Config.StateDir
    if ([string]::IsNullOrWhiteSpace($stateDir)) { $stateDir = Join-Path ([string]$Config.LocalRoot) 'state' }
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
    return (Join-Path $stateDir 'taskmgr-policy.txt')
}

function Set-AuditTaskMgrPolicy {
<#
.SYNOPSIS Temporarily disable Task Manager (HKCU policy), capturing the prior state for restore.
.DESCRIPTION Writes a one-time marker recording whether DisableTaskMgr was absent or its value,
             so a crash self-heals on the next clean exit. Idempotent; never throws.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable] $Config)
    try {
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $marker = Get-AuditTaskMgrMarkerPath -Config $Config

        if (-not (Test-Path -LiteralPath $marker)) {
            $orig = 'absent'
            if (Test-Path -LiteralPath $key) {
                $p = Get-ItemProperty -LiteralPath $key -Name 'DisableTaskMgr' -ErrorAction SilentlyContinue
                if ($null -ne $p -and $null -ne $p.DisableTaskMgr) { $orig = [string][int]$p.DisableTaskMgr }
            }
            Set-Content -LiteralPath $marker -Value $orig -Encoding ASCII
        }

        if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -LiteralPath $key -Name 'DisableTaskMgr' -Value 1 -Type DWord
    } catch { }
}

function Restore-AuditTaskMgrPolicy {
<#
.SYNOPSIS Restore DisableTaskMgr to its captured pre-change state and clear the marker. Idempotent; never throws.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable] $Config)
    try {
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        $marker = Get-AuditTaskMgrMarkerPath -Config $Config
        if (-not (Test-Path -LiteralPath $marker)) { return }

        $orig = (Get-Content -LiteralPath $marker -Raw).Trim()
        if ($orig -eq 'absent') {
            if (Test-Path -LiteralPath $key) {
                Remove-ItemProperty -LiteralPath $key -Name 'DisableTaskMgr' -ErrorAction SilentlyContinue
            }
        } else {
            if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -LiteralPath $key -Name 'DisableTaskMgr' -Value ([int]$orig) -Type DWord
        }
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    } catch { }
}
```

- [ ] **Step 4: Run, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: PASS — 9 predicate assertions green, exit 0.

- [ ] **Step 5: Parse-check the module**

Run:
```powershell
$e=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path src\AuditLockdown.ps1),[ref]$null,[ref]$e);if($e){$e}else{'OK'}
```
Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
git add src/AuditLockdown.ps1 tests/Test-AuditLockdown.ps1
git commit -m "feat: add AuditLockdown.ps1 (keyboard hook + TaskMgr policy) + harness"
```

---

### Task 2: Credential-lockout fix (`Test-AuditShouldTryNextLogonType` + integrate)

**Files:**
- Modify: `src/AuditCommon.ps1` (add helper; change `Test-AuditCredential` loop)
- Modify: `tests/Test-AuditLockdown.ps1` (add predicate tests)

**Interfaces:**
- Produces: `Test-AuditShouldTryNextLogonType -Win32Error <int>` → `[bool]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/Test-AuditLockdown.ps1` before the final tally block:

```powershell
Write-Host 'Task 2: Test-AuditShouldTryNextLogonType'
Assert-True (-not (Test-AuditShouldTryNextLogonType -Win32Error 1326)) '1326 (bad password) => stop'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 1385))     '1385 (type not granted) => try next'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 0))        '0 => try next'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 5))        'access denied => try next'
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: FAIL — `Test-AuditShouldTryNextLogonType` not defined.

- [ ] **Step 3: Add the helper to `src/AuditCommon.ps1`**

Add this function immediately **before** `function Test-AuditCredential {`:

```powershell
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
```

- [ ] **Step 4: Integrate into the `Test-AuditCredential` loop**

In `Test-AuditCredential`, the `else` branch of the `foreach ($logonType ...)` loop (around [AuditCommon.ps1:458-465](../../../src/AuditCommon.ps1#L458-L465)) currently just closes a dangling token. Replace that `else { ... }` block with one that captures the Win32 error **immediately** after the failed call and breaks on a genuine bad-password:

```powershell
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
```

> Note: `$ok = [SharedAccountAuth.NativeLogon]::LogonUser(...)` must be the call right before this; `GetLastWin32Error()` reads the marshaler-cached error from that call. Do not insert other P/Invoke calls between them.

- [ ] **Step 5: Run tests + parse-check**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: PASS (Task 1 + Task 2 assertions).
Run: `powershell -NoProfile -Command "$e=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path src\AuditCommon.ps1),[ref]$null,[ref]$e);if($e){$e}else{'OK'}"`
Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
git add src/AuditCommon.ps1 tests/Test-AuditLockdown.ps1
git commit -m "fix: stop credential fallback on bad-password (1326) to prevent lockout"
```

---

### Task 3: `Get-AuditClassification` (banner color resolver)

**Files:**
- Modify: `src/AuditCommon.ps1` (add function)
- Modify: `tests/Test-AuditLockdown.ps1` (add tests)

**Interfaces:**
- Produces: `Get-AuditClassification -Level <string> [-Text <string>] [-Foreground <string>] [-Background <string>]` → `[pscustomobject]{ Text; Foreground; Background; Show }`

- [ ] **Step 1: Write the failing tests**

Append to `tests/Test-AuditLockdown.ps1` before the tally:

```powershell
Write-Host 'Task 3: Get-AuditClassification'
$s = Get-AuditClassification -Level 'SECRET'
Assert-True $s.Show 'SECRET shown'
Assert-Eq $s.Text 'SECRET' 'SECRET text defaults to level'
Assert-Eq $s.Background '#FFC8102E' 'SECRET red'
Assert-Eq $s.Foreground '#FFFFFFFF' 'SECRET white text'
$ts = Get-AuditClassification -Level 'top secret'
Assert-Eq $ts.Background '#FFFF8C00' 'TOP SECRET orange (case-insensitive)'
Assert-Eq $ts.Foreground '#FF000000' 'TOP SECRET black text'
$cui = Get-AuditClassification -Level 'CUI'
Assert-Eq $cui.Background '#FF512B85' 'CUI purple'
$u = Get-AuditClassification -Level 'UNCLASSIFIED'
Assert-Eq $u.Background '#FF007A33' 'UNCLASSIFIED green'
$blank = Get-AuditClassification -Level ''
Assert-True (-not $blank.Show) 'blank level hidden'
$bogus = Get-AuditClassification -Level 'NOPE'
Assert-True (-not $bogus.Show) 'unknown level hidden'
$ovr = Get-AuditClassification -Level 'SECRET' -Text 'SECRET//NOFORN' -Background '#FF990000'
Assert-Eq $ovr.Text 'SECRET//NOFORN' 'text override'
Assert-Eq $ovr.Background '#FF990000' 'background override'
Assert-Eq $ovr.Foreground '#FFFFFFFF' 'foreground still default'
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: FAIL — `Get-AuditClassification` not defined.

- [ ] **Step 3: Add the function to `src/AuditCommon.ps1`**

Add near the other config helpers:

```powershell
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
```

- [ ] **Step 4: Run tests, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/AuditCommon.ps1 tests/Test-AuditLockdown.ps1
git commit -m "feat: add Get-AuditClassification banner resolver"
```

---

### Task 4: Username-only roster (`ConvertFrom-AuditRoster`)

Extract the roster row → entries logic into a pure helper that requires **only `Username`**, and route `Get-AuditRosterEntries` through it.

**Files:**
- Modify: `src/AuditCommon.ps1` (add `ConvertFrom-AuditRoster`; call it from `Get-AuditRosterEntries`)
- Modify: `sample/roster.csv`
- Modify: `tests/Test-AuditLockdown.ps1` (add tests)

**Interfaces:**
- Produces: `ConvertFrom-AuditRoster -Rows <object[]>` → `[pscustomobject]{ Entries = @(@{LastName;FirstName;Username;Display}); Valid = [bool] }`

- [ ] **Step 1: Write the failing tests**

Append to `tests/Test-AuditLockdown.ps1` before the tally:

```powershell
Write-Host 'Task 4: ConvertFrom-AuditRoster'
$r1 = ConvertFrom-AuditRoster -Rows @([pscustomobject]@{Username='bnguyen'}, [pscustomobject]@{Username='asmith'})
Assert-True $r1.Valid 'username-only roster valid'
Assert-Eq @($r1.Entries).Count 2 'two entries'
Assert-Eq @($r1.Entries)[0].Username 'asmith' 'sorted by username (asmith first)'
Assert-Eq @($r1.Entries)[0].Display 'asmith' 'display defaults to username'
Assert-Eq @($r1.Entries)[0].LastName '' 'lastname blank when absent'
$r2 = ConvertFrom-AuditRoster -Rows @([pscustomobject]@{LastName='Smith';FirstName='Alice';Username='asmith'})
Assert-Eq @($r2.Entries)[0].Display 'Smith, Alice' 'display uses names when present'
$r3 = ConvertFrom-AuditRoster -Rows @([pscustomobject]@{Name='foo'})
Assert-True (-not $r3.Valid) 'missing Username column => invalid'
$r4 = ConvertFrom-AuditRoster -Rows @([pscustomobject]@{Username='dup'}, [pscustomobject]@{Username='dup'})
Assert-Eq @($r4.Entries).Count 1 'deduped by username'
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: FAIL — `ConvertFrom-AuditRoster` not defined.

- [ ] **Step 3: Add `ConvertFrom-AuditRoster` to `src/AuditCommon.ps1`**

Add it immediately **before** `function Get-AuditRosterEntries {`:

```powershell
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
```

- [ ] **Step 4: Route `Get-AuditRosterEntries` through it**

Read `Get-AuditRosterEntries` (around [AuditCommon.ps1:900-1010](../../../src/AuditCommon.ps1#L900)). It currently: reads CSV rows (central → cache), **validates `LastName,FirstName,Username` all present**, builds entries inline, sorts, dedupes. Replace the inline column-validation + per-row build + sort + dedup with a single call to `ConvertFrom-AuditRoster` on the parsed rows:

- Where it currently checks `($props -notcontains 'LastName') -or ($props -notcontains 'FirstName') -or ($props -notcontains 'Username')` and the row-build loop, replace with:
```powershell
        $parsed = ConvertFrom-AuditRoster -Rows $rows
        if (-not $parsed.Valid) {
            Write-AuditDiag -Config $Config -Level Error -Message ("Roster missing Username column (source={0})." -f $source)
            # fall through to the next source (cache) or return none, per the existing control flow
        } else {
            $built = $parsed.Entries
        }
```
Preserve the function's existing central→cache fallback, cache-refresh-on-central-success, and the final `@{ Entries; Source }` return shape (`Entries = $built`, sorted/deduped already by the helper). Keep `Display` consumers working (the prompt now uses Username anyway).

- [ ] **Step 5: Update `sample/roster.csv`**

Replace the contents of `sample/roster.csv` with a username-only example plus a commented note that names are optional:

```csv
Username
asmith
bnguyen
cobrien
dgarcia
```

- [ ] **Step 6: Run tests + parse-check**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1` → PASS.
Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1` → still PASS (roster preview path unaffected).
Parse-check `src\AuditCommon.ps1` → `OK`.

- [ ] **Step 7: Commit**

```bash
git add src/AuditCommon.ps1 sample/roster.csv tests/Test-AuditLockdown.ps1
git commit -m "feat: roster requires only Username (ConvertFrom-AuditRoster)"
```

---

### Task 5: Config keys + defaults

Add the five new keys to the config template, fill defaults in `Get-AuditConfig`, and preserve them in the installer's `Write-AuditConfigFile`.

**Files:**
- Modify: `config/AuditConfig.psd1`
- Modify: `src/AuditCommon.ps1` (`Get-AuditConfig` defaults)
- Modify: `deploy/AuditInstallCommon.ps1` (`Write-AuditConfigFile` known-keys + defaults)
- Modify: `tests/Test-AuditInstall.ps1` (round-trip a new key)

**Interfaces:** none new (config plumbing).

- [ ] **Step 1: Write the failing test**

Append to `tests/Test-AuditInstall.ps1` before its tally block:

```powershell
Write-Host 'Task 5: classification/logo config keys round-trip'
$tmpC = Join-Path $env:TEMP ('audcfg2-' + [System.IO.Path]::GetRandomFileName() + '.psd1')
try {
    [void](Write-AuditConfigFile -ConfigPath $tmpC -Settings @{
        LogPath='\\s\a\l.csv'; RosterPath='\\s\a\r.csv'; SharedAccount='.\X'
        ClassificationLevel='TOP SECRET'; LogoPath='C:\x\logo.png'
    } -NoBackup)
    $rc = Import-PowerShellDataFile -LiteralPath $tmpC
    Assert-Eq $rc.ClassificationLevel 'TOP SECRET' 'ClassificationLevel round-trips'
    Assert-Eq $rc.LogoPath 'C:\x\logo.png' 'LogoPath round-trips'
    Assert-Eq $rc.ClassificationForeground '' 'unspecified classification key defaults to empty'
} finally { Remove-Item -LiteralPath $tmpC -Force -ErrorAction SilentlyContinue }
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — the keys aren't in `Write-AuditConfigFile`'s known list, so they aren't emitted (`ClassificationLevel` missing from the re-read file).

- [ ] **Step 3: Add the keys to `config/AuditConfig.psd1`**

Add before the closing `}` (after the UI text block):

```powershell

    # --- Classification banner (top + bottom). Level drives default colors;
    #     blank/unknown level => no banner. Override text/colors as needed. ---
    ClassificationLevel      = 'SECRET'   # '' | UNCLASSIFIED | CUI | CONFIDENTIAL | SECRET | TOP SECRET
    ClassificationText       = ''         # '' => the level name (e.g. set 'SECRET//NOFORN')
    ClassificationForeground = ''         # '' => level default (ARGB #AARRGGBB)
    ClassificationBackground = ''         # '' => level default

    # --- Logo on the auth card. Blank => <InstallRoot>\assets\GE-Aerospace-Emblem.png ---
    LogoPath                 = ''
```

- [ ] **Step 4: Fill defaults in `Get-AuditConfig`**

In `src/AuditCommon.ps1`, inside `Get-AuditConfig`, after the existing derived-path/`SharedAccount` handling and before it returns the config hashtable, add (idempotent — only set when the key is absent):

```powershell
    # New optional keys: ensure present so the prompt can read them under StrictMode.
    foreach ($kv in @(
        @{ K = 'ClassificationLevel';      V = '' },
        @{ K = 'ClassificationText';       V = '' },
        @{ K = 'ClassificationForeground'; V = '' },
        @{ K = 'ClassificationBackground'; V = '' },
        @{ K = 'LogoPath';                 V = '' })) {
        if (-not $cfg.ContainsKey($kv.K)) { $cfg[$kv.K] = $kv.V }
    }
```
(Use the actual config hashtable variable name from `Get-AuditConfig` in place of `$cfg` if different.)

- [ ] **Step 5: Add the keys to `Write-AuditConfigFile`**

In `deploy/AuditInstallCommon.ps1`, in `Write-AuditConfigFile`: add the five keys to `$known` (after `WindowSubtitle`), add their defaults to `$defaults` (all `''`), and emit them in the builder after the UI-text block:

```powershell
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Classification banner + logo ---')
    [void]$sb.AppendLine(('    ClassificationLevel      = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationLevel')))
    [void]$sb.AppendLine(('    ClassificationText       = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationText')))
    [void]$sb.AppendLine(('    ClassificationForeground = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationForeground')))
    [void]$sb.AppendLine(('    ClassificationBackground = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationBackground')))
    [void]$sb.AppendLine(('    LogoPath                 = {0}' -f (ConvertTo-AuditPsd1Value 'LogoPath')))
```
And in `$known` add: `'ClassificationLevel','ClassificationText','ClassificationForeground','ClassificationBackground','LogoPath'`; in `$defaults` add each `= ''`. (Default `ClassificationLevel` to `''` in `Write-AuditConfigFile` — the GUI passes the value the operator chose; the template file is what ships `SECRET`.)

- [ ] **Step 6: Run both harnesses + parse-check**

Run `tests\Test-AuditInstall.ps1` → PASS; `tests\Test-AuditLockdown.ps1` → PASS. Parse-check `src\AuditCommon.ps1` and `deploy\AuditInstallCommon.ps1` → `OK`.

- [ ] **Step 7: Commit**

```bash
git add config/AuditConfig.psd1 src/AuditCommon.ps1 deploy/AuditInstallCommon.ps1 tests/Test-AuditInstall.ps1
git commit -m "feat: add classification + logo config keys (defaults + writer)"
```

---

### Task 6: Prompt integration — `src/SharedAccountAuth.ps1`

Wire everything into the WPF prompt: username dropdown, combo/button styling + watermark, classification bars, logo, keyboard-hook + Task-Manager-policy lifecycle, and cover-before-roster. This is one reviewable deliverable (the XAML names and code-behind must agree); the predicate logic it relies on is already tested in Tasks 1–4.

**Files:**
- Modify: `src/SharedAccountAuth.ps1`
- Modify: `tests/Test-AuditLockdown.ps1` (XAML-load + named-control assertions)

**Interfaces:**
- Consumes: `Test-AuditShouldSwallowKey`, `Install-AuditKeyboardHook`, `Remove-AuditKeyboardHook`, `Set-AuditTaskMgrPolicy`, `Restore-AuditTaskMgrPolicy` (AuditLockdown.ps1); `Get-AuditClassification`, `Get-AuditRosterEntries` (AuditCommon.ps1).
- Produces: `Get-AuditPromptXaml` → `[string]` (factored XAML so the test can load it without showing the window).

- [ ] **Step 1: Write the failing test**

Append to `tests/Test-AuditLockdown.ps1` before the tally:

```powershell
Write-Host 'Task 6: prompt XAML + named controls'
$promptPath = Join-Path $RepoRoot 'src\SharedAccountAuth.ps1'
. $promptPath   # must NOT run the prompt body (guarded) - only define functions
Assert-True ([bool](Get-Command Get-AuditPromptXaml -ErrorAction SilentlyContinue)) 'Get-AuditPromptXaml defined'
Add-Type -AssemblyName PresentationFramework
$w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml](Get-AuditPromptXaml))))
foreach ($n in 'TopBanner','BottomBanner','LogoImage','NameCombo','PwBox','ConfirmButton','StatusText') {
    Assert-True ($null -ne $w.FindName($n)) "control '$n' present"
}
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1`
Expected: FAIL — `Get-AuditPromptXaml` not defined (and dot-sourcing currently runs the prompt body).

- [ ] **Step 3: Make the prompt body dot-source-safe + factor the XAML**

In `src/SharedAccountAuth.ps1`:
1. Dot-source the lockdown module next to the common one (after `. (Join-Path $PSScriptRoot 'AuditCommon.ps1')`):
```powershell
    . (Join-Path $PSScriptRoot 'AuditLockdown.ps1')
```
2. Move the `$xaml = @' … '@` here-string into a function `Get-AuditPromptXaml` (returns the string), defined near the top (after param/StrictMode, before the main `try`). Replace the inline `$xaml = @'...'@` with `$xaml = Get-AuditPromptXaml`.
3. Guard the main body so dot-sourcing (for tests) does not execute it: wrap the existing top-level `try { … } catch { … }` flow in:
```powershell
if ($MyInvocation.InvocationName -ne '.') {
    # ... existing startup try/catch (config load, self-check, debounce, window, ShowDialog) ...
}
```
(Keep `Get-AuditPromptXaml` and any other helper functions OUTSIDE the guard so they are defined on dot-source.)

- [ ] **Step 4: XAML — banners, logo, combo style, button style, watermark**

Edit `Get-AuditPromptXaml`'s returned XAML:

a. **Root layout** — wrap the existing centered card so two full-width bars dock top and bottom. Replace the outer `<Grid> … </Grid>` with a `DockPanel`:
```xml
  <DockPanel>
    <Border x:Name="TopBanner" DockPanel.Dock="Top" Background="#FFC8102E" Visibility="Collapsed" Padding="0,4">
      <TextBlock x:Name="TopBannerText" Text="" Foreground="#FFFFFFFF" FontWeight="Bold" FontSize="14" HorizontalAlignment="Center"/>
    </Border>
    <Border x:Name="BottomBanner" DockPanel.Dock="Bottom" Background="#FFC8102E" Visibility="Collapsed" Padding="0,4">
      <TextBlock x:Name="BottomBannerText" Text="" Foreground="#FFFFFFFF" FontWeight="Bold" FontSize="14" HorizontalAlignment="Center"/>
    </Border>
    <Grid>
      <!-- existing centered card Border goes here, unchanged -->
    </Grid>
  </DockPanel>
```

b. **Logo** — at the very top of the card's `<StackPanel>` (before `TitleText`):
```xml
        <Image x:Name="LogoImage" MaxHeight="56" Stretch="Uniform" HorizontalAlignment="Left" Margin="0,0,0,12" Visibility="Collapsed"/>
```

c. **Confirm button** — replace the `<Button x:Name="ConfirmButton" …/>` with a styled one:
```xml
        <Button x:Name="ConfirmButton" Content="Confirm" IsEnabled="False" FontSize="17" Height="44" Margin="0,18,0,0" Foreground="#FFFFFFFF" BorderThickness="0">
          <Button.Style>
            <Style TargetType="Button">
              <Setter Property="Template">
                <Setter.Value>
                  <ControlTemplate TargetType="Button">
                    <Border x:Name="bd" CornerRadius="6" Background="#FF2D6CDF" BorderBrush="#FF3A4656" BorderThickness="0">
                      <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsEnabled" Value="False">
                        <Setter TargetName="bd" Property="Background" Value="#FF33404F"/>
                        <Setter TargetName="bd" Property="BorderThickness" Value="1"/>
                        <Setter Property="Foreground" Value="#FF8A97A6"/>
                      </Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </Setter.Value>
              </Setter>
            </Style>
          </Button.Style>
        </Button>
```
(`<Border>…</Border>` holds the `ContentPresenter`; `<ControlTemplate.Triggers>` is a sibling of that `Border` inside the `ControlTemplate`. The XAML-load test in Step 1 will catch any structural slip.)

d. **Combo affordance + watermark** — give `NameCombo` an explicit border and add a watermark overlay. Wrap the existing `<ComboBox x:Name="NameCombo" …/>` and a watermark `TextBlock` in a `Grid`:
```xml
        <Grid>
          <ComboBox x:Name="NameCombo" IsEditable="True" IsTextSearchEnabled="True" StaysOpenOnEdit="True" FontSize="18" Height="40" BorderBrush="#FF3A4656" BorderThickness="1"/>
          <TextBlock x:Name="NameWatermark" Text="— select your name —" Foreground="#FF6B7480" FontSize="15" Margin="10,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
        </Grid>
```

- [ ] **Step 5: Code-behind — grab new controls, classification, logo, username items, hook lifecycle, cover-first**

a. After the existing `FindName` block, grab the new controls:
```powershell
    $topBanner       = $window.FindName('TopBanner')
    $topBannerText   = $window.FindName('TopBannerText')
    $bottomBanner    = $window.FindName('BottomBanner')
    $bottomBannerText= $window.FindName('BottomBannerText')
    $logoImage       = $window.FindName('LogoImage')
    $nameWatermark   = $window.FindName('NameWatermark')
```

b. **Classification bars** — resolve and apply (after the static text block):
```powershell
    $cls = Get-AuditClassification -Level ([string]$cfg.ClassificationLevel) `
                                   -Text ([string]$cfg.ClassificationText) `
                                   -Foreground ([string]$cfg.ClassificationForeground) `
                                   -Background ([string]$cfg.ClassificationBackground)
    if ($cls.Show) {
        $bg = [System.Windows.Media.BrushConverter]::new().ConvertFromString($cls.Background)
        $fg = [System.Windows.Media.BrushConverter]::new().ConvertFromString($cls.Foreground)
        $topBanner.Background = $bg; $bottomBanner.Background = $bg
        $topBannerText.Foreground = $fg; $bottomBannerText.Foreground = $fg
        $topBannerText.Text = $cls.Text; $bottomBannerText.Text = $cls.Text
        $topBanner.Visibility = 'Visible'; $bottomBanner.Visibility = 'Visible'
    }
```

c. **Logo** — load from `LogoPath` (blank ⇒ default), collapse on failure:
```powershell
    try {
        $logoPath = [string]$cfg.LogoPath
        if ([string]::IsNullOrWhiteSpace($logoPath)) {
            $logoPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets\GE-Aerospace-Emblem.png'
        }
        if (Test-Path -LiteralPath $logoPath) {
            $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
            $bmp.BeginInit()
            $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $bmp.UriSource = New-Object System.Uri((Resolve-Path -LiteralPath $logoPath).Path)
            $bmp.EndInit()
            $logoImage.Source = $bmp
            $logoImage.Visibility = 'Visible'
        }
    } catch { }   # missing/unreadable logo => no logo, no crash
```

d. **Username items** — change the dropdown source from `Display` to `Username`. Where `$displayList`/`$displayToEntry` are built, key on `Username` and sort:
```powershell
    $displayToEntry = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $displayList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in ($entries | Sort-Object -Property Username)) {
        $u = [string]$e.Username
        if (-not $displayToEntry.ContainsKey($u)) { $displayToEntry[$u] = $e; $displayList.Add($u) }
    }
```
The `$updateState`/`$onNameTextChanged` logic already keys lookups off `$nameCombo.Text` against `$displayToEntry`, so it now matches on usernames unchanged. Update the watermark visibility in `$updateState` (and once on load):
```powershell
        $nameWatermark.Visibility = if ([string]::IsNullOrEmpty([string]$nameCombo.Text)) { 'Visible' } else { 'Collapsed' }
```

e. **Hook + policy lifecycle** — in the `Loaded` handler, after `Activate`/focus, add:
```powershell
        try { Set-AuditTaskMgrPolicy -Config $cfg } catch { }
        try { [void](Install-AuditKeyboardHook) } catch { }
```
In the `Closing` handler (after the `AllowClose` check) and in the outer `catch`/just after `ShowDialog` returns, add (idempotent, safe to call in both):
```powershell
        try { Remove-AuditKeyboardHook } catch { }
        try { Restore-AuditTaskMgrPolicy -Config $cfg } catch { }
```

f. **Cover-before-roster** (optional reorder if low-risk): if the roster fetch (`Get-AuditRosterEntries`) currently happens before `$window` is shown, it may be left as-is for this task (the window still covers the screen quickly). Do **not** restructure the show/populate order in this task unless the XAML-load test and a manual smoke both pass; if deferred, note it. (Task priority in Task 7 is the primary flash mitigation.)

- [ ] **Step 6: Run the XAML test + parse-check**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditLockdown.ps1` → PASS (incl. the 7 named controls).
Parse-check `src\SharedAccountAuth.ps1` → `OK`.

- [ ] **Step 7: Manual smoke (documented; not automatable here)**

On a target shared session: Win/Win+R/Alt+Tab/Ctrl+Shift+Esc all swallowed while up; Task Manager disabled during and restored after; **a wrong password no longer locks the account in 1–2 tries**; disabled Confirm reads as a button; dropdown shows usernames + clear arrow + watermark; SECRET bars top/bottom; GE logo renders; correct password still unlocks and writes a row.

- [ ] **Step 8: Commit**

```bash
git add src/SharedAccountAuth.ps1 tests/Test-AuditLockdown.ps1
git commit -m "feat: prompt - username dropdown, banner, logo, keyboard hook lifecycle, styling"
```

---

### Task 7: Task priority (#4 launch half)

**Files:**
- Modify: `deploy/Register-AuditTasks.ps1`
- Modify: `tests/Test-AuditInstall.ps1` (assert generated XML priority)

**Interfaces:** none.

- [ ] **Step 1: Write the failing test**

Append to `tests/Test-AuditInstall.ps1` before its tally. This dot-sources the registration script's XML builder without registering anything — but `Register-AuditTasks.ps1` runs its main flow on load. Instead, assert against a freshly generated reference XML by invoking the builder in isolation is not safe; simplest robust check: assert the **committed reference** XML carries priority 4 after Step 2 regenerates it. Use:

```powershell
Write-Host 'Task 7: task priority'
$logonXml = Get-Content -Raw (Join-Path $RepoRoot 'tasks\SharedAccountAuth-Logon.xml')
Assert-True ($logonXml -match '<Priority>4</Priority>') 'Logon task priority is 4'
$unlockXml = Get-Content -Raw (Join-Path $RepoRoot 'tasks\SharedAccountAuth-Unlock.xml')
Assert-True ($unlockXml -match '<Priority>4</Priority>') 'Unlock task priority is 4'
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — the reference XML still says `<Priority>7</Priority>`.

- [ ] **Step 3: Change the priority in the builder + regenerate the reference XML**

In `deploy/Register-AuditTasks.ps1`, in `New-AuditTaskXml`, change `<Priority>7</Priority>` to `<Priority>4</Priority>`. Then regenerate the two reference files in `tasks/` (the generator writes them). If running the full registration requires admin/a live machine, instead edit the two committed `tasks/*.xml` files directly to `<Priority>4</Priority>` so the reference matches the builder.

- [ ] **Step 4: Run test, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1` → PASS.
Parse-check `deploy\Register-AuditTasks.ps1` → `OK`.

- [ ] **Step 5: Commit**

```bash
git add deploy/Register-AuditTasks.ps1 tasks/SharedAccountAuth-Logon.xml tasks/SharedAccountAuth-Unlock.xml tests/Test-AuditInstall.ps1
git commit -m "perf: raise audit task priority 7 -> 4 to reduce logon desktop flash"
```

---

### Task 8: Docs — README + parent spec

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-06-17-sign-on-audit-logger-design.md`

**Interfaces:** none (docs).

- [ ] **Step 1: README — roster format, hardening, classification, deploy tree**

In `README.md`:
- **Roster format** section: state that **only `Username` is required**; `LastName`/`FirstName` are optional. Update the sample to match `sample/roster.csv`.
- **STIG (§6)**: add that the prompt installs a low-level keyboard hook (blocks Win/Win+R/Alt+Tab/Ctrl+Esc/Ctrl+Shift+Esc) and temporarily disables Task Manager while up; the lockout fix (one bad-password strike per attempt); the raised task priority. Restate the **honest ceiling** (Ctrl+Alt+Del SAS not suppressible; some flash intrinsic).
- **Known limitations (§11)**: replace "Ctrl+Alt+Del → Task Manager kill" wording to reflect that Task Manager is now disabled while up, but Ctrl+Alt+Del Sign-out remains (ends the session, not an auth bypass).
- **Config**: document `ClassificationLevel`/`Text`/`Foreground`/`Background` and `LogoPath`, including the level→color defaults.
- **Deploy tree**: add `assets/` to the "copy the whole tree" list.

- [ ] **Step 2: Parent spec — revise the locked decision**

In `docs/superpowers/specs/2026-06-17-sign-on-audit-logger-design.md`, add a dated **rev** note to §2 Locked Decisions: the "Baseline modal … No hooks, no policy edits" decision is superseded — a low-level keyboard hook + temporary `DisableTaskMgr` are now used while the prompt is up; the roster requires only `Username`; restate the honest ceiling.

- [ ] **Step 3: Verify references**

Run:
```powershell
Select-String -Path README.md -Pattern 'ClassificationLevel','Username','keyboard hook','assets' | Select-Object LineNumber
```
Expected: matches present.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/specs/2026-06-17-sign-on-audit-logger-design.md
git commit -m "docs: roster username-only, hardening, classification, deploy tree"
```

---

## Self-Review

**Spec coverage:**
- #1 keyboard hook + TaskMgr → Task 1 (module) + Task 6 (lifecycle). ✓
- #2 username dropdown + username-only roster → Task 4 (roster) + Task 6 (dropdown). ✓
- #3 dropdown affordance → Task 6 (combo style + watermark). ✓
- #4 desktop flash → Task 7 (priority) + Task 6.5f (cover note). ✓
- #5 disabled Confirm styling → Task 6 (button template). ✓
- #6 lockout fix → Task 2. ✓
- #7 classification banner (all levels) → Task 3 (`Get-AuditClassification`) + Task 5 (config) + Task 6 (bars). ✓
- #8 GE logo → Task 5 (config) + Task 6 (Image) + asset already moved. ✓
- Pure helpers tested → Tasks 1–4; config round-trip → Task 5; XAML/parse → Tasks 1,2,4,5,6,7. ✓
- Honest-ceiling language preserved in module header + docs. ✓

**Placeholder scan:** complete code in every code step; the one judgment point (Task 6.5f cover reorder) is explicitly bounded and gated on tests, not a vague "handle edge cases." ✓

**Type consistency:** `Test-AuditShouldSwallowKey(VkCode,AltDown,CtrlDown,ShiftDown)` used identically in Task 1 test, the hook callback, and Task 6. `Test-AuditShouldTryNextLogonType(Win32Error)` consistent (Task 2). `Get-AuditClassification` returns `{Text;Foreground;Background;Show}` used in Task 3 test and Task 6 binding. `ConvertFrom-AuditRoster` returns `{Entries;Valid}` used in Task 4 test and `Get-AuditRosterEntries`. Named controls `TopBanner/BottomBanner/LogoImage/NameCombo/PwBox/ConfirmButton/StatusText` match between the Task 6 XAML, the Task 6 test, and the code-behind `FindName` calls. Config keys identical across Tasks 5/6. ✓
