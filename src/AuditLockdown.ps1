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
