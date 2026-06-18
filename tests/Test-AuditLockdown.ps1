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
