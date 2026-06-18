# Built-in test runner (no Pester). Exits 1 on any failure.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$CommonPath = Join-Path $RepoRoot 'deploy\AuditInstallCommon.ps1'
$AuditPath  = Join-Path $RepoRoot 'src\AuditCommon.ps1'

$script:Failures = 0
function Assert-True($cond, $msg) {
    if ($cond) { Write-Host "  PASS  $msg" -ForegroundColor Green }
    else { Write-Host "  FAIL  $msg" -ForegroundColor Red; $script:Failures++ }
}
function Assert-Eq($actual, $expected, $msg) {
    Assert-True ($actual -eq $expected) ("{0} (expected '{1}', got '{2}')" -f $msg, $expected, $actual)
}

Write-Host 'Loading libraries...'
. $AuditPath
. $CommonPath

Write-Host 'Task 1: shared library functions'
foreach ($fn in 'Get-AuditLeafName','Get-LocalUserNameSet','New-AuditCheckResult','Invoke-AuditPreflight') {
    Assert-True ([bool](Get-Command $fn -ErrorAction SilentlyContinue)) "function $fn is defined"
}
Assert-Eq (Get-AuditLeafName -Name 'LAB-PC01\LabShared') 'LabShared' 'leaf of MACHINE\name'
Assert-Eq (Get-AuditLeafName -Name '.\LabShared')        'LabShared' 'leaf of .\name'
Assert-Eq (Get-AuditLeafName -Name 'LabShared')          'LabShared' 'leaf of bare name'
Assert-Eq (Get-AuditLeafName -Name '')                   ''          'leaf of empty'
$r = New-AuditCheckResult -Check 'X' -Status 'OK' -Detail 'Y'
Assert-Eq $r.Status 'OK' 'New-AuditCheckResult Status'
Assert-True ($r.PSObject.Properties.Name -contains 'Check') 'result has Check'
$set = Get-LocalUserNameSet
Assert-True ($set -is [System.Collections.Generic.HashSet[string]]) 'Get-LocalUserNameSet returns a HashSet'

Write-Host ''
if ($script:Failures -gt 0) { Write-Host ("$($script:Failures) failure(s)") -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
