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
Write-Host 'Task 2: Write-AuditConfigFile'
$tmp = Join-Path $env:TEMP ('audcfg-' + [System.IO.Path]::GetRandomFileName() + '.psd1')
try {
    $settings = @{
        LogPath       = '\\srv\share\audit\access_log.csv'
        RosterPath    = '\\srv\share\audit\roster.csv'
        SharedAccount = ".\Lab'Shared"        # apostrophe must be escaped
        RetryDelayMs  = 2500                    # numeric must stay numeric
        WindowTitle   = "O'Brien's window"
    }
    $bak = Write-AuditConfigFile -ConfigPath $tmp -Settings $settings -NoBackup
    Assert-True ($null -eq $bak) 'no backup returned when target absent'
    $read = Import-PowerShellDataFile -LiteralPath $tmp
    Assert-Eq $read.LogPath       $settings.LogPath        'round-trip LogPath'
    Assert-Eq $read.SharedAccount ".\Lab'Shared"           'round-trip apostrophe SharedAccount'
    Assert-Eq $read.WindowTitle   "O'Brien's window"       'round-trip apostrophe WindowTitle'
    Assert-Eq $read.RetryDelayMs  2500                     'round-trip numeric value'
    Assert-True ($read.RetryDelayMs -is [int])             'numeric stays [int]'
    Assert-Eq $read.AuthDomain    '.'                      'unspecified key falls to default'

    # backup behaviour
    Set-Content -LiteralPath $tmp -Value "@{ LogPath = 'old' }" -Encoding UTF8
    $bak2 = Write-AuditConfigFile -ConfigPath $tmp -Settings @{ LogPath = 'new' }
    Assert-Eq $bak2 "$tmp.bak" 'backup path returned'
    Assert-True (Test-Path -LiteralPath "$tmp.bak") 'backup file created'
    Assert-Eq (Import-PowerShellDataFile -LiteralPath "$tmp.bak").LogPath 'old' 'backup holds old value'
    Assert-Eq (Import-PowerShellDataFile -LiteralPath $tmp).LogPath       'new' 'target holds new value'
} finally {
    Remove-Item -LiteralPath $tmp, "$tmp.bak" -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Task 3: Resolve-AuditConfigFromValues'
$cfg = Resolve-AuditConfigFromValues -Settings @{
    LogPath       = '\\srv\share\audit\access_log.csv'
    RosterPath    = '\\srv\share\audit\roster.csv'
    SharedAccount = '.\LabShared'
}
Assert-Eq $cfg.SharedAccount '.\LabShared' 'resolved SharedAccount preserved'
Assert-True (-not [string]::IsNullOrWhiteSpace($cfg.RosterCachePath)) 'derived RosterCachePath filled'
Assert-True ($cfg.RosterCachePath -like '*\cache\roster.csv') 'derived cache path shape'

Write-Host ''
Write-Host 'Task 4: GUI XAML + scaffold'
$guiPath = Join-Path $RepoRoot 'deploy\Install-Audit-GUI.ps1'
Assert-True (Test-Path -LiteralPath $guiPath) 'Install-Audit-GUI.ps1 exists'
# Dot-source must NOT trigger the interactive flow (guarded by InvocationName).
. $guiPath
Assert-True ([bool](Get-Command Get-AuditGuiXaml -ErrorAction SilentlyContinue)) 'Get-AuditGuiXaml defined'
Add-Type -AssemblyName PresentationFramework
$xaml = Get-AuditGuiXaml
$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [System.Windows.Markup.XamlReader]::Load($reader)
Assert-True ($null -ne $win) 'XAML loads into a Window'
foreach ($name in 'LogBox','RosterBox','AccountBox','RosterGrid','ResultGrid','ValidateBtn','InstallBtn','CloseBtn','StatusText') {
    Assert-True ($null -ne $win.FindName($name)) "control '$name' present"
}

if ($script:Failures -gt 0) { Write-Host ("$($script:Failures) failure(s)") -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
