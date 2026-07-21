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
$guiPath = Join-Path $RepoRoot 'deploy\Shared-Auth-Setup.ps1'
Assert-True (Test-Path -LiteralPath $guiPath) 'Shared-Auth-Setup.ps1 exists'
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

Write-Host ''
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

Write-Host ''
Write-Host 'Task 7: task priority'
$logonXml = Get-Content -Raw (Join-Path $RepoRoot 'tasks\SharedAccountAuth-Logon.xml')
Assert-True ($logonXml -match '<Priority>4</Priority>') 'Logon task priority is 4'
$unlockXml = Get-Content -Raw (Join-Path $RepoRoot 'tasks\SharedAccountAuth-Unlock.xml')
Assert-True ($unlockXml -match '<Priority>4</Priority>') 'Unlock task priority is 4'

Write-Host ''
Write-Host 'Task 1: ACL engine in AuditInstallCommon'
foreach ($fn in 'Set-AuditLogAcl','Set-AuditLocalStateAcl','New-SharedDirCreateAce','New-SharedFileAppendAce','New-SharedDenyAce','New-AuditorsReadAce','New-AdminFullControlAce') {
    Assert-True ([bool](Get-Command $fn -ErrorAction SilentlyContinue)) "function $fn is defined"
}
# ACE builders are pure — they must produce FileSystemAccessRule objects without touching disk.
$__ace = New-SharedDirCreateAce -Principal $env:USERNAME
Assert-True ($__ace -is [System.Security.AccessControl.FileSystemAccessRule]) 'New-SharedDirCreateAce returns a FileSystemAccessRule'
$__deny = New-SharedDenyAce -Principal $env:USERNAME
Assert-True ($__deny.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) 'New-SharedDenyAce is a Deny rule'
Assert-True (($__deny.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) -ne 0) 'deny ACE includes ReadData (no read of the log)'
$__app = New-SharedFileAppendAce -Principal $env:USERNAME
Assert-True ($__app.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) 'append ACE is Allow'
Assert-True (($__app.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::AppendData) -ne 0) 'append ACE includes AppendData'
# Set-AuditLogAcl -WhatIf must validate + gate without applying or throwing, and must
# return $false (per its documented contract: $true if applied, $false if skipped/failed).
$__d = Join-Path $env:TEMP ('logacl_' + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force $__d | Out-Null
$__threw = $false
try { $__wr = Set-AuditLogAcl -LogDir $__d -SharedPrincipal $env:USERNAME -AuditorsPrincipal 'Administrators' -WhatIf } catch { $__threw = $true }
Assert-True (-not $__threw) 'Set-AuditLogAcl -WhatIf does not throw'
Assert-True ($__wr -eq $false) 'Set-AuditLogAcl -WhatIf returns $false (does not apply)'
try { Remove-Item -LiteralPath $__d -Recurse -Force -ErrorAction SilentlyContinue } catch { }

if ($script:Failures -gt 0) { Write-Host ("$($script:Failures) failure(s)") -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
