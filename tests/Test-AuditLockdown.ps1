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

Write-Host 'Task 2: Test-AuditShouldTryNextLogonType'
Assert-True (-not (Test-AuditShouldTryNextLogonType -Win32Error 1326)) '1326 (bad password) => stop'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 1385))     '1385 (type not granted) => try next'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 0))        '0 => try next'
Assert-True ( (Test-AuditShouldTryNextLogonType -Win32Error 5))        'access denied => try next'

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

Write-Host 'Task 6: prompt XAML + named controls'
$promptPath = Join-Path $RepoRoot 'src\SharedAccountAuth.ps1'
# Pass -EventType (it is a MANDATORY param; omitting it would prompt/hang). The
# dot-source guard (InvocationName -eq '.') still skips the prompt body, so this
# only defines functions like Get-AuditPromptXaml.
. $promptPath -EventType Logon
Assert-True ([bool](Get-Command Get-AuditPromptXaml -ErrorAction SilentlyContinue)) 'Get-AuditPromptXaml defined'
Add-Type -AssemblyName PresentationFramework
$w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml](Get-AuditPromptXaml))))
foreach ($n in 'TopBanner','BottomBanner','LogoImage','NameCombo','PwBox','ConfirmButton','StatusText') {
    Assert-True ($null -ne $w.FindName($n)) "control '$n' present"
}
# The name field must be SELECTION-ONLY: a non-editable ComboBox admits no free
# text, so the only settable value is a roster username picked from the list.
Assert-True (-not $w.FindName('NameCombo').IsEditable) 'NameCombo is selection-only (IsEditable=$false)'

Write-Host 'Regression: Write-AuditRow accepts empty LastName/FirstName (username-only roster)'
$__rr = "$env:TEMP\audrowtest_$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory -Force "$__rr\logs" | Out-Null
$__cfgp = "$__rr\cfg.psd1"
@"
@{
    LogPath='$__rr\logs\access_log.csv'; RosterPath='$__rr\roster.csv'; LocalRoot='$__rr\state'
    RosterCachePath=''; SpoolDir=''; DiagLogPath=''; StateDir=''
    SharedAccount='.\test'; AuthDomain='.'; RetryDelayMs=0; DebounceSeconds=0; WriteRetryCount=3; WriteRetryBaseMs=10
    AppName='x'; WindowTitle='x'; WindowSubtitle='x'
    ClassificationLevel=''; ClassificationText=''; ClassificationForeground=''; ClassificationBackground=''; LogoPath=''
}
"@ | Set-Content -LiteralPath $__cfgp -Encoding UTF8
$__cfg = Get-AuditConfig -ConfigPath $__cfgp
$__threw = $false
try { $__res = Write-AuditRow -Config $__cfg -Username 'asmith' -LastName '' -FirstName '' -EventType 'Unlock' -AuthResult 'Success' }
catch { $__threw = $true }
Assert-True (-not $__threw) 'Write-AuditRow does not throw on empty LastName/FirstName'
Assert-True ($__threw -or $__res.Written) 'row was written (not spooled) with empty names'
try { Remove-Item -LiteralPath $__rr -Recurse -Force -ErrorAction SilentlyContinue } catch { }

Write-Host ''
if ($script:Failures -gt 0) { Write-Host ("$($script:Failures) failure(s)") -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
