# Install GUI Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single-pane WPF GUI front-end (`deploy/Install-Audit-GUI.ps1`) over the existing per-PC install — collect the three config values, preview the roster read-only, write the config (with backup), register the tasks, and show the shared preflight.

**Architecture:** Extract the preflight engine + helpers from `deploy/Install-Audit.ps1` into a new shared `deploy/AuditInstallCommon.ps1` dot-sourced by both the CLI and the GUI. Add a `Write-AuditConfigFile` (psd1 writer) and a `Resolve-AuditConfigFromValues` (render→`Get-AuditConfig`) helper to that library. The GUI is a thin WPF shell that reuses those plus the runtime `Get-AuditConfig` / `Get-AuditRosterEntries` / `Write-AuditDiag`.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework 4.x WPF (XAML via `XamlReader`), ADSI WinNT provider, ScheduledTasks module. No external modules. Tests are a plain built-in PowerShell script (no Pester dependency).

## Global Constraints

Copy these verbatim into every task's mental checklist:

- **Windows PowerShell 5.1 syntax only** — no PS7-only constructs (`??`, `?.`, ternary `? :`, `&&`, `||`, `ForEach-Object -Parallel`, `Clean{}`).
- **.NET Framework 4.x WPF only** (no .NET Core/5+).
- **No external modules** — built-ins only: `Microsoft.PowerShell.*`, `ScheduledTasks`, `PresentationFramework`/`PresentationCore`/`WindowsBase`, ADSI (`[ADSI]`).
- **Fully offline** at build and runtime. No network calls except `Test-Path`/reads against the configured UNC.
- **Scripts are unsigned**, launched with `-ExecutionPolicy Bypass`; AppLocker over the install dir is the integrity control. The GUI self-elevates via UAC.
- **Preflight never writes to the central log**; diagnostics (`Write-AuditDiag`) never throw.
- **Style:** `Verb-Noun` functions, comment-based help on each function, a header comment block on each script, match the surrounding heavy-comment density.
- **Spec:** [docs/superpowers/specs/2026-06-18-install-gui-wizard-design.md](../specs/2026-06-18-install-gui-wizard-design.md).

---

### Task 1: Shared install library + test harness (refactor)

Move the four install-time helpers out of `Install-Audit.ps1` into a new shared library, making `Invoke-AuditPreflight` self-contained (parameterized), and create the test harness. The CLI's behavior is unchanged.

**Files:**
- Create: `deploy/AuditInstallCommon.ps1`
- Create: `tests/Test-AuditInstall.ps1`
- Modify: `deploy/Install-Audit.ps1` (remove the 4 moved functions; dot-source the library; update the preflight call site)

**Interfaces:**
- Produces:
  - `Get-AuditLeafName -Name <string>` → `[string]`
  - `Get-LocalUserNameSet` → `[System.Collections.Generic.HashSet[string]]`
  - `New-AuditCheckResult -Check <string> -Status <OK|WARN|FAIL> -Detail <string>` → `[pscustomobject]{Check,Status,Detail}`
  - `Invoke-AuditPreflight -Config <hashtable> -SrcDir <string> [-LogonTaskName <string>] [-UnlockTaskName <string>]` → `[object[]]` of result rows

- [ ] **Step 1: Write the failing test harness**

Create `tests/Test-AuditInstall.ps1`:

```powershell
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
```

- [ ] **Step 2: Run the test, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — the dot-source of `deploy\AuditInstallCommon.ps1` throws (file does not exist yet).

- [ ] **Step 3: Create the shared library**

Create `deploy/AuditInstallCommon.ps1` with a header block and the four functions. Copy `Get-AuditLeafName`, `Get-LocalUserNameSet`, and `New-AuditCheckResult` verbatim from the current `deploy/Install-Audit.ps1`. Add `Invoke-AuditPreflight` **parameterized** (it previously read script-scope `$SrcDir`/`$LogonTaskName`/`$UnlockTaskName`; now they are parameters):

```powershell
<#
=======================================================================
 AuditInstallCommon.ps1 - shared install-time library for the Shared-
 Account Sign-On Audit Logger. Dot-sourced by deploy\Install-Audit.ps1
 (CLI) and deploy\Install-Audit-GUI.ps1 (WPF). PS 5.1 / built-ins only;
 fully offline. Provides the preflight engine, local-account enumeration,
 a psd1 writer, and a value->resolved-config helper.
=======================================================================
#>
Set-StrictMode -Version 2.0

function Get-AuditLeafName {
<#
.SYNOPSIS Returns the leaf account name (after the last backslash), trimmed.
#>
    [CmdletBinding()]
    param([string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $i = $Name.LastIndexOf('\')
    if ($i -lt 0) { return $Name.Trim() }
    return $Name.Substring($i + 1).Trim()
}

function Get-LocalUserNameSet {
<#
.SYNOPSIS Lower-cased HashSet of LOCAL user account names via ADSI WinNT (offline).
#>
    [CmdletBinding()]
    param()
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    try {
        $root = [ADSI]("WinNT://" + $env:COMPUTERNAME)
        foreach ($child in $root.Children) {
            try {
                if ($child.SchemaClassName -eq 'User') {
                    [void]$set.Add(([string]$child.Name).ToLowerInvariant())
                }
            } catch { }
        }
    } catch { }
    return ,$set
}

function New-AuditCheckResult {
<#
.SYNOPSIS Builds one preflight result row.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Check,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'WARN', 'FAIL')] [string] $Status,
        [Parameter(Mandatory = $true)] [string] $Detail
    )
    [pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail }
}

function Invoke-AuditPreflight {
<#
.SYNOPSIS Install-time validation. Best-effort, never throws, never writes the central log.
.PARAMETER Config Resolved config hashtable from Get-AuditConfig.
.PARAMETER SrcDir The src\ directory (for the install-files check). Blank => skip that check.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable] $Config,
        [string] $SrcDir = '',
        [string] $LogonTaskName  = 'SharedAccountAuth-Logon',
        [string] $UnlockTaskName = 'SharedAccountAuth-Unlock'
    )

    $results    = New-Object System.Collections.Generic.List[object]
    $localUsers = Get-LocalUserNameSet

    # 1. SharedAccount present.
    $shared = [string]$Config.SharedAccount
    if ([string]::IsNullOrWhiteSpace($shared)) {
        $results.Add((New-AuditCheckResult -Check 'Config: SharedAccount' -Status 'FAIL' -Detail 'blank - the prompt self-check would exit and nothing would ever log'))
    } else {
        $results.Add((New-AuditCheckResult -Check 'Config: SharedAccount' -Status 'OK' -Detail $shared))
    }

    # 2. Install files present (only if SrcDir supplied).
    if (-not [string]::IsNullOrWhiteSpace($SrcDir)) {
        foreach ($leaf in 'SharedAccountAuth.ps1','AuditCommon.ps1','Launch-SharedAccountAuth.vbs') {
            $f = Join-Path $SrcDir $leaf
            if (Test-Path -LiteralPath $f) {
                $results.Add((New-AuditCheckResult -Check ("Install file: $leaf") -Status 'OK' -Detail $f))
            } else {
                $results.Add((New-AuditCheckResult -Check ("Install file: $leaf") -Status 'FAIL' -Detail ("missing: $f")))
            }
        }
    }

    # 2b. Execution-policy GPO override (scripts are unsigned + launched Bypass).
    try {
        $mp = [string](Get-ExecutionPolicy -Scope MachinePolicy)
        $up = [string](Get-ExecutionPolicy -Scope UserPolicy)
        $effPol = ''; $effScope = ''
        if ($mp -ne 'Undefined') { $effPol = $mp; $effScope = 'MachinePolicy' }
        elseif ($up -ne 'Undefined') { $effPol = $up; $effScope = 'UserPolicy' }
        if ([string]::IsNullOrEmpty($effPol)) {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'OK' -Detail 'no GPO override; launcher Bypass runs the unsigned scripts'))
        } elseif ($effPol -eq 'AllSigned') {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'FAIL' -Detail ("$effScope=AllSigned overrides Bypass - UNSIGNED scripts are BLOCKED; sign them or relax the GPO")))
        } elseif ($effPol -eq 'RemoteSigned') {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'WARN' -Detail ("$effScope=RemoteSigned blocks only Mark-of-the-Web files; Unblock-File the install dir if copied via ZIP/USB")))
        } else {
            $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'OK' -Detail ("$effScope=$effPol does not block unsigned scripts")))
        }
    } catch {
        $results.Add((New-AuditCheckResult -Check 'Execution policy (GPO)' -Status 'WARN' -Detail ("could not read execution policy: {0}" -f $_.Exception.Message)))
    }

    # 3. SharedAccount local-account existence.
    $sharedLeaf = (Get-AuditLeafName -Name $shared).ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($sharedLeaf)) {
        if ($localUsers.Count -eq 0) {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'WARN' -Detail 'could not enumerate local accounts to verify'))
        } elseif ($localUsers.Contains($sharedLeaf)) {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'OK' -Detail $sharedLeaf))
        } else {
            $results.Add((New-AuditCheckResult -Check 'SharedAccount exists locally' -Status 'WARN' -Detail ("no local account '$sharedLeaf' (fine if it is a domain account)")))
        }
    }

    # 4. Central LogPath reachability (parent dir only; never probe-write).
    $logPath = [string]$Config.LogPath
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        $results.Add((New-AuditCheckResult -Check 'Central LogPath' -Status 'FAIL' -Detail 'blank in config'))
    } else {
        $logDir = Split-Path -Parent $logPath
        if (-not [string]::IsNullOrWhiteSpace($logDir) -and (Test-Path -LiteralPath $logDir)) {
            $results.Add((New-AuditCheckResult -Check 'Central LogPath reachable' -Status 'OK' -Detail $logDir))
        } else {
            $results.Add((New-AuditCheckResult -Check 'Central LogPath reachable' -Status 'WARN' -Detail ("$logDir unreachable now - runtime will SPOOL locally until it returns")))
        }
    }

    # 5. Roster load + per-username local-account cross-check.
    try {
        $roster  = Get-AuditRosterEntries -Config $Config
        $entries = @($roster.Entries)
        switch ([string]$roster.Source) {
            'central' { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'OK'   -Detail ("central ({0} entries)" -f $entries.Count))) }
            'cache'   { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'WARN' -Detail ("central unreadable; using local cache ({0} entries)" -f $entries.Count))) }
            default   { $results.Add((New-AuditCheckResult -Check 'Roster source' -Status 'FAIL' -Detail 'unavailable from central AND cache - Confirm stays disabled')) }
        }
        if ($entries.Count -gt 0) {
            if ($localUsers.Count -eq 0) {
                $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'WARN' -Detail 'could not enumerate local accounts to verify'))
            } else {
                $missing = @()
                foreach ($e in $entries) {
                    $u = (Get-AuditLeafName -Name ([string]$e.Username)).ToLowerInvariant()
                    if (-not [string]::IsNullOrWhiteSpace($u) -and -not $localUsers.Contains($u)) { $missing += [string]$e.Username }
                }
                if ($missing.Count -eq 0) {
                    $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'OK' -Detail 'every roster Username has a local account on this PC'))
                } else {
                    $results.Add((New-AuditCheckResult -Check 'Roster users exist locally' -Status 'WARN' -Detail ("{0} cannot authenticate here (no local account): {1}" -f $missing.Count, ($missing -join ', '))))
                }
            }
        }
    } catch {
        $results.Add((New-AuditCheckResult -Check 'Roster check' -Status 'WARN' -Detail ("could not evaluate roster: {0}" -f $_.Exception.Message)))
    }

    # 6. Local state root present.
    $localRoot = [string]$Config.LocalRoot
    if (-not [string]::IsNullOrWhiteSpace($localRoot) -and (Test-Path -LiteralPath $localRoot)) {
        $results.Add((New-AuditCheckResult -Check 'Local state root' -Status 'OK' -Detail $localRoot))
    } else {
        $results.Add((New-AuditCheckResult -Check 'Local state root' -Status 'WARN' -Detail ("not present yet: $localRoot")))
    }

    # 7. Tasks registered + enabled.
    foreach ($tn in @($LogonTaskName, $UnlockTaskName)) {
        $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($null -eq $t) {
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'FAIL' -Detail 'not registered'))
        } elseif ([string]$t.State -eq 'Disabled') {
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'WARN' -Detail 'registered but DISABLED'))
        } else {
            $uid = ''
            try { $uid = [string]$t.Principal.UserId } catch { }
            $results.Add((New-AuditCheckResult -Check ("Task: $tn") -Status 'OK' -Detail ("state=$($t.State), UserId=$uid")))
        }
    }

    return $results.ToArray()
}
```

- [ ] **Step 4: Refactor `deploy/Install-Audit.ps1`**

In `deploy/Install-Audit.ps1`:
1. After the `$RegisterPath = ...` line in the path-resolution block, add:
```powershell
$InstallCommonPath = Join-Path $DeployDir 'AuditInstallCommon.ps1'
```
2. **Delete** the four function definitions now living in the library: `Test-IsAdministrator` stays, but **remove** `Get-LocalUserNameSet`, `Get-AuditLeafName`, `New-AuditCheckResult`, and `Invoke-AuditPreflight` from this file.
3. After the existing `. $CommonPath` dot-source line in MAIN, add the library dot-source:
```powershell
if (-not (Test-Path -LiteralPath $InstallCommonPath)) { throw "AuditInstallCommon.ps1 not found at $InstallCommonPath" }
. $InstallCommonPath
```
4. Update the preflight call site to pass `-SrcDir` (and the task names default in the function):
```powershell
$results = Invoke-AuditPreflight -Config $cfg -SrcDir $SrcDir
```

- [ ] **Step 5: Run the test, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: PASS — all Task 1 assertions green, exit 0.

- [ ] **Step 6: Parse-check the refactored CLI**

Run:
```powershell
$e=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path deploy\Install-Audit.ps1), [ref]$null, [ref]$e); if($e){$e}else{'OK'}
```
Expected: `OK` (no parse errors).

- [ ] **Step 7: Commit**

```bash
git add deploy/AuditInstallCommon.ps1 deploy/Install-Audit.ps1 tests/Test-AuditInstall.ps1
git commit -m "refactor: extract shared AuditInstallCommon.ps1 + test harness"
```

---

### Task 2: `Write-AuditConfigFile` (psd1 writer)

**Files:**
- Modify: `deploy/AuditInstallCommon.ps1` (add the function)
- Modify: `tests/Test-AuditInstall.ps1` (add round-trip/backup/escaping tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Write-AuditConfigFile -ConfigPath <string> -Settings <hashtable> [-NoBackup]` → `[string]` backup path or `$null`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/Test-AuditInstall.ps1` *before* the final tally block:

```powershell
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
```

- [ ] **Step 2: Run the test, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — `Write-AuditConfigFile` is not defined.

- [ ] **Step 3: Implement `Write-AuditConfigFile`**

Append to `deploy/AuditInstallCommon.ps1`:

```powershell
function Write-AuditConfigFile {
<#
.SYNOPSIS Writes a fully-commented AuditConfig.psd1 from $Settings, backing up any prior file.
.PARAMETER ConfigPath Target psd1 path.
.PARAMETER Settings   Hashtable of key->value. Unspecified known keys fall to project defaults.
.PARAMETER NoBackup   Skip the .bak copy of an existing target.
.OUTPUTS [string] backup path, or $null if none was made.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $ConfigPath,
        [Parameter(Mandatory = $true)][hashtable] $Settings,
        [switch] $NoBackup
    )

    $known = @('LogPath','RosterPath','LocalRoot','RosterCachePath','SpoolDir','DiagLogPath',
               'StateDir','SharedAccount','AuthDomain','RetryDelayMs','DebounceSeconds',
               'WriteRetryCount','WriteRetryBaseMs','AppName','WindowTitle','WindowSubtitle')
    $numeric  = @('RetryDelayMs','DebounceSeconds','WriteRetryCount','WriteRetryBaseMs')
    $defaults = @{
        LogPath='\\server\share\audit\access_log.csv'; RosterPath='\\server\share\audit\roster.csv'
        LocalRoot='C:\ProgramData\SharedAccountAuth'; RosterCachePath=''; SpoolDir=''; DiagLogPath=''; StateDir=''
        SharedAccount='.\LabShared'; AuthDomain='.'
        RetryDelayMs=1000; DebounceSeconds=5; WriteRetryCount=10; WriteRetryBaseMs=50
        AppName='SharedAccountAuth'; WindowTitle='Shared Account - Authenticate to Continue'
        WindowSubtitle='Select your name and enter your personal account password. This window cannot be dismissed.'
    }

    # psd1 literal for a key: single-quoted+escaped string, or a bare integer.
    function ConvertTo-AuditPsd1Value([string]$key) {
        $val = if ($Settings.ContainsKey($key)) { $Settings[$key] } else { $defaults[$key] }
        if ($numeric -contains $key) {
            $n = 0
            if ([int]::TryParse([string]$val, [ref]$n)) { return [string]$n }
            return [string]([int]$defaults[$key])
        }
        return "'" + (([string]$val) -replace "'", "''") + "'"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('@{')
    [void]$sb.AppendLine('    # =====================================================================')
    [void]$sb.AppendLine('    #  AuditConfig.psd1 - written by the audit install GUI. Edit per site.')
    [void]$sb.AppendLine('    #  Loaded via Import-PowerShellDataFile by Get-AuditConfig. SharedAccount REQUIRED.')
    [void]$sb.AppendLine('    # =====================================================================')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Central share paths (UNC) ---')
    [void]$sb.AppendLine(('    LogPath          = {0}' -f (ConvertTo-AuditPsd1Value 'LogPath')))
    [void]$sb.AppendLine(('    RosterPath       = {0}' -f (ConvertTo-AuditPsd1Value 'RosterPath')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Local state root (blank derived keys => under LocalRoot) ---')
    [void]$sb.AppendLine(('    LocalRoot        = {0}' -f (ConvertTo-AuditPsd1Value 'LocalRoot')))
    [void]$sb.AppendLine(('    RosterCachePath  = {0}' -f (ConvertTo-AuditPsd1Value 'RosterCachePath')))
    [void]$sb.AppendLine(('    SpoolDir         = {0}' -f (ConvertTo-AuditPsd1Value 'SpoolDir')))
    [void]$sb.AppendLine(('    DiagLogPath      = {0}' -f (ConvertTo-AuditPsd1Value 'DiagLogPath')))
    [void]$sb.AppendLine(('    StateDir         = {0}' -f (ConvertTo-AuditPsd1Value 'StateDir')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Shared-account scoping (REQUIRED) ---')
    [void]$sb.AppendLine(('    SharedAccount    = {0}' -f (ConvertTo-AuditPsd1Value 'SharedAccount')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Authentication (local accounts) ---')
    [void]$sb.AppendLine(('    AuthDomain       = {0}' -f (ConvertTo-AuditPsd1Value 'AuthDomain')))
    [void]$sb.AppendLine(('    RetryDelayMs     = {0}' -f (ConvertTo-AuditPsd1Value 'RetryDelayMs')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Behaviour tunables ---')
    [void]$sb.AppendLine(('    DebounceSeconds  = {0}' -f (ConvertTo-AuditPsd1Value 'DebounceSeconds')))
    [void]$sb.AppendLine(('    WriteRetryCount  = {0}' -f (ConvertTo-AuditPsd1Value 'WriteRetryCount')))
    [void]$sb.AppendLine(('    WriteRetryBaseMs = {0}' -f (ConvertTo-AuditPsd1Value 'WriteRetryBaseMs')))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- UI text ---')
    [void]$sb.AppendLine(('    AppName          = {0}' -f (ConvertTo-AuditPsd1Value 'AppName')))
    [void]$sb.AppendLine(('    WindowTitle      = {0}' -f (ConvertTo-AuditPsd1Value 'WindowTitle')))
    [void]$sb.AppendLine(('    WindowSubtitle   = {0}' -f (ConvertTo-AuditPsd1Value 'WindowSubtitle')))

    # Preserve any extra (non-standard) keys rather than dropping them.
    $extra = @($Settings.Keys | Where-Object { $known -notcontains $_ })
    if ($extra.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('    # --- additional keys (carried over) ---')
        foreach ($k in $extra) {
            [void]$sb.AppendLine(('    {0} = {1}' -f $k, ("'" + (([string]$Settings[$k]) -replace "'", "''") + "'")))
        }
    }
    [void]$sb.AppendLine('}')

    # Backup, then write (UTF-8 with BOM so non-ASCII UI text survives).
    $backup = $null
    if ((Test-Path -LiteralPath $ConfigPath) -and -not $NoBackup) {
        $backup = "$ConfigPath.bak"
        Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force
    }
    $dir = Split-Path -Parent $ConfigPath
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($ConfigPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
    return $backup
}
```

- [ ] **Step 4: Run the test, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: PASS — Task 2 assertions green, exit 0.

- [ ] **Step 5: Commit**

```bash
git add deploy/AuditInstallCommon.ps1 tests/Test-AuditInstall.ps1
git commit -m "feat: add Write-AuditConfigFile psd1 writer with backup"
```

---

### Task 3: `Resolve-AuditConfigFromValues`

**Files:**
- Modify: `deploy/AuditInstallCommon.ps1` (add the function)
- Modify: `tests/Test-AuditInstall.ps1` (add a resolution test)

**Interfaces:**
- Consumes: `Write-AuditConfigFile`; `Get-AuditConfig` (from `src/AuditCommon.ps1`, dot-sourced by callers/tests).
- Produces: `Resolve-AuditConfigFromValues -Settings <hashtable>` → `[hashtable]` resolved config (derived paths filled).

- [ ] **Step 1: Write the failing test**

Append to `tests/Test-AuditInstall.ps1` before the tally block:

```powershell
Write-Host 'Task 3: Resolve-AuditConfigFromValues'
$cfg = Resolve-AuditConfigFromValues -Settings @{
    LogPath       = '\\srv\share\audit\access_log.csv'
    RosterPath    = '\\srv\share\audit\roster.csv'
    SharedAccount = '.\LabShared'
}
Assert-Eq $cfg.SharedAccount '.\LabShared' 'resolved SharedAccount preserved'
Assert-True (-not [string]::IsNullOrWhiteSpace($cfg.RosterCachePath)) 'derived RosterCachePath filled'
Assert-True ($cfg.RosterCachePath -like '*\cache\roster.csv') 'derived cache path shape'
```

- [ ] **Step 2: Run the test, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — `Resolve-AuditConfigFromValues` is not defined.

- [ ] **Step 3: Implement `Resolve-AuditConfigFromValues`**

Append to `deploy/AuditInstallCommon.ps1`:

```powershell
function Resolve-AuditConfigFromValues {
<#
.SYNOPSIS Resolves a config hashtable from in-memory values WITHOUT committing the real file.
.DESCRIPTION Renders $Settings to a temp psd1, runs the authoritative Get-AuditConfig
             resolver on it (filling derived cache/spool/diag/state paths), and returns
             the result. Requires Get-AuditConfig (src\AuditCommon.ps1) to be dot-sourced.
.PARAMETER Settings Hashtable of the collected field values.
.OUTPUTS [hashtable] resolved config.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable] $Settings)

    $tmp = Join-Path $env:TEMP ('AuditCfg-' + [System.IO.Path]::GetRandomFileName() + '.psd1')
    try {
        [void](Write-AuditConfigFile -ConfigPath $tmp -Settings $Settings -NoBackup)
        return (Get-AuditConfig -ConfigPath $tmp)
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
```

- [ ] **Step 4: Run the test, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: PASS — Task 3 assertions green.

- [ ] **Step 5: Commit**

```bash
git add deploy/AuditInstallCommon.ps1 tests/Test-AuditInstall.ps1
git commit -m "feat: add Resolve-AuditConfigFromValues helper"
```

---

### Task 4: `Install-Audit-GUI.ps1` (WPF front-end)

**Files:**
- Create: `deploy/Install-Audit-GUI.ps1`
- Modify: `tests/Test-AuditInstall.ps1` (add a XAML-load / named-controls test)

**Interfaces:**
- Consumes: `Get-AuditConfig`, `Get-AuditRosterEntries`, `Write-AuditDiag` (src/AuditCommon.ps1); `Resolve-AuditConfigFromValues`, `Invoke-AuditPreflight`, `Write-AuditConfigFile`, `Get-LocalUserNameSet`, `Get-AuditLeafName` (AuditInstallCommon.ps1); `Register-AuditTasks.ps1`.
- Produces: `Get-AuditGuiXaml` → `[string]` XAML (testable without showing the window).

- [ ] **Step 1: Write the failing test**

Append to `tests/Test-AuditInstall.ps1` before the tally block:

```powershell
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
```

- [ ] **Step 2: Run the test, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — `deploy\Install-Audit-GUI.ps1` does not exist.

- [ ] **Step 3: Create `deploy/Install-Audit-GUI.ps1`**

```powershell
<#
=======================================================================
 Install-Audit-GUI.ps1 - single-pane WPF front-end for the per-PC
 install of the Shared-Account Sign-On Audit Logger.
 PS 5.1 / .NET 4.x WPF / built-ins only; fully offline. Self-elevates.
 Collects LogPath / RosterPath / SharedAccount, previews the roster
 read-only, writes config (with .bak backup), registers the tasks, and
 shows the shared preflight. Scripts are unsigned (launched via Bypass).
=======================================================================
#>
[CmdletBinding()]
param([string] $ConfigPath)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$DeployDir         = $PSScriptRoot
$InstallRoot       = Split-Path -Parent $DeployDir
$SrcDir            = Join-Path $InstallRoot 'src'
$CommonPath        = Join-Path $SrcDir 'AuditCommon.ps1'
$InstallCommonPath = Join-Path $DeployDir 'AuditInstallCommon.ps1'
$RegisterPath      = Join-Path $DeployDir 'Register-AuditTasks.ps1'
$DefaultConfigPath = Join-Path $InstallRoot 'config\AuditConfig.psd1'

function Test-IsAdministrator {
    [CmdletBinding()] param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-AuditGuiXaml {
<#
.SYNOPSIS Returns the window XAML. Factored out so it can be validated without showing the UI.
#>
    [CmdletBinding()] param()
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Shared-Account Sign-On Audit - Setup" Height="640" Width="780"
        WindowStartupLocation="CenterScreen" ResizeMode="CanResize">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>

    <TextBlock Grid.Row="0" Grid.Column="0" Text="Central log (UNC):" Margin="4" VerticalAlignment="Center"/>
    <TextBox   Grid.Row="0" Grid.Column="1" x:Name="LogBox" Margin="4"/>
    <Button    Grid.Row="0" Grid.Column="2" x:Name="TestLogBtn" Content="Test" Width="70" Margin="4"/>

    <TextBlock Grid.Row="1" Grid.Column="0" Text="Roster (UNC):" Margin="4" VerticalAlignment="Center"/>
    <TextBox   Grid.Row="1" Grid.Column="1" x:Name="RosterBox" Margin="4"/>
    <Button    Grid.Row="1" Grid.Column="2" x:Name="TestRosterBtn" Content="Test" Width="70" Margin="4"/>

    <TextBlock Grid.Row="2" Grid.Column="0" Text="Shared account:" Margin="4" VerticalAlignment="Center"/>
    <TextBox   Grid.Row="2" Grid.Column="1" x:Name="AccountBox" Margin="4"/>
    <Button    Grid.Row="2" Grid.Column="2" x:Name="TestAccountBtn" Content="Check" Width="70" Margin="4"/>

    <TextBlock Grid.Row="3" Grid.Column="0" Text="Install dir:" Margin="4" VerticalAlignment="Center"/>
    <TextBlock Grid.Row="3" Grid.Column="1" x:Name="InstallDirText" Margin="4" Foreground="Gray" VerticalAlignment="Center"/>

    <GroupBox Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="3" Header="Roster preview (read-only)" Margin="4">
      <ListView x:Name="RosterGrid">
        <ListView.View>
          <GridView>
            <GridViewColumn Header="Last"     Width="150" DisplayMemberBinding="{Binding LastName}"/>
            <GridViewColumn Header="First"    Width="150" DisplayMemberBinding="{Binding FirstName}"/>
            <GridViewColumn Header="Username" Width="150" DisplayMemberBinding="{Binding Username}"/>
            <GridViewColumn Header="Local acct?" Width="100" DisplayMemberBinding="{Binding Local}"/>
          </GridView>
        </ListView.View>
      </ListView>
    </GroupBox>

    <GroupBox Grid.Row="5" Grid.Column="0" Grid.ColumnSpan="3" Header="Preflight" Margin="4">
      <ListView x:Name="ResultGrid">
        <ListView.View>
          <GridView>
            <GridViewColumn Header="Status" Width="70"  DisplayMemberBinding="{Binding Status}"/>
            <GridViewColumn Header="Check"  Width="220" DisplayMemberBinding="{Binding Check}"/>
            <GridViewColumn Header="Detail" Width="430" DisplayMemberBinding="{Binding Detail}"/>
          </GridView>
        </ListView.View>
        <ListView.ItemContainerStyle>
          <Style TargetType="ListViewItem">
            <Style.Triggers>
              <DataTrigger Binding="{Binding Status}" Value="FAIL">
                <Setter Property="Foreground" Value="Red"/>
              </DataTrigger>
              <DataTrigger Binding="{Binding Status}" Value="WARN">
                <Setter Property="Foreground" Value="#B8860B"/>
              </DataTrigger>
              <DataTrigger Binding="{Binding Status}" Value="OK">
                <Setter Property="Foreground" Value="Green"/>
              </DataTrigger>
            </Style.Triggers>
          </Style>
        </ListView.ItemContainerStyle>
      </ListView>
    </GroupBox>

    <TextBlock Grid.Row="6" Grid.Column="0" Grid.ColumnSpan="3" x:Name="StatusText" Margin="4" TextWrapping="Wrap"/>

    <StackPanel Grid.Row="7" Grid.Column="0" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="4">
      <Button x:Name="ValidateBtn" Content="Validate" Width="100" Margin="4"/>
      <Button x:Name="InstallBtn"  Content="Install"  Width="100" Margin="4"/>
      <Button x:Name="CloseBtn"    Content="Close"    Width="100" Margin="4"/>
    </StackPanel>
  </Grid>
</Window>
'@
}

function Get-AuditGuiSettings($win) {
    @{
        LogPath       = $win.FindName('LogBox').Text.Trim()
        RosterPath    = $win.FindName('RosterBox').Text.Trim()
        SharedAccount = $win.FindName('AccountBox').Text.Trim()
    }
}

function Set-AuditRosterGrid($win, $config) {
    # Populate the read-only roster preview with a per-row local-account flag.
    $grid = $win.FindName('RosterGrid')
    try {
        $roster = Get-AuditRosterEntries -Config $config
        $local  = Get-LocalUserNameSet
        $rows = foreach ($e in @($roster.Entries)) {
            $u = (Get-AuditLeafName -Name ([string]$e.Username)).ToLowerInvariant()
            $has = if ($local.Count -gt 0 -and $local.Contains($u)) { 'YES' } elseif ($local.Count -eq 0) { '?' } else { 'NO' }
            [pscustomobject]@{ LastName = $e.LastName; FirstName = $e.FirstName; Username = $e.Username; Local = $has }
        }
        $grid.ItemsSource = @($rows)
        return ([string]$roster.Source)
    } catch {
        $grid.ItemsSource = @()
        return 'error'
    }
}

function Invoke-AuditGuiMain {
    # 1. Self-elevate (the whole GUI runs elevated; registering needs admin).
    if (-not (Test-IsAdministrator)) {
        $inner = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
        if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $inner += " -ConfigPath `"$ConfigPath`"" }
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList $inner -Verb RunAs | Out-Null }
        catch { [System.Windows.MessageBox]::Show("Self-elevation failed. Re-run elevated.`n$($_.Exception.Message)") | Out-Null }
        return
    }

    if (-not (Test-Path -LiteralPath $CommonPath))        { throw "AuditCommon.ps1 not found at $CommonPath" }
    if (-not (Test-Path -LiteralPath $InstallCommonPath)) { throw "AuditInstallCommon.ps1 not found at $InstallCommonPath" }
    . $CommonPath
    . $InstallCommonPath

    $realConfig = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $DefaultConfigPath } else { $ConfigPath }

    # Prefill tolerantly (NOT Get-AuditConfig, which throws on a blank SharedAccount).
    $pref = @{ LogPath=''; RosterPath=''; SharedAccount='' }
    if (Test-Path -LiteralPath $realConfig) {
        try {
            $raw = Import-PowerShellDataFile -LiteralPath $realConfig
            foreach ($k in 'LogPath','RosterPath','SharedAccount') { if ($raw.ContainsKey($k)) { $pref[$k] = [string]$raw[$k] } }
        } catch { }
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $reader = New-Object System.Xml.XmlNodeReader ([xml](Get-AuditGuiXaml))
    $win = [System.Windows.Markup.XamlReader]::Load($reader)

    $win.FindName('LogBox').Text         = $pref.LogPath
    $win.FindName('RosterBox').Text      = $pref.RosterPath
    $win.FindName('AccountBox').Text     = $pref.SharedAccount
    $win.FindName('InstallDirText').Text = $InstallRoot
    $status = $win.FindName('StatusText')

    # --- per-field Test buttons ---
    $win.FindName('TestLogBtn').Add_Click({
        try {
            $p = $win.FindName('LogBox').Text.Trim()
            $dir = Split-Path -Parent $p
            if (-not [string]::IsNullOrWhiteSpace($dir) -and (Test-Path -LiteralPath $dir)) { $status.Text = "Log path reachable: $dir" }
            else { $status.Text = "Log path NOT reachable now (runtime would spool): $dir" }
        } catch { $status.Text = "Log test error: $($_.Exception.Message)" }
    })
    $win.FindName('TestRosterBtn').Add_Click({
        try {
            $cfg = Resolve-AuditConfigFromValues -Settings (Get-AuditGuiSettings $win)
            $src = Set-AuditRosterGrid $win $cfg
            $status.Text = "Roster source: $src"
        } catch { $status.Text = "Roster test error: $($_.Exception.Message)" }
    })
    $win.FindName('TestAccountBtn').Add_Click({
        try {
            $leaf = (Get-AuditLeafName -Name $win.FindName('AccountBox').Text).ToLowerInvariant()
            $local = Get-LocalUserNameSet
            if ([string]::IsNullOrWhiteSpace($leaf)) { $status.Text = 'Shared account is blank (required).' }
            elseif ($local.Count -gt 0 -and $local.Contains($leaf)) { $status.Text = "Local account '$leaf' exists." }
            else { $status.Text = "No local account '$leaf' (fine if it is a domain account)." }
        } catch { $status.Text = "Account test error: $($_.Exception.Message)" }
    })

    # --- Validate (no changes on disk) ---
    $runPreflight = {
        param($cfg)
        $results = Invoke-AuditPreflight -Config $cfg -SrcDir $SrcDir
        $win.FindName('ResultGrid').ItemsSource = @($results)
        $fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
        $warn = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
        return @{ Fail = $fail; Warn = $warn }
    }
    $win.FindName('ValidateBtn').Add_Click({
        try {
            $cfg = Resolve-AuditConfigFromValues -Settings (Get-AuditGuiSettings $win)
            [void](Set-AuditRosterGrid $win $cfg)
            $t = & $runPreflight $cfg
            $status.Text = "Validated: $($t.Fail) FAIL, $($t.Warn) WARN."
        } catch { $status.Text = "Validate error: $($_.Exception.Message)" }
    })

    # --- Install (writes config, registers, re-validates) ---
    $win.FindName('InstallBtn').Add_Click({
        try {
            $settings = Get-AuditGuiSettings $win
            if ([string]::IsNullOrWhiteSpace($settings.SharedAccount)) { $status.Text = 'Shared account is required.'; return }
            $ans = [System.Windows.MessageBox]::Show("Write config to:`n$realConfig`nand register the tasks?", 'Confirm install', 'OKCancel', 'Question')
            if ($ans -ne 'OK') { $status.Text = 'Install cancelled.'; return }

            $bak = Write-AuditConfigFile -ConfigPath $realConfig -Settings $settings
            Write-AuditDiag -Config (Get-AuditConfig -ConfigPath $realConfig) -Level Info -Message ("GUI: wrote config (backup={0})" -f $bak)

            & $RegisterPath -ConfigPath $realConfig

            $cfg = Get-AuditConfig -ConfigPath $realConfig
            [void](Set-AuditRosterGrid $win $cfg)
            $t = & $runPreflight $cfg
            $status.Text = "Installed. Config written (backup: $bak). Preflight: $($t.Fail) FAIL, $($t.Warn) WARN."
            Write-AuditDiag -Config $cfg -Level Info -Message ("GUI: installed; preflight {0} FAIL {1} WARN" -f $t.Fail, $t.Warn)
        } catch { $status.Text = "Install error: $($_.Exception.Message)" }
    })

    $win.FindName('CloseBtn').Add_Click({ $win.Close() })

    [void]$win.ShowDialog()
}

# Only run the interactive flow when executed directly (NOT when dot-sourced for tests).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-AuditGuiMain
}
```

- [ ] **Step 4: Run the test, expect pass**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: PASS — `Get-AuditGuiXaml` loads, all named controls present.

- [ ] **Step 5: Parse-check the GUI script**

Run:
```powershell
$e=$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path deploy\Install-Audit-GUI.ps1), [ref]$null, [ref]$e); if($e){$e}else{'OK'}
```
Expected: `OK`.

- [ ] **Step 6: Manual smoke (documented, optional in CI-less env)**

Run `deploy\Install-Audit-GUI.ps1` directly. Expected: UAC prompt → window opens prefilled from `config\AuditConfig.psd1`; **Validate** populates the preflight + roster grids without touching disk; **Close** exits. (A live share is not required — unreachable paths show as WARN.)

- [ ] **Step 7: Commit**

```bash
git add deploy/Install-Audit-GUI.ps1 tests/Test-AuditInstall.ps1
git commit -m "feat: add WPF install GUI front-end (Install-Audit-GUI.ps1)"
```

---

### Task 5: README — document the GUI installer

**Files:**
- Modify: `README.md` (install section B, file tree)

**Interfaces:** none (docs).

- [ ] **Step 1: Update the deploy file tree**

In `README.md`, in the `deploy/` block of the file tree, add the GUI line under `Install-Audit.ps1`:

```
│  ├─ Install-Audit.ps1          # one-command per-PC install: self-elevate, register tasks, preflight-validate
│  ├─ Install-Audit-GUI.ps1      # WPF single-pane front-end over Install-Audit (collect paths, preview roster, install)
│  ├─ AuditInstallCommon.ps1     # shared install-time library (preflight, local-account check, config writer)
```

- [ ] **Step 2: Add the GUI as an alternative in install step 6**

In `README.md`, immediately after the `> **No signing.** ...` blockquote in step 6, add:

```markdown
   **Prefer a GUI?** Run `.\deploy\Install-Audit-GUI.ps1` instead — a single-pane window that self-elevates, prefills from the current config, lets you Test each path and preview the roster (read-only, with a "has a local account here?" column), then writes the config (backing up the prior file to `AuditConfig.psd1.bak`) and registers the tasks. It runs the same preflight as the CLI. The CLI remains for scripted/silent installs.
```

- [ ] **Step 3: Verify the README references resolve**

Run:
```powershell
Select-String -Path README.md -Pattern 'Install-Audit-GUI.ps1','AuditInstallCommon.ps1' | Select-Object LineNumber, Line
```
Expected: matches in both the file tree and step 6.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document the WPF install GUI in README"
```

---

## Self-Review

**Spec coverage:**
- Single-pane layout, three fields + Test buttons, roster preview, preflight panel, Validate/Install/Close → Task 4 (XAML + handlers). ✓
- Read-only roster preview with local-account column → `Set-AuditRosterGrid` (Task 4). ✓
- Self-elevation at launch → `Invoke-AuditGuiMain` (Task 4). ✓
- Config writing with `.bak` backup → `Write-AuditConfigFile` (Task 2), called by Install (Task 4). ✓
- Shared preflight extracted to `AuditInstallCommon.ps1`, used by CLI + GUI → Tasks 1, 4. ✓
- Field-resolution helper (temp psd1 → Get-AuditConfig) → `Resolve-AuditConfigFromValues` (Task 3). ✓
- GPO execution-policy check preserved in the moved preflight → Task 1. ✓
- Error handling (handlers wrap in try/catch, surface to status line; diag-logged) → Task 4. ✓
- Verification: parse-check + Write-AuditConfigFile round-trip + manual smoke → Tasks 1–4. ✓
- Out of scope honored: no file copy, no roster editing, runtime untouched, no CLI param-config. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output. ✓

**Type consistency:** `Invoke-AuditPreflight` gains `-SrcDir`/`-LogonTaskName`/`-UnlockTaskName` (Task 1) and is called with `-SrcDir $SrcDir` in both the CLI (Task 1) and GUI (`$runPreflight`, Task 4). `Write-AuditConfigFile` returns the backup path used by Install (Task 4). `Resolve-AuditConfigFromValues -Settings` consumes the hashtable from `Get-AuditGuiSettings`. `Get-AuditGuiXaml` control names (`LogBox`,`RosterBox`,`AccountBox`,`RosterGrid`,`ResultGrid`,`ValidateBtn`,`InstallBtn`,`CloseBtn`,`StatusText`) match the test (Task 4) and the handler `FindName` calls. ✓
