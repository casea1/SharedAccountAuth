# Unified Setup Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the whole per-PC install into one tool, `deploy/Shared-Auth-Setup.ps1`, that does config + folder ACLs + task registration + preflight in a single window; retire the CLI installer; extract shared ACL logic so there is one implementation.

**Architecture:** Move the reusable ACL engine (`Set-AuditLogAcl` append-only model + `Set-AuditLocalStateAcl` ProgramData grant) into `deploy/AuditInstallCommon.ps1`. `Setup-SharePermissions.ps1` becomes a thin server-side wrapper over it. Rename `Install-Audit-GUI.ps1` → `Shared-Auth-Setup.ps1`, add Auditors + Classification fields and a Permissions install step, and delete `Install-Audit.ps1`. Simplify the README install section.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework 4.x WPF (XAML via `XamlReader`), `icacls`/`Set-Acl`, ScheduledTasks. No external modules. Tests are plain built-in PowerShell (no Pester).

## Global Constraints

- **Windows PowerShell 5.1 syntax only** — no PS7-only constructs (`??`, `?.`, ternary, `&&`, `||`, `ForEach-Object -Parallel`).
- **.NET Framework 4.x WPF** + `icacls`/`Set-Acl` built-ins. No external modules. Fully offline.
- **ACL/task helpers never throw** — a failed step reports and returns `$false`/warns; the tool must not crash.
- **No password path touched.**
- Append-only log ACL model (verbatim intent): shared account **CreateFiles + AppendData**, **DENY ReadData + Delete**; auditors **Read**; admin **FullControl**; DACL **protected** (no inherited ACEs).
- **Auditors** field default value is the group name **`Audit`**. Classification dropdown values: `(none)`, `UNCLASSIFIED`, `CUI`, `CONFIDENTIAL`, `SECRET`, `TOP SECRET`; `(none)` ⇒ empty `ClassificationLevel`.
- Style: `Verb-Noun`, comment-based help, header block; match surrounding comment density.
- Tests run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\<file>.ps1` (exit 0 = pass).
- **Spec:** [docs/superpowers/specs/2026-07-21-unified-setup-tool-design.md](../specs/2026-07-21-unified-setup-tool-design.md).

---

### Task 1: ACL engine in `AuditInstallCommon.ps1`

Move the ACE builders + local-state grant into the shared lib and add `Set-AuditLogAcl`.

**Files:**
- Modify: `deploy/AuditInstallCommon.ps1` (add functions)
- Modify: `deploy/Setup-SharePermissions.ps1` (cut the ACE-builder functions — moved, not copied)
- Modify: `tests/Test-AuditInstall.ps1` (add smoke tests)

**Interfaces:**
- Produces:
  - `Set-AuditLogAcl -LogDir <string> -SharedPrincipal <string> -AuditorsPrincipal <string> [-AdminPrincipal <string>='BUILTIN\Administrators']` (supports `-WhatIf`) → `[bool]`
  - `Set-AuditLocalStateAcl -Config <hashtable> [-SharedAccountOverride <string>]` → `void`
  - The ACE builders `New-SharedDirCreateAce`, `New-SharedFileAppendAce`, `New-SharedDenyAce`, `New-AuditorsReadAce`, `New-AdminFullControlAce` (moved into the lib).

- [ ] **Step 1: Write the failing tests**

Append to `tests/Test-AuditInstall.ps1` before its final tally block:

```powershell
Write-Host 'Task 1: ACL engine in AuditInstallCommon'
foreach ($fn in 'Set-AuditLogAcl','Set-AuditLocalStateAcl','New-SharedDirCreateAce','New-AuditorsReadAce') {
    Assert-True ([bool](Get-Command $fn -ErrorAction SilentlyContinue)) "function $fn is defined"
}
# ACE builders are pure — they must produce FileSystemAccessRule objects without touching disk.
$__ace = New-SharedDirCreateAce -Principal $env:USERNAME
Assert-True ($__ace -is [System.Security.AccessControl.FileSystemAccessRule]) 'New-SharedDirCreateAce returns a FileSystemAccessRule'
# Set-AuditLogAcl -WhatIf must validate + gate without applying or throwing.
$__d = Join-Path $env:TEMP ('logacl_' + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force $__d | Out-Null
$__threw = $false
try { $__r = Set-AuditLogAcl -LogDir $__d -SharedPrincipal $env:USERNAME -AuditorsPrincipal 'Administrators' -WhatIf } catch { $__threw = $true }
Assert-True (-not $__threw) 'Set-AuditLogAcl -WhatIf does not throw'
try { Remove-Item -LiteralPath $__d -Recurse -Force -ErrorAction SilentlyContinue } catch { }
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — `Set-AuditLogAcl`/`Set-AuditLocalStateAcl`/the ACE builders are not defined in the lib yet.

- [ ] **Step 3: Move the ACE builders into `AuditInstallCommon.ps1`**

**Cut** these five functions **verbatim** from `deploy/Setup-SharePermissions.ps1` and **paste** them into `deploy/AuditInstallCommon.ps1` (after the existing functions, before any trailing content): `New-SharedDirCreateAce`, `New-SharedFileAppendAce`, `New-SharedDenyAce`, `New-AuditorsReadAce`, `New-AdminFullControlAce`. Do not change their bodies. (They are pure `FileSystemAccessRule` builders.)

- [ ] **Step 4: Add `Set-AuditLocalStateAcl` to `AuditInstallCommon.ps1`**

Copy this function from `deploy/Install-Audit.ps1` into `deploy/AuditInstallCommon.ps1` verbatim (it is deleted from `Install-Audit.ps1` in Task 3):

```powershell
function Set-AuditLocalStateAcl {
<#
.SYNOPSIS
    Grant the shared account Modify on the local state root (LocalRoot) so the
    prompt (which runs as that account) can write ALL of its state files
    (cache/diag/spool/state), not just create new spool files. Never throws.
.PARAMETER Config
    Resolved config hashtable (LocalRoot, SharedAccount).
.PARAMETER SharedAccountOverride
    Optional explicit shared account (else uses config SharedAccount).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable] $Config,
        [string] $SharedAccountOverride
    )
    try {
        $localRoot = [string]$Config.LocalRoot
        if ([string]::IsNullOrWhiteSpace($localRoot)) { return }
        if (-not (Test-Path -LiteralPath $localRoot)) {
            New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
        }
        $acct = if (-not [string]::IsNullOrWhiteSpace($SharedAccountOverride)) { $SharedAccountOverride } else { [string]$Config.SharedAccount }
        $leaf = Get-AuditLeafName -Name $acct
        if ([string]::IsNullOrWhiteSpace($leaf)) { return }
        $bs = $acct.IndexOf('\')
        if ($bs -ge 0 -and $acct.Substring(0, $bs) -ne '.' -and -not [string]::IsNullOrWhiteSpace($acct.Substring(0, $bs))) {
            $grantee = $acct
        } else {
            $grantee = '{0}\{1}' -f $env:COMPUTERNAME, $leaf
        }
        $icaclsOut = & icacls "$localRoot" /grant ("{0}:(OI)(CI)M" -f $grantee) /T /C 2>&1
        if ($LASTEXITCODE -ne 0) { throw ("icacls returned {0}: {1}" -f $LASTEXITCODE, ($icaclsOut -join '; ')) }
        Write-Host ("Granted '{0}' write access to local state: {1}" -f $grantee, $localRoot) -ForegroundColor Cyan
        try { Write-AuditDiag -Config $Config -Level Info -Message ("Setup: granted {0} Modify on {1}" -f $grantee, $localRoot) } catch { }
    } catch {
        Write-Warning ("Could not set local-state ACL (non-fatal): {0}" -f $_.Exception.Message)
        try { Write-AuditDiag -Config $Config -Level Warn -Message ("Setup: could not set local-state ACL: {0}" -f $_.Exception.Message) } catch { }
    }
}
```

- [ ] **Step 5: Add `Set-AuditLogAcl` to `AuditInstallCommon.ps1`**

```powershell
function Set-AuditLogAcl {
<#
.SYNOPSIS
    Apply the append-only NTFS model to the central audit-log directory:
    the shared account may CREATE + APPEND but is DENIED read/delete; auditors
    get read; admin gets full; the DACL is protected (no inherited ACEs). This
    is the one implementation used by both Shared-Auth-Setup.ps1 (local logs)
    and Setup-SharePermissions.ps1 (server-side).
.PARAMETER LogDir
    The directory holding access_log.csv (created if missing).
.PARAMETER SharedPrincipal
    The shared account/group (create+append; DENY read+delete).
.PARAMETER AuditorsPrincipal
    The read-only reviewers group.
.PARAMETER AdminPrincipal
    FullControl principal (default BUILTIN\Administrators).
.OUTPUTS
    [bool] $true if applied, $false if skipped (WhatIf) or on failure. Never throws.
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string] $LogDir,
        [Parameter(Mandatory = $true)][string] $SharedPrincipal,
        [Parameter(Mandatory = $true)][string] $AuditorsPrincipal,
        [string] $AdminPrincipal = 'BUILTIN\Administrators'
    )
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            if ($PSCmdlet.ShouldProcess($LogDir, 'Create audit log directory')) {
                New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            } else { return $false }
        }
        $resolved = (Resolve-Path -LiteralPath $LogDir).Path

        # Build all ACEs first (validates principal-name resolution before we mutate).
        $aceSharedCreate = New-SharedDirCreateAce  -Principal $SharedPrincipal
        $aceSharedAppend = New-SharedFileAppendAce -Principal $SharedPrincipal
        $aceSharedDeny   = New-SharedDenyAce       -Principal $SharedPrincipal
        $aceAuditors     = New-AuditorsReadAce     -Principal $AuditorsPrincipal
        $aceAdmin        = New-AdminFullControlAce -Principal $AdminPrincipal

        if (-not $PSCmdlet.ShouldProcess($resolved, 'Apply append-only audit ACL (deny read/delete to shared principal)')) {
            return $false
        }

        $acl = Get-Acl -LiteralPath $resolved
        # Protect from inheritance and DROP inherited ACEs (so a broad Users:Read
        # cannot leak a read of the log to the shared account).
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($aceSharedCreate, $aceSharedAppend, $aceSharedDeny, $aceAuditors, $aceAdmin)) {
            [void]$acl.RemoveAccessRuleAll($r)
        }
        $acl.AddAccessRule($aceSharedDeny)     # DENY read + delete (hard wall)
        $acl.AddAccessRule($aceSharedCreate)   # ALLOW create file + traverse (this folder)
        $acl.AddAccessRule($aceSharedAppend)   # ALLOW append rows (files only)
        $acl.AddAccessRule($aceAuditors)       # ALLOW auditors read
        $acl.AddAccessRule($aceAdmin)          # ALLOW admin full control
        Set-Acl -LiteralPath $resolved -AclObject $acl
        return $true
    } catch {
        Write-Warning ("Set-AuditLogAcl failed on {0}: {1}" -f $LogDir, $_.Exception.Message)
        return $false
    }
}
```

- [ ] **Step 6: Run tests + parse-check**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1` → PASS.
Parse-check: `powershell -NoProfile -Command "$e=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path deploy\AuditInstallCommon.ps1),[ref]$null,[ref]$e);if($e){$e}else{'OK'}"` → `OK`.

- [ ] **Step 7: Commit**

```bash
git add deploy/AuditInstallCommon.ps1 deploy/Setup-SharePermissions.ps1 tests/Test-AuditInstall.ps1
git commit -m "refactor: move ACL engine (Set-AuditLogAcl + Set-AuditLocalStateAcl + ACE builders) into AuditInstallCommon"
```

---

### Task 2: `Setup-SharePermissions.ps1` → thin wrapper

**Files:**
- Modify: `deploy/Setup-SharePermissions.ps1`

**Interfaces:**
- Consumes: `Set-AuditLogAcl`, `Set-AuditLocalStateAcl`, `New-*Ace`, `Test-IsElevated`? (see below) from `AuditInstallCommon.ps1`.

- [ ] **Step 1: Dot-source the lib + replace MAIN with the wrapper**

In `deploy/Setup-SharePermissions.ps1`:
1. Near the top (after `Set-StrictMode`/`$ErrorActionPreference`), dot-source the shared lib:
```powershell
$DeployDir = $PSScriptRoot
. (Join-Path $DeployDir 'AuditInstallCommon.ps1')
```
2. The ACE-builder functions were moved out in Task 1 — they are no longer defined in this file. Keep the file's own `Test-IsElevated` (used below) OR, if it was also referenced by the moved code, keep a local copy. (`Test-IsElevated` stays in this file.)
3. Replace the MAIN body (the elevated check → build ACEs → protect DACL → Set-Acl → verification block) with:
```powershell
if (-not (Test-IsElevated)) {
    Write-Warning 'This script must be run ELEVATED (Run as administrator).'
    throw 'Not elevated - aborting before touching any ACLs.'
}

Write-Host ''
Write-Host '=== Audit log ACL hardening (append-only) ==='
Write-Host ("  Directory : {0}" -f $LogDir)
Write-Host ("  Shared    : {0}   (create + append; DENY read/delete)" -f $SharedPrincipal)
Write-Host ("  Auditors  : {0}   (read-only)" -f $AuditorsPrincipal)
Write-Host ("  Admin     : {0}   (full control)" -f $AdminPrincipal)

$applied = Set-AuditLogAcl -LogDir $LogDir -SharedPrincipal $SharedPrincipal `
                           -AuditorsPrincipal $AuditorsPrincipal -AdminPrincipal $AdminPrincipal
if ($applied) { Write-Host 'ACL applied.' } else { Write-Host 'ACL not applied (WhatIf or failure — see warnings).' }

# Verification: print the resulting ACL.
if (Test-Path -LiteralPath $LogDir) {
    Write-Host ''
    Write-Host '=== Resulting ACL (verification) ==='
    & icacls "$LogDir" | Out-Host
}
```
4. Keep the existing `-LocalStateDir` block (the optional local-state grant) as-is — but it can now also call `Set-AuditLocalStateAcl` if you prefer; leaving the existing icacls grant is fine. Do NOT change its behaviour.

Note: `Set-AuditLogAcl` supports `-WhatIf`; the script already declares `[CmdletBinding(SupportsShouldProcess=$true)]`, so `-WhatIf` on the script flows into `Set-AuditLogAcl`.

- [ ] **Step 2: Parse-check + smoke**

Parse-check `deploy\Setup-SharePermissions.ps1` → `OK`.
Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1` → still PASS.

- [ ] **Step 3: Commit**

```bash
git add deploy/Setup-SharePermissions.ps1
git commit -m "refactor: Setup-SharePermissions is a thin wrapper over Set-AuditLogAcl"
```

---

### Task 3: Rename GUI → `Shared-Auth-Setup.ps1`; delete `Install-Audit.ps1`

**Files:**
- Rename: `deploy/Install-Audit-GUI.ps1` → `deploy/Shared-Auth-Setup.ps1`
- Delete: `deploy/Install-Audit.ps1`
- Modify: `tests/Test-AuditInstall.ps1` (update the GUI file-path reference)

- [ ] **Step 1: Rename + delete via git**

```bash
git mv deploy/Install-Audit-GUI.ps1 deploy/Shared-Auth-Setup.ps1
git rm deploy/Install-Audit.ps1
```

- [ ] **Step 2: Update the file's own header + any self-references**

In `deploy/Shared-Auth-Setup.ps1`, update the header comment block's filename from `Install-Audit-GUI.ps1` to `Shared-Auth-Setup.ps1`, and its `Invoke-SelfElevate` relaunch (which uses `$PSCommandPath`, so no literal name — verify no hard-coded `Install-Audit-GUI` string remains):
```powershell
# Search the file for the old name and update comments only:
#   Select-String -Path deploy\Shared-Auth-Setup.ps1 -Pattern 'Install-Audit-GUI|Install-Audit\.ps1'
```
Fix any comment references. The registration call still points at `Register-AuditTasks.ps1` (unchanged).

- [ ] **Step 3: Update the test's GUI path reference**

In `tests/Test-AuditInstall.ps1`, find the block that dot-sources the GUI (`$guiPath = Join-Path $RepoRoot 'deploy\Install-Audit-GUI.ps1'`) and change it to:
```powershell
$guiPath = Join-Path $RepoRoot 'deploy\Shared-Auth-Setup.ps1'
```
Also grep the whole repo for stragglers and confirm nothing else references the deleted/renamed files:
```powershell
Select-String -Path tests\*.ps1, deploy\*.ps1 -Pattern 'Install-Audit-GUI|Install-Audit\.ps1'
```
(README is handled in Task 5. Any hit in `deploy\`/`tests\` must be fixed now.)

- [ ] **Step 4: Run tests + parse-check**

Run both harnesses → PASS. Parse-check `deploy\Shared-Auth-Setup.ps1` → `OK`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: rename install GUI to Shared-Auth-Setup.ps1; delete CLI Install-Audit.ps1"
```

---

### Task 4: Expand `Shared-Auth-Setup.ps1` (Auditors + Classification + Permissions step)

**Files:**
- Modify: `deploy/Shared-Auth-Setup.ps1`
- Modify: `tests/Test-AuditInstall.ps1` (new named controls)

**Interfaces:**
- Consumes: `Set-AuditLogAcl`, `Set-AuditLocalStateAcl` (AuditInstallCommon); `Write-AuditConfigFile`, `Get-AuditConfig`, `Register-AuditTasks.ps1`.

Read `deploy/Shared-Auth-Setup.ps1` fully first — you are editing a large existing WPF script.

- [ ] **Step 1: Write the failing test (new controls)**

In `tests/Test-AuditInstall.ps1`, extend the GUI named-controls assertion list (the `foreach ($n in 'LogBox','RosterBox',...)` block) to include the two new controls:
```powershell
foreach ($n in 'LogBox','RosterBox','AccountBox','AuditorsBox','ClassificationCombo','RosterGrid','ResultGrid','ValidateBtn','InstallBtn','CloseBtn','StatusText') {
    Assert-True ($null -ne $w.FindName($n)) "control '$n' present"
}
```

- [ ] **Step 2: Run, expect failure**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1`
Expected: FAIL — `AuditorsBox` / `ClassificationCombo` not present in the XAML yet.

- [ ] **Step 3: Add the two fields to the XAML (`Get-AuditGuiXaml`)**

In the XAML string, after the `AccountBox` row (Shared account), add an Auditors row and a Classification row. Add these controls inside the same fields grid, following the existing row pattern (label + input):
```xml
    <TextBlock Text="Auditors (read-only group):" Margin="4" VerticalAlignment="Center"/>
    <TextBox   x:Name="AuditorsBox" Margin="4" Text="Audit"/>

    <TextBlock Text="Classification:" Margin="4" VerticalAlignment="Center"/>
    <ComboBox  x:Name="ClassificationCombo" Margin="4">
      <ComboBoxItem Content="(none)"/>
      <ComboBoxItem Content="UNCLASSIFIED"/>
      <ComboBoxItem Content="CUI"/>
      <ComboBoxItem Content="CONFIDENTIAL"/>
      <ComboBoxItem Content="SECRET"/>
      <ComboBoxItem Content="TOP SECRET"/>
    </ComboBox>
```
(Match the existing grid's row/column layout — the exact `Grid.Row`/`Grid.Column` or DockPanel wrapping follows whatever the surrounding fields use; the XAML-load test validates it parses and the names resolve.)

- [ ] **Step 4: Prefill + read the new fields (code-behind)**

a. Where the code prefills the fields from the loaded config, set the classification combo from `$pref` / raw config and leave Auditors at its `Audit` default:
```powershell
    # Select the classification combo item matching the config (or "(none)").
    $clsWanted = ''
    if ($raw -and $raw.ContainsKey('ClassificationLevel')) { $clsWanted = [string]$raw['ClassificationLevel'] }
    $clsCombo = $win.FindName('ClassificationCombo')
    $clsSel = 0
    for ($i = 0; $i -lt $clsCombo.Items.Count; $i++) {
        $txt = [string]$clsCombo.Items[$i].Content
        if ($txt -eq $clsWanted -or ($clsWanted -eq '' -and $txt -eq '(none)')) { $clsSel = $i; break }
    }
    $clsCombo.SelectedIndex = $clsSel
```
b. Extend `Get-AuditGuiSettings` to include the classification level (mapping `(none)` → `''`), and expose the auditors value. Update the function to return both the config settings and the auditors principal, e.g.:
```powershell
function Get-AuditGuiSettings($win) {
    $clsItem = $win.FindName('ClassificationCombo').SelectedItem
    $cls = if ($null -ne $clsItem) { [string]$clsItem.Content } else { '' }
    if ($cls -eq '(none)') { $cls = '' }
    @{
        LogPath             = $win.FindName('LogBox').Text.Trim()
        RosterPath          = $win.FindName('RosterBox').Text.Trim()
        SharedAccount       = $win.FindName('AccountBox').Text.Trim()
        ClassificationLevel = $cls
    }
}
```
And read the auditors value where needed:
```powershell
    $auditors = $win.FindName('AuditorsBox').Text.Trim()
    if ([string]::IsNullOrWhiteSpace($auditors)) { $auditors = 'Audit' }
```

- [ ] **Step 5: Add the Permissions step to the Install handler**

In the `InstallBtn` click handler, **after** `Write-AuditConfigFile` succeeds and **before/around** the register call, insert the Permissions step. Resolve the shared + auditors principals to grantable identities, grant local state always, and apply the append-only log ACL only when the log path is local:
```powershell
            # --- Permissions ---
            # Local state (always): the shared account must write its own cache/diag/spool/state.
            try {
                Set-AuditLocalStateAcl -Config (Get-AuditConfig -ConfigPath $realConfig) -SharedAccountOverride $settings.SharedAccount
                $status.Text = 'Local-state permissions set.'
            } catch { $status.Text = "Local-state ACL error: $($_.Exception.Message)" }

            # Log folder ACL: only when the log path is LOCAL (a workstation can't
            # set a remote server's NTFS ACLs — for a UNC share use Setup-SharePermissions on the server).
            $logDir = Split-Path -Parent $settings.LogPath
            if ($settings.LogPath -like '\\*') {
                $status.Text = "Log is a UNC share — set its ACL on the server with Setup-SharePermissions.ps1."
            } elseif (-not [string]::IsNullOrWhiteSpace($logDir)) {
                # Resolve grantable principals (MACHINE\name for bare/.\; keep MACHINE\/DOMAIN\).
                $sharedLeaf = Get-AuditLeafName -Name $settings.SharedAccount
                $sharedGrantee = if ($settings.SharedAccount -like '*\*' -and $settings.SharedAccount -notlike '.\*') { $settings.SharedAccount } else { "$env:COMPUTERNAME\$sharedLeaf" }
                $audLeaf = Get-AuditLeafName -Name $auditors
                $audGrantee = if ($auditors -like '*\*' -and $auditors -notlike '.\*') { $auditors } else { "$env:COMPUTERNAME\$audLeaf" }
                $ok = Set-AuditLogAcl -LogDir $logDir -SharedPrincipal $sharedGrantee -AuditorsPrincipal $audGrantee
                if ($ok) { $status.Text = "Log-folder append-only ACL applied: $logDir" }
                else { $status.Text = "Log-folder ACL not applied (see warnings) — $logDir" }
            }
```
Keep the existing config-write, register, and preflight calls. `Get-AuditGuiSettings` now includes `ClassificationLevel`, so the existing `Write-AuditConfigFile -Settings $settings` write persists it — no other change needed there.

- [ ] **Step 6: Run tests + parse-check**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Test-AuditInstall.ps1` → PASS (incl. the 11 named controls).
Parse-check `deploy\Shared-Auth-Setup.ps1` → `OK`.

- [ ] **Step 7: Manual smoke (documented; not automatable here)**

On a target PC with a **local** log path: run `Shared-Auth-Setup.ps1`, fill the fields (Auditors defaults to `Audit`, pick a Classification), Install → confirm config written (incl. classification), the log folder shows the append-only ACL (shared can append, not read/delete; `Audit` can read), local-state ACL applied, tasks registered, preflight green; then a real logon writes a row.

- [ ] **Step 8: Commit**

```bash
git add deploy/Shared-Auth-Setup.ps1 tests/Test-AuditInstall.ps1
git commit -m "feat: Shared-Auth-Setup does config + folder ACLs + tasks + preflight (auditors, classification)"
```

---

### Task 5: README + docs

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-06-18-install-gui-wizard-design.md`

- [ ] **Step 1: Simplify the README install section**

In `README.md`:
- **`deploy/` file tree:** replace the `Install-Audit.ps1` and `Install-Audit-GUI.ps1` lines with a single `Shared-Auth-Setup.ps1  # one-command setup: config + folder ACLs + tasks + preflight` line; add a one-line "engine/advanced" note next to `Register-AuditTasks.ps1` / `Setup-SharePermissions.ps1`.
- **Install steps (§2):** replace the multi-step A/B (server + per-PC) list with:
  ```
  ### On each workstation
  1. Copy the whole tree to C:\Program Files\SharedAccountAuth\.
  2. Run  .\deploy\Shared-Auth-Setup.ps1  (it self-elevates).
     Fill in: central log path, roster path, shared account, auditors group
     (default 'Audit'), classification. Click Install.
     It writes the config, sets folder permissions, registers the tasks, and
     runs the preflight. Done.

  ### Only if the log is a central SERVER share (\\server\share)
  Run  deploy\Setup-SharePermissions.ps1  on the SERVER once to set the
  append-only ACL there (a workstation can't set a remote server's NTFS ACLs).
  ```
- Remove references to `Install-Audit.ps1` and the old per-PC "sign / register / ensure local accounts / set ACLs" step list. Update the troubleshooting/roster/classification cross-references that named `Install-Audit-GUI.ps1` to `Shared-Auth-Setup.ps1`.

- [ ] **Step 2: Verify README references**

Run:
```powershell
Select-String -Path README.md -Pattern 'Install-Audit\.ps1|Install-Audit-GUI'
```
Expected: **no matches** (all replaced by `Shared-Auth-Setup.ps1`).

- [ ] **Step 3: Rev note on the prior spec**

In `docs/superpowers/specs/2026-06-18-install-gui-wizard-design.md`, add a dated rev note near the top: the GUI is renamed to `Shared-Auth-Setup.ps1` and expanded to also set folder ACLs (append-only log ACL when local + local-state) and collect Auditors + Classification; the CLI `Install-Audit.ps1` is retired. Point to `2026-07-21-unified-setup-tool-design.md`.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/specs/2026-06-18-install-gui-wizard-design.md
git commit -m "docs: simplify install to one Shared-Auth-Setup.ps1 step"
```

---

## Self-Review

**Spec coverage:**
- Rename GUI → `Shared-Auth-Setup.ps1` → Task 3. ✓
- Auditors field (default `Audit`) + Classification dropdown → Task 4. ✓
- Permissions step: local-state always + append-only log ACL when local + UNC skip/guide → Task 4 (Step 5). ✓
- `Set-AuditLogAcl` + `Set-AuditLocalStateAcl` extracted to shared lib → Task 1. ✓
- `Setup-SharePermissions.ps1` thin wrapper → Task 2. ✓
- Delete `Install-Audit.ps1` → Task 3. ✓
- Keep `Register-AuditTasks`/`Unregister` → unchanged. ✓
- Config: classification written, auditors transient → Task 4 (Get-AuditGuiSettings includes ClassificationLevel; auditors read separately, not in Settings). ✓
- README simplification + spec rev note → Task 5. ✓
- Never-throw ACL helpers → Task 1 (try/catch, return $false/warn). ✓

**Placeholder scan:** every code step shows complete code; refactor/rename steps name exact functions/files and provide the new bodies. The two "match the surrounding grid layout" notes are bounded (the XAML-load test enforces correctness), not vague. ✓

**Type consistency:** `Set-AuditLogAcl(-LogDir,-SharedPrincipal,-AuditorsPrincipal,-AdminPrincipal)→[bool]` used identically in Task 1 test, Task 2 wrapper, and Task 4 Install handler. `Set-AuditLocalStateAcl(-Config,-SharedAccountOverride)` consistent across Task 1 def and Task 4 call. New controls `AuditorsBox`/`ClassificationCombo` match between Task 4 XAML, the Task 4 test, and the code-behind `FindName` calls. `Get-AuditGuiSettings` returns `ClassificationLevel` (Task 4) consumed by the existing `Write-AuditConfigFile` call. ✓
