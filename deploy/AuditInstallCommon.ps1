<#
=======================================================================
 AuditInstallCommon.ps1 - shared install-time library for the Shared-
 Account Sign-On Audit Logger. Dot-sourced by deploy\Shared-Auth-Setup.ps1
 (WPF). PS 5.1 / built-ins only; fully offline. Provides the preflight
 engine, local-account enumeration, a psd1 writer, and a value->resolved-
 config helper.
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
               'WriteRetryCount','WriteRetryBaseMs','AppName','WindowTitle','WindowSubtitle',
               'ClassificationLevel','ClassificationText','ClassificationForeground','ClassificationBackground','LogoPath')
    $numeric  = @('RetryDelayMs','DebounceSeconds','WriteRetryCount','WriteRetryBaseMs')
    $defaults = @{
        LogPath='\\server\share\audit\access_log.csv'; RosterPath='\\server\share\audit\roster.csv'
        LocalRoot='C:\ProgramData\SharedAccountAuth'; RosterCachePath=''; SpoolDir=''; DiagLogPath=''; StateDir=''
        SharedAccount='.\LabShared'; AuthDomain='.'
        RetryDelayMs=1000; DebounceSeconds=5; WriteRetryCount=10; WriteRetryBaseMs=50
        AppName='SharedAccountAuth'; WindowTitle='Shared Account - Authenticate to Continue'
        WindowSubtitle='Select your name and enter your personal account password. This window cannot be dismissed.'
        ClassificationLevel=''; ClassificationText=''; ClassificationForeground=''; ClassificationBackground=''; LogoPath=''
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

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    # --- Classification banner + logo ---')
    [void]$sb.AppendLine(('    ClassificationLevel      = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationLevel')))
    [void]$sb.AppendLine(('    ClassificationText       = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationText')))
    [void]$sb.AppendLine(('    ClassificationForeground = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationForeground')))
    [void]$sb.AppendLine(('    ClassificationBackground = {0}' -f (ConvertTo-AuditPsd1Value 'ClassificationBackground')))
    [void]$sb.AppendLine(('    LogoPath                 = {0}' -f (ConvertTo-AuditPsd1Value 'LogoPath')))

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

function New-SharedDirCreateAce {
<#
.SYNOPSIS
    Builds the SHARED principal's "this-folder-only" ALLOW rule that lets
    it create the log file and traverse, WITHOUT listing the directory.
.DESCRIPTION
    Rights (each bit explained):
      CreateFiles    0x2  — on a DIRECTORY = AddFile = create a new file
                            (this is how access_log.csv gets created). NOTE:
                            this same bit is WriteData on a FILE, which is
                            why we keep it dir-only (no object inheritance).
      AppendData     0x4  — on a DIRECTORY = AddSubdirectory (harmless here;
                            included for parity with the create capability).
      Synchronize    0x100000 — required for normal synchronous file I/O;
                            without it many file opens fail with odd errors.
      ReadAttributes 0x80 — query file/dir attributes (size/timestamps).
                            Reading ATTRIBUTES is not reading CONTENT, so it
                            does not violate the no-read rule.
      Traverse       0x20 — on a DIRECTORY = pass THROUGH the folder to a
                            named child (open access_log.csv by full path)
                            WITHOUT being able to ListDirectory.

    Inheritance: NONE (this folder only). InheritanceFlags=None means the
    ACE does not propagate to files or subfolders, so CreateFiles (=WriteData
    on a file) can NEVER leak onto a file and allow overwriting rows.
    PropagationFlags=None.
.PARAMETER Principal
    The shared account/group (DOMAIN\name, .\name, or MACHINE\name).
.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Principal)

    # NOTE: AppendData (=AddSubdirectory on a directory) is deliberately NOT
    # granted — the shared account needs to create access_log.csv (CreateFiles),
    # not arbitrary subfolders inside the locked audit directory. Least privilege.
    $rights = `
        [System.Security.AccessControl.FileSystemRights]::CreateFiles    -bor `  # 0x2  create access_log.csv (dir: AddFile)
        [System.Security.AccessControl.FileSystemRights]::Synchronize    -bor `  # 0x100000 synchronous I/O
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `  # 0x80 attrs only (NOT content)
        [System.Security.AccessControl.FileSystemRights]::Traverse              # 0x20 pass-through to a named child

    # InheritanceFlags::None + PropagationFlags::None  => THIS FOLDER ONLY.
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Principal,
        $rights,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}


function New-SharedFileAppendAce {
<#
.SYNOPSIS
    Builds the SHARED principal's ALLOW rule that lets it APPEND rows to
    files in this folder (inherited to files only).
.DESCRIPTION
    Rights (each bit explained):
      AppendData     0x4  — on a FILE = FILE_APPEND_DATA = append to the
                            END of the file. CRUCIALLY this does NOT permit
                            seeking back to overwrite existing rows — that
                            would require WriteData (0x2), which we DELIBERATELY
                            omit. This is the "append, never overwrite" control.
      Synchronize    0x100000 — required for normal synchronous file I/O.
      ReadAttributes 0x80 — query attributes (NOT content).
      WriteAttributes 0x100 — update attributes (e.g. archive bit / timestamps
                            the OS touches on write). Not content; safe.

    Notably ABSENT: WriteData (0x2) and ReadData (0x1). No WriteData means
    no overwrite of prior rows; no ReadData means no reading the log. (Read is
    also affirmatively DENIED below, which wins regardless.)

    Inheritance: ObjectInherit + InheritOnly  => applies to FILES only, and
    NOT to the directory object itself (so it never grants AppendData on the
    container, only on files within it).
.PARAMETER Principal
    The shared account/group.
.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Principal)

    $rights = `
        [System.Security.AccessControl.FileSystemRights]::AppendData      -bor `  # 0x4   append rows (no overwrite)
        [System.Security.AccessControl.FileSystemRights]::Synchronize     -bor `  # 0x100000 synchronous I/O
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes  -bor `  # 0x80  attrs only (NOT content)
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes        # 0x100 update attrs on write

    # ObjectInherit  => inherit to FILES.
    # InheritOnly    => this ACE does NOT apply to the directory object itself,
    #                   only to the files that inherit it.
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Principal,
        $rights,
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Allow)
}


function New-SharedDenyAce {
<#
.SYNOPSIS
    Builds the SHARED principal's DENY rule (read + delete). DENY ACEs
    override ALLOW ACEs for the same principal, so this is the hard wall.
.DESCRIPTION
    Rights (each bit explained):
      ReadData       0x1     — on a FILE = read bytes; on a DIR = ListDirectory.
                              Denying this is THE control that makes the log
                              unreadable to the shared account (no header
                              check, no dedup, no exfiltration).
      Delete         0x10000 — delete THIS object. Denied so the account
                              cannot remove access_log.csv.
      DeleteSubdirectoriesAndFiles 0x40 — (directory right) delete children.
                              Denied so the account cannot delete files in
                              the folder via the parent's delete-child right.

    Inheritance: ContainerInherit + ObjectInherit (applies to this folder,
    its subfolders, AND its files). PropagationFlags=None so it cascades
    fully. A DENY that covers BOTH the container and inherited files ensures
    the account can neither list the directory nor read/delete any file in it.

    ORDERING NOTE: When persisted, the OS canonicalizes the DACL so explicit
    DENY ACEs sort before explicit ALLOW ACEs. Thus this deny is evaluated
    first and reliably overrides the create/append allows above for the same
    principal. (DENY ReadData + ALLOW AppendData = "append-only, no read".)
.PARAMETER Principal
    The shared account/group.
.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Principal)

    $rights = `
        [System.Security.AccessControl.FileSystemRights]::ReadData -bor `                       # 0x1     no read / no list
        [System.Security.AccessControl.FileSystemRights]::Delete   -bor `                       # 0x10000 no delete of the log
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles          # 0x40    no delete of children

    # ContainerInherit + ObjectInherit => this folder + subfolders + files.
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Principal,
        $rights,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Deny)
}


function New-AuditorsReadAce {
<#
.SYNOPSIS
    Builds the AUDITORS group's ALLOW rule: ReadAndExecute + Synchronize,
    inherited to subfolders and files.
.DESCRIPTION
    Rights:
      ReadAndExecute  — composite = ReadData + ExecuteFile + ReadAttributes
                        + ReadExtendedAttributes + ReadPermissions + Synchronize.
                        This is exactly the "read the CSV, list the folder"
                        capability auditors need.
      Synchronize     — explicitly OR'd in for clarity (already part of
                        ReadAndExecute, but stated to be unambiguous).
    Auditors get NO write/append/delete — read-only review.

    Inheritance: ContainerInherit + ObjectInherit so the right reaches
    subfolders and files (the log file inherits Read).
.PARAMETER Principal
    The auditors group (DOMAIN\Auditors or .\Auditors).
.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Principal)

    $rights = `
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `   # read content + list + traverse
        [System.Security.AccessControl.FileSystemRights]::Synchronize            # 0x100000 synchronous I/O

    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Principal,
        $rights,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}


function New-AdminFullControlAce {
<#
.SYNOPSIS
    Builds the ADMIN/service principal's ALLOW FullControl rule, inherited
    to subfolders and files.
.DESCRIPTION
    FullControl so administrators / the service account can manage, rotate,
    archive, and (if ever needed) delete the log. Inherited to children.
.PARAMETER Principal
    The admin/service principal (defaults to BUILTIN\Administrators).
.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Principal)

    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Principal,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}

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
