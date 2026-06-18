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
