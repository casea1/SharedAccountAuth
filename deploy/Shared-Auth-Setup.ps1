<#
=======================================================================
 Shared-Auth-Setup.ps1 - single-pane WPF front-end for the per-PC
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
