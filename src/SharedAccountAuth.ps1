<#
=======================================================================
 SharedAccountAuth.ps1 — fullscreen lockdown WPF prompt (entry point)
 Windows PowerShell 5.1 / .NET Framework 4.x (WPF) ONLY. No external
 modules. Fully offline. Append-only to the central CSV (never read).

 Spec: docs\superpowers\specs\2026-06-17-sign-on-audit-logger-design.md
       (sections 9 "Lockdown Prompt", 6 "AuditCommon API", 15
       "Diagnostics/Security", 17 "Hard Constraints").

 -----------------------------------------------------------------------
 WHAT THIS IS / TRADEOFF (read before changing the lockdown behaviour):
 -----------------------------------------------------------------------
 This is a MODAL, POST-LOGON DESKTOP LOCK — NOT a credential provider.
 The shared account is ALREADY logged on (Task Scheduler launches us in
 its interactive session). We block the visible desktop with a topmost,
 borderless, un-closable window that spans every monitor, and we verify —
 via the person's OWN local password (Test-AuditCredential -> LogonUser
 against the local SAM) — WHO is using the already-logged-in shared
 session. We then append one row to the central audit CSV.

 Honest limitations (documented, not hidden):
   * This is NOT a logon gate. Windows is already at the desktop; we
     merely cover it. A determined user can press Ctrl+Alt+Del to reach
     the Secure Desktop, open Task Manager, and kill this process —
     there is no way to suppress the Secure Desktop from user-mode here.
   * Therefore auth here proves "who is at the keyboard of the shared
     session", it is NOT an access-control boundary. The real boundary is
     the append-only NTFS ACL on the central log + the auditable record.
   * TRUE pre-logon enforcement would require a custom Windows Credential
     Provider (a signed COM DLL), which is OUT OF SCOPE for this offline,
     no-external-components design.

 DEGRADE SAFELY: every failure path keeps the window locked, spools/logs,
 and NEVER crashes to an unlocked desktop. If we cannot even show the
 window, we log a diag breadcrumb and exit — we never throw to a console.

 PASSWORD SECURITY (spec §15): the password is a SecureString read from
 the WPF PasswordBox (.SecurePassword). It is passed straight into
 Test-AuditCredential, which is the ONLY place it becomes plaintext (at
 the P/Invoke boundary, zeroed immediately). We NEVER bind it, copy it to
 a string, write it to the diag log, the CSV, a spool file, or any
 longer-lived variable. We Dispose() the SecureString after each attempt.

 -----------------------------------------------------------------------
 Config block (single source of truth: config\AuditConfig.psd1, loaded by
 Get-AuditConfig). Keys this script relies on:
 -----------------------------------------------------------------------
   SharedAccount    self-check guard (Test-AuditIsSharedAccount)
   AuthDomain       '.' -> local SAM (passed to Test-AuditCredential)
   RetryDelayMs     inter-attempt delay after a failed password
   DebounceSeconds  suppress a duplicate prompt (Test-AuditDebounce)
   WindowTitle      heading text
   WindowSubtitle   sub-heading text
   AppName          used in diag/window identity
 =======================================================================
#>

[CmdletBinding()]
param(
    # Which event launched us. Logon and Unlock are the only valid values.
    [Parameter(Mandatory = $true)]
    [ValidateSet('Logon', 'Unlock')]
    [string] $EventType,

    # Optional override of the config path (defaults to ..\config\AuditConfig.psd1).
    [string] $ConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# =====================================================================
# Startup step 0: dot-source the shared library via $PSScriptRoot, then
# resolve config. Everything is wrapped so a fatal startup error becomes
# a diag breadcrumb (best-effort) and a clean exit — never a crash to an
# unlocked desktop / visible console.
# =====================================================================
$cfg = $null
try {
    . (Join-Path $PSScriptRoot 'AuditCommon.ps1')
    $cfg = Get-AuditConfig -ConfigPath $ConfigPath
}
catch {
    # We may not have a usable $cfg, so guard the diag call too. If we
    # cannot even load config, there is nothing safe to show; exit quietly
    # (Task Scheduler relaunches on the next logon/unlock).
    try {
        if ($null -ne $cfg) {
            Write-AuditDiag -Config $cfg -Level Error -Message ("Startup failed before window: {0}" -f $_.Exception.Message)
        }
    } catch { }
    return
}

# From here we have a valid $cfg, so we can always Write-AuditDiag safely.
try {

    # =================================================================
    # Startup step 0 (cont.): SHARED-ACCOUNT SELF-CHECK (spec §9.2).
    # This is the backstop that guarantees the prompt NEVER appears on an
    # individual's personal login, even if a scheduled task misfires. If
    # the current user is not the configured SharedAccount, log and EXIT
    # WITH NO WINDOW.
    # =================================================================
    if (-not (Test-AuditIsSharedAccount -Config $cfg)) {
        Write-AuditDiag -Config $cfg -Level Info -Message ("not shared account ({0}); exiting" -f (Get-AuditCurrentUser))
        return
    }

    # =================================================================
    # Startup step 1: DEBOUNCE (spec §9.3). At sign-in the Logon and
    # Unlock triggers can both fire; suppress a duplicate prompt shown
    # within DebounceSeconds. Test-AuditDebounce updates its own marker.
    # =================================================================
    if (Test-AuditDebounce -Config $cfg) {
        Write-AuditDiag -Config $cfg -Level Info -Message ("debounced ({0}); exiting" -f $EventType)
        return
    }

    # =================================================================
    # Startup step 2: resolve ComputerName (never blank) and load roster
    # (central -> cache fallback). A 'none' source still locks the desktop
    # but keeps Confirm disabled with a clear message.
    # =================================================================
    $computerName = Get-AuditComputerName
    $roster       = Get-AuditRosterEntries -Config $cfg
    $rosterSource = $roster.Source
    $entries      = @($roster.Entries)

    Write-AuditDiag -Config $cfg -Level Info -Message (
        "showing prompt: event={0} host={1} rosterSource={2} rosterCount={3}" -f `
            $EventType, $computerName, $rosterSource, $entries.Count)

    # =================================================================
    # Load WPF (.NET Framework 4.x). PresentationFramework/Core +
    # WindowsBase give us Window/PasswordBox/ComboBox; System.Xaml +
    # XamlReader parse the layout string.
    # =================================================================
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Xaml

    # -----------------------------------------------------------------
    # XAML layout (single-quoted here-string — no PS interpolation; all
    # dynamic text is set from code-behind by x:Name). WindowStyle=None,
    # ResizeMode=NoResize, Topmost, ShowInTaskbar=False. Bounds are set in
    # code from the VIRTUAL SCREEN (NOT WindowState=Maximized, which snaps
    # to a single monitor). A centered card holds the controls.
    # -----------------------------------------------------------------
    $xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    WindowStyle="None"
    ResizeMode="NoResize"
    Topmost="True"
    ShowInTaskbar="False"
    WindowStartupLocation="Manual"
    WindowState="Normal"
    Background="#FF101418"
    AllowsTransparency="False">
  <Grid>
    <Border
        HorizontalAlignment="Center"
        VerticalAlignment="Center"
        Background="#FF1B2129"
        BorderBrush="#FF3A4656"
        BorderThickness="1"
        CornerRadius="10"
        Padding="36"
        Width="640">
      <Border.Effect>
        <DropShadowEffect BlurRadius="28" ShadowDepth="0" Opacity="0.55" Color="#FF000000"/>
      </Border.Effect>
      <StackPanel>
        <TextBlock x:Name="TitleText"
                   Text="Workstation Access"
                   Foreground="#FFFFFFFF"
                   FontSize="26"
                   FontWeight="SemiBold"
                   TextWrapping="Wrap"/>
        <TextBlock x:Name="SubtitleText"
                   Text="Select your name and enter your password."
                   Foreground="#FFB7C0CC"
                   FontSize="15"
                   Margin="0,10,0,0"
                   TextWrapping="Wrap"/>
        <Grid Margin="0,22,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Event:" Foreground="#FF8A97A6" FontSize="13" Margin="0,0,10,0"/>
          <TextBlock x:Name="EventText" Grid.Column="1" Text="" Foreground="#FFD7DEE6" FontSize="13"/>
        </Grid>
        <Grid Margin="0,4,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Computer:" Foreground="#FF8A97A6" FontSize="13" Margin="0,0,10,0"/>
          <TextBlock x:Name="ComputerText" Grid.Column="1" Text="" Foreground="#FFD7DEE6" FontSize="13"/>
        </Grid>

        <TextBlock Text="Your name" Foreground="#FFB7C0CC" FontSize="14" Margin="0,24,0,6"/>
        <ComboBox x:Name="NameCombo"
                  IsEditable="True"
                  IsTextSearchEnabled="True"
                  StaysOpenOnEdit="True"
                  FontSize="18"
                  Height="40"/>

        <TextBlock Text="Your password" Foreground="#FFB7C0CC" FontSize="14" Margin="0,18,0,6"/>
        <PasswordBox x:Name="PwBox"
                     IsEnabled="False"
                     FontSize="18"
                     Height="40"
                     Padding="6,8,6,8"/>

        <TextBlock x:Name="StatusText"
                   Text=""
                   Foreground="#FFFF8A8A"
                   FontSize="14"
                   Margin="0,16,0,0"
                   TextWrapping="Wrap"
                   MinHeight="20"/>

        <Button x:Name="ConfirmButton"
                Content="Confirm"
                IsEnabled="False"
                FontSize="17"
                Height="44"
                Margin="0,18,0,0"
                Background="#FF2D6CDF"
                Foreground="#FFFFFFFF"
                BorderThickness="0"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
'@

    # Parse the XAML into a live Window object.
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    # -----------------------------------------------------------------
    # Grab named controls.
    # -----------------------------------------------------------------
    $titleText     = $window.FindName('TitleText')
    $subtitleText  = $window.FindName('SubtitleText')
    $eventText     = $window.FindName('EventText')
    $computerText  = $window.FindName('ComputerText')
    $nameCombo     = $window.FindName('NameCombo')
    $pwBox         = $window.FindName('PwBox')
    $statusText    = $window.FindName('StatusText')
    $confirmButton = $window.FindName('ConfirmButton')

    # -----------------------------------------------------------------
    # Static text from config + runtime context.
    # -----------------------------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.WindowTitle))    { $titleText.Text    = [string]$cfg.WindowTitle }
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.WindowSubtitle)) { $subtitleText.Text = [string]$cfg.WindowSubtitle }
    $eventText.Text    = $EventType
    $computerText.Text = $computerName
    $window.Title      = [string]$cfg.AppName

    # -----------------------------------------------------------------
    # Cover ALL monitors via the VIRTUAL SCREEN. We do NOT use
    # WindowState=Maximized (that snaps to one monitor). For non-
    # rectangular multi-monitor layouts the documented alternative is a
    # per-monitor "blocker" window per screen; a single virtual-screen
    # rectangle is sufficient for the common (aligned) layouts.
    # -----------------------------------------------------------------
    $window.Left   = [System.Windows.SystemParameters]::VirtualScreenLeft
    $window.Top    = [System.Windows.SystemParameters]::VirtualScreenTop
    $window.Width  = [System.Windows.SystemParameters]::VirtualScreenWidth
    $window.Height = [System.Windows.SystemParameters]::VirtualScreenHeight

    # =================================================================
    # Script-scoped state shared with the event handlers. We keep the
    # selected entry (LastName/FirstName/Username) and the close gate.
    # =================================================================
    $script:AllowClose        = $false   # Closing handler refuses unless this is $true
    $script:SelectedEntry     = $null    # the currently-valid roster pscustomobject (or $null)
    $script:RosterAvailable   = ($rosterSource -ne 'none' -and $entries.Count -gt 0)
    $script:LastAttemptFailed = $false   # true after a failed auth; clears the status on next keystroke
    $script:NameFilterText    = ''       # current substring filter for the name dropdown
    $script:RetryThrottled    = $false   # true during the post-failure delay; blocks input re-enable

    # Build a fast lookup: Display string -> roster entry. Display values
    # are the ComboBox items; a name is "valid" only on an EXACT match.
    $displayToEntry = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $entries) {
        if (-not $displayToEntry.ContainsKey($e.Display)) {
            $displayToEntry[$e.Display] = $e
        }
    }

    # Populate the ComboBox via an ICollectionView so we can apply a LIVE
    # case-insensitive SUBSTRING filter as the user types (spec §9 type-to-
    # filter). WPF's IsTextSearchEnabled only does PREFIX auto-complete; it
    # does NOT narrow the dropdown, so we filter the view ourselves.
    $displayList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $entries) { $displayList.Add([string]$e.Display) }

    $nameView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($displayList)
    $nameView.Filter = [System.Predicate[object]] {
        param($item)
        $f = [string]$script:NameFilterText
        if ([string]::IsNullOrWhiteSpace($f)) { return $true }
        return (([string]$item).IndexOf($f.Trim(), [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    }
    $nameCombo.ItemsSource = $nameView

    # -----------------------------------------------------------------
    # Roster-unavailable path (spec §9): keep the window locking the
    # desktop but disable Confirm and show a clear message. Already
    # diag-logged inside Get-AuditRosterEntries; add a prompt-level note.
    # -----------------------------------------------------------------
    if (-not $script:RosterAvailable) {
        $statusText.Text       = 'Roster unavailable - contact admin.'
        $nameCombo.IsEnabled   = $false
        $pwBox.IsEnabled       = $false
        $confirmButton.IsEnabled = $false
        Write-AuditDiag -Config $cfg -Level Error -Message 'Prompt shown with no roster; Confirm disabled (desktop still locked).'
    }

    # =================================================================
    # Helper: recompute the valid selection + enabled states.
    #   * A name is valid ONLY on an exact roster Display match (no free
    #     text). Selecting from the dropdown or typing an exact match both
    #     count.
    #   * PasswordBox enabled once a valid name is selected.
    #   * Confirm enabled when a valid name is selected AND the password
    #     is non-empty.
    # =================================================================
    $updateState = {
        if (-not $script:RosterAvailable) { return }

        # The editable ComboBox exposes the typed/selected text via .Text.
        $text  = [string]$nameCombo.Text
        $entry = $null
        if (-not [string]::IsNullOrWhiteSpace($text) -and $displayToEntry.ContainsKey($text.Trim())) {
            $entry = $displayToEntry[$text.Trim()]
        }
        $script:SelectedEntry = $entry

        $validName = ($null -ne $entry)

        # Enable the PasswordBox only when a valid name is chosen AND we are not
        # inside the post-failure throttle window. Gating on RetryThrottled is
        # essential: $pwBox.Clear() fires PasswordChanged -> this handler, which
        # would otherwise re-enable input mid-delay and let Enter re-auth early.
        $pwBox.IsEnabled = ($validName -and -not $script:RetryThrottled)

        # Confirm requires a valid name AND a non-empty password (and not throttled).
        # Read the length only — NEVER the plaintext (SecurePassword.Length is safe).
        $pwLen = 0
        try { $pwLen = $pwBox.SecurePassword.Length } catch { $pwLen = 0 }
        $confirmButton.IsEnabled = ($validName -and $pwLen -gt 0 -and -not $script:RetryThrottled)

        # Clear a stale "Incorrect password" message once the user starts
        # typing a new password after a failed attempt.
        if ($script:LastAttemptFailed -and $pwLen -gt 0) {
            $statusText.Text = ''
            $script:LastAttemptFailed = $false
        }
    }

    # =================================================================
    # The authentication flow (Confirm). Defined as a scriptblock reused
    # by the Confirm button and the Enter key.
    # =================================================================
    $doConfirm = {
        # Guard: never authenticate without a valid selection.
        if (-not $confirmButton.IsEnabled) { return }
        $entry = $script:SelectedEntry
        if ($null -eq $entry) { return }

        $username = [string]$entry.Username

        # Disable input during the check so a double-click can't double-fire.
        # Set the throttle flag FIRST so the $pwBox.Clear() on a failure (which
        # synchronously fires PasswordChanged -> $updateState) cannot re-enable
        # inputs before the retry timer elapses.
        $script:RetryThrottled   = $true
        $confirmButton.IsEnabled = $false
        $nameCombo.IsEnabled     = $false
        $pwBox.IsEnabled         = $false
        $statusText.Text         = 'Checking...'

        # Read the SecureString fresh from the PasswordBox. This is the ONLY
        # credential object we hold; it is passed straight into
        # Test-AuditCredential (the sole place it becomes plaintext) and is
        # Disposed in finally. We never copy it to a string.
        $secure = $pwBox.SecurePassword
        $ok = $false
        try {
            $ok = Test-AuditCredential -Username $username -Password $secure -Domain ([string]$cfg.AuthDomain)
        }
        catch {
            # A failure to even run the check is NOT a valid auth; degrade
            # safely by treating it as a failed attempt (stay locked).
            $ok = $false
            Write-AuditDiag -Config $cfg -Level Error -Message ("Credential check error (no password logged): {0}" -f $_.Exception.Message)
        }
        finally {
            # Dispose the SecureString as soon as the check returns. The
            # plaintext was already zeroed inside Test-AuditCredential.
            if ($null -ne $secure) {
                try { $secure.Dispose() } catch { }
            }
            $secure = $null
        }

        if ($ok) {
            # ---- SUCCESS: record the verified row, then allow close. ----
            $statusText.Foreground = [System.Windows.Media.Brushes]::LightGreen
            $statusText.Text       = 'Verified. Unlocking...'

            $res = Write-AuditRow -Config $cfg `
                                  -Username $username `
                                  -LastName ([string]$entry.LastName) `
                                  -FirstName ([string]$entry.FirstName) `
                                  -EventType $EventType `
                                  -AuthResult 'Success' `
                                  -ComputerName $computerName

            # Whether written to central or spooled locally, the audit record
            # is captured — release the lock. (No password is in $res.)
            Write-AuditDiag -Config $cfg -Level Info -Message (
                "auth success user={0} event={1} written={2} spooled={3}" -f `
                    $username, $EventType, $res.Written, $res.Spooled)

            $script:AllowClose = $true
            $window.Close()
        }
        else {
            # ---- FAILURE: log the failed attempt, stay locked, retry. ----
            $res = Write-AuditRow -Config $cfg `
                                  -Username $username `
                                  -LastName ([string]$entry.LastName) `
                                  -FirstName ([string]$entry.FirstName) `
                                  -EventType $EventType `
                                  -AuthResult 'Failure' `
                                  -ComputerName $computerName

            Write-AuditDiag -Config $cfg -Level Warn -Message (
                "auth failure user={0} event={1} written={2} spooled={3}" -f `
                    $username, $EventType, $res.Written, $res.Spooled)

            $statusText.Foreground = [System.Windows.Media.Brushes]::Salmon
            $statusText.Text       = 'Incorrect password - try again'

            # Clear the PasswordBox so the next attempt starts fresh, and flag
            # the failure so the message clears when the user types again.
            $pwBox.Clear()
            $script:LastAttemptFailed = $true

            # Short inter-attempt delay (slows brute force; no attempt cap).
            # Use a one-shot DispatcherTimer so we DO NOT block the UI thread —
            # a blocked dispatcher can't repaint or re-assert Topmost.
            $delayMs = 0
            try { $delayMs = [int]$cfg.RetryDelayMs } catch { $delayMs = 0 }
            if ($delayMs -lt 1) {
                # No throttle configured — clear the flag and re-enable now.
                $script:RetryThrottled = $false
                $nameCombo.IsEnabled = $true
                $pwBox.IsEnabled     = $true
                & $updateState
                try { $pwBox.Focus() } catch { }
            } else {
                # Inputs stay disabled (RetryThrottled stays $true) until the
                # timer Tick clears the flag and re-enables them.
                $retryTimer.Interval = [System.TimeSpan]::FromMilliseconds($delayMs)
                $retryTimer.Start()
            }
        }
    }

    # =================================================================
    # Wire up control events.
    # =================================================================
    # ComboBox text/selection changes -> recompute valid selection + states.
    $nameCombo.Add_SelectionChanged({ & $updateState })

    # Editable-ComboBox text edits (typing, paste, IME composition) bubble the
    # inner edit TextBox's TextChanged as a routed event. Hooking that is more
    # reliable than KeyUp (which misses paste / mouse-driven edits). On each
    # edit we update the substring filter, refresh the view, open the dropdown
    # while the text is a partial match, and recompute the enabled-state.
    $onNameTextChanged = {
        param($s, $e)
        $script:NameFilterText = [string]$nameCombo.Text
        try { $nameView.Refresh() } catch { }
        $trimmed = $script:NameFilterText.Trim()
        $isExact = (-not [string]::IsNullOrEmpty($trimmed)) -and $displayToEntry.ContainsKey($trimmed)
        if ((-not [string]::IsNullOrEmpty($trimmed)) -and (-not $isExact)) {
            # Show the filtered matches. StaysOpenOnEdit=True keeps the caret
            # in the edit box, so opening the dropdown does not steal focus.
            if (-not $nameCombo.IsDropDownOpen) { $nameCombo.IsDropDownOpen = $true }
        }
        & $updateState
    }
    $nameCombo.AddHandler(
        [System.Windows.Controls.Primitives.TextBoxBase]::TextChangedEvent,
        [System.Windows.RoutedEventHandler]$onNameTextChanged)

    # Password changes -> recompute Confirm-enabled (length only, no plaintext).
    $pwBox.Add_PasswordChanged({ & $updateState })

    # One-shot throttle timer for failed attempts. We re-enable inputs from its
    # Tick instead of blocking the dispatcher with Start-Sleep — a blocked
    # dispatcher can't repaint OR re-assert Topmost during the delay. Defined
    # at this scope so it captures the controls like the other handlers do.
    $retryTimer = New-Object System.Windows.Threading.DispatcherTimer
    $retryTimer.Add_Tick({
        $retryTimer.Stop()
        $script:RetryThrottled = $false
        $nameCombo.IsEnabled = $true
        $pwBox.IsEnabled     = $true
        & $updateState
        try { $pwBox.Focus() } catch { }
    })

    # Confirm button.
    $confirmButton.Add_Click({ & $doConfirm })

    # =================================================================
    # LOCKDOWN HANDLERS (spec §9).
    # =================================================================
    # Closing: refuse unless we explicitly allowed it (successful auth).
    $window.Add_Closing({
        param($s, $e)
        if (-not $script:AllowClose) {
            $e.Cancel = $true
        }
    })

    # KeyDown: swallow Esc and Alt+F4; Enter triggers Confirm only when
    # the button is enabled. We use PreviewKeyDown so the keys are caught
    # before any control acts on them.
    $window.Add_PreviewKeyDown({
        param($s, $e)
        $key = $e.Key
        # System key (Alt held) shows up as Key.System with SystemKey set.
        $sysKey = $e.SystemKey

        if ($key -eq [System.Windows.Input.Key]::Escape) {
            # Swallow Escape — cannot dismiss the lock.
            $e.Handled = $true
            return
        }

        # Alt+F4 -> Key=System, SystemKey=F4. Swallow it.
        if ($key -eq [System.Windows.Input.Key]::System -and $sysKey -eq [System.Windows.Input.Key]::F4) {
            $e.Handled = $true
            return
        }

        # Enter -> trigger Confirm, but ONLY when Confirm is enabled.
        if ($key -eq [System.Windows.Input.Key]::Enter -or $key -eq [System.Windows.Input.Key]::Return) {
            if ($confirmButton.IsEnabled) {
                $e.Handled = $true
                & $doConfirm
            }
            # If not enabled, let Enter behave normally (e.g. accept the
            # ComboBox dropdown selection).
            return
        }
    })

    # Deactivated: re-assert topmost so nothing can sit on top of us.
    $window.Add_Deactivated({
        param($s, $e)
        try {
            $window.Topmost = $false
            $window.Topmost = $true
            [void]$window.Activate()
        } catch { }
    })

    # Loaded: activate and focus the ComboBox (or surface roster-unavailable
    # focus to nothing actionable).
    $window.Add_Loaded({
        param($s, $e)
        try { [void]$window.Activate() } catch { }
        try {
            if ($script:RosterAvailable) {
                [void]$nameCombo.Focus()
            }
        } catch { }
        # Initial enabled-state pass.
        & $updateState
    })

    # =================================================================
    # Show the window MODALLY. ShowDialog() blocks until AllowClose lets
    # Closing through. Any exception here must NOT crash to an unlocked
    # desktop — it is caught by the outer try/catch which logs and exits.
    # =================================================================
    [void]$window.ShowDialog()

    Write-AuditDiag -Config $cfg -Level Info -Message ("prompt closed cleanly (event={0})" -f $EventType)
}
catch {
    # =================================================================
    # Last-resort safety net: anything unhandled inside the prompt logic
    # lands here. We log a diag breadcrumb (no password — none is in scope
    # at this point) and exit cleanly. We DELIBERATELY do not rethrow:
    # surfacing an error to the hidden console would just leave the desktop
    # unlocked with no record, which is worse than failing closed-but-quiet.
    # =================================================================
    try {
        Write-AuditDiag -Config $cfg -Level Error -Message ("Unhandled prompt error (no password logged): {0}" -f $_.Exception.Message)
    } catch { }
    return
}
