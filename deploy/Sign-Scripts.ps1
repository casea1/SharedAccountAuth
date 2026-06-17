<#
=======================================================================
 Sign-Scripts.ps1 — Authenticode signing helper for the Sign-On Audit
 Logger (spec section 14).

 Windows PowerShell 5.1 / .NET Framework 4.x ONLY. No external modules
 (only the built-in PKI module supplies Set-AuthenticodeSignature).
 Fully OFFLINE: this box is air-gapped, so we sign WITHOUT a timestamp
 (no internet Time-Stamping Authority is reachable).

 What it does:
   * Resolves a CodeSigning certificate: the explicit -Thumbprint if
     supplied, otherwise it AUTO-PICKS the first CodeSigning certificate
     found in Cert:\CurrentUser\My, then (if none) Cert:\LocalMachine\My.
   * Runs Set-AuthenticodeSignature over every *.ps1 and *.psd1 under the
     repository root (recursive). The signing posture for the project is
     AllSigned, so all PowerShell scripts AND the .psd1 data file must be
     signed for them to load/run under AllSigned.
   * Prints a summary table (file, status, timestamped?, message) of what
     was signed.

 What it deliberately does NOT do:
   * It does NOT timestamp the signatures. Timestamping requires reaching
     an internet TSA (e.g. http://timestamp.digicert.com), which an
     air-gapped machine cannot do, so no -TimestampServer is ever passed.
     CONSEQUENCE (documented, by design): an un-timestamped Authenticode
     signature is only valid while the signing certificate is within its
     validity window. Once the cert EXPIRES, every signature produced here
     STOPS validating and the scripts will fail to run under AllSigned
     until they are re-signed with a still-valid certificate. Re-run this
     script before cert expiry (or re-sign with a new cert).
   * It does NOT sign src\Launch-SharedAccountAuth.vbs. Authenticode signing of
     a .vbs is a separate mechanism, and the VBS is launched by wscript,
     which does NOT enforce the AllSigned execution policy (that policy
     only gates PowerShell). The VBS is instead governed by AppLocker
     (see README / spec sections 10 & 16.6). Signing it here is moot.

 ---------------------------------------------------------------------
 Config block (mirrors config\AuditConfig.psd1 — the single source of
 truth for the project). This helper does not need the runtime paths,
 but it loads the config when present so it shares the project's diag
 log for an audit trail of signing runs. Keys (filled by Get-AuditConfig):
 ---------------------------------------------------------------------
   LogPath          \\server\share\audit\access_log.csv  (append-only)
   RosterPath       \\server\share\audit\roster.csv      (read-only)
   LocalRoot        C:\ProgramData\SharedAccountAuth
   RosterCachePath  '' -> $LocalRoot\cache\roster.csv
   SpoolDir         '' -> $LocalRoot\spool
   DiagLogPath      '' -> $LocalRoot\diag\audit-diag.log
   StateDir         '' -> $LocalRoot\state
   DebounceSeconds  / WriteRetryCount / WriteRetryBaseMs
   SharedAccount    '.\LabShared'
   AppName / WindowTitle / WindowSubtitle  (UI text)

 NOTE: this is a build-time DEVELOPER/ADMIN tool, not the runtime prompt.
 It is run once on the (offline) build/admin box that holds the signing
 certificate. It does not touch the central CSV and reads nothing over
 the network.
=======================================================================
#>

[CmdletBinding()]
param(
    # Thumbprint of the CodeSigning certificate to use. OPTIONAL: if
    # omitted, the first CodeSigning cert in CurrentUser\My, then
    # LocalMachine\My, is auto-selected (spec section 14).
    [Parameter(Mandatory = $false)]
    [string] $Thumbprint,

    # Repository root to sign under. Defaults to the parent of this
    # deploy\ folder (i.e. the repo root), resolved from $PSScriptRoot.
    [Parameter(Mandatory = $false)]
    [string] $RepoRoot
)

# Strict mode + stop-on-error: this is a build tool, so we want loud,
# early failures rather than a half-signed tree. (PS 5.1 compatible.)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


function Test-AuditCodeSigningEku {
<#
.SYNOPSIS
    Returns $true if the certificate carries the Code Signing EKU.
.DESCRIPTION
    Checks EnhancedKeyUsageList for the Code Signing OID (1.3.6.1.5.5.7.3.3).
    A cert with NO EKU extension at all is technically valid for any
    purpose, but for this helper we require an explicit Code Signing EKU
    so we never sign with, say, a TLS-only certificate by accident.
.PARAMETER Certificate
    The X509Certificate2 to test.
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    try {
        $ekus = $Certificate.EnhancedKeyUsageList
    } catch {
        # Some certs throw when the EKU list is parsed; treat as "no EKU".
        return $false
    }
    if ($null -eq $ekus) { return $false }

    foreach ($eku in $ekus) {
        if ($null -ne $eku -and $eku.ObjectId -eq $codeSigningOid) {
            return $true
        }
    }
    return $false
}


function Test-AuditCertValidityWindow {
<#
.SYNOPSIS
    Returns $true if "now" is within the certificate's NotBefore..NotAfter.
.DESCRIPTION
    An un-timestamped Authenticode signature is only trusted while the cert
    is valid, so signing with an already-expired (or not-yet-valid) cert
    would produce a signature that never validates. We screen those out so
    auto-pick never hands back a cert that is dead on arrival.
.PARAMETER Certificate
    The X509Certificate2 to test.
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $now = [DateTime]::Now
    return ($now -ge $Certificate.NotBefore -and $now -le $Certificate.NotAfter)
}


function Test-AuditCertHasPrivateKey {
<#
.SYNOPSIS
    Returns $true if the certificate has an associated private key.
.DESCRIPTION
    Set-AuthenticodeSignature needs the private key to sign. A cert with
    only the public key (e.g. imported without the .pfx key material) cannot
    sign, so auto-pick must skip it rather than fail mid-run.
.PARAMETER Certificate
    The X509Certificate2 to test.
.OUTPUTS
    [bool]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    try {
        return [bool] $Certificate.HasPrivateKey
    } catch {
        return $false
    }
}


function Assert-AuditCertUsable {
<#
.SYNOPSIS
    Throws a clear error if the supplied cert cannot produce a usable
    Authenticode signature.
.DESCRIPTION
    Used for the explicit -Thumbprint path, where we want a loud, specific
    failure rather than silently skipping the cert. Verifies: has a private
    key, carries the Code Signing EKU, and is inside its validity window.
.PARAMETER Certificate
    The X509Certificate2 to validate.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    if (-not (Test-AuditCertHasPrivateKey -Certificate $Certificate)) {
        throw "Certificate $($Certificate.Thumbprint) has no associated private key; cannot sign with it."
    }
    if (-not (Test-AuditCodeSigningEku -Certificate $Certificate)) {
        throw "Certificate $($Certificate.Thumbprint) does not have the Code Signing EKU (1.3.6.1.5.5.7.3.3); refusing to use it."
    }
    if (-not (Test-AuditCertValidityWindow -Certificate $Certificate)) {
        throw "Certificate $($Certificate.Thumbprint) is outside its validity window (NotBefore=$($Certificate.NotBefore), NotAfter=$($Certificate.NotAfter)); an un-timestamped signature from it would never validate."
    }
}


function Get-AuditSigningCert {
<#
.SYNOPSIS
    Resolves the Authenticode CodeSigning certificate to sign with.
.DESCRIPTION
    If -Thumbprint is supplied, looks that certificate up in
    Cert:\CurrentUser\My and then Cert:\LocalMachine\My and validates it
    is usable for code signing (private key + Code Signing EKU + in
    validity window) via Assert-AuditCertUsable.

    If -Thumbprint is blank, AUTO-PICKS the FIRST certificate that
      (a) has the Code Signing EKU, (b) has a private key, and
      (c) is inside its validity window,
    scanning Cert:\CurrentUser\My first and then Cert:\LocalMachine\My
    (spec section 14: "first CodeSigning cert").

    Auto-pick prefers CurrentUser\My over LocalMachine\My because a
    developer's personal signing cert normally lives in the user store;
    the machine store is the fallback. The private-key and validity-window
    filters ensure we never auto-select a cert that cannot sign or that
    would emit a signature that is already invalid (no timestamp => the
    signature dies with the cert).
.PARAMETER Thumbprint
    Optional exact thumbprint (case-insensitive, spaces ignored).
.OUTPUTS
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
.NOTES
    No network use. Reads only the local certificate stores. Throws a
    clear error if no usable certificate is found.
#>
    [CmdletBinding()]
    param(
        [string] $Thumbprint
    )

    # The two stores we will consult, in priority order.
    $storePaths = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')

    # --- Explicit thumbprint path -------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        # Normalise: drop spaces, upper-case, so pasted "AA BB CC" matches.
        $wanted = ($Thumbprint -replace '\s', '').ToUpperInvariant()

        foreach ($store in $storePaths) {
            if (-not (Test-Path -LiteralPath $store)) { continue }
            $match = Get-ChildItem -LiteralPath $store |
                     Where-Object { $_.Thumbprint -eq $wanted } |
                     Select-Object -First 1
            if ($null -ne $match) {
                # Loud failure if the named cert is unusable.
                Assert-AuditCertUsable -Certificate $match
                return $match
            }
        }
        throw "No certificate with thumbprint '$wanted' found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
    }

    # --- Auto-pick path: first usable CodeSigning cert -----------------
    # The Code Signing EKU OID is 1.3.6.1.5.5.7.3.3. We test for it via
    # EnhancedKeyUsageList (PKI-populated) so we do not depend on the
    # CodeSigningCert dynamic parameter being available in every host.
    foreach ($store in $storePaths) {
        if (-not (Test-Path -LiteralPath $store)) { continue }

        $candidate = Get-ChildItem -LiteralPath $store |
                     Where-Object { Test-AuditCodeSigningEku       -Certificate $_ } |
                     Where-Object { Test-AuditCertHasPrivateKey    -Certificate $_ } |
                     Where-Object { Test-AuditCertValidityWindow   -Certificate $_ } |
                     Select-Object -First 1

        if ($null -ne $candidate) {
            return $candidate
        }
    }

    throw "No usable (private key + Code Signing EKU + in-validity) certificate found in Cert:\CurrentUser\My or Cert:\LocalMachine\My. Supply one with -Thumbprint, or install/import a code-signing certificate."
}


function Get-AuditRepoRoot {
<#
.SYNOPSIS
    Resolves the repository root to scan for files to sign.
.DESCRIPTION
    If -RepoRoot is supplied and exists, it is used. Otherwise the root is
    the parent of this script's deploy\ folder (this file lives at
    <repo>\deploy\Sign-Scripts.ps1, so the repo root is one level up).
.PARAMETER RepoRoot
    Optional explicit root.
.OUTPUTS
    [string] absolute path to the repository root.
#>
    [CmdletBinding()]
    param(
        [string] $RepoRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($RepoRoot)) {
        if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
            throw "RepoRoot '$RepoRoot' does not exist or is not a directory."
        }
        return (Resolve-Path -LiteralPath $RepoRoot).ProviderPath
    }

    # $PSScriptRoot is <repo>\deploy ; the repo root is its parent.
    $root = Split-Path -Parent $PSScriptRoot
    return (Resolve-Path -LiteralPath $root).ProviderPath
}


function Get-AuditSignableFile {
<#
.SYNOPSIS
    Returns the list of files to sign under the repo root.
.DESCRIPTION
    All *.ps1 and *.psd1 files, recursive. The .vbs is intentionally
    EXCLUDED (see the file header: wscript does not enforce AllSigned;
    AppLocker governs the VBS), as are .xml/.md/.csv etc.

    IMPORTANT (PS 5.1 gotcha): we do NOT use Get-ChildItem -Include here.
    With -LiteralPath (a non-wildcard path), -Include is SILENTLY IGNORED
    even when -Recurse is present, so it would return EVERY file — and we
    must never hand the .vbs/.xml/.md to Set-AuthenticodeSignature. Instead
    we enumerate all files and filter on the extension explicitly, which is
    predictable and host-independent.
.PARAMETER RepoRoot
    The directory to scan.
.OUTPUTS
    [System.IO.FileInfo[]] (may be empty).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepoRoot
    )

    # Extension match is case-insensitive (PowerShell -eq is case-insensitive
    # for strings by default), so Foo.PS1 and bar.psd1 are both caught.
    Get-ChildItem -LiteralPath $RepoRoot -Recurse -File |
        Where-Object { $_.Extension -eq '.ps1' -or $_.Extension -eq '.psd1' } |
        Sort-Object -Property FullName
}


function Write-AuditSigningDiag {
<#
.SYNOPSIS
    Best-effort: append a line about this signing run to the project diag
    log, if the config (and thus the diag path) is resolvable.
.DESCRIPTION
    The audit logger keeps a local diag log at
    C:\ProgramData\SharedAccountAuth\diag\audit-diag.log. Recording signing runs
    there gives an admin one place to see "these scripts were (re)signed on
    <date> with cert <thumbprint>". NEVER throws — diagnostics must not
    break a build step. Does NOT touch the central CSV. Never logs any
    secret (there are none in this tool).
.PARAMETER Message
    The text to log.
.PARAMETER Level
    Info | Warn | Error. Defaults to Info.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,

        [ValidateSet('Info', 'Warn', 'Error')]
        [string] $Level = 'Info'
    )

    try {
        # Resolve the repo root and the project config relative to here.
        $repoRoot   = Split-Path -Parent $PSScriptRoot
        $configPath = Join-Path $repoRoot 'config\AuditConfig.psd1'
        if (-not (Test-Path -LiteralPath $configPath)) { return }

        # Derive the diag path the same way Get-AuditConfig would. We avoid
        # dot-sourcing AuditCommon.ps1 here so this build tool stays usable
        # even if the runtime library is mid-edit.
        $cfg = Import-PowerShellDataFile -LiteralPath $configPath
        $localRoot = $cfg.LocalRoot
        if ([string]::IsNullOrWhiteSpace($localRoot)) { $localRoot = 'C:\ProgramData\SharedAccountAuth' }

        $diagPath = $cfg.DiagLogPath
        if ([string]::IsNullOrWhiteSpace($diagPath)) {
            $diagPath = Join-Path $localRoot 'diag\audit-diag.log'
        }

        $diagDir = Split-Path -Parent $diagPath
        if (-not (Test-Path -LiteralPath $diagDir)) {
            New-Item -ItemType Directory -Path $diagDir -Force | Out-Null
        }

        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line  = "$stamp [$($Level.ToUpperInvariant())] [$PID] $Message"
        # Write BOM-less UTF-8 to match the runtime diag writer (Write-AuditDiag
        # in AuditCommon.ps1). Add-Content -Encoding UTF8 would emit a BOM under
        # PS 5.1 and could insert one mid-file if the runtime created the log first.
        [System.IO.File]::AppendAllText(
            $diagPath,
            ($line + "`r`n"),
            (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        # Swallow — diagnostics never throw.
    }
}


# =====================================================================
#  Main
# =====================================================================
try {
    # 1. Resolve the certificate (explicit thumbprint or auto-pick).
    $cert = Get-AuditSigningCert -Thumbprint $Thumbprint

    Write-Host ''
    Write-Host 'Sign-Scripts.ps1 — Authenticode signing (air-gapped, NO timestamp)' -ForegroundColor Cyan
    Write-Host '-----------------------------------------------------------------' -ForegroundColor Cyan
    Write-Host ("Certificate : {0}" -f $cert.Subject)
    Write-Host ("Thumbprint  : {0}" -f $cert.Thumbprint)
    Write-Host ("Valid until : {0}  <-- signatures STOP validating after this (no timestamp)" -f $cert.NotAfter)
    Write-Host ''
    Write-Host 'NOTE: This is an OFFLINE / air-gapped build. Signatures are produced'
    Write-Host '      WITHOUT a timestamp because no internet Time-Stamping Authority'
    Write-Host '      is reachable. Un-timestamped signatures become INVALID once the'
    Write-Host '      certificate above expires. Re-run this script before expiry.'
    Write-Host '      The .vbs launcher is NOT Authenticode-signed here (wscript ignores'
    Write-Host '      AllSigned; AppLocker governs the VBS).'
    Write-Host ''

    # 2. Resolve the repo root and enumerate the files to sign.
    $root  = Get-AuditRepoRoot -RepoRoot $RepoRoot
    $files = @(Get-AuditSignableFile -RepoRoot $root)

    if ($files.Count -eq 0) {
        Write-Warning "No *.ps1 or *.psd1 files found under '$root'. Nothing to sign."
        Write-AuditSigningDiag -Level 'Warn' -Message "Sign-Scripts: no signable files under $root"
        return
    }

    Write-Host ("Found {0} file(s) to sign under: {1}" -f $files.Count, $root)
    Write-Host ''

    # 3. Sign each file (no -TimestampServer: air-gapped). Collect results.
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($file in $files) {
        # Show a path relative to the repo root for a tidy summary table.
        $relative = $file.FullName
        if ($relative.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
        }

        $status    = ''
        $statusMsg = ''
        try {
            # Set-AuthenticodeSignature with HashAlgorithm SHA256. We pass NO
            # -TimestampServer parameter; omitting it means "do not timestamp",
            # which is required on this air-gapped box. The signature is then
            # only valid while $cert is within its validity window.
            $sig = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -HashAlgorithm 'SHA256' -ErrorAction Stop

            $status    = [string] $sig.Status        # e.g. Valid, UnknownError, NotSigned
            $statusMsg = [string] $sig.StatusMessage
        } catch {
            $status    = 'Error'
            $statusMsg = $_.Exception.Message
        }

        $results.Add([pscustomobject]@{
            File          = $relative
            Status        = $status
            Timestamped   = 'No'                # always No on this air-gapped box
            StatusMessage = $statusMsg
        })
    }

    # 4. Print the summary table.
    Write-Host 'Signing summary:' -ForegroundColor Cyan
    $results | Format-Table -AutoSize File, Status, Timestamped, StatusMessage | Out-Host

    # 5. Tally and report; log the run to the diag log.
    $valid  = @($results | Where-Object { $_.Status -eq 'Valid' }).Count
    $failed = $results.Count - $valid

    Write-Host ''
    if ($failed -eq 0) {
        Write-Host ("All {0} file(s) signed with status 'Valid'." -f $results.Count) -ForegroundColor Green
    } else {
        Write-Warning ("{0} of {1} file(s) did NOT reach status 'Valid'. Review the table above." -f $failed, $results.Count)
    }
    Write-Host ''
    Write-Host "Reminder: these signatures are NOT timestamped and will stop validating"
    Write-Host ("          when the certificate expires on {0}. Re-sign before then." -f $cert.NotAfter)

    Write-AuditSigningDiag -Level 'Info' -Message ("Sign-Scripts: signed {0} file(s) ({1} Valid, {2} other) with cert {3}; NO timestamp (air-gapped); cert NotAfter={4}" -f $results.Count, $valid, $failed, $cert.Thumbprint, $cert.NotAfter)

    if ($failed -gt 0) {
        # Surface a terminating error so an automated caller notices, but
        # only after the table has been printed so the operator sees details.
        throw "$failed file(s) failed to sign cleanly. See the summary table above."
    }
} catch {
    Write-AuditSigningDiag -Level 'Error' -Message ("Sign-Scripts FAILED: {0}" -f $_.Exception.Message)
    Write-Error ("Sign-Scripts.ps1 failed: {0}" -f $_.Exception.Message)
    throw
}
