#Requires -Version 7.0
<#
.SYNOPSIS
    ClipboardSync — Bidirectional plain-text clipboard sync across multiple machines
    via a private GitHub Gist.

.DESCRIPTION
    Run the same command on every machine. Each instance simultaneously:
      - Watches the local clipboard for text changes and pushes them to the Gist.
      - Polls the Gist for changes made by other machines and applies them locally.

    Supported content : plain text and file paths (as newline-separated text).
    Ignored content   : images, rich text, HTML — silently skipped.

    Conflict resolution : last write wins.
    Multi-machine       : unlimited. Each machine ignores its own pushes.

.PARAMETER GistId
    The 32-character ID of your private GitHub Gist.

.PARAMETER Token
    GitHub Personal Access Token with the gist scope only.
    Best practice: store in $env:GITHUB_TOKEN.

.PARAMETER FileName
    Filename used inside the Gist. Default: clipboard.json
    Must be the same on all machines.

.PARAMETER PollMin
    Minimum Gist poll interval in seconds. Default: 15

.PARAMETER PollMax
    Maximum Gist poll interval in seconds. Default: 30
    The actual interval is randomised between PollMin and PollMax each cycle.

.PARAMETER Passphrase
    Enables AES-256-CBC encryption. All machines must share the same passphrase.
    Best practice: store in $env:CLIPBOARD_PASSPHRASE.

.EXAMPLE
    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN

    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
        -Passphrase $env:CLIPBOARD_PASSPHRASE

    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
        -PollMin 10 -PollMax 20
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]  [string]$GistId,
    [Parameter(Mandatory = $true)]  [string]$Token,
    [string]$FileName   = "clipboard.json",
    [int]   $PollMin    = 15,
    [int]   $PollMax    = 30,
    [string]$Passphrase = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
#  LOGGING  (main thread)
# =============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO", [string]$Tag = "   ")
    $color = switch ($Level) {
        "OK"    { "Green"  }
        "WARN"  { "Yellow" }
        "ERROR" { "Red"    }
        default { "Cyan"   }
    }
    Write-Host "[$( Get-Date -Format 'yyyy-MM-dd HH:mm:ss')][$Level][$Tag] $Message" -ForegroundColor $color
}

# =============================================================================
#  CREDENTIAL / SECRET DETECTION
# =============================================================================

$script:SecretPatterns = @(
    'ghp_[0-9A-Za-z]{36}',
    'gho_[0-9A-Za-z]{36}',
    'ghs_[0-9A-Za-z]{36}',
    'ghr_[0-9A-Za-z]{36}',
    'github_pat_[0-9A-Za-z_]{82}',
    '(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)\s*[:=]\s*[''"]?[0-9A-Za-z\-_]{16,}',
    'AKIA[0-9A-Z]{16}',
    '(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[0-9A-Za-z/+]{40}',
    '-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
    '(?i)(password|passwd|pwd)\s*[:=]\s*[^\s;,''\"]{8,}',
    'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
)

function Test-ContainsSecret {
    param([string]$Text)
    foreach ($p in $script:SecretPatterns) {
        if ($Text -match $p) { return $true }
    }
    return $false
}

# =============================================================================
#  AES-256-CBC ENCRYPTION
# =============================================================================
#
#  Gist envelope (always JSON):
#    { "encrypted": true|false, "payload": "<string>" }
#
#  When encrypted=true, payload is:
#    { "salt": "<base64>", "iv": "<base64>", "cipher": "<base64>" }
#
#  Key derivation : PBKDF2-SHA256, 200 000 iterations, 32-byte key.
#  Fresh random salt + IV generated on every write.

function Invoke-DeriveKey {
    param([string]$Pass, [byte[]]$Salt)
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
               [System.Text.Encoding]::UTF8.GetBytes($Pass),
               $Salt, 200000,
               [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    return $kdf.GetBytes(32)
}

function Protect-Payload {
    param([string]$Plaintext)
    if ([string]::IsNullOrEmpty($Passphrase)) { return $Plaintext }

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7

        $salt = [byte[]]::new(16)
        $iv   = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)

        $aes.Key = Invoke-DeriveKey -Pass $Passphrase -Salt $salt
        $aes.IV  = $iv

        $enc = $aes.CreateEncryptor()
        try {
            $plain  = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
            $cipher = $enc.TransformFinalBlock($plain, 0, $plain.Length)
        }
        finally { $enc.Dispose() }

        return @{
            salt   = [Convert]::ToBase64String($salt)
            iv     = [Convert]::ToBase64String($iv)
            cipher = [Convert]::ToBase64String($cipher)
        } | ConvertTo-Json -Compress
    }
    finally { $aes.Dispose() }
}

function Unprotect-Payload {
    param([string]$EncJson)
    if ([string]::IsNullOrEmpty($Passphrase)) { return $EncJson }

    try   { $e = $EncJson | ConvertFrom-Json }
    catch { return $EncJson }

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = Invoke-DeriveKey -Pass $Passphrase -Salt ([Convert]::FromBase64String($e.salt))
        $aes.IV        = [Convert]::FromBase64String($e.iv)

        $dec = $aes.CreateDecryptor()
        try {
            $cipher = [Convert]::FromBase64String($e.cipher)
            $plain  = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
        }
        finally { $dec.Dispose() }

        return [System.Text.Encoding]::UTF8.GetString($plain)
    }
    finally { $aes.Dispose() }
}

# =============================================================================
#  GITHUB GIST REST API
# =============================================================================

$script:GistUri = "https://api.github.com/gists/$GistId"
$script:Headers = @{
    "Authorization"        = "Bearer $Token"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "ClipboardSync-PowerShell/3.0"
}

function Push-Gist {
    param([string]$JsonContent)
    $body = @{ files = @{ $FileName = @{ content = $JsonContent } } } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri $script:GistUri -Method Patch `
        -Headers $script:Headers -Body $body -ContentType "application/json" | Out-Null
}

function Get-Gist {
    $r = Invoke-RestMethod -Uri $script:GistUri -Method Get -Headers $script:Headers
    if (-not $r.files.$FileName) { return $null }
    return @{ Content = $r.files.$FileName.content; UpdatedAt = $r.updated_at }
}

# =============================================================================
#  CLIPBOARD  (plain text only)
# =============================================================================

function Get-ClipboardText {
    # Returns the plain-text content of the clipboard, or $null if there is
    # nothing text-like (images, rich text and empty clipboard return $null).
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue

    # Skip non-text formats entirely
    if ([System.Windows.Forms.Clipboard]::ContainsImage()) { return $null }

    # File drop list → newline-separated paths
    if ([System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
        $files = [System.Windows.Forms.Clipboard]::GetFileDropList()
        if ($files.Count -gt 0) { return ($files | ForEach-Object { $_ }) -join "`n" }
        return $null
    }

    # Rich text present: read the plain-text slot only (ignore CF_HTML / CF_RTF)
    if ([System.Windows.Forms.Clipboard]::ContainsText()) {
        $text = [System.Windows.Forms.Clipboard]::GetText(
            [System.Windows.Forms.TextDataFormat]::UnicodeText)
        if (-not [string]::IsNullOrWhiteSpace($text)) { return $text }
    }

    return $null
}

function Get-TextHash {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "empty" }
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try   { return [Convert]::ToBase64String($sha256.ComputeHash($bytes)) }
    finally { $sha256.Dispose() }
}

# =============================================================================
#  SHARED STATE
#
#  A synchronized hashtable accessed by both the main (outbound) thread and
#  the inbound runspace. Keys:
#
#  LastPushedHash  — hash of the text both sides already agree is in sync:
#                   set by the outbound loop after IT pushes, and by the
#                   inbound loop after it applies a peer payload. Either loop
#                   sees this hash on the clipboard and treats it as already
#                   synced instead of re-pushing/re-applying it.
#
#  IgnoreUntil     — [datetime] until which the outbound loop suppresses pushes.
#                   Set by the inbound loop after applying a peer payload, to
#                   prevent the received text from being immediately re-pushed.
#
#  LastRemoteStamp — updated_at of the last Gist version the inbound loop acted
#                   on. Only the inbound loop writes this.
#
#  LogQueue        — ConcurrentQueue used by the inbound runspace to pass log
#                   messages to the main thread for printing (Write-Host does
#                   not reach the parent console from inside a runspace).
# =============================================================================

$shared = [hashtable]::Synchronized(@{
    LastPushedHash  = ""
    IgnoreUntil     = [datetime]::MinValue
    LastRemoteStamp = ""
    LogQueue        = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
})

# =============================================================================
#  STARTUP VALIDATION
# =============================================================================

if ($GistId -notmatch '^[0-9a-f]{20,40}$') {
    Write-Log "GistId does not look like a valid Gist ID (expected 20-40 hex chars)." "ERROR" "SYS"
    exit 1
}

if ($Token -notmatch '^(gh[psohr]_|github_pat_)') {
    Write-Log "Token does not look like a GitHub PAT (expected ghp_, gho_, ghs_, ghr_, or github_pat_)." "WARN" "SYS"
}

if ($PollMin -le 0 -or $PollMax -lt $PollMin) {
    Write-Log "Invalid poll interval: PollMin ($PollMin) must be > 0 and PollMax ($PollMax) must be >= PollMin." "ERROR" "SYS"
    exit 1
}

if ($Passphrase) {
    Write-Log "Encryption: AES-256-CBC, PBKDF2-SHA256 (200 000 iterations)." "INFO" "SYS"
}

Write-Log "Verifying Gist access..." "INFO" "SYS"
try {
    $probe = Get-Gist
    $shared.LastRemoteStamp = if ($probe) { $probe.UpdatedAt } else { "" }
    Write-Log "Gist access confirmed. Host: $($env:COMPUTERNAME)" "OK" "SYS"
}
catch {
    Write-Log "Could not reach the Gist. Check GistId and Token. Error: $_" "ERROR" "SYS"
    exit 1
}

Write-Log "ClipboardSync started. Press Ctrl+C to stop." "OK" "SYS"
Write-Log ("Host: {0}  |  Gist: {1}  |  Poll: {2}-{3}s  |  Enc: {4}" -f
    $env:COMPUTERNAME, $GistId, $PollMin, $PollMax,
    $(if ($Passphrase) { "ON" } else { "OFF" })) "INFO" "SYS"

# =============================================================================
#  INBOUND SCRIPT BLOCK  (Gist → clipboard)
#
#  Runs inside a dedicated PowerShell runspace. All functions it needs are
#  defined inline — runspaces start with a blank session state.
#  All communication with the outbound loop is via $shared.
# =============================================================================

$inboundScript = {
    param(
        [hashtable]$shared,
        [string]$GistId,
        [string]$Token,
        [string]$FileName,
        [int]$PollMin,
        [int]$PollMax,
        [string]$Passphrase
    )

    # ── logging (via queue — Write-Host doesn't reach parent console) ─────────
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $shared.LogQueue.Enqueue([pscustomobject]@{
            Ts      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Level   = $Level
            Message = $Message
        })
    }

    # ── crypto ────────────────────────────────────────────────────────────────
    function Invoke-DeriveKey {
        param([string]$Pass, [byte[]]$Salt)
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                   [System.Text.Encoding]::UTF8.GetBytes($Pass),
                   $Salt, 200000,
                   [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        return $kdf.GetBytes(32)
    }

    function Unprotect-Payload {
        param([string]$EncJson)
        if ([string]::IsNullOrEmpty($Passphrase)) { return $EncJson }
        try   { $e = $EncJson | ConvertFrom-Json }
        catch { return $EncJson }
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize   = 256
            $aes.BlockSize = 128
            $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key       = Invoke-DeriveKey -Pass $Passphrase -Salt ([Convert]::FromBase64String($e.salt))
            $aes.IV        = [Convert]::FromBase64String($e.iv)
            $dec = $aes.CreateDecryptor()
            try {
                $cipher = [Convert]::FromBase64String($e.cipher)
                $plain  = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
            }
            finally { $dec.Dispose() }
            return [System.Text.Encoding]::UTF8.GetString($plain)
        }
        finally { $aes.Dispose() }
    }

    # ── hash ──────────────────────────────────────────────────────────────────
    function Get-TextHash {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "empty" }
        $bytes  = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try   { return [Convert]::ToBase64String($sha256.ComputeHash($bytes)) }
        finally { $sha256.Dispose() }
    }

    # ── Gist fetch ────────────────────────────────────────────────────────────
    function Get-GistRemote {
        $headers = @{
            "Authorization"        = "Bearer $Token"
            "Accept"               = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "ClipboardSync-PowerShell/3.0"
        }
        $r = Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" `
                -Method Get -Headers $headers
        if (-not $r.files.$FileName) { return $null }
        return @{ Content = $r.files.$FileName.content; UpdatedAt = $r.updated_at }
    }

    # ── inbound loop ──────────────────────────────────────────────────────────
    Write-Log "Inbound loop started — polling every $PollMin-$PollMax s." "OK"
    $rng       = New-Object System.Random
    $firstPoll = $true

    while ($true) {
        try {
            if ($firstPoll) {
                $firstPoll = $false
                Write-Log "Performing initial poll..."
            }
            else {
                $delay = $rng.Next($PollMin, $PollMax + 1)
                Write-Log "Next poll in $delay s..."
                Start-Sleep -Seconds $delay
            }

            $remote = Get-GistRemote

            if ($null -eq $remote -or $remote.Content -eq "{}") { continue }

            if ($remote.UpdatedAt -eq $shared.LastRemoteStamp) {
                Write-Log "No new data from peers."
                continue
            }

            # Parse outer envelope
            $outer = $remote.Content | ConvertFrom-Json

            # Decrypt inner payload if needed
            if ($outer.encrypted) {
                if ([string]::IsNullOrEmpty($Passphrase)) {
                    Write-Log "Payload is encrypted but no -Passphrase supplied — skipping." "WARN"
                    $shared.LastRemoteStamp = $remote.UpdatedAt
                    continue
                }
                try {
                    $innerJson = Unprotect-Payload -EncJson $outer.payload
                }
                catch {
                    Write-Log "Decryption failed — wrong passphrase? Error: $_" "ERROR"
                    $shared.LastRemoteStamp = $remote.UpdatedAt
                    continue
                }
            }
            else {
                $innerJson = $outer.payload
            }

            $parsed = $innerJson | ConvertFrom-Json

            # Skip payloads that originated from this machine
            $incomingHash = Get-TextHash -Text $parsed.data
            if ($parsed.host -eq $env:COMPUTERNAME -or $incomingHash -eq $shared.LastPushedHash) {
                Write-Log "Skipping — payload originated from this machine."
                $shared.LastRemoteStamp = $remote.UpdatedAt
                continue
            }

            # Apply to clipboard
            Write-Log "━━ Data received from computer '$($parsed.host)' — synced at $(Get-Date -Format 'HH:mm:ss')" "OK"
            Set-Clipboard -Value $parsed.data

            # Mark this hash as already in sync so the outbound loop doesn't
            # see the clipboard change and immediately re-push it as its own.
            $shared.LastPushedHash = $incomingHash

            # Tell outbound loop to pause briefly so it doesn't echo this back
            $shared.IgnoreUntil     = [datetime]::UtcNow.AddSeconds(5)
            $shared.LastRemoteStamp = $remote.UpdatedAt
        }
        catch {
            Write-Log "Inbound error: $_" "ERROR"
        }
    }
}

# =============================================================================
#  LAUNCH INBOUND RUNSPACE
# =============================================================================

$rs = [runspacefactory]::CreateRunspace()
$rs.ApartmentState = [System.Threading.ApartmentState]::STA
$rs.ThreadOptions  = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
$rs.Open()

$ps = [powershell]::Create()
$ps.Runspace = $rs
$null = $ps.AddScript($inboundScript).AddArgument($shared).AddArgument($GistId).AddArgument($Token).AddArgument($FileName).AddArgument($PollMin).AddArgument($PollMax).AddArgument($Passphrase)
$asyncHandle = $ps.BeginInvoke()

# =============================================================================
#  OUTBOUND LOOP  (clipboard → Gist)  — main thread
# =============================================================================

# Drain log messages queued by the inbound runspace and print them here on the
# main thread (the only place Write-Host reaches the console).
function Invoke-DrainLogQueue {
    $item = $null
    while ($shared.LogQueue.TryDequeue([ref]$item)) {
        $color = switch ($item.Level) {
            "OK"    { "Green"  }
            "WARN"  { "Yellow" }
            "ERROR" { "Red"    }
            default { "Cyan"   }
        }
        Write-Host "[$($item.Ts)][$($item.Level)][ IN] $($item.Message)" -ForegroundColor $color
    }
}

Write-Log "Outbound loop started — watching clipboard every 500 ms." "OK" "OUT"
$lastLocalHash = ""
$inboundDead   = $false

try {
    while ($true) {
        Start-Sleep -Milliseconds 500
        Invoke-DrainLogQueue

        if (-not $inboundDead -and $ps.InvocationStateInfo.State -in @('Failed', 'Stopped', 'Completed')) {
            $inboundDead = $true
            Write-Log "Inbound loop thread stopped unexpectedly (state: $($ps.InvocationStateInfo.State)). Incoming sync from peers is no longer active; outbound push will keep running." "ERROR" "SYS"
            if ($ps.Streams.Error.Count -gt 0) {
                Write-Log "Last inbound error: $($ps.Streams.Error[-1])" "ERROR" "SYS"
            }
        }

        try {
            # Suppress push briefly after receiving from a peer
            if ([datetime]::UtcNow -lt $shared.IgnoreUntil) { continue }

            $text = Get-ClipboardText

            # Nothing text-like on clipboard (image, rich text, or empty)
            if ($null -eq $text) { continue }

            $hash = Get-TextHash -Text $text
            if ($hash -eq $lastLocalHash) { continue }

            # Content just arrived from a peer (or is what we last pushed) — already in sync, don't re-push it.
            if ($hash -eq $shared.LastPushedHash) {
                $lastLocalHash = $hash
                continue
            }

            # Credential scan before pushing
            if (Test-ContainsSecret -Text $text) {
                Write-Log "BLOCKED: credential pattern detected — not syncing." "WARN" "OUT"
                $lastLocalHash = $hash   # advance so warning isn't repeated every 500 ms
                continue
            }

            Write-Log "Local clipboard changed — pushing to Gist." "INFO" "OUT"

            $inner = @{
                data      = $text
                timestamp = (Get-Date -Format "o")
                host      = $env:COMPUTERNAME
            } | ConvertTo-Json -Compress

            $gistContent = @{
                encrypted = ($Passphrase -ne "")
                payload   = (Protect-Payload -Plaintext $inner)
            } | ConvertTo-Json -Compress

            Push-Gist -JsonContent $gistContent
            Write-Log "Pushed successfully." "OK" "OUT"

            $shared.LastPushedHash = $hash
            $lastLocalHash         = $hash
        }
        catch {
            Write-Log "Outbound error: $_" "ERROR" "OUT"
        }
    }
}
finally {
    Write-Log "Shutting down..." "WARN" "SYS"
    try { $ps.Stop()    } catch { }
    try { $ps.Dispose() } catch { }
    try { $rs.Close()   } catch { }
    try { $rs.Dispose() } catch { }
    Write-Log "ClipboardSync stopped." "WARN" "SYS"
}
