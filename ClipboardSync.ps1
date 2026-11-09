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
    Enables AES-256-GCM encryption. All machines must share the same passphrase.
    With a passphrase set, unencrypted payloads from the Gist are refused.
    Best practice: store in $env:CLIPBOARD_PASSPHRASE.

.EXAMPLE
    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN

    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
        -Passphrase $env:CLIPBOARD_PASSPHRASE

    .\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
        -PollMin 10 -PollMax 20
#>

# The passphrase is meant to come from an environment variable (-Passphrase $env:CLIPBOARD_PASSPHRASE);
# a SecureString parameter would break that.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Passphrase', Justification = 'Passed from an environment variable')]
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

function Write-SyncLog {
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
#  JSON HELPER
# =============================================================================

# Reads one field of an object from ConvertFrom-Json / Invoke-RestMethod, or $null if the object
# isn't one or has no such field. Under Set-StrictMode a missing property would throw instead.
function Get-JsonField {
    param($Object, [string]$Name)
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# =============================================================================
#  AES-256-GCM ENCRYPTION
# =============================================================================
#
#  Gist file, payload format v2 (always JSON):
#    { "v": 2, "encrypted": true|false, "payload": "<string>" }
#
#  payload, unencrypted : { "data": "<base64 of the UTF-8 text>", "timestamp": "<ISO 8601>", "host": "<name>" }
#  payload, encrypted   : { "salt": "<b64, 16 B>", "nonce": "<b64, 12 B>", "tag": "<b64, 16 B>", "cipher": "<b64>" }
#                         where the ciphertext is the unencrypted payload above.
#
#  Key derivation : PBKDF2-SHA256, 200 000 iterations, 32-byte key, fresh random salt per write.
#  Cipher         : AES-256-GCM, fresh random nonce per write, 128-bit tag, associated data
#                   "ClipboardSync/v2". A wrong passphrase or any change to salt, nonce, tag or
#                   ciphertext fails the tag check, so nothing tampered is ever applied.
#  The text is base64 inside the payload so ConvertFrom-Json can't turn date-like text into a
#  [datetime]. Format v1 (AES-CBC, no integrity check) is no longer read.

function Invoke-DeriveKey {
    param([string]$Pass, [byte[]]$Salt)
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
               [System.Text.Encoding]::UTF8.GetBytes($Pass),
               $Salt, 200000,
               [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try     { return , $kdf.GetBytes(32) }
    finally { $kdf.Dispose() }
}

function Get-AesGcm {
    param([byte[]]$Key)
    # .NET 8+ (PowerShell 7.4+) wants the tag size stated; older .NET only has the key-only constructor.
    if ([System.Security.Cryptography.AesGcm].GetConstructor([type[]]@([byte[]], [int]))) {
        return [System.Security.Cryptography.AesGcm]::new($Key, 16)
    }
    return [System.Security.Cryptography.AesGcm]::new($Key)
}

function Protect-Payload {
    param([string]$Plaintext, [string]$Pass)
    $salt  = [byte[]]::new(16)
    $nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

    $plain  = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
    $cipher = [byte[]]::new($plain.Length)
    $tag    = [byte[]]::new(16)
    $aad    = [System.Text.Encoding]::UTF8.GetBytes('ClipboardSync/v2')

    [byte[]]$key = Invoke-DeriveKey -Pass $Pass -Salt $salt
    try {
        $gcm = Get-AesGcm -Key $key
        try     { $gcm.Encrypt($nonce, $plain, $cipher, $tag, $aad) }
        finally { $gcm.Dispose() }
    }
    finally { [Array]::Clear($key, 0, $key.Length) }

    return [ordered]@{
        salt   = [Convert]::ToBase64String($salt)
        nonce  = [Convert]::ToBase64String($nonce)
        tag    = [Convert]::ToBase64String($tag)
        cipher = [Convert]::ToBase64String($cipher)
    } | ConvertTo-Json -Compress
}

# Throws if the JSON is malformed, the passphrase is wrong, or anything was altered.
function Unprotect-Payload {
    param([string]$EncJson, [string]$Pass)
    $e      = $EncJson | ConvertFrom-Json
    $salt   = [Convert]::FromBase64String([string](Get-JsonField $e 'salt'))
    $nonce  = [Convert]::FromBase64String([string](Get-JsonField $e 'nonce'))
    $tag    = [Convert]::FromBase64String([string](Get-JsonField $e 'tag'))
    $cipher = [Convert]::FromBase64String([string](Get-JsonField $e 'cipher'))
    if ($salt.Length -ne 16 -or $nonce.Length -ne 12 -or $tag.Length -ne 16) {
        throw "Malformed encrypted payload (salt, nonce or tag has the wrong length)."
    }
    $plain = [byte[]]::new($cipher.Length)
    $aad   = [System.Text.Encoding]::UTF8.GetBytes('ClipboardSync/v2')

    [byte[]]$key = Invoke-DeriveKey -Pass $Pass -Salt $salt
    try {
        $gcm = Get-AesGcm -Key $key
        try     { $gcm.Decrypt($nonce, $cipher, $tag, $plain, $aad) }
        finally { $gcm.Dispose() }
    }
    finally { [Array]::Clear($key, 0, $key.Length) }

    return [System.Text.Encoding]::UTF8.GetString($plain)
}

# =============================================================================
#  PAYLOAD FORMAT v2  (pure: no I/O)
# =============================================================================

# Builds the Gist file content for one clipboard text. Encrypted whenever a passphrase is given.
function ConvertTo-GistContent {
    param([string]$Text, [string]$HostName, [string]$Pass, [string]$Timestamp = (Get-Date -Format 'o'))
    $inner = [ordered]@{
        data      = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
        timestamp = $Timestamp
        host      = $HostName
    } | ConvertTo-Json -Compress

    $encrypted = -not [string]::IsNullOrEmpty($Pass)
    $payload   = if ($encrypted) { Protect-Payload -Plaintext $inner -Pass $Pass } else { $inner }

    return [ordered]@{ v = 2; encrypted = $encrypted; payload = $payload } | ConvertTo-Json -Compress
}

# Reads a Gist file written by ConvertTo-GistContent. Never throws. Returns
#   @{ Ok = $true;  Text; Host }               when the payload can be applied, or
#   @{ Ok = $false; Level; Message }           when it must be skipped, and why.
# With a passphrase set, only authenticated encrypted payloads are accepted.
function ConvertFrom-GistContent {
    param([string]$Content, [string]$Pass)
    $skip = { param($Level, $Message) @{ Ok = $false; Level = $Level; Message = $Message } }

    try   { $outer = $Content | ConvertFrom-Json }
    catch { return (& $skip 'ERROR' 'The Gist file is not valid JSON - skipping.') }

    $version = Get-JsonField $outer 'v'
    if ($null -eq $version -or "$version" -ne '2') {
        $seen = if ($null -eq $version) { 'v1' } else { "v$version" }
        return (& $skip 'WARN' "Payload is in format $seen, this machine reads v2 - skipping. Run the same ClipboardSync version on every machine.")
    }

    $payload = Get-JsonField $outer 'payload'
    if ($payload -isnot [string]) { return (& $skip 'ERROR' 'Payload is malformed (no payload text) - skipping.') }

    $isEncrypted = (Get-JsonField $outer 'encrypted') -eq $true
    $hasPass     = -not [string]::IsNullOrEmpty($Pass)

    if ($isEncrypted -and -not $hasPass) {
        return (& $skip 'WARN' 'Payload is encrypted but no -Passphrase supplied - skipping.')
    }
    if (-not $isEncrypted -and $hasPass) {
        return (& $skip 'WARN' 'Refusing an unencrypted payload: encryption is on here, so every machine must use the same -Passphrase.')
    }

    if ($isEncrypted) {
        try   { $innerJson = Unprotect-Payload -EncJson $payload -Pass $Pass }
        catch { return (& $skip 'ERROR' "Decryption failed - wrong passphrase, or the payload was altered. Skipping. ($($_.Exception.Message))") }
    }
    else {
        $innerJson = $payload
    }

    try {
        $inner = $innerJson | ConvertFrom-Json
        $data  = Get-JsonField $inner 'data'
        $from  = Get-JsonField $inner 'host'
        if ($data -isnot [string] -or $from -isnot [string]) { throw 'missing data or host' }
        $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($data))
    }
    catch { return (& $skip 'ERROR' 'Payload is malformed - skipping.') }

    if ($text.Length -eq 0) { return (& $skip 'WARN' 'Payload has no text - skipping.') }
    return @{ Ok = $true; Text = $text; Host = $from }
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
#  SYNC DECISIONS  (pure: no I/O; the loops below act on the result)
# =============================================================================

# Outbound: what to do with the text currently on the local clipboard. Returns @{ Action; Hash }:
#   none     nothing text-like, or unchanged since the last check
#   synced   this text is what was last pushed or received: remember it, don't push
#   blocked  matches a credential pattern: remember it (so the warning shows once), don't push
#   push     new local text: push it
function Get-OutboundAction {
    param([string]$Text, [string]$LastLocalHash, [string]$LastPushedHash)
    if ([string]::IsNullOrEmpty($Text)) { return @{ Action = 'none'; Hash = $null } }
    $hash = Get-TextHash -Text $Text
    if ($hash -eq $LastLocalHash)        { return @{ Action = 'none';    Hash = $hash } }
    if ($hash -eq $LastPushedHash)       { return @{ Action = 'synced';  Hash = $hash } }
    if (Test-ContainsSecret -Text $Text) { return @{ Action = 'blocked'; Hash = $hash } }
    return @{ Action = 'push'; Hash = $hash }
}

# Inbound: what to do with what was fetched from the Gist ($Remote = @{ Content; UpdatedAt } or $null).
# Returns @{ Action; Level; Message; MarkSeen; Text; Hash }:
#   Action    none   empty Gist, or nothing new since the last poll
#             skip   a new version this machine won't apply (its own echo, refused, unreadable)
#             apply  put Text on the clipboard
#   MarkSeen  remember this Gist version (UpdatedAt) so it isn't looked at again
function Resolve-InboundUpdate {
    param($Remote, [string]$LastRemoteStamp, [string]$LastPushedHash, [string]$LocalHost, [string]$Pass)
    $result = { param($Action, $Level, $Message, $MarkSeen)
        @{ Action = $Action; Level = $Level; Message = $Message; MarkSeen = $MarkSeen; Text = $null; Hash = $null } }

    if ($null -eq $Remote -or [string]::IsNullOrWhiteSpace($Remote.Content) -or $Remote.Content.Trim() -eq '{}') {
        return (& $result 'none' 'INFO' $null $false)
    }
    if ([string]($Remote.UpdatedAt) -eq $LastRemoteStamp) {
        return (& $result 'none' 'INFO' 'No new data from peers.' $false)
    }

    $read = ConvertFrom-GistContent -Content $Remote.Content -Pass $Pass
    if (-not $read.Ok) { return (& $result 'skip' $read.Level $read.Message $true) }

    $hash = Get-TextHash -Text $read.Text
    if ($read.Host -eq $LocalHost -or $hash -eq $LastPushedHash) {
        return (& $result 'skip' 'INFO' 'Skipping - payload originated from this machine or is already in sync.' $true)
    }

    # The host name comes from the Gist: strip control characters (terminal escapes) before logging it.
    $shownHost = $read.Host -replace '\p{C}', '?'
    if ($shownHost.Length -gt 64) { $shownHost = $shownHost.Substring(0, 64) + '...' }

    $r = & $result 'apply' 'OK' "━━ Data received from computer '$shownHost' — synced at $(Get-Date -Format 'HH:mm:ss')" $true
    $r.Text = $read.Text
    $r.Hash = $hash
    return $r
}

# =============================================================================
#  GITHUB GIST REST API
# =============================================================================

function Get-GistRequestHeader {
    param([string]$Token)
    return @{
        "Authorization"        = "Bearer $Token"
        "Accept"               = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "ClipboardSync-PowerShell/4.0"
    }
}

# Returns @{ Content; UpdatedAt } for the sync file, or $null if the Gist has no such file.
function Get-Gist {
    param([string]$GistId, [hashtable]$Headers, [string]$FileName)
    $r    = Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" -Method Get -Headers $Headers
    $file = Get-JsonField (Get-JsonField $r 'files') $FileName
    if ($null -eq $file) { return $null }
    return @{ Content = [string](Get-JsonField $file 'content'); UpdatedAt = [string](Get-JsonField $r 'updated_at') }
}

function Push-Gist {
    param([string]$GistId, [hashtable]$Headers, [string]$FileName, [string]$JsonContent)
    $body = @{ files = @{ $FileName = @{ content = $JsonContent } } } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri "https://api.github.com/gists/$GistId" -Method Patch `
        -Headers $Headers -Body $body -ContentType "application/json" | Out-Null
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
    Write-SyncLog "GistId does not look like a valid Gist ID (expected 20-40 hex chars)." "ERROR" "SYS"
    exit 1
}

if ($Token -notmatch '^(gh[psohr]_|github_pat_)') {
    Write-SyncLog "Token does not look like a GitHub PAT (expected ghp_, gho_, ghs_, ghr_, or github_pat_)." "WARN" "SYS"
}

if ($PollMin -le 0 -or $PollMax -lt $PollMin) {
    Write-SyncLog "Invalid poll interval: PollMin ($PollMin) must be > 0 and PollMax ($PollMax) must be >= PollMin." "ERROR" "SYS"
    exit 1
}

if ($Passphrase) {
    Write-SyncLog "Encryption: AES-256-GCM, PBKDF2-SHA256 (200 000 iterations). Unencrypted payloads are refused." "INFO" "SYS"
}

$headers = Get-GistRequestHeader -Token $Token

Write-SyncLog "Verifying Gist access..." "INFO" "SYS"
try {
    $probe = Get-Gist -GistId $GistId -Headers $headers -FileName $FileName
    $shared.LastRemoteStamp = if ($probe) { $probe.UpdatedAt } else { "" }
    Write-SyncLog "Gist access confirmed. Host: $($env:COMPUTERNAME)" "OK" "SYS"
}
catch {
    Write-SyncLog "Could not reach the Gist. Check GistId and Token. Error: $_" "ERROR" "SYS"
    exit 1
}

Write-SyncLog "ClipboardSync started. Press Ctrl+C to stop." "OK" "SYS"
Write-SyncLog ("Host: {0}  |  Gist: {1}  |  Poll: {2}-{3}s  |  Enc: {4}" -f
    $env:COMPUTERNAME, $GistId, $PollMin, $PollMax,
    $(if ($Passphrase) { "ON" } else { "OFF" })) "INFO" "SYS"

# =============================================================================
#  INBOUND SCRIPT BLOCK  (Gist → clipboard)
#
#  Runs inside a dedicated PowerShell runspace. Runspaces start with a blank
#  session state, so the functions it needs are copied in from this script
#  (see LAUNCH INBOUND RUNSPACE). All communication with the outbound loop is
#  via $shared.
# =============================================================================

$inboundScript = {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Passphrase', Justification = 'Comes from an environment variable; see the main param block')]
    param(
        [hashtable]$shared,
        [string]$GistId,
        [hashtable]$Headers,
        [string]$FileName,
        [int]$PollMin,
        [int]$PollMax,
        [string]$Passphrase,
        [string]$LocalHost
    )

    # ── logging (via queue — Write-Host doesn't reach parent console) ─────────
    function Write-SyncLog {
        param([string]$Message, [string]$Level = "INFO")
        $shared.LogQueue.Enqueue([pscustomobject]@{
            Ts      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Level   = $Level
            Message = $Message
        })
    }

    # ── inbound loop ──────────────────────────────────────────────────────────
    Write-SyncLog "Inbound loop started — polling every $PollMin-$PollMax s." "OK"
    $rng       = New-Object System.Random
    $firstPoll = $true

    while ($true) {
        try {
            if ($firstPoll) {
                $firstPoll = $false
                Write-SyncLog "Performing initial poll..."
            }
            else {
                $delay = $rng.Next($PollMin, $PollMax + 1)
                Write-SyncLog "Next poll in $delay s..."
                Start-Sleep -Seconds $delay
            }

            $remote = Get-Gist -GistId $GistId -Headers $Headers -FileName $FileName
            $update = Resolve-InboundUpdate -Remote $remote -LastRemoteStamp $shared.LastRemoteStamp `
                          -LastPushedHash $shared.LastPushedHash -LocalHost $LocalHost -Pass $Passphrase

            if ($update.Message) { Write-SyncLog $update.Message $update.Level }

            if ($update.Action -eq 'apply') {
                Set-Clipboard -Value $update.Text

                # Mark this hash as already in sync so the outbound loop doesn't
                # see the clipboard change and immediately re-push it as its own.
                $shared.LastPushedHash = $update.Hash

                # Tell outbound loop to pause briefly so it doesn't echo this back
                $shared.IgnoreUntil = [datetime]::UtcNow.AddSeconds(5)
            }

            if ($update.MarkSeen) { $shared.LastRemoteStamp = $remote.UpdatedAt }
        }
        catch {
            Write-SyncLog "Inbound error: $_" "ERROR"
        }
    }
}

# =============================================================================
#  LAUNCH INBOUND RUNSPACE
# =============================================================================

# Copy the functions the inbound loop uses into the runspace, so there is one definition of each.
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($name in 'Get-JsonField', 'Invoke-DeriveKey', 'Get-AesGcm', 'Unprotect-Payload',
                  'ConvertFrom-GistContent', 'Get-TextHash', 'Resolve-InboundUpdate', 'Get-Gist') {
    $definition = (Get-Command -Name $name -CommandType Function).Definition
    $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $definition))
}

$rs = [runspacefactory]::CreateRunspace($iss)
$rs.ApartmentState = [System.Threading.ApartmentState]::STA
$rs.ThreadOptions  = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
$rs.Open()

$ps = [powershell]::Create()
$ps.Runspace = $rs
$null = $ps.AddScript($inboundScript).AddArgument($shared).AddArgument($GistId).AddArgument($headers).AddArgument($FileName).AddArgument($PollMin).AddArgument($PollMax).AddArgument($Passphrase).AddArgument($env:COMPUTERNAME)
$null = $ps.BeginInvoke()   # the runspace runs until shutdown; nothing waits on the handle

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

Write-SyncLog "Outbound loop started — watching clipboard every 500 ms." "OK" "OUT"
$lastLocalHash = ""
$inboundDead   = $false

try {
    while ($true) {
        Start-Sleep -Milliseconds 500
        Invoke-DrainLogQueue

        if (-not $inboundDead -and $ps.InvocationStateInfo.State -in @('Failed', 'Stopped', 'Completed')) {
            $inboundDead = $true
            Write-SyncLog "Inbound loop thread stopped unexpectedly (state: $($ps.InvocationStateInfo.State)). Incoming sync from peers is no longer active; outbound push will keep running." "ERROR" "SYS"
            if ($ps.Streams.Error.Count -gt 0) {
                Write-SyncLog "Last inbound error: $($ps.Streams.Error[-1])" "ERROR" "SYS"
            }
        }

        try {
            # Suppress push briefly after receiving from a peer
            if ([datetime]::UtcNow -lt $shared.IgnoreUntil) { continue }

            $text = Get-ClipboardText
            $out  = Get-OutboundAction -Text $text -LastLocalHash $lastLocalHash -LastPushedHash $shared.LastPushedHash

            if ($out.Action -eq 'none') { continue }

            if ($out.Action -eq 'synced') {
                $lastLocalHash = $out.Hash
                continue
            }

            if ($out.Action -eq 'blocked') {
                Write-SyncLog "BLOCKED: credential pattern detected — not syncing." "WARN" "OUT"
                $lastLocalHash = $out.Hash   # advance so warning isn't repeated every 500 ms
                continue
            }

            Write-SyncLog "Local clipboard changed — pushing to Gist." "INFO" "OUT"
            $content = ConvertTo-GistContent -Text $text -HostName $env:COMPUTERNAME -Pass $Passphrase
            Push-Gist -GistId $GistId -Headers $headers -FileName $FileName -JsonContent $content
            Write-SyncLog "Pushed successfully." "OK" "OUT"

            # Only after a successful push, so a failed one is retried on the next check.
            $shared.LastPushedHash = $out.Hash
            $lastLocalHash         = $out.Hash
        }
        catch {
            Write-SyncLog "Outbound error: $_" "ERROR" "OUT"
        }
    }
}
finally {
    Write-SyncLog "Shutting down..." "WARN" "SYS"
    try { $ps.Stop()    } catch { Write-Verbose "Shutdown: $_" }
    try { $ps.Dispose() } catch { Write-Verbose "Shutdown: $_" }
    try { $rs.Close()   } catch { Write-Verbose "Shutdown: $_" }
    try { $rs.Dispose() } catch { Write-Verbose "Shutdown: $_" }
    Write-SyncLog "ClipboardSync stopped." "WARN" "SYS"
}
