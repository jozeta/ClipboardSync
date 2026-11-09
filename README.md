# ClipboardSync — Setup & Usage Guide

> Bidirectional plain-text clipboard sync across multiple Windows machines via a private GitHub Gist.

---

## Table of contents

1. [Overview](#1-overview)
2. [Requirements](#2-requirements)
3. [Step-by-step setup](#3-step-by-step-setup)
4. [Running the script](#4-running-the-script)
5. [Encryption](#5-encryption)
6. [Credential detection](#6-credential-detection)
7. [Storing credentials safely](#7-storing-credentials-safely)
8. [Running automatically at login](#8-running-automatically-at-login)
9. [Security considerations](#9-security-considerations)
10. [Troubleshooting](#10-troubleshooting)
11. [Known limitations](#11-known-limitations)
12. [Quick reference](#12-quick-reference)

---

## 1. Overview

Run the **same command on every machine**. Each instance simultaneously:

- **Pushes** — watches the local clipboard every 500 ms and uploads any text change to a private GitHub Gist via the REST API.
- **Pulls** — polls the Gist at a random interval and applies changes made by other machines to the local clipboard.

**No git installation required.** All communication is HTTPS to `api.github.com`.

| Property | Detail |
|---|---|
| Supported content | Plain text, file paths (as newline-separated text) |
| Ignored content | Images, rich text, HTML — silently skipped |
| Conflict resolution | Last write wins |
| Number of machines | Unlimited |
| Echo prevention | Each machine ignores its own pushes (hostname + content hash) |
| PowerShell requirement | **7.0 or later** |

---

## 2. Requirements

- Windows 10 version 1903 or later
- **PowerShell 7.0 or later** — [download here](https://aka.ms/powershell)
- Internet access on port 443 (HTTPS to `api.github.com`)
- A free GitHub account

> Use `pwsh.exe` to launch PowerShell 7. The script will not run correctly on Windows PowerShell 5.1 (`powershell.exe`).

---

## 3. Step-by-step setup

### Step 1 — Create a GitHub Personal Access Token (PAT)

1. Sign in to GitHub and go to:
   **Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token → Generate new token (classic)**.
3. Give it a name, e.g. `ClipboardSync`.
4. Set an expiration (90 days recommended).
5. Tick **only** the `gist` checkbox. No other scope is needed.
6. Click **Generate token**. Copy it immediately — GitHub shows it only once.

> The token looks like `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`. Store it in a password manager.

---

### Step 2 — Create a private Gist

1. Go to <https://gist.github.com>
2. **Gist description:** `ClipboardSync`
3. **Filename:** `clipboard.json`
4. **Content:** `{}`
5. Click **Create secret gist**.
6. Copy the **Gist ID** from the URL — the 32-character hex string at the end:
   `https://gist.github.com/yourusername/`**`abc123def456abc123def456abc123de`**

---

### Step 3 — Save the script

Save `ClipboardSync.ps1` to a permanent location on each machine, for example:

```
C:\Scripts\ClipboardSync.ps1
```

---

### Step 4 — Allow the script to run

Run once in a **PowerShell 7** window:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## 4. Running the script

Run the **same command on every machine**:

```powershell
.\ClipboardSync.ps1 -GistId "YOUR_GIST_ID" -Token "YOUR_PAT"
```

Using environment variables (recommended):

```powershell
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-GistId` | *(required)* | 32-character Gist ID |
| `-Token` | *(required)* | GitHub PAT with `gist` scope |
| `-FileName` | `clipboard.json` | Filename used inside the Gist — must match on all machines |
| `-PollMin` | `15` | Minimum poll interval in seconds |
| `-PollMax` | `30` | Maximum poll interval in seconds |
| `-Passphrase` | *(off)* | Shared passphrase for AES-256-GCM encryption |

### Console output

Each log line is tagged with its source:

| Tag | Source |
|---|---|
| `[SYS]` | Startup, shutdown, validation |
| `[OUT]` | Outbound loop — local clipboard → Gist |
| `[IN ]` | Inbound loop — Gist → local clipboard |

When another machine's clipboard arrives you will see:

```
[2026-03-27 14:32:07][OK][ IN] ━━ Data received from computer 'DESKTOP-ABC123' — synced at 14:32:07
```

---

## 5. Encryption

Add `-Passphrase` to encrypt all payloads. Every machine must use the same passphrase.

```powershell
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
    -Passphrase $env:CLIPBOARD_PASSPHRASE
```

| Property | Value |
|---|---|
| Algorithm | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256, 200,000 iterations |
| Salt | 16 bytes, random per write |
| Nonce | 12 bytes, random per write |
| Authentication tag | 128 bits; associated data `ClipboardSync/v2` |

What this gives you:

- **Confidentiality:** the Gist (and its revision history) holds only ciphertext. The text and the sending machine's name are both inside the encrypted part.
- **Integrity:** a wrong passphrase, or any change to the salt, nonce, tag or ciphertext, fails the tag check. The payload is skipped with a `Decryption failed` error and never reaches the clipboard.
- **No plaintext injection:** with `-Passphrase` set, a machine **refuses unencrypted payloads**. Someone who has only the Gist token can't push text onto your clipboard.

The passphrase is the only secret that protects this: anyone who knows it can write payloads every machine will accept.

> **Payload format v2.** Since the switch to AES-GCM the Gist file has a version field (`"v": 2`). Machines skip payloads in any other format with a `format v1, this machine reads v2` warning, and older versions of the script can't read v2. **Upgrade ClipboardSync on every machine at the same time.**

> Never pass the passphrase as a literal string on the command line — store it in `$env:CLIPBOARD_PASSPHRASE` (see [Section 7](#7-storing-credentials-safely)).

---

## 6. Credential detection

Before every push, the outbound loop scans the clipboard text for known credential patterns. If a match is found the content is **not pushed**, a `[WARN]` line is written to the console, and the Gist is left unchanged.

Patterns detected:

- GitHub PATs (all variants: `ghp_`, `gho_`, `ghs_`, `ghr_`, fine-grained)
- Generic `api_key` / `secret` / `token` assignment lines
- AWS access key IDs and secret access keys
- PEM private key headers (RSA, EC, OPENSSH, PGP)
- Connection strings and config files containing a password field
- JSON Web Tokens (JWT)

> **This is a best-effort heuristic, not a guarantee.** It's a fixed list of regex patterns — secrets in a format it doesn't recognize, split across multiple clipboard entries, or wrapped/encoded (e.g. base64) will not be caught. Don't rely on it as your only safeguard against leaking credentials; it's a backstop, not a filter you should trust blindly.

---

## 7. Storing credentials safely

### Option A — Environment variables (recommended)

Add to your PowerShell 7 profile (`$PROFILE`):

```powershell
$env:GITHUB_TOKEN         = "ghp_your_token_here"
$env:CLIPBOARD_GIST       = "your_gist_id_here"
$env:CLIPBOARD_PASSPHRASE = "your_strong_passphrase"
```

Then run without inline secrets:

```powershell
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST `
    -Token $env:GITHUB_TOKEN -Passphrase $env:CLIPBOARD_PASSPHRASE
```

### Option B — Windows Credential Manager

Store once:

```powershell
cmdkey /generic:ClipboardSyncToken /user:github /pass:"ghp_your_token_here"
```

Retrieve in your session:

```powershell
$cred  = Get-StoredCredential -Target "ClipboardSyncToken"
$token = $cred.GetNetworkCredential().Password
```

---

## 8. Running automatically at login

1. Press `Win + R`, type `taskschd.msc`, press Enter.
2. Click **Create Basic Task**.
3. Name: `ClipboardSync`
4. Trigger: **When I log on**
5. Action: **Start a program**
6. Program/script: `pwsh.exe`
7. Arguments:

```
-WindowStyle Hidden -NonInteractive -File "C:\Scripts\ClipboardSync.ps1" -GistId YOUR_GIST_ID -Token YOUR_PAT
```

8. Click **Finish**.

> `-WindowStyle Hidden` runs without a visible window. Use `pwsh.exe` (PowerShell 7), **not** `powershell.exe` (Windows PowerShell 5.1).

---

## 9. Security considerations

| Topic | Guidance |
|---|---|
| Token scope | PAT only needs the `gist` scope. Do not grant `repo` or any other permission. |
| Gist visibility | Always create a **Secret Gist**. Enable `-Passphrase` if the clipboard may contain sensitive data. |
| Credential detection | The outbound loop scans for secrets before every push. If content is blocked, it matched a known credential pattern. |
| Passphrase strength | Use a long random passphrase (20+ characters). Store it in a password manager. |
| Token rotation | Set an expiration. Revoke immediately at [github.com/settings/tokens](https://github.com/settings/tokens) if compromised. |
| Rate limits | GitHub allows 5,000 authenticated requests/hour. Default poll settings use at most ~240 requests/hour — well within limits. |
| Gist history | GitHub Gists keep **every revision forever**. Each push is a new revision, so even after content is overwritten by a later sync, the old (unencrypted, if `-Passphrase` isn't used) clipboard text is still readable by anyone with access to the Gist via its revision history. Use `-Passphrase` if the clipboard may ever contain anything sensitive. |
| Encryption is authenticated | AES-256-GCM: tampered or wrongly keyed payloads are detected and skipped, and with `-Passphrase` set unencrypted payloads are refused (see [Section 5](#5-encryption)). Without `-Passphrase`, anyone with the Gist token can put text on every machine's clipboard. |
| Untrusted peer data | Text from the Gist is only ever placed on the clipboard, never run. The sender's host name is stripped of control characters before it is logged. |
| Command-line exposure | `-Token` and `-Passphrase` are visible in plaintext to other processes on the same machine for the life of the process (e.g. Task Manager's "Command line" column, `Get-CimInstance Win32_Process`) — this is true even when the *value* comes from an environment variable at the call site, since PowerShell substitutes the literal value into the argument list before the process starts. A Scheduled Task that embeds these values in its **Arguments** field (see [Section 8](#8-running-automatically-at-login)) stores them in plaintext in the Task Scheduler configuration on disk. |

---

## 10. Troubleshooting

| Problem | Solution |
|---|---|
| `401 Unauthorized` | Token is wrong or expired. Regenerate at GitHub → Settings → Developer settings. |
| `404 Not Found` | Gist ID is incorrect or the Gist was deleted. Check the URL at gist.github.com. |
| Script blocked / not signed | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in a `pwsh` window. |
| `[IN ]` lines never appear | The inbound runspace may have crashed. Look for `[ERROR][SYS]` "Inbound loop thread stopped unexpectedly" — it reports the last inbound error and keeps outbound push running. |
| Content blocked | Clipboard matched a credential pattern. Check the `[WARN]` log line for details. |
| Decryption failed | Passphrase mismatch between machines, or the payload was altered. Ensure all machines use the same `-Passphrase` value. |
| Payload encrypted, no passphrase | Run the script with `-Passphrase` matching the other machines. |
| Refusing an unencrypted payload | Another machine runs without `-Passphrase`. Give every machine the same passphrase. |
| Payload is in format v1 | Another machine runs an older version of the script. Update ClipboardSync on every machine. |
| Script fails / syntax errors | Ensure you are using `pwsh.exe` (PowerShell 7), not `powershell.exe` (PS 5.1). |
| Clipboard not updating on receive | Verify the `[IN ]` log shows the receive message. If it does, check that no other application is locking the clipboard. |

---

## 11. Known limitations

- **Windows only.** The script relies on `System.Windows.Forms.Clipboard` and the `Set-Clipboard` cmdlet, both Windows-specific. It will not run on macOS or Linux, even under PowerShell 7.
- **Clearing the clipboard doesn't sync.** If you cut/clear the clipboard so it's empty, or copy an image/rich text/HTML, nothing is pushed — peers simply keep showing their last-synced text. There's no way to propagate "clipboard is now empty" or "clipboard now holds non-text content."
- **Last write wins, with no merge.** If two machines change their clipboard within the same poll window, whichever push reaches the Gist last simply overwrites the other — there is no conflict warning.
- **Gist history is permanent** — see [Section 9](#9-security-considerations).
- **Upgrades must be done on all machines together** when the payload format changes (it did with the switch to AES-GCM) — see [Section 5](#5-encryption).
- **Secret detection is a heuristic**, not a guarantee — see the caveat in [Section 6](#6-credential-detection).
- **Secrets can leak via the process command line and Scheduled Task config**, independent of anything the script does — see the "Command-line exposure" row in [Section 9](#9-security-considerations). Where possible, prefer typing the token/passphrase into your `$PROFILE` as environment variables over pasting them into a Scheduled Task's Arguments field.

---

## 12. Quick reference

```powershell
# Basic — all machines
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN

# With encryption
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
    -Passphrase $env:CLIPBOARD_PASSPHRASE

# Faster polling (10–20 s)
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
    -PollMin 10 -PollMax 20

# Encrypted + faster polling
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN `
    -Passphrase $env:CLIPBOARD_PASSPHRASE -PollMin 10 -PollMax 20
```
