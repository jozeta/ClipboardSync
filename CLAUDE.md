# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ClipboardSync is a single PowerShell 7+ script (`ClipboardSync.ps1`) that syncs plain-text
clipboard contents in both directions between multiple Windows machines through a private GitHub
Gist. The same command runs on every machine. Optional AES-256 encryption and an outbound secret
scanner. The README is the full user guide.

## Running

```powershell
.\ClipboardSync.ps1 -GistId $env:CLIPBOARD_GIST -Token $env:GITHUB_TOKEN [-Passphrase $env:CLIPBOARD_PASSPHRASE]
```

Parameters: `-GistId` and `-Token` (PAT with `gist` scope only) are required; `-FileName`
(default `clipboard.json`, must match on all machines), `-PollMin`/`-PollMax` (15/30 s),
`-Passphrase`. Windows-only (uses the Windows clipboard). `Invoke-Pester -Path tests` covers the secret scanner and the
encryption (functions loaded from the syntax tree; the sync loop never runs); test syncing itself with two
machines or two sessions pointed at a throwaway secret Gist.

## How it works

- **Push loop:** polls the local clipboard every 500 ms; text changes are scanned for credentials
  (blocked if they match a pattern), optionally encrypted, then written to the Gist via the
  GitHub REST API (no git needed).
- **Pull loop:** polls the Gist at a random interval between `PollMin` and `PollMax` and applies
  other machines' changes. **Last write wins.**
- **Echo prevention:** each payload carries hostname + content hash, so a machine ignores its own
  pushes.
- **Encryption:** AES-256-CBC, PBKDF2-SHA256 (200,000 iterations), random 16-byte salt and IV per
  write, PKCS7. Confidentiality only: there is no MAC, so tampering isn't detected.
- Only plain text and file paths are synced; images, rich text and HTML are skipped.

## Things to keep true when changing it

- Never log, print or persist the token or passphrase. Prefer env vars / Credential Manager in
  docs and examples; the README explains why command-line values are visible to other processes.
- Keep request volume well under GitHub's 5,000/hour limit (defaults use about 240/hour).
- Gists keep every revision forever. Anything that weakens the secret scanner or makes encryption
  easier to skip is a security regression; update README §5–§9 if behaviour changes.
- Keep the payload format backward compatible, or all machines must be upgraded together.

## App standards

This repo follows the app standards in `~/Desktop/code/tools/standards/STANDARDS.md` (rule IDs,
severities; decisions and waivers in `.claude-standards`). `claude-check --repo .` checks it.
Lint: `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1`; CI runs it
and Pester on Windows.

