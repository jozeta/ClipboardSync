# Changelog

All notable changes to ClipboardSync are listed here, newest first.

The project has no tagged releases yet, so changes are grouped by date. Entries before November 2026 were reconstructed from the commit history.

## Unreleased

- **Breaking: payload format v2 with AES-256-GCM.** Encryption is now authenticated: a wrong
  passphrase or a tampered payload is detected and skipped instead of possibly decrypting to
  garbage. Payloads without `"v": 2` are skipped, so every machine must be upgraded together.
- With `-Passphrase` set, unencrypted payloads from the Gist are refused (before, anyone with the
  Gist token could push plain text onto an encrypted machine's clipboard)
- Clipboard text is base64 inside the payload, so date-like text is no longer turned into a date by
  `ConvertFrom-Json`
- The peer's host name is stripped of control characters before it is logged
- Malformed or refused Gist versions are skipped once instead of logging an error on every poll;
  a missing sync file no longer fails startup under StrictMode
- Refactor: the push and pull decisions are pure functions with Pester tests (echo prevention,
  secret blocking, downgrade and plaintext refusal, tampering); the inbound runspace reuses the
  script's functions instead of its own copies; PSScriptAnalyzer's unused-parameter rule is back on
- CI: `actions/checkout@v5` (Node 24)
- PSScriptAnalyzer clean-up: `Write-Log` is now `Write-SyncLog` (it shadowed a built-in cmdlet),
  shutdown errors are logged verbosely instead of swallowed, and the deliberate cases (plain-text
  passphrase from an environment variable, parameters used by nested functions) are marked with why

- First automated tests (Pester: secret scanner, AES-256 round trip, text hash) and CI on Windows
  that runs PSScriptAnalyzer and the tests

## 2026-11-03

- Add `.claude-audit-allow`: reviewed fake keys for claude-audit

## 2026-11-02

- Add security policy

## 2026-11-01

- Ignore macOS, Claude Code and secret files; add MIT license
- Add CLAUDE.md with project guidance for Claude Code

## 2026-08-10

- Initial commit: ClipboardSync PowerShell script and setup guide
