# Changelog

All notable changes to ClipboardSync are listed here, newest first.

The project has no tagged releases yet, so changes are grouped by date. Entries before November 2026 were reconstructed from the commit history.

## Unreleased

- PSScriptAnalyzer clean-up: `Write-Log` is now `Write-SyncLog` (it shadowed a built-in cmdlet),
  shutdown errors are logged verbosely instead of swallowed, and the deliberate cases (plain-text
  passphrase from an environment variable, parameters used by nested functions) are marked with why

- First automated tests (Pester: secret scanner, AES-256 round trip, text hash) and CI on Windows
  that runs PSScriptAnalyzer and the tests

## 2026-11-02

- Add security policy

## 2026-11-01

- Ignore macOS, Claude Code and secret files; add MIT license
- Add CLAUDE.md with project guidance for Claude Code

## 2026-08-10

- Initial commit: ClipboardSync PowerShell script and setup guide
