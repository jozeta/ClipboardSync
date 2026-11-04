# Pester 5 tests for ClipboardSync.ps1: the script parses, the outbound secret scanner catches
# credentials (and leaves normal text alone), and the AES-256 envelope round-trips. The sync loop is
# never started: the functions are loaded from the script's syntax tree.
#   Invoke-Pester -Path tests
# The fake credentials are assembled at run time, so no token-shaped literal sits in this file.

# $Passphrase is set in each test for the functions it calls (they read it from the caller's scope).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Passphrase', Justification = 'Read by the functions under test')]
param()

BeforeAll {
    $path = Join-Path $PSScriptRoot '..' 'ClipboardSync.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = $errors

    $names = 'Test-ContainsSecret', 'Invoke-DeriveKey', 'Protect-Payload', 'Unprotect-Payload', 'Get-TextHash'
    $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $names -contains $_.Name })
    $patterns = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$script:SecretPatterns' }, $false) | Select-Object -First 1
    $script:Loaded = $defs.Count + @($patterns).Count

    # $script:SecretPatterns becomes a plain variable, so nothing depends on the script's own scope.
    $code = (@($patterns) + $defs | ForEach-Object { $_.Extent.Text }) -join "`n`n"
    . ([scriptblock]::Create(($code -replace '(?i)\$script:SecretPatterns', '$SecretPatterns')))
}

Describe 'ClipboardSync.ps1' {
    It 'parses without syntax errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'has the pattern list and the functions these tests use' {
        $script:Loaded | Should -Be 6
    }
}

Describe 'Test-ContainsSecret (outbound scanner)' {
    It 'catches <name>' -ForEach @(
        @{ name = 'a GitHub classic token';  text = 'token ' + 'gh' + 'p_' + ('A1' * 18) }
        @{ name = 'a GitHub fine-grained token'; text = 'github' + '_pat_' + ('a' * 82) }
        @{ name = 'an AWS access key id';    text = 'AK' + 'IA' + ('Z' * 16) }
        @{ name = 'a private key block';     text = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----' }
        @{ name = 'an api_key assignment';   text = 'api' + '_key = "' + ('x' * 20) + '"' }
        @{ name = 'a password assignment';   text = 'pass' + 'word=' + 'correcthorse1' }
        @{ name = 'a JWT';                   text = 'ey' + 'J' + ('a' * 12) + '.' + ('b' * 12) + '.' + ('c' * 12) }
    ) {
        Test-ContainsSecret -Text $text | Should -BeTrue
    }

    It 'leaves normal clipboard text alone: <text>' -ForEach @(
        @{ text = 'Meeting moved to 14:30, room B' }
        @{ text = 'https://example.com/docs?page=2' }
        @{ text = 'password reset link sent' }
        @{ text = '' }
    ) {
        Test-ContainsSecret -Text $text | Should -BeFalse
    }
}

Describe 'AES-256 envelope' {
    It 'round-trips text, including non-ASCII, with a fresh salt and IV each time' {
        $Passphrase = 'correct horse battery staple'
        $plain = "Hej då – åäö ✓`nline 2"
        $a = Protect-Payload -Plaintext $plain
        $b = Protect-Payload -Plaintext $plain
        $a | Should -Not -Be $b
        ($a | ConvertFrom-Json).cipher | Should -Not -Match 'Hej'
        Unprotect-Payload -EncJson $a | Should -Be $plain
    }

    It 'never yields the text with the wrong passphrase' {
        $Passphrase = 'right one'
        $enc = Protect-Payload -Plaintext 'secret text'
        $Passphrase = 'wrong one'
        # Usually a padding error; rarely (about 1 in 256) the padding happens to fit and the
        # result is garbage. Either way the plaintext must not come back.
        $out = try { Unprotect-Payload -EncJson $enc } catch { $null }
        $out | Should -Not -Be 'secret text'
    }

    It 'passes text through unchanged without a passphrase' {
        $Passphrase = ''
        Protect-Payload -Plaintext 'plain' | Should -Be 'plain'
        Unprotect-Payload -EncJson 'plain' | Should -Be 'plain'
    }
}

Describe 'Get-TextHash' {
    It 'is stable, differs per text, and names the empty clipboard' {
        Get-TextHash 'abc' | Should -Be (Get-TextHash 'abc')
        Get-TextHash 'abc' | Should -Not -Be (Get-TextHash 'abd')
        Get-TextHash '' | Should -Be 'empty'
    }
}
