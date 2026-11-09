# Pester 5 tests for ClipboardSync.ps1: the script parses, the outbound secret scanner catches
# credentials (and leaves normal text alone), the AES-256-GCM payload format v2 round-trips and
# rejects tampering, downgrades and plaintext, and the push/pull loops decide correctly. The sync
# loops are never started: the functions are loaded from the script's syntax tree and run under
# Set-StrictMode, like the script itself. Clipboard and Gist I/O are not exercised here.
#   Invoke-Pester -Path tests
# The fake credentials are assembled at run time, so no token-shaped literal sits in this file.

BeforeAll {
    $path = Join-Path $PSScriptRoot '..' 'ClipboardSync.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = $errors

    $script:Names = 'Get-JsonField', 'Test-ContainsSecret', 'Invoke-DeriveKey', 'Get-AesGcm', 'Protect-Payload',
        'Unprotect-Payload', 'ConvertTo-GistContent', 'ConvertFrom-GistContent', 'Get-TextHash',
        'Get-OutboundAction', 'Resolve-InboundUpdate'
    $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $script:Names -contains $_.Name })
    $patterns = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$script:SecretPatterns' }, $false) | Select-Object -First 1
    $script:Loaded = $defs.Count + @($patterns).Count

    # $script:SecretPatterns becomes a plain variable, so nothing depends on the script's own scope.
    $code = (@($patterns) + $defs | ForEach-Object { $_.Extent.Text }) -join "`n`n"
    . ([scriptblock]::Create(($code -replace '(?i)\$script:SecretPatterns', '$SecretPatterns')))

    # Builds a Gist file the way an older or hostile writer might.
    function Format-RawContent {
        param($Version, [bool]$Encrypted, [string]$Payload)
        $o = [ordered]@{}
        if ($null -ne $Version) { $o.v = $Version }
        $o.encrypted = $Encrypted
        $o.payload   = $Payload
        $o | ConvertTo-Json -Compress
    }
    function Format-InnerPayload {
        param([string]$Text, [string]$From = 'PC2')
        [ordered]@{ data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)); timestamp = 'x'; host = $From } |
            ConvertTo-Json -Compress
    }
    # Replaces one base64 field of an encrypted payload with the same bytes, first byte flipped.
    function Edit-EncryptedField {
        param([string]$EncJson, [string]$Field)
        $e = $EncJson | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($e.$Field)
        $bytes[0] = $bytes[0] -bxor 0x01
        $e.$Field = [Convert]::ToBase64String($bytes)
        $e | ConvertTo-Json -Compress
    }
}

BeforeEach {
    # BeforeEach shares the scope of each It, so the functions under test run in strict mode.
    Set-StrictMode -Version Latest
}

Describe 'ClipboardSync.ps1' {
    It 'parses without syntax errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'has the pattern list and the functions these tests use' {
        $script:Loaded | Should -Be ($script:Names.Count + 1)
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

Describe 'AES-256-GCM (Protect-Payload / Unprotect-Payload)' {
    BeforeAll { $script:Pass = 'correct horse battery staple' }

    It 'round-trips text, including non-ASCII, with a fresh salt and nonce each time' {
        $plain = "Hej då – åäö ✓`nline 2"
        $a = Protect-Payload -Plaintext $plain -Pass $script:Pass
        $b = Protect-Payload -Plaintext $plain -Pass $script:Pass
        $ea = $a | ConvertFrom-Json; $eb = $b | ConvertFrom-Json
        $ea.salt  | Should -Not -Be $eb.salt
        $ea.nonce | Should -Not -Be $eb.nonce
        $a | Should -Not -Match 'Hej'
        Unprotect-Payload -EncJson $a -Pass $script:Pass | Should -Be $plain
    }

    It 'throws with the wrong passphrase' {
        $enc = Protect-Payload -Plaintext 'secret text' -Pass 'right one'
        { Unprotect-Payload -EncJson $enc -Pass 'wrong one' } | Should -Throw
    }

    It 'throws when the <field> was altered' -ForEach @(
        @{ field = 'cipher' }, @{ field = 'tag' }, @{ field = 'nonce' }, @{ field = 'salt' }
    ) {
        $enc = Protect-Payload -Plaintext 'pay 100 to alice' -Pass $script:Pass
        $bad = Edit-EncryptedField -EncJson $enc -Field $field
        { Unprotect-Payload -EncJson $bad -Pass $script:Pass } | Should -Throw
    }

    It 'throws on a payload with missing fields' {
        { Unprotect-Payload -EncJson '{"cipher":"AAAA"}' -Pass $script:Pass } | Should -Throw
    }
}

Describe 'Payload format v2 (ConvertTo-GistContent / ConvertFrom-GistContent)' {
    It 'round-trips unencrypted, keeping date-like text as text' {
        $text = '2026-11-09T10:00:00Z'
        $content = ConvertTo-GistContent -Text $text -HostName 'PC1' -Pass ''
        ($content | ConvertFrom-Json).v | Should -Be 2
        $r = ConvertFrom-GistContent -Content $content -Pass ''
        $r.Ok   | Should -BeTrue
        $r.Text | Should -BeExactly $text
        $r.Text | Should -BeOfType [string]
        $r.Host | Should -Be 'PC1'
    }

    It 'round-trips encrypted, and the Gist file does not reveal the text or host' {
        $content = ConvertTo-GistContent -Text 'meet at 5' -HostName 'PC1' -Pass 'pw'
        $outer = $content | ConvertFrom-Json
        $outer.encrypted | Should -BeTrue
        $content | Should -Not -Match 'PC1'
        $content | Should -Not -Match ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('meet at 5')))
        $r = ConvertFrom-GistContent -Content $content -Pass 'pw'
        $r.Ok   | Should -BeTrue
        $r.Text | Should -Be 'meet at 5'
    }

    It 'rejects a v1 payload (no version field), encrypted or not' {
        $plainV1 = Format-RawContent -Version $null -Encrypted $false -Payload '{"data":"hi","host":"PC2"}'
        $encV1   = Format-RawContent -Version $null -Encrypted $true  -Payload '{"salt":"","iv":"","cipher":""}'
        foreach ($c in $plainV1, $encV1) {
            foreach ($pass in '', 'pw') {
                $r = ConvertFrom-GistContent -Content $c -Pass $pass
                $r.Ok      | Should -BeFalse
                $r.Message | Should -Match 'v1'
            }
        }
    }

    It 'rejects an unknown version' {
        $r = ConvertFrom-GistContent -Content (Format-RawContent -Version 3 -Encrypted $false -Payload (Format-InnerPayload 'hi')) -Pass ''
        $r.Ok      | Should -BeFalse
        $r.Message | Should -Match 'v3'
    }

    It 'refuses an unencrypted payload when a passphrase is set (no plaintext injection)' {
        $content = Format-RawContent -Version 2 -Encrypted $false -Payload (Format-InnerPayload 'evil')
        $r = ConvertFrom-GistContent -Content $content -Pass 'pw'
        $r.Ok      | Should -BeFalse
        $r.Message | Should -Match 'unencrypted'
    }

    It 'skips an encrypted payload when no passphrase is set' {
        $content = ConvertTo-GistContent -Text 'x' -HostName 'PC1' -Pass 'pw'
        $r = ConvertFrom-GistContent -Content $content -Pass ''
        $r.Ok      | Should -BeFalse
        $r.Message | Should -Match 'no -Passphrase'
    }

    It 'skips, without throwing, on a wrong passphrase' {
        $content = ConvertTo-GistContent -Text 'x' -HostName 'PC1' -Pass 'pw'
        $r = ConvertFrom-GistContent -Content $content -Pass 'other'
        $r.Ok    | Should -BeFalse
        $r.Level | Should -Be 'ERROR'
    }

    It 'skips, without throwing, on <name>' -ForEach @(
        @{ name = 'text that is not JSON'; content = 'not json' }
        @{ name = 'a JSON array';          content = '[1,2]' }
        @{ name = 'a missing payload';     content = '{"v":2,"encrypted":false}' }
        @{ name = 'inner data not base64'; content = '{"v":2,"encrypted":false,"payload":"{\"data\":\"%%%\",\"host\":\"PC2\"}"}' }
        @{ name = 'inner host missing';    content = '{"v":2,"encrypted":false,"payload":"{\"data\":\"aGk=\"}"}' }
        @{ name = 'empty text';            content = '{"v":2,"encrypted":false,"payload":"{\"data\":\"\",\"host\":\"PC2\"}"}' }
    ) {
        $r = ConvertFrom-GistContent -Content $content -Pass ''
        $r.Ok | Should -BeFalse
        $r.Message | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-OutboundAction (push loop)' {
    It 'does nothing for an empty clipboard' {
        (Get-OutboundAction -Text '' -LastLocalHash '' -LastPushedHash '').Action | Should -Be 'none'
    }

    It 'does nothing when the text has not changed' {
        $h = Get-TextHash 'same'
        (Get-OutboundAction -Text 'same' -LastLocalHash $h -LastPushedHash '').Action | Should -Be 'none'
    }

    It 'does not re-push text that was just pushed or received' {
        $h = Get-TextHash 'from peer'
        $r = Get-OutboundAction -Text 'from peer' -LastLocalHash 'old' -LastPushedHash $h
        $r.Action | Should -Be 'synced'
        $r.Hash   | Should -Be $h
    }

    It 'blocks a credential' {
        $r = Get-OutboundAction -Text ('AK' + 'IA' + ('Q' * 16)) -LastLocalHash '' -LastPushedHash ''
        $r.Action | Should -Be 'blocked'
        $r.Hash   | Should -Not -BeNullOrEmpty
    }

    It 'pushes new text' {
        $r = Get-OutboundAction -Text 'new note' -LastLocalHash 'old' -LastPushedHash 'older'
        $r.Action | Should -Be 'push'
        $r.Hash   | Should -Be (Get-TextHash 'new note')
    }
}

Describe 'Resolve-InboundUpdate (pull loop)' {
    BeforeAll {
        function Get-Remote { param([string]$Text, [string]$From = 'PC2', [string]$Pass = '', [string]$Stamp = 's2')
            @{ Content = (ConvertTo-GistContent -Text $Text -HostName $From -Pass $Pass); UpdatedAt = $Stamp }
        }
    }

    It 'does nothing for <name>, and does not mark it seen' -ForEach @(
        @{ name = 'no file';       remote = $null }
        @{ name = 'an empty Gist'; remote = @{ Content = '{}'; UpdatedAt = 's2' } }
    ) {
        $r = Resolve-InboundUpdate -Remote $remote -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass ''
        $r.Action   | Should -Be 'none'
        $r.MarkSeen | Should -BeFalse
    }

    It 'does nothing when the Gist version was already seen' {
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'hi' -Stamp 's1') -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass ''
        $r.Action   | Should -Be 'none'
        $r.MarkSeen | Should -BeFalse
    }

    It 'skips its own push' {
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'mine' -From 'PC1') -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass ''
        $r.Action   | Should -Be 'skip'
        $r.MarkSeen | Should -BeTrue
    }

    It 'skips text that is already in sync' {
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'same') -LastRemoteStamp 's1' -LastPushedHash (Get-TextHash 'same') -LocalHost 'PC1' -Pass ''
        $r.Action | Should -Be 'skip'
    }

    It 'applies a peer''s text and returns its hash' {
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'hello' -Pass 'pw') -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass 'pw'
        $r.Action   | Should -Be 'apply'
        $r.Text     | Should -Be 'hello'
        $r.Hash     | Should -Be (Get-TextHash 'hello')
        $r.MarkSeen | Should -BeTrue
        $r.Message  | Should -Match "'PC2'"
    }

    It 'skips and marks seen a refused payload, so it is not retried every poll' {
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'evil') -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass 'pw'
        $r.Action   | Should -Be 'skip'
        $r.Level    | Should -Be 'WARN'
        $r.MarkSeen | Should -BeTrue
        $r.Text     | Should -BeNullOrEmpty
    }

    It 'strips control characters from the peer''s host name before logging it' {
        $esc = [char]27
        $r = Resolve-InboundUpdate -Remote (Get-Remote 'hi' -From "PC2$($esc)[31m") -LastRemoteStamp 's1' -LastPushedHash '' -LocalHost 'PC1' -Pass ''
        $r.Action  | Should -Be 'apply'
        $r.Message | Should -Not -Match ([regex]::Escape([string]$esc))
    }
}

Describe 'Get-TextHash' {
    It 'is stable, differs per text, and names the empty clipboard' {
        Get-TextHash 'abc' | Should -Be (Get-TextHash 'abc')
        Get-TextHash 'abc' | Should -Not -Be (Get-TextHash 'abd')
        Get-TextHash '' | Should -Be 'empty'
    }
}
