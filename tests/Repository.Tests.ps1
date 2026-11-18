# Repository-wide checks: every PowerShell file parses, text files are plain
# ASCII, no file carries a private address, a user profile path or code that
# runs strings as commands, and every pointer into the docs leads somewhere.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeAll variables with It blocks.')]
param()

Describe 'Repository files' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
        $all = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\\.git\\' })
        $textExtensions = @('.ps1', '.psm1', '.psd1', '.md', '.json', '.txt', '.yml', '.gitignore', '.gitattributes', '')
        $textFiles = @($all | Where-Object { $textExtensions -contains $_.Extension })
        $scripts = @($all | Where-Object { @('.ps1', '.psm1', '.psd1') -contains $_.Extension })
        function Get-TestHeading {
            # The headings of a Markdown file, without the leading #s.
            param([string]$Path)
            return @([System.IO.File]::ReadAllLines($Path) | Where-Object { $_ -match '^#{1,6} ' } | ForEach-Object { ($_ -replace '^#{1,6} ', '').Trim() })
        }
    }

    It 'has the files a release needs' {
        foreach ($name in @('README.md', 'LICENSE', '.gitignore', 'SECURITY.md')) {
            Assert-HvLabTrue (Test-Path -LiteralPath (Join-Path $root $name) -PathType Leaf) "$name exists"
        }
    }

    It 'parses every PowerShell file' {
        foreach ($file in $scripts) {
            $tokens = $null
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            Assert-HvLabEqual 0 @($errors).Count "$($file.Name): $(@($errors | ForEach-Object { $_.Message }) -join '; ')"
        }
    }

    It 'keeps text files plain ASCII with no trailing whitespace' {
        foreach ($file in $textFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $bad = @($bytes | Where-Object { ($_ -gt 126) -or ($_ -lt 32 -and $_ -ne 9 -and $_ -ne 10 -and $_ -ne 13) })
            Assert-HvLabEqual 0 $bad.Count "$($file.Name) has non-ASCII or control bytes"
            $lines = [System.IO.File]::ReadAllLines($file.FullName)
            $trailing = @($lines | Where-Object { $_ -match '[ \t]+$' })
            Assert-HvLabEqual 0 $trailing.Count "$($file.Name) has trailing whitespace"
        }
    }

    It 'contains no private addresses and no user profile paths' {
        $private = '(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])'
        $profilePath = '[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9]'
        foreach ($file in $textFiles) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            Assert-HvLabTrue ($text -notmatch $private) "$($file.Name) has a private IPv4 address"
            Assert-HvLabTrue ($text -notmatch $profilePath) "$($file.Name) has a user profile path"
        }
    }

    It 'never runs strings as commands' {
        foreach ($file in @($scripts | Where-Object { $_.DirectoryName -notmatch '\\tests$' })) {
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $names = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            Assert-HvLabTrue ($names -notcontains 'Invoke-Expression' -and $names -notcontains 'iex') "$($file.Name) uses Invoke-Expression"
            $text = [System.IO.File]::ReadAllText($file.FullName)
            Assert-HvLabTrue ($text -notmatch '-EncodedCommand|FromBase64String\([^)]*\)\s*\|\s*Invoke') "$($file.Name) runs encoded code"
        }
    }

    It 'gives every script comment-based help' {
        foreach ($file in @($scripts | Where-Object { $_.Extension -eq '.ps1' -and $_.DirectoryName -notmatch '\\tests$' })) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            Assert-HvLabTrue ($text -match '\.SYNOPSIS') "$($file.Name) has .SYNOPSIS"
        }
    }

    It 'points every docs reference in the scripts at an existing file and heading' {
        $found = 0
        foreach ($file in @($scripts | Where-Object { $_.DirectoryName -notmatch '\\tests$' })) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            foreach ($match in [regex]::Matches($text, 'docs\\([A-Za-z0-9._-]+\.md)(?:, ([A-Z][^)''"`]*?)(?=[)''".]))?')) {
                $found++
                $docPath = Join-Path $root ('docs\' + $match.Groups[1].Value)
                Assert-HvLabTrue (Test-Path -LiteralPath $docPath -PathType Leaf) "$($file.Name) refers to a missing file: $($match.Value)"
                if ($match.Groups[2].Success) {
                    Assert-HvLabTrue ((Get-TestHeading -Path $docPath) -contains $match.Groups[2].Value) "$($file.Name) refers to a missing heading: $($match.Value)"
                }
            }
        }
        Assert-HvLabTrue ($found -gt 0) 'there are docs references to check'
    }

    It 'links only to files and headings that exist' {
        foreach ($markdown in @($all | Where-Object { $_.Extension -eq '.md' })) {
            $text = [System.IO.File]::ReadAllText($markdown.FullName)
            foreach ($match in [regex]::Matches($text, '\]\(([^)\s]+)\)')) {
                $target = $match.Groups[1].Value
                if ($target -match '^(https?|mailto):') { continue }
                $parts = @($target -split '#', 2)
                $targetPath = $markdown.FullName
                if ($parts[0]) { $targetPath = Join-Path $markdown.DirectoryName ($parts[0].Replace('/', '\')) }
                Assert-HvLabTrue (Test-Path -LiteralPath $targetPath) "$($markdown.Name) links to a missing file: $target"
                if ($parts.Count -eq 2 -and $parts[1]) {
                    # GitHub anchors: lowercase, punctuation removed, spaces as hyphens.
                    $anchors = @(Get-TestHeading -Path $targetPath | ForEach-Object { ($_.ToLowerInvariant() -replace '[^a-z0-9 _-]', '') -replace ' ', '-' })
                    Assert-HvLabTrue ($anchors -contains $parts[1]) "$($markdown.Name) links to a missing heading: $target"
                }
            }
        }
    }

    It 'uses the module result prefix in both guest helpers' {
        Import-Module (Join-Path $root 'host\HvLab.Common.psm1') -Force
        $literal = "'" + (Get-HvLabResultPrefix) + "' + "
        foreach ($name in @('Get-HvLabKdnetInfo.ps1', 'Get-HvLabDumpInfo.ps1')) {
            $text = [System.IO.File]::ReadAllText((Join-Path $root "guest\$name"))
            Assert-HvLabTrue ($text.Contains($literal)) "$name prints its result line with the prefix $literal"
        }
    }
}
