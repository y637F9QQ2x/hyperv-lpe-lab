# Offline tests for functions of the guest scripts. Only the named function
# definitions are taken from each script (by its syntax tree) and defined
# here; the rest of the script, which changes guest settings, never runs.
# Files are written only in the Pester TestDrive.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeAll variables with It blocks.')]
param()

Describe 'Guest helper functions' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        function Import-TestFunction {
            # Returns the text of the named function definitions in a script.
            param([string]$Path, [string[]]$Name)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Path).ProviderPath, [ref]$tokens, [ref]$parseErrors)
            foreach ($functionName in $Name) {
                $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
                if ($null -eq $definition) { throw "$functionName not found in $Path" }
                $definition.Extent.Text
            }
        }
        $kdnetHelper = Join-Path $PSScriptRoot '..\guest\Get-HvLabKdnetInfo.ps1'
        $sshSetup = Join-Path $PSScriptRoot '..\guest\Install-HvLabGuestSsh.ps1'
        foreach ($text in @(Import-TestFunction -Path $kdnetHelper -Name 'ConvertFrom-HvLabBcdText', 'Get-HvLabValue')) {
            . ([scriptblock]::Create($text))
        }
        foreach ($text in @(Import-TestFunction -Path $sshSetup -Name 'Resolve-HvLabPublicKey', 'Get-HvLabKeyBody', 'Add-HvLabAuthorizedKey')) {
            . ([scriptblock]::Create($text))
        }
        # Public key lines in the OpenSSH format. The base64 parts are filler,
        # not real keys.
        $keyOne = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFillerFillerFillerFillerFillerFillerFiller1 hvlab-admin'
        $keyTwo = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFillerFillerFillerFillerFillerFillerFiller2 hvlab-user'
    }

    It 'reads bcdedit values by name and keeps the first of duplicate names' {
        $lines = @(
            'Windows Boot Loader',
            '-------------------',
            'identifier              {current}',
            'device                  partition=C:',
            'debug                   Yes',
            'debug                   No',
            '',
            'key                     aaaa.bbbb.cccc.dddd',
            'debugtype               NET',
            'hostip                  192.0.2.1',
            'port                    50000   '
        )
        $values = ConvertFrom-HvLabBcdText -Lines $lines
        Assert-HvLabEqual 'Yes' (Get-HvLabValue -Table $values -Key 'debug') 'debug, first value wins'
        Assert-HvLabEqual 'NET' (Get-HvLabValue -Table $values -Key 'debugtype') 'debugtype'
        Assert-HvLabEqual '50000' (Get-HvLabValue -Table $values -Key 'port') 'port without trailing spaces'
        Assert-HvLabEqual 'partition=C:' (Get-HvLabValue -Table $values -Key 'device') 'value with punctuation'
        Assert-HvLabEqual $null (Get-HvLabValue -Table $values -Key 'busparams') 'missing value'
    }

    It 'accepts one public key line and refuses anything else' {
        Assert-HvLabEqual $keyOne (Resolve-HvLabPublicKey -Value "  $keyOne  " -Label 'test') 'trimmed key line'
        $file = Join-Path $TestDrive 'key.pub'
        [System.IO.File]::WriteAllText($file, "`r`n$keyTwo`r`n")
        Assert-HvLabEqual $keyTwo (Resolve-HvLabPublicKey -Value $file -Label 'test') 'first non-empty line of a .pub file'
        # The header of a private key file, built from two parts so that secret
        # scanners do not report this test file.
        $privateKeyHeader = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'
        foreach ($bad in @($privateKeyHeader, 'ssh-ed25519', 'ssh-dss AAAAB3NzaC1kc3M= old', 'not a key', "$keyOne`nssh-ed25519 AAAA second")) {
            Assert-HvLabThrow { Resolve-HvLabPublicKey -Value $bad -Label 'test' } "refuses '$bad'"
        }
        Assert-HvLabEqual 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFillerFillerFillerFillerFillerFillerFiller1' (Get-HvLabKeyBody -Line $keyOne) 'key body without the comment'
    }

    It 'merges a key into authorized_keys as UTF-8 without BOM, LF only, without duplicates' {
        $path = Join-Path $TestDrive 'authorized_keys'
        # Windows PowerShell 5.1 writes UTF-16 with a byte order mark when a key is added with > or Out-File.
        [System.IO.File]::WriteAllText($path, "$keyOne`r`n", [System.Text.Encoding]::Unicode)
        Assert-HvLabTrue (Add-HvLabAuthorizedKey -Path $path -Key $keyTwo) 'a new key is added'
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Assert-HvLabTrue ($bytes[0] -ne 0xFF -and $bytes[0] -ne 0xEF) 'no byte order mark'
        Assert-HvLabEqual 0 @($bytes | Where-Object { $_ -eq 13 -or $_ -eq 0 }).Count 'no CR and no UTF-16 zero bytes'
        Assert-HvLabEqual "$keyOne`n$keyTwo`n" ([System.Text.Encoding]::UTF8.GetString($bytes)) 'both keys, one per line'
        $sameKeyOtherComment = (Get-HvLabKeyBody -Line $keyTwo) + ' another comment'
        Assert-HvLabTrue (-not (Add-HvLabAuthorizedKey -Path $path -Key $sameKeyOtherComment)) 'the same key is not added twice'
        Assert-HvLabEqual "$keyOne`n$keyTwo`n" ([System.IO.File]::ReadAllText($path)) 'file unchanged by the duplicate'
    }
}
