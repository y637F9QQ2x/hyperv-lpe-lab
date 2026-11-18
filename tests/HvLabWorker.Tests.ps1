# Offline tests for host\worker\HvLabWorker.ps1.
#
# The worker is dot-sourced, which defines its functions and runs nothing.
# Every Hyper-V and job cmdlet it calls is replaced by a function defined here
# (functions take precedence over cmdlets), and each test checks that the
# replacement, not the real cmdlet, is what PowerShell resolves. No VM, no
# Hyper-V service and no network is contacted.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeAll variables with It blocks.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test replacements for Hyper-V cmdlets.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test replacements accept the parameters the worker passes.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Replacing these cmdlets keeps the tests offline.')]
param()

Describe 'Worker static rules' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        $workerPath = Join-Path $PSScriptRoot '..\host\worker\HvLabWorker.ps1'
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $workerPath).ProviderPath, [ref]$tokens, [ref]$parseErrors)
    }

    It 'parses without errors' {
        Assert-HvLabEqual 0 @($parseErrors).Count 'parse errors'
    }

    It 'accepts exactly the six actions' {
        $parameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Action' })[0]
        $set = @($parameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' })[0]
        $values = @($set.PositionalArguments | ForEach-Object { $_.Value })
        Assert-HvLabEqual ((Get-HvLabAction) -join ',') ($values -join ',') 'ValidateSet matches Get-HvLabAction'
        Assert-HvLabEqual 1 @($ast.ParamBlock.Parameters).Count 'no other parameter'
    }

    It 'loads no code other than the Hyper-V module' {
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
        $names = @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        foreach ($banned in @('Invoke-Expression', 'iex', 'Add-Type', 'Invoke-Command', 'Start-Process', 'Invoke-Item')) {
            Assert-HvLabTrue ($names -notcontains $banned) "does not call $banned"
        }
        $dotSourced = @($commands | Where-Object { $_.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot })
        Assert-HvLabEqual 0 $dotSourced.Count 'no dot-sourcing'
        $imports = @($commands | Where-Object { $_.GetCommandName() -eq 'Import-Module' })
        Assert-HvLabEqual 1 $imports.Count 'one Import-Module'
        Assert-HvLabTrue ($imports[0].Extent.Text -match "-Name Hyper-V\b") 'imports Hyper-V by name'
        $text = [System.IO.File]::ReadAllText((Resolve-Path $workerPath).ProviderPath)
        Assert-HvLabTrue ($text -notmatch 'HKCU:|EncodedCommand|DownloadString|Net\.WebClient') 'no per-user registry, no encoded or downloaded code'
    }

    It 'restricts the module path before any command that can load a module' {
        # A cmdlet such as Join-Path loads its module through the PSModulePath
        # that the task inherited, so no such command may run before the
        # assignment, and the new value must be built without one.
        $isCommand = { param($node) $node -is [System.Management.Automation.Language.CommandAst] }
        $assignments = @($ast.FindAll({ param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -eq '$env:PSModulePath' }, $true))
        Assert-HvLabEqual 1 $assignments.Count 'one assignment to PSModulePath'
        $assignment = $assignments[0]
        Assert-HvLabEqual "[System.IO.Path]::Combine(`$PSHOME, 'Modules')" $assignment.Right.Extent.Text 'the Windows PowerShell module folder, built with .NET'
        Assert-HvLabEqual 0 @($assignment.Right.FindAll($isCommand, $true)).Count 'no command builds the new value'

        $main = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-WorkerMain' }, $true)
        $statements = @($main.Body.EndBlock.Statements)
        $position = [array]::IndexOf($statements, $assignment)
        Assert-HvLabTrue ($position -ge 0) 'the assignment is a statement of Invoke-WorkerMain'
        for ($i = 0; $i -lt $position; $i++) {
            Assert-HvLabEqual 0 @($statements[$i].FindAll($isCommand, $true)).Count "Invoke-WorkerMain runs no command before it: $($statements[$i].Extent.Text)"
        }
        foreach ($paramBlock in @($ast.ParamBlock, $main.Body.ParamBlock)) {
            if ($null -ne $paramBlock) { Assert-HvLabEqual 0 @($paramBlock.FindAll($isCommand, $true)).Count 'no command in a param block' }
        }

        # Outside the functions, the script runs Set-StrictMode, which is part
        # of the engine and loads no module, and then Invoke-WorkerMain.
        $topLevel = @($ast.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] })
        $topCommands = @($topLevel | ForEach-Object { $_.FindAll($isCommand, $true) } | ForEach-Object { $_.GetCommandName() })
        Assert-HvLabEqual 'Set-StrictMode,Invoke-WorkerMain' ($topCommands -join ',') 'commands outside the functions'
        Assert-HvLabTrue ($null -eq $ast.BeginBlock -and $null -eq $ast.ProcessBlock -and $null -eq $ast.DynamicParamBlock) 'only an end block'
        Assert-HvLabTrue ($null -eq $ast.ScriptRequirements) 'no #Requires statement, which could load a module first'
        Assert-HvLabEqual 0 @($ast.UsingStatements).Count 'no using statement'
    }
}

Describe 'Worker actions' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Join-Path $PSScriptRoot '..\host\worker\HvLabWorker.ps1')

        function Get-VM {
            [CmdletBinding()]
            param([guid]$Id)
            [pscustomobject]@{
                Name      = $fake.Name
                Id        = $Id
                State     = $fake.State
                Heartbeat = $fake.Heartbeat
                Uptime    = [timespan]::FromSeconds(42)
            }
        }
        function Get-VMNetworkAdapter {
            [CmdletBinding()]
            param([object]$VM)
            [pscustomobject]@{ IPAddresses = @('192.0.2.10', 'fe80::10') }
        }
        function Start-VM {
            [CmdletBinding()]
            param([object]$VM)
            $fake.Calls.Add('Start-VM')
            $fake.State = 'Running'
        }
        function Stop-VM {
            [CmdletBinding()]
            param([object]$VM, [switch]$Force, [switch]$TurnOff, [switch]$AsJob)
            $fake.Calls.Add(('Stop-VM Force={0} TurnOff={1} AsJob={2}' -f [bool]$Force, [bool]$TurnOff, [bool]$AsJob))
            if ($TurnOff) { $fake.State = 'Off' }
            if ($AsJob) { return [pscustomobject]@{ Name = 'fake-job' } }
        }
        function Suspend-VM {
            [CmdletBinding()]
            param([object]$VM)
            $fake.Calls.Add('Suspend-VM')
            $fake.State = 'Paused'
        }
        function Resume-VM {
            [CmdletBinding()]
            param([object]$VM)
            $fake.Calls.Add('Resume-VM')
            $fake.State = 'Running'
        }
        function Wait-Job {
            [CmdletBinding()]
            param([object]$Job, [int]$Timeout)
            if ($fake.ShutdownCompletes) {
                $fake.State = 'Off'
                return $Job
            }
        }
        function Receive-Job {
            [CmdletBinding()]
            param([object]$Job)
        }
        function Remove-Job {
            [CmdletBinding()]
            param([object]$Job, [switch]$Force)
        }
        function Start-Sleep {
            [CmdletBinding()]
            param([int]$Seconds)
        }
        function Initialize-FakeVm {
            param([string]$State, [bool]$ShutdownCompletes = $true)
            return @{
                Name              = 'lab-vm'
                State             = $State
                Heartbeat         = 'OkApplicationsHealthy'
                ShutdownCompletes = $ShutdownCompletes
                Calls             = New-Object System.Collections.Generic.List[string]
            }
        }
        function Assert-WorkerStub {
            # Fail closed: never let a test reach a real Hyper-V cmdlet.
            foreach ($name in @('Get-VM', 'Get-VMNetworkAdapter', 'Start-VM', 'Stop-VM', 'Suspend-VM', 'Resume-VM', 'Wait-Job', 'Receive-Job', 'Remove-Job', 'Start-Sleep')) {
                if ([string](Get-Command -Name $name).CommandType -ne 'Function') { throw "$name is not replaced; stopping before the worker runs" }
            }
        }
        $config = [pscustomobject]@{ VmId = [guid]'11111111-2222-3333-4444-555555555555'; VmName = 'lab-vm'; Lab = 'lab1' }
    }

    It 'resolves every Hyper-V and job command to a test replacement' {
        foreach ($name in @('Get-VM', 'Get-VMNetworkAdapter', 'Start-VM', 'Stop-VM', 'Suspend-VM', 'Resume-VM', 'Wait-Job', 'Receive-Job', 'Remove-Job', 'Start-Sleep')) {
            Assert-HvLabEqual 'Function' ([string](Get-Command -Name $name).CommandType) "$name is replaced"
        }
    }

    It 'starts a VM that is off' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Off'
        $outcome = Invoke-WorkerAction -Action Start -Config $config
        Assert-HvLabTrue $outcome.Ok 'ok'
        Assert-HvLabEqual 'Start-VM' ($fake.Calls -join ';') 'calls'
        Assert-HvLabEqual 'Running' $outcome.Info.State 'state after'
        Assert-HvLabEqual '192.0.2.10' ($outcome.Info.IPv4 -join ',') 'IPv4 only'
    }

    It 'starts a VM that is saved' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Saved'
        $outcome = Invoke-WorkerAction -Action Start -Config $config
        Assert-HvLabTrue $outcome.Ok 'ok'
        Assert-HvLabEqual 'Start-VM' ($fake.Calls -join ';') 'calls'
    }

    It 'does nothing when the VM already runs' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Running'
        $outcome = Invoke-WorkerAction -Action Start -Config $config
        Assert-HvLabTrue $outcome.Ok 'ok'
        Assert-HvLabEqual 0 $fake.Calls.Count 'no calls'
    }

    It 'refuses to start a paused VM' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Paused'
        $outcome = Invoke-WorkerAction -Action Start -Config $config
        Assert-HvLabTrue (-not $outcome.Ok) 'not ok'
        Assert-HvLabEqual 0 $fake.Calls.Count 'no calls'
    }

    It 'shuts down through the guest for Stop' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Running'
        $outcome = Invoke-WorkerAction -Action Stop -Config $config
        Assert-HvLabTrue $outcome.Ok 'ok'
        Assert-HvLabEqual 'Stop-VM Force=True TurnOff=False AsJob=True' ($fake.Calls -join ';') 'graceful shutdown as a job'
    }

    It 'reports a shutdown that does not finish' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Running' -ShutdownCompletes $false
        $outcome = Invoke-WorkerAction -Action Stop -Config $config
        Assert-HvLabTrue (-not $outcome.Ok) 'not ok'
        Assert-HvLabTrue ($outcome.Message -match 'TurnOff') 'suggests TurnOff'
    }

    It 'cuts power for TurnOff' {
        Assert-WorkerStub
        foreach ($state in @('Paused', 'Running')) {
            $fake = Initialize-FakeVm -State $state
            $outcome = Invoke-WorkerAction -Action TurnOff -Config $config
            Assert-HvLabTrue $outcome.Ok "ok from $state"
            Assert-HvLabEqual 'Stop-VM Force=True TurnOff=True AsJob=False' ($fake.Calls -join ';') "turn off from $state"
        }
        $fake = Initialize-FakeVm -State 'Off'
        Assert-HvLabTrue (Invoke-WorkerAction -Action TurnOff -Config $config).Ok 'already off'
        Assert-HvLabEqual 0 $fake.Calls.Count 'no call when already off'
    }

    It 'pauses and resumes' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Running'
        Assert-HvLabTrue (Invoke-WorkerAction -Action Pause -Config $config).Ok 'pause ok'
        Assert-HvLabTrue (Invoke-WorkerAction -Action Resume -Config $config).Ok 'resume ok'
        Assert-HvLabEqual 'Suspend-VM;Resume-VM' ($fake.Calls -join ';') 'calls'
    }

    It 'changes nothing for Status' {
        Assert-WorkerStub
        foreach ($state in @('Off', 'Running', 'Paused', 'Saved')) {
            $fake = Initialize-FakeVm -State $state
            $outcome = Invoke-WorkerAction -Action Status -Config $config
            Assert-HvLabTrue $outcome.Ok "status ok in $state"
            Assert-HvLabEqual 0 $fake.Calls.Count "no calls in $state"
        }
    }

    It 'refuses a VM whose name no longer matches' {
        Assert-WorkerStub
        $fake = Initialize-FakeVm -State 'Off'
        $fake.Name = 'renamed-vm'
        Assert-HvLabThrow { Invoke-WorkerAction -Action Start -Config $config } 'name mismatch'
        Assert-HvLabEqual 0 $fake.Calls.Count 'no calls'
    }
}

Describe 'Worker files' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        . (Join-Path $PSScriptRoot '..\host\worker\HvLabWorker.ps1')
    }

    It 'reads a valid worker.json and refuses a bad one' {
        $good = Join-Path $TestDrive 'good'
        $null = New-Item -ItemType Directory -Path $good
        [System.IO.File]::WriteAllText((Join-Path $good 'worker.json'), '{"schema":"hvlab-worker/1","lab":"lab1","vmName":"lab-vm","vmId":"11111111-2222-3333-4444-555555555555"}')
        $config = Read-WorkerConfig -Directory $good
        Assert-HvLabEqual 'lab-vm' $config.VmName 'name'
        Assert-HvLabEqual 'lab1' $config.Lab 'lab'
        $cases = @(
            @{ Name = 'bad GUID'; Json = '{"schema":"hvlab-worker/1","lab":"lab1","vmName":"lab-vm","vmId":"not-a-guid"}' },
            @{ Name = 'no schema'; Json = '{"lab":"lab1","vmName":"lab-vm","vmId":"11111111-2222-3333-4444-555555555555"}' },
            @{ Name = 'other schema'; Json = '{"schema":"hvlab-worker/2","lab":"lab1","vmName":"lab-vm","vmId":"11111111-2222-3333-4444-555555555555"}' },
            @{ Name = 'other key casing'; Json = '{"schema":"hvlab-worker/1","Lab":"lab1","vmName":"lab-vm","vmId":"11111111-2222-3333-4444-555555555555"}' },
            @{ Name = 'unknown key'; Json = '{"schema":"hvlab-worker/1","lab":"lab1","vmName":"lab-vm","vmId":"11111111-2222-3333-4444-555555555555","path":"x"}' },
            @{ Name = 'not an object'; Json = '[1,2]' }
        )
        foreach ($case in $cases) {
            $bad = Join-Path $TestDrive ('bad-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $bad
            [System.IO.File]::WriteAllText((Join-Path $bad 'worker.json'), $case.Json)
            Assert-HvLabThrow { Read-WorkerConfig -Directory $bad } $case.Name
        }
    }

    It 'lets only one state-changing run hold the lock' {
        $folder = Join-Path $TestDrive 'lock'
        $null = New-Item -ItemType Directory -Path $folder
        $first = Enter-WorkerLock -Directory $folder -TimeoutSec 0
        try {
            Assert-HvLabTrue ($null -ne $first) 'first run gets the lock'
            Assert-HvLabEqual $null (Enter-WorkerLock -Directory $folder -TimeoutSec 0) 'second run is refused while the first holds it'
        }
        finally {
            if ($null -ne $first) { $first.Dispose() }
        }
        $again = Enter-WorkerLock -Directory $folder -TimeoutSec 0
        Assert-HvLabTrue ($null -ne $again) 'the lock is free again'
        $again.Dispose()
    }

    It 'writes the result file in one step and can replace it' {
        $folder = Join-Path $TestDrive 'result'
        $null = New-Item -ItemType Directory -Path $folder
        Write-WorkerResult -Directory $folder -Action 'Status' -Result ([ordered]@{ ok = $true; startedUtc = '2026-01-02T03:04:05.0000000Z' })
        Write-WorkerResult -Directory $folder -Action 'Status' -Result ([ordered]@{ ok = $false; startedUtc = '2026-01-02T03:04:06.0000000Z' })
        $read = [System.IO.File]::ReadAllText((Join-Path $folder 'state\Status.json')) | ConvertFrom-Json
        Assert-HvLabTrue (-not $read.ok) 'second write wins'
        Assert-HvLabEqual 0 @(Get-ChildItem -LiteralPath (Join-Path $folder 'state') -Filter '*.tmp').Count 'no temp file left'
    }
}
