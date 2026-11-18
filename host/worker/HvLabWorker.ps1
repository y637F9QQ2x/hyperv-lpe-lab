<#
.SYNOPSIS
    Fixed-action Hyper-V worker run by the hyperv-lpe-lab scheduled tasks.

.DESCRIPTION
    Install-HvLab.ps1 copies this file into the lab folder, which only SYSTEM
    and Administrators can change, and registers one task per action. Each task
    runs this file as SYSTEM with a fixed -Action value that is part of the task
    definition. The VM is selected by the Id in worker.json, which the installer
    writes next to this file in the same protected folder.

    The worker reads nothing that the operator account can write, and it acts
    on one VM with the six actions below only.

    Start    Start-VM when the VM is Off or Saved, wait for Running, then wait
             for a healthy heartbeat when the guest reports one.
    Stop     Ask the guest to shut down (Stop-VM -Force), wait for Off.
    TurnOff  Cut power (Stop-VM -TurnOff -Force), wait for Off.
    Pause    Suspend-VM when Running.
    Resume   Resume-VM when Paused.
    Status   Change nothing.

    Start, Stop, Pause and Resume hold an exclusive lock file in the lab folder
    (state\action.lock) while they run, so only one of them acts on the VM at
    a time; a second one waits up to 5 seconds and then reports busy. TurnOff
    takes no lock, so it can still end a Stop that waits for a hung guest.
    Status changes nothing and takes no lock.

    Each run writes state\<Action>.json and appends one line to logs\worker.log
    in the lab folder. Exit code 0 means the VM ended in the state the action
    asks for; 1 means it did not, or an error occurred.

    This file is self-contained and Windows PowerShell 5.1 compatible. It
    imports only the Hyper-V module. Before any command that can load a module
    runs, it sets PSModulePath to the Windows PowerShell module folder
    ($PSHOME\Modules) with a .NET call, so Hyper-V and the PowerShell modules
    that load on first use (such as Microsoft.PowerShell.Management) come from
    that folder only. A cmdlet such as Join-Path would load its own module
    through the inherited PSModulePath first. A test checks this order.

.PARAMETER Action
    The action. It is fixed in the task definition; the operator cannot pass it.
#>
[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'TurnOff', 'Pause', 'Resume', 'Status')]
    [string]$Action
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:WorkerVersion = 1
$script:StartTimeoutSec = 120
$script:HeartbeatTimeoutSec = 180
$script:ShutdownTimeoutSec = 300
$script:StateTimeoutSec = 60
$script:LockTimeoutSec = 5
$script:LogLimitBytes = 1MB

function Read-WorkerConfig {
    # Reads worker.json as the installer writes it: schema hvlab-worker/1 and
    # the keys lab, vmName and vmId, with exactly that casing. Any other key
    # is refused, as in the host config.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)
    $path = Join-Path $Directory 'worker.json'
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($raw -isnot [System.Management.Automation.PSCustomObject]) { throw 'worker.json does not hold one JSON object' }
    $values = @{}
    foreach ($property in $raw.PSObject.Properties) {
        if (@('schema', 'lab', 'vmName', 'vmId') -cnotcontains $property.Name) { throw "worker.json: unknown key '$($property.Name)'" }
        $values[$property.Name] = $property.Value
    }
    if ([string]$values['schema'] -cne 'hvlab-worker/1') { throw 'worker.json: schema is not hvlab-worker/1' }
    $id = [guid]::Empty
    if (-not [guid]::TryParse([string]$values['vmId'], [ref]$id)) { throw 'worker.json: vmId is not a GUID' }
    $name = [string]$values['vmName']
    if (-not $name) { throw 'worker.json: vmName is empty' }
    $lab = [string]$values['lab']
    if ($lab -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,31}$') { throw 'worker.json: lab is not a valid lab name' }
    return [pscustomobject]@{ VmId = $id; VmName = $name; Lab = $lab }
}

function Enter-WorkerLock {
    # Opens state\action.lock with no sharing. Returns the open file, or $null
    # when another run still holds it after -TimeoutSec. A file in the lab
    # folder is used rather than a named mutex, which any account on the host
    # could create first. The operator can read the lab folder, so it can hold
    # the file open too; that only makes its own actions report busy.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][int]$TimeoutSec
    )
    $stateDirectory = Join-Path $Directory 'state'
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $stateDirectory
    }
    $path = Join-Path $stateDirectory 'action.lock'
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try {
            return [System.IO.File]::Open($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSec) { return $null }
            Start-Sleep -Seconds 1
        }
    }
}

function Get-WorkerVm {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Config)
    $vm = Get-VM -Id $Config.VmId -ErrorAction Stop
    if ($null -eq $vm) { throw "no VM has Id $($Config.VmId)" }
    if ($vm.Name -cne $Config.VmName) {
        throw "the VM with Id $($Config.VmId) is now named '$($vm.Name)', not '$($Config.VmName)'; run Install-HvLab.ps1 again"
    }
    return $vm
}

function Get-WorkerVmInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Config)
    $vm = Get-WorkerVm -Config $Config
    $ipv4 = @()
    try {
        $ipv4 = @(Get-VMNetworkAdapter -VM $vm | ForEach-Object { $_.IPAddresses } |
                Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    }
    catch {
        # Addresses come from the guest (KVP); a guest without it reports none.
        $ipv4 = @()
    }
    $heartbeat = $null
    if ($null -ne $vm.Heartbeat) { $heartbeat = [string]$vm.Heartbeat }
    return [pscustomobject]@{
        State     = [string]$vm.State
        Heartbeat = $heartbeat
        UptimeSec = [int64]$vm.Uptime.TotalSeconds
        IPv4      = [string[]]$ipv4
    }
}

function Wait-WorkerVmState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][int]$TimeoutSec
    )
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if ([string](Get-WorkerVm -Config $Config).State -eq $State) { return $true }
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSec) { return $false }
        Start-Sleep -Seconds 2
    }
}

function Wait-WorkerHeartbeat {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][int]$TimeoutSec
    )
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $vm = Get-WorkerVm -Config $Config
        if ($null -eq $vm.Heartbeat) { return 'not reported' }
        $heartbeat = [string]$vm.Heartbeat
        if ($heartbeat -like 'Ok*') { return $heartbeat }
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSec) { return $heartbeat }
        Start-Sleep -Seconds 2
    }
}

function Invoke-WorkerAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'TurnOff', 'Pause', 'Resume', 'Status')][string]$Action,
        [Parameter(Mandatory)][psobject]$Config
    )
    $vm = Get-WorkerVm -Config $Config
    $before = [string]$vm.State
    $ok = $false
    $message = ''

    switch ($Action) {
        'Status' {
            $ok = $true
            $message = 'no change'
        }
        'Start' {
            if ($before -eq 'Running') {
                $ok = $true
                $message = 'already running'
            }
            elseif ($before -eq 'Off' -or $before -eq 'Saved') {
                Start-VM -VM $vm
                $ok = Wait-WorkerVmState -Config $Config -State 'Running' -TimeoutSec $StartTimeoutSec
                if ($ok) {
                    $heartbeat = Wait-WorkerHeartbeat -Config $Config -TimeoutSec $HeartbeatTimeoutSec
                    $message = "started; heartbeat $heartbeat"
                }
                else {
                    $message = "not Running after $StartTimeoutSec s"
                }
            }
            elseif ($before -eq 'Paused') {
                $message = 'the VM is paused; use Resume'
            }
            else {
                $message = "the VM is in state $before; try again when it settles"
            }
        }
        'Stop' {
            if ($before -eq 'Off') {
                $ok = $true
                $message = 'already off'
            }
            elseif ($before -eq 'Running') {
                $job = Stop-VM -VM $vm -Force -AsJob
                $finished = Wait-Job -Job $job -Timeout $ShutdownTimeoutSec
                if ($null -eq $finished) {
                    $message = "the guest did not finish shutting down within $ShutdownTimeoutSec s; use TurnOff"
                }
                else {
                    $jobErrors = @()
                    $null = Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErrors
                    Remove-Job -Job $job -Force
                    $ok = Wait-WorkerVmState -Config $Config -State 'Off' -TimeoutSec $StateTimeoutSec
                    if ($ok) { $message = 'shut down' }
                    elseif (@($jobErrors).Count -gt 0) { $message = "shutdown failed: $($jobErrors[0])" }
                    else { $message = 'the shutdown request ended but the VM is not Off' }
                }
            }
            else {
                $message = "the VM is in state $before; Stop needs a Running VM (TurnOff works in any state)"
            }
        }
        'TurnOff' {
            if ($before -eq 'Off') {
                $ok = $true
                $message = 'already off'
            }
            else {
                Stop-VM -VM $vm -TurnOff -Force
                $ok = Wait-WorkerVmState -Config $Config -State 'Off' -TimeoutSec $StateTimeoutSec
                if ($ok) { $message = 'turned off' } else { $message = "not Off after $StateTimeoutSec s" }
            }
        }
        'Pause' {
            if ($before -eq 'Paused') {
                $ok = $true
                $message = 'already paused'
            }
            elseif ($before -eq 'Running') {
                Suspend-VM -VM $vm
                $ok = Wait-WorkerVmState -Config $Config -State 'Paused' -TimeoutSec $StateTimeoutSec
                if ($ok) { $message = 'paused' } else { $message = "not Paused after $StateTimeoutSec s" }
            }
            else {
                $message = "the VM is in state $before; Pause needs a Running VM"
            }
        }
        'Resume' {
            if ($before -eq 'Running') {
                $ok = $true
                $message = 'already running'
            }
            elseif ($before -eq 'Paused') {
                Resume-VM -VM $vm
                $ok = Wait-WorkerVmState -Config $Config -State 'Running' -TimeoutSec $StateTimeoutSec
                if ($ok) { $message = 'resumed' } else { $message = "not Running after $StateTimeoutSec s" }
            }
            else {
                $message = "the VM is in state $before; Resume needs a Paused VM"
            }
        }
    }

    return [pscustomobject]@{
        Ok          = [bool]$ok
        Message     = $message
        StateBefore = $before
        Info        = (Get-WorkerVmInfo -Config $Config)
    }
}

function Write-WorkerResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result
    )
    $stateDirectory = Join-Path $Directory 'state'
    if (-not (Test-Path -LiteralPath $stateDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $stateDirectory
    }
    $json = ConvertTo-Json -InputObject $Result -Depth 4
    $final = Join-Path $stateDirectory "$Action.json"
    $temp = "$final.tmp"
    [System.IO.File]::WriteAllText($temp, $json, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $final -PathType Leaf) {
        # [NullString]::Value: PowerShell would pass $null as an empty string.
        [System.IO.File]::Replace($temp, $final, [NullString]::Value)
    }
    else {
        [System.IO.File]::Move($temp, $final)
    }
}

function Write-WorkerLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Line
    )
    $logDirectory = Join-Path $Directory 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $logDirectory
    }
    $log = Join-Path $logDirectory 'worker.log'
    if ((Test-Path -LiteralPath $log -PathType Leaf) -and (Get-Item -LiteralPath $log).Length -gt $LogLimitBytes) {
        $old = "$log.1"
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old -Force }
        [System.IO.File]::Move($log, $old)
    }
    [System.IO.File]::AppendAllText($log, $Line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-WorkerMain {
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Action)

    $started = [DateTime]::UtcNow
    $directory = $PSScriptRoot
    # Load modules from the Windows PowerShell folder only. The only command
    # that runs before this line is Set-StrictMode, which is part of the
    # engine. A cmdlet such as Join-Path would load its module through the
    # inherited PSModulePath, so the path is built with .NET.
    $env:PSModulePath = [System.IO.Path]::Combine($PSHOME, 'Modules')

    $result = [ordered]@{
        schema        = 'hvlab-result/1'
        workerVersion = $WorkerVersion
        action        = $Action
        # The lab folder is <InstallRoot>\<Lab>, so even a run that cannot read
        # worker.json reports its lab.
        lab           = (Split-Path -Leaf $directory)
        vmName        = $null
        vmId          = $null
        ok            = $false
        busy          = $false
        message       = ''
        stateBefore   = $null
        stateAfter    = $null
        heartbeat     = $null
        uptimeSec     = $null
        ipv4          = @()
        account       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        startedUtc    = $started.ToString('o')
        finishedUtc   = $null
    }
    $code = 1
    try {
        if (-not $Action) { throw 'no -Action given' }
        $config = Read-WorkerConfig -Directory $directory
        $result.lab = $config.Lab
        $result.vmName = $config.VmName
        $result.vmId = $config.VmId.ToString()
        Import-Module -Name Hyper-V -ErrorAction Stop
        $lock = $null
        if (@('Start', 'Stop', 'Pause', 'Resume') -contains $Action) {
            $lock = Enter-WorkerLock -Directory $directory -TimeoutSec $LockTimeoutSec
            if ($null -eq $lock) {
                $result.busy = $true
                throw 'another Start, Stop, Pause or Resume of this lab is running; try again when it ends'
            }
        }
        try {
            $outcome = Invoke-WorkerAction -Action $Action -Config $config
        }
        finally {
            if ($null -ne $lock) { $lock.Dispose() }
        }
        $result.ok = $outcome.Ok
        $result.message = $outcome.Message
        $result.stateBefore = $outcome.StateBefore
        $result.stateAfter = $outcome.Info.State
        $result.heartbeat = $outcome.Info.Heartbeat
        $result.uptimeSec = $outcome.Info.UptimeSec
        $result.ipv4 = @($outcome.Info.IPv4)
        if ($outcome.Ok) { $code = 0 }
    }
    catch {
        $result.message = "error: $($_.Exception.Message)"
    }
    $result.finishedUtc = [DateTime]::UtcNow.ToString('o')

    try {
        Write-WorkerResult -Directory $directory -Action $(if ($Action) { $Action } else { 'none' }) -Result $result
    }
    catch {
        $code = 1
    }
    try {
        $line = '{0} action={1} ok={2} before={3} after={4} message={5}' -f $result.finishedUtc, $result.action,
        $result.ok, $result.stateBefore, $result.stateAfter, $result.message
        Write-WorkerLog -Directory $directory -Line $line
    }
    catch {
        # The result file is the record the client reads; a log failure does not change the outcome.
        Write-Verbose "worker.log not written: $($_.Exception.Message)"
    }
    return $code
}

# Dot-sourcing (used by the offline tests) defines the functions and runs nothing.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-WorkerMain -Action $Action)
}
