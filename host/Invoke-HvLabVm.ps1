<#
.SYNOPSIS
    Starts, stops, turns off, pauses, resumes or queries the lab VM without
    elevation.

.DESCRIPTION
    Runs the on-demand task \HyperVLpeLab\<Lab>\<Action> that Install-HvLab.ps1
    registered, waits for it to finish, and returns the result the worker wrote
    to <InstallRoot>\<Lab>\state\<Action>.json.

    The task runs a fixed script with a fixed action; nothing is passed to it.
    Only the operator named at install can run the tasks. A result counts only
    when it has schema hvlab-result/1, names this lab and this action, and
    started after this script triggered the task.

    Exit codes:
      0    the VM is in the state the action asks for (Status: a state was read)
      1    the action did not reach that state, or the worker reported an error
      2    usage or config error
      3    the task is missing, this account may not run it, or Task
           Scheduler refused to start it
      75   the task is already running, or another Start, Stop, Pause or
           Resume of this lab is running
      124  no result within -TimeoutSec

.PARAMETER Action
    Start, Stop (guest shutdown), TurnOff (power off), Pause, Resume or Status.

.PARAMETER Lab
    Lab name. Default: Lab from the config file.

.PARAMETER ConfigPath
    Config file. Default: $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.
    Not needed when -Lab is given.

.PARAMETER InstallRoot
    Install root. Default: InstallRoot from the config file, or %ProgramData%\HyperVLpeLab.

.PARAMETER TimeoutSec
    Longest wait for the worker. The task itself stops after 10 minutes.

.PARAMETER AsJson
    Print the result as one JSON object instead of a PowerShell object.

.EXAMPLE
    .\Invoke-HvLabVm.ps1 -Action Status

.EXAMPLE
    .\Invoke-HvLabVm.ps1 -Lab lab1 -Action TurnOff -AsJson
#>
#Requires -Version 5.1
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][ValidateSet('Start', 'Stop', 'TurnOff', 'Pause', 'Resume', 'Status')][string]$Action,
    [string]$Lab,
    [string]$ConfigPath,
    [string]$InstallRoot,
    [ValidateRange(10, 900)][int]$TimeoutSec = 660,
    [switch]$AsJson
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

function Exit-HvLab {
    param([int]$Code, [string]$Message)
    if ($Message) { [Console]::Error.WriteLine("hvlab: $Message") }
    exit $Code
}

try {
    $target = Resolve-HvLabLifecycleTarget -Lab $Lab -ConfigPath $ConfigPath -InstallRoot $InstallRoot
}
catch {
    Exit-HvLab -Code 2 -Message $_.Exception.Message
}

$Lab = $target.Lab
$folderPath = $target.TaskFolder
$resultPath = $target.LabDirectory + '\state\' + $Action + '.json'
$logPath = $target.LabDirectory + '\logs\worker.log'
$taskRunning = 4

try {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder($folderPath)
    $task = $folder.GetTask($Action)
}
catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    $hr = $inner.HResult
    if ($hr -eq -2147024894) { Exit-HvLab -Code 3 -Message "Task $folderPath\$Action not found. Run Install-HvLab.ps1 for lab '$Lab' first (elevated)." }
    if ($hr -eq -2147024891) { Exit-HvLab -Code 3 -Message "Access to $folderPath\$Action denied. Only the operator account named at install may run it." }
    Exit-HvLab -Code 3 -Message "Cannot open task $folderPath\$Action`: $($_.Exception.Message)"
}

if ($task.State -eq $taskRunning) { Exit-HvLab -Code 75 -Message "Task $folderPath\$Action is already running. Try again when it ends." }

$triggeredUtc = [DateTime]::UtcNow
try {
    $null = $task.Run($null)
}
catch {
    # For example: the task is disabled, Task Scheduler is stopped, or the
    # run right was removed from the task.
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Exit-HvLab -Code 3 -Message ('Task {0}\{1} could not be started (0x{2:X8}): {3}' -f $folderPath, $Action, $inner.HResult, $inner.Message)
}

$watch = [System.Diagnostics.Stopwatch]::StartNew()
$result = $null
while ($watch.Elapsed.TotalSeconds -lt $TimeoutSec) {
    Start-Sleep -Milliseconds 500
    $task = $folder.GetTask($Action)
    $taskDone = ($task.State -ne $taskRunning)
    if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        try {
            $candidate = [System.IO.File]::ReadAllText($resultPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            $startedUtc = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $candidate -Name 'startedUtc')
            $fresh = ($null -ne $startedUtc -and $startedUtc -ge $triggeredUtc.AddSeconds(-2) -and
                $null -ne (Get-HvLabPropertyValue -Object $candidate -Name 'finishedUtc'))
            # Task paths and file names ignore case, so lab and action do too.
            $ours = ([string](Get-HvLabPropertyValue -Object $candidate -Name 'schema' -Default '') -ceq 'hvlab-result/1' -and
                [string](Get-HvLabPropertyValue -Object $candidate -Name 'lab' -Default '') -eq $Lab -and
                [string](Get-HvLabPropertyValue -Object $candidate -Name 'action' -Default '') -eq $Action)
            if ($fresh -and $ours) {
                $result = $candidate
                if ($taskDone) { break }
            }
        }
        catch {
            # The worker replaces the file in one step; a read that races it is retried.
            $result = $null
        }
    }
    $lastRunUtc = $task.LastRunTime.ToUniversalTime()
    if ($taskDone -and $lastRunUtc -ge $triggeredUtc.AddSeconds(-2) -and $null -eq $result -and $watch.Elapsed.TotalSeconds -gt 5) {
        Exit-HvLab -Code 1 -Message ('The task ended (result 0x{0:X8}) without writing a new result. See {1}.' -f
            $task.LastTaskResult, $logPath)
    }
}
if ($null -eq $result) { Exit-HvLab -Code 124 -Message "No result from $folderPath\$Action within $TimeoutSec s." }

$output = [pscustomobject]@{
    Lab         = $Lab
    Action      = $Action
    Ok          = ((Get-HvLabPropertyValue -Object $result -Name 'ok' -Default $false) -eq $true)
    Message     = Get-HvLabPropertyValue -Object $result -Name 'message' -Default ''
    VmName      = Get-HvLabPropertyValue -Object $result -Name 'vmName'
    StateBefore = Get-HvLabPropertyValue -Object $result -Name 'stateBefore'
    StateAfter  = Get-HvLabPropertyValue -Object $result -Name 'stateAfter'
    Heartbeat   = Get-HvLabPropertyValue -Object $result -Name 'heartbeat'
    UptimeSec   = Get-HvLabPropertyValue -Object $result -Name 'uptimeSec'
    IPv4        = @(Get-HvLabPropertyValue -Object $result -Name 'ipv4' -Default @())
    StartedUtc  = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $result -Name 'startedUtc')
    FinishedUtc = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $result -Name 'finishedUtc')
    TaskResult  = ('0x{0:X8}' -f $task.LastTaskResult)
}
if ($AsJson) { ConvertTo-Json -InputObject $output -Depth 3 -Compress } else { $output }
if ($output.Ok) { exit 0 }
if ((Get-HvLabPropertyValue -Object $result -Name 'busy' -Default $false) -eq $true) { exit 75 }
exit 1
