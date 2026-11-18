<#
.SYNOPSIS
    Checks an installed lab from the operator's side. Run as the operator,
    not elevated.

.DESCRIPTION
    Changes nothing. The checks:
      - Every folder above the install root is owned by SYSTEM,
        Administrators or TrustedInstaller, is not a link, and gives nobody
        else the right to delete, rename or re-permission it.
      - No folder in the machine PATH lets another account add, delete or
        rename files.
      - The install root (that folder only) and the lab folder (with
        everything in it) are owned by SYSTEM or Administrators, do not
        inherit permissions, contain no links or junctions, and grant write,
        delete, permission or ownership rights to SYSTEM and Administrators
        only.
      - Creating a file in the lab folder fails for this account.
      - The installed worker is byte-identical to worker\HvLabWorker.ps1 in
        this copy of the repository, and matches the hash in install.json.
      - Each task runs as SYSTEM, has no trigger, runs the fixed worker command
        line, has no $(ArgN) placeholder, is enabled, and its security
        descriptor gives change rights to SYSTEM and Administrators only.
      - With -RunStatus, the Status task runs for this account and returns a
        fresh result.

    Exit codes: 0 all checks passed, 2 usage error or the shell is elevated,
    3 at least one check failed.

.PARAMETER Lab
    Lab name. Default: Lab from the config file.

.PARAMETER ConfigPath
    Config file. Default: $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.

.PARAMETER InstallRoot
    Install root. Default: InstallRoot from the config file, or %ProgramData%\HyperVLpeLab.

.PARAMETER RunStatus
    Also run the Status task through Invoke-HvLabVm.ps1.

.EXAMPLE
    .\Test-HvLabInstall.ps1 -Lab lab1 -RunStatus
#>
#Requires -Version 5.1
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Lab,
    [string]$ConfigPath,
    [string]$InstallRoot,
    [switch]$RunStatus
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('hvlab: this shell is elevated. Run this check as the operator account, not elevated.')
    exit 2
}

try {
    $target = Resolve-HvLabLifecycleTarget -Lab $Lab -ConfigPath $ConfigPath -InstallRoot $InstallRoot
}
catch {
    [Console]::Error.WriteLine("hvlab: $($_.Exception.Message)")
    exit 2
}

$checks = New-Object System.Collections.Generic.List[object]
function Add-HvLabCheck {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $checks.Add([pscustomobject]@{ Check = $Name; Ok = $Ok; Detail = $Detail })
}

$problems = @(Get-HvLabAncestorProblem -Path $target.InstallRoot)
$detail = 'only SYSTEM, Administrators and TrustedInstaller can replace them'
if ($problems.Count -gt 0) { $detail = $problems -join '; ' }
Add-HvLabCheck -Name 'Folders above the install root' -Ok ($problems.Count -eq 0) -Detail $detail

$problems = @(Get-HvLabSearchPathProblem -PathValue ([Environment]::GetEnvironmentVariable('Path', 'Machine')))
$detail = 'no folder lets another account add or replace files'
if ($problems.Count -gt 0) { $detail = $problems -join '; ' }
Add-HvLabCheck -Name 'Machine PATH folders' -Ok ($problems.Count -eq 0) -Detail $detail

if (-not (Test-Path -LiteralPath $target.InstallRoot -PathType Container)) {
    Add-HvLabCheck -Name 'Install root' -Ok $false -Detail "$($target.InstallRoot) not found or not readable"
}
else {
    $problems = @(Get-HvLabAclProblem -Path $target.InstallRoot -RequireProtected)
    $detail = 'only SYSTEM and Administrators can change it'
    if ($problems.Count -gt 0) { $detail = $problems -join '; ' }
    Add-HvLabCheck -Name 'Install root ACL' -Ok ($problems.Count -eq 0) -Detail $detail
}

$labDirectory = $target.LabDirectory
if (-not (Test-Path -LiteralPath $labDirectory -PathType Container)) {
    Add-HvLabCheck -Name 'Lab folder' -Ok $false -Detail "$labDirectory not found or not readable"
}
else {
    $problems = @(Get-HvLabAclProblem -Path $labDirectory -Recurse -RequireProtected)
    $detail = 'only SYSTEM and Administrators can change it'
    if ($problems.Count -gt 0) { $detail = $problems -join '; ' }
    Add-HvLabCheck -Name 'Lab folder ACL' -Ok ($problems.Count -eq 0) -Detail $detail

    $probe = Join-Path $labDirectory ('write-probe-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $stream = [System.IO.File]::Open($probe, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        $stream.Dispose()
        Remove-Item -LiteralPath $probe -Force
        Add-HvLabCheck -Name 'Write attempt' -Ok $false -Detail 'this account could create a file in the lab folder'
    }
    catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $denied = $inner -is [System.UnauthorizedAccessException]
        $detail = 'denied, as expected'
        if (-not $denied) { $detail = "unexpected error: $($inner.Message)" }
        Add-HvLabCheck -Name 'Write attempt' -Ok $denied -Detail $detail
    }

    $installedWorker = Join-Path $labDirectory 'HvLabWorker.ps1'
    $repoWorker = Join-Path $PSScriptRoot 'worker\HvLabWorker.ps1'
    $manifestPath = Join-Path $labDirectory 'install.json'
    if ((Test-Path -LiteralPath $installedWorker -PathType Leaf) -and (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $installedHash = (Get-FileHash -LiteralPath $installedWorker -Algorithm SHA256).Hash
        $repoHash = (Get-FileHash -LiteralPath $repoWorker -Algorithm SHA256).Hash
        $manifest = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        $manifestHash = [string]$manifest.files.'HvLabWorker.ps1'
        Add-HvLabCheck -Name 'Worker matches install.json' -Ok ($installedHash -eq $manifestHash) -Detail $installedHash
        $detail = 'identical'
        if ($installedHash -ne $repoHash) { $detail = 'differs from this copy; run Install-HvLab.ps1 again if you updated the repository' }
        Add-HvLabCheck -Name 'Worker matches repository' -Ok ($installedHash -eq $repoHash) -Detail $detail
    }
    else {
        Add-HvLabCheck -Name 'Worker files' -Ok $false -Detail 'HvLabWorker.ps1 or install.json is missing'
    }
}

$powerShellPath = Get-HvLabWindowsPowerShellPath
try {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder($target.TaskFolder)
    foreach ($action in Get-HvLabAction) {
        $name = "Task $($target.TaskFolder)\$action"
        try {
            $task = $folder.GetTask($action)
            $problems = @(Get-HvLabTaskXmlProblem -Xml $task.Xml -Action $action -LabDirectory $labDirectory -PowerShellPath $powerShellPath)
            $problems += @(Get-HvLabSddlProblem -Sddl ($task.GetSecurityDescriptor(4)))
            $detail = 'SYSTEM, on demand, fixed command line, change rights for SYSTEM and Administrators only'
            if ($problems.Count -gt 0) { $detail = $problems -join '; ' }
            Add-HvLabCheck -Name $name -Ok ($problems.Count -eq 0) -Detail $detail
        }
        catch {
            Add-HvLabCheck -Name $name -Ok $false -Detail $_.Exception.Message
        }
    }
}
catch {
    Add-HvLabCheck -Name 'Task folder' -Ok $false -Detail "$($target.TaskFolder): $($_.Exception.Message)"
}

if ($RunStatus) {
    $vmScript = Join-Path $PSScriptRoot 'Invoke-HvLabVm.ps1'
    $json = & $vmScript -Action Status -Lab $target.Lab -InstallRoot $target.InstallRoot -AsJson
    $code = $LASTEXITCODE
    $detail = "exit $code"
    if ($code -eq 0 -and $json) {
        $status = $json | ConvertFrom-Json
        $detail = "VM '$($status.VmName)' is $($status.StateAfter)"
    }
    Add-HvLabCheck -Name 'Status task run by this account' -Ok ($code -eq 0) -Detail $detail
}

$checks
if (@($checks | Where-Object { -not $_.Ok }).Count -gt 0) { exit 3 }
exit 0
