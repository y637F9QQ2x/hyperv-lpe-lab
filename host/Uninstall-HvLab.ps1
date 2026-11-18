<#
.SYNOPSIS
    Removes what Install-HvLab.ps1 created for one lab. Run elevated.

.DESCRIPTION
    Deletes the tasks in \HyperVLpeLab\<Lab>\ and that task folder, the
    firewall rule HyperVLpeLab-<Lab>-KDNET, and the folder <InstallRoot>\<Lab>
    (unless -KeepFiles). The root task folder is removed when no other lab
    uses it, and the install root when it is empty after the lab folder was
    removed. The VM and the guest are not touched.

    Before it changes anything, it checks that <InstallRoot>\<Lab> is a lab
    folder that Install-HvLab.ps1 created for this lab: its install.json must
    have schema hvlab-install/1 and name this lab (case-sensitive), this
    folder and this install root, and the folder must contain no link or
    junction and be changeable only by SYSTEM and Administrators. Otherwise it
    stops and changes nothing, so a mistyped -Lab or -InstallRoot cannot
    delete another folder.

.PARAMETER Lab
    The lab name used at install.

.PARAMETER InstallRoot
    The install root used at install. Default: %ProgramData%\HyperVLpeLab.

.PARAMETER KeepFiles
    Keep the lab folder (worker, results and logs). Tasks and the firewall
    rule are still removed, and the lab folder is not checked.

.EXAMPLE
    .\Uninstall-HvLab.ps1 -Lab lab1
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$Lab,
    [string]$InstallRoot = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HyperVLpeLab'),
    [switch]$KeepFiles
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

if (-not (Test-HvLabName -Name $Lab)) { throw "Lab '$Lab' must be 1 to 32 letters, digits or hyphens." }
$InstallRoot = $InstallRoot.TrimEnd('\')
$problem = Get-HvLabInstallRootProblem -Path $InstallRoot
if ($problem) { throw "InstallRoot '$InstallRoot': $problem." }
$labDirectory = $InstallRoot + '\' + $Lab
$labTaskPath = Get-HvLabTaskFolderPath -Lab $Lab
$ruleName = "HyperVLpeLab-$Lab-KDNET"

$deleteFolder = (-not $KeepFiles) -and (Test-Path -LiteralPath $labDirectory)
if ($deleteFolder) {
    $problems = @(Get-HvLabInstalledLabProblem -LabDirectory $labDirectory -Lab $Lab -InstallRoot $InstallRoot)
    if ($problems.Count -gt 0) {
        throw ("Nothing was removed. '$labDirectory' is not a lab folder that Install-HvLab.ps1 created for lab '$Lab':`n  " +
            ($problems -join "`n  ") + "`nCheck -Lab and -InstallRoot. To remove only the tasks and the firewall rule, add -KeepFiles.")
    }
}

$what = "tasks in $labTaskPath, firewall rule $ruleName"
if ($deleteFolder) { $what += ", folder $labDirectory and everything in it" }
if (-not $PSCmdlet.ShouldProcess("lab '$Lab' ($what)", 'Remove')) { return }

$removed = New-Object System.Collections.Generic.List[string]

# Tasks and task folders.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
foreach ($item in @(Remove-HvLabTaskFolder -Service $service -Lab $Lab -Confirm:$false)) { $removed.Add($item) }

# Firewall rule.
$rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($null -ne $rule) {
    $rule | Remove-NetFirewallRule
    $removed.Add("firewall rule $ruleName")
}

# Files. The check above found no reparse point, so the recursive delete stays
# inside the lab folder.
if ($deleteFolder) {
    Remove-Item -LiteralPath $labDirectory -Recurse -Force
    $removed.Add("folder $labDirectory")
    if ((Test-Path -LiteralPath $InstallRoot -PathType Container) -and @(Get-ChildItem -LiteralPath $InstallRoot -Force).Count -eq 0) {
        Remove-Item -LiteralPath $InstallRoot -Force
        $removed.Add("folder $InstallRoot")
    }
}

[pscustomobject]@{
    Lab     = $Lab
    Removed = $removed.ToArray()
}
