<#
.SYNOPSIS
    Runs the offline checks of this repository: parse, PSScriptAnalyzer and
    the Pester tests.

.DESCRIPTION
    1. Parses every .ps1, .psm1 and .psd1 file with the PowerShell parser of
       the shell that runs this script.
    2. Runs PSScriptAnalyzer with PSScriptAnalyzerSettings.psd1 when the
       module is installed: the newest installed version, or exactly
       -AnalyzerVersion. Without it the step is reported as skipped, or as
       failed with -RequireAnalyzer or -AnalyzerVersion.
    3. Runs the tests in this folder with the newest Pester installed
       (Pester 3.4, which ships with Windows, or Pester 5), or exactly
       -PesterVersion. Without Pester the step fails.

    Nothing here contacts a VM, the network or a system service, and nothing
    is written outside the Pester TestDrive (a folder under %TEMP%).

    Run it in both shells, because the host scripts target PowerShell 7 and
    the worker and guest helpers target Windows PowerShell 5.1:
      powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File tests\Invoke-HvLabChecks.ps1
      pwsh -NoProfile -File tests\Invoke-HvLabChecks.ps1

    Exit code 0 when every step passed (a step skipped with -SkipAnalyzer or
    -SkipPester, or a missing analyzer without -RequireAnalyzer or
    -AnalyzerVersion, does not count), 1 otherwise.

.PARAMETER SkipAnalyzer
    Do not run PSScriptAnalyzer.

.PARAMETER RequireAnalyzer
    Fail when PSScriptAnalyzer is not installed. The CI workflow uses it.

.PARAMETER AnalyzerVersion
    Use exactly this PSScriptAnalyzer version, and fail when it is not
    installed. The CI workflow passes the version it installs, so that
    another version on the runner image is not used instead.

.PARAMETER SkipPester
    Do not run the Pester tests.

.PARAMETER PesterVersion
    Use exactly this Pester version, and fail when it is not installed. The
    CI workflow passes the version it installs.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$SkipAnalyzer,
    [switch]$RequireAnalyzer,
    [version]$AnalyzerVersion,
    [switch]$SkipPester,
    [version]$PesterVersion
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-HvLabCheckModule {
    # The newest installed version of a module, or exactly -Version. Returns
    # nothing when there is none.
    param([Parameter(Mandatory)][string]$Name, [version]$Version)
    $found = @(Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending)
    if ($null -ne $Version) { $found = @($found | Where-Object { $_.Version -eq $Version }) }
    return ($found | Select-Object -First 1)
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$failed = $false
$summary = New-Object System.Collections.Generic.List[object]

$files = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { @('.ps1', '.psm1', '.psd1') -contains $_.Extension })
$parseErrors = 0
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($item in @($errors)) {
        $parseErrors++
        Write-Warning ('{0}:{1}: {2}' -f $file.FullName, $item.Extent.StartLineNumber, $item.Message)
    }
}
$summary.Add([pscustomobject]@{ Step = 'Parse'; Result = $(if ($parseErrors -eq 0) { 'passed' } else { 'failed' }); Detail = "$($files.Count) files, $parseErrors errors, PowerShell $($PSVersionTable.PSVersion)" })
if ($parseErrors -gt 0) { $failed = $true }

if ($SkipAnalyzer) {
    $summary.Add([pscustomobject]@{ Step = 'PSScriptAnalyzer'; Result = 'skipped'; Detail = '-SkipAnalyzer' })
}
else {
    $analyzer = Get-HvLabCheckModule -Name PSScriptAnalyzer -Version $AnalyzerVersion
    if ($null -eq $analyzer) {
        $result = 'skipped'
        if ($RequireAnalyzer -or $null -ne $AnalyzerVersion) {
            $result = 'failed'
            $failed = $true
        }
        $missing = 'module not installed'
        if ($null -ne $AnalyzerVersion) { $missing = "version $AnalyzerVersion not installed" }
        $summary.Add([pscustomobject]@{ Step = 'PSScriptAnalyzer'; Result = $result; Detail = "$missing (Install-Module PSScriptAnalyzer -Scope CurrentUser)" })
    }
    else {
        Import-Module $analyzer.Path -Force
        $findings = @(Invoke-ScriptAnalyzer -Path $root -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1'))
        foreach ($finding in $findings) {
            Write-Warning ('{0}:{1}: {2} {3}' -f $finding.ScriptPath, $finding.Line, $finding.RuleName, $finding.Message)
        }
        $summary.Add([pscustomobject]@{ Step = 'PSScriptAnalyzer'; Result = $(if ($findings.Count -eq 0) { 'passed' } else { 'failed' }); Detail = "PSScriptAnalyzer $($analyzer.Version): $($findings.Count) findings" })
        if ($findings.Count -gt 0) { $failed = $true }
    }
}

if ($SkipPester) {
    $summary.Add([pscustomobject]@{ Step = 'Pester'; Result = 'skipped'; Detail = '-SkipPester' })
}
else {
    $pester = Get-HvLabCheckModule -Name Pester -Version $PesterVersion
    if ($null -eq $pester) {
        $missing = 'module not installed'
        if ($null -ne $PesterVersion) { $missing = "version $PesterVersion not installed" }
        $summary.Add([pscustomobject]@{ Step = 'Pester'; Result = 'failed'; Detail = $missing })
        $failed = $true
    }
    else {
        Import-Module $pester.Path -Force
        if ($pester.Version.Major -ge 5) {
            $run = Invoke-Pester -Path $PSScriptRoot -PassThru -Output Detailed
            # Result is 'Failed' also when a BeforeAll block or a file fails.
            $pesterFailed = ($run.Result -ne 'Passed')
        }
        else {
            $run = Invoke-Pester -Script $PSScriptRoot -PassThru
            $pesterFailed = ($run.FailedCount -gt 0)
        }
        $summary.Add([pscustomobject]@{ Step = 'Pester'; Result = $(if ($pesterFailed) { 'failed' } else { 'passed' }); Detail = "Pester $($pester.Version): $($run.PassedCount) passed, $($run.FailedCount) failed" })
        if ($pesterFailed) { $failed = $true }
    }
}

$summary | Format-Table -AutoSize | Out-String -Width 200
if ($failed) { exit 1 }
exit 0
