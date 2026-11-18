<#
.SYNOPSIS
    Guest helper for Get-HvLabCrashDump.ps1: lists crash dumps, stages one for
    copying, and removes the staged copy.

.DESCRIPTION
    Runs in the guest as the admin account, uploaded and started by the host.
    It reads the crash dump settings and dump files, and writes only to
    %USERPROFILE%\hvlab-stage of the account that runs it (and deletes its own
    uploaded copy).

    List     Crash dump settings, the newest minidumps (up to 20), the full
             dump file if present, and the last boot time.
    Stage    Make the chosen dump readable from the home folder as
             hvlab-stage\<name> (a hard link when the dump is on the profile
             volume, otherwise a copy) and return its SHA-256.
    Cleanup  Delete hvlab-stage\<name>, and the folder when it is empty.

    If Cleanup does not run (for example because the connection broke), the
    staged hard link or copy stays in hvlab-stage. A hard link keeps the
    dump's disk space in use after Windows deletes the original. Delete
    %USERPROFILE%\hvlab-stage of the admin account to free it.

    It uses New-Object for .NET types, so it does not run in Constrained
    Language Mode (for example under a WDAC or AppLocker policy that enforces
    it).

    The result is one line on stdout: 'HVLAB-RESULT ' followed by base64 of
    UTF-8 JSON. Exit code 0 on success, 1 on error.

    When started from a file named hvlab-<32 hex>.ps1 (the upload name), the
    script deletes that file before it exits.

.PARAMETER Mode
    List, Stage or Cleanup.

.PARAMETER Kind
    Stage: Minidump (default) or Full.

.PARAMETER Name
    Stage with Minidump, and Cleanup: the file name.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('List', 'Stage', 'Cleanup')][string]$Mode = 'List',
    [ValidateSet('Minidump', 'Full')][string]$Kind = 'Minidump',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')][string]$Name
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-HvLabResult {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 5 -Compress
    'HVLAB-RESULT ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
}

function Get-HvLabRegistryValue {
    param([string]$Path, [string]$ValueName, [object]$Default)
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $Default }
    $property = $item.PSObject.Properties[$ValueName]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-HvLabDumpSetting {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $miniDir = [Environment]::ExpandEnvironmentVariables([string](Get-HvLabRegistryValue -Path $key -ValueName 'MinidumpDir' -Default '%SystemRoot%\Minidump'))
    $dumpFile = [Environment]::ExpandEnvironmentVariables([string](Get-HvLabRegistryValue -Path $key -ValueName 'DumpFile' -Default '%SystemRoot%\MEMORY.DMP'))
    return [ordered]@{
        crashDumpEnabled = [int](Get-HvLabRegistryValue -Path $key -ValueName 'CrashDumpEnabled' -Default -1)
        autoReboot       = [int](Get-HvLabRegistryValue -Path $key -ValueName 'AutoReboot' -Default -1)
        minidumpDir      = $miniDir
        dumpFile         = $dumpFile
    }
}

$stageDirectory = Join-Path $env:USERPROFILE 'hvlab-stage'
$code = 1
try {
    $settings = Get-HvLabDumpSetting
    switch ($Mode) {
        'List' {
            $minidumps = @()
            if (Test-Path -LiteralPath $settings.minidumpDir -PathType Container) {
                $minidumps = @(Get-ChildItem -LiteralPath $settings.minidumpDir -Filter '*.dmp' -File -Force |
                        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20 | ForEach-Object {
                            [ordered]@{ name = $_.Name; sizeBytes = $_.Length; lastWriteUtc = $_.LastWriteTimeUtc.ToString('o') }
                        })
            }
            $full = $null
            if (Test-Path -LiteralPath $settings.dumpFile -PathType Leaf) {
                $item = Get-Item -LiteralPath $settings.dumpFile -Force
                $full = [ordered]@{ name = $item.Name; sizeBytes = $item.Length; lastWriteUtc = $item.LastWriteTimeUtc.ToString('o') }
            }
            Write-HvLabResult -Data ([ordered]@{
                    ok          = $true
                    settings    = $settings
                    minidumps   = $minidumps
                    full        = $full
                    lastBootUtc = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
                })
        }
        'Stage' {
            if ($Kind -eq 'Full') {
                $source = $settings.dumpFile
            }
            else {
                if (-not $Name -or $Name -notmatch '\.dmp$') { throw 'Stage of a minidump needs -Name <file>.dmp' }
                $source = Join-Path $settings.minidumpDir $Name
            }
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "dump not found: $source" }
            $item = Get-Item -LiteralPath $source -Force
            if ($item.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw "unexpected dump file name '$($item.Name)'" }
            if (-not (Test-Path -LiteralPath $stageDirectory -PathType Container)) { $null = New-Item -ItemType Directory -Path $stageDirectory }
            $target = Join-Path $stageDirectory $item.Name
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
            $method = 'hardlink'
            try {
                $null = New-Item -ItemType HardLink -Path $target -Value $item.FullName
            }
            catch {
                $method = 'copy'
                $drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($stageDirectory))
                if ($drive.AvailableFreeSpace -lt $item.Length) { throw "not enough free space in $stageDirectory to copy $($item.Length) bytes" }
                Copy-Item -LiteralPath $item.FullName -Destination $target
            }
            $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            Write-HvLabResult -Data ([ordered]@{
                    ok           = $true
                    stagedPath   = 'hvlab-stage/' + $item.Name
                    name         = $item.Name
                    sha256       = $hash
                    sizeBytes    = $item.Length
                    lastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
                    method       = $method
                })
        }
        'Cleanup' {
            if (-not $Name) { throw 'Cleanup needs -Name' }
            $target = Join-Path $stageDirectory $Name
            if (Test-Path -LiteralPath $target -PathType Leaf) { Remove-Item -LiteralPath $target -Force }
            if ((Test-Path -LiteralPath $stageDirectory -PathType Container) -and
                @(Get-ChildItem -LiteralPath $stageDirectory -Force).Count -eq 0) {
                Remove-Item -LiteralPath $stageDirectory -Force
            }
            Write-HvLabResult -Data ([ordered]@{ ok = $true; removed = $Name })
        }
    }
    $code = 0
}
catch {
    Write-HvLabResult -Data ([ordered]@{ ok = $false; error = $_.Exception.Message })
    $code = 1
}

if ($PSCommandPath -and (Split-Path -Leaf $PSCommandPath) -match '^hvlab-[0-9a-f]{32}\.ps1$') {
    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}
exit $code
