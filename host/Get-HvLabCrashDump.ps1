<#
.SYNOPSIS
    Copies the newest guest crash dump (or a chosen one) to the host and checks
    its SHA-256.

.DESCRIPTION
    Uses the guest admin account over SSH and the helper
    guest\Get-HvLabDumpInfo.ps1:
      1. Lists the guest's crash dump settings, minidumps and full dump.
      2. Stages the chosen dump in the admin's home folder (a hard link when
         possible, otherwise a copy) and hashes it in the guest. The staged
         name and size must match the listed dump.
      3. Copies it with scp to <Destination>\<name>.part, stops the copy if
         the file grows past the size the guest reported, hashes it on the
         host, and renames it only when the two hashes match.
      4. Removes the staged file in the guest.

    The guest is untrusted: names, sizes, hashes and paths it returns are
    checked against strict patterns, and control characters in printed values
    are replaced.

    The host file is named <Lab>-<guest LastWriteTime UTC>-<dump name>. An
    existing file with the same name is kept when its hash matches, and is
    never overwritten.

    The newest dump is not necessarily from your last step: compare
    GuestLastWriteUtc with the time of that step. A dump can take a while to
    appear after the guest restarts.

    Exit codes: 0 copied (or listed), 2 usage or config error, 3 nothing to
    copy or not enough free space on the host, 255 ssh failed, 1 any other
    failure (guest helper error, unexpected guest data, copy failure, hash
    mismatch).

.PARAMETER Destination
    Host folder for dumps, on a local drive. Default: DumpDirectory from the
    config file.

.PARAMETER Full
    Copy the full dump (MEMORY.DMP or the configured DumpFile) instead of a
    minidump.

.PARAMETER Name
    Copy this minidump instead of the newest one.

.PARAMETER ListOnly
    Print what the guest has and copy nothing.

.PARAMETER ConfigPath
    Config file. Default: $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.

.PARAMETER TrustNewHostKey
    Accept and store the guest host key on the first connection.

.EXAMPLE
    .\Get-HvLabCrashDump.ps1 -ListOnly

.EXAMPLE
    .\Get-HvLabCrashDump.ps1

.EXAMPLE
    .\Get-HvLabCrashDump.ps1 -Full
#>
#Requires -Version 7.3
[CmdletBinding(DefaultParameterSetName = 'Minidump', PositionalBinding = $false)]
param(
    [string]$Destination,
    [Parameter(ParameterSetName = 'Full')][switch]$Full,
    [Parameter(ParameterSetName = 'Minidump')][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.dmp$')][string]$Name,
    [Parameter(ParameterSetName = 'List')][switch]$ListOnly,
    [string]$ConfigPath,
    [switch]$TrustNewHostKey
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:PSNativeCommandArgumentPassing = 'Standard'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

function Exit-HvLab {
    param([int]$Code, [string]$Message)
    if ($Message) { [Console]::Error.WriteLine("hvlab: $Message") }
    exit $Code
}

function Invoke-HvLabDumpHelper {
    param([string[]]$Arguments, [switch]$Trust)
    $run = Invoke-HvLabGuestScript -Config $config -ScriptPath $helper -ScriptArgument $Arguments -TrustNewHostKey:$Trust
    if ($run.ExitCode -eq 255) { Exit-HvLab -Code 255 -Message "ssh exit 255 during $($run.Stage): the connection, the host key or the key was refused (docs\ssh.md, Exit code 255)." }
    if ($null -eq $run.Result) { Exit-HvLab -Code 1 -Message "The guest helper returned no result (stage $($run.Stage), exit $($run.ExitCode))." }
    if ((Get-HvLabPropertyValue -Object $run.Result -Name 'ok' -Default $false) -ne $true) {
        Exit-HvLab -Code 1 -Message "Guest helper error: $(ConvertTo-HvLabSafeText (Get-HvLabPropertyValue -Object $run.Result -Name 'error' -Default 'no error text'))"
    }
    return $run.Result
}

function ConvertTo-HvLabNumber {
    # A number from the guest: a whole number, or $null.
    param([AllowNull()][object]$Value)
    $number = [int64]0
    if ([int64]::TryParse([string]$Value, [ref]$number)) { return $number }
    return $null
}

function ConvertTo-HvLabDumpEntry {
    # One dump file from the guest's list, checked: a plain file name that
    # matches -Pattern, a size of 0 or more bytes, and a time. Returns $null
    # for anything else.
    param([AllowNull()][object]$Entry, [Parameter(Mandatory)][string]$Pattern)
    $entryName = [string](Get-HvLabPropertyValue -Object $Entry -Name 'name' -Default '')
    $size = ConvertTo-HvLabNumber (Get-HvLabPropertyValue -Object $Entry -Name 'sizeBytes')
    $written = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $Entry -Name 'lastWriteUtc')
    if ($entryName -notmatch $Pattern -or $null -eq $size -or $size -lt 0 -or $null -eq $written) { return $null }
    return [pscustomobject]@{ Name = $entryName; SizeBytes = $size; LastWriteUtc = $written }
}

try {
    $config = Get-HvLabConfig -Path $ConfigPath
    if (-not $Destination) { $Destination = $config.DumpDirectory } else { $Destination = Resolve-HvLabPath -Path $Destination }
    if ($Destination -notmatch '^[A-Za-z]:\\') { throw "Destination '$Destination' must be a folder on a local drive, so that its free space can be checked." }
    $helper = Join-Path (Split-Path -Parent $PSScriptRoot) 'guest\Get-HvLabDumpInfo.ps1'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "Guest helper '$helper' not found." }
}
catch {
    Exit-HvLab -Code 2 -Message $_.Exception.Message
}

$list = Invoke-HvLabDumpHelper -Arguments @('-Mode', 'List') -Trust:$TrustNewHostKey
$settings = Get-HvLabPropertyValue -Object $list -Name 'settings'
$minidumpDir = ConvertTo-HvLabSafeText (Get-HvLabPropertyValue -Object $settings -Name 'minidumpDir' -Default '')
$dumpFile = ConvertTo-HvLabSafeText (Get-HvLabPropertyValue -Object $settings -Name 'dumpFile' -Default '')
$rawMinidumps = @(Get-HvLabPropertyValue -Object $list -Name 'minidumps' -Default @())
$minidumps = @($rawMinidumps | ForEach-Object { ConvertTo-HvLabDumpEntry -Entry $_ -Pattern '^[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.dmp$' } |
        Where-Object { $null -ne $_ })
if ($minidumps.Count -lt $rawMinidumps.Count) {
    Write-Warning "$($rawMinidumps.Count - $minidumps.Count) minidump entries from the guest had an unexpected name, size or time and were skipped."
}
$rawFull = Get-HvLabPropertyValue -Object $list -Name 'full'
$fullDump = $null
if ($null -ne $rawFull) {
    $fullDump = ConvertTo-HvLabDumpEntry -Entry $rawFull -Pattern '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    if ($null -eq $fullDump) { Write-Warning 'The full dump entry from the guest had an unexpected name, size or time and was skipped.' }
}

if ($ListOnly) {
    [pscustomobject]@{
        CrashDumpEnabled = ConvertTo-HvLabNumber (Get-HvLabPropertyValue -Object $settings -Name 'crashDumpEnabled')
        AutoReboot       = ConvertTo-HvLabNumber (Get-HvLabPropertyValue -Object $settings -Name 'autoReboot')
        MinidumpDir      = $minidumpDir
        DumpFile         = $dumpFile
        Minidumps        = $minidumps
        Full             = $fullDump
        GuestLastBootUtc = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $list -Name 'lastBootUtc')
    }
    exit 0
}

if ($Full) {
    if ($null -eq $fullDump) { Exit-HvLab -Code 3 -Message "No full dump at $dumpFile." }
    $chosen = $fullDump
    $stageArguments = @('-Mode', 'Stage', '-Kind', 'Full')
}
else {
    if ($minidumps.Count -eq 0) { Exit-HvLab -Code 3 -Message "No minidump in $minidumpDir. Use -Full for the full dump, or -ListOnly." }
    if ($Name) {
        $chosen = @($minidumps | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if ($null -eq $chosen) { Exit-HvLab -Code 3 -Message "Minidump '$Name' is not among the newest $($minidumps.Count) in the guest." }
    }
    else {
        $chosen = $minidumps[0]
    }
    $stageArguments = @('-Mode', 'Stage', '-Kind', 'Minidump', '-Name', $chosen.Name)
}

if (-not (Test-Path -LiteralPath $Destination -PathType Container)) { $null = New-Item -ItemType Directory -Path $Destination -Force }
$drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($Destination))
if ($drive.AvailableFreeSpace -lt $chosen.SizeBytes) {
    Exit-HvLab -Code 3 -Message "Not enough free space on $($drive.Name) for $($chosen.SizeBytes) bytes."
}

$staged = Invoke-HvLabDumpHelper -Arguments $stageArguments
# The guest runs untrusted code during research; check what it returned before
# using it in a host file name or as a copy limit.
$stagedName = [string](Get-HvLabPropertyValue -Object $staged -Name 'name' -Default '')
$stagedHash = [string](Get-HvLabPropertyValue -Object $staged -Name 'sha256' -Default '')
$stagedPath = [string](Get-HvLabPropertyValue -Object $staged -Name 'stagedPath' -Default '')
$stagedSize = ConvertTo-HvLabNumber (Get-HvLabPropertyValue -Object $staged -Name 'sizeBytes')
$stagedWriteUtc = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $staged -Name 'lastWriteUtc')
$stagedMethod = [string](Get-HvLabPropertyValue -Object $staged -Name 'method' -Default '')
if ($stagedName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
    $stagedHash -cnotmatch '^[0-9a-f]{64}$' -or
    $stagedPath -cne ('hvlab-stage/' + $stagedName) -or
    @('hardlink', 'copy') -cnotcontains $stagedMethod -or
    $null -eq $stagedWriteUtc) {
    Exit-HvLab -Code 1 -Message 'The guest helper returned an unexpected staging result; nothing was copied.'
}
if ($stagedName -cne $chosen.Name -or $stagedSize -ne $chosen.SizeBytes) {
    $null = Invoke-HvLabGuestScript -Config $config -ScriptPath $helper -ScriptArgument @('-Mode', 'Cleanup', '-Name', $stagedName)
    Exit-HvLab -Code 1 -Message "The dump changed between listing and staging (listed $($chosen.Name), $($chosen.SizeBytes) bytes). Run again."
}
$stamp = $stagedWriteUtc.ToString('yyyyMMddTHHmmssZ')
$finalName = '{0}-{1}-{2}' -f $config.Lab, $stamp, $stagedName
$finalPath = Join-Path $Destination $finalName
$partName = "$finalName.part"
$partPath = Join-Path $Destination $partName

try {
    if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
        $existing = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing -ne $stagedHash) {
            Exit-HvLab -Code 1 -Message "$finalPath exists with a different SHA-256; it is not overwritten. Move it away and run again."
        }
        $reused = $true
    }
    else {
        $reused = $false
        if (Test-Path -LiteralPath $partPath) { Remove-Item -LiteralPath $partPath -Force }
        $copy = Copy-HvLabGuestFile -Config $config -RemotePath $stagedPath -LocalDirectory $Destination -LocalName $partName -MaxBytes $stagedSize
        if ($copy.Exceeded) {
            Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
            Exit-HvLab -Code 1 -Message "The guest sent more than the $stagedSize bytes it reported; the copy was stopped and deleted."
        }
        if ($copy.ExitCode -eq 255) { Exit-HvLab -Code 255 -Message 'scp exit 255: the connection, the host key or the key was refused (docs\ssh.md, Exit code 255).' }
        if ($copy.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $partPath -PathType Leaf)) { Exit-HvLab -Code 1 -Message "scp failed (exit $($copy.ExitCode))." }
        $hostHash = (Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hostHash -ne $stagedHash) {
            Exit-HvLab -Code 1 -Message "SHA-256 mismatch: guest $stagedHash, host $hostHash. The copy is kept as $partPath."
        }
        Move-Item -LiteralPath $partPath -Destination $finalPath
    }
}
finally {
    $null = Invoke-HvLabGuestScript -Config $config -ScriptPath $helper -ScriptArgument @('-Mode', 'Cleanup', '-Name', $stagedName)
}

[pscustomobject]@{
    Dump              = $finalPath
    Sha256            = $stagedHash
    SizeBytes         = $stagedSize
    Kind              = $(if ($Full) { 'Full' } else { 'Minidump' })
    GuestLastWriteUtc = $stagedWriteUtc
    GuestLastBootUtc  = ConvertTo-HvLabUtc -Value (Get-HvLabPropertyValue -Object $list -Name 'lastBootUtc')
    StagedBy          = $stagedMethod
    Reused            = $reused
}
exit 0
