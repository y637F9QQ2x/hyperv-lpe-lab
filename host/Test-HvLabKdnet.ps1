<#
.SYNOPSIS
    Checks that the guest and the host are set up for a KDNET kernel
    debugging session. Read-only.

.DESCRIPTION
    Guest side, as the guest admin through guest\Get-HvLabKdnetInfo.ps1:
      - the boot entry has debug Yes
      - dbgsettings: debugtype NET, port equal to KdnetPort, hostip equal to
        an IPv4 address of this host (or to -HostAddress)
      - the key equals the key in -KeyFile. Only a salted SHA-256 travels;
        the key itself is never sent in either direction.
      - the running boot has kernel debugging enabled, and whether a debugger
        is attached right now
      - Secure Boot and HVCI state (reported)

    Host side:
      - an enabled inbound allow rule covers UDP KdnetPort
      - which process, if any, holds UDP KdnetPort
      - kd.exe is present

    Not ready (exit 3) when: debug is not Yes, debugtype is not NET, port or
    hostip differ or are not plain values, the key differs, the running boot
    has debugging disabled, or no enabled inbound allow rule covers the port.
    Warnings only: no key file, a key file that accounts other than yours,
    SYSTEM and Administrators can read, a debugger is attached now, the port
    is held by a process, a block rule also covers the port, firewall rules
    cannot be read, kd.exe not found, Secure Boot on, HVCI running, bcdedit
    values in a language other than English.

    Values from the guest are checked against strict patterns, and control
    characters in them are replaced before they are printed.

    The firewall check reads the local rules (the default policy store), not
    rules from Group Policy. It does not evaluate profiles or rule precedence.

    Exit codes: 0 ready, 3 not ready, 2 usage or config error, 255 ssh
    failed, 1 the guest helper failed.

.PARAMETER KeyFile
    File whose first line is the KDNET key. Default: KdnetKeyFile from the
    config. Keep it readable by your account only; the script warns when it
    is not.

.PARAMETER HostAddress
    The IPv4 address the guest should send to. Default: any IPv4 address of
    this host.

.PARAMETER DebuggerPath
    Path to kd.exe. Default: the Debugging Tools for Windows folder of the
    Windows Kits, or kd.exe on PATH.

.PARAMETER ConfigPath
    Config file. Default: $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.

.PARAMETER TrustNewHostKey
    Accept and store the guest host key on the first connection.

.PARAMETER AsJson
    Print one JSON object.

.EXAMPLE
    .\Test-HvLabKdnet.ps1

.EXAMPLE
    .\Test-HvLabKdnet.ps1 -KeyFile ~\hvlab-kdnet.key -AsJson
#>
#Requires -Version 7.3
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$KeyFile,
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')][string]$HostAddress,
    [string]$DebuggerPath,
    [string]$ConfigPath,
    [switch]$TrustNewHostKey,
    [switch]$AsJson
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:PSNativeCommandArgumentPassing = 'Standard'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

try {
    $config = Get-HvLabConfig -Path $ConfigPath
    $port = $config.KdnetPort
    if ($KeyFile) { $KeyFile = Resolve-HvLabPath -Path $KeyFile } else { $KeyFile = $config.KdnetKeyFile }
    if ($KeyFile -and -not (Test-Path -LiteralPath $KeyFile -PathType Leaf)) { throw "Key file '$KeyFile' not found." }
    $helper = Join-Path (Split-Path -Parent $PSScriptRoot) 'guest\Get-HvLabKdnetInfo.ps1'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "Guest helper '$helper' not found." }
}
catch {
    [Console]::Error.WriteLine("hvlab: $($_.Exception.Message)")
    exit 2
}

$errors = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

if ($KeyFile) {
    foreach ($item in @(Get-HvLabSecretFileProblem -Path $KeyFile)) {
        $warnings.Add("Key file: $item. Fix: $(Get-HvLabSecretFileFix -Path $KeyFile)")
    }
}

# Guest side.
$nonceBytes = [byte[]]::new(16)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($nonceBytes) } finally { $rng.Dispose() }
$nonce = -join ($nonceBytes | ForEach-Object { $_.ToString('x2') })
$run = Invoke-HvLabGuestScript -Config $config -ScriptPath $helper -ScriptArgument @('-Nonce', $nonce) -TrustNewHostKey:$TrustNewHostKey
if ($run.ExitCode -eq 255) {
    [Console]::Error.WriteLine("hvlab: ssh exit 255 during $($run.Stage): the connection, the host key or the key was refused (docs\ssh.md, Exit code 255).")
    exit 255
}
if ($null -eq $run.Result -or (Get-HvLabPropertyValue -Object $run.Result -Name 'ok' -Default $false) -ne $true) {
    $reason = "no result (exit $($run.ExitCode))"
    if ($null -ne $run.Result) { $reason = ConvertTo-HvLabSafeText (Get-HvLabPropertyValue -Object $run.Result -Name 'error' -Default 'no error text') }
    [Console]::Error.WriteLine("hvlab: the guest helper failed: $reason")
    exit 1
}
# The guest may run untrusted code: every value below is checked against a
# pattern, and passes through ConvertTo-HvLabSafeText before it is printed.
$guest = $run.Result
$bootEntry = Get-HvLabPropertyValue -Object $guest -Name 'bootEntry'
$dbgsettings = Get-HvLabPropertyValue -Object $guest -Name 'dbgsettings'
$running = Get-HvLabPropertyValue -Object $guest -Name 'running'
$os = Get-HvLabPropertyValue -Object $guest -Name 'os'

$debug = ConvertTo-HvLabSafeText ([string](Get-HvLabPropertyValue -Object $bootEntry -Name 'debug' -Default ''))
if ($debug -eq 'No' -or -not $debug) {
    $errors.Add("Boot entry: debug is $(if ($debug) { $debug } else { 'not set' }). In the guest: bcdedit /debug on, then restart it.")
}
elseif ($debug -ne 'Yes') {
    $warnings.Add("Boot entry: debug is '$debug' (not English Yes or No). Check it by hand.")
}
$secureBoot = Get-HvLabPropertyValue -Object $guest -Name 'secureBoot'
if ($secureBoot -eq $true) {
    $warnings.Add('Secure Boot is on in the guest. If bcdedit refuses the debug settings, turn Secure Boot off in the VM settings.')
}

$debugType = ConvertTo-HvLabSafeText ([string](Get-HvLabPropertyValue -Object $dbgsettings -Name 'debugtype' -Default ''))
if ($debugType -notmatch '^[A-Za-z0-9]{1,16}$') {
    $errors.Add("dbgsettings: debugtype is not a plain value ('$debugType'). In the guest: bcdedit /dbgsettings net hostip:<host address> port:$port")
}
elseif ($debugType -ne 'NET') {
    $errors.Add("dbgsettings: debugtype is '$debugType', not NET. In the guest: bcdedit /dbgsettings net hostip:<host address> port:$port")
}
$guestPort = ConvertTo-HvLabSafeText ([string](Get-HvLabPropertyValue -Object $dbgsettings -Name 'port' -Default ''))
if ($guestPort -notmatch '^\d{1,5}$') { $errors.Add("dbgsettings: port is not a number ('$guestPort'), expected $port (KdnetPort in the config).") }
elseif ([int]$guestPort -ne $port) { $errors.Add("dbgsettings: port is $guestPort, expected $port (KdnetPort in the config).") }

$guestHostIp = ConvertTo-HvLabSafeText ([string](Get-HvLabPropertyValue -Object $dbgsettings -Name 'hostip' -Default ''))
$hostIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
if ($guestHostIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    $errors.Add("dbgsettings: hostip is not an IPv4 address ('$guestHostIp').")
}
elseif ($HostAddress) {
    if ($guestHostIp -ne $HostAddress) { $errors.Add("dbgsettings: hostip is '$guestHostIp', expected $HostAddress.") }
}
elseif ($hostIps -notcontains $guestHostIp) {
    $errors.Add("dbgsettings: hostip '$guestHostIp' is not an IPv4 address of this host.")
}

$keyMatch = $null
if ($KeyFile) {
    $keyText = ([string](Get-Content -LiteralPath $KeyFile -TotalCount 1)).Trim()
    $guestKeyHash = [string](Get-HvLabPropertyValue -Object $dbgsettings -Name 'keyHash' -Default '')
    if (-not $keyText) {
        $errors.Add('The key file is empty.')
        $keyMatch = $false
    }
    elseif (-not $guestKeyHash) {
        $errors.Add('dbgsettings: the guest has no key set.')
        $keyMatch = $false
    }
    elseif ($guestKeyHash -cnotmatch '^[0-9a-f]{64}$') {
        $errors.Add('dbgsettings: the guest returned a key hash that is not 64 hex characters.')
        $keyMatch = $false
    }
    else {
        $keyMatch = ((Get-HvLabKdnetKeyHash -Nonce $nonce -Key $keyText) -ceq $guestKeyHash)
        if (-not $keyMatch) {
            $caseOnly = ((Get-HvLabKdnetKeyHash -Nonce $nonce -Key $keyText.ToLowerInvariant()) -ceq $guestKeyHash) -or
                ((Get-HvLabKdnetKeyHash -Nonce $nonce -Key $keyText.ToUpperInvariant()) -ceq $guestKeyHash)
            if ($caseOnly) {
                $errors.Add('dbgsettings: the key file differs from the guest key in letter case only. Copy the key exactly as bcdedit /dbgsettings prints it.')
            }
            else {
                $errors.Add('dbgsettings: the guest key differs from the key file.')
            }
        }
    }
    $keyText = $null
}
else {
    $warnings.Add('The key was not compared: no -KeyFile and no KdnetKeyFile in the config.')
}

$kdEnabled = ((Get-HvLabPropertyValue -Object $running -Name 'kdEnabled' -Default $false) -eq $true)
$kdNotPresent = ((Get-HvLabPropertyValue -Object $running -Name 'kdNotPresent' -Default $true) -eq $true)
if (-not $kdEnabled -and $debug -eq 'Yes') {
    $errors.Add('The running boot has kernel debugging disabled. Restart the guest so the boot entry applies.')
}
$attached = ($kdEnabled -and -not $kdNotPresent)
if ($attached) { $warnings.Add('A kernel debugger is attached to the guest right now.') }
$hvciRunning = Get-HvLabPropertyValue -Object $guest -Name 'hvciRunning'
if ($hvciRunning -eq $true) { $warnings.Add('HVCI (memory integrity) is running in the guest.') }
$windows = ConvertTo-HvLabSafeText ('{0} {1} build {2}.{3}' -f (Get-HvLabPropertyValue -Object $os -Name 'ProductName'),
    (Get-HvLabPropertyValue -Object $os -Name 'DisplayVersion'), (Get-HvLabPropertyValue -Object $os -Name 'CurrentBuild'),
    (Get-HvLabPropertyValue -Object $os -Name 'UBR'))

# Host side.
$allowRules = @()
try {
    $filters = @(Get-NetFirewallPortFilter -Protocol UDP -ErrorAction Stop | Where-Object { Test-HvLabPortInList -PortList $_.LocalPort -Port $port })
    $rules = @($filters | Get-NetFirewallRule -ErrorAction Stop | Where-Object { "$($_.Enabled)" -eq 'True' -and "$($_.Direction)" -eq 'Inbound' })
    $allowRules = @($rules | Where-Object { "$($_.Action)" -eq 'Allow' } | ForEach-Object { $_.DisplayName })
    $blockRules = @($rules | Where-Object { "$($_.Action)" -eq 'Block' } | ForEach-Object { $_.DisplayName })
    if ($allowRules.Count -eq 0) {
        $errors.Add("No enabled inbound firewall rule allows UDP $port. Run Install-HvLab.ps1 with -KdnetPort $port (elevated), or add a rule.")
    }
    if ($blockRules.Count -gt 0) { $warnings.Add("Inbound block rules also cover UDP ${port}: $($blockRules -join ', ').") }
}
catch {
    $warnings.Add("Firewall rules could not be read: $($_.Exception.Message)")
}

$holders = @()
foreach ($endpoint in @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue)) {
    $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
    $processName = if ($null -ne $process) { $process.ProcessName } else { 'unknown' }
    $holders += "$processName (pid $($endpoint.OwningProcess))"
}
if ($holders.Count -gt 0) { $warnings.Add("UDP $port is in use on the host by: $($holders -join ', ').") }

$debugger = $null
if ($DebuggerPath) {
    if (Test-Path -LiteralPath $DebuggerPath -PathType Leaf) { $debugger = $DebuggerPath }
}
else {
    $candidates = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) { $candidates += (Join-Path $base 'Windows Kits\10\Debuggers\x64\kd.exe') }
    }
    $debugger = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }) | Select-Object -First 1
    if (-not $debugger) {
        $onPath = Get-Command kd.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $onPath) { $debugger = $onPath.Source }
    }
}
if (-not $debugger) { $warnings.Add('kd.exe not found. Install Debugging Tools for Windows, or pass -DebuggerPath.') }

$output = [pscustomobject]@{
    Ready    = ($errors.Count -eq 0)
    Errors   = $errors.ToArray()
    Warnings = $warnings.ToArray()
    Guest    = [pscustomobject]@{
        Debug            = $debug
        DebugType        = $debugType
        Port             = $guestPort
        HostIp           = $guestHostIp
        KeyMatch         = $keyMatch
        KdEnabled        = $kdEnabled
        DebuggerAttached = [bool]$attached
        SecureBoot       = $(if ($null -eq $secureBoot) { $null } else { $secureBoot -eq $true })
        HvciRunning      = $(if ($null -eq $hvciRunning) { $null } else { $hvciRunning -eq $true })
        Windows          = $windows
    }
    Host     = [pscustomobject]@{
        Port          = $port
        FirewallRules = $allowRules
        PortInUseBy   = $holders
        Debugger      = $debugger
    }
    Next     = "kd.exe -k net:port=$port,key=<key>"
}
if ($AsJson) { ConvertTo-Json -InputObject $output -Depth 4 -Compress } else { $output }
if ($output.Ready) { exit 0 }
exit 3
