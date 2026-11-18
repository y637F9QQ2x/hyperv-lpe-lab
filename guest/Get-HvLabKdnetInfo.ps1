<#
.SYNOPSIS
    Guest helper for Test-HvLabKdnet.ps1: reads the kernel debugger settings.

.DESCRIPTION
    Runs in the guest as the admin account, uploaded and started by the host.
    It changes nothing in the guest except deleting its own uploaded copy. It
    reports:
      - the boot entry ({current}): debug
      - bcdedit /dbgsettings: debugtype, hostip, port
      - for the running boot: whether kernel debugging is enabled and whether
        a debugger is attached (NtQuerySystemInformation class 35,
        SystemKernelDebuggerInformation)
      - Secure Boot, whether HVCI is running, and the Windows build

    The KDNET key never leaves the guest. The script returns only
    SHA-256(nonce bytes + UTF-8 key) in hex (Get-HvLabKeyHash), where the
    nonce is a fresh random value from the host; the host computes the same
    value from its copy of the key (Get-HvLabKdnetKeyHash in
    host\HvLab.Common.psm1) and compares.

    It uses Add-Type, so it does not run in Constrained Language Mode (for
    example under a WDAC or AppLocker policy that enforces it).

    bcdedit prints values in the guest's display language; Yes and No are
    recognized in English only. Other values are returned as they are.

    The result is one line on stdout: 'HVLAB-RESULT ' followed by base64 of
    UTF-8 JSON. When started from a file named hvlab-<32 hex>.ps1 (the upload
    name), the script deletes that file before it exits.

.PARAMETER Nonce
    32 lowercase hex characters from the host.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$Nonce
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-HvLabResult {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 5 -Compress
    'HVLAB-RESULT ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
}

function ConvertFrom-HvLabBcdText {
    param([string[]]$Lines)
    $values = @{}
    foreach ($line in @($Lines)) {
        if ($line -match '^\s*([A-Za-z][A-Za-z0-9]*)\s+(\S.*?)\s*$') {
            if (-not $values.ContainsKey($Matches[1])) { $values[$Matches[1]] = $Matches[2] }
        }
    }
    return $values
}

function Get-HvLabValue {
    param([hashtable]$Table, [string]$Key)
    if ($Table.ContainsKey($Key)) { return $Table[$Key] }
    return $null
}

function Get-HvLabKeyHash {
    # SHA-256(nonce bytes + UTF-8 key) as lowercase hex. The host function
    # Get-HvLabKdnetKeyHash has the same body; a test checks that they agree.
    param([Parameter(Mandatory)][string]$Nonce, [Parameter(Mandatory)][AllowEmptyString()][string]$Key)
    $nonceBytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $nonceBytes[$i] = [Convert]::ToByte($Nonce.Substring($i * 2, 2), 16) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([byte[]]($nonceBytes + [System.Text.Encoding]::UTF8.GetBytes($Key)))
        return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
    }
    finally {
        $sha.Dispose()
    }
}

$code = 1
try {
    $bcdLines = @(& bcdedit.exe /enum '{current}')
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /enum {current} failed with exit $LASTEXITCODE" }
    $bcd = ConvertFrom-HvLabBcdText -Lines $bcdLines

    $dbgLines = @(& bcdedit.exe /dbgsettings)
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings failed with exit $LASTEXITCODE" }
    $dbg = ConvertFrom-HvLabBcdText -Lines $dbgLines

    $keyHash = $null
    $key = Get-HvLabValue -Table $dbg -Key 'key'
    if ($key) { $keyHash = Get-HvLabKeyHash -Nonce $Nonce -Key ([string]$key) }
    $key = $null
    $dbg.Remove('key')

    if (-not ('HvLabKernelDebugger' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HvLabKernelDebugger
{
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, byte[] info, int length, out int returned);

    public static byte[] Query()
    {
        byte[] buffer = new byte[2];
        int returned;
        int status = NtQuerySystemInformation(35, buffer, buffer.Length, out returned);
        if (status != 0)
        {
            throw new InvalidOperationException("NtQuerySystemInformation(35) returned 0x" + status.ToString("X8"));
        }
        return buffer;
    }
}
'@
    }
    $kd = [HvLabKernelDebugger]::Query()

    $secureBoot = $null
    try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $null }

    $hvci = $null
    try {
        $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
        $hvci = @($guard.SecurityServicesRunning) -contains 2
    }
    catch {
        $hvci = $null
    }

    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $osInfo = [ordered]@{}
    foreach ($name in @('ProductName', 'DisplayVersion', 'CurrentBuild', 'UBR')) {
        $property = $os.PSObject.Properties[$name]
        $osInfo[$name] = if ($null -ne $property) { [string]$property.Value } else { $null }
    }

    Write-HvLabResult -Data ([ordered]@{
            ok          = $true
            bootEntry   = [ordered]@{
                debug = Get-HvLabValue -Table $bcd -Key 'debug'
            }
            dbgsettings = [ordered]@{
                debugtype = Get-HvLabValue -Table $dbg -Key 'debugtype'
                hostip    = Get-HvLabValue -Table $dbg -Key 'hostip'
                port      = Get-HvLabValue -Table $dbg -Key 'port'
                keyHash   = $keyHash
            }
            running     = [ordered]@{
                kdEnabled    = ($kd[0] -ne 0)
                kdNotPresent = ($kd[1] -ne 0)
            }
            secureBoot  = $secureBoot
            hvciRunning = $hvci
            os          = $osInfo
        })
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
