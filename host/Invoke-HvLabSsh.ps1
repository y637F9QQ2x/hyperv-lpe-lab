<#
.SYNOPSIS
    Runs one command in the guest over key-based SSH, as the guest admin or as
    the guest standard user.

.DESCRIPTION
    -Role User signs in as UserAccount with UserKeyPath. -Role Admin signs in
    as AdminAccount with AdminKeyPath. The two keys are different files, so the
    user key cannot open an admin session even if an account name is mixed up.

    ssh.exe runs as the current (non-elevated) host account. It never prompts:
    BatchMode is on and password and keyboard-interactive authentication are
    off, so a missing or refused key fails at once with exit 255. Agent and
    X11 forwarding, port forwardings, LocalCommand and ProxyCommand are turned
    off on the command line, and -F none keeps ssh from reading any config
    file, so ~/.ssh/config cannot change them for the guest (docs\ssh.md).

    The command runs in the guest's OpenSSH default shell (cmd.exe unless it
    was changed). Pass it as one string; quoting inside it follows that shell.
    Its output is passed through unchanged, as ssh prints it.

    -ShowContext signs in as the role and reports the session: account,
    integrity level, logon type, session id, groups, privileges, Developer
    Mode, and the stored host key fingerprint. Groups are read by SID and
    privileges by name, so the report does not depend on the guest's display
    language. For -Role User, every group and every privilege must be one that
    a standard-user token of a Windows client edition has by default; for
    -Role Admin, the session must be elevated and in Administrators. It exits
    4 when the session does not fit the role.

    -WithContext adds the same report to a -Command run. It first checks the
    role in its own SSH session, and does not run the command when that check
    fails. Then it runs the report and the command in one SSH session, so the
    report describes the sign-in that ran the command.

    -ShowContext and -WithContext need cmd.exe as the guest's OpenSSH default
    shell, which is the Windows default. The report comes from whoami in the
    guest, so it is only as trustworthy as the guest; take it on a guest that
    has not yet run untrusted code.

    Exit codes:
      any  the guest command's own exit code; Windows exit codes are 32-bit
      255  ssh failed, or the guest command itself returned 255; a warning
           says which of the two is more likely
      1    -ShowContext or -WithContext could not read the report, or
           -ResetHostKey failed
      2    usage or config error; nothing ran in the guest
      4    -ShowContext or -WithContext: the session does not fit the role
    When the script sets 1, 2 or 4 itself, it first writes a line that starts
    with 'hvlab:' to stderr. Without such a line, the code is the guest
    command's. When the parameters do not bind, ssh does not run: pwsh -File
    exits 1, and in an open session $LASTEXITCODE keeps its previous value.

.PARAMETER Role
    Admin or User.

.PARAMETER Command
    The command line to run in the guest.

.PARAMETER WithContext
    With -Command: check the role first, then run the session report and the
    command in one SSH session.

.PARAMETER ShowContext
    Report the SSH session of the role instead of running a command.

.PARAMETER ResetHostKey
    Remove the guest's entry from the lab known_hosts file (after a guest
    rebuild). Then connect once with -TrustNewHostKey.

.PARAMETER ConfigPath
    Config file. Default: $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.

.PARAMETER TrustNewHostKey
    Accept and store the guest host key if none is stored yet
    (StrictHostKeyChecking=accept-new). A changed key is still refused. Verify
    the stored fingerprint afterwards; -ShowContext prints it.

.PARAMETER AsJson
    With -ShowContext or -WithContext, print the report as one JSON line.

.EXAMPLE
    .\Invoke-HvLabSsh.ps1 -Role User -ShowContext -TrustNewHostKey

.EXAMPLE
    .\Invoke-HvLabSsh.ps1 -Role User -Command 'C:\lab\poc.exe' -WithContext
#>
#Requires -Version 7.3
[CmdletBinding(DefaultParameterSetName = 'Command', PositionalBinding = $false)]
param(
    [Parameter(Mandatory, ParameterSetName = 'Command')]
    [Parameter(Mandatory, ParameterSetName = 'Context')]
    [ValidateSet('Admin', 'User')]
    [string]$Role,

    [Parameter(Mandatory, ParameterSetName = 'Command')]
    [string]$Command,

    [Parameter(ParameterSetName = 'Command')]
    [switch]$WithContext,

    [Parameter(Mandatory, ParameterSetName = 'Context')]
    [switch]$ShowContext,

    [Parameter(Mandatory, ParameterSetName = 'ResetHostKey')]
    [switch]$ResetHostKey,

    [string]$ConfigPath,

    [switch]$TrustNewHostKey,

    [Parameter(ParameterSetName = 'Command')]
    [Parameter(ParameterSetName = 'Context')]
    [switch]$AsJson
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

if ($AsJson -and $PSCmdlet.ParameterSetName -eq 'Command' -and -not $WithContext) {
    Exit-HvLab -Code 2 -Message '-AsJson needs -ShowContext or -WithContext.'
}

try {
    $config = Get-HvLabConfig -Path $ConfigPath
    if (-not $ResetHostKey) { Assert-HvLabSshPrerequisite -Config $config -Role $Role }
    $ssh = Get-HvLabOpenSshTool -Name ssh
}
catch {
    Exit-HvLab -Code 2 -Message $_.Exception.Message
}

function Get-HvLabStoredHostKey {
    # SHA256 fingerprints of the guest's entry in the lab known_hosts file.
    $keygen = Get-HvLabOpenSshTool -Name ssh-keygen
    $entry = Get-HvLabKnownHostsEntry -Config $config
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($line in @(& $keygen -l -F $entry -f $config.KnownHostsPath 2>$null)) {
        if ($line -match '(SHA256:[A-Za-z0-9+/=]+)') { $found.Add($Matches[1]) }
    }
    return $found.ToArray()
}

function ConvertTo-HvLabContextReport {
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [AllowNull()][AllowEmptyString()][string]$Problem,
        [AllowEmptyCollection()][string[]]$HostKey = @()
    )
    return [pscustomobject]@{
        Role                  = $Role
        Account               = $Context.Account
        Sid                   = $Context.Sid
        IntegrityLevel        = $Context.IntegrityLevel
        Elevated              = $Context.Elevated
        LogonType             = $Context.LogonType
        SessionId             = $Context.SessionId
        DeveloperMode         = $Context.DeveloperMode
        NonStandardGroups     = @($Context.NonStandardGroups)
        NonStandardPrivileges = @($Context.NonStandardPrivileges)
        Privileges            = @($Context.Privileges)
        Groups                = @($Context.Groups)
        FitsRole              = (-not $Problem)
        Problem               = $Problem
        HostKey               = @($HostKey)
    }
}

function Write-HvLabReport {
    param([Parameter(Mandatory)][psobject]$Report)
    if ($AsJson) { ConvertTo-Json -InputObject $Report -Depth 3 -Compress } else { $Report }
    if ($Role -eq 'User' -and $Report.DeveloperMode -eq $true) {
        Write-Warning ('Developer Mode is on in the guest, so a standard user can create symbolic links without ' +
            'SeCreateSymbolicLinkPrivilege. State this with any proof that uses symbolic links.')
    }
}

function Get-HvLabSessionContext {
    # Runs the session report alone, in its own SSH session.
    param([switch]$Trust)
    $arguments = @(Get-HvLabSshArgument -Config $config -Role $Role -TrustNewHostKey:$Trust) + @('--', $config.GuestAddress, (Get-HvLabContextCommand))
    $lines = @(& $ssh @arguments)
    $code = $LASTEXITCODE
    if ($code -eq 255) {
        Exit-HvLab -Code 255 -Message 'ssh exit 255: the connection, the host key or the key was refused (docs\ssh.md, Exit code 255).'
    }
    $context = ConvertFrom-HvLabContextOutput -Line $lines
    if ($null -eq $context) {
        Exit-HvLab -Code 1 -Message ("the guest did not return the session report (ssh exit $code). It needs cmd.exe as the guest's " +
            "OpenSSH default shell (docs\ssh.md, What an SSH session is).")
    }
    return $context
}

function Write-HvLabExit255Warning {
    # ssh returns 255 for its own failures and passes on the guest command's
    # code otherwise, so a second connection tells the two cases apart.
    $probe = @(Get-HvLabSshArgument -Config $config -Role $Role) + @('--', $config.GuestAddress, 'exit 0')
    $null = & $ssh @probe 2>$null
    if ($LASTEXITCODE -eq 255) {
        Write-Warning ('ssh exit 255, and a second connection failed too: the connection, the host key or the key was refused, ' +
            'so nothing is known about the guest command. Check the VM state (Invoke-HvLabVm.ps1 -Action Status), the guest ' +
            'address, the host key (-ResetHostKey after a rebuild) and the key setup (docs\ssh.md, Exit code 255).')
    }
    else {
        Write-Warning 'ssh exit 255, but a second connection with the same key succeeded, so the 255 most likely came from the guest command.'
    }
}

if ($ResetHostKey) {
    $entry = Get-HvLabKnownHostsEntry -Config $config
    if (Test-Path -LiteralPath $config.KnownHostsPath -PathType Leaf) {
        $keygen = Get-HvLabOpenSshTool -Name ssh-keygen
        & $keygen -R $entry -f $config.KnownHostsPath
        if ($LASTEXITCODE -ne 0) { Exit-HvLab -Code 1 -Message "ssh-keygen -R failed (exit $LASTEXITCODE) for $($config.KnownHostsPath)." }
    }
    "Removed '$entry' from $($config.KnownHostsPath). Connect once with -ShowContext -TrustNewHostKey and compare the fingerprint with the guest's (docs\ssh.md, Host key)."
    exit 0
}

if ($ShowContext) {
    $context = Get-HvLabSessionContext -Trust:$TrustNewHostKey
    $problem = Get-HvLabRoleProblem -Context $context -Role $Role
    Write-HvLabReport -Report (ConvertTo-HvLabContextReport -Context $context -Problem $problem -HostKey @(Get-HvLabStoredHostKey))
    if ($problem) { Exit-HvLab -Code 4 -Message $problem }
    exit 0
}

if ($WithContext) {
    $gate = Get-HvLabSessionContext -Trust:$TrustNewHostKey
    $gateProblem = Get-HvLabRoleProblem -Context $gate -Role $Role
    if ($gateProblem) { Exit-HvLab -Code 4 -Message "$gateProblem. The command was not run." }
    # Read before the run, so that no other program starts while ssh runs.
    $hostKey = @(Get-HvLabStoredHostKey)

    $state = @{ InReport = $true; Lines = New-Object System.Collections.Generic.List[string]; Context = $null }
    $remote = (Get-HvLabContextCommand) + ' & ' + $Command
    $arguments = @(Get-HvLabSshArgument -Config $config -Role $Role) + @('--', $config.GuestAddress, $remote)
    & $ssh @arguments | ForEach-Object {
        if (-not $state.InReport) {
            $_
        }
        else {
            $state.Lines.Add([string]$_)
            if (Test-HvLabContextEndLine -Line ([string]$_)) {
                $state.InReport = $false
                $state.Context = ConvertFrom-HvLabContextOutput -Line $state.Lines.ToArray()
                if ($null -ne $state.Context) {
                    $runReport = ConvertTo-HvLabContextReport -Context $state.Context -Problem (Get-HvLabRoleProblem -Context $state.Context -Role $Role) -HostKey $hostKey
                    Write-HvLabReport -Report $runReport
                }
            }
        }
    }
    $code = $LASTEXITCODE
    if ($state.InReport) {
        # The end of the report never arrived, so the command may not have run.
        foreach ($line in $state.Lines) { $line }
        if ($code -eq 255) { Exit-HvLab -Code 255 -Message 'ssh exit 255 before the session report ended; the command most likely did not run (docs\ssh.md, Exit code 255).' }
        Exit-HvLab -Code 1 -Message "the session report did not end (ssh exit $code), so it is not known whether the command ran."
    }
    $runProblem = 'the session report of this run could not be read'
    if ($null -ne $state.Context) { $runProblem = Get-HvLabRoleProblem -Context $state.Context -Role $Role }
    if ($code -eq 255) { Write-HvLabExit255Warning }
    if ($runProblem) { Exit-HvLab -Code 4 -Message "$runProblem. The command ran in this session and returned $code." }
    exit $code
}

$arguments = @(Get-HvLabSshArgument -Config $config -Role $Role -TrustNewHostKey:$TrustNewHostKey) + @('--', $config.GuestAddress, $Command)
& $ssh @arguments
$code = $LASTEXITCODE
if ($code -eq 255) { Write-HvLabExit255Warning }
exit $code
