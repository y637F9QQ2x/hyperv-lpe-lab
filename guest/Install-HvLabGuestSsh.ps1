<#
.SYNOPSIS
    Sets up key-based SSH in the guest for the admin key and one standard
    account. Run inside the guest, elevated.

.DESCRIPTION
    Run this in the guest (at the VM console, or in another admin session) in
    an elevated Windows PowerShell. It changes only the guest.

      1. With -InstallOpenSshServer, adds the OpenSSH Server optional feature
         (this needs Windows Update or another feature source).
      2. Sets the sshd service to start automatically and starts it.
      3. Makes sure the inbound firewall rule OpenSSH-Server-In-TCP (TCP 22)
         exists and is enabled, and sets its remote address to -AllowFrom.
         Only with -AllowAnyAddress does it accept every address, with a
         warning.
      4. Adds the admin public key to
         %ProgramData%\ssh\administrators_authorized_keys. With the default
         sshd_config, sshd uses this file for every member of Administrators
         and ignores their per-user authorized_keys.
      5. Adds the user public key to <StandardUser profile>\.ssh\authorized_keys.
      6. Sets the owner and ACL that Windows OpenSSH requires, and reads them
         back (docs\ssh.md):
           administrators_authorized_keys: owner Administrators; access for
             SYSTEM and Administrators only; no inherited entries.
           authorized_keys: owner the user; access for the user, SYSTEM and
             Administrators only; no inherited entries.
      7. Refuses a StandardUser that is directly in a privileged local group,
         and warns when sshd_config lacks the default Match Group
         administrators block.

    Key files are written as UTF-8 without a byte order mark, one key per
    line, LF line endings. Keys already in the files are kept.

    It does not create accounts, set passwords, edit sshd_config, or change
    UAC, Microsoft Defender or any other protection. The check in step 7 is a
    first filter; Invoke-HvLabSsh.ps1 -ShowContext on the host checks the
    groups and privileges that the SSH session reports.

.PARAMETER AdminPublicKey
    The admin public key: the text of the .pub file, or a path to it.

.PARAMETER StandardUser
    The local standard account used for standard-user proofs. It must exist
    and must have signed in once, so that its profile folder exists.

.PARAMETER UserPublicKey
    The standard user's public key: the text of the .pub file, or a path to
    it. It must differ from the admin key.

.PARAMETER AllowFrom
    The remote address or prefix that the TCP 22 firewall rule accepts,
    normally the host's address on the lab virtual switch. Required unless
    -AllowAnyAddress is given.

.PARAMETER AllowAnyAddress
    Accept SSH from every address that can reach the guest, instead of
    -AllowFrom. The script warns when it is used.

.PARAMETER InstallOpenSshServer
    Add the OpenSSH Server optional feature first.

.EXAMPLE
    .\Install-HvLabGuestSsh.ps1 -AdminPublicKey .\hvlab_admin_ed25519.pub -StandardUser labuser -UserPublicKey .\hvlab_user_ed25519.pub -AllowFrom 192.0.2.1
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Scoped', PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$AdminPublicKey,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')][string]$StandardUser,
    [Parameter(Mandatory)][string]$UserPublicKey,
    [Parameter(Mandatory, ParameterSetName = 'Scoped')][ValidatePattern('^[0-9A-Fa-f:.]+(/\d{1,3})?$')][string]$AllowFrom,
    [Parameter(Mandatory, ParameterSetName = 'AnyAddress')][switch]$AllowAnyAddress,
    [switch]$InstallOpenSshServer
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sidSystem = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$sidAdministrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$privilegedGroups = @{
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-578' = 'Hyper-V Administrators'
}

function Resolve-HvLabPublicKey {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Label)
    $text = $Value
    if (Test-Path -LiteralPath $Value -PathType Leaf) {
        $text = @([System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Value).ProviderPath) | Where-Object { $_.Trim() }) | Select-Object -First 1
    }
    $text = ([string]$text).Trim()
    $pattern = '^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [ -~]*)?$'
    if ($text -notmatch $pattern) { throw "$Label is not one OpenSSH public key line (type, base64 and an optional comment)." }
    return $text
}

function Get-HvLabKeyBody {
    param([string]$Line)
    $parts = $Line.Trim() -split '\s+'
    if ($parts.Count -ge 2) { return ($parts[0] + ' ' + $parts[1]) }
    return $Line.Trim()
}

function Add-HvLabAuthorizedKey {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Key)
    $lines = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        # ReadAllLines honours a byte order mark, so a file written as UTF-16 by
        # Out-File is read correctly and rewritten as UTF-8 below.
        foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
            if ($line.Trim()) { $lines.Add($line.TrimEnd()) }
        }
    }
    $body = Get-HvLabKeyBody -Line $Key
    $present = @($lines | Where-Object { (Get-HvLabKeyBody -Line $_) -ceq $body }).Count -gt 0
    if (-not $present) { $lines.Add($Key) }
    $text = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
    return (-not $present)
}

function Set-HvLabKeyFileAcl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$Owner,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier[]]$Allowed
    )
    if (-not $PSCmdlet.ShouldProcess($Path, 'Set owner and ACL')) { return }
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $Allowed) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
        $security.AddAccessRule($rule)
    }
    # The .NET API writes only the DACL that was built here; Set-Acl may also
    # try to write the owner or the audit list and fail.
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]
    if ($null -ne $extensions) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($Path), $security)
    }
    else {
        [System.IO.File]::SetAccessControl($Path, $security)
    }
    # Giving ownership to another account needs a privilege that icacls
    # enables and the .NET API does not.
    $output = & icacls.exe $Path /setowner ('*' + $Owner.Value) 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for ${Path}: $($output -join ' ')" }
}

function Get-HvLabKeyFileProblem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][string[]]$AllowedSids
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $OwnerSid) { $problems.Add("owner is $owner, expected $OwnerSid") }
    if (-not $acl.AreAccessRulesProtected) { $problems.Add('it still inherits permissions') }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($AllowedSids -notcontains $rule.IdentityReference.Value) {
            $problems.Add("extra entry for $($rule.IdentityReference.Value)")
        }
    }
    return $problems.ToArray()
}

# Input checks.
$adminKey = Resolve-HvLabPublicKey -Value $AdminPublicKey -Label 'AdminPublicKey'
$userKey = Resolve-HvLabPublicKey -Value $UserPublicKey -Label 'UserPublicKey'
if ((Get-HvLabKeyBody -Line $adminKey) -ceq (Get-HvLabKeyBody -Line $userKey)) {
    throw 'AdminPublicKey and UserPublicKey are the same key. Use two key pairs, so the user key cannot open an admin session.'
}
try {
    $userSid = ([System.Security.Principal.NTAccount]::new($StandardUser)).Translate([System.Security.Principal.SecurityIdentifier])
}
catch {
    throw "Account '$StandardUser' not found in the guest. Create it first (for example with New-LocalUser) and sign in once."
}
foreach ($groupSid in $privilegedGroups.Keys) {
    $group = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='$groupSid'"
    if ($null -eq $group) { continue }
    $members = @(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser)
    if (@($members | Where-Object { $_.SID -eq $userSid.Value }).Count -gt 0) {
        throw "'$StandardUser' is a member of $($privilegedGroups[$groupSid]). A standard-user proof needs an account outside the privileged groups."
    }
}
$profileInfo = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($userSid.Value)'"
if ($null -eq $profileInfo -or -not $profileInfo.LocalPath) {
    throw "'$StandardUser' has no profile yet. Sign in once as $StandardUser at the VM console, then run this script again."
}
$userHome = [string]$profileInfo.LocalPath

if (-not $PSCmdlet.ShouldProcess("guest $env:COMPUTERNAME", "Set up key-based SSH for Administrators and $StandardUser")) { return }

# 1-3. Service and firewall.
if ($InstallOpenSshServer -and -not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    $null = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
}
if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    throw 'The sshd service is not installed. Run again with -InstallOpenSshServer, or add OpenSSH Server in Settings, Optional features.'
}
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
$firewallRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if ($null -eq $firewallRule) {
    $null = New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' -Enabled True `
        -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
else {
    # An existing rule can be disabled; sshd is then unreachable (ssh exit 255).
    Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'
}
$firewallScope = 'Any'
if ($AllowFrom) { $firewallScope = $AllowFrom }
Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -RemoteAddress $firewallScope
if ($AllowAnyAddress) {
    Write-Warning 'SSH to this guest is now allowed from every address that can reach it. Prefer -AllowFrom <host address on the lab switch>.'
}
$firewallProfile = [string](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP').Profile

# 4-6. Key files.
$sshFolder = Join-Path $env:ProgramData 'ssh'
$adminFile = Join-Path $sshFolder 'administrators_authorized_keys'
$adminAdded = Add-HvLabAuthorizedKey -Path $adminFile -Key $adminKey
Set-HvLabKeyFileAcl -Path $adminFile -Owner $sidAdministrators -Allowed @($sidSystem, $sidAdministrators)

$userSshFolder = Join-Path $userHome '.ssh'
if (-not (Test-Path -LiteralPath $userSshFolder -PathType Container)) { $null = New-Item -ItemType Directory -Path $userSshFolder }
$userFile = Join-Path $userSshFolder 'authorized_keys'
$userAdded = Add-HvLabAuthorizedKey -Path $userFile -Key $userKey
Set-HvLabKeyFileAcl -Path $userFile -Owner $userSid -Allowed @($userSid, $sidSystem, $sidAdministrators)

# 7. Read back and check.
$problems = New-Object System.Collections.Generic.List[string]
foreach ($item in @(Get-HvLabKeyFileProblem -Path $adminFile -OwnerSid 'S-1-5-32-544' -AllowedSids @('S-1-5-18', 'S-1-5-32-544'))) {
    $problems.Add("${adminFile}: $item")
}
foreach ($item in @(Get-HvLabKeyFileProblem -Path $userFile -OwnerSid $userSid.Value -AllowedSids @($userSid.Value, 'S-1-5-18', 'S-1-5-32-544'))) {
    $problems.Add("${userFile}: $item")
}
if ($problems.Count -gt 0) { throw ("Key file ACL check failed:`n  " + ($problems -join "`n  ")) }

$configPath = Join-Path $sshFolder 'sshd_config'
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    $sshdConfig = [System.IO.File]::ReadAllText($configPath)
    if ($sshdConfig -notmatch '(?im)^\s*Match\s+Group\s+administrators\s*$' -or
        $sshdConfig -notmatch '(?im)^\s*AuthorizedKeysFile\s+__PROGRAMDATA__/ssh/administrators_authorized_keys\s*$') {
        Write-Warning "sshd_config has no default 'Match Group administrators' block. Admin keys may be read from a different file; see docs\ssh.md."
    }
    if ($sshdConfig -match '(?im)^\s*PubkeyAuthentication\s+no\s*$') {
        Write-Warning 'sshd_config sets PubkeyAuthentication no. Key sign-in will fail until that line is removed.'
    }
}

[pscustomobject]@{
    AdminKeyFile    = $adminFile
    AdminKeyAdded   = $adminAdded
    UserKeyFile     = $userFile
    UserKeyAdded    = $userAdded
    StandardUser    = $StandardUser
    FirewallScope   = $firewallScope
    FirewallProfile = $firewallProfile
    Next            = 'On the host: Invoke-HvLabSsh.ps1 -Role User -ShowContext -TrustNewHostKey, then the same with -Role Admin.'
}
