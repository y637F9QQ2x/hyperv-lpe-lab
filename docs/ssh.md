# SSH setup and pitfalls

Guest commands run over Windows OpenSSH with key authentication only. The
host scripts never prompt and never fall back to a password: `BatchMode=yes`,
`PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`,
`PreferredAuthentications=publickey` and `IdentitiesOnly=yes`.

The guest is untrusted, so every connection also sets `ForwardAgent=no`,
`ForwardX11=no`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`,
`ProxyCommand=none` (which also turns off `ProxyJump`), `UpdateHostKeys=no`
and `RequestTTY=no`. It also passes `-F none`, so ssh reads no config file:
neither `~\.ssh\config` nor the host-wide `%ProgramData%\ssh\ssh_config` can
add a setting for the guest, such as a `HostName`, an `IdentityFile` or a
forwarding. `GlobalKnownHostsFile` names the lab-only `KnownHostsPath` file
too, so the host-wide `%ProgramData%\ssh\ssh_known_hosts` is not read either.

## Two accounts, two keys

| Role | Guest account | Key | Guest file that holds the public key |
|---|---|---|---|
| Admin | a local administrator (`AdminAccount`) | `AdminKeyPath` | `%ProgramData%\ssh\administrators_authorized_keys` |
| User | a local standard user (`UserAccount`) | `UserKeyPath` | `<user profile>\.ssh\authorized_keys` |

The config loader refuses the same account or the same key file for both
roles, and the guest setup script refuses the same public key for both. With
separate keys, the user key cannot open an admin session, even if an account
name is mixed up in a command.

## Host side

Create the two key pairs as the operator:

```powershell
New-Item -ItemType Directory -Force "$HOME\.ssh"
ssh-keygen -t ed25519 -f "$HOME\.ssh\hvlab_admin_ed25519" -C hvlab-admin
ssh-keygen -t ed25519 -f "$HOME\.ssh\hvlab_user_ed25519" -C hvlab-user
```

`ssh-keygen` asks for a passphrase twice; press Enter both times for a key
without one. Because the scripts run in BatchMode, a key with a passphrase
works only when it is loaded into `ssh-agent`. The `ssh-agent` service is
disabled by default; enabling it needs an elevated shell once:

```powershell
# elevated, once
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
# as the operator
ssh-add "$HOME\.ssh\hvlab_admin_ed25519"
ssh-add "$HOME\.ssh\hvlab_user_ed25519"
```

Windows OpenSSH ignores a private key file that other accounts can read. The
host scripts check the key ACL before they start `ssh.exe` and print a fix.
Keys created by `ssh-keygen` in your own `.ssh` folder normally pass. To limit
a key file's ACL to your account:

```powershell
icacls "$HOME\.ssh\hvlab_user_ed25519" /inheritance:r /grant:r "$($env:USERNAME):F"
```

Then check that `icacls` lists no other account for the file.

## Guest side

`guest\Install-HvLabGuestSsh.ps1` does the guest part. Copy it and the two
`.pub` files into the guest (for example through an enhanced session, or with
`Copy-VMFile` from an elevated host shell when the Guest Service Interface is
enabled), then run it elevated in the guest:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-HvLabGuestSsh.ps1 -AdminPublicKey .\hvlab_admin_ed25519.pub -StandardUser <guest-user> -UserPublicKey .\hvlab_user_ed25519.pub -AllowFrom <host address on the lab switch>
```

What it changes in the guest, and nothing else:

- with `-InstallOpenSshServer` only: adds the OpenSSH Server optional
  feature;
- the `sshd` service: start type Automatic, and started;
- the inbound firewall rule `OpenSSH-Server-In-TCP` (TCP 22): created if
  missing, enabled, and limited to `-AllowFrom`. It accepts every address
  only with `-AllowAnyAddress`, and then warns;
- `%ProgramData%\ssh\administrators_authorized_keys`: the admin key is added,
  and the owner and ACL are set;
- `<standard user profile>\.ssh\authorized_keys`: the `.ssh` folder is
  created when it is missing, the user key is added, and the owner and ACL
  of the file are set.

The keys open sign-in for every member of Administrators (through
`administrators_authorized_keys`) and for the standard account. The script
creates no account, sets no password, does not edit `sshd_config`, and does
not change UAC, Microsoft Defender or any other protection.

The standard account must exist and must have signed in once, so that its
profile folder exists. Sign in once at the VM console. The script refuses an
account that is directly in Administrators, Backup Operators, Server
Operators, Account Operators, Print Operators or Hyper-V Administrators. That
is a first filter; `-ShowContext` on the host checks what the SSH session
itself reports.

### The rules that make sshd ignore a key file

These are the usual reasons why key sign-in fails on Windows even though the
key is in the file:

1. **The wrong file for administrators.** With the default `sshd_config`, the
   block `Match Group administrators` points every member of Administrators
   to `%ProgramData%\ssh\administrators_authorized_keys`. Their per-user
   `authorized_keys` is not read at all. The setup script warns when that
   block is missing.
2. **The owner or the ACL.** Windows OpenSSH checks the owner and the ACL of
   these files. The setup script removes inherited entries and grants access
   to these principals only, which passes the check:
   - `administrators_authorized_keys`: owner Administrators; SYSTEM and
     Administrators.
   - `authorized_keys`: owner the user; the user, SYSTEM and Administrators.

   If you edit an ACL by hand, keep it like that. An entry for another account
   or group (for example Users or Authenticated Users, including an inherited
   one) can make sshd ignore the file.
3. **The encoding.** In Windows PowerShell 5.1, `>` and `Out-File` write
   UTF-16, which sshd does not read as a key file. The setup script writes
   UTF-8 without a byte order mark and LF line endings, and it converts a
   UTF-16 file it finds.
4. **The service.** `sshd` must run, and the firewall rule
   `OpenSSH-Server-In-TCP` must be enabled and allow the host.

When sshd ignores a key file, an interactive `ssh` falls back to asking for a
password. The host scripts do not allow that, so the same problem shows up as
exit code 255.

## Host key

Every connection uses the lab-only `KnownHostsPath` file and
`StrictHostKeyChecking=yes`, so a changed guest host key is refused. The first
connection needs `-TrustNewHostKey` (`StrictHostKeyChecking=accept-new`):

```powershell
.\Invoke-HvLabSsh.ps1 -Role User -ShowContext -TrustNewHostKey
```

The output field `HostKey` is the stored fingerprint. Compare it with the
guest's own key, read at the VM console:

```powershell
ssh-keygen -l -f "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
```

After you rebuild the guest, remove the old entry and trust the new key the
same way:

```powershell
.\Invoke-HvLabSsh.ps1 -ResetHostKey
```

## What an SSH session is

Win32-OpenSSH signs a key-authenticated user on without the password: sshd,
which runs as SYSTEM, asks Windows for a token with an S4U logon of the
network type, and starts the user's shell in session 0. That differs from a
console sign-in in ways that change local privilege escalation results, in
both directions:

| | SSH key sign-in | Console sign-in |
|---|---|---|
| Logon | network (S4U), no password | interactive, with the password |
| Logon type group | NETWORK (S-1-5-2) | INTERACTIVE (S-1-5-4) |
| Session | 0, no desktop | an interactive session with a desktop |
| Network credentials | none | yes |
| DPAPI secrets that depend on the user's password | not usable | usable |
| ACEs that grant INTERACTIVE | do not apply | apply |
| File mappings in the global namespace | allowed without SeCreateGlobalPrivilege, as in every session 0 process | need SeCreateGlobalPrivilege |
| Administrators | elevated token, no UAC split | filtered token until elevation |

The table states how Win32-OpenSSH and Windows work, not a measurement of your
guest. `-ShowContext` prints `LogonType` and `SessionId` from the session
itself, so check them on your guest. The global namespace row comes from
Microsoft's documentation of kernel object namespaces. Show bugs that depend
on DPAPI, on a desktop or a session, on ACEs that grant INTERACTIVE, or on
squatting a name in the global namespace at the VM console instead.

### The session report

`-ShowContext` signs in as the role and runs one cmd.exe command line in the
guest: `whoami /user`, `whoami /groups` and `whoami /priv` (CSV), the
Developer Mode registry value, and the session id. Groups are read by SID and
privileges by name, so the report does not depend on the guest's display
language. It exits 4 when the session does not fit the role:

- **Admin:** the token must be elevated (High or System integrity) and carry
  Administrators.
- **User:** the token must be Medium integrity, and every group and privilege
  in it must belong to a default standard-user token. Groups: Everyone, Users,
  Authenticated Users, This Organization, Local account, LOCAL, CONSOLE
  LOGON, NETWORK, INTERACTIVE, REMOTE INTERACTIVE LOGON, Remote Desktop Users
  (a standard account needs it for Remote Desktop and Hyper-V enhanced
  session sign-in), the logon session SID (S-1-5-5-x-y), the authentication
  package SID (S-1-5-64-x), the asserted identity SIDs (S-1-18-x), the
  account's own RID 513 group (None or Domain Users), and the Medium label.
  Privileges: SeChangeNotifyPrivilege, SeShutdownPrivilege,
  SeUndockPrivilege, SeIncreaseWorkingSetPrivilege and SeTimeZonePrivilege,
  the default User Rights Assignment of Windows client editions. Any other
  group (Backup Operators, Remote Management Users, Device Owners, a custom
  group) or privilege (SeDebugPrivilege, SeCreateSymbolicLinkPrivilege and so
  on) is named in the output, and the account is refused.

The report also shows `DeveloperMode`. With Developer Mode on, a standard user
can create symbolic links without SeCreateSymbolicLinkPrivilege, and the
script warns; say so with any proof that uses symbolic links.

`-WithContext` adds the report to a `-Command` run. It first checks the role
in its own session and does not run the command when that check fails. Then
it runs the report and the command in one SSH session, so the report
describes the sign-in that ran the command. Keep its output with the proof.

The report needs cmd.exe as the guest's OpenSSH default shell, the Windows
default. It comes from `whoami` in the guest, so a guest that already ran
untrusted code can make it say anything; take it on a fresh guest.

## Exit code 255

`ssh.exe` returns 255 for its own failures, and passes on the guest command's
exit code otherwise. A guest command that itself exits 255 cannot be told
apart from an SSH failure by the code alone. `Invoke-HvLabSsh.ps1` therefore
opens a second connection that runs only `exit 0` after a 255. When that
connection succeeds, the warning says that the 255 most likely came from the
guest command; when it fails too, the warning says that SSH failed.

Checks for a real SSH failure:

1. Is the VM running? `.\Invoke-HvLabVm.ps1 -Action Status`
2. Is `GuestAddress` right? `Status` lists the guest's IPv4 addresses when the
   guest reports them.
3. Did the host key change? See Host key above.
4. Is the key accepted? In the guest, read the event log **Applications and
   Services Logs > OpenSSH > Operational**. To see the client side, run
   `ssh -v -F none` by hand with the same key and account.
5. Is the firewall rule `OpenSSH-Server-In-TCP` in the guest enabled, and does
   its remote address include the host?
