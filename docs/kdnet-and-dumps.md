# KDNET preflight and crash dumps

Both scripts use the guest admin account over SSH and upload a small helper
from `guest\` for each run. The helper deletes its uploaded copy when it
finishes. The KDNET helper changes nothing else in the guest; the dump helper
writes only to a staging folder in the admin's profile (see Crash dumps).

## KDNET kernel debugging

### One-time setup

In the guest, elevated (replace the address with the host's address on the
lab switch):

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host address> port:50000
```

`bcdedit /dbgsettings` then generates a key and prints it. To choose the key
yourself instead, add `key:<w.x.y.z>` to the second command. Save the key on
the host in a file that only your account can read, and set `KdnetKeyFile` in
the config to that file. Restart the guest so the boot entry applies.

On the host, the debugger needs an inbound UDP rule for the port. The
installer can add one. It accepts the port only from `-KdnetRemoteAddress`,
which is required with `-KdnetPort`:

```powershell
# elevated, in <repository>\host
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-HvLab.ps1 -VmName '<vm name>' -Lab lab1 -OperatorAccount "$env:COMPUTERNAME\<operator>" -KdnetPort 50000 -KdnetRemoteAddress <lab network prefix> -KdnetInterfaceAlias 'vEthernet (<lab switch>)'
```

Use the prefix of the lab network, such as `192.0.2.0/24`, for
`-KdnetRemoteAddress`. The KDNET transport in the guest can use a different
address than Windows in the guest, so a single address fits only when you know
the one that KDNET uses. `-KdnetInterfaceAlias` (the lab switch's adapter on
the host) and
`-KdnetProgram` (the full path of the debugger program, such as `kd.exe`) are
optional and narrow the rule further. Leave `-KdnetProgram` out when another
program receives the connection. The rule applies to all firewall profiles;
the remote address, and the adapter when given, limit it. While a debugger
waits for a connection, it listens on the port on every host adapter, and the
key protects the connection itself.

If the guest has Secure Boot on, `bcdedit` may refuse the debug settings until
Secure Boot is turned off in the VM settings.

Enabling KDNET can change which network adapter Windows uses in the guest, so
an address set on the original adapter may stop applying. After the first
debug boot, check the guest's address with `Invoke-HvLabVm.ps1 -Action Status`
and update `GuestAddress` if it changed.

### Before each session

```powershell
.\Test-HvLabKdnet.ps1
```

It changes nothing. It reports `Ready`, a list of `Errors` (each one makes the
result not ready, exit 3) and a list of `Warnings`:

| Check | Not ready when |
|---|---|
| boot entry `debug` | not `Yes` |
| `debugtype` | not `NET` |
| `port` | not a number, or differs from `KdnetPort` |
| `hostip` | not an IPv4 address of this host, or not `-HostAddress` |
| key | differs from the key file (compared by salted SHA-256); the error says when only the letter case differs |
| running boot | debugging disabled although the boot entry has it (restart needed) |
| host firewall | no enabled inbound allow rule covers the UDP port |

Warnings: no key file given, a key file that accounts other than yours,
SYSTEM and Administrators can read (with the `icacls` command that fixes it),
a debugger is attached right now, the port is in use on the host, a block rule
also covers the port, firewall rules cannot be read, `kd.exe` not found,
Secure Boot on, HVCI running, `bcdedit` values in a language other than
English.

How the key is compared: the host sends a fresh random nonce; the guest
returns SHA-256(nonce + key); the host computes the same from its key file.
The key itself travels in neither direction and is never printed. The two
computations are the functions `Get-HvLabKdnetKeyHash` (host) and
`Get-HvLabKeyHash` (guest helper), and an offline test checks that they
agree. The comparison is exact: copy the key as `bcdedit /dbgsettings` prints
it.

Then connect from the host:

```powershell
kd.exe -k net:port=50000,key=<key>
```

### Limits

- `bcdedit` prints values in the guest's display language. The helper
  recognizes `Yes` and `No` in English only and reports any other value as a
  warning.
- The firewall check reads the local rules (the default policy store), not
  rules from Group Policy. It does not evaluate profiles or the order in which
  Windows Firewall applies rules.
- The running-boot state comes from `NtQuerySystemInformation` class 35
  (`SystemKernelDebuggerInformation`).
- The helper uses `Add-Type`, so it does not run under Constrained Language
  Mode.

## Crash dumps

```powershell
.\Get-HvLabCrashDump.ps1 -ListOnly   # what the guest has, copies nothing
.\Get-HvLabCrashDump.ps1             # newest minidump
.\Get-HvLabCrashDump.ps1 -Name <file>.dmp
.\Get-HvLabCrashDump.ps1 -Full       # MEMORY.DMP, or the configured DumpFile
```

Which files exist depends on the guest's crash dump settings
(`HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`); `-ListOnly` shows
them. `CrashDumpEnabled` 0 means no dump is written.

How a copy works:

1. The guest helper makes the dump readable from the admin's home folder as
   `hvlab-stage\<name>`. It uses a hard link when the dump and the profile are
   on the same volume, so a multi-GB `MEMORY.DMP` is not copied inside the
   guest. Otherwise it copies the file after checking free space.
2. The helper hashes the staged file (SHA-256). The host requires the staged
   name and size to match the dump it chose from the list.
3. `scp` copies it to `<DumpDirectory>\<name>.part` on the host. The host
   checks free space first, and stops the copy and deletes the `.part` file
   when the file grows past the size that the guest reported.
4. The host hashes the copy. Only when both hashes match is the file renamed
   to `<Lab>-<guest LastWriteTime UTC>-<name>`. On a mismatch the `.part`
   file is kept for inspection and the exit code is 1.
5. The staged file is removed in the guest.

An existing host file with the same name is reused when its hash matches and
never overwritten. Names, sizes, hashes and paths returned by the guest are
checked against strict patterns before the host uses them. `DumpDirectory`
must be on a local drive, so that its free space can be checked.

If step 5 does not run, for example because the connection broke, the staged
hard link or copy stays in `%USERPROFILE%\hvlab-stage` of the guest admin. A
hard link keeps the dump's disk space in use even after Windows deletes the
original dump. Delete that folder in the guest to free the space.

The newest dump is not necessarily from your last step. Compare
`GuestLastWriteUtc` with the time of that step, and with `GuestLastBootUtc`.
Windows can take a while after the restart to write the dump file. A full dump
of a large guest can take minutes to hash and copy.

To read a dump on the host, for example:

```powershell
kd.exe -z <path to dump>
# then: !analyze -v
```
