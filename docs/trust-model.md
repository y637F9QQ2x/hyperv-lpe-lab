# Trust model

This page explains what the lifecycle tasks allow, who can use them, and which
design choice closes which attack. Read it before you run `Install-HvLab.ps1`.

## The short version

An administrator runs `Install-HvLab.ps1` once. After that, one named host
account (the operator) can start, stop, turn off, pause, resume and query one
named Hyper-V VM without a UAC prompt. That is the whole grant.

- It is deliberate. The installer needs an elevated shell, and it names the
  VM and the account explicitly.
- Any code that runs as the operator account can use the same six actions.
  That includes a malicious program the operator runs by mistake.
- It gives the operator no other rights: no code execution as SYSTEM or as an
  administrator, no access to other VMs, no change to Hyper-V settings. That
  holds as long as the folders on the worker's path and the machine PATH stay
  as the installer found them (see The path to the worker is protected).
- Use it only on a dedicated research host, where turning the lab VM off at
  the wrong moment is the worst outcome you accept.

## What is delegated

| Action | What the worker runs | Worker calls it when the VM is |
|---|---|---|
| Start | `Start-VM` | Off, Saved |
| Stop | `Stop-VM -Force` (asks the guest to shut down) | Running |
| TurnOff | `Stop-VM -TurnOff -Force` (cuts power) | any state except Off |
| Pause | `Suspend-VM` | Running |
| Resume | `Resume-VM` | Paused |
| Status | nothing; reads the state | any |

The third column is the worker's own rule. Hyper-V can still refuse an action
in some of these states, for example while a VM is starting or saving; the
worker then reports Hyper-V's error. The offline tests check this logic
against replacement Hyper-V cmdlets; the transitions have not been run against
a real VM.

The worst the operator can do with these is to turn the VM off, or to start
and stop it repeatedly. Turning the VM off loses unsaved guest data.

## How the pieces fit

```
operator (standard user, medium integrity)
  |  IRegisteredTask::Run() on \HyperVLpeLab\<Lab>\<Action>   (allowed by the task DACL)
  v
Task Scheduler service
  |  starts, as SYSTEM, the fixed command line stored in the task:
  |  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile
  |    -NonInteractive -ExecutionPolicy RemoteSigned -File "<lab folder>\HvLabWorker.ps1" -Action <Action>
  v
HvLabWorker.ps1 (in the lab folder: only SYSTEM and Administrators can change it)
  |  reads worker.json (same folder), imports Hyper-V, acts on the VM with that Id
  v
state\<Action>.json and logs\worker.log (same folder; the operator can read them)
```

## Design choices and what each one prevents

### The tasks run as SYSTEM, not as the operator

A common way to skip UAC prompts is a task that runs as the user's own
administrator account with "run with highest privileges" and the S4U logon
type. This repository does not do that, for two reasons.

1. Such a task runs with the operator's profile. PowerShell then searches the
   operator's own module folder (`Documents\WindowsPowerShell\Modules`) before
   the system module folder, and the process gets the operator's per-user
   environment variables. Code at medium integrity in the operator's session
   can change both, so it could plant a module or an environment variable that
   the elevated task then loads. That would be a real path from medium to
   high integrity.
2. It requires the operator to be an administrator. With a SYSTEM task the
   operator can be a standard account.

A SYSTEM task uses the SYSTEM profile and environment, which the operator
cannot change. As an extra layer, the worker sets `PSModulePath` to the
Windows PowerShell module folder only, before any command that can load a
module runs. It builds that value with a .NET call, because a cmdlet such as
`Join-Path` would first load its own module through the inherited
`PSModulePath`, which includes the machine `PSModulePath` folders. An offline
test checks that order.

The task XML contains `<RunLevel>HighestAvailable</RunLevel>`. Its principal
is SYSTEM (S-1-5-18), which has no filtered UAC token, so the run level has
nothing to raise. The operator never receives the task's token; the task
security descriptor lets it start the fixed command line, and nothing else.

Two other designs were considered:

- **A dedicated account in Hyper-V Administrators.** Microsoft documents that
  group as having complete and unrestricted access to all features of
  Hyper-V. Code running as such an account could change every VM and every
  Hyper-V setting on the host. The tasks give the operator six fixed actions
  on one VM.
- **PowerShell Direct (`Invoke-Command -VMName`).** It needs Hyper-V rights
  on the host and a guest credential, so it would put Hyper-V control and a
  guest password into the operator's reach. The tasks need neither, and the
  guest commands use SSH keys instead.

### No input crosses from the operator to SYSTEM

- Each action is its own task. The action name is part of the stored command
  line, which only SYSTEM and Administrators can change.
- The command line contains no `$(Arg0)` style placeholder, so values passed to
  `Run()` are ignored by Task Scheduler.
- The command line uses literal paths. It contains no environment variable,
  so the operator's environment cannot redirect it.
- The worker reads only `worker.json` from its own folder, and refuses a
  schema other than `hvlab-worker/1` and any key it does not know. It reads no
  file, registry value or environment variable that the operator can write.
- The VM is selected by its Id. The worker also checks that the VM still has
  the name recorded at install, and refuses to act if it does not.

### The lab folder is protected and checked

- The installer creates `<InstallRoot>` and `<InstallRoot>\<Lab>` with their
  final ACL in the call that creates them. That call also reports success
  when another account created the folder a moment earlier, and then applies
  no ACL, so the installer reads the owner back and stops unless it is
  Administrators, SYSTEM or the installing account. After that, nobody but
  SYSTEM and Administrators can create a file or a link in the folder.
- The ACLs: owner Administrators; SYSTEM and Administrators full control;
  Authenticated Users may list the install root (that folder only); the
  operator may read and execute the lab folder; no entries inherited from
  the parent folder.
- If the install root or the lab folder already exists and anyone other than
  SYSTEM or Administrators owns it or could write to it, the installer stops
  and asks a person to inspect it. It does not try to repair it, because a
  handle opened before a repair would keep its access.
- After it writes the files, the installer reads back the ACLs of the install
  root and of the lab folder with everything in it, and compares the worker's
  hash, before any task exists.
- It registers all six tasks disabled, reads back every task's command line,
  principal, triggers, enabled state and security descriptor, registers them
  again enabled, and reads them back again. When a check fails, it deletes
  the lab's tasks before it stops, so a failed install leaves no task that the
  operator could run.
- `Test-HvLabInstall.ps1` repeats these checks from the operator's side, tries
  to create a file in the lab folder (this must fail), and compares the
  installed worker with the repository copy and with the hash in
  `install.json`.

Because the operator cannot create files or links in the lab folder, it also
cannot redirect the result and log files that SYSTEM writes there.

### The path to the worker is protected

The tasks start the worker by its literal path. An account that could delete,
rename or change the permissions of any folder on that path could put its own
`HvLabWorker.ps1` there. `C:\` lets every signed-in user create folders, and a
folder created directly under it inherits Modify for Authenticated Users, so
`-InstallRoot C:\Lab\HyperVLpeLab` would be such a path.

So the installer and `Test-HvLabInstall.ps1` check every folder above the
install root, from the volume root down. Each must exist, must not be a link
or junction, must be owned by SYSTEM, Administrators or TrustedInstaller, and
must not give anyone else DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER,
GENERIC_ALL or GENERIC_WRITE. Entries that are only inherited by child
objects (for example CREATOR OWNER) are not counted, because they grant
nothing on the folder itself. The right to create files and subfolders is
allowed: `C:\` and `C:\ProgramData` give it to all users by default, and it
does not let anyone replace a folder that already exists. The volume must be
a fixed local drive. With the default ACLs of `C:\` and `C:\ProgramData`, the
default root `%ProgramData%\HyperVLpeLab` passes these checks (read with
`Get-Acl` on a Windows 11 host); any other root must pass them too.

The tasks also start a SYSTEM `powershell.exe` whenever the operator asks. A
DLL that a process does not find in its own folder or in the system folders
is searched for in the folders of the PATH. So the installer and
`Test-HvLabInstall.ps1` also check every folder in the machine PATH: no
account other than SYSTEM, Administrators or TrustedInstaller may add,
delete or rename files in it or change its permissions, and a PATH folder that
does not exist must not be one that such an account could create. Network
paths and paths relative to a drive are refused. A plain relative entry
resolves against the task's working directory, the protected lab folder.
Which DLLs a SYSTEM `powershell.exe` actually searches for has not been traced
with Process Monitor; the PATH check does not depend on it.

The installer stops before it changes anything when one of these checks
fails, and names the folder and the account.

### The tasks themselves are protected

| Object | Security descriptor | Meaning |
|---|---|---|
| Task folder `\HyperVLpeLab` | `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)` | anyone signed in can list lab names |
| Task folder `\HyperVLpeLab\<Lab>` | `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<operator>)` | only the operator can open it |
| Each task | `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;<operator>)` | only the operator can run it; only SYSTEM and Administrators can change or delete it |

Other settings: no triggers (on demand only), one instance of each task at a
time (`IgnoreNew`), and a 10-minute execution limit. Across tasks, Start,
Stop, Pause and Resume share a lock file in the lab folder, so only one of
them acts on the VM at a time; a second one reports busy (exit code 75 in
`Invoke-HvLabVm.ps1`). TurnOff does not wait for the lock, so it can still end
a Stop that waits for a hung guest, and Status changes nothing. The lock is a
file in the lab folder rather than a named mutex, because any account on the
host could create such a mutex first. The operator can read the lab folder,
so code running as the operator can hold the lock file or a result file open.
That only makes the operator's own actions report busy or end without a
result, which is less than TurnOff already allows.

### Nothing secret is stored

No password or key is stored by the lifecycle part. The worker does not use
PowerShell Direct or any guest credential.

## What an administrator should still know

- The installer runs elevated and copies `worker\HvLabWorker.ps1` as it finds
  it. If the operator account can write to your checkout, code running as the
  operator could change the worker before you install it. Install from a copy
  the operator cannot change, or review the files first. `install.json`
  records the SHA-256 of what was installed.
- Members of the built-in Hyper-V Administrators group can control every VM
  and every Hyper-V setting on the host. These tasks are narrower: one VM, six
  actions.
- If the operator account is itself a local administrator, the tasks only save
  it the UAC prompt for these six actions. The installer warns in that case.
- The operator can be one account, or a group created for the lab: every
  member of such a group gets the six actions. Built-in and well-known groups
  (Users, Authenticated Users, Domain Users and similar) are refused.
- `Uninstall-HvLab.ps1 -Lab <Lab>` removes the tasks, the task folders, the
  KDNET firewall rule and the lab folder. It deletes the lab folder only when
  its `install.json` names this lab, this folder and this install root, and
  its ACL passes the same check as at install; otherwise it changes nothing.

## The guest is untrusted

The guest exists to run untrusted code. The host scripts treat everything the
guest sends as data:

- Guest helper scripts return one base64 line of JSON. The host decodes it and
  never runs it.
- Names, sizes, hashes, ports and addresses from the guest are checked against
  strict patterns before the host uses them, and control characters in guest
  text are replaced before the host prints it, so guest output cannot redraw
  the console.
- A crash dump copy stops when the file grows past the size the guest
  reported, and the staged name and size must match the dump that was listed.
- Arguments sent to guest helpers are limited to plain tokens.
- Each SSH connection pins the guest host key in a lab-only `known_hosts`
  file, refuses a changed key, turns off agent, X11 and port forwarding, and
  reads no ssh config file ([ssh.md](ssh.md)).

The output of a command that you run in the guest with `Invoke-HvLabSsh.ps1
-Command` is printed as ssh prints it. The SSH keys open the guest, not the
host. Keep the admin private key in the operator's profile, and keep the VM on
an internal virtual switch.

## KDNET

The KDNET key protects the debug connection. Treat it as a secret: keep the
key file readable by your account only. `Test-HvLabKdnet.ps1` warns, with the
`icacls` command that fixes it, when other accounts can read the file. It
compares keys by a salted SHA-256 and never sends the key.

While a kernel debugger waits for a KDNET connection, it listens on the UDP
port on the host. The optional firewall rule that
`Install-HvLab.ps1 -KdnetPort` creates accepts that port only from
`-KdnetRemoteAddress`, which is required, normally the lab network's prefix.
`-KdnetInterfaceAlias` limits it to the lab switch's
adapter, and `-KdnetProgram` to one debugger program. The rule applies to all
firewall profiles, because Windows assigns the profile of the lab switch's
adapter; the address, and the adapter when given, limit it instead. The
installer prints the resulting scope.
