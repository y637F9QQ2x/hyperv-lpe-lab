# hyperv-lpe-lab

PowerShell scripts for a headless Hyper-V lab in which a Windows local
privilege escalation is shown from a standard-user SSH session in the guest
(an S4U network logon in session 0; see [docs/ssh.md](docs/ssh.md)).

It is plain PowerShell: no service, no MCP server and no network listener on
the host. The only inbound firewall rule it can add on the host is the
optional KDNET UDP rule for your debugger.

- **VM lifecycle without elevation.** One host account (the operator) can
  start, stop, turn off, pause, resume and query one named VM with UAC left
  on. An administrator registers six on-demand scheduled tasks once; each runs
  a fixed script as SYSTEM and takes no input from the operator.
- **Guest commands as admin or as a standard user.** Key-based SSH with one
  key per role, no password fallback, a pinned host key, no agent or port
  forwarding, and a session report (integrity level, groups, privileges,
  logon type, session id) that must fit the role.
- **KDNET preflight.** A check of the guest boot settings, the key, the
  running boot and the host firewall before you connect a kernel debugger.
- **Crash dump retrieval.** Copies the newest (or a chosen) dump to the host
  and accepts it only when the SHA-256 in the guest and on the host match.

Before you install anything, read [docs/trust-model.md](docs/trust-model.md).

## Contents

- [What this is not](#what-this-is-not)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Security and trust model](#security-and-trust-model)
- [Limitations](#limitations)
- [Tests](#tests)
- [Repository layout](#repository-layout)
- [Related projects](#related-projects)
- [Credits and license](#credits-and-license)

## What this is not

- Not a UAC bypass. An administrator installs it, and it grants one account
  six actions on one VM. Code running as that account can use the same six
  actions, so use it on a dedicated research host only.
- Not an exploit kit. It contains no exploit code. In the guest,
  `Install-HvLabGuestSsh.ps1` changes only the sshd service (it sets it to
  start automatically and starts it), its firewall rule
  `OpenSSH-Server-In-TCP`, and two `authorized_keys` files with their ACLs
  (it creates the standard user's `.ssh` folder when it is missing); with
  `-InstallOpenSshServer` it also adds the OpenSSH Server feature
  ([docs/ssh.md](docs/ssh.md)). It does not turn off UAC, Microsoft Defender
  or any other protection. The KDNET settings are manual steps that you run
  yourself ([docs/kdnet-and-dumps.md](docs/kdnet-and-dumps.md)).
- Not a VM builder. It does not create the VM, the guest accounts or
  checkpoints, and it does not repair guest networking.

## Requirements

| Where | What |
|---|---|
| Host | Windows with Hyper-V and the Hyper-V PowerShell module |
| Host | Windows PowerShell 5.1 (built in) for `Install-HvLab.ps1` and `Uninstall-HvLab.ps1`, as in the setup steps; the worker always runs in it |
| Host | Windows PowerShell 5.1 or PowerShell 7 for `Invoke-HvLabVm.ps1` and `Test-HvLabInstall.ps1` |
| Host | PowerShell 7.3 or later (`pwsh`) for `Invoke-HvLabSsh.ps1`, `Test-HvLabKdnet.ps1`, `Get-HvLabCrashDump.ps1`, which rely on its exact argument passing to `ssh.exe` |
| Host | Windows OpenSSH client (`ssh.exe`, `scp.exe`, `ssh-keygen.exe`) |
| Host, optional | Debugging Tools for Windows (`kd.exe`) for KDNET |
| Guest | Windows with OpenSSH Server and cmd.exe as its default shell (the Windows default), one local administrator, one local standard account that has signed in once |

## Install

### 0. Before you start

Get the files with `git clone`. If you download a ZIP instead, review the
files, then remove the download mark (Mark of the Web), which makes
PowerShell refuse unsigned scripts:

```powershell
Get-ChildItem -LiteralPath <repository> -Recurse -File | Unblock-File
```

On Windows client editions, Windows PowerShell runs no script until an
execution policy allows it; the default policy there is Restricted. The
commands below start each shell with `-ExecutionPolicy RemoteSigned`, which
applies to that one process and changes no saved policy. An execution policy
set by Group Policy takes precedence and can still block the scripts.

### 1. Register the lifecycle tasks (host, elevated, once)

In an elevated Windows PowerShell:

```powershell
cd <repository>\host
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-HvLab.ps1 -VmName '<vm name>' -Lab lab1 -OperatorAccount "$env:COMPUTERNAME\<operator>"
```

`-VmName` is matched exactly. `-OperatorAccount` is the account that will run
the host scripts; only an account, or a group created for the lab, is
accepted, and built-in or well-known groups such as Users or Domain Users are
refused. Add `-KdnetPort 50000 -KdnetRemoteAddress <lab network prefix>`
(for example `192.0.2.0/24`) to create the KDNET firewall rule as well.

Before it changes anything, the installer checks that no account other than
SYSTEM, Administrators or TrustedInstaller can replace a folder above the
install root, or add files to a folder in the machine PATH, and it refuses an
existing lab folder that another account could have changed. It prints what
it created.

Then, as the operator, in a Windows PowerShell that is not elevated:

```powershell
cd <repository>\host
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-HvLabInstall.ps1 -Lab lab1 -RunStatus
```

Every check must show `True` in the `Ok` column, and the exit code
(`$LASTEXITCODE`) must be 0. The last check runs the Status task as the
operator.

### 2. Keys and config (host, operator)

```powershell
New-Item -ItemType Directory -Force "$HOME\.ssh"
ssh-keygen -t ed25519 -f "$HOME\.ssh\hvlab_admin_ed25519" -C hvlab-admin
ssh-keygen -t ed25519 -f "$HOME\.ssh\hvlab_user_ed25519" -C hvlab-user
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\HyperVLpeLab"
Copy-Item <repository>\config\hvlab.example.json "$env:LOCALAPPDATA\HyperVLpeLab\config.json"
notepad "$env:LOCALAPPDATA\HyperVLpeLab\config.json"
```

`ssh-keygen` asks for a passphrase twice. Press Enter both times for a key
without a passphrase, which only its file ACL protects. A key with a
passphrase needs `ssh-agent`, because the scripts never prompt
([docs/ssh.md](docs/ssh.md#host-side)).

Set `GuestAddress`, `AdminAccount` and `UserAccount`. The example values
(`192.0.2.10`, `<guest-admin>`, `<guest-user>`) are placeholders, and the
account placeholders are refused until you replace them. Unknown settings are
refused too, so a typo does not pass silently. `$env:HVLAB_CONFIG` or
`-ConfigPath` can point to another file.

| Setting | Default | Meaning |
|---|---|---|
| `Lab` | (required) | lab name used at install |
| `InstallRoot` | `%ProgramData%\HyperVLpeLab` | install root used at install |
| `GuestAddress` | (required) | guest IPv4 or IPv6 address, or DNS name |
| `SshPort` | 22 | guest SSH port |
| `AdminAccount`, `UserAccount` | (required) | guest accounts; must differ |
| `AdminKeyPath`, `UserKeyPath` | (required) | private key files; must differ |
| `KnownHostsPath` | `~\.ssh\hvlab_known_hosts` | lab-only known_hosts file |
| `ConnectTimeoutSec` | 10 | SSH connect timeout |
| `KdnetPort` | 50000 | KDNET UDP port |
| `KdnetKeyFile` | none | file whose first line is the KDNET key |
| `DumpDirectory` | `~\hvlab-dumps` | host folder for crash dumps, on a local drive |

### 3. Install the public keys (guest, elevated)

Copy `guest\Install-HvLabGuestSsh.ps1` and the two `.pub` files into the
guest. If the script came from a download in the guest, run `Unblock-File`
on it. Then run in an elevated Windows PowerShell there:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Install-HvLabGuestSsh.ps1 -AdminPublicKey .\hvlab_admin_ed25519.pub -StandardUser <guest-user> -UserPublicKey .\hvlab_user_ed25519.pub -AllowFrom <host address on the lab switch>
```

`-AllowFrom` limits the guest's SSH firewall rule to the host. It is
required (PowerShell asks for it when it is missing), unless you pass
`-AllowAnyAddress` instead.
[docs/ssh.md](docs/ssh.md) explains what it changes and the ACL and encoding
rules that make Windows OpenSSH ignore a key file.

### 4. First connection (host, operator)

Start PowerShell 7 with `pwsh -NoProfile -ExecutionPolicy RemoteSigned`, go
to `<repository>\host`, and run:

```powershell
.\Invoke-HvLabSsh.ps1 -Role User -ShowContext -TrustNewHostKey
.\Invoke-HvLabSsh.ps1 -Role Admin -ShowContext
```

Compare the `HostKey` fingerprint with the guest's own key
([docs/ssh.md](docs/ssh.md#host-key)). Both commands must exit 0: the User
session must be Medium integrity with only the groups and privileges of a
standard user, and the Admin session must be elevated.

## Usage

In `<repository>\host`, in a shell started with
`pwsh -NoProfile -ExecutionPolicy RemoteSigned`:

```powershell
# VM lifecycle (this script also runs in Windows PowerShell 5.1)
.\Invoke-HvLabVm.ps1 -Action Status
.\Invoke-HvLabVm.ps1 -Action Start
.\Invoke-HvLabVm.ps1 -Action Stop        # guest shutdown
.\Invoke-HvLabVm.ps1 -Action TurnOff     # power off, for a hung guest
.\Invoke-HvLabVm.ps1 -Action Pause
.\Invoke-HvLabVm.ps1 -Action Resume

# Guest commands (PowerShell 7.3 or later)
.\Invoke-HvLabSsh.ps1 -Role User -ShowContext
.\Invoke-HvLabSsh.ps1 -Role User -Command 'C:\lab\poc.exe' -WithContext
.\Invoke-HvLabSsh.ps1 -Role Admin -Command 'sc.exe query <service>'

# Kernel debugging and crash dumps (PowerShell 7.3 or later)
.\Test-HvLabKdnet.ps1
.\Get-HvLabCrashDump.ps1 -ListOnly
.\Get-HvLabCrashDump.ps1
```

A standard-user proof is a run with `-Role User -WithContext`. The session
report and the command then come from one SSH session, and the command does
not run when the account does not fit the role. Guest commands run in the
guest's OpenSSH default shell (cmd.exe unless changed); pass the command as
one string. [docs/kdnet-and-dumps.md](docs/kdnet-and-dumps.md) covers the
KDNET and crash dump workflow.

### Exit codes

| Script | Codes |
|---|---|
| `Invoke-HvLabVm.ps1` | 0 done, 1 action failed, 2 usage, 3 task missing, access denied or not started, 75 task already running or another state change of the lab running, 124 timeout |
| `Invoke-HvLabSsh.ps1` | the guest command's code; 255 SSH failure, or 255 from the guest command (a warning says which is likely); 1 session report unreadable or `-ResetHostKey` failed; 2 usage; 4 session does not fit the role |
| `Test-HvLabKdnet.ps1` | 0 ready, 3 not ready, 2 usage, 255 SSH failure, 1 guest helper error |
| `Get-HvLabCrashDump.ps1` | 0 copied or listed, 3 nothing to copy or no space, 2 usage, 255 SSH failure, 1 other failure |
| `Test-HvLabInstall.ps1` | 0 all checks passed, 3 a check failed, 2 usage or elevated shell |

When `Invoke-HvLabSsh.ps1` sets 1, 2 or 4 itself, it also writes a line that
starts with `hvlab:` to stderr; without that line, the code came from the
guest command. Windows exit codes are 32-bit, so a guest command that crashes
can return an NTSTATUS code such as 0xC0000005, which `$LASTEXITCODE` shows
as -1073741819. Whether `ssh.exe` passes such a code on unchanged has not been
measured.

When the parameters do not bind, nothing runs in the guest. A run with
`pwsh -File` then exits 1; in an open session, `$?` is `False` and
`$LASTEXITCODE` keeps its previous value.

## Security and trust model

Summary of [docs/trust-model.md](docs/trust-model.md):

- The tasks run as SYSTEM, not as the operator. A task that runs as the
  operator's own account with highest privileges would load the operator's
  profile, module folder and environment, which code at medium integrity can
  change.
- Each task has one fixed command line with literal paths and no argument
  placeholder. Only the operator may run the tasks; only SYSTEM and
  Administrators may change or delete them.
- The worker lives in a folder that only SYSTEM and Administrators can change.
  The installer refuses an install root below a folder that other accounts
  could delete, rename or re-permission, and a machine PATH folder in which
  other accounts can add files. It creates the folders with their ACL in one
  step, checks their owner afterwards, and keeps the tasks disabled until it
  has read all of them back. `Test-HvLabInstall.ps1` repeats the checks from
  the operator's side.
- The worker reads nothing the operator can write, and acts on one VM by Id.
  It imports only the Hyper-V module, and it loads modules only from the
  Windows PowerShell folder: it sets PSModulePath before any command that can
  load a module runs.
- No password or key is stored by the lifecycle part.
- The guest is treated as untrusted: what the scripts read from it is parsed
  as data and checked before use, control characters in it are replaced
  before it is printed, ssh forwards neither the agent nor ports to it, and
  ssh reads no config file. The output of a `-Command` run is printed as ssh
  prints it.

Report security problems as described in [SECURITY.md](SECURITY.md).

## Limitations

- One VM per lab and six actions. No checkpoints, no NMI injection, no guest
  network repair; those need more rights than this design hands out.
- `Stop` asks the guest to shut down and waits up to 300 seconds; a guest that
  does not shut down needs `TurnOff`.
- An SSH key sign-in is an S4U network logon in session 0, not a console
  sign-in. It has no network credentials and cannot use DPAPI secrets that
  depend on the user's password, ACEs that grant INTERACTIVE do not apply to
  it, and a process in session 0 can create objects in the global namespace
  without SeCreateGlobalPrivilege. Show bugs that depend on DPAPI, a desktop
  or a session, INTERACTIVE ACEs or global object names at the VM console
  ([docs/ssh.md](docs/ssh.md#what-an-ssh-session-is)).
- The session report comes from `whoami` in the guest, so it is only as
  trustworthy as the guest, and it needs cmd.exe as the guest's OpenSSH
  default shell.
- The standard-user privilege set is the default User Rights Assignment of
  Windows client editions. A guest whose defaults grant Users more is
  refused as a standard-user guest.
- Exit code 255 from a guest command cannot be told apart from an SSH failure
  by the code alone; `Invoke-HvLabSsh.ps1` runs a second connection to tell.
- The guest helpers need Windows PowerShell to run a local script with
  `-ExecutionPolicy RemoteSigned`. A Group Policy that enforces `AllSigned`
  blocks them, and so does Constrained Language Mode (enforced by WDAC or
  AppLocker), because they use `Add-Type` and `New-Object`.
- `Test-HvLabKdnet.ps1` reads `bcdedit` values in English only. Its firewall
  check reads the local rules only, not rules from Group Policy, and does not
  evaluate profiles or rule order.
- Account names are limited to letters, digits, dots, underscores and hyphens
  (1 to 20 characters).

## Tests

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File tests\Invoke-HvLabChecks.ps1
pwsh -NoProfile -File tests\Invoke-HvLabChecks.ps1
```

This parses every PowerShell file, runs PSScriptAnalyzer when it is installed
(`-RequireAnalyzer` turns a missing analyzer into a failure), and runs the
Pester tests (Pester 3.4, which ships with Windows, or Pester 5). It uses the
newest installed version of each module; `-AnalyzerVersion` and
`-PesterVersion` select an exact version. `.github\workflows\checks.yml`
installs PSScriptAnalyzer and Pester 5 on a GitHub-hosted Windows runner, and
runs both commands with `-RequireAnalyzer` and those exact versions.

The tests are offline. They cover the worker's action logic and its lock
against replacement Hyper-V functions, that the worker sets its module path
before any command that can load a module, the task XML, the order of task
registration against an in-memory stand-in for the Task Scheduler API, the
security descriptors, the folder, ancestor and machine PATH checks, config
validation, the session report parser, the KDNET key hash of host and guest,
the guest scripts' `bcdedit` parser, public key check and `authorized_keys`
merge, the copy size limit, and repository-wide text and link rules.

They do not exercise Task Scheduler, Hyper-V, OpenSSH or a guest. Those parts
are checked on your host by the setup steps above, mainly
`Test-HvLabInstall.ps1 -RunStatus` and `Invoke-HvLabSsh.ps1 -ShowContext`.

## Repository layout

| Path | What it is |
|---|---|
| `host\Install-HvLab.ps1` | elevated, once: lab folder, worker, tasks, optional KDNET firewall rule |
| `host\Uninstall-HvLab.ps1` | elevated: removes all of the above for one lab |
| `host\Test-HvLabInstall.ps1` | operator: checks the install from the operator's side |
| `host\Invoke-HvLabVm.ps1` | operator: Start, Stop, TurnOff, Pause, Resume, Status |
| `host\Invoke-HvLabSsh.ps1` | operator: run a guest command as Admin or User, or report the session |
| `host\Test-HvLabKdnet.ps1` | operator: KDNET preflight |
| `host\Get-HvLabCrashDump.ps1` | operator: list or copy guest crash dumps |
| `host\HvLab.Common.psm1` | shared host functions (not used by the worker) |
| `host\worker\HvLabWorker.ps1` | the fixed-action worker that the installer copies into the protected lab folder |
| `guest\Install-HvLabGuestSsh.ps1` | run in the guest, elevated: SSH keys with the ACLs Windows OpenSSH requires |
| `guest\Get-HvLabKdnetInfo.ps1`, `guest\Get-HvLabDumpInfo.ps1` | helpers that the host uploads and runs for each check; they delete their uploaded copy and change nothing else, except the dump helper's staging folder in the guest admin's profile |
| `config\hvlab.example.json` | config template |
| `tests\` | offline checks (parse, PSScriptAnalyzer, Pester) |
| `.github\workflows\checks.yml` | runs the offline checks on a GitHub-hosted Windows runner |

## Related projects

Other repositories by the same author:

- [binja-agent-mcp](https://github.com/y637F9QQ2x/binja-agent-mcp): an MCP
  server for Binary Ninja, built for LLM agents.
- [windbg-hyperv-mcp](https://github.com/y637F9QQ2x/windbg-hyperv-mcp): an MCP
  server for Windows kernel and user-mode debugging of one Hyper-V guest. It
  runs this lab's VM tasks.
- [win-agent-probes](https://github.com/y637F9QQ2x/win-agent-probes):
  PowerShell probes for Windows security research; each prints one JSON
  document.
- [winremote-session-ext](https://github.com/y637F9QQ2x/winremote-session-ext):
  an extension for winremote-mcp that reports the Windows logon session the
  server runs in and restricts how its HTTP endpoint can be exposed.

The author's blog: [y637f9qq2x.com](https://y637f9qq2x.com).

## Credits and license

Written by Kazuma Matsumoto ([y637F9QQ2x](https://github.com/y637F9QQ2x)). No
third-party code is included.

The scripts use Windows components: the Hyper-V PowerShell module, the Task
Scheduler scripting API, Windows OpenSSH and, optionally, Debugging Tools for
Windows (not included). References:

- [Key-based authentication in OpenSSH for Windows](https://learn.microsoft.com/windows-server/administration/openssh/openssh_keymanagement)
- [Security protection of various files in Win32 OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH)
- [ITaskFolder::RegisterTask](https://learn.microsoft.com/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertask)
- [Set up KDNET network kernel debugging manually](https://learn.microsoft.com/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection)
- [Kernel object namespaces](https://learn.microsoft.com/windows/win32/termserv/kernel-object-namespaces)

License: MIT, Copyright (c) 2026 Kazuma Matsumoto. See [LICENSE](LICENSE).

This project is not affiliated with or endorsed by Microsoft. Windows and
Hyper-V are trademarks of Microsoft.
