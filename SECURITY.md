# Security policy

## Reporting a problem

Report a security problem in these scripts privately, through GitHub's
"Report a vulnerability" button on the Security tab of this repository.
Please do not open a public issue for it.

If the Security tab shows no such button, open an issue that asks for a
private contact, and leave every detail of the problem out of it.

Include the script name, the Windows build of the host or guest, and the
steps that show the problem.

## In scope

- A way for the operator account, or for code running as it, to run code as
  SYSTEM or as an administrator through the lab tasks or the lab folder.
- A host whose folders pass the installer's checks (the folders above the
  install root, the machine PATH folders, the install root and the lab
  folder) while another account can still replace the worker or put a DLL in
  the way of the SYSTEM task.
- A way for an account other than the operator to run the lab tasks.
- A way for a guest to make a host script write outside its target folder,
  write more than the size it reported, or run guest-supplied data.
- A host script that sends the KDNET key or a private key anywhere.

## Out of scope

- The six VM actions themselves. Letting the operator start, stop, turn off,
  pause and resume the VM without a UAC prompt is the purpose of the tool
  (see docs/trust-model.md).
- Anything that already requires administrator rights on the host.
- Weaknesses of the guest VM, which exists to run untrusted code.
