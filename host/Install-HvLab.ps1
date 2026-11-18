<#
.SYNOPSIS
    Registers the lab tasks for one Hyper-V VM. Run once, elevated.

.DESCRIPTION
    Lets one operator account start, stop, turn off, pause, resume and query
    one named Hyper-V VM without elevation, through six on-demand scheduled
    tasks. Read docs\trust-model.md before you run it.

    Checks before it changes anything:
      - The install root is on a fixed local drive, and every folder above it
        is owned by SYSTEM, Administrators or TrustedInstaller, is not a link,
        and gives nobody else the right to delete, rename or re-permission it.
      - No folder in the machine PATH lets another account add, delete or
        rename files, because a SYSTEM process searches these folders for
        DLLs it does not find elsewhere.
      - An install root or lab folder that already exists could not have been
        changed by another account. Such a folder is refused, not repaired.

    What it changes on the host:
      1. Creates <InstallRoot> and <InstallRoot>\<Lab> with ACLs that only
         SYSTEM and Administrators can change (the operator may read the lab
         folder), and checks afterwards that no other account created them
         first.
      2. Copies worker\HvLabWorker.ps1 into the lab folder, writes worker.json
         (VM name and Id) and install.json (what was installed, with SHA-256
         hashes), and checks both folders again.
      3. Registers the tasks \HyperVLpeLab\<Lab>\<Action>, disabled at first.
         Each runs the worker as SYSTEM with one fixed action. Only the
         operator may run them, and only SYSTEM and Administrators may change
         or delete them. The tasks are enabled only after all of them were
         read back and checked; when a check fails, they are deleted.
      4. With -KdnetPort, adds an inbound UDP firewall rule for KDNET that
         accepts only -KdnetRemoteAddress (and, when given, only on
         -KdnetInterfaceAlias and for -KdnetProgram).

    It changes nothing in the guest. Uninstall-HvLab.ps1 removes all of it.

    The installer runs elevated and copies the worker as it finds it next to
    this script. Run it from a copy that the operator account cannot change,
    or review the files first.

.PARAMETER VmName
    Exact name of the Hyper-V VM (case-sensitive, no wildcards).

.PARAMETER Lab
    Short lab name: 1 to 32 letters, digits or hyphens. It names the task
    folder and the lab folder.

.PARAMETER OperatorAccount
    The account allowed to run the tasks, as DOMAIN\name, COMPUTER\name or a
    SID. Only an account, or a group created for the lab, is accepted;
    well-known and built-in groups (Everyone, Users, Authenticated Users,
    Domain Users and similar) are refused.

.PARAMETER InstallRoot
    Folder that holds the lab folders. Default: %ProgramData%\HyperVLpeLab.
    Its parent folder must exist and pass the checks above.

.PARAMETER KdnetPort
    When not 0, adds the inbound firewall rule HyperVLpeLab-<Lab>-KDNET for
    this UDP port, so a non-elevated debugger can receive the KDNET connection.

.PARAMETER KdnetRemoteAddress
    Required with -KdnetPort: the only remote addresses the rule accepts.
    Use the lab network's prefix, such as 192.0.2.0/24. The KDNET transport
    in the guest can use a different address than Windows in the guest, so
    a single address fits only when you know the one that KDNET uses.

.PARAMETER KdnetInterfaceAlias
    Optional with -KdnetPort: limit the rule to this host network adapter,
    normally the lab switch's adapter 'vEthernet (<switch name>)'.

.PARAMETER KdnetProgram
    Optional with -KdnetPort: limit the rule to this program, for example the
    full path of kd.exe. Leave it out when another debugger host process
    receives the connection.

.EXAMPLE
    .\Install-HvLab.ps1 -VmName 'LPE Lab' -Lab lab1 -OperatorAccount "$env:COMPUTERNAME\researcher"

.EXAMPLE
    .\Install-HvLab.ps1 -VmName 'LPE Lab' -Lab lab1 -OperatorAccount "$env:COMPUTERNAME\researcher" -KdnetPort 50000 -KdnetRemoteAddress 192.0.2.0/24 -KdnetInterfaceAlias 'vEthernet (Lab)'
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$VmName,
    [Parameter(Mandatory)][string]$Lab,
    [Parameter(Mandatory)][string]$OperatorAccount,
    [string]$InstallRoot = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HyperVLpeLab'),
    [ValidateRange(0, 65535)][int]$KdnetPort = 0,
    [string]$KdnetRemoteAddress,
    [string]$KdnetInterfaceAlias,
    [string]$KdnetProgram
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HvLab.Common.psm1') -Force

function New-HvLabSecureDirectory {
    # Creates the folder with its final ACL in one call, so no other account
    # can create anything in it between creation and locking.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$Security
    )
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create folder')) { return }
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]
    if ($null -ne $extensions) {
        $null = [System.IO.FileSystemAclExtensions]::CreateDirectory($Security, $Path)
    }
    else {
        $null = [System.IO.Directory]::CreateDirectory($Path, $Security)
    }
}

function Set-HvLabDirectorySecurity {
    # Applies owner and DACL with the .NET API, which writes only the parts
    # that were set (Set-Acl may also try to write the audit list).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$Security
    )
    if (-not $PSCmdlet.ShouldProcess($Path, 'Set owner and ACL')) { return }
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]
    if ($null -ne $extensions) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($Path), $Security)
    }
    else {
        [System.IO.Directory]::SetAccessControl($Path, $Security)
    }
}

function Initialize-HvLabFolder {
    # Creates the folder with its final ACL, or accepts an existing folder only
    # when no account other than SYSTEM and Administrators could have changed
    # it. Then applies the owner and ACL, and reads them back.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$Security,
        [Parameter(Mandatory)][string]$InstallerSid,
        [switch]$Recurse
    )
    if (Test-Path -LiteralPath $Path) {
        $problems = @(Get-HvLabAclProblem -Path $Path -Recurse:$Recurse -RequireProtected)
        if ($problems.Count -gt 0) {
            throw ("'$Path' already exists and another account could have changed it:`n  " + ($problems -join "`n  ") +
                "`nInspect it, remove it, and run this script again.")
        }
    }
    else {
        New-HvLabSecureDirectory -Path $Path -Security $Security
        # CreateDirectory also reports success for a folder that another account
        # created a moment earlier, and then applies no ACL. The owner shows who
        # created the folder: this script asks for Administrators.
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (@('S-1-5-32-544', 'S-1-5-18', $InstallerSid) -notcontains $owner) {
            throw ("'$Path' is owned by $owner, so another account created it while this script was creating it. " +
                'Inspect it, remove it, and run this script again.')
        }
    }
    Set-HvLabDirectorySecurity -Path $Path -Security $Security
    $problems = @(Get-HvLabAclProblem -Path $Path -Recurse:$Recurse -RequireProtected)
    if ($problems.Count -gt 0) {
        throw ("'$Path' does not have the ACL that this script set:`n  " + ($problems -join "`n  "))
    }
}

# Input checks. Nothing is changed before all of them pass.
if (-not (Test-HvLabName -Name $Lab)) { throw "Lab '$Lab' must be 1 to 32 letters, digits or hyphens, starting with a letter or digit." }
$InstallRoot = $InstallRoot.TrimEnd('\')
$problem = Get-HvLabInstallRootProblem -Path $InstallRoot
if ($problem) { throw "InstallRoot '$InstallRoot': $problem." }
$labDirectory = $InstallRoot + '\' + $Lab
$problem = Get-HvLabInstallRootProblem -Path $labDirectory
if ($problem) { throw "Lab folder '$labDirectory': $problem." }
$workerSource = Join-Path $PSScriptRoot 'worker\HvLabWorker.ps1'
if (-not (Test-Path -LiteralPath $workerSource -PathType Leaf)) { throw "Worker '$workerSource' not found next to this script." }
if ($KdnetPort -gt 0) {
    if (-not $KdnetRemoteAddress) {
        throw '-KdnetPort needs -KdnetRemoteAddress: the prefix of the lab network, for example 192.0.2.0/24.'
    }
    if (-not (Test-HvLabRemoteAddress -Address $KdnetRemoteAddress)) {
        throw "KdnetRemoteAddress '$KdnetRemoteAddress' must be one IPv4 or IPv6 address, or an address prefix such as 192.0.2.0/24."
    }
    if ($KdnetInterfaceAlias -and $null -eq (Get-NetAdapter -Name $KdnetInterfaceAlias -IncludeHidden -ErrorAction SilentlyContinue)) {
        throw "No network adapter is named '$KdnetInterfaceAlias'. Get-NetAdapter lists them; the lab switch's adapter is named 'vEthernet (<switch name>)'."
    }
    if ($KdnetProgram -and -not ([System.IO.Path]::IsPathRooted($KdnetProgram) -and (Test-Path -LiteralPath $KdnetProgram -PathType Leaf))) {
        throw "KdnetProgram '$KdnetProgram' must be the full path of an existing program, such as kd.exe."
    }
}
elseif ($KdnetRemoteAddress -or $KdnetInterfaceAlias -or $KdnetProgram) {
    throw '-KdnetRemoteAddress, -KdnetInterfaceAlias and -KdnetProgram need -KdnetPort.'
}
$powerShellPath = Get-HvLabWindowsPowerShellPath
if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) { throw "Windows PowerShell not found at '$powerShellPath'." }

try {
    if ($OperatorAccount -match '^S-1-') {
        $operatorSid = ([System.Security.Principal.SecurityIdentifier]::new($OperatorAccount)).Value
    }
    else {
        $operatorSid = ([System.Security.Principal.NTAccount]::new($OperatorAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
}
catch {
    throw "Cannot resolve OperatorAccount '$OperatorAccount' to a SID: $($_.Exception.Message)"
}
$problem = Get-HvLabOperatorSidProblem -Sid $operatorSid
if ($problem) { throw "OperatorAccount '$OperatorAccount': $problem." }
try {
    $operatorName = ([System.Security.Principal.SecurityIdentifier]::new($operatorSid)).Translate([System.Security.Principal.NTAccount]).Value
}
catch {
    $operatorName = $operatorSid
}

try {
    $adminGroup = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
    $adminMembers = @(Get-CimAssociatedInstance -InputObject $adminGroup -Association Win32_GroupUser -ErrorAction Stop)
    if (@($adminMembers | Where-Object { $_.SID -eq $operatorSid }).Count -gt 0) {
        Write-Warning ("$operatorName is a direct member of Administrators. The tasks then only save it the UAC prompt " +
            'for these six actions. The design aims at a standard operator account; see docs\trust-model.md.')
    }
}
catch {
    Write-Warning "Could not list the Administrators group to check the operator: $($_.Exception.Message)"
}

Import-Module -Name Hyper-V -ErrorAction Stop
$matchingVms = @(Get-VM | Where-Object { $_.Name -ceq $VmName })
if ($matchingVms.Count -ne 1) {
    throw "Expected exactly one VM named '$VmName' (case-sensitive), found $($matchingVms.Count)."
}
$vmId = $matchingVms[0].Id.ToString()

# Host checks that the install depends on. Nothing has been changed yet.
$installerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$hostProblems = New-Object System.Collections.Generic.List[string]
foreach ($item in @(Get-HvLabAncestorProblem -Path $InstallRoot)) { $hostProblems.Add($item) }
foreach ($item in @(Get-HvLabSearchPathProblem -PathValue ([Environment]::GetEnvironmentVariable('Path', 'Machine')))) { $hostProblems.Add($item) }
if ($hostProblems.Count -gt 0) {
    throw ("Nothing was changed. Another account could replace the worker, or a DLL that the SYSTEM tasks load:`n  " +
        ($hostProblems -join "`n  ") + "`nSee docs\trust-model.md, The path to the worker is protected.")
}

$ruleName = $null
if ($KdnetPort -gt 0) { $ruleName = "HyperVLpeLab-$Lab-KDNET" }

if (-not $PSCmdlet.ShouldProcess("lab '$Lab' (VM '$VmName', operator $operatorName, folder $labDirectory)", 'Install hyperv-lpe-lab folder, worker and tasks')) {
    return
}

# 1. Folders.
Initialize-HvLabFolder -Path $InstallRoot -Security (Get-HvLabDirectorySecurity -Kind Root) -InstallerSid $installerSid
Initialize-HvLabFolder -Path $labDirectory -Security (Get-HvLabDirectorySecurity -Kind Lab -OperatorSid $operatorSid) -InstallerSid $installerSid -Recurse
foreach ($sub in @('state', 'logs')) {
    $subPath = Join-Path $labDirectory $sub
    if (-not (Test-Path -LiteralPath $subPath -PathType Container)) { $null = New-Item -ItemType Directory -Path $subPath }
}

# 2. Files, then a check of both folders before any task exists.
$utf8 = New-Object System.Text.UTF8Encoding($false)
$workerTarget = Join-Path $labDirectory 'HvLabWorker.ps1'
[System.IO.File]::WriteAllBytes($workerTarget, [System.IO.File]::ReadAllBytes($workerSource))
$workerHash = (Get-FileHash -LiteralPath $workerTarget -Algorithm SHA256).Hash
if ($workerHash -ne (Get-FileHash -LiteralPath $workerSource -Algorithm SHA256).Hash) { throw 'The copied worker does not match its source.' }
$workerConfigPath = Join-Path $labDirectory 'worker.json'
$workerConfig = [ordered]@{ schema = 'hvlab-worker/1'; lab = $Lab; vmName = $VmName; vmId = $vmId }
[System.IO.File]::WriteAllText($workerConfigPath, (ConvertTo-Json -InputObject $workerConfig), $utf8)
$manifest = [ordered]@{
    schema          = 'hvlab-install/1'
    lab             = $Lab
    vmName          = $VmName
    vmId            = $vmId
    operatorAccount = $operatorName
    operatorSid     = $operatorSid
    installRoot     = $InstallRoot
    labDirectory    = $labDirectory
    taskFolder      = (Get-HvLabTaskFolderPath -Lab $Lab)
    tasks           = @(Get-HvLabAction)
    firewallRule    = $ruleName
    files           = [ordered]@{
        'HvLabWorker.ps1' = $workerHash
        'worker.json'     = (Get-FileHash -LiteralPath $workerConfigPath -Algorithm SHA256).Hash
    }
    installedBy     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    installedUtc    = [DateTime]::UtcNow.ToString('o')
}
$manifestPath = Join-Path $labDirectory 'install.json'
[System.IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $manifest -Depth 4), $utf8)
# New files may be owned by the installing account; make Administrators the
# owner of everything in the lab folder, so the ACL check below is exact.
$icaclsOutput = & icacls.exe $labDirectory /setowner '*S-1-5-32-544' /T /C /Q 2>&1
if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed for ${labDirectory}: $($icaclsOutput -join ' ')" }

$fileProblems = New-Object System.Collections.Generic.List[string]
foreach ($item in @(Get-HvLabAclProblem -Path $InstallRoot -RequireProtected)) { $fileProblems.Add($item) }
foreach ($item in @(Get-HvLabAclProblem -Path $labDirectory -Recurse -RequireProtected)) { $fileProblems.Add($item) }
if ((Get-FileHash -LiteralPath $workerTarget -Algorithm SHA256).Hash -ne $workerHash) { $fileProblems.Add("$workerTarget changed after it was copied") }
if ($fileProblems.Count -gt 0) {
    throw ("The folder check failed, so no task was registered:`n  " + ($fileProblems -join "`n  ") +
        "`nRun Uninstall-HvLab.ps1 -Lab $Lab and investigate.")
}

# 3. Tasks: registered disabled, checked, enabled, checked again.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
try {
    $null = Register-HvLabTaskSet -Service $service -Lab $Lab -LabDirectory $labDirectory -PowerShellPath $powerShellPath -OperatorSid $operatorSid
}
catch {
    throw "$($_.Exception.Message)`nThe lab folder is still there; Uninstall-HvLab.ps1 -Lab $Lab removes it."
}

# 4. Firewall rule for KDNET (optional).
$ruleScope = $null
if ($KdnetPort -gt 0) {
    $ruleArguments = @{
        Name          = $ruleName
        DisplayName   = "HyperVLpeLab $Lab KDNET UDP $KdnetPort"
        Group         = 'HyperVLpeLab'
        Description   = 'Inbound KDNET for a hyperv-lpe-lab guest. Removed by Uninstall-HvLab.ps1.'
        Direction     = 'Inbound'
        Action        = 'Allow'
        Protocol      = 'UDP'
        LocalPort     = $KdnetPort
        RemoteAddress = $KdnetRemoteAddress
        Profile       = 'Any'
    }
    if ($KdnetInterfaceAlias) { $ruleArguments.InterfaceAlias = $KdnetInterfaceAlias }
    if ($KdnetProgram) { $ruleArguments.Program = $KdnetProgram }
    Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $null = New-NetFirewallRule @ruleArguments
    $interfaceText = 'any interface'
    if ($KdnetInterfaceAlias) { $interfaceText = "interface '$KdnetInterfaceAlias'" }
    $programText = 'any program'
    if ($KdnetProgram) { $programText = $KdnetProgram }
    $ruleScope = "inbound UDP $KdnetPort from $KdnetRemoteAddress only, $interfaceText, $programText, all profiles"
}

[pscustomobject]@{
    Lab           = $Lab
    VmName        = $VmName
    VmId          = $vmId
    Operator      = $operatorName
    LabDirectory  = $labDirectory
    TaskFolder    = (Get-HvLabTaskFolderPath -Lab $Lab)
    Tasks         = (@(Get-HvLabAction) -join ', ')
    FirewallRule  = $ruleName
    FirewallScope = $ruleScope
    WorkerSha256  = $workerHash
    Next          = "As $operatorName, not elevated: powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-HvLabInstall.ps1 -Lab $Lab -RunStatus"
}
