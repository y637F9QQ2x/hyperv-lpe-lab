<#
.SYNOPSIS
    Shared helpers for the hyperv-lpe-lab host scripts.

.DESCRIPTION
    Validation, scheduled task XML and registration, security descriptors, ACL
    checks, config loading, and the OpenSSH helpers used by the host scripts.

    The module loads in Windows PowerShell 5.1 and in PowerShell 7. The SSH
    helpers are called only from scripts that require PowerShell 7.3 or later,
    because those scripts rely on its exact native argument passing.

    The elevated worker (worker\HvLabWorker.ps1) does not load this module. It
    is self-contained on purpose: the installer copies it alone into a folder
    that only SYSTEM and Administrators can change.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:PSNativeCommandArgumentPassing = 'Standard'

$script:Actions = @('Start', 'Stop', 'TurnOff', 'Pause', 'Resume', 'Status')
$script:TaskRootName = 'HyperVLpeLab'
$script:ResultPrefix = 'HVLAB-RESULT '
$script:TrustedSids = @('S-1-5-18', 'S-1-5-32-544')
# SYSTEM, Administrators and TrustedInstaller. TrustedInstaller owns C:\ and
# the Windows folders.
$script:SystemOwnerSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

# Rights that let a principal change a file, a folder or a task definition:
# FILE_WRITE_DATA 0x2, FILE_APPEND_DATA 0x4, FILE_WRITE_EA 0x10,
# FILE_DELETE_CHILD 0x40, FILE_WRITE_ATTRIBUTES 0x100, DELETE 0x10000,
# WRITE_DAC 0x40000, WRITE_OWNER 0x80000, GENERIC_ALL 0x10000000,
# GENERIC_WRITE 0x40000000.
$script:WriteMask = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)

# Rights that let a principal delete or rename a folder or the items in it, or
# change its permissions: FILE_DELETE_CHILD 0x40, DELETE 0x10000, WRITE_DAC
# 0x40000, WRITE_OWNER 0x80000, GENERIC_ALL 0x10000000, GENERIC_WRITE
# 0x40000000. The rights to create files and subfolders are not part of it:
# C:\ and C:\ProgramData give them to all users, and they do not let anyone
# replace an item that already exists.
$script:ReplaceMask = [int64](0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)

# ReplaceMask plus FILE_ADD_FILE 0x2: enough to put a DLL into a folder.
$script:PlantMask = [int64]($script:ReplaceMask -bor 0x2)

# ReplaceMask plus FILE_ADD_SUBDIRECTORY 0x4: enough to create a missing folder.
$script:CreateMask = [int64]($script:ReplaceMask -bor 0x4)

# Privileges of a standard user's token on a Windows client edition, from the
# default User Rights Assignment for Everyone and Users. Server editions give
# Users fewer of them.
$script:StandardUserPrivileges = @('SeChangeNotifyPrivilege', 'SeShutdownPrivilege', 'SeUndockPrivilege',
    'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege')

# Groups that a standard user's token carries: Everyone, LOCAL, CONSOLE LOGON,
# NETWORK, INTERACTIVE, Authenticated Users, REMOTE INTERACTIVE LOGON, This
# Organization, Local account, Users, Remote Desktop Users and the Medium
# integrity label. Remote Desktop Users is included because a standard account
# needs it to sign in through Remote Desktop or a Hyper-V enhanced session; it
# grants a logon right and no privilege. The pattern below adds the logon
# session SID (S-1-5-5-x-y), the authentication package SID (S-1-5-64-x) and
# the asserted identity SIDs (S-1-18-x). The account's own RID 513 group (None
# for a local account, Domain Users in a domain) is matched separately.
$script:StandardUserGroupSids = @('S-1-1-0', 'S-1-2-0', 'S-1-2-1', 'S-1-5-2', 'S-1-5-4', 'S-1-5-11', 'S-1-5-14',
    'S-1-5-15', 'S-1-5-113', 'S-1-5-32-545', 'S-1-5-32-555', 'S-1-16-8192')
$script:StandardUserGroupPattern = '^S-1-5-5-\d+-\d+$|^S-1-5-64-\d+$|^S-1-18-\d+$'

# The guest commands of the session report, run as one cmd.exe command line.
$script:ContextCommands = @(
    'whoami /user /fo csv /nh',
    'whoami /groups /fo csv /nh',
    'whoami /priv /fo csv /nh',
    'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense 2>nul || echo HVLAB-NOVALUE',
    'powershell.exe -NoLogo -NoProfile -NonInteractive -Command [Diagnostics.Process]::GetCurrentProcess().SessionId 2>nul'
)
$script:ContextSection = 'HVLAB-SECTION'
$script:ContextEnd = 'HVLAB-CONTEXT-END'

function Get-HvLabAction {
    <#
    .SYNOPSIS
        Returns the fixed list of VM actions.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return [string[]]$script:Actions.Clone()
}

function Get-HvLabTaskFolderPath {
    <#
    .SYNOPSIS
        Returns the Task Scheduler folder path of a lab, or of the root folder.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Lab)
    if (-not $Lab) { return "\$script:TaskRootName" }
    if (-not (Test-HvLabName -Name $Lab)) { throw "Invalid lab name '$Lab'." }
    return "\$script:TaskRootName\$Lab"
}

function Get-HvLabResultPrefix {
    <#
    .SYNOPSIS
        Returns the prefix of the result line that guest helper scripts print.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:ResultPrefix
}

function Test-HvLabName {
    <#
    .SYNOPSIS
        Tests a lab name: 1 to 32 characters, letters, digits and hyphens,
        starting with a letter or digit.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Name)
    return [bool]($Name -cmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,31}$')
}

function Get-HvLabInstallRootProblem {
    <#
    .SYNOPSIS
        Returns why a path cannot be the install root or a lab folder, or $null.
    .DESCRIPTION
        The path ends up, as literal text, in the action of a task that runs as
        SYSTEM. So it must be absolute, on a local drive, and made of plain
        characters only (no quotes, no environment variables, no wildcards).
        Get-HvLabAncestorProblem checks the folders above it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'the path is empty' }
    if ($Path -notmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+$') {
        return 'use an absolute path on a local drive, made of letters, digits, spaces, dots, underscores, hyphens and backslashes'
    }
    if ($Path.Length -gt 150) { return 'the path is longer than 150 characters' }
    foreach ($segment in $Path.Substring(3).Split('\')) {
        if ($segment -eq '') { return 'the path has an empty segment or a trailing backslash' }
        if ($segment -eq '.' -or $segment -eq '..') { return 'the path has a . or .. segment' }
        if ($segment -ne $segment.Trim() -or $segment.EndsWith('.')) {
            return 'a path segment starts or ends with a space, or ends with a dot'
        }
    }
    if ($Path -match '^[A-Za-z]:\\Users(\\|$)') {
        return 'the path is under the Users folder, where accounts other than administrators can create files'
    }
    return $null
}

function Get-HvLabOperatorSidProblem {
    <#
    .SYNOPSIS
        Returns why a SID cannot be the operator, or $null.
    .DESCRIPTION
        The operator is one account, or a group created for the lab, that may
        run the lab tasks. Only two kinds of SID are accepted: an account or
        group of a machine or domain with a RID of 1000 or higher
        (S-1-5-21-a-b-c-RID), and a Microsoft Entra ID account
        (S-1-12-1-a-b-c-d). Every well-known and service SID is refused, and so
        are the built-in accounts and groups of a machine or domain (RID below
        1000), such as Administrator, Guest, Domain Users and Domain Admins.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sid)

    try {
        $value = ([System.Security.Principal.SecurityIdentifier]::new($Sid)).Value
    }
    catch {
        return "'$Sid' is not a valid SID"
    }
    if ($script:TrustedSids -contains $value) {
        return 'SYSTEM and Administrators already have full control; name the account that runs the host scripts'
    }
    if ($value -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        if ([int64]$Matches[1] -ge 1000) { return $null }
        return "$value is a built-in account or group of its machine or domain (RID below 1000); name one account, or a group created for this lab"
    }
    if ($value -match '^S-1-12-1-\d+-\d+-\d+-\d+$') { return $null }
    return "$value is a well-known or service SID, not one account; name one account, or a group created for this lab"
}

function Get-HvLabSddl {
    <#
    .SYNOPSIS
        Returns the security descriptor (SDDL) for the lab task folders and tasks.
    .DESCRIPTION
        TaskRootFolder: SYSTEM and Administrators full control, Authenticated
        Users may read the folder (it lists lab names only).
        LabTaskFolder: SYSTEM and Administrators full control, the operator may
        read the folder.
        Task: SYSTEM and Administrators full control, the operator may read and
        run the task (FRFX). Nobody else may change, delete or run it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateSet('TaskRootFolder', 'LabTaskFolder', 'Task')][string]$Kind,
        [string]$OperatorSid
    )
    if ($Kind -eq 'TaskRootFolder') { return 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)' }
    $problem = Get-HvLabOperatorSidProblem -Sid $OperatorSid
    if ($problem) { throw $problem }
    $sid = ([System.Security.Principal.SecurityIdentifier]::new($OperatorSid)).Value
    if ($Kind -eq 'LabTaskFolder') { return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$sid)" }
    return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;$sid)"
}

function Test-HvLabWriteAccess {
    <#
    .SYNOPSIS
        Tests whether an access mask contains any right that allows a change.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][int64]$AccessMask)
    return (($AccessMask -band $script:WriteMask) -ne 0)
}

function Get-HvLabSddlProblem {
    <#
    .SYNOPSIS
        Lists the ACEs of an SDDL string that let anyone other than SYSTEM or
        Administrators change or delete the object.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Sddl)

    $problems = New-Object System.Collections.Generic.List[string]
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $sd.DiscretionaryAcl) {
        $problems.Add('the security descriptor has no DACL, so everyone has full access')
        return $problems.ToArray()
    }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $known = $ace -is [System.Security.AccessControl.KnownAce]
        if (-not $known) {
            $problems.Add("unrecognized ACE type $($ace.AceType)")
            continue
        }
        $allowed = "$($ace.AceType)" -like 'AccessAllowed*'
        if (-not $allowed) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if ($script:TrustedSids -contains $sid) { continue }
        if (Test-HvLabWriteAccess -AccessMask ([int64]$ace.AccessMask)) {
            $problems.Add(('{0} has access mask 0x{1:X8}, which allows changes' -f $sid, $ace.AccessMask))
        }
    }
    return $problems.ToArray()
}

function Get-HvLabWindowsPowerShellPath {
    <#
    .SYNOPSIS
        Returns the literal path of the built-in Windows PowerShell 5.1.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    return ($system.TrimEnd('\') + '\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-HvLabTaskArgument {
    <#
    .SYNOPSIS
        Returns the fixed argument string of one lab task.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$Action
    )
    if ($script:Actions -cnotcontains $Action) { throw "Unknown action '$Action'." }
    $problem = Get-HvLabInstallRootProblem -Path $LabDirectory
    if ($problem) { throw "Invalid lab folder '$LabDirectory': $problem." }
    $worker = $LabDirectory.TrimEnd('\') + '\HvLabWorker.ps1'
    return ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "{0}" -Action {1}' -f $worker, $Action)
}

function Get-HvLabTaskXml {
    <#
    .SYNOPSIS
        Returns the Task Scheduler XML of one lab task.
    .DESCRIPTION
        The task has no trigger (it runs only on demand), runs as SYSTEM, allows
        one instance of itself at a time, stops after 10 minutes, and has one
        action: the built-in Windows PowerShell running the worker with a fixed
        -Action. The action has no $(Arg0) placeholder, so arguments given to
        Run() are ignored. -Enabled $false writes a disabled task; the
        installer registers the tasks disabled first and enables them only
        after it has read them back.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Lab,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$PowerShellPath,
        [bool]$Enabled = $true
    )
    if (-not (Test-HvLabName -Name $Lab)) { throw "Invalid lab name '$Lab'." }
    if ($PowerShellPath -notmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+\\powershell\.exe$') {
        throw "Unexpected Windows PowerShell path '$PowerShellPath'."
    }
    $arguments = Get-HvLabTaskArgument -LabDirectory $LabDirectory -Action $Action
    $description = "hyperv-lpe-lab: runs the fixed $Action action on the VM of lab $Lab. No parameters."
    $enabledText = 'false'
    if ($Enabled) { $enabledText = 'true' }
    $lines = @(
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '  <RegistrationInfo>'
        '    <Author>hyperv-lpe-lab</Author>'
        ('    <Description>{0}</Description>' -f [System.Security.SecurityElement]::Escape($description))
        '  </RegistrationInfo>'
        '  <Principals>'
        '    <Principal id="Author">'
        '      <UserId>S-1-5-18</UserId>'
        # The principal is SYSTEM, which has no filtered (UAC split) token, so
        # this run level has nothing to raise. The operator gets the right to
        # start the fixed command line, never the task's token.
        '      <RunLevel>HighestAvailable</RunLevel>'
        '    </Principal>'
        '  </Principals>'
        '  <Settings>'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
        '    <AllowHardTerminate>true</AllowHardTerminate>'
        '    <StartWhenAvailable>false</StartWhenAvailable>'
        '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
        '    <IdleSettings>'
        '      <StopOnIdleEnd>false</StopOnIdleEnd>'
        '      <RestartOnIdle>false</RestartOnIdle>'
        '    </IdleSettings>'
        '    <AllowStartOnDemand>true</AllowStartOnDemand>'
        ('    <Enabled>{0}</Enabled>' -f $enabledText)
        '    <Hidden>false</Hidden>'
        '    <RunOnlyIfIdle>false</RunOnlyIfIdle>'
        '    <WakeToRun>false</WakeToRun>'
        '    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>'
        '    <Priority>7</Priority>'
        '  </Settings>'
        '  <Actions Context="Author">'
        '    <Exec>'
        ('      <Command>{0}</Command>' -f [System.Security.SecurityElement]::Escape($PowerShellPath))
        ('      <Arguments>{0}</Arguments>' -f [System.Security.SecurityElement]::Escape($arguments))
        ('      <WorkingDirectory>{0}</WorkingDirectory>' -f [System.Security.SecurityElement]::Escape($LabDirectory))
        '    </Exec>'
        '  </Actions>'
        '</Task>'
    )
    return ($lines -join "`r`n")
}

function Get-HvLabTaskXmlProblem {
    <#
    .SYNOPSIS
        Compares a registered task's XML with what the installer writes.
    .DESCRIPTION
        -Enabled says which state the task should be in: enabled (the default),
        or disabled, as the installer registers it before its checks.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$Xml,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$PowerShellPath,
        [bool]$Enabled = $true
    )
    $problems = New-Object System.Collections.Generic.List[string]
    [xml]$doc = $Xml
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')

    $userIds = @($doc.SelectNodes('/t:Task/t:Principals/t:Principal/t:UserId', $ns))
    $sid = $null
    if ($userIds.Count -eq 1) {
        $text = $userIds[0].InnerText
        try { $sid = ([System.Security.Principal.NTAccount]::new($text)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = $text }
    }
    if ($sid -ne 'S-1-5-18') { $problems.Add("the task does not run as SYSTEM (UserId: $(@($userIds | ForEach-Object { $_.InnerText }) -join ', '))") }

    $triggers = @($doc.SelectNodes('/t:Task/t:Triggers/*', $ns))
    if ($triggers.Count -ne 0) { $problems.Add("the task has $($triggers.Count) trigger(s); it should run on demand only") }

    $actions = @($doc.SelectNodes('/t:Task/t:Actions/*', $ns))
    if ($actions.Count -ne 1 -or $actions[0].LocalName -ne 'Exec') {
        $problems.Add("the task has $($actions.Count) action(s); expected one Exec action")
    }
    else {
        $command = $actions[0].SelectSingleNode('t:Command', $ns)
        $arguments = $actions[0].SelectSingleNode('t:Arguments', $ns)
        $expectedArguments = Get-HvLabTaskArgument -LabDirectory $LabDirectory -Action $Action
        if ($null -eq $command -or $command.InnerText -ne $PowerShellPath) {
            $problems.Add('the task command is not the built-in Windows PowerShell path')
        }
        if ($null -eq $arguments -or $arguments.InnerText -cne $expectedArguments) {
            $problems.Add('the task arguments differ from the fixed worker command line')
        }
    }
    if ($Xml -match '\$\(Arg\d+\)') { $problems.Add('the task contains a $(ArgN) placeholder') }

    $enabledNode = $doc.SelectSingleNode('/t:Task/t:Settings/t:Enabled', $ns)
    $isEnabled = ($null -eq $enabledNode -or $enabledNode.InnerText -eq 'true')
    if ($Enabled -and -not $isEnabled) { $problems.Add('the task is disabled') }
    if (-not $Enabled -and $isEnabled) { $problems.Add('the task is enabled, but it should still be disabled') }
    return $problems.ToArray()
}

function Initialize-HvLabTaskFolder {
    <#
    .SYNOPSIS
        Returns a Task Scheduler folder, creating it with an SDDL or resetting
        its SDDL.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][object]$Service,
        [Parameter(Mandatory)][string]$ParentPath,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Sddl
    )
    $fullPath = ($ParentPath.TrimEnd('\') + '\' + $Name)
    $folder = $null
    try { $folder = $Service.GetFolder($fullPath) } catch { $folder = $null }
    if ($null -eq $folder) {
        $folder = $Service.GetFolder($ParentPath).CreateFolder($Name, $Sddl)
    }
    else {
        $folder.SetSecurityDescriptor($Sddl, 0)
    }
    return $folder
}

function Get-HvLabRegisteredTaskProblem {
    <#
    .SYNOPSIS
        Reads the lab's six registered tasks back and lists every difference
        from what the installer writes.
    .DESCRIPTION
        Checks each task's principal, triggers, command line, placeholders,
        enabled state (-Enabled) and security descriptor, and that the operator
        has an entry in it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][object]$Folder,
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$PowerShellPath,
        [Parameter(Mandatory)][string]$OperatorSid,
        [bool]$Enabled = $true
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $operatorEntry = [regex]::Escape(";$OperatorSid)")
    foreach ($action in $script:Actions) {
        try {
            $task = $Folder.GetTask($action)
        }
        catch {
            $problems.Add("task $action cannot be read: $($_.Exception.Message)")
            continue
        }
        foreach ($item in @(Get-HvLabTaskXmlProblem -Xml $task.Xml -Action $action -LabDirectory $LabDirectory -PowerShellPath $PowerShellPath -Enabled $Enabled)) {
            $problems.Add("$($task.Path): $item")
        }
        $sddl = [string]$task.GetSecurityDescriptor(4)
        foreach ($item in @(Get-HvLabSddlProblem -Sddl $sddl)) { $problems.Add("$($task.Path): $item") }
        if ($sddl -notmatch $operatorEntry) { $problems.Add("$($task.Path): the operator has no access entry") }
    }
    return $problems.ToArray()
}

function Remove-HvLabTaskFolder {
    <#
    .SYNOPSIS
        Deletes the tasks and the task folder of one lab, and the root task
        folder when it is then empty. Returns what was removed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][object]$Service,
        [Parameter(Mandatory)][string]$Lab
    )
    $removed = New-Object System.Collections.Generic.List[string]
    $rootPath = Get-HvLabTaskFolderPath
    $labPath = Get-HvLabTaskFolderPath -Lab $Lab
    if (-not $PSCmdlet.ShouldProcess($labPath, 'Delete the lab tasks and their task folder')) { return $removed.ToArray() }
    $labFolder = $null
    try { $labFolder = $Service.GetFolder($labPath) } catch { $labFolder = $null }
    if ($null -ne $labFolder) {
        foreach ($name in @($labFolder.GetTasks(1) | ForEach-Object { $_.Name })) {
            $labFolder.DeleteTask($name, 0)
            $removed.Add("task $labPath\$name")
        }
        $Service.GetFolder($rootPath).DeleteFolder($Lab, 0)
        $removed.Add("task folder $labPath")
    }
    $root = $null
    try { $root = $Service.GetFolder($rootPath) } catch { $root = $null }
    if ($null -ne $root -and @($root.GetFolders(0)).Count -eq 0 -and @($root.GetTasks(1)).Count -eq 0) {
        $Service.GetFolder('\').DeleteFolder($script:TaskRootName, 0)
        $removed.Add("task folder $rootPath")
    }
    return $removed.ToArray()
}

function Register-HvLabTaskSet {
    <#
    .SYNOPSIS
        Registers the six lab tasks so that none of them can run before all of
        them have been checked.
    .DESCRIPTION
        1. Creates the task folders with their security descriptors.
        2. Registers every task disabled, then reads all of them back.
        3. Registers them again enabled, then reads all of them back again.
        If a check fails, the lab's tasks and task folder are deleted and the
        function throws, so a failed install leaves no task that the operator
        could run. Returns the lab task folder.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][object]$Service,
        [Parameter(Mandatory)][string]$Lab,
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$PowerShellPath,
        [Parameter(Mandatory)][string]$OperatorSid
    )
    $taskCreateOrUpdate = 6
    $taskLogonServiceAccount = 5
    $rootPath = Get-HvLabTaskFolderPath
    try {
        $taskSddl = Get-HvLabSddl -Kind Task -OperatorSid $OperatorSid
        $null = Initialize-HvLabTaskFolder -Service $Service -ParentPath '\' -Name $script:TaskRootName -Sddl (Get-HvLabSddl -Kind TaskRootFolder)
        $labFolder = Initialize-HvLabTaskFolder -Service $Service -ParentPath $rootPath -Name $Lab -Sddl (Get-HvLabSddl -Kind LabTaskFolder -OperatorSid $OperatorSid)
        foreach ($enabled in @($false, $true)) {
            foreach ($action in $script:Actions) {
                $xml = Get-HvLabTaskXml -Lab $Lab -Action $action -LabDirectory $LabDirectory -PowerShellPath $PowerShellPath -Enabled $enabled
                $null = $labFolder.RegisterTask($action, $xml, $taskCreateOrUpdate, 'SYSTEM', $null, $taskLogonServiceAccount, $taskSddl)
            }
            $problems = @(Get-HvLabRegisteredTaskProblem -Folder $labFolder -LabDirectory $LabDirectory -PowerShellPath $PowerShellPath -OperatorSid $OperatorSid -Enabled $enabled)
            if ($problems.Count -gt 0) {
                $stage = 'while they were still disabled'
                if ($enabled) { $stage = 'after they were enabled' }
                throw ("The task check failed $stage`:`n  " + ($problems -join "`n  "))
            }
        }
    }
    catch {
        $failure = $_.Exception.Message
        try {
            $null = Remove-HvLabTaskFolder -Service $Service -Lab $Lab -Confirm:$false
        }
        catch {
            throw "$failure`nThe lab tasks could not be removed either ($($_.Exception.Message)). Run Uninstall-HvLab.ps1 -Lab $Lab."
        }
        throw "$failure`nThe lab tasks were removed."
    }
    return $labFolder
}

function Get-HvLabDirectorySecurity {
    <#
    .SYNOPSIS
        Builds the ACL of the install root or of a lab folder.
    .DESCRIPTION
        Root: owner Administrators; SYSTEM and Administrators full control;
        Authenticated Users read this folder only (no inheritance).
        Lab: owner Administrators; SYSTEM and Administrators full control; the
        operator read and execute, inherited by files and subfolders.
        Inheritance from the parent folder is removed in both cases.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.DirectorySecurity])]
    param(
        [Parameter(Mandatory)][ValidateSet('Root', 'Lab')][string]$Kind,
        [string]$OperatorSid
    )
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    $both = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.InheritanceFlags]::None
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')

    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $full, $both, $prop, $allow)))
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $full, $both, $prop, $allow)))
    if ($Kind -eq 'Root') {
        $authenticated = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($authenticated, $readExecute, $none, $prop, $allow)))
    }
    else {
        $problem = Get-HvLabOperatorSidProblem -Sid $OperatorSid
        if ($problem) { throw $problem }
        $operator = [System.Security.Principal.SecurityIdentifier]::new($OperatorSid)
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($operator, $readExecute, $both, $prop, $allow)))
    }
    $sec.SetOwner($admins)
    return $sec
}

function Get-HvLabAclProblem {
    <#
    .SYNOPSIS
        Lists everything under a path that a principal other than SYSTEM or
        Administrators could change.
    .DESCRIPTION
        Reports reparse points, owners other than SYSTEM or Administrators, and
        allow entries that grant any write, delete, permission or ownership
        right to another principal. With -RequireProtected the top item must
        not inherit permissions from its parent.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [switch]$RequireProtected
    )
    $problems = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) {
        $problems.Add("$Path does not exist")
        return $problems.ToArray()
    }
    $top = Get-Item -LiteralPath $Path -Force
    $items = New-Object System.Collections.Generic.List[object]
    $items.Add($top)
    if ($Recurse -and $top.PSIsContainer -and -not ($top.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) { $items.Add($child) }
    }
    foreach ($item in $items) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            $problems.Add("$($item.FullName) is a reparse point (link or junction)")
            continue
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($script:TrustedSids -notcontains $owner) {
            $problems.Add("$($item.FullName) is owned by $owner, not by SYSTEM or Administrators")
        }
        if ($RequireProtected -and [object]::ReferenceEquals($item, $top) -and -not $acl.AreAccessRulesProtected) {
            $problems.Add("$($item.FullName) inherits permissions from its parent folder")
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $rule.IdentityReference.Value
            if ($script:TrustedSids -contains $sid) { continue }
            if (Test-HvLabWriteAccess -AccessMask ([int64]$rule.FileSystemRights)) {
                $problems.Add("$($item.FullName) grants '$($rule.FileSystemRights)' to $sid")
            }
        }
    }
    return $problems.ToArray()
}

function Get-HvLabSecurityRightProblem {
    <#
    .SYNOPSIS
        Lists what in a file system security descriptor gives a principal other
        than SYSTEM, Administrators or TrustedInstaller a right in -Mask.
    .DESCRIPTION
        Reports an owner outside those three (an owner can always change the
        permissions) and every allow entry for another principal whose rights
        intersect -Mask. Inherit-only entries, such as CREATOR OWNER on C:\,
        are skipped, because they grant nothing on the object itself.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity]$Security,
        [Parameter(Mandatory)][int64]$Mask,
        [Parameter(Mandatory)][string]$Label
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $owner = $Security.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($null -eq $owner) {
        $problems.Add("$Label has no owner")
    }
    elseif ($script:SystemOwnerSids -notcontains $owner.Value) {
        $problems.Add("$Label is owned by $($owner.Value), not by SYSTEM, Administrators or TrustedInstaller")
    }
    foreach ($rule in $Security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $sid = $rule.IdentityReference.Value
        if ($script:SystemOwnerSids -contains $sid) { continue }
        $rights = [int64]$rule.FileSystemRights -band 4294967295
        if (($rights -band $Mask) -ne 0) {
            $problems.Add(('{0} grants {1} (0x{2:X8}) to {3}' -f $Label, $rule.FileSystemRights, $rights, $sid))
        }
    }
    return $problems.ToArray()
}

function Get-HvLabFolderRightProblem {
    <#
    .SYNOPSIS
        Checks one existing folder: not a reparse point, and nothing in its
        owner or ACL gives a principal other than SYSTEM, Administrators or
        TrustedInstaller a right in -Mask.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int64]$Mask
    )
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            return @("$Path is a reparse point (link or junction)")
        }
        $security = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return @("the ACL of $Path could not be read: $($_.Exception.Message)")
    }
    return @(Get-HvLabSecurityRightProblem -Security $security -Mask $Mask -Label $Path)
}

function Get-HvLabAncestorProblem {
    <#
    .SYNOPSIS
        Checks every folder above the install root, from the volume root down.
    .DESCRIPTION
        The SYSTEM tasks run the worker by its literal path. An account that
        could delete, rename or re-permission any folder on that path could put
        its own worker there. So the volume must be a fixed local drive, and
        every folder above the install root must exist, must not be a reparse
        point, must be owned by SYSTEM, Administrators or TrustedInstaller, and
        must give nobody else DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER,
        GENERIC_ALL or GENERIC_WRITE. Rights to create files or subfolders are
        allowed: C:\ and C:\ProgramData give them to all users, and they do not
        let anyone replace an existing folder. The install root and the lab
        folder themselves are checked with Get-HvLabAclProblem.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)
    $full = $Path.TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\.') { return @("$Path is not an absolute path below a drive root") }
    $problems = New-Object System.Collections.Generic.List[string]
    $drive = New-Object System.IO.DriveInfo($full.Substring(0, 1))
    if ([string]$drive.DriveType -ne 'Fixed') {
        $problems.Add("$($drive.Name) is not a fixed local drive (drive type $($drive.DriveType))")
        return $problems.ToArray()
    }
    $segments = $full.Split('\')
    $current = $segments[0] + '\'
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        if ($i -gt 0) { $current = $current.TrimEnd('\') + '\' + $segments[$i] }
        if (-not (Test-Path -LiteralPath $current -PathType Container)) {
            $problems.Add("$current does not exist; create it first, with an ACL that only administrators can change")
            break
        }
        foreach ($item in @(Get-HvLabFolderRightProblem -Path $current -Mask $script:ReplaceMask)) { $problems.Add($item) }
    }
    return $problems.ToArray()
}

function Get-HvLabSearchPathProblem {
    <#
    .SYNOPSIS
        Lists the folders of a PATH value in which an account other than
        SYSTEM, Administrators or TrustedInstaller could plant a DLL.
    .DESCRIPTION
        The lab tasks start powershell.exe as SYSTEM whenever the operator asks.
        A DLL that a process does not find in its own folder or in the system
        folders is searched for in the PATH folders. So in no PATH folder may
        such an account add, delete or rename files or change the permissions,
        and a PATH folder that does not exist must not be one that such an
        account could create. Network paths, and paths relative to a drive
        (C:bin) or to the drive root (\bin), are reported too. A plain relative
        entry (bin) is skipped: it resolves against the working directory,
        which for the lab tasks is the protected lab folder.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyString()][AllowNull()][string]$PathValue)
    $problems = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in ([string]$PathValue).Split(';')) {
        $entry = [Environment]::ExpandEnvironmentVariables($raw.Trim().Trim('"'))
        if (-not $entry) { continue }
        if ($entry -match '^[A-Za-z]:\\') {
            if ($entry.Length -gt 3) { $entry = $entry.TrimEnd('\') }
        }
        elseif ($entry.StartsWith('\\')) {
            $problems.Add("PATH entry '$entry' is a network path")
            continue
        }
        elseif ($entry -match '^[A-Za-z]:' -or $entry.StartsWith('\')) {
            $problems.Add("PATH entry '$entry' is relative to a drive or to the root of the current drive")
            continue
        }
        else {
            continue
        }
        if (-not $seen.Add($entry)) { continue }
        if (Test-Path -LiteralPath $entry -PathType Container) {
            foreach ($item in @(Get-HvLabFolderRightProblem -Path $entry -Mask $script:PlantMask)) { $problems.Add("PATH folder: $item") }
            continue
        }
        $parent = Split-Path -Parent $entry
        while ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) { $parent = Split-Path -Parent $parent }
        if (-not $parent) { continue }
        foreach ($item in @(Get-HvLabFolderRightProblem -Path $parent -Mask $script:CreateMask)) {
            $problems.Add("PATH entry $entry does not exist, and $item")
        }
    }
    return $problems.ToArray()
}

function Get-HvLabInstalledLabProblem {
    <#
    .SYNOPSIS
        Returns why a folder is not a lab folder that Install-HvLab.ps1 created
        for this lab, or nothing.
    .DESCRIPTION
        Uninstall-HvLab.ps1 deletes the lab folder recursively. So it first
        requires install.json with schema hvlab-install/1 that names this lab
        (case-sensitive), this folder and this install root, and an ACL that
        only SYSTEM and Administrators can change, with no link or junction.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$LabDirectory,
        [Parameter(Mandatory)][string]$Lab,
        [Parameter(Mandatory)][string]$InstallRoot
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $manifestPath = Join-Path $LabDirectory 'install.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $problems.Add("$manifestPath is missing")
        return $problems.ToArray()
    }
    $manifest = $null
    try {
        $manifest = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $problems.Add("$manifestPath is not valid JSON")
    }
    if ($null -ne $manifest) {
        $schema = [string](Get-HvLabPropertyValue -Object $manifest -Name 'schema' -Default '')
        if ($schema -cne 'hvlab-install/1') { $problems.Add("install.json has schema '$schema', not hvlab-install/1") }
        $manifestLab = [string](Get-HvLabPropertyValue -Object $manifest -Name 'lab' -Default '')
        if ($manifestLab -cne $Lab) { $problems.Add("install.json is for lab '$manifestLab', not '$Lab'") }
        $manifestFolder = [string](Get-HvLabPropertyValue -Object $manifest -Name 'labDirectory' -Default '')
        if ($manifestFolder.TrimEnd('\') -ne $LabDirectory.TrimEnd('\')) {
            $problems.Add("install.json names the lab folder '$manifestFolder', not '$LabDirectory'")
        }
        $manifestRoot = [string](Get-HvLabPropertyValue -Object $manifest -Name 'installRoot' -Default '')
        if ($manifestRoot.TrimEnd('\') -ne $InstallRoot.TrimEnd('\')) {
            $problems.Add("install.json names the install root '$manifestRoot', not '$InstallRoot'")
        }
    }
    foreach ($item in @(Get-HvLabAclProblem -Path $LabDirectory -Recurse -RequireProtected)) { $problems.Add($item) }
    return $problems.ToArray()
}

function Get-HvLabSecretFileProblem {
    <#
    .SYNOPSIS
        Lists ACL problems of a secret file: an SSH private key or the KDNET
        key file.
    .DESCRIPTION
        Only the current account, SYSTEM and Administrators may own the file or
        have an allow entry on it. Windows OpenSSH ignores a private key that
        other accounts can read; the KDNET key file is held to the same rule.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)
    $problems = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $problems.Add("'$Path' not found")
        return $problems.ToArray()
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($me) + $script:TrustedSids
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { $problems.Add("'$Path' is owned by $owner") }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($allowed -notcontains $rule.IdentityReference.Value) {
            $problems.Add("'$Path' grants '$($rule.FileSystemRights)' to $($rule.IdentityReference.Value)")
        }
    }
    return $problems.ToArray()
}

function Get-HvLabSecretFileFix {
    <#
    .SYNOPSIS
        Returns the icacls command that limits a file to the current account
        (SYSTEM and Administrators keep their access through ownership rules).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ('icacls "{0}" /inheritance:r /grant:r "*{1}:F", then remove any other entry that icacls "{0}" still lists' -f $Path, $me)
}

function Test-HvLabRemoteAddress {
    <#
    .SYNOPSIS
        Tests a firewall remote address: one IPv4 or IPv6 address, or an
        address prefix such as 192.0.2.0/24. Keywords such as Any and
        LocalSubnet are refused.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][AllowNull()][string]$Address)
    if ($Address -notmatch '^([0-9A-Fa-f:.]+)(?:/(\d{1,3}))?$') { return $false }
    $addressPart = $Matches[1]
    $prefixPart = $Matches[2]
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($addressPart, [ref]$ip)) { return $false }
    $maxPrefix = 128
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($addressPart -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
        $maxPrefix = 32
    }
    if ($prefixPart) {
        $length = [int]$prefixPart
        if ($length -lt 1 -or $length -gt $maxPrefix) { return $false }
    }
    return $true
}

function Test-HvLabPortInList {
    <#
    .SYNOPSIS
        Tests whether a port is covered by a firewall LocalPort value
        ('Any', a number, a range such as 50000-50039, or a list of these).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][object]$PortList,
        [Parameter(Mandatory)][int]$Port
    )
    foreach ($entry in @($PortList)) {
        $text = [string]$entry
        if ($text -eq 'Any') { return $true }
        if ($text -match '^\d+$' -and [int]$text -eq $Port) { return $true }
        if ($text -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
    }
    return $false
}

function ConvertTo-HvLabUtc {
    <#
    .SYNOPSIS
        Converts a DateTime or an ISO 8601 string to UTC, or returns $null.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function ConvertTo-HvLabSafeText {
    <#
    .SYNOPSIS
        Replaces control characters (C0, DEL and C1) in text from the guest
        with '?', so that guest output cannot move the cursor or redraw the
        console when the host prints it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0, ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $null }
        return [regex]::Replace([string]$Value, '[\x00-\x1F\x7F-\x9F]', '?')
    }
}

function ConvertFrom-HvLabWhoami {
    <#
    .SYNOPSIS
        Summarizes 'whoami /user', 'whoami /groups' and 'whoami /priv', each
        run with /fo csv /nh.
    .DESCRIPTION
        Uses SIDs and privilege names, which whoami does not translate, so the
        result does not depend on the guest's display language. Names from
        the guest pass through ConvertTo-HvLabSafeText. NonStandardGroups and
        NonStandardPrivileges list what the token holds beyond a default
        standard-user token of a Windows client edition. LogonType comes from
        the logon type group in the token (NETWORK, INTERACTIVE and so on);
        '(S4U)' is added when the token has the Service asserted identity SID
        (S-1-18-2), which a logon made by a service without the password has.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()][string[]]$UserLines = @(),
        [AllowEmptyCollection()][string[]]$GroupLines = @(),
        [AllowEmptyCollection()][string[]]$PrivilegeLines = @()
    )
    $userRows = @(@($UserLines) | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv -Header 'Name', 'Sid')
    $groupRows = @(@($GroupLines) | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv -Header 'Name', 'Type', 'Sid', 'Attributes')
    $privilegeRows = @(@($PrivilegeLines) | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv -Header 'Name', 'Description', 'State')

    $rid = $null
    foreach ($row in $groupRows) {
        if ([string]$row.Sid -match '^S-1-16-(\d{1,9})$') { $rid = [int]$Matches[1] }
    }
    $names = @{ 0 = 'Untrusted'; 4096 = 'Low'; 8192 = 'Medium'; 8448 = 'MediumPlus'; 12288 = 'High'; 16384 = 'System' }
    $level = 'Unknown'
    if ($null -ne $rid) {
        if ($names.ContainsKey($rid)) { $level = $names[$rid] } else { $level = "S-1-16-$rid" }
    }

    $account = $null
    $accountSid = $null
    if ($userRows.Count -gt 0) {
        $account = ConvertTo-HvLabSafeText $userRows[0].Name
        $accountSid = ConvertTo-HvLabSafeText $userRows[0].Sid
    }
    $ownDomainGroup = $null
    if ([string]$accountSid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { $ownDomainGroup = $Matches[1] + '-513' }

    $sids = @($groupRows | ForEach-Object { ConvertTo-HvLabSafeText $_.Sid })
    $groups = New-Object System.Collections.Generic.List[string]
    $nonStandardGroups = New-Object System.Collections.Generic.List[string]
    foreach ($row in $groupRows) {
        $sid = ConvertTo-HvLabSafeText $row.Sid
        $label = '{0} ({1})' -f (ConvertTo-HvLabSafeText $row.Name), $sid
        $groups.Add($label)
        $standard = [bool]$sid -and (($script:StandardUserGroupSids -contains $sid) -or ($sid -match $script:StandardUserGroupPattern) -or
            ($null -ne $ownDomainGroup -and $sid -eq $ownDomainGroup))
        if (-not $standard) { $nonStandardGroups.Add($label) }
    }
    $privileges = @($privilegeRows | ForEach-Object { ConvertTo-HvLabSafeText $_.Name } | Where-Object { $_ })
    $nonStandardPrivileges = @($privileges | Where-Object { $script:StandardUserPrivileges -notcontains $_ })

    $logonType = 'Unknown'
    if ($sids -contains 'S-1-5-2') { $logonType = 'Network' }
    elseif ($sids -contains 'S-1-5-14') { $logonType = 'RemoteInteractive' }
    elseif ($sids -contains 'S-1-5-4') { $logonType = 'Interactive' }
    elseif ($sids -contains 'S-1-5-3') { $logonType = 'Batch' }
    elseif ($sids -contains 'S-1-5-6') { $logonType = 'Service' }
    if ($sids -contains 'S-1-18-2') { $logonType += ' (S4U)' }

    return [pscustomobject]@{
        Account               = $account
        Sid                   = $accountSid
        IntegrityLevel        = $level
        IntegrityRid          = $rid
        Elevated              = ($null -ne $rid -and $rid -ge 12288)
        InAdministrators      = ($sids -contains 'S-1-5-32-544')
        LogonType             = $logonType
        Groups                = $groups.ToArray()
        GroupSids             = $sids
        Privileges            = $privileges
        NonStandardGroups     = $nonStandardGroups.ToArray()
        NonStandardPrivileges = $nonStandardPrivileges
    }
}

function Get-HvLabRoleProblem {
    <#
    .SYNOPSIS
        Returns why a session summary does not fit its role, or $null.
    .DESCRIPTION
        Admin: the token must be elevated (High or System integrity) and carry
        the Administrators group. User: the token must be Medium integrity,
        and every group and privilege in it must be one that a standard-user
        token has by default; a privileged group counts even as deny-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][ValidateSet('Admin', 'User')][string]$Role
    )
    if ($Role -eq 'Admin') {
        if (-not $Context.Elevated) { return "the admin account's SSH token is not elevated (integrity $($Context.IntegrityLevel))" }
        if (-not $Context.InAdministrators) { return "the admin account's SSH token has no Administrators group" }
        return $null
    }
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($Context.IntegrityRid -ne 8192) { $reasons.Add("integrity $($Context.IntegrityLevel), not Medium") }
    if (@($Context.NonStandardGroups).Count -gt 0) {
        $reasons.Add("groups outside the standard-user set: $(@($Context.NonStandardGroups) -join ', ')")
    }
    if (@($Context.NonStandardPrivileges).Count -gt 0) {
        $reasons.Add("privileges outside the standard-user set: $(@($Context.NonStandardPrivileges) -join ', ')")
    }
    if ($reasons.Count -eq 0) { return $null }
    return ("the standard account's SSH session does not fit a standard-user proof: " + ($reasons -join '; '))
}

function Get-HvLabContextCommand {
    <#
    .SYNOPSIS
        Returns the guest command line that reports the SSH session.
    .DESCRIPTION
        One cmd.exe command line, for the default shell of Windows OpenSSH. It
        prints, separated by marker lines: whoami /user, /groups and /priv as
        CSV, the Developer Mode registry value, and the session id. It ends
        with an end marker, so the output of a command appended after it can
        be told apart.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (($script:ContextCommands -join " & echo $script:ContextSection & ") + " & echo $script:ContextEnd")
}

function Test-HvLabContextEndLine {
    <#
    .SYNOPSIS
        Tests whether a line of guest output is the end marker of the session
        report.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Line)
    return (([string]$Line).Trim() -ceq $script:ContextEnd)
}

function ConvertFrom-HvLabContextOutput {
    <#
    .SYNOPSIS
        Summarizes the output of the command from Get-HvLabContextCommand.
    .DESCRIPTION
        Returns the summary of ConvertFrom-HvLabWhoami plus DeveloperMode
        ($true, $false, or $null when unknown) and SessionId ($null when
        unknown). Returns $null when the output does not have the expected
        sections, for example because the guest's default shell is not cmd.exe.
        Lines after the end marker are ignored.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowNull()][AllowEmptyCollection()][string[]]$Line)
    $sections = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[string]
    $ended = $false
    foreach ($text in @($Line)) {
        $trimmed = ([string]$text).Trim()
        if ($trimmed -ceq $script:ContextSection -or $trimmed -ceq $script:ContextEnd) {
            $sections.Add($current.ToArray())
            $current = New-Object System.Collections.Generic.List[string]
            if ($trimmed -ceq $script:ContextEnd) {
                $ended = $true
                break
            }
            continue
        }
        $current.Add([string]$text)
    }
    if (-not $ended -or $sections.Count -ne $script:ContextCommands.Count) { return $null }

    $context = ConvertFrom-HvLabWhoami -UserLines $sections[0] -GroupLines $sections[1] -PrivilegeLines $sections[2]
    $developerMode = $null
    $registryText = @($sections[3]) -join "`n"
    if ($registryText -match 'AllowDevelopmentWithoutDevLicense\s+REG_DWORD\s+0x([0-9A-Fa-f]{1,8})') {
        $developerMode = ([Convert]::ToInt64($Matches[1], 16) -ne 0)
    }
    elseif ($registryText -match 'HVLAB-NOVALUE') {
        $developerMode = $false
    }
    $sessionId = $null
    $sessionText = (@($sections[4]) -join '').Trim()
    if ($sessionText -match '^\d{1,9}$') { $sessionId = [int]$sessionText }
    $context | Add-Member -NotePropertyName DeveloperMode -NotePropertyValue $developerMode
    $context | Add-Member -NotePropertyName SessionId -NotePropertyValue $sessionId
    return $context
}

function ConvertFrom-HvLabResultLine {
    <#
    .SYNOPSIS
        Decodes the last 'HVLAB-RESULT <base64 JSON>' line of guest output.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowNull()][AllowEmptyCollection()][string[]]$Line)
    $payload = $null
    foreach ($text in @($Line)) {
        if ($null -ne $text -and $text.StartsWith($script:ResultPrefix)) {
            $payload = $text.Substring($script:ResultPrefix.Length).Trim()
        }
    }
    if (-not $payload) { return $null }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-HvLabKdnetKeyHash {
    <#
    .SYNOPSIS
        Returns SHA-256(nonce bytes + UTF-8 key) as lowercase hex.
    .DESCRIPTION
        The guest helper Get-HvLabKdnetInfo.ps1 computes the same value from
        the guest's key (its function Get-HvLabKeyHash), so the key itself
        never travels. The nonce is 16 random bytes, as 32 lowercase hex
        characters.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$Nonce,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Key
    )
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

function Test-HvLabGuestAddress {
    <#
    .SYNOPSIS
        Tests a guest address: a dotted IPv4 address, an IPv6 address, or a DNS
        name. A value that could be read as an ssh option is refused.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][AllowNull()][string]$Address)
    if ([string]::IsNullOrEmpty($Address)) { return $false }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Address, [ref]$ip)) {
        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return [bool]($Address -match '^\d{1,3}(\.\d{1,3}){3}$')
        }
        return [bool]($Address -match '^[0-9A-Fa-f:.]+$')
    }
    return [bool]($Address -match '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
}

function Test-HvLabAccountName {
    <#
    .SYNOPSIS
        Tests a guest account name: 1 to 20 letters, digits, dots, underscores
        and hyphens, starting with a letter or digit.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][AllowNull()][string]$Name)
    return [bool]($Name -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')
}

function Resolve-HvLabPath {
    <#
    .SYNOPSIS
        Expands a leading ~ to the home folder and returns a full path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $value = $Path
    if ($value -match '^~(?=$|[\\/])') { $value = $HOME + $value.Substring(1) }
    if (-not [System.IO.Path]::IsPathRooted($value) -or $value -notmatch '^([A-Za-z]:\\|\\\\)') {
        throw "Path '$Path' must be absolute or start with ~."
    }
    return [System.IO.Path]::GetFullPath($value)
}

function Get-HvLabDefaultConfigPath {
    <#
    .SYNOPSIS
        Returns $env:HVLAB_CONFIG, or %LOCALAPPDATA%\HyperVLpeLab\config.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($env:HVLAB_CONFIG) { return $env:HVLAB_CONFIG }
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    return (Join-Path $base 'HyperVLpeLab\config.json')
}

function Get-HvLabPropertyValue {
    <#
    .SYNOPSIS
        Returns a property of an object parsed from JSON, or -Default when the
        object, the property or its value is missing or empty.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default
    )
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value -or [string]$property.Value -eq '') { return $Default }
    return $property.Value
}

function Get-HvLabConfig {
    <#
    .SYNOPSIS
        Loads and validates a lab config file (JSON).
    .DESCRIPTION
        Unknown settings are an error, so a typo does not pass silently. With
        -LifecycleOnly only Lab and InstallRoot are read and required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Path,
        [switch]$LifecycleOnly
    )
    if (-not $Path) { $Path = Get-HvLabDefaultConfigPath }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Config file '$Path' not found. Copy config\hvlab.example.json there and edit it, or pass -ConfigPath."
    }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Config file '$Path' is not valid JSON: $($_.Exception.Message)"
    }
    if ($raw -isnot [System.Management.Automation.PSCustomObject]) { throw "Config file '$Path' must hold one JSON object." }

    $known = @('Lab', 'InstallRoot', 'GuestAddress', 'SshPort', 'AdminAccount', 'UserAccount', 'AdminKeyPath',
        'UserKeyPath', 'KnownHostsPath', 'ConnectTimeoutSec', 'KdnetPort', 'KdnetKeyFile', 'DumpDirectory')
    foreach ($property in $raw.PSObject.Properties) {
        if ($known -cnotcontains $property.Name) { throw "Config file '$Path': unknown setting '$($property.Name)'." }
    }

    $lab = [string](Get-HvLabPropertyValue -Object $raw -Name 'Lab' -Default '')
    if (-not (Test-HvLabName -Name $lab)) { throw "Config file '$Path': Lab must be 1 to 32 letters, digits or hyphens." }
    $defaultRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'HyperVLpeLab'
    $installRoot = [string](Get-HvLabPropertyValue -Object $raw -Name 'InstallRoot' -Default $defaultRoot)
    $problem = Get-HvLabInstallRootProblem -Path $installRoot
    if ($problem) { throw "Config file '$Path': InstallRoot: $problem." }

    $config = [ordered]@{
        Path        = $Path
        Lab         = $lab
        InstallRoot = $installRoot
    }
    if ($LifecycleOnly) { return [pscustomobject]$config }

    $address = [string](Get-HvLabPropertyValue -Object $raw -Name 'GuestAddress' -Default '')
    if (-not (Test-HvLabGuestAddress -Address $address)) { throw "Config file '$Path': GuestAddress must be an IPv4 address, an IPv6 address or a DNS name." }
    $admin = [string](Get-HvLabPropertyValue -Object $raw -Name 'AdminAccount' -Default '')
    $user = [string](Get-HvLabPropertyValue -Object $raw -Name 'UserAccount' -Default '')
    foreach ($pair in @(@('AdminAccount', $admin), @('UserAccount', $user))) {
        if (-not (Test-HvLabAccountName -Name $pair[1])) {
            throw "Config file '$Path': $($pair[0]) must be 1 to 20 letters, digits, dots, underscores or hyphens."
        }
    }
    if ($admin -eq $user) { throw "Config file '$Path': AdminAccount and UserAccount must be different accounts." }

    $intSettings = @{
        SshPort           = @(22, 1, 65535)
        ConnectTimeoutSec = @(10, 1, 120)
        KdnetPort         = @(50000, 1, 65535)
    }
    foreach ($name in @('SshPort', 'ConnectTimeoutSec', 'KdnetPort')) {
        $spec = $intSettings[$name]
        $value = Get-HvLabPropertyValue -Object $raw -Name $name -Default $spec[0]
        $number = 0
        if (-not [int]::TryParse([string]$value, [ref]$number) -or $number -lt $spec[1] -or $number -gt $spec[2]) {
            throw "Config file '$Path': $name must be a whole number from $($spec[1]) to $($spec[2])."
        }
        $config[$name] = $number
    }

    foreach ($name in @('AdminKeyPath', 'UserKeyPath')) {
        $value = [string](Get-HvLabPropertyValue -Object $raw -Name $name -Default '')
        if (-not $value) { throw "Config file '$Path': $name is required." }
        $config[$name] = Resolve-HvLabPath -Path $value
    }
    if ($config.AdminKeyPath -eq $config.UserKeyPath) {
        throw "Config file '$Path': AdminKeyPath and UserKeyPath must be different keys, so the user key cannot sign in as the admin account."
    }
    $config.KnownHostsPath = Resolve-HvLabPath -Path ([string](Get-HvLabPropertyValue -Object $raw -Name 'KnownHostsPath' -Default '~\.ssh\hvlab_known_hosts'))
    $config.DumpDirectory = Resolve-HvLabPath -Path ([string](Get-HvLabPropertyValue -Object $raw -Name 'DumpDirectory' -Default '~\hvlab-dumps'))
    $kdnetKey = [string](Get-HvLabPropertyValue -Object $raw -Name 'KdnetKeyFile' -Default '')
    $config.KdnetKeyFile = if ($kdnetKey) { Resolve-HvLabPath -Path $kdnetKey } else { $null }
    $config.GuestAddress = $address
    $config.AdminAccount = $admin
    $config.UserAccount = $user
    return [pscustomobject]$config
}

function Resolve-HvLabLifecycleTarget {
    <#
    .SYNOPSIS
        Resolves the lab name and install root from parameters and the config.
    .DESCRIPTION
        Explicit values win. A config file is read only when a value is
        missing; when only -Lab is given and no config file exists, the default
        install root is used.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Lab,
        [string]$ConfigPath,
        [string]$InstallRoot
    )
    $config = $null
    if (-not $Lab -or -not $InstallRoot) {
        $skipConfig = $Lab -and -not $ConfigPath -and -not (Test-Path -LiteralPath (Get-HvLabDefaultConfigPath) -PathType Leaf)
        if (-not $skipConfig) { $config = Get-HvLabConfig -Path $ConfigPath -LifecycleOnly }
    }
    if (-not $Lab) { $Lab = $config.Lab }
    if (-not $InstallRoot) {
        if ($null -ne $config) { $InstallRoot = $config.InstallRoot }
        else { $InstallRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'HyperVLpeLab' }
    }
    if (-not (Test-HvLabName -Name $Lab)) { throw "Lab '$Lab' must be 1 to 32 letters, digits or hyphens." }
    $root = $InstallRoot.TrimEnd('\')
    $problem = Get-HvLabInstallRootProblem -Path $root
    if ($problem) { throw "InstallRoot '$InstallRoot': $problem." }
    return [pscustomobject]@{
        Lab          = $Lab
        InstallRoot  = $root
        LabDirectory = $root + '\' + $Lab
        TaskFolder   = Get-HvLabTaskFolderPath -Lab $Lab
    }
}

function Get-HvLabOpenSshTool {
    <#
    .SYNOPSIS
        Returns the path of ssh.exe, scp.exe or ssh-keygen.exe (the Windows
        OpenSSH client first, then PATH).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][ValidateSet('ssh', 'scp', 'ssh-keygen')][string]$Name)
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $inbox = Join-Path $system "OpenSSH\$Name.exe"
    if (Test-Path -LiteralPath $inbox -PathType Leaf) { return $inbox }
    $command = Get-Command "$Name.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    throw "$Name.exe not found. Install the Windows OpenSSH client (Settings, Optional features) or put $Name.exe on PATH."
}

function Get-HvLabRoleAccount {
    <#
    .SYNOPSIS
        Returns the guest account name of a role.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][ValidateSet('Admin', 'User')][string]$Role
    )
    if ($Role -eq 'Admin') { return $Config.AdminAccount }
    return $Config.UserAccount
}

function Get-HvLabSshArgument {
    <#
    .SYNOPSIS
        Returns the OpenSSH options used for every guest connection.
    .DESCRIPTION
        Key authentication only (BatchMode, no password or keyboard-interactive
        fallback), one identity file per role, a dedicated known_hosts file
        (UserKnownHostsFile and GlobalKnownHostsFile both name it, so the
        host-wide ssh_known_hosts is not read), and strict host key checking
        unless -TrustNewHostKey is given for the first connection.

        The guest is untrusted, so agent and X11 forwarding, port forwardings,
        LocalCommand, ProxyCommand (which also disables ProxyJump), host key
        updates from the guest and a terminal are turned off. -F none keeps
        ssh from reading any config file, so neither ~/.ssh/config nor
        %ProgramData%\ssh\ssh_config can add settings for the guest.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][ValidateSet('Admin', 'User')][string]$Role,
        [ValidateSet('ssh', 'scp')][string]$Tool = 'ssh',
        [switch]$TrustNewHostKey
    )
    $key = if ($Role -eq 'Admin') { $Config.AdminKeyPath } else { $Config.UserKeyPath }
    $policy = if ($TrustNewHostKey) { 'accept-new' } else { 'yes' }
    $knownHosts = $Config.KnownHostsPath
    if ($knownHosts -match '\s') { $knownHosts = '"' + $knownHosts + '"' }
    $list = @(
        '-F', 'none',
        '-i', $key,
        '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', "StrictHostKeyChecking=$policy",
        '-o', "UserKnownHostsFile=$knownHosts",
        '-o', "GlobalKnownHostsFile=$knownHosts",
        '-o', 'UpdateHostKeys=no',
        '-o', 'ForwardAgent=no',
        '-o', 'ForwardX11=no',
        '-o', 'ClearAllForwardings=yes',
        '-o', 'PermitLocalCommand=no',
        '-o', 'ProxyCommand=none',
        '-o', 'RequestTTY=no',
        '-o', "ConnectTimeout=$($Config.ConnectTimeoutSec)",
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=4'
    )
    if ($Tool -eq 'ssh') {
        $list += @('-p', [string]$Config.SshPort, '-l', (Get-HvLabRoleAccount -Config $Config -Role $Role))
    }
    else {
        $list += @('-P', [string]$Config.SshPort)
    }
    return [string[]]$list
}

function Get-HvLabScpRemote {
    <#
    .SYNOPSIS
        Returns 'account@host:path' for scp, with brackets around IPv6.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][ValidateSet('Admin', 'User')][string]$Role,
        [Parameter(Mandatory)][string]$RemotePath
    )
    if ($RemotePath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$' -or $RemotePath -match '\.\.') {
        throw "Unsafe remote path '$RemotePath'."
    }
    $address = $Config.GuestAddress
    if ($address.Contains(':')) { $address = "[$address]" }
    return ('{0}@{1}:{2}' -f (Get-HvLabRoleAccount -Config $Config -Role $Role), $address, $RemotePath)
}

function Get-HvLabKnownHostsEntry {
    <#
    .SYNOPSIS
        Returns the known_hosts name of the guest ('host' or '[host]:port').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Config)
    if ($Config.SshPort -eq 22) { return $Config.GuestAddress }
    return ('[{0}]:{1}' -f $Config.GuestAddress, $Config.SshPort)
}

function Assert-HvLabSshPrerequisite {
    <#
    .SYNOPSIS
        Checks the identity file of a role and creates the known_hosts folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][ValidateSet('Admin', 'User')][string]$Role
    )
    $key = if ($Role -eq 'Admin') { $Config.AdminKeyPath } else { $Config.UserKeyPath }
    if (-not (Test-Path -LiteralPath $key -PathType Leaf)) {
        throw "The $Role identity file '$key' does not exist. Create it with ssh-keygen (README, Install, step 2)."
    }
    $problems = @(Get-HvLabSecretFileProblem -Path $key)
    if ($problems.Count -gt 0) {
        throw ("The $Role identity file cannot be used: $($problems -join '; '). Fix: $(Get-HvLabSecretFileFix -Path $key)")
    }
    $folder = Split-Path -Parent $Config.KnownHostsPath
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $folder -Force
    }
}

function Invoke-HvLabGuestScript {
    <#
    .SYNOPSIS
        Copies a helper script to the guest admin's home folder, runs it with
        Windows PowerShell, and decodes its result line.
    .DESCRIPTION
        The copy has a random name (hvlab-<32 hex>.ps1) and the helper deletes
        it when it finishes. Arguments are limited to plain tokens. The helper
        runs as the guest admin account, because it reads boot settings and
        crash dumps.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][string]$ScriptPath,
        [AllowEmptyCollection()][string[]]$ScriptArgument = @(),
        [switch]$TrustNewHostKey
    )
    foreach ($argument in $ScriptArgument) {
        if ($argument -notmatch '^-?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw "Unsafe guest script argument '$argument'." }
    }
    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Guest helper '$ScriptPath' not found." }
    Assert-HvLabSshPrerequisite -Config $Config -Role Admin
    $ssh = Get-HvLabOpenSshTool -Name ssh
    $scp = Get-HvLabOpenSshTool -Name scp
    $remoteName = 'hvlab-' + [guid]::NewGuid().ToString('N') + '.ps1'

    $scpArguments = @(Get-HvLabSshArgument -Config $Config -Role Admin -Tool scp -TrustNewHostKey:$TrustNewHostKey) +
        @('-q', '--', (Split-Path -Leaf $ScriptPath), (Get-HvLabScpRemote -Config $Config -Role Admin -RemotePath $remoteName))
    # scp reads 'C:\...' as host 'C'; run it from the script's folder with a bare file name.
    Push-Location -LiteralPath (Split-Path -Parent $ScriptPath)
    try {
        & $scp @scpArguments
        $uploadExit = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($uploadExit -ne 0) {
        return [pscustomobject]@{ ExitCode = $uploadExit; Stage = 'upload'; Result = $null }
    }

    $remoteCommand = (@('powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $remoteName) + $ScriptArgument) -join ' '
    $sshArguments = @(Get-HvLabSshArgument -Config $Config -Role Admin -Tool ssh) + @('--', $Config.GuestAddress, $remoteCommand)
    $lines = @(& $ssh @sshArguments)
    $exitCode = $LASTEXITCODE
    return [pscustomobject]@{
        ExitCode = $exitCode
        Stage    = 'run'
        Result   = (ConvertFrom-HvLabResultLine -Line $lines)
    }
}

function Wait-HvLabCopy {
    <#
    .SYNOPSIS
        Waits for a copy process, and stops it as soon as the target file is
        larger than -MaxBytes.
    .DESCRIPTION
        The guest reports the size of the file it sends. This keeps a guest
        that sends more than it reported from filling the host volume.
        Returns the exit code and whether the limit was exceeded.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Process,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int64]$MaxBytes,
        [ValidateRange(10, 5000)][int]$PollMilliseconds = 500
    )
    $exceeded = $false
    while (-not $Process.HasExited) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and $item.Length -gt $MaxBytes) {
            $exceeded = $true
            # $true also stops the ssh.exe that scp.exe starts for the transfer.
            try { $Process.Kill($true) } catch { Write-Verbose "The copy process could not be stopped: $($_.Exception.Message)" }
            break
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
    $Process.WaitForExit()
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.Length -gt $MaxBytes) { $exceeded = $true }
    return [pscustomobject]@{ ExitCode = [int]$Process.ExitCode; Exceeded = $exceeded }
}

function Copy-HvLabGuestFile {
    <#
    .SYNOPSIS
        Copies one file from the guest admin's home folder to a host folder,
        and stops the copy when the file grows past -MaxBytes.
    .DESCRIPTION
        Needs PowerShell 7 (ProcessStartInfo.ArgumentList). Returns the scp
        exit code and whether the size limit was exceeded.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$LocalDirectory,
        [Parameter(Mandatory)][string]$LocalName,
        [Parameter(Mandatory)][int64]$MaxBytes
    )
    if ($LocalName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$') { throw "Unsafe local file name '$LocalName'." }
    $scp = Get-HvLabOpenSshTool -Name scp
    $arguments = @(Get-HvLabSshArgument -Config $Config -Role Admin -Tool scp) +
        @('-q', '--', (Get-HvLabScpRemote -Config $Config -Role Admin -RemotePath $RemotePath), $LocalName)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    if ($null -eq $info.PSObject.Properties['ArgumentList']) { throw 'Copy-HvLabGuestFile needs PowerShell 7.3 or later.' }
    $info.FileName = $scp
    foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
    # scp reads 'C:\...' as host 'C'; run it in the target folder with a bare file name.
    $info.WorkingDirectory = $LocalDirectory
    $info.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        return (Wait-HvLabCopy -Process $process -Path (Join-Path $LocalDirectory $LocalName) -MaxBytes $MaxBytes)
    }
    finally {
        $process.Dispose()
    }
}

Export-ModuleMember -Function @(
    'Get-HvLabAction', 'Get-HvLabTaskFolderPath', 'Get-HvLabResultPrefix', 'Test-HvLabName',
    'Get-HvLabInstallRootProblem', 'Get-HvLabOperatorSidProblem', 'Get-HvLabSddl', 'Test-HvLabWriteAccess',
    'Get-HvLabSddlProblem', 'Get-HvLabWindowsPowerShellPath', 'Get-HvLabTaskArgument', 'Get-HvLabTaskXml',
    'Get-HvLabTaskXmlProblem', 'Initialize-HvLabTaskFolder', 'Get-HvLabRegisteredTaskProblem', 'Remove-HvLabTaskFolder',
    'Register-HvLabTaskSet', 'Get-HvLabDirectorySecurity', 'Get-HvLabAclProblem', 'Get-HvLabSecurityRightProblem',
    'Get-HvLabFolderRightProblem', 'Get-HvLabAncestorProblem', 'Get-HvLabSearchPathProblem', 'Get-HvLabInstalledLabProblem',
    'Get-HvLabSecretFileProblem', 'Get-HvLabSecretFileFix', 'Test-HvLabRemoteAddress', 'Test-HvLabPortInList',
    'ConvertTo-HvLabUtc', 'ConvertTo-HvLabSafeText', 'ConvertFrom-HvLabWhoami', 'Get-HvLabRoleProblem',
    'Get-HvLabContextCommand', 'Test-HvLabContextEndLine', 'ConvertFrom-HvLabContextOutput', 'ConvertFrom-HvLabResultLine',
    'Get-HvLabKdnetKeyHash', 'Test-HvLabGuestAddress', 'Test-HvLabAccountName', 'Resolve-HvLabPath',
    'Get-HvLabDefaultConfigPath', 'Get-HvLabPropertyValue', 'Get-HvLabConfig', 'Resolve-HvLabLifecycleTarget',
    'Get-HvLabOpenSshTool', 'Get-HvLabRoleAccount', 'Get-HvLabSshArgument', 'Get-HvLabScpRemote',
    'Get-HvLabKnownHostsEntry', 'Assert-HvLabSshPrerequisite', 'Invoke-HvLabGuestScript', 'Wait-HvLabCopy',
    'Copy-HvLabGuestFile'
)
