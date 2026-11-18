# Offline tests for host\HvLab.Common.psm1. They create files only in the
# Pester TestDrive and contact no VM, no network and no system service. Task
# Scheduler and scp are replaced by in-memory objects.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares BeforeAll variables with It blocks.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The replacement objects accept the arguments that the module passes.')]
param()

Describe 'Names and paths' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
    }

    It 'accepts valid lab names and refuses the rest' {
        foreach ($name in @('lab1', 'a', 'Lab-2', ('a' * 32))) {
            Assert-HvLabTrue (Test-HvLabName -Name $name) "valid name '$name'"
        }
        foreach ($name in @('', '-lab', 'lab_1', 'lab 1', ('a' * 33), 'lab;x', '..', 'lab/1')) {
            Assert-HvLabTrue (-not (Test-HvLabName -Name $name)) "invalid name '$name'"
        }
    }

    It 'accepts a plain install root and refuses unsafe ones' {
        Assert-HvLabEqual $null (Get-HvLabInstallRootProblem -Path 'C:\ProgramData\HyperVLpeLab') 'default root'
        foreach ($path in @('', 'ProgramData\x', '\\server\share\x', 'C:\', 'C:\Program%TEMP%', 'C:\a"b', 'C:\a\..\b',
                'C:\a\.\b', 'C:\a\', 'C:\a\\b', 'C:\Users', 'C:\a\b.', 'C:\a\ b', ('C:\' + ('a' * 150)))) {
            Assert-HvLabTrue ($null -ne (Get-HvLabInstallRootProblem -Path $path)) "refuses '$path'"
        }
    }

    It 'accepts only an account or a lab group as the operator' {
        $refused = @('S-1-1-0', 'S-1-2-0', 'S-1-2-1', 'S-1-3-0', 'S-1-5-2', 'S-1-5-4', 'S-1-5-11', 'S-1-5-18', 'S-1-5-19',
            'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-556', 'S-1-5-32-559', 'S-1-5-32-562', 'S-1-5-32-573',
            'S-1-5-32-580', 'S-1-5-32-583', 'S-1-5-64-10', 'S-1-5-80-0', 'S-1-5-113', 'S-1-15-2-1', 'S-1-16-8192',
            'S-1-18-1', 'S-1-18-2', 'S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-513', 'S-1-5-21-1-2-3-999', 'not-a-sid')
        foreach ($sid in $refused) {
            Assert-HvLabTrue ($null -ne (Get-HvLabOperatorSidProblem -Sid $sid)) "refuses $sid"
        }
        foreach ($sid in @('S-1-5-21-1-2-3-1000', 'S-1-5-21-1-2-3-1001', 'S-1-12-1-1-2-3-4')) {
            Assert-HvLabEqual $null (Get-HvLabOperatorSidProblem -Sid $sid) "accepts $sid"
        }
    }

    It 'checks guest addresses and account names' {
        foreach ($address in @('192.0.2.10', '2001:db8::10', 'lab-guest', 'guest.lab.example')) {
            Assert-HvLabTrue (Test-HvLabGuestAddress -Address $address) "valid address '$address'"
        }
        foreach ($address in @('', '-oProxyCommand=x', '1', 'a b', 'host;x', 'user@host', 'fe80::1%3')) {
            Assert-HvLabTrue (-not (Test-HvLabGuestAddress -Address $address)) "invalid address '$address'"
        }
        Assert-HvLabTrue (Test-HvLabAccountName -Name 'labuser') 'valid account'
        foreach ($name in @('', '-x', 'a@b', 'a b', ('a' * 21), '<guest-user>')) {
            Assert-HvLabTrue (-not (Test-HvLabAccountName -Name $name)) "invalid account '$name'"
        }
    }

    It 'accepts only an address or a prefix as the KDNET remote address' {
        foreach ($address in @('192.0.2.10', '192.0.2.0/24', '2001:db8::10', '2001:db8::/64')) {
            Assert-HvLabTrue (Test-HvLabRemoteAddress -Address $address) "valid remote address '$address'"
        }
        foreach ($address in @('', 'LocalSubnet', 'Any', '192.0.2', '192.0.2.0/0', '192.0.2.0/33', '2001:db8::/129',
                '192.0.2.10,192.0.2.11', 'a.b.c.d', '192.0.2.10 ')) {
            Assert-HvLabTrue (-not (Test-HvLabRemoteAddress -Address $address)) "invalid remote address '$address'"
        }
    }

    It 'matches firewall port values' {
        Assert-HvLabTrue (Test-HvLabPortInList -PortList 'Any' -Port 50000) 'Any'
        Assert-HvLabTrue (Test-HvLabPortInList -PortList '50000' -Port 50000) 'single'
        Assert-HvLabTrue (Test-HvLabPortInList -PortList '49999-50001' -Port 50000) 'range'
        Assert-HvLabTrue (Test-HvLabPortInList -PortList @('22', '50000') -Port 50000) 'list'
        Assert-HvLabTrue (-not (Test-HvLabPortInList -PortList '50001' -Port 50000)) 'other port'
        Assert-HvLabTrue (-not (Test-HvLabPortInList -PortList $null -Port 50000)) 'null'
    }

    It 'converts timestamps to UTC' {
        $value = ConvertTo-HvLabUtc -Value '2026-01-02T03:04:05.0000000Z'
        Assert-HvLabEqual ([DateTimeKind]::Utc) $value.Kind 'kind'
        Assert-HvLabEqual 3 $value.Hour 'hour'
        Assert-HvLabEqual $null (ConvertTo-HvLabUtc -Value 'not a date') 'invalid string'
        Assert-HvLabEqual $null (ConvertTo-HvLabUtc -Value $null) 'null'
    }

    It 'replaces control characters in guest text' {
        $escape = [string][char]27
        $text = ConvertTo-HvLabSafeText ('Ready' + $escape + '[2J' + [char]7 + [char]0x9B + 'x')
        Assert-HvLabEqual 'Ready?[2J??x' $text 'ESC, BEL and CSI'
        Assert-HvLabEqual 'plain text' (ConvertTo-HvLabSafeText 'plain text') 'plain text is unchanged'
        Assert-HvLabEqual $null (ConvertTo-HvLabSafeText $null) 'null'
    }
}

Describe 'Scheduled task definition' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        $labDirectory = 'C:\ProgramData\HyperVLpeLab\lab1'
        $powerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    It 'builds a SYSTEM, on-demand, fixed-command task for every action' {
        foreach ($action in Get-HvLabAction) {
            $text = Get-HvLabTaskXml -Lab 'lab1' -Action $action -LabDirectory $labDirectory -PowerShellPath $powerShellPath
            [xml]$doc = $text
            $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
            $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
            Assert-HvLabEqual 'S-1-5-18' $doc.SelectSingleNode('/t:Task/t:Principals/t:Principal/t:UserId', $ns).InnerText "$action principal"
            Assert-HvLabEqual 0 @($doc.SelectNodes('/t:Task/t:Triggers', $ns)).Count "$action has no triggers"
            Assert-HvLabEqual 1 @($doc.SelectNodes('/t:Task/t:Actions/t:Exec', $ns)).Count "$action has one Exec"
            Assert-HvLabEqual $powerShellPath $doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command', $ns).InnerText "$action command"
            $expected = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$labDirectory\HvLabWorker.ps1`" -Action $action"
            Assert-HvLabEqual $expected $doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Arguments', $ns).InnerText "$action arguments"
            Assert-HvLabEqual 'IgnoreNew' $doc.SelectSingleNode('/t:Task/t:Settings/t:MultipleInstancesPolicy', $ns).InnerText "$action one instance"
            Assert-HvLabEqual "hyperv-lpe-lab: runs the fixed $action action on the VM of lab lab1. No parameters." $doc.SelectSingleNode('/t:Task/t:RegistrationInfo/t:Description', $ns).InnerText "$action description"
            Assert-HvLabTrue ($text -notmatch '\$\(Arg') "$action has no argument placeholder"
            Assert-HvLabTrue ($text -notmatch '%') "$action has no environment variable"
            Assert-HvLabEqual 0 @(Get-HvLabTaskXmlProblem -Xml $text -Action $action -LabDirectory $labDirectory -PowerShellPath $powerShellPath).Count "$action passes its own check"
        }
    }

    It 'writes a disabled task on request and checks the enabled state' {
        $disabled = Get-HvLabTaskXml -Lab 'lab1' -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -Enabled $false
        Assert-HvLabTrue ($disabled -match '<Enabled>false</Enabled>') 'disabled XML'
        Assert-HvLabEqual 0 @(Get-HvLabTaskXmlProblem -Xml $disabled -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -Enabled $false).Count 'disabled as expected'
        Assert-HvLabTrue (@(Get-HvLabTaskXmlProblem -Xml $disabled -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath) -contains 'the task is disabled') 'disabled when enabled is expected'
        $enabled = Get-HvLabTaskXml -Lab 'lab1' -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath
        Assert-HvLabTrue (@(Get-HvLabTaskXmlProblem -Xml $enabled -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -Enabled $false).Count -gt 0) 'enabled when disabled is expected'
    }

    It 'refuses unknown actions and unsafe inputs' {
        Assert-HvLabThrow { Get-HvLabTaskXml -Lab 'lab1' -Action 'Checkpoint' -LabDirectory $labDirectory -PowerShellPath $powerShellPath } 'unknown action'
        Assert-HvLabThrow { Get-HvLabTaskXml -Lab 'lab1' -Action 'start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath } 'action is case-sensitive'
        Assert-HvLabThrow { Get-HvLabTaskXml -Lab 'lab 1' -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath } 'bad lab'
        Assert-HvLabThrow { Get-HvLabTaskXml -Lab 'lab1' -Action 'Start' -LabDirectory 'C:\a"b' -PowerShellPath $powerShellPath } 'quote in folder'
        Assert-HvLabThrow { Get-HvLabTaskXml -Lab 'lab1' -Action 'Start' -LabDirectory $labDirectory -PowerShellPath 'C:\tmp\pwsh.exe' } 'other shell'
    }

    It 'flags a task that was changed after install' {
        $good = Get-HvLabTaskXml -Lab 'lab1' -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath
        $extraArgument = $good.Replace('-Action Start</Arguments>', '-Action Start $(Arg0)</Arguments>')
        Assert-HvLabTrue (@(Get-HvLabTaskXmlProblem -Xml $extraArgument -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath).Count -gt 0) 'placeholder'
        $otherUser = $good.Replace('<UserId>S-1-5-18</UserId>', '<UserId>S-1-5-21-1-2-3-1001</UserId>')
        Assert-HvLabTrue (@(Get-HvLabTaskXmlProblem -Xml $otherUser -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath).Count -gt 0) 'principal'
        $trigger = $good.Replace('  <Principals>', "  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>`r`n  <Principals>")
        Assert-HvLabTrue (@(Get-HvLabTaskXmlProblem -Xml $trigger -Action 'Start' -LabDirectory $labDirectory -PowerShellPath $powerShellPath).Count -gt 0) 'trigger'
    }

    It 'builds security descriptors that give change rights to SYSTEM and Administrators only' {
        $operator = 'S-1-5-21-1-2-3-1001'
        $task = Get-HvLabSddl -Kind Task -OperatorSid $operator
        Assert-HvLabEqual "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;$operator)" $task 'task SDDL'
        Assert-HvLabEqual 0 @(Get-HvLabSddlProblem -Sddl $task).Count 'task SDDL has no write for the operator'
        Assert-HvLabEqual 0 @(Get-HvLabSddlProblem -Sddl (Get-HvLabSddl -Kind LabTaskFolder -OperatorSid $operator)).Count 'lab folder'
        Assert-HvLabEqual 0 @(Get-HvLabSddlProblem -Sddl (Get-HvLabSddl -Kind TaskRootFolder)).Count 'root folder'
        Assert-HvLabTrue (@(Get-HvLabSddlProblem -Sddl 'D:(A;;FA;;;SY)(A;;FA;;;AU)').Count -gt 0) 'full access for Authenticated Users'
        Assert-HvLabTrue (@(Get-HvLabSddlProblem -Sddl "D:(A;;FA;;;SY)(A;;GW;;;$operator)").Count -gt 0) 'generic write'
        Assert-HvLabTrue (@(Get-HvLabSddlProblem -Sddl "D:(A;;FA;;;SY)(A;;WD;;;$operator)").Count -gt 0) 'write DACL'
        Assert-HvLabThrow { Get-HvLabSddl -Kind Task -OperatorSid 'S-1-5-11' } 'broad operator'
    }

    It 'builds folder ACLs with no write access for the operator' {
        $operator = 'S-1-5-21-1-2-3-1001'
        $lab = Get-HvLabDirectorySecurity -Kind Lab -OperatorSid $operator
        Assert-HvLabTrue $lab.AreAccessRulesProtected 'lab folder does not inherit'
        Assert-HvLabEqual 'S-1-5-32-544' $lab.GetOwner([System.Security.Principal.SecurityIdentifier]).Value 'owner'
        $rules = @($lab.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        Assert-HvLabEqual 3 $rules.Count 'three entries'
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -eq $operator) {
                Assert-HvLabTrue (-not (Test-HvLabWriteAccess -AccessMask ([int64]$rule.FileSystemRights))) 'operator has no write right'
            }
            else {
                Assert-HvLabTrue (@('S-1-5-18', 'S-1-5-32-544') -contains $rule.IdentityReference.Value) 'only SYSTEM and Administrators besides the operator'
            }
        }
        $root = Get-HvLabDirectorySecurity -Kind Root
        foreach ($rule in @($root.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
            if ($rule.IdentityReference.Value -eq 'S-1-5-11') {
                Assert-HvLabEqual ([System.Security.AccessControl.InheritanceFlags]::None) $rule.InheritanceFlags 'root read right is not inherited'
                Assert-HvLabTrue (-not (Test-HvLabWriteAccess -AccessMask ([int64]$rule.FileSystemRights))) 'root read only'
            }
        }
    }
}

Describe 'Task registration' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        $labDirectory = 'C:\ProgramData\HyperVLpeLab\lab1'
        $powerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $operator = 'S-1-5-21-1-2-3-1001'

        function Initialize-FakeTaskService {
            # Stands in for the Schedule.Service COM object: folders and tasks
            # live in memory, and every change is recorded in .Log. With
            # -TamperSddl, every task reports that security descriptor.
            param([string]$TamperSddl)
            $service = [pscustomobject]@{ Log = (New-Object System.Collections.Generic.List[string]); Folders = @{}; Tamper = $TamperSddl }
            $service | Add-Member -MemberType ScriptMethod -Name NewFolder -Value {
                param([string]$Path)
                $folder = [pscustomobject]@{ Path = $Path; Service = $this; Tasks = [ordered]@{} }
                $folder | Add-Member -MemberType ScriptMethod -Name CreateFolder -Value {
                    param([string]$Name, [string]$Sddl)
                    $childPath = $this.Path.TrimEnd('\') + '\' + $Name
                    $this.Service.Log.Add("CreateFolder $childPath")
                    return $this.Service.NewFolder($childPath)
                }
                $folder | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptor -Value {
                    param([string]$Sddl, [int]$Flags)
                    $this.Service.Log.Add("SetSecurityDescriptor $($this.Path)")
                }
                # The fifth argument is the logon password, which the installer
                # passes as $null for the SYSTEM account.
                $folder | Add-Member -MemberType ScriptMethod -Name RegisterTask -Value {
                    param([string]$Name, [string]$Xml, [int]$Flags, [string]$User, [object]$Fifth, [int]$LogonType, [string]$Sddl)
                    $enabled = ([xml]$Xml).Task.Settings.Enabled
                    $this.Service.Log.Add("RegisterTask $Name enabled=$enabled")
                    $task = [pscustomobject]@{ Name = $Name; Path = ($this.Path + '\' + $Name); Xml = $Xml; Sddl = $Sddl; Service = $this.Service }
                    $task | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
                        param([int]$Information)
                        if ($this.Service.Tamper) { return $this.Service.Tamper }
                        return $this.Sddl
                    }
                    $this.Tasks[$Name] = $task
                    return $task
                }
                $folder | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
                    param([string]$Name)
                    if (-not $this.Tasks.Contains($Name)) { throw "task $Name not found" }
                    return $this.Tasks[$Name]
                }
                # The leading comma returns the array itself, also when it is
                # empty, as the COM collections do.
                $folder | Add-Member -MemberType ScriptMethod -Name GetTasks -Value {
                    param([int]$Flags)
                    return , @($this.Tasks.Values)
                }
                $folder | Add-Member -MemberType ScriptMethod -Name GetFolders -Value {
                    param([int]$Flags)
                    $prefix = $this.Path.TrimEnd('\') + '\'
                    return , @($this.Service.Folders.Values | Where-Object {
                            $_.Path -ne $this.Path -and $_.Path.StartsWith($prefix) -and $_.Path.Substring($prefix.Length) -notmatch '\\'
                        })
                }
                $folder | Add-Member -MemberType ScriptMethod -Name DeleteTask -Value {
                    param([string]$Name, [int]$Flags)
                    $this.Tasks.Remove($Name)
                    $this.Service.Log.Add("DeleteTask $Name")
                }
                $folder | Add-Member -MemberType ScriptMethod -Name DeleteFolder -Value {
                    param([string]$Name, [int]$Flags)
                    $childPath = $this.Path.TrimEnd('\') + '\' + $Name
                    $this.Service.Folders.Remove($childPath)
                    $this.Service.Log.Add("DeleteFolder $childPath")
                }
                $this.Folders[$Path] = $folder
                return $folder
            }
            $service | Add-Member -MemberType ScriptMethod -Name GetFolder -Value {
                param([string]$Path)
                if (-not $this.Folders.ContainsKey($Path)) { throw "folder $Path not found" }
                return $this.Folders[$Path]
            }
            $null = $service.NewFolder('\')
            return $service
        }
    }

    It 'registers every task disabled, checks them, and only then enables them' {
        $service = Initialize-FakeTaskService
        $folder = Register-HvLabTaskSet -Service $service -Lab 'lab1' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -OperatorSid $operator
        Assert-HvLabEqual '\HyperVLpeLab\lab1' $folder.Path 'returns the lab task folder'
        $log = @($service.Log)
        $registered = @($log | Where-Object { $_ -like 'RegisterTask *' })
        Assert-HvLabEqual 12 $registered.Count 'six tasks, registered twice'
        Assert-HvLabEqual 6 @($registered[0..5] | Where-Object { $_ -like '*enabled=false' }).Count 'the first six are disabled'
        Assert-HvLabEqual 6 @($registered[6..11] | Where-Object { $_ -like '*enabled=true' }).Count 'the last six are enabled'
        Assert-HvLabEqual 0 @($log | Where-Object { $_ -like 'Delete*' }).Count 'nothing is deleted'
        foreach ($action in Get-HvLabAction) {
            Assert-HvLabEqual 0 @(Get-HvLabTaskXmlProblem -Xml $folder.GetTask($action).Xml -Action $action -LabDirectory $labDirectory -PowerShellPath $powerShellPath).Count "$action ends enabled and unchanged"
        }
    }

    It 'deletes the tasks and never enables them when a check fails' {
        $service = Initialize-FakeTaskService -TamperSddl "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$operator)"
        Assert-HvLabThrow { Register-HvLabTaskSet -Service $service -Lab 'lab1' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -OperatorSid $operator } 'a task that grants the operator full access'
        $log = @($service.Log)
        Assert-HvLabEqual 6 @($log | Where-Object { $_ -like 'RegisterTask * enabled=false' }).Count 'registered disabled'
        Assert-HvLabEqual 0 @($log | Where-Object { $_ -like 'RegisterTask * enabled=true' }).Count 'never enabled'
        Assert-HvLabEqual 6 @($log | Where-Object { $_ -like 'DeleteTask *' }).Count 'all six deleted'
        Assert-HvLabTrue ($log -contains 'DeleteFolder \HyperVLpeLab\lab1') 'lab task folder deleted'
        Assert-HvLabTrue ($log -contains 'DeleteFolder \HyperVLpeLab') 'empty root task folder deleted'
    }

    It 'keeps the root task folder while another lab uses it' {
        $service = Initialize-FakeTaskService
        $null = Register-HvLabTaskSet -Service $service -Lab 'lab1' -LabDirectory $labDirectory -PowerShellPath $powerShellPath -OperatorSid $operator
        $null = Register-HvLabTaskSet -Service $service -Lab 'lab2' -LabDirectory 'C:\ProgramData\HyperVLpeLab\lab2' -PowerShellPath $powerShellPath -OperatorSid $operator
        $removed = @(Remove-HvLabTaskFolder -Service $service -Lab 'lab1' -Confirm:$false)
        Assert-HvLabEqual 7 $removed.Count 'six tasks and the lab folder'
        Assert-HvLabTrue ($service.Folders.ContainsKey('\HyperVLpeLab')) 'root folder kept'
        Assert-HvLabTrue ($service.Folders.ContainsKey('\HyperVLpeLab\lab2')) 'other lab kept'
    }
}

Describe 'Guest output parsing' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        $user = @('"guest\labuser","S-1-5-21-1-2-3-1002"')
        $standardGroups = @(
            '"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"',
            '"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"',
            '"BUILTIN\Remote Desktop Users","Alias","S-1-5-32-555","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\NETWORK","Well-known group","S-1-5-2","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\Authenticated Users","Well-known group","S-1-5-11","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\This Organization","Well-known group","S-1-5-15","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\Local account","Well-known group","S-1-5-113","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\LogonSessionId_0_12345","Well-known group","S-1-5-5-0-12345","Mandatory group, Enabled by default, Enabled group"',
            '"NT AUTHORITY\NTLM Authentication","Well-known group","S-1-5-64-10","Mandatory group, Enabled by default, Enabled group"',
            '"Service asserted identity","Well-known group","S-1-18-2","Mandatory group, Enabled by default, Enabled group"',
            '"guest\None","Group","S-1-5-21-1-2-3-513","Mandatory group, Enabled by default, Enabled group"',
            '"Mandatory Label\Medium Mandatory Level","Label","S-1-16-8192",""'
        )
        $standardPrivileges = @(
            '"SeShutdownPrivilege","Shut down the system","Disabled"',
            '"SeChangeNotifyPrivilege","Bypass traverse checking","Enabled"',
            '"SeUndockPrivilege","Remove computer from docking station","Disabled"',
            '"SeIncreaseWorkingSetPrivilege","Increase a process working set","Disabled"',
            '"SeTimeZonePrivilege","Change the time zone","Disabled"'
        )
    }

    It 'accepts a standard-user token by SID and privilege name' {
        $context = ConvertFrom-HvLabWhoami -UserLines $user -GroupLines $standardGroups -PrivilegeLines $standardPrivileges
        Assert-HvLabEqual 'Medium' $context.IntegrityLevel 'integrity'
        Assert-HvLabTrue (-not $context.Elevated) 'not elevated'
        Assert-HvLabEqual 'Network (S4U)' $context.LogonType 'logon type'
        Assert-HvLabEqual 0 @($context.NonStandardGroups).Count 'no other group'
        Assert-HvLabEqual 0 @($context.NonStandardPrivileges).Count 'no other privilege'
        Assert-HvLabEqual $null (Get-HvLabRoleProblem -Context $context -Role User) 'fits User'
        Assert-HvLabTrue ($null -ne (Get-HvLabRoleProblem -Context $context -Role Admin)) 'does not fit Admin'
    }

    It 'refuses a "standard" account with a group outside the standard set' {
        foreach ($sid in @('S-1-5-32-551', 'S-1-5-32-580', 'S-1-5-32-583', 'S-1-5-32-559', 'S-1-5-32-544', 'S-1-5-21-1-2-3-1050', 'S-1-5-21-9-9-9-513')) {
            $groups = $standardGroups + @("`"some group`",`"Alias`",`"$sid`",`"Mandatory group, Enabled by default, Enabled group`"")
            $context = ConvertFrom-HvLabWhoami -UserLines $user -GroupLines $groups -PrivilegeLines $standardPrivileges
            $problem = Get-HvLabRoleProblem -Context $context -Role User
            Assert-HvLabTrue ($null -ne $problem -and $problem -match [regex]::Escape($sid)) "group $sid is refused and named"
        }
    }

    It 'refuses a "standard" account with a privilege outside the standard set' {
        foreach ($privilege in @('SeDebugPrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege')) {
            $privileges = $standardPrivileges + @("`"$privilege`",`"description`",`"Disabled`"")
            $context = ConvertFrom-HvLabWhoami -UserLines $user -GroupLines $standardGroups -PrivilegeLines $privileges
            $problem = Get-HvLabRoleProblem -Context $context -Role User
            Assert-HvLabTrue ($null -ne $problem -and $problem -match $privilege) "$privilege is refused and named"
        }
    }

    It 'reads an elevated admin token' {
        $groups = @(
            '"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled group, Group owner"',
            '"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""'
        )
        $context = ConvertFrom-HvLabWhoami -UserLines @('"guest\labadmin","S-1-5-21-1-2-3-500"') -GroupLines $groups
        Assert-HvLabTrue $context.Elevated 'elevated'
        Assert-HvLabEqual $null (Get-HvLabRoleProblem -Context $context -Role Admin) 'fits Admin'
        Assert-HvLabTrue ($null -ne (Get-HvLabRoleProblem -Context $context -Role User)) 'does not fit User'
    }

    It 'reads the session report from one command line' {
        $command = Get-HvLabContextCommand
        Assert-HvLabTrue ($command.StartsWith('whoami /user /fo csv /nh & ')) 'starts with whoami /user'
        Assert-HvLabTrue ($command.EndsWith(' & echo HVLAB-CONTEXT-END')) 'ends with the end marker'
        Assert-HvLabEqual 4 ([regex]::Matches($command, 'echo HVLAB-SECTION')).Count 'five sections'
        $lines = @($user + 'HVLAB-SECTION ' + $standardGroups + 'HVLAB-SECTION ' + $standardPrivileges + 'HVLAB-SECTION ' +
            '' + 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' +
            '    AllowDevelopmentWithoutDevLicense    REG_DWORD    0x1' + '' + 'HVLAB-SECTION ' + '0' + 'HVLAB-CONTEXT-END ' + 'HVLAB-SECTION ' + 'output of the command')
        $context = ConvertFrom-HvLabContextOutput -Line $lines
        Assert-HvLabTrue ($null -ne $context) 'report read'
        Assert-HvLabEqual 'guest\labuser' $context.Account 'account'
        Assert-HvLabEqual 0 $context.SessionId 'session id'
        Assert-HvLabEqual $true $context.DeveloperMode 'Developer Mode on'
        Assert-HvLabEqual $null (Get-HvLabRoleProblem -Context $context -Role User) 'fits User'
        Assert-HvLabTrue (Test-HvLabContextEndLine -Line 'HVLAB-CONTEXT-END ') 'end marker with a trailing space'
        Assert-HvLabTrue (-not (Test-HvLabContextEndLine -Line 'output')) 'other line'
    }

    It 'reports Developer Mode off and refuses an incomplete report' {
        $lines = @($user + 'HVLAB-SECTION ' + $standardGroups + 'HVLAB-SECTION ' + $standardPrivileges + 'HVLAB-SECTION ' +
            'HVLAB-NOVALUE ' + 'HVLAB-SECTION ' + 'HVLAB-CONTEXT-END ')
        $context = ConvertFrom-HvLabContextOutput -Line $lines
        Assert-HvLabEqual $false $context.DeveloperMode 'value missing means off'
        Assert-HvLabEqual $null $context.SessionId 'session id unknown'
        Assert-HvLabEqual $null (ConvertFrom-HvLabContextOutput -Line @($user + 'HVLAB-CONTEXT-END')) 'too few sections'
        Assert-HvLabEqual $null (ConvertFrom-HvLabContextOutput -Line @("The ampersand (&) character is not allowed.")) 'no markers, as from a PowerShell default shell'
    }

    It 'replaces control characters in names from the guest' {
        $escape = [string][char]27
        $context = ConvertFrom-HvLabWhoami -UserLines @('"guest\lab' + $escape + '[2Juser","S-1-5-21-1-2-3-1002"') -GroupLines $standardGroups -PrivilegeLines $standardPrivileges
        Assert-HvLabTrue (-not $context.Account.Contains($escape)) 'no ESC in the account name'
    }

    It 'decodes the last result line and ignores other output' {
        $prefix = Get-HvLabResultPrefix
        $first = $prefix + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"ok":false}'))
        $last = $prefix + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"ok":true,"name":"x.dmp"}'))
        $result = ConvertFrom-HvLabResultLine -Line @('noise', $first, 'more noise', "$last`r")
        Assert-HvLabTrue $result.ok 'last line wins'
        Assert-HvLabEqual 'x.dmp' $result.name 'field'
        Assert-HvLabEqual $null (ConvertFrom-HvLabResultLine -Line @('nothing here')) 'no result line'
        Assert-HvLabEqual $null (ConvertFrom-HvLabResultLine -Line @($prefix + 'not base64!')) 'bad payload'
    }

    It 'computes the same KDNET key hash as the guest helper' {
        $tokens = $null
        $parseErrors = $null
        $helperPath = (Resolve-Path (Join-Path $PSScriptRoot '..\guest\Get-HvLabKdnetInfo.ps1')).ProviderPath
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$parseErrors)
        $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-HvLabKeyHash' }, $true)
        Assert-HvLabTrue ($null -ne $definition) 'the guest helper defines Get-HvLabKeyHash'
        # Defines that one function from the helper; the rest of the helper does not run.
        . ([scriptblock]::Create($definition.Extent.Text))
        $cases = @(
            @('00000000000000000000000000000000', 'aaaa.bbbb.cccc.dddd'),
            @('00112233445566778899aabbccddeeff', 'aaaa.bbbb.cccc.dddd'),
            @('ffffffffffffffffffffffffffffffff', 'AAAA.BBBB.CCCC.DDDD'),
            @('0123456789abcdef0123456789abcdef', '')
        )
        foreach ($case in $cases) {
            Assert-HvLabEqual (Get-HvLabKdnetKeyHash -Nonce $case[0] -Key $case[1]) (Get-HvLabKeyHash -Nonce $case[0] -Key $case[1]) "host and guest agree for nonce $($case[0])"
        }
        # SHA-256 of 16 zero bytes followed by the key, computed with Python's hashlib.
        Assert-HvLabEqual '8b663e0c6d1928b2e551c67b01e9f7c9bb6fb1efff01208f2c82c1647751c5e9' (Get-HvLabKdnetKeyHash -Nonce ('0' * 32) -Key 'aaaa.bbbb.cccc.dddd') 'known answer'
        Assert-HvLabTrue ((Get-HvLabKdnetKeyHash -Nonce ('0' * 32) -Key 'aaaa.bbbb.cccc.dddd') -cne (Get-HvLabKdnetKeyHash -Nonce ('0' * 32) -Key 'AAAA.BBBB.CCCC.DDDD')) 'letter case changes the hash'
    }
}

Describe 'Config file' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        $base = [ordered]@{
            Lab          = 'lab1'
            GuestAddress = '192.0.2.10'
            AdminAccount = 'labadmin'
            UserAccount  = 'labuser'
            AdminKeyPath = '~/.ssh/hvlab_admin_ed25519'
            UserKeyPath  = '~/.ssh/hvlab_user_ed25519'
        }
        function Write-TestConfig {
            param([System.Collections.IDictionary]$Values, [string]$Name)
            $path = Join-Path $TestDrive $Name
            [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Values))
            return $path
        }
        function Copy-TestConfig {
            param([System.Collections.IDictionary]$Changes)
            $copy = [ordered]@{}
            foreach ($key in $base.Keys) { $copy[$key] = $base[$key] }
            foreach ($key in $Changes.Keys) { $copy[$key] = $Changes[$key] }
            return $copy
        }
    }

    It 'loads a valid file and fills in defaults' {
        $config = Get-HvLabConfig -Path (Write-TestConfig -Values $base -Name 'ok.json')
        Assert-HvLabEqual 22 $config.SshPort 'default port'
        Assert-HvLabEqual 50000 $config.KdnetPort 'default KDNET port'
        Assert-HvLabTrue ($config.AdminKeyPath.StartsWith($HOME)) 'tilde expanded'
        Assert-HvLabTrue ($config.KnownHostsPath.EndsWith('hvlab_known_hosts')) 'default known_hosts'
        Assert-HvLabEqual $null $config.KdnetKeyFile 'no key file'
    }

    It 'refuses typos, unsafe values and shared keys' {
        $cases = @(
            @{ Name = 'typo.json'; Changes = @{ GuestAdress = '192.0.2.10' } },
            @{ Name = 'option.json'; Changes = @{ GuestAddress = '-oProxyCommand=calc' } },
            @{ Name = 'account.json'; Changes = @{ UserAccount = 'a@b' } },
            @{ Name = 'same-account.json'; Changes = @{ UserAccount = 'LabAdmin' } },
            @{ Name = 'same-key.json'; Changes = @{ UserKeyPath = '~/.ssh/hvlab_admin_ed25519' } },
            @{ Name = 'port.json'; Changes = @{ SshPort = 70000 } },
            @{ Name = 'relative.json'; Changes = @{ AdminKeyPath = 'keys\admin' } },
            @{ Name = 'lab.json'; Changes = @{ Lab = 'lab one' } }
        )
        foreach ($case in $cases) {
            $path = Write-TestConfig -Values (Copy-TestConfig -Changes $case.Changes) -Name $case.Name
            Assert-HvLabThrow { Get-HvLabConfig -Path $path } $case.Name
        }
        Assert-HvLabThrow { Get-HvLabConfig -Path (Join-Path $TestDrive 'missing.json') } 'missing file'
    }

    It 'needs only Lab for lifecycle use' {
        $path = Write-TestConfig -Values ([ordered]@{ Lab = 'lab2' }) -Name 'lifecycle.json'
        $config = Get-HvLabConfig -Path $path -LifecycleOnly
        Assert-HvLabEqual 'lab2' $config.Lab 'lab'
        Assert-HvLabThrow { Get-HvLabConfig -Path $path } 'full load needs the SSH settings'
    }

    It 'builds strict, key-only ssh options with one key per role and no forwarding' {
        $config = Get-HvLabConfig -Path (Write-TestConfig -Values $base -Name 'ssh.json')
        $userArgs = @(Get-HvLabSshArgument -Config $config -Role User)
        $joined = $userArgs -join ' '
        $required = @('BatchMode=yes', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'IdentitiesOnly=yes',
            'StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'ForwardAgent=no', 'ForwardX11=no', 'ClearAllForwardings=yes',
            'PermitLocalCommand=no', 'ProxyCommand=none', 'RequestTTY=no')
        foreach ($option in $required) {
            $index = [array]::IndexOf($userArgs, $option)
            Assert-HvLabTrue ($index -gt 0 -and $userArgs[$index - 1] -eq '-o') "option -o $option"
        }
        Assert-HvLabEqual $config.UserKeyPath $userArgs[[array]::IndexOf($userArgs, '-i') + 1] 'user key'
        Assert-HvLabEqual 'labuser' $userArgs[[array]::IndexOf($userArgs, '-l') + 1] 'user account'
        Assert-HvLabTrue ($joined -notmatch 'accept-new') 'strict by default'
        $adminArgs = @(Get-HvLabSshArgument -Config $config -Role Admin -TrustNewHostKey)
        Assert-HvLabEqual $config.AdminKeyPath $adminArgs[[array]::IndexOf($adminArgs, '-i') + 1] 'admin key'
        Assert-HvLabTrue ($adminArgs -contains 'StrictHostKeyChecking=accept-new') 'accept-new on request'
        $scpArgs = @(Get-HvLabSshArgument -Config $config -Role Admin -Tool scp)
        Assert-HvLabTrue ($scpArgs -contains '-P' -and $scpArgs -notcontains '-l') 'scp uses -P and no -l'
        foreach ($option in $required) { Assert-HvLabTrue ($scpArgs -contains $option) "scp option $option" }
        foreach ($list in @(@{ Name = 'ssh'; Value = $userArgs }, @{ Name = 'scp'; Value = $scpArgs })) {
            $values = $list.Value
            Assert-HvLabEqual 'none' $values[[array]::IndexOf($values, '-F') + 1] "$($list.Name) reads no config file (-F none)"
            $userFile = @($values | Where-Object { $_ -like 'UserKnownHostsFile=*' } | ForEach-Object { $_.Substring('UserKnownHostsFile='.Length) })
            $globalFile = @($values | Where-Object { $_ -like 'GlobalKnownHostsFile=*' } | ForEach-Object { $_.Substring('GlobalKnownHostsFile='.Length) })
            Assert-HvLabEqual 1 $userFile.Count "$($list.Name) names one user known_hosts file"
            Assert-HvLabEqual $config.KnownHostsPath $userFile[0].Trim('"') "$($list.Name) uses the lab known_hosts file"
            Assert-HvLabEqual $userFile[0] ($globalFile -join ' ') "$($list.Name) reads no host-wide known_hosts file"
        }
        Assert-HvLabEqual 'labadmin@192.0.2.10:hvlab-stage/x.dmp' (Get-HvLabScpRemote -Config $config -Role Admin -RemotePath 'hvlab-stage/x.dmp') 'scp remote'
        Assert-HvLabThrow { Get-HvLabScpRemote -Config $config -Role Admin -RemotePath '../x' } 'no parent paths'
        Assert-HvLabThrow { Get-HvLabScpRemote -Config $config -Role Admin -RemotePath 'C:/Windows/x' } 'no absolute paths'
    }
}

Describe 'ACL checks on real files' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        function Write-TestAcl {
            # Replaces the ACL of a file or folder in the TestDrive: full
            # control for this account, plus -Extra rules.
            param([string]$Path, [object[]]$Extra = @())
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $isFolder = Test-Path -LiteralPath $Path -PathType Container
            if ($isFolder) {
                $acl = New-Object System.Security.AccessControl.DirectorySecurity
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
            }
            else {
                $acl = New-Object System.Security.AccessControl.FileSecurity
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
            }
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in $Extra) { $acl.AddAccessRule($rule) }
            if ('System.IO.FileSystemAclExtensions' -as [type]) {
                if ($isFolder) { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($Path), $acl) }
                else { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($Path), $acl) }
            }
            elseif ($isFolder) { [System.IO.Directory]::SetAccessControl($Path, $acl) }
            else { [System.IO.File]::SetAccessControl($Path, $acl) }
        }
        function Get-TestRule {
            param([string]$Sid, [string]$Rights, [string]$Inheritance = 'ContainerInherit, ObjectInherit', [string]$Propagation = 'None')
            return New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.SecurityIdentifier]::new($Sid), $Rights, $Inheritance, $Propagation, 'Allow')
        }
    }

    It 'reports the owner of a folder unless it is SYSTEM or Administrators' {
        $folder = Join-Path $TestDrive 'new-folder'
        $null = New-Item -ItemType Directory -Path $folder
        $problems = @(Get-HvLabAclProblem -Path $folder -Recurse -RequireProtected)
        # A new folder is owned by this account, or by Administrators when the
        # account runs elevated, as on a GitHub-hosted runner. Only the owner
        # line is counted: an inherited entry for this account names it too.
        $owner = (Get-Acl -LiteralPath $folder).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (@('S-1-5-18', 'S-1-5-32-544') -contains $owner) {
            Assert-HvLabEqual 0 @($problems | Where-Object { $_ -like '*owned by*' }).Count 'a SYSTEM or Administrators owner is not reported'
        }
        else {
            Assert-HvLabEqual 1 @($problems | Where-Object { $_ -like "* is owned by $owner, not by SYSTEM or Administrators" }).Count 'owner is reported'
        }
        Assert-HvLabTrue (@($problems | Where-Object { $_ -match 'inherits' }).Count -gt 0) 'inheritance is reported'
        Assert-HvLabTrue (@(Get-HvLabAclProblem -Path (Join-Path $TestDrive 'missing')).Count -gt 0) 'missing path is reported'
    }

    It 'reports a secret file that another group can read' {
        $key = Join-Path $TestDrive 'key'
        [System.IO.File]::WriteAllText($key, 'not a real key')
        Write-TestAcl -Path $key
        Assert-HvLabEqual 0 @(Get-HvLabSecretFileProblem -Path $key).Count 'owner-only file passes'
        Write-TestAcl -Path $key -Extra @((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Read', 'Allow')))
        Assert-HvLabTrue (@(Get-HvLabSecretFileProblem -Path $key).Count -gt 0) 'Users read access is reported'
        Assert-HvLabTrue (@(Get-HvLabSecretFileProblem -Path (Join-Path $TestDrive 'nokey')).Count -gt 0) 'missing file is reported'
        $fix = Get-HvLabSecretFileFix -Path $key
        Assert-HvLabTrue ($fix.StartsWith('icacls "') -and $fix.Contains([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 'fix names icacls and this account'
    }

    It 'judges folder rights by owner and by entries that apply to the folder itself' {
        $replace = [int64](0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'))
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-5-18' -Rights 'FullControl'))
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-5-32-545' -Rights 'ReadAndExecute'))
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-5-11' -Rights 'AppendData' -Inheritance 'None'))
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify' -Propagation 'InheritOnly'))
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-3-0' -Rights 'FullControl' -Propagation 'InheritOnly'))
        Assert-HvLabEqual 0 @(Get-HvLabSecurityRightProblem -Security $security -Mask $replace -Label 'like C:\').Count 'the C:\ pattern passes'
        Assert-HvLabEqual 1 @(Get-HvLabSecurityRightProblem -Security $security -Mask ($replace -bor 0x4) -Label 'x').Count 'add subfolder counts when the mask has it'
        $security.AddAccessRule((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify'))
        Assert-HvLabTrue ((@(Get-HvLabSecurityRightProblem -Security $security -Mask $replace -Label 'x') -match 'S-1-5-11').Count -gt 0) 'Modify on the folder itself is reported'
        $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001'))
        Assert-HvLabTrue ((@(Get-HvLabSecurityRightProblem -Security $security -Mask $replace -Label 'x') -match 'owned by S-1-5-21-1-2-3-1001').Count -gt 0) 'an ordinary owner is reported'
    }

    It 'refuses an install root below a folder that other accounts can replace' {
        $weak = Join-Path $TestDrive 'weak'
        $null = New-Item -ItemType Directory -Path $weak
        Write-TestAcl -Path $weak -Extra @((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify'))
        $problems = @(Get-HvLabAncestorProblem -Path (Join-Path $weak 'HyperVLpeLab'))
        Assert-HvLabTrue (@($problems | Where-Object { $_.StartsWith("$weak grants") -and $_ -match 'S-1-5-11' }).Count -eq 1) 'Modify for Authenticated Users is reported'

        $inheritOnly = Join-Path $TestDrive 'inherit-only'
        $null = New-Item -ItemType Directory -Path $inheritOnly
        Write-TestAcl -Path $inheritOnly -Extra @((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify' -Propagation 'InheritOnly'))
        $problems = @(Get-HvLabAncestorProblem -Path (Join-Path $inheritOnly 'HyperVLpeLab'))
        Assert-HvLabEqual 0 @($problems | Where-Object { $_.StartsWith("$inheritOnly grants") -and $_ -match 'S-1-5-11' }).Count 'an inherit-only entry is not reported'

        $problems = @(Get-HvLabAncestorProblem -Path (Join-Path $TestDrive 'missing\deeper\HyperVLpeLab'))
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like "*\missing does not exist*" }).Count -eq 1) 'a missing parent is reported'
    }

    It 'reports PATH folders where other accounts can plant a DLL' {
        $open = Join-Path $TestDrive 'path-open'
        $null = New-Item -ItemType Directory -Path $open
        Write-TestAcl -Path $open -Extra @((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify'))
        $closed = Join-Path $TestDrive 'path-inherit-only'
        $null = New-Item -ItemType Directory -Path $closed
        Write-TestAcl -Path $closed -Extra @((Get-TestRule -Sid 'S-1-5-11' -Rights 'Modify' -Propagation 'InheritOnly'))
        $value = "$open;$closed\;relative\bin;\\server\share\bin;C:bin;;`"$open\missing`""
        $problems = @(Get-HvLabSearchPathProblem -PathValue $value)
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like "PATH folder: $open grants*S-1-5-11" }).Count -eq 1) 'a writable PATH folder is reported'
        Assert-HvLabEqual 0 @($problems | Where-Object { $_ -like "*$closed grants*S-1-5-11" }).Count 'an inherit-only entry is not reported'
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like '*\\server\share\bin*network path*' }).Count -eq 1) 'a network path is reported'
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like "*'C:bin' is relative to a drive*" }).Count -eq 1) 'a drive-relative path is reported'
        Assert-HvLabEqual 0 @($problems | Where-Object { $_ -like '*relative\bin*' }).Count 'a plain relative entry is skipped'
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like "PATH entry $open\missing does not exist, and $open grants*S-1-5-11" }).Count -eq 1) 'a missing folder that others could create is reported'
    }

    It 'refuses to treat a folder as a lab folder without a matching install.json' {
        $root = Join-Path $TestDrive 'root'
        $lab = Join-Path $root 'lab1'
        $null = New-Item -ItemType Directory -Path $lab -Force
        $problems = @(Get-HvLabInstalledLabProblem -LabDirectory $lab -Lab 'lab1' -InstallRoot $root)
        Assert-HvLabTrue (@($problems | Where-Object { $_ -like '*install.json is missing' }).Count -eq 1) 'no install.json'

        $manifest = [ordered]@{ schema = 'hvlab-install/1'; lab = 'lab1'; labDirectory = $lab; installRoot = $root }
        $manifestPath = Join-Path $lab 'install.json'
        [System.IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $manifest))
        $problems = @(Get-HvLabInstalledLabProblem -LabDirectory $lab -Lab 'lab1' -InstallRoot $root)
        Assert-HvLabEqual 0 @($problems | Where-Object { $_ -like 'install.json*' }).Count 'a matching install.json passes'
        # The ACL check requires a protected ACL, and this new folder inherits
        # its permissions, so that line is always there. An owner line is not:
        # an elevated account, as on a GitHub-hosted runner, makes
        # Administrators the owner, and that owner is not reported.
        Assert-HvLabEqual 1 @($problems | Where-Object { $_ -like '*\lab1 inherits permissions from its parent folder' }).Count 'the ACL is still checked'

        $cases = @(
            @{ Field = 'schema'; Value = 'hvlab-install/2' },
            @{ Field = 'lab'; Value = 'Lab1' },
            @{ Field = 'labDirectory'; Value = (Join-Path $root 'other') },
            @{ Field = 'installRoot'; Value = 'C:\ProgramData' }
        )
        foreach ($case in $cases) {
            $changed = [ordered]@{}
            foreach ($key in $manifest.Keys) { $changed[$key] = $manifest[$key] }
            $changed[$case.Field] = $case.Value
            [System.IO.File]::WriteAllText($manifestPath, (ConvertTo-Json -InputObject $changed))
            $problems = @(Get-HvLabInstalledLabProblem -LabDirectory $lab -Lab 'lab1' -InstallRoot $root)
            Assert-HvLabTrue (@($problems | Where-Object { $_ -like 'install.json*' }).Count -eq 1) "a different $($case.Field) is refused"
        }
    }
}

Describe 'Copy size limit' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
        function Initialize-FakeProcess {
            # Stands in for System.Diagnostics.Process: it exits after
            # -ExitAfter polls, or when Kill() is called.
            param([int]$ExitAfter)
            $process = [pscustomobject]@{ Polls = 0; ExitAfter = $ExitAfter; Killed = $false; ExitCode = 0 }
            $process | Add-Member -MemberType ScriptProperty -Name HasExited -Value {
                $this.Polls++
                return ($this.Killed -or $this.Polls -gt $this.ExitAfter)
            }
            $process | Add-Member -MemberType ScriptMethod -Name Kill -Value {
                param([bool]$EntireProcessTree)
                $this.Killed = $true
                $this.ExitCode = -1
            }
            $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
            return $process
        }
    }

    It 'stops a copy that grows past the reported size' {
        $path = Join-Path $TestDrive 'big.part'
        [System.IO.File]::WriteAllBytes($path, (New-Object byte[] 100))
        $process = Initialize-FakeProcess -ExitAfter 1000
        $result = Wait-HvLabCopy -Process $process -Path $path -MaxBytes 50 -PollMilliseconds 10
        Assert-HvLabTrue $result.Exceeded 'exceeded'
        Assert-HvLabTrue $process.Killed 'process stopped'
    }

    It 'lets a copy of the reported size finish' {
        $path = Join-Path $TestDrive 'exact.part'
        [System.IO.File]::WriteAllBytes($path, (New-Object byte[] 50))
        $process = Initialize-FakeProcess -ExitAfter 2
        $result = Wait-HvLabCopy -Process $process -Path $path -MaxBytes 50 -PollMilliseconds 10
        Assert-HvLabTrue (-not $result.Exceeded) 'not exceeded'
        Assert-HvLabTrue (-not $process.Killed) 'not stopped'
        Assert-HvLabEqual 0 $result.ExitCode 'exit code'
        $result = Wait-HvLabCopy -Process (Initialize-FakeProcess -ExitAfter 0) -Path (Join-Path $TestDrive 'none.part') -MaxBytes 50 -PollMilliseconds 10
        Assert-HvLabTrue (-not $result.Exceeded) 'no file at all'
    }
}

Describe 'Lifecycle target and known_hosts name' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        Import-Module (Join-Path $PSScriptRoot '..\host\HvLab.Common.psm1') -Force
    }

    It 'uses explicit values without reading a config file' {
        $target = Resolve-HvLabLifecycleTarget -Lab 'lab1' -InstallRoot 'C:\ProgramData\HyperVLpeLab\'
        Assert-HvLabEqual 'C:\ProgramData\HyperVLpeLab\lab1' $target.LabDirectory 'lab folder'
        Assert-HvLabEqual '\HyperVLpeLab\lab1' $target.TaskFolder 'task folder'
        Assert-HvLabThrow { Resolve-HvLabLifecycleTarget -Lab 'lab 1' -InstallRoot 'C:\ProgramData\HyperVLpeLab' } 'bad lab'
    }

    It 'reads the lab name from a config file' {
        $path = Join-Path $TestDrive 'target.json'
        [System.IO.File]::WriteAllText($path, '{"Lab":"lab7","InstallRoot":"D:\\LabData"}')
        $target = Resolve-HvLabLifecycleTarget -ConfigPath $path
        Assert-HvLabEqual 'lab7' $target.Lab 'lab'
        Assert-HvLabEqual 'D:\LabData\lab7' $target.LabDirectory 'lab folder'
    }

    It 'names the known_hosts entry with the port when it is not 22' {
        Assert-HvLabEqual '192.0.2.10' (Get-HvLabKnownHostsEntry -Config ([pscustomobject]@{ GuestAddress = '192.0.2.10'; SshPort = 22 })) 'port 22'
        Assert-HvLabEqual '[192.0.2.10]:2222' (Get-HvLabKnownHostsEntry -Config ([pscustomobject]@{ GuestAddress = '192.0.2.10'; SshPort = 2222 })) 'port 2222'
    }
}
