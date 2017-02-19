
throw "Don't run this blindly - copy-and-paste the bits you want"


#Things I'm bored of typing:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
notepad C:\Windows\System32\drivers\etc\hosts
net localgroup administrators
(Get-WmiObject Win32_ComputerSystem).Domain
nslookup -querytype=srv "_ldap._tcp.pdc._msdcs.$((Get-WmiObject Win32_ComputerSystem).Domain)"



#Get all the DNS names used on a cluster
function Get-ClusterName {
 	Get-ClusterNode | select @{Name = "ClusterResource"; Expression={"Cluster Node"}}, OwnerGroup, Name, DnsSuffix
	Get-Cluster | Get-ClusterResource | ?{$_.ResourceType -like "Network Name"} | %{
		$_ | select `
			@{Name = "ClusterResource"; Expression={$_.Name}},
			OwnerGroup,
			@{Name="Name"; Expression={$_ | Get-ClusterParameter -Name Name | select -ExpandProperty Value}},
			@{Name="DnsSuffix"; Expression={$_ | Get-ClusterParameter -Name DnsSuffix | select -ExpandProperty Value}}
	}
}



#Get all the IP addresses used by a cluster
function Get-ClusterIpAddress {
	Get-Cluster | Get-ClusterResource | ?{$_.ResourceType -like "IP Address"} | %{
		$_ | select `
			@{Name = "ClusterResource"; Expression={$_.Name}},
			OwnerGroup,
			@{Name="Address"; Expression={$_ | Get-ClusterParameter -Name Address | select -ExpandProperty Value}},
			@{Name="SubnetMask"; Expression={$_ | Get-ClusterParameter -Name SubnetMask | select -ExpandProperty Value}}
	}
}



#Get all SQL cluster instance names
function Get-ClusterSqlInstanceName {
    if (-not (Get-Command Get-ClusterName -ErrorAction SilentlyContinue)) {
        throw "Please also import the Get-ClusterName function from https://github.com/fsackur/PowerShell-Snippets/"
    }

    $ClusterNames = Get-ClusterName;
    $ClusterGroups = Get-ClusterGroup
    $Namespace = (Get-WmiObject -Namespace "ROOT\Microsoft\SqlServer" -Class "__Namespace" -Filter "Name LIKE 'ComputerManagement%'" | sort Name -Descending | select -First 1 @{Name="Namespace"; Expression={$_.__NAMESPACE + "\" + $_.Name}}).Namespace
    $SqlInstanceWmi = Get-WmiObject -Namespace $Namespace -Class "SqlService" -Filter "SqlServiceType = 1"

    $SqlInstanceWmi | ForEach-Object {

        $InstanceId = $_.ServiceName
        [bool]$IsDefaultInstance = $InstanceId -like "MSSQLSERVER"
        $Instance = $InstanceId -replace '^MSSQL\$'

        $ClusteredWmi = Get-WmiObject -Namespace $Namespace -Class "SqlServiceAdvancedProperty" -Filter "PropertyName = 'CLUSTERED' AND ServiceName = `'$InstanceId`'"
        [bool]$IsClustered = $ClusteredWmi.PropertyNumValue -ne 0
        
        if ($IsClustered) {
            # Virtual Server object, for clusters
            $VsNameWmi = Get-WmiObject -Namespace $Namespace -Class "SqlServiceAdvancedProperty" -Filter "PropertyName = 'VSNAME' AND ServiceName = `'$InstanceId`'"
            $NetworkName = $VsNameWmi.PropertyStrValue
        } else {
            $NetworkName = $env:COMPUTERNAME
        }

        if ($IsDefaultInstance) {$InstanceName = $NetworkName} else {$InstanceName = $NetworkName + "\" + $Instance}

        $ClusterName = $ClusterNames | ?{$_.Name -like $NetworkName}

        return New-Object psobject -Property @{
            InstanceName  = $InstanceName;
            OwnerGroup    = $ClusterName.OwnerGroup
        }
    }
}



#Get SQL service accounts
Get-WmiObject Win32_Service -Filter "DisplayName LIKE 'SQL%'" | select Name, DisplayName, @{Name='ServiceAccount';Expression={$_.StartName}}

 

#Kerberos logging
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters -Name LogLevel -Value 0x01 -PropertyType Dword -Force  #0x00 to turn off


#Get web bindings, but with sitenames!
function Get-WebBinding {
    Import-Module WebAdministration
    $Sites = Get-ChildItem IIS:\Sites
    foreach ($Site in $Sites) {
        $Site.Bindings.collection | %{
            $Tokens = $_.bindingInformation -split ':'
            New-Object psobject -Property @{
                Protocol = $_.protocol
                IP = $Tokens[0]
                Port = $Tokens[1]
                Hostname = $Tokens[2]
                Site = $Site.Name
            }       
        }
    }
}



#Find all recent user logons
[int]$Days = 2
$EventLogs = Get-EventLog -LogName Security -After (Get-Date).AddDays(-$Days) | Where-Object {$_.EventID -eq 4624}
$EventLogs | %{New-Object psobject -Property @{"Time" = $_.TimeGenerated; "User" = ($_ | select -exp ReplacementStrings)[6..5] -join '\'}} | sort -Property User -Unique | sort -Property Time



#Last boot time - from WMI
$Boot = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
Get-Date -Year $Boot.Substring(0,4) -Month $Boot.Substring(4,2) -Day $Boot.Substring(6,2) -Hour $Boot.Substring(8,2) -Minute $Boot.Substring(10,2) -Second $Boot.Substring(12,2)


#All boot times - from system log
Get-WinEvent -FilterHashtable @{Logname="System"; Id=12}

#Install Wireshark (PS 4+)
Invoke-WebRequest https://chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression
choco install winpcap -y
choco install wireshark -y

function New-RandomPassword {
    return (
        ([char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 15)) -join ""
    )
}


#High CPU - find PID and process name of top offender, and application pool if the process is w3wp
function Get-CpuTopOffender {
    #we require this select statement to break the link to the live data, so that the processlist contains point-in-time data
    $ProcessList1 = Get-Process | select ProcessName, Id, @{name='ms'; expr={$_.TotalProcessorTime.TotalMilliSeconds}} | Group-Object -Property ID -AsString -AsHashTable
    $Seconds = 5
    Start-Sleep -Seconds $Seconds
    $ProcessList2 = Get-Process | select ProcessName, Id, @{name='ms'; expr={$_.TotalProcessorTime.TotalMilliSeconds}} | Group-Object -Property ID -AsString -AsHashTable
	
    $CalculatedProcessList = @()
	
    foreach ($ProcessId in $ProcessList1.Keys) {
        $Name = ($ProcessList1.$ProcessID)[0].ProcessName
        
        $CpuTotalMs1 = ($ProcessList1.$ProcessID)[0].ms
        if (-not ($ProcessList2.$ProcessID)) {continue}
        $CpuTotalMs2 = ($ProcessList2.$ProcessID)[0].ms
        
        $Calc = New-Object psobject -Property @{
            Name = $Name;
            PID = $ProcessID;
            CPU = $($CpuTotalMs2 - $CpuTotalMs1)
        }
        
        $CalculatedProcessList += $Calc
    }
	        
    $TopOffender = $CalculatedProcessList | sort CPU -Descending | select -First 1
    
    $Output = "Top CPU hog in last $Seconds seconds: $($TopOffender.Name) with PID $($TopOffender.PID)"
    
    #Add extra info
    if ($TopOffender.Name -like "svchost") {
        $ServiceNames = (Get-WmiObject -Query "SELECT Name FROM Win32_Service WHERE ProcessId = $($TopOffender.PID)" | %{$_.Name})
        $Output += "`nServices hosted: $($ServiceNames -join ', ')"
    }

    if ($TopOffender.Name -like "w3wp") {
        $ProcessWmi = (Get-WmiObject -Query "SELECT CommandLine FROM Win32_Process WHERE ProcessId = $($TopOffender.PID)")
        $Cli = $ProcessWmi.CommandLine
        $AppPool = ($Cli -split '"')[1]
        $Output += "`nApplication pool: $AppPool"
    }


    $Output

}
