# Live Forensicator Powershell Script
# Part of the Black Widow Tools
# Coded by Ebuka John Onyejegbu



[cmdletbinding()]
param( 
    
    
    [String]$LOG4J,
    [String]$RAM,
    [String]$EVTX,
	[String]$OPERATOR,
	[String]$CASE,
	[String]$TITLE,
	[String]$LOCATION,
	[String]$DEVICE,
	[String]$RANSOMWARE,
	[String]$WEBLOGS,
	[String]$BROWSER,
	[String]$PCAP,
	[String]$ENCRYPTED,
	[switch]$UPDATE,
	[switch]$VERSION,
	[switch]$DECRYPT,
	[switch]$USAGE
)


$ErrorActionPreference= 'silentlycontinue'

##################################################
#region        Versioning & Update               #
##################################################
$version_file = $PSScriptRoot + "\" + "Updated" + "\" + "version.txt"
$current_version = $PSScriptRoot + "\" + "version.txt"

$MyVersion = Get-Content -Path .\version.txt

if ($VERSION.IsPresent) {
   Write-Host -Fore Cyan "[!] You are currently running" $MyVersion
   Write-Host ''
   exit 0
}


if ($UPDATE) {
	Write-Host -Fore DarkCyan "[*] Downloading & Comparing Version Files"
	New-Item -Name "Updated" -ItemType "directory" -Force | Out-Null
	Set-Location Updated

	$source = 'https://raw.githubusercontent.com/Johnng007/Live-Forensicator/main/version.txt'

	$destination = 'version.txt'

if (((Test-NetConnection www.githubusercontent.com -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) -eq $true) {
	
	Invoke-WebRequest -Uri $source -OutFile $destination	
}

else {
	Write-Host -Fore DarkCyan "[*] githubusercontent.com is not reacheable, please check your connection"
	cd $PSScriptRoot
	Remove-Item 'Updated' -Force -Recurse
	exit 0
}

if((Get-FileHash $version_file).hash  -eq (Get-FileHash $current_version).hash) {
	 
	Write-Host -Fore Cyan "[*] Congratualtion you have the current version"
	cd $PSScriptRoot
	Remove-Item 'Updated' -Force -Recurse
    exit
 }

else {
	Write-Host -Fore DarkCyan "[!] You have an outdated version, we are sorting that out..."
	$source = 'https://github.com/Johnng007/Live-Forensicator/archive/refs/heads/main.zip'
    $destination = 'Live-Forensicator-main.zip'
    Invoke-WebRequest -Uri $source -OutFile $destination
	Write-Host -Fore DarkCyan "[*] Extracting the downloads....."
	Expand-Archive -Force $PSScriptRoot\Updated\Live-Forensicator-main.zip -DestinationPath $PSScriptRoot\Updated 
	Write-Host -Fore DarkCyan "[*] Cleaning Up...."
	Remove-Item -Path $PSScriptRoot\Updated\Live-Forensicator-main.zip -Force
	Remove-Item -Path $PSScriptRoot\Updated\version.txt -Force
	Write-Host -Fore Cyan "[*] All Done Enjoy the new version in the Updated Folder"
	cd $PSScriptRoot
	exit 0
	}	
} 


##################################################
#endregion     Versioning & Update               #
##################################################

##################################################
#region    ARTIFACT DECRYPTION SWITCH            #
##################################################

if ($DECRYPT) {
	
   $DecryptPath = $PSScriptRoot + "\" + "$env:computername" + "\" 
	
if (!(gci $DecryptPath *.forensicator))  { 
	
   Write-Host -Fore DarkCyan "[!] Cannot find encrypted file, Did you relocate it?"
   $TargetPath = Read-Host -Prompt 'Enter Path to the Encrypted File'
}
else {
	
    $TargetPath = $PSScriptRoot + "\" + "$env:computername" + "\"	
}

	
# Import FileCryptography module
Import-Module "$PSScriptRoot\Forensicator-Share\FileCryptography.psm1"

$key = Read-Host -Prompt 'Enter Decryption Key'
$Extension = ".forensicator"
  
# Gather all files from the target path and its subdirectories
    $FilestoDecrypt = get-childitem -path $TargetPath\* -Include *$Extension -Recurse -force | where { ! $_.PSIsContainer }

    # Decrypt the files
    foreach ($file in $FilestoDecrypt)
    {
        Write-Host "Decrypting $file"
        Unprotect-File $file -Algorithm AES -KeyAsPlainText $key -Suffix $Extension  -RemoveSource
    }
	exit 0
}else{
	
}

##################################################
#endregion ARTIFACT DECRYPTION SWITCH            #
##################################################

##################################################
#region             USAGE                        #
##################################################

if ($USAGE) {
	
	Write-Host ''
    Write-Host -Fore DarkCyan   'FORESNSICATOR USAGE'
    Write-Host ''
    Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1   This runs the Basic checks on a system.'
	Write-Host ''
	Write-Host -Fore DarkCyan   'FLAGS'
	Write-Host -Fore Cyan   'The below flags can be added to the Basic Usage'
	Write-Host ''
    Write-Host -Fore DarkCyan   '[*] -EVTX EVTX           Also grab Event Logs'
	Write-Host -Fore DarkCyan   '[*] -WEBLOGS WEBLOGS     Also grab Web Logs.'
    Write-Host -Fore DarkCyan   '[*] -PCAP PCAP           Run network tracing and capture PCAP for 120seconds'
	Write-Host -Fore Cyan       "[!] requires the etl2pcapng file in share folder"
    Write-Host -Fore DarkCyan   '[*] -RAM RAM             Extract RAM Dump'
	Write-Host -Fore Cyan       "[!] requires the winpmem file in share folder"
	Write-Host -Fore DarkCyan   '[*] -LOG4J LOG4J         Checks for vulnerable log4j files'
	Write-Host -Fore DarkCyan   '[*] -ENCRYPTED ENCRYPTED Encrypt Artifacts after collecting them'
	Write-Host -Fore Cyan       "[!] requires the FileCryptography file in share folder"
	Write-Host -Fore DarkCyan   '[*] -BROWSER BROWSER     Grabs a detailed browsing history from system'
	Write-Host -Fore Cyan       "[!] requires the Nirsoft BrowserView file in share folder"
	Write-Host -Fore DarkCyan   ''
	Write-Host -Fore DarkCyan   'SWITCHES'
	Write-Host -Fore DarkCyan   ''
    Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -VERSION           This checks the version of Foresicator you have'
    Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -UPDATE            This checks for and updates your copy of Forensicator'
    Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -DECRYPT DECRYPT   This decrypts a Foresicator encrypted Artifact'
	Write-Host -Fore Cyan       "[!] requires the FileCryptography file in share folder"
	Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -USAGE             Prints this help file'

	exit 0
}else{
	
}

##################################################
#endregion ARTIFACT DECRYPTION SWITCH            #
##################################################

$ErrorActionPreference= 'silentlycontinue'

$t = @"

___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          $MyVersion

"@

for ($i=0;$i -lt $t.length;$i++) {
if ($i%2) {
 $c = "red"
}
elseif ($i%5) {
 $c = "yellow"
}
elseif ($i%7) {
 $c = "green"
}
else {
   $c = "white"
}
write-host $t[$i] -NoNewline -ForegroundColor $c
}

##################################################
#region      Check if the share folder exists    #
##################################################
Write-Host ''

$Folder = 'Forensicator-Share'

if (Test-Path -Path $Folder) {
    #Write-Host -Fore Cyan "[!] You have the share folder moving on.."
} else {
    Write-Host -Fore Cyan "[!] Forensicator-Share folder not found, some flags will not work, use the -UPDATE flag to import the complete Arsenal.."
	Write-Host -Fore Cyan "[!] Moving on...."
}


##################################################
#endregion   Check if the share folder exists    #
##################################################

Write-Host ''
Write-Host ''
Write-Host ''
Write-Host -Fore DarkCyan   '[!] Live Forensicator'
Write-Host ''
Write-Host -Fore DarkCyan   '[!] Examines the host for suspicious activities and grabs required data for further forensics.'
Write-Host -Fore DarkCyan   '[!] By Ebuka John Onyejegbu.'
Write-Host -Fore DarkCyan   '[!] https://github.com/Johnng007/Live-Forensicator'
Write-Host -Fore DarkCyan   '[!] https://john.ng'
Write-Host ''
Write-Host ''
Write-Host ''

#######################################################################
#region PARAMETER SETTINGS  ###########################################
#######################################################################

#FOR OPERATOR

if ($OPERATOR) {
   
   $Handler = $OPERATOR
   
} 
else {
	
   $Handler = Read-Host -Prompt 'Enter Investigator Name'	

}

#FOR CASE REFERENCE
if ($CASE) {
   
   $CASENO = $CASE
   
} 
else {
	
   $CASENO = Read-Host -Prompt 'Enter Case Reference'

}

#EXHIBIT REFERENCE
if ($TITLE) {
   
   $Ref = $TITLE
   
} 
else {
	
   $Ref = Read-Host -Prompt 'Enter Investigation Title'

}

#LOCATION
if ($LOCATION) {
   
   $Loc = $LOCATION
   
} 
else {
	
   $Loc = Read-Host -Prompt 'Enter examination location'

}

#DESCRIPTION
if ($DEVICE) {
   
   $Des = $DEVICE
   
} 
else {
	
   $Des = Read-Host -Prompt 'Enter description of device e.g. "Asus Laptop"'

}

#######################################################################
#endregion END PARAMETER SETTINGS #####################################
#######################################################################

Write-Host ''
Write-Host ''
Write-Host ''

$DateFormat = "yyyy'-'MM'-'dd HH':'mm':'ss"

$StartTime = Get-Date -Format $DateFormat

# creating a directory to store the artifacts of this host
mkdir $env:computername -Force | Out-Null

# Moving to the new folder
Set-Location $env:computername


# Setting index output file
$FinalDes = 'index.html'

# Setting Network Information Output
$NetDes = 'network.html'

# Setting Users Information Output
$UserDes = 'users.html'

# Setting System Information Output
$SysDes = 'system.html'

# Setting Processes Output
$ProcDes = 'processes.html'

# Setting Other Checks Output
$OtherDes = 'others.html'

# Setting Evtx Checks Output
$EVTXDes = 'evtx.html'

Write-Host -Fore DarkCyan "[*] Gathering Network & Network Settings"

##################################################
#region Network Information and Settings         #
##################################################

#Gets DNS cache. Replaces ipconfig /dislaydns

$DNSCache = Get-DnsClientCache | select Entry,Name, Status, TimeToLive, Data | ConvertTo-Html -fragment

$NetworkAdapter = Get-WmiObject -class Win32_NetworkAdapter  | Select-Object -Property AdapterType,ProductName,Description,MACAddress,Availability,NetconnectionStatus,NetEnabled,PhysicalAdapter | ConvertTo-Html -Fragment

#Replaces ipconfig:

$IPConfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration |  select Description, @{Name='IpAddress';Expression={$_.IpAddress -join '; '}}, @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}}, MACAddress, @{Name='DefaultIPGateway';Expression={$_.DefaultIPGateway -join '; '}}, DNSDomain, DNSHostName, DHCPEnabled, ServiceName | convertTo-Html -fragment
$NetIPAddress = Get-NetIPaddress | select InterfaceAlias, IPaddress, EnabledState, OperatingStatus | ConvertTo-Html -fragment 
$NetConnectProfile = Get-NetConnectionProfile | select Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity | ConvertTo-Html -fragment 
$NetAdapter = Get-NetAdapter | select Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Html -fragment

#Replaces arp -a:

$NetNeighbor = Get-NetNeighbor | select InterfaceAlias, IPAddress, LinkLayerAddress | ConvertTo-Html -fragment

#Replaces netstat commands

$NetTCPConnect = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}| ConvertTo-Html -Fragment


#Get Wi-fi Names and Passwords

$WlanPasswords = netsh.exe wlan show profiles | Select-String "\:(.+)$" | %{$wlanname=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$wlanname" key=clear)}  | Select-String 'Key Content\W+\:(.+)$' | %{$wlanpass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$wlanname;PASSWORD=$wlanpass }} | ConvertTo-Html -fragment

#Get Firewall Information. Replaces netsh firewall show config

$FirewallRule = Get-NetFirewallRule | select-object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus | ConvertTo-Html -fragment 

#Display active samba sessions

$SMBSessions = Get-SMBSession -ea silentlycontinue | convertTo-Html -fragment


#Display active samba shares

$SMBShares = Get-SMBShare | select description, path, volume | convertTo-Html -fragment

#Get IP routes to non-local destinations

$NetHops = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | convertTo-Html -fragment

#Get network adapters that have IP routes to non-local destinations

$AdaptHops = Get-NetRoute | Where-Object -FilterScript {$_.NextHop -Ne "::"} | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | Get-NetAdapter | convertTo-Html -fragment

#Get IP routes that have an infinite valid lifetime

$IpHops = Get-NetRoute | Where-Object -FilterScript { $_.ValidLifetime -Eq ([TimeSpan]::MaxValue) } | convertTo-Html -fragment

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region User & Account Information               #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering User & Account Information"


$currentuser = Get-WMIObject -class Win32_ComputerSystem | select username | ConvertTo-Html -Fragment
$systemname = Get-WmiObject -Class Win32_ComputerSystem | select Name, DNSHostName, Domain, Manufacturer, Model, PrimaryOwnerName, TotalPhysicalMemory, Workgroup   | ConvertTo-Html -Fragment 
#$useraccounts = Get-WmiObject -Class Win32_UserAccount  | Select-Object -Property AccountType,Domain,LocalAccount,Name,PasswordRequired,SID,SIDType | ConvertTo-Html -fragment
$logonsession = Get-WmiObject -Class Win32_LogonSession | Select-Object -Property LogonID,LogonType,StartTime,  @{Name='Start Time';Expression={$_.ConvertToDateTime($_.starttime)}}  | ConvertTo-Html -fragment
#######ADDITIONS
$logonsession = query user | ConvertTo-Html -Fragment
$userprocesses = Get-Process -includeusername | ConvertTo-Html -fragment
$userprofiles = Get-WmiObject -Class Win32_UserProfile | Select-object -property Caption, LocalPath, SID, @{Name='Last Used';Expression={$_.ConvertToDateTime($_.lastusetime)}} | ConvertTo-Html -Fragment 

$administrators = Get-LocalGroupMember -Group "Administrators" | ConvertTo-Html -Fragment

$LocalGroup = Get-LocalGroup | ConvertTo-Html -Fragment

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Installed Programs                       #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering Installed Programs"

$InstProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | ConvertTo-Html -Fragment

$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -Fragment

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region System Info                              #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering System Information"

#Environment Settings
$env = Get-ChildItem ENV: | select name, value | convertto-html -fragment 

#System Info
$systeminfo = Get-WmiObject -Class Win32_ComputerSystem  | Select-Object -Property Name,Caption,SystemType,Manufacturer,Model,DNSHostName,Domain,PartOfDomain,WorkGroup,CurrentTimeZone,PCSystemType,HyperVisorPresent | ConvertTo-Html -Fragment 

#OS Info
$OSinfo = Get-WmiObject -Class Win32_OperatingSystem   | Select-Object -Property Name, Description,Version,BuildNumber,InstallDate,SystemDrive,SystemDevice,WindowsDirectory,LastBootupTime,Locale,LocalDateTime,NumberofUsers,RegisteredUser,Organization,OSProductSuite | ConvertTo-Html -Fragment

#Hotfixes
$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption,Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -fragment 


#Get Windows Defender Status
$WinDefender = Get-MpComputerStatus | convertto-html -fragment

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Live Running Processes & Scheduled Tasks #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering Processes and Tasks"


$Processes = Get-Process | Select Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion | ConvertTo-Html -Fragment 

#Items set to run on startup

$StartupProgs = Get-WmiObject Win32_StartupCommand | select Command, User, Caption | ConvertTo-Html -fragment 

# Scheduled Tasks
$ScheduledTask = Get-ScheduledTask | ? State -eq running | ConvertTo-Html -Fragment

# Get Running Tasks and Their state
$ScheduledTask2 = Get-ScheduledTask | ? State -eq running | Get-ScheduledTaskInfo | ConvertTo-Html -Fragment 

#Services
$Services = Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Html -Fragment 

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Settings from the Registry			     #
##################################################

Write-Host -Fore DarkCyan "[*] Checking Registry for persistance"

$RegRun = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Html -Fragment 

$RegRunOnce = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ConvertTo-Html -Fragment 

$RegRunOnceEx = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx | ConvertTo-Html -Fragment 

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Checking other worthwhiles			     #
##################################################

Write-Host -Fore DarkCyan "[*] Running Peripheral Checks..."

#Logical drives (current session)
$LogicalDrives = get-wmiobject win32_logicaldisk | select DeviceID, DriveType, FreeSpace, Size, VolumeName | ConvertTo-Html -fragment


#Gets list of USB devices

$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | select FriendlyName, Driver, mfg, DeviceDesc | ConvertTo-Html -fragment  

#Identifies any connected/previously connected webcams
#$Imagedevice = Get-PnpDevice  -class 'image' -EA SilentlyContinue |  ConvertTo-Html -Fragment
$Imagedevice = Get-WmiObject Win32_PnPEntity | where {$_.caption -match 'camera'} -EA SilentlyContinue | where caption -match 'camera' | ConvertTo-Html -Fragment

#All currently connected PNP devices
$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | ConvertTo-Html -Fragment

#All previously connected disk drives not currently accounted for. Useful if target computer has had drive replaced/hidden
$UnknownDrives = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName | ConvertTo-Html -Fragment

#Gets all link files created in last 180 days. Perhaps export this as a separate CSV and make it keyword searchable?

$LinkFiles = Get-WmiObject Win32_ShortcutFile | select Filename, Caption, @{NAME='CreationDate';Expression={$_.ConvertToDateTime($_.CreationDate)}}, @{Name='LastAccessed';Expression={$_.ConvertToDateTime($_.LastAccessed)}}, @{Name='LastModified';Expression={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.LastModified -gt ((Get-Date).AddDays(-180)) } | sort LastModified -Descending | ConvertTo-Html -Fragment 

#Gets last 100 days worth of Powershell History

$PSHistory = Get-History -count 500 | select id, commandline, startexecutiontime, endexecutiontime | ConvertTo-Html -fragment


#All items in Downloads folder. This may cause an error if the script is run from an external USB or Network drive, even when
$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment

#Executables Running From Obscure Places
$HiddenExecs1 = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$HiddenExecs2 = Get-ChildItem C:\Temp\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$HiddenExecs3 = Get-ChildItem C:\PerfLogs\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment
$HiddenExecs4 = Get-ChildItem C:\Users\*\Documents\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | where {$_.extension -eq '.exe'} | ConvertTo-Html -Fragment

 

#endregion

##################################################
#region     EVENT LOG ANALYSIS		     	     #
##################################################

Write-Host -Fore DarkYellow "[*] Entering Event Log Analysis Mode"

Write-Host -Fore DarkPink "[!] User Related Activity Probes"


##### USER RELATED CHECKS ##########

###############################################################################
### Enumerated a User's Group Membership        ###############################
###############################################################################

Write-Host -Fore DarkCyan "[*] Checking Enumerated Users"

$GroupMembershipID = @(
'4798'

)
$GroupMembershipFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$GroupMembershipID }
$GroupMembership = Get-WinEvent -FilterHashtable $GroupMembershipFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $GroupMembershipEventXml = ([xml]$_.ToXml()).Event
    $GroupMembershipEnumAccount = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $GroupMembershipPerformedBy = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
	$GroupMembershipPerformedLogon = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
	$GroupMembershipPerformedPID = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessId' }).'#text'
	$GroupMembershipPerformedPName = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$GroupMembershipEventXml.System.TimeCreated.SystemTime
        PerformedOn = $GroupMembershipEnumAccount
        PerformedBy = $GroupMembershipPerformedBy
		LogonType = $GroupMembershipPerformedLogon
		PID = $GroupMembershipPerformedPID
		ProcessName = $GroupMembershipPerformedPName
    }
} | ConvertTo-Html -fragment
 
Write-Host -Fore Cyan "[!] Done"

###############################################################################
### RDP Logins                        #########################################
###############################################################################

Write-Host -Fore DarkCyan "[*] Fetching RDP Logons"

$RDPGroupID = @(
'4624'
)

$RDPFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$RDPGroupID } 
$RDPLogins = Get-WinEvent -FilterHashtable $RDPFilter | where {$_.properties[8].value -eq 10} | ForEach-Object {
    # convert the event to XML and grab the Event node
    $RDPEventXml = ([xml]$_.ToXml()).Event
    $RDPLogonUser = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
	$RDPLogonUserDomain = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $RDPLogonIP = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$RDPEventXml.System.TimeCreated.SystemTime
        LogonUser = $RDPLogonUser
		LogonUserDomain = $RDPLogonUserDomain
        LogonIP = $RDPLogonIP
    }
} | ConvertTo-Html -fragment


Write-Host -Fore Cyan "[!] Done"


###############################################################################
### Created Users                 #############################################
###############################################################################


Write-Host -Fore DarkCyan "[*] Fetching Created Users"

$CreatedUsersGroupID = @(
'4720'
)

$CreatedUsersFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$CreatedUsersGroupID }
$CreatedUsers = Get-WinEvent -FilterHashtable $CreatedUsersFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $CreatedUsersEventXml = ([xml]$_.ToXml()).Event
    $CreatedUser = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $CreatedUsersTarget = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$CreatedUsersEventXml.System.TimeCreated.SystemTime
        CreatedUser = $CreatedUser
        CreatedBy = $CreatedUsersTarget
    }
} | ConvertTo-Html -fragment


Write-Host -Fore Cyan "[!] Done"


###############################################################################
### Password Resets               #############################################
###############################################################################


Write-Host -Fore DarkCyan "[*] Checking for password resets"

$PassResetGroupID = @(
'4724'
)

$PassResetFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$PassResetGroupID }
$PassReset = Get-WinEvent -FilterHashtable $filter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $PassResetEventXml = ([xml]$_.ToXml()).Event
    $PassResetTargetUser = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $PassResetActionedBy = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$PassResetEventXml.System.TimeCreated.SystemTime
        TargetUser = $PassResetTargetUser
        ActionedBy = $PassResetActionedBy
    }
} | ConvertTo-Html -fragment


Write-Host -Fore Cyan "[!] Done"


###############################################################################
### Added users to Group          #############################################
###############################################################################

$AddedUsersGroupID = @(
'4732',
'4728'
)
$AddedUsersFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$AddedUsersGroupID }
$AddedUsers = Get-WinEvent -FilterHashtable $AddedUsersFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $AddedUsersEventXml = ([xml]$_.ToXml()).Event
    $AddedUsersAddedBy = ($AddedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $AddedUsersTarget = ($AddedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'MemberSid' }).'#text'
	#SID CONVERSION
    $AddedUsersGobjSID = New-Object System.Security.Principal.SecurityIdentifier($AddedUsersTarget)
    $AddedUsersGobjUser = $AddedUsersGobjSID.Translate([System.Security.Principal.NTAccount])
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$AddedUsersEventXml.System.TimeCreated.SystemTime
        AddedBy = $AddedUsersAddedBy
        Target = $AddedUsersGobjUser
    }
} | ConvertTo-Html -fragment




###############################################################################
### Enabled Users                 #############################################
###############################################################################

$EnabledUsersGroupID = @(
'4722'

)
$EnabledUsersFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$EnabledUsersGroupID }
$EnabledUsers = Get-WinEvent -FilterHashtable $EnabledUsersFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $EnabledUsersEventXml = ([xml]$_.ToXml()).Event
    $EnabledBy = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $EnabledTarget = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$EnabledUsersEventXml.System.TimeCreated.SystemTime
        EnabledBy = $EnabledBy
        EnabledAccount = $EnabledTarget
    }
} | ConvertTo-Html -fragment




###############################################################################
### Disabled Users                #############################################
###############################################################################

$DisabledUsersGroupID = @(
'4723'

)
$DisabledUsersFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$DisabledUsersGroupID }
$DisabledUsers = Get-WinEvent -FilterHashtable $DisabledUsersFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $DisabledUsersEventXml = ([xml]$_.ToXml()).Event
    $DisabledBy = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $DisabledTarget = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$DisabledUsersEventXml.System.TimeCreated.SystemTime
        DisabledBy = $DisabledBy
        Disabled = $DisabledTarget
    }
} | ConvertTo-Html -fragment



###############################################################################
### Deleted Users                #############################################
###############################################################################

$DeletedUsersGroupID = @(
'4726'

)
$DeletedUsersFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$DeletedUsersGroupID }
$DeletedUsers = Get-WinEvent -FilterHashtable $DeletedUsersFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $DeletedUsersEventXml = ([xml]$_.ToXml()).Event
    $DeletedBy = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $DeletedTarget = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$DeletedUsersEventXml.System.TimeCreated.SystemTime
        DeletedBy = $DeletedBy
        DeletedAccount = $DeletedTarget
    }
} | ConvertTo-Html -fragment




###############################################################################
### Account Lockout               #############################################
###############################################################################

$LockOutGroupID = @(
'4740'

)
$LockOutFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$LockOutGroupID }
$LockOut = Get-WinEvent -FilterHashtable $LockOutFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $LockOutEventXml = ([xml]$_.ToXml()).Event
    $LockedOutAcct = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $System = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$LockOutEventXml.System.TimeCreated.SystemTime
        LockedOutAccount = $LockedOutAcct
        System = $System
    }
} | ConvertTo-Html -fragment



###############################################################################
### Credential Manager Backup                   ###############################
###############################################################################

$CredManBackupGroupID = @(
'5376'

)
$CredManBackupFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$CredManBackupGroupID }
$CredManBackup = Get-WinEvent -FilterHashtable $CredManBackupFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $CredManBackupEventXml = ([xml]$_.ToXml()).Event
    $CredManBackupAcct = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $CredManBackupAcctLogon = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$CredManBackupEventXml.System.TimeCreated.SystemTime
        BackupAccount = $CredManBackupAcct
        AccountLogonType = $CredManBackupAcctLogon

    }
} | ConvertTo-Html -fragment




###############################################################################
### Credential Manager Restore                  ###############################
###############################################################################

$CredManRestoreGroupID = @(
'5377'

)
$CredManRestoreFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=$CredManRestoreGroupID }
$CredManRestore = Get-WinEvent -FilterHashtable $CredManRestoreFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $CredManRestoreEventXml = ([xml]$_.ToXml()).Event
    $RestoredAcct = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $CredManRestoreAcctLogon = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$CredManRestoreEventXml.System.TimeCreated.SystemTime
        RestoredAccount = $RestoredAcct
        AccountLogonType = $CredManRestoreAcctLogon

    }
} | ConvertTo-Html -fragment




#endregion


















#End time date stamp

$EndTime = Get-Date -Format $DateFormat








###########################################################################################################
#region ########################## CREATING AND FORMATTING THE HTML FILES  ################################
###########################################################################################################

Write-Host -Fore DarkCyan "[*] Creating and Formatting our Index file"


# Setting Head for the index file
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername" >$FinalDes

# Setting up index style
$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $FinalDes


# Making the Menus for Index File

$IndexNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;


}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>'"

$BlackWidow ='
<div class="logo-container" align="center">
  <ul>


    <li>
      <div class="logo-holder logo-3">
        <a href="">
          <h3>Live Forensicator</h3>
          <p>A Black Widow Tool</p>
        </a>
      </div>
    </li>
    
  </ul>
</div>'

$BlackWidowStyle = '
<style>
@import url("https://fonts.googleapis.com/css?family=Bangers|Cinzel:400,700,900|Lato:100,300,400,700,900|Lobster|Lora:400,700|Mansalva|Muli:200,300,400,600,700,800,900|Open+Sans:300,400,600,700,800|Oswald:200,300,400,500,600,700|Roboto:100,300,400,500,700,900&display=swap");
/* Used Google Fonts */
font-family: "Roboto", sans-serif;
font-family: "Mansalva", cursive;
font-family: "Lato", sans-serif;
font-family: "Open Sans", sans-serif;
font-family: "Oswald", sans-serif;
font-family: "Lora", serif;
font-family: "Muli", sans-serif;
font-family: "Lobster", cursive;
font-family: "Cinzel", serif;
font-family: "Bangers", cursive;
/* Used Google Fonts */
*{
  margin:0;
  padding:0;
}
body{
  font-size:17px;
  color:#424242;
  font-family: "Open Sans", sans-serif;
  background-color: #ffffff;
  background-image: url("data:image/png;base64,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");
}
h1, h2, h3, h4, h5, h6, p{
  margin:0px;
  padding:0px;
}
.logo-container ul {
    margin: 0;
    padding: 0;
    list-style: none;
    display:inline-block;
}
.logo-container ul li {
    width: 300px;
    height: 120px;
    background: #fff;
    border-radius: 10px;
    margin: 10px;
    float: left;
    padding:20px;
    box-shadow: 0px 5px 10px rgba(0, 0, 0, 0.25);    
    display: flex;
    align-items: center;
    justify-content: center;
}
.logo-container ul li a{
  text-decoration:none !important;
  display: inline-block;
}
.logo-holder{
  text-align:center;
}

/* Logo-3 */
.logo-3 h3 {
    color: #e74c3c;
    font-family: "Oswald", sans-serif;
    font-weight: 300;
    font-size: 50px;
    line-height:1.3;
}
.logo-3 p {
    font-size: 14px;
    letter-spacing: 7px;
    text-transform: uppercase;
    background: #34495e;
    font-weight: 400;
    color: #fff;
    padding-left: 5px;
}


</style>'

$BlackWidowStyle >> $FinalDes
$BlackWidow >> $FinalDes
$IndexNav >> $FinalDes

'<br><br>' >> $FinalDes

# Setting Body content for index file.
echo "<h2><u><center>Live Forensics Result for $env:computername</center></u></h2>"                                | Out-File -Append $FinalDes

'<br><br>' >> $FinalDes

#Case information

echo "<h2><center> Case reference: $CASENO </center></h2><br>"                                                        | Out-File -Append $FinalDes

echo "<h2><center> Examiner Name: $Handler </center></h2><br>"                                                     | Out-File -Append $FinalDes

echo "<h2><center>Exhibit reference: $Ref </center></h2>"                                                       | Out-File -Append $FinalDes

echo "<h2><center>Device: $Des </center></h2><br>"                                                          | Out-File -Append $FinalDes

echo "<h2><center>Examination Location: $Loc </center></h2><br>"                                               | Out-File -Append $FinalDes

echo "<h3><center> Start Time and Date: $StartTime </center></h3><br>"                                            | Out-File -Append $FinalDes
echo "<h3><center> End Time and Date: $EndTime </h3><br>"                                                      | Out-File -Append $FinalDes

'<br><br>' >> $FinalDes
'<br><br>' >> $FinalDes

#endregion

###########################################################################################################
#region #######  VIEW USER GP RESULTS    ##################################################################
###########################################################################################################
# get GPO REsult if on domain

if ((gwmi win32_computersystem).partofdomain -eq $true) {
    
	Write-Host -Fore DarkCyan "[*] Collecting GPO Results"
    $GP = GPRESULT /H GPOReport.html /F
    echo "<center><h3>Group Policy Report</h3><table><a href='GPOReport.html' target='_blank'>View the GPO report </a></table></center><br>"  | Out-File -Append $FinalDes
    Write-Host -Fore Cyan "[!] Done"
} else {
    Write-Host -Fore Cyan "[!] Computer is not on the domain...moving on"
}



#endregion


###########################################################################################################
#region  MEMORY (RAM) CAPTURE    ##########################################################################
###########################################################################################################


if ($RAM) {
   # capture the RAM
   mkdir RAM | Out-Null
   Write-Host -Fore DarkCyan "[*] Capturing The RAM"
	
if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit"){
    
& $PSScriptRoot\Forensicator-Share\winpmem_mini_x64_rc2.exe RAM\$env:computername.raw | Out-Null

   Write-Host -Fore Cyan "[!] Done"
  
   echo "<center><h3>WINPMEM RAM CAPTURE:</h3><table></table><a href='RAM'>View RAM Capture</a></center><br>"     | Out-File -Append $FinalDes
	
}
else{
    
& $PSScriptRoot\Forensicator-Share\winpmem_mini_x86.exe RAM\$env:computername.raw | Out-Null

   Write-Host -Fore Cyan "[!] Done"
  
   echo "<center><h3>WINPMEM RAM CAPTURE:</h3><table></table><a href='RAM'>View RAM Capture</a></center><br>"     | Out-File -Append $FinalDes
}
   
   
} 
else {

}

#endregion



if ($BROWSER) {

###########################################################################################################
#region  BROWSER NIRSOFT                ###################################################################
###########################################################################################################

   Write-Host -Fore DarkCyan "[*] Extracting Browser History"

   #GETTING BROWSING History
if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit"){
    
& $PSScriptRoot\Forensicator-Share\BrowsingHistoryView64.exe /sverhtml "BrowserHistory.html" /SaveDirect /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1
   echo "<center><h3>BROWSING HISTORY:</h3><table></table><a href='BrowserHistory.html'>View Browsing History</a></center><br>"     | Out-File -Append $FinalDes

	
}
else{
    
& $PSScriptRoot\Forensicator-Share\BrowsingHistoryView86.exe /sverhtml "BrowserHistory.html" /SaveDirect /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1

   echo "<center><h3>BROWSING HISTORY:</h3><table></table><a href='BrowserHistory.html'>View Browsing History</a></center><br>"     | Out-File -Append $FinalDes
}

#Lets wait a while for this to finish
Start-Sleep -s 15

Write-Host -Fore Cyan "[!] Done"

###########################################################################################################
#endregion    BROWSER NIRSOFT           ###################################################################
###########################################################################################################

} 
else {

###########################################################################################################
#region  BROWSER  INBUILT        ##########################################################################
###########################################################################################################

    Write-Host -Fore DarkCyan "[*] Extracting Browser History (Inbuilt)"
		
	
	#CHROME

mkdir BROWSING_HISTORY | Out-Null

$users = Get-ChildItem $Env:SystemDrive\Users|where{$_.name -notmatch 'Public|default'}
foreach ($user in $users){

    $Path = "$($user.fullname)\AppData\Local\Google\Chrome\User Data\Default\History"
    if (-not (Test-Path -Path $Path)) {
        Write-Verbose "[!] Could not find Chrome History for username: $user"
    }
    $Regex = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $Value = Get-Content -Path $path | Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
    $Value | ForEach-Object {
        $Key = $_
        if ($Key -match $Search){
		
           New-Object -TypeName PSObject -Property @{
                User = $user
                Browser = 'Chrome'
                DataType = 'History'
                Data = $_
            }
			
        } 
    } | Out-File BROWSING_HISTORY\Chrome_History_of_$user.txt
	
}

#MOZILLA

$users = Get-ChildItem $Env:SystemDrive\Users|where{$_.name -notmatch 'Public|default'}
foreach ($user in $users){

    $Path = "$($user.fullname)\AppData\Roaming\Mozilla\Firefox\Profiles\"
    if (-not (Test-Path -Path $Path)) {
        Write-Verbose "[!] Could not find Chrome History for username: $user"
    }
	$Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
    $Regex = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $Value = Get-Content $Profiles\places.sqlite | Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
    $Value | ForEach-Object {
        $Key = $_
        if ($Key -match $Search){
		
           New-Object -TypeName PSObject -Property @{
                User = $user
                Browser = 'Firefox'
                DataType = 'History'
                Data = $_
            }
			
        } 
    } | Out-File BROWSING_HISTORY\Firefox_History_of_$user.txt
	
}

#IE



$Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

        ForEach($Path in $Paths) {

            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

            $Path = $Path | Select-Object -ExpandProperty PSPath

            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[!] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User = $_.Name
                                Browser = 'IE'
                                DataType = 'History'
                                Data = $Value
                            }
                        }
                    }
                } | Out-File BROWSING_HISTORY\IE_History.txt
            }
        }


echo "<center><h3>BROWSING HISTORY:</h3><table></table><a href='BROWSING_HISTORY'>View Browsing History</a></center><br>"     | Out-File -Append $FinalDes

Write-Host -Fore Cyan "[!] Done"
###########################################################################################################
#endregion   BROWSER INBUILT                ###############################################################
###########################################################################################################	

}




###########################################################################################################
#region  CHECKING FOR RANSOMWARE ENCRYPTED FILES    #######################################################
###########################################################################################################

if ($RANSOMWARE) {
	
   Write-Host -Fore DarkCyan "[*] Checking For Ransomware Encrypted Files"
   Write-Host -Fore DarkCyan "[!] NOTE: This May Take a While Depending on the Number of Drives"

#CHECKING FOR RANSOMWARE ENCRYPTED FILES

   $Drives = Get-PSDrive -PSProvider 'FileSystem'

foreach($Drive in $drives) {

   $FindFiles = Get-ChildItem -Path $Drive.Root -Include *._AiraCropEncrypted,*.1cbu1,*.1txt,*.73i87A,*.a5zfn,*.aaa,*.abc,*.adk,*.aesir,*.alcatraz,*.angelamerkel,*.AngleWare,*.antihacker2017,*.atlas,*.axx,*.BarRax,*.bitstak,*.braincrypt,*.breaking_bad,*.bript,*.btc,*.ccc,*.CCCRRRPPP,*.cerber,*.cerber2,*.cerber3,*.coded,*.comrade,*.conficker,*.coverton,*.crab,*.crinf,*.crjoker,*.crptrgr,*.cry,*.cryeye,*.cryp1,*.crypt,*.crypte,*.crypted,*.cryptolocker,*.cryptowall,*.crypz,*.czvxce,*.d4nk,*.dale,*.damage,*.darkness,*.dCrypt,*.decrypt2017,*.Dexter,*.dharma,*.dxxd,*.ecc,*.edgel,*.enc,*.enc,*.enciphered,*.EnCiPhErEd,*.encr,*.encrypt,*.encrypted,*.encrypted,*.encrypted,*.enigma,*.evillock,*.exotic,*.exx,*.ezz,*.fantom,*.file0locked,*.fucked,*.fun,*.fun,*.gefickt,*.globe,*.good,*.grt,*.ha3,*.helpmeencedfiles,*.herbst,*.hnumkhotep,*.hush,*.ifuckedyou,*.info,*.kernel_complete,*.kernel_pid,*.kernel_time,*.keybtc@inbox_com,*.kimcilware,*.kkk,*.kostya,*.kraken,*.kratos,*.kyra,*.lcked,*.LeChiffre,*.legion,*.lesli,*.lock93,*.locked,*.locklock,*.locky,*.lol!,*.loli,*.lovewindows,*.madebyadam,*.magic,*.maya,*.MERRY,*.micro,*.mole,*.MRCR1,*.noproblemwedecfiles​,*.nuclear55,*.odcodc,*.odin,*.onion,*.oops,*.osiris,*.p5tkjw,*.padcrypt,*.paym,*.paymrss,*.payms,*.paymst,*.paymts,*.payrms,*.pays,*.pdcr,*.pec,*.PEGS1,*.perl,*.PoAr2w,*.potato,*.powerfulldecrypt,*.pubg,*.purge,*.pzdc,*.R16m01d05,*.r5a,*.raid10,*.RARE1,*.razy,*.rdm,*.realfs0ciety@sigaint.org.fs0ciety,*.rekt,*.rekt,*.rip,*.RMCM1,*.rmd,*.rnsmwr,*.rokku,*.rrk,*.ruby,*.sage,*.SecureCrypted,*.serp,*.serpent,*.sexy,*.shit,*.spora,*.stn,*.surprise,*.szf,*.theworldisyours,*.thor,*.ttt,*.unavailable,*.vbransom,*.venusf,*.VforVendetta,*.vindows,*.vvv,*.vxlock,*.wallet,*.wcry,*.wflx,*.Whereisyourfiles,*.windows10,*.xxx,*.xxx,*.xyz,*.ytbl,*.zcrypt,*.zepto,*.zorro,*.zyklon,*.zzz,*.zzzzz -File -Force -Recurse | select PSChildName, FullName, LastWriteTimeUTC, Extension | ConvertTo-Html -Fragment 

}

   Write-Host -Fore Cyan "[!] Done"

} 
else {

}

#endregion

###########################################################################################################
#region  NETWORK TRACE ####################################################################################
###########################################################################################################

if ($PCAP) {
	

   mkdir PCAP | Out-Null

   Write-Host -Fore DarkCyan "[*] Starting Network Trace"
   Write-Host -Fore DarkCyan "[*] Running....."
   
   netsh trace start capture=yes Ethernet.Type=IPv4 tracefile=PCAP\$env:computername.et1 | Out-Null
   Start-Sleep -s 120
   $job = Start-Job { netsh trace stop } | Out-Null
   Wait-Job $job
   Receive-Job $job

   Write-Host -Fore Cyan "[!] Trace Completed"

   Write-Host -Fore DarkCyan "[*] Converting to PCAP"
   #Start-Sleep -s 250
   


if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit"){
    

& $PSScriptRoot\Forensicator-Share\etl2pcapng64.exe PCAP\$env:computername.et1 PCAP\$env:computername.pcap
   echo "<center><h3>NETWORK TRACE:</h3><table></table><a href='PCAP'>View PCAP FILES</a></center><br>"     | Out-File -Append $FinalDes 
	
}
else{
    
& $PSScriptRoot\Forensicator-Share\etl2pcapng86.exe PCAP\$env:computername.et1 PCAP\$env:computername.pcap

   echo "<center><h3>NETWORK TRACE:</h3><table></table><a href='PCAP'>View PCAP FILES</a></center><br>"      | Out-File -Append $FinalDes   
}

   Write-Host -Fore Cyan "[!] Done"


   
} 
else {
		

}

#endregion

###########################################################################################################
#region NETWORK TRACE #####################################################################################
###########################################################################################################


###########################################################################################################
#region  Export Event Logs       ##########################################################################
###########################################################################################################



if ($EVTX) {
	
   Write-Host -Fore DarkCyan "[*] Gettting hold of some event logs"
   
   # capture the EVENTLOGS
   # Logs to extract from server
   $logArray = @("System","Security","Application")

   # Grabs the server name to append to the log file extraction
   $servername = $env:computername

   # Provide the path with ending "\" to store the log file extraction.
   $destinationpath = "EVTLOGS\"

   # If the destination path does not exist it will create it
if (!(Test-Path -Path $destinationpath)){
	
    New-Item -ItemType directory -Path $destinationpath | Out-Null
}

    # Get the current date in YearMonthDay format
    $logdate = Get-Date -format yyyyMMddHHmm

    # Start Process Timer
    $StopWatch = [system.diagnostics.stopwatch]::startNew()


Foreach($log in $logArray){
	
    # If using Clear and backup
    $destination = $destinationpath + $servername + "-" + $log + "-" + $logdate + ".evtx"

    Write-Host -Fore DarkCyan "[!] Finalizing"

    # Extract each log file listed in $logArray from the local server.
    wevtutil epl $log $destination
}

    Write-Host -Fore Cyan "[!] Done"
    # End Code

    # Stop Timer
    $StopWatch.Stop()
    $TotalTime = $StopWatch.Elapsed.TotalSeconds
    $TotalTime = [math]::Round($totalTime, 2)

    Write-Host -Fore DarkCyan "[!] Extracting the logs took $TotalTime to Complete."


    echo "<center><h3>EVENT LOGS:</h3><table></table><a href='EVTLOGS'>View Event Logs</a></center><br>"      | Out-File -Append $FinalDes
   
} 
else {

}

#endregion


############################################################
#region GETTING HOLD OF IIS & APACHE WEBLOGS ###############
############################################################

if ($WEBLOGS) {

   #Lets get hold of some weblogs
   Write-Host -Fore DarkCyan "[*] Lets Get hold of some weblogs"
   Write-Host -Fore DarkCyan "[!] NOTE: This can take a while if you have large Apache/IIS Log Files"

   #checking if logs exists in the IIS Log directory
if (!(gci C:\inetpub\logs\ *.log)){
   Write-Host -Fore DarkCyan "[!] Cannot find any logs in IIS Log Directory"
}
else{
	
   #create IIS log Dirs
   mkdir IISLogs | Out-Null

   $IISLogs = Copy-Item -Path 'C:\inetpub\logs\*' -Destination 'IISLogs' -Recurse | Out-Null

   echo "<center><h3>IIS Logs</h3><table></table><a href='IISLogs' >View IIS Logs</a></center><br>"           | Out-File -Append $FinalDes
	
}


   #checking for Tomcat and try to get log files

   $FoundRegKey = $null
   $ApacheRegKeyExists = (Test-Path 'HKLM:\Software\Apache Software Foundation')

If ($ApacheRegKeyExists)
{
   Get-ChildItem 'HKLM:\Software\Apache Software Foundation' -Recurse -ErrorAction SilentlyContinue | 
   ForEach-Object
    {
        If ($_.Property -match 'InstallPath') 
        {$FoundRegKey = Get-ItemProperty $_.pspath | Select InstallPath}
    }
}
else
{
    Write-Host -Fore DarkCyan "[!] Cannot find Tomcat software keys in registry"
    
}
 
If ($FoundRegKey)
    {
	mkdir TomCatLogs | Out-Null
    $logfolder=($FoundRegKey.InstallPath+'\logs')
	$TomcatLogs = Copy-Item -Path '$logfolder\*' -Destination '$GetLoc\TomCatLogs' -Recurse | Out-Null
	echo "<center><h3>TomCat Logs</h3><table></table><a href='TomCatLogs'>View TomCat Logs</a></center><br>"   | Out-File -Append $FinalDes
	
    }
else
    {
    Write-Host -Fore DarkCyan "[!] Cannot find Tomcat install path in registry"
    
    }
} 
else {

}


#'<br><br>' >> $FinalDes

#endregion


#############################################################################################################
#region   View Log4j Paths        ###########################################################################
#############################################################################################################

if ($LOG4J) {
   
   Write-Host -Fore DarkCyan "[*] Checking for log4j on all drives .....this may take a while."

   mkdir LOG4J | Out-Null	
   # Checking for Log4j
   $DriveList = (Get-PSDrive -PSProvider FileSystem).Root
      ForEach($Drive In $DriveList) {
	  $Log4j = gci $Drive -rec -force -include *.jar -ea 0 | foreach {select-string 'JndiLookup.class' $_} | select -exp Path | Out-File LOG4J\$env:computername.txt
      echo "<center><h3>Discovered Log4j</h3><table></table><a href='LOG4J' >View File</a></center><br>"                                                               | Out-File -Append $FinalDes

      }
   
   Write-Host -Fore Cyan "[!] Done"
   
   
} 
else {

}

#'<br><br>' >> $FinalDes

#endregion


#############################################################################################################
#region   FOOTER                  ###########################################################################
#############################################################################################################


'<br><br>' >> $FinalDes

'<center>' >> $FinalDes
echo "<h3> Evidence gathered from  $env:computername  by  $operator at: $EndTime with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator </a> </h3>" | Out-File -Append $FinalDes
'</center>' >> $FinalDes

Write-Host -Fore DarkCyan "[!] Hang on, the Forensicator is compiling your results"

#endregion


#############################################################################################################
#region   NETWORKS SECTION     ##############################################################################
#############################################################################################################

# Making the head for network.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername"  >$NetDes

# Header style for Network Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $NetDes


# Making the menus for network.html

$NetNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$NetNav >> $NetDes

'<br><br>' >> $NetDes





echo "<h2><u>Network Information</u></h2>"'' >> $NetDes


'<details>' >> $NetDes
echo "<summary>Network Adapter Information</summary>"                                                                | Out-File -Append $NetDes
if ($NetworkAdapter) {echo "<table>$NetworkAdapter</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Current IP Configuration</summary>"                                                                | Out-File -Append $NetDes
if ($IPConfiguration) {echo "<table>$IPConfiguration</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Network Adapter IP Addresses - IPv4 and v6</summary>"                                                                | Out-File -Append $NetDes
if ($NetIPaddress) {echo "<table>$NetIPaddress</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Current Connection Profiles</summary>"                                                                | Out-File -Append $NetDes
if ($NetConnectProfile) {echo "<table>$NetConnectProfile</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Associated WiFi Networks and Passwords</summary>"                                                                | Out-File -Append $NetDes
if ($WlanPasswords) {echo "<table>$WlanPasswords</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Address Resolution Protocol Cache</summary>"                                                                | Out-File -Append $NetDes
if ($NetNeighbor) {echo "<table>$NetNeighbor</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Current TCP Connections and Associated Processes</summary>"                                                                | Out-File -Append $NetDes
if ($NetTCPConnect) {echo "<table>$NetTCPConnect</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>DNS Cache</summary>"                                                                | Out-File -Append $NetDes
if ($DNSCache) {echo "<table>$DNSCache</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Current Firewall Rules</summary>"                                                                | Out-File -Append $NetDes
if ($FirewallProfile) {echo "<table>$FirewallProfile</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Active SMB sessions (if this device is a server)</summary>"                                                                | Out-File -Append $NetDes
if ($SMBSessions) {echo "<table>$SMBSessions</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Active SMB Shares on this device</summary>"                                                                | Out-File -Append $NetDes
if ($SMBSessions) {echo "<table>$SMBShares</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>IP Routes to non local Destinations</summary>"                                                                | Out-File -Append $NetDes
if ($NetHops) {echo "<table>$NetHops</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>Network Adapters with IP Routes to non Local Destination</summary>"                                                                | Out-File -Append $NetDes
if ($IpHops) {echo "<table>$IpHops</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<details>' >> $NetDes
echo "<summary>IP Routes with infinite valid lifetime</summary>"                                                                | Out-File -Append $NetDes
if ($IpHops) {echo "<table>$IpHops</table><br> "                                                              | Out-File -Append $NetDes}
'</details>' >> $NetDes
'<br><br>' >> $NetDes




'<br><br>'>> $NetDes

'<center>' >> $NetDes
echo "<h3> Evidence gathered from  $env:computername  by  $operator at: $EndTime with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator </a> </h3>" | Out-File -Append $NetDes
'</center>' >> $NetDes

#endregion


#############################################################################################################
#region   USER & ACCOUNTS SECTION     #######################################################################
#############################################################################################################

# Making the head for users.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername"  >$UserDes

# Header style for Network Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $UserDes


# Making the menus for network.html

$UserNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$UserNav >> $UserDes

'<br><br>' >> $UserDes





echo "<h2><u>User(s) Information</u></h2>"                                                                                   | Out-File -Append $UserDes


'<details>' >> $UserDes
echo "<summary>Current User Information </summary>"                                                                | Out-File -Append $UserDes
if ($currentuser) {echo "<table>$currentuser</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes




'<details>' >> $UserDes
echo "<summary>System Details </summary>"                                                                | Out-File -Append $UserDes
if ($systemname) {echo "<table>$systemname</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes



'<details>' >> $UserDes
echo "<summary>Logon Sessions</summary>"                                                                | Out-File -Append $UserDes
if ($logonsession) {echo "<table>$logonsession</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes



'<details>' >> $UserDes
echo "<summary>User Profile</summary>"                                                                | Out-File -Append $UserDes
if ($userprofiles) {echo "<table>$userprofiles</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes




'<details>' >> $UserDes
echo "<summary>Administrator Accounts</summary>"                                                                | Out-File -Append $UserDes
if ($administrators) {echo "<table>$administrators</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes



'<details>' >> $UserDes
echo "<summary>Local Groups</summary>"                                                                | Out-File -Append $UserDes
if ($LocalGroup) {echo "<table>$LocalGroup</table><br> "                                                              | Out-File -Append $UserDes}
'</details>' >> $UserDes
'<br><br>' >> $UserDes




'<br><br>'>> $UserDes

'<center>' >> $UserDes
echo "<h3> Evidence gathered from  $env:computername  by  $operator at: $EndTime with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator </a> </h3>"  | Out-File -Append $UserDes
'</center>' >> $UserDes

#endregion

#############################################################################################################
#region   INSTALLED PROGS | SYSTEM INFO    ##################################################################
#############################################################################################################

# Making the head for system.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername" >$SysDes

# Header style for System Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $SysDes


# Making the menus for system.html

$SysNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$SysNav >> $SysDes

'<br><br>' >> $SysDes




echo "<h2><u>System Information</u></h2>"                                                                            | Out-File -Append $SysDes

'<details>' >> $SysDes
echo "<summary>Installed Programs </summary>"                                                                | Out-File -Append $SysDes
if ($InstProgs) {echo "<table>$InstProgs</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes




'<details>' >> $SysDes
echo "<summary>Installed Programs - From Registry</summary>"                                                                | Out-File -Append $SysDes
if ($InstalledApps) {echo "<table>$InstalledApps</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes



'<details>' >> $SysDes
echo "<summary>Environment Variables</summary>"                                                                | Out-File -Append $SysDes
if ($env) {echo "<table>$env</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes



'<details>' >> $SysDes
echo "<summary>System Information</summary>"                                                                | Out-File -Append $SysDes
if ($systeminfo) {echo "<table>$systeminfo</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes




'<details>' >> $SysDes
echo "<summary>Operating System Information</summary>"                                                                | Out-File -Append $SysDes
if ($OSinfo) {echo "<table>$OSinfo</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes




'<details>' >> $SysDes
echo "<summary>Hotfixes</summary>"                                                                | Out-File -Append $SysDes
if ($Hotfixes) {echo "<table>$Hotfixes</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes



'<details>' >> $SysDes
echo "<summary>Windows Defender Status</summary>"                                                                | Out-File -Append $SysDes
if ($WinDefender) {echo "<table>$WinDefender</table><br> "                                                              | Out-File -Append $SysDes}
'</details>' >> $SysDes
'<br><br>' >> $SysDes





'<br><br>'>> $SysDes

'<center>' >> $SysDes
"'<h3> Evidence gathered from  $env:computername  by  $operator at: $EndTime with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator </a> </h3>'" >>$SysDes
'</center>' >> $SysDes

#endregion

#############################################################################################################
#region   PROCESSES | SCHEDULED TASK | REGISTRY    ##########################################################
#############################################################################################################

# Making the head for processes.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername" >$ProcDes

# Header style for System Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $ProcDes


# Making the menus for system.html

$ProcNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$ProcNav >> $ProcDes

'<br><br>' >> $ProcDes



echo "<h2><u>PROCESSES | SCHEDULED TASK | REGISTRY</u></h2>"                                                      | Out-File -Append $ProcDes

'<details>' >> $ProcDes
echo "<summary>Processes </summary>"                                                                | Out-File -Append $ProcDes
if ($Processes) {echo "<table>$Processes</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Startup Programs </summary>"                                                                | Out-File -Append $ProcDes
if ($StartupProgs) {echo "<table>$StartupProgs</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Startup Programs </summary>"                                                                | Out-File -Append $ProcDes
if ($StartupProgs) {echo "<table>$StartupProgs</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Scheduled Task </summary>"                                                                | Out-File -Append $ProcDes
if ($ScheduledTask) {echo "<table>$ScheduledTask</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Scheduled Task </summary>"                                                                | Out-File -Append $ProcDes
if ($ScheduledTask) {echo "<table>$ScheduledTask</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes




'<details>' >> $ProcDes
echo "<summary>Scheduled Task & State </summary>"                                                                | Out-File -Append $ProcDes
if ($ScheduledTask2) {echo "<table>$ScheduledTask2</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Services </summary>"                                                                | Out-File -Append $ProcDes
if ($Services) {echo "<table>$Services</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes




'<details>' >> $ProcDes
echo "<summary>Services Detailed </summary>"                                                                | Out-File -Append $ProcDes
if ($Services2) {echo "<table>$Services2</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes




'<details>' >> $ProcDes
echo "<summary>Persistance in RegRun Registry </summary>"                                                                | Out-File -Append $ProcDes
if ($RegRun) {echo "<table>$RegRun</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Persistance in RegRunOnce Registry </summary>"                                                                | Out-File -Append $ProcDes
if ($RegRunOnce) {echo "<table>$RegRunOnce</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes



'<details>' >> $ProcDes
echo "<summary>Persistance in RegRunOnceEx Registry </summary>"                                                                | Out-File -Append $ProcDes
if ($RegRunOnceEx) {echo "<table>$RegRunOnceEx</table><br> "                                                              | Out-File -Append $ProcDes}
'</details>' >> $ProcDes
'<br><br>' >> $ProcDes





'<br><br>'>> $ProcDes

'<center>' >> $ProcDes
echo "<h3> Evidence gathered from  $env:computername  by  $operator at: $EndTime with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator </a> </h3>" | Out-File -Append $ProcDes
'</center>' >> $ProcDes

#endregion

#############################################################################################################
#region   EVENT LOG ANALYSIS           ######################################################################
#############################################################################################################

# Making the head for evtx.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername" > $EVTXDes

# Header style for System Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $EVTXDes


# Making the menus for system.html

$EVTXNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  border-right:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}


</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$EVTXNav >> $EVTXDes

'<br><br>' >> $EVTXDes





echo "<h2><u>EVENT LOG ANALYSIS</u></h2> "                                                                                 | Out-File -Append $EVTXDes
echo "<h3><u><center>USERS & GROUPS ACTIVITIES</center></u></h3> "                                                         | Out-File -Append $EVTXDes

'<details>' >> $EVTXDes
echo "<summary>A user's local group membership was enumerated</summary>"                                                   | Out-File -Append $EVTXDes
if ($GroupMembership) {echo "<table>$GroupMembership</table><br> "                                                         | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes
   
   
'<details>' >> $EVTXDes
echo "<summary>RDP Login Activities </summary>"                                                                            | Out-File -Append $EVTXDes
if ($RDPLogins) {echo "<table>$RDPLogins</table><br> "                                                                     | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


'<details>' >> $EVTXDes
echo "<summary>User Creation Activity </summary>"                                                                           | Out-File -Append $EVTXDes
if ($CreatedUsers) {echo "<table>$CreatedUsers</table><br> "                                                                | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes

     

'<details>' >> $EVTXDes
echo "<summary>Password Reset Activities </summary>"                                                                        | Out-File -Append $EVTXDes
if ($PassReset) {echo "<table>$PassReset</table><br> "                                                                      | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


  
'<details>' >> $EVTXDes
echo "<summary>Users Added to Group </summary>"                                                                             | Out-File -Append $EVTXDes
if ($AddedUsers) {echo "<table>$AddedUsers</table><br> "                                                                    | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


     
'<details>' >> $EVTXDes
echo "<summary>User Enabling Activities </summary>"                                                                          | Out-File -Append $EVTXDes
if ($EnabledUsers) {echo "<table>$EnabledUsers</table><br> "                                                                 | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


     
'<details>' >> $EVTXDes
echo "<summary>User Disabling Activities </summary>"                                                                         | Out-File -Append $EVTXDes
if ($DisabledUsers) {echo "<table>$DisabledUsers</table><br> "                                                               | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


     
'<details>' >> $EVTXDes
echo "<summary>User Deletion Activities </summary>"                                                                          | Out-File -Append $EVTXDes
if ($DeletedUsers) {echo "<table>$DeletedUsers</table><br> "                                                                 | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


    
'<details>' >> $EVTXDes
echo "<summary>User LockOut Activities </summary>"                                                                           | Out-File -Append $EVTXDes
if ($LockOut) {echo "<table>$LockOut</table><br> "                                                                           | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


     
'<details>' >> $EVTXDes
echo "<summary>Credential Manager Backup Activity </summary>"                                                                | Out-File -Append $EVTXDes
if ($CredManBackup) {echo "<table>$CredManBackup</table><br> "                                                               | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


     
'<details>' >> $EVTXDes
echo "<summary>Credential Manager Restore Activity </summary>"                                                                | Out-File -Append $EVTXDes
if ($CredManRestore) {echo "<table>$CredManRestore</table><br> "                                                              | Out-File -Append $EVTXDes}
'</details>' >> $EVTXDes
'<br><br>' >> $EVTXDes


#cd $PSScriptRoot

#endregion




#############################################################################################################
#region   OTHER NOTABLE CHECKS         ######################################################################
#############################################################################################################

# Making the head for others.html
ConvertTo-Html -Head $head -Title "Live Forensic Output For $env:computername" > $OtherDes

# Header style for System Page

$head = '<style> 
BODY{font-family:calibri; background-color: #f6ebf4;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em;color:#f6ebf4; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #482673} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

$head >> $OtherDes


# Making the menus for system.html

$OtherNav = "'
<html>
<style>
ul#list-nav {
width:1200px;
margin:0 auto;
list-style:none;
}

ul#list-nav li {

float:left;
}

ul#list-nav li a {
  text-decoration:none;
  padding:5px 0;
  width:100%;
  background:#482673;
  color:#f6ebf4;
  float:left;
  text-align:center;
  border-left:2px solid #a2b3a1;
  border-top:2px solid #a2b3a1;
  border-bottom:2px solid #a2b3a1;
  border-right:2px solid #a2b3a1;
  display:block;
  font-size:20px
}

ul#list-nav li a:hover {
  background:#B73225;
  color:#ffff
}
</style>
<body>
<ul id='list-nav'>
  <li><a href='index.html'>Home</a></li>
  <li><a href='users.html'>Users & Accounts</a></li>
  <li><a href='system.html'>System Information</a></li>
  <li><a href='network.html'>Network Information</a></li>
  <li><a href='processes.html'>System Processes</a></li>
  <li><a href='evtx.html'>Event Log Analysis</a></li>
  <li><a href='others.html'>Other Information</a></li>
</ul>
</body>
</html>
'"

$OtherNav >> $OtherDes

'<br><br>' >> $OtherDes




echo "<h2><u>OTHER NOTABLE CHECKS</u></h2> "                                                                              | Out-File -Append $OtherDes

'<details>' >> $OtherDes
echo "<summary>Logical Drives </summary>"                                                                | Out-File -Append $OtherDes
if ($LogicalDrives) {echo "<table>$LogicalDrives</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Connected & Disconnected Webcams </summary>"                                                                | Out-File -Append $OtherDes
if ($Imagedevice) {echo "<table>$Imagedevice</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>USB Devices </summary>"                                                                | Out-File -Append $OtherDes
if ($USBDevices) {echo "<table>$USBDevices</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>UPNPDevices </summary>"                                                                | Out-File -Append $OtherDes
if ($UPNPDevices) {echo "<table>$UPNPDevices</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>All Previously Connected Drives </summary>"                                                                | Out-File -Append $OtherDes
if ($UnknownDrives) {echo "<table>$UnknownDrives</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes


'<details>' >> $OtherDes
echo "<summary>All Files Created in the last 180days </summary>"                                                                | Out-File -Append $OtherDes
if ($UnknownDrives) {echo "<table>$UnknownDrives</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>All Files Created in the last 180days </summary>"                                                                | Out-File -Append $OtherDes
if ($LinkFiles) {echo "<table>$LinkFiles</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>500Days Powershell History </summary>"                                                                | Out-File -Append $OtherDes
if ($PSHistory) {echo "<table>$PSHistory</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Executables in the Downloads folder </summary>"                                                                | Out-File -Append $OtherDes
if ($Downloads) {echo "<table>$Downloads</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Executables In AppData </summary>"                                                                | Out-File -Append $OtherDes
if ($HiddenExecs1) {echo "<table>$HiddenExecs1</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Executables In Temp</summary>"                                                                | Out-File -Append $OtherDes
if ($HiddenExecs2) {echo "<table>$HiddenExecs2</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Executables In Perflogs</summary>"                                                                | Out-File -Append $OtherDes
if ($HiddenExecs3) {echo "<table>$HiddenExecs3</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Executables In Documents Folder</summary>"                                                                | Out-File -Append $OtherDes
if ($HiddenExecs4) {echo "<table>$HiddenExecs4</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes



'<details>' >> $OtherDes
echo "<summary>Files with same extension as well-known ransomware encrypted files </summary>"                        | Out-File -Append $OtherDes
if ($FindFiles) {echo "<table>$FindFiles</table><br> "                                                              | Out-File -Append $OtherDes}
'</details>' >> $OtherDes
'<br><br>' >> $OtherDes


'<br><br>' >> $OtherDes

'<center>' >> $OtherDes
echo "<h3> Evidence gathered from  $env:computername  by  $operator at: $Endtimecheck with: <a href='https://github.com/Johnng007/Live-Forensicator' >Live Forensicator</a> </h3>" | Out-File -Append $OtherDes
'</center>' >> $OtherDes

#cd $PSScriptRoot

#endregion










if ($ENCRYPTED) {
	
   Write-Host -Fore DarkCyan "[*] You choose to Encrypt the Artifacts but lets first Archive it"	

   $ParentFolder = $PSScriptRoot + "\" + "$env:computername" + "\" #files will be stored with a path relative to this folder
   $ZipPath = $PSScriptRoot + "\" + "$env:computername" + "\" + "$env:computername.zip" #the zip file should not be under $ParentFolder or an exception will be raised

@( 'System.IO.Compression','System.IO.Compression.FileSystem') | % { [void][Reflection.Assembly]::LoadWithPartialName($_) }
   Push-Location $ParentFolder #change to the parent folder so we can get $RelativePath
   $FileList = (Get-ChildItem '*.*' -File -Recurse) #use the -File argument because empty folders can't be stored
Try{
    $WriteArchive = [IO.Compression.ZipFile]::Open( $ZipPath,'Update')
    ForEach ($File in $FileList){
        $RelativePath = (Resolve-Path -LiteralPath "$($File.FullName)" -Relative) -replace '^.\\' #trim leading .\ from path 
        Try{    
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($WriteArchive, $File.FullName, $RelativePath, 'Optimal').FullName
        }Catch{ #Single file failed - usually inaccessible or in use
            Write-Warning  "$($File.FullName) could not be archived. `n $($_.Exception.Message)"  
        }
    }
}Catch [Exception]{ #failure to open the zip file
    Write-Error $_.Exception
}Finally{
    $WriteArchive.Dispose() #always close the zip file so it can be read later 
	#Remove-Item -Exclude *.zip -Recurse -Force
	Get-ChildItem * -Exclude *.zip -Recurse | Remove-Item -Force -Recurse
}

Write-Host -Fore DarkCyan "[*] Artifacts Archived, now lets encrypt it..."

Pop-Location



$Password = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 12  | % {[char]$_}) )

$MYTEXT = $Password
$ENCODED = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MYTEXT))
#Write-Host $ENCODED | Out-File .\key.txt
Write-Host $ENCODED
echo YOUR ENCRYPTION KEY IS: $ENCODED | Out-File -Force .\key.txt 

Write-Host -Fore DarkCyan "[!] That is your Encryption key please keep it safe"

# Define target file types
$TargetFiles = '*.zip'
$TargetPath = $PSScriptRoot + "\" + "$env:computername" + "\"
$Extension = ".forensicator"
$Key = $ENCODED

# Import FileCryptography module
Import-Module "$PSScriptRoot\Forensicator-Share\FileCryptography.psm1"


    # Gather all files from the target path and its subdirectories
    $FilesToEncrypt = get-childitem -path $TargetPath\* -Include $TargetFiles -Exclude *$Extension -Recurse -force | where { ! $_.PSIsContainer } 
    $NumFiles = $FilesToEncrypt.length

    # Encrypt the files
    foreach ($file in $FilesToEncrypt)
    {
        Write-Host "Encrypting $file"
        Protect-File $file -Algorithm AES -KeyAsPlainText $key -Suffix $Extension -RemoveSource
    }
    Write-Host "Encrypted $NumFiles files." | Start-Sleep -Seconds 10

Write-Host -Fore DarkCyan "[*] Artifact Encrypted successfully"

Write-Host -Fore Cyan "[!] All Done... you can find the key in the Artifact Folder"	

cd $PSScriptRoot

	
   
} 
else {
	
cd $PSScriptRoot
	
Write-Host -Fore Cyan "[!] All Done... you can find the results in the script execution folder"	

}


Write-Host ''
Write-Host ''
Write-Host ''
