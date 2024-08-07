
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
  [String]$HASHCHECK,
  [String]$ENCRYPTED,
  [switch]$UPDATE,
  [switch]$VERSION,
  [switch]$DECRYPT,
  [switch]$USAGE
)


$ErrorActionPreference = 'silentlycontinue'

Write-Host -Fore DarkCyan "[!] Starting... "



##################################################
#region        Auto Check Update                 #
##################################################

$Hostname = $env:computername
$localVersion = Get-Content -Path .\version.txt

# GitHub repository details
$repoOwner = "johnng007"
$repoName = "Live-Forensicator"
$branch = "main"
$versionFile = "version.txt"
$rawUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch/Windows/$versionFile"

# Function to check for updates
function CheckForUpdates {
  try {
    # Fetch the version from GitHub
    $remoteVersion = (Invoke-RestMethod -Uri $rawUrl).Trim() -replace '\s+'

    # Compare local and remote versions
    if ($localVersion -lt $remoteVersion) {
      Write-Host -Fore Cyan "[!] A new version $remoteVersion is available on Github. Please upgrade your copy of Forensicator."
    }
    else {
      Write-Host -Fore Cyan "[!] You are using the latest version $localVersion No updates available."
    }
  }
  catch {
    Write-Host "Failed to check for updates. You probably don't have an internet connection."
    Write-Host "Error: $_"
  }
}

# Call the function to check for updates
CheckForUpdates

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

  #$source = 'https://raw.githubusercontent.com/Johnng007/Live-Forensicator/main/version.txt'

  $destination = 'version.txt'

  if (((Test-NetConnection www.githubusercontent.com -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) -eq $true) {
	
    Invoke-WebRequest -Uri $source -OutFile $rawUrl	
  }

  else {
    Write-Host -Fore DarkCyan "[*] githubusercontent.com is not reacheable, please check your connection"
    Set-Location $PSScriptRoot
    Remove-Item 'Updated' -Force -Recurse
    exit 0
  }

  if ((Get-FileHash $version_file).hash -eq (Get-FileHash $current_version).hash) {
	 
    Write-Host -Fore Cyan "[*] Congratualtion you have the current version"
    Set-Location $PSScriptRoot
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
    Set-Location $PSScriptRoot
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
	
  if (!(Get-ChildItem $DecryptPath *.forensicator)) { 
	
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
  $FilestoDecrypt = get-childitem -path $TargetPath\* -Include *$Extension -Recurse -force | Where-Object { ! $_.PSIsContainer }

  # Decrypt the files
  foreach ($file in $FilestoDecrypt) {
    Write-Host "Decrypting $file"
    Unprotect-File $file -Algorithm AES -KeyAsPlainText $key -Suffix $Extension  -RemoveSource
  }
  exit 0
}
else {
	
}

##################################################
#endregion ARTIFACT DECRYPTION SWITCH            #
##################################################

##################################################
#region             USAGE                        #
##################################################

if ($USAGE) {
	
  Write-Host ''
  Write-Host -Fore Cyan       'FORESNSICATOR USAGE'
  Write-Host ''
  Write-Host -Fore DarkCyan   'Note: This may not be up to date please check github'
  Write-Host ''
  Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1   This runs the Basic checks on a system.'
  Write-Host ''
  Write-Host -Fore Cyan       'FLAGS'
  Write-Host -Fore Cyan       'The below flags can be added to the Basic Usage'
  Write-Host ''
  Write-Host -Fore DarkCyan   '[*] -EVTX EVTX               Also grab Event Logs'
  Write-Host -Fore DarkCyan   '[*] -WEBLOGS WEBLOGS         Also grab Web Logs.'
  Write-Host -Fore DarkCyan   '[*] -PCAP PCAP               Run network tracing and capture PCAP for 120seconds'
  Write-Host -Fore Cyan       "[!] requires the etl2pcapng file in share folder"
  Write-Host -Fore DarkCyan   '[*] -RAM RAM                 Extract RAM Dump'
  Write-Host -Fore Cyan       "[!] requires the winpmem file in share folder"
  Write-Host -Fore DarkCyan   '[*] -LOG4J LOG4J             Checks for vulnerable log4j files'
  Write-Host -Fore DarkCyan   '[*] -ENCRYPTED ENCRYPTED     Encrypts Artifacts after collecting them'
  Write-Host -Fore Cyan       "[!] requires the FileCryptography file in share folder"
  Write-Host -Fore DarkCyan   '[*] -BROWSER BROWSER         Grabs a detailed browsing history from system'
  Write-Host -Fore Cyan       "[!] requires the Nirsoft BrowserView file in share folder"
  Write-Host -Fore DarkCyan   '[*] -HASHCHECK HASHCHECK     Check executable hashes for latest malware'
  Write-Host -Fore DarkCyan   ''
  Write-Host -Fore DarkCyan   'SWITCHES' 
  Write-Host -Fore DarkCyan   ''
  Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -VERSION           This checks the version of Foresicator you have'
  Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -UPDATE            This checks for and updates your copy of Forensicator'
  Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -DECRYPT DECRYPT   This decrypts a Foresicator encrypted Artifact'
  Write-Host -Fore Cyan       "[!] requires the FileCryptography file in share folder"
  Write-Host -Fore DarkCyan   '[*] .\Forensicator.ps1 -USAGE             Prints this help file'

  exit 0
}
else {
	
}

# Function to check if running as administrator
function Test-IsAdministrator {
  $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $isDomainAdmin = $currentUser.IsInRole("Domain Admins")
  return $isAdmin -or $isDomainAdmin
}

# Check if running as administrator
if (-not (Test-IsAdministrator)) {
  Write-Host -Fore DarkCyan "[!] Forensicator is not running with admin rights"
  Write-Host -Fore DarkCyan "[!] To get the best of results, please run as an admin!"

}


##################################################
#endregion ARTIFACT DECRYPTION SWITCH            #
##################################################

$ErrorActionPreference = 'silentlycontinue'

$t = @"

___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          $MyVersion

"@

for ($i = 0; $i -lt $t.length; $i++) {
  if ($i % 2) {
    $c = "red"
  }
  elseif ($i % 5) {
    $c = "yellow"
  }
  elseif ($i % 7) {
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
}
else {
  Write-Host -Fore Cyan "[!] Forensicator-Share folder not found, some flags and functions will not work! use the -UPDATE flag to import the complete Arsenal.."
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
$ForensicatorIndexFile = 'index.html'

# Setting Extras Output file
$ForensicatorExtrasFile = 'extras.html'

# Setting Network Information Output
$NetworkFile = 'network.html'

# Setting Users Information Output
$UserFile = 'users.html'

# Setting System Information Output
$SystemFile = 'system.html'

# Setting Processes Output
$ProcessFile = 'processes.html'

# Setting Other Checks Output
$OthersFile = 'others.html'

# Setting Evtx Checks Output
$EvtxUserFile = 'evtx_user.html'

# Setting Evtx Logon Eents Checks Output
$LogonEventsFile = 'evtx_logons.html'

# Setting Evtx Object Access Checks Output
$ObjectEventsFile = 'evtx_object.html'

# Setting Evtx Process Execution Checks Output
$ProcessEventsFile = 'evtx_process.html'

# Setting Evtx Suspicious Activities Output
$SuspiciousEventsFile = 'evtx_suspicious.html'


##################################################
#region Network Information and Settings         #
##################################################
Write-Host -Fore DarkCyan "[*] Gathering Network & Network Settings"

#Gets DNS cache. Replaces ipconfig /dislaydns
$DNSCache = Get-DnsClientCache | Select-Object Entry, Name, Status, TimeToLive, Data #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $DNSCache) {
  $DNSCacheFragment += "<tr>"
  $DNSCacheFragment += "<td>$($process.Entry)</td>"
  $DNSCacheFragment += "<td>$($process.Name)</td>"
  $DNSCacheFragment += "<td>$($process.Status)</td>"
  $DNSCacheFragment += "<td>$($process.TimeToLive)</td>"
  $DNSCacheFragment += "<td>$($process.Data)</td>"
  $DNSCacheFragment += "</tr>"
}

$NetworkAdapter = Get-WmiObject -class Win32_NetworkAdapter  | Select-Object -Property AdapterType, ProductName, Description, MACAddress, Availability, NetconnectionStatus, NetEnabled, PhysicalAdapter #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetworkAdapter) {
  $NetworkAdapterFragment += "<tr>"
  $NetworkAdapterFragment += "<td>$($process.AdapterType)</td>"
  $NetworkAdapterFragment += "<td>$($process.ProductName)</td>"
  $NetworkAdapterFragment += "<td>$($process.Description)</td>"
  $NetworkAdapterFragment += "<td>$($process.MACAddress)</td>"
  $NetworkAdapterFragment += "<td>$($process.Availability)</td>"
  $NetworkAdapterFragment += "<td>$($process.NetconnectionStatus)</td>"
  $NetworkAdapterFragment += "<td>$($process.NetEnabled)</td>"
  $NetworkAdapterFragment += "<td>$($process.PhysicalAdapter)</td>"
  $NetworkAdapterFragment += "</tr>"
}

#Replaces ipconfig:
$IPConfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration |  Select-Object Description, @{Name = 'IpAddress'; Expression = { $_.IpAddress -join '; ' } }, @{Name = 'IpSubnet'; Expression = { $_.IpSubnet -join '; ' } }, MACAddress, @{Name = 'DefaultIPGateway'; Expression = { $_.DefaultIPGateway -join '; ' } }, DNSDomain, DNSHostName, DHCPEnabled, ServiceName #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $IPConfiguration) {
  $IPConfigurationFragment += "<tr>"
  $IPConfigurationFragment += "<td>$($process.Description)</td>"
  $IPConfigurationFragment += "<td>$($process.MACAddress)</td>"
  $IPConfigurationFragment += "<td>$($process.DNSDomain)</td>"
  $IPConfigurationFragment += "<td>$($process.DNSHostName)</td>"
  $IPConfigurationFragment += "<td>$($process.DHCPEnabled)</td>"
  $IPConfigurationFragment += "<td>$($process.ServiceName)</td>"
  $IPConfigurationFragment += "</tr>"
}

$NetIPAddress = Get-NetIPaddress | Select-Object InterfaceAlias, IPaddress, EnabledState, OperatingStatus #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetIPAddress) {
  $NetIPAddressFragment += "<tr>"
  $NetIPAddressFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetIPAddressFragment += "<td>$($process.IPaddress)</td>"
  $NetIPAddressFragment += "<td>$($process.EnabledState)</td>"
  $NetIPAddressFragment += "<td>$($process.OperatingStatus)</td>"
  $NetIPAddressFragment += "</tr>"
}

$NetConnectProfile = Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetConnectProfile) {
  $NetConnectProfileFragment += "<tr>"
  $NetConnectProfileFragment += "<td>$($process.Name)</td>"
  $NetConnectProfileFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetConnectProfileFragment += "<td>$($process.NetworkCategory)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPV4Connectivity)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPv6Connectivity)</td>"
  $NetConnectProfileFragment += "</tr>"
}

$NetAdapter = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetAdapter) {
  $NetAdapterFragment += "<tr>"
  $NetAdapterFragment += "<td>$($process.Name)</td>"
  $NetAdapterFragment += "<td>$($process.InterfaceDescription)</td>"
  $NetAdapterFragment += "<td>$($process.Status)</td>"
  $NetAdapterFragment += "<td>$($process.MacAddress)</td>"
  $NetAdapterFragment += "<td>$($process.LinkSpeed)</td>"
  $NetAdapterFragment += "</tr>"
}

#Replaces arp -a:
$NetNeighbor = Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetNeighbor) {
  $NetNeighborFragment += "<tr>"
  $NetNeighborFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetNeighborFragment += "<td>$($process.IPAddress)</td>"
  $NetNeighborFragment += "<td>$($process.LinkLayerAddress)</td>"
  $NetNeighborFragment += "</tr>"
}

#Replaces netstat commands
$NetTCPConnect = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetTCPConnect) {
  $NetTCPConnectFragment += "<tr>"
  $NetTCPConnectFragment += "<td>$($process.LocalAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.LocalPort)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemoteAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemotePort)</td>"
  $NetTCPConnectFragment += "<td>$($process.State)</td>"
  $NetTCPConnectFragment += "<td>$($process.OwningProcess)</td>"
  $NetTCPConnectFragment += "</tr>"
}

#Get Wi-fi Names and Passwords
$WlanPasswords = netsh.exe wlan show profiles | Select-String "\:(.+)$" | ForEach-Object { $wlanname = $_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object { (netsh wlan show profile name="$wlanname" key=clear) }  | Select-String 'Key Content\W+\:(.+)$' | ForEach-Object { $wlanpass = $_.Matches.Groups[1].Value.Trim(); [PSCustomObject]@{ PROFILE_NAME = $wlanname; PASSWORD = $wlanpass } }

$WlanPasswordsFragment = ""

foreach ($process in $WlanPasswords) {
  $WlanPasswordsFragment += "<tr>"
  $WlanPasswordsFragment += "<td>$($process.PROFILE_NAME)</td>"
  $WlanPasswordsFragment += "<td>$($process.PASSWORD)</td>"
  $WlanPasswordsFragment += "</tr>"
}


#Get Firewall Information. Replaces netsh firewall show config
$FirewallRule = Get-NetFirewallRule | select-object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $FirewallRule) {
  $FirewallRuleFragment += "<tr>"
  $FirewallRuleFragment += "<td>$($process.Name)</td>"
  $FirewallRuleFragment += "<td>$($process.DisplayName)</td>"
  $FirewallRuleFragment += "<td>$($process.Description)</td>"
  $FirewallRuleFragment += "<td>$($process.Direction)</td>"
  $FirewallRuleFragment += "<td>$($process.Action)</td>"
  $FirewallRuleFragment += "<td>$($process.EdgeTraversalPolicy)</td>"
  $FirewallRuleFragment += "<td>$($process.Owner)</td>"
  $FirewallRuleFragment += "<td>$($process.EnforcementStatus)</td>"
  $FirewallRuleFragment += "</tr>"
}

#Outgoing SMB Session
$outboundSmbSessions = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 -and $_.State -eq "Established" }
foreach ($process in $outboundSmbSessions) {
  $outboundSmbSessionsFragment += "<tr>"
  $outboundSmbSessionsFragment += "<td>$($process.LocalAddress)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.LocalPort)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.RemoteAddress)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.RemotePort)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.State)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.AppliedSetting)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.OwningProcess)</td>"
  $outboundSmbSessionsFragment += "</tr>"
}

#Display active samba sessions
$SMBSessions = Get-SMBSession -ea silentlycontinue #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $SMBSessions) {
  $SMBSessionsFragment += "<tr>"
  $SMBSessionsFragment += "<td>$($process.SessionId)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientComputerName)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientUserName)</td>"
  $SMBSessionsFragment += "<td>$($process.NumOpens)</td>"
  $SMBSessionsFragment += "</tr>"
}

#Display active samba shares
$SMBShares = Get-SMBShare | Select-Object description, path, volume #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $SMBShares) {
  $SMBSharesFragment += "<tr>"
  $SMBSharesFragment += "<td>$($process.description)</td>"
  $SMBSharesFragment += "<td>$($process.path)</td>"
  $SMBSharesFragment += "<td>$($process.volume)</td>"
  $SMBSharesFragment += "</tr>"
}

#Get IP routes to non-local destinations
$NetHops = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0, 6) -Ne "fe80::") } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetHops) {
  $NetHopsFragment += "<tr>"
  $NetHopsFragment += "<td>$($process.ifIndex)</td>"
  $NetHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $NetHopsFragment += "<td>$($process.NextHop)</td>"
  $NetHopsFragment += "<td>$($process.RouteMetric)</td>"
  $NetHopsFragment += "<td>$($process.ifMetric)</td>"
  $NetHopsFragment += "<td>$($process.PolicyStore)</td>"
  $NetHopsFragment += "</tr>"
}

#Get network adapters that have IP routes to non-local destinations
$AdaptHops = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0, 6) -Ne "fe80::") } | Get-NetAdapter #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $AdaptHops) {
  $AdaptHopsFragment += "<tr>"
  $AdaptHopsFragment += "<td>$($process.Name)</td>"
  $AdaptHopsFragment += "<td>$($process.InterfaceDescription)</td>"
  $AdaptHopsFragment += "<td>$($process.ifIndex)</td>"
  $AdaptHopsFragment += "<td>$($process.Status)</td>"
  $AdaptHopsFragment += "<td>$($process.MacAddress)</td>"
  $AdaptHopsFragment += "<td>$($process.LinkSpeed)</td>"
  $AdaptHopsFragment += "</tr>"
}

#Get IP routes that have an infinite valid lifetime
$IpHops = Get-NetRoute | Where-Object -FilterScript { $_.ValidLifetime -Eq ([TimeSpan]::MaxValue) } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
# Populate the HTML table with process information
foreach ($process in $IpHops) {
  $IpHopsFragment += "<tr>"
  $IpHopsFragment += "<td>$($process.ifIndex)</td>"
  $IpHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $IpHopsFragment += "<td>$($process.NextHop)</td>"
  $IpHopsFragment += "<td>$($process.RouteMetric)</td>"
  $IpHopsFragment += "<td>$($process.ifMetric)</td>"
  $IpHopsFragment += "<td>$($process.PolicyStore)</td>"
  $IpHopsFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region User & Account Information               #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering User & Account Information"

$userUID = id
$systemname = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, DNSHostName, Domain, Manufacturer, Model, PrimaryOwnerName, TotalPhysicalMemory, Workgroup  #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$systemnameFragment = ""
# Populate the HTML table with process information
foreach ($process in $systemname) {
  $systemnameFragment += "<tr>"
  $systemnameFragment += "<td>$($process.Name)</td>"
  $systemnameFragment += "<td>$($process.DNSHostName)</td>"
  $systemnameFragment += "<td>$($process.Domain)</td>"
  $systemnameFragment += "<td>$($process.Manufacturer)</td>"
  $systemnameFragment += "<td>$($process.Model)</td>"
  $systemnameFragment += "<td>$($process.PrimaryOwnerName)</td>"
  $systemnameFragment += "<td>$($process.TotalPhysicalMemory)</td>"
  $systemnameFragment += "<td>$($process.Workgroup)</td>"
  $systemnameFragment += "</tr>"
}

#$useraccounts = Get-WmiObject -Class Win32_UserAccount  | Select-Object -Property AccountType,Domain,LocalAccount,Name,PasswordRequired,SID,SIDType | ConvertTo-Html -fragment
#$logonsessionhistory = Get-WmiObject -Class Win32_LogonSession | Select-Object -Property LogonID, LogonType, StartTime, @{Name = 'Start Time'; Expression = { $_.ConvertToDateTime($_.starttime) } }   | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#######ADDITIONS
$logonsession = (((quser) -replace '^>', '') -replace '\s{2,}', ',').Trim() | ConvertFrom-Csv #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#$userprocesses = Get-Process -includeusername | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$logonsessionFragment = ""
# Populate the HTML table with process information
foreach ($process in $logonsession) {
  $logonsessionFragment += "<tr>"
  $logonsessionFragment += "<td>$($process.USERNAME)</td>"
  $logonsessionFragment += "<td>$($process.SESSIONNAME)</td>"
  $logonsessionFragment += "<td>$($process.STATE)</td>"
  $logonsessionFragment += "<td>$($process.ID)</td>"
  $logonsessionFragment += "<td>$($process.'IDLE TIME')</td>"
  $logonsessionFragment += "<td>$($process.'LOGON TIME')</td>"
  $logonsessionFragment += "</tr>"
}

$userprocesses = Get-Process -includeusername | Select-Object Name, Id, Username, CPU, Memory, Path 
# Populate the HTML table with process information
$userprocessesFragment = ""
foreach ($process in $userprocesses) {
  $userprocessesFragment += "<tr>"
  $userprocessesFragment += "<td>$($process.Name)</td>"
  $userprocessesFragment += "<td>$($process.Id)</td>"
  $userprocessesFragment += "<td>$($process.UserName)</td>"
  $userprocessesFragment += "<td>$($process.CPU)</td>"
  $userprocessesFragment += "<td>$($process.Memory)</td>"
  $userprocessesFragment += "<td>$($process.Path)</td>"
  $userprocessesFragment += "</tr>"
}

#$userprofiles = Get-WmiObject -Class Win32_UserProfile | Select-object -property Caption, LocalPath, SID, @{Name = 'Last Used'; Expression = { $_.ConvertToDateTime($_.lastusetime) } } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$userprofiles = Get-WmiObject -Class Win32_UserProfile | Select-object -property PSComputerName, LocalPath, SID, lastusetime
# Populate the HTML table with process information
$profileFragment = ""

foreach ($process in $userprofiles) {
  $profileFragment += "<tr>"
  $profileFragment += "<td>$($process.PSComputerName)</td>"
  $profileFragment += "<td>$($process.LocalPath)</td>"
  $profileFragment += "<td>$($process.SID)</td>"
  $profileFragment += "<td>$([Management.ManagementDateTimeConverter]::ToDateTime($process.lastusetime))</td>"
  $profileFragment += "</tr>"
}


#$administrators = Get-LocalGroupMember -Group "Administrators" | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$administrators = Get-LocalGroupMember -Group "Administrators"
# Populate the HTML table with process information
$adminFragment = ""

foreach ($process in $administrators) {
  $adminFragment += "<tr>"
  $adminFragment += "<td>$($process.Name)</td>"
  $adminFragment += "<td>$($process.ObjectClass)</td>"
  $adminFragment += "<td>$($process.PrincipalSource)</td>"
  $adminFragment += "</tr>"
}


#$LocalGroup = Get-LocalGroup | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$LocalGroup = Get-LocalGroup
# Populate the HTML table with process information
$localFragment = ""
foreach ($process in $LocalGroup) {
  $localFragment += "<tr>"
  $localFragment += "<td>$($process.Name)</td>"
  $localFragment += "<td>$($process.Description)</td>"
  $localFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Installed Programs                       #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering Installed Programs"

#$InstProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$InstProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage
# Populate the HTML table with process information
foreach ($process in $InstProgs) {
  $InstProgsFragment += "<tr>"
  $InstProgsFragment += "<td>$($process.Name)</td>"
  $InstProgsFragment += "<td>$($process.Version)</td>"
  $InstProgsFragment += "<td>$($process.Vendor)</td>"
  $InstProgsFragment += "<td>$($process.InstallDate)</td>"
  $InstProgsFragment += "<td>$($process.InstallSource)</td>"
  $InstProgsFragment += "<td>$($process.PackageName)</td>"
  $InstProgsFragment += "<td>$($process.LocalPackage)</td>"
  $InstProgsFragment += "</tr>"
}

#$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
# Populate the HTML table with process information
foreach ($process in $InstalledApps) {
  $InstalledAppsFragment += "<tr>"
  $InstalledAppsFragment += "<td>$($process.DisplayName)</td>"
  $InstalledAppsFragment += "<td>$($process.DisplayVersion)</td>"
  $InstalledAppsFragment += "<td>$($process.Publisher)</td>"
  $InstalledAppsFragment += "<td>$($process.InstallDate)</td>"
  $InstalledAppsFragment += "</tr>"
}


Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region System Info                              #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering System Information"

#Environment Settings
#$env = Get-ChildItem ENV: | Select-Object name, value | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$env = Get-ChildItem ENV: | Select-Object name, value
# Populate the HTML table with process information
foreach ($process in $env) {
  $envFragment += "<tr>"
  $envFragment += "<td>$($process.name)</td>"
  $envFragment += "<td>$($process.value)</td>"
  $envFragment += "</tr>"
}

#System Info
#$systeminfo = Get-WmiObject -Class Win32_ComputerSystem  | Select-Object -Property Name, Caption, SystemType, Manufacturer, Model, DNSHostName, Domain, PartOfDomain, WorkGroup, CurrentTimeZone, PCSystemType, HyperVisorPresent | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$systeminfo = Get-WmiObject -Class Win32_ComputerSystem  | Select-Object -Property Name, Caption, SystemType, Manufacturer, Model, DNSHostName, Domain, PartOfDomain, WorkGroup, CurrentTimeZone, PCSystemType, HyperVisorPresent
# Populate the HTML table with process information
foreach ($process in $systeminfo) {
  $systeminfoFragment += "<tr>"
  $systeminfoFragment += "<td>$($process.Name)</td>"
  $systeminfoFragment += "<td>$($process.Caption)</td>"
  $systeminfoFragment += "<td>$($process.SystemType)</td>"
  $systeminfoFragment += "<td>$($process.Manufacturer)</td>"
  $systeminfoFragment += "<td>$($process.Model)</td>"
  $systeminfoFragment += "<td>$($process.DNSHostName)</td>"
  $systeminfoFragment += "<td>$($process.Domain)</td>"
  $systeminfoFragment += "<td>$($process.PartOfDomain)</td>"
  $systeminfoFragment += "<td>$($process.WorkGroup)</td>"
  $systeminfoFragment += "<td>$($process.CurrentTimeZone)</td>"
  $systeminfoFragment += "<td>$($process.PCSystemType)</td>"
  $systeminfoFragment += "<td>$($process.HyperVisorPresent)</td>"
  $systeminfoFragment += "</tr>"
}

#OS Info
#$OSinfo = Get-WmiObject -Class Win32_OperatingSystem   | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$OSinfo = Get-WmiObject -Class Win32_OperatingSystem   | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite
# Populate the HTML table with process information
foreach ($process in $OSinfo) {
  $OSinfoFragment += "<tr>"
  $OSinfoFragment += "<td>$($process.Name)</td>"
  $OSinfoFragment += "<td>$($process.Description)</td>"
  $OSinfoFragment += "<td>$($process.Version)</td>"
  $OSinfoFragment += "<td>$($process.BuildNumber)</td>"
  $OSinfoFragment += "<td>$($process.InstallDate)</td>"
  $OSinfoFragment += "<td>$($process.SystemDrive)</td>"
  $OSinfoFragment += "<td>$($process.SystemDevice)</td>"
  $OSinfoFragment += "<td>$($process.WindowsDirectory)</td>"
  $OSinfoFragment += "<td>$($process.LastBootupTime)</td>"
  $OSinfoFragment += "<td>$($process.Locale)</td>"
  $OSinfoFragment += "<td>$($process.LocalDateTime)</td>"
  $OSinfoFragment += "<td>$($process.NumberofUsers)</td>"
  $OSinfoFragment += "<td>$($process.RegisteredUser)</td>"
  $OSinfoFragment += "<td>$($process.Organization)</td>"
  $OSinfoFragment += "<td>$($process.OSProductSuite)</td>"
  $OSinfoFragment += "</tr>"
}

#Hotfixes
#$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption, Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption, Description, HotfixID, InstalledBy, InstalledOn
# Populate the HTML table with process information
foreach ($process in $Hotfixes) {
  $HotfixesFragment += "<tr>"
  $HotfixesFragment += "<td>$($process.CSName)</td>"
  $HotfixesFragment += "<td>$($process.Caption)</td>"
  $HotfixesFragment += "<td>$($process.Description)</td>"
  $HotfixesFragment += "<td>$($process.HotfixID)</td>"
  $HotfixesFragment += "<td>$($process.InstalledBy)</td>"
  $HotfixesFragment += "<td>$($process.InstalledOn)</td>"
  $HotfixesFragment += "</tr>"
}

#Get Windows Defender Status
#$WinDefender = Get-MpComputerStatus | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$WinDefender = Get-MpComputerStatus | Select-Object -Property AMProductVersion, AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, BehaviorMonitorEnabled, DefenderSignaturesOutOfDate, DeviceControlPoliciesLastUpdated, DeviceControlState, NISSignatureLastUpdated, QuickScanEndTime, RealTimeProtectionEnabled
# Populate the HTML table with process information
foreach ($process in $WinDefender) {
  $WinDefenderFragment += "<tr>"
  $WinDefenderFragment += "<td>$($process.AMProductVersion)</td>"
  $WinDefenderFragment += "<td>$($process.AMRunningMode)</td>"
  $WinDefenderFragment += "<td>$($process.AMServiceEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusSignatureLastUpdatedn)</td>"
  $WinDefenderFragment += "<td>$($process.BehaviorMonitorEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.DefenderSignaturesOutOfDate)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlPoliciesLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlState)</td>"
  $WinDefenderFragment += "<td>$($process.NISSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.QuickScanEndTime)</td>"
  $WinDefenderFragment += "<td>$($process.RealTimeProtectionEnabled)</td>"
  $WinDefenderFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Live Running Processes & Scheduled Tasks #
##################################################

Write-Host -Fore DarkCyan "[*] Gathering Processes and Tasks"


#$Processes = Get-Process | Select-Object Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Processes = Get-Process | Select-Object Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion
# Populate the HTML table with process information
foreach ($process in $Processes) {
  $ProcessesFragment += "<tr>"
  $ProcessesFragment += "<td>$($process.Handles)</td>"
  $ProcessesFragment += "<td>$($process.StartTime)</td>"
  $ProcessesFragment += "<td>$($process.PM)</td>"
  $ProcessesFragment += "<td>$($process.VM)</td>"
  $ProcessesFragment += "<td>$($process.SI)</td>"
  $ProcessesFragment += "<td>$($process.id)</td>"
  $ProcessesFragment += "<td>$($process.ProcessName)</td>"
  $ProcessesFragment += "<td>$($process.Path)</td>"
  $ProcessesFragment += "<td>$($process.Product)</td>"
  $ProcessesFragment += "<td>$($process.FileVersion)</td>"
  $ProcessesFragment += "</tr>"
}

#Items set to run on startup
#$StartupProgs = Get-WmiObject Win32_StartupCommand | Select-Object Command, User, Caption | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$StartupProgs = Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User
# Populate the HTML table with process information
foreach ($process in $StartupProgs) {
  $StartupProgsFragment += "<tr>"
  $StartupProgsFragment += "<td>$($process.Name)</td>"
  $StartupProgsFragment += "<td>$($process.command)</td>"
  $StartupProgsFragment += "<td>$($process.Location)</td>"
  $StartupProgsFragment += "<td>$($process.User)</td>"
  $StartupProgsFragment += "</tr>"
}

# Scheduled Tasks
#$ScheduledTask = Get-ScheduledTask | Where-Object State -eq running | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$ScheduledTask = Get-ScheduledTask | Select-Object TaskPath, TaskName, State
# Populate the HTML table with process information
foreach ($process in $ScheduledTask) {
  $ScheduledTaskFragment += "<tr>"
  $ScheduledTaskFragment += "<td>$($process.TaskPath)</td>"
  $ScheduledTaskFragment += "<td>$($process.TaskName)</td>"
  $ScheduledTaskFragment += "<td>$($process.State)</td>"
  $ScheduledTaskFragment += "</tr>"
}

# Get Running Tasks and Their state
#$ScheduledTask2 = Get-ScheduledTask | Where-Object State -eq running | Get-ScheduledTaskInfo | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$ScheduledTask2 = Get-ScheduledTask | Get-ScheduledTaskInfo | Select-Object -Property LastRunTime, LastTaskResult, NextRunTime, NumberOfMissedRuns, TaskName, TaskPath, PSComputerName
# Populate the HTML table with process information
foreach ($process in $ScheduledTask2) {
  $ScheduledTask2Fragment += "<tr>"
  $ScheduledTask2Fragment += "<td>$($process.LastRunTime)</td>"
  $ScheduledTask2Fragment += "<td>$($process.LastTaskResult)</td>"
  $ScheduledTask2Fragment += "<td>$($process.NextRunTime)</td>"
  $ScheduledTask2Fragment += "<td>$($process.NumberOfMissedRuns)</td>"
  $ScheduledTask2Fragment += "<td>$($process.TaskName)</td>"
  $ScheduledTask2Fragment += "<td>$($process.TaskPath)</td>"
  $ScheduledTask2Fragment += "<td>$($process.PSComputerName)</td>"
  $ScheduledTask2Fragment += "</tr>"
}

#Services
#$Services = Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Services = Get-Service | Select-Object -Property DisplayName, ServiceName, Status, StartType, @{Name = 'StartName'; Expression = { $_.StartName } }, @{Name = 'Description'; Expression = { (Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").Description } }

foreach ($process in $Services) {
  $ServicesFragment += "<tr>"
  $ServicesFragment += "<td>$($process.ServiceName)</td>"
  $ServicesFragment += "<td>$($process.DisplayName)</td>"
  $ServicesFragment += "<td>$($process.Status)</td>"
  $ServicesFragment += "<td>$($process.StartType)</td>"
  $ServicesFragment += "<td>$($process.Description)</td>"
  $ServicesFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Settings from the Registry			     #
##################################################

Write-Host -Fore DarkCyan "[*] Checking Registry for persistance"

$RegRun = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$RegRunOnce = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$RegRunOnceEx = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

Write-Host -Fore Cyan "[!] Done"

#endregion


##################################################
#region Checking other worthwhiles			     #
##################################################

Write-Host -Fore DarkCyan "[*] Running Peripheral Checks..."

#Logical drives (current session)
#$LogicalDrives = get-wmiobject win32_logicaldisk | Select-Object DeviceID, DriveType, FreeSpace, Size, VolumeName | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$LogicalDrives = get-wmiobject win32_logicaldisk | Select-Object DeviceID, DriveType, FreeSpace, Size, VolumeName
# Populate the HTML table with process information
foreach ($process in $LogicalDrives) {
  $LogicalDrivesFragment += "<tr>"
  $LogicalDrivesFragment += "<td>$($process.DeviceID)</td>"
  $LogicalDrivesFragment += "<td>$($process.DriveType)</td>"
  $LogicalDrivesFragment += "<td>$($process.FreeSpace)</td>"
  $LogicalDrivesFragment += "<td>$($process.Size)</td>"
  $LogicalDrivesFragment += "<td>$($process.VolumeName)</td>"
  $LogicalDrivesFragment += "</tr>"
}

#Gets list of USB devices
#$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select-Object FriendlyName, Driver, mfg, DeviceDesc | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1 
$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select-Object FriendlyName, Driver, mfg, DeviceDesc
# Populate the HTML table with process information
foreach ($process in $USBDevices) {
  $USBDevicesFragment += "<tr>"
  $USBDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $USBDevicesFragment += "<td>$($process.Driver)</td>"
  $USBDevicesFragment += "<td>$($process.mfg)</td>"
  $USBDevicesFragment += "<td>$($process.DeviceDesc)</td>"
  $USBDevicesFragment += "</tr>"
}

#Identifies any connected/previously connected webcams
#$Imagedevice = Get-PnpDevice  -class 'image' -EA SilentlyContinue |  ConvertTo-Html -Fragment
#$Imagedevice = Get-WmiObject Win32_PnPEntity | Where-Object { $_.caption -match 'camera' } -EA SilentlyContinue | Where-Object caption -match 'camera' | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Imagedevice = Get-WmiObject Win32_PnPEntity | Where-Object { $_.caption -match 'camera' } -EA SilentlyContinue | Where-Object caption -match 'camera' | Select-Object Caption, CreationClassName, Description, DeviceID, InstallDate, Manufacturer, Present, Status, SystemCreationClassName, SystemName
foreach ($process in $Imagedevice) {
  $ImagedeviceFragment += "<tr>"
  $ImagedeviceFragment += "<td>$($process.Caption)</td>"
  $ImagedeviceFragment += "<td>$($process.CreationClassName)</td>"
  $ImagedeviceFragment += "<td>$($process.Description)</td>"
  $ImagedeviceFragment += "<td>$($process.DeviceID)</td>"
  $ImagedeviceFragment += "<td>$($process.InstallDate)</td>"
  $ImagedeviceFragment += "<td>$($process.Manufacturer)</td>"
  $ImagedeviceFragment += "<td>$($process.Present)</td>"
  $ImagedeviceFragment += "<td>$($process.Status)</td>"
  $ImagedeviceFragment += "<td>$($process.SystemCreationClassName)</td>"
  $ImagedeviceFragment += "<td>$($process.SystemName)</td>"
  $ImagedeviceFragment += "</tr>"
}

#All currently connected PNP devices
#$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | Select-Object Status, Class, FriendlyName
# Populate the HTML table with process information
foreach ($process in $UPNPDevices) {
  $UPNPDevicesFragment += "<tr>"
  $UPNPDevicesFragment += "<td>$($process.Status)</td>"
  $UPNPDevicesFragment += "<td>$($process.Class)</td>"
  $UPNPDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $UPNPDevicesFragment += "</tr>"
}

#All previously connected disk drives not currently accounted for. Useful if target computer has had drive replaced/hidden
#$UnknownDrives = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select-Object FriendlyName | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$UnknownDrives = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select-Object FriendlyName
# Populate the HTML table with process information
foreach ($process in $UnknownDrives) {
  $UnknownDrivesFragment += "<tr>"
  $UnknownDrivesFragment += "<td>$($process.FriendlyName)</td>"
  $UnknownDrivesFragment += "</tr>"
}

#Gets all link files created in last 180 days. Perhaps export this as a separate CSV and make it keyword searchable?
#$LinkFiles = Get-WmiObject Win32_ShortcutFile | Select-Object Filename, Caption, @{NAME = 'CreationDate'; Expression = { $_.ConvertToDateTime($_.CreationDate) } }, @{Name = 'LastAccessed'; Expression = { $_.ConvertToDateTime($_.LastAccessed) } }, @{Name = 'LastModified'; Expression = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.LastModified -gt ((Get-Date).AddDays(-180)) } | Sort-Object LastModified -Descending | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#$LinkFiles = Get-WmiObject Win32_ShortcutFile | Select-Object Filename, Caption, @{NAME = 'CreationDate'; Expression = { $_.ConvertToDateTime($_.CreationDate) } }, @{Name = 'LastAccessed'; Expression = { $_.ConvertToDateTime($_.LastAccessed) } }, @{Name = 'LastModified'; Expression = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.LastModified -gt ((Get-Date).AddDays(-180)) } | Sort-Object LastModified -Descending
$LinkFiles = Get-CimInstance Win32_ShortcutFile | Select-Object Name, FileName, CreationDate, LastAccessed, Drive, Path, FileType
# Populate the HTML table with process information
foreach ($process in $LinkFiles) {
  $LinkFilesFragment += "<tr>"
  $LinkFilesFragment += "<td>$($process.Name)</td>"
  $LinkFilesFragment += "<td>$($process.FileName)</td>"
  $LinkFilesFragment += "<td>$($process.CreationDate)</td>"
  $LinkFilesFragment += "<td>$($process.LastAccessed)</td>"
  $LinkFilesFragment += "<td>$($process.Drive)</td>"
  $LinkFilesFragment += "<td>$($process.Path)</td>"
  $LinkFilesFragment += "<td>$($process.FileType)</td>"
  $LinkFilesFragment += "</tr>"
}

#Gets last 100 days worth of Powershell History
#$PSHistory = Get-History -count 500 | Select-Object id, commandline, startexecutiontime, endexecutiontime | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$PSHistory = Get-History -count 500 | Select-Object id, commandline, startexecutiontime, endexecutiontime
# Populate the HTML table with process information
foreach ($process in $PSHistory) {
  $PSHistoryFragment += "<tr>"
  $PSHistoryFragment += "<td>$($process.id)</td>"
  $PSHistoryFragment += "<td>$($process.commandline)</td>"
  $PSHistoryFragment += "<td>$($process.startexecutiontime)</td>"
  $PSHistoryFragment += "<td>$($process.endexecutiontime)</td>"
  $PSHistoryFragment += "</tr>"
}

#All execs in Downloads folder. This may cause an error if the script is run from an external USB or Network drive.
#$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }
# Populate the HTML table with process information
foreach ($process in $Downloads) {
  $DownloadsFragment += "<tr>"
  $DownloadsFragment += "<td>$($process.PSChildName)</td>"
  $DownloadsFragment += "<td>$($process.Root)</td>"
  $DownloadsFragment += "<td>$($process.Name)</td>"
  $DownloadsFragment += "<td>$($process.FullName)</td>"
  $DownloadsFragment += "<td>$($process.Extension)</td>"
  $DownloadsFragment += "<td>$($process.CreationTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.Attributes)</td>"
  $DownloadsFragment += "</tr>"
}

#Executables Running From Obscure Places
#$HiddenExecs1 = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs1 = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }
# Populate the HTML table with process information
foreach ($process in $HiddenExecs1) {
  $HiddenExecs1Fragment += "<tr>"
  $HiddenExecs1Fragment += "<td>$($process.PSChildName)</td>"
  $HiddenExecs1Fragment += "<td>$($process.Root)</td>"
  $HiddenExecs1Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs1Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs1Fragment += "<td>$($process.Extension)</td>"
  $HiddenExecs1Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs1Fragment += "</tr>"
}

#$HiddenExecs2 = Get-ChildItem C:\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs2 = Get-ChildItem C:\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }
# Populate the HTML table with process information
foreach ($process in $HiddenExecs2) {
  $HiddenExecs2Fragment += "<tr>"
  $HiddenExecs2Fragment += "<td>$($process.PSChildName)</td>"
  $HiddenExecs2Fragment += "<td>$($process.Root)</td>"
  $HiddenExecs2Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs2Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs2Fragment += "<td>$($process.Extension)</td>"
  $HiddenExecs2Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs2Fragment += "</tr>"
}

#$HiddenExecs3 = Get-ChildItem C:\PerfLogs\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs3 = Get-ChildItem C:\PerfLogs\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }
# Populate the HTML table with process information
foreach ($process in $HiddenExecs3) {
  $HiddenExecs3Fragment += "<tr>"
  $HiddenExecs3Fragment += "<td>$($process.PSChildName)</td>"
  $HiddenExecs3Fragment += "<td>$($process.Root)</td>"
  $HiddenExecs3Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs3Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs3Fragment += "<td>$($process.Extension)</td>"
  $HiddenExecs3Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs3Fragment += "</tr>"
}

#$HiddenExecs4 = Get-ChildItem C:\Users\*\Documents\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs4 = Get-ChildItem C:\Users\*\Documents\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }
# Populate the HTML table with process information
foreach ($process in $HiddenExecs4) {
  $HiddenExecs4Fragment += "<tr>"
  $HiddenExecs4Fragment += "<td>$($process.PSChildName)</td>"
  $HiddenExecs4Fragment += "<td>$($process.Root)</td>"
  $HiddenExecs4Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs4Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs4Fragment += "<td>$($process.Extension)</td>"
  $HiddenExecs4Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs4Fragment += "</tr>"
}

#endregion

###########################################################################################################
#region #######  VIEW USER GP RESULTS    ##################################################################
###########################################################################################################
# get GPO REsult if on domain

if ((gwmi win32_computersystem).partofdomain -eq $true) {
    
  Write-Host -Fore DarkCyan "[*] Collecting GPO Results"
  GPRESULT /H GPOReport.html /F
  Write-Host -Fore Cyan "[!] Done"
}
else {
  Write-Host -Fore Cyan "[!] Computer is not joined to a domain...moving on"
}



#endregion


###########################################################################################################
#region  MEMORY (RAM) CAPTURE    ##########################################################################
###########################################################################################################


if ($RAM) {
  # capture the RAM
  mkdir RAM | Out-Null
  Write-Host -Fore DarkCyan "[*] Capturing The RAM"
	
  if ((gwmi win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit") {
    
    & $PSScriptRoot\Forensicator-Share\winpmem_mini_x64_rc2.exe RAM\$env:computername.raw | Out-Null

    Write-Host -Fore Cyan "[!] Done"
	
  }
  else {
    
    & $PSScriptRoot\Forensicator-Share\winpmem_mini_x86.exe RAM\$env:computername.raw | Out-Null

    Write-Host -Fore Cyan "[!] Done"

  }
   
   
} 
else {

}

#endregion


###########################################################################################################
#region  BROWSER NIRSOFT                ###################################################################
###########################################################################################################
if ($BROWSER) {

  Write-Host -Fore DarkCyan "[*] Extracting Browser History"

  #GETTING BROWSING History
  if ((gwmi win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit") {
    
    & $PSScriptRoot\Forensicator-Share\BrowsingHistoryView64.exe /sverhtml "BrowserHistory.html" /SaveDirect /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1

  }
  else {
    
    & $PSScriptRoot\Forensicator-Share\BrowsingHistoryView86.exe /sverhtml "BrowserHistory.html" /SaveDirect /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1

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
		

mkdir BROWSING_HISTORY | Out-Null


# path to the malicious URLs file
$maliciousUrlsFilePath = "$PSScriptRoot\Forensicator-Share\malicious_URLs.txt"

# Loading the malicious URLs
$maliciousUrls = Get-Content -Path $maliciousUrlsFilePath

# check URLs against the malicious list
function Check-MaliciousUrl {
    param (
        [string]$url
    )
    return $maliciousUrls -contains $url
}

# convert Firefox timestamp to human-readable format
function Convert-FirefoxTime {
    param (
        [long]$firefoxTime
    )
    $epoch = [datetime]'1970-01-01'
    $humanReadableTime = $epoch.AddSeconds($firefoxTime / 1000000)
    return $humanReadableTime.ToString("yyyy-MM-dd HH:mm:ss")
}

# process Chrome history
function Process-ChromeHistory {
    param (
        [string]$user
    )

    $chromeHistoryPath = "$($user)\AppData\Local\Google\Chrome\User Data\Default\History"
    if (-not (Test-Path -Path $chromeHistoryPath)) {
        Write-Verbose "[!] Could not find Chrome History for username: $user"
        return
    }

    $query = "SELECT url, datetime(last_visit_time/1000000-11644473600,'unixepoch') as chromeTime FROM urls"
    $sqlitePath = "$PSScriptRoot\Forensicator-Share\sqlite3.exe"
    $urls = & $sqlitePath $chromeHistoryPath $query

    $history = @()
    $maliciousMatches = @()
    foreach ($entry in $urls) {
        $splitEntry = $entry -split "\|"
        $url = $splitEntry[0]

        $chromeTime = $splitEntry[1]


        $historyEntry = @{
            User          = $user
            Browser       = 'Chrome'
            DataType      = 'History'
            URL           = $url
            #LastVisitTime = $lastVisitTime
            LastVisitTime = $chromeTime
            IsMalicious   = Check-MaliciousUrl -url $url
        }
        $history += $historyEntry

        if ($historyEntry.IsMalicious) {
            $maliciousMatches += $historyEntry
        }
    }

    $outputHistoryFilePath = "BROWSING_HISTORY\Chrome_History_of_$($user.Split('\')[-1]).txt"
    $history | ForEach-Object {
        $_ | Out-String
    } | Out-File $outputHistoryFilePath

    if ($maliciousMatches.Count -gt 0) {
        $outputMaliciousFilePath = "BROWSING_HISTORY\Malicious_Chrome_History_of_$($user.Split('\')[-1]).txt"
        $maliciousMatches | ForEach-Object {
            $_ | Out-String
        } | Out-File $outputMaliciousFilePath
    }
}

# process Firefox history
function Process-FirefoxHistory {
    param (
        [string]$user
    )

    $firefoxProfilesPath = "$($user)\AppData\Roaming\Mozilla\Firefox\Profiles\"
    if (-not (Test-Path -Path $firefoxProfilesPath)) {
        Write-Verbose "[!] Could not find Firefox profiles for username: $user"
        return
    }

    $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory
    foreach ($profile in $profiles) {
        $firefoxHistoryPath = "$($profile.FullName)\places.sqlite"
        if (-not (Test-Path -Path $firefoxHistoryPath)) {
            Write-Verbose "[!] Could not find Firefox History for profile: $($profile.Name)"
            continue
        }

        $query = "SELECT url, last_visit_date FROM moz_places"
        $sqlitePath = "$PSScriptRoot\Forensicator-Share\sqlite3.exe"
        $urls = & $sqlitePath $firefoxHistoryPath $query

        $history = @()
        $maliciousMatches = @()
        foreach ($entry in $urls) {
            $splitEntry = $entry -split "\|"
            $url = $splitEntry[0]
            $lastVisitTimeRaw = [long]$splitEntry[1]
            $lastVisitTime = Convert-FirefoxTime -firefoxTime $lastVisitTimeRaw

            $historyEntry = @{
                User          = $user
                Browser       = 'Firefox'
                DataType      = 'History'
                URL           = $url
                LastVisitTime = $lastVisitTime
                IsMalicious   = Check-MaliciousUrl -url $url
            }
            $history += $historyEntry

            if ($historyEntry.IsMalicious) {
                $maliciousMatches += $historyEntry
            }
        }

        $outputHistoryFilePath = "BROWSING_HISTORY\Firefox_History_of_$($user.Split('\')[-1])_$($profile.Name).txt"
        $history | ForEach-Object {
            $_ | Out-String
        } | Out-File $outputHistoryFilePath

        if ($maliciousMatches.Count -gt 0) {
            $outputMaliciousFilePath = "BROWSING_HISTORY\Malicious_Firefox_History_of_$($user.Split('\')[-1])_$($profile.Name).txt"
            $maliciousMatches | ForEach-Object {
                $_ | Out-String
            } | Out-File $outputMaliciousFilePath
        }
    }
}

# process Edge history
function Process-EdgeHistory {
    param (
        [string]$user
    )

    $edgeHistoryPath = "$($user)\AppData\Local\Microsoft\Edge\User Data\Default\History"
    if (-not (Test-Path -Path $edgeHistoryPath)) {
        Write-Verbose "[!] Could not find Edge History for username: $user"
        return
    }

    $query = "SELECT url, last_visit_time FROM urls"
    $sqlitePath = "$PSScriptRoot\Forensicator-Share\sqlite3.exe"
    $urls = & $sqlitePath $edgeHistoryPath $query

    $history = @()
    $maliciousMatches = @()
    foreach ($entry in $urls) {
        $splitEntry = $entry -split "\|"
        $url = $splitEntry[0]
        $lastVisitTimeRaw = [long]$splitEntry[1]
        $lastVisitTime = Convert-ChromeTime -chromeTime $lastVisitTimeRaw

        $historyEntry = @{
            User          = $user
            Browser       = 'Edge'
            DataType      = 'History'
            URL           = $url
            LastVisitTime = $lastVisitTime
            IsMalicious   = Check-MaliciousUrl -url $url
        }
        $history += $historyEntry

        if ($historyEntry.IsMalicious) {
            $maliciousMatches += $historyEntry
        }
    }

    $outputHistoryFilePath = "BROWSING_HISTORY\Edge_History_of_$($user.Split('\')[-1]).txt"
    $history | ForEach-Object {
        $_ | Out-String
    } | Out-File $outputHistoryFilePath

    if ($maliciousMatches.Count -gt 0) {
        $outputMaliciousFilePath = "BROWSING_HISTORY\Malicious_Edge_History_of_$($user.Split('\')[-1]).txt"
        $maliciousMatches | ForEach-Object {
            $_ | Out-String
        } | Out-File $outputMaliciousFilePath
    }
}

# process Internet Explorer history
function Process-IEHistory {
    param (
        [string]$user
    )

    $userSid = (New-Object System.Security.Principal.NTAccount($user.Split('\')[-1])).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $ieHistoryPath = "HKU:\$userSid\Software\Microsoft\Internet Explorer\TypedURLs"
    if (-not (Test-Path -Path $ieHistoryPath)) {
        Write-Verbose "[!] Could not find IE History for username: $user"
        return
    }

    $history = @()
    $maliciousMatches = @()
    $key = Get-Item -Path $ieHistoryPath
    foreach ($valueName in $key.GetValueNames()) {
        $url = $key.GetValue($valueName)
        $historyEntry = @{
            User          = $user
            Browser       = 'Internet Explorer'
            DataType      = 'History'
            URL           = $url
            LastVisitTime = "N/A"  # IE does not store visit time in TypedURLs
            IsMalicious   = Check-MaliciousUrl -url $url
        }
        $history += $historyEntry

        if ($historyEntry.IsMalicious) {
            $maliciousMatches += $historyEntry
        }
    }

    $outputHistoryFilePath = "BROWSING_HISTORY\IE_History_of_$($user.Split('\')[-1]).txt"
    $history | ForEach-Object {
        $_ | Out-String
    } | Out-File $outputHistoryFilePath

    if ($maliciousMatches.Count -gt 0) {
        $outputMaliciousFilePath = "BROWSING_HISTORY\Malicious_IE_History_of_$($user.Split('\')[-1]).txt"
        $maliciousMatches | ForEach-Object {
            $_ | Out-String
        } | Out-File $outputMaliciousFilePath
    }
}

# Get all users
$users = Get-ChildItem $Env:SystemDrive\Users | Where-Object { $_.Name -notmatch 'Public|default' } | ForEach-Object { $_.FullName }

# Process browsing history for each user
foreach ($user in $users) {
    Process-ChromeHistory -user $user
    Process-FirefoxHistory -user $user
    Process-EdgeHistory -user $user
    Process-IEHistory -user $user
}

Write-Host -Fore Cyan "[!] Done"


} 

###########################################################################################################
#endregion   BROWSER INBUILT                ###############################################################
###########################################################################################################	


###########################################################################################################
#region  CHECKING FOR RANSOMWARE ENCRYPTED FILES    #######################################################
###########################################################################################################

if ($RANSOMWARE) {
	
  Write-Host -Fore DarkCyan "[*] Checking For Ransomware Encrypted Files"
  Write-Host -Fore DarkCyan "[!] NOTE: This May Take a While Depending on the Number of Drives"

  #CHECKING FOR RANSOMWARE ENCRYPTED FILES
  # Read target file extensions from the YAML configuration file
  $configFile = "$PSScriptRoot\config.json"
  $configData = Get-Content $configFile | ConvertFrom-Json
  $ransomwareExtensions = $configData.Ransomeware_Extensions

  $Drives = Get-PSDrive -PSProvider 'FileSystem'

  foreach ($Drive in $drives) {

    $FindFiles = Get-ChildItem -Path $Drive.Root -File -Force -Recurse | Where-Object { $ransomwareExtensions -contains $_.Extension }  | Select-Object PSChildName, FullName, LastWriteTimeUTC, Extension #| ConvertTo-Html -Fragment 

  }

  # Populate the HTML table with process information
  foreach ($process in $FindFiles) {
    $FindFilesFragment += "<tr>"
    $FindFilesFragment += "<td>$($process.PSChildName)</td>"
    $FindFilesFragment += "<td>$($process.FullName)</td>"
    $FindFilesFragment += "<td>$($process.LastWriteTimeUTC)</td>"
    $FindFilesFragment += "<td>$($process.Extension)</td>"
    $FindFilesFragment += "</tr>"
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


  if ((gwmi win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit") {
    

    & $PSScriptRoot\Forensicator-Share\etl2pcapng64.exe PCAP\$env:computername.et1 PCAP\$env:computername.pcap
	
  }
  else {
    
    & $PSScriptRoot\Forensicator-Share\etl2pcapng86.exe PCAP\$env:computername.et1 PCAP\$env:computername.pcap

  }

  Write-Host -Fore Cyan "[!] Done"


   
} 
else {
		

}

#endregion


###########################################################################################################
#region  Export Event Logs       ##########################################################################
###########################################################################################################



if ($EVTX) {
	
  Write-Host -Fore DarkCyan "[*] Gettting hold of some event logs"
   
  # capture the EVENTLOGS
  # Logs to extract from server
  $logArray = @("System", "Security", "Application")

  # Grabs the server name to append to the log file extraction
  $servername = $env:computername

  # Provide the path with ending "\" to store the log file extraction.
  $destinationpath = "EVTLOGS\"

  # If the destination path does not exist it will create it
  if (!(Test-Path -Path $destinationpath)) {
	
    New-Item -ItemType directory -Path $destinationpath | Out-Null
  }

  # Get the current date in YearMonthDay format
  $logdate = Get-Date -format yyyyMMddHHmm

  # Start Process Timer
  $StopWatch = [system.diagnostics.stopwatch]::startNew()


  Foreach ($log in $logArray) {
	
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
  if (!(Get-ChildItem C:\inetpub\logs\ *.log)) {
    Write-Host -Fore DarkCyan "[!] Cannot find any logs in IIS Log Directory"
  }
  else {
	
    #create IIS log Dirs
    mkdir IISLogs | Out-Null

    Copy-Item -Path 'C:\inetpub\logs\*' -Destination 'IISLogs' -Recurse | Out-Null

	
  }


  #checking for Tomcat and try to get log files


  mkdir TomCatLogs | Out-Null
  # Define the destination directory where you want to copy the logs
  $destinationDirectory = "$GetLoc\TomCatLogs"

  # Check if Tomcat is installed by checking the registry
  $regKey = "HKLM:\SOFTWARE\Apache Software Foundation\Tomcat"
  if (Test-Path $regKey) {
    Write-Host "Tomcat is installed. Proceeding with log file copy."
    
    # Get Tomcat installation directory from registry
    $tomcatInstallDir = (Get-ItemProperty -Path $regKey).InstallPath

    # Construct the source directory for Tomcat logs
    $sourceDirectory = Join-Path -Path $tomcatInstallDir -ChildPath "logs"

    # Check if the logs directory exists
    if (Test-Path $sourceDirectory) {
      # Create the destination directory if it doesn't exist
      if (-not (Test-Path $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory | Out-Null
      }

      # Copy the Tomcat log files to the destination directory
      Copy-Item -Path "$sourceDirectory\*.log" -Destination $destinationDirectory -Force -Recurse
        
      Write-Host "TomCat Log files copied successfully to $destinationDirectory"
    }
    else {
      Write-Host "Tomcat logs directory not found. Cannot proceed with log file copy."
    }
  }
  else {
    Write-Host "Tomcat is not installed. Cannot proceed with log file copy."
  }


} 
else {

}

#endregion


#############################################################################################################
#region   View Log4j Paths        ###########################################################################
#############################################################################################################

if ($LOG4J) {
   
  Write-Host -Fore DarkCyan "[*] Checking for log4j on all drives .....this may take a while."

  mkdir LOG4J | Out-Null	
  # Checking for Log4j
  $DriveList = (Get-PSDrive -PSProvider FileSystem).Root
  ForEach ($Drive In $DriveList) {
    $Log4j = Get-ChildItem $Drive -rec -force -include *.jar -ea 0 | ForEach-Object { select-string 'JndiLookup.class' $_ } | Select-Object -exp Path | Out-File LOG4J\$env:computername.txt

  }
   
  Write-Host -Fore Cyan "[!] Done"
   
   
} 
else {

}

#endregion



#############################################################################################################
#region   Checking File Hashes for Malware        ###########################################################
#############################################################################################################

if ($HASHCHECK) {
  
  Write-Host -Fore DarkCyan "[*] Starting Hash lookup."

  # Define the path to the configuration file
  $configFile = "$PSScriptRoot\config.json"

  # Read and parse the configuration file
  $configData = Get-Content $configFile | ConvertFrom-Json

  # Get the executable extensions and hash source URL from the configuration
  $ExecExtensions = $configData.executables_extensions
  $hashsource = $configData.hash_source

  # Define the directory to scan
  #$directory = "C:\"  # Replace with your actual directory
  #$Drives = Get-PSDrive -PSProvider 'FileSystem'

  # Define the path to save the downloaded hash file
  $hashFilePath = "$PSScriptRoot\Forensicator-Share\md5hashes.txt"

  # Function to compute MD5 hash of a file
  function Get-FileMD5 {
    param (
      [string]$filePath
    )
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $hashBytes = $md5.ComputeHash($fileStream)
    $fileStream.Close()
    return ([BitConverter]::ToString($hashBytes) -replace "-", "").ToLower()
  }

  # Download the MD5 hash file if it does not exist
  if (-Not (Test-Path $hashFilePath)) {
    Write-Host -Fore DarkCyan "[*] Hash file not found in Forensicator-Share"
    Write-Host -Fore DarkCyan "[*] I will attempt to download it."

    if ((Test-NetConnection bazaar.abuse.ch -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) {
      Write-Host -Fore DarkCyan "[*] Downloading..."
      Invoke-WebRequest -Uri $hashsource -OutFile $hashFilePath
    }
    else {
      Write-Host -Fore DarkCyan "[*] bazaar.abuse.ch is not reachable, please check your connection"
      Write-Host -Fore DarkCyan "[*] Moving on..."
    }
  }
  else {
    Write-Host -Fore Cyan "[!] I will use the hashfile provided..."
  }

  # Read the downloaded MD5 hashes
  $downloadedHashes = Get-Content $hashFilePath

  # Get the MD5 hashes of the specified files in the directory
  $localHashes = @()
  foreach ($ExecExtension in $ExecExtensions) {
    #$files = Get-ChildItem -Path $directory -Filter $ExecExtension -Recurse
    $files = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Get-ChildItem -Path $_.Root -Filter $ExecExtension -Recurse -ErrorAction SilentlyContinue }
    foreach ($file in $files) {
      $hash = Get-FileMD5 -filePath $file.FullName
      $localHashes += [PSCustomObject]@{
        FileName = $file.FullName
        MD5Hash  = $hash
      }
    }
  }

  # Compare local hashes with downloaded hashes and output matches
  $hashmatch = @()
  foreach ($localHash in $localHashes) {
    if ($downloadedHashes -contains $localHash.MD5Hash) {
      $hashmatch += [PSCustomObject]@{
        DetectedFile     = $localHash.FileName
        OriginalFileHash = $localHash.MD5Hash
        MatchingMD5      = ($downloadedHashes | Where-Object { $_ -eq $localHash.MD5Hash })
      }
    }
  }

  # Output the matches

  mkdir HashMatches | Out-Null
  $HashMatchFilePath = "HashMatches\MalwareHashMatch.txt"
  if ($hashmatch.Count -gt 0) {
    $hashmatch | Format-Table -AutoSize | Out-File $HashMatchFilePath
    #$hashmatch | ConvertTo-Html -As LIST -fragment
  }
  else {
    Write-Output "No matches found." | Out-File $HashMatchFilePath
  }


} 
else {

}

Write-Host -Fore Cyan "[!] Done."

#endregion




#####################################################################################################################
######################################################################################################################
#region     EVENT LOG ANALYSIS SECTION		     	     #################################################################
######################################################################################################################
######################################################################################################################

Write-Host -Fore DarkYellow "[*] Performing Some EventLog Analysis"

Write-Host -Fore DarkPink "[!] User Related Activity Probes"


##### USER RELATED CHECKS ##########

###############################################################################
### Enumerated a User's Group Membership        ###############################
###############################################################################

Write-Host -Fore DarkCyan "[*] Checking Enumerated Users"

$GroupMembershipID = @(
  '4798'

)
$GroupMembershipFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $GroupMembershipID }
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
    Time        = [DateTime]$GroupMembershipEventXml.System.TimeCreated.SystemTime
    PerformedOn = $GroupMembershipEnumAccount
    PerformedBy = $GroupMembershipPerformedBy
    LogonType   = $GroupMembershipPerformedLogon
    PID         = $GroupMembershipPerformedPID
    ProcessName = $GroupMembershipPerformedPName
  }
} 

# Populate the HTML table with process information
foreach ($process in $GroupMembership) {
  $GroupMembershipFragment += "<tr>"
  $GroupMembershipFragment += "<td>$([DateTime]$GroupMembershipEventXml.System.TimeCreated.SystemTime)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipEnumAccount)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipPerformedBy)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipPerformedLogon)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipPerformedPID)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipPerformedPName)</td>"
  $GroupMembershipFragment += "</tr>"
}


Write-Host -Fore Cyan "[!] Done"

###############################################################################
### RDP Logins                        #########################################
###############################################################################

Write-Host -Fore DarkCyan "[*] Fetching RDP Logons"

$RDPGroupID = @(
  '4624,4778'
)

$RDPFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $RDPGroupID } 
$RDPLogins = Get-WinEvent -FilterHashtable $RDPFilter | Where-Object { $_.properties[8].value -eq 10 } | ForEach-Object {
  # convert the event to XML and grab the Event node
  $RDPEventXml = ([xml]$_.ToXml()).Event
  $RDPLogonUser = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $RDPLogonUserDomain = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
  $RDPLogonIP = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time            = [DateTime]$RDPEventXml.System.TimeCreated.SystemTime
    LogonUser       = $RDPLogonUser
    LogonUserDomain = $RDPLogonUserDomain
    LogonIP         = $RDPLogonIP
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1


# Populate the HTML table with process information
foreach ($process in $RDPLogins) {
  $RDPLoginsFragment += "<tr>"
  $RDPLoginsFragment += "<td>$([DateTime]$RDPEventXml.System.TimeCreated.SystemTime)</td>"
  $RDPLoginsFragment += "<td>$($RDPLogonUser)</td>"
  $RDPLoginsFragment += "<td>$($RDPLogonUserDomain)</td>"
  $RDPLoginsFragment += "<td>$($RDPLogonIP)</td>"
  $RDPLoginsFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"

###############################################################################
### RDP Logins All History            #########################################
###############################################################################

Write-Host -Fore DarkCyan "[*] Fetching History of All RDP Logons to this system"

$RDPGroupID = @(
  '1149'
)

$RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
[xml[]]$xml = $RDPAuths | ForEach-Object { $_.ToXml() }
$EventData = Foreach ($event in $xml.Event) {
  New-Object PSObject -Property @{
    TimeCreated = (Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K')
    User        = $event.UserData.EventXML.Param1
    Domain      = $event.UserData.EventXML.Param2
    Client      = $event.UserData.EventXML.Param3
  }
} #$EventData | FT

# Populate the HTML table with process information
foreach ($process in $EventData) {
  $RDPAuthsFragment += "<tr>"
  $RDPAuthsFragment += "<td>$((Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K'))</td>"
  $RDPAuthsFragment += "<td>$($event.UserData.EventXML.Param1)</td>"
  $RDPAuthsFragment += "<td>$($event.UserData.EventXML.Param2)</td>"
  $RDPAuthsFragment += "<td>$($event.UserData.EventXML.Param3)</td>"
  $RDPAuthsFragment += "</tr>"
}


Write-Host -Fore Cyan "[!] Done"

###############################################################################
### Outgoing RDP Connections            #########################################
###############################################################################

Write-Host -Fore DarkCyan "[*] Fetching All outgoing RDP connection History"


# Define the properties array properly
$properties = @(
  @{n = 'TimeStamp'; e = { $_.TimeCreated } }
  @{n = 'LocalUser'; e = { [System.Security.Principal.SecurityIdentifier]::new($_.UserID).Translate([System.Security.Principal.NTAccount]).Value } }
  @{n = 'Target RDP host'; e = { $_.Properties[1].Value } }
)

# Retrieve the events
$OutRDP = Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; ID = '1102' } | Select-Object $properties

# Initialize the HTML fragment
$OutRDPFragment = ""

# Populate the HTML table with event information
foreach ($event in $OutRDP) {
  $OutRDPFragment += "<tr>"
  $OutRDPFragment += "<td>$($event.TimeStamp)</td>"
  $OutRDPFragment += "<td>$($event.LocalUser)</td>"
  $OutRDPFragment += "<td>$($event.'Target RDP host')</td>"  
  $OutRDPFragment += "</tr>"
}


Write-Host -Fore Cyan "[!] Done"

###############################################################################
### Created Users                 #############################################
###############################################################################


Write-Host -Fore DarkCyan "[*] Fetching Created Users"

$CreatedUsersGroupID = @(
  '4720'
)

$CreatedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CreatedUsersGroupID }
$CreatedUsers = Get-WinEvent -FilterHashtable $CreatedUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CreatedUsersEventXml = ([xml]$_.ToXml()).Event
  $CreatedUser = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $CreatedUsersTarget = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time        = [DateTime]$CreatedUsersEventXml.System.TimeCreated.SystemTime
    CreatedUser = $CreatedUser
    CreatedBy   = $CreatedUsersTarget
  }
} # | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $CreatedUsers) {
  $CreatedUsersFragment += "<tr>"
  $CreatedUsersFragment += "<td>$([DateTime]$CreatedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $CreatedUsersFragment += "<td>$($CreatedUser)</td>"
  $CreatedUsersFragment += "<td>$($CreatedUsersTarget)</td>"  
  $CreatedUsersFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"


###############################################################################
### Password Resets               #############################################
###############################################################################


Write-Host -Fore DarkCyan "[*] Checking for password resets"

$PassResetGroupID = @(
  '4724'
)

$PassResetFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $PassResetGroupID }
$PassReset = Get-WinEvent -FilterHashtable $PassResetFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $PassResetEventXml = ([xml]$_.ToXml()).Event
  $PassResetTargetUser = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $PassResetActionedBy = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = [DateTime]$PassResetEventXml.System.TimeCreated.SystemTime
    TargetUser = $PassResetTargetUser
    ActionedBy = $PassResetActionedBy
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $PassReset) {
  $PassResetFragment += "<tr>"
  $PassResetFragment += "<td>$([DateTime]$PassResetEventXml.System.TimeCreated.SystemTime)</td>"
  $PassResetFragment += "<td>$($PassResetTargetUser)</td>"
  $PassResetFragment += "<td>$($PassResetActionedBy)</td>"  
  $PassResetFragment += "</tr>"
}

Write-Host -Fore Cyan "[!] Done"


###############################################################################
### Added users to Group          #############################################
###############################################################################
Write-Host -Fore DarkCyan "[*] Checking for user, group, object access and credential manager actions"

$AddedUsersGroupID = @(
  '4732',
  '4728'
)
$AddedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $AddedUsersGroupID }
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
    Time    = [DateTime]$AddedUsersEventXml.System.TimeCreated.SystemTime
    AddedBy = $AddedUsersAddedBy
    Target  = $AddedUsersGobjUser
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $AddedUsers) {
  $AddedUsersFragment += "<tr>"
  $AddedUsersFragment += "<td>$([DateTime]$AddedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $AddedUsersFragment += "<td>$($AddedUsersAddedBy)</td>"
  $AddedUsersFragment += "<td>$($AddedUsersGobjUser)</td>"  
  $AddedUsersFragment += "</tr>"
}


###############################################################################
### Enabled Users                 #############################################
###############################################################################

$EnabledUsersGroupID = @(
  '4722'

)
$EnabledUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $EnabledUsersGroupID }
$EnabledUsers = Get-WinEvent -FilterHashtable $EnabledUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $EnabledUsersEventXml = ([xml]$_.ToXml()).Event
  $EnabledBy = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $EnabledTarget = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = [DateTime]$EnabledUsersEventXml.System.TimeCreated.SystemTime
    EnabledBy      = $EnabledBy
    EnabledAccount = $EnabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $EnabledUsers) {
  $EnabledUsersFragment += "<tr>"
  $EnabledUsersFragment += "<td>$([DateTime]$EnabledUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $EnabledUsersFragment += "<td>$($EnabledBy)</td>"
  $EnabledUsersFragment += "<td>$($EnabledTarget)</td>"  
  $EnabledUsersFragment += "</tr>"
}


###############################################################################
### Disabled Users                #############################################
###############################################################################

$DisabledUsersGroupID = @(
  '4723'

)
$DisabledUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $DisabledUsersGroupID }
$DisabledUsers = Get-WinEvent -FilterHashtable $DisabledUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DisabledUsersEventXml = ([xml]$_.ToXml()).Event
  $DisabledBy = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DisabledTarget = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = [DateTime]$DisabledUsersEventXml.System.TimeCreated.SystemTime
    DisabledBy = $DisabledBy
    Disabled   = $DisabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $DisabledUsers) {
  $DisabledUsersFragment += "<tr>"
  $DisabledUsersFragment += "<td>$([DateTime]$DisabledUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $DisabledUsersFragment += "<td>$($DisabledBy)</td>"
  $DisabledUsersFragment += "<td>$($DisabledTarget)</td>"  
  $DisabledUsersFragment += "</tr>"
}

###############################################################################
### Deleted Users                #############################################
###############################################################################

$DeletedUsersGroupID = @(
  '4726'

)
$DeletedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $DeletedUsersGroupID }
$DeletedUsers = Get-WinEvent -FilterHashtable $DeletedUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DeletedUsersEventXml = ([xml]$_.ToXml()).Event
  $DeletedBy = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DeletedTarget = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = [DateTime]$DeletedUsersEventXml.System.TimeCreated.SystemTime
    DeletedBy      = $DeletedBy
    DeletedAccount = $DeletedTarget
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $DeletedUsers) {
  $DeletedUsersFragment += "<tr>"
  $DeletedUsersFragment += "<td>$([DateTime]$DeletedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $DeletedUsersFragment += "<td>$($DeletedBy)</td>"
  $DeletedUsersFragment += "<td>$($DeletedTarget)</td>"  
  $DeletedUsersFragment += "</tr>"
}


###############################################################################
### Account Lockout               #############################################
###############################################################################

$LockOutGroupID = @(
  '4740'

)
$LockOutFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $LockOutGroupID }
$LockOut = Get-WinEvent -FilterHashtable $LockOutFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $LockOutEventXml = ([xml]$_.ToXml()).Event
  $LockedOutAcct = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $System = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$LockOutEventXml.System.TimeCreated.SystemTime
    LockedOutAccount = $LockedOutAcct
    System           = $System
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $LockOut) {
  $LockOutFragment += "<tr>"
  $LockOutFragment += "<td>$([DateTime]$LockOutEventXml.System.TimeCreated.SystemTime)</td>"
  $LockOutFragment += "<td>$($LockedOutAcct)</td>"
  $LockOutFragment += "<td>$($System)</td>"  
  $LockOutFragment += "</tr>"
}

###############################################################################
### Credential Manager Backup                   ###############################
###############################################################################

$CredManBackupGroupID = @(
  '5376'

)
$CredManBackupFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CredManBackupGroupID }
$CredManBackup = Get-WinEvent -FilterHashtable $CredManBackupFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManBackupEventXml = ([xml]$_.ToXml()).Event
  $CredManBackupAcct = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManBackupAcctLogon = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$CredManBackupEventXml.System.TimeCreated.SystemTime
    BackupAccount    = $CredManBackupAcct
    AccountLogonType = $CredManBackupAcctLogon

  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $CredManBackup) {
  $CredManBackupFragment += "<tr>"
  $CredManBackupFragment += "<td>$([DateTime]$CredManBackupEventXml.System.TimeCreated.SystemTime)</td>"
  $CredManBackupFragment += "<td>$($CredManBackupAcct)</td>"
  $CredManBackupFragment += "<td>$($CredManBackupAcctLogon)</td>"  
  $CredManBackupFragment += "</tr>"
}


###############################################################################
### Credential Manager Restore                  ###############################
###############################################################################

$CredManRestoreGroupID = @(
  '5377'

)
$CredManRestoreFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CredManRestoreGroupID }
$CredManRestore = Get-WinEvent -FilterHashtable $CredManRestoreFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManRestoreEventXml = ([xml]$_.ToXml()).Event
  $RestoredAcct = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManRestoreAcctLogon = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$CredManRestoreEventXml.System.TimeCreated.SystemTime
    RestoredAccount  = $RestoredAcct
    AccountLogonType = $CredManRestoreAcctLogon

  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $CredManRestore) {
  $CredManRestoreFragment += "<tr>"
  $CredManRestoreFragment += "<td>$([DateTime]$CredManRestoreEventXml.System.TimeCreated.SystemTime)</td>"
  $CredManRestoreFragment += "<td>$($RestoredAcct)</td>"
  $CredManRestoreFragment += "<td>$($CredManRestoreAcctLogon)</td>"  
  $CredManRestoreFragment += "</tr>"
}

#endregion




#############################################################################################################
#region   EVENT LOG ANALYSIS   LOGON EVENTS           #######################################################
#############################################################################################################


# SUCCESSFUL LOGON EVENTS

# Define variables for the event log name and event ID
$logName = "Security"
$eventID = 4624
#$eventID = 4625

# Query the event log for logon events
$logonEvents = Get-EventLog -LogName $logName -InstanceId $eventID -Newest 1000

# Create an array to hold the logon event details
$logonDetails = @()

# Loop through each logon event and extract the relevant details
foreach ($logonEvent in $logonEvents) {
  $eventProperties = [ordered]@{
    "Time"                   = $logonEvent.TimeGenerated
    "User"                   = $logonEvent.ReplacementStrings[5]
    "Logon Type"             = $logonEvent.ReplacementStrings[8]
    "Source Network Address" = $logonEvent.ReplacementStrings[18]
    "Status"                 = $logonEvent.ReplacementStrings[11]
  }
  $logonDetails += New-Object PSObject -Property $eventProperties
}

# Convert the logon details to HTML
#$Successhtml = $logonDetails #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $logonEvents) {
  $logonEventsFragment += "<tr>"
  $logonEventsFragment += "<td>$($logonEvent.TimeGenerated)</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[5])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[8])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[18])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[11])</td>"  
  $logonEventsFragment += "</tr>"
}


#endregion

#region
# FAILED LOGON EVENTS

# Define variables for the event log name and event ID
$logName = "Security"
#$eventID = 4624
$eventID = 4625

# Query the event log for logon events
$logonEventsFailed = Get-EventLog -LogName $logName -InstanceId $eventID -Newest 1000

# Create an array to hold the logon event details
$logonDetails = @()

# Loop through each logon event and extract the relevant details
foreach ($logonEvent in $logonEventsFailed) {
  $eventProperties = [ordered]@{
    "Time"                   = $logonEvent.TimeGenerated
    "User"                   = $logonEvent.ReplacementStrings[5]
    "Logon Type"             = $logonEvent.ReplacementStrings[8]
    "Source Network Address" = $logonEvent.ReplacementStrings[18]
    "Status"                 = $logonEvent.ReplacementStrings[11]
  }
  $logonDetails += New-Object PSObject -Property $eventProperties
}

# Convert the logon details to HTML
#$Failedhtml = $logonDetails | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

# Populate the HTML table with event information
foreach ($event in $logonEventsFailed) {
  $logonEventsFailedFragment += "<tr>"
  $logonEventsFailedFragment += "<td>$($logonEvent.TimeGenerated)</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[5])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[8])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[18])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[11])</td>"  
  $logonEventsFailedFragment += "</tr>"
}

#endregion


#############################################################################################################
#region   EVENT LOG ANALYSIS   OBJECT ACCESS          #######################################################
#############################################################################################################


# Define the start and end times for the query
$StartTime = (Get-Date).AddDays(-1000)
$EndTime = Get-Date

# Define the event log and event IDs to query
$EventLog = "Security"
$EventIDs = @(4656, 4663)

# Build the query string
$Query = @"
<QueryList>
  <Query Path='$EventLog'>
    <Select Path='$EventLog'>*[System[(EventID=$($EventIDs[0]) or EventID=$($EventIDs[1])) and TimeCreated[@SystemTime&gt;='$($StartTime.ToUniversalTime().ToString("o"))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString("o"))']]]</Select>
  </Query>
</QueryList>
"@

# Run the query and save the results to a variable
$Events = Get-WinEvent -FilterXml $Query

# Create an HTML table to display the results
$ObjectHtmlTable1 = "<thead><tr><th>Time</th><th>User</th><th>Object</th><th>Access Type</th></tr></thead>"
$ObjectHtmlTable1 += "<tbody>"
foreach ($Event in $Events) {
  $Properties = [ordered]@{
    Time       = $Event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
    User       = $Event.Properties[1].Value
    Object     = $Event.Properties[5].Value
    AccessType = $Event.Properties[10].Value
  }
  $Row = "<tr>" + ($Properties.Values | ForEach-Object { "<td>$_</td>" }) + "</tr>"
  $ObjectHtmlTable1 += $Row
}
$ObjectHtmlTable1 += "</tbody>"

#endregion

Write-Host -Fore Cyan "[!] Done"


#############################################################################################################
#region   EVENT LOG ANALYSIS   PROCESS EXECUTION      #######################################################
#############################################################################################################

Write-Host -Fore DarkCyan "[*] Checking for process executions"

# Define the start and end dates for the query
$startDate = (Get-Date).AddDays(-1000)
$endDate = Get-Date

# Query the event logs for process execution events within the specified time frame
$events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4688; StartTime = $startDate; EndTime = $endDate }


# Define the table header for the HTML output
$tableHeader = "<thead><tr><th>Time</th><th>Process Name</th><th>Process ID</th><th>User</th></tr></thead>"
$tableHeader2 += "<tbody>"
# Loop through each event and extract the relevant information
$tableBody = ""
foreach ($event in $events) {
  $time = $event.TimeCreated
  $processName = $event.Properties[5].Value
  $processID = $event.Properties[0].Value
  $user = $event.Properties[1].Value

  # Format the time as a string
  $timeString = $time.ToString("yyyy-MM-dd HH:mm:ss")

  # Add the event information to the table body
  $tableBody += "<tr><td>$timeString</td><td>$processName</td><td>$processID</td><td>$user</td></tr>"
}

# Define the table footer for the HTML output
$tableFooter = "</tbody>"

# Combine the table header, body, and footer into a single HTML string
$ObjectHtmlTable2 = $tableHeader + $tableHeader2 + $tableBody + $tableFooter

#endregion

Write-Host -Fore Cyan "[!] Done"

#############################################################################################################
#region   EVENT LOG ANALYSIS   SUSPICIOUS ACTIVITIES          ###############################################
#############################################################################################################
Write-Host -Fore DarkCyan "[*] Checking for suspecious activities from config.json and event IDs"

# Define the log name and severity levels
$logName = "Security"
$severityLevels = @{
  16 = "Critical"
  8  = "Error"
  4  = "Warning"
  2  = "Information"
}

# Get suspicious executables and PowerShell commands from config.json
$json = Get-Content -Raw -Path "$PSScriptRoot\config.json" | ConvertFrom-Json
$suspiciousExecutables = $json.suspicious_executables -join "|"
$suspiciousPSCommands = $json.suspicious_PS_commands -join "|"

# Define the combined regular expression pattern
$pattern = "($suspiciousExecutables)|($suspiciousPSCommands)"

# Get the event log entries
$entries = Get-WinEvent -LogName $logName -MaxEvents 5000 | Where-Object { $_.Id -eq 4625 -or $_.Id -eq 4672 -or ($_.Id -eq 4688 -and $_.Message -match $pattern) }

# Initialize the fragment variable
$maliciousEventsFragment = ""

# Format the malicious events into HTML table rows
foreach ($event in $entries) {
  $maliciousEventsFragment += "<tr>"
  $maliciousEventsFragment += "<td>$($severityLevels[$event.Level])</td>"
  $maliciousEventsFragment += "<td>$($event.TimeCreated)</td>"
  $maliciousEventsFragment += "<td>$($event.TimeCreated.ToShortDateString())</td>"
  $maliciousEventsFragment += "<td>$($event.Id)</td>"
  $maliciousEventsFragment += "<td>$($event.Message)</td>"
  $maliciousEventsFragment += "</tr>"
}

# Output the malicious events fragment


#endregion

Write-Host -Fore Cyan "[!] Done"
Write-Host -Fore DarkYellow "[!] Completed EventLog Analysis"

#End time date stamp
$EndTime = Get-Date -Format $DateFormat


###########################################################################################################
###########################################################################################################
########################## START OF STYLES AND HTML FORMATTING             ################################
###########################################################################################################
###########################################################################################################

Write-Host -Fore DarkCyan "[!] Hang on, the Forensicator is compiling your results"

###########################################################################################################
#region ########################## CREATING AND FORMATTING THE HTML FILES  ################################
###########################################################################################################

Write-Host -Fore DarkCyan "[*] Creating and Formatting our HTML files"


function ForensicatorIndex {

  @"
<!DOCTYPE html>
<html>
<head>
<!-- Basic Page Info -->
<meta charset="utf-8" />
<title>Live Forensicator - Results for $env:computername</title>

<!-- Mobile Specific Metas -->
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<!-- Google Font -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
rel="stylesheet" />
<!-- CSS -->
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
<div class="pre-loader">
<div class="pre-loader-box">
<div class="loader-logo">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="loader-progress" id="progress_div">
<div class="bar" id="bar1"></div>
</div>
<div class="percent" id="percent1">0%</div>
<div class="loading-text">Loading...</div>
</div>
</div>
<div class="header">
<div class="header-left">
<div class="menu-icon bi bi-list"></div>
<div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
<div class="header-search">
<form>
<div class="form-group mb-0">
<i class="dw dw-search2 search-icon"></i>
<input type="text" class="form-control search-input" placeholder="Search Here" />
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<i class="ion-arrow-down-c"></i>
</a>
<div class="dropdown-menu dropdown-menu-right">
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">From</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">To</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">Subject</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="text-right">
<button class="btn btn-primary">Search</button>
</div>
</div>
</div>
</div>
</form>
</div>
</div>
<div class="header-right">
<div class="user-info-dropdown">
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<span class="bi bi-laptop" style="font-size: 1.50em;">
</span>
<span class="user-name">$env:computername</span>
</a>
</div>
</div>
<div class="github-link">
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
alt="" /></a>
</div>
</div>
</div>
<div class="right-sidebar">
<div class="right-sidebar-body customscroll">
<div class="right-sidebar-body-content">
<h4 class="weight-600 font-18 pb-10">Header Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
</div>
<h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
</div>
</div>
</div>
</div>
<div class="left-side-bar header-white active">
<div class="brand-logo">
<a href="index.html">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
</a>
<div class="close-sidebar" data-toggle="left-sidebar-close">
<i class="ion-close-round"></i>
</div>
</div>
<div class="menu-block customscroll">
<div class="sidebar-menu">
<ul id="accordion-menu">
<li class="dropdown">
<a href="index.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-house"></span><span class="mtext">Home</span>
</a>
</li>
<li class="dropdown">
<a href="users.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
</a>
</li>
<li class="dropdown">
<a href="system.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
</a>
</li>
<li class="dropdown">
<a href="network.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
</a>
</li>
<li class="dropdown">
<a href="processes.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
</a>
</li>
<li class="dropdown">
<a href="others.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
</a>
</li>
<li class="dropdown">
<a href="javascript:;" class="dropdown-toggle">
<span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
</a>
<ul class="submenu">
<li><a href="evtx_user.html">User Actions</a></li>
<li>
<a href="evtx_logons.html">Logon Events</a>
</li>
<li><a href="evtx_object.html">Object Access</a></li>
<li><a href="evtx_process.html">Process Execution</a></li>
<li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
</ul>
</li>
<li>
<div class="dropdown-divider"></div>
</li>
<li>
<div class="sidebar-small-cap">Extra</div>
</li>
<li class="dropdown">
<a href="extras.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
</a>
</li>
</ul>
</div>
</div>
</div>
<div class="mobile-menu-overlay"></div>
<div class="main-container">
<div class="pd-ltr-20 xs-pd-20-10">
<div class="min-height-200px">
<div class="page-header">
<div class="row">
<div class="col-md-6 col-sm-12">
<div class="title">
<h4>Home</h4>
</div>
<nav aria-label="breadcrumb" role="navigation">
<ol class="breadcrumb">
<li class="breadcrumb-item">
<a href="index.html">Home</a>
</li>
<li class="breadcrumb-item active" aria-current="page">
Index
</li>
</ol>
</nav>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<div class="card-box pd-20 height-100-p mb-30">
<div class="row align-items-center">
<div class="col-md-4">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="col-md-8">
<h4 class="font-20 weight-500 mb-10 text-capitalize">
Live Forensics Results for
<div class="weight-600 font-30 text-blue">$env:computername</div>
</h4>
<p class="font-18 max-width-600">
This HTML File and its associated files were generated by the
Live Forensicator script, we believe the contents will aid
you to understand if the system has been compromised, the
final conclusion is up to the investigator.
</p>
</div>
</div>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<!-- Bordered table  start -->
<div class="pd-20 card-box mb-30">
<div class="clearfix mb-20">
<div class="pull-left">
<h4 class="text-blue h4">Key Information</h4>
<p>
This space contains information about the examiner, case and exhibit details
Analysis Start and end time is also recorded.
</p>
</div>
</div>
<table class="table table-bordered">
<thead>
<tr>
<th scope="col">#</th>
<th scope="col">Details</th>
<th scope="col">Values</th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1</th>
<td>Case reference:</td>
<td>$CASENO</td>
</tr>
<tr>
<th scope="row">2</th>
<td>Examiner Name:</td>
<td>$Handler</td>
</tr>
<tr>
<th scope="row">3</th>
<td>Exhibit reference:</td>
<td>$Ref</td>
</tr>
</tr>
<tr>
<th scope="row">4</th>
<td>Device:</td>
<td>$Des</td>
</tr>
</tr>
<tr>
<th scope="row">5</th>
<td>Examination Location:</td>
<td>$Loc</td>
</tr>
</tr>
<tr>
<th scope="row">6</th>
<td>Start Time and Date:</td>
<td>$StartTime</td>
</tr>
</tr>
<tr>
<th scope="row">7</th>
<td>End Time and Date:</td>
<td>$EndTime</td>
</tr>
</tbody>
</table>
</div>
<!--Bordered table End -->
</div>
</div>
<!-- Export Datatable End -->
</div>
<div class="footer-wrap pd-20 mb-20 card-box">
Live Forensicator - Coded By
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
</div>
</div>
</div>
<!-- js -->
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
<!-- buttons for Export datatable -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
<!-- Datatable Setting js -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
</body>
</html>

"@
}

# Call the function to generate the report
ForensicatorIndex | Out-File -FilePath $ForensicatorIndexFile


#############################################################################################################
#region   STYLES FOR NETWORKS                                   #############################################
#############################################################################################################

function NetworkStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">DNS Cache</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Entry</th>
                  <th >Name</th>
                  <th >Status</th>
                  <th >TimeToLive</th>
                  <th >Data</th>
                </tr>
              </thead>
              <tbody>
                $DNSCacheFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapters & Bandwidth</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">AdapterType</th>
                  <th >ProductName</th>
                  <th >Description</th>
                  <th >MACAddress</th>
                  <th >Availability</th>
                  <th >NetconnectionStatus</th>
                  <th >NetEnabled</th>
                  <th >PhysicalAdapter</th>
                </tr>
              </thead>
              <tbody>
               $NetworkAdapterFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current IP Configuration</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Description</th>
                  <th >MACAddress</th>
                  <th >DNSDomain</th>
                  <th >DNSHostName</th>
                  <th >DHCPEnabled</th>
                  <th >ServiceName</th>
                </tr>
              </thead>
              <tbody>
               $IPConfigurationFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapter IP Address - IPv4 & IPv6</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">InterfaceAlias</th>
                  <th >IPaddress</th>
                  <th >EnabledState</th>
                  <th >OperatingStatus</th>
                </tr>
              </thead>
              <tbody>
               $NetIPAddressFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Connection Profile</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceAlias</th>
                  <th >NetworkCategory</th>
                  <th >IPV4Connectivity</th>
                  <th >IPv6Connectivity</th>
                </tr>
              </thead>
              <tbody>
               $NetConnectProfileFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapters & Bandwidth</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceDescription</th>
                  <th >Status</th>
                  <th >MacAddress</th>
                  <th >LinkSpeed</th>
                </tr>
              </thead>
              <tbody>
               $NetAdapterFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Addres Resolution Protocol Cache</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">InterfaceAlias</th>
                  <th >IPAddress</th>
                  <th >LinkLayerAddress</th>
                </tr>
              </thead>
              <tbody>
               $NetNeighborFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current TCP Connections and Associated Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LocalAddress</th>
                  <th >LocalPort</th>
                  <th >RemoteAddress</th>
                  <th >RemotePort</th>
                  <th >State</th>
                  <th >OwningProcess</th>
                </tr>
              </thead>
              <tbody>
               $NetTCPConnectFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Associated WIFI Networks and Passwords</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PROFILE_NAME</th>
                  <th >PASSWORD</th>
                </tr>
              </thead>
              <tbody>
               $WlanPasswordsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current Firewall Rules</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >DisplayName</th>
                  <th >Description</th>
                  <th >Direction</th>
                  <th >Action</th>
                  <th >EdgeTraversalPolicy</th>
                  <th >Owner</th>
                  <th >EnforcementStatus</th>
                </tr>
              </thead>
              <tbody>
               $FirewallRuleFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Outbound SMB Sessions</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LocalAddress</th>
                  <th >LocalPort</th>
                  <th >RemoteAddress</th>
                  <th >RemotePort</th>
                  <th >State</th>
                  <th >AppliedSetting</th>
                  <th >OwningProcess</th>
                </tr>
              </thead>
              <tbody>
                 $outboundSmbSessionsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Active SMB Sessions (If Device is a Server)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">SessionId</th>
                  <th >ClientComputerName</th>
                  <th >ClientUserName</th>
                  <th >NumOpens</th>
                </tr>
              </thead>
              <tbody>
               $SMBSessionsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Active SMB Shares on this device</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">description</th>
                  <th >path</th>
                  <th >volume</th>
                </tr>
              </thead>
              <tbody>
               $SMBSharesFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">IP Route to non local Destination</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ifIndex</th>
                  <th >DestinationPrefix</th>
                  <th >NextHop</th>
                  <th >RouteMetric</th>
                  <th >ifMetric</th>
                  <th >PolicyStore</th>
                </tr>
              </thead>
              <tbody>
               $NetHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network adapters with IP Route to non local Destination</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceDescription</th>
                  <th >ifIndex</th>
                  <th >Status</th>
                  <th >MacAddress</th>
                  <th >LinkSpeed</th>
                </tr>
              </thead>
              <tbody>
               $AdaptHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Ip hops with valid infinite lifetime</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ifIndex</th>
                  <th >DestinationPrefix</th>
                  <th >NextHop</th>
                  <th >RouteMetric</th>
                  <th >ifMetric</th>
                  <th >PolicyStore</th>
                </tr>
              </thead>
              <tbody>
               $IpHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
NetworkStyle | Out-File -FilePath $NetworkFile

#endregion


#############################################################################################################
#region   STYLES FOR USER SECTION                               #############################################
#############################################################################################################

function UserStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current User Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">UserName</th>
                  <th >Domain</th>
                  <th >User UUID</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td class="table-plus">$Env:UserName</td>
                  <td>$Env:UserDomain</td>
                  <td>$userUID</td>
                </tr>
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">System Details</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>DNSHostName</th>
                  <th>Domain</th>
                  <th>Manufacturer</th>
                  <th>Model</th>
                  <th>PrimaryOwnerName</th>
                  <th>TotalPhysicalMemory</th>
                  <th>Workgroup</th>
                </tr>
              </thead>
              <tbody>
               $systemnameFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Logon Sessions</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">USERNAME</th>
                  <th>SESSIONNAME</th>
                  <th>STATE</th>
                  <th>ID</th>
                  <th>IDLE TIME</th>
                  <th>LOGON TIME</th>
                </tr>
              </thead>
              <tbody>
               $logonsessionFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap ">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Id</th>
                  <th>User Name</th>
                  <th>CPU</th>
                  <th>Memory</th>
                  <th>Path</th>
                </tr>
              </thead>
              <tbody>
               $userprocessesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Profile</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Caption</th>
                  <th>Local Path</th>
                  <th>SID</th>
                  <th>Last Used</th>
                </tr>
              </thead>
              <tbody>
               $profileFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Administrator Accounts</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Object Class</th>
                  <th>Principle Source</th>
                </tr>
              </thead>
              <tbody>
               $adminFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Local Groups</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
               $localFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->



        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
UserStyle | Out-File -FilePath $UserFile

#endregion

#############################################################################################################
#region   STYLES FOR INSTALLED PROGS | SYSTEM INFO              #############################################
#############################################################################################################

function SystemStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Installed Programs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Version</th>
                  <th>Vendor</th>
                  <th>InstallDate</th>
                  <th>InstallSource</th>
                  <th>PackageName</th>
                  <th>LocalPackage</th>
                </tr>
              </thead>
              <tbody>
               $InstProgsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->



        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Installed Programs - From Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">DisplayName</th>
                  <th>DisplayVersion</th>
                  <th>Publisher</th>
                  <th>InstallDate</th>
                </tr>
              </thead>
              <tbody>
               $InstalledAppsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Environment Variables</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">name</th>
                  <th>value</th>
                </tr>
              </thead>
              <tbody>
               $envFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">System Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Caption</th>
                  <th>SystemType</th>
                  <th>Manufacturer</th>
                  <th>Model</th>
                  <th>DNSHostName</th>
                  <th>Domain</th>
                  <th>PartOfDomain</th>
                  <th>WorkGroup</th>
                  <th>CurrentTimeZone</th>
                  <th>PCSystemType</th>
                  <th>HyperVisorPresent</th>
                </tr>
              </thead>
              <tbody>
               $systeminfoFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Operating System Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Description</th>
                  <th>Version</th>
                  <th>BuildNumber</th>
                  <th>InstallDate</th>
                  <th>SystemDrive</th>
                  <th>SystemDevice</th>
                  <th>WindowsDirectory</th>
                  <th>LastBootupTime</th>
                  <th>Locale</th>
                  <th>LocalDateTime</th>
                  <th>NumberofUsers</th>
                  <th>RegisteredUser</th>
                  <th>Organization</th>
                  <th>OSProductSuite</th>
                </tr>
              </thead>
              <tbody>
               $OSinfoFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Hotfixes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">CSName</th>
                  <th>Caption</th>
                  <th>Description</th>
                  <th>HotfixID</th>
                  <th>InstalledBy</th>
                  <th>InstalledOn</th>
                </tr>
              </thead>
              <tbody>
               $HotfixesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Windows Defender Status</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">AMProductVersion</th>
                  <th>AMRunningMode</th>
                  <th>AMServiceEnabled</th>
                  <th>AntispywareEnabled</th>
                  <th>AntispywareSignatureLastUpdated</th>
                  <th>AntivirusEnabled</th>
                  <th>AntivirusSignatureLastUpdated</th>
                  <th>BehaviorMonitorEnabled</th>
                  <th>DefenderSignaturesOutOfDate</th>
                  <th>DeviceControlPoliciesLastUpdated</th>
                  <th>DeviceControlState</th>
                  <th>NISSignatureLastUpdated</th>
                  <th>QuickScanEndTime</th>
                  <th>RealTimeProtectionEnabled</th>
                </tr>
              </thead>
            <tbody>
               $WinDefenderFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
SystemStyle | Out-File -FilePath $SystemFile

#endregion



#############################################################################################################
#region   STYLES FOR PROCESSES, SCHEDULED TASK | REGISTRY       #############################################
#############################################################################################################

function ProcessStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Handles</th>
                  <th>StartTime</th>
                  <th>PM</th>
                  <th>VM</th>
                  <th>SI</th>
                  <th>id</th>
                  <th>ProcessName</th>
                  <th>Path</th>
                  <th>Product</th>
                  <th>FileVersion</th>
                </tr>
              </thead>
              <tbody>
               $ProcessesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Startup Programs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>command</th>
                  <th>Location</th>
                  <th>User</th>
                </tr>
              </thead>
              <tbody>
               $StartupProgsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Scheduled Task</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TaskPath</th>
                  <th>TaskName</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
               $ScheduledTaskFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Scheduled Task & State</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LastRunTime</th>
                  <th>LastTaskResult</th>
                  <th>NextRunTime</th>
                  <th>NumberOfMissedRuns</th>
                  <th>TaskName</th>
                  <th>TaskPath</th>
                  <th>PSComputerName</th>
                </tr>
              </thead>
              <tbody>
               $ScheduledTask2Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Services</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ServiceName</th>
                  <th>DisplayName</th>
                  <th>Status</th>
                  <th>StartType</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
               $ServicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRun Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRun
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRunOnce Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRunOnce
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRunOnceEx Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRunOnceEx
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ProcessStyle | Out-File -FilePath $ProcessFile

#endregion

#############################################################################################################
#region   OTHER NOTABLE CHECKS         ######################################################################
#############################################################################################################

function OthersStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Logical Drives</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">DeviceID</th>
                  <th>DriveType</th>
                  <th>FreeSpace</th>
                  <th>Size</th>
                  <th>VolumeName</th>
                </tr>
              </thead>
              <tbody>
                 $LogicalDrivesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">USB Devices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">FriendlyName</th>
                  <th>Driver</th>
                  <th>mfg</th>
                  <th>DeviceDesc</th>
                </tr>
              </thead>
              <tbody>
               $USBDevicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Connected & Disconnected Webcams</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Caption</th>
                  <th>CreationClassName</th>
                  <th>Description</th>
                  <th>DeviceID</th>
                  <th>InstallDate</th>
                  <th>Manufacturer</th>
                  <th>Present</th>
                  <th>Status</th>
                  <th>SystemCreationClassName</th>
                  <th>SystemName</th>
                </tr>
              </thead>
              <tbody>
               $ImagedeviceFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">UPNPDevices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Class</th>
                  <th>Status</th>
                  <th>FriendlyName</th>
                </tr>
              </thead>
              <tbody>
               $UPNPDevicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Previously Connected Drives</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">FriendlyName</th>
                </tr>
              </thead>
              <tbody>
               $UnknownDrivesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Link Files Created in the last 180days</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FileName</th>
                  <th>CreationDate</th>
                  <th>LastAccessed</th>
                  <th>Drive</th>
                  <th>Path</th>
                  <th>FileType</th>
                </tr>
              </thead>
              <tbody>
               $LinkFilesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">500Days Powershell History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">id</th>
                  <th>commandline</th>
                  <th>startexecutiontime</th>
                  <th>endexecutiontime</th>
                </tr>
              </thead>
              <tbody>
               $PSHistoryFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables in the Downloads folder</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>Root</th>
                  <th>Name</th>
                  <th>FullName</th>
                  <th>Extension</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $DownloadsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In AppData</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>Root</th>
                  <th>Name</th>
                  <th>FullName</th>
                  <th>Extension</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs1Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Temp</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>Root</th>
                  <th>Name</th>
                  <th>FullName</th>
                  <th>Extension</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs2Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Perflogs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>Root</th>
                  <th>Name</th>
                  <th>FullName</th>
                  <th>Extension</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs3Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Documents Folder</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>Root</th>
                  <th>Name</th>
                  <th>FullName</th>
                  <th>Extension</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs4Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Files with same extension as well-known ransomware encrypted files</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PSChildName</th>
                  <th>FullName</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Extension</th>
                </tr>
              </thead>
              <tbody>
               $FindFilesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
OthersStyle | Out-File -FilePath $OthersFile

#endregion


###########################################################################################################
#region ########################## CREATING AND FORMATTING THE EXTRAS FILE  ###############################
###########################################################################################################



function ForensicatorExtras {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-download"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Extras</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Extras
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <div class="main-container">
          <div class="pd-ltr-20">
            <!-- Bordered table  start -->
            <!-- Simple Datatable start -->
            <div class="card-box mb-30">
              <div class="pd-20">
                <h4 class="text-blue h4">Extra Outputs</h4>
                <p class="mb-0">
                  Note: Not all checks will have a location output because the system might not meet the condition for the check.
                </p>
              </div>
              <div class="pb-20">
                <table class="data-table table nowrap">
                  <thead>
                    <tr>
                      <th class="table-plus">Extra Checks</th>
                      <th class="datatable-nosort">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Group Policy Report</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="GPOReport.html">GPOReport.html</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">WINPMEM RAM CAPTURE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="RAM">/RAM</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">BROWSING HISTORY NIRSOFT</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="BrowserHistory.html">BrowserHistory.html</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">BROWSING HISTORY INBUILT</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="BROWSING_HISTORY">/BROWSING_HISTORY</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">NETWORK TRACE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="PCAP">/PCAP</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">EVENT LOGS</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="EVTXLOGS">/EVTXLOGS</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">IIS Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="IISLogs">/IISLogs</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">TomCat Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="TomCatLogs">/TomCatLogs</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Discovered Log4j</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="LOG4J">/LOG4J</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Matched Hashes</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="HashMatches">/LOG4J</a>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <!-- Simple Datatable End -->
            <!-- Bordered table End -->
          </div>
        </div>
        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>

  <!-- js -->

  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>


</body>

</html>

"@
}

# Call the function to generate the report
ForensicatorExtras | Out-File -FilePath $ForensicatorExtrasFile

#endregion


##################################################################################################################
##################################################################################################################
### EVENT LOG ANALYSIS STYLING         ###########################################################################
##################################################################################################################
##################################################################################################################


#############################################################################################################
#region   EVENT LOG ANALYSIS   USER ACTIVITIES        #######################################################
#############################################################################################################

function EvtxUserStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">A user's local group membership was enumerated</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>PerformedOn</th>
                  <th>PerformedBy</th>
                  <th>LogonType</th>
                  <th>PID</th>
                  <th>ProcessName</th>
                </tr>
              </thead>
              <tbody>
               $GroupMembershipFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">RDP Login Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>LogonUser</th>
                  <th>LogonUserDomain</th>
                  <th>LogonIP</th>
                </tr>
              </thead>
              <tbody>
               $RDPLoginsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All RDP Login History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TimeCreated</th>
                  <th>User</th>
                  <th>Domain</th>
                  <th>Client</th>
                </tr>
              </thead>
              <tbody>
               $RDPAuthsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Outgoing RDP Connection History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TimeStamp</th>
                  <th>LocalUser</th>
                  <th>Target RDP Host</th>
                </tr>
              </thead>
              <tbody>
               $OutRDPFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Creation Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>CreatedUser</th>
                  <th>CreatedBy</th>
                </tr>
              </thead>
              <tbody>
               $CreatedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Password Reset Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>TargetUser</th>
                  <th>ActionedBy</th>
                </tr>
              </thead>
              <tbody>
               $PassResetFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Users Added to Group</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>AddedBy</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
               $AddedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Enabling Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>EnabledBy</th>
                  <th>EnabledAccount</th>
                </tr>
              </thead>
              <tbody>
               $EnabledUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Disabling Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>DisabledBy</th>
                  <th>Disabled</th>
                </tr>
              </thead>
              <tbody>
               $DisabledUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Deletion Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>DeletedBy</th>
                  <th>DeletedAccount</th>
                </tr>
              </thead>
              <tbody>
               $DeletedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User LockOut Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>LockedOutAccount</th>
                  <th>System</th>
                </tr>
              </thead>
              <tbody>
               $LockOutFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Credential Manager Backup Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>BackupAccount</th>
                  <th>AccountLogonType</th>
                </tr>
              </thead>
              <tbody>
               $CredManBackupFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Credential Manager Restore Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>RestoredAccount</th>
                  <th>AccountLogonType</th>
                </tr>
              </thead>
              <tbody>
               $CredManRestoreFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
EvtxUserStyle | Out-File -FilePath $EvtxUserFile

#endregion

#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   LOGON EVENTS         #############################################
#############################################################################################################

function LogonEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Successful Logon Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>User</th>
                  <th>Logon Type</th>
                  <th>SourceNetworkAddress</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
               $logonEventsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->



        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Failed Logon Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>User</th>
                  <th>Logon Type</th>
                  <th>SourceNetworkAddress</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
               $logonEventsFailedFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->
        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
LogonEventsStyle | Out-File -FilePath $LogonEventsFile

#endregion




#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   Object Access         #############################################
#############################################################################################################

function ObjectEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Object Access</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
               $ObjectHtmlTable1
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ObjectEventsStyle | Out-File -FilePath $ObjectEventsFile

#endregion



#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   PROCESS EVENTS        #############################################
#############################################################################################################

function ProcessEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Object Access</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
               $ObjectHtmlTable2
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->
        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ProcessEventsStyle | Out-File -FilePath $ProcessEventsFile

#endregion



#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   Suspicious Activities         #####################################
#############################################################################################################



function SuspiciousEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
              <li><a href="evtx_suspicious.html">Suspicious Activities</a></li>
            </ul>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Suspecious Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap ">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Severity</th>
                  <th>Timestamp</th>
                  <th>Date</th>
                  <th>EventID</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
               $maliciousEventsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
SuspiciousEventsStyle | Out-File -FilePath $SuspiciousEventsFile

#endregion




################################################################################################################################
## ENCRYPTION SECTION                                       ###################################################################
###############################################################################################################################


if ($ENCRYPTED) {
	
  Write-Host -Fore DarkCyan "[*] You choose to Encrypt the Artifacts but lets first Archive it"	

  $ParentFolder = $PSScriptRoot + "\" + "$env:computername" + "\" #files will be stored with a path relative to this folder
  $ZipPath = $PSScriptRoot + "\" + "$env:computername" + "\" + "$env:computername.zip" #the zip file should not be under $ParentFolder or an exception will be raised

  @( 'System.IO.Compression', 'System.IO.Compression.FileSystem') | ForEach-Object { [void][Reflection.Assembly]::LoadWithPartialName($_) }
  Push-Location $ParentFolder #change to the parent folder so we can get $RelativePath
  $FileList = (Get-ChildItem '*.*' -File -Recurse) #use the -File argument because empty folders can't be stored
  Try {
    $WriteArchive = [IO.Compression.ZipFile]::Open( $ZipPath, 'Update')
    ForEach ($File in $FileList) {
      $RelativePath = (Resolve-Path -LiteralPath "$($File.FullName)" -Relative) -replace '^.\\' #trim leading .\ from path 
      Try {    
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($WriteArchive, $File.FullName, $RelativePath, 'Optimal').FullName
      }
      Catch {
        #Single file failed - usually inaccessible or in use
        Write-Warning  "$($File.FullName) could not be archived. `n $($_.Exception.Message)"  
      }
    }
  }
  Catch [Exception] {
    #failure to open the zip file
    Write-Error $_.Exception
  }
  Finally {
    $WriteArchive.Dispose() #always close the zip file so it can be read later 
    #Remove-Item -Exclude *.zip -Recurse -Force
    Get-ChildItem * -Exclude *.zip -Recurse | Remove-Item -Force -Recurse
  }

  Write-Host -Fore DarkCyan "[*] Artifacts Archived, now lets encrypt it..."

  Pop-Location



  $Password = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 12  | ForEach-Object { [char]$_ }) )

  $MYTEXT = $Password
  $ENCODED = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MYTEXT))
  #Write-Host $ENCODED | Out-File .\key.txt
  Write-Host $ENCODED
  Write-Output YOUR ENCRYPTION KEY IS: $ENCODED | Out-File -Force .\key.txt 

  Write-Host -Fore DarkCyan "[!] That is your Encryption key please keep it safe"

  # Define target file types
  $TargetFiles = '*.zip'
  $TargetPath = $PSScriptRoot + "\" + "$env:computername" + "\"
  $Extension = ".forensicator"
  $Key = $ENCODED

  # Import FileCryptography module
  Import-Module "$PSScriptRoot\Forensicator-Share\FileCryptography.psm1"


  # Gather all files from the target path and its subdirectories
  $FilesToEncrypt = get-childitem -path $TargetPath\* -Include $TargetFiles -Exclude *$Extension -Recurse -force | Where-Object { ! $_.PSIsContainer } 
  $NumFiles = $FilesToEncrypt.length

  # Encrypt the files
  foreach ($file in $FilesToEncrypt) {
    Write-Host "Encrypting $file"
    Protect-File $file -Algorithm AES -KeyAsPlainText $key -Suffix $Extension -RemoveSource
  }
  Write-Host "Encrypted $NumFiles files." | Start-Sleep -Seconds 10

  Write-Host -Fore DarkCyan "[*] Artifact Encrypted successfully"

  Write-Host -Fore Cyan "[!] All Done... you can find the key in the Artifact Folder"	

  Set-Location $PSScriptRoot

	
   
} 
else {
	


}

Set-Location $PSScriptRoot
	
Write-Host -Fore Cyan "[!] All Done... you can find the results in the script execution folder"	


Write-Host ''
Write-Host ''
Write-Host ''
