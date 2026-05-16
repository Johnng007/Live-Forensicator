
# Live Forensicator Powershell Script
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
  [String]$PCAP,
  [String]$HASHCHECK,
  [String]$ENCRYPTED,
  [switch]$UPDATE,
  [switch]$VERSION,
  [switch]$DECRYPT,
  [switch]$USAGE
)

$ErrorActionPreference = 'silentlycontinue'

##################################################
#region        Versioning & Update               #
##################################################
$version_file = $PSScriptRoot + "\" + "Updated" + "\" + "version.txt"
$current_version = $PSScriptRoot + "\" + "version.txt"

$MyVersion = Get-Content -Path .\version.txt

if ($VERSION.IsPresent) {
  Write-Host -Fore Cyan "[!] You are currently running $MyVersion" 
  Write-Host -Fore Cyan ''
  exit 0
}


##################################################
#region        Auto Check Update                 #
##################################################

$localVersion = Get-Content -Path "$PSScriptRoot\version.txt"

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
      Write-Host -ForegroundColor Cyan "[!] A new version $remoteVersion is available on Github. Please upgrade your copy of Forensicator."
    }
    else {
      Write-Host -ForegroundColor Cyan "[!] You are using the latest version $localVersion No updates available."
    }
  }
  catch {
    Write-Host -ForegroundColor Red "Failed to check for updates. You probably don't have an internet connection."
    Write-Host -ForegroundColor Red "Error: $_"
  }
}

# Call the function to check for updates
CheckForUpdates

#endregion 


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
  Write-Host $t[$i] -NoNewline -ForegroundColor $c
}
Write-Host ''

Write-Host ''
Write-Host ''
Write-Host ''
Write-Host -ForegroundColor DarkCyan '[!] Live Forensicator'
Write-Host ''
Write-Host -ForegroundColor DarkCyan '[!] Live Forensicator is a free and open-source PowerShell script designed to automate the collection of forensic artifacts from Windows systems. It provides a comprehensive set of features for incident responders, digital forensic analysts, and cybersecurity professionals to efficiently gather critical information during investigations.'
Write-Host -ForegroundColor DarkCyan '[!] https://forensicator.io'
Write-Host -ForegroundColor DarkCyan '[!] https://github.com/Johnng007/Live-Forensicator'
Write-Host ''


#################################################
##region Functions for Version Check and Update##
#################################################
if ($UPDATE) {
  Write-Host -ForegroundColor DarkCyan "[*] Downloading & Comparing Version Files"
  New-Item -Name "Updated" -ItemType "directory" -Force | Out-Null
  Set-Location Updated

  $destination = 'version.txt'

  if (((Test-NetConnection www.githubusercontent.com -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) -eq $true) {
	
    Invoke-WebRequest -Uri $rawUrl -OutFile $destination	
  }

  else {
    Write-Host -ForegroundColor DarkCyan "[*] githubusercontent.com is not reacheable, please check your connection"
    Set-Location $PSScriptRoot
    Remove-Item 'Updated' -Force -Recurse
    exit 0
  }

  if ((Get-FileHash $version_file).hash -eq (Get-FileHash $current_version).hash) {
	 
    Write-Host -ForegroundColor Cyan "[*] Congratualtion you have the current version"
    Set-Location $PSScriptRoot
    Remove-Item 'Updated' -Force -Recurse
    exit
  }

  else {
    Write-Host -Fore DarkCyan "[!] You have an outdated version, we are sorting that out..." 
    $source = 'https://github.com/Johnng007/Live-Forensicator/archive/refs/heads/main.zip'
    $destination = 'Live-Forensicator-main.zip'
    Invoke-WebRequest -Uri $source -OutFile $destination
    Write-Host -ForegroundColor DarkCyan "[*] Extracting the downloads....."
    Expand-Archive -Force $PSScriptRoot\Updated\Live-Forensicator-main.zip -DestinationPath $PSScriptRoot\Updated 
    Write-Host -ForegroundColor DarkCyan "[*] Cleaning Up...."
    Remove-Item -Path $PSScriptRoot\Updated\Live-Forensicator-main.zip -Force
    Remove-Item -Path $PSScriptRoot\Updated\version.txt -Force
    Write-Host -Fore Cyan "[*] All Done Enjoy the new version in the Updated Folder"
    Set-Location $PSScriptRoot
    exit 0
  }	
} 

#endregion

##################################################
#region    ARTIFACT DECRYPTION SWITCH            #
##################################################

function Unprotect-FileNative {
    param(
        [string]$FilePath,
        [string]$KeyB64,
        [string]$Suffix = ".forensicator"
    )

    if(-not $FilePath.EndsWith($Suffix)){
        Write-ForensicLog -Fore Yellow "[!] $FilePath does not have expected suffix $Suffix" -Level WARN -Section "CRYPT"
        return
    }

    $outPath  = $FilePath -replace [regex]::Escape($Suffix),''
    $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))

    try{
        $inStream = [System.IO.File]::OpenRead($FilePath)

        # Read the 16-byte salt written during encryption
        $salt = [byte[]]::new(16)
        [void]$inStream.Read($salt, 0, 16)

        $pbkdf2   = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                        $password, $salt, 100000,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256
                    )
        $keyBytes = $pbkdf2.GetBytes(32)
        $ivBytes  = $pbkdf2.GetBytes(16)
        $pbkdf2.Dispose()

        $aes         = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key     = $keyBytes
        $aes.IV      = $ivBytes
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $decryptor    = $aes.CreateDecryptor()
        $outStream    = [System.IO.File]::Create($outPath)
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                            $inStream,
                            $decryptor,
                            [System.Security.Cryptography.CryptoStreamMode]::Read
                        )
        $cryptoStream.CopyTo($outStream)
    }
    catch{
        # Clean up incomplete output file if decryption failed
        # Most likely cause is a wrong key
        if($outStream){ $outStream.Dispose() }
        if(Test-Path $outPath){ Remove-Item $outPath -Force }
        throw
    }
    finally{
        if($cryptoStream){ $cryptoStream.Dispose() }
        if($outStream)   { $outStream.Dispose()    }
        if($inStream)    { $inStream.Dispose()     }
        if($decryptor)   { $decryptor.Dispose()    }
        if($aes)         { $aes.Dispose()          }
    }

    if(Test-Path $outPath){
        Remove-Item $FilePath -Force
    }
}


if($DECRYPT){

    $DefaultPath = "$PSScriptRoot\$env:COMPUTERNAME\"

    # Determine target path — check default location first
    if(Test-Path $DefaultPath){
        $forensicatorFiles = Get-ChildItem $DefaultPath -Filter "*.forensicator" -ErrorAction SilentlyContinue
    }

    if(-not $forensicatorFiles){
        Write-ForensicLog "[!] Cannot find encrypted file in default location." -Level WARN -Section "CRYPT"
        $TargetPath = Read-Host -Prompt "Enter full path to folder containing the encrypted file"

        # Validate the provided path exists and contains .forensicator files
        if(-not (Test-Path $TargetPath)){
            Write-ForensicLog "[!] Path does not exist: $TargetPath" -Level ERROR -Section "CRYPT"
            exit 1
        }

        $forensicatorFiles = Get-ChildItem "$TargetPath\*" -Filter "*.forensicator" -Recurse -Force |
                             Where-Object { -not $_.PSIsContainer }

        if(-not $forensicatorFiles){
            Write-ForensicLog "[!] No .forensicator files found in: $TargetPath" -Level ERROR -Section "CRYPT"
            exit 1
        }
    }
    else{
        $TargetPath = $DefaultPath
    }

    # Prompt for key
    $KeyInput = Read-Host -Prompt "Enter Decryption Key"

    if([string]::IsNullOrWhiteSpace($KeyInput)){
        Write-ForensicLog "[!] No key provided — aborting" -Level ERROR -Section "CRYPT"
        exit 1
    }

    # Validate key is valid Base64 before attempting decryption
    try{
        [void][Convert]::FromBase64String($KeyInput)
    }
    catch{
        Write-ForensicLog "[!] Key does not appear to be valid Base64 — check your key.txt" -Level ERROR -Section "CRYPT"
        exit 1
    }

    # Gather all .forensicator files under the target path
    $FilesToDecrypt = Get-ChildItem -Path "$TargetPath\*" `
                                    -Filter "*.forensicator" `
                                    -Recurse -Force |
                      Where-Object { -not $_.PSIsContainer }

    $total    = $FilesToDecrypt.Count
    $success  = 0
    $failed   = 0

    Write-ForensicLog "[*] Found $total file(s) to decrypt"

    foreach($file in $FilesToDecrypt){
        Write-ForensicLog "Decrypting $($file.Name)..."
        try{
            Unprotect-FileNative -FilePath $file.FullName -KeyB64 $KeyInput
            $success++
        }
        catch{
            Write-ForensicLog "[!] Failed to decrypt $($file.Name) — wrong key or corrupted file" -Level ERROR -Section "CRYPT"
            Write-ForensicLog "    $($_.Exception.Message)" -Level ERROR -Section "CRYPT"
            $failed++
        }
    }

    Write-ForensicLog "[!] Decryption complete — $success succeeded, $failed failed" -Level INFO -Section "CRYPT"

    exit 0
}
else{

}

#endregion 


##################################################
#region             USAGE                        #
##################################################

if ($USAGE) {
	
  Write-Host ''
  Write-Host -ForegroundColor Cyan 'SAMPLE FORESNSICATOR USAGE'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan 'Note: This may not be up to date please check github'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1   This runs the Basic checks on a system.'
  Write-Host ''
  Write-Host -ForegroundColor Cyan 'FLAGS'
  Write-Host -ForegroundColor Cyan 'The below sample flags can be added to the Basic Usage'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan '[*] -EVTX EVTX               Also grab Event Logs'
  Write-Host -ForegroundColor DarkCyan '[*] -WEBLOGS WEBLOGS         Also grab Web Logs.'
  Write-Host -ForegroundColor DarkCyan '[*] -PCAP PCAP               Run network tracing and capture PCAP for 120seconds'
  Write-Host -ForegroundColor Cyan "[!] requires the etl2pcapng file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] -RAM RAM                 Extract RAM Dump'
  Write-Host -ForegroundColor Cyan "[!] requires the winpmem file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] -LOG4J LOG4J             Checks for vulnerable log4j files'
  Write-Host -ForegroundColor DarkCyan '[*] -ENCRYPTED ENCRYPTED     Encrypts Artifacts after collecting them'
  Write-Host -ForegroundColor DarkCyan '[*] -HASHCHECK HASHCHECK     Check executable hashes for latest malware'
  Write-Host -ForegroundColor DarkCyan ''
  Write-Host -ForegroundColor DarkCyan 'SWITCHES' 
  Write-Host -ForegroundColor DarkCyan ''
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -VERSION           This checks the version of Foresicator you have'
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -UPDATE            This checks for and updates your copy of Forensicator'
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -DECRYPT DECRYPT   This decrypts a Foresicator encrypted Artifact'
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -USAGE             Prints this help file'
  Write-Host -ForegroundColor Cyan '[!] Stay up to date with usage options by visiting https://forensicator.io'

  exit 0
}
else {
	
}

#endregion 


#############################################################################################################
#region   LOGGING INITIALISATION
#############################################################################################################

$LogFolder    = "$PSScriptRoot\LOGS"
$LogTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile      = "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp.log"

New-Item $LogFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

$script:LogEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ErrorCount = 0

# ---------------------------------------------------------
# DEFINE ALL FUNCTIONS FIRST before any execution code
# ---------------------------------------------------------
function Write-ForensicLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","CRITICAL","SUCCESS","FINDING")]
        [string]$Level   = "INFO",
        [string]$Section = "",
        [string]$Detail  = ""
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $script:LogEntries.Add([PSCustomObject]@{
        Timestamp = $timestamp
        Level     = $Level
        Section   = $Section
        Message   = $Message
        Detail    = $Detail
        Host      = $env:COMPUTERNAME
        User      = $env:USERNAME
    })

    $color = switch($Level){
        "INFO"     { "DarkCyan" }
        "WARN"     { "Yellow"   }
        "ERROR"    { "Red"      }
        "CRITICAL" { "Magenta"  }
        "SUCCESS"  { "Green"    }
        "FINDING"  { "Cyan"     }
        default    { "White"    }
    }

    Write-Host -ForegroundColor $color "[$timestamp][$Level]$(if($Section){" [$Section]"}) $Message$(if($Detail){" | $Detail"})"
    #Write-Host -ForegroundColor $color "$(if($Section){" [$Section]"}) $Message$(if($Detail){" | $Detail"})"
}

function Save-ForensicLogs {
    if($script:LogEntries.Count -eq 0){ return }

    try{
        $script:LogEntries | ConvertTo-Json -Depth 3 |
            Out-File "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_structured.json" -Encoding UTF8

        $script:LogEntries | Export-Csv `
            "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_structured.csv" `
            -NoTypeInformation -Encoding UTF8

        $findings = $script:LogEntries |
                    Where-Object { $_.Level -in @("FINDING","CRITICAL","ERROR") }

        $scripterror = $script:LogEntries |
                    Where-Object { $_.Level -in @("CRITICAL","ERROR") }

        if($findings.Count -gt 0){
            $findings | Export-Csv `
                "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_findings_only.csv" `
                -NoTypeInformation -Encoding UTF8
        }

        Write-Host "[!] Logs saved to $LogFolder" -ForegroundColor Cyan
        Write-Host "[!] Total entries  : $($script:LogEntries.Count)" -ForegroundColor Cyan
        Write-Host "[!] Findings: $($findings.Count)" -ForegroundColor Cyan
        Write-Host "[!] Errors: $($scripterror.Count)" -ForegroundColor Cyan
        Write-Host "[!] System errors  : $($script:ErrorCount)" -ForegroundColor Cyan
    }
    catch{
        Write-Warning "[!] Could not save structured logs: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------
# NOW START TRANSCRIPT — functions are defined so catch
# block can safely call Write-ForensicLog
# ---------------------------------------------------------
Write-Host ""
try{
    Start-Transcript -Path $LogFile -Append -ErrorAction Stop
    #Write-ForensicLog "Transcript logging started: $LogFile" -Level INFO
}
catch{
    # Write-ForensicLog is now defined so this call is safe
    Write-ForensicLog "Could not start transcript: $($_.Exception.Message)" -Level WARN
}

# ---------------------------------------------------------
# GLOBAL ERROR HANDLER — Save-ForensicLogs now defined
# ---------------------------------------------------------
trap{
    $script:ErrorCount++
    Write-ForensicLog "UNHANDLED ERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Level ERROR
    Write-ForensicLog $_.ScriptStackTrace -Level ERROR
    continue
}

Write-Host ""

# ---------------------------------------------------------
# EXIT HANDLER — Save-ForensicLogs now defined
# ---------------------------------------------------------
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Save-ForensicLogs
} | Out-Null

Write-ForensicLog "Forensicator Initialised on $env:COMPUTERNAME as $env:USERNAME" -Level INFO -Section "INFO"

#endregion



Write-Host ""

#################################################
#region      Defining Constants                 #
#################################################

# configuration file path
$configFile = "$PSScriptRoot\config.json"

# Read and parse the configuration file
$configData = Get-Content $configFile | ConvertFrom-Json

$Hostname = $env:computername


# ── Safe defaults for JS data globals — overwritten later after data collection ──
# Using $script: scope so they are visible inside the HTMLFiles function's here-string.
$script:sigmaJsonSafe      = '[]'
$script:hashJsonSafe       = '[]'
$script:iocJsonSafe        = '[]'
$script:evtlogCountsJson   = '{}'
$script:topEventIdsJson    = '{}'

#$userUID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

#endregion



##################################################
#region             CHECK ADMIN RIGHTS           #
##################################################

Write-ForensicLog "[*] Checking for administrative rights" -Level INFO -Section "CORE"

# Function to check if running as administrator
function Test-IsAdministrator {
  $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $isDomainAdmin = $currentUser.IsInRole("Domain Admins")
  return $isAdmin -or $isDomainAdmin
}

# Check if running as administrator
if (-not (Test-IsAdministrator)) {
  Write-ForensicLog "[!] Forensicator is not running with admin rights" -Level WARN -Section "CORE"
  Write-ForensicLog "[!] To get the best of results, please run as an admin!" -Level WARN -Section "CORE"

}
else {
  Write-ForensicLog "[!] Forensicator is running with admin rights" -Level SUCCESS -Section "CORE"
}

#endregion

Write-ForensicLog ""

##################################################
#region      Check if the share folder exists    #
##################################################

Write-ForensicLog "[*] Checking for Forensicator-Share folder" -Level INFO -Section "CORE"

$Folder = 'Forensicator-Share'

if (Test-Path -Path $Folder) {

  Write-ForensicLog "[!] Great, You have the Forensicator-Share folder" -Level SUCCESS -Section "CORE"
}
else {
  Write-ForensicLog "[!] Forensicator-Share folder not found, some flags and functions will not work! use the -UPDATE flag to import the complete Arsenal.." -Level WARN -Section "CORE"
  Write-ForensicLog "[!] Moving on...." -Level INFO -Section "CORE"
}

#endregion

Write-Host ""

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
   
  $CaseTitle = $TITLE
   
} 
else {
	
  $CaseTitle = Read-Host -Prompt 'Enter Investigation Title'

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
   
  $Device = $DEVICE
   
} 
else {
	
  $Device = Read-Host -Prompt 'Enter description of device e.g. "Asus Laptop"'

}


#endregion

Write-Host ""

#Write-ForensicLog "[*] Starting Forensicator on $env:COMPUTERNAME with parameters: Handler=$Handler, Case=$CASENO, Title=$Ref, Location=$Loc, Description=$Des" -Level INFO -Section "CORE"


$ForensicatorDateFormat = "yyyy'-'MM'-'dd HH':'mm':'ss"

$ForensicatorStartTime = Get-Date -Format $ForensicatorDateFormat

# creating a directory to store the artifacts of this host
mkdir $env:computername -Force | Out-Null

# Moving to the new folder
#Set-Location $env:computername


# Setting index output file
$HTMLFiles = "$PSScriptRoot\$env:COMPUTERNAME\index.html"


##################################################
#region Network Information and Settings         #
##################################################
Write-ForensicLog "[*] Gathering Network & Network Settings" -Level INFO -Section "NETWORK"

#Gets DNS cache. Replaces ipconfig /dislaydns
$Cmd_DnsCache = @{
    Display = 'Get-DnsClientCache | Select-Object Entry, Name, Status, TimeToLive, Data'
    Action  = { Get-DnsClientCache | Select-Object Entry, Name, Status, TimeToLive, Data }
}
$DNSCache = & $Cmd_DnsCache.Action
foreach ($process in $DNSCache) {
  $DNSCacheFragment += "<tr>"
  $DNSCacheFragment += "<td>$($process.Entry)</td>"
  $DNSCacheFragment += "<td>$($process.Name)</td>"
  $DNSCacheFragment += "<td>$($process.Status)</td>"
  $DNSCacheFragment += "<td>$($process.TimeToLive)</td>"
  $DNSCacheFragment += "<td>$($process.Data)</td>"
  $DNSCacheFragment += "</tr>"
}

# Replaces ipconfig /all and network adapter details
$Cmd_NetworkAdapter = @{
    Display = 'Get-CimInstance -Class Win32_NetworkAdapter | Select-Object AdapterType, ProductName, Description, MACAddress, Availability, NetConnectionStatus, NetEnabled, PhysicalAdapter'
    Action  = { Get-CimInstance -Class Win32_NetworkAdapter | Select-Object -Property AdapterType, ProductName, Description, MACAddress, Availability, NetconnectionStatus, NetEnabled, PhysicalAdapter }
}
$NetworkAdapter = & $Cmd_NetworkAdapter.Action
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
$Cmd_IPConfiguration = @{
    Display = "Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description, @{Name='IpAddress';Expression={`$_.IpAddress -join '; '}}, @{Name='IpSubnet';Expression={`$_.IpSubnet -join '; '}}, MACAddress, @{Name='DefaultIPGateway';Expression={`$_.DefaultIPGateway -join '; '}}, DNSDomain, DNSHostName, DHCPEnabled, ServiceName"
    Action  = { Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description, @{Name='IpAddress';Expression={$_.IpAddress -join '; '}}, @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}}, MACAddress, @{Name='DefaultIPGateway';Expression={$_.DefaultIPGateway -join '; '}}, DNSDomain, DNSHostName, DHCPEnabled, ServiceName }
}
$IPConfiguration = & $Cmd_IPConfiguration.Action
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

# Gets IP Address details. Replaces ipconfig and Get-NetIPAddress
$Cmd_NetIPAddress = @{
    Display = 'Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254)" } | Select-Object InterfaceAlias, IPAddress, @{Name="Status";Expression={(Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).Status}}, @{Name="LinkSpeed";Expression={(Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).LinkSpeed}}'
}

$NetIPAddress = foreach ($ip in Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^(127\.|169\.254)"
}) {

    $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        InterfaceAlias   = $ip.InterfaceAlias
        IPAddress        = $ip.IPAddress
        Status     = $adapter.Status
        LinkSpeed  = $adapter.LinkSpeed
    }
}

foreach ($process in $NetIPAddress) {

  $NetIPAddressFragment += "<tr>"
  $NetIPAddressFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetIPAddressFragment += "<td>$($process.IPAddress)</td>"
  $NetIPAddressFragment += "<td>$($process.Status)</td>"
  $NetIPAddressFragment += "<td>$($process.LinkSpeed)</td>"
  $NetIPAddressFragment += "</tr>"

}

# Gets network profiles and network category. 
$Cmd_NetConnectProfile = @{
    Display = 'Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity'
    Action  = { Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity }
}
$NetConnectProfile = & $Cmd_NetConnectProfile.Action
foreach ($process in $NetConnectProfile) {
  $NetConnectProfileFragment += "<tr>"
  $NetConnectProfileFragment += "<td>$($process.Name)</td>"
  $NetConnectProfileFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetConnectProfileFragment += "<td>$($process.NetworkCategory)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPV4Connectivity)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPv6Connectivity)</td>"
  $NetConnectProfileFragment += "</tr>"
}

# Gets network adapter details.
$Cmd_NetAdapter = @{
    Display = 'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed'
    Action  = { Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed }
}
$NetAdapter = & $Cmd_NetAdapter.Action
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
$Cmd_NetNeighbor = @{
    Display = 'Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress'
    Action  = { Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress }
}
$NetNeighbor = & $Cmd_NetNeighbor.Action
foreach ($process in $NetNeighbor) {
  $NetNeighborFragment += "<tr>"
  $NetNeighborFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetNeighborFragment += "<td>$($process.IPAddress)</td>"
  $NetNeighborFragment += "<td>$($process.LinkLayerAddress)</td>"
  $NetNeighborFragment += "</tr>"
}

#Replaces netstat commands
$Cmd_NetTCPConnect = @{
    Display = "Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name='Process';Expression={(Get-Process -Id `$_.OwningProcess).ProcessName}}"
    Action  = { Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} }
}
$NetTCPConnect = & $Cmd_NetTCPConnect.Action
foreach ($process in $NetTCPConnect) {
  $NetTCPConnectFragment += "<tr>"
  $NetTCPConnectFragment += "<td>$($process.LocalAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.LocalPort)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemoteAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemotePort)</td>"
  $NetTCPConnectFragment += "<td>$($process.State)</td>"
  $NetTCPConnectFragment += "<td>$($process.OwningProcess)</td>"
  $NetTCPConnectFragment += "<td>$($process.Process)</td>"
  $NetTCPConnectFragment += "</tr>"
}

# Replaces netstat -an | find "LISTEN"
$Cmd_ListeningPorts = @{
    Display = "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, State, OwningProcess, @{Name='Process';Expression={(Get-Process -Id `$_.OwningProcess).ProcessName}}"
    #Action  = { Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, State, OwningProcess, @{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} }
}

$procIndex = Get-Process | Group-Object Id -AsHashTable -AsString

$NetListenFragment = @()

# TCP LISTENING
$NetListenFragment += foreach ($c in Get-NetTCPConnection -State Listen) {
    $gp = $procIndex["$($c.OwningProcess)"]; if ($gp -is [Array]) { $gp = $gp[0] }
    $proc = $gp.ProcessName
    "<tr><td>$($c.LocalPort)</td><td>TCP</td><td>$($c.OwningProcess)</td><td>$proc</td></tr>"
}

# UDP (no state, but effectively listening)
$NetListenFragment += foreach ($c in Get-NetUDPEndpoint) {
    $gp = $procIndex["$($c.OwningProcess)"]; if ($gp -is [Array]) { $gp = $gp[0] }
    $proc = $gp.ProcessName
    "<tr><td>$($c.LocalPort)</td><td>UDP</td><td>$($c.OwningProcess)</td><td>$proc</td></tr>"
}

#Get Wi-fi Names and Passwords
$Cmd_WlanPasswords = @{
    Display = 'netsh.exe wlan show profiles | Select-String "\:(.+)$" | ForEach-Object { $wlanname = $_.Matches.Groups[1].Value.Trim(); netsh wlan show profile name="$wlanname" key=clear } | Select-String "Key Content\W+\:(.+)$" | ForEach-Object { $wlanpass = $_.Matches.Groups[1].Value.Trim(); [PSCustomObject]@{ PROFILE_NAME = $wlanname; PASSWORD = $wlanpass } }'
    Action  = { netsh.exe wlan show profiles | Select-String "\:(.+)$" | ForEach-Object { $wlanname = $_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object { (netsh wlan show profile name="$wlanname" key=clear) }  | Select-String 'Key Content\W+\:(.+)$' | ForEach-Object { $wlanpass = $_.Matches.Groups[1].Value.Trim(); [PSCustomObject]@{ PROFILE_NAME = $wlanname; PASSWORD = $wlanpass } } }
}

$WlanPasswords = & $Cmd_WlanPasswords.Action

$WlanPasswordsFragment = ""

foreach ($process in $WlanPasswords) {
  $WlanPasswordsFragment += "<tr>"
  $WlanPasswordsFragment += "<td>$($process.PROFILE_NAME)</td>"
  $WlanPasswordsFragment += "<td>$($process.PASSWORD)</td>"
  $WlanPasswordsFragment += "</tr>"
}


#Get Firewall Information. Replaces netsh firewall show config
$Cmd_FirewallRule = @{
    Display = 'Get-NetFirewallRule | Select-Object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus'
    Action  = { Get-NetFirewallRule | Select-Object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus }
}
$FirewallRule = & $Cmd_FirewallRule.Action
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
$Cmd_OutboundSmbSessions = @{
    Display = 'Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 -and $_.State -eq "Established" }'
    Action  = { Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 -and $_.State -eq "Established" } }
}

$outboundSmbSessions = & $Cmd_OutboundSmbSessions.Action
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
$Cmd_SMBSessions = @{
    Display = 'Get-SmbSession -ErrorAction SilentlyContinue'
    Action  = { Get-SmbSession -ErrorAction SilentlyContinue }
}
$SMBSessions = & $Cmd_SMBSessions.Action
foreach ($process in $SMBSessions) {
  $SMBSessionsFragment += "<tr>"
  $SMBSessionsFragment += "<td>$($process.SessionId)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientComputerName)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientUserName)</td>"
  $SMBSessionsFragment += "<td>$($process.NumOpens)</td>"
  $SMBSessionsFragment += "</tr>"
}

#Display active samba shares
$Cmd_SMBShares = @{
    Display = 'Get-SmbShare | Select-Object Description, Path, Volume'
    Action  = { Get-SmbShare | Select-Object Description, Path, Volume }
}
$SMBShares = & $Cmd_SMBShares.Action
foreach ($process in $SMBShares) {
  $SMBSharesFragment += "<tr>"
  $SMBSharesFragment += "<td>$($process.description)</td>"
  $SMBSharesFragment += "<td>$($process.path)</td>"
  $SMBSharesFragment += "<td>$($process.volume)</td>"
  $SMBSharesFragment += "</tr>"
}

#Get IP routes to non-local destinations
$Cmd_NetHops = @{
    Display = 'Get-NetRoute | Where-Object { $_.NextHop -ne "::" } | Where-Object { $_.NextHop -ne "0.0.0.0" } | Where-Object { $_.NextHop.Substring(0,6) -ne "fe80::" }'
    Action  = { Get-NetRoute | Where-Object { $_.NextHop -ne '::' } | Where-Object { $_.NextHop -ne '0.0.0.0' } | Where-Object { $_.NextHop.SubString(0,6) -ne 'fe80::' } }
}
$NetHops = & $Cmd_NetHops.Action
foreach ($process in $NetHops) {
  $NetHopsFragment += "<tr>"
  $NetHopsFragment += "<td>$($process.ifIndex)</td>"
  $NetHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $NetHopsFragment += "<td>$($process.NextHop)</td>"
  $NetHopsFragment += "<td>$($process.RouteMetric)</td>"
  $NetHopsFragment += "<td>$($process.InterfaceMetric)</td>"
  $NetHopsFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetHopsFragment += "</tr>"
}

#Get network adapters that have IP routes to non-local destinations
$Cmd_AdaptHops = @{
    Display = 'Get-NetRoute | Where-Object { $_.NextHop -ne "::" } | Where-Object { $_.NextHop -ne "0.0.0.0" } | Where-Object { $_.NextHop.Substring(0,6) -ne "fe80::" } | Get-NetAdapter'
    Action  = { Get-NetRoute | Where-Object { $_.NextHop -ne '::' } | Where-Object { $_.NextHop -ne '0.0.0.0' } | Where-Object { $_.NextHop.SubString(0,6) -ne 'fe80::' } | Get-NetAdapter }
}
$AdaptHops = & $Cmd_AdaptHops.Action
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

#Get IP routes that have an infINFOe valid lifetime
$Cmd_IpHops = @{
    Display = 'Get-NetRoute | Where-Object { $_.ValidLifetime -eq ([TimeSpan]::MaxValue) }'
    Action  = { Get-NetRoute | Where-Object { $_.ValidLifetime -eq ([TimeSpan]::MaxValue) } }
}
$IpHops = & $Cmd_IpHops.Action
# Populate the HTML table with process information
foreach ($process in $IpHops) {
  $IpHopsFragment += "<tr>"
  $IpHopsFragment += "<td>$($process.ifIndex)</td>"
  $IpHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $IpHopsFragment += "<td>$($process.NextHop)</td>"
  $IpHopsFragment += "<td>$($process.RouteMetric)</td>"
  $IpHopsFragment += "<td>$($process.InterfaceMetric)</td>"
  $IpHopsFragment += "<td>$($process.InterfaceAlias)</td>"
  $IpHopsFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "NETWORK"

#endregion

Write-ForensicLog ""

##################################################
#region User & Account Information               #
##################################################

Write-ForensicLog "[*] Gathering User Account Details" -Level INFO -Section "USER"

# Gets local user accounts and details. Replaces net user and wmic useraccount list full
$Cmd_LocalUserAccounts = @{
    Display = 'Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description, PasswordChangeableDate, UserMayChangePassword'
    Action  = { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description, PasswordChangeableDate, UserMayChangePassword }
}
$LocalUserAccounts = & $Cmd_LocalUserAccounts.Action
foreach ($process in $LocalUserAccounts) {
  $LocalUserAccountsFragment += "<tr>"
  $LocalUserAccountsFragment += "<td>$($process.Name)</td>"
  $LocalUserAccountsFragment += "<td>$($process.Enabled)</td>"
  $LocalUserAccountsFragment += "<td>$($process.LastLogon)</td>"
  $LocalUserAccountsFragment += "<td>$($process.PasswordLastSet)</td>"
  $LocalUserAccountsFragment += "<td>$($process.PasswordExpires)</td>"
  $LocalUserAccountsFragment += "<td>$($process.Description)</td>"
  $LocalUserAccountsFragment += "<td>$($process.PasswordChangeableDate)</td>"
  $LocalUserAccountsFragment += "<td>$($process.UserMayChangePassword)</td>"
  $LocalUserAccountsFragment += "</tr>"
}

# Gets local administrators group members. Replaces net localgroup administrators
$Cmd_Administrators = @{
    Display = 'Get-LocalGroupMember -Group "Administrators"'
    Action  = { Get-LocalGroupMember -Group 'Administrators' }
}
$administrators = & $Cmd_Administrators.Action

$adminFragment = ""

foreach ($process in $administrators) {
  $adminFragment += "<tr>"
  $adminFragment += "<td>$($process.Name)</td>"
  $adminFragment += "<td>$($process.ObjectClass)</td>"
  $adminFragment += "<td>$($process.PrincipalSource)</td>"
  $adminFragment += "</tr>"
}

# Gets active logon sessions. 
$Cmd_logonsession = @{
    Display = 'quser 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_ -replace "^\s*>?", "") -replace "\s{2,}", "," } | ConvertFrom-Csv -Header Username,SessionName,ID,State,IdleTime,LogonTime | Select-Object @{N="Username";E={$_.Username}}, @{N="Domain";E={$env:COMPUTERNAME}}, @{N="LogonType";E={"Interactive"}}, @{N="LogonTime";E={$_.LogonTime}}, @{N="IDLETIME";E={$_.IdleTime}}'
    Action  = { quser 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_ -replace '^\s*>?', '') -replace '\s{2,}', ',' } | ConvertFrom-Csv -Header Username,SessionName,ID,State,IdleTime,LogonTime | Select-Object @{N='Username';E={$_.Username}}, @{N='Domain';E={$env:COMPUTERNAME}}, @{N='LogonType';E={'Interactive'}}, @{N='LogonTime';E={$_.LogonTime}}, @{N='IDLETIME';E={$_.IdleTime}} }
}

$logonsession = & $Cmd_logonsession.Action

$logonsessionFragment = ""
# Populate the HTML table with process information
foreach ($process in $logonsession) {
  $logonsessionFragment += "<tr>"
  $logonsessionFragment += "<td>$($process.Username)</td>"
  $logonsessionFragment += "<td>$($process.Domain)</td>"
  $logonsessionFragment += "<td>$($process.LogonType)</td>"
  $logonsessionFragment += "<td>$($process.LogonTime)</td>"
  $logonsessionFragment += "<td>$($process.IdleTime)</td>"
  $logonsessionFragment += "</tr>"
}

# Gets user profiles and last use time. Replaces wmic userprofile list full
$Cmd_UserProfiles = @{
    Display = 'Get-CimInstance Win32_UserProfile | Where-Object {$_.LocalPath -like "C:\Users\*"} | Select-Object @{N="Username";E={Split-Path $_.LocalPath -Leaf}}, SID, @{N="LastUseTime";E={[datetime]$_.LastUseTime}}'
    Action  = { Get-CimInstance Win32_UserProfile | Where-Object {$_.LocalPath -like 'C:\Users\*'} | Select-Object @{N='Username';E={Split-Path $_.LocalPath -Leaf}}, SID, @{N='LastUseTime';E={[datetime]$_.LastUseTime}} }
}

$userprofiles = & $Cmd_UserProfiles.Action

$profileFragment = ""

foreach ($process in $userprofiles) {
  $profileFragment += "<tr>"
  $profileFragment += "<td>$($process.Username)</td>"
  $profileFragment += "<td>$($process.SID)</td>"
  $profileFragment += "<td>$($process.LastUseTime)</td>"
  $profileFragment += "</tr>"
}

# Gets members of local groups. Replaces net localgroup and net localgroup "Remote Desktop Users"
$Cmd_LocalGroup = @{
    Display = "'Administrators','Remote Desktop Users','Backup Operators','Power Users' | ForEach-Object { Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue } | Select-Object @{N='Group';E={$_.'Group'}}, @{N='Username';E={($_.Name -split '\\')[-1]}}, @{N='Domain';E={($_.Name -split '\\')[0]}}, @{N='Type';E={$_.ObjectClass}}"
    Action  = { 'Administrators','Remote Desktop Users','Backup Operators','Power Users' | ForEach-Object { Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue } | Select-Object @{N='Group';E={$_.'Group'}}, @{N='Username';E={($_.Name -split '\\')[-1]}}, @{N='Domain';E={($_.Name -split '\\')[0]}}, @{N='Type';E={$_.ObjectClass}} }
}

$LocalGroup = & $Cmd_LocalGroup.Action

$localFragment = ""
foreach ($process in $LocalGroup) {
  $localFragment += "<tr>"
  $localFragment += "<td>$($process.Group)</td>"
  $localFragment += "<td>$($process.Username)</td>"
  $localFragment += "<td>$($process.Domain)</td>"
  $localFragment += "<td>$($process.Type)</td>"
  $localFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "USER"

#endregion

Write-ForensicLog ""



##################################################
#region System Info                              #
##################################################

Write-ForensicLog "[*] Gathering System Information" -Level INFO -Section "SYSTEM_INFO"

# Gets operating system information. Replaces systeminfo and wmic os get /format:list
$Cmd_OSinfo = @{
    Display = 'Get-CimInstance -Class Win32_OperatingSystem | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite'
    Action  = { Get-CimInstance -Class Win32_OperatingSystem | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite }
}
$OSinfo = & $Cmd_OSinfo.Action

foreach ($process in $OSinfo) {
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Name</div><div class='kv-list-v'>$($process.Name)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Version</div><div class='kv-list-v'>$($process.Version)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Build Number</div><div class='kv-list-v'>$($process.BuildNumber)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Install Date</div><div class='kv-list-v'>$($process.InstallDate)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>System Drive</div><div class='kv-list-v'>$($process.SystemDrive)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Windows Directory</div><div class='kv-list-v'>$($process.WindowsDirectory)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Last Bootup Time</div><div class='kv-list-v'>$($process.LastBootupTime)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Number of Users</div><div class='kv-list-v'>$($process.NumberofUsers)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Registered User</div><div class='kv-list-v'>$($process.RegisteredUser)</div></div>"
  $OSinfoFragment += "<div class='kv-list-row'><div class='kv-list-k'>Organization</div><div class='kv-list-v'>$($process.Organization)</div></div>"
}

# Gets installed applications. Replaces wmic product get /format:list and Get-Package
$Cmd_InstalledApps = @{
    Display = 'Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString'
    #Action  = { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString }
}

$paths = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$InstalledApps = Get-ItemProperty $paths | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString

if ($InstalledApps) {
    foreach ($process in $InstalledApps) {
        $InstalledAppsFragment += "<tr>"
        $InstalledAppsFragment += "<td>$($process.DisplayName)</td>"
        $InstalledAppsFragment += "<td>$($process.DisplayVersion)</td>"
        $InstalledAppsFragment += "<td>$($process.Publisher)</td>"
        $InstalledAppsFragment += "<td>$($process.InstallDate)</td>"
        $InstalledAppsFragment += "<td>$($process.InstallLocation)</td>"
        $InstalledAppsFragment += "<td>$($process.UninstallString)</td>"
        $InstalledAppsFragment += "</tr>"
    }
}
else {
   # $InstalledAppsFragment = "<tr><td colspan='7'>No installed applications found.</td></tr>"
}

# Gets logical drive information. Replaces wmic logicaldisk get /format:list and fsutil fsinfo drives
$Cmd_LogicalDrives = @{
    Display = 'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, VolumeName, @{N="Size (GB)";E={[math]::Round($_.Size/1GB,2)}}, @{N="Free (GB)";E={[math]::Round($_.FreeSpace/1GB,2)}}, @{N="%Free";E={ if ($_.Size -gt 0) {[math]::Round(($_.FreeSpace/$_.Size)*100,2)} else {0} }}'
    Action  = { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object @{N='Drive';E={$_.DeviceID}}, @{N='Label';E={$_.VolumeName}}, @{N='Size (GB)';E={[math]::Round($_.Size/1GB,2)}}, @{N='Free (GB)';E={[math]::Round($_.FreeSpace/1GB,2)}}, @{N='%Free';E={ if ($_.Size -gt 0) {[math]::Round(($_.FreeSpace/$_.Size)*100,2)} else {0} }} }
}

$LogicalDrives = & $Cmd_LogicalDrives.Action

if ($LogicalDrives) {

    foreach ($process in $LogicalDrives) {
        $LogicalDrivesFragment += "<tr>"
        $LogicalDrivesFragment += "<td>$($process.Drive)</td>"
        $LogicalDrivesFragment += "<td>$($process.Label)</td>"
        $LogicalDrivesFragment += "<td>$($process.'Size (GB)')</td>"
        $LogicalDrivesFragment += "<td>$($process.'Free (GB)')</td>"
        $LogicalDrivesFragment += "<td>$($process.'%Free')</td>"
        $LogicalDrivesFragment += "</tr>"
    }

}
else {
   # $LogicalDrivesFragment = "<tr><td colspan='5'>No local fixed drives found.</td></tr>"
}

# Gets environment variables. Replaces set and wmic environment list full
$Cmd_interestingenv = @{
    Display = "'PATH','TEMP','TMP','USERNAME','USERDOMAIN','COMPUTERNAME','APPDATA','LOCALAPPDATA','PROCESSOR_ARCHITECTURE','ProgramFiles','ProgramFiles(x86)' | ForEach-Object { Get-ChildItem Env:\$_ } | Select-Object Name, Value"
    #Action  = { 'PATH','TEMP','TMP','USERNAME','USERDOMAIN','COMPUTERNAME','APPDATA','LOCALAPPDATA','PROCESSOR_ARCHITECTURE','ProgramFiles','ProgramFiles(x86)' | ForEach-Object { Get-ChildItem Env:\$_ } | Select-Object Name, Value }
}

$interestingenv = 'PATH','TEMP','TMP','USERNAME','USERDOMAIN','COMPUTERNAME','APPDATA','LOCALAPPDATA','PROCESSOR_ARCHITECTURE','ProgramFiles','ProgramFiles(x86)'

$envFragment = ""

Get-ChildItem Env: | Where-Object { $interestingenv -contains $_.Name } |
Select-Object Name, Value | ForEach-Object {
  $envFragment += "<tr>"
  $envFragment += "<td>$($_.Name)</td>"
  $envFragment += "<td>$($_.Value)</td>"
  $envFragment += "</tr>"
}

# Gets installed hotfixes. Replaces wmic qfe list full and systeminfo
$Cmd_Hotfixes = @{
    Display = 'Get-HotFix | Select-Object -Property CSName, Caption, Description, HotFixID, InstalledBy, InstalledOn'
    Action  = { Get-Hotfix | Select-Object -Property CSName, Caption, Description, HotfixID, InstalledBy, InstalledOn }
}
$Hotfixes = & $Cmd_Hotfixes.Action

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

# Gets Windows Defender status and configuration. 
$Cmd_WinDefender = @{
    Display = 'Get-MpComputerStatus | Select-Object -Property AMProductVersion, AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, BehaviorMonitorEnabled, DefenderSignaturesOutOfDate, DeviceControlPoliciesLastUpdated, DeviceControlState, NISSignatureLastUpdated, QuickScanEndTime, RealTimeProtectionEnabled'
    Action  = { Get-MpComputerStatus | Select-Object -Property AMProductVersion, AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, BehaviorMonitorEnabled, DefenderSignaturesOutOfDate, DeviceControlPoliciesLastUpdated, DeviceControlState, NISSignatureLastUpdated, QuickScanEndTime, RealTimeProtectionEnabled }
}
$WinDefender = & $Cmd_WinDefender.Action
# Populate the HTML table with process information
foreach ($process in $WinDefender) {
  $WinDefenderFragment += "<tr>"
  $WinDefenderFragment += "<td>$($process.AMProductVersion)</td>"
  $WinDefenderFragment += "<td>$($process.AMRunningMode)</td>"
  $WinDefenderFragment += "<td>$($process.AMServiceEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.BehaviorMonitorEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.DefenderSignaturesOutOfDate)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlPoliciesLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlState)</td>"
  $WinDefenderFragment += "<td>$($process.NISSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.QuickScanEndTime)</td>"
  $WinDefenderFragment += "<td>$($process.RealTimeProtectionEnabled)</td>"
  $WinDefenderFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "SYSTEM_INFO"

Write-ForensicLog ""

#endregion



##################################################
#region Live Running Processes & Startup programs #
##################################################

Write-ForensicLog "[*] Gathering Processes" -Level INFO -Section "PROCESSES"

# Gets running processes and details. Replaces tasklist /v and wmic process list full
$Cmd_Processes = @{
    Display = 'Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate'
}

$processByPid = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
    Group-Object -Property Id -AsHashTable -AsString

$sigCache = @{}

$ProcessFragment = foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {

    $gp = $processByPid["$($p.ProcessId)"]
    if ($gp -is [Array]) { $gp = $gp[0] }

    $sigStatus = ''
    if ($p.ExecutablePath) {
        if (-not $sigCache.ContainsKey($p.ExecutablePath)) {
            $sigCache[$p.ExecutablePath] = (Get-AuthenticodeSignature -LiteralPath $p.ExecutablePath -ErrorAction SilentlyContinue).Status
        }
        $sigStatus = $sigCache[$p.ExecutablePath]
    }

    [PSCustomObject]@{
        Name             = $p.Name
        PID              = $p.ProcessId
        PPID             = $p.ParentProcessId
        UserName         = $gp.UserName
        ExecutablePath   = $p.ExecutablePath
        CommandLine      = $p.CommandLine
        CPU              = $gp.CPU
        MemoryMB         = [math]::Round($p.WorkingSetSize / 1MB, 2)
        CreationDate     = $p.CreationDate
        SignatureStatus  = $sigStatus
    }
}

function Encode-Cell {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$ProcessFragmentrows = $ProcessFragment | ForEach-Object {
  "<tr><td>$(Encode-Cell $_.Name)</td><td>$(Encode-Cell $_.PID)</td><td>$(Encode-Cell $_.PPID)</td><td>$(Encode-Cell $_.UserName)</td><td class='path-cell'>$(Encode-Cell $_.ExecutablePath)</td><td class='cmd-cell'>$(Encode-Cell $_.CommandLine)</td><td>$(Encode-Cell $_.CPU)</td><td>$(Encode-Cell $_.MemoryMB)</td><td>$(Encode-Cell $_.CreationDate)</td><td>$(Encode-Cell $_.SignatureStatus)</td></tr>"
}

# Gets startup programs. Replaces wmic startup get /format:list and autoruns
$Cmd_StartupProgs = @{
    Display = 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User'
    Action  = { Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User }
}
$StartupProgs = & $Cmd_StartupProgs.Action

foreach ($process in $StartupProgs) {
  $StartupProgsFragment += "<tr>"
  $StartupProgsFragment += "<td>$(Encode-Cell $process.Name)</td>"
  $StartupProgsFragment += "<td>$(Encode-Cell $process.command)</td>"
  $StartupProgsFragment += "<td>$(Encode-Cell $process.Location)</td>"
  $StartupProgsFragment += "<td>$(Encode-Cell $process.User)</td>"
  $StartupProgsFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "PROCESSES"

Write-ForensicLog ""

#endregion


################################################################################
#region Services                                                              ##
################################################################################

Write-ForensicLog "[*] Gathering Services" -Level INFO -Section "SERVICES"

# Gets services and details. Replaces wmic service list full and sc queryex type= service
$Cmd_Services = @{
    Display = 'Get-CimInstance Win32_Service | Select-Object DisplayName, Name, State, StartMode, StartName, @{Name="Command";Expression={$_.PathName}}, @{Name="BinaryPath";Expression={ if ($_.PathName -match "^\"([^\"]+)\"") { $matches[1] } else { ($_.PathName -split "\s+")[0] } }}, Description'
}

$Services = Get-CimInstance Win32_Service | Select-Object `
    DisplayName,
    Name,
    State,
    StartMode,
    StartName,
    @{Name='Command';Expression={$_.PathName}},
    @{Name='BinaryPath';Expression={
        if ($_.PathName -match '^"([^"]+)"') {
            $matches[1]
        } else {
            ($_.PathName -split '\s+')[0]
        }
    }},
    Description

foreach ($process in $Services) {
  $ServicesFragment += "<tr>"
  $ServicesFragment += "<td>$(Encode-Cell $process.Name)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.DisplayName)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.State)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.StartMode)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.StartName)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.Command)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.BinaryPath)</td>"
  $ServicesFragment += "<td>$(Encode-Cell $process.Description)</td>"
  $ServicesFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "SERVICES"

Write-ForensicLog ""

#endregion


################################################################################
#region Scheduled Tasks                                                      ##
################################################################################

Write-ForensicLog "[*] Gathering Scheduled Tasks" -Level INFO -Section "SCHEDULED_TASKS"

# Gets scheduled tasks and details. Replaces schtasks /query /v and wmic path Win32_ScheduledJob list full
$Cmd_ScheduledTasks = @{
    Display = 'Get-ScheduledTask | Get-ScheduledTaskInfo'
}

$ScheduledTasksFragment = foreach ($t in Get-ScheduledTask) {
    $info = $t | Get-ScheduledTaskInfo


    "<tr><td>$(Encode-Cell $t.TaskName)</td><td>$(Encode-Cell $t.TaskPath)</td><td>$(Encode-Cell $t.State)</td><td>$(Encode-Cell $t.Principal.UserId)</td><td>$(Encode-Cell (($t.Actions | ForEach-Object { $_.Execute }) -join ', '))</td><td>$(Encode-Cell $info.LastRunTime)</td><td>$(Encode-Cell $info.NextRunTime)</td><td>$(Encode-Cell $info.LastTaskResult)</td></tr>"

}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "SCHEDULED_TASKS"

Write-ForensicLog ""

#endregion


<#

##################################################
#region Settings from the Registry			     #
##################################################

Write-ForensicLog "[*] Checking Registry for persistance" -Level INFO -Section "REGISTRY"

function Get-RegistryHtml {
    param($Path)

    try{
        $data = Get-ItemProperty -Path $Path -ErrorAction Stop

        if($data){
            return $data | ConvertTo-Html -As List -Fragment |
                   Select-Object -Skip 1 |
                   Select-Object -SkipLast 1
        }
        else{
            return "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>No Entry Found</td></tr>"
        }
    }
    catch{
        return "<tr><td colspan='9' style='text-align:center;color:#e74c3c;'>Key not found or inaccessible</td></tr>"
    }
}

$RegRun = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

$RegRunOnce = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

$RegRunOnceEx = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "REGISTRY"

#endregion

Write-ForensicLog ""
#>


##################################################
#region Files & USB			                         #
##################################################

Write-ForensicLog "[*] Gathering Files & USB Information" -Level INFO -Section "FILES_USB"

#Gets list of USB devices
$Cmd_USBDevices = @{
    Display = 'Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select-Object FriendlyName, Driver, Mfg, DeviceDesc'
    Action  = { Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Enum\USB*\*\*' | Select-Object FriendlyName, Driver, mfg, DeviceDesc }
}
$USBDevices = & $Cmd_USBDevices.Action

if ($USBDevices) {
foreach ($process in $USBDevices) {
  $USBDevicesFragment += "<tr>"
  $USBDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $USBDevicesFragment += "<td>$($process.Driver)</td>"
  $USBDevicesFragment += "<td>$($process.mfg)</td>"
  $USBDevicesFragment += "<td>$($process.DeviceDesc)</td>"
  $USBDevicesFragment += "</tr>"
}

} else {
    $USBDevicesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Gets list of imaging devices (cameras, webcams, etc)
$Cmd_Imagedevice = @{
    Display = 'Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq "Image" -or $_.Caption -match "camera|webcam" } | Select-Object Caption, Manufacturer, DeviceID, Status, Present'
    Action  = { Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq "Image" -or $_.Caption -match "camera|webcam" } | Select-Object Caption, Manufacturer, DeviceID, Status, Present }
}

$Imagedevice = & $Cmd_Imagedevice.Action

if ($Imagedevice) {
foreach ($process in $Imagedevice) {
  $ImagedeviceFragment += "<tr>"
  $ImagedeviceFragment += "<td>$($process.Caption)</td>"
  $ImagedeviceFragment += "<td>$($process.Manufacturer)</td>"
  $ImagedeviceFragment += "<td>$($process.Status)</td>"
  $ImagedeviceFragment += "<td>$($process.Present)</td>"
  $ImagedeviceFragment += "</tr>"
}
} else {
    $ImagedeviceFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# All currently connected PNP devices
$Cmd_UPNPDevices = @{
    Display = 'Get-PnpDevice -PresentOnly | Where-Object { $_.Class -in @("USB","DiskDrive","Mouse","Keyboard","Net","Image","Media","Monitor") } | Select-Object Status, Class, FriendlyName, InstanceId'
    Action  = { Get-PnpDevice -PresentOnly | Where-Object { $_.Class -in @('USB','DiskDrive','Mouse','Keyboard','Net','Image','Media','Monitor') } | Select-Object Status, Class, FriendlyName, InstanceId }
}

$UPNPDevices = & $Cmd_UPNPDevices.Action


if ($UPNPDevices) {
foreach ($process in $UPNPDevices) {
  $UPNPDevicesFragment += "<tr>"
  $UPNPDevicesFragment += "<td>$($process.Status)</td>"
  $UPNPDevicesFragment += "<td>$($process.Class)</td>"
  $UPNPDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $UPNPDevicesFragment += "<td>$($process.InstanceId)</td>"
  $UPNPDevicesFragment += "</tr>"
}
} else {
    $UPNPDevicesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# All previously connected disk drives not currently accounted for. Useful if target computer has had drive replaced/hidden
$Cmd_UnknownDrives = @{
    Display = 'Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName } | Select-Object FriendlyName, Mfg, @{Name="Serial";Expression={$_.PSChildName}}, @{Name="LastWriteTime";Expression={ (Get-Item $_.PSPath).LastWriteTime }} | Sort-Object LastWriteTime -Descending'
    Action  = { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName } | Select-Object FriendlyName, Mfg, @{Name="Serial";Expression={$_.PSChildName}}, @{Name="LastWriteTime";Expression={ (Get-Item $_.PSPath).LastWriteTime }} | Sort-Object LastWriteTime -Descending }
}

$UnknownDrives = & $Cmd_UnknownDrives.Action

if ($UnknownDrives) {
foreach ($process in $UnknownDrives) {
  $UnknownDrivesFragment += "<tr>"
  $UnknownDrivesFragment += "<td>$($process.FriendlyName)</td>"
  $UnknownDrivesFragment += "<td>$($process.Mfg)</td>"
  $UnknownDrivesFragment += "<td>$($process.Serial)</td>"
  $UnknownDrivesFragment += "<td>$($process.LastWriteTime)</td>"
  $UnknownDrivesFragment += "</tr>"
}
} else {
    $UnknownDrivesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Gets all link files created in last 180 days. Perhaps export this as a separate CSV and make it keyword searchable?
$Cmd_LinkFiles = @{
    Display = 'Get-ChildItem -Path "C:\Users" -Recurse -Filter *.lnk'
}

$lnkFiles = Get-ChildItem -Path "C:\Users" -Recurse -Filter *.lnk -ErrorAction SilentlyContinue

$WshShell = New-Object -ComObject WScript.Shell

$shortcuts = foreach ($file in $lnkFiles) {
    try {
        $shortcut = $WshShell.CreateShortcut($file.FullName)

        [PSCustomObject]@{
            Name         = $file.Name
            Path         = $file.FullName
            Target       = $shortcut.TargetPath
            Arguments    = $shortcut.Arguments
            LastAccess   = $file.LastAccessTime
            Created      = $file.CreationTime
        }
    }
    catch { }
}


if ($shortcuts) {
    foreach ($s in $shortcuts) {
        $LinkFilesFragment += "<tr>"
        $LinkFilesFragment += "<td>$(Encode-Cell $s.Name)</td>"
        $LinkFilesFragment += "<td>$(Encode-Cell $s.Target)</td>"
        $LinkFilesFragment += "<td>$(Encode-Cell $s.Arguments)</td>"
        $LinkFilesFragment += "<td>$(Encode-Cell $s.LastAccess)</td>"
        $LinkFilesFragment += "<td>$(Encode-Cell $s.Created)</td>"
        $LinkFilesFragment += "</tr>"
    }
}
else {
    $LinkFilesFragment += "<tr><td colspan='4'>No shortcuts found</td></tr>"
}

# Gets PowerShell command history from current session and PSReadLine history file. Note that PSReadLine history may not be available if the user has disabled it or is using a custom shell like Windows Terminal that doesn't use the default PSReadLine configuration.
$Cmd_PSHistory = @{
    Display = 'Get-History -ErrorAction SilentlyContinue | Select-Object Id, CommandLine, StartExecutionTime, EndExecutionTime'
}

$sessionHistory = Get-History -ErrorAction SilentlyContinue |
    Select-Object Id, CommandLine, StartExecutionTime, EndExecutionTime

$fileHistory = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    ForEach-Object {
        Get-Content $_.FullName | ForEach-Object {
            [PSCustomObject]@{
                Source = "File"
                Command = $_
            }
        }
    }

$PSHistory = @($sessionHistory) + @($fileHistory)


if ($PSHistory) {
    foreach ($cmd in $PSHistory) {
        $PSHistoryFragment += "<tr>"
        $PSHistoryFragment += "<td>$(Encode-Cell $cmd.User)</td>"
        $PSHistoryFragment += "<td>$(Encode-Cell $cmd.Command)</td>"
        $PSHistoryFragment += "</tr>"
    }
}
else {
    $PSHistoryFragment += "<tr><td colspan='2'>No PowerShell history found</td></tr>"
}

# Gets all executables created in last 180 days in common user accessible locations. This may be a bit noisy but can be useful for identifying recently added files that may have been used for persistence or lateral movement. Perhaps export this as a separate CSV and make it keyword searchable?
$Cmd_NewFiles = @{
    Display = 'Get-ChildItem -Path $paths -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-180) -and $_.Extension -match ''\.exe|\.dll|\.ps1|\.bat|\.vbs|\.js'' }'
}

$paths = @(
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "C:\Users\Public",
    "C:\ProgramData"
)

$NewFiles = foreach ($path in $paths) {
    Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -ge (Get-Date).AddDays(-180) -and
        $_.Extension -match '\.exe|\.dll|\.ps1|\.bat|\.vbs|\.js'
    } | ForEach-Object {
        "<tr><td>$(Encode-Cell $_.Name)</td><td>$(Encode-Cell $_.Extension)</td><td>$(Encode-Cell $_.FullName)</td><td>$(Encode-Cell $_.LastWriteTime)</td><td>$(Encode-Cell ('{0} KB' -f [math]::Round($_.Length/1KB,2)))</td></tr>"
    }
}


# Gets all executables in Downloads folder. This may cause an error if the script is run from an external USB or Network drive.
$Cmd_Downloads = @{
    Display = 'Get-ChildItem C:\Users\*\Downloads\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.Extension -eq ".exe" }'
    Action  = { Get-ChildItem C:\Users\*\Downloads\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } }
}
$Downloads = & $Cmd_Downloads.Action

if ($Downloads) {
foreach ($process in $Downloads) {
  $DownloadsFragment += "<tr>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.Name)</td>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.FullName)</td>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.CreationTimeUTC)</td>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.LastAccessTimeUTC)</td>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.LastWriteTimeUTC)</td>"
  $DownloadsFragment += "<td>$(Encode-Cell $process.Attributes)</td>"
  $DownloadsFragment += "</tr>"
}
} else {
    $DownloadsFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Executables Running From Obscure Places
$Cmd_HiddenExecs1 = @{
    Display = 'Get-ChildItem C:\Users\*\AppData\Local\Temp\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.Extension -eq ".exe" }'
    Action  = { Get-ChildItem C:\Users\*\AppData\Local\Temp\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } }
}
$HiddenExecs1 = & $Cmd_HiddenExecs1.Action

if ($HiddenExecs1) {
foreach ($process in $HiddenExecs1) {
  $HiddenExecs1Fragment += "<tr>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.Name)</td>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.FullName)</td>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.CreationTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.LastAccessTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.LastWriteTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$(Encode-Cell $process.Attributes)</td>"
  $HiddenExecs1Fragment += "</tr>"
}
} else {
    $HiddenExecs1Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Executables Running From Obscure Places - Part 2. This is a common location for attackers to hide tools and scripts, especially if they have limited permissions on the system. It's also a common location for fileless malware to drop payloads that are then executed directly from memory.
$Cmd_HiddenExecs2 = @{
    Display = 'Get-ChildItem C:\Temp\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.Extension -eq ".exe" }'
    Action  = { Get-ChildItem C:\Temp\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } }
}
$HiddenExecs2 = & $Cmd_HiddenExecs2.Action

if ($HiddenExecs2) {
foreach ($process in $HiddenExecs2) {
  $HiddenExecs2Fragment += "<tr>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.Name)</td>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.FullName)</td>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.CreationTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.LastAccessTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.LastWriteTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$(Encode-Cell $process.Attributes)</td>"
  $HiddenExecs2Fragment += "</tr>"
}
} else {
    $HiddenExecs2Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Executables Running From Obscure Places - Part 3. This is another common location for attackers to hide tools and scripts, especially if they have limited permissions on the system. It's also a common location for fileless malware to drop payloads that are then executed directly from memory.
$Cmd_HiddenExecs3 = @{
    Display = 'Get-ChildItem C:\PerfLogs\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.Extension -eq ".exe" }'
    Action  = { Get-ChildItem C:\PerfLogs\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } }
}
$HiddenExecs3 = & $Cmd_HiddenExecs3.Action

if ($HiddenExecs3) {
foreach ($process in $HiddenExecs3) {
  $HiddenExecs3Fragment += "<tr>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.Name)</td>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.FullName)</td>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.CreationTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.LastAccessTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.LastWriteTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$(Encode-Cell $process.Attributes)</td>"
  $HiddenExecs3Fragment += "</tr>"
}
} else {
    $HiddenExecs3Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

# Executables Running From Obscure Places - Part 4. This is another common location for attackers to hide tools and scripts, especially if they have limited permissions on the system. It's also a common location for fileless malware to drop payloads that are then executed directly from memory.
$Cmd_HiddenExecs4 = @{
    Display = 'Get-ChildItem C:\Users\*\Documents\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.Extension -eq ".exe" }'
    Action  = { Get-ChildItem C:\Users\*\Documents\* -Recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } }
}
$HiddenExecs4 = & $Cmd_HiddenExecs4.Action

if ($HiddenExecs4) {
foreach ($process in $HiddenExecs4) {
  $HiddenExecs4Fragment += "<tr>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.Name)</td>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.FullName)</td>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.CreationTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.LastAccessTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.LastWriteTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$(Encode-Cell $process.Attributes)</td>"
  $HiddenExecs4Fragment += "</tr>"
}
} else {
    $HiddenExecs4Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "FILES_USB"

Write-ForensicLog ""

#endregion



###########################################################################################################
#region #######  VIEW USER GP RESULTS    ##################################################################
###########################################################################################################
# get GPO REsult if on domain

$Cmd_GPOResult = @{
    Display = 'GPRESULT /H "$PSScriptRoot\$env:COMPUTERNAME\GroupPolicy\GPOReport.html" /F'
    Action  = { GPRESULT /H "$PSScriptRoot\$env:COMPUTERNAME\GroupPolicy\GPOReport.html" /F }
}

$cs = Get-CimInstance Win32_ComputerSystem

if ($cs.PartOfDomain) {
    
  Write-ForensicLog "[*] Collecting GPO Results" -Level INFO -Section "GPORESULT"

  & $Cmd_GPOResult.Action

  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "GPORESULT"
}
else {
  Write-ForensicLog "[!] Computer is not joined to a domain...moving on" -Level INFO -Section "GPORESULT"
}

Write-ForensicLog ""

#endregion


###########################################################################################################
#region  MEMORY (RAM) CAPTURE    ##########################################################################
###########################################################################################################



if($RAM){

  Write-ForensicLog ""

    mkdir "$PSScriptRoot\$env:COMPUTERNAME\RAM" -ErrorAction SilentlyContinue | Out-Null

    # ---------------------------------------------------------
    # FULL PHYSICAL RAM — requires winpmem kernel driver
    # There is no native Windows equivalent for full acquisition
    # ---------------------------------------------------------
    $arch     = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    $winpmem  = if($arch -eq "64-bit"){
                    "$PSScriptRoot\Forensicator-Share\winpmem_mini_x64_rc2.exe"
                } else {
                    "$PSScriptRoot\Forensicator-Share\winpmem_mini_x86.exe"
                }

    $rawPath  = "$PSScriptRoot\$env:COMPUTERNAME\RAM\$env:COMPUTERNAME.raw"

    if(Test-Path $winpmem){

        Write-ForensicLog "[*] Acquiring physical RAM via winpmem..." -Level INFO -Section "RAM_CAPTURE"

        $proc = Start-Process -FilePath $winpmem `
                              -ArgumentList $rawPath `
                              -Wait -PassThru -NoNewWindow

        if(Test-Path $rawPath){

    $file    = Get-Item $rawPath
    $sizeMB  = [Math]::Round($file.Length / 1MB, 2)

    # ---------------------------------------------------------
    # Get system RAM
    # ---------------------------------------------------------
    try{
        $expectedRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $expectedMB  = [Math]::Round($expectedRAM / 1MB, 2)
    }
    catch{
        $expectedMB = 0
    }

    # ---------------------------------------------------------
    # Compare dump vs system RAM
    # ---------------------------------------------------------
    if($expectedMB -gt 0){
        $percent = [Math]::Round(($sizeMB / $expectedMB) * 100, 2)
    }
    else{
        $percent = 0
    }

    # ---------------------------------------------------------
    # Evaluation logic
    # ---------------------------------------------------------
    if($sizeMB -lt 100){
      Write-ForensicLog ("[!] RAM dump too small ({0} MB) - acquisition likely failed" -f $sizeMB) -Level ERROR -Section "RAM_CAPTURE" -Detail "Acquired RAM size is less than 100 MB. This may indicate acquisition failure, or antivirus blocking the tool from writing the dump."
    }
    else{
        if($proc.ExitCode -ne 0){
            Write-ForensicLog "[!] RAM acquired but tool returned exit code $($proc.ExitCode) — likely non-critical" -Level WARN -Section "RAM_CAPTURE" -Detail "winpmem returned a non-zero exit code ($($proc.ExitCode)). However, the RAM dump was created and is of a reasonable size. This may indicate a non-critical issue with the tool, or antivirus interference causing it to return an error code despite successful acquisition."
        }

        if($percent -ge 90){
          Write-ForensicLog ("[+] RAM acquired - {0} ({1} MB | ~{2}% of system RAM)" -f $rawPath, $sizeMB, $percent) -Level INFO -Section "RAM_CAPTURE" -Detail "Acquired RAM size is 90% or more of expected system RAM. This is a strong indicator of successful acquisition, though antivirus interference cannot be fully ruled out."
        }
        elseif($percent -ge 70){
          Write-ForensicLog ("[!] RAM partially acquired - {0} ({1} MB | ~{2}% of system RAM)" -f $rawPath, $sizeMB, $percent) -Level WARN -Section "RAM_CAPTURE" -Detail "Acquired RAM size is between 70% and 90% of expected system RAM. This may indicate partial acquisition or interference from antivirus software."
        }
        else{
          Write-ForensicLog ("[!] RAM acquisition incomplete - {0} ({1} MB | ~{2}% of system RAM)" -f $rawPath, $sizeMB, $percent) -Level ERROR -Section "RAM_CAPTURE" -Detail "Acquired RAM size is less than 70% of expected system RAM. This may indicate acquisition failure, or antivirus blocking the tool from writing the dump."
        }

        if($expectedMB -gt 0){
          Write-ForensicLog ("[i] Expected RAM: {0} MB" -f $expectedMB) -Level INFO -Section "RAM_CAPTURE" -Detail "System RAM as reported by WMI (Win32_ComputerSystem.TotalPhysicalMemory)"
        }
    }
}
else{
    Write-ForensicLog "[!] RAM acquisition failed — output file not found" -Level ERROR -Section "RAM_CAPTURE" -Detail "Expected RAM dump at $rawPath but file was not created. This may be due to acquisition failure, or antivirus blocking the tool from writing the dump."
}

    }
    else{

        Write-ForensicLog "[!] winpmem not found at $winpmem" -Level WARN -Section "RAM_CAPTURE" -Detail "Expected winpmem at $winpmem for physical RAM acquisition. This may be due to the tool not being present, or antivirus blocking it. Attempting fallback collection of volatile memory artefacts instead."
        Write-ForensicLog "[!] Falling back to volatile memory snapshot (no physical RAM dump)" -Level WARN -Section "RAM_CAPTURE"

        # ---------------------------------------------------------
        # FALLBACK — volatile memory artefacts collectable without
        # a kernel driver. Not a RAM image but captures the most
        # forensically relevant in-memory state.
        # ---------------------------------------------------------

        # 1. Full process list with commandlines, parent, and memory
        Write-ForensicLog "[*] Collecting process memory map..." -Level INFO -Section "RAM_CAPTURE"

        $processes = Get-CimInstance Win32_Process |
                     Select-Object ProcessId, ParentProcessId, Name,
                                   CommandLine, WorkingSetSize,
                                   VirtualSize, HandleCount,
                                   @{N="StartTime";E={$_.CreationDate}} |
                     Sort-Object WorkingSetSize -Descending







$ProcFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Process Memory Map</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Process Memory Map</h2>

<div class="summary">
Total URLs: $($Records.Count) |
Malicious URLs: $(( $Records | Where-Object {$_.IsMalicious}).Count)
</div>

<table>

<thead>
<tr>
<th>PID</th>
<th>PPID</th>
<th>Name</th>
<th>CommandLine</th>
<th>WorkingSet MB</th>
<th>Handles</th>
<th>StartTime</th>
</tr>
</thead>

<tbody>
"@



        foreach($p in $processes){
            $ProcFragment += "<tr>"
            $ProcFragment += "<td>$($p.ProcessId)</td>"
            $ProcFragment += "<td>$($p.ParentProcessId)</td>"
            $ProcFragment += "<td>$($p.Name)</td>"
            $ProcFragment += "<td>$([System.Web.HttpUtility]::HtmlEncode($p.CommandLine))</td>"
            $ProcFragment += "<td>$([Math]::Round($p.WorkingSetSize/1MB,1))</td>"
            $ProcFragment += "<td>$($p.HandleCount)</td>"
            $ProcFragment += "<td>$($p.StartTime)</td>"
            $ProcFragment += "</tr>"
        }



$ProcFragment += @"
</tbody>
</table>

</body>
</html>
"@


        $ProcFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\ProcessMemoryMap.html" -Encoding UTF8

        # 2. Loaded modules per process — surfaces injected DLLs
        Write-ForensicLog "[*] Collecting loaded modules..." -Level INFO -Section "RAM_CAPTURE"




$ModFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Loaded modules per process</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Loaded modules per process</h2>

<div class="summary">
Total URLs: $($Records.Count) |
Malicious URLs: $(( $Records | Where-Object {$_.IsMalicious}).Count)
</div>

<table>

<thead>
<tr>
<th>PID</th>
<th>Process</th>
<th>Module</th>
<th>Path</th>
<th>FileVersion</th>
</tr>
</thead>

<tbody>
"@



        Get-Process | ForEach-Object {
            $proc = $_
            try{
                $proc.Modules | ForEach-Object {
                    $ModFragment += "<tr>"
                    $ModFragment += "<td>$($proc.Id)</td>"
                    $ModFragment += "<td>$($proc.Name)</td>"
                    $ModFragment += "<td>$($_.ModuleName)</td>"
                    $ModFragment += "<td>$([System.Web.HttpUtility]::HtmlEncode($_.FileName))</td>"
                    $ModFragment += "<td>$($_.FileVersionInfo.FileVersion)</td>"
                    $ModFragment += "</tr>"
                }
            }
            catch{ } # Access denied on system processes is expected
        }



$ModFragment += @"
</tbody>
</table>

</body>
</html>
"@



        $ModFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\LoadedModules.html" -Encoding UTF8

        # 3. Network connections with owning PID
        Write-ForensicLog "[*] Collecting network connections..." -Level INFO -Section "RAM_CAPTURE"

        $connections = Get-NetTCPConnection |
                       Select-Object LocalAddress, LocalPort,
                                     RemoteAddress, RemotePort,
                                     State, OwningProcess,
                                     @{N="ProcessName";E={
                                         try{(Get-Process -Id $_.OwningProcess -EA Stop).Name}
                                         catch{"N/A"}
                                     }}

$NetFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network connections per process</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Network connections per process</h2>

<table>

<thead>
<tr>
<th>Local Address</th>
<th>Local Port</th>
<th>Remote Address</th>
<th>Remote Port</th>
<th>State</th>
<th>PID</th>
<th>Process</th>
</tr>
</thead>

<tbody>
"@



        foreach($c in $connections){
            $NetFragment += "<tr>"
            $NetFragment += "<td>$($c.LocalAddress)</td>"
            $NetFragment += "<td>$($c.LocalPort)</td>"
            $NetFragment += "<td>$($c.RemoteAddress)</td>"
            $NetFragment += "<td>$($c.RemotePort)</td>"
            $NetFragment += "<td>$($c.State)</td>"
            $NetFragment += "<td>$($c.OwningProcess)</td>"
            $NetFragment += "<td>$($c.ProcessName)</td>"
            $NetFragment += "</tr>"
        }



$NetFragment += @"
</tbody>
</table>

</body>
</html>
"@




        $NetFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\NetworkConnections.html" -Encoding UTF8

        # 4. Handles — open named pipes and mutants surface C2 IOCs
        # Requires SysInternals handle.exe for full fidelity
        # Best native alternative is querying WMI for named pipes
        Write-ForensicLog "[*] Collecting named pipes..."

        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') |
                 ForEach-Object { [PSCustomObject]@{ PipeName = $_ } }

        $PipeFragment  = "<table><thead><tr><th>Named Pipe</th></tr></thead><tbody>"
        foreach($pipe in $pipes){
            $PipeFragment += "<tr><td>$($pipe.PipeName)</td></tr>"
        }
        $PipeFragment += "</tbody></table>"
        $PipeFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\NamedPipes.html" -Encoding UTF8

        # 5. Clipboard contents — volatile, lost on reboot
        Write-ForensicLog "[*] Collecting clipboard..." -Level INFO -Section "RAM_CAPTURE"
        try{
            Add-Type -AssemblyName System.Windows.Forms
            $clipboard = [System.Windows.Forms.Clipboard]::GetText()
            if(-not [string]::IsNullOrWhiteSpace($clipboard)){
                $clipboard | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\Clipboard.txt" -Encoding UTF8
            }
        }
        catch{
            Write-ForensicLog "[!] Could not retrieve clipboard contents" -Level ERROR -Section "RAM_CAPTURE" -Detail $_.Exception.Message
        }

        Write-ForensicLog "[!] Volatile snapshot complete — no physical RAM image" -Level WARN -Section "RAM_CAPTURE"
        Write-ForensicLog "[!] For full acquisition ensure winpmem is present and run the script with -RAM switch" -Level WARN -Section "RAM_CAPTURE"
    }

    Write-ForensicLog "[!] Done" -Level SUCCESS -Section "RAM_CAPTURE" -Detail "RAM acquisition complete (physical dump or volatile snapshot)"
}
else{
    Write-ForensicLog "[!] RAM capture not selected...moving on" -Level INFO -Section "RAM_CAPTURE"
}



Write-ForensicLog ""

#endregion




###########################################################################################################
#region  BROWSER HISTORY EXTRACTION              ##########################################################
###########################################################################################################

Write-ForensicLog "[*] Extracting Browser History" -Level INFO -Section "BROWSER_HISTORY"

#mkdir $PSScriptRoot\$env:COMPUTERNAME\BROWSING_HISTORY -ErrorAction SilentlyContinue | Out-Null

$sqlitePath = "$PSScriptRoot\Forensicator-Share\sqlite3.exe"

if(-not (Test-Path $sqlitePath)){
    Write-ForensicLog "[!] sqlite3.exe not found at $sqlitePath — cannot extract SQLite-based history" -Level ERROR -Section "BROWSER_HISTORY" -Detail "SQLLite not found in $sqlitePath SQLite-based browsers (Chrome, Edge, Firefox) will be skipped"
   
}

# ---------------------------------------------------------
# USER ENUMERATION — done first, used throughout
# Pulls all real user profiles, skips system/default accounts
# ---------------------------------------------------------
$users = Get-CimInstance Win32_UserProfile |
         Where-Object {
             $_.Special     -eq $false -and
             $_.LocalPath   -notmatch '(Public|Default|NetworkService|LocalService|systemprofile)$' -and
             (Test-Path $_.LocalPath)
         } |
         ForEach-Object { $_.LocalPath }

if($users.Count -eq 0){
    # Fallback to filesystem enumeration if WMI returns nothing
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory |
             Where-Object { $_.Name -notmatch '^(Public|Default|default user|All Users)$' } |
             ForEach-Object { $_.FullName }
}

Write-ForensicLog "[*] Found $($users.Count) user profile(s) to process" -Level FINDING -Section "BROWSER_HISTORY" -Detail "Number of Users Found: $($users.Count)"

# Accumulators — populated by Save-HistoryOutput during collection,
# then injected directly into the main HTML report
$script:BrowserFragmentRows = ''
$script:IocHits             = [System.Collections.Generic.List[PSCustomObject]]::new()

# ---------------------------------------------------------
# MALICIOUS URL LIST — used for flagging bad URLs in history
# ---------------------------------------------------------
$maliciousUrlsFilePath = "$PSScriptRoot\Forensicator-Share\malicious_URLs.txt"


$configFile = "$PSScriptRoot\config.json"
  $configData = Get-Content $configFile | ConvertFrom-Json



if($null -ne $configData){
    $urlSource = $configData.url_source
}

if(-not (Test-Path $maliciousUrlsFilePath)){
    Write-ForensicLog "[*] malicious_URLs.txt not found — attempting download..." -Level INFO -Section "BROWSER_HISTORY"
    try{
        # Quick TCP reachability check without Test-NetConnection overhead
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connected = $tcp.ConnectAsync("bazaar.abuse.ch", 443).Wait(3000)
        $tcp.Dispose()

        if($connected){
            Write-ForensicLog "[*] Downloading from abuse.ch..." -Level INFO -Section "BROWSER_HISTORY"
            Invoke-WebRequest -Uri $urlSource -OutFile $maliciousUrlsFilePath -UseBasicParsing -TimeoutSec 30
        }
        else{
            Write-ForensicLog "[!] bazaar.abuse.ch unreachable — malicious URL checking disabled" -Level ERROR -Section "BROWSER_HISTORY"
        }
    }
    catch{
        Write-ForensicLog "[!] Download failed — malicious URL checking disabled" -Level ERROR -Section "BROWSER_HISTORY"
    }
}

# Build HashSet for O(1) domain lookup — critical when checking
# thousands of URLs against a large IOC list
$maliciousDomainSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

if(Test-Path $maliciousUrlsFilePath){
    Get-Content $maliciousUrlsFilePath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") } |
        ForEach-Object { [void]$maliciousDomainSet.Add($_.Trim().ToLower()) }

    Write-ForensicLog "[*] Loaded $($maliciousDomainSet.Count) malicious domain(s)" -Level INFO -Section "BROWSER_HISTORY" -Detail "Source: $($maliciousDomainSet.Count) domains from $urlSource"
}

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
function Get-UrlDomain {
    param([string]$Url)
    try{
        return ([System.Uri]$Url).Host.ToLower()
    }
    catch{ return $Url.ToLower() }
}


function Test-MaliciousUrl {
    param([string]$Url)

    if($maliciousDomainSet.Count -eq 0){ return $false }

    $urlLower = $Url.ToLower()

    # --- Direct URL match ---
    if($maliciousDomainSet.Contains($urlLower)){
        return $true
    }

    # --- Domain extraction ---
    $domain = Get-UrlDomain $urlLower

    # Exact domain match
    if($maliciousDomainSet.Contains($domain)){
        return $true
    }

    # Parent domain match (sub.evil.com -> evil.com)
    $parts = $domain -split "\."

    for($i = 1; $i -lt $parts.Count - 1; $i++){
        $parent = ($parts[$i..($parts.Count-1)]) -join "."
        if($maliciousDomainSet.Contains($parent)){
            return $true
        }
    }

    return $false
}

function Convert-ChromeTime {
    param([long]$t)
    if($t -le 0){ return "N/A" }
    try{ return ([datetime]'1601-01-01').AddSeconds($t / 1000000).ToString("yyyy-MM-dd HH:mm:ss") }
    catch{ return "N/A" }
}

function Convert-FirefoxTime {
    param([long]$t)
    if($t -le 0){ return "N/A" }
    try{ return ([datetime]'1970-01-01').AddMilliseconds($t / 1000).ToString("yyyy-MM-dd HH:mm:ss") }
    catch{ return "N/A" }
}

function Escape-Html {
    param([string]$s)
    if([string]::IsNullOrEmpty($s)){ return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;")
}

function Invoke-SQLiteQuery {
    param([string]$DbPath, [string]$Query)
    $tempDb = "$env:TEMP\frnsctr_$(New-Guid).db"
    try{
        Copy-Item $DbPath $tempDb -Force -ErrorAction Stop
        # Use a separator that cannot appear in URLs or timestamps
        # ASCII 0x1F = Unit Separator — safe for this purpose
        $sep     = [char]0x1F
        $results = & $sqlitePath $tempDb -separator $sep $Query 2>$null
        return [PSCustomObject]@{ Rows = $results; Separator = $sep }
    }
    catch{
        Write-ForensicLog "[!] SQLite query failed on $DbPath — $($_.Exception.Message)" -Level ERROR -Section "BROWSER_HISTORY" -Detail "Failed to query $DbPath with query: $Query"
        return [PSCustomObject]@{ Rows = @(); Separator = [char]0x1F }
    }
    finally{
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    }
}





function Save-HistoryOutput {
    param([array]$Records, [string]$Browser, [string]$UserName, [string]$ProfileSuffix="")

    if ($Records.Count -eq 0) { return }

    # Accumulate rows directly into the main report's browser-tbody
    foreach ($r in $Records) {
        $iocCell = if ($r.IsMalicious) {
            "<span style='color:#ef4444;font-weight:600;'>&#9888; IOC</span>"
        } else {
            "<td><span style='color:#7f8c8d;font-weight:600;'>Clean</span></td>"
        }
        $rowClass = if ($r.IsMalicious) { " class='ioc-row'" } else { "" }
        $script:BrowserFragmentRows += "<tr$rowClass>"
        $script:BrowserFragmentRows += "<td>$(Escape-Html $r.User)</td>"
        $script:BrowserFragmentRows += "<td>$($r.Browser)</td>"
        $script:BrowserFragmentRows += "<td>$(Escape-Html $r.Profile)</td>"
        $script:BrowserFragmentRows += "<td class='url-cell'>$(Escape-Html $r.URL)</td>"
        $script:BrowserFragmentRows += "<td>$($r.LastVisit)</td>"
        $script:BrowserFragmentRows += "<td>$iocCell</td>"
        $script:BrowserFragmentRows += "</tr>"
    }

    # Collect malicious hits for IOC_DATA JS variable
    $Records | Where-Object { $_.IsMalicious } | ForEach-Object {
        $script:IocHits.Add($_)
    }
<#
    # Also export per-browser CSV for external analysis
    $safeSuffix = $ProfileSuffix -replace '[^a-zA-Z0-9_-]', '_'
    $csvBase    = "$PSScriptRoot\$env:COMPUTERNAME\BROWSING_HISTORY\${Browser}_${UserName}$(if($safeSuffix){"_$safeSuffix"})"
    New-Item (Split-Path $csvBase) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $Records | Select-Object User, Browser, Profile, URL, LastVisit, IsMalicious |
        Export-Csv "$csvBase.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue

    $malicious = $Records | Where-Object { $_.IsMalicious }
    if ($malicious.Count -gt 0) {
        Write-ForensicLog "[!] $($malicious.Count) malicious URL(s) in $Browser history — $UserName$(if($ProfileSuffix){" / $ProfileSuffix"})" -Level FINDING -Section "BROWSER_HISTORY" -Detail "$($malicious.Count) malicious URL(s) found in $Browser history for user $UserName$(if($ProfileSuffix){" / profile $ProfileSuffix"})"
    }
#>
}

# ---------------------------------------------------------
# CHROMIUM-BASED BROWSERS (Chrome, Edge, Brave, Opera)
# Dynamically discovers ALL profiles under User Data\
# not just Default — catches secondary signed-in profiles
# ---------------------------------------------------------
function Process-ChromiumBrowser {
    param(
        [string]$UserPath,
        [string]$BrowserName,
        [string]$UserDataRelPath
    )

    $userDataPath = "$UserPath\$UserDataRelPath"
    if(-not (Test-Path $userDataPath)){ return }

    $userName    = Split-Path $UserPath -Leaf
    $profileDirs = Get-ChildItem $userDataPath -Directory |
                   Where-Object { $_.Name -match '^(Default|Profile \d+)$' }

    foreach($profileDir in $profileDirs){
        $dbPath = "$($profileDir.FullName)\History"
        if(-not (Test-Path $dbPath)){ continue }

        $query  = "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        $result = Invoke-SQLiteQuery $dbPath $query
        $sep    = $result.Separator

        $records = foreach($row in $result.Rows){
            if([string]::IsNullOrWhiteSpace($row)){ continue }

            # Split on separator — last token is always the timestamp
            # everything before it is the URL (handles pipes in URLs)
            $parts = $row -split [regex]::Escape($sep)
            if($parts.Count -lt 2){ continue }

            $url       = ($parts[0..($parts.Count-2)] -join $sep).Trim()
            $timeRaw   = $parts[-1].Trim()

            $visitTime = "N/A"
            [long]$ts  = 0
            if([long]::TryParse($timeRaw, [ref]$ts)){
                $visitTime = Convert-ChromeTime $ts
            }

            [PSCustomObject]@{
                User        = $userName
                Browser     = $BrowserName
                Profile     = $profileDir.Name
                URL         = $url
                LastVisit   = $visitTime
                IsMalicious = Test-MaliciousUrl $url
            }
        }

        $profileSuffix = if($profileDir.Name -ne "Default"){ $profileDir.Name } else { "" }
        Save-HistoryOutput $records $BrowserName $userName $profileSuffix
    }
}

# ---------------------------------------------------------
# FIREFOX
# Dynamically discovers all release/default profiles
# ---------------------------------------------------------
function Process-FirefoxHistory {
    param([string]$UserPath)

    $profilesPath = "$UserPath\AppData\Roaming\Mozilla\Firefox\Profiles"
    if(-not (Test-Path $profilesPath)){ return }

    $userName = Split-Path $UserPath -Leaf

    foreach($profile in Get-ChildItem $profilesPath -Directory){
        $dbPath = "$($profile.FullName)\places.sqlite"
        if(-not (Test-Path $dbPath)){ continue }

        $query  = "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC"
        $result = Invoke-SQLiteQuery $dbPath $query
        $sep    = $result.Separator

        $records = foreach($row in $result.Rows){
            if([string]::IsNullOrWhiteSpace($row)){ continue }

            $parts   = $row -split [regex]::Escape($sep)
            if($parts.Count -lt 2){ continue }

            $url      = ($parts[0..($parts.Count-2)] -join $sep).Trim()
            $timeRaw  = $parts[-1].Trim()

            $visitTime = "N/A"
            [long]$ts  = 0
            if([long]::TryParse($timeRaw, [ref]$ts)){
                $visitTime = Convert-FirefoxTime $ts
            }

            [PSCustomObject]@{
                User        = $userName
                Browser     = "Firefox"
                Profile     = $profile.Name
                URL         = $url
                LastVisit   = $visitTime
                IsMalicious = Test-MaliciousUrl $url
            }
        }

        Save-HistoryOutput $records "Firefox" $userName $profile.Name
    }
}

# ---------------------------------------------------------
# INTERNET EXPLORER — TypedURLs (registry, no SQLite needed)
# Limitation noted: clicked links require WebCacheV01.dat
# (ESE database, needs esentutl — outside scope here)
# ---------------------------------------------------------
function Process-IEHistory {
    param([string]$UserPath)

    $userName = Split-Path $UserPath -Leaf

    if(-not (Test-Path "HKU:\")){ 
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }

    try{
        $sid = (New-Object System.Security.Principal.NTAccount($userName)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
    }
    catch{ return }

    $regPath = "HKU:\$sid\Software\Microsoft\Internet Explorer\TypedURLs"
    if(-not (Test-Path $regPath)){ return }

    $key     = Get-Item $regPath -ErrorAction SilentlyContinue
    $records = foreach($valueName in $key.GetValueNames()){
        $url = $key.GetValue($valueName)
        [PSCustomObject]@{
            User        = $userName
            Browser     = "Internet Explorer"
            Profile     = "Default"
            URL         = $url
            LastVisit   = "N/A (TypedURLs only)"
            IsMalicious = Test-MaliciousUrl $url
        }
    }

    Save-HistoryOutput $records "IE" $userName
}

# ---------------------------------------------------------
# PROCESS ALL USERS
# Chromium browser paths are declared inline so adding a new
# browser only requires one new entry in the $chromiumBrowsers table
# ---------------------------------------------------------
$chromiumBrowsers = @(
    @{ Name="Chrome"; RelPath="AppData\Local\Google\Chrome\User Data"           },
    @{ Name="Edge";   RelPath="AppData\Local\Microsoft\Edge\User Data"           },
    @{ Name="Brave";  RelPath="AppData\Local\BraveSoftware\Brave-Browser\User Data" },
    @{ Name="Opera";  RelPath="AppData\Roaming\Opera Software\Opera Stable"      }
)

foreach($user in $users){
    $userName = Split-Path $user -Leaf
    Write-ForensicLog "[*] Processing $userName" -Level INFO -Section "BROWSER_HISTORY" -Detail "Processing user profile at $user"

    foreach($browser in $chromiumBrowsers){
        Process-ChromiumBrowser -UserPath $user `
                                -BrowserName $browser.Name `
                                -UserDataRelPath $browser.RelPath
    }

    Process-FirefoxHistory $user
    Process-IEHistory      $user
}

Write-ForensicLog "[!] Browser history extraction complete" -Level SUCCESS -Section "BROWSER_HISTORY"


#endregion




###########################################################################################################
#region  CHECKING FOR RANSOMWARE ENCRYPTED FILES    #######################################################
###########################################################################################################

if($RANSOMWARE){

  Write-ForensicLog ""
    Write-ForensicLog "[*] Checking For Ransomware Indicators" -Level INFO -Section "RANSOMWARE_SCAN"
    Write-ForensicLog "[!] NOTE: This may take a while depending on disk size" -Level WARN -Section "RANSOMWARE_SCAN"

    # ---------------------------------------------------------
    # KNOWN PLAINTEXT-HEADER EXTENSIONS
    # These are naturally high entropy — excluded from entropy
    # scan to eliminate the biggest source of false positives
    # ---------------------------------------------------------
    $excludedEntropyExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        '.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff','.webp','.ico',
        '.mp3','.mp4','.m4a','.m4v','.aac','.ogg','.flac','.wav','.wma',
        '.avi','.mkv','.mov','.wmv','.flv','.mpeg','.mpg',
        '.zip','.gz','.7z','.rar','.bz2','.xz','.cab','.iso',
        '.pdf','.docx','.xlsx','.pptx','.odt','.ods',
        '.exe','.dll','.sys'   # PE files have naturally high entropy sections
    ) | ForEach-Object { [void]$excludedEntropyExtensions.Add($_) }

    # ---------------------------------------------------------
    # RANSOMWARE EXTENSIONS from config
    # ---------------------------------------------------------
    $ransomExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    if($null -ne $configData -and $configData.PSObject.Properties["Ransomeware_Extensions"]){
        $configData.Ransomeware_Extensions |
            ForEach-Object { [void]$ransomExtensionSet.Add($_) }
        Write-ForensicLog "[*] Loaded $($ransomExtensionSet.Count) ransomware extension(s) from config" -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Source: $($ransomExtensionSet.Count) extensions from config"
    }

    # ---------------------------------------------------------
    # RANSOM NOTE NAMES
    # ---------------------------------------------------------
    $ransomNotesFile = "$PSScriptRoot\Forensicator-Share\ransom_notes.txt"
    $repoUrl         = "https://github.com/ThreatLabz/ransomware_notes/archive/refs/heads/main.zip"
    $tempZip         = "$env:TEMP\ransomnotes_$(New-Guid).zip"
    $tempExtract     = "$env:TEMP\ransomnotes_$(New-Guid)"

    if(-not (Test-Path $ransomNotesFile)){
        Write-ForensicLog "[*] Downloading ransomware note dataset..." -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Attempting to download ransomware note dataset from $repoUrl"
        try{
            $tcp       = [System.Net.Sockets.TcpClient]::new()
            $reachable = $tcp.ConnectAsync("github.com", 443).Wait(3000)
            $tcp.Dispose()

            if($reachable){
                Invoke-WebRequest $repoUrl -OutFile $tempZip -UseBasicParsing -TimeoutSec 60
                Expand-Archive $tempZip -DestinationPath $tempExtract -Force

                Get-ChildItem $tempExtract -Recurse -File |
                    Select-Object -ExpandProperty Name |
                    Sort-Object -Unique |
                    Out-File $ransomNotesFile -Encoding UTF8

                Write-ForensicLog "[+] Ransom note list saved ($ransomNotesFile)" -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Ransom note list saved to $ransomNotesFile"
            }
            else{
                Write-ForensicLog "[!] github.com unreachable — skipping note dataset download" -Level WARN -Section "RANSOMWARE_SCAN" -Detail "Could not reach github.com to download ransomware note dataset"
            }
        }
        catch{
            Write-ForensicLog "[!] Failed to download ransomware notes: $($_.Exception.Message)" -Level ERROR -Section "RANSOMWARE_SCAN" -Detail "Attempted Download from URL: $repoUrl Failed"
        }
        finally{
            Remove-Item $tempZip      -Force -ErrorAction SilentlyContinue
            Remove-Item $tempExtract  -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Build HashSet for O(1) case-insensitive note name lookup
    $ransomNoteSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    if(Test-Path $ransomNotesFile){
        Get-Content $ransomNotesFile |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [void]$ransomNoteSet.Add($_.Trim()) }
    }
    Write-ForensicLog "[*] Loaded $($ransomNoteSet.Count) ransom note indicator(s)" -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Source: $($ransomNoteSet.Count) note names from $repoUrl"

    # ---------------------------------------------------------
    # ENTROPY — samples beginning, middle, and end of file
    # Catches partially encrypted files that a head-only read misses
    # ---------------------------------------------------------
    function Get-FileEntropy {
        param([string]$Path, [long]$FileSize)

        try{
            $stream    = [System.IO.File]::OpenRead($Path)
            $chunkSize = 65536  # 64KB per sample
            $buffer    = [byte[]]::new($chunkSize * 3)
            $totalRead = 0

            # Sample start
            $read       = $stream.Read($buffer, 0, $chunkSize)
            $totalRead += $read

            # Sample middle
            if($FileSize -gt $chunkSize * 2){
                $stream.Seek([long]($FileSize / 2), [System.IO.SeekOrigin]::Begin) | Out-Null
                $read       = $stream.Read($buffer, $chunkSize, $chunkSize)
                $totalRead += $read
            }

            # Sample end
            if($FileSize -gt $chunkSize){
                $stream.Seek([Math]::Max(0, $FileSize - $chunkSize), [System.IO.SeekOrigin]::Begin) | Out-Null
                $read       = $stream.Read($buffer, $chunkSize * 2, $chunkSize)
                $totalRead += $read
            }

            $stream.Close()
            if($totalRead -le 0){ return 0 }

            $counts = [int[]]::new(256)
            for($i = 0; $i -lt $totalRead; $i++){ $counts[$buffer[$i]]++ }

            $entropy = 0.0
            foreach($count in $counts){
                if($count -le 0){ continue }
                $p        = $count / $totalRead
                $entropy -= $p * [Math]::Log($p, 2)
            }
            return $entropy
        }
        catch{ return 0 }
    }

    # ---------------------------------------------------------
    # SHADOW COPY DELETION CHECK
    # These are the canonical methods ransomware uses to prevent
    # recovery — presence of any of these in recent event logs
    # or running processes is a strong indicator
    # ---------------------------------------------------------
    function Get-ShadowCopyDeletionIndicators {

        $indicators = @()

        # Method 1 — check if VSS snapshots still exist
        # If a machine that had snapshots now has none, deletion may have occurred
        $vssSnapshots = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        if($null -eq $vssSnapshots -or $vssSnapshots.Count -eq 0){
            $indicators += [PSCustomObject]@{
                Method   = "No VSS snapshots present"
                Detail   = "No shadow copies found — may have been deleted or never created"
                Severity = "Medium"
            }
        }
        else{
            Write-ForensicLog "[+] $($vssSnapshots.Count) VSS snapshot(s) still present" -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Snapshot count: $($vssSnapshots.Count) — presence of snapshots does not rule out ransomware but is a positive sign"
        }

        # Method 2 — Security event log: Process creation events (4688)
        # Looks for vssadmin, wmic, wbadmin, bcdedit with deletion args
        $deletionPatterns = @(
            'vssadmin.*delete.*shadows',
            'wmic.*shadowcopy.*delete',
            'wbadmin.*delete.*catalog',
            'bcdedit.*/set.*recoveryenabled.*no',
            'bcdedit.*/set.*bootstatuspolicy',
            'diskshadow.*delete'
        )

        try{
            $events = Get-ForensicWinEvent -LogName 'Security' -Id 4688 -ProviderName 'Microsoft-Windows-Security-Auditing' |
            Where-Object {
                $msg = $_.Message
                $deletionPatterns | Where-Object { $msg -match $_ }
            }

            foreach($e in $events){
                $indicators += [PSCustomObject]@{
                    Method   = "Process creation (Event 4688)"
                    Detail   = ($e.Message -replace '\s+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
                    Severity = "High"
                }
            }
        }
        catch{
            Write-ForensicLog "[!] Could not query Security event log — may need elevated privileges" -Level ERROR -Section "RANSOMWARE_SCAN"
        }

        # Method 3 — PowerShell/System event logs for wbadmin/vssadmin
        try{
            $psEvents = Get-ForensicWinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 |
            Where-Object {
                $msg = $_.Message
                $deletionPatterns | Where-Object { $msg -match $_ }
            }

            foreach($e in $psEvents){
                $indicators += [PSCustomObject]@{
                    Method   = "PowerShell ScriptBlock (Event 4104)"
                    Detail   = ($e.Message -replace '\s+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
                    Severity = "High"
                }
            }
        }
        catch{ }

        # Method 4 — Check if bcdedit has recovery disabled RIGHT NOW
        try{
            $bcdedit = & bcdedit /enum {current} 2>$null
            if($bcdedit -match 'recoveryenabled\s+No'){
                $indicators += [PSCustomObject]@{
                    Method   = "Boot recovery disabled (bcdedit)"
                    Detail   = "bcdedit shows recoveryenabled=No on current boot entry"
                    Severity = "High"
                }
            }
            if($bcdedit -match 'bootstatuspolicy\s+IgnoreAllFailures'){
                $indicators += [PSCustomObject]@{
                    Method   = "Boot status policy tampered (bcdedit)"
                    Detail   = "bootstatuspolicy=IgnoreAllFailures — suppresses recovery boot menu"
                    Severity = "High"
                }
            }
        }
        catch{ }

        # Method 5 — Check currently running processes for deletion tools
        $suspiciousProcs = Get-CimInstance Win32_Process |
            Where-Object {
                $_.CommandLine -match 'vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete|diskshadow'
            }

        foreach($proc in $suspiciousProcs){
            $indicators += [PSCustomObject]@{
                Method   = "Live process — shadow deletion in progress"
                Detail   = "PID $($proc.ProcessId): $($proc.CommandLine)"
                Severity = "Critical"
            }
        }

        return $indicators
    }

    # ---------------------------------------------------------
    # SCAN PATHS
    # ---------------------------------------------------------
    $ScanPaths = @(
        "$env:SystemDrive\Users",
        "$env:SystemDrive\ProgramData",
        "$env:SystemRoot\Temp"
    )

    $RansomNotesFound  = @()
    $HighEntropyFiles  = @()
    $RansomExtFiles    = @()
    $RecentFiles       = @()
    $cutoffTime        = (Get-Date).AddHours(-1)

    foreach($scanPath in $ScanPaths){
        if(-not (Test-Path $scanPath)){ continue }

        Write-ForensicLog "[*] Scanning $scanPath ..." -Level INFO -Section "RANSOMWARE_SCAN" -Detail "Scanning $scanPath for ransom notes, suspicious extensions, high entropy, and recent modifications"

        Get-ChildItem $scanPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $file = $_
            $ext  = $file.Extension.ToLower()

            # Ransom note check — case insensitive via HashSet
            if($ransomNoteSet.Contains($file.Name)){
                $RansomNotesFound += $file
            }

            # Ransomware extension check
            if($ransomExtensionSet.Count -gt 0 -and $ransomExtensionSet.Contains($ext)){
                $RansomExtFiles += [PSCustomObject]@{
                    File      = $file.FullName
                    Extension = $ext
                    Size      = $file.Length
                    LastWrite = $file.LastWriteTimeUTC
                }
            }

            # Entropy check — skip naturally high-entropy formats
            # Only check files >10KB to avoid noise from tiny files
            if($file.Length -gt 10240 -and -not $excludedEntropyExtensions.Contains($ext)){
                $entropy = Get-FileEntropy $file.FullName $file.Length
                if($entropy -gt 7.8){
                    $HighEntropyFiles += [PSCustomObject]@{
                        File      = $file.FullName
                        Extension = $ext
                        Entropy   = [Math]::Round($entropy, 3)
                        Size      = $file.Length
                        LastWrite = $file.LastWriteTimeUTC
                    }
                }
            }

            # Mass modification detection
            if($file.LastWriteTime -gt $cutoffTime){
                $RecentFiles += $file
            }
        }
    }

    # ---------------------------------------------------------
    # SHADOW COPY DELETION
    # ---------------------------------------------------------
    Write-ForensicLog "[*] Checking shadow copy deletion indicators..." -Level INFO -Section "RANSOMWARE_SCAN"
    $ShadowIndicators = Get-ShadowCopyDeletionIndicators

    # ---------------------------------------------------------
    # HTML OUTPUT
    # ---------------------------------------------------------


    foreach($note in $RansomNotesFound){
        $RansomNoteFragment += "<tr style='background-color:#ffcccc;'>"
        $RansomNoteFragment += "<td>Ransom Note</td>"
        $RansomNoteFragment += "<td>$($note.FullName)</td>"
        $RansomNoteFragment += "<td>Filename matches known ransom note: $($note.Name)</td>"
        $RansomNoteFragment += "<td>$($note.LastWriteTimeUTC)</td>"
        $RansomNoteFragment += "</tr>"
    }

    foreach($f in $RansomExtFiles){
        $RansomExtFragment += "<tr style='background-color:#ffddcc;'>"
        $RansomExtFragment += "<td>Ransomware Extension</td>"
        $RansomExtFragment += "<td>$($f.File)</td>"
        $RansomExtFragment += "<td>Extension: $($f.Extension)</td>"
        $RansomExtFragment += "<td>$($f.LastWrite)</td>"
        $RansomExtFragment += "</tr>"
    }

    foreach($f in $HighEntropyFiles){
        $HighEntropyFragment += "<tr style='background-color:#fff3cc;'>"
        $HighEntropyFragment += "<td>High Entropy File</td>"
        $HighEntropyFragment += "<td>$($f.File)</td>"
        $HighEntropyFragment += "<td>Entropy: $($f.Entropy) / 8.0 (ext: $($f.Extension))</td>"
        $HighEntropyFragment += "<td>$($f.LastWrite)</td>"
        $HighEntropyFragment += "</tr>"
    }

    

    # Shadow copy deletion table — separate fragment


    foreach($s in $ShadowIndicators){
        $color = switch($s.Severity){
            "Critical" { "#ffcccc" }
            "High"     { "#a85125" }
            "Medium"   { "#fff3cc" }
            default    { "#ffffff" }
        }
        $ShadowFragment += "<tr style='background-color:$color;'>"
        $ShadowFragment += "<td>$($s.Severity)</td>"
        $ShadowFragment += "<td>$($s.Method)</td>"
        $ShadowFragment += "<td>$($s.Detail)</td>"
        $ShadowFragment += "</tr>"
    }


    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------
    Write-Host ""
    Write-ForensicLog "[!] Ransomware Scan Summary" -Level INFO -Section "RANSOMWARE_SCAN"
    Write-ForensicLog "    Ransom notes detected       : $($RansomNotesFound.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Detail "$($RansomNotesFound.Count) Files matching known ransom note names"
    Write-ForensicLog "    Ransomware extensions found : $($RansomExtFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Detail "$($RansomExtFiles.Count) Files with known ransomware extensions"
    Write-ForensicLog "    High entropy files          : $($HighEntropyFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Detail "$($HighEntropyFiles.Count) Files with high entropy indicating possible encryption"
    Write-ForensicLog "    Files modified in last hour : $($RecentFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Detail "$($RecentFiles.Count) Files modified within the last hour"
    Write-ForensicLog "    Shadow deletion indicators  : $($ShadowIndicators.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Detail "$($ShadowIndicators.Count) Indicators of shadow copy deletion"

    if($RansomNotesFound.Count -gt 0 -or $RansomExtFiles.Count -gt 0){
        Write-ForensicLog "[!] RANSOMWARE INDICATORS FOUND — escalate immediately" -Level FINDING -Section "RANSOMWARE_SCAN"
    }
    elseif($HighEntropyFiles.Count -gt 50 -and $RecentFiles.Count -gt 200){
        Write-ForensicLog "[!] High entropy + mass modification — possible active encryption" -Level FINDING -Section "RANSOMWARE_SCAN"
    }
    elseif($ShadowIndicators | Where-Object { $_.Severity -in @("High","Critical") }){
        Write-ForensicLog "[!] Shadow copy deletion detected — possible ransomware preparation" -Level FINDING -Section "RANSOMWARE_SCAN"
    }

    Write-ForensicLog "[!] Done"

    
} else {
    $ShadowFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $HighEntropyFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $RansomExtFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $RansomNoteFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
}

#endregion

Write-ForensicLog ""

###########################################################################################################
#region NETWORK TRACE
###########################################################################################################

# configuration file path
#$configFile = "$PSScriptRoot\config.json"

# Read and parse the configuration file
#$configData = Get-Content $configFile | ConvertFrom-Json

<#


mkdir $PSScriptRoot\$env:COMPUTERNAME\PCAP -ErrorAction SilentlyContinue | Out-Null

$session = "ForensicatorCapture"
$etlPath = "$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:COMPUTERNAME.etl"
$netshduration = $configData.net_capture_duration

Write-ForensicLog "[*] Starting Network Trace" -Level INFO -Section "NETWORKTRACE"

# create session
New-NetEventSession -Name $session -LocalFilePath $etlPath | Out-Null

# add packet capture provider
Add-NetEventPacketCaptureProvider -SessionName $session `
                                  -Level 4 `
                                  -CaptureType BothPhysicalAndSwitch | Out-Null


# start capture
Start-NetEventSession -Name $session | Out-Null



Write-ForensicLog "[*] Capturing for $netshduration seconds..." -Level INFO -Section "NETWORKTRACE"
Start-Sleep -Seconds $netshduration


Stop-NetEventSession -Name $session
Remove-NetEventSession -Name $session

Write-ForensicLog "[!] Trace Completed — ETL saved to $etlPath" -Level SUCCESS -Section "NETWORKTRACE" -Detail "Captured $netshduration seconds of network traffic to $etlPath"

#endregion

#>

if($PCAP){

  Write-ForensicLog ""

    #mkdir $PSScriptRoot\$env:COMPUTERNAME\PCAP -ErrorAction SilentlyContinue | Out-Null
    $pcapPath = "$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:COMPUTERNAME.pcapng"
    $netshduration   = $configData.net_capture_duration
    # Check pktmon supports direct pcapng output (build 2004+)
    $build = [System.Environment]::OSVersion.Version.Build
    

    if($build -ge 19041){
        Write-ForensicLog "[*] Starting Network Trace via pktmon" -Level INFO -Section "NETWORKTRACE"
        # Direct pcapng output — no conversion needed
        pktmon start --capture --pkt-size 0 --log-mode circular `
               --file-name $pcapPath 2>&1 | Out-Null

        Write-ForensicLog "[*] Capturing for $netshduration seconds..." -Level INFO -Section "NETWORKTRACE"
        Start-Sleep -Seconds $netshduration

        pktmon stop | Out-Null

        Write-ForensicLog "[!] Capture complete — PCAP saved to $pcapPath" -Level SUCCESS -Section "NETWORKTRACE" -Detail "Captured $netshduration seconds of network traffic to $pcapPath"

    }
    else{

        Write-ForensicLog "[*] Starting Network Trace" -Level INFO -Section "NETWORKTRACE"
  Write-ForensicLog "[*] Running....." -Level INFO -Section "NETWORKTRACE"
   $netshduration   = $configData.net_capture_duration
  netsh trace start capture=yes Ethernet.Type=IPv4 tracefile=$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 | Out-Null
  Start-Sleep -s $netshduration
  $job = Start-Job { netsh trace stop } | Out-Null
  Wait-Job $job
  Receive-Job $job

  Write-ForensicLog "[!] Trace Completed" -Level SUCCESS -Section "NETWORKTRACE"

  Write-ForensicLog "[*] Converting to PCAP" -Level INFO -Section "NETWORKTRACE"


  if ((gwmi win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit") {
    

    & $PSScriptRoot\Forensicator-Share\etl2pcapng64.exe $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.pcap
	
  }
  else {
    
    & $PSScriptRoot\Forensicator-Share\etl2pcapng86.exe $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.pcap

  }


    }

    Write-ForensicLog "[!] Done" -Level SUCCESS -Section "NETWORKTRACE"
}
 



#endregion




###########################################################################################################
#region  Export Event Logs       ##########################################################################
###########################################################################################################



if ($EVTX) {

  Write-ForensicLog ""
	
  Write-ForensicLog "[*] Gettting hold of some event logs" -Level INFO -Section "EVENTLOGS"
   
  # capture the EVENTLOGS
  # Logs to extract from server
  $logArray = @("System", "Security", "Application")

  # Grabs the server name to append to the log file extraction
  $servername = $env:computername

  # Provide the path with ending "\" to store the log file extraction.
  $destinationpath = "$PSScriptRoot\$env:COMPUTERNAME\EVTX\"

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

    Write-ForensicLog "[!] Finalizing" -Level INFO -Section "EVENTLOGS"

    # Extract each log file listed in $logArray from the local server.
    wevtutil epl $log $destination
  }

  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EVENTLOGS"
  # End Code

  # Stop Timer
  $StopWatch.Stop()
  $TotalTime = $StopWatch.Elapsed.TotalSeconds
  $TotalTime = [math]::Round($totalTime, 2)

  Write-ForensicLog "[!] Extracting the logs took $TotalTime to Complete." -Level SUCCESS -Section "EVENTLOGS" -Detail "Time taken to extract logs: $TotalTime seconds"


} 
else {

}

#endregion


############################################################
#region GETTING HOLD OF IIS & APACHE WEBLOGS ###############
############################################################

if ($WEBLOGS) {

  Write-ForensicLog ""

  #Lets get hold of some weblogs
  Write-ForensicLog "[*] Lets Get hold of some weblogs" -Level INFO -Section "WEBLOGS"
  Write-ForensicLog "[!] NOTE: This can take a while if you have large Apache/IIS Log Files" -Level INFO -Section "WEBLOGS"

  #checking if logs exists in the IIS Log directory
  if (!(Get-ChildItem C:\inetpub\logs\ *.log)) {
    Write-ForensicLog "[!] Cannot find any logs in IIS Log Directory" -Level WARN -Section "WEBLOGS"
  }
  else {
	
    #create IIS log Dirs
    mkdir "$PSScriptRoot\$env:COMPUTERNAME\IISLogs" | Out-Null

    Copy-Item -Path 'C:\inetpub\logs\*' -Destination "$PSScriptRoot\$env:COMPUTERNAME\IISLogs" -Recurse | Out-Null

	
  }


  #checking for Tomcat and try to get log files


  mkdir "$PSScriptRoot\$env:COMPUTERNAME\TomCatLogs" | Out-Null
  # Define the destination directory where you want to copy the logs
  $destinationDirectory = "$PSScriptRoot\$env:COMPUTERNAME\TomCatLogs"

  # Check if Tomcat is installed by checking the registry
  $regKey = "HKLM:\SOFTWARE\Apache Software Foundation\Tomcat"
  if (Test-Path $regKey) {
    Write-ForensicLog "Tomcat is installed. Proceeding with log file copy."
    
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
        
      Write-ForensicLog "TomCat Log files copied successfully to $destinationDirectory" -Level SUCCESS -Section "WEBLOGS"
    }
    else {
      Write-ForensicLog "Tomcat logs directory not found. Cannot proceed with log file copy." -Level WARN -Section "WEBLOGS"
    }
  }
  else {
    Write-ForensicLog "Tomcat is not installed. Cannot proceed with log file copy." -Level WARN -Section "WEBLOGS"
  }


} 
else {

}

#endregion


#############################################################################################################
#region   View Log4j Paths        ###########################################################################
#############################################################################################################

if ($LOG4J) {
  Write-ForensicLog ""
   
  Write-ForensicLog "[*] Checking for log4j on all drives .....this may take a while." -Level INFO -Section "LOG4J"

  mkdir "$PSScriptRoot\$env:COMPUTERNAME\LOG4J" | Out-Null	
  # Checking for Log4j
  $DriveList = (Get-PSDrive -PSProvider FileSystem).Root
  ForEach ($Drive In $DriveList) {
    $Log4j = Get-ChildItem $Drive -rec -force -include *.jar -ea 0 | ForEach-Object { select-string 'JndiLookup.class' $_ } | Select-Object -exp Path | Out-File "$PSScriptRoot\$env:COMPUTERNAME\LOG4J\$env:computername.txt"

  }
   
  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "LOG4J"
   
   
} 
else {

}

#endregion




if ($HASHCHECK) {
  
Write-ForensicLog ""

#############################################################################################################
#region   MALWARE HASH LOOKUP — OPTIMISED
#############################################################################################################

Write-ForensicLog "Starting malware hash lookup" -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# SCAN TARGET CONFIGURATION
# Prioritised paths — most likely locations for malware
# Scanned in order, most suspicious first
# Add or remove paths to suit your environment
# ---------------------------------------------------------
$scanConfig = [ordered]@{

    # Tier 1 — Highest priority, always scan
    # These are the most common malware staging locations
    "UserWritable" = @{
        Paths = @(
            "$env:SystemDrive\Users",
            "$env:TEMP",
            "$env:SystemRoot\Temp",
            "$env:ProgramData"
        )
        Priority  = 1
        Recurse   = $true
        MaxAgeDays = 90     # only files modified in last 90 days
    }

    # Tier 2 — High priority system locations
    # Legitimate software rarely drops new files here
    "SystemBinaries" = @{
        Paths = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:SystemRoot\Tasks"
        )
        Priority   = 2
        Recurse    = $false  # non-recursive — legit files are not in subdirs
        MaxAgeDays = 180
    }

    # Tier 3 — Program directories
    # Slower, more false positives but catches trojanised installs
    "ProgramFiles" = @{
        Paths = @(
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        )
        Priority   = 3
        Recurse    = $true
        MaxAgeDays = 60
    }

    # Tier 4 — Full drive scan (optional, slowest)
    # Only enable if Tier 1-3 clean and deeper analysis needed
    # Comment out if you want faster results
    <#
    "FullScan" = @{
        Paths = @( "$env:SystemDrive\" )
        Priority   = 4
        Recurse    = $true
        MaxAgeDays = 365
    }
    #>
}



# Paths to always skip regardless of scan tier
# Add any known-clean noisy directories here
$skipPaths = @(
    "$env:SystemRoot\WinSxS",
    "$env:SystemRoot\servicing",
    "$env:SystemRoot\assembly",
    "$env:SystemRoot\Microsoft.NET",
    "$env:SystemDrive\`$Recycle.Bin",
    "$env:SystemDrive\`$Windows.~WS",
    "$env:SystemDrive\`$Windows.~BT"
)

$skipPathSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$skipPaths | ForEach-Object { [void]$skipPathSet.Add($_) }

$execExtensions = if($null -ne $configData -and $configData.PSObject.Properties["executables_extensions"]){
    $configData.executables_extensions
} else {
    @("*.exe","*.dll","*.bat","*.cmd","*.ps1","*.vbs","*.js","*.hta","*.scr","*.com")
}

$hashSource   = if($null -ne $configData -and $configData.PSObject.Properties["hash_source"]){
    $configData.hash_source
} else {
    "https://bazaar.abuse.ch/export/txt/md5/recent/"
}

$hashFilePath = "$PSScriptRoot\Forensicator-Share\md5hashes.txt"
mkdir "$PSScriptRoot\$env:COMPUTERNAME\HashMatches" -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------
# HASH FILE — download or refresh if stale
# ---------------------------------------------------------
$needsDownload = -not (Test-Path $hashFilePath)
if(-not $needsDownload){
    $ageDays = (New-TimeSpan -Start (Get-Item $hashFilePath).LastWriteTime -End (Get-Date)).TotalDays
    if($ageDays -gt 7){
        $needsDownload = $true
        Write-ForensicLog "Hash file is $([Math]::Round($ageDays,0)) days old — refreshing" `
                          -Level WARN -Section "HASHLOOKUP"
    }
}

if($needsDownload){
    try{
        $tcp = [System.Net.Sockets.TcpClient]::new()
        if($tcp.ConnectAsync("bazaar.abuse.ch", 443).Wait(3000)){
            Invoke-WebRequest -Uri $hashSource -OutFile $hashFilePath `
                              -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            Write-ForensicLog "Hash file downloaded" -Level SUCCESS -Section "HASHLOOKUP"
        }
        $tcp.Dispose()
    }
    catch{
        Write-ForensicLog "Hash file download failed: $($_.Exception.Message)" `
                          -Level ERROR -Section "HASHLOOKUP"
    }
}

if(-not (Test-Path $hashFilePath)){
    Write-ForensicLog "No hash file available — cannot proceed" -Level ERROR -Section "HASHLOOKUP" -Detail "Hash lookup stage requires a local hash file. Attempted to download from $hashSource but failed. Check network connectivity and try again."
}

# ---------------------------------------------------------
# LOAD HASHES INTO HASHSET
# ---------------------------------------------------------
Write-ForensicLog "Loading hash database" -Level INFO -Section "HASHLOOKUP"

$knownBadHashes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
Get-Content $hashFilePath |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") } |
    ForEach-Object { [void]$knownBadHashes.Add($_.Trim().ToLower()) }

Write-ForensicLog "Loaded $($knownBadHashes.Count) known-bad hashes" -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# FILE COLLECTION
# Gather candidate files across all tiers before hashing
# Applying all filters here means the hash stage only touches
# files that actually need checking
# ---------------------------------------------------------
Write-ForensicLog "Collecting candidate files across scan tiers" -Level INFO -Section "HASHLOOKUP"

$candidateFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$cutoffDates    = @{}

foreach($tier in $scanConfig.GetEnumerator() | Sort-Object { $_.Value.Priority }){

    $tierName  = $tier.Key
    $tierConf  = $tier.Value
    $cutoff    = (Get-Date).AddDays(-$tierConf.MaxAgeDays)
    $cutoffDates[$tierName] = $cutoff

    Write-ForensicLog "Collecting Tier $($tierConf.Priority) — $tierName" `
                      -Level INFO -Section "HASHLOOKUP"

    foreach($path in $tierConf.Paths){
        if(-not (Test-Path $path)){ continue }

        foreach($ext in $execExtensions){
            try{
                Get-ChildItem -Path $path `
                              -Filter $ext `
                              -Recurse:$tierConf.Recurse `
                              -Force `
                              -ErrorAction SilentlyContinue |
                Where-Object {
                    -not $_.PSIsContainer           -and
                    $_.Length -gt 0                 -and
                    $_.Length -le 500MB             -and
                    $_.LastWriteTime -gt $cutoff    -and
                    # Skip files in excluded paths
                    -not ($skipPathSet | Where-Object { $_.FullName -like "$_*" })
                } |
                ForEach-Object { $candidateFiles.Add($_) }
            }
            catch{ }
        }
    }
}

# Deduplicate by full path — a file may be caught by multiple tiers
$candidateFiles = $candidateFiles |
                  Sort-Object FullName -Unique

Write-ForensicLog "Candidate files to hash: $($candidateFiles.Count)" `
                  -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# PARALLEL HASHING
# Uses runspaces for PS5.1 compatibility
# ForEach-Object -Parallel requires PS7 — runspaces work on both
# ---------------------------------------------------------
$hashResults  = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$threadCount  = [Math]::Min([Environment]::ProcessorCount, 8)  # cap at 8 threads

Write-ForensicLog "Hashing with $threadCount parallel threads" -Level INFO -Section "HASHLOOKUP"

$scriptBlock = {
    param($FilePath, $KnownBadHashes)

    try{
        $md5Alg    = [System.Security.Cryptography.MD5]::Create()
        $sha256Alg = [System.Security.Cryptography.SHA256]::Create()
        $stream    = [System.IO.File]::OpenRead($FilePath)

        $md5Hash    = ([BitConverter]::ToString($md5Alg.ComputeHash($stream))    -replace "-","").ToLower()
        $stream.Position = 0
        $sha256Hash = ([BitConverter]::ToString($sha256Alg.ComputeHash($stream)) -replace "-","").ToLower()

        $stream.Dispose()
        $md5Alg.Dispose()
        $sha256Alg.Dispose()

        $md5Match    = $KnownBadHashes.Contains($md5Hash)
        $sha256Match = $KnownBadHashes.Contains($sha256Hash)

        if($md5Match -or $sha256Match){
            return [PSCustomObject]@{
                FilePath    = $FilePath
                MD5         = $md5Hash
                SHA256      = $sha256Hash
                MD5Match    = $md5Match
                SHA256Match = $sha256Match
            }
        }
    }
    catch{ }
    return $null
}

# Runspace pool
$pool    = [RunspaceFactory]::CreateRunspacePool(1, $threadCount)
$pool.Open()
$jobs    = [System.Collections.Generic.List[hashtable]]::new()
$total   = $candidateFiles.Count
$counter = 0

foreach($file in $candidateFiles){
    $counter++

    if($counter % 200 -eq 0){
        Write-Progress -Activity "Hashing files" `
                       -Status "[$counter / $total] $($file.Name)" `
                       -PercentComplete ([Math]::Round(($counter / $total) * 100))
    }

    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($scriptBlock)
    [void]$ps.AddArgument($file.FullName)
    [void]$ps.AddArgument($knownBadHashes)

    $jobs.Add(@{
        PS     = $ps
        Handle = $ps.BeginInvoke()
        File   = $file
    })

    # Collect completed jobs in batches to keep memory controlled
    if($jobs.Count -ge $threadCount * 4){
        $completed = $jobs | Where-Object { $_.Handle.IsCompleted }
        foreach($job in $completed){
            $result = $job.PS.EndInvoke($job.Handle)
            if($result){ $hashResults.Add($result) }
            $job.PS.Dispose()
            [void]$jobs.Remove($job)
        }
    }
}

# Collect remaining jobs
foreach($job in $jobs){
    $job.Handle.AsyncWaitHandle.WaitOne() | Out-Null
    $result = $job.PS.EndInvoke($job.Handle)
    if($result){ $hashResults.Add($result) }
    $job.PS.Dispose()
}

$pool.Close()
$pool.Dispose()
Write-Progress -Activity "Hashing files" -Completed

# ---------------------------------------------------------
# ENRICH MATCHES with file metadata
# Done after hashing — only on matched files (hopefully few)
# ---------------------------------------------------------
$hashMatches = foreach($match in $hashResults){
    try{
        $fileInfo = Get-Item $match.FilePath -ErrorAction Stop
        $owner    = (Get-Acl $match.FilePath -ErrorAction SilentlyContinue).Owner

        [PSCustomObject]@{
            DetectedFile  = $match.FilePath
            FileName      = $fileInfo.Name
            Extension     = $fileInfo.Extension
            FileSizeKB    = [Math]::Round($fileInfo.Length / 1KB, 1)
            MD5           = $match.MD5
            SHA256        = $match.SHA256
            MD5Match      = $match.MD5Match
            SHA256Match   = $match.SHA256Match
            LastModified  = $fileInfo.LastWriteTimeUTC.ToString("yyyy-MM-dd HH:mm:ss")
            CreationTime  = $fileInfo.CreationTimeUTC.ToString("yyyy-MM-dd HH:mm:ss")
            Owner         = $owner
        }
    }
    catch{ }
}

Write-ForensicLog "Scan complete — Scanned: $total | Matches: $($hashMatches.Count)" `
                  -Level $(if($hashMatches.Count -gt 0){ "FINDING" } else { "SUCCESS" }) `
                  -Section "HASHLOOKUP" `
                  -Detail "Threads: $threadCount"

# ---------------------------------------------------------
# HTML OUTPUT
# ---------------------------------------------------------


if($hashMatches.Count -gt 0){
    foreach($m in $hashMatches){
        $HashMatchFragment += "<tr>"
        $HashMatchFragment += "<td>$($m.DetectedFile)</td>"
        $HashMatchFragment += "<td>$($m.Extension)</td>"
        $HashMatchFragment += "<td>$($m.FileSizeKB)</td>"
        $HashMatchFragment += "<td><code>$($m.MD5)</code></td>"
        $HashMatchFragment += "<td><code>$($m.SHA256)</code></td>"
        $HashMatchFragment += "<td>$(if($m.MD5Match)   {'&#9888; YES'} else {''})</td>"
        $HashMatchFragment += "<td>$(if($m.SHA256Match){'&#9888; YES'} else {''})</td>"
        $HashMatchFragment += "<td>$($m.LastModified)</td>"
        $HashMatchFragment += "<td>$($m.CreationTime)</td>"
        $HashMatchFragment += "<td>$($m.Owner)</td>"
        $HashMatchFragment += "</tr>"
    }

    $hashMatches | Export-Csv `
        "$PSScriptRoot\$env:COMPUTERNAME\HashMatches\MalwareHashMatch.csv" `
        -NoTypeInformation -Encoding UTF8

    Write-ForensicLog "$($hashMatches.Count) malware match(es) found" `
                      -Level FINDING -Section "HASHLOOKUP"
}
else{
    #$HashMatchFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No hash matches found across $total files scanned</td></tr>"
}




Write-ForensicLog "Hash lookup complete" -Level SUCCESS -Section "HASHLOOKUP"



} 
else {
  $HashMatchFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>Hash lookup skipped or nothing found</td></tr>"

}

#endregion

Write-ForensicLog ""


#####################################################################################################################
######################################################################################################################
#region     EVENT LOG ANALYSIS SECTION		     	     #################################################################
######################################################################################################################
######################################################################################################################


# configuration file path
$configFile = "$PSScriptRoot\config.json"

# Read and parse the configuration file
$configData = Get-Content $configFile | ConvertFrom-Json


function ConvertTo-ConfigStringArray {
  param($Value)

  if($null -eq $Value){
    return @()
  }

  return @(
    @($Value) |
      ForEach-Object { [string]$_ } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      Select-Object -Unique
  )
}

function ConvertTo-ConfigPositiveInt {
  param(
    $Value,
    [int]$Default,
    [string]$Name
  )

  $parsed = 0
  if($null -ne $Value -and [int]::TryParse([string]$Value, [ref]$parsed) -and $parsed -gt 0){
    return $parsed
  }

  if($null -ne $Value){
    Write-ForensicLog "Invalid $Name in config.json — using default" -Level WARN -Section "CONFIG" -Detail "Configured value: $Value | Default: $Default"
  }

  return $Default
}

$eventLogConfig = $null
if($null -ne $configData -and $null -ne $configData.eventlog){
  $eventLogConfig = $configData.eventlog
}
elseif($null -ne $configData -and $null -ne $configData.event_log){
  $eventLogConfig = $configData.event_log
}

$script:EventLogDaysBack = 30
if($null -ne $eventLogConfig -and $null -ne $eventLogConfig.days_back){
  $script:EventLogDaysBack = ConvertTo-ConfigPositiveInt -Value $eventLogConfig.days_back -Default 30 -Name "eventlog.days_back"
}
elseif($null -ne $configData -and $null -ne $configData.sigma -and $null -ne $configData.sigma.days_back){
  $script:EventLogDaysBack = ConvertTo-ConfigPositiveInt -Value $configData.sigma.days_back -Default 30 -Name "sigma.days_back"
}

$script:EventLogEndTime   = Get-Date
$script:EventLogStartTime = $script:EventLogEndTime.AddDays(-$script:EventLogDaysBack)
$script:ForensicEventDateFormat = "yyyy-MM-dd HH:mm:ss"

function Format-ForensicEventTime {
  param($Value)

  if($null -eq $Value){
    return ""
  }

  $dateTime = [datetime]::MinValue
  if($Value -is [datetime]){
    $dateTime = [datetime]$Value
  }
  elseif(-not [datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dateTime)){
    return [string]$Value
  }

  if($dateTime.Kind -eq [System.DateTimeKind]::Utc){
    $dateTime = $dateTime.ToLocalTime()
  }

  return $dateTime.ToString($script:ForensicEventDateFormat, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-ForensicWinEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [string]$LogName,
    [int[]]$Id,
    [string]$ProviderName,
    [switch]$UseProviderFilter,
    [datetime]$StartTime = $script:EventLogStartTime,
    [datetime]$EndTime = $script:EventLogEndTime,
    [int]$MaxEvents = 0
  )

  $safeLogName = [System.Security.SecurityElement]::Escape($LogName)
  $systemClauses = [System.Collections.Generic.List[string]]::new()

  $eventIdClauses = @($Id | Where-Object { $_ -gt 0 } | ForEach-Object { "EventID=$([int]$_)" })
  if($eventIdClauses.Count -gt 0){
    $systemClauses.Add("(" + ($eventIdClauses -join " or ") + ")")
  }

  if($UseProviderFilter -and -not [string]::IsNullOrWhiteSpace($ProviderName)){
    $safeProviderName = [System.Security.SecurityElement]::Escape($ProviderName)
    $systemClauses.Add("Provider[@Name='$safeProviderName']")
  }

  if($null -ne $StartTime){
    $startTimeUtc = $StartTime.ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    $systemClauses.Add("TimeCreated[@SystemTime&gt;='$startTimeUtc']")
  }

  if($null -ne $EndTime){
    $endTimeUtc = $EndTime.ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    $systemClauses.Add("TimeCreated[@SystemTime&lt;='$endTimeUtc']")
  }

  $systemFilter = $systemClauses -join " and "
  if([string]::IsNullOrWhiteSpace($systemFilter)){
    $systemFilter = "*"
  }

  $query = [xml]@"
<QueryList>
  <Query Id="0" Path="$safeLogName">
    <Select Path="$safeLogName">*[System[$systemFilter]]</Select>
  </Query>
</QueryList>
"@

  $queryParams = @{
    FilterXml   = $query
    ErrorAction = "Stop"
  }
  if($MaxEvents -gt 0){
    $queryParams.MaxEvents = $MaxEvents
  }

  try{
    return @(Get-WinEvent @queryParams)
  }
  catch{
    if($_.Exception.Message -match "No events were found|No matching events|No matches found"){
      return @()
    }
    throw
  }
}

Write-ForensicLog "EventLog lookback resolved" -Level INFO -Section "EventLog" -Detail "DaysBack: $script:EventLogDaysBack | Start: $(Format-ForensicEventTime $script:EventLogStartTime) | End: $(Format-ForensicEventTime $script:EventLogEndTime)"


<#
$logonTypeMap = @{
    "2"  = @{ Name="Interactive";        Risk="Medium"; Note="Console/RunAs logon" }
    "3"  = @{ Name="Network";            Risk="Medium"; Note="SMB/WMI/net use" }
    "4"  = @{ Name="Batch";              Risk="Low";    Note="Scheduled task" }
    "5"  = @{ Name="Service";            Risk="Low";    Note="Service account" }
    "7"  = @{ Name="Unlock";             Risk="Medium"; Note="Workstation unlock" }
    "8"  = @{ Name="NetworkCleartext";   Risk="High";   Note="Plaintext credentials over network" }
    "9"  = @{ Name="NewCredentials";     Risk="High";   Note="RunAs /netonly — lateral movement" }
    "10" = @{ Name="RemoteInteractive";  Risk="Medium"; Note="RDP" }
    "11" = @{ Name="CachedInteractive";  Risk="Medium"; Note="Cached credentials" }
}


$failureReasons = @{
    "0xC000005E" = "No logon servers available"
    "0xC0000064" = "Username does not exist"
    "0xC000006A" = "Wrong password"
    "0xC000006D" = "Bad username or auth package"
    "0xC000006E" = "Account restriction"
    "0xC000006F" = "Outside allowed logon hours"
    "0xC0000070" = "Workstation restriction"
    "0xC0000071" = "Password expired"
    "0xC0000072" = "Account disabled"
    "0xC0000193" = "Account expired"
    "0xC0000224" = "Password must change"
    "0xC0000234" = "Account locked out
    "0xC00002EE" = "An error occurred during logon"
}

#>

#############################################################################################################
#region   EVENT LOG ANALYSIS — GROUP ENUMERATION (4798 / 4799)
#############################################################################################################





Write-ForensicLog "[*] Checking for user/group enumeration events" -Level INFO -Section "EventLog"

$GroupMembershipID = @(
  4798,
  4799

)
$GroupMembership = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $GroupMembershipID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $GroupMembershipEventXml = ([xml]$_.ToXml()).Event
  $GroupMembershipEnumAccount = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $GroupMembershipPerformedBy = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $GroupMembershipPerformedLogon = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  $GroupMembershipPerformedPID = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessId' }).'#text'
  $GroupMembershipPerformedPName = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time        = Format-ForensicEventTime $_.TimeCreated
    PerformedOn = $GroupMembershipEnumAccount
    PerformedBy = $GroupMembershipPerformedBy
    LogonType   = $GroupMembershipPerformedLogon
    PID         = $GroupMembershipPerformedPID
    ProcessName = $GroupMembershipPerformedPName
  }
} 

if ($GroupMembership.Count -eq 0) {
    $GroupMembershipFragment += "<tr><td colspan='7' style='text-align:center;color:#27ae60;'>No group enumeration events found</td></tr>"
}

# Populate the HTML table with process information
foreach ($process in $GroupMembership) {
  $GroupMembershipFragment += "<tr>"
  $GroupMembershipFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.Time))</td>"
  $GroupMembershipFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$($process.PerformedOn)))</td>"
  $GroupMembershipFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$($process.PerformedBy)))</td>"
  $GroupMembershipFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$($process.LogonType)))</td>"
  $GroupMembershipFragment += "<td>$($process.PID)</td>"
  $GroupMembershipFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$($process.ProcessName)))</td>"
  $GroupMembershipFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion



###############################################################################
### RDP Logins                        #########################################
###############################################################################

Write-ForensicLog "[*] Fetching RDP Logins" -Level INFO -Section "EventLog"

$RDPLoginsGroupIDs = @(4624, 4778)

$RDPLogins = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $RDPLoginsGroupIDs | ForEach-Object {
    $eventId = $_.Id
    $xml     = ([xml]$_.ToXml()).Event
    $data    = $xml.EventData.Data

    # Extract LogonType safely
    $logonType = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    $targetUser = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'

    # Only keep RDP logons (LogonType 10) for 4624
   if ($eventId -eq 4624) {
    if ($logonType -notin @('3','10')) { return }
}
	
	if ($targetUser -like "*$") { return }

    # Select correct IP field
    $ipField = if ($eventId -eq 4624) { 'IpAddress' } else { 'ClientAddress' }

    [PSCustomObject]@{
        EventID         = $eventId
        Type            = if ($eventId -eq 4624) { 'New Session' } else { 'Reconnect' }
        Time            = Format-ForensicEventTime $_.TimeCreated
        LogonUser       = $targetUser
        LogonUserDomain = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        LogonIP         = ($data | Where-Object { $_.Name -eq $ipField }).'#text'
    }
}

# Build HTML
$RDPLoginsFragment = ''

if (!$RDPLogins) {
    $RDPLoginsFragment = "<tr><td colspan='6' style='text-align:center;color:#27ae60;'>No RDP logins found</td></tr>"
}
else {
    foreach ($process in $RDPLogins) {
        $RDPLoginsFragment += "<tr>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.EventID))</td>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.Type))</td>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.Time))</td>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.LogonUser))</td>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.LogonUserDomain))</td>"
        $RDPLoginsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$process.LogonIP))</td>"
        $RDPLoginsFragment += "</tr>"
    }
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion

###############################################################################
### RDP Logins All History            #########################################
###############################################################################

Write-ForensicLog "[*] Fetching History of All RDP Logons to this system" -Level INFO -Section "EventLog"

$RDPAuthsFragment = ''

try {
    $RDPAuths = Get-ForensicWinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149

    $EventData = foreach ($evt in $RDPAuths) {
        $xml = ([xml]$evt.ToXml()).Event
        $user   = $xml.UserData.EventXML.Param1
        $domain = $xml.UserData.EventXML.Param2
        $client = $xml.UserData.EventXML.Param3

        # Skip machine accounts and blank users — usually noise
        if ([string]::IsNullOrWhiteSpace($user) -or $user -match '\$$') { continue }

        [PSCustomObject]@{
            TimeCreated = Format-ForensicEventTime $evt.TimeCreated
            User        = $user
            Domain      = $domain
            Client      = $client
        }
    }

    if (!$EventData -or $EventData.Count -eq 0) {
        $RDPAuthsFragment = "<tr><td colspan='4' style='text-align:center;color:#27ae60;'>No RDP authentication events found</td></tr>"
    } else {
        foreach ($process in $EventData) {
            $RDPAuthsFragment += "<tr>"
            $RDPAuthsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($process.TimeCreated))</td>"
            $RDPAuthsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($process.User))</td>"
            $RDPAuthsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($process.Domain))</td>"
            $RDPAuthsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($process.Client))</td>"
            $RDPAuthsFragment += "</tr>"
        }
    }
} catch {
    # Log is disabled or RDP was never enabled on this machine
    Write-ForensicLog "TerminalServices-RemoteConnectionManager log unavailable: $($_.Exception.Message)" -Level WARN -Section "EventLog"
    #$RDPAuthsFragment = "<tr><td colspan='4' style='text-align:center;color:#e67e22;'>RDP operational log unavailable or empty</td></tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Outgoing RDP Connections            #########################################
###############################################################################

Write-ForensicLog "[*] Fetching All outgoing RDP connection History" -Level INFO -Section "EventLog"


# Define the properties array properly
$properties = @(
  @{n = 'TimeStamp'; e = { Format-ForensicEventTime $_.TimeCreated } }
  @{n = 'LocalUser'; e = { [System.Security.Principal.SecurityIdentifier]::new($_.UserID).Translate([System.Security.Principal.NTAccount]).Value } }
  @{n = 'Target RDP host'; e = { $_.Properties[1].Value } }
)

# Retrieve the events
$OutRDP = Get-ForensicWinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -Id 1102 | Select-Object $properties

# Initialize the HTML fragment
$OutRDPFragment = ""

if ($OutRDP.Count -eq 0) {
    $OutRDPFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No outgoing RDP connection events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $OutRDP) {
  $OutRDPFragment += "<tr>"
  $OutRDPFragment += "<td>$($event.TimeStamp)</td>"
  $OutRDPFragment += "<td>$($event.LocalUser)</td>"
  $OutRDPFragment += "<td>$($event.'Target RDP host')</td>"  
  $OutRDPFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Created Users                 #############################################
###############################################################################


Write-ForensicLog "[*] Fetching Created Users" -Level INFO -Section "EventLog"

$CreatedUsersGroupID = @(
  4720
)

$CreatedUsers = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $CreatedUsersGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CreatedUsersEventXml = ([xml]$_.ToXml()).Event
  $CreatedUser = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $CreatedUsersTarget = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time        = Format-ForensicEventTime $_.TimeCreated
    CreatedUser = $CreatedUser
    CreatedBy   = $CreatedUsersTarget
  }
} # | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($CreatedUsers.Count -eq 0) {
    $CreatedUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user creation events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CreatedUsers) {
  $CreatedUsersFragment += "<tr>"
  $CreatedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $CreatedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.CreatedUser))</td>"
  $CreatedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.CreatedBy))</td>"  
  $CreatedUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"


###############################################################################
### Password Resets               #############################################
###############################################################################


Write-ForensicLog "[*] Checking for password resets" -Level INFO -Section "EventLog"

$PassResetGroupID = @(
  4724
)

$PassReset = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $PassResetGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $PassResetEventXml = ([xml]$_.ToXml()).Event
  $PassResetTargetUser = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $PassResetActionedBy = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = Format-ForensicEventTime $_.TimeCreated
    TargetUser = $PassResetTargetUser
    ActionedBy = $PassResetActionedBy
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($PassReset.Count -eq 0) {
    $PassResetFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No password reset events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $PassReset) {
  $PassResetFragment += "<tr>"
  $PassResetFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $PassResetFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.TargetUser))</td>"
  $PassResetFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.ActionedBy))</td>"  
  $PassResetFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"


###############################################################################
### Added users to Group          #############################################
###############################################################################

Write-ForensicLog "[*] Checking for user, group, object access and credential manager actions" -Level INFO -Section "EventLog"

$AddedUsersFragment = ''

try {
    $AddedUsers = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id @(4728, 4732) | ForEach-Object {

        $xml     = ([xml]$_.ToXml()).Event
        $addedBy = ($xml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $group   = ($xml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName'  }).'#text'
        $sid     = ($xml.EventData.Data | Where-Object { $_.Name -eq 'MemberSid'       }).'#text'

        # Resolve SID to account name — gracefully fall back to raw SID
        # if the account is deleted, from an unreachable domain, or a well-known built-in
        $targetName = $sid  # default to raw SID
        if (-not [string]::IsNullOrWhiteSpace($sid)) {
            try {
                $targetName = (New-Object System.Security.Principal.SecurityIdentifier($sid))
                                .Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $targetName = "$sid (deleted/unknown account)"   # keep raw SID — don't crash
            }
        }

        [PSCustomObject]@{
            Time    = Format-ForensicEventTime $_.TimeCreated
            AddedBy = $addedBy
            Group   = $group
            Target  = $targetName
        }
    }

    if (-not $AddedUsers -or $AddedUsers.Count -eq 0) {
        $AddedUsersFragment = "<tr><td colspan='4' style='text-align:center;color:#27ae60;'>No group membership change events found in the last $script:EventLogDaysBack days</td></tr>"
    } else {
        foreach ($event in $AddedUsers) {
            $AddedUsersFragment += "<tr>"
            $AddedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($event.Time))</td>"
            $AddedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($event.AddedBy))</td>"
            $AddedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($event.Group))</td>"
            $AddedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode($event.Target))</td>"
            $AddedUsersFragment += "</tr>"
        }
    }
} catch {
    Write-ForensicLog "Failed to query group membership events: $($_.Exception.Message)" -Level WARN -Section "EventLog"
    $AddedUsersFragment = "<tr><td colspan='4' style='text-align:center;color:#e67e22;'>Could not retrieve group membership events</td></tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Enabled Users                 #############################################
###############################################################################

Write-ForensicLog "[*] Checking for enabled users" -Level INFO -Section "EventLog"

$EnabledUsersGroupID = @(
  4722

)
$EnabledUsers = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $EnabledUsersGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $EnabledUsersEventXml = ([xml]$_.ToXml()).Event
  $EnabledBy = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $EnabledTarget = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = Format-ForensicEventTime $_.TimeCreated
    EnabledBy      = $EnabledBy
    EnabledAccount = $EnabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($EnabledUsers.Count -eq 0) {
    $EnabledUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user enablement events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $EnabledUsers) {
  $EnabledUsersFragment += "<tr>"
  $EnabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $EnabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.EnabledBy))</td>"
  $EnabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.EnabledAccount))</td>"  
  $EnabledUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Disabled Users                #############################################
###############################################################################

Write-ForensicLog "[*] Checking for disabled users" -Level INFO -Section "EventLog"

$DisabledUsersGroupID = @(
  4723

)
$DisabledUsers = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $DisabledUsersGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DisabledUsersEventXml = ([xml]$_.ToXml()).Event
  $DisabledBy = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DisabledTarget = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = Format-ForensicEventTime $_.TimeCreated
    DisabledBy = $DisabledBy
    Disabled   = $DisabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($DisabledUsers.Count -eq 0) {
    $DisabledUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user disablement events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $DisabledUsers) {
  $DisabledUsersFragment += "<tr>"
  $DisabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $DisabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.DisabledBy))</td>"
  $DisabledUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Disabled))</td>"  
  $DisabledUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Deleted Users                #############################################
###############################################################################

Write-ForensicLog "[*] Checking for deleted users" -Level INFO -Section "EventLog"

$DeletedUsersGroupID = @(
  4726

)
$DeletedUsers = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $DeletedUsersGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DeletedUsersEventXml = ([xml]$_.ToXml()).Event
  $DeletedBy = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DeletedTarget = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = Format-ForensicEventTime $_.TimeCreated
    DeletedBy      = $DeletedBy
    DeletedAccount = $DeletedTarget
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($DeletedUsers.Count -eq 0) {
    $DeletedUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user deletion events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $DeletedUsers) {
  $DeletedUsersFragment += "<tr>"
  $DeletedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $DeletedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.DeletedBy))</td>"
  $DeletedUsersFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.DeletedAccount))</td>"  
  $DeletedUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Account Lockout               #############################################
###############################################################################

Write-ForensicLog "[*] Checking for account lockout events" -Level INFO -Section "EventLog"

$LockOutGroupID = @(
  4740

)
$LockOut = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $LockOutGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $LockOutEventXml = ([xml]$_.ToXml()).Event
  $LockedOutAcct = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $System = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = Format-ForensicEventTime $_.TimeCreated
    LockedOutAccount = $LockedOutAcct
    System           = $System
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($LockOut.Count -eq 0) {
    $LockOutFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No account lockout events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $LockOut) {
  $LockOutFragment += "<tr>"
  $LockOutFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $LockOutFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.LockedOutAccount))</td>"
  $LockOutFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.System))</td>"  
  $LockOutFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Credential Manager Backup                   ###############################
###############################################################################

Write-ForensicLog "[*] Checking for credential manager backup events" -Level INFO -Section "EventLog"

$CredManBackupGroupID = @(
  5376

)
$CredManBackup = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $CredManBackupGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManBackupEventXml = ([xml]$_.ToXml()).Event
  $CredManBackupAcct = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManBackupAcctLogon = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  $CredManBackupFileName = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'BackupFileName' }).'#text'
  $CredManBackupProcessID = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'ClientProcessId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = Format-ForensicEventTime $_.TimeCreated
    BackupAccount    = $CredManBackupAcct
    AccountLogonType = $CredManBackupAcctLogon
    BackupFileName   = $CredManBackupFileName
    ProcessID        = $CredManBackupProcessID
  }
}

if ($CredManBackup.Count -eq 0) {
    $CredManBackupFragment += "<tr><td colspan='5' style='text-align:center;color:#27ae60;'>No credential manager backup events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CredManBackup) {
  $CredManBackupFragment += "<tr>"
  $CredManBackupFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $CredManBackupFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.BackupAccount))</td>"
  $CredManBackupFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.AccountLogonType))</td>"  
  $CredManBackupFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.BackupFileName))</td>"
  $CredManBackupFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.ProcessID))</td>"
  $CredManBackupFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Credential Manager Restore                  ###############################
###############################################################################

Write-ForensicLog "[*] Checking for credential manager restore events" -Level INFO -Section "EventLog"

$CredManRestoreGroupID = @(
  5377

)
$CredManRestore = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $CredManRestoreGroupID | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManRestoreEventXml = ([xml]$_.ToXml()).Event
  $RestoredAcct = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManRestoreAcctLogon = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = Format-ForensicEventTime $_.TimeCreated
    RestoredAccount  = $RestoredAcct
    AccountLogonType = $CredManRestoreAcctLogon

  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($CredManRestore.Count -eq 0) {
    $CredManRestoreFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No credential manager restore events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CredManRestore) {
  $CredManRestoreFragment += "<tr>"
  $CredManRestoreFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $CredManRestoreFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.RestoredAccount))</td>"
  $CredManRestoreFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.AccountLogonType))</td>"  
  $CredManRestoreFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################################
#region   EVENT LOG ANALYSIS   LOGON EVENTS           #######################################################
#############################################################################################################

Write-ForensicLog "[*] Checking for logon events" -Level INFO -Section "EventLog"

# SUCCESSFUL LOGON EVENTS

# Define variables for the event log name and event ID
$logName = "Security"
$eventID = 4624
#$eventID = 4625

# Query the event log for logon events
$logonEvents = Get-ForensicWinEvent -LogName $logName -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $eventID

# Create an array to hold the logon event details
$logonDetails = foreach ($logonEvent in $logonEvents) {
  $xml = ([xml]$logonEvent.ToXml()).Event
  $data = @{}
  foreach($node in @($xml.EventData.Data)){
    if($node.Name){ $data[[string]$node.Name] = [string]$node.'#text' }
  }

  [PSCustomObject]@{
    Time                 = Format-ForensicEventTime $logonEvent.TimeCreated
    User                 = $data["TargetUserName"]
    LogonType            = $data["LogonType"]
    SourceNetworkAddress = $data["IpAddress"]
    Status               = "Success"
  }
}

# Convert the logon details to HTML
#$Successhtml = $logonDetails #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($logonDetails.Count -eq 0) {
    $logonEventsFragment += "<tr><td colspan='5' style='text-align:center;color:#27ae60;'>No logon events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $logonDetails) {
  $logonEventsFragment += "<tr>"
  $logonEventsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $logonEventsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.User))</td>"
  $logonEventsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.LogonType))</td>"
  $logonEventsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.SourceNetworkAddress))</td>"
  $logonEventsFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Status))</td>"  
  $logonEventsFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################
#region FAILED LOGON EVENTS           #######################################################
#############################################################################################

Write-ForensicLog "[*] Checking for failed logon events" -Level INFO -Section "EventLog"

# Define variables for the event log name and event ID
$logName = "Security"
#$eventID = 4624
$eventID = 4625

# Query the event log for logon events


    $Events = $null
    try{
        $Events = $logonEventsFailed = Get-ForensicWinEvent -LogName $logName -ProviderName 'Microsoft-Windows-Security-Auditing' -Id $eventID
        Write-ForensicLog "[*] Retrieved $($Events.Count) failed logon event(s)" -Level SUCCESS -Section "EventLog" -Detail "Failed Logon Retrieved $($Events.Count) events"
    }
    catch [System.Exception]{
        if($_.Exception.Message -match "No matches found"){
            Write-ForensicLog "[!] No failed logon events found" -Level WARN -Section "EventLog" -Detail "Failed Logon Retrieved 0 events"
            Write-ForensicLog "[!] This is expected if failed logon auditing is not configured" -Level WARN -Section "EventLog"
            $logonEventsFailedFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No failed logon events found</td></tr>"
        }
        else{
            Write-ForensicLog "[!] Query failed: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Failed Logon Query Failed"
        }
    }

# Create an array to hold the logon event details
$logonDetails = foreach ($logonEvent in $logonEventsFailed) {
  $xml = ([xml]$logonEvent.ToXml()).Event
  $data = @{}
  foreach($node in @($xml.EventData.Data)){
    if($node.Name){ $data[[string]$node.Name] = [string]$node.'#text' }
  }

  [PSCustomObject]@{
    Time                 = Format-ForensicEventTime $logonEvent.TimeCreated
    User                 = $data["TargetUserName"]
    LogonType            = $data["LogonType"]
    SourceNetworkAddress = $data["IpAddress"]
    Status               = $data["Status"]
  }
}

# Convert the logon details to HTML
#$Failedhtml = $logonDetails | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1



if ($logonDetails.Count -eq 0 -and [string]::IsNullOrWhiteSpace($logonEventsFailedFragment)) {
    $logonEventsFailedFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No failed logon events found</td></tr>"
}


# Populate the HTML table with event information
foreach ($event in $logonDetails) {
  $logonEventsFailedFragment += "<tr>"
  $logonEventsFailedFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Time))</td>"
  $logonEventsFailedFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.User))</td>"
  $logonEventsFailedFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.LogonType))</td>"
  $logonEventsFailedFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.SourceNetworkAddress))</td>"
  $logonEventsFailedFragment += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$event.Status))</td>"  
  $logonEventsFailedFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion

#############################################################################################################
#region   EVENT LOG ANALYSIS   OBJECT ACCESS          #######################################################
#############################################################################################################

Write-ForensicLog "[*] Checking for object access events" -Level INFO -Section "EventLog"

# ---------------------------------------------------------
# OBJECT ACCESS EVENTS — 4656 (handle requested) 
#                         4663 (object accessed)
# Requires: Audit Object Access enabled in Local Security Policy
# Requires: Elevated privileges to read Security log
# ---------------------------------------------------------

$StartTime = $script:EventLogStartTime
$EndTime   = $script:EventLogEndTime
$EventLog  = "Security"
$EventIDs  = @(4656, 4663)

# ---------------------------------------------------------
# CHECK 1 — confirm we can read the Security log at all
# ---------------------------------------------------------
$canReadLog = $false
try{
    Get-WinEvent -LogName $EventLog -MaxEvents 1 -ErrorAction Stop | Out-Null
    $canReadLog = $true
}
catch [System.UnauthorizedAccessException]{
    Write-ForensicLog "[!] Access denied reading Security log — run as Administrator" -Level ERROR -Section "EventLog" -Detail "Object Access Log Access Denied"
}
catch{
    Write-ForensicLog "[!] Cannot access Security log: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Object Access Log Access Failed"
}

# ---------------------------------------------------------
# CHECK 2 — confirm Object Access auditing is actually enabled
# Without this 4656/4663 will never be generated regardless
# of how far back you look
# ---------------------------------------------------------
if($canReadLog){
    try{
        $auditPol = & auditpol /get /subcategory:"File System" 2>$null
        if($auditPol -notmatch "Success|Failure"){
            Write-ForensicLog "[!] Object Access auditing (File System) does not appear to be enabled" -Level WARN -Section "EventLog"
        }
    }
    catch{ }
}



if($canReadLog){

    $Query = @"
<QueryList>
  <Query Path="$EventLog">
    <Select Path="$EventLog">*[System[(EventID=$($EventIDs[0]) or EventID=$($EventIDs[1])) and TimeCreated[@SystemTime&gt;='$($StartTime.ToUniversalTime().ToString("o"))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString("o"))']]]</Select>
  </Query>
</QueryList>
"@

    $Events = $null
    try{
        $Events = Get-WinEvent -FilterXml $Query -ErrorAction Stop
        Write-ForensicLog "[*] Retrieved $($Events.Count) object access event(s)" -Level SUCCESS -Section "EventLog" -Detail "Object Access Retrieved $($Events.Count) events (FilterXml) in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days"
    }
    catch [System.Exception]{
        if($_.Exception.Message -match "No events were found"){
            Write-ForensicLog "[!] No object access events found in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days" -Level WARN -Section "EventLog" -Detail "Object Access Retrieved 0 events (FilterXml) in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days"
            Write-ForensicLog "[!] This is expected if Object Access auditing is not configured" -Level WARN -Section "EventLog"
            $ObjectHtmlTable1 += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No object access events found in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days</td></tr>"
        }
        else{
            Write-ForensicLog "[!] Query failed: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Object Access Query Failed"
        }
    }

    foreach($Event in $Events){
        # Parse via XML instead of property index — property offsets
        # differ between 4656 and 4663 and vary by Windows version
        try{
            $xml  = [xml]$Event.ToXml()
            $data = @{}
            foreach($node in $xml.Event.EventData.Data){
                if($node.Name){ $data[$node.Name] = $node.'#text' }
            }

            $time       = $Event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            $eventId    = $Event.Id
            $user       = $data["SubjectUserName"]
            $domain     = $data["SubjectDomainName"]
            $objectName = $data["ObjectName"]
            $objectType = $data["ObjectType"]
            $access     = $data["AccessMask"]
            $process    = $data["ProcessName"]

            # Translate common access masks to readable names
            $accessLabel = switch($access){
                "0x1"    { "ReadData" }
                "0x2"    { "WriteData" }
                "0x4"    { "AppendData" }
                "0x20"   { "Execute" }
                "0x10000"{ "Delete" }
                "0x40000"{ "Write DAC" }
                "0x80000"{ "Write Owner" }
                default  { $access }
            }

            # Skip noisy system accounts — focus on real user activity
            if($user -match '^\$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$'){ continue }

            # Skip registry and pipe objects — file objects are the signal
            if($objectType -match 'Key|Pipe|Token'){ continue }


            $ObjectHtmlTable1 += "<td>$time</td>"
            $ObjectHtmlTable1 += "<td>$eventId</td>"
            $ObjectHtmlTable1 += "<td>$user</td>"
            $ObjectHtmlTable1 += "<td>$domain</td>"
            $ObjectHtmlTable1 += "<td>$objectName</td>"
            $ObjectHtmlTable1 += "<td>$objectType</td>"
            $ObjectHtmlTable1 += "<td>$accessLabel</td>"
            $ObjectHtmlTable1 += "<td>$process</td>"

        }
        catch{
            Write-ForensicLog "[!] Failed to parse event $($Event.Id): $($_.Exception.Message)" -Level ERROR -Section "EventLog"
        }
    }
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################################
#region   EVENT LOG ANALYSIS — PROCESS EXECUTION (CLEAN)
#############################################################################################################

Write-ForensicLog "[*] Collecting process execution events" -Level INFO -Section "EventLog"

# ---------------------------------------------------------
# HELPER — convert hex PID strings (e.g. 0x66d4) to decimal
# ---------------------------------------------------------
function ConvertFrom-HexId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    try { [Convert]::ToInt32($Value.Trim(), 16) } catch { $Value }
}

# ---------------------------------------------------------
# SYSTEM ACCOUNTS TO SKIP (reduce noise)
# ---------------------------------------------------------
$systemAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')

# ---------------------------------------------------------
# QUERY (RESILIENT — handles malformed events)
# ---------------------------------------------------------
$startDate = $script:EventLogStartTime
$endDate   = $script:EventLogEndTime
$events    = $null

try {
    $events = Get-ForensicWinEvent -LogName 'Security' -ProviderName 'Microsoft-Windows-Security-Auditing' -Id 4688 -StartTime $startDate -EndTime $endDate

    Write-ForensicLog "[*] Retrieved $($events.Count) events (FilterXml)" -Level INFO -Section "EventLog" -Detail "Process Execution Retrieved $($events.Count) events (FilterXml)"
}
catch {
    Write-ForensicLog "[!] Filter failed — falling back to XPath" -Level WARN -Section "EventLog"

    try {
        $fallbackStartUtc = $startDate.ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
        $fallbackEndUtc   = $endDate.ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
        $fallbackQuery = [xml]@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688) and TimeCreated[@SystemTime&gt;='$fallbackStartUtc' and @SystemTime&lt;='$fallbackEndUtc']]]</Select>
  </Query>
</QueryList>
"@
        $events = Get-WinEvent -FilterXml $fallbackQuery -ErrorAction Stop

        Write-ForensicLog "[*] Retrieved $($events.Count) events (FilterXml fallback)" -Level INFO -Section "EventLog" -Detail "Process Execution Retrieved $($events.Count) events (FilterXml fallback)"
    }
    catch {
        Write-ForensicLog "[!] Failed to query events: $($_.Exception.Message)" -Level ERROR -Section "EventLog"
    }
}

if (-not $events) {
    Write-ForensicLog "[!] No events found" -Level WARN -Section "EventLog"
    $ObjectHtmlTable2 += "<tr><td colspan='8' style='text-align:center;color:#27ae60;'>No process execution events found in the last $((New-TimeSpan -Start $startDate -End $endDate).Days) days</td></tr>"
}

# ---------------------------------------------------------
# PROCESS EVENTS
# ---------------------------------------------------------
foreach ($event in $events) {
    try {
        $xml  = [xml]$event.ToXml()
        $data = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = $node.'#text' }
        }

        $user   = $data["SubjectUserName"]
        $domain = $data["SubjectDomainName"]

        # Skip system noise
        if ($systemAccounts -contains $user) { continue }
        if ($user -match '\$$') { continue }

        $time        = $event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $processName = $data["NewProcessName"]
        $processId   = ConvertFrom-HexId $data["NewProcessId"]
        $parentName  = $data["ParentProcessName"]
        $parentId    = ConvertFrom-HexId $data["ProcessId"]
        $commandLine = $data["CommandLine"]

        $ObjectHtmlTable2 += "<tr>"
        $ObjectHtmlTable2 += "<td>$time</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$user))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$domain))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$processName))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$processId))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$parentName))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$parentId))</td>"
        $ObjectHtmlTable2 += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$commandLine))</td>"
        $ObjectHtmlTable2 += "</tr>"
    }
    catch {
        Write-ForensicLog "[!] Failed to parse event: $($_.Exception.Message)" -Level ERROR -Section "EventLog"
        continue
    }
}



Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"



#endregion



Write-ForensicLog ""

#############################################################################################################
#region   BITLOCKER KEY EXTRACTION
#############################################################################################################

Write-ForensicLog "[*] Checking BitLocker encryption status and extracting recovery keys" -Level INFO -Section "BitLocker"

$Cmd_BitLocker = @{
    Display = "manage-bde -protectors -get C:"
}

# ---------------------------------------------------------
# REQUIRES ELEVATION
# BitLocker key material is only accessible as Administrator
# ---------------------------------------------------------
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if(-not $isElevated){
    Write-ForensicLog "[!] BitLocker key extraction requires Administrator privileges" -Level ERROR -Section "BitLocker"
}

# ---------------------------------------------------------
# CHECK BITLOCKER MODULE AVAILABILITY
# BitLocker cmdlets require the BitLocker feature/module
# Available on: Win 8+/Server 2012+ with BitLocker feature
# Falls back to WMI if module not available
# ---------------------------------------------------------
$useBitLockerModule = $false
if(Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue){
    $useBitLockerModule = $true
    Write-ForensicLog "[*] BitLocker PowerShell module available, I will use it" -Level Info -Section "BitLocker"
}
else{
    Write-ForensicLog "[!] BitLocker module not available — falling back to WMI/manage-bde" -Level Warning -Section "BitLocker"
}

# ---------------------------------------------------------
# KEY PROTECTOR TYPE MAP
# ---------------------------------------------------------
$protectorTypeMap = @{
    "Tpm"                       = "TPM"
    "TpmPin"                    = "TPM + PIN"
    "TpmStartupKey"             = "TPM + Startup Key"
    "TpmPinStartupKey"          = "TPM + PIN + Startup Key"
    "RecoveryPassword"          = "Recovery Password (48-digit)"
    "Password"                  = "Password"
    "ExternalKey"               = "External Key (USB)"
    "Certificate"               = "Certificate"
    "SidProtector"              = "Active Directory SID"
    "Unknown"                   = "Unknown"
}

$BitLockerResults = @()

# ---------------------------------------------------------
# METHOD 1 — BitLocker PowerShell module
# Most complete — returns all protectors including passwords
# ---------------------------------------------------------
if($useBitLockerModule){

    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

    foreach($vol in $volumes){

        $mountPoint     = $vol.MountPoint
        $encryptionPct  = $vol.EncryptionPercentage
        $protectionStatus = $vol.ProtectionStatus
        $encryptionMethod = $vol.EncryptionMethod
        $lockStatus     = $vol.LockStatus
        $volumeType     = $vol.VolumeType

        # Skip volumes with no encryption at all
        if($vol.VolumeStatus -eq "FullyDecrypted" -and $protectionStatus -eq "Off"){ continue }

        foreach($protector in $vol.KeyProtector){

            $protectorType  = $protector.KeyProtectorType.ToString()
            $protectorId    = $protector.KeyProtectorId
            $protectorLabel = if($protectorTypeMap.ContainsKey($protectorType)){ $protectorTypeMap[$protectorType] } else { $protectorType }

            # Recovery password is the key material we care most about
            $keyMaterial = switch($protectorType){
                "RecoveryPassword" { $protector.RecoveryPassword }
                "ExternalKey"      { $protector.KeyFileName       }
                "Certificate"      { $protector.CertificateThumbprint }
                "Password"         { "** Present but not extractable via module **" }
                default            { "N/A" }
            }

            $BitLockerResults += [PSCustomObject]@{
                MountPoint        = $mountPoint
                VolumeType        = $volumeType
                VolumeStatus      = $vol.VolumeStatus
                EncryptionMethod  = $encryptionMethod
                EncryptionPct     = $encryptionPct
                ProtectionStatus  = $protectionStatus
                LockStatus        = $lockStatus
                ProtectorType     = $protectorLabel
                ProtectorId       = $protectorId
                KeyMaterial       = $keyMaterial
            }
        }

        # If no key protectors enumerated but volume is encrypted
        # note it so the investigator knows to use manage-bde manually
        if($vol.KeyProtector.Count -eq 0 -and $vol.VolumeStatus -ne "FullyDecrypted"){
            $BitLockerResults += [PSCustomObject]@{
                MountPoint        = $mountPoint
                VolumeType        = $volumeType
                VolumeStatus      = $vol.VolumeStatus
                EncryptionMethod  = $encryptionMethod
                EncryptionPct     = $encryptionPct
                ProtectionStatus  = $protectionStatus
                LockStatus        = $lockStatus
                ProtectorType     = "None enumerated"
                ProtectorId       = "N/A"
                KeyMaterial       = "Run: manage-bde -protectors -get $mountPoint"
            }
        }
    }
}

# ---------------------------------------------------------
# METHOD 2 — manage-bde fallback
# Works even without the BitLocker module
# Parses text output — less structured but universally available
# ---------------------------------------------------------
else{

    # Get all fixed and removable drive letters
    $drives = Get-CimInstance Win32_LogicalDisk |
              Where-Object { $_.DriveType -in @(2,3) } |
              Select-Object -ExpandProperty DeviceID

    foreach($drive in $drives){
        try{
            $bdeOutput = & manage-bde -protectors -get $drive 2>$null
            if(-not $bdeOutput){ continue }

            $bdeText = $bdeOutput -join "`n"

            # Skip if not encrypted
            if($bdeText -match "No key protectors"){ continue }
            if($bdeText -match "BitLocker Drive Encryption: Volume $drive" -and
               $bdeText -match "Protection Status:\s+Protection Off" -and
               $bdeText -notmatch "Recovery Password"){ continue }

            # Get volume status separately
            $statusOutput = & manage-bde -status $drive 2>$null
            $statusText   = $statusOutput -join "`n"

            $encMethod   = if($statusText -match "Encryption Method:\s+(.+)"){   $matches[1].Trim() } else { "N/A" }
            $encPct      = if($statusText -match "Percentage Encrypted:\s+(.+)"){ $matches[1].Trim() } else { "N/A" }
            $lockStatus  = if($statusText -match "Lock Status:\s+(.+)"){          $matches[1].Trim() } else { "N/A" }
            $protection  = if($statusText -match "Protection Status:\s+(.+)"){    $matches[1].Trim() } else { "N/A" }

            # Extract each protector block from manage-bde output
            # manage-bde separates protectors with blank lines and labels
            $protectorBlocks = $bdeText -split "(?=\n\s{4}[A-Z])"

            foreach($block in $protectorBlocks){

                $pType = if($block -match "Numerical Password")        { "Recovery Password (48-digit)" }
                         elseif($block -match "TPM And PIN")           { "TPM + PIN" }
                         elseif($block -match "TPM And Startup Key")   { "TPM + Startup Key" }
                         elseif($block -match "TPM")                   { "TPM" }
                         elseif($block -match "External Key")          { "External Key (USB)" }
                         elseif($block -match "Password")              { "Password" }
                         elseif($block -match "Certificate")           { "Certificate" }
                         else                                          { continue }

                # Extract ID
                $pIdd  = if($block -match "ID:\s+(\{[^}]+\})"){ $matches[1] } else { "N/A" }

                # Extract recovery password if present
                $pKey = if($block -match "Password:\s+([\d-]{54,})"){
                            $matches[1].Trim()
                        }
                        elseif($block -match "Key File Name:\s+(.+)"){
                            $matches[1].Trim()
                        }
                        else{ "N/A" }

                $BitLockerResults += [PSCustomObject]@{
                    MountPoint        = $drive
                    VolumeType        = "N/A"
                    VolumeStatus      = "N/A"
                    EncryptionMethod  = $encMethod
                    EncryptionPct     = $encPct
                    ProtectionStatus  = $protection
                    LockStatus        = $lockStatus
                    ProtectorType     = $pType
                    ProtectorId       = $pIdd
                    KeyMaterial       = $pKey
                }
            }
        }
        catch{
            Write-ForensicLog "[!] manage-bde failed on $drive — $($_.Exception.Message)" -Level ERROR -Section "BITLOCKER"
        }
    }
}

# ---------------------------------------------------------
# ALSO CHECK ACTIVE DIRECTORY IF DOMAIN JOINED
# Recovery keys are often escrowed to AD — retrieve them
# Requires AD module and appropriate permissions
# ---------------------------------------------------------
$isDomainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain

if($isDomainJoined){
    Write-ForensicLog "[*] Domain joined — checking AD for escrowed recovery keys" -Level INFO -Section "BITLOCKER"

    if(Get-Command Get-ADObject -ErrorAction SilentlyContinue){
        try{
            $computerName = $env:COMPUTERNAME
            $adComputer   = Get-ADComputer $computerName -ErrorAction Stop

            # BitLocker recovery info is stored in msFVE-RecoveryInformation child objects
            $recoveryObjects = Get-ADObject -Filter * `
                                            -SearchBase $adComputer.DistinguishedName `
                                            -Properties "msFVE-RecoveryPassword","msFVE-RecoveryGuid","whenCreated" `
                                            -ErrorAction SilentlyContinue |
                               Where-Object { $_.ObjectClass -eq "msFVE-RecoveryInformation" }

            foreach($obj in $recoveryObjects){
                $BitLockerResults += [PSCustomObject]@{
                    MountPoint        = "AD Escrowed Key"
                    VolumeType        = "N/A"
                    VolumeStatus      = "Stored in Active Directory"
                    EncryptionMethod  = "N/A"
                    EncryptionPct     = "N/A"
                    ProtectionStatus  = "N/A"
                    LockStatus        = "N/A"
                    ProtectorType     = "Recovery Password (AD Escrow)"
                    ProtectorId       = $obj."msFVE-RecoveryGuid"
                    KeyMaterial       = $obj."msFVE-RecoveryPassword"
                }
            }

            Write-ForensicLog "[*] Found $($recoveryObjects.Count) AD escrowed key(s)" -Level SUCCESS -Section "BITLOCKER"
        }
        catch{
            Write-ForensicLog "[!] Could not retrieve AD escrowed keys: $($_.Exception.Message)" -Level WARN -Section "BITLOCKER"
        }
    }
    else{
        Write-ForensicLog "[!] AD module not available — skipping AD escrow check" -Level WARN -Section "BITLOCKER"
    }
}

# ---------------------------------------------------------
# BUILD HTML
# ---------------------------------------------------------


foreach($r in $BitLockerResults){


    # Wrap key material in monospace and flag if missing
    $keyDisplay = if($r.KeyMaterial -and $r.KeyMaterial -ne "N/A"){
        "<code>$($r.KeyMaterial)</code>"
    } else {
        "<span style='color:#999;'>Not available</span>"
    }

    $BitLockerFragment += "<tr"
    $BitLockerFragment += "<td>$($r.MountPoint)</td>"
    $BitLockerFragment += "<td>$($r.VolumeType)</td>"
    $BitLockerFragment += "<td>$($r.VolumeStatus)</td>"
    $BitLockerFragment += "<td>$($r.EncryptionMethod)</td>"
    $BitLockerFragment += "<td>$($r.EncryptionPct)</td>"
    $BitLockerFragment += "<td>$($r.ProtectionStatus)</td>"
    $BitLockerFragment += "<td>$($r.LockStatus)</td>"
    $BitLockerFragment += "<td>$($r.ProtectorType)</td>"
    $BitLockerFragment += "<td><code>$($r.ProtectorId)</code></td>"
    $BitLockerFragment += "<td>$keyDisplay</td>"
    $BitLockerFragment += "</tr>"
}


#$BitLockerFragment

$recoveryKeys = $BitLockerResults | Where-Object { $_.ProtectorType -match "Recovery Password" }
Write-ForensicLog "[!] $($BitLockerResults.Count) BitLocker protector(s) found across $($BitLockerResults.MountPoint | Sort-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count) volume(s)"
if($recoveryKeys.Count -gt 0){
    Write-ForensicLog "[!] $($recoveryKeys.Count) recovery password(s) extracted — store securely" -Level SUCCESS -Section "BITLOCKER"
} else {
    Write-ForensicLog "[!] No recovery passwords found — if volumes are encrypted, keys may not be extractable via PowerShell" -Level WARN -Section "BITLOCKER"
    Write-ForensicLog "[!] Check the HTML report for details and consider using manage-bde manually if needed" -Level WARN -Section "BITLOCKER"
    $BitLockerFragment += "<tr><td colspan='12' style='text-align:center;color:#27ae60;'>No BitLocker protectors found or no recovery passwords extractable</td></tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "BITLOCKER"

#endregion

Write-ForensicLog ""

#############################################################################################################
#region   SIGMA RULE ENGINE
#############################################################################################################

# ---------------------------------------------------------
# SHIPPED SIGMA RUNTIME
# End-user execution uses the shipped runtime and the
# structured JSON rules folder only.
# ---------------------------------------------------------
$sigmaRulesRoot   = "$PSScriptRoot\Forensicator-Share\rules"
$sigmaRuntimePath = "$PSScriptRoot\Forensicator-Share\SigmaRuntime.ps1"
$sigmaConfig      = $configData.sigma
$sigmaDaysBack    = 30
$sigmaMinLevel    = "medium"
$sigmaEnableSysmon = $true
$sigmaMaxEventsPerSource = 0
$sigmaIncludeSourceIds = @()
$sigmaExcludeSourceIds = @()
$sigmaIncludeLogNames  = @()
$sigmaExcludeLogNames  = @()
$sigmaIncludeCategories = @()
$sigmaExcludeCategories = @()

if($null -ne $sigmaConfig){
    if($null -ne $sigmaConfig.days_back){
        $parsedSigmaDaysBack = 0
        if([int]::TryParse([string]$sigmaConfig.days_back, [ref]$parsedSigmaDaysBack) -and $parsedSigmaDaysBack -gt 0){
            $sigmaDaysBack = $parsedSigmaDaysBack
        }
        else{
            Write-ForensicLog "Invalid sigma.days_back in config.json — using default" -Level WARN -Section "SIGMA" -Detail "Configured value: $($sigmaConfig.days_back) | Default: 30"
        }
    }

    if($null -ne $sigmaConfig.min_level){
        $configuredMinLevel = [string]$sigmaConfig.min_level
        if(@("critical","high","medium","low","informational") -contains $configuredMinLevel){
            $sigmaMinLevel = $configuredMinLevel
        }
        else{
            Write-ForensicLog "Invalid sigma.min_level in config.json — using default" -Level WARN -Section "SIGMA" -Detail "Configured value: $configuredMinLevel | Default: medium"
        }
    }

    if($null -ne $sigmaConfig.enable_sysmon){
        $sigmaEnableSysmon = [bool]$sigmaConfig.enable_sysmon
    }

    if($null -ne $sigmaConfig.max_events_per_source){
        $parsedSigmaMaxEvents = 0
        if([int]::TryParse([string]$sigmaConfig.max_events_per_source, [ref]$parsedSigmaMaxEvents) -and $parsedSigmaMaxEvents -ge 0){
            $sigmaMaxEventsPerSource = $parsedSigmaMaxEvents
        }
        else{
            Write-ForensicLog "Invalid sigma.max_events_per_source in config.json — using unbounded scan" -Level WARN -Section "SIGMA" -Detail "Configured value: $($sigmaConfig.max_events_per_source)"
        }
    }

    $sigmaIncludeSourceIds  = ConvertTo-ConfigStringArray $sigmaConfig.include_source_ids
    $sigmaExcludeSourceIds  = ConvertTo-ConfigStringArray $sigmaConfig.exclude_source_ids
    $sigmaIncludeLogNames   = ConvertTo-ConfigStringArray $sigmaConfig.include_log_names
    $sigmaExcludeLogNames   = ConvertTo-ConfigStringArray $sigmaConfig.exclude_log_names
    $sigmaIncludeCategories = ConvertTo-ConfigStringArray $sigmaConfig.include_categories
    $sigmaExcludeCategories = ConvertTo-ConfigStringArray $sigmaConfig.exclude_categories
}

if(-not $sigmaEnableSysmon){
    $sigmaExcludeLogNames = @(
        $sigmaExcludeLogNames +
        @("Microsoft-Windows-Sysmon/Operational")
    ) | Select-Object -Unique
}

Write-ForensicLog "Initialising Sigma detection engine" -Level INFO -Section "SIGMA"
$sigmaMaxEventsLabel = if($sigmaMaxEventsPerSource -gt 0){ [string]$sigmaMaxEventsPerSource } else { "unbounded" }
Write-ForensicLog "Sigma configuration resolved" -Level INFO -Section "SIGMA" -Detail "DaysBack: $sigmaDaysBack | MinLevel: $sigmaMinLevel | SysmonEnabled: $sigmaEnableSysmon | MaxEventsPerSource: $sigmaMaxEventsLabel"

if(Test-Path $sigmaRuntimePath){
    # Use the shipped runtime and structured rule set instead of the legacy in-file parser above.
    . $sigmaRuntimePath
    $sigmaScanParams = @{
        RulesRoot = $sigmaRulesRoot
        DaysBack  = $sigmaDaysBack
        MinLevel  = $sigmaMinLevel
        MaxEventsPerSource = $sigmaMaxEventsPerSource
    }

    if($sigmaIncludeSourceIds.Count -gt 0){ $sigmaScanParams.IncludeSourceIds = $sigmaIncludeSourceIds }
    if($sigmaExcludeSourceIds.Count -gt 0){ $sigmaScanParams.ExcludeSourceIds = $sigmaExcludeSourceIds }
    if($sigmaIncludeLogNames.Count  -gt 0){ $sigmaScanParams.IncludeLogNames  = $sigmaIncludeLogNames }
    if($sigmaExcludeLogNames.Count  -gt 0){ $sigmaScanParams.ExcludeLogNames  = $sigmaExcludeLogNames }
    if($sigmaIncludeCategories.Count -gt 0){ $sigmaScanParams.IncludeCategories = $sigmaIncludeCategories }
    if($sigmaExcludeCategories.Count -gt 0){ $sigmaScanParams.ExcludeCategories = $sigmaExcludeCategories }

    $sigmaFindings = Invoke-SigmaScan @sigmaScanParams
}
else{
    Write-ForensicLog "Sigma runtime file missing — skipping detection" -Level ERROR -Section "SIGMA" -Detail "Expected runtime at $sigmaRuntimePath"
    $sigmaFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
}

# ---------------------------------------------------------
# SIGMA DATA — serialised as inline JSON for Discover page
# ---------------------------------------------------------
$sigmaJsonData = '[]'
$script:SigmaOverviewRows = ''
$script:SigmaDetectionRows = ''
if($sigmaFindings.Count -gt 0){
    $orderedFindings = $sigmaFindings | Sort-Object {
        switch($_.RuleLevel){
            "critical"{"0"} "high"{"1"} "medium"{"2"} "low"{"3"} default{"4"}
        }
    }

  $toSigmaRow = {
    param($finding)
    $timeCreated = [System.Net.WebUtility]::HtmlEncode([string]($finding.TimeCreated))
    $ruleLevel   = [System.Net.WebUtility]::HtmlEncode([string]($finding.RuleLevel))
    $ruleTitle   = [System.Net.WebUtility]::HtmlEncode([string]($finding.RuleTitle))
    $eventId     = [System.Net.WebUtility]::HtmlEncode([string]($finding.EventId))
    $userName    = [System.Net.WebUtility]::HtmlEncode([string]($finding.User))
    $processName = [System.Net.WebUtility]::HtmlEncode([string]($finding.Process))
    "<tr><td></td><td>$timeCreated</td><td>$ruleLevel</td><td>$ruleTitle</td><td>$eventId</td><td>$userName</td><td>$processName</td></tr>"
  }

  $script:SigmaDetectionRows = (($orderedFindings | ForEach-Object { & $toSigmaRow $_ }) -join "`n")
  $script:SigmaOverviewRows  = (($orderedFindings | Select-Object -First 12 | ForEach-Object { & $toSigmaRow $_ }) -join "`n")

    $sigmaJsonData = ($orderedFindings | ConvertTo-Json -Depth 3 -Compress)
    # Always wrap as array even for single finding
    if($sigmaJsonData -notmatch '^\['){
        $sigmaJsonData = "[$sigmaJsonData]"
    }

    # Export findings for external analysis
    $sigmaFindings | Export-Csv `
        "$PSScriptRoot\$env:COMPUTERNAME\SigmaFindings.csv" `
        -NoTypeInformation -Encoding UTF8
}
# HTML-safe: prevent </script> in command lines from breaking the page
$script:sigmaJsonSafe = $sigmaJsonData -replace '</', '\/'

# ── HASH_DATA ── map $hashMatches into the same schema JS expects
$hashJsonData = if ($hashMatches -and $hashMatches.Count -gt 0) {
    $hashMatches | ForEach-Object {
        [PSCustomObject]@{
            RuleTitle   = "Hash Match: $($_.DetectedFile)"
            RuleLevel   = "high"
            TimeCreated = "$($_.LastModified)"
            User        = "$($_.Owner)"
            Process     = "$($_.DetectedFile)"
            CommandLine = "MD5=$($_.MD5) | SHA256=$($_.SHA256)"
            RuleFile    = "$($_.Extension)"
        }
    } | ConvertTo-Json -Depth 2 -Compress
} else { '[]' }
if ($hashJsonData -notmatch '^\[') { $hashJsonData = "[$hashJsonData]" }
$script:hashJsonSafe = $hashJsonData -replace '</', '\/'

# ── IOC_DATA ── malicious browser URLs collected during history scan
$iocJsonData = if ($script:IocHits -and $script:IocHits.Count -gt 0) {
    $script:IocHits | ForEach-Object {
        [PSCustomObject]@{
            RuleTitle   = "Malicious URL"
            RuleLevel   = "high"
            TimeCreated = "$($_.LastVisit)"
            User        = "$($_.User)"
            Process     = "$($_.Browser)"
            CommandLine = "$($_.URL)"
            RuleFile    = "$($_.Profile)"
        }
    } | ConvertTo-Json -Depth 2 -Compress
} else { '[]' }
if ($iocJsonData -notmatch '^\[') { $iocJsonData = "[$iocJsonData]" }
$script:iocJsonSafe = $iocJsonData -replace '</', '\/'

Write-ForensicLog "Sigma scan complete — $($sigmaFindings.Count) finding(s)" `
                  -Level $(if($sigmaFindings.Count -gt 0){ "FINDING" } else { "SUCCESS" }) `
                  -Section "SIGMA"

#endregion

Write-ForensicLog ""




#######################################################################################
## Tooltip    -  Forensicator Info Panel (FI Panel)                                  ##
#######################################################################################


function Get-ForensicatorDetectionCommandsMap {
  return [ordered]@{

    # Users & Accounts
    'LOCAL_USER_ACCOUNTS' = $Cmd_LocalUserAccounts.Display
    'ACTIVE_LOGON_SESSIONS' = $Cmd_logonsession.Display
    'ADMIN_GROUP_MEMBERS' = $Cmd_Administrators.Display
    'IMPORTANT_USERS_GROUPS' = $Cmd_LocalGroup.Display
    'HISTORICAL_USER_PRESENCE' = $Cmd_UserProfiles.Display

    # System Information
    'OPERATING_SYSTEM_INFORMATION' = $Cmd_OSinfo.Display
    'DRIVES_STORAGE'   = $Cmd_LogicalDrives.Display
    'ENVIRONMENT_VARIABLES' = $Cmd_interestingenv.Display
    'HOTFIXES' = $Cmd_Hotfixes.Display
    'INSTALLED_SOFTWARE' = $Cmd_InstalledApps.Display
    'WINDOWS_DEFENDER_STATUS' = $Cmd_WinDefender.Display

    # Processes
    'PROCESSES' = $Cmd_Processes.Display
    'STARTUP_PROGRAMS' = $Cmd_StartupProgs.Display

    # Network
    'TCP_CONNECTIONS' = $Cmd_NetTCPConnect.Display
    'LISTENING_PORTS'   = $Cmd_ListeningPorts.Display
    'DNS_CACHE' = $Cmd_DnsCache.Display
    'IP_CONFIGURATION' = $Cmd_IPConfiguration.Display
    'NET_IP_ADDRESS' = $Cmd_NetIPAddress.Display
    'NETWORK_CONNECTION_PROFILE' = $Cmd_NetConnectProfile.Display
    'NET_INTERFACES' = $Cmd_NetAdapter.Display
    'NET_NEIGBOUR' = $Cmd_NetNeighbor.Display
    'WIFI_PASSWORDS' = $Cmd_WlanPasswords.Display
    'NETWORK_SHARES' = $Cmd_SMBShares.Display
    'NETWORK_ADAPTERS' = $Cmd_NetworkAdapter.Display
    'FIREWALL_RULES' = $Cmd_FirewallRule.Display
    'OUTBOUND_SMB_SESSIONS' = $Cmd_OutboundSmbSessions.Display
    'ALL_SMB_SESSIONS' = $Cmd_SMBSessions.Display
    'NETWORK_HOPS' = $Cmd_NetHops.Display
    'ADAPTER_HOPS' = $Cmd_AdaptHops.Display
    'IP_HOPS' = $Cmd_IpHops.Display    

    # Services
    'SERVICES' = $Cmd_Services.Display

    # Scheduled Tasks
    'SCHEDULED_TASK' = $Cmd_ScheduledTasks.Display

    # Event Logs
    'GROUP_ENUMERATION' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id @(4798, 4799)'
    'RDP_LOGINS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id @(4624, 4778)'
    'RDP_AUTHS' = 'Get-ForensicWinEvent -LogName ''Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'' -Id 1149'
    'OUTGOING_RDP_CONNECTIONS' = 'Get-ForensicWinEvent -LogName ''Microsoft-Windows-TerminalServices-RDPClient/Operational'' -Id 1102 | Select-Object $properties'
    'CREATED_USERS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4720'
    'PASSWORD_RESETS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4724'
    'ADDED_USERS_TO_GROUPS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id @(4732, 4728)'
    'ENABLED_USERS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4722'
    'DISABLED_USERS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4723'
    'DELETED_USERS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4726'
    'LOCKED_OUT_USERS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4740'
    'CREDENTIAL_MANAGER_BACKUP' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 5376'
    'CREDENTIAL_MANAGER_RESTORE' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 5377'
    'LOGON_EVENTS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4624'
    'FAILED_LOGON_EVENTS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4625'
    'OBJECT_ACCESS_EVENTS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id @(4656, 4663)'
    'PROCESS_EXECUTION_EVENTS' = 'Get-ForensicWinEvent -LogName ''Security'' -ProviderName ''Microsoft-Windows-Security-Auditing'' -Id 4688'

    # Files & USB
    'USB_DEVICES' = $Cmd_USBDevices.Display
    'IMAGE_DEVICES' = $Cmd_Imagedevice.Display
    'UPNP_DEVICES' = $Cmd_UPNPDevices.Display
    'UNKNOWN_DRIVES' = $Cmd_UnknownDrives.Display
    'RECENT_FILES'    = $Cmd_NewFiles.Display
    'LINK_FILES' = $Cmd_LinkFiles.Display
    'EXECUTABLES_IN_UNUSUAL_LOCATIONS' = $Cmd_HiddenExecs2.Display
    'POWERSHELL_COMMAND_HISTORY' = $Cmd_PSHistory.Display
    'BITLOCKER_DRIVES' = $Cmd_BitLocker.Display

    'REGRUN' = 'Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"'
    'REGRUNONCE' = 'Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"'
    'REGRUNONCEEX' = 'Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"'

  }
}

$ForensicatorDetectionCommandsJson = Get-ForensicatorDetectionCommandsMap | ConvertTo-Json -Depth 6

# ---- JAVASCRIPT (MAPPING + RENDERER) ----
$Global:FI_Scripts = @'
<script>

// ── BASE URL ──────────────────────────────────────────────────────────────────
const FI_BASE = "https://raw.githubusercontent.com/Raptormatics/forensicator-docs/main/detections/JSON/";

const ForensicatorDocs = {

  // ── USER ACCOUNTS ────────────────────────────────────────────────────────────
  "LOCAL_USER_ACCOUNTS": {
    "url": FI_BASE + "user-accounts.json",
    "title": "Local User Accounts"
  },
  "ACTIVE_LOGON_SESSIONS": {
    "url": FI_BASE + "user-accounts.json",
    "title": "Active Logon Sessions"
  },
  "ADMIN_GROUP_MEMBERS": {
    "url": FI_BASE + "user-accounts.json",
    "title": "Administrator Group Members"
  },
  "IMPORTANT_USERS_GROUPS": {
    "url": FI_BASE + "user-accounts.json",
    "title": "Important User Groups"
  },
  "HISTORICAL_USER_PRESENCE": {
    "url": FI_BASE + "user-accounts.json",
    "title": "Historical User Presence"
  },


  // ── SYSTEM INFORMATION ───────────────────────────────────────────────────────
  "OPERATING_SYSTEM_INFORMATION": {
    "url": FI_BASE + "system-information.json",
    "title": "Operating System Information"
  },
  "DRIVES_STORAGE": {
    "url": FI_BASE + "system-information.json",
    "title": "Drives & Storage"
  },
  "ENVIRONMENT_VARIABLES": {
    "url": FI_BASE + "system-information.json",
    "title": "Environment Variables"
  },
  "HOTFIXES": {
    "url": FI_BASE + "system-information.json",
    "title": "Installed Hotfixes (Patches)"
  },
  "INSTALLED_SOFTWARE": {
    "url": FI_BASE + "system-information.json",
    "title": "Installed Software"
  },
  "WINDOWS_DEFENDER_STATUS": {
    "url": FI_BASE + "system-information.json",
    "title": "Windows Defender Status"
  },

  // ── SYSTEM PROCESSES ─────────────────────────────────────────────────────────
  "PROCESSES": {
    "url": FI_BASE + "system-processes.json",
    "title": "Processes"
  },
  "STARTUP_PROGRAMS": {
    "url": FI_BASE + "system-processes.json",
    "title": "Startup Programs"
  },


  // ── NETWORK INFORMATION ──────────────────────────────────────────────────────
  "TCP_CONNECTIONS": {
    "url": FI_BASE + "network-information.json",
    "title": "TCP Connections"
  },
    "LISTENING_PORTS": {
    "url": FI_BASE + "network-information.json",
    "title": "Listening Ports"
  },
  "DNS_CACHE": {
    "url": FI_BASE + "network-information.json",
    "title": "DNS Cache"
  },
  "IP_CONFIGURATION": {
    "url": FI_BASE + "network-information.json",
    "title": "IP Configuration"
  },
  "NET_IP_ADDRESS": {
    "url": FI_BASE + "network-information.json",
    "title": "Net IP Address Information"
  },
  "NETWORK_CONNECTION_PROFILE": {
    "url": FI_BASE + "network-information.json",
    "title": "Network Connection Profiles"
  },
  "NET_INTERFACES": {
    "url": FI_BASE + "network-information.json",
    "title": "Network Interfaces"
  },
  "NET_NEIGBOUR": {
    "url": FI_BASE + "network-information.json",
    "title": "Net Neighbour Information"
  },
  "WIFI_PASSWORDS": {
    "url": FI_BASE + "network-information.json",
    "title": "WiFi Passwords"
  },
  "NETWORK_SHARES": {
    "url": FI_BASE + "network-information.json",
    "title": "Network Shares"
  },
  "NETWORK_ADAPTERS": {
    "url": FI_BASE + "network-information.json",
    "title": "Network Adapters"
  },
  "FIREWALL_RULES": {
    "url": FI_BASE + "network-information.json",
    "title": "Firewall Rules"
  },
  "OUTBOUND_SMB_SESSIONS": {
    "url": FI_BASE + "network-information.json",
    "title": "Outbound SMB Sessions"
  },
  "ALL_SMB_SESSIONS": {
    "url": FI_BASE + "network-information.json",
    "title": "All SMB Sessions"
  },
  "NETWORK_HOPS": {
    "url": FI_BASE + "network-information.json",
    "title": "Network Hops"
  },
  "ADAPTER_HOPS": {
    "url": FI_BASE + "network-information.json",
    "title": "Adapter Hops"
  },
  "IP_HOPS": {
    "url": FI_BASE + "network-information.json",
    "title": "IP Hops"
  },
  // ── SERVICES ───────────────────────────────────────────────────────

  "SERVICES": {
    "url": FI_BASE + "services.json",
    "title": "Services"
  },
  // ── SCHEDULED TASKS ───────────────────────────────────────────────────────

  "SCHEDULED_TASKS": {
    "url": FI_BASE + "scheduled-tasks.json",
    "title": "Scheduled Tasks"
  },

  // ── EVENT LOG ANALYSIS ───────────────────────────────────────────────────────
  "GROUP_ENUMERATION": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "User and Group Enumeration (Security Log)"
  },
  "RDP_LOGINS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "RDP Logins (Security Log)"
  },
  "RDP_AUTHS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "RDP Authentication Events (Security Log)"
  },
  "OUTGOING_RDP_CONNECTIONS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Outgoing RDP Connections (Security Log)"
  },
  "CREATED_USERS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Created User Accounts (Security Log)"
  },
  "PASSWORD_RESETS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Password Reset Events (Security Log)"
  },
  "ADDED_USERS_TO_GROUPS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Added Users to Groups (Security Log)"
  },
  "ENABLED_USERS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Enabled User Accounts (Security Log)"
  },
  "DISABLED_USERS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Disabled User Accounts (Security Log)"
  },
  "DELETED_USERS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Deleted User Accounts (Security Log)"
  },
  "LOCKED_OUT_USERS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Locked Out User Accounts (Security Log)"
  },
  "CREDENTIAL_MANAGER_BACKUP": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Credential Manager Backup Events (Security Log)"
  },
  "CREDENTIAL_MANAGER_RESTORE": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Credential Manager Restore Events (Security Log)"
  },
  "LOGON_EVENTS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Logon Events (Security Log)"
  },
  "FAILED_LOGON_EVENTS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Failed Logon Events (Security Log)"
  },
  "OBJECT_ACCESS_EVENTS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Object Access Events (Security Log)"
  },
  "PROCESS_EXECUTION_EVENTS": {
    "url": FI_BASE + "event-log-analysis.json",
    "title": "Process Execution Events (Security Log)"
  },

  // ── FILES & USB ─────────────────────────────────────────────────────────────
  "USB_DEVICES": {
    "url": FI_BASE + "files-usb.json",
    "title": "USB Devices"
  },
  "IMAGE_DEVICES": {
    "url": FI_BASE + "files-usb.json",
    "title": "Image Devices"
  },
  "UPNP_DEVICES": {
    "url": FI_BASE + "files-usb.json",
    "title": "UPnP Devices"
  },
  "UNKNOWN_DRIVES": {
    "url": FI_BASE + "files-usb.json",
    "title": "Unknown Drives"
  },
  "RECENT_FILES": {
    "url": FI_BASE + "files-usb.json",
    "title": "Recent Files (180 days)"
  },
  "LINK_FILES": {
    "url": FI_BASE + "files-usb.json",
    "title": "All Link Files Created in the last 180days"
  },
  "EXECUTABLES_IN_UNUSUAL_LOCATIONS": {
    "url": FI_BASE + "files-usb.json",
    "title": "Executables in Unusual Locations"
  },
  "POWERSHELL_COMMAND_HISTORY": {
    "url": FI_BASE + "files-usb.json",
    "title": "PowerShell Command History"
  },
  "BITLOCKER_DRIVES": {
    "url": FI_BASE + "files-usb.json",
    "title": "BitLocker Drives"
  }


};

// ── FORENSICATOR DOC ALIASES ─────────────────────────────────────────────────
// Maps all input keys (script variable names, event keys, etc.) to
// canonical ForensicatorDocs keys above.
const ForensicatorDocAliases = {

  // User accounts
  "LOCAL_USER_ACCOUNT":                   "LOCAL_USER_ACCOUNTS",
  "ACTIVE_LOGON_SESSIONS":                "ACTIVE_LOGON_SESSIONS",
  "ADMIN_GROUP_MEMBERS":                  "ADMIN_GROUP_MEMBERS",
  "HISTORICAL_USER_PRESENCE":             "HISTORICAL_USER_PRESENCE",
  "IMPORTANT_USERS_GROUPS":               "IMPORTANT_USERS_GROUPS",

  // System information
  "OPERATING_SYSTEM_INFORMATION":         "OPERATING_SYSTEM_INFORMATION",
  "DRIVES_STORAGE":                       "DRIVES_STORAGE",
  "ENVIRONMENT_VARIABLES":                "ENVIRONMENT_VARIABLES",
  "HOTFIXES":                             "HOTFIXES",
  "INSTALLED_SOFTWARE":                   "INSTALLED_SOFTWARE",
  "WINDOWS_DEFENDER_STATUS":              "WINDOWS_DEFENDER_STATUS",

  // System Processes
  "PROCESSES":                            "PROCESSES",
  "STARTUP_PROGRAMS":                     "STARTUP_PROGRAMS",

  // Network
  "TCP_CONNECTIONS":                      "TCP_CONNECTIONS",
  "LISTENING_PORTS":                      "LISTENING_PORTS",
  "DNS_CACHE":                            "DNS_CACHE",
  "IP_CONFIGURATION":                     "IP_CONFIGURATION",
  "NET_IP_ADDRESS":                       "NET_IP_ADDRESS",
  "NETWORK_CONNECTION_PROFILE":           "NETWORK_CONNECTION_PROFILE",
  "NET_INTERFACES":                       "NET_INTERFACES",
  "NET_NEIGBOUR":                         "NET_NEIGBOUR",
  "WIFI_PASSWORDS":                       "WIFI_PASSWORDS",
  "NETWORK_SHARES":                       "NETWORK_SHARES",
  "NETWORK_ADAPTERS":                     "NETWORK_ADAPTERS",
  "FIREWALL_RULES":                       "FIREWALL_RULES",
  "OUTBOUND_SMB_SESSIONS":                "OUTBOUND_SMB_SESSIONS",
  "ALL_SMB_SESSIONS":                     "ALL_SMB_SESSIONS",
  "NETWORK_HOPS":                         "NETWORK_HOPS",
  "ADAPTER_HOPS":                         "ADAPTER_HOPS",
  "IP_HOPS":                              "IP_HOPS",

  // Services
  "SERVICES":                             "SERVICES",

  // Scheduled Tasks
  "SCHEDULED_TASKS":                      "SCHEDULED_TASKS",

  // Event log analysis
  "GROUP_ENUMERATION":                    "GROUP_ENUMERATION",
  "RDP_LOGINS":                           "RDP_LOGINS",
  "RDP_AUTHS":                            "RDP_AUTHS",
  "OUTGOING_RDP_CONNECTIONS":             "OUTGOING_RDP_CONNECTIONS",
  "CREATED_USERS":                        "CREATED_USERS",
  "PASSWORD_RESETS":                      "PASSWORD_RESETS",
  "ADDED_USERS_TO_GROUPS":                "ADDED_USERS_TO_GROUPS",
  "ENABLED_USERS":                        "ENABLED_USERS",
  "DISABLED_USERS":                       "DISABLED_USERS",
  "DELETED_USERS":                        "DELETED_USERS",
  "LOCKED_OUT_USERS":                     "LOCKED_OUT_USERS",
  "CREDENTIAL_MANAGER_BACKUP":            "CREDENTIAL_MANAGER_BACKUP",
  "CREDENTIAL_MANAGER_RESTORE":           "CREDENTIAL_MANAGER_RESTORE",
  "LOGON_EVENTS":                         "LOGON_EVENTS",
  "FAILED_LOGON_EVENTS":                  "FAILED_LOGON_EVENTS",
  "PROCESS_EXECUTION_EVENTS":             "PROCESS_EXECUTION_EVENTS",
  "OBJECT_ACCESS_EVENTS":                 "OBJECT_ACCESS_EVENTS",
  "PROCESS_EXECUTION_EVENTS":             "PROCESS_EXECUTION_EVENTS",


  // Files & USB
  "USB_DEVICES":                          "USB_DEVICES",
  "IMAGE_DEVICES":                        "IMAGE_DEVICES",
  "UPNP_DEVICES":                         "UPNP_DEVICES",
  "UNKNOWN_DRIVES":                       "UNKNOWN_DRIVES",
  "RECENT_FILES":                         "RECENT_FILES",
  "LINK_FILES":                           "LINK_FILES",
  "EXECUTABLES_IN_UNUSUAL_LOCATIONS":     "EXECUTABLES_IN_UNUSUAL_LOCATIONS",
  "POWERSHELL_COMMAND_HISTORY":           "POWERSHELL_COMMAND_HISTORY",
  "BITLOCKER_DRIVES":                     "BITLOCKER_DRIVES",


};

const ForensicatorDetectionCommands = __FI_DETECTION_COMMANDS__;

// Cache (performance boost)
const fiCache = {};

function resolveDocConfig(key) {
  const canonicalKey = ForensicatorDocAliases[key] || key;
  return ForensicatorDocs[canonicalKey] || null;
}

function resolveDetectionCommand(key) {
  const canonicalKey = ForensicatorDocAliases[key] || key;
  return ForensicatorDetectionCommands[key] || ForensicatorDetectionCommands[canonicalKey] || null;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, function (char) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[char];
  });
}

function hasContent(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some(item => hasContent(item));
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function renderMitreItem(item) {
  if (!item || typeof item !== "object") {
    return `<li>${escapeHtml(item)}</li>`;
  }
  const tactic = escapeHtml(item.tactic || "");
  const description = escapeHtml(item.description || "");
  if (tactic && description) {
    return `<li><strong>${tactic}</strong>: ${description}</li>`;
  }
  return `<li>${tactic || description}</li>`;
}

async function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

function setCopyState(button, label) {
  if (!button.dataset.originalLabel) {
    button.dataset.originalLabel = button.textContent.trim() || "Copy";
  }

  button.textContent = label;
  button.classList.add("copied");
  window.clearTimeout(button._copyTimer);
  button._copyTimer = window.setTimeout(() => {
    button.textContent = button.dataset.originalLabel;
    button.classList.remove("copied");
  }, 1600);
}

function normalizeSection(section) {
  const source = section && typeof section === "object" ? section : {};
  const overview = source.overview && typeof source.overview === "object" ? source.overview : {};
  const analysis = source.analysis && typeof source.analysis === "object" ? source.analysis : {};
  const aiAnalysis = source.ai_analysis && typeof source.ai_analysis === "object" ? source.ai_analysis : {};

  return {
    title: source.title || "Detection Details",
    overview: {
      summary: overview.summary ?? null,
      why_it_matters: overview.why_it_matters ?? null
    },
    analysis: {
      detection: analysis.detection ?? null,
      what_to_look_out_for: analysis.what_to_look_out_for ?? null,
      mitre_mapping: analysis.mitre_mapping ?? null
    },
    ai_analysis: {
      forensicator_ai: aiAnalysis.forensicator_ai ?? null
    }
  };
}

function renderTextBlock(title, value) {
  if (!hasContent(value)) {
    return "";
  }
  if (Array.isArray(value)) {
    return renderListBlock(title, value);
  }
  const safeValue = escapeHtml(value).replace(/\r?\n/g, "<br>");
  return `<div class="fi-block">
    <h3>${escapeHtml(title)}</h3>
    <p>${safeValue}</p>
  </div>`;
}

function renderCodeBlock(title, value) {
  if (!hasContent(value)) {
    return "";
  }
  const safeValue = escapeHtml(String(value).replace(/\r\n/g, "\n"));
  return `<div class="fi-block">
    <div class="fi-block-header">
      <h3>${escapeHtml(title)}</h3>
      <button type="button" class="fi-copy-btn">Copy</button>
    </div>
    <pre class="fi-code"><code>${safeValue}</code></pre>
  </div>`;
}

function renderListBlock(title, values) {
  const items = (Array.isArray(values) ? values : [values]).filter(item => hasContent(item));
  if (!items.length) {
    return "";
  }
  return `<div class="fi-block">
    <h3>${escapeHtml(title)}</h3>
    <ul>
      ${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
    </ul>
  </div>`;
}

function renderMitreBlock(title, values) {
  const items = (Array.isArray(values) ? values : [values]).filter(item => hasContent(item));
  if (!items.length) {
    return "";
  }
  return `<div class="fi-block">
    <h3>${escapeHtml(title)}</h3>
    <ul>
      ${items.map(item => renderMitreItem(item)).join("")}
    </ul>
  </div>`;
}

function buildTabs(section, key) {
  const normalized = normalizeSection(section);
  const detectionCommand = resolveDetectionCommand(key);
  if (hasContent(detectionCommand)) {
    normalized.analysis.detection = detectionCommand;
  }
  const tabs = [];

  const overviewHtml =
    renderTextBlock("Summary", normalized.overview.summary) +
    renderTextBlock("Why It Matters", normalized.overview.why_it_matters);

  if (overviewHtml) {
    tabs.push({
      id: "overview",
      label: "Overview",
      html: overviewHtml
    });
  }

  const analysisHtml =
    renderCodeBlock("Detection", normalized.analysis.detection) +
    renderListBlock("What to Look Out For", normalized.analysis.what_to_look_out_for) +
    renderMitreBlock("Mitre Mapping", normalized.analysis.mitre_mapping);

  if (analysisHtml) {
    tabs.push({
      id: "analysis",
      label: "Analysis",
      html: analysisHtml
    });
  }

  const aiHtml = renderTextBlock("Forensicator AI", normalized.ai_analysis.forensicator_ai);

  if (aiHtml) {
    tabs.push({
      id: "ai-analysis",
      label: "AI Analysis",
      html: aiHtml
    });
  }

  return {
    normalized,
    tabs
  };
}

function setActiveTab(tabId) {
  document.querySelectorAll("#fi-panel-tabs .fi-tab").forEach(button => {
    button.classList.toggle("active", button.dataset.tab === tabId);
  });
  document.querySelectorAll("#fi-panel-content .fi-tab-panel").forEach(panel => {
    panel.classList.toggle("active", panel.dataset.tabPanel === tabId);
  });
}

function renderPanelState(title, tabs, fallbackHtml) {
  const tabsContainer = document.getElementById("fi-panel-tabs");
  const content = document.getElementById("fi-panel-content");

  document.getElementById("fi-panel-title").innerText = title;

  if (!tabs.length) {
    tabsContainer.innerHTML = "";
    content.innerHTML = `<div class="fi-message">${fallbackHtml}</div>`;
    return;
  }

  tabsContainer.innerHTML = tabs.map((tab, index) => `
    <button type="button" class="fi-tab${index === 0 ? " active" : ""}" data-tab="${tab.id}">
      ${escapeHtml(tab.label)}
    </button>
  `).join("");

  content.innerHTML = tabs.map((tab, index) => `
    <div class="fi-tab-panel${index === 0 ? " active" : ""}" data-tab-panel="${tab.id}">
      ${tab.html}
    </div>
  `).join("");
}

function showPanelMessage(title, html) {
  const panel = document.getElementById("fi-panel");
  panel.classList.add("open");
  document.getElementById("fi-backdrop").classList.add("open");
  renderPanelState(title, [], html);
}

async function openPanelFromJSON(url, title, key) {
  const panel = document.getElementById("fi-panel");
  panel.classList.add("open");
  document.getElementById("fi-backdrop").classList.add("open");
  renderPanelState(title, [], "Loading...");

  try {
    let data;

    if (fiCache[url]) {
      data = fiCache[url];
    } else {
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      data = await res.json();
      fiCache[url] = data;
    }

    const section = data.find(i => i.title === title);

    if (!section) {
      renderPanelState(title, [], "No documentation found.");
      return;
    }

    const panelState = buildTabs(section, key);
    renderPanelState(panelState.normalized.title, panelState.tabs, "No documentation found.");

  } catch (err) {
    console.error("Failed to load documentation:", err);
    renderPanelState(title, [], "Failed to load documentation.<br>Ensure the JSON source is reachable from this machine.");
  }
}

function closePanel() {
  document.getElementById("fi-panel").classList.remove("open");
  document.getElementById("fi-backdrop").classList.remove("open");
}

// Global click handler (NO HARDCODING IN HTML)
document.addEventListener("click", function(e) {
  if (e.target.id === "fi-backdrop") { closePanel(); return; }

  const copyButton = e.target.closest(".fi-copy-btn");
  if (copyButton) {
    const codeNode = copyButton.closest(".fi-block")?.querySelector(".fi-code code");
    if (!codeNode) {
      return;
    }

    copyTextToClipboard(codeNode.innerText)
      .then(() => setCopyState(copyButton, "Copied"))
      .catch(() => setCopyState(copyButton, "Copy failed"));
    return;
  }

  const tab = e.target.closest(".fi-tab");
  if (tab) {
    setActiveTab(tab.dataset.tab);
    return;
  }

  const el = e.target.closest(".fd-info-trigger");
  if (!el) return;

  const key = el.dataset.detection;
  const config = resolveDocConfig(key);

  if (!config) {
    showPanelMessage("Detection Details", `No documentation mapping configured for <code>${escapeHtml(key)}</code>.`);
    console.warn("No mapping for:", key);
    return;
  }

  openPanelFromJSON(config.url, config.title, key);
});

function initializeForensicatorExportTables() {
  if (!window.jQuery || !jQuery.fn || !jQuery.fn.DataTable) {
    return;
  }

  jQuery("table.data-table-export").each(function () {
    if (jQuery.fn.DataTable.isDataTable(this)) {
      return;
    }

    jQuery(this).DataTable({
      dom: "Bfrtip",
      pageLength: 25,
      responsive: true,
      buttons: [
        { extend: "csvHtml5", titleAttr: "Export CSV" },
        { extend: "pdfHtml5", titleAttr: "Export PDF" },
        { extend: "print", titleAttr: "Print" }
      ]
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeForensicatorExportTables);
} else {
  initializeForensicatorExportTables();
}

// Section accordion toggle — works on all report pages
(function () {
  function initAccordion() {
    document.querySelectorAll('.det-card-head').forEach(function (h) {
      // skip sigma discover topbar (has its own click handling)
      if (h.closest('.discover-wrapper')) return;
      if (h.dataset.accordionInit) return;
      h.dataset.accordionInit = '1';
      h.addEventListener('click', function () {
        var body = h.nextElementSibling;
        if (!body || !body.classList.contains('det-card-body')) return;
        var isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : '';
        h.classList.toggle('collapsed', isOpen);
      });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAccordion);
  } else {
    initAccordion();
  }
}());

// ── FI AUTO-ICON INJECTION ─────────────────────────────────────────────────────
// Maps substrings of .panel-title text to ForensicatorDocs canonical keys.
// Icons are injected automatically — no HTML data-attributes needed.
// Values are canonical ForensicatorDocs keys (or aliases that resolve to them)
const FI_TITLE_MAP = [
  // Users & accounts
  ['Local User Account',         'LOCAL_USER_ACCOUNTS'],
  ['Active Logon Sessions',      'ACTIVE_LOGON_SESSIONS'],
  ['Admin Group Members',        'ADMIN_GROUP_MEMBERS'],
  ['Important Users & Groups',   'IMPORTANT_USERS_GROUPS'],
  ['Historical User Presence',   'HISTORICAL_USER_PRESENCE'],

  // System info
  ['OS Details',                 'OPERATING_SYSTEM_INFORMATION'],
  ['Drives & Storage',           'DRIVES_STORAGE'],
  ['Environment Variables',      'ENVIRONMENT_VARIABLES'],
  ['Hotfix',                     'HOTFIXES'],
  ['Installed Software',         'INSTALLED_SOFTWARE'],
  ['Windows Defender Status',    'WINDOWS_DEFENDER_STATUS'],

  // Processes
  ['Process List',               'PROCESSES'],
  ['Startup Programs',           'STARTUP_PROGRAMS'],

  // Network
  ['TCP Connection',             'TCP_CONNECTIONS'],
  ['Listening Ports',            'LISTENING_PORTS'],
  ['DNS Cache',                  'DNS_CACHE'],
  ['IP Configuration',           'IP_CONFIGURATION'],
  ['Net IP Address',             'NET_IP_ADDRESS'],
  ['Network Connection Profile', 'NETWORK_CONNECTION_PROFILE'],
  ['Network Interface',          'NET_INTERFACES'],
  ['Net Neigbour',               'NET_NEIGBOUR'],
  ['WIFI Passwords',             'WIFI_PASSWORDS'],
  ['Network Share',              'NETWORK_SHARES'],
  ['Network Adapters',           'NETWORK_ADAPTERS'],
  ['Firewall Rules',             'FIREWALL_RULES'],
  ['Outbound SMB Sessions',      'OUTBOUND_SMB_SESSIONS'],
  ['All SMB Sessions',           'ALL_SMB_SESSIONS'],
  ['Network Hops',               'NETWORK_HOPS'],
  ['Adapter Hops',               'ADAPTER_HOPS'],
  ['IP Hops',                    'IP_HOPS'],

  // Services
  ['Service List',               'SERVICES'],

  // Scheduled Tasks
  ['Task List',                  'SCHEDULED_TASKS'],

  // Event log analysis
  ['Group Enumeration',          'GROUP_ENUMERATION'],
  ['RDP Logins',                 'RDP_LOGINS'],
  ['RDP Auths',  'RDP_AUTHS'],
  ['Outgoing RDP Connections',   'OUTGOING_RDP_CONNECTIONS'],
  ['Created Users',              'CREATED_USERS'],
  ['Password Resets',             'PASSWORD_RESETS'],
  ['Added users to Group',        'ADDED_USERS_TO_GROUPS'],
  ['Enabled Users',               'ENABLED_USERS'],
  ['Disabled Users',              'DISABLED_USERS'],
  ['Deleted Users',               'DELETED_USERS'],
  ['Locked Out Users',            'LOCKED_OUT_USERS'],
  ['Credential Manager Backup',   'CREDENTIAL_MANAGER_BACKUP'],
  ['Logon Events',                'LOGON_EVENTS'],
  ['Failed Logon Events',         'FAILED_LOGON_EVENTS'],
  ['Object Access Events',        'OBJECT_ACCESS_EVENTS'],
  ['Process Execution Events',    'PROCESS_EXECUTION_EVENTS'],

  // Devices & files
  ['USB Devices',                 'USB_DEVICES'],
  ['Image Devices',               'IMAGE_DEVICES'],
  ['UPnP Devices',                'UPNP_DEVICES'],
  ['Unknown Drives',              'UNKNOWN_DRIVES'],
  ['Recent Files',                'RECENT_FILES'],
  ['Link Files',                  'LINK_FILES'],
  ['Executables in',             'EXECUTABLES_IN_UNUSUAL_LOCATIONS'],
  ['PowerShell History',         'POWERSHELL_COMMAND_HISTORY'],
  ['BitLocker',                  'BITLOCKER_DRIVES']

];

function injectFiIcons() {
  document.querySelectorAll('.panel-title').forEach(function(el) {
    if (el.querySelector('.fd-info-trigger')) return;
    var text = el.textContent || '';
    var matchedKey = null;
    for (var i = 0; i < FI_TITLE_MAP.length; i++) {
      if (text.toLowerCase().indexOf(FI_TITLE_MAP[i][0].toLowerCase()) !== -1) {
        matchedKey = FI_TITLE_MAP[i][1];
        break;
      }
    }
    if (!matchedKey) return;
    var icon = document.createElement('span');
    icon.className = 'fd-info-trigger';
    icon.dataset.detection = matchedKey;
    icon.title = 'View investigation guidance';
    icon.textContent = 'ⓘ';
    el.appendChild(icon);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectFiIcons);
} else {
  injectFiIcons();
}

</script>
'@

$Global:FI_Scripts = $Global:FI_Scripts.Replace('__FI_DETECTION_COMMANDS__', $ForensicatorDetectionCommandsJson)

# ---- HELPER FUNCTION (ICON) ----
function New-FIIcon {
    param($Key)

    return "<span class='fd-info-trigger' data-detection='$Key' data-tooltip='View investigation guidance'>ⓘ</span>"
}




###########################################################################################################
#region ########################## CREATING AND FORMATTING THE HTML FILES  ################################
###########################################################################################################

Write-ForensicLog "[*] Creating and Formatting the HTML files" -Level INFO -Section "CORE"


$ArtifactRootPath = "$PSScriptRoot\$env:COMPUTERNAME"

function New-ExtrasArtifactRow {
  param(
    [string]$Label,
    [string]$Folder,
    [string[]]$Patterns
  )

  $folderPath = Join-Path $ArtifactRootPath $Folder
  $exists = Test-Path $folderPath

  $browseCell = if ($exists) {
    $folderUri = ([Uri](Get-Item -Path $folderPath).FullName).AbsoluteUri
    "<a class='btn' href='$folderUri' target='_blank' rel='noopener'>Open Folder</a>"
  } else {
    "<span class='dim-cell'>Not collected</span>"
  }

  $allFiles = @()
  $latestFile = $null
  if ($exists) {
    $allFiles = @(Get-ChildItem -Path $folderPath -Recurse -File -ErrorAction SilentlyContinue)
    if ($Patterns -and $Patterns.Count -gt 0) {
      $latestFile = $allFiles |
        Where-Object {
          $name = $_.Name.ToLowerInvariant()
          $matched = $false
          foreach ($pattern in $Patterns) {
            if ($name -like $pattern.ToLowerInvariant()) {
              $matched = $true
              break
            }
          }
          $matched
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    }
  }

  $latestCell = if ($latestFile) {
    $latestUri = ([Uri]$latestFile.FullName).AbsoluteUri
    "<a class='btn' href='$latestUri' target='_blank' rel='noopener'>Open Latest</a>"
  } else {
    "<span class='dim-cell'>N/A</span>"
  }

  $statusCell = if ($exists) { "<span class='ok-cell'>Collected</span>" } else { "<span class='dim-cell'>Missing</span>" }
  $fileCount = if ($exists) { $allFiles.Count } else { 0 }

  return "<tr><td>$Label</td><td class='mono-cell'>$Folder/</td><td>$browseCell $latestCell</td><td>$statusCell</td><td class='mono-cell'>$fileCount</td></tr>"
}

$ExtrasArtifactsFragment = @(
  (New-ExtrasArtifactRow -Label 'RAM Capture'                 -Folder 'RAM'              -Patterns @('*.raw','*.dmp','*.vmem')),
  (New-ExtrasArtifactRow -Label 'Network Capture'             -Folder 'PCAP'             -Patterns @('*.pcap','*.pcapng','*.etl')),
#  (New-ExtrasArtifactRow -Label 'Forensicator Logs' -Folder 'LOGS'             -Patterns @('*.csv','*.json','*.txt')),
  (New-ExtrasArtifactRow -Label 'Hash Matches'                -Folder 'HashMatches'      -Patterns @('*.csv','*.json','*.txt')),
  (New-ExtrasArtifactRow -Label 'Group Policy Report'         -Folder 'GroupPolicy'      -Patterns @('*.html')),
  (New-ExtrasArtifactRow -Label 'EVTX Logs'                   -Folder 'EVTX'             -Patterns @('*.evtx')),
  (New-ExtrasArtifactRow -Label 'IIS Logs'                    -Folder 'IISLogs'          -Patterns @('*.log')),
  (New-ExtrasArtifactRow -Label 'TomCat Logs'                 -Folder 'TomCatLogs'       -Patterns @('*.log')),
  (New-ExtrasArtifactRow -Label 'Log4j Findings'              -Folder 'LOG4J'       -Patterns @('*.txt'))

  
) -join "`n"



function HTMLFiles {

@"



<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Live Forensicator — $Hostname</title>
<style>
/* ═══════════════════════════════════════════════════════════════════════════
   FORENSICATOR REPORT TEMPLATE  —  Elastic / Wazuh Discover Style
   ═══════════════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');

:root {
  /* surfaces */
  --bg:        #07090f;
  --surface:   #0d111a;
  --surface2:  #111827;
  --surface3:  #161e2e;
  --border:    #1e2d42;
  --border2:   #243650;

  /* brand */
  --blue:      #3b82f6;
  --blue-dim:  #1d4ed8;
  --blue-bg:   rgba(59,130,246,.08);

  /* severity */
  --crit:      #ef4444;
  --high:      #f97316;
  --med:       #eab308;
  --low:       #22c55e;
  --info:      #3b82f6;

  /* text */
  --text:      #e2e8f0;
  --text2:     #94a3b8;
  --text3:     #4b6278;

  /* sidebar */
  --sb-w:      220px;
  --topbar-h:  52px;

  --font:      'IBM Plex Sans',  system-ui, sans-serif;
  --mono:      'IBM Plex Mono', monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }

body {
  font-family: var(--font);
  background:  var(--bg);
  color:       var(--text);
  font-size:   13px;
  line-height: 1.5;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

/* ── TOPBAR ────────────────────────────────────────────────────────────────── */
#topbar {
  position: fixed; top:0; left:0; right:0;
  height: var(--topbar-h);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  padding: 0 16px 0 0;
  z-index: 300;
  gap: 0;
}

.topbar-brand {
  width: var(--sb-w);
  flex-shrink: 0;
  display: flex; align-items: center; gap: 10px;
  padding: 0 16px;
  border-right: 1px solid var(--border);
  height: 100%;
  text-decoration: none;
}

.brand-icon {
  width: 28px; height: 28px;
  background: var(--blue);
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; flex-shrink: 0;
}

.brand-text {
  font-size: 13px; font-weight: 700;
  color: var(--text);
  letter-spacing: -.3px;
}

.brand-text span { color: var(--blue); }

.topbar-meta {
  display: flex; align-items: center; gap: 0;
  padding: 0 20px;
  flex: 1;
}

.meta-chip {
  display: flex; align-items: center; gap: 6px;
  padding: 4px 12px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 11px;
  color: var(--text2);
  margin-right: 8px;
  font-family: var(--mono);
}

.meta-chip strong { color: var(--text); }

.topbar-right {
  margin-left: auto;
  display: flex; align-items: center; gap: 8px;
}

.version-pill {
  background: rgba(59,130,246,.15);
  border: 1px solid rgba(59,130,246,.3);
  color: var(--blue);
  font-size: 10px; font-weight: 600;
  padding: 3px 9px; border-radius: 12px;
  letter-spacing: .06em;
}

/* ── SIDEBAR ───────────────────────────────────────────────────────────────── */
#sidebar {
  position: fixed;
  top: var(--topbar-h); left: 0; bottom: 0;
  width: var(--sb-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  z-index: 200;
  padding: 16px 0 40px;
  scrollbar-width: thin;
  scrollbar-color: var(--border2) transparent;
}

.sb-section { margin-bottom: 4px; }

.sb-label {
  font-size: 10px; font-weight: 600;
  letter-spacing: .14em; text-transform: uppercase;
  color: var(--text3);
  padding: 10px 16px 5px;
}

.sb-link {
  display: flex; align-items: center; gap: 9px;
  padding: 7px 16px;
  color: var(--text2);
  cursor: pointer;
  border-left: 2px solid transparent;
  transition: all .12s;
  user-select: none;
  font-size: 13px;
}

.sb-link:hover { color: var(--text); background: rgba(255,255,255,.03); }

.sb-link.active {
  color: var(--blue);
  border-left-color: var(--blue);
  background: var(--blue-bg);
}

.sb-icon { width: 16px; text-align: center; font-style: normal; flex-shrink: 0; }

.sb-badge {
  margin-left: auto;
  background: var(--crit);
  color: #fff;
  font-size: 10px; font-weight: 700;
  padding: 1px 6px; border-radius: 10px;
  display: none;
}

.sb-badge.show { display: inline-block; }

.sb-divider {
  height: 1px; background: var(--border);
  margin: 10px 0;
}

/* ── MAIN LAYOUT ───────────────────────────────────────────────────────────── */
#main {
  margin-left: var(--sb-w);
  margin-top: var(--topbar-h);
  flex: 1;
  min-width: 0;
}

/* ── VIEWS ─────────────────────────────────────────────────────────────────── */
.view { display: none; padding: 24px 28px 60px; }
.view.active { display: block; }

.view-header {
  display: flex; align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 24px;
  gap: 16px;
  flex-wrap: wrap;
}

.view-title {
  font-size: 18px; font-weight: 700;
  color: var(--text);
  letter-spacing: -.3px;
}

.view-sub {
  font-size: 12px; color: var(--text2);
  margin-top: 3px;
}

/* ── STAT CARDS ────────────────────────────────────────────────────────────── */
.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}

.stat-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: border-color .15s, transform .15s;
  position: relative;
  overflow: hidden;
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: var(--accent, var(--blue));
  opacity: .6;
}

.stat-card:hover {
  border-color: var(--accent, var(--blue));
  transform: translateY(-1px);
}

.stat-num {
  font-size: 28px; font-weight: 700;
  color: var(--accent, var(--blue));
  line-height: 1;
  font-family: var(--mono);
}

.stat-label {
  font-size: 11px; color: var(--text2);
  text-transform: uppercase; letter-spacing: .08em;
  margin-top: 5px;
}

.stat-trend {
  font-size: 10px; color: var(--text3);
  margin-top: 3px;
}

/* ── PANEL ─────────────────────────────────────────────────────────────────── */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 20px;
  overflow: hidden;
}

.panel-head {
  display: flex; align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  gap: 12px;
}

.panel-title {
  font-size: 13px; font-weight: 600;
  color: var(--text);
  display: flex; align-items: center; gap: 8px;
}

.panel-count {
  font-family: var(--mono);
  font-size: 11px; color: var(--text2);
  background: var(--surface3);
  border: 1px solid var(--border);
  padding: 2px 8px; border-radius: 4px;
}

.panel-actions { display: flex; gap: 6px; align-items: center; }

/* ── SEARCH BAR ────────────────────────────────────────────────────────────── */
.search-bar {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 16px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}

.search-wrap { flex: 1; position: relative; }

.search-wrap input {
  width: 100%;
  background: var(--surface2);
  border: 1px solid var(--border2);
  color: var(--text);
  font-family: var(--mono);
  font-size: 12px;
  padding: 7px 12px 7px 32px;
  border-radius: 5px;
  outline: none;
  transition: border-color .15s;
}

.search-wrap input:focus { border-color: var(--blue); }
.search-wrap input::placeholder { color: var(--text3); }

.search-ico {
  position: absolute; left: 10px; top: 50%;
  transform: translateY(-50%);
  color: var(--text3); font-size: 12px;
  pointer-events: none;
}

.hits-lbl {
  font-size: 11px; color: var(--text2);
  font-family: var(--mono);
  white-space: nowrap;
  min-width: 55px;
}

/* ── FILTER PILLS ──────────────────────────────────────────────────────────── */
.filter-row {
  display: flex; gap: 6px; flex-wrap: wrap;
  padding: 8px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}

.f-pill {
  display: flex; align-items: center; gap: 5px;
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 11px; font-weight: 600;
  border: 1px solid;
  cursor: pointer;
  transition: all .12s;
  user-select: none;
}

.f-pill:hover { filter: brightness(1.2); }
.f-pill.active { filter: brightness(1.15); }

.f-num { font-family: var(--mono); font-size: 13px; font-weight: 700; }

/* ── SEVERITY BADGES ───────────────────────────────────────────────────────── */
.sev {
  display: inline-block;
  padding: 2px 7px; border-radius: 3px;
  font-size: 10px; font-weight: 700;
  letter-spacing: .05em; text-transform: uppercase;
  white-space: nowrap;
}

/* ── DISCOVER TABLE ────────────────────────────────────────────────────────── */
.disc-wrap { overflow-x: auto; }

table.disc {
  width: 100%; border-collapse: collapse;
  font-size: 12px;
}

.disc thead th {
  background: var(--surface2);
  color: var(--text3);
  font-size: 10px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .06em;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  text-align: left;
}

.disc tbody tr.d-row {
  border-bottom: 1px solid var(--surface2);
  cursor: pointer;
  transition: background .08s;
}

.disc tbody tr.d-row:hover { background: var(--surface2); }

.disc td {
  padding: 8px 12px;
  color: var(--text);
  vertical-align: middle;
}

.d-expand { width: 20px; color: var(--text3); font-size: 10px; text-align: center; }
.d-time   { font-family: var(--mono); font-size: 11px; color: var(--text2); white-space: nowrap; }
.d-rule   { max-width: 280px; font-weight: 500; }
.d-evid   { font-family: var(--mono); font-size: 11px; color: #7dd3fc; text-align: center; width: 55px; }
.d-user   { font-size: 11px; color: #c4b5fd; max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.d-proc   { font-family: var(--mono); font-size: 11px; color: #93c5fd; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.d-flag   { width: 8px; padding: 0; }

/* KV detail panel */
tr.d-detail td { background: var(--surface3) !important; padding: 0 !important; border: none !important; }

.kv-panel { border-top: 1px solid var(--border2); }

.kv-panel table { width: 100%; border-collapse: collapse; }

.kv-panel tr { border-bottom: 1px solid var(--border); }

.kv-panel td { padding: 6px 20px; vertical-align: top; font-size: 12px; }

.kv-k { color: var(--text2); font-family: var(--mono); width: 230px; white-space: nowrap; font-weight: 500; }

.kv-v { color: var(--text); font-family: var(--mono); word-break: break-all; }

.kv-v code {
  background: var(--surface);
  padding: 3px 7px; border-radius: 3px;
  font-size: 11px; display: inline-block;
  border: 1px solid var(--border);
}

/* ── STANDARD TABLE ────────────────────────────────────────────────────────── */
.tbl-wrap { overflow-x: auto; }

table.std {
  width: 100%; border-collapse: collapse;
  font-size: 12px;
}

.std thead th {
  background: var(--surface2);
  color: var(--text3);
  font-size: 10px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .06em;
  padding: 9px 14px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  text-align: left;
}

.std tbody tr { border-bottom: 1px solid var(--surface2); transition: background .08s; }
.std tbody tr:hover { background: var(--surface2); }
.std td { padding: 8px 14px; color: var(--text); vertical-align: top; }

/* Browser history URL column wrap guard */
#view-browser .url-cell {
  white-space: normal;
  word-break: break-word;
  overflow-wrap: anywhere;
  max-width: 560px;
}

/* Process path and command line cell wrapping */
.path-cell, .cmd-cell {
  white-space: normal;
  word-break: break-word;
  overflow-wrap: anywhere;
  max-width: 400px;
}

.cmd-cell { max-width: 500px; }

.mono-cell { font-family: var(--mono); font-size: 11px; color: #93c5fd; }
.flag-cell { color: var(--crit) !important; font-weight: 600; }
.warn-cell { color: var(--high) !important; }
.ok-cell   { color: var(--low)  !important; }
.dim-cell  { color: var(--text2); }

/* ── BAR CHART (pure CSS) ──────────────────────────────────────────────────── */
.bar-chart { padding: 12px 16px 16px; }

.bar-row {
  display: flex; align-items: center;
  gap: 10px; margin-bottom: 9px;
}

.bar-label { width: 160px; font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex-shrink: 0; }

.bar-track {
  flex: 1; height: 16px;
  background: var(--surface2);
  border-radius: 3px; overflow: hidden;
  border: 1px solid var(--border);
}

.bar-fill {
  height: 100%; border-radius: 3px;
  background: var(--blue);
  transition: width .4s ease;
}

.bar-val { width: 40px; text-align: right; font-family: var(--mono); font-size: 11px; color: var(--text2); }

/* ── TIMELINE ──────────────────────────────────────────────────────────────── */
.timeline { padding: 0 16px 16px; display: flex; align-items: flex-end; gap: 3px; height: 80px; }

.tl-bar {
  flex: 1; background: rgba(59,130,246,.3);
  border-radius: 2px 2px 0 0;
  border: 1px solid rgba(59,130,246,.5);
  cursor: pointer;
  transition: background .12s;
  position: relative;
}

.tl-bar:hover { background: rgba(59,130,246,.6); }

.tl-bar::after {
  content: attr(data-label);
  position: absolute; bottom: -16px; left: 50%;
  transform: translateX(-50%);
  font-size: 9px; color: var(--text3);
  white-space: nowrap;
}

/* ── GRID LAYOUTS ──────────────────────────────────────────────────────────── */
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

@media (max-width: 1024px) { .grid-2 { grid-template-columns: 1fr; } }

/* ── EMPTY STATE ───────────────────────────────────────────────────────────── */
.empty {
  text-align: center;
  padding: 48px 20px;
  color: var(--text3);
}

.empty-icon { font-size: 32px; margin-bottom: 10px; }
.empty-msg  { font-size: 13px; }

/* ── BUTTONS / CONTROLS ────────────────────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 12px;
  border-radius: 5px;
  font-family: var(--font);
  font-size: 12px; font-weight: 500;
  border: 1px solid var(--border2);
  background: var(--surface2);
  color: var(--text2);
  cursor: pointer;
  transition: all .12s;
  white-space: nowrap;
}

.btn:hover { border-color: var(--blue); color: var(--text); }
.btn.primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.btn.primary:hover { background: var(--blue-dim); }

/* ── ALERT BANNER ──────────────────────────────────────────────────────────── */
.alert-banner {
  border-left: 3px solid;
  padding: 10px 14px;
  border-radius: 0 5px 5px 0;
  font-size: 12px;
  margin-bottom: 12px;
}

.alert-banner.crit  { background: rgba(239,68,68,.08);  border-color: var(--crit); color: #fca5a5; }
.alert-banner.high  { background: rgba(249,115,22,.08); border-color: var(--high); color: #fdba74; }
.alert-banner.info  { background: rgba(59,130,246,.08); border-color: var(--blue); color: #93c5fd; }

/* ── DETAIL KEY/VALUE LIST ─────────────────────────────────────────────────── */
.kv-list { padding: 12px 0; }

.kv-list-row {
  display: flex; gap: 0;
  border-bottom: 1px solid var(--border);
  padding: 7px 16px;
}

.kv-list-row:last-child { border-bottom: none; }

.kv-list-k {
  width: 200px; flex-shrink: 0;
  color: var(--text2); font-family: var(--mono);
  font-size: 11px; font-weight: 500;
}

.kv-list-v {
  color: var(--text); font-size: 12px;
  word-break: break-all;
}

/* ── SCROLLBAR ─────────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

/* ── NO-PRINT CONTROLS ─────────────────────────────────────────────────────── */
@media print {
  #sidebar, #topbar { display: none; }
  #main { margin: 0; }
  .view { display: block !important; page-break-before: always; }
  .view:first-of-type { page-break-before: avoid; }
}


/* ── PAGINATION BAR ────────────────────────────────────────────────────────── */
.pg-bar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 9px 16px;
  border-top: 1px solid var(--border);
  background: var(--surface2);
  gap: 12px; flex-wrap: wrap;
}

.pg-info {
  font-size: 11px; color: var(--text2);
  font-family: var(--mono);
  white-space: nowrap;
}

.pg-controls { display: flex; align-items: center; gap: 3px; }

.pg-btn {
  background: var(--surface3);
  border: 1px solid var(--border2);
  color: var(--text2);
  font-family: var(--mono);
  font-size: 12px;
  padding: 4px 9px; border-radius: 4px;
  cursor: pointer;
  transition: all .12s;
  min-width: 30px; text-align: center;
  line-height: 1.4;
}

.pg-btn:hover:not([disabled]) { border-color: var(--blue); color: var(--blue); }
.pg-btn.pg-active { background: var(--blue); border-color: var(--blue); color: #fff; }
.pg-btn[disabled] { opacity: .28; cursor: not-allowed; }

.pg-ellipsis { padding: 0 5px; color: var(--text3); font-size: 12px; line-height: 1.8; }

.pg-select {
  background: var(--surface3);
  border: 1px solid var(--border2);
  color: var(--text2);
  font-family: var(--mono);
  font-size: 11px;
  padding: 4px 7px; border-radius: 4px;
  cursor: pointer; outline: none;
  margin-right: 10px;
}

.pg-select:focus { border-color: var(--blue); }


/* ── FORENSICATOR INFO PANEL ─────────────────────────────────────────────────── */
#fi-backdrop {
  position: fixed; inset: 0;
  z-index: 499;
  background: rgba(0,0,0,.4);
  display: none;
}
#fi-backdrop.open { display: block; }

#fi-panel {
  position: fixed;
  top: var(--topbar-h);
  right: -500px;
  bottom: 0;
  width: 480px;
  max-width: calc(100vw - 40px);
  background: var(--surface2);
  border-left: 1px solid var(--border);
  z-index: 500;
  display: flex;
  flex-direction: column;
  transition: right .28s cubic-bezier(.4,0,.2,1);
  overflow: hidden;
}
#fi-panel.open { right: 0; }

#fi-panel-header {
  display: flex; align-items: center;
  justify-content: space-between;
  padding: 13px 16px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0; gap: 10px;
  background: var(--surface3);
}

#fi-panel-title {
  font-size: 12px; font-weight: 700;
  color: var(--text);
  flex: 1; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap;
  letter-spacing: -.1px;
}

#fi-panel-close {
  background: none;
  border: 1px solid var(--border2);
  color: var(--text2);
  cursor: pointer;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 11px;
  flex-shrink: 0;
  transition: border-color .15s, color .15s;
}
#fi-panel-close:hover { border-color: var(--blue); color: var(--blue); }

#fi-panel-tabs {
  display: flex; gap: 0;
  padding: 0 16px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  background: var(--surface2);
}

.fi-tab {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text2);
  cursor: pointer;
  font-family: var(--font);
  font-size: 11px; font-weight: 500;
  padding: 8px 12px 10px;
  transition: color .15s, border-color .15s;
  white-space: nowrap;
}
.fi-tab.active  { color: var(--blue); border-bottom-color: var(--blue); }
.fi-tab:hover:not(.active) { color: var(--text); }

#fi-panel-content {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  scrollbar-width: thin;
  scrollbar-color: var(--border2) transparent;
}
.fi-tab-panel          { display: none; }
.fi-tab-panel.active   { display: block; }

.fi-block              { margin-bottom: 20px; }
.fi-block:last-child   { margin-bottom: 0; }

.fi-block h3 {
  font-size: 10px; font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .1em;
  color: var(--text3);
  margin-bottom: 8px;
  padding-bottom: 5px;
  border-bottom: 1px solid var(--border);
}

.fi-block p {
  font-size: 12px;
  color: var(--text2);
  line-height: 1.7;
}

.fi-block ul {
  padding-left: 14px; margin: 0;
}
.fi-block ul li {
  font-size: 12px;
  color: var(--text2);
  line-height: 1.65;
  margin-bottom: 5px;
}
.fi-block ul li strong { color: var(--text); }

.fi-block-header {
  display: flex; align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.fi-block-header h3 { margin-bottom: 0; border: none; padding: 0; }

.fi-code {
  background: var(--surface3);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 10px 12px;
  font-family: var(--mono);
  font-size: 11px;
  color: #7dd3fc;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.55;
}

.fi-copy-btn {
  background: var(--surface3);
  border: 1px solid var(--border);
  color: var(--text2);
  cursor: pointer;
  font-size: 10px;
  padding: 3px 8px;
  border-radius: 4px;
  white-space: nowrap;
  transition: border-color .15s, color .15s;
}
.fi-copy-btn:hover  { border-color: var(--blue); color: var(--blue); }
.fi-copy-btn.copied { color: var(--low); border-color: var(--low); }

.fi-message {
  font-size: 12px;
  color: var(--text3);
  padding: 24px 0;
  text-align: center;
}

/* ── TRIGGER ICON ───────────────────────────────────────────────────────────── */
.fd-info-trigger {
  display: inline-flex;
  align-items: center; justify-content: center;
  width: 15px; height: 15px;
  margin-left: 7px;
  border-radius: 50%;
  background: rgba(59,130,246,.12);
  border: 1px solid rgba(59,130,246,.22);
  color: var(--blue);
  font-size: 9px;
  cursor: pointer;
  vertical-align: middle;
  flex-shrink: 0;
  transition: background .15s, border-color .15s;
  font-style: normal;
  line-height: 1;
  user-select: none;
}
.fd-info-trigger:hover {
  background: rgba(59,130,246,.28);
  border-color: var(--blue);
}

</style>
</head>
<body>

<!-- ── FORENSICATOR INFO PANEL ─────────────────────────────────────────────── -->
<div id="fi-backdrop"></div>
<div id="fi-panel">
  <div id="fi-panel-header">
    <span id="fi-panel-title">Detection Details</span>
    <button id="fi-panel-close" onclick="closePanel()">✕ Close</button>
  </div>
  <div id="fi-panel-tabs"></div>
  <div id="fi-panel-content"></div>
</div>

<script id="forensicator-data">
/* ── INLINE DATA — injected by PowerShell at report generation time ── */
var SIGMA_DATA      = $($script:sigmaJsonSafe);
var HASH_DATA       = $($script:hashJsonSafe);
var IOC_DATA        = $($script:iocJsonSafe);
var EVTLOG_COUNTS   = $($script:evtlogCountsJson);
var TOP_EVENT_IDS   = $($script:topEventIdsJson);
</script>
<script defer src="forensicator-runtime.js"></script>

<!-- ═══════════════════════════════════════════════════════════════════════════
     TOPBAR
═══════════════════════════════════════════════════════════════════════════ -->
<header id="topbar">
  <div class="topbar-brand">
    <div class="brand-icon">🔍</div>
    <div class="brand-text">Live<span>Forensicator</span></div>
  </div>

  <div class="topbar-meta">
    <div class="meta-chip">🖥 <strong id="tb-host">$Hostname</strong></div>
    <div class="meta-chip">👤 <strong id="tb-operator">$Handler</strong></div>
    <div class="meta-chip">📋 <strong id="tb-caseno">$CASENO</strong></div>
    <div class="meta-chip">📁 <strong id="tb-case-title">$CaseTitle</strong></div>
    <div class="meta-chip">🌐 <strong id="tb-loc">$Loc</strong></div>
    <div class="meta-chip">💻 <strong id="tb-device">$Device</strong></div>
    <div class="meta-chip">🕐 <strong id="tb-date">$ForensicatorStartTime </strong></div>
  </div>

  <div class="topbar-right">
    <span class="version-pill">$MyVersion</span>
    <button class="btn" onclick="window.print()">🖨 Print</button>
  </div>
</header>

<!-- ═══════════════════════════════════════════════════════════════════════════
     SIDEBAR
═══════════════════════════════════════════════════════════════════════════ -->
<nav id="sidebar">

  <div class="sb-section">
    <div class="sb-label">Navigation</div>
    <div class="sb-link active" onclick="nav('overview')">
      <i class="sb-icon">📊</i> Overview
    </div>
  </div>

  <div class="sb-divider"></div>

  <div class="sb-section">
    <div class="sb-label">Host Data</div>
    <div class="sb-link" onclick="nav('users')">
      <i class="sb-icon">👤</i> Users &amp; Accounts
    </div>
    <div class="sb-link" onclick="nav('system')">
      <i class="sb-icon">🖥</i> System Info
    </div>
    <div class="sb-link" onclick="nav('processes')">
      <i class="sb-icon">⚙</i> Processes
    </div>
    <div class="sb-link" onclick="nav('network')">
      <i class="sb-icon">🌐</i> Network
    </div>
    <div class="sb-link" onclick="nav('services')">
      <i class="sb-icon">⚡</i> Services
    </div>
    <div class="sb-link" onclick="nav('scheduled')">
      <i class="sb-icon">📅</i> Scheduled Tasks
    </div>
  </div>

  <div class="sb-divider"></div>

  <div class="sb-section">
    <div class="sb-label">Analysis</div>
    <div class="sb-link" onclick="nav('eventlog')">
      <i class="sb-icon">📋</i> Event Log
    </div>
    <div class="sb-link" onclick="nav('browser')">
      <i class="sb-icon">🌍</i> Browser History
    </div>
    <div class="sb-link" onclick="nav('files')">
      <i class="sb-icon">📁</i> Files &amp; USB
    </div>
  </div>

  <div class="sb-divider"></div>

  <div class="sb-section">
    <div class="sb-label">Extras</div>
    <div class="sb-link" onclick="nav('extras')">
      <i class="sb-icon">🧰</i> Extras
    </div>
  </div>

  <div class="sb-divider"></div>

  <div class="sb-section">
    <div class="sb-label">Detections</div>
    <div class="sb-link" onclick="nav('detections')">
      <i class="sb-icon">🚨</i> Sigma / Rules
      <span class="sb-badge" id="badge-detections">0</span>
    </div>
    <div class="sb-link" onclick="nav('hashes')">
      <i class="sb-icon">🦠</i> Hash Matches
      <span class="sb-badge" id="badge-hashes">0</span>
    </div>
    <div class="sb-link" onclick="nav('ioc')">
      <i class="sb-icon">🔗</i> IOC Matches
      <span class="sb-badge" id="badge-ioc">0</span>
    </div>
  </div>

</nav>

<script>
window.nav = window.nav || function(id) {
  document.querySelectorAll('.view').forEach(function(v){ v.classList.remove('active'); });
  document.querySelectorAll('.sb-link').forEach(function(l){ l.classList.remove('active'); });
  var view = document.getElementById('view-' + id);
  if (view) view.classList.add('active');
  document.querySelectorAll('.sb-link').forEach(function(link){
    var handler = link.getAttribute('onclick') || '';
    if (handler.indexOf("'" + id + "'") !== -1) link.classList.add('active');
  });
  window.scrollTo(0,0);
};
</script>

<!-- ═══════════════════════════════════════════════════════════════════════════
     MAIN CONTENT AREA
═══════════════════════════════════════════════════════════════════════════ -->
<main id="main">

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: OVERVIEW
══════════════════════════════════════════════════════════════════════════ -->
<div class="view active" id="view-overview">

  <div class="view-header">
    <div>
      <div class="view-title">Investigation Overview</div>
      <div class="view-sub">Summary of all collected artifacts and detections</div>
    </div>
    <button class="btn primary" onclick="nav('detections')">🚨 View Detections</button>
  </div>

  <!-- Alert banners — shown only when findings exist -->
  <div id="overview-alerts"></div>

  <!-- Summary stat cards -->
  <div class="stat-row" id="overview-stats">
    <div class="js-rendered"></div>
  </div>

  <!-- Detection severity breakdown -->
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🚨 Detection Breakdown</div>
      </div>
      <div class="bar-chart" id="sev-bars"></div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">📋 Host Summary</div>
      </div>
      <div class="kv-list" id="host-summary">$OSinfoFragment</div>
    </div>
  </div>

  <!-- Top Sigma hits -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🔥 Top Detections</div>
      <button class="btn" onclick="nav('detections')">View all →</button>
    </div>
    <div class="disc-wrap">
      <table class="disc" id="overview-top-hits">
        <thead>
          <tr>
            <th></th><th>Time</th><th>Severity</th>
            <th>Rule</th><th>Evt</th><th>User</th><th>Process</th>
          </tr>
        </thead>
        <tbody id="overview-hits-body">$script:SigmaOverviewRows</tbody>
      </table>
    </div>
  </div>

</div><!-- /overview -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: USERS & ACCOUNTS
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-users">

  <div class="view-header">
    <div>
      <div class="view-title">Users &amp; Accounts </div>
      <div class="view-sub">Local accounts, logon sessions, admin group members</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">👤 Local User Accounts <span class="panel-count" id="users-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, status, description..." oninput="filterTable('users-tbody', this.value, [0,1,3,6,7,8])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Username</th><th>Enabled</th><th>Last Logon</th>
            <th>Password Last Set</th><th>Password Expires</th><th>Description</th><th>Password Changeable Date</th><th>User May Change Password</th>
          </tr>
        </thead>
        <tbody id="users-tbody">$LocalUserAccountsFragment</tbody>
      </table>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🛡 Admin Group Members <span class="panel-count" id="admins-count">0</span></div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Domain/Username</th><th>Type</th><th>Principal Source</th></tr></thead>
          <tbody id="admins-tbody">$adminFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🔑 Active Logon Sessions <span class="panel-count" id="sessions-count">0</span></div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Username</th><th>Domain</th><th>LogonType</th><th>LogonTime</th><th>IdleTime</th></tr></thead>
          <tbody id="sessions-tbody">$logonsessionFragment</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🛡 Important Users & Groups <span class="panel-count" id="groups-count">0</span></div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Group</th><th>Username</th><th>Domain</th><th>Type</th></tr></thead>
          <tbody id="groups-tbody">$localFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🔑 Historical User Presence <span class="panel-count" id="history-count">0</span></div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Username</th><th>SID</th><th>Last Use Time</th></tr></thead>
          <tbody id="history-tbody">$profileFragment</tbody>
        </table>
      </div>
    </div>
  </div>




</div><!-- /users -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: SYSTEM INFO
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-system">

  <div class="view-header">
    <div>
      <div class="view-title">System Information</div>
      <div class="view-sub">OS details, installed software, startup items</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">🖥 OS Details</div></div>
      <div class="kv-list" id="os-details">$OSinfoFragment</div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">💾 Drives &amp; Storage</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Drive</th><th>Label</th><th>Size (GB)</th><th>Free (GB)</th><th>%Free</th></tr></thead>
          <tbody id="drives-tbody">$LogicalDrivesFragment</tbody>
        </table>
      </div>
    </div>
  </div>


  <div class="grid-2">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🛡 Environment Variables </div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Variable</th><th>Value</th></tr></thead>
          <tbody id="env-tbody">$envFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">🔑 Hotfix </div>
      </div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Computer Name</th><th>Caption</th><th>Description</th><th>Hotfix ID</th><th>Installed By</th><th>Installed On</th></tr></thead>
          <tbody id="hotfix-tbody">$HotfixesFragment</tbody>
        </table>
      </div>
    </div>
  </div>



  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📦 Installed Software <span class="panel-count" id="software-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter software..." oninput="filterTable('software-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Install Date</th><th>Install Location</th><th>Uninstall String</th></tr></thead>
        <tbody id="software-tbody">$InstalledAppsFragment</tbody>
      </table>
    </div>
  </div>


  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📦 Windows Defender Status <span class="panel-count" id="defender-count">0</span></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>AM Product Version</th><th>AM Running Mode</th><th>AM Service Enabled</th><th>Antispyware Enabled</th><th>Antispyware Signature LastUpdated</th><th>Antivirus Enabled</th><th>Antivirus Signature LastUpdated</th><th>Behavior Monitor Enabled</th><th>Defender Signatures OutOfDate</th><th>Device Control Policies LastUpdated</th><th>Device Control State</th><th>NIS Signature LastUpdated</th><th>Quick Scan EndTime</th><th>RealTime Protection Enabled</th></tr></thead>
        <tbody id="defender-tbody">$WinDefenderFragment</tbody>
      </table>
    </div>
  </div>


</div><!-- /system -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: PROCESSES
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-processes">

  <div class="view-header">
    <div>
      <div class="view-title">Running Processes</div>
      <div class="view-sub">All processes active at time of collection — flagged items lack a path or match known-bad names</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">⚙ Process List <span class="panel-count" id="procs-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by PID, name, path, company..." oninput="filterTable('procs-tbody', this.value, [0,1,2,3,4,5,6,7,8,9,10])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Name</th><th>PID</th><th>Parent PID</th><th>User</th><th>Path</th>
            <th>Command Line</th><th>CPU (s)</th><th>RAM (MB)</th><th>Start Time</th><th>Signature</th>
          </tr>
        </thead>
        <tbody id="procs-tbody">$ProcessFragmentrows</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">⚙ Startup Programs <span class="panel-count" id="startup-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, command, location, user..." oninput="filterTable('startup-tbody', this.value, [0,1,2,3])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Name</th><th>Command</th><th>Location</th><th>User</th>
          </tr>
        </thead>
        <tbody id="startup-tbody">$StartupProgsFragment</tbody>
      </table>
    </div>
  </div>






</div><!-- /processes -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: NETWORK
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-network">

  <div class="view-header">
    <div>
      <div class="view-title">Network</div>
      <div class="view-sub">Active connections, listening ports, DNS cache, ARP table</div>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat-card" style="--accent:var(--blue)" onclick="document.getElementById('net-connections').scrollIntoView()">
      <div class="stat-num" id="net-established-count">0</div>
      <div class="stat-label">Established</div>
    </div>
    <div class="stat-card" style="--accent:var(--low)" onclick="document.getElementById('net-listen').scrollIntoView()">
      <div class="stat-num" id="net-listen-count">0</div>
      <div class="stat-label">Listening</div>
    </div>
    <div class="stat-card" style="--accent:var(--crit)" id="net-external-card">
      <div class="stat-num" id="net-external-count">0</div>
      <div class="stat-label">External Connections</div>
    </div>
  </div>

  <div class="panel" id="net-connections">
    <div class="panel-head">
      <div class="panel-title">🌐 TCP Connections <span class="panel-count" id="net-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by IP, port, process, state..." oninput="filterTable('net-tbody', this.value, [0,1,2,3,4,5,6])"/>
      </div>
      <div class="hits-lbl" id="net-hits"></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Local Addr</th><th>L.Port</th><th>Remote Addr</th>
            <th>R.Port</th><th>State</th><th>PID</th><th>Process</th>
          </tr>
        </thead>
        <tbody id="net-tbody">$NetTCPConnectFragment</tbody>
      </table>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel" id="net-ipconfig">
      <div class="panel-head"><div class="panel-title">👂 Listening Ports</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Local Port</th><th>Protocol</th><th>PID</th><th>Process</th></tr></thead>
          <tbody id="listen-tbody">$NetListenFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><div class="panel-title">🗃 DNS Cache (Top 50)</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Entry</th><th>Name</th><th>Status</th><th>TTL</th><th>Data</th></tr></thead>
          <tbody id="dns-tbody">$DNSCacheFragment</tbody>
        </table>
      </div>
    </div>
  </div>


  <div class="grid-2">
    <div class="panel" id="net-connection-profile">
      <div class="panel-head"><div class="panel-title">👂 IP Configuration</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Description</th><th>MAC Address</th><th>DNS Domain</th><th>DNS HostName</th><th>DHCP Enabled</th><th>Service Name</th></tr></thead>
          <tbody id="ipconfig-tbody">$IPConfigurationFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><div class="panel-title">🗃 Net IP Address</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Name</th><th>Interface Alias</th><th>Network Category</th><th>IPv4</th><th>IPv6</th></tr></thead>
          <tbody id="net-ip-tbody">$NetIPAddressFragment</tbody>
        </table>
      </div>
    </div>
  </div>


    <div class="grid-2">
    <div class="panel" id="net-neighbor">
      <div class="panel-head"><div class="panel-title">👂 Net Connection Profiles</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Name</th><th>Interface Alias</th><th>Network Category</th><th>IPv4 Connectivity</th><th>IPv6 Connectivity</th></tr></thead>
          <tbody id="net-profile-tbody">$NetConnectProfileFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><div class="panel-title">🗃 Net Interfaces</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Name</th><th>Interface Description</th><th>Status</th><th>MAC Address</th><th>Link Speed</th></tr></thead>
          <tbody id="net-adapter-tbody">$NetAdapterFragment</tbody>
        </table>
      </div>
    </div>
  </div>



    <div class="grid-2">
    <div class="panel" id="net-listen">
      <div class="panel-head"><div class="panel-title">👂 Net Neigbour</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Interface Alias</th><th>IP Address</th><th>Link Layer Address</th></tr></thead>
          <tbody id="neighbor-tbody">$NetNeighborFragment</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><div class="panel-title">🗃 WIFI Passwords</div></div>
      <div class="tbl-wrap">
        <table class="std">
          <thead><tr><th>Profile Name</th><th>Password</th></tr></thead>
          <tbody id="wlan-tbody">$WlanPasswordsFragment</tbody>
        </table>
      </div>
    </div>
  </div>






  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Network Shares</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Description</th><th>Path</th><th>Volume</th></tr></thead>
        <tbody id="shares-tbody">$SMBSharesFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Network Adapters</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Adapter Type</th><th>Product Name</th><th>Description</th><th>MAC</th><th>Availability</th><th>Status</th><th>Enabled</th><th>Physical Adapter</th></tr></thead>
        <tbody id="network-adapter-tbody">$NetworkAdapterFragment</tbody>
      </table>
    </div>
  </div>


   <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Firewall Rules</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Name</th><th>Display Name</th><th>Description</th><th>Direction</th><th>Action</th><th>Edge Traversal Policy</th><th>Owner</th><th>Enforcement Status</th></tr></thead>
        <tbody id="firewall-tbody">$FirewallRuleFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Outbound SMB Sessions</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Local Address</th><th>Local Port</th><th>Remote Address</th><th>Remote Port</th><th>State</th><th>Applied Settings</th><th>Owning Process</th></tr></thead>
        <tbody id="outbound-smb-tbody">$outboundSmbSessionsFragment</tbody>
      </table>
    </div>
  </div>


  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 All SMB Sessions</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Session ID</th><th>Client Computer Name</th><th>Client Username</th><th>NumOpens</th></tr></thead>
        <tbody id="smb-sessions-tbody">$SMBSessionsFragment</tbody>
      </table>
    </div>
  </div>


  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Network Hops</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>If Index</th><th>Destination Prefix</th><th>Next Hop</th><th>Route Metric</th><th>Interface Metric</th><th>Interface Alias</th></tr></thead>
        <tbody id="net-hops-tbody">$NetHopsFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 Adapter Hops</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Name</th><th>Interface Description</th><th>If Index</th><th>Status</th><th>MAC Address</th><th>Link Speed</th></tr></thead>
        <tbody id="adapter-hops-tbody">$AdaptHopsFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head"><div class="panel-title">📡 IP Hops</div></div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>If Index</th><th>Destination Prefix</th><th>Next Hop</th><th>Route Metric</th><th>Interface Metric</th><th>Interface Alias</th></tr></thead>
        <tbody id="ip-hops-tbody">$IpHopsFragment</tbody>
      </table>
    </div>
  </div>



</div><!-- /network -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: SERVICES
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-services">

  <div class="view-header">
    <div>
      <div class="view-title">Services</div>
      <div class="view-sub">All installed services with state and startup type</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">⚡ Service List <span class="panel-count" id="svc-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, state, startup type, path..." oninput="filterTable('svc-tbody', this.value, [0,1,2,3,4,5,6,7])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Name</th><th>Display Name</th><th>State</th>
            <th>Startup</th><th>Start Name</th><th>Command</th><th>Path</th><th>Description</th>
          </tr>
        </thead>
        <tbody id="svc-tbody">$ServicesFragment</tbody>
      </table>
    </div>
  </div>


</div><!-- /services -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: SCHEDULED TASKS
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-scheduled">

  <div class="view-header">
    <div>
      <div class="view-title">Scheduled Tasks</div>
      <div class="view-sub">Tasks registered on this host — non-Microsoft tasks highlighted</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📅 Task List <span class="panel-count" id="tasks-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter tasks..." oninput="filterTable('tasks-tbody', this.value, [0,1,2,3,4,5,6,7])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr>
            <th>Task Name</th><th>Task Path</th><th>State</th><th>Principle</th><th>Actions</th><th>Last Run</th>
            <th>Next Run</th><th>Last Result</th>
          </tr>
        </thead>
        <tbody id="tasks-tbody">$ScheduledTasksFragment</tbody>
      </table>
    </div>
  </div>





</div><!-- /scheduled -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: EVENT LOG
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-eventlog">

  <div class="view-header">
    <div>
      <div class="view-title">Event Log Analysis</div>
      <div class="view-sub">Logon events, account changes, process creation, object access</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">📊 Events by Category</div></div>
      <div class="bar-chart" id="evtlog-category-bars"></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">📊 Top Event IDs</div></div>
      <div class="bar-chart" id="evtlog-evid-bars"></div>
    </div>
  </div>

  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Group Enumeration <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Performed On</th>
            <th>Performed By</th><th>Logon Type</th><th>PID</th><th>Performed</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$GroupMembershipFragment</tbody>
      </table>
    </div>
  </div>



  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 RDP Logins <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Event ID</th><th>Type</th>
            <th>Time</th><th>Logon User</th><th>Logon User Domain</th><th>Logon IP</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$RDPLoginsFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 RDP Auths <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time Created</th>
            <th>User</th><th>Domain</th><th>Client</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$RDPAuthsFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Outgoing RDP Connections <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Local User</th>
            <th>Target Host</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$OutRDPFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Created Users <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Created User</th>
            <th>Actioned By</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$CreatedUsersFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Password Resets <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Target User</th>
            <th>Actioned By</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$PassResetFragment</tbody>
      </table>
    </div>
  </div>

  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Added users to Group <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Added By</th><th>Group</th><th>Target User</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$AddedUsersFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Enabled Users <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Enabled By</th>
            <th>Enabled User</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$EnabledUsersFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Disabled Users <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Disabled By</th>
            <th>Disabled User</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$DisabledUsersFragment</tbody>
      </table>
    </div>
  </div>

  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Deleted Users <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Deleted By</th>
            <th>Deleted User</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$DeletedUsersFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Locked Out Users <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Locked Out User</th>
            <th>System</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$LockOutFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Credential Manager Backup <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Actioned By</th>
            <th>Logon ID</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$CredManBackupFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Credential Manager Restore <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Restored Account</th>
            <th>Credential Manager Restore Account</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$CredManRestoreFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Logon Events <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>User</th>
            <th>Logon Type</th><th>Source Network Address</th><th>Status</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$logonEventsFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Failed Logon Events <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>User</th>
            <th>Logon Type</th><th>Source Network Address</th><th>Status</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$logonEventsFailedFragment</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Object Access Events <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>Event ID</th>
            <th>User</th><th>Domain</th><th>Object Name</th><th>Object Type</th><th>Access Label</th><th>Process</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$ObjectHtmlTable1</tbody>
      </table>
    </div>
  </div>


  <!-- Discover-style event table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📋 Process Execution Events <span class="panel-count" id="evtlog-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="evtlog-search"
               placeholder="Search by event ID, user, process, message..."
               oninput="renderEventLog(this.value)"/>
      </div>
      <div class="hits-lbl" id="evtlog-hits"></div>
    </div>
    <div class="filter-row" id="evtlog-filters"></div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th>Time</th><th>User</th>
            <th>Domain</th><th>Process Name</th><th>Process ID</th><th>Parent Name</th><th>Parent ID</th><th>Command Line</th>
          </tr>
        </thead>
        <tbody id="evtlog-tbody">$ObjectHtmlTable2</tbody>
      </table>
    </div>
  </div>



</div><!-- /eventlog -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: BROWSER HISTORY
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-browser">

  <div class="view-header">
    <div>
      <div class="view-title">Browser History</div>
      <div class="view-sub">Chrome, Firefox, Edge, IE history — IOC matches flagged in red</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🌍 Visited URLs <span class="panel-count" id="browser-count">0</span></div>
      <div class="panel-actions">
        <button class="btn" onclick="filterBrowser('ioc')">🔴 Show IOC Only</button>
        <button class="btn" onclick="filterBrowser('all')">Show All</button>
      </div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Search URL, title, browser..." oninput="filterTable('browser-tbody', this.value, [0,1,2,3])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead>
          <tr><th>User</th><th>Browser</th><th>Profile</th><th>URL</th><th>Last Visit</th><th>IOC</th></tr>
        </thead>
        <tbody id="browser-tbody">$($script:BrowserFragmentRows)</tbody>
      </table>
    </div>
  </div>

</div><!-- /browser -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: FILES & USB
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-files">

  <div class="view-header">
    <div>
      <div class="view-title">Files &amp; USB Devices</div>
      <div class="view-sub">Recently created files, executables in suspicious paths, USB history</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🔌 USB Devices <span class="panel-count" id="usb-count">0</span></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Friendly Name</th><th>Driver</th><th>MFG</th><th>Device Description</th></tr></thead>
        <tbody id="usb-tbody">$USBDevicesFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🔌 Image Devices <span class="panel-count" id="image-count">0</span></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Caption</th><th>Manufacturer</th><th>Status</th><th>Present</th></tr></thead>
        <tbody id="image-tbody">$ImagedeviceFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🔌 UPNP Devices <span class="panel-count" id="upnp-count">0</span></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Status</th><th>Class</th><th>Friendly Name</th><th>Instance ID</th></tr></thead>
        <tbody id="upnp-tbody">$UPNPDevicesFragment</tbody>
      </table>
    </div>
  </div>

    <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🔌 Unknown Drives <span class="panel-count" id="unknown-drives-count">0</span></div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Friendly Name</th><th>Manufacturer</th><th>Serial Number</th><th>Last Write Time</th></tr></thead>
        <tbody id="unknown-drives-tbody">$UnknownDrivesFragment</tbody>
      </table>
    </div>
  </div>




  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Recent Files (180 days) <span class="panel-count" id="files-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, extension..." oninput="filterTable('files-tbody', this.value, [0,1,2])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Extension</th><th>Path</th><th>Modified</th><th>Size (KB)</th></tr></thead>
        <tbody id="files-tbody">$NewFiles</tbody>
      </table>
    </div>
  </div>


  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Link Files <span class="panel-count" id="links-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('links-tbody', this.value, [0,1,2,3,4])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Target</th><th>Arguments</th><th>Last Access</th><th>Created</th></tr></thead>
        <tbody id="links-tbody">$LinkFilesFragment</tbody>
      </table>
    </div>
  </div>


  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Executables in Downloads <span class="panel-count" id="downloads-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('downloads-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Full Name</th><th>Creation Time</th><th>Last Access Time</th><th>Last Write Time</th><th>Attributes</th></tr></thead>
        <tbody id="downloads-tbody">$DownloadsFragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Executables in User Temp Folders <span class="panel-count" id="hidden-1-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('hidden-1-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Full Name</th><th>Creation Time</th><th>Last Access Time</th><th>Last Write Time</th><th>Attributes</th></tr></thead>
        <tbody id="hidden-1-tbody">$HiddenExecs1Fragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Executables in System Temp Folders <span class="panel-count" id="hidden-2-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('hidden-2-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Full Name</th><th>Creation Time</th><th>Last Access Time</th><th>Last Write Time</th><th>Attributes</th></tr></thead>
        <tbody id="hidden-2-tbody">$HiddenExecs2Fragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Executables in Perflogs <span class="panel-count" id="hidden-3-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('hidden-3-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Full Name</th><th>Creation Time</th><th>Last Access Time</th><th>Last Write Time</th><th>Attributes</th></tr></thead>
        <tbody id="hidden-3-tbody">$HiddenExecs3Fragment</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 Executables in User Document Folder <span class="panel-count" id="hidden-4-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by name, path, created..." oninput="filterTable('hidden-4-tbody', this.value, [0,1,2,3,4,5])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>File Name</th><th>Full Name</th><th>Creation Time</th><th>Last Access Time</th><th>Last Write Time</th><th>Attributes</th></tr></thead>
        <tbody id="hidden-4-tbody">$HiddenExecs4Fragment</tbody>
      </table>
    </div>
  </div>

    <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 PowerShell History <span class="panel-count" id="ps-history-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by user, command..." oninput="filterTable('ps-history-tbody', this.value, [0,1])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>User</th><th>Command</th></tr></thead>
        <tbody id="ps-history-tbody">$PSHistoryFragment</tbody>
      </table>
    </div>
  </div>


    <div class="panel">
    <div class="panel-head">
      <div class="panel-title">📄 BitLocker Key <span class="panel-count" id="bitlocker-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by mount point, status, protector, key..." oninput="filterTable('bitlocker-tbody', this.value, [0,1,2,3,4,5,6,7,8,9])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Mount Point</th><th>Volume Type</th><th>Volume Status</th><th>Encryption Method</th><th>Encryption PCT</th><th>Protection Status</th><th>Lock Status</th><th>Protector Type</th><th>Protector ID</th><th>Key</th></tr></thead>
        <tbody id="bitlocker-tbody">$BitLockerFragment</tbody>
      </table>
    </div>
  </div>



</div><!-- /files -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: EXTRAS
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-extras">

  <div class="view-header">
    <div>
      <div class="view-title">Extras</div>
      <div class="view-sub">Browsable artifact folders (RAM, PCAP, browser exports, logs)</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">🧰 Artifact Browser <span class="panel-count" id="extras-count">0</span></div>
    </div>
    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" placeholder="Filter by artifact, folder, status..." oninput="filterTable('extras-tbody', this.value, [0,1,3,4])"/>
      </div>
    </div>
    <div class="tbl-wrap">
      <table class="std">
        <thead><tr><th>Artifact</th><th>Folder</th><th>Browse</th><th>Status</th><th>Files</th></tr></thead>
        <tbody id="extras-tbody">$ExtrasArtifactsFragment</tbody>
      </table>
    </div>
  </div>

</div><!-- /extras -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: DETECTIONS  (Sigma / Rules — Discover style)
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-detections">

  <div class="view-header">
    <div>
      <div class="view-title">🚨 Sigma / Rule Detections</div>
      <div class="view-sub">Events matched against detection rules and config.json bad-actor lists</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">
        <span style="background:#1d4ed8;width:22px;height:22px;border-radius:4px;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:#fff;margin-right:4px">Σ</span>
        Detection Engine — Live Forensicator
      </div>
    </div>

    <!-- Severity filter pills -->
    <div class="filter-row" id="det-filter-row"></div>

    <div class="search-bar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input type="text" id="det-search"
               placeholder="Search rule, user, process, command, tags..."
               oninput="renderDetections()"/>
      </div>
      <div class="hits-lbl" id="det-hits"></div>
    </div>

    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th></th><th>Time</th><th>Rule Level</th><th>Rule Title</th>
            <th>Event ID</th><th>Username</th><th>Process Name</th>
          </tr>
        </thead>
        <tbody id="det-tbody">$script:SigmaDetectionRows</tbody>
      </table>
    </div>
  </div>

</div><!-- /detections -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: HASH MATCHES
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-hashes">

  <div class="view-header">
    <div>
      <div class="view-title">🦠 Malicious Hash Matches</div>
      <div class="view-sub">Executables whose SHA256 hash matched abuse.ch or config hash lists</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">Hash Match Results <span class="panel-count" id="hash-count">0</span></div>
    </div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th></th><th>Detected File</th><th>Extension</th><th>File Size (KB)</th>
            <th>MD5</th><th>SHA256</th><th>MD5 Matched</th><th>SHA256 Matched</th><th>Last Modified</th><th>Creation Time</th><th>Owner</th>
          </tr>
        </thead>
        <tbody id="hash-tbody">$HashMatchFragment</tbody>
      </table>
    </div>
  </div>

</div><!-- /hashes -->

<!-- ╔══════════════════════════════════════════════════════════════════════════
     ║  VIEW: IOC MATCHES
══════════════════════════════════════════════════════════════════════════ -->
<div class="view" id="view-ioc">

  <div class="view-header">
    <div>
      <div class="view-title">🔗 IOC Matches</div>
      <div class="view-sub">URLs from browser history and web logs matched against IOC feed</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">IOC URL Results <span class="panel-count" id="ioc-count">0</span></div>
    </div>
    <div class="disc-wrap">
      <table class="disc">
        <thead>
          <tr>
            <th></th><th>Time</th><th>Severity</th><th>URL</th>
            <th>Browser</th><th>IOC Source</th><th>User</th>
          </tr>
        </thead>
        <tbody id="ioc-tbody"></tbody>
      </table>
    </div>
  </div>

</div><!-- /ioc -->

</main><!-- /main -->

<template id="forensicator-inline-runtime-disabled">

/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE — all rendering logic below
═══════════════════════════════════════════════════════════════════════════ */

// severity config
var SEV = {
  critical:      { label:'CRITICAL', bg:'#ef4444', fg:'#fff' },
  high:          { label:'HIGH',     bg:'#f97316', fg:'#fff' },
  medium:        { label:'MEDIUM',   bg:'#eab308', fg:'#111' },
  low:           { label:'LOW',      bg:'#22c55e', fg:'#111' },
  informational: { label:'INFO',     bg:'#3b82f6', fg:'#fff' }
};

function sevCfg(lv) {
  return SEV[(lv||'').toLowerCase()] || { label:(lv||'INFO').toUpperCase(), bg:'#555', fg:'#fff' };
}

function esc(s) {
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sevBadge(lv) {
  var c = sevCfg(lv);
  return '<span class="sev" style="background:'+c.bg+';color:'+c.fg+'">'+esc(c.label)+'</span>';
}

/* ── NAV ────────────────────────────────────────────────────────────────────── */
function nav(id) {
  document.querySelectorAll('.view').forEach(function(v){ v.classList.remove('active'); });
  document.querySelectorAll('.sb-link').forEach(function(l){ l.classList.remove('active'); });
  var v = document.getElementById('view-'+id);
  if (v) v.classList.add('active');
  document.querySelectorAll('.sb-link').forEach(function(l){
    if (l.getAttribute('onclick') && l.getAttribute('onclick').includes("'"+id+"'")) l.classList.add('active');
  });
  window.scrollTo(0,0);
}

/* ── TABLE FILTER ───────────────────────────────────────────────────────────── */
/* ══════════════════════════════════════════════════════════════════════════════
   PAGINATION ENGINE
   Usage:  initPagination(tbodyId, filterColIndexes, pageSize)
   All existing  oninput="filterTable('xxx-tbody', ...)"  calls work unchanged —
   filterTable checks the registry and delegates automatically.
══════════════════════════════════════════════════════════════════════════════ */
var _paginators = {};

function PaginatedTable(tbodyId, filterCols, pageSize) {
  this.id        = tbodyId;
  this.cols      = filterCols || [];
  this.pageSize  = pageSize   || 25;
  this.page      = 1;
  this.query     = '';
  this.allRows   = [];
  this.filtered  = [];
  this.footerId  = tbodyId + '-pgbar';

  this._readRows();
  this._ensureBar();
  this.render();
}

PaginatedTable.prototype._readRows = function () {
  var tbody = document.getElementById(this.id);
  this.allRows = [];
  if (!tbody) return;

  var rows = Array.from(tbody.children).filter(function (node) {
    return node.tagName && node.tagName.toLowerCase() === 'tr';
  });
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.classList.contains('d-detail')) continue;
    if (isPlaceholderRow(row)) continue;

    var item = { row: row, detail: null };
    if (row.classList.contains('d-row') && rows[i + 1] && rows[i + 1].classList.contains('d-detail')) {
      item.detail = rows[i + 1];
      i++;
    }
    this.allRows.push(item);
  }
};

PaginatedTable.prototype._ensureBar = function () {
  if (document.getElementById(this.footerId)) return;
  var tbody = document.getElementById(this.id);
  if (!tbody) return;
  var wrap  = tbody.closest('.tbl-wrap') || tbody.closest('.disc-wrap');
  var panel = tbody.closest('.panel');
  var bar   = document.createElement('div');
  bar.id        = this.footerId;
  bar.className = 'pg-bar';
  if (wrap) {
    /* insert bar after the wrap div, stays inside the panel */
    wrap.parentNode.insertBefore(bar, wrap.nextSibling);
  } else if (panel) {
    /* no tbl-wrap / disc-wrap — append to panel */
    panel.appendChild(bar);
  }
  /* else: no suitable container — skip gracefully (no crash) */
};

PaginatedTable.prototype.filter = function (q) {
  this.query = q;
  this.page  = 1;
  this.render();
};

PaginatedTable.prototype.goPage = function (p) {
  this.page = p;
  this.render();
  var tbody = document.getElementById(this.id);
  if (tbody) {
    var panel = tbody.closest('.panel');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
};

PaginatedTable.prototype.setPageSize = function (n) {
  this.pageSize = n;
  this.page     = 1;
  this.render();
};

PaginatedTable.prototype.reload = function () {
  this._readRows();
  this.page = 1;
  this.render();
};

PaginatedTable.prototype.render = function () {
  var q    = this.query.toLowerCase();
  var cols = this.cols;

  this.filtered = this.allRows.filter(function (item) {
    if (!q) return true;
    var tds = item.row.querySelectorAll('td');
    return cols.map(function (i) {
      return tds[i] ? tds[i].innerText : '';
    }).join(' ').toLowerCase().indexOf(q) !== -1;
  });

  var total = this.filtered.length;
  var pages = Math.max(1, Math.ceil(total / this.pageSize));
  if (this.page > pages) this.page = pages;

  var start = (this.page - 1) * this.pageSize;
  var end   = start + this.pageSize;

  this.allRows.forEach(function (item) {
    item.row.style.display = 'none';
    if (item.detail) item.detail.style.display = 'none';
  });
  this.filtered.forEach(function (item, i) {
    var isVisible = i >= start && i < end;
    item.row.style.display = isVisible ? '' : 'none';
    if (item.detail) {
      item.detail.style.display = isVisible && item.detail.dataset.expanded === 'true' ? 'table-row' : 'none';
    }
  });

  this._renderBar(total, pages, start, end);
  syncLiveBadge(this.id, total);
};

PaginatedTable.prototype._renderBar = function (total, pages, start, end) {
  var bar = document.getElementById(this.footerId);
  if (!bar) return;
  if (total === 0) { bar.innerHTML = ''; return; }

  var self = this;
  var html = '<div class="pg-info">Showing '
    + (start + 1) + '–' + Math.min(end, total)
    + ' of ' + total + ' rows</div>';

  html += '<div class="pg-controls">';
  html += '<select class="pg-select" onchange="_paginators[\'' + this.id + '\'].setPageSize(+this.value);this.blur()">';
  [25, 50, 100, 250].forEach(function (n) {
    html += '<option value="' + n + '"' + (n === self.pageSize ? ' selected' : '') + '>' + n + ' / page</option>';
  });
  html += '</select>';

  html += '<button class="pg-btn" ' + (this.page <= 1 ? 'disabled' : '')
        + ' onclick="_paginators[\'' + this.id + '\'].goPage(' + (this.page - 1) + ')">‹</button>';

  this._pageRange(pages).forEach(function (p) {
    if (p === '…') {
      html += '<span class="pg-ellipsis">…</span>';
    } else {
      html += '<button class="pg-btn' + (p === self.page ? ' pg-active' : '') + '"'
            + ' onclick="_paginators[\'' + self.id + '\'].goPage(' + p + ')">' + p + '</button>';
    }
  });

  html += '<button class="pg-btn" ' + (this.page >= pages ? 'disabled' : '')
        + ' onclick="_paginators[\'' + this.id + '\'].goPage(' + (this.page + 1) + ')">›</button>';

  html += '</div>';
  bar.innerHTML = html;
};

PaginatedTable.prototype._pageRange = function (pages) {
  if (pages <= 7) {
    var r = [];
    for (var i = 1; i <= pages; i++) r.push(i);
    return r;
  }
  var p   = this.page;
  var out = [1];
  if (p > 3)          out.push('…');
  for (var i = Math.max(2, p - 1); i <= Math.min(pages - 1, p + 1); i++) out.push(i);
  if (p < pages - 2)  out.push('…');
  out.push(pages);
  return out;
};

function initPagination(tbodyId, filterCols, pageSize) {
  try {
    _paginators[tbodyId] = new PaginatedTable(tbodyId, filterCols, pageSize || 25);
  } catch(e) { console.error('[Forensicator] initPagination failed:', tbodyId, e); }
}

/* ── TABLE FILTER — routes through paginator if registered ───────────────── */
function filterTable(tbodyId, q, cols) {
  if (_paginators[tbodyId]) {
    _paginators[tbodyId].filter(q);
    return;
  }
  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  var count = 0;
  tbody.querySelectorAll('tr').forEach(function (r) {
    var tds  = r.querySelectorAll('td');
    var text = cols.map(function (i) { return tds[i] ? tds[i].innerText : ''; })
                   .join(' ').toLowerCase();
    var show = !q || text.indexOf(q.toLowerCase()) !== -1;
    r.style.display = show ? '' : 'none';
    if (show) count++;
  });
  syncLiveBadge(tbodyId, count);
  return count;
}

function getLinkedCountId(tbodyId) {
  if (!tbodyId || tbodyId.slice(-6) !== '-tbody') return null;
  return tbodyId.slice(0, -6) + '-count';
}

function setCountBadge(countId, countValue) {
  var badge = document.getElementById(countId);
  if (badge) badge.textContent = countValue;
}

function isPlaceholderRow(row) {
  if (!row) return true;
  if (row.classList.contains('d-detail')) return true;
  var cells = row.querySelectorAll('td');
  if (!cells.length) return true;
  if (cells.length === 1 && cells[0].hasAttribute('colspan')) return true;
  var txt = (row.textContent || '').trim().toLowerCase();
  return !txt || txt === 'no data' || txt === 'no data available' || txt.indexOf('no matches found') !== -1 || txt.indexOf('hash lookup skipped') !== -1 || txt.indexOf('not collected') === 0;
}

function refreshPagination(tbodyId) {
  if (_paginators[tbodyId]) {
    _paginators[tbodyId].reload();
    return;
  }
  var countId = getLinkedCountId(tbodyId);
  if (countId) syncCount(tbodyId, countId);
}

function syncLiveBadge(tbodyId, countValue) {
  var countId = getLinkedCountId(tbodyId);
  if (countId) setCountBadge(countId, countValue);
  if (tbodyId === 'net-tbody' || tbodyId === 'listen-tbody') {
    syncNetworkCards(true);
  }
}

function getDataRows(tbody) {
  if (!tbody) return [];
  return Array.from(tbody.querySelectorAll('tr')).filter(function (row) {
    return !isPlaceholderRow(row) && !row.classList.contains('d-detail');
  });
}

function getVisibleDataRows(tbody) {
  return getDataRows(tbody).filter(function (row) {
    return row.style.display !== 'none';
  });
}


/* ── AUTO-COUNT ── reads any tbody and updates its panel-count badge ── */
function syncCount(tbodyId, countId) {
  var tbody = document.getElementById(tbodyId);
  var badge = document.getElementById(countId);
  if (!tbody || !badge) return;
  badge.textContent = getDataRows(tbody).length;
}

function isExternalIp(ip) {
  var value = String(ip || '').trim().toLowerCase();
  if (!value || value === '*' || value === '::' || value === '0.0.0.0') return false;
  if (value === '::1' || value.indexOf('127.') === 0) return false;
  if (value.indexOf('10.') === 0 || value.indexOf('192.168.') === 0 || value.indexOf('169.254.') === 0) return false;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(value)) return false;
  if (value.indexOf('fe80:') === 0 || value.indexOf('fc') === 0 || value.indexOf('fd') === 0) return false;
  if (value === 'localhost') return false;
  return true;
}

function syncNetworkCards(visibleOnly) {
  var picker = visibleOnly ? getVisibleDataRows : getDataRows;
  var netRows = picker(document.getElementById('net-tbody'));
  var listenRows = picker(document.getElementById('listen-tbody'));

  var established = netRows.filter(function (row) {
    var cells = row.querySelectorAll('td');
    return cells[4] && String(cells[4].textContent || '').trim().toLowerCase() === 'established';
  }).length;

  var external = netRows.filter(function (row) {
    var cells = row.querySelectorAll('td');
    return cells[2] && isExternalIp(cells[2].textContent);
  }).length;

  var establishedEl = document.getElementById('net-established-count');
  var listenEl = document.getElementById('net-listen-count');
  var externalEl = document.getElementById('net-external-count');

  if (establishedEl) establishedEl.textContent = established;
  if (listenEl) listenEl.textContent = listenRows.length;
  if (externalEl) externalEl.textContent = external;
}

function normalizeEventLogPanels() {
  var panels = Array.from(document.querySelectorAll('#view-eventlog .panel')).filter(function (panel) {
    return !!panel.querySelector('tbody[id="evtlog-tbody"]');
  });

  panels.forEach(function (panel, idx) {
    var prefix = 'evtlog-' + (idx + 1);
    var tbody = panel.querySelector('tbody[id="evtlog-tbody"]');
    var count = panel.querySelector('span[id="evtlog-count"]');
    var search = panel.querySelector('input[id="evtlog-search"]');
    var hits = panel.querySelector('div[id="evtlog-hits"]');
    var filters = panel.querySelector('div[id="evtlog-filters"]');

    if (!tbody) return;

    tbody.id = prefix + '-tbody';

    if (count) count.id = prefix + '-count';
    if (hits) hits.id = prefix + '-hits';
    if (filters) {
      filters.id = prefix + '-filters';
      filters.innerHTML = '';
    }

    if (search) {
      search.id = prefix + '-search';
      search.setAttribute('oninput', "filterTable('" + tbody.id + "', this.value, [0,1,2,3,4,5,6,7,8])");
    }

    initPagination(tbody.id, [0,1,2,3,4,5,6,7,8], 25);
    if (count) syncCount(tbody.id, count.id);
  });
}


/* ── DETECT RENDER ──────────────────────────────────────────────────────────── */
var detActive = 'all';

function buildDetFilters(data) {
  var cnt = { all: data.length, critical:0, high:0, medium:0, low:0, informational:0 };
  data.forEach(function(d){ var lv=(d.RuleLevel||'informational').toLowerCase(); if(cnt[lv]!==undefined) cnt[lv]++; });
  var pills = [
    ['all','All',cnt.all,'#3b82f6','rgba(59,130,246,.15)'],
    ['critical','Critical',cnt.critical,'#ef4444','rgba(239,68,68,.15)'],
    ['high','High',cnt.high,'#f97316','rgba(249,115,22,.15)'],
    ['medium','Medium',cnt.medium,'#eab308','rgba(234,179,8,.15)'],
    ['low','Low',cnt.low,'#22c55e','rgba(34,197,94,.15)'],
    ['informational','Info',cnt.informational,'#3b82f6','rgba(59,130,246,.15)']
  ];
  return pills.map(function(p){
    var isA = detActive===p[0];
    return '<div class="f-pill" style="border-color:'+p[3]+';background:'+(isA?p[4]:'transparent')+';color:'+p[3]+'" onclick="setDetLevel(\''+p[0]+'\')">'
      +'<span class="f-num">'+p[2]+'</span> '+p[1]+'</div>';
  }).join('');
}

function setDetLevel(lv) {
  detActive = lv;
  renderDetections();
}

function renderDiscoverTable(data, tbodyId, searchId, hitsId, filterRowId, allData) {
  var q = searchId ? (document.getElementById(searchId)||{value:''}).value.toLowerCase() : '';
  var filtered = (allData||data).filter(function(d){
    if (detActive!=='all' && (d.RuleLevel||'informational').toLowerCase()!==detActive) return false;
    if (!q) return true;
    return [d.RuleTitle,d.User,d.Process,d.CommandLine,d.RuleTags,String(d.EventId||'')]
      .join(' ').toLowerCase().indexOf(q)!==-1;
  });

  if (filterRowId) {
    var fr = document.getElementById(filterRowId);
    if (fr) fr.innerHTML = buildDetFilters(allData||data);
  }

  if (hitsId) {
    var h = document.getElementById(hitsId);
    if (h) h.textContent = filtered.length+' hit'+(filtered.length!==1?'s':'');
  }

  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-icon">'
      +((allData||data).length===0?'✔':'🔍')+'</div><div class="empty-msg">'
      +((allData||data).length===0?'No findings on this host.':'No results match the current filter.')
      +'</div></div></td></tr>';
    return;
  }

  var rows = [];
  filtered.forEach(function(d,i){
    var uid = tbodyId+'-'+i;
    var c = sevCfg(d.RuleLevel);
    var procFull = String(d.Process||'N/A');
    var procSh = procFull.length>52 ? '&hellip;'+esc(procFull.slice(-52)) : esc(procFull);
    rows.push(
      '<tr class="d-row" style="border-left:3px solid '+c.bg+'" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(d.TimeCreated)+'</td>'
      +'<td>'+sevBadge(d.RuleLevel)+'</td>'
      +'<td class="d-rule"><strong>'+esc(d.RuleTitle)+'</strong></td>'
      +'<td class="d-evid">'+esc(String(d.EventId||''))+'</td>'
      +'<td class="d-user">'+esc(d.User||'N/A')+'</td>'
      +'<td class="d-proc" title="'+esc(procFull)+'">'+procSh+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('rule.title',d.RuleTitle)+kv('rule.level',d.RuleLevel)
      +kv('rule.tags',d.RuleTags)+kv('rule.file',d.RuleFile)
      +kv('event.id',d.EventId)+kv('event.log_name',d.LogName)
      +kv('@timestamp',d.TimeCreated)+kv('user.name',d.User)
      +kv('process.executable',d.Process)+kvCode('process.command_line',d.CommandLine)
      +'</table></div></td></tr>'
    );
  });
  tbody.innerHTML = rows.join('');
}

function kv(k,v){ return '<tr><td class="kv-k">'+esc(k)+'</td><td class="kv-v">'+esc(String(v==null?'N/A':v))+'</td></tr>'; }
function kvCode(k,v){ return '<tr><td class="kv-k">'+esc(k)+'</td><td class="kv-v"><code>'+esc(String(v==null?'N/A':v))+'</code></td></tr>'; }

window.toggleDRow = function(uid) {
  var det = document.getElementById('det-'+uid);
  var ico = document.getElementById('ico-'+uid);
  if (!det) return;
  var open = det.style.display==='none'||!det.style.display;
  det.dataset.expanded = open ? 'true' : 'false';
  det.style.display = open ? 'table-row' : 'none';
  ico.innerHTML = open ? '▼' : '▶';
};

function renderDetections() {
  renderDiscoverTable(SIGMA_DATA, 'det-tbody', 'det-search', 'det-hits', 'det-filter-row', SIGMA_DATA);
  refreshPagination('det-tbody');
}

/* ── EVENT LOG RENDER ───────────────────────────────────────────────────────── */
var evtLogActive = 'all';

function renderEventLog(q) {
  var source = (typeof SAMPLE_EVTLOG_DATA !== 'undefined' && Array.isArray(SAMPLE_EVTLOG_DATA)) ? SAMPLE_EVTLOG_DATA : null;
  if (!source) {
    var existingRows = document.querySelectorAll('#evtlog-tbody tr.d-row').length;
    var hitsEl = document.getElementById('evtlog-hits');
    var countEl = document.getElementById('evtlog-count');
    if (hitsEl) hitsEl.textContent = existingRows + ' events';
    if (countEl) countEl.textContent = existingRows;
    return;
  }

  var filtered = source.filter(function(e){
    if (evtLogActive!=='all' && e.Category!==evtLogActive) return false;
    if (!q) return true;
    return [String(e.EventId),e.User,e.Category,e.Message].join(' ').toLowerCase().indexOf(q.toLowerCase())!==-1;
  });

  document.getElementById('evtlog-hits').textContent = filtered.length+' events';
  document.getElementById('evtlog-count').textContent = filtered.length;

  // Build category filter
  var cats = {};
  source.forEach(function(e){ cats[e.Category]=(cats[e.Category]||0)+1; });
  var catColors = { 'Logon':'#3b82f6','Process Creation':'#f97316','Account Management':'#ef4444','Scheduled Task':'#eab308','Object Access':'#a855f7' };
  var pills = '<div class="f-pill '+(evtLogActive==='all'?'active':'')+'" style="border-color:#3b82f6;color:#3b82f6" onclick="setEvtCat(\'all\')"><span class="f-num">'+source.length+'</span> All</div>';
  Object.keys(cats).forEach(function(c){
    var col = catColors[c]||'#94a3b8';
    pills += '<div class="f-pill '+(evtLogActive===c?'active':'')+'" style="border-color:'+col+';color:'+col+'" onclick="setEvtCat(\''+c+'\')">'
      +'<span class="f-num">'+cats[c]+'</span> '+c+'</div>';
  });
  document.getElementById('evtlog-filters').innerHTML = pills;

  var rows = [];
  filtered.forEach(function(e,i){
    var uid = 'evtlog-'+i;
    rows.push(
      '<tr class="d-row" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(e.Time)+'</td>'
      +'<td class="d-evid">'+esc(String(e.EventId))+'</td>'
      +'<td><span style="font-size:11px;color:#94a3b8">'+esc(e.Category)+'</span></td>'
      +'<td class="d-user">'+esc(e.User)+'</td>'
      +'<td class="d-proc">'+esc(e.Computer)+'</td>'
      +'<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#94a3b8">'+esc(e.Message)+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('event.id',e.EventId)+kv('event.category',e.Category)
      +kv('@timestamp',e.Time)+kv('user.name',e.User)
      +kv('host.name',e.Computer)+kvCode('message',e.Message)
      +'</table></div></td></tr>'
    );
  });
  document.getElementById('evtlog-tbody').innerHTML = rows.join('');
  refreshPagination('evtlog-tbody');

  // Category bars
  buildBars('evtlog-category-bars', cats, catColors);
  // Event ID bars
  var evids = {};
  source.forEach(function(e){ var k='EID '+e.EventId; evids[k]=(evids[k]||0)+1; });
  buildBars('evtlog-evid-bars', evids, {});
}

window.setEvtCat = function(c){ evtLogActive=c; renderEventLog(''); };

/* ── BAR CHART BUILDER ──────────────────────────────────────────────────────── */
function buildBars(containerId, data, colors) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var entries = Object.entries(data).sort(function(a,b){ return b[1]-a[1]; }).slice(0,8);
  var max = entries.reduce(function(m,e){ return Math.max(m,e[1]); }, 1);
  var defaultColors = ['#3b82f6','#f97316','#ef4444','#eab308','#22c55e','#a855f7','#ec4899','#14b8a6'];
  el.innerHTML = entries.map(function(e,i){
    var pct = Math.round(e[1]/max*100);
    var col = colors[e[0]] || defaultColors[i%defaultColors.length];
    return '<div class="bar-row">'
      +'<div class="bar-label" title="'+esc(e[0])+'">'+esc(e[0])+'</div>'
      +'<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+col+'"></div></div>'
      +'<div class="bar-val">'+e[1]+'</div>'
      +'</div>';
  }).join('');
}

/* ── BROWSER FILTER ─────────────────────────────────────────────────────────── */
window.filterBrowser = function(mode) {
  var tbody = document.getElementById('browser-tbody');
  var rows = document.querySelectorAll('#browser-tbody tr');
  rows.forEach(function(r){
    if (mode==='ioc') {
      r.style.display = r.querySelector('.flag-cell') ? '' : 'none';
    } else {
      r.style.display = '';
    }
  });
  syncLiveBadge('browser-tbody', getVisibleDataRows(tbody).length);
};

/* ── OVERVIEW BUILD ─────────────────────────────────────────────────────────── */
function buildOverview() {
  var totalDet = SIGMA_DATA.length + HASH_DATA.length + IOC_DATA.length;
  var crits = SIGMA_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='critical'; }).length
            + HASH_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='critical'; }).length;

  // Stat row
  var stats = [
    { n: totalDet,          lbl:'Total Detections', accent:'var(--crit)',  view:'detections' },
    { n: crits,             lbl:'Critical',         accent:'var(--crit)',  view:'detections' },
    { n: SIGMA_DATA.length, lbl:'Sigma Hits',       accent:'var(--high)',  view:'detections' },
    { n: HASH_DATA.length,  lbl:'Hash Matches',     accent:'var(--med)',   view:'hashes'     },
    { n: IOC_DATA.length,   lbl:'IOC Matches',      accent:'var(--blue)',  view:'ioc'        }
  ];
  document.getElementById('overview-stats').innerHTML = stats.map(function(s){
    return '<div class="stat-card" style="--accent:'+s.accent+'" onclick="nav(\''+s.view+'\')">'
      +'<div class="stat-num">'+s.n+'</div>'
      +'<div class="stat-label">'+s.lbl+'</div>'
      +'</div>';
  }).join('');

  // Alert banners
  var banners = '';
  if (crits) banners += '<div class="alert-banner crit">🔴 <strong>'+crits+' CRITICAL</strong> finding'+(crits!==1?'s':'')+' detected — immediate review required.</div>';
  if (SIGMA_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='high'; }).length)
    banners += '<div class="alert-banner high">🟠 High-severity Sigma rule matches detected.</div>';
  if (!totalDet) banners = '<div class="alert-banner info">✔ No detections found on this host.</div>';
  document.getElementById('overview-alerts').innerHTML = banners;

  // Severity bars
  var sevCounts = {};
  SIGMA_DATA.concat(HASH_DATA).concat(IOC_DATA).forEach(function(d){
    var lv = (d.RuleLevel||'informational');
    lv = lv.charAt(0).toUpperCase()+lv.slice(1);
    sevCounts[lv] = (sevCounts[lv]||0)+1;
  });
  var sevColors = { Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e',Informational:'#3b82f6' };
  buildBars('sev-bars', sevCounts, sevColors);

  // Sidebar badges
  function showBadge(id, n) {
    var b = document.getElementById('badge-'+id);
    if (!b) return;
    b.textContent = n;
    b.classList.toggle('show', n > 0);
  }
  showBadge('detections', SIGMA_DATA.length);
  showBadge('hashes',     HASH_DATA.length);
  showBadge('ioc',        IOC_DATA.length);

  // Top hits table is server-rendered from PowerShell ($sigmaFindings).
}

/* ── HASH & IOC TABLES ──────────────────────────────────────────────────────── */
function renderSimpleDetectTable(data, tbodyId, countId, col4Label, col4Field) {
  var count = document.getElementById(countId);
  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (count) count.textContent = data.length;
  if (!data.length) {
    if (tbody.querySelectorAll('tr').length) {
      refreshPagination(tbodyId);
      return;
    }
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-icon">✔</div><div class="empty-msg">No matches found on this host.</div></div></td></tr>';
    refreshPagination(tbodyId);
    return;
  }
  var rows = [];
  data.forEach(function(d,i){
    var uid = tbodyId+'-'+i;
    var c = sevCfg(d.RuleLevel);
    rows.push(
      '<tr class="d-row" style="border-left:3px solid '+c.bg+'" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(d.TimeCreated)+'</td>'
      +'<td>'+sevBadge(d.RuleLevel)+'</td>'
      +'<td class="d-rule"><strong>'+esc(d.RuleTitle)+'</strong></td>'
      +'<td class="d-proc" style="max-width:300px">'+esc(d.Process||'')+'</td>'
      +'<td class="d-proc" style="color:#94a3b8">'+esc(d.CommandLine||'')+'</td>'
      +'<td style="font-size:11px;color:#94a3b8">'+esc(d.RuleFile||'')+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('rule.title',d.RuleTitle)+kv('rule.level',d.RuleLevel)
      +kv('@timestamp',d.TimeCreated)+kv('user.name',d.User)
      +kv('process.executable',d.Process)+kvCode('details',d.CommandLine)
      +kv('source',d.RuleFile)
      +'</table></div></td></tr>'
    );
  });
  tbody.innerHTML = rows.join('');
  refreshPagination(tbodyId);
}

/* ── EVENT LOG BAR CHARTS ───────────────────────────────────────────────────── */
function buildEventLogBarCharts() {
  // Skip if dynamic SAMPLE_EVTLOG_DATA is available — renderEventLog() handles it
  if (typeof SAMPLE_EVTLOG_DATA !== 'undefined' && Array.isArray(SAMPLE_EVTLOG_DATA) && SAMPLE_EVTLOG_DATA.length > 0) return;

  // ── Category bars: use PowerShell-injected counts (reliable, no DOM scraping) ──
  var cats = {};
  if (typeof EVTLOG_COUNTS === 'object' && EVTLOG_COUNTS !== null) {
    Object.keys(EVTLOG_COUNTS).forEach(function(label) {
      var n = EVTLOG_COUNTS[label];
      if (n > 0) cats[label] = n;
    });
  }
  buildBars('evtlog-category-bars', cats, {});

  // ── Event ID bars: use PowerShell-injected top event IDs (reliable, no DOM scraping) ──
  var evids = {};
  if (typeof TOP_EVENT_IDS === 'object' && TOP_EVENT_IDS !== null) {
    Object.keys(TOP_EVENT_IDS).forEach(function(label) {
      var n = TOP_EVENT_IDS[label];
      if (n > 0) evids[label] = n;
    });
  }
  buildBars('evtlog-evid-bars', evids, {});
}

/* ── BOOT ─────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  try { normalizeEventLogPanels(); } catch(e) { console.error('[Forensicator] normalizeEventLogPanels:', e); }
  try { buildEventLogBarCharts(); } catch(e) { console.error('[Forensicator] buildEventLogBarCharts:', e); }
  try { buildOverview(); } catch(e) { console.error('[Forensicator] buildOverview:', e); }
  try { renderDetections(); } catch(e) { console.error('[Forensicator] renderDetections:', e); }
  if (typeof SAMPLE_EVTLOG_DATA !== 'undefined' && Array.isArray(SAMPLE_EVTLOG_DATA) && SAMPLE_EVTLOG_DATA.length > 0) {
    renderEventLog('');
  }
  renderSimpleDetectTable(HASH_DATA, 'hash-tbody', 'hash-count');
  renderSimpleDetectTable(IOC_DATA,  'ioc-tbody',  'ioc-count');

// Init pagination first -- reads all rows, hides beyond page 1
  initPagination('det-tbody',            [1, 2, 3, 4, 5, 6],         25);
  initPagination('hash-tbody',           [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 25);
  initPagination('ioc-tbody',            [1, 2, 3, 4, 5, 6],         25);
  initPagination('users-tbody',          [0, 1, 3, 6, 7, 8],         25);
  initPagination('admins-tbody',         [0, 1, 2],                  25);
  initPagination('groups-tbody',         [0, 1, 2, 3],               25);
  initPagination('sessions-tbody',       [0, 1, 2, 3, 4],            25);
  initPagination('history-tbody',        [0, 1, 2],                  25);
  initPagination('drives-tbody',         [0, 1, 2, 3, 4],            25);
  initPagination('env-tbody',            [0, 1],                     25);
  initPagination('hotfix-tbody',         [0, 1, 2, 3, 4, 5],         25);
  initPagination('software-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('defender-tbody',       [0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('procs-tbody',          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 25);
  initPagination('startup-tbody',        [0, 1, 2, 3],               25);
  initPagination('net-tbody',            [0, 1, 2, 3, 4, 5, 6],      25);
  initPagination('listen-tbody',         [0, 1, 2, 3],               25);
  initPagination('dns-tbody',            [0, 1, 2, 3, 4],            25);
  initPagination('ipconfig-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('net-ip-tbody',         [0, 1, 2, 3, 4],            25);
  initPagination('net-profile-tbody',    [0, 1, 2, 3, 4],            25);
  initPagination('net-adapter-tbody',    [0, 1, 2, 3, 4],            25);
  initPagination('neighbor-tbody',       [0, 1, 2],                  25);
  initPagination('wlan-tbody',           [0, 1],                     25);
  initPagination('shares-tbody',         [0, 1, 2],                  25);
  initPagination('network-adapter-tbody',[0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('firewall-tbody',       [0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('outbound-smb-tbody',   [0, 1, 2, 3, 4, 5, 6],      25);
  initPagination('smb-sessions-tbody',   [0, 1, 2, 3],               25);
  initPagination('net-hops-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('adapter-hops-tbody',   [0, 1, 2, 3, 4, 5],         25);
  initPagination('ip-hops-tbody',        [0, 1, 2, 3, 4, 5],         25);
  initPagination('svc-tbody',            [0, 1, 2, 3, 4],            25);
  initPagination('tasks-tbody',          [0, 1, 2, 3],               25);
  initPagination('browser-tbody',        [0, 1, 2, 3],               25);
  initPagination('usb-tbody',            [0, 1, 2, 3],               25);
  initPagination('image-tbody',          [0, 1, 2, 3],               25);
  initPagination('upnp-tbody',           [0, 1, 2, 3],               25);
  initPagination('unknown-drives-tbody', [0, 1, 2, 3],               25);
  initPagination('files-tbody',          [0, 1, 2],                  50);
  initPagination('links-tbody',          [0, 1, 2, 3, 4],            50);
  initPagination('downloads-tbody',      [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-1-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-2-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-3-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-4-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('ps-history-tbody',     [0, 1],                     50);
  initPagination('bitlocker-tbody',      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 50);
  initPagination('extras-tbody',         [0, 1, 3, 4],               25);

  // Sync count badges after pagination (querySelectorAll counts ALL rows, incl. hidden)
  syncCount('users-tbody',         'users-count');
  syncCount('admins-tbody',        'admins-count');
  syncCount('groups-tbody',        'groups-count');
  syncCount('sessions-tbody',      'sessions-count');
  syncCount('history-tbody',       'history-count');
  syncCount('software-tbody',      'software-count');
  syncCount('defender-tbody',      'defender-count');
  syncCount('procs-tbody',         'procs-count');
  syncCount('startup-tbody',       'startup-count');
  syncCount('net-tbody',           'net-count');
  syncCount('svc-tbody',           'svc-count');
  syncCount('tasks-tbody',         'tasks-count');
  syncCount('browser-tbody',       'browser-count');
  syncCount('usb-tbody',           'usb-count');
  syncCount('image-tbody',         'image-count');
  syncCount('upnp-tbody',          'upnp-count');
  syncCount('unknown-drives-tbody','unknown-drives-count');
  syncCount('files-tbody',         'files-count');
  syncCount('links-tbody',         'links-count');
  syncCount('downloads-tbody',     'downloads-count');
  syncCount('hidden-1-tbody',      'hidden-1-count');
  syncCount('hidden-2-tbody',      'hidden-2-count');
  syncCount('hidden-3-tbody',      'hidden-3-count');
  syncCount('hidden-4-tbody',      'hidden-4-count');
  syncCount('ps-history-tbody',    'ps-history-count');
  syncCount('bitlocker-tbody',     'bitlocker-count');
  syncCount('extras-tbody',        'extras-count');
  syncCount('hash-tbody',          'hash-count');
  syncCount('ioc-tbody',           'ioc-count');
  syncNetworkCards();

});

</template>

$($Global:FI_Scripts)

</body>
</html>





"@
}


# ── EVTLOG BAR CHART COUNTS ─────────────────────────────────────────────────
# Count real data rows in each event log fragment (excludes colspan/empty rows)
function Get-EvtlogRowCount {
  param([string]$Frag)
  if ([string]::IsNullOrEmpty($Frag)) { return 0 }
  $tr   = ([regex]::Matches($Frag, '<tr>')).Count
  $span = ([regex]::Matches($Frag, 'colspan')).Count
  return [Math]::Max(0, $tr - $span)
}

$evtlogCountsObj = [ordered]@{
  'Group Enumeration'        = Get-EvtlogRowCount ([string]$GroupMembershipFragment)
  'RDP Logins'               = Get-EvtlogRowCount ([string]$RDPLoginsFragment)
  'RDP Auths'                = Get-EvtlogRowCount ([string]$RDPAuthsFragment)
  'Outgoing RDP'             = Get-EvtlogRowCount ([string]$OutRDPFragment)
  'Created Users'            = Get-EvtlogRowCount ([string]$CreatedUsersFragment)
  'Password Resets'          = Get-EvtlogRowCount ([string]$PassResetFragment)
  'Added to Group'           = Get-EvtlogRowCount ([string]$AddedUsersFragment)
  'Enabled Users'            = Get-EvtlogRowCount ([string]$EnabledUsersFragment)
  'Disabled Users'           = Get-EvtlogRowCount ([string]$DisabledUsersFragment)
  'Deleted Users'            = Get-EvtlogRowCount ([string]$DeletedUsersFragment)
  'Locked Out Users'         = Get-EvtlogRowCount ([string]$LockOutFragment)
  'Cred Manager Backup'      = Get-EvtlogRowCount ([string]$CredManBackupFragment)
  'Cred Manager Restore'     = Get-EvtlogRowCount ([string]$CredManRestoreFragment)
  'Logon Events'             = Get-EvtlogRowCount ([string]$logonEventsFragment)
  'Failed Logon Events'      = Get-EvtlogRowCount ([string]$logonEventsFailedFragment)
  'Object Access Events'     = Get-EvtlogRowCount ([string]$ObjectHtmlTable1)
  'Process Execution Events' = Get-EvtlogRowCount ([string]$ObjectHtmlTable2)
}
$script:evtlogCountsJson = $evtlogCountsObj | ConvertTo-Json -Compress

# ── Top Event IDs: count occurrences of each Windows event ID across all collected fragments ──
$topEventIdsRaw = @{}
foreach ($fragment in @($GroupMembershipFragment, $RDPLoginsFragment, $RDPAuthsFragment, $OutRDPFragment,
                         $CreatedUsersFragment, $PassResetFragment, $AddedUsersFragment,
                         $EnabledUsersFragment, $DisabledUsersFragment, $DeletedUsersFragment,
                         $LockOutFragment, $CredManBackupFragment, $CredManRestoreFragment,
                         $logonEventsFragment, $logonEventsFailedFragment,
                         $ObjectHtmlTable1, $ObjectHtmlTable2)) {
    if (-not $fragment) { continue }
    [regex]::Matches($fragment, '(?<=<td>)(\d{4,5})(?=</td>)') | ForEach-Object {
        $n = [int]$_.Value
        if ($n -ge 1000 -and $n -le 65535) {
            $k = 'EID ' + $_.Value
            $topEventIdsRaw[$k] = ($topEventIdsRaw[$k] -as [int]) + 1
        }
    }
}
$script:topEventIdsJson = if ($topEventIdsRaw.Count -gt 0) { $topEventIdsRaw | ConvertTo-Json -Compress } else { '{}' }

HTMLFiles | Out-File -FilePath $HTMLFiles

$ReportRuntimeScriptSource = Join-Path $PSScriptRoot 'forensicator-runtime.js'
$ReportRuntimeScriptTarget = Join-Path "$PSScriptRoot\$env:COMPUTERNAME" 'forensicator-runtime.js'

if (Test-Path -LiteralPath $ReportRuntimeScriptSource) {
    Copy-Item -LiteralPath $ReportRuntimeScriptSource -Destination $ReportRuntimeScriptTarget -Force
} else {
    Write-ForensicLog "[!] Missing report runtime asset: $ReportRuntimeScriptSource" -Level WARN -Section "CORE"
}



Write-ForensicLog "[*] Done" -Level SUCCESS -Section "CORE" -Detail "HTML Report generation complete"

#endregion

Write-ForensicLog ""


################################################################################################################################
## ENCRYPTION SECTION                                       ###################################################################
###############################################################################################################################



if($ENCRYPTED){

    Write-ForensicLog "[*] Archiving artifacts..." -Level INFO -Section "ENCRYPTION" -Detail "Archiving artifacts..."

    $ArtifactFolder = "$PSScriptRoot\$env:COMPUTERNAME"
    $ZipPath        = "$ArtifactFolder\$env:COMPUTERNAME.zip"

# ---------------------------------------------------------
# ZIP — streaming large file support
# CreateEntryFromFile fails on files >2GB due to .NET 32-bit
# stream length limit. Stream large files manually in chunks.
# Skip compression on binary/already-compressed formats.
# ---------------------------------------------------------
@('System.IO.Compression','System.IO.Compression.FileSystem') |
    ForEach-Object { [void][Reflection.Assembly]::LoadWithPartialName($_) }

# Extensions where compression is pointless or harmful
$noCompressExtensions = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
@('.raw','.img','.dd','.vmem','.dmp','.zip','.gz','.7z',
  '.rar','.mp4','.mp3','.jpg','.jpeg','.png') |
    ForEach-Object { [void]$noCompressExtensions.Add($_) }

# Threshold above which we stream manually instead of CreateEntryFromFile
# Set to 1.8GB to stay safely under the 2GB limit
$largeFileThreshold = [long]1.8GB

Push-Location $ArtifactFolder

$FileList = Get-ChildItem '*.*' -File -Recurse

try{
    # Use ZipArchiveMode::Update so existing entries are preserved
    # if the zip already partially exists
    $WriteArchive = [IO.Compression.ZipFile]::Open($ZipPath, 'Update')

    foreach($File in $FileList){

        # Skip the zip file itself
        if($File.FullName -eq $ZipPath){ continue }

        $RelativePath   = (Resolve-Path -LiteralPath $File.FullName -Relative) -replace '^.\\'
        $compressionLvl = if($noCompressExtensions.Contains($File.Extension)){
                              [IO.Compression.CompressionLevel]::NoCompression
                          } else {
                              [IO.Compression.CompressionLevel]::Optimal
                          }

        try{
            if($File.Length -gt $largeFileThreshold){

                # Stream manually in 64MB chunks to bypass the 2GB limit
                Write-ForensicLog "[*] Streaming large file: $($File.Name) ($([Math]::Round($File.Length/1GB,2)) GB)" -Level INFO -Section "ARCHIVING" -Detail "Streaming large file: $($File.Name) ($([Math]::Round($File.Length/1GB,2)) GB)"

                $entry      = $WriteArchive.CreateEntry($RelativePath, $compressionLvl)
                $entryStream = $entry.Open()
                $fileStream  = [System.IO.File]::OpenRead($File.FullName)

                try{
                    $bufferSize = 64MB
                    $buffer     = [byte[]]::new($bufferSize)
                    $totalBytes = 0

                    while(($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0){
                        $entryStream.Write($buffer, 0, $bytesRead)
                        $totalBytes += $bytesRead

                        # Progress indicator for large files
                        $pct = [Math]::Round(($totalBytes / $File.Length) * 100, 0)
                        Write-Progress -Activity "Archiving $($File.Name)" `
                                       -Status "$pct% ($([Math]::Round($totalBytes/1MB,0)) MB / $([Math]::Round($File.Length/1MB,0)) MB)" `
                                       -PercentComplete $pct
                    }

                    Write-Progress -Activity "Archiving $($File.Name)" -Completed
                }
                finally{
                    $entryStream.Dispose()
                    $fileStream.Dispose()
                }

            }
            else{
                # Standard path for files under the threshold
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $WriteArchive,
                    $File.FullName,
                    $RelativePath,
                    $compressionLvl
                ) | Out-Null
            }
        }
        catch{
            Write-ForensicLog "$($File.FullName) could not be archived.`n$($_.Exception.Message)" -Level ERROR -Section "ARCHIVING" -Detail "$($File.FullName) could not be archived. due to error: `n$($_.Exception.Message)"
        }
    }
}
catch{
    Write-Error $_.Exception
}
finally{
    $WriteArchive.Dispose()
    Write-Progress -Activity "Archiving" -Completed -ErrorAction SilentlyContinue
    Get-ChildItem * -Exclude *.zip -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}

Pop-Location

    Write-ForensicLog "[*] Archive complete, encrypting..." -Level INFO -Section "ENCRYPTION" -Detail "Archive complete, encrypting..."

    # ---------------------------------------------------------
    # KEY GENERATION
    # Use RNGCryptoServiceProvider instead of Get-Random
    # Get-Random uses a seeded PRNG — not suitable for key material
    # RNGCryptoServiceProvider uses the OS CSPRNG (same source as
    # CryptGenRandom) which is cryptographically strong
    # ---------------------------------------------------------
    function New-CryptoRandomPassword {
        param([int]$Length = 32)
        $chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $rng    = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $result = [System.Text.StringBuilder]::new($Length)
        $byte   = [byte[]]::new(1)

        while($result.Length -lt $Length){
            $rng.GetBytes($byte)
            # Discard values outside the usable range to avoid modulo bias
            if($byte[0] -lt ($chars.Length * [Math]::Floor(256 / $chars.Length))){
                [void]$result.Append($chars[$byte[0] % $chars.Length])
            }
        }
        $rng.Dispose()
        return $result.ToString()
    }

    $Password = New-CryptoRandomPassword -Length 32
    $KeyB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password))

    Write-ForensicLog "[!] ENCRYPTION KEY: $KeyB64" -Level SUCCESS -Section "ENCRYPTION" -Detail "This key is required for decryption — keep it safe!"
    "YOUR ENCRYPTION KEY IS: $KeyB64" | Out-File -Force "$PSScriptRoot\key.txt"
    Write-ForensicLog "[!] Key saved to key.txt — keep it safe" -Level INFO -Section "ENCRYPTION" -Detail "Key saved to key.txt — keep it safe"

    # ---------------------------------------------------------
    # ENCRYPT — pure .NET AES-256-CBC, no external module
    # ---------------------------------------------------------
    function Protect-FileNative {
        param(
            [string]$FilePath,
            [string]$KeyB64,
            [string]$Suffix = ".forensicator"
        )

        # Derive a 256-bit key and 128-bit IV from the password
        # using PBKDF2 (Rfc2898DeriveBytes) with a random salt
        # This is far stronger than using the raw password as a key
        $salt       = [byte[]]::new(16)
        $rng        = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($salt)
        $rng.Dispose()

        $password   = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))
        $pbkdf2     = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                          $password, $salt, 100000,
                          [System.Security.Cryptography.HashAlgorithmName]::SHA256
                      )
        $keyBytes   = $pbkdf2.GetBytes(32)   # AES-256
        $ivBytes    = $pbkdf2.GetBytes(16)   # AES block size
        $pbkdf2.Dispose()

        $aes            = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key        = $keyBytes
        $aes.IV         = $ivBytes
        $aes.Mode       = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding    = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor      = $aes.CreateEncryptor()
        $outPath        = "$FilePath$Suffix"

        try{
            $inStream   = [System.IO.File]::OpenRead($FilePath)
            $outStream  = [System.IO.File]::Create($outPath)

            # Write salt at the top of the file so decryption can re-derive the key
            # Format: [16 bytes salt][encrypted data]
            $outStream.Write($salt, 0, $salt.Length)

            $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                                $outStream,
                                $encryptor,
                                [System.Security.Cryptography.CryptoStreamMode]::Write
                            )

            $inStream.CopyTo($cryptoStream)
            $cryptoStream.FlushFinalBlock()
        }
        finally{
            if($cryptoStream){ $cryptoStream.Dispose() }
            if($outStream)   { $outStream.Dispose()    }
            if($inStream)    { $inStream.Dispose()     }
            $encryptor.Dispose()
            $aes.Dispose()
        }

        # Remove source only after confirming output was written
        if(Test-Path $outPath){
            Remove-Item $FilePath -Force
        }
    }

    # Companion decryption function — include this in your documentation
    function Unprotect-FileNative {
        param(
            [string]$FilePath,
            [string]$KeyB64,
            [string]$Suffix = ".forensicator"
        )

        if(-not $FilePath.EndsWith($Suffix)){
            Write-ForensicLog "$FilePath does not have expected suffix $Suffix" -Level ERROR -Section "DECRYPTION" -Detail "No file with suffix $Suffix found for decryption"
        }

        $outPath  = $FilePath -replace [regex]::Escape($Suffix),''
        $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))

        try{
            $inStream = [System.IO.File]::OpenRead($FilePath)

            # Read the 16-byte salt written by Protect-FileNative
            $salt = [byte[]]::new(16)
            [void]$inStream.Read($salt, 0, 16)

            $pbkdf2   = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                            $password, $salt, 100000,
                            [System.Security.Cryptography.HashAlgorithmName]::SHA256
                        )
            $keyBytes = $pbkdf2.GetBytes(32)
            $ivBytes  = $pbkdf2.GetBytes(16)
            $pbkdf2.Dispose()

            $aes         = [System.Security.Cryptography.AesManaged]::new()
            $aes.Key     = $keyBytes
            $aes.IV      = $ivBytes
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $decryptor    = $aes.CreateDecryptor()
            $outStream    = [System.IO.File]::Create($outPath)
            $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                                $inStream,
                                $decryptor,
                                [System.Security.Cryptography.CryptoStreamMode]::Read
                            )
            $cryptoStream.CopyTo($outStream)
        }
        finally{
            if($cryptoStream){ $cryptoStream.Dispose() }
            if($outStream)   { $outStream.Dispose()    }
            if($inStream)    { $inStream.Dispose()     }
            if($decryptor)   { $decryptor.Dispose()    }
            if($aes)         { $aes.Dispose()          }
        }

        if(Test-Path $outPath){
            Remove-Item $FilePath -Force
        }
    }

    # ---------------------------------------------------------
    # ENCRYPT ALL ZIP FILES
    # ---------------------------------------------------------
    $FilesToEncrypt = Get-ChildItem -Path "$ArtifactFolder\*" `
                                    -Include '*.zip' `
                                    -Exclude "*forensicator*" `
                                    -Recurse -Force |
                      Where-Object { -not $_.PSIsContainer }

    foreach($file in $FilesToEncrypt){
        Write-ForensicLog "Encrypting $($file.Name)..."
        Protect-FileNative -FilePath $file.FullName -KeyB64 $KeyB64
    }

    Write-ForensicLog "[*] Encryption complete — $($FilesToEncrypt.Count) file(s) encrypted" -Level SUCCESS -Section "ENCRYPTION" -Detail "Files encrypted: $($FilesToEncrypt.Count)"
    Write-ForensicLog "[!] Key is in $PSScriptRoot\key.txt" -Level INFO -Section "ENCRYPTION"

    Set-Location $PSScriptRoot

}else{

}





Write-ForensicLog ''

Write-ForensicLog "Summarizing Forensicator logs files" -Level INFO -Section "CORE"

#End time date stamp
$ForensicatorEndTime = Get-Date -Format $ForensicatorDateFormat

#############################################################################################################
#region   LOGGING FINALISATION
#############################################################################################################

# Save structured logs
Save-ForensicLogs

Write-ForensicLog "Done" -Level SUCCESS -Section "CORE"

Write-ForensicLog ''

Write-ForensicLog "Stoping Transcript and ending Forensicator" -Level INFO -Section "CORE"

# Stop transcript last — captures the Save-ForensicLogs output too
try{
    Stop-Transcript
}
catch{ }

Write-ForensicLog "Done - Happy Investigation" -Level SUCCESS -Section "CORE"
