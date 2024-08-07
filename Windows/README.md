<h1 align="center">📝 Forensicator 📝</h1>
<h3 align="center">POWERSHELL SCRIPT TO AID LIVE FORENSICS & INCIDENCE RESPONSE</h3>
                                               
```bash


___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v4.0.1



```


# 🤔 ABOUT

Live Forensicator is part of the Black Widow Toolbox, it aims to assist Forensic Investigators and Incident responders in carrying out a quick live forensic investigation.
<p>It achieves this by gathering different system information for further review for anomalous behavior or unexpected data entry, it also looks out for unusual files or activities and points it out to the investigator.</p>
<p> **The latest version now analyzes Event Logs, it queries the event logs for certain log IDs that might point to an unusual activity or compromise. </p>
<p>It is paramount to note that this script has no inbuilt intelligence it is left for the investigator to analyze the output and decide on a conclusion or conduct a deeper investigation.</p>


```

## 🎫 Optional Dependencies

This script is written in Powershell for use on Windows PCs and Servers. 
For additional features it depends on external binaries, they are in the Forensicator-Share folder.
But Forensicator can work without these dependencies, they help with additional features
```
```
winpmem_mini_x64_rc2.exe   For taking RAM capture (https://github.com/Velocidex/WinPmem)
BrowsingHistoryView64.exe  For a more robust Browsing History View (http://www.nirsoft.net/utils/browsing_history_view.html)
etl2pcapng64.exe           For converting network trace to pcap
FileCryptography.psm1      For Encrypting the Artifacts
```
```
## 🎫 Other Dependencies
There are other files within the Forensicator-Share folder that this script depends on to offer more robust features.
```
```
malicious_URLs.txt          This file contains a list of malicious URLs used by the Forensicator
                            to match Browsing History to malicious domains. 
sqlite3.exe                 Assists with extracting Browser History. 
```

## 🔨 Usage

```bash
# copy the files to the computer
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execution
.\Forensicator.ps1 <parameters>

# Windows Binary
.\Forensicator.exe <parameters>

NOTE: You can just double-click the exe to run the default checks
      The Forensicator-Share is parked into the EXE which will self-extract on run.

```

## 🥊 Examples

```python
# Basic
.\Forensicator.ps1

# Check your Version
.\Forensicator.ps1 -VERSION

# Check for Updates
.\Forensicator.ps1 -UPDATE

# Check Usage
.\Forensicator.ps1 -USAGE

# Decrypt An Encrypted Artifact
.\Forensicator.ps1 -DECRYPT DECRYPT

# Extract Event Logs alongside Basic Usage
.\Forensicator.ps1 -EVTX EVTX

# Use the Nirsoft Browser History View to Capture Browser History
.\Forensicator.ps1 -BROWSER BROWSER

#Grab weblogs IIS & Apache
.\Forensicator.ps1 -WEBLOGS WEBLOGS

#Run Network Tracing & Capture PCAPNG for 120 seconds
.\Forensicator.ps1 -PCAP PCAP

# Extract RAM Dump alongside Basic Usage
.\Forensicator.ps1 -RAM RAM

# Check for log4j with the JNDILookup.class
.\Forensicator.ps1 -LOG4J LOG4J

# Encrypt the Artifact after collecting it
.\Forensicator.ps1 -ENCRYPTED ENCRYPTED

# Yes of course you can do all
.\Forensicator.ps1 -EVTX EVTX -RAM RAM -log4j log4j -PCAP PCAP -WEBLOGS WEBLOGS

# For Unattended Mode on Basic Usage
.\Forensicator.ps1 -OPERATOR "Ebuka John" -CASE 01123 -TITLE "Ransomware Infected Laptop" -LOCATION Nigeria -DEVICE AZUZ

# You can use unattended mode for each of the other parameters
.\Forensicator.ps1 -OPERATOR "Ebuka John" -CASE 01123 -TITLE "Ransomware Infected Laptop" -LOCATION Nigeria -DEVICE AZUZ -EVTX EVTX -RAM RAM -log4j log4j

# Check for files that have similar extensions with ransomware encrypted files (can take some time to complete)
.\Forensicator.ps1 -RANSOMWARE RANSOMWARE

# You can match hashes of executables on the system to publicly available malware hashes
.\Forensicator.ps1 -HASHCHECK HASHCHECK

# You can compress the Forensicator output immediately after execution Oneliner
.\Forensicator.ps1 ; Start-Sleep -s 15 ; Compress-Archive -Path "$env:computername" -DestinationPath "C:\inetpub\wwwroot\$env:computername.zip" -Force

```

## ✍ Notes
* Run the script as an administrator to get value.<br>

* Forensicator Activities may be flagged by IDS or IPS Solutions so take note.<br>

* The results are output in nice-looking html files with an index file, You can find all extracted Artifacts in the script's working directory.

* <p>Forensicator Can Search through all the folders within a system looking for files with similar extensions as well-known Ransomware, this     search takes a long but is helpful if the Alert you received is related to a Ransomware attack, Use the -RANSOMWARE Parameter to invoke this.</p>

* <p>Forensictor can capture network traffic using netsh trace, this is useful when your investigation has to do with assets communicating with known malicious IPs,       this way you can parse the pcapng file to Wireshark and examine for C&C servers. By default, I set the capture to take 120secs</p>

* <p>Sometimes it may be paramount to maintain the integrity of the Artifacts, where lawyers may argue that they might have been compromised in transit to your lab.
  Forensicator can now encrypt the Artifact with a unique randomly generated key using the AES algorithm, you can specify this by using the -ENCRYPTED parameter. You can   decrypt it at will anywhere anytime even with another copy of Forensicator, just keep your key safe. This task is performed by the FileCryptography.psm1 file</p>

* <p>Forensictor looks out for suspicious activities within the Event Log, it has a long list of malicious executables, and PowerShell commands which it queries the event log against.</p>

- Forensictor extracts Browsing History from Chrome, Mozilla, Edge, and IE, this browsing history is further passed through a list of malicious URLs for detection - [See More In Wiki](https://github.com/Johnng007/Live-Forensicator/wiki/Usage-%E2%80%90-Windows#-malicious-web-traffic-analysis).
  
- Forensicator matches the hashes of executables on the machine to publicly available malicious hash databases, this helps detect malicious executables. [See More In Wiki](https://github.com/Johnng007/Live-Forensicator/wiki/Usage-%E2%80%90-Windows#-malware-static-analysis)
 

## 🔥 What Forensicator Grabs
```bash

   =================================
     USER AND ACCOUNT INFORMATION
   =================================
     1. GETS CURRENT USER.
     2. SYSTEM DETAILS.
     3. USER ACCOUNTS
     4. LOGON SESSIONS
     5. USER PROFILES
     6. ADMINISTRATOR ACCOUNTS
     7. LOCAL GROUPS

   =================================
     SYSTEM INFORMATION
   =================================
     1. INSTALLED PROGRAMS.
     2. INSTALLED PROGRAMS FROM REGISTERY.
     3. ENVIRONMENT VARIABLES
     4. SYSTEM INFORMATION
     5. OPERATING SYSTEM INFORMATION
     6. HOTFIXES
     8. WINDOWS DEFENDER STATUS AND DETAILS

   =================================
     NETWORK INFORMATION
   =================================
     1. NETWORK ADAPTER INFORMATION.
     2. CURRENT IP CONFIGURATION IPV6 IPV4.
     3. CURRENT CONNECTION PROFILES.
     4. ASSOCIATED WIFI NETWORKS AND PASSWORDS.
     5. ARP CACHES
     6. CURRENT TCP CONNECTIONS AND ASSOCIATED PROCESSES
     7. DNS CACHE
     8. CURRENT FIREWALL RULES
     9. ACTIVE SMB SESSIONS (IF ITS A SERVER)
     10. ACTIVE SMB SHARES
     11. IP ROUTES TO NON-LOCAL DESTINATIONS
     12. NETWORK ADAPTERS WITH IP ROUTES TO NON-LOCAL DESTINATIONS
     13. IP ROUTES WITH INFINITE VALID LIFETIME
     14. All RDP Connections
     15. All Outgoing RDP Connection History

   ========================================
     PROCESSES | SCHEDULED TASK | REGISTRY
   ========================================
    1. PROCESSES.
    2. STARTUP PROGRAMS
    3. SCHEDULED TASK
    4. SCHEDULED TASKS AND STATE
    5. SERVICES
    6. PERSISTENCE IN REGISTRY
    
   ========================================
     EVENTLOG ANALYSIS
   ========================================
    1. USER RELATED ACTIVITIES.
       1. RDP LOGINS
       2. ENUMERATED A USER GROUP MEMBERSHIP
       3. CREATED USERS
       4. PASSWORD RESETS
       5. ADDED USERS TO GROUP
       6. ENABLED USERS
       7. DISABLED USERS
       8. DELETED USERS
       9. ACCOUNT LOCKOUTS
       10. CREDENTIAL MANAGER BACKUPS
       11. CREDNTIAL MANAGER RESTORES
       12. LOGON EVENTS
       13. OBJECT ACCESS
       14. PROCESS EXECUTION
       15. SUSPICIOUS ACTIVITIES
       
    NOTE: I WILL KEEP UPDATING THE ANALYSIS SCOPE WITH TIME.

   =================================
     OTHER CHECKS
   =================================
    1.  LOGICAL DRIVES
    2.  CONNECTED AND DISCONNECTED WEBCAMS
    3.  USB DEVICES
    4.  UPNP DEVICES
    5.  ALL PREVIOUSLY CONNECTED DRIVES
    6.  ALL FILES CREATED IN THE LAST 180 DAYS
    7.  500 DAYS WORTH OF POWERSHELL HISTORY
    9.  EXECUTABLES IN THE DOWNLOADS FOLDER
    10. EXECUTABLES IN APPDATA
    11. EXECUATBLES IN TEMP
    12. EXECUTABLES IN PERFLOGS
    13. EXECUTABLES IN THE DOCUMENTS FOLDER

   =========================================
      OTHER FORENSICATOR EXTRA CHECKS
   =========================================
    1.  GROUP POLICY REPORT
    2.  WINPMEM RAM CAPTURE
    3.  LOG4J
    4.  IIS LOGS
    5.  TOMCAT LOGS
    6.  BROWSING HISTORY OF ALL USERS 
    7.  CHECK FOR FILES THAT HAVE SIMILAR EXTENSIONS WITH KNOWN RANSOMWARE-ENCRYPTED FILES
        NOTE: THIS CHECK CAN TAKE SOME TIME TO COMPLETE DEPENDING ON THE NUMBER OF DRIVES AND AMOUNT OF FILES.
    8.  RUNS NETWORK TRACING USING NETSH TRACE & CONVERTS TO PCAPNG FOR FURTHER ANALYSIS
    9.  Event Logs in EVTX Format.
   10.  Forensictor extracts Browsing History from Chrome, Mozilla, Edge and IE, this browsing history is further passed through a list of malicious URLs for detection
   11.  Forensicator matches the hashes of executables on the machine to publicly available malicious hash databases for malware detection

```


## Screenshot
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_Output.png?raw=true" alt="Forensicator"  /> <br>
## HTML Output
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" alt="Forensicator"  /> <br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML2.png?raw=true" alt="Forensicator"  /> <br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" alt="Forensicator"  /> <br>
<br></br>

## Contributing
Just to let you know, pull requests are welcome. For major changes, please open an issue first to talk about what you would like to change or add.



## License
[MIT](https://mit.com/licenses/mit/)


<h3 align="left">Support:</h3>
<p><a href="https://ko-fi.com/forensicator"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="ebuka" /></a></p><br><br>

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://www.linkedin.com/in/ebuka-john-onyejegbu" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="ebuka john onyejegbu" height="30" width="40" /></a>
</p>

