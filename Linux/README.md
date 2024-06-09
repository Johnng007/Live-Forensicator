<h1 align="center">📝 Forensicator 📝</h1>
<h3 align="center">BASH SCRIPT TO AID LIVE FORENSICS & INCIDENCE RESPONSE</h3>
                                               
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

Live Forensicator is part of the Black Widow Toolbox, its aim is to assist Forensic Investigators and Incidence responders in carrying out a quick live forensic investigation.
<p>It achieves this by gathering different system information for further review for anomalous behaviour or unexpected data entry, it also looks out for unusual files or activities and points it out to the investigator.</p>
<p>Forensicator for Linux offers a timeline feature for fetching Linux logs from different sources for a specified date and time. </p>
<p>It is paramount to note that this script has no inbuilt intelligence its left for the investigator to analyse the output and decide on a conclusion or decide on carrying out more deeper investigation.</p>


```bash

## 🎫 Optional Dependencies

This script is written in bash for use on Linux PCs and Servers. 
For additional features it depends on external binaries, they are in the Forensicator-Share folder.
But Forensicator can work without these dependencies, they just help with additional features
```
```bash
avml     For taking RAM capture (https://github.com/microsoft/avml)
aqlite3  Aids in Browsing history extraction (https://sqlite.org/)
```

## 🔨 Usage

```bash
# copy the files to the computer
git clone https://github.com/Johnng007/Live-Forensicator.git

# change to the Linux Directory and Make script executable
cd Linux && chmod 777 Forensicator.sh

# Execution
.\Forensicator.sh <parameters>

```

## 🥊 Examples

```python
# Basic
.\Forensicator.sh

# Check Usage
.\Forensicator.sh -u, --usage

# Capture network traffic for 60 secounds
.\Forensicator.sh -p, pcap

# Check for files that has similar extensions with ransomware encrypted files (can take some time to complete)
.\Forensicator.sh -s, ransom

# Grab weblogs NGINX & Apache
.\Forensicator.sh -w, weblogs

# Extract logs based on a timeline (e.g --timeline 'startdate' 'enddate')(e.g --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59')
.\Forensicator.sh -t, --timeline

# Collect browsing history
.\Forensicator.sh -b, browser

# Define LogFiles to search through when using timeline
.\Forensicator.sh -log, logfiles (e.g --logfiles auth.log,syslog,kern.log)

# Define log directory to loop through when using timeline
.\Forensicator.sh -logdir, --logdir (e.g --outputdir /custom/log/directory)

# Extract RAM
.\Forensicator.sh -r, --ram

# Yes of course you can do all (Defining log files and directory is actually optional when using timeline.)
.\Forensicator.sh -p -s -w --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59'

# For Unattended Mode on Basic Usage
.\Forensicator.sh -name 'Ebuka John' -case 01123 -title 'Ransomware Infected Laptop' -loc Prague -device AZUZ

# You can use unattended mode for each of the other parameters
.\Forensicator.sh -name 'Ebuka John' -case 01123 -title 'Ransomware Infected Laptop' -loc Prague -device AZUZ -p -s -w


```

## ✍ Notes
* Run the script as an administrator to get value.<br>

* Forensicator Activities may be flagged by IDS or IPS Solutions so take note.<br>
  The results are outputed in nice looking html files with an index file. <br>

* You can find all extracted Artifacts in the script's working directory.

* <p>Forensicator Has the ability to Search through all the folders within a system looking for files with similar extensions as well known Ransomwares, Albeit this     search takes long but its helpful if the Alert you recieved is related to a Ransomware attack, Use the -RANSOMWARE Parameter to invoke this.</p>

* <p>Forensictor can capture network traffic using netsh trace, this is useful when your investigation has to do with asset communicating with known malicious IPs,       this way you can parse the pcapng file to wireshark and examine for C&C servers. By Defult i set the capture to take 120secs</p>

* <p>Sometimes it may be paramount to maintain the integrity of the Artifacts, where lawyers may argue that it might have been compromised on transit to your lab.
  Forensicator can now encrypt the Artifact with a unique randomely generated key using AES algorithm, you can specify this by using the -ENCRYPTED parameter. You can   decrypt it at will anywhere anytime even with another copy of Forensicator, just keep your key safe. This task is performed by the FileCryptography.psm1 file</p>

* <p>Forensictor looks out for suspicious activities within the Event Log, it has a long list of malicious executables, and powershell commands which it queries the event log against.</p>

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
     11. IP ROUTES TO NON LOCAL DESTINATIONS
     12. NETWORK ADAPTERS WITH IP ROUTES TO NON LOCAL DESTINATIONS
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
    6. PERSISTANCE IN REGISTRY
    
   ========================================
     EVENTLOG ANALYSIS
   ========================================
    1. USER RELATED ACTIVITES.
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
    9.  EXECUTABLES IN DOWNLOADS FOLDER
    10. EXECUTABLES IN APPDATA
    11. EXECUATBLES IN TEMP
    12. EXECUTABLES IN PERFLOGS
    13. EXECUTABLES IN THE DOCUMENTS FOLDER

   =========================================
      ORTHER FORENSICATOR EXTRA CHECKS
   =========================================
    1.  GROUP POLICY REPORT
    2.  WINPMEM RAM CAPTURE
    3.  LOG4J
    4.  IIS LOGS
    5.  TOMCAT LOGS
    6.  BROWSING HISTORY OF ALL USERS 
    7.  CHECK FOR FILES THAT HAS SIMILAR EXTENSIONS WITH KNOWN RANSOMWARE ENCRYPTED FILES
        NOTE: THIS CHECK CAN TAKE SOME TIME TO COMPLETE DEPENDING ON THE NUMBER OF DRIVES AND AMOUNT OF FILES.
    8.  RUNS NETWORK TRACING USING NETSH TRACE & CONVERTS TO PCAPNG FOR FURTHER ANALYSIS
    9.  Event Logs in EVTX Format

```



## 🤔 MORE TOOLS
Want to check out other Black Widow Tools?
1. Anteater - A python based web reconnaisence tool. https://github.com/Johnng007/Anteater
2. Nessus Pro API - A powershell Script to Export and Download Nessus Scan Results via Nessus API. https://github.com/Johnng007/PowershellNessus

## ✨ ChangeLog
```bash
V4.0 13/02/2024 - Big Update
1. General Code Improvement and Standardization.
2. Output HTML File has been improved greatly.
3. Ability to search individual checks in a table from the html output.
4. Ability to export each check to excel, pdf or print. from the html output.
5. A new visually stunning HTML output.
6. Added RDP logon History (Outgoing & Incoming)
7. changed the config file from config.yml to config.json so the script can use default powershell json manipulation.

v3.3.2 13/05/2023
Fixed Windows Defender warning while running Forensicator.
Added config.yml to handle malicious file names, executable names and powershell commands.
      In the future config.yml may hold more configuration information.

v3.3.1 22/02/2023
Updated The UI
Added Eventlog Analysis for {Logon Events, Object Access, Process Execution & Suspicious Activities}
Added auto checking of update.

v3.2.1 29/06/2022
Updated The UI
Added EventLog Analysis

v3.1.0 27/05/2022
Moved all the Binary Helpers to a folder.
Added an inbuilt powershell based browser history extractor.
Added a flag for calling Nirsoft Based browser history extractor in case you need a robust extraction.
Added a usage switch to show usage options.
Minor Bug fixes.

v2.0 25/04/2022
Minor Bug Fixes
Added the possiblity of encrypting the Artifact after acquiring it to maintain integrity.

v1.4 14/04/2022
Added Ability perform network tracing using netsh trace, the subsequent et1 is converted to pcapng
Minor Bug Fixes in Script Update.
Added Weblogs as an option parameter.

v1.3 11/04/2022
Added a feature to check for files that has similar extensions with known ransomware encrypted files.
You can now check for updates within the script.
UI update

v1.2 29/03/2022 
Added unattended Mode Feature
Added Ability to grab browsing history of all users
Minor Bug Fix

v1 28/01/2022
Initial Release

```

## Screenshot
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_Output.png?raw=true" alt="Forensicator"  /> <br>
## HTML Output
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" alt="Forensicator"  /> <br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML2.png?raw=true" alt="Forensicator"  /> <br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" alt="Forensicator"  /> <br>
<br></br>

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change or add.



## License
[MIT](https://mit.com/licenses/mit/)


<h3 align="left">Support:</h3>
<p><a href="https://ko-fi.com/forensicator"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="ebuka" /></a></p><br><br>

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://www.linkedin.com/in/ebuka-john-onyejegbu" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="ebuka john onyejegbu" height="30" width="40" /></a>
</p>

