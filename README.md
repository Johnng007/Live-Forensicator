<h1 align="center">📝 Forensicator 📝</h1>
<h3 align="center">POWERSHELL SCRIPT TO AID LIVE FORENSICS & INCIDENCE RESPONSE</h3>
                                               
```bash


___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v1.0



```


# ABOUT

Live Forensicator is part of the Black Widow Toolbox, its aim is to assist Forensic Investigator and Incidence responders in carrying out a quick live forensic investigation.
It achieves this by gathering different system information for further review for anomalous behaviour or unexpected data entry, it also looks out for unusual files or activities and points it out to the investigator.
It is paramount to note that this script has no inbuilt intelligence its left for the investigator to analyse the output and decide on a conclusion or decide on carrying out more deeper investigation.

## Dependencies

This script is written in powershell for use on windows PCs and Servers. 
It has a supporting file WINPMEM for taking RAM dumps https://github.com/Velocidex/WinPmem
This script is expected to work out of the box.

```bash
powershell 2.* or 3.* | winpmem_mini_x64_rc2.exe 
```

## Usage

```python
# copy the files to the computer
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execution
run Forensicator.ps1 <parameters>

```

## Examples

```python
# Basic Usage
.\Forensicator.ps1

# Extract Event Logs alongside Basic Usage
.\Forensicator.ps1 -EVTX EVTX

# Extract RAM Dump alongside Basic Usage
.\Forensicator.ps1 -RAM RAM

# Check for log4j with the JNDILookup.class
.\Forensicator.ps1 -log4j log4j

# Yes of course you can do all
.\Forensicator.ps1 -EVTX EVTX -RAM RAM -log4j log4j

```

NOTE: Run the script as an administrator to get value.<br>
NOTE: The results are outputed in nice looking html files with an index file. <br>
      You can find all extracted Artifacts in the script's working directory.

## Features
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

   ========================================
     PROCESSES | SCHEDULED TASK | REGISTRY
   ========================================
    1. PROCESSES.
    2. STARTUP PROGRAMS
    3. SCHEDULED TASK
    4. SCHEDULED TASKS AND STATE
    5. SERVICES
    6. PERSISTANCE IN REGISTRY

   =================================
     OTHER CHECKS
   =================================
    1. LOGICAL DRIVES
    2. CONNECTED AND DISCONNECTED WEBCAMS
    3. USB DEVICES
    4. UPNP DEVICES
    5. ALL PREVIOUSLY CONNECTED DRIVES
    6. ALL FILES CREATED IN THE LAST 180 DAYS
    7. 100 DAYS WORTH OF POWERSHELL HISTORY
    8. EXECUTABLES IN DOWNLOADS FOLDER
    9. EXECUTABLES IN APPDATA
    10. EXECUATBLES IN TEMP
    11. EXECUTABLES IN PERFLOGS
    12. EXECUTABLES IN THE DOCUMENTS FOLDER

   =========================================
      ORTHER REPORTS IN THE HTML INDEX FILE
   =========================================
    1. GROUP POLICY REPORT
    2. WINPMEM RAM CAPTURE
    3. LOG4J
    4. IIS LOGS
    5. TOMCAT LOGS

```
## Screesnhot
<img align="left" src="https://john.ng/wp-content/uploads/2022/02/Screenshot-2022-02-10-183038.png" alt="ebuka" /> <br>


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change or add.



## License
[MIT](https://mit.com/licenses/mit/)


<h3 align="left">Support:</h3>
<p><a href="https://www.buymeacoffee.com/ebuka"> <img align="left" src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="ebuka" /></a></p><br><br>

<h3 align="left">Connect with me:</h3>
<p align="left">
<a href="https://linkedin.com/in/ebuka john onyejegbu" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="ebuka john onyejegbu" height="30" width="40" /></a>
</p>

