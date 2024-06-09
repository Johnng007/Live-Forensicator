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

> `avml`     For taking RAM capture (https://github.com/microsoft/avml)
> 
> `aqlite3`  Aids in Browsing history extraction (https://sqlite.org/)


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

* <p>Forensicator Has the ability to Search through all the folders within a system looking for files with similar extensions as well known Ransomwares, Albeit this     search takes long but its helpful if the Alert you recieved is related to a Ransomware attack, Use the --ransom Parameter to invoke this.</p>

* <p>Forensictor can capture network traffic, this is useful when your investigation has to do with asset communicating with known malicious IPs,       this way you can parse the pcapng file to wireshark and examine for C&C servers. By Defult i set the capture to take 60secs</p>


## 🔥 What Forensicator Grabs
```bash

   =================================
     USER AND ACCOUNT INFORMATION
   =================================
     1. Current User Sessions.
     2. Users with Login Shell.
     3. Users with SSH Auth keys.
     4. Passwd File.
     5. Sudoers File.

   =================================
     SYSTEM INFORMATION
   =================================
     1. System Info.
     2. Kernel Information.
     3. CPU Information.
     4. Block Devices.
     5. USB Controllers.
     6. SATA Devices.

   =================================
     NETWORK INFORMATION
   =================================
     1. Routing Table.
     2. Processes & Networking.
     3. TCP only connection.
     4. Firewall Rules.
     5. Hosts File.
     6. Hosts Allow.
     7. Hosts Resolv.
     8. IP Information.

   ========================================
     PROCESSES | SCHEDULED TASK | REGISTRY
   ========================================
    1. Processes.
    2. Services.
    3. Enabled services.
    4. All Timers.
    5. Crons.

   =================================
     OTHER CHECKS
   =================================
    1.  Last Logins.
    2.  Loaded Modules Status.
    3.  Get Binary File(/usr/bin/) Capabilities.
    4.  Get Binary File(/bin/) Capabilities.
    5.  Get Binary File(/) Capabilities.
    6.  Find files with setuid bit set.
    7.  Looking for persistence in cron (/etc/cron*/).
    9.  Looking for persistence in cron (/etc/incron.d/*).
    10. Looking for persistence in (/etc/init.d/*).
    11. Looking for persistence in (/etc/rc*.d/*)
    12. Looking for persistence in (/etc/systemd/system/*).
    13. Looking for persistence in (/etc/update.d/*).
    14. Looking for persistence in (/var/spool/cron/*).
    15. Looking for persistence in (/var/spool/incron/*).
    16. Looking for persistence in (/var/run/motd.d/*).

   =========================================
      ORTHER FORENSICATOR EXTRA CHECKS
   =========================================
    1.  AuthLogs.
    2.  BROWSING HISTORY.
    3.  Current User Bash Profile.
    4.  NETWORK TRACE.
    5.  Open Files.
    6.  PCI Devices.
    7.  RAM CAPTURE.
    8.  Ransomware Extensions.
    9.  Timeline Logs.
   10.  Web Logs

```



## 🤔 MORE TOOLS
Want to check out other Black Widow Tools?
1. Anteater - A python based web reconnaisence tool. https://github.com/Johnng007/Anteater
2. Nessus Pro API - A powershell Script to Export and Download Nessus Scan Results via Nessus API. https://github.com/Johnng007/PowershellNessus

## ✨ ChangeLog
```bash

Linux: v1.0 09/06/2024
1. Created Forensicator for Linux machines.
2. Re-arranged the Directory to show that Forensicator has moved from just a powershell tool to a suite of tools.

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

