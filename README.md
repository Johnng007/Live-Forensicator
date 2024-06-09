<h1 align="center">📝 Forensicator 📝</h1>
<h3 align="center">WINDOWS(PowerShell) | LINUX(Bash) | MacOS(Bash) SCRIPTS TO AID LIVE FORENSICS & INCIDENCE RESPONSE</h3>
                                               
```bash


___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          


```


# 🤔 ABOUT

Live Forensicator is part of the Black Widow Toolbox, its aim is to assist Forensic Investigators and Incidence responders in carrying out a quick live forensic investigation.
<p>It achieves this by gathering different system information for further review for anomalous behaviour or unexpected data entry, it also looks out for unusual files or activities and points it out to the investigator.</p>
<p>It is paramount to note that these scripts have no inbuilt intelligence its left for the investigator to analyse the output and decide on a conclusion or decide on carrying out more deeper investigation.</p>

# 🖳 WINDOWS
<p>The windows version of Forensicator is written in Powershell.</p>
<p> Forensicator analysis Event Logs, it querries the event logs for certain log IDs that might point to an unusual activity or compromise. </p>
[View More On The Windows Tree](https://github.com/Johnng007/Live-Forensicator/tree/main/Windows)


# 👨‍💻 MacOS
The MacOS version is written in Bash.
[View More On The MacOS Tree](https://github.com/Johnng007/Live-Forensicator/tree/main/MacOS)


# 👩‍💻 LINUX
The Linux version is written in Bash.
[View More On The MacOS Tree](https://github.com/Johnng007/Live-Forensicator/tree/main/Linux)
> #### NOTE: 
> The Bash codes were written for cross compatibility so therefore efforts were made to use factory shipped commands and avoid secoundary utitlities like `net-tools`.



## ✍ Notes
* Run the scripts as a priviledged user to get value.<br>

* Forensicator Activities may be flagged by IDS or IPS Solutions so take note.<br>
  The results are outputed in nice looking html files with an index file. <br>

* You can find all extracted Artifacts in the script's working directory.

* <p>Forensicator Has the ability to Search through all the folders within a system looking for files with similar extensions as well known Ransomwares, Albeit this     search takes long but its helpful if the Alert you recieved is related to a Ransomware attack</p>

* <p>Forensictor can capture network traffic using netsh trace, this is useful when your investigation has to do with asset communicating with known malicious IPs,       this way you can parse the pcapng file to wireshark and examine for C&C servers. By Defult i set the capture to take 120secs</p>

* <p>Sometimes it may be paramount to maintain the integrity of the Artifacts, where lawyers may argue that it might have been compromised on transit to your lab.
  Forensicator can now encrypt the Artifact with a unique randomely generated key using AES algorithm, you can specify this by using the -ENCRYPTED parameter. You can   decrypt it at will anywhere anytime even with another copy of Forensicator, just keep your key safe. This task is performed by the FileCryptography.psm1 file
> #### NOTE: 
> This feature is only currently available in the Windows Module..
</p>

* <p>In the Windows module Forensictor looks out for suspicious activities within the Event Log, it has a long list of malicious executables, and powershell commands which it queries the event log against.</p>



## 🤔 MORE TOOLS
Want to check out other Black Widow Tools?
1. Anteater - A python based web reconnaisence tool. https://github.com/Johnng007/Anteater
2. Nessus Pro API - A powershell Script to Export and Download Nessus Scan Results via Nessus API. https://github.com/Johnng007/PowershellNessus

## ✨ ChangeLog
```bash
Linux: v1.0 09/06/2024
1. Created Forensicator for Linux machines.
2. Re-arranged the Directory to show that Forensicator has moved from just a powershell tool to a suite of tools.

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

