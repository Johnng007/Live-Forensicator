<h1 align="center">🛡️ Forensicator (Windows) 🛡️</h1>

<h3 align="center">
PowerShell-based Incident Response & Live Forensics Toolkit
</h3>

<p align="center">
Advanced event log analysis, detection logic, and forensic artifact collection for Windows systems.
</p>

<img width="1953" height="805" alt="forensicator logo" src="https://github.com/user-attachments/assets/bddffeb5-0352-4f30-9abd-55f80fbb1298" />

---

# 🤔 About

**Forensicator (Windows)** is a PowerShell-based incident response and live forensics tool designed to assist investigators in rapidly collecting artifacts and analyzing systems for malicious activities.

It enables:

* Rapid triage of compromised systems
* Detection of suspicious behavior via Event Logs
* Identification of anomalies and indicators of compromise
* Generation of structured, investigation-ready output

Key capabilities include:

* Event Log analysis (targeted Event IDs)
* Sigma rule integration
* Malware hash matching (e.g., abuse.ch feeds)
* Browser history extraction and IOC matching

---

# 🔨 Usage

```powershell
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execute
.\Forensicator.ps1 <parameters>
```
<a href="https://forensicator.io/walkthrough.html">See full Usage</a>
---

# ⚠️ Important Notes

* Run as Administrator for full visibility
* Execution may trigger IDS/IPS alerts
* Configurable via `config.json`

---

# 🔐 Artifact Integrity & Encryption

Artifacts can be encrypted using AES:

* Ensures secure transport
* Preserves evidentiary integrity
* Supports chain-of-custody requirements

```powershell
.\Forensicator.ps1 -ENCRYPTED ENCRYPTED
```

> ⚠️ Not backward compatible before v4.1.1

---

# 🧠 Detection Capabilities

Forensicator detects suspicious activity through:

* Event Log correlation
* Sigma-based detections
* Malicious hash matching
* Browser history IOC analysis

---

# 📊 Data Collected

## 👤 User & Account Information

* Current user
* User accounts & groups
* Logon sessions
* Admin accounts

## 💻 System Information

* Installed programs
* OS & environment details
* Hotfixes
* Defender status

## 🌐 Network Information

* Active connections & processes
* DNS cache
* Firewall rules
* RDP history
* SMB sessions & shares

## ⚙️ Processes & Persistence

* Running processes
* Startup items
* Scheduled tasks
* Services
* Registry persistence

## 📜 Event Log Analysis

* Logon events
* Account changes
* Process execution
* Object access
* Suspicious activities

## 🏛️ Active Directory (Domain Controllers only)

Automatically detected and enabled only when the host is a Domain Controller:

* NTDS database integrity & metadata
* SYSVOL / GPO script analysis (suspicious keyword matching, configurable via `config.json`)
* Privileged group membership (Domain/Enterprise/Schema Admins, Operators)
* KRBTGT account age
* Service Principal Names — Kerberoasting exposure
* Kerberos delegation (unconstrained, constrained, RBCD)
* DCSync rights enumeration
* Privileged & Kerberos security events, directory object changes
* WMI permanent event subscriptions
* Known AD attack tooling process cross-check (configurable via `config.json`)
* Domain password policy, FSMO role owners, LDAP/SMB signing configuration

## 🗄️ Microsoft SQL Server (MSSQL, if installed)

Automatically detected and enabled only when a SQL Server instance is present:

* Service inventory & service account exposure
* Dangerous configuration options — `xp_cmdshell`, OLE Automation Procedures, CLR integration
* `sysadmin` role membership & `sa` account status
* Linked servers & `TRUSTWORTHY` database enumeration
* SQL Server Agent jobs with CmdExec/ActiveScripting/PowerShell steps (suspicious keyword matching, configurable via `config.json`)
* Recently created/modified SQL logins
* SQL Server login failure events (Event ID 18456)

## 📘 Microsoft SharePoint Server (if installed)

Automatically detected and enabled only when SharePoint Server is present:

* Farm overview (build version, farm services running)
* Service & IIS application pool account exposure
* Suspicious IIS worker process (`w3wp.exe`) child processes — webshell/RCE execution signature
* Webshell / dropped-file scan across LAYOUTS and web application content (suspicious keyword matching, configurable via `config.json`)
* `web.config` ViewState/`machineKey` misconfiguration review
* IIS log scan for known SharePoint exploit URI patterns (configurable via `config.json`)

## 🔎 Additional Checks

* USB devices
* PowerShell history
* Recently created files
* Suspicious executables (AppData, Temp, Downloads)
* BitLocker key extraction

## 🚀 Extended Features

* RAM acquisition
* Network tracing → PCAPNG
* Web server logs (IIS, Tomcat)
* Browser history (all users)
* Ransomware pattern detection
* EVTX export
* Detection Insight into each collected data with Mitre Mapping.
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload
* Investigation archive — a hashed, zipped copy of the investigation folder with a Readme pointing to Forensicator Enterprise for automated analysis

---

# 📸 Screenshots

<details>
<summary>Terminal Output</summary>

<img width="765" height="1127" src="https://github.com/user-attachments/assets/8e49146b-a1e4-4c28-8057-6071903baf75" />

<img width="1398" height="390" alt="image" src="https://github.com/user-attachments/assets/c2d573d6-47fd-485f-8cf8-8c4ea082ff5e" />


</details>

<details>
<summary>HTML Dashboard</summary>

<img width="1392" height="913" alt="image" src="https://github.com/user-attachments/assets/60ab5fbb-0a84-4070-a5f1-901773e01096" />
<br>
<img width="1383" height="908" alt="image" src="https://github.com/user-attachments/assets/c916c86f-10d2-4b24-8601-6cbd440baad3" />
<br>
<img width="1387" height="920" alt="image" src="https://github.com/user-attachments/assets/6cd350a4-830e-4513-922c-fc7140d13e71" />
<br>
<img width="1390" height="914" alt="image" src="https://github.com/user-attachments/assets/be3f2d07-1573-4e36-85b5-9b2191c9cfb6" />
<br>
<img width="1382" height="913" alt="image" src="https://github.com/user-attachments/assets/2d39317f-44de-45c6-9d6a-8d328f6ae4b8" />


</details>

---

# 🤝 Contributing

Pull requests are welcome.
For major changes, please open an issue first to discuss your proposal.

---

# 📄 License

MIT License
https://mit.com/licenses/mit/

---

# ☕ Full Usage & WalkThrough

<a href="https://opendocs.forensicator.io">
  <img width="239" height="31" alt="image" src="https://github.com/user-attachments/assets/f4cb261c-65c8-4592-a42e-6b9ba54dc990" />

</a>

