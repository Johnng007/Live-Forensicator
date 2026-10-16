<h1 align="center">🛡️ Forensicator Artifact Collector (Windows) 🛡️</h1>

<h3 align="center">
PowerShell-based Forensic Artifact Collector
</h3>

<p align="center">
Collects forensic artifacts from live windows systems for analysis in Forensicator Core. Includes a built-in HTML report for quick triage and preliminary findings review.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Live Forensicator (Windows)** is a PowerShell-based forensic artifact collector — it rapidly gathers the evidence an investigator needs from a live Windows host and packages it for Forensicator Core, with built-in on-host triage along the way.

It enables:

* Rapid artifact collection from compromised/live systems
* Generation of structured, investigation-ready output
* Built-in triage — detection of suspicious behavior via Event Logs, and identification of anomalies and indicators of compromise

Key capabilities include:

* Windows Artifact Analysis collection — raw Shimcache/Amcache/Prefetch/UserAssist/BAM/Autoruns/LNK/Jump List/Shellbag/$MFT/$UsnJrnl/SRUM/Defender quarantine/WER/Windows Search database/Recycle Bin/Notifications/BITS artifacts for Forensicator Core
* Event Log collection (targeted Event IDs), plus a configurable richer channel export (Sysmon, Defender Operational, PowerShell, TaskScheduler, WMI-Activity, BITS-Client, RDP, etc.) ready for Forensicator-Core's Log Analysis feature
* Browser history extraction and IOC matching
* Built-in triage: Sigma rule integration and malware hash matching (e.g., abuse.ch feeds)
* Forensicator AI — optional, per-finding AI verdicts from a local or commercial LLM

---

## 🔨 Usage

```powershell
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execute
.\Forensicator.ps1 <parameters>
```
<a href="https://opendocs.forensicator.io/">See full Usage</a>
---

## ⚠️ Important Notes

* Run as Administrator for full visibility
* Execution may trigger IDS/IPS alerts
* Configurable via `config.json`

---

## 🔐 Artifact Integrity & Encryption

Artifacts can be encrypted using AES:

* Ensures secure transport
* Preserves evidentiary integrity
* Supports chain-of-custody requirements

```powershell
.\Forensicator.ps1 -ENCRYPTED ENCRYPTED
```

> ⚠️ Not backward compatible before v4.1.1

---

## 🤖 Forensicator AI

Off by default. When enabled, each finding is sent to a local or commercial LLM as it's collected, and gets a real, plain-language verdict — shown right in the report's tooltip under **AI Analysis**, alongside the existing detection guidance.

**Quick setup (local LLM via Ollama):**

```powershell
# 1. Install Ollama (https://ollama.com) and pull a model
ollama pull mistral:7b-instruct

# 2. Enable it in config.json
```
```jsonc
"ai": {
  "enabled": true,
  "provider": "ollama",
  "base_url": "http://localhost:11434",
  "model": "mistral:7b-instruct"
}
```

Run Forensicator as usual — no other flags needed. Prefer a commercial API instead (OpenAI, Anthropic, Azure OpenAI, or any OpenAI-compatible endpoint)? Set `provider` accordingly and add your `api_key`.

> ⚠️ Each finding is a real LLM call — enabling this can noticeably extend total run time, especially on a cold-loaded model.

📘 Full setup guide (all providers, tuning, troubleshooting): <a href="https://opendocs.forensicator.io">opendocs.forensicator.io</a>

---

## 🧠 Built-in Triage

On top of collection, Forensicator detects suspicious activity on the spot through:

* Event Log correlation
* Sigma-based detections
* Malicious hash matching
* Browser history IOC analysis

---

## 📊 Data Collected

### 👤 User & Account Information

* Current user
* User accounts & groups
* Logon sessions
* Admin accounts

### 💻 System Information

* Installed programs
* OS & environment details
* Hotfixes
* Defender status

### 🌐 Network Information

* Active connections & processes
* DNS cache
* Firewall rules
* RDP history
* SMB sessions & shares

### ⚙️ Processes & Persistence

* Running processes
* Startup items
* Scheduled tasks
* Services
* Registry persistence

### 📜 Event Log Analysis

* Logon events
* Account changes
* Process execution
* Object access
* Suspicious activities

### 🏛️ Active Directory (Domain Controllers only)

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

### 🗄️ Microsoft SQL Server (MSSQL, if installed)

Automatically detected and enabled only when a SQL Server instance is present:

* Service inventory & service account exposure
* Dangerous configuration options — `xp_cmdshell`, OLE Automation Procedures, CLR integration
* `sysadmin` role membership & `sa` account status
* Linked servers & `TRUSTWORTHY` database enumeration
* SQL Server Agent jobs with CmdExec/ActiveScripting/PowerShell steps (suspicious keyword matching, configurable via `config.json`)
* Recently created/modified SQL logins
* SQL Server login failure events (Event ID 18456)

### 📘 Microsoft SharePoint Server (if installed)

Automatically detected and enabled only when SharePoint Server is present:

* Farm overview (build version, farm services running)
* Service & IIS application pool account exposure
* Suspicious IIS worker process (`w3wp.exe`) child processes — webshell/RCE execution signature
* Webshell / dropped-file scan across LAYOUTS and web application content (suspicious keyword matching, configurable via `config.json`)
* `web.config` ViewState/`machineKey` misconfiguration review
* IIS log scan for known SharePoint exploit URI patterns (configurable via `config.json`)

### 🔎 Additional Checks

* USB devices
* PowerShell history
* Recently created files
* Suspicious executables (AppData, Temp, Downloads)
* BitLocker key extraction

### 🗃️ Windows Artifact Analysis (opt-in, `-WINARTIFACTS`)

Raw artifact files for upload to Forensicator Core's Windows Artifact Analysis feature — this collects the files themselves, not a summary:

* Registry hives — `SYSTEM`, `SOFTWARE`, `SECURITY`, `Amcache.hve`, and every user profile's `NTUSER.DAT`/`UsrClass.dat` (Shimcache, Amcache, UserAssist, BAM/DAM, Autoruns, Shellbags)
* Prefetch — every `.pf` file in `C:\Windows\Prefetch`
* LNK files — every `.lnk` found under `C:\Users`
* Jump Lists — every `.automaticDestinations-ms`/`.customDestinations-ms` per profile
* `$MFT` — the volume's Master File Table
* `$UsnJrnl:$J` — the USN change journal's data stream, plus its raw `fsutil usn queryjournal` metadata (journal ID, USN range, max size, etc.), saved alongside it unparsed
* `SRUDB.dat` — the SRUM (System Resource Usage Monitor) ESE database, plus the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions` registry data needed to map its GUID-named tables to the actual SRUM provider each one is
* Windows Defender quarantine — `Quarantine\Entries` and `Quarantine\ResourceData` (both RC4-encrypted by Defender itself before collection, so this isn't live malware bytes)
* Windows Error Reporting — reports/crash metadata under `WER\ReportArchive`/`ReportQueue` (system + per-profile) and per-profile `CrashDumps\*.dmp`, size-capped via `config.json`'s `werCrashDumps.max_dump_size_mb` (default 500 MB) — anything larger is skipped and logged, not collected
* Windows Search database — `Windows.edb` (or `Windows.db` on builds that use that name)
* Recycle Bin metadata — `$I*` files only (original path, deleted time, size — not the `$R*` payload)
* Notification platform database — `wpndatabase.db` (or the older `appdb.dat`) per profile
* BITS job database — `qmgr0.dat`/`qmgr1.dat`, or `qmgr.db` on builds that use the newer ESE-based store

`SYSTEM`/`SOFTWARE`/`SECURITY`/`Amcache.hve`, NTUSER.DAT/UsrClass.dat/`wpndatabase.db`, `$MFT`, `$UsnJrnl:$J`, `SRUDB.dat`, and `Windows.edb` are all held open by Windows while running, so this uses a Volume Shadow Copy snapshot to read them (created and removed automatically — standard, auditable IR technique, same as KAPE/Velociraptor use). If VSS isn't available, registry hives fall back to `reg.exe save` for whichever are currently loaded; the rest have no equivalent fallback and are only collected where accessible without it. The journal metadata, SRUM registry data, Defender quarantine, WER, Recycle Bin, and BITS artifacts are not VSS-locked and are collected unconditionally via a plain best-effort copy.

### 🚀 Extended Features

* RAM acquisition
* Network tracing → PCAPNG
* Web server logs (IIS, Tomcat)
* Browser history (all users)
* Ransomware pattern detection
* EVTX export — System/Security/Application as raw `.evtx` (archival), plus a configurable richer channel list exported as Core-ready single-line Event XML (`config.json`: `logChannels.channels`)
* Detection Insight into each collected data with Mitre Mapping.
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload
* Investigation archive — a hashed, zipped copy of the investigation folder with a Readme pointing to Forensicator Enterprise for automated analysis
* Forensicator AI — optional, per-finding AI verdicts (local Ollama or a commercial LLM), off by default (see [🤖 Forensicator AI](#-forensicator-ai))

---

## 📸 Screenshots

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

<details>
<summary>Terminal Output with Forensicator AI</summary>

<img width="1293" height="762" alt="image" src="https://github.com/user-attachments/assets/2306f048-8a22-4203-92d5-934fb761c62b" />

</details>

<details>
<summary>AI Analysis</summary>

<img width="1731" height="955" alt="image" src="https://github.com/user-attachments/assets/89ab171c-f08d-4add-ad60-33f2e464c1d8" />
<br>
<img width="1730" height="649" alt="image" src="https://github.com/user-attachments/assets/ae56795f-9f2c-4a44-b020-76b16946bce5" />
<br>
<img width="1730" height="862" alt="image" src="https://github.com/user-attachments/assets/5ab5104c-3d3c-43da-8e58-fceddfca7ca0" />
<br>
<img width="1729" height="860" alt="image" src="https://github.com/user-attachments/assets/cc99d059-a69d-4d65-b652-199d7ab1f7be" />
<br>
<img width="1728" height="854" alt="image" src="https://github.com/user-attachments/assets/d9d8721f-3cf9-4196-9404-fa63bd385c51" />
<br>
<img width="1732" height="865" alt="image" src="https://github.com/user-attachments/assets/124dca06-757e-4839-92f1-b9136022fd7c" />
<br>
<img width="1734" height="854" alt="image" src="https://github.com/user-attachments/assets/d7b7e764-40e4-4783-bcc2-4a5dcfd532db" />
<br>
<img width="1730" height="946" alt="image" src="https://github.com/user-attachments/assets/3ca78232-66ca-42ae-adaf-32320b4e47fc" />

</details>

---

## 🤝 Contributing

Contributions are welcome.

* Open an issue to discuss major changes
* Submit pull requests with clear descriptions
* Focus on accuracy, clarity, and usability

---

## 📄 License

Live-Forensicator is open-source software licensed under the **Apache License 2.0**.

Copyright © 2026 Raptormatics.

You are free to use, reproduce, modify, and distribute Live-Forensicator in accordance with the terms of the Apache License 2.0.

See the [`LICENSE`](LICENSE) file for the full license text.

### Third-Party Components

Live-Forensicator may include or interact with third-party tools, libraries, scripts, or components that are distributed under their own licenses. Those licenses remain applicable to their respective components.

Users are responsible for complying with the applicable licenses and terms of any third-party components they use with Live-Forensicator.


---

## ☕ Documentation

<a href="https://docs.forensicator.io"> OpenDocs</a>

