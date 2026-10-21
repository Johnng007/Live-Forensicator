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

* Windows Artifact Analysis collection — raw Shimcache/Amcache/Prefetch/UserAssist/BAM/Autoruns/LNK/Jump List/Shellbag/$MFT/$UsnJrnl/SRUM/Defender quarantine/WER/Windows Search database/Recycle Bin/Notifications/BITS/Windows Timeline artifacts for Forensicator Core, plus each registry hive's own `.LOG1`/`.LOG2` transaction logs for Core to replay into a more complete hive
* Event Log collection (targeted Event IDs), plus a configurable richer channel export (Sysmon, Defender Operational, PowerShell, TaskScheduler, WMI-Activity, BITS-Client, RDP, etc.) ready for Forensicator-Core's Log Analysis feature
* Browser history extraction and IOC matching
* Built-in triage: Sigma rule integration (opt-in, off by default — see `config.json`: `sigma.enabled`) and malware hash matching (e.g., abuse.ch feeds)
* Forensicator AI — optional, per-finding AI verdicts from a local or commercial LLM

---

## 🧩 Analyzing the Output in Forensicator Core

**[Forensicator Core](https://github.com/Raptormatics/Forensicator-Core)** is the free, self-hosted analysis platform for this collector's output. Each part of a run's `<HOSTNAME>\` output folder uploads to its own Core section:

| Collector output | Collected with | Core section |
|---|---|---|
| `artifacts\` (the whole folder) | `-WINARTIFACTS` | **Windows Artifact Analysis** → *Collector folder* mode. Each file is routed to its parser by path and verified against the SHA-256 in `WindowsArtifacts\CollectionManifest\`. LOG4J, GPResult, and RAM-triage extras from the same folder are picked up too. |
| `artifacts\EVTX\*.evtx` and `artifacts\EVTX\LogChannels\*.log` | `-EVTX` | **Log Analysis**. Upload either the raw `.evtx` or the single-line Event XML. Built-in decoders cover Security, Sysmon, PowerShell, Defender, Task Scheduler, WMI-Activity, BITS-Client, RDP, and the AD/DNS channels. |
| `artifacts\RAM\<HOSTNAME>.raw` | `-RAM` | **RAM Analysis** (Volatility3) |
| `artifacts\PCAP\<HOSTNAME>.pcapng` | Network tracing | **PCAP Analysis** |
| `investigation.zip` | Every run | **Investigations**. Normalized findings, a timeline, and attack-path reconstruction, rolled into the host's profile. |

Core also enriches IOCs against VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, and MalwareBazaar. It groups uploads under Cases, correlates findings across them, and produces executive and technical reports.

👉 Installation and setup (Docker or a Linux machine or VM): https://github.com/Raptormatics/Forensicator-Core

---

## 🔨 Usage

```powershell
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Execute
.\Forensicator.ps1 <parameters>
```
<a href="https://docs.forensicator.io/">See full Usage</a>
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

📘 Full setup guide (all providers, tuning, troubleshooting): <a href="https://docs.forensicator.io">docs.forensicator.io</a>

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
* SYSVOL/GPO analysis — AD-side GPO inventory, AD/GPT version comparison, recursive policy/script file inventory with SHA-256, bounded collection of SYSVOL files, GPO write-ACL review, and Group Policy Preferences `cpassword` detection (value is not emitted)
* Critical directory-object write-ACL review (domain root, AdminSDHolder, Domain Controllers OU) and AD CS certificate-template ACL/configuration inventory
* Enterprise trust, DNS zone, and `repadmin` replication-health inventories
* Directory Service Access Event 4662 export when generated by configured auditing/SACLs
* AD CS request/issuance/denial audit events (4886–4888) from the local CA's Security log when the Certification Authority service is installed; enterprise CA/template metadata is queried from AD
* Privileged group membership (Domain/Enterprise/Schema Admins, Operators)
* KRBTGT account age
* Service Principal Names — Kerberoasting exposure
* Kerberos delegation (unconstrained, constrained, RBCD)
* DCSync rights enumeration
* Privileged & Kerberos security events, directory object changes
* WMI permanent event subscriptions
* Known AD attack tooling process cross-check (configurable via `config.json`)
* Domain password policy, FSMO role owners, LDAP/SMB signing configuration

SYSVOL file hashing and copying are capped per file by `ad.sysvol_hash_max_file_mb` (10 MB default) and `ad.sysvol_collect_max_file_mb` (25 MB default), with a 500 MB total-copy cap (`ad.sysvol_collect_max_total_mb`). These caps do not limit metadata inventory or the small XML `cpassword` check. ACL results are triage candidates, not automatic vulnerability verdicts. Event 4662 and AD CS audit evidence require the corresponding Windows auditing to have been enabled; absent events do not establish that the activity did not occur. Most checks run only on detected DCs; AD CS configuration is queried forest-wide, but local CA event records are only read on the machine hosting that CA. Adding `Directory Service`, `DFS Replication`, and `DNS Server` to `logChannels.channels` also enables their EVTX/XML collection under `-EVTX`.

The expanded SYSVOL collection can contain sensitive Group Policy scripts and configuration; protect the output as evidence. Inventory CSVs, replication output, trust/DNS data, ACL reviews, AD CS metadata, and full 4662 XML are written under `investigation\ad`.

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

* Registry hives — `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `Amcache.hve`, and every user profile's `NTUSER.DAT`/`UsrClass.dat` (Shimcache, Amcache, UserAssist, BAM/DAM, Autoruns, Shellbags)
* Registry transaction logs — each hive's own `.LOG1`/`.LOG2` files ("dirty page" transactions not yet flushed into the hive itself), collected alongside it; Forensicator Core replays them for a more complete/accurate hive before parsing
* Prefetch — every `.pf` file in `C:\Windows\Prefetch`
* LNK files — every `.lnk` found under `C:\Users`
* Jump Lists — every `.automaticDestinations-ms`/`.customDestinations-ms` per profile
* `$MFT` — the volume's Master File Table, read off the volume by following its own data runs, so a fragmented `$MFT` is collected whole
* `$UsnJrnl:$J` — the USN change journal's data stream, plus its raw `fsutil usn queryjournal` metadata (journal ID, USN range, max size, etc.), saved alongside it unparsed
* `SRUDB.dat` — the SRUM (System Resource Usage Monitor) ESE database, plus the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions` registry data needed to map its GUID-named tables to the actual SRUM provider each one is
* Windows Defender quarantine — `Quarantine\Entries` and `Quarantine\ResourceData` (both RC4-encrypted by Defender itself before collection, so this isn't live malware bytes)
* Windows Error Reporting — reports/crash metadata under `WER\ReportArchive`/`ReportQueue` (system + per-profile) and per-profile `CrashDumps\*.dmp`, size-capped via `config.json`'s `werCrashDumps.max_dump_size_mb` (default 500 MB) — anything larger is skipped and logged, not collected
* Windows Search databases — `Windows.edb` or `Windows.db`, plus `Windows-gather.db` and its SQLite `-wal`/`-shm` sidecar files when present
* Recycle Bin metadata — `$I*` files by default. Optional `$R*` payload collection is controlled by `winArtifacts.collect_recycle_payloads` and capped per file by `recycle_payload_max_size_mb` (default off; 100 MB).
* NTFS `$LogFile` and Windows Defender DetectionHistory/Support files (best-effort).
* SAM and DEFAULT registry hives and transaction logs, in addition to SYSTEM/SOFTWARE/SECURITY.
* Historical SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT hives from `Windows.old`, `RegBack`, and accessible existing shadow-copy restore points, stored under `Registry\Historical` or `Registry\RestorePoints` to retain provenance.
* WMI permanent event subscription instances (filters, consumers, and bindings) in `WMI\PermanentSubscriptions.json` on all hosts. Optional WBEM repository file capture is controlled by `winArtifacts.collect_wbem_repository` (default off).
* Optional `$MFT` and `$UsnJrnl:$J` collection from other local NTFS drive-letter volumes with `winArtifacts.collect_additional_ntfs_volumes` (default off; creates a VSS snapshot per volume when possible).
* Optional `pagefile.sys`, `hiberfil.sys`, and `swapfile.sys` collection via `winArtifacts.collect_memory_files` (default off; per-file cap `memory_file_max_size_mb`, default 1024 MB). These are attempted from the live volume; Windows may deny access or the size cap may skip them, and either outcome is logged.
* Notification platform database — `wpndatabase.db` (or the older `appdb.dat`) per profile
* BITS job database — `qmgr0.dat`/`qmgr1.dat`, or `qmgr.db` on builds that use the newer ESE-based store
* Windows Timeline database — `ActivitiesCache.db` per user profile, under a randomly-named `ConnectedDevicesPlatform\<UUID>\` subfolder this collector globs for

`SYSTEM`/`SOFTWARE`/`SAM`/`SECURITY`/`DEFAULT`/`Amcache.hve` (and their `.LOG1`/`.LOG2` transaction logs), NTUSER.DAT/UsrClass.dat (and their own `.LOG1`/`.LOG2`)/`wpndatabase.db`/`ActivitiesCache.db`, `$MFT`, `$UsnJrnl:$J`, `SRUDB.dat`, `$LogFile`, and Windows Search databases are read through a Volume Shadow Copy when available. If VSS isn't available, loaded registry hives fall back to `reg.exe save`; other locked files are attempted as plain copies where possible, with failures logged. Memory files are a separate opt-in live-volume copy and may be inaccessible while Windows is running. Additional-volume NTFS collection is also opt-in and limited to local drive-letter volumes.

Registry transaction sidecars are enumerated from each source directory before collection. A sidecar that is absent is recorded as `Skipped` in the manifest at INFO level, since `.LOG1`/`.LOG2` files are optional and may not exist for every hive. VSS file copies use .NET file I/O and source probes so failures include the snapshot ID, parent-directory status, source-file status, and underlying exception. If a user profile resides on a different drive volume, the collector attempts a separate VSS snapshot for that volume; when it cannot create one, the profile hives are explicitly recorded as skipped with the volume identified.

### Application-specific artifacts and collection manifest

The `-WINARTIFACTS` collection now includes application artifacts in addition to the Windows artifacts listed above:

* Cloud client metadata and logs for OneDrive, Dropbox, and Google Drive. The defaults collect client state and logs, not synced cloud documents. For OneDrive this includes each log folder's `general.keystore`, the key Forensicator Core uses to de-obfuscate the paths, URLs and account names in the `.odl` logs — protect it like the logs themselves.
* Logs from selected third-party endpoint security products (including CrowdStrike, SentinelOne, Sophos, ESET, Malwarebytes, Bitdefender, McAfee, and Trend Micro) and remote-access tools (including AnyDesk, TeamViewer, ScreenConnect, RustDesk, Splashtop, and LogMeIn).
* Windows Notepad recovery/session state and Notepad++ unsaved backups and session metadata.
* Custom application log/data directories and file patterns, configurable under `applicationArtifacts.custom_targets` in `config.json`.

These collectors run with `-WINARTIFACTS` and are enabled by default in `applicationArtifacts`. Set `applicationArtifacts.enabled` to `false` to disable them all, or set one of `collect_cloud_storage_metadata`, `collect_security_product_logs`, `collect_remote_access_logs`, or `collect_notepad_sessions` to `false` to disable an individual group. The default per-file cap is 64 MB and the combined cap for these application artifacts is 512 MB. Over-cap files are skipped and recorded.

Custom targets are recursively searched directories. `%USERPROFILE%`, `%APPDATA%`, and `%LOCALAPPDATA%` expand for each discovered profile; `%PROGRAMDATA%`, `%PROGRAMFILES%`, and `%PROGRAMFILES(X86)%` expand from the collector environment. Example:

```json
"applicationArtifacts": {
  "custom_targets": [
    {
      "name": "Example VPN logs",
      "paths": ["%PROGRAMDATA%\\ExampleVPN\\Logs"],
      "file_patterns": ["*.log", "*.txt", "*.json"],
      "max_file_size_mb": 32
    }
  ]
}
```

Collected files are stored under `artifacts\\WindowsArtifacts\\ApplicationArtifacts\\<target>\\<profile>`. Protect these files as sensitive evidence: recovery state and application logs can contain user content, account identifiers, or operational details.

The collector writes `artifact-collection-manifest.csv`, `artifact-collection-manifest.json`, and `artifact-collection-summary.json` under `artifacts\\WindowsArtifacts\\CollectionManifest\\`. The manifests include source and destination paths, file sizes, SHA-256 hashes, source/output timestamps and attributes, status, and duplicate references. Standard file copies are hashed before and after copying; a mismatch is reported as `IntegrityMismatch`. Raw-read outputs are hashed after acquisition. Identical content is retained once, with later source paths reported as `Deduplicated`. Missing files and files skipped by configured caps are reported as `Skipped`; copy and hashing errors are also recorded. Per-artifact collection messages are also written to the terminal transcript; the complete collection manifest and structured logs remain available for review.

### 🚀 Extended Features

* RAM acquisition
* Network tracing → PCAPNG
* Web server logs (IIS, Tomcat)
* Browser history (all users)
* Ransomware pattern detection
* EVTX export — System/Security/Application as raw `.evtx` (archival), plus a configurable richer channel list exported both as raw `.evtx` and Core-ready single-line Event XML (`config.json`: `logChannels.channels`). XML remains time/event-count bounded; native EVTX is a full channel export.
* Detection Insight into each collected data with Mitre Mapping.
* Structured per-check JSON output under `investigation/`, for Forensicator Core upload
* Investigation archive — a hashed, zipped copy of the investigation folder with a Readme pointing to Forensicator Core for automated analysis
* Forensicator AI — optional, per-finding AI verdicts (local Ollama or a commercial LLM), off by default (see [🤖 Forensicator AI](#-forensicator-ai))

The `-RANSOMWARE` scan downloads its filename-pattern feed from `ransomware_extension_source` in `config.json` (the Danny Roemhild ransomware-fileext-list raw text feed) only when `Forensicator-Share\ransomware_extensions.txt` does not already exist. Operators may place or update that text file themselves to avoid the download. Upstream entries are wildcard filename patterns, not all simple extensions; they are matched case-insensitively against file names. Treat matches as triage indicators, not proof of encryption.

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

<a href="https://docs.forensicator.io"> Docs</a>

