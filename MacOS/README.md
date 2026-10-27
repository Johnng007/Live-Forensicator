<h1 align="center">🛡️ Forensicator Artifact Collector (macOS) 🛡️</h1>

<h3 align="center">
Bash-based Forensic Artifact Collector
</h3>

<p align="center">
Collects forensic artifacts from macOS systems systems for analysis in Forensicator Core. Includes a built-in HTML report for quick triage and preliminary findings review.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Forensicator (macOS)** is a Bash-based forensic artifact collector — it rapidly gathers the evidence an investigator needs from a live macOS host and packages it for Forensicator Core, with built-in on-host triage along the way.

It enables:

* Collection of key forensic artifacts (system, user, network, process, file)
* macOS-native integrity checks (SIP, Gatekeeper, FileVault, Signed System Volume, code signatures)
* Built-in triage — MITRE ATT&CK-mapped detection logic, backed by a best-effort Sigma rule engine

Apple restricts real process-creation telemetry (comparable to Linux `auditd` or Windows Sysmon) to its Endpoint Security Framework, which requires a signed system extension with a special Apple-issued entitlement — not something a plain script can obtain. Where that limits a check, this README says so plainly rather than overclaiming.

---

## ⚙️ Key Features

* Raw artifact collection (`-A`) for Forensicator Core's Host Artifacts: account records, launch items, login items, code signatures, TCC, downloads, KnowledgeC, XProtect, FSEvents, histories, a process table, unified log exports and a filesystem timeline, with a SHA-256 manifest
* FileVault, SIP, Gatekeeper, and TCC privacy database inspection
* Signed System Volume (SSV) seal status and application code-signature verification (the macOS analog of package-checksum verification — there is no `rpm`/`dpkg` here)
* Credential-file tampering timeline (mtime vs. ctime on passwd/sudoers/authorized_keys)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)
* Browser history extraction (Safari, Chrome, Firefox, Edge, Brave)
* Persistence discovery (LaunchDaemons, LaunchAgents, login items, cron)
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, plus a hashed investigation archive for Forensicator Enterprise upload
* Single-page HTML dashboard report
* Built-in triage: detection engine, MITRE ATT&CK-mapped (reverse shells, attack tools, brute force, SIP/Gatekeeper tampering, dylib hijacking, timestomping, PATH hijacking, deleted-binary execution, and more)
* Best-effort Sigma rule engine sourced from real SigmaHQ community rules, evaluated against the unified log (`log show`)
* Malware hash matching and malicious URL/domain matching, with auto-updating abuse.ch/URLhaus feeds
* Ransomware extension detection, and browser-history malicious-URL IOC matching

> ⚠️ The Sigma engine requires `python3`. If it isn't present, that step is skipped cleanly and the rest of the collection is unaffected. Most Sigma rules here expect command-line/parent-process data the unified log doesn't record — expect low hit rate on rules other than the ones that only need a process's own image path. A quiet Sigma tab does not mean nothing happened; it means the telemetry those rules need isn't accessible without Endpoint Security Framework.

---

## 📦 Optional Dependencies

For additional capabilities:

```bash
osxpmem         → RAM acquisition (bundled; Intel Macs only, see below)
python3         → Sigma rule engine, Forensicator AI, and the zip/investigation-archive fallback if `zip` is unavailable
```

> Forensicator works without these, but functionality may be limited.

> `python3` comes with the Xcode Command Line Tools (`xcode-select --install`). Without them, `/usr/bin/python3` is only a stub that opens an install dialog on the screen; Forensicator detects this and skips the Python steps instead of running it.

> **RAM on macOS:** the bundled osxpmem works by loading its own kernel extension, so it only works on Intel Macs that still allow third-party kernel extensions (SIP permitting them, and the extension approved under Privacy & Security). Memory acquisition is not possible this way on Apple Silicon; `-r` then records why in `RAM/ram_extraction_error.txt` rather than failing silently.

---

## 🔨 Usage

```bash
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Navigate to the MacOS directory
cd MacOS

# Make executable
chmod +x forensicator.sh

# Execute
./forensicator.sh <parameters>
```

<a href="https://docs.forensicator.io">See full Usage</a>

---

## 🥊 Examples

```bash
# Basic execution
./forensicator.sh

# Raw artifacts for Forensicator Core (Host Artifacts -> Upload -> Collector folder)
sudo ./forensicator.sh -A

# Help
./forensicator.sh --usage

# Capture network traffic
./forensicator.sh -p

# Ransomware extension detection
./forensicator.sh -s

# Web server logs (Apache/NGINX)
./forensicator.sh -w

# Browser history extraction (also enables browser IOC matching)
./forensicator.sh -b

# Hash check running process executables against the malware hash feed
./forensicator.sh -H

# RAM capture (osxpmem, Intel Macs only)
./forensicator.sh -r

# Encrypt collected artifacts (AES-256): leaves <hostname>_artifacts.tar.gz.forensicator
# and <hostname>_key.txt, and removes the unencrypted output
./forensicator.sh -e

# Decrypt (the key file is picked up when it sits next to the encrypted file)
./forensicator.sh -d <hostname>_artifacts.tar.gz.forensicator

# Update this copy (git pull when it is a git checkout) and exit
./forensicator.sh -z

# Combined execution
./forensicator.sh -p -s -w -b -H -e

# Unattended mode
./forensicator.sh -name "Analyst" -case 01123 -title "Incident" -loc "Location" -device HOSTNAME
```

---

## ✍ Notes

* Run the script with `sudo`/as root for full visibility (many checks — TCC database, other users' SSH keys, PATH-hijack scan, package integrity — require it)
* Grant your terminal **Full Disk Access** (System Settings → Privacy & Security → Full Disk Access) or several collectors will silently come back empty
* You can find all extracted artifacts in the script's working directory — open `<hostname>/reports/index.html` to navigate the findings. An earlier collection of the same host is moved aside to `<hostname>.previous-<time>`, never deleted
* Per-user artifacts (launch agents, shell history and startup files, browser history, TCC, quarantine events, recent files) are read from every home folder, not only the account running the script
* IOC lists, hash/URL feed sources, and Sigma engine settings are configurable via `config.json`
* `-A` writes `<hostname>/artifacts/MacArtifacts/` (see below); upload the `artifacts` folder to Forensicator Core
* Operator-maintained hash/IOC lists (`Forensicator-Share/custom_hashes.txt`, `Forensicator-Share/custom_iocs.txt`) are never overwritten by the auto-download feed refresh

---

## 🤖 Forensicator AI

Off by default. When enabled, each finding is sent to a local or commercial LLM as it's collected, and gets a real, plain-language verdict written into that finding's `ai_analysis` field.

**Quick setup (local LLM via Ollama):**

```bash
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

Requires `python3` (no other dependency — HTTP calls go through Python's own standard library, not `curl`).

> ⚠️ Each finding is a real LLM call — enabling this can noticeably extend total run time, especially on a cold-loaded model.

---

## 🧠 Investigation Capabilities

### 👤 User & Account Data

* Active sessions & login history (successful and failed)
* Local user accounts from Directory Services (including accounts created with `dscl`/`sysadminctl`, which `/etc/passwd` never lists), admin/wheel group membership
* SSH authorized keys
* Login and background items (Background Task Management, `sfltool dumpbtm`, macOS 13+)
* Credential-file tampering timeline (mtime vs. ctime — flags forged modification times), including the Directory Services account records
* Multi-user, multi-shell command history (bash/zsh/sh/fish)

### 💻 System Information

* OS version, kernel, hardware, CPU, disk/volume layout, USB devices
* Installed applications, Homebrew package list
* FileVault status
* System Integrity Protection (SIP) status
* Gatekeeper status
* Kernel/kext integrity status — non-Apple loaded kernel extensions, alongside SIP context (the closest macOS analog to Linux's kernel taint flags)
* TCC privacy databases, system and per-user (app access to privacy-sensitive resources)
* Quarantine events database for every user (files downloaded from the internet)

### 🌐 Network Information

* Interfaces, routing table
* Active connections & listening ports
* Firewall rules (pf)
* ARP cache, DNS configuration

### ⚙️ Processes & Persistence

* Running processes
* LaunchCtl services, LaunchDaemons, LaunchAgents (system and every user), with each item's program, arguments and environment read from its plist
* Cron jobs for every user
* Loaded kernel extensions

### 🔎 Security Checks

* SUID/SGID binaries
* World-writable directories/files on `$PATH` (PATH-hijack risk)
* Processes running from deleted binaries (fileless/self-deleting malware indicator, via `lsof +L1` since macOS has no `/proc`)
* Signed System Volume seal status + application code-signature verification (`codesign --verify --deep --strict` across `/Applications`)
* Config-driven IOC matching (suspicious executables and shell commands) against processes, cron, and persistence paths
* Malware hash matching against a running process list, auto-downloaded and refreshed from the abuse.ch feed
* Browser history IOC matching against a malicious-URL feed (URLhaus)

### 🎯 Detection Engine & Sigma

* Built-in detection engine, MITRE ATT&CK-mapped (reverse shells, attack tools, brute force, SIP/Gatekeeper disabled, dylib hijacking via `DYLD_INSERT_LIBRARIES`, non-Apple kexts, timestomping, PATH hijacking, deleted-binary execution, SSV/code-signature tampering, and more)
* Best-effort Sigma rule engine compiled from real SigmaHQ community rules, evaluated against the unified log (`log show`) — see the caveat under Key Features
* All detections feed the same `DETECTIONS/findings.csv` and the HTML report's "Rule Detections" tab

### 📜 Logs

* Authentication logs (SSH connections and sudo commands, via `log show` with a `/var/log/system.log` fallback)
* Unified system log

### 🚀 Extended Features

* Network tracing (PCAP)
* RAM acquisition (osxpmem, Intel Macs only)
* Browser history analysis (Safari, Chrome, Firefox, Edge, Brave, Arc, Vivaldi, Opera; every user)
* Ransomware extension detection
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, plus a hashed investigation archive for Forensicator Enterprise upload

---

## 🧳 Raw Artifacts (`-A`)

`sudo ./forensicator.sh -A` copies the artifacts themselves, for Forensicator Core's **Host Artifacts** (Upload → Collector folder → pick the host folder), which parses them, checks them against built-in macOS detection rules and sends the logs to Log Analysis. Run it as root from a terminal with **Full Disk Access**, or account records, TCC, FSEvents and other users' files will be missing (the manifest records what was skipped and why).

```text
<hostname>/artifacts/MacArtifacts/
├── Files/<absolute path>      raw copies (timestamps, modes and extended attributes kept; SQLite -wal/-shm alongside)
├── Commands/                  sockets, sfltool dumpbtm, codesign.tsv, security settings, applications, kexts,
│                              system extensions, profiles, proxy, authorization rule, packages, ...
├── Processes/processes.tsv    every process with its executable's SHA-256 and signer
├── Timeline/bodyfile.txt      filesystem timeline, with birth times
├── Logs/unifiedlog-*.log      authentication, XProtect/Gatekeeper/TCC and install events (RFC 3339)
└── CollectionManifest/        artifact-collection-manifest.json — SHA-256 of every file
```

Collected: Directory Services account and group records, sudoers, PAM, LaunchAgents/LaunchDaemons, Background Task Management, login window settings, emond, periodic and rc scripts, StartupItems, cron and `at`, shell startup files, every user's shell and Terminal session histories and SSH files, the system and per-user TCC databases, quarantine events, KnowledgeC, install history, XProtect's database, FSEvents, `install.log`/`system.log`, and the code signature of every running executable and launch item program.

Settings in `config.json`: `raw_max_file_mb`, `raw_unifiedlog_days`, `raw_logarchive` (also save the full unified log as a `.logarchive`), `raw_fsevents_max_files`, `raw_bodyfile_paths`, `raw_bodyfile_excluded_dir_names`, `raw_bodyfile_max_entries`, `raw_log_globs`.

---

## 📊 Output

Forensicator generates:

* A single-page HTML dashboard report
* Organized forensic artifacts
* Per-check JSON findings for Forensicator Enterprise
* A hashed investigation archive (`investigation.zip` + `Readme.txt`) for Forensicator Enterprise upload

---

## ✨ Changelog

```bash
v4.3.0
- NEW: -A / --artifacts raw artifact collection for Forensicator Core's Host Artifacts (account records, launch and login items, code signatures, TCC, quarantine events, KnowledgeC, XProtect, FSEvents, histories, processes, unified log exports, filesystem timeline) with a SHA-256 manifest.
- FIX: The report and detection engine no longer break on the bash 3.2 that macOS ships (bash 4-only syntax).
- FIX: -e now encrypts (it was parsed but never ran); the key goes to openssl through a file, and the unencrypted output is removed. Added -d to decrypt; the format is the Linux collector's, so either one decrypts the other's.
- FIX: User accounts come from Directory Services: real users and dscl-created backdoor accounts were missing from the user list and the UID 0 check.
- FIX: Chrome/Edge/Brave/Firefox history was never collected (paths with spaces); the write-ahead log is now included, and every user's history is read.
- FIX: Per-user artifacts were read only from the home folder of the account running the script.
- FIX: An earlier collection is moved aside instead of deleted, and only after options are parsed.
- FIX: RAM capture no longer runs the Linux-only avml or reports success when nothing was captured; network capture reports failures too.
- FIX: The python3 stub on Macs without the Command Line Tools is no longer run (it opened an install dialog on the console).
- FIX: Login items come from Background Task Management instead of osascript, which raised a consent prompt and could block.
- FIX: -z checked a branch that does not exist, compared versions as strings, and ran only after the case prompts; it now updates and exits.
- FIX: Detections: launch item and cron rules now read the plists' programs (they matched file names before), DYLD/HISTFILE checks read launch items and shell startup files (not the collector's own environment), listening-port and temp-folder rules no longer fire on stock macOS services, failed logins come from the unified log (macOS has no lastb), MITRE IDs corrected.
- FIX: Sigma: log messages are no longer matched as command lines (false positives), one finding per rule and process, bounded memory.
- FIX: Ransomware scan skips system, cache and temp trees, drops .bak, and adds a per-directory count (mass encryption) and a ransom-note search.
- FIX: Finding severities follow what was found; metadata.json and LOGS/detections.csv are valid JSON/CSV; the report's launch item panel was always empty.

v4.1.6
- NEW: Best-effort Sigma rule engine sourced from real SigmaHQ community rules, evaluated against the unified log.
- NEW: Detection engine expanded — added deleted-binary execution, kernel/kext integrity status, credential-file timestomping, PATH-hijack, and application code-signature checks.
- NEW: Auto-updating malware hash and malicious URL feeds (abuse.ch, URLhaus), with operator-maintained custom lists that are never overwritten.
- NEW: Signed System Volume (SSV) seal status check.
- NEW: Multi-user, multi-shell command history collection (bash/zsh/sh/fish), previously single-user bash/zsh only.
- NEW: Investigation archive (hashed, zipped investigation/ folder + Readme) and per-check JSON output for Forensicator Enterprise.
- FIX: Auth log collection now reliably surfaces SSH connections instead of silently returning nothing.
- FIX: Ransomware/SUID/authorized_keys checks no longer re-walk the full filesystem per extension or per check.
- FIX: CWD-independence, sudo guards, and BSD-native tooling (stat, shasum) used in place of GNU-only syntax throughout.

v0.1 (23/01/2023)
- Initial Beta Release
```

---

## 📸 Screenshots

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
