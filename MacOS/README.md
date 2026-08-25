<h1 align="center">🛡️ Forensicator (macOS) 🛡️</h1>

<h3 align="center">
Bash-based Incident Response & Live Forensics Toolkit
</h3>

<p align="center">
Live forensic artifact collection, MITRE ATT&CK-mapped detections, and structured reporting for macOS systems.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Forensicator (macOS)** is a Bash-based incident response and live forensics tool designed to assist investigators in rapidly collecting and analyzing system artifacts on macOS.

It enables:

* Rapid triage of macOS systems
* Collection of key forensic artifacts (system, user, network, process, file)
* Built-in MITRE ATT&CK-mapped detection logic, backed by a best-effort Sigma rule engine
* macOS-native integrity checks (SIP, Gatekeeper, FileVault, Signed System Volume, code signatures)

Apple restricts real process-creation telemetry (comparable to Linux `auditd` or Windows Sysmon) to its Endpoint Security Framework, which requires a signed system extension with a special Apple-issued entitlement — not something a plain script can obtain. Where that limits a check, this README says so plainly rather than overclaiming.

---

## ⚙️ Key Features

* Detection engine, MITRE ATT&CK-mapped (reverse shells, attack tools, brute force, SIP/Gatekeeper tampering, dylib hijacking, timestomping, PATH hijacking, deleted-binary execution, and more)
* Best-effort Sigma rule engine sourced from real SigmaHQ community rules, evaluated against the unified log (`log show`)
* Malware hash matching and malicious URL/domain matching, with auto-updating abuse.ch/URLhaus feeds
* FileVault, SIP, Gatekeeper, and TCC privacy database inspection
* Signed System Volume (SSV) seal status and application code-signature verification (the macOS analog of package-checksum verification — there is no `rpm`/`dpkg` here)
* Credential-file tampering timeline (mtime vs. ctime on passwd/sudoers/authorized_keys)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)
* Browser history extraction (Safari, Chrome, Firefox, Edge, Brave) with malicious-URL IOC matching
* Ransomware extension detection
* Persistence discovery (LaunchDaemons, LaunchAgents, login items, cron)
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, plus a hashed investigation archive for Forensicator Enterprise upload
* Single-page HTML dashboard report

> ⚠️ The Sigma engine requires `python3`. If it isn't present, that step is skipped cleanly and the rest of the collection is unaffected. Most Sigma rules here expect command-line/parent-process data the unified log doesn't record — expect low hit rate on rules other than the ones that only need a process's own image path. A quiet Sigma tab does not mean nothing happened; it means the telemetry those rules need isn't accessible without Endpoint Security Framework.

---

## 📦 Optional Dependencies

For additional capabilities:

```bash
osxpmem / avml  → RAM acquisition 
python3         → Sigma rule engine, Forensicator AI, and the zip/investigation-archive fallback if `zip` is unavailable
```

> Forensicator works without these, but functionality may be limited.

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

<a href="https://forensicator.io/walkthrough.html">See full Usage</a>

---

## 🥊 Examples

```bash
# Basic execution
./forensicator.sh

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

# RAM capture (requires osxpmem or avml)
./forensicator.sh -r

# Encrypt collected artifacts (AES-256)
./forensicator.sh -e

# Check GitHub for a newer version
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
* You can find all extracted artifacts in the script's working directory — open `<hostname>/reports/index.html` to navigate the findings
* IOC lists, hash/URL feed sources, and Sigma engine settings are configurable via `config.json`
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
* Local user accounts, admin/wheel group membership
* SSH authorized keys
* Login items
* Credential-file tampering timeline (mtime vs. ctime — flags forged modification times)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)

### 💻 System Information

* OS version, kernel, hardware, CPU, disk/volume layout, USB devices
* Installed applications, Homebrew package list
* FileVault status
* System Integrity Protection (SIP) status
* Gatekeeper status
* Kernel/kext integrity status — non-Apple loaded kernel extensions, alongside SIP context (the closest macOS analog to Linux's kernel taint flags)
* TCC privacy database (app access to privacy-sensitive resources)
* Quarantine events database (files downloaded from the internet)

### 🌐 Network Information

* Interfaces, routing table
* Active connections & listening ports
* Firewall rules (pf)
* ARP cache, DNS configuration

### ⚙️ Processes & Persistence

* Running processes
* LaunchCtl services, LaunchDaemons, LaunchAgents (system and user)
* Cron jobs
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
* RAM acquisition (osxpmem or avml)
* Browser history analysis
* Ransomware extension detection
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, plus a hashed investigation archive for Forensicator Enterprise upload

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

<a href="https://opendocs.forensicator.io"> OpenDocs</a>
