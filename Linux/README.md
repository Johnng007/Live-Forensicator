<h1 align="center">🛡️ Forensicator Artifact Collector (Linux) 🛡️</h1>

<h3 align="center">
Bash-based Forensic Artifact Collector
</h3>

<p align="center">
Collects forensic artifacts from Linux systems for analysis in Forensicator Core. Includes a built-in HTML report for quick triage and preliminary findings review.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Live Forensicator (Linux)** is a Bash-based forensic artifact collector — it rapidly gathers the evidence an investigator needs from a live Linux host and packages it for Forensicator Core, with built-in on-host triage along the way.

It enables:

* Collection of key forensic artifacts across Linux environments
* Timeline-based log collection
* Built-in triage — MITRE ATT&CK-mapped detection logic backed by a real Sigma rule engine, and detection of suspicious persistence mechanisms

This version focuses on:

* Lightweight execution
* Cross-distribution compatibility (no non-native dependencies)
* Config-driven collection and triage, so operators can tune what's flagged without editing the script

---

## ⚙️ Key Features

* Cross-distro compatible Bash scripts, no non-native dependencies
* LUKS disk-encryption status check
* Credential-file tampering timeline (mtime vs. ctime on passwd/shadow/sudoers/authorized_keys)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)
* Timeline-based log collection
* Network capture (PCAP)
* Browser history extraction (Firefox/Chrome-family)
* Persistence discovery (cron, systemd, init, etc.)
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload
* Structured HTML output
* Built-in triage: 25-rule MITRE ATT&CK-mapped detection engine (reverse shells, timestomping, PATH hijacking, deleted-binary execution, package integrity, and more)
* Sigma rule engine sourced from real SigmaHQ community rules, evaluated against `auditd` (if configured) and `journald`
* Malware hash matching and malicious URL/domain matching, with auto-updating abuse.ch/URLhaus feeds, including browser-history IOC matching and ransomware extension detection

> ⚠️ The Sigma engine requires `python3`. If it isn't present, that step is skipped cleanly and the rest of the collection is unaffected. Real-world Sigma hit rate depends heavily on whether `auditd` is already configured on the target box — most distros don't enable exec auditing by default, so `journald`-backed rules (sshd/sudo/cron) are the more consistently useful half of the ruleset.

---

## 📦 Optional Dependencies

For additional capabilities:

```bash
avml        → RAM acquisition (https://github.com/microsoft/avml)
sqlite3     → Browser history extraction
python3     → Sigma rule engine, Forensicator AI
debsums     → Package integrity verification on Debian/Ubuntu (rpm -Va is used on RHEL/Fedora, no extra install needed)
```

> Forensicator works without these, but functionality will be limited.

---

## 🔨 Usage

```bash
# Clone repository
git clone https://github.com/Johnng007/Live-Forensicator.git

# Navigate to Linux directory
cd Linux

# Make executable
chmod +x Forensicator.sh

# Execute
./Forensicator.sh <parameters>
```

---

## 🥊 Examples

```bash
# Basic execution
./Forensicator.sh

# Raw artifact collection for Forensicator Core (run as root): files, logs,
# process table and filesystem timeline, with a SHA-256 manifest
sudo ./Forensicator.sh -A

# Help
./Forensicator.sh --usage

# Capture network traffic (60 seconds)
./Forensicator.sh -p

# Ransomware extension detection
./Forensicator.sh -s

# Web logs (NGINX/Apache)
./Forensicator.sh -w

# Timeline analysis
./Forensicator.sh --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59'

# Define log files for timeline
./Forensicator.sh --logfiles auth.log,syslog,kern.log

# Define custom log directory
./Forensicator.sh --logdir /custom/log/directory

# Browser history extraction (also enables browser IOC matching)
./Forensicator.sh -b

# Hash check running process executables against the malware hash feed
./Forensicator.sh -H

# RAM capture
./Forensicator.sh -r

# Encrypt collected artifacts (AES-256)
./Forensicator.sh -e

# Decrypt a previously encrypted artifact
./Forensicator.sh -d FILE

# Check GitHub for a newer version
./Forensicator.sh -z

# Combined execution
./Forensicator.sh -p -s -w -H -e --timeline '2024-06-01 00:00:00' '2024-06-07 23:59:59'

# Unattended mode
./Forensicator.sh -name "Analyst" -case 01123 -title "Incident" -loc "Location" -device HOSTNAME
```

---

## ⚠️ Important Notes

* Run as root for full visibility
* Execution may trigger IDS/IPS alerts
* Outputs are saved as structured HTML reports
* Artifacts are stored locally in the working directory
* IOC lists, hash/URL feed sources, Sigma engine settings, and package-integrity timeouts are all configurable via `config.json`
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
* Users with login shells
* SSH authorized keys
* `/etc/passwd`, sudoers, sudo group membership
* Credential-file tampering timeline (mtime vs. ctime on passwd/shadow/sudoers/authorized_keys — flags forged modification times)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)

### 💻 System Information

* Kernel, CPU, and OS details
* Block devices & USB controllers
* Hardware enumeration
* LUKS disk-encryption status (encrypted volumes + unlocked dm-crypt mappings)
* Kernel taint status (out-of-tree/unsigned module detection)

### 🌐 Network Information

* Routing table
* Active connections & listening ports
* Firewall rules (iptables/nft/ufw, whichever is present)
* ARP cache & DNS configuration
* Hosts configuration

### ⚙️ Processes & Persistence

* Running processes
* Services & timers
* Cron jobs
* Systemd persistence
* Init scripts
* Recently modified executables in config-driven search paths (single-pass, pruned — never a full `/` walk)

### 🔎 Security Checks

* SetUID/SGID binaries
* File capabilities
* Suspicious persistence locations
* World-writable directories/files on `$PATH` (PATH-hijack risk)
* Processes running from deleted binaries (fileless/self-deleting malware indicator)
* Package integrity verification (`debsums`/`rpm -Va`, config-driven timeout and output cap)
* Config-driven IOC matching (suspicious executables and shell commands) against processes, cron, and persistence paths
* Malware hash matching against a running process list, auto-downloaded and refreshed from the abuse.ch feed
* Browser history IOC matching against a malicious-URL feed (URLhaus)

### 🎯 Detection Engine & Sigma

* 25-rule built-in detection engine, MITRE ATT&CK-mapped (reverse shells, attack tools, brute force, log clearing, container escape, SSH key implants, rootkit modules, LD_PRELOAD hijacking, timestomping, PATH hijacking, deleted-binary execution, package tampering, and more)
* Sigma rule engine compiled from real SigmaHQ community rules, evaluated against `auditd` (process creation/network/file events, if configured) and `journald` (sshd/sudo/cron/syslog-backed rules)
* All detections feed the same `DETECTIONS/findings.csv` and the HTML report's "Rule Detections" tab

### 📜 Timeline & Logs

* Auth logs (SSH connections: accepted/failed logins, invalid users, disconnects — checked across `/var/log/auth.log`, `/var/log/secure`, and `journalctl -t sshd`)
* System logs (journalctl)
* Custom log timelines
* Web server logs

### 🚀 Extended Features

* Raw artifact collection (`-A`) for Forensicator Core's Host Artifacts upload — see below
* Network tracing (PCAP)
* RAM acquisition
* Browser history analysis
* Ransomware extension detection
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload

---

## 📊 Output

Forensicator generates:

* Structured HTML reports
* Organized forensic artifacts
* Timeline-based investigation data
* Per-check JSON findings for Forensicator Enterprise

### Raw artifacts (`-A`)

`-A` copies the artifacts themselves into `<host>/artifacts/LinuxArtifacts/`, ready to upload to Forensicator Core (**Host Artifacts → Upload → Collector folder**, picking the host folder):

| Folder | Contents |
|---|---|
| `Files/<absolute path>` | Raw copies at their real path, timestamps and modes preserved: accounts (`passwd`, `shadow`, `group`, `sudoers`, `sudoers.d`), PAM, SSH server config, every user's shell/app histories, `authorized_keys`, `known_hosts` and startup files, cron/at, systemd units and drop-ins, `ld.so.preload`, module/udev/sysctl/APT hooks, `wtmp`/`btmp`/`utmp`, and the logs listed in `raw_log_globs` (with rotations) |
| `Commands/` | Sockets, listeners, interfaces, routes, firewall, mounts, sysctl, loaded modules, packages, services, timers, eBPF programs, Docker containers, immutable files (`lsattr`), symlinks found in collected locations, kernel banner |
| `Processes/` | `processes.tsv` (PID, parent, user, start time, executable, SHA-256, cwd, command line) and `recovered/` — executables still running but deleted from disk, recovered from `/proc/<pid>/exe` |
| `Timeline/bodyfile.txt` | TSK bodyfile (MACB times) of `raw_bodyfile_paths`, capped at `raw_bodyfile_max_entries` |
| `Logs/journal.log` | systemd journal for the last `raw_journal_days` days |
| `CollectionManifest/` | Every acquisition (Collected / Skipped / Failed) with the SHA-256 of each collected file — Core verifies each upload against it |

Run it as root: without root, `shadow`, other users' homes and some processes are missing (the manifest records that the collection is partial). Volatile data — processes and sockets — is read before any file is copied, and with `-r` memory is captured first. Core parses the artifacts into records and runs its Linux detection rules on them; the logs go to Log Analysis in the same case.

Settings in `config.json`: `raw_max_file_mb`, `raw_log_globs`, `raw_journal_days`, `raw_bodyfile_paths`, `raw_bodyfile_max_entries`, plus `persistence_days_back` (the systemd detection's lookback).

---

## ✨ Changelog

```bash
v4.3.0
- NEW: -A / --artifacts raw artifact collection with a SHA-256 CollectionManifest, for Forensicator Core's Host Artifacts upload.
- NEW: Recovers executables of processes running from deleted binaries; login history from wtmp/btmp where last/lastb are no longer installed (Ubuntu 26.04, Debian 13).
- CHANGE: Memory capture (-r) now runs first, before the packet capture and the rest of the collection.
- FIX: -z/--update called a function that didn't exist; it now checks for a newer version and updates a git checkout.
- FIX: -d/--decrypt and -z deleted the previous collection folder; an earlier collection is now moved aside, never deleted.
- FIX: The -t timeline filter returned nothing for traditional syslog timestamps; it now handles RFC 3164, RFC 3339 and auditd records, rotated and .gz logs, honours -logdir/-log, and also exports the journal.
- FIX: Collection could stop silently part-way: every check re-enabled exit-on-error for the rest of the run.
- FIX: Detections tuned — brute force and log clearing read auth.log, secure or the journal; systemd persistence uses a real lookback; shared libraries are flagged only in unusual locations; listeners on loopback no longer count as non-standard ports; process-in-temp uses the real executable path; timestomping ignores unmodified package files; PATH checks follow symlinks.
- FIX: IOC matching — executables are matched as whole words, and everyday system binaries (bash, ssh, sudo, cron, ...) were removed from the list; ".*" patterns in suspicious_SH_commands now work as patterns.
- FIX: Ransomware extensions are read from Ransomware_Extensions only; Sigma rules scoped to a service (cron, sshd, ...) only match that service's log lines; wrong motd persistence paths corrected.

v4.1.6
- NEW: Sigma rule engine sourced from real SigmaHQ community rules, evaluated against auditd and journald.
- NEW: 25-rule detection engine (previously 20) — added deleted-binary execution, kernel taint, credential-file timestomping, and PATH-hijack checks.
- NEW: Auto-updating malware hash and malicious URL feeds (abuse.ch, URLhaus), with operator-maintained custom lists that are never overwritten.
- NEW: LUKS disk-encryption status check.
- NEW: Package integrity verification (debsums/rpm -Va), config-driven timeout and output cap.
- NEW: Multi-user, multi-shell command history collection (bash/zsh/sh/fish).
- NEW: JSON output for upload to Forensicator Enterprise.
- FIX: Auth log collection now reliably surfaces SSH connections (accepted/failed logins, disconnects) instead of silently returning nothing.
- FIX: Ransomware/SUID/authorized_keys checks no longer re-walk the full filesystem per extension or per check.
- FIX: CWD-independence, sudo guards, and full-disk-walk pruning across the collector.
```

---

## 📸 Screenshots

<details><summary> Terminal</summary>

<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_Output.png?raw=true" />

</details>


<details><summary>HTML Output</summary>

<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML1.png?raw=true" />
<br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML2.png?raw=true" />
<br>
<img src="https://github.com/Johnng007/Live-Forensicator/blob/main/styles/vendors/images/Forensicator_HTML3.png?raw=true" />

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
