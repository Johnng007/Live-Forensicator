<h1 align="center">🛡️ Forensicator (Linux) 🛡️</h1>

<h3 align="center">
Bash-based Incident Response & Live Forensics Toolkit
</h3>

<p align="center">
Lightweight, cross-distro forensic collection and timeline analysis for Linux systems.
</p>

```bash
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          v4.1.6
```

---

# 🤔 About

**Forensicator (Linux)** is a Bash-based incident response and live forensics tool designed to assist investigators in rapidly collecting and analyzing system artifacts across Linux environments.

It enables:

* Rapid triage of Linux systems
* Collection of key forensic artifacts
* Built-in MITRE ATT&CK-mapped detection logic, backed by a real Sigma rule engine
* Detection of suspicious persistence mechanisms
* Timeline-based log analysis

This version focuses on:

* Lightweight execution
* Cross-distribution compatibility (no non-native dependencies)
* Config-driven detection, so operators can tune what's flagged without editing the script

---

# ⚙️ Key Features

* Cross-distro compatible Bash scripts
* 25-rule MITRE ATT&CK-mapped detection engine (reverse shells, timestomping, PATH hijacking, deleted-binary execution, package integrity, and more)
* Sigma rule engine sourced from real SigmaHQ community rules, evaluated against `auditd` (if configured) and `journald`
* Malware hash matching and malicious URL/domain matching, with auto-updating abuse.ch/URLhaus feeds
* LUKS disk-encryption status check
* Credential-file tampering timeline (mtime vs. ctime on passwd/shadow/sudoers/authorized_keys)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)
* Timeline-based log analysis
* Network capture (PCAP)
* Browser history extraction (Firefox/Chrome-family), with malicious-URL IOC matching
* Ransomware extension detection
* Persistence discovery (cron, systemd, init, etc.)
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload
* Structured HTML output

> ⚠️ The Sigma engine requires `python3`. If it isn't present, that step is skipped cleanly and the rest of the collection is unaffected. Real-world Sigma hit rate depends heavily on whether `auditd` is already configured on the target box — most distros don't enable exec auditing by default, so `journald`-backed rules (sshd/sudo/cron) are the more consistently useful half of the ruleset.

---

# 📦 Optional Dependencies

For additional capabilities:

```bash
avml        → RAM acquisition (https://github.com/microsoft/avml)
sqlite3     → Browser history extraction
python3     → Sigma rule engine
debsums     → Package integrity verification on Debian/Ubuntu (rpm -Va is used on RHEL/Fedora, no extra install needed)
```

> Forensicator works without these, but functionality will be limited.

---

# 🔨 Usage

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

# 🥊 Examples

```bash
# Basic execution
./Forensicator.sh

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

# ⚠️ Important Notes

* Run as root for full visibility
* Execution may trigger IDS/IPS alerts
* Outputs are saved as structured HTML reports
* Artifacts are stored locally in the working directory
* IOC lists, hash/URL feed sources, Sigma engine settings, and package-integrity timeouts are all configurable via `config.json`
* Operator-maintained hash/IOC lists (`Forensicator-Share/custom_hashes.txt`, `Forensicator-Share/custom_iocs.txt`) are never overwritten by the auto-download feed refresh

---

# 🧠 Investigation Capabilities

## 👤 User & Account Data

* Active sessions & login history (successful and failed)
* Users with login shells
* SSH authorized keys
* `/etc/passwd`, sudoers, sudo group membership
* Credential-file tampering timeline (mtime vs. ctime on passwd/shadow/sudoers/authorized_keys — flags forged modification times)
* Multi-user, multi-shell command history (bash/zsh/sh/fish)

## 💻 System Information

* Kernel, CPU, and OS details
* Block devices & USB controllers
* Hardware enumeration
* LUKS disk-encryption status (encrypted volumes + unlocked dm-crypt mappings)
* Kernel taint status (out-of-tree/unsigned module detection)

## 🌐 Network Information

* Routing table
* Active connections & listening ports
* Firewall rules (iptables/nft/ufw, whichever is present)
* ARP cache & DNS configuration
* Hosts configuration

## ⚙️ Processes & Persistence

* Running processes
* Services & timers
* Cron jobs
* Systemd persistence
* Init scripts
* Recently modified executables in config-driven search paths (single-pass, pruned — never a full `/` walk)

## 🔎 Security Checks

* SetUID/SGID binaries
* File capabilities
* Suspicious persistence locations
* World-writable directories/files on `$PATH` (PATH-hijack risk)
* Processes running from deleted binaries (fileless/self-deleting malware indicator)
* Package integrity verification (`debsums`/`rpm -Va`, config-driven timeout and output cap)
* Config-driven IOC matching (suspicious executables and shell commands) against processes, cron, and persistence paths
* Malware hash matching against a running process list, auto-downloaded and refreshed from the abuse.ch feed
* Browser history IOC matching against a malicious-URL feed (URLhaus)

## 🎯 Detection Engine & Sigma

* 25-rule built-in detection engine, MITRE ATT&CK-mapped (reverse shells, attack tools, brute force, log clearing, container escape, SSH key implants, rootkit modules, LD_PRELOAD hijacking, timestomping, PATH hijacking, deleted-binary execution, package tampering, and more)
* Sigma rule engine compiled from real SigmaHQ community rules, evaluated against `auditd` (process creation/network/file events, if configured) and `journald` (sshd/sudo/cron/syslog-backed rules)
* All detections feed the same `DETECTIONS/findings.csv` and the HTML report's "Rule Detections" tab

## 📜 Timeline & Logs

* Auth logs (SSH connections: accepted/failed logins, invalid users, disconnects — checked across `/var/log/auth.log`, `/var/log/secure`, and `journalctl -t sshd`)
* System logs (journalctl)
* Custom log timelines
* Web server logs

## 🚀 Extended Features

* Network tracing (PCAP)
* RAM acquisition
* Browser history analysis
* Ransomware extension detection
* Optional artifact encryption (AES-256)
* Structured per-check JSON output under `investigation/`, for Forensicator Enterprise upload

---

# 📊 Output

Forensicator generates:

* Structured HTML reports
* Organized forensic artifacts
* Timeline-based investigation data
* Per-check JSON findings for Forensicator Enterprise

---

# ✨ Changelog

```bash
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

# 📸 Screenshots

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

# 🧰 More Tools (Black Widow Toolbox)

* Anteater → Web reconnaissance
  https://github.com/Johnng007/Anteater

* Nessus Pro API → Export scan results
  https://github.com/Johnng007/PowershellNessus

---

# 🤝 Contributing

Pull requests are welcome.
For major changes, please open an issue first to discuss your proposal.

---

# 📄 License

MIT License
https://mit.com/licenses/mit/

---

# ☕ Support

<a href="https://ko-fi.com/forensicator">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" />
</a>

---

# 🔗 Connect

<a href="https://www.linkedin.com/in/ebuka-john-onyejegbu">
  LinkedIn
</a>
