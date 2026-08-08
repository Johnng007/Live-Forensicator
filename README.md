<h1 align="center">🛡️ Forensicator 🛡️</h1>

<h3 align="center">
Cross-platform Incident Response & Live Forensics Toolkit<br>
Windows (PowerShell) | Linux (Bash) | macOS (Shell)
</h3>

<p align="center">
Built for fast, structured, and actionable forensic investigations.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

# 🤔 About

**Forensicator** is a cross-platform incident response and live forensics toolkit.

It is designed to help forensic investigators and incident responders rapidly collect, analyze, and interpret system artifacts during live investigations.

Forensicator:

* Collects system and user activity data
* Detects anomalous behavior and suspicious indicators
* Highlights potential compromise or misconfiguration
* Generates structured, investigation-ready HTML reports

---

# ⚙️ Platform Support

## 🖳 Windows (PowerShell)

* Advanced Event Log analysis
* Detection of suspicious activity via known Event IDs
* Sigma rule engine (1,400+ community rules) evaluated against Security/Sysmon Event Logs
* Malware hash matching (e.g., abuse.ch feeds)
* Browser history analysis with IOC matching
* Optional artifact encryption (AES)
* Detection Insight - a summary of the detection, why it matters, the detection logic, what to look for, and its MITRE mapping
* Investigation archive + structured JSON output for Forensicator Enterprise
* Forensicator AI — optional, per-finding AI verdicts from a local (Ollama) or commercial LLM, shown in the report's tooltip

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Windows

---

## 🍎 macOS (Shell)

* Detection engine covering reverse shells, SIP/Gatekeeper/kext tampering, PATH hijacking, deleted-binary execution, credential timestomping, and more
* Best-effort Sigma rule engine sourced from real SigmaHQ community rules, evaluated against the unified log
* Malware hash matching and browser history IOC matching, with auto-updating abuse.ch/URLhaus feeds
* FileVault, SIP, Gatekeeper, TCC, and Signed System Volume integrity checks
* Application code-signature verification
* Optional artifact encryption (AES)
* Investigation archive + structured JSON output for Forensicator Enterprise

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/MacOS

> ⚠️ Note: macOS restricts real process-creation telemetry to its Endpoint Security Framework, which a plain script cannot access — so Sigma coverage is narrower here than on Windows/Linux. See the [macOS README](./MacOS/README.md) for specifics.

---

## 🐧 Linux (Bash)

* Cross-distro compatible Bash scripts, no non-native dependencies
* Detection engine covering reverse shells, timestomping, PATH hijacking, deleted-binary execution, package integrity, and more
* Sigma rule engine sourced from real SigmaHQ community rules, evaluated against auditd and journald where available
* Malware hash matching and malicious URL matching, with auto-updating abuse.ch/URLhaus feeds
* LUKS disk-encryption status and credential-file tampering timeline
* Optional artifact encryption (AES)
* Structured JSON output for Forensicator Enterprise

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Linux

> ⚠️ Note: Linux scripts are designed to avoid non-native utilities (e.g., `net-tools`) for maximum compatibility. Sigma coverage depends on whether `auditd` is already configured on the target box — see the [Linux README](./Linux/README.md).

---

# 🔍 Key Features

* Cross-platform forensic artifact collection
* Detection of suspicious activity and anomalies on every platform
* Event Log analysis (Windows)
* Sigma rule integration on all three platforms — coverage and data source vary by OS; see each platform's section below and its own README
* Malware hash and IOC matching, with auto-updating threat-intel feeds
* Structured HTML reporting (with dashboards)
* Optional artifact encryption (Windows, Linux, and macOS)
* Detection Insight with Mitre Mapping
* Forensicator AI — optional, per-finding AI verdicts from a local (Ollama) or commercial LLM (Windows now; other platforms planned)

---

# 📊 Output

Forensicator generates:

* Clean, structured HTML report
* Indexed findings for easy navigation
* Extracted artifacts stored locally
* Detection insight into each finding.
* Suspicious activity statistics with Sigma Rules.

This enables fast transition from **data collection → investigation → decision-making**.

---

# ⚠️ Important Notes

* Run scripts with elevated/privileged permissions for best results
* Activity may trigger IDS/IPS alerts — this is expected behavior
* External threat intelligence (hashes, IOCs) may be updated during execution
* Configuration can be customized via `config.json`

---

# 🔐 Artifact Integrity & Encryption

Forensicator supports optional encryption of collected artifacts using AES.

This is useful when:

* Evidence must be transported securely
* Chain-of-custody concerns exist
* Legal integrity of artifacts must be preserved

> ⚠️ Available on Windows, Linux, and macOS
> ⚠️ Not backward compatible prior to v4.1.1

---

# 🤖 Forensicator AI

Off by default. When enabled, each finding is sent to a local or commercial LLM as it's collected, and gets a real, plain-language verdict shown right in the report's tooltip.

**Quick setup (local LLM via Ollama), currently Windows:**

```bash
# 1. Install Ollama (https://ollama.com) and pull a model
ollama pull mistral:7b-instruct
```
```jsonc
// 2. Enable it in config.json
"ai": {
  "enabled": true,
  "provider": "ollama",
  "base_url": "http://localhost:11434",
  "model": "mistral:7b-instruct"
}
```

Prefer a commercial API instead (OpenAI, Anthropic, Azure OpenAI, or any OpenAI-compatible endpoint)? Set `provider` accordingly and add your `api_key`.

📘 Full setup guide (all providers, tuning, troubleshooting): <a href="https://opendocs.forensicator.io">opendocs.forensicator.io</a>

---

# 🧠 Detection Capabilities

Forensicator identifies suspicious activity through:

* Event Log analysis
* Sigma-based detections
* Malicious hash matching
* IOC-based URL analysis (browser history)

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

# ✨ Changelog

Full changelog:
👉 https://forensicator.io/changelog.html

```bash
Windows: v4.1.7 (July 2026)
- NEW: Added support for PowerShell v5.
- NEW: Active Directory detection module (Domain Controllers only) — NTDS database integrity, SYSVOL/GPO script analysis, privileged group membership, KRBTGT account age, SPN/Kerberoasting exposure, Kerberos delegation, DCSync rights enumeration, DC-specific privileged/Kerberos event collection, and WMI permanent event subscription detection.
- NEW: Microsoft SQL Server detection module — dangerous configuration options (xp_cmdshell, OLE Automation Procedures, CLR), sysadmin/sa account review, linked servers, TRUSTWORTHY databases, SQL Agent job persistence checks, and login failure event collection.
- NEW: Microsoft SharePoint Server detection module — webshell/dropped-file scanning, suspicious IIS worker process (w3wp.exe) child processes, web.config ViewState/machineKey misconfiguration review, and known exploit URI matching in IIS logs.
- FIX: Sigma rule engine returning zero findings on PowerShell 5.1 due to a ConvertFrom-Json array-unrolling difference between PS5.1 and PS7.
- FIX: HTML report rendering broken on PowerShell 5.1 caused by inconsistent Out-File encoding (UTF-16 vs UTF-8) between PowerShell versions.
- FIX: Friendlier error handling when manage-bde.exe is unavailable during BitLocker key extraction.
- FIX: Improvements and bug fixes.
```

---

# 🤝 Contributing

Contributions are welcome.

* Open an issue to discuss major changes
* Submit pull requests with clear descriptions
* Focus on accuracy, clarity, and usability

---

# 📄 License

MIT License
https://mit.com/licenses/mit/

---

# ☕ Full Usage & WalkThrough

<a href="https://opendocs.forensicator.io">
  <img width="239" height="31" alt="image" src="https://github.com/user-attachments/assets/f4cb261c-65c8-4592-a42e-6b9ba54dc990" />

</a>

