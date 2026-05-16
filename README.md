<h1 align="center">🛡️ Forensicator 🛡️</h1>

<h3 align="center">
Cross-platform Incident Response & Live Forensics Toolkit<br>
Windows (PowerShell) | Linux (Bash) | macOS (Shell)
</h3>

<p align="center">
Built for fast, structured, and actionable forensic investigations.
</p>



```bash
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                        v4.1.4
```

<p align="center">
<a href="https://forensicator.io"><img width="147" height="36" alt="image" src="https://github.com/user-attachments/assets/824f5c19-9bf4-41a3-bad9-32549fa0d3bc" width="400" ></a>
</p>

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
* Integration with Sigma rules
* Malware hash matching (e.g., abuse.ch feeds)
* Browser history analysis with IOC matching
* Optional artifact encryption (AES)
* Detection Insight - A summary of the detection, why the detection matters, the detection logic code, what to look pout for in the detection and the Mitre Mapping.
* Signma Rule Integration for malicious activity detection

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Windows

---

## 🍎 macOS (Shell)

* Lightweight artifact collection
* System and user activity inspection

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/MacOS

---

## 🐧 Linux (Bash)

* Cross-distro compatible Bash scripts
* Uses native system utilities (no heavy dependencies)
* Focus on portability and reliability

👉 https://github.com/Johnng007/Live-Forensicator/tree/main/Linux

> ⚠️ Note: Linux scripts are designed to avoid non-native utilities (e.g., `net-tools`) for maximum compatibility.

---

# 🔍 Key Features

* Cross-platform forensic artifact collection
* Detection of suspicious activity and anomalies
* Event Log analysis (Windows)
* Sigma rule integration
* Malware hash and IOC matching
* Structured HTML reporting (with dashboards)
* Optional artifact encryption (Windows module)
* Detection Insight with Mitre Mapping
* Forensicator AI (Coming Soon!!!)

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

> ⚠️ Currently available only in the Windows module
> ⚠️ Not backward compatible prior to v4.1.1

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
Windows: v4.1.3 (May 2026)
- NEW: Improved Dashboard UI/UX.
- IMPROVED: Sigma Rule Support.
- IMPROVED: Script Readability.

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

<a href="https://forensicator.io/walkthrough.html">
  <img width="239" height="31" alt="image" src="https://github.com/user-attachments/assets/f4cb261c-65c8-4592-a42e-6b9ba54dc990" />

</a>

---

# 🔗 Project Home

<a href="https://forensicator.io">
  <img width="147" height="36" alt="image" src="https://github.com/user-attachments/assets/824f5c19-9bf4-41a3-bad9-32549fa0d3bc" />

</a>
