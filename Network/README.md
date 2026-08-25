<h1 align="center">🛡️ Forensicator (Network Devices) 🛡️</h1>

<h3 align="center">
Python-based Network Device Forensics &amp; Configuration Auditing
</h3>

<p align="center">
Read-only, SSH-based collection and detection for routers, switches, and firewalls.
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/f30b9752-edd4-491f-b466-40d302e5c73c">
  <img alt="Forensicator Logo" src="https://github.com/user-attachments/assets/22187cf0-5b12-4c44-8644-45405d393109" >
</picture>

---

## 🤔 About

**Forensicator (Network Devices)** connects to network infrastructure over SSH (via [Netmiko](https://github.com/ktbyers/netmiko)), collects a defined set of read-only `show` commands, and runs detection logic against the result — producing the same kind of structured per-check finding JSON as the Windows/Linux/macOS collectors, for ingestion into Forensicator Enterprise.

**Vendor support:** Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos, and VyOS for collection. 3 of the 4 starter detection rules (`insecure-mgmt-plane`, `weak-snmp-community`, `missing-aaa`) run only against the Cisco/Arista IOS-family devices (NX-OS and EOS share close-enough config syntax) — Junos/VyOS's `set`-style config syntax is fundamentally different from IOS's for those specific checks; see `collectors/juniper_junos.py`/`collectors/vyos.py`'s docstrings. `unauthorized-local-accounts` DOES cover Junos/VyOS too, via a vendor-specific local-user extractor (Cisco's `username <name>` lines vs. Junos/VyOS's `set system login user <name>` lines). Every vendor gets full collection and Detection Insight on every baseline artifact regardless.

**Safe by default:** every collected command is read-only. No configuration changes are made to any device.

---

## ⚙️ Key Features

* SSH-based collection via Netmiko — no vendor SSH/driver handling reimplemented
* Structured parsing of CLI output where an [ntc-templates](https://github.com/networktocode/ntc-templates) parser exists for the command, raw text always captured regardless
* Detection Insight on every finding — plain-language explanation, MITRE ATT&CK mapping, and recommendations, matching the Windows collector's knowledge-base pattern
* Config-driven: device inventory, which rules are enabled, and the local-account baseline are all set in `config.json` — no code changes needed to tune a deployment
* Per-device error isolation — one unreachable device or one failed command never aborts the rest of the run
* Concurrent multi-device collection (thread pool, `--max-workers`, default 4)
* Self-contained single-page HTML report per device (`reports/index.html`)
* Optional AES-256-CBC encryption of the output directory (`--encrypt`, requires `openssl`) — same approach as the Linux/macOS collectors
* Optional Forensicator AI per-finding verdicts (A `config.json` "ai" block and provider support — Ollama/OpenAI/Azure OpenAI/Anthropic), implemented natively in Python

---

## 📦 Dependencies

```bash
pip install -r requirements.txt
# netmiko, ntc-templates
```

AES encryption shells out to `openssl` (already assumed present)

---

## 🔨 Usage

```bash
cd Network

# 1. Edit config.json — add your device(s) under "devices"
# 2. Export the password for each device's configured password_env
export FORENSICATOR_NET_PASSWORD="..."

# 3. Run against every device in config.json
python3 Forensicator.py -case CASE-001 -name "Analyst" -title "Incident" -loc "DC1" -device "Core Switch Stack"

# Or a single device without editing config.json:
python3 Forensicator.py -case CASE-001 --host 10.0.0.1 --device-type cisco_ios --username netops-readonly --password-env FORENSICATOR_NET_PASSWORD

# Encrypt the output, cap concurrency at 8 devices, skip the HTML report:
python3 Forensicator.py -case CASE-001 --max-workers 8 --encrypt --no-report
```

Output lands under `<hostname-or-ip>/` for each device — one directory per device collected, matching the Windows collector's own layout:

```
<hostname-or-ip>/
├── artifacts/              (reserved artifact types, e.g. RAM)
├── investigation/
│   ├── <category>/<check>-finding.json
│   ├── metadata.json
│   └── case-summary.json
├── reports/
│   └── index.html          (this device's own report — not combined across devices)
├── investigation.zip
└── Readme.txt
```

Each device's `reports/index.html` covers only that device's own findings

---

## 🔎 Baseline Collection

`show version`, running config, active sessions, ARP table, MAC address table, routing table, ACLs/firewall filters, logs, neighbor discovery (CDP or LLDP), SNMP config, SSH/management config, clock, and NTP status — plus local user accounts extracted from the running config. Exact command syntax differs per vendor (see each `collectors/<vendor>.py`); the artifact_key and Detection Insight are shared across vendors wherever the underlying concept is the same.

---

## 🧠 Detection Rules (starter set)

| Rule | What it catches | MITRE |
|---|---|---|
| `insecure-mgmt-plane` | Telnet permitted, or a VTY line with no `access-class` | T1021.001 |
| `weak-snmp-community` | `public`/`private` SNMP community, or SNMPv1/v2c in use | T1552.001 |
| `unauthorized-local-accounts` | A local account not on the `config.json` baseline allow-list | T1136.001 |
| `missing-aaa` | No `aaa authentication login` enforcement configured | T1078 |

Toggle any rule on/off via `config.json`'s `detection_rules` block; tune the keyword lists and the local-account baseline there too — no code changes needed.

---

## 🤖 Forensicator AI

Off by default. When enabled, each finding gets a real, plain-language verdict written into its `ai_analysis` field.

```jsonc
"ai": {
  "enabled": true,
  "provider": "ollama",
  "base_url": "http://localhost:11434",
  "model": "mistral:7b-instruct"
}
```

No extra dependency — HTTP calls go through Python's own standard library. A startup reachability probe prints once before collection begins so you know up front whether findings will get a verdict on that run.

---

## 🔒 Encryption

`--encrypt` tars the entire output directory, encrypts it with `openssl enc -aes-256-cbc -pbkdf2 -iter 100000`, and writes the random key to `<case>_ENCRYPTION_KEY.txt` next to the archive, The unencrypted tarball is deleted once encryption succeeds. Requires `openssl` on the collecting machine; if it's missing, collection still completes and a warning is logged — output is simply left unencrypted.

---

## 📸 Screenshots

<details>
<summary>Terminal Output</summary>

<img width="1375" height="671" alt="image" src="https://github.com/user-attachments/assets/882d683b-9474-4484-8992-9faf64919f5c" />
<br>
<img width="1222" height="203" alt="image" src="https://github.com/user-attachments/assets/b414d43b-5cf8-41ab-857f-6b818738234d" />


</details>

<details>
<summary>HTML Dashboard</summary>

<img width="1541" height="833" alt="image" src="https://github.com/user-attachments/assets/db20da15-1132-4ca4-be5f-21c13434e1ed" />
<br>
<img width="1539" height="1101" alt="image" src="https://github.com/user-attachments/assets/4726b4a9-8da2-4ee0-8ddc-01bd31a5137c" />


</details>


---

## ✍ Notes

* Credentials are never written to config.json, findings, or logs — only an environment-variable *name* (`password_env`) is stored; the actual password is read from the environment at run time.
* The encryption key file is plaintext — move it to secure storage separately from the archive it decrypts, the same operational practice as the Linux/macOS collectors' own key files.
* Use a dedicated, least-privilege, read-only account for the credentials this module uses.

---

## 📄 License

Same license as the rest of the Live Forensicator project — see the repository root `LICENSE`.
