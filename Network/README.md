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

**Vendor support:** Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos, and VyOS for collection — every vendor gets full collection and Detection Insight on every baseline artifact. Of the 20 detection rules, most are Cisco/Arista IOS-syntax-specific (NX-OS and EOS share close-enough config syntax with IOS) and don't apply to Junos/VyOS's fundamentally different `set`-style config; `unauthorized-local-accounts`, `image-hash-mismatch`, `unexpected-flash-files`, `ntp-tampering`, `active-session-unexpected-source`, `brute-force-pattern`, `device-outbound-c2`, and `config-section-hash-mismatch` DO cover all 6 device types. `config-drift-running-vs-startup` covers 5 of 6 — VyOS is excluded, since the real running-vs-saved diff command (`compare saved`) only works inside configuration mode, which this collector deliberately never enters (read-only, operational-mode-only by design). See `rules/rules.json`'s per-rule `_note` fields and each `collectors/<vendor>.py`'s docstring for exactly which rules apply where and why.

**Safe by default:** every collected command is read-only. No configuration changes are made to any device.

---

## ⚙️ Key Features

* SSH-based collection via Netmiko — no vendor SSH/driver handling reimplemented
* Structured parsing of CLI output where an [ntc-templates](https://github.com/networktocode/ntc-templates) parser exists for the command, raw text always captured regardless
* Detection Insight on every finding — plain-language explanation, MITRE ATT&CK mapping, and recommendations, matching the Windows collector's knowledge-base pattern
* Config-driven: device inventory, which rules are enabled, and every rule's baseline (local accounts, NTP/syslog servers, expected automation policies, tunnel endpoints, etc.) are all set in `config.json` — no code changes needed to tune a deployment
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
# 2b. If the account logs in at user EXEC ('>') rather than privileged EXEC ('#'),
#     also set secret_env in config.json and export its enable/privileged-mode secret
export FORENSICATOR_NET_SECRET="..."

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

## 🧠 Detection Rules (20 rules)

| Rule | What it catches | MITRE |
|---|---|---|
| `insecure-mgmt-plane` | Telnet permitted, or a VTY line with no `access-class` | T1021.001 |
| `weak-snmp-community` | `public`/`private` SNMP community, or SNMPv1/v2c in use | T1552.001 |
| `unauthorized-local-accounts` | A local account not on the baseline allow-list (all 6 vendors) | T1136.001 |
| `missing-aaa` | No `aaa authentication login` enforcement configured | T1078 |
| `logic-implant-persistence` | Unbaselined EEM applet / task-scheduler entry / event-options policy | T1053 |
| `boot-image-tampering` | A `boot system` statement pointing to TFTP/FTP or outside the baseline | T1542.005 |
| `image-hash-mismatch` | Running image version not in the known-good baseline (best-effort — see below) | T1601.001 |
| `unexpected-flash-files` | A file in persistent storage not on the baseline | T1105 |
| `logging-tampering` | `no logging`, or a buffer size below the configured minimum | T1562 |
| `syslog-destination-changed` | Syslog destination missing from or added outside the baseline | T1562 |
| `ntp-tampering` | An expected NTP server missing from the device's config | T1070 |
| `active-session-unexpected-source` | A management session sourced from outside the baseline IP range(s) | T1133 |
| `aaa-fallback-abuse` | AAA-unreachable and a local login both in the retained log buffer | T1556 |
| `brute-force-pattern` | Repeated auth failures (over threshold) followed by a success | T1110 |
| `unexpected-span-session` | A SPAN/mirror session not on the baseline | T1040 |
| `unexpected-tunnel-interface` | A GRE/tunnel interface with an endpoint outside the baseline | T1572 |
| `acl-loosened` | A `permit ip any any`-style broad ACL entry | T1562.004 |
| `device-outbound-c2` | The device itself has a connection to a destination outside the baseline | T1071 |
| `config-drift-running-vs-startup` | Running config differs from saved/startup config | T1562 |
| `config-section-hash-mismatch` | AAA/ACL/routing config lines hash differently than the baseline | T1562 |

Toggle any rule on/off via `config.json`'s `detection_rules` block. Per-vendor coverage varies — several rules are Cisco/Arista-IOS-syntax-specific and don't apply to Junos/VyOS's `set`-style config (see `rules/rules.json`'s `_note` field on each rule and `rules/engine.py`'s module docstring for exactly why).

**Baselines** (`config.json`'s `baselines` block, including `expected_local_users`) are all optional — an unpopulated baseline just means that specific rule has nothing to compare against yet. Two automatic severity adjustments apply on top of the base rule logic:
- **No-baseline downgrade**: a few rules (`logic-implant-persistence`, `boot-image-tampering`, `unexpected-flash-files`, `unexpected-span-session`, `unexpected-tunnel-interface`) still surface real device content even with an empty baseline (so you have something to review when first populating it), but at `informational` severity rather than full severity — so a fresh deployment with nothing baselined yet doesn't read as a wall of critical findings.
- **Correlation bump**: if 2+ findings from different MITRE tactics fire on the *same device* in the *same run*, each involved finding's severity is bumped one level — a same-device, same-run signal only, not cross-device correlation (this module doesn't attempt that).

`image-hash-mismatch` is worth calling out specifically: it's a best-effort check against a version identifier in `known_good_image_hashes`' keys, **not** cryptographic hash verification — computing a real hash requires a follow-up command scoped to the exact image filename, which this single-pass collector doesn't issue automatically. Treat a fired finding as a prompt to verify manually (e.g. IOS-XE's `show software authenticity running`), not a completed check.

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

<img width="1562" height="832" alt="image" src="https://github.com/user-attachments/assets/ad6aef32-f648-4d79-878e-4270f37f3de7" />
<br>
<img width="1541" height="833" alt="image" src="https://github.com/user-attachments/assets/db20da15-1132-4ca4-be5f-21c13434e1ed" />
<br>
<img width="1539" height="1101" alt="image" src="https://github.com/user-attachments/assets/4726b4a9-8da2-4ee0-8ddc-01bd31a5137c" />


</details>


---

## ✍ Notes

* Credentials are never written to config.json, findings, or logs — only an environment-variable *name* (`password_env`, `secret_env`) is stored; the actual password/secret is read from the environment at run time.
* On Cisco/Arista-family devices, the collector calls Netmiko's `enable()` right after connecting, so an account that logs in at user EXEC (`>`) still reaches privileged EXEC (`#`) for commands like `show running-config` that otherwise fail with `% Invalid input detected`. This is a no-op if the account already logs in at privilege 15, and a no-op on VyOS/Junos (no enable-mode concept). If the account needs a real enable secret and `secret_env` isn't set, connect still succeeds but a WARN-level log line calls it out up front instead of leaving it to surface as a wall of per-command failures.
* The encryption key file is plaintext — move it to secure storage separately from the archive it decrypts, the same operational practice as the Linux/macOS collectors' own key files.
* Use a dedicated, least-privilege, read-only account for the credentials this module uses.

---

## 📄 License

Same license as the rest of the Live Forensicator project — see the repository root `LICENSE`.
