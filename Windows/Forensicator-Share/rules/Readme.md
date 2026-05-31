# Live Forensicator — Custom Detection Rules

This guide explains how to create custom detection rules for Live Forensicator's Sigma-compatible rule engine. No compilation step is needed — drop a JSON file into the right folder and it is automatically loaded on the next scan.

---

## Table of Contents

1. [How the Rule Engine Works](#how-the-rule-engine-works)
2. [Folder Structure](#folder-structure)
3. [Rule File Anatomy](#rule-file-anatomy)
4. [Top-Level Fields Reference](#top-level-fields-reference)
5. [Available Sources](#available-sources)
6. [Items — Writing Match Groups](#items--writing-match-groups)
7. [Operators](#operators)
8. [Condition — Combining Items](#condition--combining-items)
9. [Expression Types Reference](#expression-types-reference)
10. [Complete Examples](#complete-examples)
11. [Custom IOC Files](#custom-ioc-files)
12. [Tips and Common Mistakes](#tips-and-common-mistakes)

---

## How the Rule Engine Works

At scan time, `SigmaRuntime.ps1` does the following:

1. Reads `Forensicator-Share/rules/sources.json` to learn which Windows event logs to query and how to map event data fields.
2. Recursively scans every `.json` file under `Forensicator-Share/rules/` (including any sub-folder you create).
3. For each **source** selected for scanning, it queries the matching Windows event log, reads each event record, and runs every rule that declares that source in its `sources` array.
4. When a rule matches, the hit is recorded with its title, severity level, MITRE tags, matched event ID, timestamp, user, command line, and process image.

Because discovery is recursive there is no registration step. Put a valid JSON file anywhere under `rules/` and it will be loaded automatically.

---

## Folder Structure

```
Forensicator-Share/
├── custom_hashes.txt          ← operator-managed hash IOC list
├── custom_iocs.txt            ← operator-managed domain/IP/URL IOC list
└── rules/
    ├── sources.json           ← DO NOT EDIT — source definitions
    └── windows/
        ├── sigma/             ← built-in community rules (fetched from Sigma repo)
        └── custom/            ← YOUR custom rules go here
            ├── my_rule_1.json
            └── my_rule_2.json
```

Discovery is fully recursive — you can create any sub-folder structure under `rules/` and all `.json` files will be loaded automatically. No registration is needed.

---

## Rule File Anatomy

A rule file contains a single JSON object (or an array of objects for multiple rules in one file).

```json
{
  "metadata": [
    {
      "title":       "Detect Something Bad",
      "author":      "Your Name",
      "rule_id":     "custom-001",
      "date":        "2026-01-01",
      "description": "Full description of what this rule detects and why it matters.",
      "references":  ["https://attack.mitre.org/techniques/T1059/"]
    }
  ],

  "title":     "Detect Something Bad",
  "rule_id":   "custom-001",
  "rule_file": "rules/windows/custom/my_rule_1.json",
  "category":  "process_creation",
  "level":     "high",
  "status":    "stable",
  "enabled":   true,
  "tags":      ["attack.execution", "attack.t1059"],
  "sources":   ["security_process_creation", "sysmon_process_creation"],

  "items": {
    "susp_cmd": {
      "type":        "field",
      "field":       "CommandLine",
      "operator":    "contains",
      "values":      ["malicious.exe", "evil-payload"],
      "windash":     false,
      "ignore_case": true
    }
  },

  "condition": {
    "type": "item_ref",
    "name": "susp_cmd"
  }
}
```

> **`metadata` vs root fields:** `title` and `rule_id` must appear **both** inside `metadata[]` and at the root level. The engine reads them from the root; `metadata` is purely for documentation and is ignored at runtime.

---

## Top-Level Fields Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `metadata` | array | recommended | Documentation block — see [Rule File Anatomy](#rule-file-anatomy). Ignored by the engine at runtime |
| `title` | string | ✅ | Human-readable name shown in results and logs. Must also appear inside `metadata[]` |
| `rule_id` | string | ✅ | Unique identifier for the rule. Must also appear inside `metadata[]` |
| `rule_file` | string | ✅ | Relative path from `rules/`, used in deduplication keys |
| `category` | string | recommended | Informational category (e.g. `process_creation`, `ps_script`) |
| `level` | string | ✅ | Severity: `critical`, `high`, `medium`, `low`, `informational` |
| `status` | string | recommended | Rule maturity: `stable`, `test`, `experimental` |
| `enabled` | boolean | optional | Set to `false` to disable the rule without deleting it. Omit or set `true` to enable (default). Community rules without this field are always loaded |
| `tags` | array of strings | optional | MITRE ATT&CK tags (e.g. `"attack.t1059.001"`) |
| `sources` | array of strings | ✅ | Which source IDs this rule applies to (see [Available Sources](#available-sources)) |
| `items` | object | ✅ | Named match groups used in `condition` |
| `condition` | object | ✅ | Logical expression that must evaluate to `true` for a match |

### Severity Levels

The minimum severity scanned is controlled by the tool's configuration. Rules below the threshold are silently skipped.

| Level | Numeric Value |
|---|---|
| `critical` | 5 |
| `high` | 4 |
| `medium` | 3 |
| `low` | 2 |
| `informational` | 1 |

---

## Available Sources

Each source maps to a specific Windows event log and event IDs. Use the `id` value in your rule's `sources` array.

### `security_process_creation`
- **Log:** `Security`
- **Event IDs:** `4688` (process creation with command line, requires audit policy)
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Full path of the new process (`NewProcessName`) |
| `CommandLine` | Full command line of the new process |
| `ParentImage` | Full path of the parent process |
| `ParentCommandLine` | Command line of the parent process |
| `User` | Account that launched the process (`SubjectUserName`) |
| `ProcessId` | PID of the new process |
| `EventID` | Always `4688` |
| `Channel` | Always `Security` |
| `Provider_Name` | Always `Microsoft-Windows-Security-Auditing` |

---

### `sysmon_process_creation`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `1`
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Full path of the process |
| `CommandLine` | Full command line |
| `OriginalFileName` | Original PE filename from resources |
| `ParentImage` | Parent process path |
| `ParentCommandLine` | Parent command line |
| `User` | Executing user |
| `ProcessId` | PID |
| `CurrentDirectory` | Working directory at launch |
| `Description` | PE file description |
| `Company` | PE company name |
| `Product` | PE product name |
| `Hashes` | Hash string in `MD5=...,SHA256=...` format |
| `IntegrityLevel` | Process integrity level |
| `Signed` | `true` / `false` |
| `Signature` | Certificate subject |
| `SignatureStatus` | `Valid`, `Invalid`, etc. |
| `EventID` | Always `1` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

### `powershell_script_block`
- **Log:** `Microsoft-Windows-PowerShell/Operational`
- **Event IDs:** `4104` (Script Block Logging — must be enabled)
- **Available Fields:**

| Field | Description |
|---|---|
| `ScriptBlockText` | The full PowerShell script block content |
| `Path` | Script file path (empty for interactive) |
| `EventID` | Always `4104` |
| `Channel` | Always `Microsoft-Windows-PowerShell/Operational` |
| `Provider_Name` | Always `Microsoft-Windows-PowerShell` |

---

### `powershell_module_logging`
- **Log:** `Microsoft-Windows-PowerShell/Operational`
- **Event IDs:** `4103` (Module Logging — must be enabled)
- **Available Fields:**

| Field | Description |
|---|---|
| `Payload` | Module pipeline execution detail |
| `Path` | Module path |
| `EventID` | Always `4103` |
| `Channel` | Always `Microsoft-Windows-PowerShell/Operational` |
| `Provider_Name` | Always `Microsoft-Windows-PowerShell` |

---

### `powershell_classic`
- **Log:** `Windows PowerShell`
- **Event IDs:** `400`, `800`
- **Available Fields:**

| Field | Description |
|---|---|
| `HostApplication` | The application that hosted PowerShell |
| `EngineVersion` | PowerShell engine version |
| `EventID` | `400` or `800` |
| `Channel` | Always `Windows PowerShell` |
| `Provider_Name` | Always `PowerShell` |

---

### `sysmon_image_load`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `7`
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Process loading the DLL |
| `ImageLoaded` | Full path of the loaded DLL |
| `OriginalFileName` | DLL original filename from resources |
| `Description` | PE description |
| `Company` | PE company |
| `Product` | PE product |
| `Hashes` | Hash string |
| `Signed` | `true` / `false` |
| `Signature` | Certificate subject |
| `SignatureStatus` | `Valid`, `Invalid`, etc. |
| `User` | User |
| `EventID` | Always `7` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

### `sysmon_network_connection`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `3`
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Process making the connection |
| `User` | User |
| `Protocol` | `tcp` / `udp` |
| `SourceIp` | Source IP address |
| `SourceHostname` | Source hostname |
| `SourcePort` | Source port |
| `DestinationIp` | Destination IP address |
| `DestinationHostname` | Destination hostname |
| `DestinationPort` | Destination port |
| `Initiated` | `true` if outbound |
| `EventID` | Always `3` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

### `sysmon_pipe_created`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `17` (pipe created), `18` (pipe connected)
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Process that created/connected the pipe |
| `PipeName` | Named pipe path |
| `User` | User |
| `EventID` | `17` or `18` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

### `sysmon_file_event`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `11` (file create)
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Process that created the file |
| `TargetFilename` | Full path of the created file |
| `User` | User |
| `EventID` | Always `11` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

### `sysmon_registry_event`
- **Log:** `Microsoft-Windows-Sysmon/Operational`
- **Event IDs:** `12` (key create/delete), `13` (value set), `14` (key/value rename)
- **Available Fields:**

| Field | Description |
|---|---|
| `Image` | Process making the registry change |
| `EventType` | `CreateKey`, `DeleteKey`, `SetValue`, etc. |
| `TargetObject` | Full registry key/value path |
| `Details` | Value data (for `SetValue`) |
| `User` | User |
| `EventID` | `12`, `13`, or `14` |
| `Channel` | Always `Microsoft-Windows-Sysmon/Operational` |

---

## Items — Writing Match Groups

The `items` object is a dictionary where each key is a name you choose freely. Each value is an **expression node** (see [Expression Types Reference](#expression-types-reference)).

The simplest item is a `field` match:

```json
"items": {
  "my_item": {
    "type":        "field",
    "field":       "CommandLine",
    "operator":    "contains",
    "values":      ["mimikatz", "sekurlsa"],
    "ignore_case": true,
    "windash":     false
  }
}
```

Items can also be nested `all` / `any` / `not` expressions:

```json
"items": {
  "is_powershell": {
    "type":     "field",
    "field":    "Image",
    "operator": "endswith",
    "values":   ["\\powershell.exe", "\\pwsh.exe"],
    "ignore_case": true
  },
  "has_download": {
    "type":     "field",
    "field":    "CommandLine",
    "operator": "contains",
    "values":   ["DownloadString", "DownloadFile", "WebClient"],
    "ignore_case": true
  },
  "both_required": {
    "type": "all",
    "children": [
      { "type": "item_ref", "name": "is_powershell" },
      { "type": "item_ref", "name": "has_download" }
    ]
  }
}
```

### The `match` property (field items only)

By default, a multi-value field item matches if **any** value matches (`match: "any"`). Set `"match": "all"` to require **all** values to match the same field:

```json
"operator": "contains",
"match":    "all",
"values":   ["-enc", "-nop"]
```

---

## Operators

| Operator | Description | Supports Wildcards |
|---|---|---|
| `contains` | Field contains the value anywhere | ✅ (`*`, `?`) |
| `startswith` | Field starts with the value | ✅ |
| `endswith` | Field ends with the value | ✅ |
| `exact` | Field exactly equals the value | ✅ |
| `re` | Value is a full .NET regex; field must match | ❌ |
| `cidr` | Field (IP string) belongs to a CIDR range | ❌ |
| `is_null` | Field is absent or empty (no `values` needed) | ❌ |

### Wildcards in values

For `contains`, `startswith`, `endswith`, and `exact`, the `*` character matches any sequence of characters and `?` matches any single character:

```json
"values": ["*\\AppData\\*\\*.exe"]
```

### `windash` — automatic slash/dash expansion

Set `"windash": true` to make the engine automatically test both `-` and `/` variants of each value. Useful for command-line switch detection:

```json
"operator": "contains",
"values":   ["-enc"],
"windash":  true
```

This will also match `/enc` without you having to list both.

### `ignore_case`

Set `"ignore_case": true` (default behaviour) for case-insensitive matching. Set to `false` for case-sensitive matching (rare).

---

## Condition — Combining Items

The `condition` field is the root expression that must evaluate to `true` for the rule to fire. You can reference items by name or build inline logic.

### Reference a single item

```json
"condition": {
  "type": "item_ref",
  "name": "my_item"
}
```

### Require ALL items to match (`all`)

```json
"condition": {
  "type": "all",
  "children": [
    { "type": "item_ref", "name": "item_a" },
    { "type": "item_ref", "name": "item_b" }
  ]
}
```

### Require ANY item to match (`any`)

```json
"condition": {
  "type": "any",
  "children": [
    { "type": "item_ref", "name": "item_a" },
    { "type": "item_ref", "name": "item_b" }
  ]
}
```

### Negate a condition (`not`)

```json
"condition": {
  "type": "not",
  "child": { "type": "item_ref", "name": "false_positive_filter" }
}
```

### Combine positives with a NOT exclusion

```json
"condition": {
  "type": "all",
  "children": [
    { "type": "item_ref", "name": "suspicious_activity" },
    {
      "type": "not",
      "child": { "type": "item_ref", "name": "known_good_parent" }
    }
  ]
}
```

### Match all items whose names share a prefix (`wildcard_ref`)

```json
"condition": {
  "type":    "wildcard_ref",
  "pattern": "filter_*",
  "mode":    "any"
}
```

| `mode` | Meaning |
|---|---|
| `any` (default) | True if at least one matching item is true |
| `all` | True only if every matching item is true |

---

## Expression Types Reference

| `type` | Purpose | Required Properties |
|---|---|---|
| `field` | Match an event field | `field`, `operator`, `values` |
| `raw` | Match anywhere in the raw event text / XML | `operator`, `values` |
| `all` | AND — all children must be true | `children` (array of expressions) |
| `any` | OR — at least one child must be true | `children` (array of expressions) |
| `not` | Negate one expression | `child` (single expression) |
| `item_ref` | Reference a named item from `items` | `name` |
| `wildcard_ref` | Reference all items whose names match a glob | `pattern`, optionally `mode` |

---

## Complete Examples

### Example 1 — Credential Dumping via Command Line (process creation)

```json
{
  "title":     "Credential Dumping Tool Detected",
  "rule_id":   "custom-cred-dump-001",
  "rule_file": "rules/windows/custom/custom_cred_dump.json",
  "category":  "process_creation",
  "level":     "critical",
  "tags":      ["attack.credential_access", "attack.t1003"],
  "sources":   ["security_process_creation", "sysmon_process_creation"],

  "items": {
    "known_tools": {
      "type":        "field",
      "field":       "Image",
      "operator":    "endswith",
      "values":      ["\\mimikatz.exe", "\\wce.exe", "\\pwdump7.exe"],
      "ignore_case": true
    },
    "procdump_lsass": {
      "type": "all",
      "children": [
        {
          "type":        "field",
          "field":       "Image",
          "operator":    "endswith",
          "values":      ["\\procdump.exe", "\\procdump64.exe"],
          "ignore_case": true
        },
        {
          "type":        "field",
          "field":       "CommandLine",
          "operator":    "contains",
          "values":      ["lsass"],
          "ignore_case": true
        }
      ]
    },
    "comsvcs_minidump": {
      "type": "all",
      "children": [
        {
          "type":        "field",
          "field":       "Image",
          "operator":    "endswith",
          "values":      ["\\rundll32.exe"],
          "ignore_case": true
        },
        {
          "type":        "field",
          "field":       "CommandLine",
          "operator":    "contains",
          "values":      ["MiniDump"],
          "ignore_case": true
        }
      ]
    }
  },

  "condition": {
    "type": "any",
    "children": [
      { "type": "item_ref", "name": "known_tools" },
      { "type": "item_ref", "name": "procdump_lsass" },
      { "type": "item_ref", "name": "comsvcs_minidump" }
    ]
  }
}
```

---

### Example 2 — Suspicious PowerShell Download Cradle (script block logging)

```json
{
  "title":     "PowerShell Download Cradle Detected",
  "rule_id":   "custom-ps-download-001",
  "rule_file": "rules/windows/custom/custom_ps_download.json",
  "category":  "ps_script",
  "level":     "high",
  "tags":      ["attack.execution", "attack.t1059.001", "attack.defense_evasion", "attack.t1140"],
  "sources":   ["powershell_script_block"],

  "items": {
    "iex_present": {
      "type":        "field",
      "field":       "ScriptBlockText",
      "operator":    "contains",
      "values":      ["IEX", "Invoke-Expression"],
      "ignore_case": true
    },
    "download_method": {
      "type":        "field",
      "field":       "ScriptBlockText",
      "operator":    "contains",
      "values":      ["DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest", "curl ", "wget "],
      "ignore_case": true
    }
  },

  "condition": {
    "type": "all",
    "children": [
      { "type": "item_ref", "name": "iex_present" },
      { "type": "item_ref", "name": "download_method" }
    ]
  }
}
```

---

### Example 3 — Suspicious Named Pipe (Cobalt Strike / C2 indicators)

```json
{
  "title":     "Suspicious Named Pipe Indicative of C2",
  "rule_id":   "custom-pipe-c2-001",
  "rule_file": "rules/windows/custom/custom_named_pipe_c2.json",
  "category":  "pipe_created",
  "level":     "high",
  "tags":      ["attack.command_and_control", "attack.t1071"],
  "sources":   ["sysmon_pipe_created"],

  "items": {
    "cs_default_pipes": {
      "type":        "field",
      "field":       "PipeName",
      "operator":    "contains",
      "values":      ["\\msagent_", "\\postex_", "\\status_", "\\mojo.", "\\wkssvc_"],
      "ignore_case": true
    }
  },

  "condition": {
    "type": "item_ref",
    "name": "cs_default_pipes"
  }
}
```

---

### Example 4 — CIDR-based Network Detection

```json
{
  "title":     "Outbound Connection to Known Malicious Range",
  "rule_id":   "custom-net-mal-range-001",
  "rule_file": "rules/windows/custom/custom_malicious_cidr.json",
  "category":  "network_connection",
  "level":     "high",
  "tags":      ["attack.command_and_control"],
  "sources":   ["sysmon_network_connection"],

  "items": {
    "mal_range": {
      "type":     "field",
      "field":    "DestinationIp",
      "operator": "cidr",
      "values":   ["198.51.100.0/24", "203.0.113.0/24"]
    }
  },

  "condition": {
    "type": "item_ref",
    "name": "mal_range"
  }
}
```

---

### Example 5 — Registry Persistence via Run Key

```json
{
  "title":     "Registry Run Key Persistence",
  "rule_id":   "custom-persist-runkey-001",
  "rule_file": "rules/windows/custom/custom_registry_runkey.json",
  "category":  "registry_event",
  "level":     "high",
  "tags":      ["attack.persistence", "attack.t1547.001"],
  "sources":   ["sysmon_registry_event"],

  "items": {
    "run_key_path": {
      "type":        "field",
      "field":       "TargetObject",
      "operator":    "contains",
      "values":      [
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      ],
      "ignore_case": true
    },
    "not_system_installer": {
      "type":        "field",
      "field":       "Image",
      "operator":    "contains",
      "values":      ["\\Windows\\", "\\Program Files\\"],
      "ignore_case": true
    }
  },

  "condition": {
    "type": "all",
    "children": [
      { "type": "item_ref", "name": "run_key_path" },
      {
        "type":  "not",
        "child": { "type": "item_ref", "name": "not_system_installer" }
      }
    ]
  }
}
```

---

## Custom IOC Files

Two plain-text files let you add your own indicators. They are **never overwritten** by automatic feed updates and are the single source of truth for operator IOCs.

### `Forensicator-Share/custom_hashes.txt`

Add one MD5 or SHA256 hash per line. Lines starting with `#` are treated as comments.

```
# Custom known-bad hashes — operator maintained
# One hash per line (MD5 or SHA256, case-insensitive)

e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
d41d8cd98f00b204e9800998ecf8427e
```

At scan time these are merged with the downloaded hash feed into the same lookup set. Any process hash that appears in this file will be flagged under the hash-lookup detection.

### `Forensicator-Share/custom_iocs.txt`

Add one domain, IP address, or URL per line. Lines starting with `#` are comments.

```
# Custom operator IOCs — domains, IPs, URLs
# One entry per line, case-insensitive

evil-c2.example.com
192.168.66.100
http://badactor.net/payload
```

This file feeds **three** detection layers simultaneously:

| Layer | How it uses `custom_iocs.txt` |
|---|---|
| **Browser history check** | Full URL match + bare domain extraction + parent-domain walk (e.g. `sub.evil.com` matches `evil.com`) |
| **Sigma IOC network rule** (`custom-net-ioc-001`) | Domains injected into `bad_hostname`; IPs injected into `bad_ip`. Fires on Sysmon Event 3 outbound connections from non-browser processes |
| **Sigma IOC script block rule** (`custom-ps-ioc-scriptblock-001`) | All domains and IPs injected into `ioc_in_script`. Fires on PowerShell Event 4104 script blocks that contain the IOC and a download verb |

The Sigma rule injection happens **automatically at scan time** — you never need to edit the rule JSON files manually. Just add entries to `custom_iocs.txt` and they will be active on the next run.

> **Why `malicious_URLs.txt` is not used in Sigma rules:** The downloaded feed contains specific file paths on shared hosting platforms (e.g. `raw.githubusercontent.com/user/repo/malware.exe`). Extracting the domain would flag every GitHub visit as malicious. That feed is used only for exact URL matching in the browser history check.

---

## Tips and Common Mistakes

### ✅ Best Practices

- **One rule per file** is the cleanest approach, but a file can contain a JSON array of multiple rule objects.
- Always include the `metadata` block with `title`, `author`, `rule_id`, `date`, `description`, and `references`. Remember `title` and `rule_id` must also be at the root level.
- Use `sysmon_process_creation` when Sysmon is available — it gives richer fields (`OriginalFileName`, `Hashes`, `IntegrityLevel`) than `security_process_creation`.
- Use `"ignore_case": true` for all path and command-line matching.
- Always set `"windash": true` when matching CLI switches (things like `-enc`, `/enc`).
- Use the `not` expression to suppress known-good processes and reduce false positives.
- Keep `rule_id` values unique across all your rule files.
- To temporarily disable a noisy rule, add `"enabled": false` rather than deleting the file. Community rules from the Sigma repo have no `enabled` field and are always loaded — do not add it to them.
- Manage all your IOC domains and IPs in `custom_iocs.txt` only — they are automatically injected into the IOC Sigma rules at scan time. Do not edit `custom_ioc_network_connection.json` or `custom_ioc_scriptblock.json` manually.

### ❌ Common Mistakes

| Mistake | Fix |
|---|---|
| Referencing a source ID that isn't in `sources.json` | Only use the 10 IDs listed in [Available Sources](#available-sources) |
| Putting a field name that doesn't exist in the source | Check the field map table for the specific source you declared |
| `"type": "field"` in `condition` without an `items` wrapper | Inline `field` nodes work directly inside `condition` — `items` is just for reuse via `item_ref` |
| Forgetting `"type"` on an expression node | Every expression node requires a `"type"` property |
| Using `children` for `not` | `not` uses `"child"` (singular), not `"children"` |
| Empty `values` array with `is_null` | `is_null` ignores `values` — you can omit the array entirely |
| Regex in `values` when `operator` is `contains` | Use `"operator": "re"` for regex; the other operators treat `*` as a glob wildcard, not regex |
| Setting `"match": "all"` expecting multiple fields to all match | `match: "all"` means all **values** in the `values` array must match the **same** field; for multi-field AND logic use an `all` expression with multiple `field` nodes |

### Debugging a rule

If a rule does not appear to fire:

1. Check the forensicator log for `Sigma rule evaluation failed` — this indicates a JSON parse or evaluation error.
2. Verify the event log exists on the target machine using `Get-WinEvent -ListLog <log_name>`.
3. Confirm the required audit policy is enabled (e.g., process creation command-line auditing for event 4688 / Sysmon installed for event 1).
4. Check that `"enabled"` is not set to `false` in the rule file. The log line `Loaded Sigma rule set` will show a `Disabled (enabled:false): N` count if any rules were skipped.
5. Temporarily lower the `level` to `informational` and the minimum scan level in `config.json` to `informational` to see if the rule is being skipped on severity.
6. Add a `raw` matcher targeting the raw event XML as a fallback to verify the event data is actually present in the log.
