#!/usr/bin/env python3
"""
Forensicator Linux Sigma engine.

Evaluates a compiled SigmaHQ Linux ruleset (see rules/linux/sigma_rules.json,
produced offline by the project's own YAML->AST compiler, not at runtime)
against whatever structured telemetry actually exists on the box:

  - auditd, via `ausearch -i` (only if auditd is installed AND has data for
    the requested window -- most distros do not enable exec auditing by
    default, so auditd-sourced rules simply produce zero matches there,
    exactly like a real Sigma pipeline pointed at an empty index).
  - journald, via `journalctl -o json` (near-universal on modern distros).

No external Python dependencies -- stdlib only, since this runs on whatever
python3 happens to be on the target box during live triage.
"""
import sys
import os
import re
import json
import subprocess
import argparse
import datetime


# ----------------------------------------------------------------------
# Rule matching (mirrors Windows/Forensicator-Share/SigmaRuntime.ps1)
# ----------------------------------------------------------------------

_REGEX_CACHE = {}


def wildcard_to_regex(value, mode):
    escaped = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
    if mode == "exact":
        return "^" + escaped + "$"
    if mode == "contains":
        return "^.*" + escaped + ".*$"
    if mode == "startswith":
        return "^" + escaped + ".*$"
    if mode == "endswith":
        return "^.*" + escaped + "$"
    raise ValueError(mode)


def cached_regex(pattern, ignore_case):
    key = (pattern, ignore_case)
    rx = _REGEX_CACHE.get(key)
    if rx is None:
        flags = re.IGNORECASE if ignore_case else 0
        rx = re.compile(pattern, flags)
        _REGEX_CACHE[key] = rx
    return rx


def scalar_match(actual, expected, operator, ignore_case):
    if actual is None:
        return False
    if operator == "re":
        try:
            return cached_regex(expected, ignore_case).search(actual) is not None
        except re.error:
            return False
    pattern = wildcard_to_regex(expected, operator)
    return cached_regex(pattern, ignore_case).match(actual) is not None


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def test_field(node, fields):
    actual_values = as_list(fields.get(node["field"]))
    if node["operator"] == "is_null":
        return len(actual_values) == 0 or all(not v for v in actual_values)
    if not actual_values:
        return False
    for actual in actual_values:
        if scalar_match(str(actual), node["value"], node["operator"], node["ignore_case"]):
            return True
    return False


def test_raw(node, raw_text):
    return scalar_match(raw_text or "", node["value"], node["operator"], node["ignore_case"])


def evaluate(node, fields, raw_text):
    t = node["type"]
    if t == "and":
        return all(evaluate(c, fields, raw_text) for c in node["children"])
    if t == "or":
        return any(evaluate(c, fields, raw_text) for c in node["children"])
    if t == "not":
        return not evaluate(node["child"], fields, raw_text)
    if t == "field":
        return test_field(node, fields)
    if t == "raw":
        return test_raw(node, raw_text)
    return False


LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def load_rules(path, min_level):
    with open(path, encoding="utf-8") as fh:
        rules = json.load(fh)
    min_rank = LEVEL_RANK.get(min_level, 3)
    return [r for r in rules if LEVEL_RANK.get(r["level"], 3) >= min_rank]


# ----------------------------------------------------------------------
# auditd event source
# ----------------------------------------------------------------------

AUDIT_LINE_RE = re.compile(r'type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)$')
KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')


def parse_audit_kv(text):
    out = {}
    for m in KV_RE.finditer(text):
        key, val = m.group(1), m.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out[key] = val
    return out


def strip_interpreted_suffix(val):
    # ausearch -i renders e.g. uid=0(root) / exe="/usr/bin/bash" -- pull the
    # parenthesized human-readable part when present, else the raw value.
    m = re.match(r'^(.*)\((.*)\)$', val)
    if m:
        return m.group(2)
    return val


def parse_auditd_text(text, max_events):
    events = {}
    order = []
    for line in text.splitlines():
        m = AUDIT_LINE_RE.match(line.strip())
        if not m:
            continue
        rtype, ts, serial, rest = m.groups()
        cookie = f"{ts}:{serial}"
        ev = events.get(cookie)
        if ev is None:
            ev = {"_types": [], "_a": {}}
            events[cookie] = ev
            order.append(cookie)
        ev["_types"].append(rtype)

        kv = parse_audit_kv(rest)

        if rtype == "EXECVE":
            argc = int(kv.get("argc", "0") or 0)
            args = []
            for i in range(argc):
                a = kv.get(f"a{i}")
                if a is None:
                    break
                args.append(a)
            ev["_a"]["CommandLine"] = " ".join(args)
        elif rtype in ("SYSCALL", "PATH", "CWD", "SOCKADDR"):
            for k, v in kv.items():
                ev["_a"][f"{rtype}.{k}"] = v

    result = []
    for cookie in order[-max_events:] if max_events else order:
        ev = events[cookie]
        a = ev["_a"]
        exe = a.get("SYSCALL.exe")
        uid_raw = a.get("SYSCALL.uid") or a.get("SYSCALL.auid")
        fields = {
            "type": ev["_types"],
            "Image": exe,
            "CommandLine": a.get("CommandLine") or exe,
            "User": strip_interpreted_suffix(uid_raw) if uid_raw else None,
            "CurrentDirectory": a.get("CWD.cwd"),
            "TargetFilename": a.get("PATH.name"),
            "DestinationIp": a.get("SOCKADDR.laddr"),
            "DestinationPort": a.get("SOCKADDR.lport"),
            "key": a.get("SYSCALL.key"),
        }
        raw_text = " ".join(str(v) for v in a.values() if v)
        result.append((fields, raw_text))
    return result


def shutil_which(name):
    from shutil import which
    return which(name)


def fetch_auditd_events(days_back, max_events):
    if not shutil_which("ausearch"):
        return None  # signal: auditd tooling not present

    since = (datetime.datetime.now() - datetime.timedelta(days=days_back)).strftime("%m/%d/%Y %H:%M:%S")
    cmd = ["ausearch", "-i", "-ts"] + since.split(" ")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception:
        return None

    text = proc.stdout
    if not text.strip():
        return []

    return parse_auditd_text(text, max_events)


# ----------------------------------------------------------------------
# journald event source
# ----------------------------------------------------------------------

def fetch_journald_events(days_back, max_events):
    if not shutil_which("journalctl"):
        return None

    since_dt = datetime.datetime.now() - datetime.timedelta(days=days_back)
    since = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    cmd = ["journalctl", "-o", "json", "--since", since, "--no-pager"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception:
        return None

    result = []
    lines = proc.stdout.splitlines()
    if max_events:
        lines = lines[-max_events:]
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = rec.get("MESSAGE", "")
        if isinstance(message, list):
            message = "".join(chr(c) for c in message if isinstance(c, int))
        fields = {
            "SyslogIdentifier": rec.get("SYSLOG_IDENTIFIER"),
            "Comm": rec.get("_COMM"),
            "Exe": rec.get("_EXE"),
        }
        result.append((fields, str(message)))
    return result


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

SEVERITY_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "LOW"}


def csv_escape(value):
    value = (value or "").replace(",", ";").replace("\n", " ").replace("\r", "")
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--output", required=True, help="findings CSV to append to")
    ap.add_argument("--days-back", type=int, default=7)
    ap.add_argument("--min-level", default="medium")
    ap.add_argument("--max-events", type=int, default=25000)
    args = ap.parse_args()

    rules = load_rules(args.rules, args.min_level)
    by_source = {}
    for r in rules:
        by_source.setdefault(r["source"], []).append(r)

    auditd_sources = {"auditd_generic", "auditd_process_creation", "auditd_network_connection", "auditd_file_event"}
    needs_auditd = any(s in by_source for s in auditd_sources)
    needs_journald = "journald" in by_source

    matches = []
    scanned = 0
    auditd_available = None
    journald_available = None

    if needs_auditd:
        auditd_events = fetch_auditd_events(args.days_back, args.max_events)
        auditd_available = auditd_events is not None
        if auditd_events:
            scanned += len(auditd_events)
            for source_id in auditd_sources:
                for rule in by_source.get(source_id, []):
                    for fields, raw_text in auditd_events:
                        if evaluate(rule["condition"], fields, raw_text):
                            matches.append((rule, fields, raw_text))

    if needs_journald:
        journald_events = fetch_journald_events(args.days_back, args.max_events)
        journald_available = journald_events is not None
        if journald_events:
            scanned += len(journald_events)
            for rule in by_source.get("journald", []):
                for fields, raw_text in journald_events:
                    if evaluate(rule["condition"], fields, raw_text):
                        matches.append((rule, fields, raw_text))

    # Append to the shared findings.csv (severity,mitre_technique,category,description,evidence)
    file_exists = os.path.isfile(args.output) and os.path.getsize(args.output) > 0
    with open(args.output, "a", encoding="utf-8", newline="") as fh:
        if not file_exists:
            fh.write("severity,mitre_technique,category,description,evidence\n")
        for rule, fields, raw_text in matches:
            severity = SEVERITY_MAP.get(rule["level"], "MEDIUM")
            mitre = ";".join(t for t in rule["tags"] if t.startswith("attack.t")) or ";".join(rule["tags"])
            category = f"Sigma:{rule['source']}"
            description = rule["title"]
            evidence = fields.get("CommandLine") or fields.get("Image") or raw_text[:200] or rule["title"]
            fh.write(",".join(csv_escape(x) for x in [severity, mitre, category, description, evidence]) + "\n")

    summary = {
        "rules_loaded": len(rules),
        "events_scanned": scanned,
        "matches": len(matches),
        "auditd_available": auditd_available,
        "journald_available": journald_available,
    }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
