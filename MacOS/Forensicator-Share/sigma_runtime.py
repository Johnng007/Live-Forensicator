#!/usr/bin/env python3
"""
Forensicator macOS Sigma engine.

IMPORTANT LIMITATION (surfaced to the user by the caller before this runs):
macOS has no accessible process-creation audit trail comparable to Linux's
auditd or Windows' Sysmon/Security log without Apple's Endpoint Security
Framework -- which requires a signed system extension carrying a special
Apple-issued entitlement, not something a plain script can obtain. The only
scriptable, historical telemetry source is the unified log (`log show`),
which is an application/diagnostic log, not a process-creation auditor: a
message only exists if some subsystem chose to emit one, and even then it
rarely carries full command-line arguments. Compiled rules that expect a
CommandLine or ParentImage match will mostly never fire here -- this engine
is deliberately best-effort, not a claim of Sysmon/auditd-equivalent
coverage.

No external Python dependencies -- stdlib only.
"""
import sys
import os
import re
import json
import subprocess
import argparse
import datetime
import shutil
import collections


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


def fetch_unified_log_events(days_back, max_events, cmd_timeout_seconds):
    """Up to max_events unified-log entries (the latest read) from the last days_back days.

    Streamed and bounded: a day of unified log runs to millions of entries,
    which must not all be held in memory. Each entry's Image is the process
    that wrote it. CommandLine stays empty: the log message is free text
    written by that process, not its command line, and matching rules
    against it raised findings whenever a message merely mentioned a
    command. Rules that need a command line or a file name therefore do
    not fire here.
    """
    if not shutil.which("log"):
        return None

    since_dt = datetime.datetime.now() - datetime.timedelta(days=days_back)
    since = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    cmd = ["log", "show", "--style", "ndjson", "--start", since]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except Exception:
        return None

    deadline = datetime.datetime.now() + datetime.timedelta(seconds=cmd_timeout_seconds)
    lines = collections.deque(maxlen=max_events or None)
    try:
        for line in proc.stdout:
            lines.append(line)
            if datetime.datetime.now() > deadline:
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    result = []
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        fields = {
            "Image": rec.get("processImagePath"),
            "CommandLine": None,
            "TargetFilename": None,
        }
        result.append((fields, str(rec.get("eventMessage", ""))))
    return result


SEVERITY_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "LOW"}


def csv_escape(value):
    value = (value or "").replace(",", ";").replace("\n", " ").replace("\r", "")
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--output", required=True, help="findings CSV to append to")
    ap.add_argument("--days-back", type=int, default=1)
    ap.add_argument("--min-level", default="medium")
    ap.add_argument("--max-events", type=int, default=25000)
    ap.add_argument("--cmd-timeout", type=int, default=120)
    args = ap.parse_args()

    rules = load_rules(args.rules, args.min_level)

    matches = []
    scanned = 0
    unified_log_available = None

    events = fetch_unified_log_events(args.days_back, args.max_events, args.cmd_timeout)
    unified_log_available = events is not None
    if events:
        scanned = len(events)
        # One finding per rule and process image, not one per log entry.
        seen = set()
        for rule in rules:
            for fields, raw_text in events:
                key = (rule.get("id") or rule["title"], fields.get("Image"))
                if key in seen:
                    continue
                if evaluate(rule["condition"], fields, raw_text):
                    seen.add(key)
                    matches.append((rule, fields, raw_text))

    file_exists = os.path.isfile(args.output) and os.path.getsize(args.output) > 0
    with open(args.output, "a", encoding="utf-8", newline="") as fh:
        if not file_exists:
            fh.write("severity,mitre_technique,category,description,evidence\n")
        for rule, fields, raw_text in matches:
            severity = SEVERITY_MAP.get(rule["level"], "MEDIUM")
            mitre = ";".join(t for t in rule["tags"] if t.startswith("attack.t")) or ";".join(rule["tags"])
            category = f"Sigma:{rule['source']}"
            description = rule["title"]
            evidence = fields.get("Image") or raw_text[:200] or rule["title"]
            fh.write(",".join(csv_escape(x) for x in [severity, mitre, category, description, evidence]) + "\n")

    summary = {
        "rules_loaded": len(rules),
        "events_scanned": scanned,
        "matches": len(matches),
        "unified_log_available": unified_log_available,
    }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
