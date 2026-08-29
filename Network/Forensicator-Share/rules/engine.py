"""
rules/engine.py — evaluates detection rules (rules.json) against one
device's collected CollectionResult, producing zero or more rule-triggered
findings via findings.build_finding().

Baseline-dependent rules (baseline_required=true in rules.json) fall into
two families, handled differently when their config.json baseline is
unpopulated:
- Presence-type rules (logic-implant-persistence, unexpected-flash-files,
  unexpected-span-session, unexpected-tunnel-interface) — real content
  exists on the device (a registered policy, a file, a mirror session, a
  tunnel) independent of whether an operator has told this tool what's
  "expected" yet. These still fire with an empty baseline (so the content
  actually gets surfaced for review on a fresh deployment), but with
  evidence["baseline_populated"]=False — evaluate_device()'s
  _apply_no_baseline_modifier() downgrades those specific findings to
  informational severity rather than reporting a full-severity false
  positive purely because nothing's been baselined yet.
- Pure-diff rules (image-hash-mismatch, config-section-hash-mismatch) —
  there is nothing to report without something to diff against, so an
  empty baseline means no finding at all (returns None), not a downgraded
  one.
Allowlist-membership rules (active-session-unexpected-source,
device-outbound-c2, ntp-tampering, syslog-destination-changed) also
return None with an empty baseline — an arbitrary IP/server isn't
inherently noteworthy without a baseline to compare it against, unlike
the presence-type rules above.

transit-known-malicious-destination is a blocklist-membership rule, the
inverse of the allowlist-membership family above: it fires when a session
in the device's NAT/conntrack table matches an entry in a loaded
threat-intel blocklist (threat_intel.py), not a config.json "expected"
baseline. No blocklist loaded means no finding, same "no data, no
finding" behavior. It's dispatched specially in evaluate_device()
(threat_intel, not baselines, as its third argument) for the same reason
unauthorized-local-accounts is.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import findings
from collectors.base import CollectionResult
from collectors.cisco_ios import extract_local_users as extract_local_users_ios
from collectors.juniper_junos import extract_local_users as extract_local_users_junos
from collectors.vyos import extract_local_users as extract_local_users_vyos

_LOCAL_USER_EXTRACTORS: Dict[str, Callable[[Optional[str]], List[str]]] = {
    "cisco_ios": extract_local_users_ios,
    "cisco_ios_xe": extract_local_users_ios,
    "cisco_nxos": extract_local_users_ios,
    "arista_eos": extract_local_users_ios,
    "vyos": extract_local_users_vyos,
    "juniper_junos": extract_local_users_junos,
}

RULES_PATH = Path(__file__).parent / "rules.json"

# A `line vty ...` block runs from that header line up to (but not
# including) the next top-level `line ` header, or end of file.
_VTY_BLOCK_RE = re.compile(r"^line vty.*?(?=^line |\Z)", re.MULTILINE | re.DOTALL)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Best-effort negative-response phrases used by the presence-type
# evaluators below to tell "genuinely empty" output apart from real
# content — necessarily approximate given how much these responses vary
# per vendor/command; documented here rather than assumed silently.
_EMPTY_MARKERS = ["no policies", "no event", "no applet", "no scheduled", "no such",
                  "not configured", "no entries", "no sessions", "no active"]


def load_rules() -> List[Dict[str, Any]]:
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]


def _raw(collection: CollectionResult, artifact_key: str) -> Optional[str]:
    result = collection.commands.get(artifact_key)
    return result.raw if result and result.ok else None


def _has_real_content(raw: Optional[str]) -> bool:
    if not raw or not raw.strip():
        return False
    lowered = raw.strip().lower()
    return not any(marker in lowered for marker in _EMPTY_MARKERS)


def _ip_in_baseline(ip_str: str, baseline_ranges: List[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable match — don't flag, avoids false positives on garbage regex hits
    for entry in baseline_ranges:
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# ── Existing rules (unchanged logic) ─────────────────────────────────────

def _eval_insecure_mgmt_plane(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not raw:
        return None
    telnet_patterns = rule.get("telnet_patterns", ["transport input telnet", "transport input all"])
    telnet_hits = [p for p in telnet_patterns if p in raw]

    vty_blocks = _VTY_BLOCK_RE.findall(raw)
    unrestricted_vty = [b.splitlines()[0].strip() for b in vty_blocks if "access-class" not in b]

    if not telnet_hits and not unrestricted_vty:
        return None
    return {"telnet_patterns_matched": telnet_hits, "vty_lines_without_access_class": unrestricted_vty}


def _eval_weak_snmp_community(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not raw:
        return None
    weak = rule.get("weak_communities", ["public", "private"])
    hits = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped.startswith("snmp-server community"):
            continue
        if any(re.search(rf"\bcommunity\s+{re.escape(w)}\b", stripped) for w in weak):
            hits.append(stripped)
    has_v2c_community = bool(re.search(r"^snmp-server community\s", raw, re.MULTILINE))
    has_v3_group = "v3" in raw.lower()
    v1_v2c_in_use = has_v2c_community and not has_v3_group

    if not hits and not v1_v2c_in_use:
        return None
    return {"weak_community_lines": hits, "snmpv1_or_v2c_in_use": v1_v2c_in_use}


def _eval_missing_aaa(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    required = rule.get("required_patterns", ["aaa authentication login"])
    if any(p in raw for p in required):
        return None
    return {"missing_patterns": required}


def _eval_unauthorized_local_accounts(
    rule: Dict[str, Any], collection: CollectionResult, host: str, device_type: Optional[str],
    expected_users_cfg: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    extractor = _LOCAL_USER_EXTRACTORS.get(device_type or "")
    if extractor is None:
        return None
    baseline = set(expected_users_cfg.get("global", []))
    baseline |= set(expected_users_cfg.get("device_overrides", {}).get(host, []))
    present = extractor(raw)
    unauthorized = sorted(u for u in present if u not in baseline)
    if not unauthorized:
        return None
    return {"unauthorized_users": unauthorized, "baseline": sorted(baseline), "all_local_users": present}


# ── New rules ──────────────────────────────────────────────────────────

def _eval_logic_implant_persistence(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not _has_real_content(raw):
        return None
    baseline = baselines.get("expected_automation_policies", [])
    return {"raw_excerpt": raw.strip()[:1000], "baseline_populated": bool(baseline)}


def _eval_boot_image_tampering(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    boot_lines = [ln.strip() for ln in raw.splitlines() if re.search(r"\bboot system\b", ln, re.IGNORECASE)]
    if not boot_lines:
        return None
    expected_path = baselines.get("expected_boot_image_path")
    suspicious = [ln for ln in boot_lines if re.search(r"\btftp\b|\bftp\b", ln, re.IGNORECASE)]
    if expected_path:
        suspicious += [ln for ln in boot_lines if expected_path not in ln and ln not in suspicious]
    if not suspicious:
        return None
    return {"boot_statements": boot_lines, "suspicious_statements": suspicious, "baseline_populated": bool(expected_path)}


def _eval_image_hash_mismatch(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Uses the "version" artifact directly (not rule["artifact_key"],
    # which is "running-config" purely for schema consistency with the
    # other rules) — image identity comes from `show version`.
    version_result = collection.commands.get("version")
    if not version_result or not version_result.ok or not version_result.raw:
        return None
    known_good = baselines.get("known_good_image_hashes", {})
    if not known_good:
        return None  # nothing to diff against — see module docstring
    raw = version_result.raw
    if any(str(version_id) in raw for version_id in known_good.keys()):
        return None
    return {"image_text_excerpt": raw.strip()[:500], "known_good_versions": sorted(known_good.keys())}


def _eval_unexpected_flash_files(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not _has_real_content(raw):
        return None
    baseline = set(baselines.get("expected_flash_files", []))
    # Heuristic filename extraction: the last whitespace-separated token
    # on each line that contains a '.' (extension) or ends in typical
    # directory-listing filename shapes — deliberately conservative,
    # since `dir`/`ls`-style output formats vary by vendor and this
    # avoids treating column headers/permission bits as filenames.
    candidates = set()
    for line in raw.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        last = tokens[-1]
        if "." in last or last.startswith(("/", "vmlinuz", "vyos-")):
            candidates.add(last)
    unexpected = sorted(c for c in candidates if c not in baseline)
    if not unexpected:
        return None
    return {"unexpected_files": unexpected, "baseline_populated": bool(baseline)}


def _eval_logging_tampering(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    issues = []
    if re.search(r"^no logging\b", raw, re.MULTILINE | re.IGNORECASE):
        issues.append("'no logging' statement present")
    buffer_match = re.search(r"logging buffered (\d+)", raw, re.IGNORECASE)
    min_buffer = baselines.get("expected_min_logging_buffer")
    if buffer_match and min_buffer and int(buffer_match.group(1)) < int(min_buffer):
        issues.append(f"logging buffer size {buffer_match.group(1)} below expected minimum {min_buffer}")
    if not issues:
        return None
    return {"issues": issues}


def _eval_syslog_destination_changed(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    expected = baselines.get("expected_syslog_servers", [])
    if not expected:
        return None
    # Only IPs that actually appear on a syslog-destination line count —
    # extracting from the whole raw text would also catch unrelated IPs
    # (e.g. an SNMP trap host on a nearby line).
    dest_lines = [ln for ln in raw.splitlines() if re.search(r"logging (host|server)", ln, re.IGNORECASE)]
    present_ips = set(_IPV4_RE.findall("\n".join(dest_lines)))
    missing = sorted(s for s in expected if s not in present_ips)
    unexpected = sorted(ip for ip in present_ips if ip not in expected)
    if not missing and not unexpected:
        return None
    return {"missing_expected_servers": missing, "unexpected_servers": unexpected}


def _eval_ntp_tampering(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    expected = baselines.get("expected_ntp_servers", [])
    if not expected:
        return None
    missing = sorted(s for s in expected if s not in raw)
    if not missing:
        return None
    return {"missing_expected_servers": missing}


def _eval_active_session_unexpected_source(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    expected_ranges = baselines.get("expected_management_ip_ranges", [])
    if not expected_ranges:
        return None
    found_ips = set(_IPV4_RE.findall(raw))
    unexpected = sorted(ip for ip in found_ips if not _ip_in_baseline(ip, expected_ranges))
    if not unexpected:
        return None
    return {"unexpected_source_ips": unexpected}


def _eval_aaa_fallback_abuse(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    unreachable_pattern = re.compile(r"(tacacs|radius|aaa).{0,40}(unreachable|timeout|dead|no response)", re.IGNORECASE)
    local_login_pattern = re.compile(r"(login|logon).{0,20}(success|local)", re.IGNORECASE)
    if unreachable_pattern.search(raw) and local_login_pattern.search(raw):
        return {"note": "AAA-unreachable and a local/successful login both appear in the retained log buffer"}
    return None


def _eval_brute_force_pattern(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    threshold = int(baselines.get("brute_force_failure_threshold", 5))
    fail_pattern = re.compile(r"login failed|authentication fail|invalid (user|password)|bad password", re.IGNORECASE)
    success_pattern = re.compile(r"login success|authentication success|accepted password", re.IGNORECASE)
    failures = fail_pattern.findall(raw)
    if len(failures) >= threshold and success_pattern.search(raw):
        return {"failure_count": len(failures), "threshold": threshold}
    return None


def _eval_unexpected_span_session(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not _has_real_content(raw):
        return None
    baseline = baselines.get("expected_span_sessions", [])
    return {"raw_excerpt": raw.strip()[:1000], "baseline_populated": bool(baseline)}


def _eval_unexpected_tunnel_interface(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    tunnel_blocks = re.findall(r"^interface Tunnel.*?(?=^interface |\Z)", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if not tunnel_blocks:
        return None
    baseline = set(baselines.get("expected_tunnel_endpoints", []))
    unexpected = []
    for block in tunnel_blocks:
        endpoints = _IPV4_RE.findall(block)
        # ALL endpoints must be baselined, not just any one — a tunnel's
        # source is typically the device's own already-baselined IP, so
        # requiring only "any" endpoint match would let an unbaselined
        # destination (the actually dangerous case) through unflagged as
        # long as the source alone happened to be recognized.
        if endpoints and not all(ep in baseline for ep in endpoints):
            unexpected.append({"interface": block.splitlines()[0].strip(), "endpoints": endpoints})
    if not unexpected:
        return None
    return {"unexpected_tunnels": unexpected, "baseline_populated": bool(baseline)}


def _eval_acl_loosened(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    broad = re.findall(r"^.*permit\s+ip\s+any\s+any.*$", raw, re.MULTILINE | re.IGNORECASE)
    if not broad:
        return None
    return {"broad_permit_lines": [ln.strip() for ln in broad]}


def _eval_device_outbound_c2(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    expected = baselines.get("expected_device_outbound_destinations", [])
    if not expected:
        return None
    found_ips = set(_IPV4_RE.findall(raw))
    unexpected = sorted(ip for ip in found_ips if not _ip_in_baseline(ip, expected) and not ip.startswith("127."))
    if not unexpected:
        return None
    return {"unexpected_destinations": unexpected}


def _eval_transit_known_malicious_destination(
    rule: Dict[str, Any], collection: CollectionResult, threat_intel: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Unlike device-outbound-c2 (the device's own sockets), this inspects
    the device's NAT/conntrack session table — traffic merely transiting
    the device on behalf of a host behind it. Checked against a loaded
    threat-intel blocklist (threat_intel.py), not a config.json
    "expected" baseline — no blocklist loaded means nothing to check
    against, same "no data, no finding" behavior as any other
    allowlist-membership rule.
    """
    raw = _raw(collection, rule["artifact_key"])
    if not _has_real_content(raw):
        return None
    entries = threat_intel.get("entries") or set()
    if not entries:
        return None
    found_ips = sorted(set(_IPV4_RE.findall(raw)))
    matches = [ip for ip in found_ips if not ip.startswith("127.") and _ip_in_baseline(ip, list(entries))]
    if not matches:
        return None
    return {"malicious_destinations": matches, "blocklist_source": threat_intel.get("source", "unknown")}


def _eval_config_drift_running_vs_startup(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if not _has_real_content(raw):
        return None
    no_diff_markers = ["no differences", "no changes", "identical", "same"]
    if any(m in raw.lower() for m in no_diff_markers) and len(raw.strip()) < 200:
        return None
    return {"diff_excerpt": raw.strip()[:1500]}


def _eval_config_section_hash_mismatch(rule: Dict[str, Any], collection: CollectionResult, baselines: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    baseline_hashes = baselines.get("baseline_section_hashes", {})
    if not baseline_hashes:
        return None

    sections = {
        "aaa": [ln for ln in raw.splitlines() if re.search(r"\baaa \b|\bset system login\b|\bset system authentication\b", ln, re.IGNORECASE)],
        "acl": [ln for ln in raw.splitlines() if re.search(r"access-list|\bfirewall\b", ln, re.IGNORECASE)],
        "routing": [ln for ln in raw.splitlines() if re.search(r"^ip route|^router |\bset protocols\b", ln, re.IGNORECASE)],
    }
    mismatches = {}
    for section_name, lines in sections.items():
        expected_hash = baseline_hashes.get(section_name)
        if not expected_hash or not lines:
            continue
        actual_hash = hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            mismatches[section_name] = {"expected": expected_hash, "actual": actual_hash}
    if not mismatches:
        return None
    return {"section_mismatches": mismatches}


# rule_id -> (rule, collection, baselines) -> match|None. Rules needing
# extra context beyond this signature ("unauthorized-local-accounts")
# are dispatched specially in evaluate_device().
_EVALUATORS: Dict[str, Callable[[Dict[str, Any], CollectionResult, Dict[str, Any]], Optional[Dict[str, Any]]]] = {
    "insecure-mgmt-plane": _eval_insecure_mgmt_plane,
    "weak-snmp-community": _eval_weak_snmp_community,
    "missing-aaa": _eval_missing_aaa,
    "logic-implant-persistence": _eval_logic_implant_persistence,
    "boot-image-tampering": _eval_boot_image_tampering,
    "image-hash-mismatch": _eval_image_hash_mismatch,
    "unexpected-flash-files": _eval_unexpected_flash_files,
    "logging-tampering": _eval_logging_tampering,
    "syslog-destination-changed": _eval_syslog_destination_changed,
    "ntp-tampering": _eval_ntp_tampering,
    "active-session-unexpected-source": _eval_active_session_unexpected_source,
    "aaa-fallback-abuse": _eval_aaa_fallback_abuse,
    "brute-force-pattern": _eval_brute_force_pattern,
    "unexpected-span-session": _eval_unexpected_span_session,
    "unexpected-tunnel-interface": _eval_unexpected_tunnel_interface,
    "acl-loosened": _eval_acl_loosened,
    "device-outbound-c2": _eval_device_outbound_c2,
    "config-drift-running-vs-startup": _eval_config_drift_running_vs_startup,
    "config-section-hash-mismatch": _eval_config_section_hash_mismatch,
}

# Presence-type rules (see module docstring) — a match with
# baseline_populated=False gets its severity downgraded to informational
# by _apply_no_baseline_modifier() rather than reported at full severity.
_PRESENCE_TYPE_RULES = {
    "logic-implant-persistence", "unexpected-flash-files", "unexpected-span-session", "unexpected-tunnel-interface",
    "boot-image-tampering",
}

_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
_SEVERITY_FLOOR_SCORE = {"informational": 0, "low": 1, "medium": 40, "high": 70, "critical": 90}


def _apply_no_baseline_modifier(rule_findings: List[Dict[str, Any]]) -> None:
    """
    Mutates matching findings in place: a presence-type rule that fired
    with an unpopulated baseline gets downgraded to informational
    severity, so a fresh deployment with no baselines configured yet
    doesn't report a wall of full-severity false positives purely because
    nothing's been told to this tool as "expected" — the content is still
    surfaced (so the operator can use it to populate the baseline), just
    not alarmingly.
    """
    for f in rule_findings:
        evidence = f.get("evidence") or {}
        if f.get("artifact_key") in _PRESENCE_TYPE_RULES and evidence.get("baseline_populated") is False:
            f["severity"] = "informational"
            f["risk"]["level"] = "informational"
            f["risk"]["score"] = 0
            f["risk"]["reason"] += " (downgraded to informational: no baseline configured yet for this check — this device's actual state is shown for review, not flagged as confirmed-suspicious.)"


def _apply_correlation_modifier(rule_findings: List[Dict[str, Any]]) -> None:
    """
    Mutates matching findings in place: if 2+ distinct MITRE tactics
    fired for this device in this run, bump each involved finding's
    severity one level. A same-device, same-run signal only (not a claim
    of cross-device correlation, which this module doesn't attempt).
    """
    tactics = {(f.get("mitre") or {}).get("tactic") for f in rule_findings if (f.get("mitre") or {}).get("tactic")}
    tactics.discard(None)
    if len(tactics) < 2:
        return
    for f in rule_findings:
        tactic = (f.get("mitre") or {}).get("tactic")
        if not tactic:
            continue
        idx = _SEVERITY_ORDER.index(f["severity"]) if f["severity"] in _SEVERITY_ORDER else 0
        new_idx = min(idx + 1, len(_SEVERITY_ORDER) - 1)
        if new_idx == idx:
            continue
        new_level = _SEVERITY_ORDER[new_idx]
        f["severity"] = new_level
        f["risk"]["level"] = new_level
        f["risk"]["score"] = max(f["risk"]["score"], _SEVERITY_FLOOR_SCORE[new_level])
        f["risk"]["reason"] += " (severity raised: correlated with finding(s) from a different MITRE tactic on this same device this run.)"


def evaluate_device(
    *,
    case: str,
    host_info: Dict[str, Optional[str]],
    collection: CollectionResult,
    rules_config: Dict[str, bool],
    expected_users_cfg: Dict[str, Any],
    baselines: Optional[Dict[str, Any]] = None,
    threat_intel: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Runs every enabled, applicable rule against one device's
    CollectionResult, returning the list of triggered finding dicts
    (already built via findings.build_finding()). A rule id absent from
    rules_config defaults to enabled, matching config.json's own
    documented convention for detection_rules. `baselines` is
    config.json's "baselines" block (all the expected_*/known_good_*/
    baseline_* config_keys the new rules read) — defaults to {} so
    existing callers that don't pass it keep working with every
    baseline-dependent rule simply finding nothing to compare against.
    `threat_intel` is threat_intel.py's load_malicious_ip_set() result —
    defaults to {} so transit-known-malicious-destination simply finds
    nothing without it, same as an unpopulated baseline.
    """
    baselines = baselines or {}
    threat_intel = threat_intel or {}
    rule_findings: List[Dict[str, Any]] = []
    device_type = host_info.get("device_type")

    for rule in load_rules():
        rule_id = rule["id"]
        if not rules_config.get(rule_id, True):
            continue
        if device_type not in rule.get("applies_to", []):
            continue
        if rule["artifact_key"] not in collection.commands:
            continue

        if rule_id == "unauthorized-local-accounts":
            match = _eval_unauthorized_local_accounts(
                rule, collection, host_info.get("host") or "", device_type, expected_users_cfg
            )
        elif rule_id == "transit-known-malicious-destination":
            match = _eval_transit_known_malicious_destination(rule, collection, threat_intel)
        else:
            evaluator = _EVALUATORS.get(rule_id)
            match = evaluator(rule, collection, baselines) if evaluator else None

        if match is None:
            continue

        command = collection.commands[rule["artifact_key"]].command
        finding = findings.build_finding(
            case=case, artifact_key=rule_id, host_info=host_info, command=command, evidence=match
        )
        rule_findings.append(finding)

    _apply_no_baseline_modifier(rule_findings)
    _apply_correlation_modifier(rule_findings)
    return rule_findings
