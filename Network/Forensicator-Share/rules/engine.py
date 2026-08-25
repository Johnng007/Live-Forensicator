"""
rules/engine.py — evaluates detection rules (rules.json) against one
device's collected CollectionResult, producing zero or more rule-triggered
findings via findings.build_finding().
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import findings
from collectors.base import CollectionResult
from collectors.cisco_ios import extract_local_users as extract_local_users_ios
from collectors.juniper_junos import extract_local_users as extract_local_users_junos
from collectors.vyos import extract_local_users as extract_local_users_vyos

# device_type -> the extractor matching THAT vendor's actual local-user
# config syntax. Cisco/Arista family uses `username <name> ...` lines;
# VyOS/Junos (both Vyatta-derived) use `set system login user <name>
# ...` lines instead — completely different syntax, so dispatching by
# device_type here (rather than assuming one extractor fits everyone) is
# what actually makes the unauthorized-local-accounts rule correct
# per-vendor rather than silently never matching on non-Cisco devices.
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


def load_rules() -> List[Dict[str, Any]]:
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]


def _raw(collection: CollectionResult, artifact_key: str) -> Optional[str]:
    result = collection.commands.get(artifact_key)
    return result.raw if result and result.ok else None


def _eval_insecure_mgmt_plane(rule: Dict[str, Any], collection: CollectionResult) -> Optional[Dict[str, Any]]:
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


def _eval_weak_snmp_community(rule: Dict[str, Any], collection: CollectionResult) -> Optional[Dict[str, Any]]:
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


def _eval_missing_aaa(rule: Dict[str, Any], collection: CollectionResult) -> Optional[Dict[str, Any]]:
    raw = _raw(collection, rule["artifact_key"])
    if raw is None:
        return None
    required = rule.get("required_patterns", ["aaa authentication login"])
    if any(p in raw for p in required):
        return None
    return {"missing_patterns": required}


# Rules that fit the (rule, collection) -> match signature. "unauthorized-local-accounts"
# needs extra context (host + baseline config) and is dispatched specially in evaluate_device().
_EVALUATORS: Dict[str, Callable[[Dict[str, Any], CollectionResult], Optional[Dict[str, Any]]]] = {
    "insecure-mgmt-plane": _eval_insecure_mgmt_plane,
    "weak-snmp-community": _eval_weak_snmp_community,
    "missing-aaa": _eval_missing_aaa,
}


def evaluate_device(
    *,
    case: str,
    host_info: Dict[str, Optional[str]],
    collection: CollectionResult,
    rules_config: Dict[str, bool],
    expected_users_cfg: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Runs every enabled, applicable rule against one device's
    CollectionResult, returning the list of triggered finding dicts
    (already built via findings.build_finding()). A rule id absent from
    rules_config defaults to enabled, matching config.json's own
    documented convention for detection_rules.
    """
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
        else:
            evaluator = _EVALUATORS.get(rule_id)
            match = evaluator(rule, collection) if evaluator else None

        if match is None:
            continue

        command = collection.commands[rule["artifact_key"]].command
        finding = findings.build_finding(
            case=case, artifact_key=rule_id, host_info=host_info, command=command, evidence=match
        )
        rule_findings.append(finding)

    return rule_findings
