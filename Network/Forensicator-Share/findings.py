"""
findings.py — the JSON schema builder for the Network Devices module.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Flat top-level import, not relative — "Forensicator-Share" (the directory
# this file lives in) has a hyphen, which isn't a valid Python package/
# identifier name, so it can't be imported as a dotted package itself.
# Forensicator.py adds this directory straight onto sys.path at startup
# instead, and every module here imports its siblings by plain name
# (mirrors how a directory on PYTHONPATH/site-packages works).
import knowledge_base

logger = logging.getLogger("forensicator.network")

MODULE_VERSION = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def risk_level_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 1:
        return "low"
    return "informational"


def build_finding(
    *,
    case: str,
    artifact_key: str,
    host_info: Dict[str, Optional[str]],
    command: str,
    evidence: Dict[str, Any],
    risk_reason: Optional[str] = None,
    override_risk_score: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Builds one finding dict for a single artifact_key on a single device.
    `override_risk_score` is used by rule-triggered findings (rules/engine.py)
    to supply the rule's own severity instead of the KB entry's baseline
    score — the KB entry (title/description/MITRE/recommendations) is still
    used for everything else.
    """
    kb = knowledge_base.lookup(artifact_key)
    if kb is knowledge_base.GENERIC_FALLBACK:
        logger.warning("No knowledge-base entry for artifact_key=%r — using generic fallback", artifact_key)

    risk_score = override_risk_score if override_risk_score is not None else kb.get("base_risk_score", 0)
    host_label = host_info.get("hostname") or host_info.get("host") or "unknown-host"
    ts = _now()

    return {
        "finding_id": f"{case}-{host_label}-{artifact_key}",
        "artifact_key": artifact_key,
        "finding_type": kb["finding_type"],
        "category": kb.get("category", "network"),
        "findingtags": list(kb.get("findingtags", [])) + ["network-device"],
        "severity": risk_level_from_score(risk_score),
        "host": {
            "hostname": host_info.get("hostname"),
            "ip": host_info.get("host"),
            "device_type": host_info.get("device_type"),
            "vendor": host_info.get("vendor"),
            "os_version": host_info.get("os_version"),
            "model": host_info.get("model"),
        },
        "source": {
            "collector": "Live Forensicator - Network Devices",
            "artifact_type": kb["finding_type"],
            "command": command,
        },
        "summary": {
            "title": kb["title"],
            "description": kb["description"],
        },
        "risk": {
            "score": risk_score,
            "level": risk_level_from_score(risk_score),
            "reason": risk_reason or kb["description"],
        },
        "mitre": {
            "technique_id": kb.get("mitre_technique_id"),
            "technique": kb.get("mitre_technique"),
            "tactic": kb.get("mitre_tactic"),
        },
        "human_context": {
            "plain_english": kb.get("what_is_this", ""),
            "technical_summary": kb.get("suspicious_behaviour", ""),
            "executive_summary": kb.get("why_this_matters", ""),
        },
        "recommendations": kb.get("recommendations", []),
        "analyst": {
            "notes": "",
            "disposition": "unreviewed",
            "false_positive": False,
            "verified": False,
        },
        "ai_analysis": {"status": "pending", "summary": None, "anomalies": [], "confidence": None},
        "metadata": {
            "collector": "Live Forensicator - Network Devices",
            "version": MODULE_VERSION,
            "platform": "network-device",
            "collection_time": ts,
        },
        "timeline": {"collection_timestamp": ts, "event": "artifact_collected"},
        "evidence": evidence,
    }


def write_finding_json(finding: Dict[str, Any], output_root: Path) -> Path:
    """
    Writes one finding to
    <output_root>/<hostname>/investigation/<category>/<check_name>-finding.json
    — same layout convention as the Linux/macOS collectors, so an
    operator zipping <hostname>/investigation/ produces an archive
    Forensicator Enterprise ingests exactly the same way.
    """
    host_label = finding["host"]["hostname"] or finding["host"]["ip"] or "unknown-host"
    category = finding["category"]
    check_name = finding["artifact_key"]
    out_dir = output_root / host_label / "investigation" / category
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{check_name}-finding.json"
    out_file.write_text(json.dumps(finding, indent=2), encoding="utf-8")
    return out_file


def write_metadata_json(
    *, output_root: Path, host_label: str, host_info: Dict[str, Optional[str]], username: str,
    case: str, title: Optional[str], operator: Optional[str], location: Optional[str],
    findingtags: List[str], collection_start_time: str, collection_end_time: str,
    device_findings: List[Dict[str, Any]],
) -> Path:
    """
    Writes <output_root>/<host_label>/investigation/metadata.json,
    matching the Windows collector's metadata.json field-for-field —
    several fields (os.build, network.domain, timezone) have no real
    network-device equivalent and are left null rather than guessed.
    "statistics" only counts rule-triggered findings as "detections" —
    baseline collected-artifact findings are informational, not
    detections, same distinction findings.py itself already draws.
    """
    rule_findings = [f for f in device_findings if (f.get("mitre") or {}).get("technique_id")]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in rule_findings:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    metadata = {
        "os": {
            "build": None,
            "version": host_info.get("os_version"),
            "platform": host_info.get("vendor"),
        },
        "collection_start_time": collection_start_time,
        "device": host_info.get("model") or host_info.get("device_type"),
        "hostname": host_label,
        "username": username,
        "title": title,
        "investigation_id": case,
        "operator": operator,
        "findingtags": findingtags,
        "timezone": None,
        "network": {
            "hostname": host_info.get("hostname"),
            "local_ip": host_info.get("host"),
            "domain": None,
        },
        "collector_version": MODULE_VERSION,
        "collection_end_time": collection_end_time,
        "collector_type": "Live Forensicator - Network Devices",
        "statistics": {
            "hash_detections": 0,
            "sigma_detections": 0,
            "ioc_detections": 0,
            "critical_detections": severity_counts["critical"],
            "total_detections": len(rule_findings),
            "low_detections": severity_counts["low"],
            "medium_detections": severity_counts["medium"],
            "high_detections": severity_counts["high"],
        },
        "location": location,
    }
    out_dir = output_root / host_label / "investigation"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "metadata.json"
    out_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return out_file


def write_case_summary_json(case_summary: Dict[str, Any], output_root: Path, host_label: str) -> Path:
    """Writes <output_root>/<host_label>/investigation/case-summary.json — see case_summary.py for how it's built."""
    out_dir = output_root / host_label / "investigation"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "case-summary.json"
    out_file.write_text(json.dumps(case_summary, indent=2), encoding="utf-8")
    return out_file
