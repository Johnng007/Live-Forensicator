"""
case_summary.py — builds <hostname>/investigation/case-summary.json
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import findings as findings_module


def _tactic_label(tactic: Optional[str]) -> str:
    return tactic.lower() if tactic else "uncategorized"


def _level_label(score: int) -> str:
    return findings_module.risk_level_from_score(score).capitalize()


def build_case_summary(device_findings: List[Dict[str, Any]], degraded_commands: List[str]) -> Dict[str, Any]:
    """
    device_findings: every finding written for this one device (baseline
    + rule findings mixed, same list passed to report.py).
    degraded_commands: command strings that failed/errored during
    collection for this device — feeds the "gaps" field so a case summary
    honestly says what data was or wasn't available, rather than silently
    scoring only on what happened to succeed.
    """
    rule_findings = [f for f in device_findings if (f.get("mitre") or {}).get("technique_id")]
    total_findings = len(device_findings)

    gaps: List[str] = []
    if degraded_commands:
        gaps.append(f"{len(degraded_commands)} command(s) failed to collect: {', '.join(degraded_commands)} — findings and detections for those artifacts are absent, not confirmed-clean.")

    if not rule_findings:
        return {
            "overall_score": 0,
            "overall_level": "Informational",
            "confidence": 0,
            "total_findings": total_findings,
            "risk_breakdown": [],
            "confirmed": 0,
            "high_confidence": 0,
            "correlated": 0,
            "gaps": gaps or ["No detection rules matched this device's collected configuration."],
            "timeline": [],
            "attack_chain": [],
            "top_priorities": [],
            "correlation_pairs": [],
            "next_steps": [
                "Review the baseline collected artifacts under investigation/ even though no rule fired — absence of a rule match is not the same as a clean bill of health.",
            ],
            "why_tier": "No detection rules matched this device's collected configuration this run.",
            "narrative": "No findings scored high enough this run to warrant a case narrative.",
            "narrative_source": "template",
        }

    overall_score = max(f["risk"]["score"] for f in rule_findings)
    overall_level = _level_label(overall_score)

    buckets: Dict[str, List[int]] = {}
    for f in rule_findings:
        tactic = _tactic_label((f.get("mitre") or {}).get("tactic"))
        buckets.setdefault(tactic, []).append(f["risk"]["score"])
    risk_breakdown = [
        {"Bucket": tactic, "Score": max(scores), "Level": _level_label(max(scores))}
        for tactic, scores in sorted(buckets.items(), key=lambda kv: -max(kv[1]))
    ]

    ranked = sorted(rule_findings, key=lambda f: -f["risk"]["score"])
    top_priorities = [
        {"Title": f["summary"]["title"], "Score": f["risk"]["score"], "Level": f["severity"].capitalize()}
        for f in ranked[:6]
    ]

    chronological = sorted(rule_findings, key=lambda f: f["timeline"]["collection_timestamp"])
    timeline = [
        {
            "Time": f["timeline"]["collection_timestamp"],
            "Tactic": (f.get("mitre") or {}).get("tactic") or "Uncategorized",
            "Title": f["summary"]["title"],
            "Score": f["risk"]["score"],
        }
        for f in chronological
    ]
    attack_chain = list(dict.fromkeys(e["Tactic"] for e in timeline))

    top_bucket_names = [b["Bucket"] for b in risk_breakdown[:2]]
    bucket_phrase = " and ".join(top_bucket_names) if top_bucket_names else "no single dominant category"
    why_tier = (
        f"{len(rule_findings)} detection(s) matched on this device this run; the highest-scoring was "
        f"'{ranked[0]['summary']['title']}' at {overall_score}/100, concentrated in {bucket_phrase}."
    )

    if len(chronological) >= 2:
        narrative = (
            f"Detections span {len(attack_chain)} distinct MITRE tactic(s) this run: "
            f"{' -> '.join(attack_chain)}. Highest-severity finding: '{ranked[0]['summary']['title']}' ({overall_score}/100)."
        )
    else:
        narrative = f"A single detection fired this run: '{ranked[0]['summary']['title']}' ({overall_score}/100)."

    # Simple, explicitly-documented heuristic (not a sophisticated
    # confidence model): rule findings can only be as trustworthy as the
    # running-config collection they're derived from actually succeeding.
    running_config_ok = "show running-config" not in " ".join(degraded_commands) and \
        "show configuration" not in " ".join(degraded_commands) and \
        "show configuration commands" not in " ".join(degraded_commands)
    confidence = 90 if running_config_ok else 40

    next_steps = [
        "Prioritize triage by each finding's own documented severity level, not just match count.",
        "Verify any unauthorized local account with the device's administrators before taking action — see the unauthorized-local-accounts finding's evidence for the exact account name(s).",
        "Cross-reference any weak-SNMP or insecure-management-plane finding against this device's actual network exposure (internet-facing vs. internal-only management VLAN).",
        "Re-run collection after remediation to confirm the finding clears.",
    ]

    return {
        "overall_score": overall_score,
        "overall_level": overall_level,
        "confidence": confidence,
        "total_findings": total_findings,
        "risk_breakdown": risk_breakdown,
        "confirmed": 0,
        "high_confidence": 0,
        "correlated": 0,
        "gaps": gaps,
        "timeline": timeline,
        "attack_chain": attack_chain,
        "top_priorities": top_priorities,
        "correlation_pairs": [],
        "next_steps": next_steps,
        "why_tier": why_tier,
        "narrative": narrative,
        "narrative_source": "template",
    }
