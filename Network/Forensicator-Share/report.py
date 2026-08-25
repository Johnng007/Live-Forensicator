"""
report.py — single-page HTML report generator for the Network Devices
module.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}

CSS = """
:root{--bg:#07090f;--surface:#0d111a;--surface2:#111827;--surface3:#161e2e;--border:#1e2d42;--border2:#243650;
--blue:#3b82f6;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;--info:#3b82f6;
--text:#e2e8f0;--text2:#94a3b8;--text3:#4b6278;--font:'IBM Plex Sans',system-ui,sans-serif;--mono:'IBM Plex Mono',monospace;}
*{box-sizing:border-box;}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;margin:0;}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 28px;}
header h1{margin:0 0 4px;font-size:20px;}
.case-meta{color:var(--text2);font-size:12px;}
.kpi-row{display:flex;gap:12px;padding:20px 28px;flex-wrap:wrap;}
.kpi{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 18px;min-width:90px;text-align:center;}
.kpi-value{font-size:22px;font-weight:600;}
.kpi-label{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:.04em;margin-top:2px;}
.kpi-critical .kpi-value{color:var(--crit);} .kpi-high .kpi-value{color:var(--high);}
.kpi-medium .kpi-value{color:var(--med);} .kpi-low .kpi-value{color:var(--low);} .kpi-informational .kpi-value{color:var(--info);}
.severity-filter{padding:0 28px 16px;display:flex;gap:8px;}
.filter-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text2);border-radius:6px;
padding:6px 14px;font-size:12px;cursor:pointer;font-family:inherit;}
.filter-btn.active{background:var(--blue);border-color:var(--blue);color:#fff;}
.device-section{margin:0 28px 28px;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;}
.device-section h2{margin:0;padding:14px 18px;font-size:15px;border-bottom:1px solid var(--border);}
.device-meta{color:var(--text2);font-weight:400;font-size:12px;margin-left:8px;}
.device-counts{margin:0;padding:8px 18px;color:var(--text2);font-size:12px;border-bottom:1px solid var(--border);}
.findings-table{width:100%;border-collapse:collapse;}
.findings-table th{text-align:left;color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:.03em;
padding:8px 18px;border-bottom:1px solid var(--border);}
.findings-table td{padding:8px 18px;border-bottom:1px solid var(--border2);vertical-align:top;}
.finding-row{cursor:pointer;}
.finding-row:hover{background:var(--surface2);}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;}
.sev-critical{background:rgba(239,68,68,.15);color:var(--crit);}
.sev-high{background:rgba(249,115,22,.15);color:var(--high);}
.sev-medium{background:rgba(234,179,8,.15);color:var(--med);}
.sev-low{background:rgba(34,197,94,.15);color:var(--low);}
.sev-informational{background:rgba(59,130,246,.15);color:var(--info);}
.evidence-row td{background:var(--surface3);}
.why{color:var(--text2);margin-bottom:8px;font-style:italic;}
pre.evidence{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;
font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow:auto;margin:0;}
.no-findings{padding:18px;color:var(--text2);}
.ai-pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;
background:rgba(59,130,246,.15);color:var(--blue);vertical-align:middle;}
.ai-pill-failed{background:var(--surface3);color:var(--text3);}
.ai-block{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);border-radius:6px;
padding:10px 12px;margin-bottom:8px;}
.ai-block-failed{background:var(--surface3);border-color:var(--border2);}
.ai-block .ai-label{font-size:11px;font-weight:600;color:var(--blue);margin-bottom:4px;text-transform:uppercase;letter-spacing:.03em;}
.ai-block-failed .ai-label{color:var(--text2);}
.ai-block p{margin:0;color:var(--text);}
"""

JS = """
function toggleEvidence(id) {
  var row = document.getElementById('ev-' + id);
  if (row) row.style.display = (row.style.display === 'none' || !row.style.display) ? 'table-row' : 'none';
}
function filterSeverity(sev, btn) {
  document.querySelectorAll('.finding-row').forEach(function(row) {
    var show = sev === 'all' || row.dataset.sev === sev;
    row.style.display = show ? '' : 'none';
    var ev = row.nextElementSibling;
    if (ev && ev.classList.contains('evidence-row') && !show) ev.style.display = 'none';
  });
  document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value)) if value is not None else ""


def _safe_id(finding_id: str) -> str:
    """finding_id can contain arbitrary characters (case/investigator-supplied text) —
    sanitized to a valid HTML id / JS string-literal-safe token; the real finding_id
    is still shown as text content, this is only used for id="..."/onclick wiring."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", finding_id)


def _evidence_block(evidence: Dict[str, Any]) -> str:
    text = json.dumps(evidence, indent=2, default=str)
    if len(text) > 8000:
        text = text[:8000] + "\n... (truncated — see the full finding JSON under investigation/ for the complete evidence)"
    return f"<pre class='evidence'>{_esc(text)}</pre>"


def _ai_badge(finding: Dict[str, Any]) -> str:
    status = (finding.get("ai_analysis") or {}).get("status")
    if status == "complete":
        return '<span class="ai-pill" title="AI verdict available — expand to read it">🤖 AI</span>'
    if status == "failed":
        return '<span class="ai-pill ai-pill-failed" title="AI was enabled but returned no verdict for this finding">🤖 no verdict</span>'
    return ""


def _ai_analysis_block(finding: Dict[str, Any]) -> str:
    ai = finding.get("ai_analysis") or {}
    status = ai.get("status")
    if status == "complete" and ai.get("summary"):
        return f'<div class="ai-block"><div class="ai-label">🤖 Forensicator AI</div><p>{_esc(ai["summary"])}</p></div>'
    if status == "failed":
        return '<div class="ai-block ai-block-failed"><div class="ai-label">🤖 Forensicator AI</div><p>Enabled, but no verdict was returned for this finding (unreachable endpoint, timeout, or empty response — see the console/structured log for the reason).</p></div>'
    return ""


def _finding_rows(finding: Dict[str, Any]) -> str:
    sev = finding["severity"]
    mitre = finding.get("mitre") or {}
    mitre_str = f"{mitre['technique_id']} — {mitre['technique']}" if mitre.get("technique_id") else "—"
    safe_id = _safe_id(finding["finding_id"])
    return f"""
    <tr class="finding-row" data-sev="{_esc(sev)}" onclick="toggleEvidence('{safe_id}')">
      <td>{_sev_badge(sev)}</td>
      <td>{_esc(finding['summary']['title'])} {_ai_badge(finding)}</td>
      <td><code>{_esc(finding['source']['command'])}</code></td>
      <td>{_esc(mitre_str)}</td>
    </tr>
    <tr class="evidence-row" id="ev-{safe_id}" style="display:none">
      <td colspan="4">
        <div class="why">{_esc(finding['human_context']['executive_summary'])}</div>
        {_ai_analysis_block(finding)}
        {_evidence_block(finding['evidence'])}
      </td>
    </tr>"""


def _sev_badge(sev: str) -> str:
    return f'<span class="sev-badge sev-{_esc(sev)}">{_esc(sev)}</span>'


def _device_section(host_key: str, device_findings: List[Dict[str, Any]]) -> str:
    host_info = device_findings[0]["host"] if device_findings else {}
    sorted_findings = sorted(device_findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
    counts: Dict[str, int] = {}
    for f in device_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    count_str = " · ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if s in counts)
    rows = "".join(_finding_rows(f) for f in sorted_findings)
    label = host_info.get("hostname") or host_key
    meta = " · ".join(filter(None, [host_info.get("ip"), host_info.get("vendor"), host_info.get("os_version")]))
    return f"""
    <section class="device-section">
      <h2>{_esc(label)}<span class="device-meta">{_esc(meta)}</span></h2>
      <p class="device-counts">{_esc(count_str) or "No findings"}</p>
      <table class="findings-table">
        <thead><tr><th>Severity</th><th>Finding</th><th>Command</th><th>MITRE</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def generate_html_report(all_findings: List[Dict[str, Any]], case_meta: Dict[str, Any], output_path: Path) -> Path:
    """
    Writes a single self-contained HTML file (inline CSS/JS, no external
    assets) summarizing every finding across every device collected this
    run. `all_findings` is the flat list of finding dicts already built
    via findings.build_finding() (baseline + rule findings mixed
    together, same as what's written to JSON).
    """
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    for f in all_findings:
        host_key = f["host"].get("ip") or f["host"].get("hostname") or "unknown-host"
        by_device.setdefault(host_key, []).append(f)

    severity_counts: Dict[str, int] = {}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    kpi_cards = "".join(
        f'<div class="kpi kpi-{sev}"><div class="kpi-value">{severity_counts.get(sev, 0)}</div>'
        f'<div class="kpi-label">{_esc(sev)}</div></div>'
        for sev in SEVERITY_ORDER
    )
    filter_buttons = '<button class="filter-btn active" data-filter="all" onclick="filterSeverity(\'all\', this)">All</button>' + "".join(
        f'<button class="filter-btn" data-filter="{sev}" onclick="filterSeverity(\'{sev}\', this)">{_esc(sev.capitalize())}</button>'
        for sev in SEVERITY_ORDER
    )
    device_sections = "".join(_device_section(host, findings) for host, findings in sorted(by_device.items())) or \
        '<p class="no-findings">No devices collected this run.</p>'

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forensicator — Network Devices Report</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>🛡️ Forensicator — Network Devices</h1>
  <div class="case-meta">Case: {_esc(case_meta.get('case', 'UNSPECIFIED'))} · Investigator: {_esc(case_meta.get('name', 'N/A'))} · Generated {_esc(case_meta.get('generated_at', ''))}</div>
</header>
<div class="kpi-row">
  <div class="kpi"><div class="kpi-value">{len(by_device)}</div><div class="kpi-label">devices</div></div>
  <div class="kpi"><div class="kpi-value">{len(all_findings)}</div><div class="kpi-label">findings</div></div>
  {kpi_cards}
</div>
<div class="severity-filter">{filter_buttons}</div>
{device_sections}
<script>{JS}</script>
</body>
</html>"""

    output_path.write_text(doc, encoding="utf-8")
    return output_path
