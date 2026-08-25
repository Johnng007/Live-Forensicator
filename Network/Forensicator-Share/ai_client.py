"""
ai_client.py — Forensicator AI for the Network Devices module. 
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "provider": "ollama",
    "base_url": "http://localhost:11434",
    "api_key": "",
    "model": "mistral:7b-instruct",
    "timeout_seconds": 60,
    "max_evidence_rows": 15,
}


def load_ai_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(DEFAULTS)
    ai = config.get("ai") if isinstance(config, dict) else None
    if not isinstance(ai, dict):
        return cfg
    if isinstance(ai.get("enabled"), bool):
        cfg["enabled"] = ai["enabled"]
    for key in ("provider", "base_url", "api_key", "model"):
        if ai.get(key):
            cfg[key] = str(ai[key])
    cfg["provider"] = cfg["provider"].lower().strip()
    cfg["base_url"] = cfg["base_url"].rstrip("/")
    for key in ("timeout_seconds", "max_evidence_rows"):
        if ai.get(key):
            try:
                cfg[key] = int(ai[key])
            except (TypeError, ValueError):
                pass
    return cfg


def _truncate_evidence(evidence: Dict[str, Any], max_lines: int) -> Dict[str, Any]:
    """
    Returns a prompt-safe copy of evidence, truncating any large string
    VALUE by its own real line count — not by counting lines in the
    json.dumps()'d text afterward, which silently doesn't work: a
    multi-hundred-line "raw" command blob (e.g. a full running-config)
    collapses to ONE line once JSON-escaped, since its embedded newlines
    become literal `\\n` characters inside that one JSON string rather
    than actual line breaks in the serialized text. Truncating on the
    serialized text's line count therefore never catches it, and the
    entire raw blob — however large — was silently goes into every AI
    prompt in full. 
    """
    truncated: Dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, str) and "\n" in value:
            value_lines = value.splitlines()
            if len(value_lines) > max_lines:
                value = "\n".join(value_lines[:max_lines]) + f"\n... ({len(value_lines) - max_lines} more line(s) truncated)"
        elif isinstance(value, str) and len(value) > 2000:
            value = value[:2000] + f"... ({len(value) - 2000} more char(s) truncated)"
        truncated[key] = value
    return truncated


def build_prompt(finding: Dict[str, Any], max_evidence_rows: int) -> str:
    host = finding.get("host", {})
    lines = [
        "You are assisting a digital forensics and incident response (DFIR) analyst reviewing output from an automated network-device collector.",
        "Give a short (2-4 sentence) plain-language verdict on the finding below: what it shows, whether it looks suspicious given the ACTUAL evidence (not just the general category), and one concrete next step for the analyst. Reference specific evidence values where relevant. Respond with plain text only — no markdown, no headers, no bullet points.",
        "",
        f"Finding type: {finding.get('finding_type', '')}",
        f"Device: {host.get('hostname') or host.get('ip')} ({host.get('vendor')} {host.get('device_type')})",
        f"Severity: {finding.get('severity', '')}",
        f"Description: {finding.get('summary', {}).get('description', '')}",
    ]
    mitre = finding.get("mitre") or {}
    if mitre.get("technique_id"):
        lines.append(f"MITRE: {mitre['technique_id']} — {mitre.get('technique')} ({mitre.get('tactic')})")

    max_rows = max(1, max_evidence_rows)
    safe_evidence = _truncate_evidence(finding.get("evidence") or {}, max_rows)
    evidence_text = json.dumps(safe_evidence, indent=2, default=str)

    # Absolute backstop even after per-value truncation above — e.g. many
    # small fields adding up, or one very long line with no newlines at
    # all (which the line-based truncation above can't catch either).
    max_chars = 4000
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars] + "\n... (truncated)"

    lines.append("")
    lines.append("Evidence:")
    lines.append(evidence_text)

    return "\n".join(lines)


def _post_json(url: str, body: Dict[str, Any], headers: Dict[str, str], timeout_seconds: int) -> Dict[str, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        return json.loads(resp.read().decode("utf-8"))


def call_provider(cfg: Dict[str, Any], prompt: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (text, error) — exactly one is None."""
    provider = cfg["provider"]
    timeout = cfg["timeout_seconds"]
    try:
        if provider == "ollama":
            body = {"model": cfg["model"], "prompt": prompt, "stream": False}
            resp = _post_json(f"{cfg['base_url']}/api/generate", body, {}, timeout)
            return resp.get("response"), None

        if provider in ("openai", "openai_compatible", "azure_openai"):
            headers = {}
            if cfg["api_key"]:
                headers["Authorization"] = f"Bearer {cfg['api_key']}"
            body = {"model": cfg["model"], "messages": [{"role": "user", "content": prompt}]}
            resp = _post_json(f"{cfg['base_url']}/v1/chat/completions", body, headers, timeout)
            return resp["choices"][0]["message"]["content"], None

        if provider == "anthropic":
            headers = {"x-api-key": cfg["api_key"], "anthropic-version": "2023-06-01"}
            body = {"model": cfg["model"], "max_tokens": 400, "messages": [{"role": "user", "content": prompt}]}
            resp = _post_json(f"{cfg['base_url']}/v1/messages", body, headers, timeout)
            return resp["content"][0]["text"], None

        return None, (
            f"Unknown AI provider '{provider}' in config.json "
            "(expected ollama, openai, openai_compatible, azure_openai, or anthropic)"
        )
    except urllib.error.HTTPError as e:
        # The request DID reach the server — it responded with a non-2xx
        # status. Not a reachability problem, so don't call it one.
        # Ollama/OpenAI-compatible APIs put the actual reason in the
        # response body (e.g. Ollama returns {"error": "model
        # 'x' not found, try pulling it first"}) — surface it instead of
        # just the generic "HTTP Error 500: Internal Server Error", which
        # tells you nothing about WHY.
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            detail = ""
        return None, f"{provider} at {cfg['base_url']} returned HTTP {e.code} {e.reason}{': ' + detail if detail else ''}"
    except urllib.error.URLError as e:
        return None, f"could not reach {provider} at {cfg['base_url']}: {e}"
    except Exception as e:
        return None, f"{provider} call failed: {e}"


def probe(cfg: Dict[str, Any]) -> str:
    """One-line startup reachability check: DISABLED | ONLINE ... | UNREACHABLE ..."""
    if not cfg["enabled"]:
        return "DISABLED"
    start = time.time()
    text, err = call_provider(cfg, "Reply with exactly the single word: OK")
    ms = round((time.time() - start) * 1000)
    if text and text.strip():
        return f"ONLINE {cfg['provider']}/{cfg['model']} {ms}ms"
    return f"UNREACHABLE {err or 'empty response'}"


def analyze_finding(finding: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    """
    Mutates finding['ai_analysis'] in place — mirrors the other three
    collectors' Add-ForensicatorAiVerdict / process_finding_file. No-op
    when AI is disabled (finding keeps its default {"status": "pending"}).
    """
    if not cfg["enabled"]:
        return
    prompt = build_prompt(finding, cfg["max_evidence_rows"])
    text, err = call_provider(cfg, prompt)
    if text and text.strip():
        finding["ai_analysis"] = {"status": "complete", "summary": text.strip(), "anomalies": [], "confidence": None}
    else:
        finding["ai_analysis"] = {"status": "failed", "summary": None, "anomalies": [], "confidence": None}
