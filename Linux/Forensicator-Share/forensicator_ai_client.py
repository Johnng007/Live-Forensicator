#!/usr/bin/env python3
"""
Forensicator AI Client (Linux)
===============================
Optional, local-first LLM integration for the free/open-source collector —
a straight port of the Windows collector's ForensicatorAiClient.ps1, using
Python's stdlib (json + urllib) instead of PowerShell's Invoke-RestMethod so
this needs nothing beyond python3, which the collector already treats as a
soft/optional dependency elsewhere (Sigma engine, zip fallback).

Off by default — enable via config.json's "ai" block (same shape/defaults
as the Windows collector):

    "ai": {
      "enabled": true,
      "provider": "ollama",
      "base_url": "http://localhost:11434",
      "api_key": "",
      "model": "mistral:7b-instruct",
      "timeout_seconds": 60,
      "max_evidence_rows": 15
    }

Supported "provider" values: ollama | openai / openai_compatible /
azure_openai | anthropic — identical to Windows.

Usage (invoked by forensicator.sh, not meant to be run standalone):
  forensicator_ai_client.py probe
      One-line startup reachability check, printed to stdout as one of:
        DISABLED
        ONLINE <provider>/<model> <ms>ms
        UNREACHABLE <reason>

  forensicator_ai_client.py process <finding.json>
      Reads a single *-finding.json (the same shape write_finding_json()
      in forensicator.sh produces), sends its evidence to the configured
      LLM, and rewrites the file's "ai_analysis" field in place. Prints
      one line to stdout: "RESULT status=complete ms=<n>" or
      "RESULT status=failed ms=<n>". Never raises past main() — a
      misconfigured or unreachable LLM must never break collection.
"""
import json
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATH = "config.json"

DEFAULTS = {
    "enabled": False,
    "provider": "ollama",
    "base_url": "http://localhost:11434",
    "api_key": "",
    "model": "mistral:7b-instruct",
    "timeout_seconds": 60,
    "max_evidence_rows": 15,
}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
    except Exception:
        return cfg
    ai = data.get("ai") if isinstance(data, dict) else None
    if not isinstance(ai, dict):
        return cfg
    if isinstance(ai.get("enabled"), bool):
        cfg["enabled"] = ai["enabled"]
    if ai.get("provider"):
        cfg["provider"] = str(ai["provider"]).lower().strip()
    if ai.get("base_url"):
        cfg["base_url"] = str(ai["base_url"]).rstrip("/")
    if ai.get("api_key"):
        cfg["api_key"] = str(ai["api_key"])
    if ai.get("model"):
        cfg["model"] = str(ai["model"])
    if ai.get("timeout_seconds"):
        try:
            cfg["timeout_seconds"] = int(ai["timeout_seconds"])
        except (TypeError, ValueError):
            pass
    if ai.get("max_evidence_rows"):
        try:
            cfg["max_evidence_rows"] = int(ai["max_evidence_rows"])
        except (TypeError, ValueError):
            pass
    return cfg


def build_prompt(finding, max_evidence_rows):
    lines = [
        "You are assisting a digital forensics and incident response (DFIR) analyst reviewing output from an automated endpoint collector.",
        "Give a short (2-4 sentence) plain-language verdict on the finding below: what it shows, whether it looks suspicious given the ACTUAL evidence (not just the general category), and one concrete next step for the analyst. Reference specific evidence values where relevant. Respond with plain text only — no markdown, no headers, no bullet points.",
        "",
        f"Finding type: {finding.get('finding_type', '')}",
        f"Category: {finding.get('category', '')}",
        f"Severity: {finding.get('severity', '')}",
    ]
    description = (finding.get("summary") or {}).get("description")
    if description:
        lines.append(f"Description: {description}")
    risk_reason = (finding.get("risk") or {}).get("reason")
    if risk_reason:
        lines.append(f"Risk reason: {risk_reason}")

    evidence_rows = finding.get("evidence") or []
    if evidence_rows:
        max_rows = max(1, max_evidence_rows)
        shown = evidence_rows[:max_rows]
        lines.append("")
        lines.append(f"Evidence ({len(evidence_rows)} row(s) total, showing up to {max_rows}):")
        for row in shown:
            if isinstance(row, dict) and "data" in row:
                lines.append(str(row["data"]))
            else:
                lines.append(str(row))
    else:
        lines.append("")
        lines.append("No evidence rows were collected for this finding (empty result) — this is likely a clean/negative finding.")

    return "\n".join(lines)


def _post_json(url, body, headers, timeout_seconds):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        return json.loads(resp.read().decode("utf-8"))


def call_provider(cfg, prompt):
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
    except urllib.error.URLError as e:
        return None, f"could not reach {provider} at {cfg['base_url']}: {e}"
    except Exception as e:
        return None, f"{provider} call failed: {e}"


def cmd_probe():
    cfg = load_config()
    if not cfg["enabled"]:
        print("DISABLED")
        return
    start = time.time()
    text, err = call_provider(cfg, "Reply with exactly the single word: OK")
    ms = round((time.time() - start) * 1000)
    if text and text.strip():
        print(f"ONLINE {cfg['provider']}/{cfg['model']} {ms}ms")
    else:
        print(f"UNREACHABLE {err or 'empty response'}")


def cmd_process(finding_path):
    cfg = load_config()
    if not cfg["enabled"]:
        return  # not reached in practice — forensicator.sh only calls this when enabled

    start = time.time()
    try:
        with open(finding_path, "r") as f:
            finding = json.load(f)
    except Exception as e:
        print(f"RESULT status=failed ms=0", flush=True)
        print(f"[AI] could not read {finding_path}: {e}", file=sys.stderr)
        return

    prompt = build_prompt(finding, cfg["max_evidence_rows"])
    text, err = call_provider(cfg, prompt)
    ms = round((time.time() - start) * 1000)

    if text and text.strip():
        finding["ai_analysis"] = {"status": "complete", "summary": text.strip()}
        status = "complete"
    else:
        finding["ai_analysis"] = {"status": "failed"}
        status = "failed"
        if err:
            print(f"[AI] {err}", file=sys.stderr)

    try:
        with open(finding_path, "w") as f:
            json.dump(finding, f, indent=2)
    except Exception as e:
        print(f"[AI] could not write {finding_path}: {e}", file=sys.stderr)

    print(f"RESULT status={status} ms={ms}", flush=True)


def main():
    if len(sys.argv) < 2:
        print("usage: forensicator_ai_client.py probe|process <finding.json>", file=sys.stderr)
        sys.exit(1)
    cmd = sys.argv[1]
    try:
        if cmd == "probe":
            cmd_probe()
        elif cmd == "process" and len(sys.argv) >= 3:
            cmd_process(sys.argv[2])
        else:
            print("usage: forensicator_ai_client.py probe|process <finding.json>", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        # Absolute last resort — this script must never take down the
        # collector run it's a side-effect of.
        print(f"[AI] unexpected error: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
