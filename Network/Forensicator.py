#!/usr/bin/env python3
"""
Live Forensicator — Network Devices module.
Collects read-only state from network devices over SSH (via Netmiko),
runs detection rules against it.

Supports Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos, and
VyOS.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
SHARE_DIR = SCRIPT_DIR / "Forensicator-Share"
# Forensicator-Share can't be imported as a dotted package (its name has a
# hyphen — not a valid Python identifier), so it's added straight onto
# sys.path instead, the same way any directory on PYTHONPATH works. Every
# module under it imports its siblings by plain top-level name.
sys.path.insert(0, str(SHARE_DIR))

import ai_client  # noqa: E402
import archive  # noqa: E402
import case_summary as case_summary_module  # noqa: E402
import findings  # noqa: E402
import report  # noqa: E402
import structured_log  # noqa: E402
from collectors import arista_eos, cisco_ios, cisco_nxos, juniper_junos, vyos  # noqa: E402
from collectors.base import NetmikoConnection  # noqa: E402
from rules import engine as rule_engine  # noqa: E402

# Emulates the Windows collector's Write-ForensicLog — every call both
# prints (colored, [timestamp][LEVEL] [Section] Message | Detail) and
# accumulates into a structured log persisted at the end of the run (see
# structured_log.py and main()'s closing structured_log.save() call).
flog = structured_log.log

# device_type -> collector module. Extending vendor support (brief §9
# step 7) means adding an entry here plus a new collectors/<vendor>.py,
# nothing else in this file changes.
COLLECTORS = {
    "cisco_ios": cisco_ios,
    "cisco_ios_xe": cisco_ios,  # same command set/parser family as ios
    "cisco_nxos": cisco_nxos,
    "arista_eos": arista_eos,
    "juniper_junos": juniper_junos,
    "vyos": vyos,
}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live Forensicator - Network Devices module")
    parser.add_argument("-name", "--name", dest="name", help="Investigator name")
    parser.add_argument("-case", "--case", dest="case", help="Case reference number")
    parser.add_argument("-title", "--title", dest="title", help="Investigation title")
    parser.add_argument("-loc", "--location", dest="location", help="Examination location")
    parser.add_argument("-device", "--device", dest="device_desc", help="Device/environment description")
    parser.add_argument("--config", dest="config_path", default=str(SCRIPT_DIR / "config.json"),
                         help="Path to config.json (default: ./config.json)")
    parser.add_argument("--output-dir", dest="output_dir", default=str(SCRIPT_DIR),
                         help="Directory findings are written under (default: script directory)")
    parser.add_argument("--host", dest="single_host", help="Collect from a single host instead of config.json's devices[] list")
    parser.add_argument("--device-type", dest="single_device_type", default="cisco_ios")
    parser.add_argument("--username", dest="single_username")
    parser.add_argument("--password-env", dest="single_password_env")
    parser.add_argument("--no-report", dest="no_report", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--max-workers", dest="max_workers", type=int, default=4,
                         help="Max devices to collect from concurrently (default 4)")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true",
                         help="AES-256-CBC encrypt the output directory into a single archive after collection (requires openssl)")
    return parser.parse_args(argv)


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_devices(args: argparse.Namespace, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    if args.single_host:
        return [{
            "host": args.single_host,
            "device_type": args.single_device_type,
            "username": args.single_username,
            "password_env": args.single_password_env,
            "port": 22,
            "timeout_seconds": 30,
            "fast_cli": False,
        }]
    return config.get("devices", [])


def resolve_password(device: Dict[str, Any]) -> Optional[str]:
    env_var = device.get("password_env")
    if not env_var:
        return None
    return os.environ.get(env_var)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_device(case: str, device: Dict[str, Any], rules_config: Dict[str, bool],
                    expected_users_cfg: Dict[str, Any], output_root: Path, ai_cfg: Dict[str, Any],
                    run_meta: Dict[str, Optional[str]], no_report: bool = False
                    ) -> "tuple[Dict[str, Any], List[Dict[str, Any]]]":
    """
    Collects + detects + writes everything for one device.
    """
    host = device["host"]
    device_type = device.get("device_type", "cisco_ios")
    summary: Dict[str, Any] = {"host": host, "device_type": device_type, "ok": False,
                                "findings_written": 0, "error": None}
    device_findings: List[Dict[str, Any]] = []
    degraded_commands: List[str] = []
    collection_start_time = _iso_now()

    ai_counter = 0

    def _run_ai(finding: Dict[str, Any]) -> None:
        nonlocal ai_counter
        if not ai_cfg.get("enabled"):
            return
        ai_counter += 1
        title = finding["summary"]["title"]
        flog(f"[AI {ai_counter}] Analyzing '{title}'...", level="INFO", section="AI", device=host)
        start = datetime.now()
        ai_client.analyze_finding(finding, ai_cfg)
        ms = round((datetime.now() - start).total_seconds() * 1000)
        status = finding["ai_analysis"]["status"]
        if status == "complete":
            flog(f"[AI {ai_counter}] Verdict received ({ms}ms)", level="SUCCESS", section="AI", device=host)
        else:
            flog(f"[AI {ai_counter}] No verdict ({ms}ms)", level="WARN", section="AI", device=host)

    try:
        collector_module = COLLECTORS.get(device_type)
        if collector_module is None:
            summary["error"] = f"unsupported device_type '{device_type}' — supported: {sorted(COLLECTORS)}"
            flog(summary["error"], level="ERROR", section="Collection", device=host)
            return summary, device_findings

        password = resolve_password(device)
        if not password:
            summary["error"] = f"no password available (checked env var {device.get('password_env')!r})"
            flog(summary["error"], level="ERROR", section="Collection", device=host)
            return summary, device_findings

        username = device.get("username")
        if not username:
            summary["error"] = "no username configured for this device"
            flog(summary["error"], level="ERROR", section="Collection", device=host)
            return summary, device_findings

        flog(f"Connecting ({device_type})...", level="INFO", section="Collection", device=host)
        conn = NetmikoConnection(
            host=host, device_type=device_type, username=username, password=password,
            port=device.get("port", 22), timeout_seconds=device.get("timeout_seconds", 30),
            fast_cli=device.get("fast_cli", False), global_delay_factor=device.get("global_delay_factor", 1.0),
        )
        connect_error = conn.connect()
        if connect_error:
            summary["error"] = connect_error
            flog(f"Connection failed: {connect_error}", level="ERROR", section="Collection", device=host)
            return summary, device_findings
        flog("Connected", level="SUCCESS", section="Collection", device=host)

        try:
            collection = collector_module.collect(conn)
        finally:
            conn.disconnect()

        host_info = collector_module.build_host_info(collection.commands)
        host_info["host"] = host
        host_info["device_type"] = device_type

        written = 0
        for artifact_key, result in collection.commands.items():
            if not result.ok:
                flog(f"Command failed: {result.command}", level="WARN", section="Collection", device=host, detail=result.error or "")
                degraded_commands.append(result.command)
                continue
            finding = findings.build_finding(
                case=case, artifact_key=artifact_key, host_info=host_info, command=result.command,
                evidence={"raw": result.raw, "parsed": result.parsed, "collected_at": result.timestamp},
            )
            _run_ai(finding)
            findings.write_finding_json(finding, output_root)
            device_findings.append(finding)
            written += 1

        for finding in rule_engine.evaluate_device(
            case=case, host_info=host_info, collection=collection,
            rules_config=rules_config, expected_users_cfg=expected_users_cfg,
        ):
            flog(f"{finding['summary']['title']}", level="FINDING", section="Detection", device=host,
                 detail=f"severity={finding['severity']} score={finding['risk']['score']}")
            _run_ai(finding)
            findings.write_finding_json(finding, output_root)
            device_findings.append(finding)
            written += 1

        collection_end_time = _iso_now()
        host_label = host_info.get("hostname") or host_info.get("host") or "unknown-host"
        device_dir = output_root / host_label

        # Reserved for future artifact types (e.g. RAM) — created now so
        # the layout matches the Windows collector's even before this
        # module collects anything into it.
        (device_dir / "artifacts").mkdir(parents=True, exist_ok=True)

        findingtags = sorted({tag for f in device_findings for tag in f.get("findingtags", [])})
        findings.write_metadata_json(
            output_root=output_root, host_label=host_label, host_info=host_info, username=username,
            case=case, title=run_meta.get("title"), operator=run_meta.get("operator"),
            location=run_meta.get("location"), findingtags=findingtags,
            collection_start_time=collection_start_time, collection_end_time=collection_end_time,
            device_findings=device_findings,
        )

        case_summary = case_summary_module.build_case_summary(device_findings, degraded_commands)
        findings.write_case_summary_json(case_summary, output_root, host_label)

        # reports/ is always created (matching the Windows collector's
        # folder layout) even when --no-report skips actually populating it.
        reports_dir = device_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        if not no_report:
            report.generate_html_report(
                device_findings,
                {"case": case, "name": run_meta.get("operator") or "N/A", "generated_at": collection_end_time},
                reports_dir / "index.html",
            )

        archive.create_investigation_archive(device_dir, host_label)

        summary["ok"] = True
        summary["findings_written"] = written
        return summary, device_findings
    except Exception as exc:
        # Genuinely never raise out of here (brief §8) — a bug in a
        # collector/rule/dependency for ONE device must not abort
        # collection for every other device in the run.
        summary["error"] = f"unexpected error: {exc}"
        flog("Unexpected error during collection", level="CRITICAL", section="Collection", device=host,
             detail=traceback.format_exc())
        return summary, device_findings


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    run_started_at = datetime.now()

    try:
        config = load_config(args.config_path)
    except FileNotFoundError:
        flog(f"Config file not found: {args.config_path}", level="ERROR", section="Config")
        return 1
    except json.JSONDecodeError as exc:
        flog(f"Config file is not valid JSON: {exc}", level="ERROR", section="Config")
        return 1

    devices = resolve_devices(args, config)
    if not devices:
        flog("No devices to collect from — check config.json's devices[] list or pass --host.", level="ERROR", section="Config")
        return 1

    case = args.case or "UNSPECIFIED-CASE"
    rules_config = config.get("detection_rules", {})
    expected_users_cfg = config.get("expected_local_users", {})
    output_root = Path(args.output_dir)

    # Forensicator AI status check — a real reachability probe (not just
    # "enabled in config.json"), printed once up front so the operator
    # knows before collection starts whether findings will get an AI
    # verdict this run. Mirrors the Windows/Linux/macOS collectors' own
    # startup probe. Never blocks/fails the run either way.
    ai_cfg = ai_client.load_ai_config(config)
    probe_result = ai_client.probe(ai_cfg)
    if probe_result == "DISABLED":
        flog("Disabled (set ai.enabled=true in config.json for AI verdicts on findings)", level="INFO", section="AI")
    elif probe_result.startswith("ONLINE"):
        flog(f"{probe_result} — findings will include AI verdicts this run", level="SUCCESS", section="AI")
    else:
        flog("Enabled but unreachable — findings will NOT include AI verdicts this run", level="WARN", section="AI", detail=probe_result)

    run_meta = {"title": args.title, "operator": args.name, "location": args.location}

    flog(f"{len(devices)} device(s) to collect (max {args.max_workers} concurrent)", level="INFO", section="Collection")
    results = []
    max_workers = max(1, min(args.max_workers, len(devices)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(collect_device, case, device, rules_config, expected_users_cfg, output_root,
                             ai_cfg, run_meta, args.no_report): device["host"]
            for device in devices
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result, _device_findings = future.result()
            except Exception as exc:
                # collect_device() already catches everything internally
                # (verified) — this is defense-in-depth against a
                # thread-pool-level failure, so it still can't take down
                # collection for every other device in the run.
                flog("Thread-level failure", level="CRITICAL", section="Collection", device=host, detail=traceback.format_exc())
                result = {"host": host, "device_type": "unknown", "ok": False, "findings_written": 0,
                          "error": f"thread failure: {exc}"}
            results.append(result)
            if result["ok"]:
                flog(f"Done — {result['findings_written']} finding(s) written", level="SUCCESS", section="Collection", device=host)
            else:
                flog(f"Skipped — {result['error']}", level="ERROR", section="Collection", device=host)

    ok_count = sum(1 for r in results if r["ok"])
    total_findings = sum(r["findings_written"] for r in results)
    flog(f"Collection complete: {ok_count}/{len(results)} device(s) succeeded, {total_findings} finding(s) written",
         level="SUCCESS" if ok_count == len(results) else "WARN", section="Collection")
    flog(f"Output under: {output_root}/<hostname-or-ip>/ (artifacts/, investigation/, reports/index.html, investigation.zip, Readme.txt)",
         level="INFO", section="Collection")

    if args.encrypt:
        encrypted = archive.encrypt_output(output_root, case)
        if encrypted:
            encrypted_path, key_path = encrypted
            flog(f"Encrypted archive: {encrypted_path}", level="SUCCESS", section="Encryption", detail=f"key: {key_path}")
        else:
            flog("Encryption requested but failed (openssl missing, or the archive/encrypt step errored) — output left unencrypted",
                 level="WARN", section="Encryption", detail=str(output_root))

    log_dir = output_root / "LOGS"
    run_label = f"{case}_{run_started_at.strftime('%Y%m%d_%H%M%S')}"
    saved_log = structured_log.save(log_dir, run_label)
    if saved_log:
        flog(f"Structured logs saved to {log_dir}", level="INFO", section="Logging",
             detail=f"{run_label}_structured.json/.csv")

    return 0 if ok_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
