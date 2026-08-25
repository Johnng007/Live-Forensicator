"""
structured_log.py — every log call is printed to console in the
same `[timestamp][LEVEL] [Section] Message | Detail` format (color-coded
per level, matching Windows' color scheme) AND accumulated in memory,
then persisted at the end of the run as the same three-file convention
Windows produces — `<run_label>_structured.json`, `_structured.csv`, and
`_findings_only.csv` (filtered to FINDING/CRITICAL/ERROR levels).

"""
from __future__ import annotations

import csv
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

LEVELS = ("INFO", "WARN", "ERROR", "CRITICAL", "SUCCESS", "FINDING")

# Matches Write-ForensicLog's PowerShell console color scheme as closely
# as ANSI allows (DarkCyan/Yellow/Red/Magenta/Green/Cyan).
_ANSI = {
    "INFO": "\033[36m",
    "WARN": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[35m",
    "SUCCESS": "\033[32m",
    "FINDING": "\033[96m",
}
_RESET = "\033[0m"

_FIELDNAMES = ["Timestamp", "Level", "Section", "Message", "Detail", "Device"]


class StructuredLogger:
    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def log(self, message: str, level: str = "INFO", section: str = "", detail: str = "", device: str = "") -> None:
        if level not in LEVELS:
            level = "INFO"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"Timestamp": timestamp, "Level": level, "Section": section,
                  "Message": message, "Detail": detail, "Device": device}

        color = _ANSI.get(level, "")
        section_part = f" [{section}]" if section else ""
        detail_part = f" | {detail}" if detail else ""
        line = f"{color}[{timestamp}][{level}]{section_part} {message}{detail_part}{_RESET}"

        with self._lock:
            self.entries.append(entry)
            print(line, flush=True)

    def save(self, log_dir: Path, run_label: str) -> Optional[Path]:
        """
        Writes <run_label>_structured.json/.csv + _findings_only.csv into
        log_dir, mirroring Save-ForensicLogs exactly. Returns the json
        path on success, None if there's nothing to save or writing
        failed — never raises, matching this module's "optional/
        supporting feature degrades gracefully" convention.
        """
        with self._lock:
            entries_snapshot = list(self.entries)
        if not entries_snapshot:
            return None

        try:
            log_dir.mkdir(parents=True, exist_ok=True)

            json_path = log_dir / f"{run_label}_structured.json"
            json_path.write_text(json.dumps(entries_snapshot, indent=2), encoding="utf-8")

            csv_path = log_dir / f"{run_label}_structured.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
                writer.writeheader()
                writer.writerows(entries_snapshot)

            findings_only = [e for e in entries_snapshot if e["Level"] in ("FINDING", "CRITICAL", "ERROR")]
            if findings_only:
                findings_path = log_dir / f"{run_label}_findings_only.csv"
                with open(findings_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
                    writer.writeheader()
                    writer.writerows(findings_only)

            return json_path
        except Exception:
            return None


# Module-level singleton — mirrors Write-ForensicLog's $script:LogEntries
# being a single script-scoped list every call appends to from anywhere
# in the run, regardless of which function/thread is logging.
_logger = StructuredLogger()


def log(message: str, level: str = "INFO", section: str = "", detail: str = "", device: str = "") -> None:
    _logger.log(message, level=level, section=section, detail=detail, device=device)


def save(log_dir: Path, run_label: str) -> Optional[Path]:
    return _logger.save(log_dir, run_label)
