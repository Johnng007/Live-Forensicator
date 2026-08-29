"""
Malicious-IP blocklist loading for the transit-known-malicious-destination
rule. Mirrors the Windows collector's hash_source/url_source pattern
(Forensicator.ps1's HASHLOOKUP section): a local cache file is refreshed
from a list of URLs (tried in order, first success wins) only when it's
missing or older than a configurable max age; any fetch failure just
falls back to whatever's already cached, however stale — this never
blocks or fails a collection run.
"""
from __future__ import annotations

import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set

_USER_AGENT = "Forensicator-Network-Collector/1.0"


def _read_entries(path: str) -> List[str]:
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # FireHOL-style netset files sometimes carry a trailing
            # comment after the CIDR (e.g. "1.2.3.0/24 # some ISP") —
            # only the first whitespace-separated token is the IP/CIDR.
            entries.append(line.split()[0])
    return entries


def _is_stale(path: str, max_age_days: float) -> bool:
    if not os.path.isfile(path):
        return True
    age_days = (time.time() - os.path.getmtime(path)) / 86400.0
    return age_days > max_age_days


def _fetch_one(url: str, timeout: int = 30) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def load_malicious_ip_set(
    config: Dict[str, Any], share_dir: str, log: Optional[Callable[..., None]] = None
) -> Dict[str, Any]:
    """
    Returns {"entries": set[str] (IPs and/or CIDRs), "count": int,
    "source": str describing where the data came from}. An empty result
    (count=0) means the transit-known-malicious-destination rule finds
    nothing this run — same "no data, no finding" behavior as every
    other allowlist/threat-intel-style rule in this collector.
    """
    def _log(msg, level="INFO"):
        if log:
            log(msg, level=level, section="ThreatIntel")

    ti_cfg = config.get("threat_intel", {})
    sources = ti_cfg.get("malicious_ip_sources", [])
    max_age_days = ti_cfg.get("malicious_ip_max_age_days", 7)
    cache_rel = ti_cfg.get("malicious_ips_cache_file", "Forensicator-Share/malicious_ips_cache.txt")
    custom_rel = ti_cfg.get("custom_malicious_ips_file", "Forensicator-Share/custom_malicious_ips.txt")

    cache_path = os.path.join(share_dir, "..", cache_rel) if not os.path.isabs(cache_rel) else cache_rel
    cache_path = os.path.normpath(cache_path)
    custom_path = os.path.join(share_dir, "..", custom_rel) if not os.path.isabs(custom_rel) else custom_rel
    custom_path = os.path.normpath(custom_path)

    fetched_from = None
    if sources and _is_stale(cache_path, max_age_days):
        for url in sources:
            _log(f"Fetching malicious-IP blocklist from {url} ...")
            text = _fetch_one(url)
            if text:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(text)
                fetched_from = url
                _log(f"Malicious-IP blocklist refreshed from {url}", level="SUCCESS")
                break
        if not fetched_from:
            if os.path.isfile(cache_path):
                _log("All blocklist sources unreachable — using existing cached copy (may be stale)", level="WARN")
            else:
                _log("All blocklist sources unreachable and no cached copy exists — threat-intel rule will find nothing this run", level="WARN")

    entries: Set[str] = set(_read_entries(cache_path))
    cache_count = len(entries)

    custom_entries = _read_entries(custom_path)
    entries.update(custom_entries)

    if entries:
        source_desc = fetched_from or (cache_path if cache_count else "custom list only")
        _log(f"Loaded {len(entries)} malicious IP/CIDR entries ({cache_count} from feed, {len(custom_entries)} custom)")
    else:
        source_desc = "none"

    return {"entries": entries, "count": len(entries), "source": source_desc}
