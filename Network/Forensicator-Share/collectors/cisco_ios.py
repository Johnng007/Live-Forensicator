"""
Cisco IOS / IOS-XE collector — the baseline read-only command set.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from collectors.base import CollectionResult, NetmikoConnection

DEVICE_TYPE = "cisco_ios"

# artifact_key -> CLI command. Read-only only — no config changes (brief §8).
COMMANDS: Dict[str, str] = {
    "version": "show version",
    "running-config": "show running-config",
    "sessions": "show users",
    "arp-table": "show ip arp",
    "mac-address-table": "show mac address-table",
    "ip-route": "show ip route",
    "access-lists": "show access-lists",
    "logging": "show logging",
    "cdp-neighbors": "show cdp neighbors detail",
    "snmp-config": "show snmp",
    "ssh-config": "show ip ssh",
    "clock": "show clock",
    "ntp-associations": "show ntp associations",
    "event-manager": "show event manager policy registered",
    "flash-listing": "dir flash:/ all-filesystems",
    "span-sessions": "show monitor session all",
    "device-sockets": "show ip sockets",
    "config-diff": "show archive config differences nvram:startup-config system:running-config",
    # Only meaningful if this device does NAT — empty output otherwise,
    # which the transit-known-malicious-destination rule treats as
    # nothing-to-check, same as any other empty artifact.
    "transit-sessions": "show ip nat translations",
}

_USERNAME_LINE_RE = re.compile(r"^username\s+(\S+)\b", re.MULTILINE)


def collect(connection: NetmikoConnection) -> CollectionResult:
    """Runs the full baseline command set against an already-connected NetmikoConnection."""
    return connection.run_commands(COMMANDS)


def extract_local_users(running_config_text: Optional[str]) -> List[str]:
    """
    Local user accounts aren't their own `show` command on IOS — they're
    `username <name> ...` lines inside running-config (brief §5's "Local
    user accounts section of running-config"). Returns the deduplicated,
    sorted list of usernames found; empty list if running-config wasn't
    collected.
    """
    if not running_config_text:
        return []
    return sorted(set(_USERNAME_LINE_RE.findall(running_config_text)))


def build_host_info(commands: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Best-effort device identity from `show version`'s parsed output
    (ntc-templates' cisco_ios_show_version template). Falls back to
    "unknown" fields rather than raising when the parse didn't happen
    (no ntc-templates installed) or came back empty — device identity is
    metadata, never something that should block finding output.
    """
    info: Dict[str, Optional[str]] = {"hostname": None, "vendor": "Cisco", "os_version": None, "model": None}
    version_result = commands.get("version")
    parsed = getattr(version_result, "parsed", None)
    if not parsed:
        return info
    row = parsed[0]
    info["hostname"] = row.get("HOSTNAME") or None
    info["os_version"] = row.get("VERSION") or None
    hardware = row.get("HARDWARE")
    if isinstance(hardware, list) and hardware:
        info["model"] = hardware[0]
    elif isinstance(hardware, str):
        info["model"] = hardware
    return info
