"""
VyOS collector. VyOS's CLI is directly modeled on Junos's (same Vyatta
heritage).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from collectors.base import CollectionResult, NetmikoConnection

DEVICE_TYPE = "vyos"

COMMANDS: Dict[str, str] = {
    "version": "show version",
    "running-config": "show configuration commands",
    "sessions": "show users",
    "arp-table": "show arp",
    "mac-address-table": "show bridge mac-table",
    "ip-route": "show ip route",
    "access-lists": "show firewall",
    "logging": "show log",
    "lldp-neighbors": "show lldp neighbors detail",
    "snmp-config": "show configuration commands | match snmp",
    "ssh-config": "show configuration commands | match ssh",
    "clock": "show system uptime",
    "ntp-associations": "show ntp",
}


_LOGIN_USER_RE = re.compile(r"^set system login user (\S+)\b", re.MULTILINE)


def extract_local_users(running_config_text: Optional[str]) -> List[str]:
    """
    Local user accounts on VyOS are `set system login user <name> ...`
    lines in `show configuration commands` output — completely different
    syntax from Cisco's `username <name> ...` lines
    (collectors/cisco_ios.py's extract_local_users()), which is why this
    needs its own extractor rather than reusing that one. Used by the
    unauthorized-local-accounts rule (rules/engine.py dispatches to this
    function specifically for device_type == "vyos").
    """
    if not running_config_text:
        return []
    return sorted(set(_LOGIN_USER_RE.findall(running_config_text)))


def collect(connection: NetmikoConnection) -> CollectionResult:
    return connection.run_commands(COMMANDS)


def build_host_info(commands: Dict[str, Any]) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {"hostname": None, "vendor": "VyOS", "os_version": None, "model": None}
    version_result = commands.get("version")
    parsed = getattr(version_result, "parsed", None)
    if not parsed:
        return info
    row = parsed[0]
    info["hostname"] = row.get("HOSTNAME") or None
    info["os_version"] = row.get("VERSION") or None
    info["model"] = row.get("HARDWARE") or row.get("MODEL") or None
    return info
