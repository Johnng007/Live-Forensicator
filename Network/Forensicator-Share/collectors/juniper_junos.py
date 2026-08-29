"""
Juniper Junos collector. 
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from collectors.base import CollectionResult, NetmikoConnection

DEVICE_TYPE = "juniper_junos"

COMMANDS: Dict[str, str] = {
    "version": "show version",
    # "show configuration commands" (flat `set ...` lines), not the
    # default "show configuration" (curly-brace hierarchical format) —
    # matches VyOS's own choice (collectors/vyos.py) and is what
    # extract_local_users() below actually needs to regex-match against.
    "running-config": "show configuration commands",
    "sessions": "show system users",
    "arp-table": "show arp",
    "mac-address-table": "show ethernet-switching table",
    "ip-route": "show route",
    "access-lists": "show configuration firewall",
    "logging": "show log messages",
    "lldp-neighbors": "show lldp neighbors detail",
    "snmp-config": "show configuration snmp",
    "ssh-config": "show configuration system services",
    "clock": "show system uptime",
    "ntp-associations": "show ntp associations",
    "event-manager": "show configuration event-options",
    "flash-listing": "file list /var/tmp",
    "span-sessions": "show configuration forwarding-options port-mirroring",
    "device-sockets": "show system connections",
    "config-diff": "show configuration | compare rollback 1",
}


_LOGIN_USER_RE = re.compile(r"^set system login user (\S+)\b", re.MULTILINE)


def extract_local_users(running_config_text: Optional[str]) -> List[str]:
    """
    Local user accounts on Junos are `set system login user <name> ...`
    lines in `show configuration commands` output — same syntax as VyOS
    (both are Vyatta-derived), completely different from Cisco's
    `username <name> ...` lines. Used by the unauthorized-local-accounts
    rule (rules/engine.py dispatches to this function specifically for
    device_type == "juniper_junos").
    """
    if not running_config_text:
        return []
    return sorted(set(_LOGIN_USER_RE.findall(running_config_text)))


def collect(connection: NetmikoConnection) -> CollectionResult:
    return connection.run_commands(COMMANDS)


def build_host_info(commands: Dict[str, Any]) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {"hostname": None, "vendor": "Juniper", "os_version": None, "model": None}
    version_result = commands.get("version")
    parsed = getattr(version_result, "parsed", None)
    if not parsed:
        return info
    row = parsed[0]
    info["hostname"] = row.get("HOSTNAME") or None
    info["os_version"] = row.get("JUNOS_VERSION") or row.get("VERSION") or None
    info["model"] = row.get("HARDWARE_MODEL") or row.get("MODEL") or None
    return info
