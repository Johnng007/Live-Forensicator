"""
Cisco NX-OS (Nexus) collector. 
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from collectors.base import CollectionResult, NetmikoConnection

DEVICE_TYPE = "cisco_nxos"

COMMANDS: Dict[str, str] = {
    "version": "show version",
    "running-config": "show running-config",
    "sessions": "show users",
    "arp-table": "show ip arp",
    "mac-address-table": "show mac address-table",
    "ip-route": "show ip route",
    "access-lists": "show access-lists",
    "logging": "show logging last 500",
    "cdp-neighbors": "show cdp neighbors detail",
    "snmp-config": "show snmp",
    "ssh-config": "show ssh server",
    "clock": "show clock",
    "ntp-associations": "show ntp peer-status",
}


def collect(connection: NetmikoConnection) -> CollectionResult:
    return connection.run_commands(COMMANDS)


def build_host_info(commands: Dict[str, Any]) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {"hostname": None, "vendor": "Cisco", "os_version": None, "model": None}
    version_result = commands.get("version")
    parsed = getattr(version_result, "parsed", None)
    if not parsed:
        return info
    row = parsed[0]
    info["hostname"] = row.get("HOSTNAME") or None
    info["os_version"] = row.get("OS") or row.get("IMAGE_VERSION") or None
    info["model"] = row.get("PLATFORM") or None
    return info
