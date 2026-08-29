"""
Arista EOS collector. EOS's CLI is heavily IOS-derived, but defaults to
LLDP rather than CDP for neighbor discovery, so this uses the
"lldp-neighbors" artifact_key (shared with Junos) instead of
"cdp-neighbors".
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from collectors.base import CollectionResult, NetmikoConnection

DEVICE_TYPE = "arista_eos"

COMMANDS: Dict[str, str] = {
    "version": "show version",
    "running-config": "show running-config",
    "sessions": "show users",
    "arp-table": "show ip arp",
    "mac-address-table": "show mac address-table",
    "ip-route": "show ip route",
    "access-lists": "show ip access-lists",
    "logging": "show logging",
    "lldp-neighbors": "show lldp neighbors detail",
    "snmp-config": "show snmp",
    "ssh-config": "show management ssh",
    "clock": "show clock",
    "ntp-associations": "show ntp status",
    # No "event-manager" entry — EOS has no EEM-equivalent event/action
    # engine (confirmed real platform limitation, not an oversight); the
    # logic-implant-persistence rule's applies_to excludes arista_eos
    # entirely rather than pointing at a non-equivalent mechanism.
    "flash-listing": "bash ls -la /mnt/flash",
    "span-sessions": "show monitor session",
    "device-sockets": "bash netstat -tupn",
    "config-diff": "diff running-config flash:startup-config",
}


def collect(connection: NetmikoConnection) -> CollectionResult:
    return connection.run_commands(COMMANDS)


def build_host_info(commands: Dict[str, Any]) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {"hostname": None, "vendor": "Arista", "os_version": None, "model": None}
    version_result = commands.get("version")
    parsed = getattr(version_result, "parsed", None)
    if not parsed:
        return info
    row = parsed[0]
    info["hostname"] = row.get("HOSTNAME") or None
    info["os_version"] = row.get("VERSION") or None
    info["model"] = row.get("MODEL") or None
    return info
