"""
NetmikoConnection — the connection/execution layer for the Network Devices
collector. 
"""
from __future__ import annotations

import dataclasses
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:  # netmiko not installed — see requirements.txt
    ConnectHandler = None
    NetmikoAuthenticationException = NetmikoTimeoutException = Exception

try:
    from ntc_templates.parse import parse_output
except ImportError:  # ntc-templates not installed
    parse_output = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclasses.dataclass
class CommandResult:
    command: str
    raw: Optional[str]
    parsed: Optional[List[Dict[str, Any]]]
    timestamp: str
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclasses.dataclass
class CollectionResult:
    host: str
    device_type: str
    connected: bool
    connect_error: Optional[str]
    commands: Dict[str, CommandResult]


def parse_command_output(platform: str, command: str, raw_text: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    """
    Best-effort structured parse of ALREADY-CAPTURED raw text via
    ntc-templates — deliberately decoupled from the live device call
    (rather than netmiko's own send_command(..., use_textfsm=True), which
    would issue the command a second time) so every command is sent to
    the device exactly once. Returns None — never raises — when no
    template exists for this platform/command or parsing otherwise fails;
    the caller always still has the raw text either way.
    """
    if parse_output is None or not raw_text:
        return None
    try:
        result = parse_output(platform=platform, command=command, data=raw_text)
        return result or None
    except Exception:
        return None


class NetmikoConnection:
    """One SSH session to one device."""

    def __init__(
        self,
        host: str,
        device_type: str,
        username: str,
        password: str,
        secret: str = "",
        port: int = 22,
        timeout_seconds: int = 30,
        fast_cli: bool = False,
        connect_retries: int = 2,
        retry_backoff_seconds: float = 3.0,
        global_delay_factor: float = 1.0,
    ):
        if ConnectHandler is None:
            raise RuntimeError("netmiko is not installed — see requirements.txt")
        self.host = host
        self.device_type = device_type
        self._device_params = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
            # Used by enable() below to escalate from user EXEC ('>') to
            # privileged EXEC ('#') on Cisco/Arista-family devices whose
            # login account doesn't already land at privilege 15 — see
            # the comment in connect(). Harmless if unused: platforms
            # with no enable-mode concept (VyOS, Junos) never read it.
            "secret": secret,
            "port": port,
            "timeout": timeout_seconds,
            "fast_cli": fast_cli,
            # Scales ALL of Netmiko's internal expect/pattern-detection
            # delays — including the paging-disable step it runs during
            # connection setup — not just the socket-level connect
            # timeout above. The standard fix for a "Pattern not
            # detected" error on a slow/high-latency link (e.g. a device
            # reached over the public internet rather than a LAN):
            # raise this via config.json's per-device global_delay_factor
            # rather than just the socket timeout, which doesn't cover
            # this internal expect logic at all.
            "global_delay_factor": global_delay_factor,
        }
        self.connect_retries = connect_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        # Also used as the per-command read_timeout in run_command() —
        # Netmiko's own default there is shorter than most operators
        # would expect for a slow device, so this device's own configured
        # timeout_seconds applies to BOTH the connection and every
        # individual command, not just the connection.
        self.read_timeout_seconds = timeout_seconds
        self._conn = None
        # Set by connect() if enable() fails — non-fatal (see connect()'s
        # comment): collection continues, but privileged-only commands on
        # that device will likely fail one by one with a much more
        # cryptic "% Invalid input detected" from the device itself, so
        # the caller should surface this once up front instead.
        self.enable_error: Optional[str] = None

    def connect(self) -> Optional[str]:
        """Returns None on success, or an error message after exhausting retries."""
        last_error = None
        for attempt in range(self.connect_retries + 1):
            try:
                self._conn = ConnectHandler(**self._device_params)
                # Escalates '>' (user EXEC) to '#' (privileged EXEC) on
                # Cisco/Arista-family devices whose login account doesn't
                # already land at privilege 15 — without this, commands
                # like "show running-config" or "show archive config
                # differences ..." fail with "% Invalid input detected"
                # even though the command itself is correct. Safe to call
                # unconditionally: Netmiko's enable() is a documented
                # no-op if already in privileged mode, and platforms with
                # no enable-mode concept (VyOS, Junos) use a NoEnableMixin
                # that returns "" rather than erroring.
                try:
                    self._conn.enable()
                except Exception as exc:
                    self.enable_error = (
                        f"could not enter privileged/enable mode ({exc}) — privileged-only commands on this "
                        "device will likely fail. If this account needs enable-mode escalation, set its "
                        "secret_env in config.json."
                    )
                return None
            except NetmikoAuthenticationException as exc:
                # Retrying won't fix bad credentials — fail fast rather
                # than burning the full retry budget on a login that will
                # never succeed.
                return f"authentication failed: {exc}"
            except (NetmikoTimeoutException, OSError) as exc:
                last_error = str(exc)
                if attempt < self.connect_retries:
                    time.sleep(self.retry_backoff_seconds)
        return f"connection failed after {self.connect_retries + 1} attempt(s): {last_error}"

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def run_command(self, command: str) -> CommandResult:
        if self._conn is None:
            return CommandResult(command=command, raw=None, parsed=None, timestamp=_now(), error="not connected")
        try:
            raw = self._conn.send_command(command, read_timeout=self.read_timeout_seconds)
        except Exception as exc:
            message = str(exc)
            if "Pattern not detected" in message:
                # Netmiko couldn't find the expected prompt back within
                # read_timeout_seconds — the classic signature of a
                # slow/high-latency device (e.g. reached over the public
                # internet) rather than a real command failure. Point
                # directly at the fix instead of leaving the operator to
                # dig through Netmiko's own generic troubleshooting text.
                message = (
                    f"{message.splitlines()[0]} — likely means this device is slower to respond than "
                    f"timeout_seconds={self.read_timeout_seconds}s allows for (common over a high-latency/"
                    "internet-facing link). Try raising this device's timeout_seconds and/or "
                    "global_delay_factor in config.json."
                )
            return CommandResult(command=command, raw=None, parsed=None, timestamp=_now(), error=message)
        parsed = parse_command_output(self.device_type, command, raw)
        return CommandResult(command=command, raw=raw, parsed=parsed, timestamp=_now())

    def run_commands(self, commands: Dict[str, str]) -> CollectionResult:
        """commands: {artifact_key: command_string} -> results keyed the same way."""
        results = {key: self.run_command(command) for key, command in commands.items()}
        return CollectionResult(
            host=self.host, device_type=self.device_type, connected=True, connect_error=None, commands=results
        )

    def __enter__(self) -> "NetmikoConnection":
        error = self.connect()
        if error:
            raise ConnectionError(error)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.disconnect()
        return False
