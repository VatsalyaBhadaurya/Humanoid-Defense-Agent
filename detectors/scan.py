"""
Port scan / recon detector.
Reads /proc/net/tcp (and tcp6) to track how many distinct local ports
a remote IP has touched. Emits events when the count exceeds thresholds.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field

import config


@dataclass
class ScanEvent:
    source_ip: str
    ports_touched: int
    window_secs: int
    confidence: str
    evidence: dict = field(default_factory=dict)


def _hex_to_ip(hex_str: str) -> str:
    addr = int(hex_str, 16)
    return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"


def _read_tcp_entries() -> list[tuple[str, int]]:
    """Return list of (remote_ip, local_port) for all TCP entries."""
    entries = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_hex, remote_hex = parts[1], parts[2]
                    local_port = int(local_hex.split(":")[1], 16)
                    remote_ip_hex = remote_hex.split(":")[0]
                    # Skip IPv6 mapped addresses (length > 8)
                    if len(remote_ip_hex) == 8:
                        remote_ip = _hex_to_ip(remote_ip_hex)
                        entries.append((remote_ip, local_port))
        except (FileNotFoundError, ValueError):
            continue
    return entries


class ScanDetector:
    def __init__(self) -> None:
        # ip -> list of (timestamp, port)
        self._contacts: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._alerted: dict[str, int] = {}

    def _purge_old(self, now: float) -> None:
        cutoff = now - config.SCAN_WINDOW_SECS
        for ip in list(self._contacts):
            self._contacts[ip] = [(t, p) for t, p in self._contacts[ip] if t > cutoff]
            if not self._contacts[ip]:
                del self._contacts[ip]

    def _confidence(self, count: int) -> str | None:
        if count >= config.SCAN_PORT_CRITICAL:
            return "critical"
        if count >= config.SCAN_PORT_HIGH:
            return "high"
        if count >= config.SCAN_PORT_MEDIUM:
            return "medium"
        return None

    def poll(self) -> list[ScanEvent]:
        now = time.time()
        entries = _read_tcp_entries()

        for remote_ip, local_port in entries:
            if remote_ip in ("0.0.0.0", "127.0.0.1"):
                continue
            known_ports = {p for _, p in self._contacts[remote_ip]}
            if local_port not in known_ports:
                self._contacts[remote_ip].append((now, local_port))

        self._purge_old(now)

        events: list[ScanEvent] = []
        for ip, contacts in self._contacts.items():
            distinct_ports = len({p for _, p in contacts})
            confidence = self._confidence(distinct_ports)
            if confidence is None:
                continue

            prev = self._alerted.get(ip, 0)
            if distinct_ports <= prev:
                continue

            self._alerted[ip] = distinct_ports
            events.append(ScanEvent(
                source_ip=ip,
                ports_touched=distinct_ports,
                window_secs=config.SCAN_WINDOW_SECS,
                confidence=confidence,
                evidence={
                    "distinct_ports": distinct_ports,
                    "window_secs": config.SCAN_WINDOW_SECS,
                    "threshold": config.SCAN_PORT_MEDIUM,
                },
            ))

        return events
