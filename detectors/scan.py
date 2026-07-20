"""
Port scan / recon detector.
- Reads /proc/net/tcp and /proc/net/tcp6 each poll cycle.
- Tracks distinct local ports contacted by each remote IP within a rolling window.
- Also detects SYN-flood indicators: large number of SYN_RECV entries per remote IP.
- Emits DetectorEvent when port-touch count exceeds configured thresholds.
"""

import time
from collections import defaultdict
from typing import Iterator

import config
import state
from detectors.base import DetectorEvent

# TCP state codes in /proc/net/tcp
_SYN_RECV  = "03"
_ESTABLISHED = "01"

# Alert if a remote IP has this many SYN_RECV entries (half-open connections)
_SYN_FLOOD_THRESHOLD = 30


def _hex_to_ipv4(h: str) -> str:
    v = int(h, 16)
    return f"{v & 0xFF}.{(v >> 8) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 24) & 0xFF}"


def _read_tcp_snapshot() -> tuple[list[tuple[str, int, str]], dict[str, int]]:
    """
    Returns:
        entries: list of (remote_ip, local_port, tcp_state)
        syn_counts: remote_ip → count of SYN_RECV entries
    """
    entries: list[tuple[str, int, str]] = []
    syn_counts: dict[str, int]          = defaultdict(int)

    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)   # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_hex  = parts[1]
                    remote_hex = parts[2]
                    state_hex  = parts[3]

                    local_port    = int(local_hex.split(":")[1], 16)
                    remote_ip_hex = remote_hex.split(":")[0]

                    if len(remote_ip_hex) != 8:
                        continue   # skip IPv6 for now (tcp6 uses 32-char hex)

                    remote_ip = _hex_to_ipv4(remote_ip_hex)

                    if remote_ip in ("0.0.0.0", "127.0.0.1"):
                        continue

                    entries.append((remote_ip, local_port, state_hex))

                    if state_hex == _SYN_RECV:
                        syn_counts[remote_ip] += 1

        except (FileNotFoundError, ValueError):
            continue

    return entries, syn_counts


class ScanDetector:
    def __init__(self) -> None:
        # ip → list of (timestamp, local_port) within the scan window
        self._contacts: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # ip → last alerted distinct-port count
        self._alerted_count: dict[str, int] = {}

    def _purge_old(self, now: float) -> None:
        cutoff = now - config.SCAN_WINDOW_SECS
        for ip in list(self._contacts):
            self._contacts[ip] = [(t, p) for t, p in self._contacts[ip] if t > cutoff]
            if not self._contacts[ip]:
                del self._contacts[ip]

    def _port_confidence(self, count: int) -> str | None:
        if count >= config.SCAN_PORT_CRITICAL: return "critical"
        if count >= config.SCAN_PORT_HIGH:     return "high"
        if count >= config.SCAN_PORT_MEDIUM:   return "medium"
        return None

    def poll(self) -> Iterator[DetectorEvent]:
        now = time.time()
        entries, syn_counts = _read_tcp_snapshot()

        # Update contacts with new port touches
        for remote_ip, local_port, _ in entries:
            known_ports = {p for _, p in self._contacts[remote_ip]}
            if local_port not in known_ports:
                self._contacts[remote_ip].append((now, local_port))

        self._purge_old(now)

        # Port scan events
        for ip, contacts in self._contacts.items():
            if state.is_whitelisted(ip):
                continue

            distinct = len({p for _, p in contacts})
            confidence = self._port_confidence(distinct)
            if confidence is None:
                continue

            if distinct <= self._alerted_count.get(ip, 0):
                continue

            self._alerted_count[ip] = distinct
            yield DetectorEvent(
                detector   = "scan",
                threat     = "port_scan",
                source_ip  = ip,
                pid        = None,
                confidence = confidence,
                evidence   = {
                    "distinct_ports": distinct,
                    "window_secs":    config.SCAN_WINDOW_SECS,
                    "threshold":      config.SCAN_PORT_MEDIUM,
                },
            )

        # SYN flood events
        for ip, count in syn_counts.items():
            if state.is_whitelisted(ip):
                continue
            if count >= _SYN_FLOOD_THRESHOLD:
                syn_confidence = "critical" if count >= _SYN_FLOOD_THRESHOLD * 3 else "high"
                yield DetectorEvent(
                    detector   = "scan",
                    threat     = "ddos",
                    source_ip  = ip,
                    pid        = None,
                    confidence = syn_confidence,
                    evidence   = {
                        "syn_recv_count": count,
                        "threshold":      _SYN_FLOOD_THRESHOLD,
                    },
                    notes="SYN flood indicator",
                )
