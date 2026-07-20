"""
DDoS / traffic flood detector.
- Reads /proc/net/dev per poll cycle for interface-level bytes/packets.
- Computes delta rate since last poll.
- Also reads /proc/net/tcp to detect per-IP connection floods
  (high connection count from single IP = targeted flood).
- Emits DetectorEvent when rate exceeds configured thresholds.
"""

import time
from collections import defaultdict
from typing import Iterator

import config
import state
from detectors.base import DetectorEvent


def _read_iface_bytes(iface: str) -> tuple[int, int]:
    """Return (rx_bytes, tx_bytes) for the given interface from /proc/net/dev."""
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    parts = line.split()
                    # Format: iface: rx_bytes rx_pkts rx_err ... tx_bytes tx_pkts ...
                    return int(parts[1]), int(parts[9])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return 0, 0


def _hex_to_ipv4(h: str) -> str:
    v = int(h, 16)
    return f"{v & 0xFF}.{(v >> 8) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 24) & 0xFF}"


def _count_connections_per_ip() -> dict[str, int]:
    """Count established TCP connections grouped by remote IP."""
    counts: dict[str, int] = defaultdict(int)
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state_hex = parts[3]
                if state_hex != "01":   # 01 = ESTABLISHED
                    continue
                remote_hex = parts[2].split(":")[0]
                if len(remote_hex) == 8:
                    ip = _hex_to_ipv4(remote_hex)
                    if ip not in ("0.0.0.0", "127.0.0.1"):
                        counts[ip] += 1
    except (FileNotFoundError, ValueError):
        pass
    return counts


# High connection count from one IP indicates targeted flood
_CONN_FLOOD_THRESHOLD = 200


class TrafficDetector:
    def __init__(self) -> None:
        self._last_rx: int   = 0
        self._last_tx: int   = 0
        self._last_ts: float = 0.0

    def _confidence(self, bps: float) -> str | None:
        if bps >= config.TRAFFIC_FLOOD_CRITICAL: return "critical"
        if bps >= config.TRAFFIC_FLOOD_HIGH:     return "high"
        if bps >= config.TRAFFIC_FLOOD_MEDIUM:   return "medium"
        return None

    def poll(self) -> Iterator[DetectorEvent]:
        now      = time.time()
        rx, tx   = _read_iface_bytes(config.MONITOR_INTERFACE)

        if self._last_ts == 0.0:
            self._last_rx, self._last_tx, self._last_ts = rx, tx, now
            return

        elapsed = now - self._last_ts
        if elapsed <= 0:
            return

        rx_bps = (rx - self._last_rx) / elapsed
        tx_bps = (tx - self._last_tx) / elapsed
        self._last_rx, self._last_tx, self._last_ts = rx, tx, now

        peak       = max(rx_bps, tx_bps)
        confidence = self._confidence(peak)
        if confidence:
            yield DetectorEvent(
                detector   = "traffic",
                threat     = "ddos",
                source_ip  = None,   # interface-level — no single source
                pid        = None,
                confidence = confidence,
                evidence   = {
                    "rx_bps":          round(rx_bps),
                    "tx_bps":          round(tx_bps),
                    "interface":       config.MONITOR_INTERFACE,
                    "threshold_bps":   config.TRAFFIC_FLOOD_MEDIUM,
                },
                notes="source IP indeterminate from interface stats; router-side mitigation applied",
            )

        # Per-IP connection flood check
        for ip, count in _count_connections_per_ip().items():
            if state.is_whitelisted(ip):
                continue
            if count >= _CONN_FLOOD_THRESHOLD:
                conn_confidence = "critical" if count >= _CONN_FLOOD_THRESHOLD * 2 else "high"
                yield DetectorEvent(
                    detector   = "traffic",
                    threat     = "ddos",
                    source_ip  = ip,
                    pid        = None,
                    confidence = conn_confidence,
                    evidence   = {
                        "established_connections": count,
                        "threshold":               _CONN_FLOOD_THRESHOLD,
                    },
                    notes="targeted connection flood from single IP",
                )
