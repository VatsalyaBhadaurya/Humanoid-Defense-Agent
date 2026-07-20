"""
DDoS / traffic flood detector.
Reads /proc/net/dev each poll cycle, computes delta bytes-per-second,
and emits events when the rate exceeds configured thresholds.
"""

import time
from dataclasses import dataclass

import config


@dataclass
class TrafficEvent:
    interface: str
    rx_bps: float
    tx_bps: float
    confidence: str
    evidence: dict


class TrafficDetector:
    def __init__(self) -> None:
        self._last_rx: int = 0
        self._last_tx: int = 0
        self._last_ts: float = 0.0

    def _read_iface_bytes(self) -> tuple[int, int]:
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if config.MONITOR_INTERFACE in line:
                        parts = line.split()
                        # columns: iface rx_bytes rx_packets ... tx_bytes ...
                        # rx_bytes = index 1, tx_bytes = index 9
                        return int(parts[1]), int(parts[9])
        except (FileNotFoundError, IndexError, ValueError):
            pass
        return 0, 0

    def _confidence(self, bps: float) -> str | None:
        if bps >= config.TRAFFIC_FLOOD_CRITICAL:
            return "critical"
        if bps >= config.TRAFFIC_FLOOD_HIGH:
            return "high"
        if bps >= config.TRAFFIC_FLOOD_MEDIUM:
            return "medium"
        return None

    def poll(self) -> TrafficEvent | None:
        now = time.time()
        rx, tx = self._read_iface_bytes()

        if self._last_ts == 0.0:
            self._last_rx, self._last_tx, self._last_ts = rx, tx, now
            return None

        elapsed = now - self._last_ts
        if elapsed <= 0:
            return None

        rx_bps = (rx - self._last_rx) / elapsed
        tx_bps = (tx - self._last_tx) / elapsed
        self._last_rx, self._last_tx, self._last_ts = rx, tx, now

        peak = max(rx_bps, tx_bps)
        confidence = self._confidence(peak)
        if confidence is None:
            return None

        return TrafficEvent(
            interface=config.MONITOR_INTERFACE,
            rx_bps=rx_bps,
            tx_bps=tx_bps,
            confidence=confidence,
            evidence={
                "rx_bps": round(rx_bps),
                "tx_bps": round(tx_bps),
                "threshold_bps": config.TRAFFIC_FLOOD_MEDIUM,
            },
        )
