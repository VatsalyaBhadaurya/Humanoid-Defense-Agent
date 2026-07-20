"""
Multi-detector correlation engine.
Tracks events per IP across all detectors within a rolling window.
When multiple detectors fire on the same IP, escalates to a correlated
threat type at critical confidence.

Covered correlation pairs:
  ssh + scan        → correlated_ssh_scan (critical)
  ddos + scan       → correlated_ddos_scan (critical)
  malware + ssh     → correlated_malware_net (critical)
  malware + scan    → correlated_malware_net (critical)
  malware + ddos    → correlated_malware_net (critical)
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

from detectors.base import DetectorEvent

# How long a detector hit stays relevant for correlation (seconds)
_CORRELATION_WINDOW = 120


@dataclass
class _Hit:
    detector: str
    threat: str
    ts: float


class Correlator:
    def __init__(self) -> None:
        # ip → list of recent hits
        self._hits: dict[str, list[_Hit]] = defaultdict(list)
        # (ip, corr_type) → last escalation time (rate-limit re-firing)
        self._escalated: dict[tuple[str, str], float] = {}

    def record(self, event: DetectorEvent) -> None:
        if event.source_ip is None:
            return
        self._hits[event.source_ip].append(
            _Hit(detector=event.detector, threat=event.threat, ts=time.time())
        )

    def _purge_old(self, now: float) -> None:
        cutoff = now - _CORRELATION_WINDOW
        for ip in list(self._hits):
            self._hits[ip] = [h for h in self._hits[ip] if h.ts > cutoff]
            if not self._hits[ip]:
                del self._hits[ip]

    def _detectors_seen(self, ip: str) -> set[str]:
        return {h.detector for h in self._hits.get(ip, [])}

    def _threats_seen(self, ip: str) -> set[str]:
        return {h.threat for h in self._hits.get(ip, [])}

    def flush(self) -> Iterator[DetectorEvent]:
        now = time.time()
        self._purge_old(now)

        for ip, hits in self._hits.items():
            dets    = {h.detector for h in hits}
            threats = {h.threat   for h in hits}

            corr_type: str | None = None

            if "ssh" in dets and "scan" in dets:
                corr_type = "correlated_ssh_scan"
            elif "traffic" in dets and "scan" in dets:
                corr_type = "correlated_ddos_scan"
            elif "process" in dets and ("ssh" in dets or "scan" in dets or "traffic" in dets):
                corr_type = "correlated_malware_net"

            if corr_type is None:
                continue

            key = (ip, corr_type)
            last = self._escalated.get(key, 0)
            if now - last < _CORRELATION_WINDOW:
                continue   # already escalated this pair recently

            self._escalated[key] = now

            yield DetectorEvent(
                detector   = "correlator",
                threat     = corr_type,
                source_ip  = ip,
                pid        = None,
                confidence = "critical",
                evidence   = {
                    "detectors_triggered": sorted(dets),
                    "threats_seen":        sorted(threats),
                    "hit_count":           len(hits),
                    "window_secs":         _CORRELATION_WINDOW,
                },
                notes=f"Multi-detector correlation: {', '.join(sorted(dets))}",
            )
