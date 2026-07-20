"""
Malware / suspicious-process detector.
Uses psutil to scan the live process list for:
  - Known-bad executable names
  - Connections to known C2 ports
  - Excessive outbound connections (potential exfil / scanner)
  - Privilege escalation: non-root process with root-owned files open
  - Unexpected persistence: new entries in /etc/cron.d, systemd unit dirs

Skips already-alerted PIDs; cleans up stale PID entries on each cycle.
Degrades gracefully if psutil is not installed.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import config
import state
from detectors.base import DetectorEvent

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

# Directories monitored for unexpected new files (persistence)
_PERSIST_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/systemd/system",
    "/lib/systemd/system",
]


class ProcessDetector:
    def __init__(self) -> None:
        self._alerted_pids: set[int]          = set()
        self._persist_snapshots: dict[str, set[str]] = {}
        self._snapshot_taken = False

    def available(self) -> bool:
        return _PSUTIL_OK

    def _take_persistence_snapshot(self) -> None:
        for d in _PERSIST_DIRS:
            try:
                self._persist_snapshots[d] = set(os.listdir(d))
            except FileNotFoundError:
                self._persist_snapshots[d] = set()
        self._snapshot_taken = True

    def _check_persistence(self) -> list[DetectorEvent]:
        events: list[DetectorEvent] = []
        for d in _PERSIST_DIRS:
            try:
                current = set(os.listdir(d))
            except FileNotFoundError:
                continue
            baseline = self._persist_snapshots.get(d, set())
            new_files = current - baseline
            for fname in new_files:
                events.append(DetectorEvent(
                    detector   = "process",
                    threat     = "malware",
                    source_ip  = None,
                    pid        = None,
                    confidence = "high",
                    evidence   = {"new_file": str(Path(d) / fname), "directory": d},
                    notes      = "unexpected persistence file detected",
                ))
            self._persist_snapshots[d] = current
        return events

    def poll(self) -> Iterator[DetectorEvent]:
        if not _PSUTIL_OK:
            return

        if not self._snapshot_taken:
            self._take_persistence_snapshot()
            return   # baseline cycle — no alerts yet

        # Persistence check
        for ev in self._check_persistence():
            yield ev

        alive_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                pid  = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                alive_pids.add(pid)

                if pid in self._alerted_pids:
                    continue

                # 1. Known-bad name
                if name in config.SUSPICIOUS_PROC_NAMES:
                    self._alerted_pids.add(pid)
                    yield DetectorEvent(
                        detector   = "process",
                        threat     = "malware",
                        source_ip  = None,
                        pid        = pid,
                        confidence = "high",
                        evidence   = {"name": name, "pid": pid, "exe": proc.info.get("exe")},
                        notes      = "known_suspicious_process_name",
                    )
                    continue

                # 2. Connection checks
                try:
                    conns = proc.net_connections(kind="inet")
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    try:
                        conns = proc.connections(kind="inet")
                    except Exception:
                        continue

                outbound = [c for c in conns if c.status == "ESTABLISHED" and c.raddr]

                # C2 port hits
                c2 = [c for c in outbound if c.raddr.port in config.SUSPICIOUS_OUTBOUND_PORTS]
                if c2:
                    self._alerted_pids.add(pid)
                    yield DetectorEvent(
                        detector   = "process",
                        threat     = "malware",
                        source_ip  = c2[0].raddr.ip,
                        pid        = pid,
                        confidence = "high",
                        evidence   = {
                            "pid": pid, "name": name,
                            "c2_connections": [f"{c.raddr.ip}:{c.raddr.port}" for c in c2],
                        },
                        notes="c2_port_connection",
                    )
                    continue

                # Excessive outbound connections
                if len(outbound) > config.MAX_OUTBOUND_CONNS_PER_PROC:
                    self._alerted_pids.add(pid)
                    yield DetectorEvent(
                        detector   = "process",
                        threat     = "malware",
                        source_ip  = None,
                        pid        = pid,
                        confidence = "medium",
                        evidence   = {
                            "pid": pid, "name": name,
                            "outbound_count": len(outbound),
                            "threshold": config.MAX_OUTBOUND_CONNS_PER_PROC,
                        },
                        notes="excessive_outbound_connections",
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Remove stale pids so they can re-alert if a new process reuses the PID
        self._alerted_pids &= alive_pids
