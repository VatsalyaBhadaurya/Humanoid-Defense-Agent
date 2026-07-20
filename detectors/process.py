"""
Malware / suspicious-process detector.
Uses psutil to scan the running process list for:
  - Known-bad process names
  - Processes with excessive outbound connections
  - Connections to known C2 ports
"""

from dataclasses import dataclass, field

import config

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False


@dataclass
class ProcessEvent:
    pid: int
    name: str
    reason: str
    confidence: str
    evidence: dict = field(default_factory=dict)


class ProcessDetector:
    def __init__(self) -> None:
        self._alerted_pids: set[int] = set()

    def available(self) -> bool:
        return _PSUTIL_OK

    def poll(self) -> list[ProcessEvent]:
        if not _PSUTIL_OK:
            return []

        events: list[ProcessEvent] = []

        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()

                if pid in self._alerted_pids:
                    continue

                # Known-bad name
                if name in config.SUSPICIOUS_PROC_NAMES:
                    events.append(ProcessEvent(
                        pid=pid,
                        name=name,
                        reason="known_suspicious_name",
                        confidence="high",
                        evidence={"name": name, "pid": pid},
                    ))
                    self._alerted_pids.add(pid)
                    continue

                # Check connections
                try:
                    conns = proc.net_connections(kind="inet")
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                outbound = [
                    c for c in conns
                    if c.status == "ESTABLISHED" and c.raddr
                ]

                c2_hits = [
                    c for c in outbound
                    if c.raddr.port in config.SUSPICIOUS_OUTBOUND_PORTS
                ]

                if c2_hits:
                    events.append(ProcessEvent(
                        pid=pid,
                        name=name,
                        reason="c2_port_connection",
                        confidence="high",
                        evidence={
                            "pid": pid,
                            "name": name,
                            "c2_connections": [
                                f"{c.raddr.ip}:{c.raddr.port}" for c in c2_hits
                            ],
                        },
                    ))
                    self._alerted_pids.add(pid)
                    continue

                if len(outbound) > config.MAX_OUTBOUND_CONNS_PER_PROC:
                    events.append(ProcessEvent(
                        pid=pid,
                        name=name,
                        reason="excessive_outbound_connections",
                        confidence="medium",
                        evidence={
                            "pid": pid,
                            "name": name,
                            "outbound_count": len(outbound),
                            "threshold": config.MAX_OUTBOUND_CONNS_PER_PROC,
                        },
                    ))
                    self._alerted_pids.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Clean up stale pids
        alive = {p.pid for p in psutil.process_iter(["pid"])}
        self._alerted_pids &= alive

        return events
