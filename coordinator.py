"""
TARA Defense Coordinator — main daemon for TARA humanoid security.
Runs a poll loop, collects detector events, correlates them,
applies TARA policy, and dispatches mitigations via responder.
"""

import signal
import sys
import time

import audit
import config
import responder
import tara_policy
from detectors.process import ProcessDetector
from detectors.scan import ScanDetector
from detectors.ssh import SSHDetector
from detectors.traffic import TrafficDetector

_running = True


def _shutdown(sig, frame):
    global _running
    audit.info("coordinator", f"Shutdown signal {sig} received")
    _running = False


def _memory_ok() -> bool:
    try:
        import psutil
        free_mb = psutil.virtual_memory().available / (1024 * 1024)
        return free_mb > config.MEMORY_PRESSURE_MB
    except ImportError:
        return True


def _handle_event(
    *,
    detector: str,
    threat: str,
    asset: str,
    source_ip: str | None,
    pid: int | None,
    confidence: str,
    evidence: dict,
    notes: str = "",
) -> None:
    policy_str = tara_policy.lookup(threat, confidence)
    actions = tara_policy.parse_actions(policy_str)
    applied = responder.dispatch(actions, source_ip=source_ip, pid=pid, threat=threat)

    audit.incident(
        detector=detector,
        threat=threat,
        asset=asset,
        source_ip=source_ip,
        evidence=evidence,
        confidence=confidence,
        recommended_action=policy_str,
        applied_action=", ".join(applied),
        notes=notes,
    )


def _correlate(ssh_ips: set[str], scan_ips: set[str]) -> None:
    """Escalate confidence when an IP appears in multiple detector buckets."""
    overlap = ssh_ips & scan_ips
    for ip in overlap:
        audit.warn(
            "correlation",
            f"{ip} flagged by BOTH ssh and scan detectors — escalating to critical",
        )
        _handle_event(
            detector="correlator",
            threat="ssh_brute_force",
            asset="jetson-tara",
            source_ip=ip,
            pid=None,
            confidence="critical",
            evidence={"reason": "ssh + port_scan correlation"},
            notes="escalated by multi-detector correlation",
        )


def run() -> None:
    audit.init(config.AUDIT_LOG)
    audit.info("coordinator", "TARA Defense Coordinator starting")

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    ssh_det   = SSHDetector()
    traffic_det = TrafficDetector()
    scan_det  = ScanDetector()
    proc_det  = ProcessDetector()

    if not proc_det.available():
        audit.warn("coordinator", "psutil not available — process detector disabled")

    while _running:
        tick_start = time.time()
        mem_ok = _memory_ok()

        # --- SSH brute-force ---
        ssh_ips: set[str] = set()
        for ev in ssh_det.poll():
            ssh_ips.add(ev.source_ip)
            _handle_event(
                detector="ssh",
                threat="ssh_brute_force",
                asset="jetson-tara/sshd",
                source_ip=ev.source_ip,
                pid=None,
                confidence=ev.confidence,
                evidence=ev.evidence,
            )

        # --- Traffic / DDoS ---
        traffic_ev = traffic_det.poll()
        if traffic_ev:
            _handle_event(
                detector="traffic",
                threat="ddos",
                asset=f"interface:{traffic_ev.interface}",
                source_ip=None,
                pid=None,
                confidence=traffic_ev.confidence,
                evidence=traffic_ev.evidence,
                notes="source IP indeterminate from /proc/net/dev; router-side rate limit applied",
            )

        # --- Port scan / recon ---
        scan_ips: set[str] = set()
        for ev in scan_det.poll():
            scan_ips.add(ev.source_ip)
            _handle_event(
                detector="scan",
                threat="port_scan",
                asset="jetson-tara",
                source_ip=ev.source_ip,
                pid=None,
                confidence=ev.confidence,
                evidence=ev.evidence,
            )

        # --- Process / malware (skip if memory is tight) ---
        if mem_ok and proc_det.available():
            for ev in proc_det.poll():
                _handle_event(
                    detector="process",
                    threat="malware",
                    asset=f"pid:{ev.pid}",
                    source_ip=None,
                    pid=ev.pid,
                    confidence=ev.confidence,
                    evidence=ev.evidence,
                    notes=ev.reason,
                )
        elif not mem_ok:
            audit.warn("coordinator", "Memory pressure — process detector skipped this cycle")

        # --- Correlation pass ---
        _correlate(ssh_ips, scan_ips)

        # --- Expire timed blocks ---
        responder.expire_blocks()

        # Sleep for remainder of poll interval
        elapsed = time.time() - tick_start
        sleep_for = max(0.0, config.POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)

    audit.info("coordinator", "TARA Defense Coordinator stopped")


if __name__ == "__main__":
    run()
