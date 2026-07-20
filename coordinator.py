"""
TARA Defense Coordinator — main daemon.

Startup sequence:
  1. Validate config and environment (iptables, auth.log, router SSH).
  2. Load persistent state and re-apply any live blocks.
  3. Write PID file.
  4. Signal systemd ready.
  5. Enter poll loop.

Signals:
  SIGTERM / SIGINT  → graceful shutdown
  SIGHUP            → reload config file without restarting
"""

import os
import signal
import sys
import time
from pathlib import Path

import audit
import config
import health
import responder
import state
import tara_policy
from correlator import Correlator
from detectors.base import DetectorEvent
from detectors.process import ProcessDetector
from detectors.scan import ScanDetector
from detectors.ssh import SSHDetector
from detectors.traffic import TrafficDetector

_running     = True
_reload_flag = False


# ── Signal handlers ───────────────────────────────────────────────────────────

def _handle_shutdown(sig: int, _frame) -> None:
    global _running
    audit.info("coordinator", f"Signal {sig} received — shutting down")
    _running = False


def _handle_reload(sig: int, _frame) -> None:
    global _reload_flag
    audit.info("coordinator", "SIGHUP received — will reload config on next cycle")
    _reload_flag = True


# ── PID file ──────────────────────────────────────────────────────────────────

def _write_pid() -> None:
    path = config.PID_FILE
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(str(os.getpid()))


def _remove_pid() -> None:
    try:
        Path(config.PID_FILE).unlink()
    except FileNotFoundError:
        pass


# ── Startup self-checks ───────────────────────────────────────────────────────

def _check_environment() -> list[str]:
    """Return list of warning strings (non-fatal) or raise on fatal issues."""
    warnings: list[str] = []

    # iptables
    result = __import__("subprocess").run(
        ["iptables", "-L", "-n"], capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError("iptables not available or insufficient permissions")

    # auth.log
    if not Path(config.AUTH_LOG).exists():
        warnings.append(f"auth.log not found at {config.AUTH_LOG} — SSH detection disabled until file appears")

    # Router SSH key
    if not Path(config.ROUTER_SSH_KEY).exists():
        warnings.append(f"Router SSH key not found at {config.ROUTER_SSH_KEY} — router enforcement disabled")

    # psutil
    try:
        import psutil
    except ImportError:
        warnings.append("psutil not installed — process detector disabled (run: pip3 install psutil)")

    return warnings


# ── Memory check ──────────────────────────────────────────────────────────────

def _memory_ok() -> bool:
    try:
        import psutil
        free_mb = psutil.virtual_memory().available / (1024 * 1024)
        if free_mb < config.MEMORY_PRESSURE_MB:
            audit.warn("coordinator", f"Memory pressure: {free_mb:.0f} MB free < {config.MEMORY_PRESSURE_MB} MB threshold")
            return False
        return True
    except ImportError:
        return True


# ── Core event handler ────────────────────────────────────────────────────────

def _handle(event: DetectorEvent, correlator: Correlator) -> None:
    correlator.record(event)

    policy = tara_policy.lookup(event.threat, event.confidence)
    applied = responder.dispatch(
        policy.actions,
        source_ip  = event.source_ip,
        pid        = event.pid,
        threat     = event.threat,
        confidence = event.confidence,
    )

    state.increment(f"incidents_{event.threat}")
    state.increment(f"incidents_{event.confidence}")

    audit.incident(
        detector          = event.detector,
        threat            = event.threat,
        asset             = "jetson-tara",
        source_ip         = event.source_ip,
        evidence          = event.evidence,
        confidence        = event.confidence,
        recommended_action= policy.description,
        applied_action    = ", ".join(applied) if applied else "none",
        notes             = event.notes,
    )


# ── Main loop ─────────────────────────────────────────────────────────────────

def run() -> None:
    global _reload_flag

    # Init config and audit
    config.init()
    config._load_values()
    audit.init()

    audit.info("coordinator", "=" * 60)
    audit.info("coordinator", "TARA Defense Coordinator starting")
    audit.info("coordinator", f"dry_run={config.DRY_RUN}  poll={config.POLL_INTERVAL}s  interface={config.MONITOR_INTERFACE}")

    # Environment checks
    try:
        warnings = _check_environment()
        for w in warnings:
            audit.warn("startup", w)
    except RuntimeError as e:
        audit.error("startup", str(e))
        sys.exit(1)

    # Load persistent state and re-apply live blocks
    state.load()
    responder.reapply_active_blocks()

    # Write PID file
    _write_pid()

    # Register signals
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT,  _handle_shutdown)
    signal.signal(signal.SIGHUP,  _handle_reload)

    # Init detectors and correlator
    ssh_det     = SSHDetector()
    traffic_det = TrafficDetector()
    scan_det    = ScanDetector()
    proc_det    = ProcessDetector()
    correlator  = Correlator()

    if not proc_det.available():
        audit.warn("coordinator", "Process detector unavailable — install psutil")

    health.startup_complete()
    audit.info("coordinator", "Startup complete — entering poll loop")

    metrics_tick = 0

    while _running:
        tick_start = time.time()

        # Config reload on SIGHUP
        if _reload_flag:
            _reload_flag = False
            config.init()
            config._load_values()
            audit.info("coordinator", "Config reloaded")

        mem_ok = _memory_ok()

        # ── SSH brute-force ───────────────────────────────────────────────
        try:
            for ev in ssh_det.poll():
                _handle(ev, correlator)
        except Exception as e:
            audit.error("ssh_detector", str(e))

        # ── Traffic / DDoS ────────────────────────────────────────────────
        try:
            for ev in traffic_det.poll():
                _handle(ev, correlator)
        except Exception as e:
            audit.error("traffic_detector", str(e))

        # ── Port scan / recon ─────────────────────────────────────────────
        try:
            for ev in scan_det.poll():
                _handle(ev, correlator)
        except Exception as e:
            audit.error("scan_detector", str(e))

        # ── Process / malware (skip under memory pressure) ────────────────
        if mem_ok and proc_det.available():
            try:
                for ev in proc_det.poll():
                    _handle(ev, correlator)
            except Exception as e:
                audit.error("process_detector", str(e))
        elif not mem_ok:
            audit.warn("coordinator", "Process detector skipped — memory pressure")

        # ── Correlation pass ──────────────────────────────────────────────
        try:
            for ev in correlator.flush():
                _handle(ev, correlator)
        except Exception as e:
            audit.error("correlator", str(e))

        # ── Block expiry ──────────────────────────────────────────────────
        try:
            responder.expire_blocks()
        except Exception as e:
            audit.error("expire_blocks", str(e))

        # ── Health heartbeat ──────────────────────────────────────────────
        health.watchdog_ping()

        # ── Periodic metrics log (every 60 cycles) ────────────────────────
        metrics_tick += 1
        if metrics_tick >= 60:
            metrics_tick = 0
            m = state.get_metrics()
            if m:
                audit.info("metrics", str(m))

        # ── Sleep for remainder of poll interval ──────────────────────────
        elapsed   = time.time() - tick_start
        sleep_for = max(0.0, config.POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)

    # ── Shutdown ──────────────────────────────────────────────────────────────
    health.stopping()
    state.save()
    _remove_pid()
    audit.info("coordinator", "TARA Defense Coordinator stopped cleanly")


if __name__ == "__main__":
    run()
