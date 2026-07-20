"""
Health check module.
- Writes a heartbeat timestamp to a file every poll cycle.
- Notifies systemd watchdog via sd_notify if WATCHDOG_USEC is set.
- External monitors can check the health file age to detect hangs.
"""

import os
import time
from pathlib import Path

import config

_sd_notify_available = False

try:
    # Try to import systemd notifier (available on most Jetson Ubuntu setups)
    import ctypes
    _libsystemd = ctypes.CDLL("libsystemd.so.0", use_errno=True)
    _sd_notify_available = True
except (OSError, ImportError):
    pass


def _sd_notify(status: str) -> None:
    if not _sd_notify_available:
        return
    try:
        _libsystemd.sd_notify(0, status.encode())
    except Exception:
        pass


def startup_complete() -> None:
    """Call once after successful initialization."""
    _sd_notify("READY=1\nSTATUS=TARA Defense Coordinator running")
    _write_heartbeat()


def watchdog_ping() -> None:
    """Call once per poll cycle to keep systemd watchdog satisfied."""
    _sd_notify("WATCHDOG=1")
    _write_heartbeat()


def stopping() -> None:
    _sd_notify("STOPPING=1\nSTATUS=TARA Defense Coordinator stopping")


def _write_heartbeat() -> None:
    path = config.HEALTH_FILE
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def is_healthy(max_age_secs: float = 30.0) -> bool:
    """Return True if the health file was updated within max_age_secs."""
    try:
        mtime = Path(config.HEALTH_FILE).stat().st_mtime
        return (time.time() - mtime) < max_age_secs
    except FileNotFoundError:
        return False
