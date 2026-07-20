"""
SSH brute-force detector.
- Tails /var/log/auth.log for failed authentication events.
- Handles log rotation by tracking file inode — resets position when the
  file is replaced by logrotate.
- Supports both IPv4 and IPv6 source addresses (including ::ffff: mapped).
- Emits a DetectorEvent when per-IP failure count crosses a threshold
  within the configured rolling window.
"""

import os
import re
import time
from collections import defaultdict
from typing import Iterator

import config
import state
from detectors.base import DetectorEvent

# Matches IPv4 and IPv6 (including compressed forms)
_IP = r"([\da-fA-F:\.]+)"

_FAIL_PATTERNS: list[re.Pattern] = [
    re.compile(rf"Failed password for .+? from {_IP}"),
    re.compile(rf"Invalid user .+? from {_IP}"),
    re.compile(rf"authentication failure.*rhost={_IP}"),
    re.compile(rf"Connection closed by authenticating user .+? {_IP} port \d+ \[preauth\]"),
    re.compile(rf"Disconnected from authenticating user .+? {_IP} port \d+ \[preauth\]"),
]


def _normalize_ip(ip: str) -> str:
    """Strip IPv6-mapped IPv4 prefix: ::ffff:1.2.3.4 → 1.2.3.4"""
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


class SSHDetector:
    def __init__(self) -> None:
        self._file_pos: int    = 0
        self._file_inode: int  = -1
        # ip → list of failure timestamps within the window
        self._attempts: dict[str, list[float]] = defaultdict(list)
        # ip → last alerted count (prevents re-firing on same count)
        self._alerted_count: dict[str, int] = {}

    def _reopen_if_rotated(self) -> None:
        """Detect log rotation by inode change or file shrink."""
        try:
            st = os.stat(config.AUTH_LOG)
            if st.st_ino != self._file_inode:
                self._file_pos   = 0
                self._file_inode = st.st_ino
        except FileNotFoundError:
            pass

    def _read_new_lines(self) -> list[str]:
        self._reopen_if_rotated()
        try:
            with open(config.AUTH_LOG, "r", errors="replace") as f:
                # If the file shrank (e.g. truncated), reset
                f.seek(0, 2)
                end = f.tell()
                if self._file_pos > end:
                    self._file_pos = 0
                f.seek(self._file_pos)
                lines = f.readlines()
                self._file_pos = f.tell()
            return lines
        except FileNotFoundError:
            return []

    def _purge_old(self, now: float) -> None:
        cutoff = now - config.SSH_FAIL_WINDOW_SECS
        for ip in list(self._attempts):
            self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
            if not self._attempts[ip]:
                del self._attempts[ip]

    def _confidence(self, count: int) -> str | None:
        if count >= config.SSH_FAIL_CRITICAL: return "critical"
        if count >= config.SSH_FAIL_HIGH:     return "high"
        if count >= config.SSH_FAIL_MEDIUM:   return "medium"
        return None

    def poll(self) -> Iterator[DetectorEvent]:
        now   = time.time()
        lines = self._read_new_lines()

        for line in lines:
            for pat in _FAIL_PATTERNS:
                m = pat.search(line)
                if m:
                    ip = _normalize_ip(m.group(1))
                    self._attempts[ip].append(now)
                    break

        self._purge_old(now)

        for ip, timestamps in self._attempts.items():
            if state.is_whitelisted(ip):
                continue

            count      = len(timestamps)
            confidence = self._confidence(count)
            if confidence is None:
                continue

            if count <= self._alerted_count.get(ip, 0):
                continue

            self._alerted_count[ip] = count

            yield DetectorEvent(
                detector   = "ssh",
                threat     = "ssh_brute_force",
                source_ip  = ip,
                pid        = None,
                confidence = confidence,
                evidence   = {
                    "failed_attempts": count,
                    "window_secs":     config.SSH_FAIL_WINDOW_SECS,
                },
            )
