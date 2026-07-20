"""
SSH brute-force detector.
Tails /var/log/auth.log, counts failed attempts per source IP in a rolling window.
Emits events when thresholds are crossed.
"""

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

import config

# Patterns that indicate a failed SSH authentication attempt
_FAIL_PATTERNS = [
    re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Connection closed by authenticating user .+ (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]"),
]


@dataclass
class SSHEvent:
    source_ip: str
    failed_count: int
    window_secs: int
    confidence: str
    evidence: dict = field(default_factory=dict)


class SSHDetector:
    def __init__(self) -> None:
        self._file_pos: int = 0
        # ip -> list of timestamps of failed attempts
        self._attempts: dict[str, list[float]] = defaultdict(list)
        # ips already acted on (avoid repeated firing)
        self._alerted: dict[str, float] = {}

    def _read_new_lines(self) -> list[str]:
        try:
            with open(config.AUTH_LOG, "r", errors="replace") as f:
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
        if count >= config.SSH_FAIL_CRITICAL:
            return "critical"
        if count >= config.SSH_FAIL_HIGH:
            return "high"
        if count >= config.SSH_FAIL_MEDIUM:
            return "medium"
        return None

    def poll(self) -> Iterator[SSHEvent]:
        now = time.time()
        lines = self._read_new_lines()

        for line in lines:
            for pattern in _FAIL_PATTERNS:
                m = pattern.search(line)
                if m:
                    ip = m.group(1)
                    self._attempts[ip].append(now)
                    break

        self._purge_old(now)

        for ip, timestamps in self._attempts.items():
            count = len(timestamps)
            confidence = self._confidence(count)
            if confidence is None:
                continue

            last_alert = self._alerted.get(ip, 0)
            # Re-fire only if count grew since last alert (avoids spam)
            if count <= self._alerted.get(f"{ip}_count", 0):
                continue

            self._alerted[ip] = now
            self._alerted[f"{ip}_count"] = count

            yield SSHEvent(
                source_ip=ip,
                failed_count=count,
                window_secs=config.SSH_FAIL_WINDOW_SECS,
                confidence=confidence,
                evidence={
                    "failed_attempts": count,
                    "window_secs": config.SSH_FAIL_WINDOW_SECS,
                },
            )
