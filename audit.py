"""
Structured audit logger.
Writes JSON-lines to the configured log file and stderr.
Thread-safe. Handles log directory creation automatically.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import config

_lock = Lock()
_initialized = False


def init() -> None:
    global _initialized
    Path(config.AUDIT_LOG).parent.mkdir(parents=True, exist_ok=True)
    _initialized = True
    info("audit", f"Audit logger started — writing to {config.AUDIT_LOG}")


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(record: dict) -> None:
    line = json.dumps(record)
    with _lock:
        if _initialized:
            try:
                with open(config.AUDIT_LOG, "a") as f:
                    f.write(line + "\n")
            except OSError as e:
                print(f"[audit] write error: {e}", file=sys.stderr)
        print(line, file=sys.stderr)


def incident(
    *,
    detector: str,
    threat: str,
    asset: str,
    source_ip: str | None,
    evidence: dict,
    confidence: str,
    recommended_action: str,
    applied_action: str,
    notes: str = "",
) -> None:
    _write({
        "level":              "INCIDENT",
        "ts":                 _ts(),
        "detector":           detector,
        "threat":             threat,
        "asset":              asset,
        "source_ip":          source_ip,
        "evidence":           evidence,
        "confidence":         confidence,
        "recommended_action": recommended_action,
        "applied_action":     applied_action,
        "notes":              notes,
        "dry_run":            config.DRY_RUN,
    })


def action(tag: str, detail: str) -> None:
    _write({"level": "ACTION", "ts": _ts(), "tag": tag, "detail": detail, "dry_run": config.DRY_RUN})


def warn(tag: str, detail: str) -> None:
    _write({"level": "WARN", "ts": _ts(), "tag": tag, "detail": detail})


def info(tag: str, detail: str) -> None:
    _write({"level": "INFO", "ts": _ts(), "tag": tag, "detail": detail})


def error(tag: str, detail: str) -> None:
    _write({"level": "ERROR", "ts": _ts(), "tag": tag, "detail": detail})
