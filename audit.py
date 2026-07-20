import json
import os
import sys
from datetime import datetime, timezone


_log_path: str = ""


def init(path: str) -> None:
    global _log_path
    _log_path = path
    os.makedirs(os.path.dirname(path), exist_ok=True)


def _entry(level: str, data: dict) -> dict:
    return {"ts": datetime.now(timezone.utc).isoformat(), "level": level, **data}


def _write(record: dict) -> None:
    line = json.dumps(record)
    if _log_path:
        with open(_log_path, "a") as f:
            f.write(line + "\n")
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
    _write(_entry("INCIDENT", {
        "detector":           detector,
        "threat":             threat,
        "asset":              asset,
        "source_ip":          source_ip,
        "evidence":           evidence,
        "confidence":         confidence,
        "recommended_action": recommended_action,
        "applied_action":     applied_action,
        "notes":              notes,
    }))


def action(tag: str, detail: str) -> None:
    _write(_entry("ACTION", {"tag": tag, "detail": detail}))


def warn(tag: str, detail: str) -> None:
    _write(_entry("WARN", {"tag": tag, "detail": detail}))


def info(tag: str, detail: str) -> None:
    _write(_entry("INFO", {"tag": tag, "detail": detail}))
