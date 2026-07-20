"""
Persistent state manager.
Saves active blocks, whitelist additions, and incident counters to a JSON file.
Atomic writes (tmp + rename) prevent corruption on crash.
Re-applies live blocks to iptables after a daemon restart.
"""

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock

import config

_lock = Lock()


@dataclass
class Block:
    ip: str
    scope: str          # "local" | "router" | "both"
    expires_at: float
    reason: str
    confidence: str


@dataclass
class _State:
    blocks: list[Block]             = field(default_factory=list)
    extra_whitelist: list[str]      = field(default_factory=list)
    metrics: dict[str, int]         = field(default_factory=dict)


_state = _State()


# ── Persistence ───────────────────────────────────────────────────────────────

def load() -> None:
    path = config.STATE_FILE
    if not Path(path).exists():
        return
    try:
        with open(path) as f:
            raw = json.load(f)
        now = time.time()
        _state.blocks = [
            Block(**b) for b in raw.get("blocks", [])
            if b.get("expires_at", 0) > now          # drop already-expired entries
        ]
        _state.extra_whitelist = raw.get("extra_whitelist", [])
        _state.metrics         = raw.get("metrics", {})
    except (json.JSONDecodeError, KeyError, TypeError):
        pass   # corrupted state — start fresh


def save() -> None:
    path = config.STATE_FILE
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "blocks":          [asdict(b) for b in _state.blocks],
        "extra_whitelist": _state.extra_whitelist,
        "metrics":         _state.metrics,
        "saved_at":        time.time(),
    }
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(Path(path).parent))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── Blocks ────────────────────────────────────────────────────────────────────

def add_block(block: Block) -> None:
    with _lock:
        # Replace if already present for same IP+scope
        _state.blocks = [b for b in _state.blocks if not (b.ip == block.ip and b.scope == block.scope)]
        _state.blocks.append(block)
    save()


def remove_block(ip: str, scope: str = "both") -> list[Block]:
    """Remove and return matching blocks."""
    with _lock:
        removed = [b for b in _state.blocks if b.ip == ip and (scope == "both" or b.scope == scope)]
        _state.blocks = [b for b in _state.blocks if b not in removed]
    if removed:
        save()
    return removed


def get_expired_blocks() -> list[Block]:
    now = time.time()
    with _lock:
        return [b for b in _state.blocks if b.expires_at <= now]


def get_active_blocks() -> list[Block]:
    now = time.time()
    with _lock:
        return [b for b in _state.blocks if b.expires_at > now]


def is_blocked(ip: str) -> bool:
    now = time.time()
    with _lock:
        return any(b.ip == ip and b.expires_at > now for b in _state.blocks)


def purge_expired() -> list[Block]:
    now = time.time()
    with _lock:
        expired = [b for b in _state.blocks if b.expires_at <= now]
        _state.blocks = [b for b in _state.blocks if b.expires_at > now]
    if expired:
        save()
    return expired


# ── Whitelist ─────────────────────────────────────────────────────────────────

def whitelist_add(ip: str) -> None:
    with _lock:
        if ip not in _state.extra_whitelist:
            _state.extra_whitelist.append(ip)
    save()


def whitelist_remove(ip: str) -> bool:
    with _lock:
        if ip in _state.extra_whitelist:
            _state.extra_whitelist.remove(ip)
            save()
            return True
    return False


def get_full_whitelist() -> set[str]:
    with _lock:
        return set(config.WHITELIST_STATIC) | set(_state.extra_whitelist)


def is_whitelisted(ip: str) -> bool:
    return ip in get_full_whitelist()


# ── Metrics ───────────────────────────────────────────────────────────────────

def increment(key: str, by: int = 1) -> None:
    with _lock:
        _state.metrics[key] = _state.metrics.get(key, 0) + by


def get_metrics() -> dict[str, int]:
    with _lock:
        return dict(_state.metrics)
