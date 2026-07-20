"""
Configuration loader.
Primary source: tara-defense.yaml (path set via TARA_CONFIG env var).
Environment variables override specific fields where documented below.
Fails fast at startup with a clear message if required values are missing.
"""

import os
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

_DEFAULT_CONFIG_PATH = "/etc/tara-defense/tara-defense.yaml"
_LOCAL_CONFIG_PATH   = str(Path(__file__).parent / "tara-defense.yaml")

# ── Loaded config dict (populated by init()) ─────────────────────────────────
_cfg: dict = {}


def init(path: str | None = None) -> None:
    global _cfg
    config_path = path or os.getenv("TARA_CONFIG", "")

    if not config_path:
        if Path(_LOCAL_CONFIG_PATH).exists():
            config_path = _LOCAL_CONFIG_PATH
        elif Path(_DEFAULT_CONFIG_PATH).exists():
            config_path = _DEFAULT_CONFIG_PATH

    if config_path and Path(config_path).exists():
        if not _YAML_OK:
            print("[config] PyYAML not installed — falling back to defaults", file=sys.stderr)
            _cfg = {}
        else:
            with open(config_path) as f:
                _cfg = yaml.safe_load(f) or {}
    else:
        _cfg = {}

    _validate()


def _get(keys: list[str], default: Any) -> Any:
    node = _cfg
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node


def _validate() -> None:
    errors = []
    if not Path(ROUTER_SSH_KEY).exists():
        errors.append(f"router.ssh_key not found: {ROUTER_SSH_KEY}")
    if errors:
        for e in errors:
            print(f"[config] WARNING: {e}", file=sys.stderr)


# ── Network ───────────────────────────────────────────────────────────────────
@property
def _iface() -> str: ...
MONITOR_INTERFACE: str = ""   # set dynamically below

# ── Router ────────────────────────────────────────────────────────────────────
ROUTER_HOST:        str = ""
ROUTER_USER:        str = ""
ROUTER_SSH_KEY:     str = ""
ROUTER_TIMEOUT:     int = 10
ROUTER_RETRY:       int = 2

# ── Thresholds ────────────────────────────────────────────────────────────────
SSH_FAIL_WINDOW_SECS:   int = 60
SSH_FAIL_MEDIUM:        int = 5
SSH_FAIL_HIGH:          int = 10
SSH_FAIL_CRITICAL:      int = 20

TRAFFIC_FLOOD_MEDIUM:   int = 50_000_000
TRAFFIC_FLOOD_HIGH:     int = 100_000_000
TRAFFIC_FLOOD_CRITICAL: int = 200_000_000

SCAN_WINDOW_SECS:       int = 30
SCAN_PORT_MEDIUM:       int = 10
SCAN_PORT_HIGH:         int = 25
SCAN_PORT_CRITICAL:     int = 50

# ── Block durations (seconds) ─────────────────────────────────────────────────
BLOCK_SOFT:  int = 300
BLOCK_HARD:  int = 1800
BLOCK_CRIT:  int = 3600

# ── Paths ─────────────────────────────────────────────────────────────────────
AUTH_LOG:    str = "/var/log/auth.log"
AUDIT_LOG:   str = "/var/log/tara-defense/incidents.jsonl"
STATE_FILE:  str = "/var/lib/tara-defense/state.json"
PID_FILE:    str = "/run/tara-defense.pid"
HEALTH_FILE: str = "/run/tara-defense.health"

# ── System ────────────────────────────────────────────────────────────────────
POLL_INTERVAL:             int   = 5
MEMORY_PRESSURE_MB:        int   = 200
DRY_RUN:                   bool  = False
OPERATOR_NOTIFY_COOLDOWN:  int   = 300

# ── Whitelist ─────────────────────────────────────────────────────────────────
WHITELIST_STATIC: list[str] = ["127.0.0.1", "::1"]

# ── Process heuristics ────────────────────────────────────────────────────────
SUSPICIOUS_PROC_NAMES:      set[str] = set()
SUSPICIOUS_OUTBOUND_PORTS:  set[int] = set()
MAX_OUTBOUND_CONNS_PER_PROC: int     = 50


def _load_values() -> None:
    """Populate module-level constants from the loaded _cfg dict + env overrides."""
    global (
        MONITOR_INTERFACE, ROUTER_HOST, ROUTER_USER, ROUTER_SSH_KEY,
        ROUTER_TIMEOUT, ROUTER_RETRY,
        SSH_FAIL_WINDOW_SECS, SSH_FAIL_MEDIUM, SSH_FAIL_HIGH, SSH_FAIL_CRITICAL,
        TRAFFIC_FLOOD_MEDIUM, TRAFFIC_FLOOD_HIGH, TRAFFIC_FLOOD_CRITICAL,
        SCAN_WINDOW_SECS, SCAN_PORT_MEDIUM, SCAN_PORT_HIGH, SCAN_PORT_CRITICAL,
        BLOCK_SOFT, BLOCK_HARD, BLOCK_CRIT,
        AUTH_LOG, AUDIT_LOG, STATE_FILE, PID_FILE, HEALTH_FILE,
        POLL_INTERVAL, MEMORY_PRESSURE_MB, DRY_RUN, OPERATOR_NOTIFY_COOLDOWN,
        WHITELIST_STATIC, SUSPICIOUS_PROC_NAMES, SUSPICIOUS_OUTBOUND_PORTS,
        MAX_OUTBOUND_CONNS_PER_PROC,
    )

    g = _get

    MONITOR_INTERFACE = os.getenv("MONITOR_IFACE",    g(["network", "interface"],        "eth0"))
    ROUTER_HOST       = os.getenv("ROUTER_HOST",      g(["router",  "host"],             "192.168.1.1"))
    ROUTER_USER       = os.getenv("ROUTER_USER",      g(["router",  "user"],             "admin"))
    ROUTER_SSH_KEY    = os.getenv("ROUTER_SSH_KEY",   g(["router",  "ssh_key"],          "/home/tara/.ssh/router_key"))
    ROUTER_TIMEOUT    =           int(g(["router",  "timeout_secs"],      10))
    ROUTER_RETRY      =           int(g(["router",  "retry_attempts"],     2))

    SSH_FAIL_WINDOW_SECS = int(g(["thresholds", "ssh", "window_secs"], 60))
    SSH_FAIL_MEDIUM      = int(g(["thresholds", "ssh", "medium"],       5))
    SSH_FAIL_HIGH        = int(g(["thresholds", "ssh", "high"],        10))
    SSH_FAIL_CRITICAL    = int(g(["thresholds", "ssh", "critical"],    20))

    TRAFFIC_FLOOD_MEDIUM   = int(g(["thresholds", "traffic", "flood_medium_bps"],    50_000_000))
    TRAFFIC_FLOOD_HIGH     = int(g(["thresholds", "traffic", "flood_high_bps"],     100_000_000))
    TRAFFIC_FLOOD_CRITICAL = int(g(["thresholds", "traffic", "flood_critical_bps"], 200_000_000))

    SCAN_WINDOW_SECS    = int(g(["thresholds", "scan", "window_secs"],    30))
    SCAN_PORT_MEDIUM    = int(g(["thresholds", "scan", "medium_ports"],   10))
    SCAN_PORT_HIGH      = int(g(["thresholds", "scan", "high_ports"],     25))
    SCAN_PORT_CRITICAL  = int(g(["thresholds", "scan", "critical_ports"], 50))

    BLOCK_SOFT = int(g(["blocks", "soft_secs"],     300))
    BLOCK_HARD = int(g(["blocks", "hard_secs"],    1800))
    BLOCK_CRIT = int(g(["blocks", "critical_secs"], 3600))

    AUTH_LOG    = g(["paths", "auth_log"],   "/var/log/auth.log")
    AUDIT_LOG   = g(["paths", "audit_log"],  "/var/log/tara-defense/incidents.jsonl")
    STATE_FILE  = g(["paths", "state_file"], "/var/lib/tara-defense/state.json")
    PID_FILE    = g(["paths", "pid_file"],   "/run/tara-defense.pid")
    HEALTH_FILE = g(["paths", "health_file"],"/run/tara-defense.health")

    POLL_INTERVAL            = int(g(["system", "poll_interval_secs"],         5))
    MEMORY_PRESSURE_MB       = int(g(["system", "memory_pressure_mb"],       200))
    DRY_RUN                  =     bool(os.getenv("TARA_DRY_RUN", str(g(["system", "dry_run"], False))))
    OPERATOR_NOTIFY_COOLDOWN = int(g(["system", "operator_notify_cooldown_secs"], 300))

    WHITELIST_STATIC = list(g(["whitelist"], ["127.0.0.1", "::1"]))

    proc_cfg = g(["suspicious_processes"], {})
    SUSPICIOUS_PROC_NAMES     = set(proc_cfg.get("names", [
        "nc","ncat","netcat","nmap","masscan","hydra","medusa",
        "john","hashcat","msfconsole","xmrig","minerd","cryptominer",
    ]))
    SUSPICIOUS_OUTBOUND_PORTS = set(int(p) for p in proc_cfg.get("outbound_ports", [4444,1337,31337,6666,9999]))
    MAX_OUTBOUND_CONNS_PER_PROC = int(proc_cfg.get("max_outbound_connections", 50))


# Auto-load when module is imported
init()
_load_values()
