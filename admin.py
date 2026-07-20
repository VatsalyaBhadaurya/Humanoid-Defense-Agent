#!/usr/bin/env python3
"""
TARA Defense Admin CLI.

Usage:
  python3 admin.py status
  python3 admin.py blocks
  python3 admin.py unblock <ip>
  python3 admin.py whitelist
  python3 admin.py whitelist add <ip>
  python3 admin.py whitelist remove <ip>
  python3 admin.py incidents [-n <count>]
  python3 admin.py metrics
  python3 admin.py reload          # send SIGHUP to running daemon
"""

import json
import os
import signal
import sys
import time
from pathlib import Path

# Bootstrap config before importing state/audit
import config
config.init()
config._load_values()

import state


def _die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def cmd_status() -> None:
    state.load()
    active = state.get_active_blocks()
    wl     = state.get_full_whitelist()
    metrics = state.get_metrics()

    print(f"Active blocks  : {len(active)}")
    print(f"Whitelist size : {len(wl)}")
    print(f"Dry-run mode   : {config.DRY_RUN}")
    print(f"Poll interval  : {config.POLL_INTERVAL}s")
    print()

    # Daemon alive check via health file
    healthy = Path(config.HEALTH_FILE).exists()
    if healthy:
        age = time.time() - Path(config.HEALTH_FILE).stat().st_mtime
        print(f"Daemon health  : {'OK' if age < 30 else 'STALE'} (last heartbeat {age:.0f}s ago)")
    else:
        print("Daemon health  : UNKNOWN (health file not found)")

    if metrics:
        print("\nMetrics:")
        for k, v in sorted(metrics.items()):
            print(f"  {k}: {v}")


def cmd_blocks() -> None:
    state.load()
    active = state.get_active_blocks()
    if not active:
        print("No active blocks.")
        return
    now = time.time()
    print(f"{'IP':<20} {'SCOPE':<8} {'CONFIDENCE':<12} {'EXPIRES IN':<14} REASON")
    print("-" * 70)
    for b in sorted(active, key=lambda x: x.expires_at):
        expires_in = f"{b.expires_at - now:.0f}s"
        print(f"{b.ip:<20} {b.scope:<8} {b.confidence:<12} {expires_in:<14} {b.reason}")


def cmd_unblock(ip: str) -> None:
    state.load()
    removed = state.remove_block(ip)
    if not removed:
        _die(f"No active block found for {ip}")
    # Remove iptables rules directly (daemon will also clean up on next expiry check)
    import subprocess
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                   capture_output=True)
    print(f"Unblocked {ip} ({len(removed)} block entry/entries removed)")


def cmd_whitelist(args: list[str]) -> None:
    state.load()
    if not args or args[0] == "list":
        wl = state.get_full_whitelist()
        static = set(config.WHITELIST_STATIC)
        print(f"{'IP':<25} SOURCE")
        print("-" * 40)
        for ip in sorted(wl):
            src = "static (config)" if ip in static else "dynamic (admin)"
            print(f"{ip:<25} {src}")
        return

    if args[0] == "add" and len(args) == 2:
        ip = args[1]
        state.whitelist_add(ip)
        print(f"Added {ip} to whitelist")
        return

    if args[0] == "remove" and len(args) == 2:
        ip = args[1]
        if state.whitelist_remove(ip):
            print(f"Removed {ip} from whitelist")
        else:
            _die(f"{ip} not found in dynamic whitelist (static IPs cannot be removed here)")
        return

    _die("Usage: whitelist [list | add <ip> | remove <ip>]")


def cmd_incidents(args: list[str]) -> None:
    n = 20
    if args and args[0] == "-n" and len(args) > 1:
        try:
            n = int(args[1])
        except ValueError:
            _die("-n requires an integer")

    log_path = config.AUDIT_LOG
    if not Path(log_path).exists():
        print(f"No audit log found at {log_path}")
        return

    lines = Path(log_path).read_text().splitlines()
    incidents = [l for l in lines if '"level": "INCIDENT"' in l or '"level":"INCIDENT"' in l]
    recent = incidents[-n:]

    if not recent:
        print("No incidents recorded.")
        return

    for line in recent:
        try:
            rec = json.loads(line)
            print(
                f"[{rec.get('ts','')}] {rec.get('confidence','?').upper()} "
                f"{rec.get('threat','?')} from {rec.get('source_ip','N/A')} "
                f"→ {rec.get('applied_action','?')}"
            )
        except json.JSONDecodeError:
            print(line)


def cmd_metrics() -> None:
    state.load()
    metrics = state.get_metrics()
    if not metrics:
        print("No metrics recorded yet.")
        return
    for k, v in sorted(metrics.items()):
        print(f"{k}: {v}")


def cmd_reload() -> None:
    pid_path = config.PID_FILE
    if not Path(pid_path).exists():
        _die(f"PID file not found at {pid_path} — is the daemon running?")
    try:
        pid = int(Path(pid_path).read_text().strip())
        os.kill(pid, signal.SIGHUP)
        print(f"Sent SIGHUP to daemon (PID {pid})")
    except (ValueError, ProcessLookupError) as e:
        _die(str(e))


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd, rest = args[0], args[1:]

    state.load()

    dispatch = {
        "status":    lambda: cmd_status(),
        "blocks":    lambda: cmd_blocks(),
        "unblock":   lambda: cmd_unblock(rest[0]) if rest else _die("unblock requires an IP"),
        "whitelist": lambda: cmd_whitelist(rest),
        "incidents": lambda: cmd_incidents(rest),
        "metrics":   lambda: cmd_metrics(),
        "reload":    lambda: cmd_reload(),
    }

    fn = dispatch.get(cmd)
    if fn is None:
        _die(f"Unknown command: {cmd}\n{__doc__}")
    fn()


if __name__ == "__main__":
    main()
