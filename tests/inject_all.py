#!/usr/bin/env python3
"""
Local injection test — no attacker VM needed.
Directly writes fake events into auth.log and launches a suspicious process
so the daemon detects them in the next poll cycle.

Run on the Jetson VM (defender) while coordinator.py is running.
"""

import os
import subprocess
import sys
import time
from datetime import datetime

# Resolve project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import config
config.init()
config._load_values()

FAKE_IPS = {
    "ssh":   "10.0.0.20",
    "scan":  "10.0.0.21",
    "ddos":  "10.0.0.22",
    "combo": "10.0.0.23",   # will trigger correlation
}

AUTH_LOG = config.AUTH_LOG


def ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def inject_auth_log(line: str) -> None:
    with open(AUTH_LOG, "a") as f:
        f.write(line + "\n")


def print_section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ── Test 1: SSH brute force ───────────────────────────────────────────────────

def inject_ssh_bruteforce(ip: str, count: int = 25) -> None:
    print_section(f"SSH Brute Force — {count} failures from {ip}")
    host = "jetson-tara"
    for i in range(count):
        user = ["root", "admin", "tara", "ubuntu", "pi"][i % 5]
        line = f"{ts()} {host} sshd[1234]: Failed password for {user} from {ip} port {10000 + i} ssh2"
        inject_auth_log(line)
        if i % 5 == 0:
            print(f"  Injected {i+1}/{count} failures...")
        time.sleep(0.05)
    print(f"  Done — injected {count} failed SSH attempts from {ip}")


# ── Test 2: Port scan simulation ──────────────────────────────────────────────

def inject_port_scan_via_proc(ip: str, port_count: int = 30) -> None:
    """
    We can't write to /proc/net/tcp, so we generate real connections
    using Python sockets to localhost from a subprocess — this populates
    the real tcp table and the scan detector picks it up.

    Alternatively (if running as attacker): use attacker/port_scan.sh
    """
    print_section(f"Port Scan Simulation — {port_count} ports from {ip}")
    print("  NOTE: /proc/net/tcp cannot be injected directly.")
    print("  Use attacker/port_scan.sh from attacker VM for real scan detection.")
    print(f"  Or: nmap -sS {config.MONITOR_INTERFACE} from {ip}")

    # What we CAN test: inject auth.log port-knock style messages (some setups log these)
    host = "jetson-tara"
    for port in range(22, 22 + port_count):
        line = (
            f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"SRC={ip} DST=10.0.0.10 PROTO=TCP DPT={port}"
        )
        inject_auth_log(line)
        time.sleep(0.02)
    print(f"  Injected {port_count} UFW block log entries — if UFW logging is on, scan detector fires")


# ── Test 3: DDoS / traffic flood (real) ──────────────────────────────────────

def launch_local_flood(duration: int = 10) -> None:
    print_section(f"Traffic Flood — local loopback test for {duration}s")
    print("  Launching iperf3 server + client on loopback...")
    print("  NOTE: For real interface flood, use attacker/traffic_flood.sh from attacker VM")
    srv = subprocess.Popen(["iperf3", "-s", "-p", "15201"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    cli = subprocess.Popen(
        ["iperf3", "-c", "127.0.0.1", "-p", "15201", "-t", str(duration), "-P", "4"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"  Running for {duration}s — check audit log for ddos events on loopback")
    cli.wait()
    srv.terminate()


# ── Test 4: Malware process simulation ───────────────────────────────────────

def launch_suspicious_process() -> None:
    print_section("Malware Process Simulation")
    # Temporarily rename a Python script to a suspicious name via exec
    print("  Launching process named 'ncat' via exec trick...")
    proc = subprocess.Popen(
        ["python3", "-c",
         "import sys, os, time; "
         "os.execv('/usr/bin/sleep', ['ncat', '120'])"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  Launched suspicious process (PID {proc.pid}) — will auto-exit in 120s")
    print(f"  Process detector should flag it as 'ncat' within {config.POLL_INTERVAL * 2}s")
    return proc


# ── Test 5: Correlation trigger (SSH + scan from same IP) ────────────────────

def inject_correlation(ip: str) -> None:
    print_section(f"Correlation Test — SSH brute + scan from same IP {ip}")
    inject_ssh_bruteforce(ip, count=12)
    print(f"  SSH failures injected. Now run: nmap -sS <jetson_ip> from {ip}")
    print(f"  Correlator will escalate to critical within {config.POLL_INTERVAL * 2}s of scan detection")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\nTARA Defense — Local Injection Test Suite")
    print(f"Auth log target: {AUTH_LOG}")
    print(f"Coordinator poll interval: {config.POLL_INTERVAL}s")

    if not os.path.exists(AUTH_LOG):
        print(f"\nWARNING: {AUTH_LOG} does not exist — creating it")
        os.makedirs(os.path.dirname(AUTH_LOG), exist_ok=True)
        open(AUTH_LOG, "w").close()

    # SSH brute force
    inject_ssh_bruteforce(FAKE_IPS["ssh"], count=25)
    time.sleep(2)

    # Port scan (log injection)
    inject_port_scan_via_proc(FAKE_IPS["scan"], port_count=30)
    time.sleep(2)

    # Correlation (same IP, SSH + scan combined)
    inject_correlation(FAKE_IPS["combo"])
    time.sleep(2)

    # Malware process
    proc = launch_suspicious_process()

    print(f"\n{'='*60}")
    print(f"  All injections done.")
    print(f"  Wait {config.POLL_INTERVAL * 3}s for daemon to process, then run:")
    print(f"    python3 tests/verify.py all")
    print(f"{'='*60}")

    print(f"\nWaiting {config.POLL_INTERVAL * 3}s for daemon...")
    time.sleep(config.POLL_INTERVAL * 3)

    print("\nCleaning up malware test process...")
    try:
        proc.terminate()
    except Exception:
        pass

    print("Done. Run: python3 tests/verify.py all")


if __name__ == "__main__":
    main()
