#!/usr/bin/env python3
"""
Detection verifier.
Reads the audit log and checks that expected incidents were recorded.

Usage:
  python3 tests/verify.py all
  python3 tests/verify.py ssh
  python3 tests/verify.py scan
  python3 tests/verify.py ddos
  python3 tests/verify.py malware
  python3 tests/verify.py correlation
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import config
config.init()
config._load_values()

PASS = "\033[92m PASS\033[0m"
FAIL = "\033[91m FAIL\033[0m"
WARN = "\033[93m WARN\033[0m"
INFO = "\033[94m INFO\033[0m"


def load_incidents() -> list[dict]:
    path = config.AUDIT_LOG
    if not Path(path).exists():
        return []
    incidents = []
    for line in Path(path).read_text().splitlines():
        try:
            rec = json.loads(line)
            if rec.get("level") == "INCIDENT":
                incidents.append(rec)
        except json.JSONDecodeError:
            continue
    return incidents


def load_actions() -> list[dict]:
    path = config.AUDIT_LOG
    if not Path(path).exists():
        return []
    actions = []
    for line in Path(path).read_text().splitlines():
        try:
            rec = json.loads(line)
            if rec.get("level") in ("ACTION", "WARN"):
                actions.append(rec)
        except json.JSONDecodeError:
            continue
    return actions


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = PASS if condition else FAIL
    print(f"  [{status}] {label}")
    if detail:
        print(f"         {detail}")
    return condition


def section(title: str) -> None:
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")


# ── Individual checks ─────────────────────────────────────────────────────────

def verify_ssh(incidents: list[dict]) -> int:
    section("SSH Brute Force Detection")
    ssh = [i for i in incidents if i.get("threat") == "ssh_brute_force"]
    passed = 0

    passed += check("At least one SSH incident detected", len(ssh) > 0,
                    f"found {len(ssh)} incident(s)")

    high_or_crit = [i for i in ssh if i.get("confidence") in ("high", "critical")]
    passed += check("High/critical confidence SSH incident detected", len(high_or_crit) > 0,
                    f"found {len(high_or_crit)} high/critical")

    blocked = [i for i in ssh if "blocked" in i.get("applied_action", "")]
    passed += check("Block action applied", len(blocked) > 0,
                    f"actions: {[i.get('applied_action') for i in ssh]}")

    tightened = [i for i in ssh if "ssh_tightened" in i.get("applied_action", "")]
    passed += check("SSH config tightened", len(tightened) > 0,
                    f"found {len(tightened)} tighten action(s)")

    return passed


def verify_scan(incidents: list[dict]) -> int:
    section("Port Scan / Recon Detection")
    scans = [i for i in incidents if i.get("threat") == "port_scan"]
    passed = 0

    passed += check("At least one scan incident detected", len(scans) > 0,
                    f"found {len(scans)} incident(s)")

    if scans:
        best = max(scans, key=lambda i: ["low","medium","high","critical"].index(
            i.get("confidence", "low")))
        passed += check("Confidence at least medium",
                        best.get("confidence") in ("medium","high","critical"),
                        f"best confidence: {best.get('confidence')}")

        ev = best.get("evidence", {})
        passed += check("Evidence contains distinct_ports",
                        "distinct_ports" in ev,
                        f"evidence keys: {list(ev.keys())}")

    return passed


def verify_ddos(incidents: list[dict]) -> int:
    section("DDoS / Traffic Flood Detection")
    ddos = [i for i in incidents if i.get("threat") == "ddos"]
    passed = 0

    passed += check("At least one DDoS incident detected", len(ddos) > 0,
                    f"found {len(ddos)} incident(s)")

    rate_limited = [i for i in ddos if "rate_limit" in i.get("applied_action", "")]
    passed += check("Router rate-limit action applied", len(rate_limited) > 0,
                    f"actions: {[i.get('applied_action') for i in ddos[:3]]}")

    return passed


def verify_malware(incidents: list[dict]) -> int:
    section("Malware / Suspicious Process Detection")
    mal = [i for i in incidents if i.get("threat") == "malware"]
    passed = 0

    passed += check("At least one malware incident detected", len(mal) > 0,
                    f"found {len(mal)} incident(s)")

    isolated = [i for i in mal if "isolated" in i.get("applied_action", "")]
    notified = [i for i in mal if "notified" in i.get("applied_action", "")]
    passed += check("Process isolated or operator notified",
                    len(isolated) > 0 or len(notified) > 0,
                    f"isolated={len(isolated)} notified={len(notified)}")

    return passed


def verify_correlation(incidents: list[dict]) -> int:
    section("Multi-Detector Correlation")
    corr = [i for i in incidents if "correlated" in i.get("threat", "")]
    passed = 0

    passed += check("Correlation event generated", len(corr) > 0,
                    f"found {len(corr)} correlated event(s)")

    if corr:
        crit = [i for i in corr if i.get("confidence") == "critical"]
        passed += check("Correlated event at critical confidence", len(crit) > 0,
                        f"threats: {[i.get('threat') for i in corr]}")

        ev = corr[0].get("evidence", {})
        passed += check("Evidence lists triggered detectors",
                        "detectors_triggered" in ev,
                        f"evidence: {ev}")

    return passed


def verify_whitelist(incidents: list[dict]) -> int:
    section("Whitelist Enforcement")
    actions = load_actions()
    whitelist_skips = [a for a in actions if "whitelisted" in a.get("detail", "").lower()]
    passed = 0
    passed += check("Whitelist skip logged (if whitelisted IP was seen)",
                    True,   # informational only
                    f"whitelist skip events: {len(whitelist_skips)}")
    return passed


def verify_block_expiry() -> int:
    section("Block Expiry Cleanup")
    actions = load_actions()
    expired = [a for a in actions if a.get("tag") == "block_expired"]
    passed = 0
    passed += check("Block expiry events present (may be 0 if blocks haven't expired yet)",
                    True,
                    f"block_expired events: {len(expired)}")
    return passed


# ── Summary ───────────────────────────────────────────────────────────────────

def summary(incidents: list[dict]) -> None:
    section("Incident Summary")
    by_threat: dict[str, list] = defaultdict(list)
    for i in incidents:
        by_threat[i.get("threat", "unknown")].append(i.get("confidence", "?"))

    if not by_threat:
        print(f"  [{WARN}] No incidents found in audit log: {config.AUDIT_LOG}")
        print("  Make sure coordinator.py is running and inject_all.py has been executed.")
        return

    print(f"  {'THREAT':<30} {'COUNT':<8} CONFIDENCES")
    print(f"  {'─'*55}")
    for threat, confs in sorted(by_threat.items()):
        conf_summary = ", ".join(sorted(set(confs)))
        print(f"  {threat:<30} {len(confs):<8} {conf_summary}")

    print(f"\n  Total incidents: {len(incidents)}")
    print(f"  Audit log: {config.AUDIT_LOG}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    incidents = load_incidents()

    print(f"\nTARA Defense — Verification Report")
    print(f"Audit log: {config.AUDIT_LOG}")
    print(f"Total incidents loaded: {len(incidents)}")

    total_passed = 0
    total_checks = 0

    run_all = target == "all"

    if run_all or target == "ssh":
        p = verify_ssh(incidents)
        total_passed += p
        total_checks += 4

    if run_all or target == "scan":
        p = verify_scan(incidents)
        total_passed += p
        total_checks += 3

    if run_all or target == "ddos":
        p = verify_ddos(incidents)
        total_passed += p
        total_checks += 2

    if run_all or target == "malware":
        p = verify_malware(incidents)
        total_passed += p
        total_checks += 2

    if run_all or target == "correlation":
        p = verify_correlation(incidents)
        total_passed += p
        total_checks += 3

    if run_all:
        verify_whitelist(incidents)
        verify_block_expiry()
        summary(incidents)

    if total_checks > 0:
        print(f"\n{'='*55}")
        color = "\033[92m" if total_passed == total_checks else "\033[91m"
        print(f"  {color}Result: {total_passed}/{total_checks} checks passed\033[0m")
        print(f"{'='*55}\n")
        sys.exit(0 if total_passed == total_checks else 1)


if __name__ == "__main__":
    main()
