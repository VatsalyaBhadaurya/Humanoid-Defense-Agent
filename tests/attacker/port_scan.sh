#!/usr/bin/env bash
# Run from the ATTACKER VM.
# Usage: bash port_scan.sh <target_ip>
# Requires: nmap

set -euo pipefail
TARGET="${1:?Usage: $0 <target_ip>}"

echo "[attacker] Port scan against $TARGET"
echo "[attacker] Phase 1: SYN scan (fast) — triggers scan detector"
nmap -sS -T4 --top-ports 100 "$TARGET" -oN /tmp/scan_phase1.txt
echo "[attacker] Phase 1 done"

echo "[attacker] Waiting 5s..."
sleep 5

echo "[attacker] Phase 2: Full port range scan — pushes port count over critical threshold"
nmap -sS -T3 -p 1-1000 "$TARGET" -oN /tmp/scan_phase2.txt
echo "[attacker] Phase 2 done"

echo ""
echo "[attacker] Results saved to /tmp/scan_phase1.txt and /tmp/scan_phase2.txt"
echo "[attacker] Check defender: tara-admin incidents -n 10"
