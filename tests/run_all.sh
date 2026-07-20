#!/usr/bin/env bash
# Full test orchestrator.
# Run on the Jetson VM (defender).
# Optionally pass attacker IP to trigger real network attacks.
#
# Usage:
#   bash tests/run_all.sh                        # local injection only
#   bash tests/run_all.sh <attacker_ip> <self_ip> # full VM test

set -euo pipefail

ATTACKER_IP="${1:-}"
DEFENDER_IP="${2:-$(hostname -I | awk '{print $1}')}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║      TARA Defense — Full Test Suite                 ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Defender : $DEFENDER_IP"
echo "║  Attacker : ${ATTACKER_IP:-'(local injection only)'}"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Check daemon is running ───────────────────────────────────────────────────
if ! pgrep -f "coordinator.py" > /dev/null; then
    echo "[test] ERROR: coordinator.py is not running."
    echo "[test] Start it first: sudo python3 $ROOT/coordinator.py"
    exit 1
fi
echo "[test] coordinator.py is running — OK"

# ── Pre-test: record baseline incident count ──────────────────────────────────
BEFORE=$(grep -c '"level": "INCIDENT"' "$(python3 -c "import sys; sys.path.insert(0,'$ROOT'); import config; config.init(); config._load_values(); print(config.AUDIT_LOG)")" 2>/dev/null || echo 0)
echo "[test] Baseline incidents in log: $BEFORE"
echo ""

# ── Test 1: Local injection (always runs) ─────────────────────────────────────
echo "━━━ [1/5] Local SSH injection ━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPT_DIR/inject_all.py"
echo ""

# ── Test 2: Malware simulation (local) ───────────────────────────────────────
echo "━━━ [2/5] Malware simulation ━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPT_DIR/sim_malware.py" --kill-after 30 &
SIM_PID=$!
echo "[test] Malware sim running as PID $SIM_PID"
echo ""

# ── Test 3: Real network attacks (only if attacker IP provided) ───────────────
if [ -n "$ATTACKER_IP" ]; then
    echo "━━━ [3/5] Real network attacks (SSH to attacker) ━━━━━━━━"
    echo "[test] Triggering attacker scripts on $ATTACKER_IP..."
    ssh "$ATTACKER_IP" "bash ~/tara-tests/ssh_bruteforce.sh $DEFENDER_IP" &
    echo "[test] SSH brute force launched (background)"
    sleep 5
    ssh "$ATTACKER_IP" "bash ~/tara-tests/port_scan.sh $DEFENDER_IP" &
    echo "[test] Port scan launched (background)"
    sleep 5
    ssh "$ATTACKER_IP" "bash ~/tara-tests/traffic_flood.sh $DEFENDER_IP 20" &
    echo "[test] Traffic flood launched (background)"
    echo ""
else
    echo "━━━ [3/5] Skipping real network attacks (no attacker IP given) ━━━━━"
fi

# ── Wait for daemon cycles ────────────────────────────────────────────────────
POLL=$(python3 -c "import sys; sys.path.insert(0,'$ROOT'); import config; config.init(); config._load_values(); print(config.POLL_INTERVAL)")
WAIT=$((POLL * 6))
echo "[test] Waiting ${WAIT}s for daemon to process all events..."
sleep "$WAIT"

# ── Kill background sims ──────────────────────────────────────────────────────
kill "$SIM_PID" 2>/dev/null || true
wait 2>/dev/null || true

# ── Test 4: Verify blocks are in iptables ─────────────────────────────────────
echo ""
echo "━━━ [4/5] iptables block verification ━━━━━━━━━━━━━━━━━━━"
RULES=$(iptables -L INPUT -n | grep -c "DROP" || echo 0)
echo "[test] DROP rules in INPUT chain: $RULES"
if [ "$RULES" -gt 0 ]; then
    echo "[test] PASS — iptables blocks applied"
    iptables -L INPUT -n | grep "DROP" | head -10
else
    echo "[test] WARN — No DROP rules found (may be in dry_run mode)"
fi
echo ""

# ── Test 5: Admin CLI verification ────────────────────────────────────────────
echo "━━━ [5/5] Admin CLI checks ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$ROOT/admin.py" status
echo ""
python3 "$ROOT/admin.py" blocks
echo ""

# ── Final verification ────────────────────────────────────────────────────────
echo "━━━ Verification report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPT_DIR/verify.py" all
echo ""

AFTER=$(grep -c '"level": "INCIDENT"' "$(python3 -c "import sys; sys.path.insert(0,'$ROOT'); import config; config.init(); config._load_values(); print(config.AUDIT_LOG)")" 2>/dev/null || echo 0)
NEW=$((AFTER - BEFORE))
echo "[test] New incidents generated: $NEW"
echo "[test] Full audit log: $(python3 -c "import sys; sys.path.insert(0,'$ROOT'); import config; config.init(); config._load_values(); print(config.AUDIT_LOG)")"
