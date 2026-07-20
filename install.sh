#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="${SERVICE_USER:-root}"

echo "[tara-defense] Installing TARA Defense System..."

# ── Dependencies ──────────────────────────────────────────────────────────────
echo "[tara-defense] Installing Python dependencies..."
pip3 install --quiet -r "$INSTALL_DIR/requirements.txt"

# ── Directories ───────────────────────────────────────────────────────────────
echo "[tara-defense] Creating runtime directories..."
mkdir -p /var/log/tara-defense
mkdir -p /var/lib/tara-defense
mkdir -p /run/tara-defense
mkdir -p /etc/tara-defense

# ── Config ────────────────────────────────────────────────────────────────────
if [ ! -f /etc/tara-defense/tara-defense.yaml ]; then
    cp "$INSTALL_DIR/tara-defense.yaml" /etc/tara-defense/tara-defense.yaml
    echo "[tara-defense] Default config installed at /etc/tara-defense/tara-defense.yaml"
    echo "[tara-defense] >>> Edit this file to set your router IP, interface, and thresholds <<<"
else
    echo "[tara-defense] Config already exists at /etc/tara-defense/tara-defense.yaml — not overwriting"
fi

# ── SSH key for router access ─────────────────────────────────────────────────
KEY_DIR="/home/tara/.ssh"
KEY="$KEY_DIR/router_key"
if [ ! -f "$KEY" ]; then
    echo "[tara-defense] Generating router SSH key..."
    mkdir -p "$KEY_DIR"
    ssh-keygen -t ed25519 -f "$KEY" -N "" -C "tara-defense-router-$(hostname)"
    chmod 700 "$KEY_DIR"
    chmod 600 "$KEY"
    echo ""
    echo "[tara-defense] ================================================================"
    echo "[tara-defense] Add this public key to your router's authorized_keys:"
    echo ""
    cat "${KEY}.pub"
    echo ""
    echo "[tara-defense] Command (replace ROUTER_IP):"
    echo "  ssh-copy-id -i ${KEY}.pub admin@ROUTER_IP"
    echo "[tara-defense] ================================================================"
    echo ""
else
    echo "[tara-defense] Router SSH key already exists at $KEY"
fi

# ── Test router connectivity ───────────────────────────────────────────────────
ROUTER_HOST="${ROUTER_HOST:-192.168.1.1}"
ROUTER_USER="${ROUTER_USER:-admin}"
echo "[tara-defense] Testing router SSH connectivity to $ROUTER_USER@$ROUTER_HOST ..."
if ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
       "$ROUTER_USER@$ROUTER_HOST" "echo tara-ok" 2>/dev/null | grep -q "tara-ok"; then
    echo "[tara-defense] Router SSH: OK"
else
    echo "[tara-defense] WARNING: Router SSH test failed — check key deployment and router config"
fi

# ── Verify iptables ────────────────────────────────────────────────────────────
if ! iptables -L -n &>/dev/null; then
    echo "[tara-defense] ERROR: iptables not accessible. Run as root or grant CAP_NET_ADMIN."
    exit 1
fi
echo "[tara-defense] iptables: OK"

# ── Notification pipe (optional) ──────────────────────────────────────────────
PIPE="/run/tara-defense/notify.pipe"
if [ ! -p "$PIPE" ]; then
    mkfifo "$PIPE"
    chmod 600 "$PIPE"
fi

# ── systemd service ───────────────────────────────────────────────────────────
echo "[tara-defense] Installing systemd service..."
cat > /etc/systemd/system/tara-defense.service <<EOF
[Unit]
Description=TARA Humanoid Defense Coordinator
Documentation=file://$INSTALL_DIR/README.md
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/coordinator.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

# Watchdog — restart if no heartbeat within 30s
WatchdogSec=30

Environment=TARA_CONFIG=/etc/tara-defense/tara-defense.yaml
Environment=MONITOR_IFACE=eth0
Environment=ROUTER_HOST=$ROUTER_HOST
Environment=ROUTER_USER=$ROUTER_USER
Environment=ROUTER_SSH_KEY=$KEY

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/tara-defense /var/lib/tara-defense /run/tara-defense /etc/ssh
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL

[Install]
WantedBy=multi-user.target
EOF

# ── Admin CLI symlink ─────────────────────────────────────────────────────────
if [ ! -f /usr/local/bin/tara-admin ]; then
    cat > /usr/local/bin/tara-admin <<EOF2
#!/usr/bin/env bash
exec python3 $INSTALL_DIR/admin.py "\$@"
EOF2
    chmod +x /usr/local/bin/tara-admin
    echo "[tara-defense] Admin CLI available as: tara-admin"
fi

# ── Enable and start ──────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable tara-defense
systemctl restart tara-defense

echo ""
echo "[tara-defense] ✓ Installation complete."
echo ""
echo "Useful commands:"
echo "  systemctl status tara-defense"
echo "  journalctl -u tara-defense -f"
echo "  tara-admin status"
echo "  tara-admin blocks"
echo "  tara-admin incidents -n 50"
echo "  tara-admin whitelist add <ip>"
echo "  tara-admin unblock <ip>"
