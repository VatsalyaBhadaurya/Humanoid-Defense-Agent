#!/usr/bin/env bash
set -euo pipefail

# TARA Defense System — installer for Jetson (Ubuntu)

echo "[tara-defense] Installing dependencies..."
pip3 install --quiet psutil

echo "[tara-defense] Creating log directory..."
sudo mkdir -p /var/log/tara-defense
sudo chown "$USER" /var/log/tara-defense

echo "[tara-defense] Generating router SSH key (if not present)..."
KEY=/home/tara/.ssh/router_key
if [ ! -f "$KEY" ]; then
    mkdir -p /home/tara/.ssh
    ssh-keygen -t ed25519 -f "$KEY" -N "" -C "tara-defense-router"
    echo "[tara-defense] Copy this public key to your router's authorized_keys:"
    cat "${KEY}.pub"
fi

echo "[tara-defense] Installing systemd service..."
sudo tee /etc/systemd/system/tara-defense.service > /dev/null <<EOF
[Unit]
Description=TARA Humanoid Defense Coordinator
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/coordinator.py
Restart=on-failure
RestartSec=5
Environment=MONITOR_IFACE=eth0
Environment=ROUTER_HOST=192.168.1.1
Environment=ROUTER_USER=admin
Environment=ROUTER_SSH_KEY=/home/tara/.ssh/router_key

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable tara-defense
sudo systemctl start tara-defense

echo "[tara-defense] Done. Status:"
sudo systemctl status tara-defense --no-pager
