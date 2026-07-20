import os

MONITOR_INTERFACE = os.getenv("MONITOR_IFACE", "eth0")

# SSH brute-force thresholds (failures per window)
SSH_FAIL_WINDOW_SECS   = 60
SSH_FAIL_MEDIUM        = 5
SSH_FAIL_HIGH          = 10
SSH_FAIL_CRITICAL      = 20

# DDoS thresholds (bytes per second on monitored interface)
TRAFFIC_FLOOD_MEDIUM   = 50_000_000   # 50 MB/s
TRAFFIC_FLOOD_HIGH     = 100_000_000  # 100 MB/s
TRAFFIC_FLOOD_CRITICAL = 200_000_000  # 200 MB/s

# Port scan thresholds (distinct ports touched per IP per window)
SCAN_WINDOW_SECS       = 30
SCAN_PORT_MEDIUM       = 10
SCAN_PORT_HIGH         = 25
SCAN_PORT_CRITICAL     = 50

# Block durations (seconds)
BLOCK_SOFT   = 300    # 5 min  — medium confidence
BLOCK_HARD   = 1800   # 30 min — high confidence
BLOCK_CRIT   = 3600   # 1 hr   — critical

# Router SSH access
ROUTER_HOST    = os.getenv("ROUTER_HOST",    "192.168.1.1")
ROUTER_USER    = os.getenv("ROUTER_USER",    "admin")
ROUTER_SSH_KEY = os.getenv("ROUTER_SSH_KEY", "/home/tara/.ssh/router_key")

# Paths
AUTH_LOG  = "/var/log/auth.log"
AUDIT_LOG = "/var/log/tara-defense/incidents.jsonl"

# Graceful-degradation threshold (MB of free RAM)
MEMORY_PRESSURE_MB = 200

POLL_INTERVAL = 5  # seconds

SUSPICIOUS_PROC_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan",
    "hydra", "medusa", "john", "hashcat",
    "msfconsole", "meterpreter",
    "xmrig", "minerd", "cryptominer",
}

SUSPICIOUS_OUTBOUND_PORTS = {4444, 1337, 31337, 6666, 9999}
MAX_OUTBOUND_CONNS_PER_PROC = 50
