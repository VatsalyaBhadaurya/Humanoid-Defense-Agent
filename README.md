# Humanoid Defense System

An edge cyber-security daemon that protects humanoid robot by monitoring the Jetson controller and enforcing threat mitigations at the router — with zero heavy dependencies and low memory overhead.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    External Network                          │
│         SSH brute force / DDoS / port scan / malware        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                ┌───────────▼────────────┐
                │       Router           │
                │  (first enforcement)   │
                │  rate-limit / drop     │
                └───────────┬────────────┘
                            │  summarized telemetry
                ┌───────────▼────────────┐
                │    Jetson (Ubuntu)     │
                │  coordinator.py        │
                │  ┌──────────────────┐  │
                │  │    Detectors     │  │
                │  │  SSH / Traffic   │  │
                │  │  Process / Scan  │  │
                │  └────────┬─────────┘  │
                │           │            │
                │  ┌────────▼─────────┐  │
                │  │   Correlator     │  │
                │  │ multi-detector   │  │
                │  │ escalation       │  │
                │  └────────┬─────────┘  │
                │           │            │
                │  ┌────────▼─────────┐  │
                │  │  Robot Policy    │  │
                │  │  Engine          │  │
                │  └────────┬─────────┘  │
                │           │            │
                │  ┌────────▼─────────┐  │
                │  │   Responder      │  │
                │  │ iptables + router│  │
                │  │ SSH enforcement  │  │
                │  └────────┬─────────┘  │
                │           │ (async,    │
                │  ┌────────▼─────────┐  │
                │  │  AI Advisory     │  │  ──── Anthropic API
                │  │  (tara_ai.py)    │  │       (Claude Opus)
                │  │  high/critical   │  │
                │  │  events only     │  │
                │  └──────────────────┘  │
                └────────────────────────┘
```

---

## Threat Coverage

| Threat | Detection Source | Response |
|---|---|---|
| SSH brute force | `/var/log/auth.log` (tail + inode rotation tracking) | Temp IP block (local + router) + SSH config tighten |
| DDoS / traffic flood | `/proc/net/dev` byte-rate delta + `/proc/net/tcp` connection count | Router rate-limit or drop |
| Port scan / recon | `/proc/net/tcp` distinct port contacts + SYN_RECV count | Soft block + monitoring escalation |
| Malware / suspicious process | `psutil` process scan + persistence dir monitoring | Process isolation (SIGSTOP) + operator notify |

### Confidence → Action mapping

| Confidence | Trigger | Action |
|---|---|---|
| Low | Single indicator, below threshold | Log only |
| Medium | Threshold crossed | Soft block (5 min) + alert |
| High | High threshold or 2 indicators | Hard block (30 min) + notify operator |
| Critical | Critical threshold or multi-detector correlation | 1-hour block + notify operator |

### Correlation escalation

When the same source IP appears in multiple detectors within 120 seconds, the event is escalated to **critical** regardless of individual confidence:

- SSH brute force + port scan → `correlated_ssh_scan`
- DDoS + port scan → `correlated_ddos_scan`
- Malware + any network threat → `correlated_malware_net`

---

## File Structure

```
tara-defense/
├── coordinator.py        # Main daemon — poll loop, signal handling, PID file
├── config.py             # YAML + env var config loader with validation
├── tara_policy.py        # Threat → mitigation policy table
├── tara_ai.py            # AI advisory layer — Claude threat analysis (async)
├── state.py              # Persistent block/whitelist/metrics (atomic JSON)
├── audit.py              # Structured JSON-lines audit logger
├── correlator.py         # Multi-detector correlation engine
├── responder.py          # iptables + router SSH enforcement
├── health.py             # systemd watchdog notify + heartbeat file
├── admin.py              # Admin CLI (tara-admin)
├── tara-defense.yaml     # Example config file
├── requirements.txt      # psutil, PyYAML, anthropic
├── install.sh            # Full installer for Jetson (Ubuntu)
├── detectors/
│   ├── base.py           # Shared DetectorEvent dataclass
│   ├── ssh.py            # SSH brute-force (auth.log watcher)
│   ├── traffic.py        # DDoS (/proc/net/dev + /proc/net/tcp)
│   ├── process.py        # Malware (psutil + persistence dirs)
│   └── scan.py           # Port scan + SYN flood (/proc/net/tcp)
└── tests/
    ├── inject_all.py     # Local injection test (no attacker VM needed)
    ├── sim_malware.py    # Suspicious process + connection flood sim
    ├── verify.py         # Audit log verifier with pass/fail output
    ├── run_all.sh        # Full test orchestrator
    └── attacker/
        ├── ssh_bruteforce.sh     # hydra SSH attack
        ├── port_scan.sh          # nmap scan
        ├── traffic_flood.sh      # hping3 / iperf3 flood
        └── correlation_attack.sh # recon then brute force (same IP)
```

---

## Requirements

- NVIDIA Jetson running **Ubuntu 20.04+** (JetPack)
- Python 3.10+
- `iptables` (run as root or with `CAP_NET_ADMIN`)
- Router accessible via SSH (OpenWrt / DD-WRT / any Linux-based router)

```bash
pip3 install -r requirements.txt
# psutil>=5.9.0
# PyYAML>=6.0
# anthropic>=0.40.0   (required only if ai.enabled: true)
```

---

## Installation

### 1. Clone

```bash
git clone https://github.com/VatsalyaBhadaurya/Humanoid-Defense-Agent.git
cd Humanoid-Defense-Agent
```

### 2. Configure

```bash
sudo cp tara-defense.yaml /etc/tara-defense/tara-defense.yaml
sudo nano /etc/tara-defense/tara-defense.yaml
```

Key fields to edit:

```yaml
network:
  interface: eth0          # your Jetson's network interface

router:
  host: 192.168.1.1        # your router's IP
  user: admin              # SSH user on the router
  ssh_key: /home/tara/.ssh/router_key
```

### 3. Install (generates SSH key, deploys systemd service)

```bash
sudo bash install.sh
```

The installer will:
- Install Python dependencies
- Generate an ed25519 SSH key for router access
- Print the public key to copy to your router
- Test router SSH connectivity
- Install and start a `systemd` service with watchdog

### 4. Verify

```bash
sudo systemctl status tara-defense
tara-admin status
tail -f /var/log/tara-defense/incidents.jsonl | python3 -m json.tool
```

---

## Configuration Reference

```yaml
# /etc/tara-defense/tara-defense.yaml

network:
  interface: eth0

router:
  host: 192.168.1.1
  user: admin
  ssh_key: /home/tara/.ssh/router_key
  timeout_secs: 10
  retry_attempts: 2

thresholds:
  ssh:
    window_secs: 60     # rolling window for counting failures
    medium: 5           # failures before medium confidence
    high: 10
    critical: 20
  traffic:
    flood_medium_bps: 50000000    # 50 MB/s
    flood_high_bps: 100000000
    flood_critical_bps: 200000000
  scan:
    window_secs: 30
    medium_ports: 10    # distinct ports before medium confidence
    high_ports: 25
    critical_ports: 50

blocks:
  soft_secs: 300        # 5 min — medium confidence
  hard_secs: 1800       # 30 min — high confidence
  critical_secs: 3600   # 1 hr — critical confidence

system:
  poll_interval_secs: 5
  memory_pressure_mb: 200   # skip optional analytics below this free RAM
  dry_run: false            # true = log only, no enforcement
  operator_notify_cooldown_secs: 300

whitelist:
  - 127.0.0.1
  - ::1
  # Add your management IPs here to prevent accidental self-block
  # - 10.0.0.1
```

All fields can also be overridden with environment variables:

| Env var | Overrides |
|---|---|
| `TARA_CONFIG` | Path to config YAML |
| `MONITOR_IFACE` | `network.interface` |
| `ROUTER_HOST` | `router.host` |
| `ROUTER_USER` | `router.user` |
| `ROUTER_SSH_KEY` | `router.ssh_key` |
| `TARA_DRY_RUN=true` | `system.dry_run` |
| `ANTHROPIC_API_KEY` | Claude API key (required when `ai.enabled: true`) |

### AI Analysis (optional)

When enabled, TARA submits high and critical incidents to Claude for a second-opinion analysis. The rule-based system enforces immediately as usual — Claude's response arrives asynchronously and is written back to the audit log.

```yaml
ai:
  enabled: true          # activate AI analysis
  model: claude-opus-4-8
  cooldown_secs: 300     # max 1 API call per (source_ip, threat) per 5 minutes
  max_tokens: 1024
```

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sudo systemctl restart tara-defense
```

AI analysis fires for:
- Any event with `high` or `critical` confidence
- Correlated multi-detector events (`correlated_ssh_scan`, `correlated_ddos_scan`, `correlated_malware_net`)

If the API is unreachable or the key is missing, a single WARN log entry is written and the system continues normally.

---

## Admin CLI

```bash
tara-admin status                  # daemon health, active blocks, metrics
tara-admin blocks                  # list active IP blocks with expiry times
tara-admin unblock <ip>            # manually remove a block
tara-admin whitelist               # show full whitelist
tara-admin whitelist add <ip>      # add IP to dynamic whitelist
tara-admin whitelist remove <ip>   # remove from dynamic whitelist
tara-admin incidents -n 50         # show last 50 incidents
tara-admin metrics                 # incident counters by type
tara-admin reload                  # send SIGHUP to reload config live
```

---

## Testing in a VM

### Network topology

```
[ Attacker VM ]  ──── same subnet ────  [ Jetson VM (defender) ]
  10.0.0.20                               10.0.0.10
```

### Attacker VM setup

```bash
sudo apt install nmap hping3 hydra iperf3 -y
```

---

### Option A — Local injection (no attacker VM needed)

Tests SSH brute force detection and correlation by writing directly to `auth.log`, and launches a suspicious process for the malware detector. Safe to run anywhere.

```bash
# Terminal 1 — start the daemon
sudo python3 coordinator.py

# Terminal 2 — inject fake events
sudo python3 tests/inject_all.py

# Terminal 3 — verify detections
python3 tests/verify.py all
```

---

### Option B — Two-VM full attack simulation

#### On the Jetson VM (defender)

```bash
sudo systemctl start tara-defense

# Watch live detections
tail -f /var/log/tara-defense/incidents.jsonl | python3 -m json.tool
```

#### On the Attacker VM

Run each attack individually:

```bash
# SSH brute force — triggers ssh_brute_force at high/critical
bash ssh_bruteforce.sh 10.0.0.10

# Port scan — triggers port_scan at medium/high
bash port_scan.sh 10.0.0.10

# Traffic flood — triggers ddos at medium/high
bash traffic_flood.sh 10.0.0.10 30

# Correlation attack — recon then brute force from same IP
# triggers correlated_ssh_scan at critical
bash correlation_attack.sh 10.0.0.10
```

#### On the Jetson VM — run malware sim in parallel

```bash
sudo python3 tests/sim_malware.py --kill-after 60
```

#### On the Jetson VM — verify everything

```bash
python3 tests/verify.py all

tara-admin blocks
sudo iptables -L INPUT -n | grep DROP
```

---

### Full automated test (one command)

```bash
# Local only
sudo bash tests/run_all.sh

# With attacker VM
sudo bash tests/run_all.sh 10.0.0.20 10.0.0.10
```

---

### Expected verify output

```
TARA Defense — Verification Report
Audit log: /var/log/tara-defense/incidents.jsonl
Total incidents loaded: 31

───────────────────────────────────────────────────────
  SSH Brute Force Detection
───────────────────────────────────────────────────────
  [ PASS] At least one SSH incident detected              (found 3)
  [ PASS] High/critical confidence SSH incident detected  (found 2)
  [ PASS] Block action applied
  [ PASS] SSH config tightened

───────────────────────────────────────────────────────
  Port Scan / Recon Detection
───────────────────────────────────────────────────────
  [ PASS] At least one scan incident detected             (found 1)
  [ PASS] Confidence at least medium                      (best: high)
  [ PASS] Evidence contains distinct_ports

...

═══════════════════════════════════════════════════════
  Result: 14/14 checks passed
═══════════════════════════════════════════════════════
```

---

## Audit Log Format

Every detection, decision, and action is written to `/var/log/tara-defense/incidents.jsonl` as newline-delimited JSON:

```json
{
  "level": "INCIDENT",
  "ts": "2026-07-20T10:31:05.123456+00:00",
  "detector": "ssh",
  "threat": "ssh_brute_force",
  "asset": "jetson-tara",
  "source_ip": "10.0.0.20",
  "evidence": { "failed_attempts": 15, "window_secs": 60 },
  "confidence": "high",
  "recommended_action": "Hard block + tighten SSH + notify operator",
  "applied_action": "blocked:10.0.0.20:1800s, ssh_tightened, operator_notified",
  "notes": "",
  "dry_run": false
}
```

When AI analysis is enabled, a second record is appended for each qualifying incident:

```json
{
  "level": "INFO",
  "ts": "2026-07-20T10:31:08.451123+00:00",
  "tag": "tara_ai",
  "detail": "{\"source_ip\": \"10.0.0.20\", \"threat\": \"ssh_brute_force\", \"original_confidence\": \"high\", \"ai_confirmed\": true, \"ai_refined_confidence\": \"high\", \"ai_false_positive\": \"low\", \"ai_reasoning\": \"15 failed SSH attempts in 60 seconds from a single IP is a textbook brute-force pattern.\", \"ai_actions\": [\"maintain block\", \"notify operator\"], \"ai_operator_summary\": \"Confirmed brute-force attack from 10.0.0.20 — block is appropriate, no action needed.\"}"
}
```

Parse with:

```bash
# All incidents
grep '"level": "INCIDENT"' /var/log/tara-defense/incidents.jsonl | python3 -m json.tool

# AI analysis records only
grep '"tag": "tara_ai"' /var/log/tara-defense/incidents.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    rec = json.loads(line)
    ai = json.loads(rec['detail'])
    print(f\"{rec['ts']} [{ai['threat']}] confirmed={ai['ai_confirmed']} fp={ai['ai_false_positive']} — {ai['ai_operator_summary']}\"
)"

# By threat type
grep '"threat": "ssh_brute_force"' /var/log/tara-defense/incidents.jsonl

# Count by confidence
grep -o '"confidence": "[^"]*"' /var/log/tara-defense/incidents.jsonl | sort | uniq -c
```

---

## Dry Run Mode

Test detection and policy decisions without applying any iptables rules or router commands:

```bash
TARA_DRY_RUN=true sudo python3 coordinator.py
```

All actions are logged with `"dry_run": true` in the audit log. Safe to run in any environment.

---

## Signals

| Signal | Effect |
|---|---|
| `SIGTERM` / `SIGINT` | Graceful shutdown — saves state, removes PID file |
| `SIGHUP` | Reload config file live (no restart needed) |

```bash
tara-admin reload        # sends SIGHUP to daemon
sudo systemctl reload tara-defense   # same via systemd
```

---

## Safety Guarantees

- **Whitelist always wins** — IPs in the whitelist are never blocked, regardless of confidence
- **Idempotent rules** — `iptables -C` check prevents duplicate rules on restart
- **Auto-expiry** — all blocks are temporary and auto-removed; no permanent bans without operator action
- **Persistent state** — active blocks survive daemon restarts and are re-applied
- **Atomic saves** — state file written via tmp+rename; no corruption on crash
- **Router retry** — SSH commands to the router retry up to `router.retry_attempts` times
- **Memory pressure** — process detector (psutil) is skipped when free RAM drops below threshold
- **Per-detector error isolation** — one failing detector does not crash the coordinator

---

## License

MIT
