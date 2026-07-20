# TARA Defense — VM Test Suite

## Setup

```
[ Attacker VM ]  ←── same subnet ──→  [ Jetson VM (defender) ]
  10.0.0.20                              10.0.0.10
```

### On Jetson VM (defender)
```bash
# Install and start the daemon in dry-run mode first
TARA_DRY_RUN=true python3 coordinator.py

# Or install fully
sudo bash install.sh
```

### On Attacker VM
```bash
sudo apt install nmap hping3 hydra iperf3 -y
```

---

## Test Execution Order

| # | Test | Script (attacker VM) | Verifier |
|---|------|----------------------|----------|
| 1 | SSH brute force | `attacker/ssh_bruteforce.sh <target>` | `python3 verify.py ssh` |
| 2 | Port scan | `attacker/port_scan.sh <target>` | `python3 verify.py scan` |
| 3 | Traffic flood | `attacker/traffic_flood.sh <target>` | `python3 verify.py ddos` |
| 4 | Malware process | run on Jetson VM: `python3 sim_malware.py` | `python3 verify.py malware` |
| 5 | Correlation (SSH+scan) | run 1 then 2 from same IP | `python3 verify.py correlation` |
| 6 | Full suite | `bash run_all.sh <attacker_ip> <target_ip>` | auto |

---

## Quick local test (no attacker VM needed)
```bash
# Inject fake events directly — safe, no real network attacks
python3 tests/inject_all.py
python3 tests/verify.py all
```
