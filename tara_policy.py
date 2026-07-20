"""
TARA threat → mitigation policy table.
Maps (threat_type, confidence_level) → ordered list of action tokens.
All action tokens are consumed by responder.dispatch().
"""

from typing import NamedTuple


class Policy(NamedTuple):
    actions: list[str]
    description: str


# Confidence levels in ascending severity order
CONFIDENCE_LEVELS = ("low", "medium", "high", "critical")

_TABLE: dict[tuple[str, str], Policy] = {
    # ── SSH brute-force ───────────────────────────────────────────────────────
    ("ssh_brute_force", "low"):      Policy(["log_only"],                                     "Log and monitor"),
    ("ssh_brute_force", "medium"):   Policy(["block_soft", "tighten_ssh"],                    "Soft block + tighten SSH"),
    ("ssh_brute_force", "high"):     Policy(["block_hard", "tighten_ssh", "notify"],          "Hard block + tighten SSH + notify operator"),
    ("ssh_brute_force", "critical"): Policy(["block_crit", "tighten_ssh", "notify"],          "Critical block + tighten SSH + notify operator"),

    # ── DDoS / traffic flood ──────────────────────────────────────────────────
    ("ddos", "low"):      Policy(["log_only"],                                                 "Log and monitor"),
    ("ddos", "medium"):   Policy(["router_rate_limit"],                                        "Router rate-limit"),
    ("ddos", "high"):     Policy(["router_rate_limit", "notify"],                              "Router rate-limit + notify operator"),
    ("ddos", "critical"): Policy(["router_block_crit", "notify"],                             "Router drop + notify operator"),

    # ── Malware / suspicious process ──────────────────────────────────────────
    ("malware", "low"):      Policy(["log_only"],                                              "Log and monitor"),
    ("malware", "medium"):   Policy(["notify"],                                                "Alert operator for review"),
    ("malware", "high"):     Policy(["isolate_process", "notify"],                            "Isolate process + notify operator"),
    ("malware", "critical"): Policy(["isolate_process", "block_crit", "notify"],             "Isolate process + block source + notify operator"),

    # ── Port scan / recon ─────────────────────────────────────────────────────
    ("port_scan", "low"):      Policy(["log_only"],                                            "Log and monitor"),
    ("port_scan", "medium"):   Policy(["block_soft", "increase_monitoring"],                  "Soft block + increase monitoring"),
    ("port_scan", "high"):     Policy(["block_hard", "notify"],                               "Hard block + notify operator"),
    ("port_scan", "critical"): Policy(["block_crit", "notify"],                              "Critical block + notify operator"),

    # ── Multi-detector correlation (escalated events) ─────────────────────────
    ("correlated_ssh_scan", "critical"):    Policy(["block_crit", "tighten_ssh", "notify"], "Correlated SSH+scan — critical block"),
    ("correlated_ddos_scan", "critical"):   Policy(["router_block_crit", "block_crit", "notify"], "Correlated DDoS+scan — full block"),
    ("correlated_malware_net", "critical"): Policy(["isolate_process", "block_crit", "notify"], "Correlated malware+network — isolate + block"),
}


def lookup(threat: str, confidence: str) -> Policy:
    return _TABLE.get((threat, confidence), Policy(["log_only"], "No matching policy — log only"))
