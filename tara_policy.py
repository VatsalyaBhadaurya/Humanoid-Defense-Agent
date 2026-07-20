"""
Compact threat → mitigation policy table.
Keys: (threat_type, confidence_level)
Values: action identifier consumed by responder.py
"""

POLICY: dict[tuple[str, str], str] = {
    # SSH brute force
    ("ssh_brute_force", "low"):      "log_only",
    ("ssh_brute_force", "medium"):   "block_soft",
    ("ssh_brute_force", "high"):     "block_hard + tighten_ssh",
    ("ssh_brute_force", "critical"): "block_crit + tighten_ssh + notify",

    # DDoS / traffic flood
    ("ddos", "low"):      "log_only",
    ("ddos", "medium"):   "router_rate_limit",
    ("ddos", "high"):     "router_rate_limit + notify",
    ("ddos", "critical"): "router_block_crit + notify",

    # Malware / suspicious process
    ("malware", "low"):      "log_only",
    ("malware", "medium"):   "alert_operator",
    ("malware", "high"):     "isolate_process + notify",
    ("malware", "critical"): "isolate_process + block_crit + notify",

    # Port scan / recon
    ("port_scan", "low"):      "log_only",
    ("port_scan", "medium"):   "block_soft + increase_monitoring",
    ("port_scan", "high"):     "block_hard + notify",
    ("port_scan", "critical"): "block_crit + notify",
}


def lookup(threat: str, confidence: str) -> str:
    return POLICY.get((threat, confidence), "log_only")


def parse_actions(action_str: str) -> list[str]:
    return [a.strip() for a in action_str.split("+")]
