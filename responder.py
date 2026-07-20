"""
Responder — executes mitigations.
Local: iptables rules on the Jetson.
Remote: SSH commands pushed to the router.
All blocks are temporary and tracked for automatic expiry.
"""

import subprocess
import time
from dataclasses import dataclass

import audit
import config


@dataclass
class _ActiveBlock:
    ip: str
    expires_at: float
    scope: str  # "local" | "router"


_blocks: list[_ActiveBlock] = []
_ssh_tightened: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], tag: str) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        audit.action(tag, " ".join(cmd))
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        audit.warn(tag, f"command failed: {e}")
        return False


def _router_cmd(cmd: str) -> bool:
    ssh = [
        "ssh",
        "-i", config.ROUTER_SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        f"{config.ROUTER_USER}@{config.ROUTER_HOST}",
        cmd,
    ]
    return _run(ssh, "router_cmd")


# ---------------------------------------------------------------------------
# Public action functions (called by coordinator via tara_policy parse)
# ---------------------------------------------------------------------------

def block_ip_local(ip: str, duration: int) -> None:
    _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], "iptables_block")
    _blocks.append(_ActiveBlock(ip=ip, expires_at=time.time() + duration, scope="local"))


def unblock_ip_local(ip: str) -> None:
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], "iptables_unblock")


def block_ip_router(ip: str, duration: int) -> None:
    _router_cmd(f"iptables -I INPUT -s {ip} -j DROP")
    _blocks.append(_ActiveBlock(ip=ip, expires_at=time.time() + duration, scope="router"))


def unblock_ip_router(ip: str) -> None:
    _router_cmd(f"iptables -D INPUT -s {ip} -j DROP")


def router_rate_limit(ip: str) -> None:
    _router_cmd(
        f"iptables -I INPUT -s {ip} -m limit --limit 10/min --limit-burst 20 -j ACCEPT && "
        f"iptables -I INPUT -s {ip} -j DROP"
    )
    audit.action("router_rate_limit", f"Applied rate limit for {ip}")


def tighten_ssh() -> None:
    global _ssh_tightened
    if _ssh_tightened:
        return
    # Allow only 2 auth attempts, 30s login grace
    _run(
        ["sed", "-i",
         "s/^#\\?MaxAuthTries.*/MaxAuthTries 2/; s/^#\\?LoginGraceTime.*/LoginGraceTime 30/",
         "/etc/ssh/sshd_config"],
        "tighten_ssh_config",
    )
    _run(["systemctl", "reload", "sshd"], "reload_sshd")
    _ssh_tightened = True


def isolate_process(pid: int) -> None:
    _run(["kill", "-STOP", str(pid)], "isolate_process")
    audit.action("isolate_process", f"SIGSTOP sent to pid {pid} — awaiting operator review")


def notify_operator(message: str) -> None:
    # Writes a prominent line to stderr / audit log.
    # Replace with your preferred channel (MQTT, email, webhook).
    audit.warn("OPERATOR_NOTIFY", message)


def increase_monitoring() -> None:
    audit.info("monitoring", "Increased monitoring mode active (scan alert)")


# ---------------------------------------------------------------------------
# Action dispatcher — called by coordinator with tara_policy action strings
# ---------------------------------------------------------------------------

def dispatch(actions: list[str], source_ip: str | None, pid: int | None, threat: str) -> list[str]:
    applied: list[str] = []

    for act in actions:
        act = act.strip()

        if act == "log_only":
            applied.append("log_only")

        elif act == "block_soft" and source_ip:
            block_ip_local(source_ip, config.BLOCK_SOFT)
            block_ip_router(source_ip, config.BLOCK_SOFT)
            applied.append(f"blocked {source_ip} for {config.BLOCK_SOFT}s")

        elif act == "block_hard" and source_ip:
            block_ip_local(source_ip, config.BLOCK_HARD)
            block_ip_router(source_ip, config.BLOCK_HARD)
            applied.append(f"blocked {source_ip} for {config.BLOCK_HARD}s")

        elif act == "block_crit" and source_ip:
            block_ip_local(source_ip, config.BLOCK_CRIT)
            block_ip_router(source_ip, config.BLOCK_CRIT)
            applied.append(f"blocked {source_ip} for {config.BLOCK_CRIT}s")

        elif act == "router_rate_limit" and source_ip:
            router_rate_limit(source_ip)
            applied.append(f"router rate-limited {source_ip}")

        elif act == "router_block_crit" and source_ip:
            block_ip_router(source_ip, config.BLOCK_CRIT)
            applied.append(f"router blocked {source_ip} for {config.BLOCK_CRIT}s")

        elif act == "tighten_ssh":
            tighten_ssh()
            applied.append("ssh_tightened")

        elif act == "isolate_process" and pid:
            isolate_process(pid)
            applied.append(f"isolated pid {pid}")

        elif act == "alert_operator":
            notify_operator(f"Medium-confidence {threat} detected — review recommended")
            applied.append("operator_alerted")

        elif act == "notify":
            notify_operator(f"High-confidence {threat} — action taken: {', '.join(applied)}")
            applied.append("operator_notified")

        elif act == "increase_monitoring":
            increase_monitoring()
            applied.append("monitoring_increased")

    return applied


# ---------------------------------------------------------------------------
# Expiry cleanup — call once per poll cycle
# ---------------------------------------------------------------------------

def expire_blocks() -> None:
    now = time.time()
    expired = [b for b in _blocks if b.expires_at <= now]
    for b in expired:
        if b.scope == "local":
            unblock_ip_local(b.ip)
        else:
            unblock_ip_router(b.ip)
        audit.action("block_expired", f"Auto-unblocked {b.ip} (scope={b.scope})")
    for b in expired:
        _blocks.remove(b)
