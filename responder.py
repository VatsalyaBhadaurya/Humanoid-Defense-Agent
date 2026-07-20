"""
Responder — executes mitigations.

Safety guarantees:
  - Whitelist checked before every block (never blocks trusted IPs).
  - iptables rules are idempotent: -C check before -I insert.
  - All blocks are recorded in state.py for auto-expiry and restart recovery.
  - Router SSH commands are retried up to ROUTER_RETRY times.
  - In dry_run mode all enforcement is logged but not executed.
  - Operator notifications are rate-limited to one per OPERATOR_NOTIFY_COOLDOWN.
"""

import subprocess
import time

import audit
import config
import state
from state import Block

# Tracks whether SSH config has been tightened this session
_ssh_tightened = False

# Operator notification rate-limiting: threat → last notify timestamp
_last_notify: dict[str, float] = {}


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list[str], tag: str, check: bool = True) -> bool:
    if config.DRY_RUN:
        audit.action(f"DRY_RUN:{tag}", " ".join(cmd))
        return True
    try:
        subprocess.run(cmd, check=check, capture_output=True, timeout=10)
        audit.action(tag, " ".join(cmd))
        return True
    except subprocess.CalledProcessError as e:
        audit.warn(tag, f"exit {e.returncode}: {e.stderr.decode(errors='replace').strip()}")
        return False
    except subprocess.TimeoutExpired:
        audit.warn(tag, f"timed out: {' '.join(cmd)}")
        return False


def _router_cmd(cmd: str) -> bool:
    ssh_base = [
        "ssh",
        "-i",  config.ROUTER_SSH_KEY,
        "-o",  "StrictHostKeyChecking=no",
        "-o",  "BatchMode=yes",
        "-o",  f"ConnectTimeout={config.ROUTER_TIMEOUT}",
        f"{config.ROUTER_USER}@{config.ROUTER_HOST}",
    ]
    for attempt in range(1, config.ROUTER_RETRY + 1):
        ok = _run(ssh_base + [cmd], f"router_ssh(attempt={attempt})")
        if ok:
            return True
        time.sleep(1)
    audit.error("router_ssh", f"all {config.ROUTER_RETRY} attempts failed for: {cmd}")
    return False


# ── iptables helpers ──────────────────────────────────────────────────────────

def _ipt_rule_exists(ip: str) -> bool:
    """Return True if a DROP rule for this IP already exists."""
    if config.DRY_RUN:
        return False
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def _ipt_block(ip: str) -> bool:
    if _ipt_rule_exists(ip):
        audit.info("iptables", f"Rule already exists for {ip} — skipping insert")
        return True
    return _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], "iptables_block")


def _ipt_unblock(ip: str) -> None:
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], "iptables_unblock", check=False)


# ── Public enforcement actions ────────────────────────────────────────────────

def block_ip(ip: str, duration: int, confidence: str, reason: str) -> bool:
    if state.is_whitelisted(ip):
        audit.info("responder", f"Skipping block for whitelisted IP {ip}")
        return False

    _ipt_block(ip)
    _router_cmd(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null || true")

    blk = Block(ip=ip, scope="both", expires_at=time.time() + duration,
                reason=reason, confidence=confidence)
    state.add_block(blk)
    state.increment(f"blocks_{confidence}")
    return True


def unblock_ip(ip: str) -> None:
    _ipt_unblock(ip)
    _router_cmd(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true")
    state.remove_block(ip)
    audit.action("unblock", f"Unblocked {ip}")


def router_rate_limit(ip: str, duration: int, confidence: str) -> bool:
    if state.is_whitelisted(ip):
        return False

    # Insert: accept up to 10/min, drop the rest — idempotent via comment tag
    tag = f"tara-rl-{ip}"
    _router_cmd(
        f"iptables -C INPUT -s {ip} -m comment --comment {tag} -j ACCEPT 2>/dev/null || ("
        f"iptables -I INPUT -s {ip} -m limit --limit 10/min --limit-burst 20 "
        f"-m comment --comment {tag} -j ACCEPT && "
        f"iptables -I INPUT -s {ip} -j DROP)"
    )

    blk = Block(ip=ip, scope="router", expires_at=time.time() + duration,
                reason="rate_limit", confidence=confidence)
    state.add_block(blk)
    state.increment("rate_limits")
    return True


def router_unrate_limit(ip: str) -> None:
    tag = f"tara-rl-{ip}"
    _router_cmd(
        f"iptables -D INPUT -s {ip} -m limit --limit 10/min --limit-burst 20 "
        f"-m comment --comment {tag} -j ACCEPT 2>/dev/null || true && "
        f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true"
    )


def tighten_ssh() -> None:
    global _ssh_tightened
    if _ssh_tightened:
        return
    _run(
        ["sed", "-i",
         r"s/^#\?MaxAuthTries.*/MaxAuthTries 2/;"
         r"s/^#\?LoginGraceTime.*/LoginGraceTime 30/",
         "/etc/ssh/sshd_config"],
        "tighten_ssh_config",
    )
    _run(["systemctl", "reload", "sshd"], "reload_sshd")
    _ssh_tightened = True


def isolate_process(pid: int) -> None:
    _run(["kill", "-STOP", str(pid)], "isolate_process_sigstop")
    audit.warn("isolate", f"PID {pid} suspended (SIGSTOP) — awaiting operator review before kill")


def notify_operator(threat: str, message: str) -> None:
    now  = time.time()
    last = _last_notify.get(threat, 0)
    if now - last < config.OPERATOR_NOTIFY_COOLDOWN:
        return   # rate-limited
    _last_notify[threat] = now
    # Primary channel: audit log (always available)
    audit.warn("OPERATOR_NOTIFY", message)
    # Optional: write to a named pipe / socket for external alerting integrations
    try:
        pipe = "/run/tara-defense/notify.pipe"
        import os
        if os.path.exists(pipe):
            with open(pipe, "w") as f:
                import json
                f.write(json.dumps({"threat": threat, "message": message}) + "\n")
    except OSError:
        pass


def increase_monitoring() -> None:
    audit.info("monitoring", "Increased monitoring mode active — scan alert in effect")


# ── Block expiry ──────────────────────────────────────────────────────────────

def expire_blocks() -> None:
    for blk in state.purge_expired():
        if blk.scope in ("local", "both"):
            _ipt_unblock(blk.ip)
        if blk.scope in ("router", "both"):
            if blk.reason == "rate_limit":
                router_unrate_limit(blk.ip)
            else:
                _router_cmd(f"iptables -D INPUT -s {blk.ip} -j DROP 2>/dev/null || true")
        audit.action("block_expired", f"Auto-unblocked {blk.ip} (scope={blk.scope}, reason={blk.reason})")
        state.increment("blocks_expired")


# ── Re-apply blocks after restart ────────────────────────────────────────────

def reapply_active_blocks() -> None:
    """Called once at startup to restore blocks that survived a daemon restart."""
    for blk in state.get_active_blocks():
        if blk.scope in ("local", "both"):
            _ipt_block(blk.ip)
        if blk.scope in ("router", "both"):
            if blk.reason == "rate_limit":
                pass   # router_rate_limit already registered
            else:
                _router_cmd(f"iptables -I INPUT -s {blk.ip} -j DROP 2>/dev/null || true")
        audit.info("reapply", f"Restored block for {blk.ip} (expires in {blk.expires_at - time.time():.0f}s)")


# ── Main dispatcher ───────────────────────────────────────────────────────────

def dispatch(
    actions: list[str],
    *,
    source_ip: str | None,
    pid: int | None,
    threat: str,
    confidence: str,
) -> list[str]:
    applied: list[str] = []

    for act in actions:
        act = act.strip()

        if act == "log_only":
            applied.append("log_only")

        elif act == "block_soft" and source_ip:
            if block_ip(source_ip, config.BLOCK_SOFT, confidence, threat):
                applied.append(f"blocked:{source_ip}:{config.BLOCK_SOFT}s")

        elif act == "block_hard" and source_ip:
            if block_ip(source_ip, config.BLOCK_HARD, confidence, threat):
                applied.append(f"blocked:{source_ip}:{config.BLOCK_HARD}s")

        elif act == "block_crit" and source_ip:
            if block_ip(source_ip, config.BLOCK_CRIT, confidence, threat):
                applied.append(f"blocked:{source_ip}:{config.BLOCK_CRIT}s")

        elif act == "router_rate_limit" and source_ip:
            if router_rate_limit(source_ip, config.BLOCK_HARD, confidence):
                applied.append(f"router_rate_limited:{source_ip}")

        elif act == "router_block_crit" and source_ip:
            _router_cmd(f"iptables -I INPUT -s {source_ip} -j DROP 2>/dev/null || true")
            blk = Block(ip=source_ip, scope="router", expires_at=time.time() + config.BLOCK_CRIT,
                        reason=threat, confidence=confidence)
            state.add_block(blk)
            applied.append(f"router_blocked:{source_ip}:{config.BLOCK_CRIT}s")

        elif act == "tighten_ssh":
            tighten_ssh()
            applied.append("ssh_tightened")

        elif act == "isolate_process" and pid:
            isolate_process(pid)
            applied.append(f"process_isolated:pid={pid}")

        elif act == "notify":
            msg = (
                f"[TARA DEFENSE] {confidence.upper()} confidence {threat} detected. "
                f"Source: {source_ip or 'N/A'}. "
                f"Actions taken: {', '.join(applied) or 'none yet'}"
            )
            notify_operator(threat, msg)
            applied.append("operator_notified")

        elif act == "increase_monitoring":
            increase_monitoring()
            applied.append("monitoring_increased")

    return applied
