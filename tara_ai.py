"""
AI-enhanced threat analysis using Claude.

Submits high/critical incidents to Claude for a second-opinion analysis.
Runs asynchronously in a background thread — never blocks the poll loop.
Writes results back to the audit log as INFO records tagged "tara_ai".

The rule-based system (tara_policy + responder) acts immediately and always.
Claude's analysis is advisory: it confirms or challenges the confidence rating,
flags likely false positives, and generates operator-friendly summaries.

Activation: set ai.enabled: true in tara-defense.yaml and export ANTHROPIC_API_KEY.
Falls back silently if the API is unreachable or the SDK is not installed.
"""

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import audit
import config
from detectors.base import DetectorEvent

# ── Rate-limit state ──────────────────────────────────────────────────────────

_cooldown: dict[tuple, float] = {}
_cooldown_lock = threading.Lock()

# Thread pool: 2 workers keeps parallelism low on resource-constrained Jetson
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None or _executor._shutdown:
            _executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tara-ai")
        return _executor


# ── Analysis result ───────────────────────────────────────────────────────────

@dataclass
class AIAnalysis:
    threat_confirmed:          bool
    refined_confidence:        str   # low | medium | high | critical
    false_positive_likelihood: str   # low | medium | high
    reasoning:                 str
    recommended_actions:       list[str]
    operator_summary:          str


# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are TARA's AI security analyst — an expert in edge cybersecurity for autonomous humanoid robots.

TARA runs on NVIDIA Jetson (Ubuntu/JetPack) and is connected to a router via SSH.
The defense daemon monitors SSH brute force, DDoS/traffic floods, port scans, and malware.
Your task: analyze a structured incident report and return a refined threat assessment.

Respond with a single JSON object — no markdown, no code fences, no other text:

{
  "threat_confirmed": true,
  "refined_confidence": "high",
  "false_positive_likelihood": "low",
  "reasoning": "1-2 sentences explaining your assessment.",
  "recommended_actions": ["block IP at router", "notify operator"],
  "operator_summary": "Human-readable alert for the security operator."
}

Valid values:
  refined_confidence: low | medium | high | critical
  false_positive_likelihood: low | medium | high

Analysis guidelines:
- SSH brute force: dozens of failures in 60 s from one IP = confirmed; 1-3 failures = noise
- Port scan: 25+ distinct ports contacted = recon; <5 ports = could be legitimate service probes
- DDoS: byte rate 2-5x above normal = attack; moderate spike during business hours = investigate
- Malware: known C2 tool name (ncat/xmrig) = high confidence; many outbound conns alone = medium
- Correlated multi-detector events (ssh_scan, ddos_scan, malware_net) almost always indicate a
  sophisticated attacker — treat them as critical unless the evidence is unusually thin
- Private-range source IPs (10.x, 192.168.x, 172.16-31.x) = insider threat or compromised LAN device
- If you suspect a false positive, lower refined_confidence and raise false_positive_likelihood
"""


# ── Qualification check ───────────────────────────────────────────────────────

_HIGH_VALUE_CONFIDENCE = {"high", "critical"}
_CORRELATED_THREATS = {
    "correlated_ssh_scan",
    "correlated_ddos_scan",
    "correlated_malware_net",
}


def _qualifies(event: DetectorEvent) -> bool:
    """Return True if this event should be sent to Claude for analysis."""
    if not config.AI_ENABLED:
        return False
    if (event.confidence not in _HIGH_VALUE_CONFIDENCE
            and event.threat not in _CORRELATED_THREATS):
        return False
    # Per-(ip, threat) cooldown prevents hammering the API on the same incident
    key = (event.source_ip or "none", event.threat)
    now = time.monotonic()
    with _cooldown_lock:
        if now - _cooldown.get(key, 0.0) < config.AI_COOLDOWN_SECS:
            return False
        _cooldown[key] = now
    return True


# ── API call ──────────────────────────────────────────────────────────────────

def _call_claude(event: DetectorEvent) -> Optional[AIAnalysis]:
    """Synchronous Claude API call. Runs inside a background thread."""
    try:
        import anthropic  # lazy import — not required if AI is disabled
    except ImportError:
        audit.warn("tara_ai", "anthropic SDK not installed — run: pip install anthropic")
        return None

    payload = {
        "detector":         event.detector,
        "threat_type":      event.threat,
        "source_ip":        event.source_ip,
        "confidence":       event.confidence,
        "evidence":         event.evidence,
        "notes":            event.notes,
    }

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model      = config.AI_MODEL,
            max_tokens = config.AI_MAX_TOKENS,
            system     = _SYSTEM_PROMPT,
            messages   = [{
                "role":    "user",
                "content": (
                    "Analyze this security incident on TARA humanoid robot:\n\n"
                    + json.dumps(payload, indent=2)
                ),
            }],
        )
    except anthropic.APIConnectionError as e:
        audit.warn("tara_ai", f"API unreachable: {e}")
        return None
    except anthropic.RateLimitError:
        audit.warn("tara_ai", "Claude API rate limited — skipping analysis")
        return None
    except anthropic.APIStatusError as e:
        audit.warn("tara_ai", f"Claude API error {e.status_code}: {e.message}")
        return None
    except Exception as e:
        audit.warn("tara_ai", f"Unexpected error: {type(e).__name__}: {e}")
        return None

    # Extract text, strip any accidental code fences
    text = next((b.text for b in response.content if b.type == "text"), "")
    m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if m:
        text = m.group(1)

    try:
        data = json.loads(text.strip())
    except json.JSONDecodeError as e:
        audit.warn("tara_ai", f"Claude returned non-JSON response: {e} — raw: {text[:200]}")
        return None

    valid_conf = {"low", "medium", "high", "critical"}
    valid_fp   = {"low", "medium", "high"}

    return AIAnalysis(
        threat_confirmed          = bool(data.get("threat_confirmed", True)),
        refined_confidence        = data.get("refined_confidence", event.confidence)
                                    if data.get("refined_confidence") in valid_conf
                                    else event.confidence,
        false_positive_likelihood = data.get("false_positive_likelihood", "low")
                                    if data.get("false_positive_likelihood") in valid_fp
                                    else "low",
        reasoning                 = str(data.get("reasoning", "")),
        recommended_actions       = list(data.get("recommended_actions", [])),
        operator_summary          = str(data.get("operator_summary", "")),
    )


# ── Background worker ─────────────────────────────────────────────────────────

def _analyze_and_log(event: DetectorEvent) -> None:
    """Called in a background thread. Analyzes the event and writes to audit log."""
    result = _call_claude(event)
    if result is None:
        return

    audit.info("tara_ai", json.dumps({
        "source_ip":               event.source_ip,
        "threat":                  event.threat,
        "original_confidence":     event.confidence,
        "ai_confirmed":            result.threat_confirmed,
        "ai_refined_confidence":   result.refined_confidence,
        "ai_false_positive":       result.false_positive_likelihood,
        "ai_reasoning":            result.reasoning,
        "ai_actions":              result.recommended_actions,
        "ai_operator_summary":     result.operator_summary,
    }))


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_async(event: DetectorEvent) -> None:
    """
    Submit event for AI analysis. Returns immediately — analysis runs in background.
    Silently skips if AI is disabled, cooldown is active, or confidence is too low.
    """
    if not _qualifies(event):
        return
    _get_executor().submit(_analyze_and_log, event)
