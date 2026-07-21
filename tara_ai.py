"""
AI-enhanced threat analysis using a local Ollama model.

Submits high/critical incidents to a locally-running LLM for second-opinion
analysis. Runs asynchronously in a background thread — never blocks the poll loop.
Writes results back to the audit log as INFO records tagged "tara_ai".

The rule-based system (tara_policy + responder) acts immediately and always.
The LLM's analysis is advisory: it confirms or challenges the confidence rating,
flags likely false positives, and generates operator-friendly summaries.

Requirements:
  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh
  2. Pull a model:   ollama pull llama3.2:3b
  3. Start server:   ollama serve   (or it auto-starts as a service)
  4. Set in YAML:    ai.enabled: true

Ollama runs on port 11434 by default and uses the Jetson GPU automatically.
Falls back silently if Ollama is not running or the model is unavailable.
"""

import json
import re
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import audit
import config
from detectors.base import DetectorEvent

# ── Rate-limit state ──────────────────────────────────────────────────────────

_cooldown: dict[tuple, float] = {}
_cooldown_lock = threading.Lock()

# 2 workers — keeps GPU load predictable on Jetson
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

TARA runs on NVIDIA Jetson (Ubuntu/JetPack) and monitors SSH brute force, DDoS/traffic floods, port scans, and malware.
Analyze security incidents and return a refined threat assessment.

Respond with a single JSON object only — no markdown, no code fences, no explanation outside the JSON:

{
  "threat_confirmed": true,
  "refined_confidence": "high",
  "false_positive_likelihood": "low",
  "reasoning": "One or two sentences explaining your assessment.",
  "recommended_actions": ["block IP at router", "notify operator"],
  "operator_summary": "Human-readable alert for the security operator."
}

Valid values:
  refined_confidence: low | medium | high | critical
  false_positive_likelihood: low | medium | high

Analysis guidelines:
- SSH brute force: dozens of failures in 60 s from one IP = confirmed; 1-3 failures = noise
- Port scan: 25+ distinct ports contacted = recon; <5 ports = likely legitimate
- DDoS: byte rate 2-5x above baseline = attack; moderate spikes may be legitimate
- Malware: known tool name (ncat/xmrig/hydra) = high confidence; many conns alone = medium
- Correlated multi-detector events almost always mean a sophisticated attacker
- Private-range source IPs (10.x, 192.168.x, 172.16-31.x) = insider threat or compromised device
- Lower confidence and raise false_positive_likelihood if evidence is thin
"""


# ── Qualification check ───────────────────────────────────────────────────────

_HIGH_VALUE_CONFIDENCE = {"high", "critical"}
_CORRELATED_THREATS = {
    "correlated_ssh_scan",
    "correlated_ddos_scan",
    "correlated_malware_net",
}


def _qualifies(event: DetectorEvent) -> bool:
    if not config.AI_ENABLED:
        return False
    if (event.confidence not in _HIGH_VALUE_CONFIDENCE
            and event.threat not in _CORRELATED_THREATS):
        return False
    key = (event.source_ip or "none", event.threat)
    now = time.monotonic()
    with _cooldown_lock:
        if now - _cooldown.get(key, 0.0) < config.AI_COOLDOWN_SECS:
            return False
        _cooldown[key] = now
    return True


# ── Ollama REST call ──────────────────────────────────────────────────────────

def _call_ollama(event: DetectorEvent) -> Optional[AIAnalysis]:
    """
    POST to Ollama's /api/chat endpoint.
    Uses only stdlib (urllib) — no extra package required.
    """
    payload = {
        "detector":    event.detector,
        "threat_type": event.threat,
        "source_ip":   event.source_ip,
        "confidence":  event.confidence,
        "evidence":    event.evidence,
        "notes":       event.notes,
    }

    body = json.dumps({
        "model":  config.AI_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Analyze this TARA security incident:\n\n"
                    + json.dumps(payload, indent=2)
                ),
            },
        ],
    }).encode()

    url = config.AI_OLLAMA_HOST.rstrip("/") + "/api/chat"
    req = urllib.request.Request(
        url,
        data    = body,
        method  = "POST",
        headers = {"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=config.AI_TIMEOUT_SECS) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        audit.warn("tara_ai", f"Ollama unreachable at {url}: {e.reason} — is 'ollama serve' running?")
        return None
    except TimeoutError:
        audit.warn("tara_ai", f"Ollama timed out after {config.AI_TIMEOUT_SECS}s")
        return None
    except json.JSONDecodeError as e:
        audit.warn("tara_ai", f"Ollama returned non-JSON: {e}")
        return None
    except Exception as e:
        audit.warn("tara_ai", f"Unexpected error calling Ollama: {type(e).__name__}: {e}")
        return None

    # Ollama chat response shape: {"message": {"content": "..."}, ...}
    text = data.get("message", {}).get("content", "")
    if not text:
        audit.warn("tara_ai", "Ollama returned empty content")
        return None

    # Strip accidental code fences from smaller models
    m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if m:
        text = m.group(1)

    # Some models wrap in extra prose — find the JSON object
    m = re.search(r"\{[\s\S]+\}", text)
    if m:
        text = m.group(0)

    try:
        result = json.loads(text.strip())
    except json.JSONDecodeError as e:
        audit.warn("tara_ai", f"Could not parse model JSON: {e} — raw: {text[:200]}")
        return None

    valid_conf = {"low", "medium", "high", "critical"}
    valid_fp   = {"low", "medium", "high"}

    rc = result.get("refined_confidence", event.confidence)
    fp = result.get("false_positive_likelihood", "low")

    return AIAnalysis(
        threat_confirmed          = bool(result.get("threat_confirmed", True)),
        refined_confidence        = rc if rc in valid_conf else event.confidence,
        false_positive_likelihood = fp if fp in valid_fp   else "low",
        reasoning                 = str(result.get("reasoning", "")),
        recommended_actions       = list(result.get("recommended_actions", [])),
        operator_summary          = str(result.get("operator_summary", "")),
    )


# ── Background worker ─────────────────────────────────────────────────────────

def _analyze_and_log(event: DetectorEvent) -> None:
    result = _call_ollama(event)
    if result is None:
        return

    audit.info("tara_ai", json.dumps({
        "source_ip":             event.source_ip,
        "threat":                event.threat,
        "original_confidence":   event.confidence,
        "ai_confirmed":          result.threat_confirmed,
        "ai_refined_confidence": result.refined_confidence,
        "ai_false_positive":     result.false_positive_likelihood,
        "ai_reasoning":          result.reasoning,
        "ai_actions":            result.recommended_actions,
        "ai_operator_summary":   result.operator_summary,
        "model":                 config.AI_MODEL,
    }))


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_async(event: DetectorEvent) -> None:
    """
    Submit event for local AI analysis. Returns immediately.
    Silently skips if AI is disabled, cooldown active, or confidence too low.
    """
    if not _qualifies(event):
        return
    _get_executor().submit(_analyze_and_log, event)
