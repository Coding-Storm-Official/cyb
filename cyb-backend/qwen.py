from __future__ import annotations
"""
qwen.py — Local Qwen 2.5 integration via Ollama
------------------------------------------------
Qwen runs locally via: ollama run qwen2.5
Default endpoint    : http://localhost:11434
"""
import os
import json
import logging
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger("xdr.qwen")

QWEN_HOST  = os.getenv("QWEN_HOST", "http://localhost:11434")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen2.5")          # or qwen2.5:7b / qwen2.5:14b
QWEN_TIMEOUT = int(os.getenv("QWEN_TIMEOUT", "60"))

# ── System prompt that turns Qwen into a SOC analyst ──────────────────────────
_SYSTEM_PROMPT = """You are an elite SOC (Security Operations Center) analyst AI.
You receive structured threat data from an XDR (Extended Detection and Response) 
platform that monitors endpoints, network flows, and Splunk SIEM telemetry.

Your job:
1. Analyse the threat data and write a concise executive-level security brief.
2. Map the attack chain to MITRE ATT&CK tactics.
3. Predict the NEXT most likely attacker move based on current stage.
4. Generate ONE targeted Splunk SPL query (in ```spl ... ``` fences) that will 
   hunt for hidden indicators NOT yet detected by the existing rules.
5. Recommend precise containment actions.

Be direct, technical, and concise. Use bullet points only where helpful.
Never hallucinate IOC values. If unsure, say so.
"""

# ── Core call ─────────────────────────────────────────────────────────────────

def _call_ollama(prompt: str, system: str = _SYSTEM_PROMPT) -> str:
    """Send a prompt to the local Ollama /api/chat endpoint and return the reply."""
    payload = {
        "model":  QWEN_MODEL,
        "stream": False,
        "messages": [
            {"role": "system",  "content": system},
            {"role": "user",    "content": prompt},
        ],
        "options": {
            "temperature": 0.2,   # low for security analysis — we want precision
            "top_p": 0.9,
        },
    }
    try:
        resp = requests.post(
            f"{QWEN_HOST}/api/chat",
            json=payload,
            timeout=QWEN_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()
    except requests.exceptions.ConnectionError:
        logger.error("[Qwen] Ollama not running. Start it: ollama run qwen2.5")
        return "[Qwen offline — start Ollama: ollama run qwen2.5]"
    except Exception as exc:
        logger.error(f"[Qwen] Call failed: {exc}")
        return f"[Qwen error: {exc}]"


# ── Public helpers ────────────────────────────────────────────────────────────

def analyze_threat(alert: Dict[str, Any]) -> Dict[str, str]:
    """
    Takes an alert dict (same shape as Alert.dump() in ml.py) and returns a
    dict with keys:
        executive_brief  — plain-English summary for the dashboard
        spl_hunt_query   — new SPL query Qwen generated for the feedback loop
        next_action      — recommended containment steps
        raw_response     — full Qwen output (for debugging)
    """
    prompt = _build_alert_prompt(alert)
    raw    = _call_ollama(prompt)
    return {
        "executive_brief": _extract_section(raw, stop_markers=["```spl", "## SPL", "### SPL"]),
        "spl_hunt_query":  _extract_spl(raw),
        "next_action":     _extract_section(raw, start_marker="Containment", fallback="See full response."),
        "raw_response":    raw,
    }


def analyze_risk_context(risk: Dict[str, Any]) -> str:
    """
    Lightweight call — takes a risk_engine result dict and returns a short
    natural-language paragraph suitable for the AI feed.
    """
    prompt = (
        f"Risk score: {risk.get('score')}/100  Threat: {risk.get('threat_level')}\n"
        f"MITRE: {', '.join(risk.get('mitre_ids', []))}\n"
        f"Triggered rules:\n" +
        "\n".join(f"  - {r}" for r in risk.get("triggered_rules", [])) +
        "\n\nIn 3 sentences, explain what is happening and what the analyst should do first."
    )
    return _call_ollama(prompt)


def generate_hunt_query(mitre_ids: List[str], behavior_tags: List[str]) -> str:
    """
    Ask Qwen to generate a brand-new SPL hunt query based on the MITRE
    techniques and behavior tags already observed. Used for the feedback loop.
    """
    prompt = (
        f"The following MITRE ATT&CK techniques have been detected: {', '.join(mitre_ids)}.\n"
        f"Behavior tags: {', '.join(behavior_tags)}.\n\n"
        "Generate ONE advanced Splunk SPL query (using sourcetype=WinEventLog:Security "
        "or sourcetype=sysmon) that will uncover HIDDEN lateral movement or persistence "
        "artifacts not yet captured by basic event-code searches. "
        "Wrap the SPL in ```spl ... ``` fences. No explanation needed."
    )
    raw = _call_ollama(prompt)
    return _extract_spl(raw) or raw


def ping() -> bool:
    """Return True if Ollama is reachable and the model is available."""
    try:
        r = requests.get(f"{QWEN_HOST}/api/tags", timeout=5)
        tags = r.json().get("models", [])
        return any(QWEN_MODEL in m.get("name", "") for m in tags)
    except Exception:
        return False


# ── Private helpers ───────────────────────────────────────────────────────────

def _build_alert_prompt(alert: Dict[str, Any]) -> str:
    mitre_lines = "\n".join(f"  - {m}" for m in alert.get("mitre", []))
    rules_lines = "\n".join(f"  - {r}" for r in alert.get("rules", []))
    tags_lines  = "\n".join(f"  - {t}" for t in alert.get("behavior_tags", []))
    ioc_lines   = "\n".join(f"  - {i}" for i in alert.get("iocs", []))
    actions     = ", ".join(alert.get("actions", []))

    # Here is the update: Check if main.py passed Splunk AI insights along
    splunk_context = alert.get("splunk_ai_context", "")
    if splunk_context:
        prompt_suffix = f"\nSplunk AI Instruct Context:\n{splunk_context}\n"
    else:
        prompt_suffix = ""

    return f"""
=== XDR ALERT ===
Incident ID  : {alert.get('incident_id', 'N/A')}
Host         : {alert.get('host_id', 'unknown')}
User         : {alert.get('user_id', 'unknown')}
Risk Score   : {alert.get('score', 0):.1f}/100
Threat Level : {alert.get('threat', 'UNKNOWN')}
Next Stage   : {alert.get('next_stage', 'Unknown')}  (confidence {alert.get('confidence', 0):.1%})
Integrity Jump: {alert.get('integrity_jump', False)}

MITRE Techniques:
{mitre_lines or '  None'}

Triggered Rules:
{rules_lines or '  None'}

Behavior Tags:
{tags_lines or '  None'}

IOC Matches:
{ioc_lines or '  None'}

Auto-Actions Deployed:
  {actions or 'None'}

================={prompt_suffix}

Tasks:
1. Write an executive brief (3-5 sentences) explaining what the attacker has done and the business impact.
2. Predict the attacker's next move.
3. Generate ONE targeted SPL query to hunt for hidden artefacts (wrap in ```spl ... ``` fences).
4. List 3 immediate containment steps under a "Containment:" header.
"""


def _extract_spl(text: str) -> str:
    """Pull the first ```spl ... ``` block from Qwen's response."""
    import re
    m = re.search(r"```spl\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # fallback: look for a raw search command
    m2 = re.search(r"(search\s+earliest.*?)\n", text, re.IGNORECASE)
    if m2:
        return m2.group(1).strip()
    return ""


def _extract_section(text: str, start_marker: str = "", stop_markers: List[str] = None, fallback: str = "") -> str:
    """Return text from start_marker until one of stop_markers (or end)."""
    if not start_marker:
        # return everything up to the first stop marker
        out = text
        for sm in (stop_markers or []):
            idx = out.find(sm)
            if idx != -1:
                out = out[:idx]
        return out.strip()

    idx = text.lower().find(start_marker.lower())
    if idx == -1:
        return fallback
    section = text[idx:]
    for sm in (stop_markers or []):
        end = section.find(sm)
        end = section.find(sm)
        if end != -1:
            section = section[:end]
    return section.strip()