from __future__ import annotations
"""
splunk_ai.py — Splunk AI Instruct integration
Calls the /services/assistant/ask endpoint on your Splunk instance.
This is the "secondary brain" that gives Splunk-native context.
"""
import os
import logging
import requests
import urllib3
from typing import Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("xdr.splunk_ai")

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"


def _auth():
    if SPLUNK_TOKEN:
        return None, {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    return (SPLUNK_USERNAME, SPLUNK_PASSWORD), {}


def ask_splunk_ai(question: str) -> str:
    """
    Send a natural-language question to Splunk AI Instruct.
    Returns Splunk AI's response as a string.
    Falls back gracefully if endpoint is unavailable.
    """
    auth, headers = _auth()
    headers["Content-Type"] = "application/json"
    
    payload = {
        "output_mode": "json",
        "query": question
    }
    
    try:
        resp = requests.post(
            f"{BASE_URL}/services/assistant/ask",
            auth=auth,
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("answer", data.get("response", str(data)))
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # Splunk AI Instruct not available on this instance
            logger.warning("[SplunkAI] AI Instruct endpoint not found — using fallback.")
            return _fallback_analysis(question)
        logger.error(f"[SplunkAI] HTTP error: {e}")
        return f"[Splunk AI unavailable: {e}]"
    except Exception as e:
        logger.error(f"[SplunkAI] Error: {e}")
        return _fallback_analysis(question)


def get_tactical_context(mitre_ids: list, triggered_rules: list, score: float) -> str:
    """
    Ask Splunk AI Instruct for tactical context about a detected threat.
    This output feeds INTO Qwen 2.5 for the feedback loop.
    """
    question = (
        f"I have detected a security threat with risk score {score:.1f}/100. "
        f"MITRE ATT&CK techniques detected: {', '.join(mitre_ids)}. "
        f"Triggered detection rules: {', '.join(triggered_rules[:5])}. "
        f"What SPL search should I run to find related artifacts in the last 30 minutes? "
        f"What is the likely attack progression?"
    )
    return ask_splunk_ai(question)


def _fallback_analysis(question: str) -> str:
    """Deterministic fallback when Splunk AI Instruct is not available."""
    return (
        "Splunk AI Instruct not available on this instance. "
        "Using local rule-based analysis. "
        "Recommend checking Splunk Enterprise version supports AI Instruct (8.2+)."
    )


def ping() -> bool:
    """Check if Splunk AI Instruct endpoint is reachable."""
    try:
        auth, headers = _auth()
        r = requests.get(
            f"{BASE_URL}/services/assistant",
            auth=auth,
            headers=headers,
            verify=False,
            timeout=5
        )
        return r.status_code in (200, 405)  # 405 = exists but GET not allowed
    except Exception:
        return False