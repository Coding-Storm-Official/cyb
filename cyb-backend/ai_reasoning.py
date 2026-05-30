from __future__ import annotations
"""
ai_reasoning.py — AI feed generator
-------------------------------------
Combines rule-based narrative (instant, always works) with a live Qwen 2.5
enrichment call (richer, requires Ollama running locally).

If Qwen is offline the feed still works — it just uses the deterministic
narrative layer.  When Qwen IS online the feed gains:
  • executive_brief   — LLM-written plain-English summary
  • spl_hunt_query    — new SPL to feed back into Splunk
  • qwen_next_action  — LLM-recommended containment steps
"""
import time
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("xdr.ai_reasoning")

try:
    from qwen import analyze_threat, analyze_risk_context, ping as qwen_ping
    _QWEN_AVAILABLE = True
except ImportError:
    _QWEN_AVAILABLE = False
    logger.warning("[ai_reasoning] qwen.py not found — Qwen enrichment disabled.")

_STAGE_NARRATIVES: Dict[str, str] = {
    "Discovery":           "Adversary is enumerating the environment — expect credential or privilege attacks next.",
    "Credential Access":   "Credential material is being harvested — lateral movement window is open.",
    "Privilege Escalation":"Token or integrity-level elevation detected — full domain compromise is feasible.",
    "Defense Evasion":     "Defensive tools are being disabled or logs cleared — attacker preparing for next phase.",
    "Lateral Movement":    "Adversary is spreading across the network — contain affected hosts immediately.",
    "Collection":          "Sensitive data is being staged for exfiltration.",
    "Exfiltration":        "Active data transfer to external destination — block egress and preserve forensics.",
    "Persistence":         "Backdoor or scheduled task installed — endpoint will survive reboot compromise.",
    "Execution":           "Malicious payload running in memory or via scripting engine.",
    "Impact":              "Destructive action underway — ransomware encryption or mass deletion in progress.",
    "Unknown":             "Attack stage unclear — broadening telemetry collection recommended.",
}

_BEHAVIOR_DETAIL: Dict[str, str] = {
    "RANSOMWARE":              "Mass file encryption with extension mutation detected — isolate immediately.",
    "INSIDER_THREAT":          "Abnormal bulk data access and download pattern consistent with insider exfiltration.",
    "INSIDER_RECON":           "Rapid directory traversal with access-denied spikes — insider enumeration profile.",
    "PRIVILEGE_ESCALATION":    "LSASS access or UAC bypass detected — credential theft attempted.",
    "INTEGRITY_LEVEL_JUMP":    "Token elevation from Medium/Low to SYSTEM — exploit or abuse of privilege API.",
    "PERSISTENCE_ESTABLISHED": "Registry Run key, scheduled task, or WMI subscription created — backdoor active.",
    "LATERAL_MOVEMENT":        "Remote execution utility detected — attacker pivoting to adjacent hosts.",
    "SHADOW_COPY_DELETION":    "Volume shadow copies deleted — ransomware pre-encryption wipe pattern.",
    "EXFIL_STAGING":           "Data compressed or copied to staging directory before transfer.",
    "DATA_EXFILTRATION":       "Large outbound data volume to suspicious destination.",
}

_ACTION_CONTEXT: Dict[str, str] = {
    "ISOLATE_HOST":            "Host network access severed via NAC or firewall rule to halt lateral spread.",
    "BLOCK_EGRESS":            "Outbound traffic to suspicious destinations blocked at perimeter.",
    "SNAPSHOT_MEMORY":         "Volatile memory image captured for forensic analysis before process termination.",
    "DISABLE_TOKENS":          "Active access tokens for compromised account invalidated across domain.",
    "DEPLOY_DECEPTION_CREDS":  "Honeypot credentials deployed to detect further credential abuse.",
    "INCREASE_SAMPLING":       "Telemetry collection rate elevated to 1-second granularity on affected host.",
    "SANDBOX_PROCESS":         "Suspicious process cloned into isolated sandbox environment for detonation analysis.",
    "NOTIFY_SOC":              "SOC analyst paged with enriched incident context.",
    "DEPLOY_HONEYTOKENS":      "Honeytoken files and credentials seeded across accessible shares.",
    "WATCHLIST":               "Entity added to elevated-monitoring watchlist for 72-hour observation.",
    "ALERT_ANALYST":           "Tier-1 analyst notified for manual review.",
}

_MITRE_DESCRIPTIONS: Dict[str, str] = {
    "T1003": "OS Credential Dumping (LSASS / Mimikatz)",
    "T1055": "Process Injection",
    "T1021": "Remote Services (Lateral Movement)",
    "T1041": "Exfiltration Over C2 Channel",
    "T1489": "Service Stop / Defense Disable",
    "T1070": "Indicator Removal (Log Clearing)",
    "T1087": "Account Discovery / Recon",
    "T1059": "Command & Scripting Interpreter",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1078": "Valid Accounts / Privilege Abuse",
    "T1547": "Boot or Logon Autostart (Persistence)",
    "T1053": "Scheduled Task / Job (Persistence)",
    "T1112": "Modify Registry",
    "T1074": "Data Staged for Collection",
    "T1083": "File and Directory Discovery",
}
 

def _severity_label(score: float) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 75: return "HIGH"
    if score >= 55: return "MEDIUM"
    return "LOW"

def _threat_summary(score: float, tags: List[str], mitre: List[str]) -> str:
    level     = _severity_label(score)
    tag_str   = ", ".join(tags) if tags else "general anomaly"
    mitre_str = ", ".join(_MITRE_DESCRIPTIONS.get(m, m) for m in mitre) if mitre else "unclassified"
    return (
        f"{level} confidence threat ({score:.1f}/100) — "
        f"Behavior profile: [{tag_str}] — "
        f"MITRE coverage: {mitre_str}."
    )


def generate_ai_feed(alert: Dict[str, Any], use_qwen: bool = True) -> List[Dict[str, str]]:
    """
    Returns a list of feed entries for the frontend dashboard.
    
    Each entry: {"type": str, "message": str}
    
    If Qwen is running AND use_qwen=True, additional entries are appended:
      QWEN_EXECUTIVE_BRIEF, QWEN_HUNT_QUERY, QWEN_CONTAINMENT
    """
    score          = float(alert.get("score", 0.0))
    threat         = alert.get("threat", _severity_label(score))
    rules          = alert.get("rules", [])
    mitre          = alert.get("mitre", [])
    behavior_tags  = alert.get("behavior_tags", [])
    actions        = alert.get("actions", [])
    next_stage     = alert.get("next_stage", "Unknown")
    confidence     = float(alert.get("confidence", 0.0))
    integrity_jump = bool(alert.get("integrity_jump", False))
    iocs           = alert.get("ioc_matches", alert.get("iocs", []))
    host_id        = alert.get("host_id", "unknown")
    user_id        = alert.get("user_id", "unknown")

    feed: List[Dict[str, str]] = []

    feed.append({
        "type": "THREAT_SUMMARY",
        "message": _threat_summary(score, behavior_tags, mitre),
    })

    for rule in rules:
        feed.append({"type": "SIGNATURE_MATCH", "message": f"Rule fired: {rule}"})

    for m in mitre:
        desc = _MITRE_DESCRIPTIONS.get(m, m)
        feed.append({"type": "MITRE_TECHNIQUE", "message": f"{m} — {desc}"})

    for tag in behavior_tags:
        detail = _BEHAVIOR_DETAIL.get(tag, tag)
        feed.append({"type": "BEHAVIOR_PATTERN", "message": f"{tag}: {detail}"})

    if integrity_jump:
        feed.append({
            "type": "INTEGRITY_ALERT",
            "message": "Token integrity level jump detected — process is running at elevated privilege.",
        })

    for ioc in iocs:
        feed.append({"type": "IOC_MATCH", "message": f"Known malicious indicator matched: {ioc}"})

    stage_narrative = _STAGE_NARRATIVES.get(next_stage, _STAGE_NARRATIVES["Unknown"])
    feed.append({
        "type": "KILL_CHAIN_POSITION",
        "message": f"Current stage: {next_stage} (Markov confidence {confidence:.1%}) — {stage_narrative}",
    })

    feed.append({
        "type": "RISK_SCORE",
        "message": f"Ensemble risk score: {score:.1f}/100 — {threat} — host={host_id}, user={user_id}",
    })

    for action in actions:
        context = _ACTION_CONTEXT.get(action, action)
        feed.append({"type": "AUTONOMOUS_ACTION", "message": f"{action}: {context}"})

    if not actions:
        feed.append({
            "type": "AUTONOMOUS_ACTION",
            "message": "No autonomous action triggered — score below response threshold.",
        })

    if use_qwen and _QWEN_AVAILABLE:
        try:
            qwen_result = analyze_threat(alert)

            if qwen_result.get("executive_brief"):
                feed.append({
                    "type": "QWEN_EXECUTIVE_BRIEF",
                    "message": qwen_result["executive_brief"],
                })

            if qwen_result.get("spl_hunt_query"):
                feed.append({
                    "type": "QWEN_HUNT_QUERY",
                    "message": qwen_result["spl_hunt_query"],
                    # This SPL string is picked up by the /feedback-loop endpoint
                    # in main.py and injected back into Splunk automatically.
                })

            if qwen_result.get("next_action"):
                feed.append({
                    "type": "QWEN_CONTAINMENT",
                    "message": qwen_result["next_action"],
                })

        except Exception as exc:
            logger.warning(f"[ai_reasoning] Qwen enrichment failed: {exc}")
            feed.append({
                "type": "QWEN_STATUS",
                "message": f"Qwen enrichment unavailable: {exc}",
            })

    return feed


def generate_ai_feed_legacy(risk_result: Dict[str, Any], events=None) -> List[Dict[str, str]]:
    score        = float(risk_result.get("score", 0)) / 6.0 * 100.0
    threat_level = risk_result.get("threat_level", "UNKNOWN")
    triggered    = risk_result.get("triggered_rules", [])
    prediction   = risk_result.get("prediction", "")
    feed: List[Dict[str, str]] = []
    for rule in triggered:
        feed.append({"type": "AI DETECTED", "message": rule})
    feed.append({
        "type": "AI REASONING",
        "message": f"Confidence score: {risk_result.get('score', 0)}/6 — {threat_level} threat level",
    })
    feed.append({"type": "PREDICTION", "message": prediction})
    if score >= (4 / 6 * 100):
        feed.append({"type": "AUTONOMOUS ACTION", "message": "Deploying deception credentials and isolating endpoint..."})
    elif score >= (2 / 6 * 100):
        feed.append({"type": "AUTONOMOUS ACTION", "message": "Deploying honeytokens and increasing monitoring..."})
    return feed