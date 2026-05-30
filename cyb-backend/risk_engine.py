from __future__ import annotations
import re
import time
import logging
import numpy as np
from typing import List, Dict, Any, Tuple
from ai_reasoning import generate_ai_feed

logger = logging.getLogger("xdr.risk_engine")

_PROC_WEIGHTS: Dict[str, Tuple[int, str]] = {
    "powershell.exe":  (2, "Suspicious PowerShell execution"),
    "cmd.exe":         (1, "Command prompt spawned"),
    "wscript.exe":     (2, "Windows Script Host execution"),
    "cscript.exe":     (2, "CScript host execution"),
    "mshta.exe":       (3, "MSHTA living-off-the-land execution"),
    "vssadmin.exe":    (3, "Shadow copy deletion attempted (T1486)"),
    "psexec.exe":      (3, "Lateral movement via PsExec (T1021)"),
    "wmic.exe":        (2, "WMIC command execution (T1047)"),
    "procdump.exe":    (4, "LSASS credential dumping attempted (T1003)"),
    "mimikatz.exe":    (5, "Mimikatz credential theft tool (T1003)"),
    "malware.exe":     (5, "Known malware process execution"),
    "rundll32.exe":    (2, "Rundll32 proxy execution (T1218)"),
    "regsvr32.exe":    (2, "Regsvr32 proxy execution (T1218)"),
    "schtasks.exe":    (2, "Scheduled task creation (T1053)"),
    "at.exe":          (2, "Legacy scheduled task (T1053)"),
    "net.exe":         (1, "Net command reconnaissance"),
    "net1.exe":        (1, "Net1 command reconnaissance"),
    "whoami.exe":      (1, "Whoami recon (T1087)"),
    "nltest.exe":      (2, "Domain recon via NLTest (T1087)"),
    "certutil.exe":    (3, "Certutil download/decode abuse (T1105)"),
    "bitsadmin.exe":   (3, "BITSAdmin download abuse (T1197)"),
    "wevtutil.exe":    (3, "Event log clearing (T1070)"),
}

_ACTION_WEIGHTS: Dict[str, Tuple[int, str]] = {
    "file_write":      (2, "File write / encryption activity detected"),
    "file_rename":     (2, "File rename — possible extension mutation"),
    "file_delete":     (2, "Mass file deletion"),
    "lateral_move":    (3, "Lateral movement action observed"),
    "access_denied":   (1, "Access denied spike — possible recon"),
    "registry_write":  (2, "Registry persistence write"),
    "net_connect":     (1, "Outbound network connection"),
    "login_fail":      (1, "Authentication failure"),
    "token_elevation": (3, "Token elevation / integrity level jump"),
}

_CMD_PATTERNS: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r'-enc|-encodedcommand|iex\s*\(|invoke-expression|downloadstring', re.I), 3,
     "Encoded / obfuscated PowerShell (T1059)"),
    (re.compile(r'vssadmin\s+delete\s+shadows|bcdedit.+recoveryenabled\s+no|wbadmin\s+delete', re.I), 4,
     "Shadow copy / backup deletion (T1490)"),
    (re.compile(r'lsass|sekurlsa|comsvcs.*minidump|procdump.*lsass', re.I), 5,
     "LSASS memory access / credential dumping (T1003)"),
    (re.compile(r'reg\s+add.+(Run|RunOnce|Winlogon|Services)', re.I), 3,
     "Registry Run key persistence (T1547)"),
    (re.compile(r'schtasks.+/create|register-scheduledtask', re.I), 2,
     "Scheduled task persistence (T1053)"),
    (re.compile(r'net\s+(user|localgroup|share|use|view)|whoami\s+/priv|nltest\s+/domain', re.I), 1,
     "Domain/account reconnaissance (T1087)"),
    (re.compile(r'psexec|wmiexec|winrm|enter-pssession', re.I), 3,
     "Remote execution / lateral movement (T1021)"),
    (re.compile(r'certutil.+-urlcache|bitsadmin.+transfer|invoke-webrequest|curl.+-o\s', re.I), 3,
     "Living-off-the-land download (T1105)"),
    (re.compile(r'\.(locked|encrypted|enc|crypt|ryuk|maze|conti|lockbit|wcry|wncry)\b', re.I), 4,
     "Ransomware extension mutation detected (T1486)"),
    (re.compile(r'fodhelper|eventvwr|computerdefaults|sdclt.*bypassuac', re.I), 3,
     "UAC bypass attempt (T1548)"),
]

def _splunk_to_engine_events(splunk_events: List[Dict]) -> List[Dict]:
    translated = []
    for e in splunk_events:
        proc    = e.get("process", "")
        action  = e.get("action", "")
        command = e.get("command", "") or e.get("command_line", "")
        fpath   = e.get("file_path", "") or e.get("target", "")
        new_p   = e.get("new_path", "")
        remote  = e.get("remote_address", "")
        bytes_s = e.get("bytes_sent", 0)
        bytes_r = e.get("bytes_recv", 0)
        int_lvl = e.get("integrity_level", "")
        reg_key = e.get("registry_key", "")
        raw_et  = e.get("event_type", "")

        if proc or command:
            translated.append({
                "event_type":    "process_spawn",
                "command_line":  f"{proc} {command}".strip(),
                "integrity_level": int_lvl,
            })

        if action == "file_write" or raw_et == "file_write":
            translated.append({"event_type": "file_write", "path": fpath})
        if action == "file_rename" or raw_et == "file_rename":
            translated.append({"event_type": "file_rename", "new_path": new_p or fpath})
        if action == "file_delete" or raw_et == "file_delete":
            translated.append({"event_type": "file_delete", "path": fpath})
        if action == "access_denied" or raw_et == "access_denied":
            translated.append({"event_type": "access_denied", "path": fpath})
        if action == "token_elevation" or int_lvl in ("System", "High"):
            translated.append({"event_type": "token_elevation", "integrity_level": int_lvl})
        if reg_key:
            translated.append({"event_type": "registry_write", "registry_key": reg_key})
        if remote:
            translated.append({
                "event_type":  "network_flow",
                "destination": remote,
                "bytes_sent":  float(bytes_s or 0),
                "bytes_recv":  float(bytes_r or 0),
            })

    return translated

def calculate_risk(events: List[Dict]) -> Dict[str, Any]:
    score      = 0
    triggered  = []
    seen_rules = set()

    processes = [str(e.get("process", "")).lower() for e in events]
    actions   = [str(e.get("action",  "")).lower() for e in events]
    commands  = [str(e.get("command", "") or e.get("command_line", "")) for e in events]

    for proc_name, (weight, desc) in _PROC_WEIGHTS.items():
        if proc_name in processes and desc not in seen_rules:
            score += weight
            triggered.append(desc)
            seen_rules.add(desc)

    for act_name, (weight, desc) in _ACTION_WEIGHTS.items():
        if act_name in actions and desc not in seen_rules:
            score += weight
            triggered.append(desc)
            seen_rules.add(desc)

    for pattern, weight, desc in _CMD_PATTERNS:
        if any(pattern.search(c) for c in commands) and desc not in seen_rules:
            score += weight
            triggered.append(desc)
            seen_rules.add(desc)

    file_writes  = sum(1 for e in events if e.get("action") == "file_write")
    file_renames = sum(1 for e in events if e.get("action") == "file_rename")
    if file_writes > 50:
        score += 3
        triggered.append(f"Mass file write activity: {file_writes} writes (ransomware encryption pattern)")
    if file_renames > 30:
        score += 3
        triggered.append(f"Mass file rename activity: {file_renames} renames (ransomware extension mutation)")

    access_denied = sum(1 for e in events if e.get("action") == "access_denied")
    if access_denied > 20:
        score += 2
        triggered.append(f"Access denied spike: {access_denied} denials (insider recon pattern)")

    hosts = {e.get("host", "") for e in events if e.get("host")}
    if len(hosts) > 3:
        score += 2
        triggered.append(f"Activity across {len(hosts)} hosts — active lateral movement")

    capped = min(score, 20)
    normalized = round((capped / 20.0) * 100.0, 1)

    if normalized >= 85:
        threat_level = "CRITICAL"
        prediction   = "Full ransomware attack chain confirmed. Encryption imminent or in progress."
        action       = "Emergency isolation. Block all lateral paths. Deploy deception credentials. Snapshot memory."
    elif normalized >= 65:
        threat_level = "HIGH"
        prediction   = "Attack chain forming. Credential dumping or staging likely next."
        action       = "Alert SOC team immediately. Prepare endpoint isolation. Increase sampling."
    elif normalized >= 40:
        threat_level = "MEDIUM"
        prediction   = "Multiple suspicious indicators. Possible early-stage attack or insider threat."
        action       = "Flag entity for review. Deploy honeytokens. Increase telemetry."
    elif normalized >= 15:
        threat_level = "LOW"
        prediction   = "Single suspicious event. Could be a false positive."
        action       = "Log and monitor for further activity."
    else:
        threat_level = "CLEAN"
        prediction   = "No significant threats detected. System appears normal."
        action       = "Continue standard monitoring."

    mitre_ids = _extract_mitre_ids(triggered)

    return {
        "score":            normalized,
        "raw_score":        capped,
        "max_score":        100,
        "threat_level":     threat_level,
        "prediction":       prediction,
        "recommended_action": action,
        "triggered_rules":  triggered,
        "mitre_ids":        mitre_ids,
        "event_count":      len(events),
        "unique_hosts":     list(hosts),
        "ts":               time.time(),
    }

def _extract_mitre_ids(triggered: List[str]) -> List[str]:
    mitre_map = {
        "T1003": ["lsass", "credential dump", "mimikatz"],
        "T1021": ["lateral movement", "psexec", "remote execution"],
        "T1041": ["exfil", "outbound"],
        "T1059": ["powershell", "encoded", "obfuscat"],
        "T1070": ["event log", "wevtutil"],
        "T1086": ["powershell"],
        "T1087": ["reconnaissance", "whoami", "nltest", "domain"],
        "T1105": ["download", "certutil", "bitsadmin"],
        "T1218": ["rundll32", "regsvr32", "mshta"],
        "T1486": ["ransomware", "encryption", "shadow copy", "extension mutation"],
        "T1490": ["shadow copy", "backup deletion"],
        "T1547": ["registry", "persistence", "run key"],
        "T1548": ["uac bypass", "token elevation", "integrity"],
        "T1053": ["scheduled task"],
    }
    found = []
    combined = " ".join(triggered).lower()
    for mid, keywords in mitre_map.items():
        if any(k in combined for k in keywords):
            found.append(mid)
    return found

def full_analysis(events: List[Dict]) -> Dict[str, Any]:
    risk     = calculate_risk(events)
    eng_evts = _splunk_to_engine_events(events)

    alert_dict = {
        "incident_id":    f"RISK-{int(time.time())}",
        "host_id":        events[0].get("host", "unknown") if events else "unknown",
        "user_id":        events[0].get("user", "unknown") if events else "unknown",
        "score":          risk["score"],
        "threat":         risk["threat_level"],
        "rules":          risk["triggered_rules"],
        "mitre":          risk["mitre_ids"],
        "behavior_tags":  _infer_behavior_tags(risk),
        "actions":        _infer_actions(risk["score"]),
        "next_stage":     _predict_next_stage(risk["mitre_ids"]),
        "confidence":     0.0,
        "integrity_jump": any("token elevation" in r.lower() or "integrity" in r.lower()
                              for r in risk["triggered_rules"]),
        "iocs":           [],
        "ioc_matches":    [],
    }

    ai_feed = generate_ai_feed(alert_dict)
    return {**risk, "ai_feed": ai_feed, "engine_events": eng_evts}

def _infer_behavior_tags(risk: Dict) -> List[str]:
    tags = []
    combined = " ".join(risk["triggered_rules"]).lower()
    if "ransomware" in combined or "extension mutation" in combined or "shadow copy" in combined:
        tags.append("RANSOMWARE")
    if "lateral movement" in combined:
        tags.append("LATERAL_MOVEMENT")
    if "lsass" in combined or "credential" in combined:
        tags.append("PRIVILEGE_ESCALATION")
    if "token elevation" in combined or "integrity" in combined:
        tags.append("INTEGRITY_LEVEL_JUMP")
    if "registry" in combined or "scheduled task" in combined:
        tags.append("PERSISTENCE_ESTABLISHED")
    if "access denied" in combined or "reconnaissance" in combined:
        tags.append("INSIDER_RECON")
    if "download" in combined or "outbound" in combined:
        tags.append("EXFIL_STAGING")
    return tags

def _infer_actions(score: float) -> List[str]:
    if score >= 85:
        return ["ISOLATE_HOST", "BLOCK_EGRESS", "SNAPSHOT_MEMORY", "DISABLE_TOKENS", "DEPLOY_DECEPTION_CREDS"]
    if score >= 65:
        return ["INCREASE_SAMPLING", "SANDBOX_PROCESS", "NOTIFY_SOC", "DEPLOY_HONEYTOKENS"]
    if score >= 40:
        return ["WATCHLIST", "ALERT_ANALYST"]
    return []

def _predict_next_stage(mitre_ids: List[str]) -> str:
    stage_map = {
        "T1087": "Credential Access",
        "T1003": "Lateral Movement",
        "T1021": "Collection",
        "T1041": "Impact",
        "T1486": "Impact",
        "T1059": "Defense Evasion",
        "T1070": "Exfiltration",
        "T1547": "Execution",
        "T1053": "Execution",
    }
    if not mitre_ids:
        return "Unknown"
    for mid in mitre_ids:
        if mid in stage_map:
            return stage_map[mid]
    return "Unknown"