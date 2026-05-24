def calculate_risk(events):
    score = 0
    triggered = []
    processes = [e.get("process", "") for e in events]
    actions = [e.get("action", "") for e in events]
    commands = [e.get("command", "") for e in events]

    if "powershell.exe" in processes:
        score += 1
        triggered.append("Suspicious PowerShell execution detected")

    if "vssadmin.exe" in processes:
        score += 1
        triggered.append("Shadow copy deletion attempted")

    if "malware.exe" in processes:
        score += 1
        triggered.append("Malware process execution detected")

    if "psexec.exe" in processes:
        score += 1
        triggered.append("Lateral movement via PsExec detected")

    if "file_write" in actions:
        score += 1
        triggered.append("File encryption activity detected")

    if "lateral_move" in actions:
        score += 1
        triggered.append("Lateral movement action observed")

    if score == 0:
        threat_level = "CLEAN"
        prediction = "No threats detected. System is normal."
        recommended_action = "Continue monitoring."

    elif score == 1:
        threat_level = "LOW"
        prediction = "Single suspicious event observed. Could be a false positive."
        recommended_action = "Log and monitor for further activity."

    elif score == 2:
        threat_level = "MEDIUM"
        prediction = "Multiple suspicious indicators. Possible early stage attack."
        recommended_action = "Increase monitoring. Flag user account for review."

    elif score == 3:
        threat_level = "HIGH"
        prediction = "Attack chain forming. Credential dumping or staging likely."
        recommended_action = "Alert SOC team. Prepare for isolation."

    elif score == 4:
        threat_level = "CRITICAL"
        prediction = "Ransomware staging confirmed. Lateral movement active."
        recommended_action = "Isolate endpoint immediately. Disable SMB."

    else:
        threat_level = "CRITICAL"
        prediction = "Full ransomware attack chain detected. Encryption imminent."
        recommended_action = "Emergency isolation. Block all lateral paths. Deploy deception credentials."

    return {
        "score": score,
        "max_score": 6,
        "threat_level": threat_level,
        "prediction": prediction,
        "recommended_action": recommended_action,
        "triggered_rules": triggered
    }