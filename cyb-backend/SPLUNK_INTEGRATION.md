# 🔗 Splunk Integration Guide

## What Does This Do?

This guide connects your **Splunk Security Data** directly to the **AI SOC Platform** for automatic threat analysis.

```
Splunk (your security data)
      ↓
  API Request
      ↓
AI SOC Platform (analyzes with ML)
      ↓
  Threat Alert
      ↓
Splunk Dashboard (shows results)
```

---

## Prerequisites

1. **Splunk Enterprise 8.0+** installed and running
2. **Splunk admin access** (to create API tokens)
3. **Network connectivity** between your server and Splunk
4. **Events flowing into Splunk** (Windows Event Logs, EDR, etc.)

---

## Step 1: Create API Token in Splunk

### 1.1 Log in to Splunk

Go to `https://your-splunk-server:8000` and log in with admin account.

### 1.2 Create an API Token

1. Click **Settings** (top right)
2. Click **Tokens for Logins**  
3. Click **New Token**
4. Fill in:
   - **Name**: `XDR-AI-SOC` (or your preference)
   - **Expiration**: `90 days` (or as needed)
   - **Authentication Type**: `Standard`
5. Click **Save**
6. Copy the token (looks like: `a1b2c3d4e5f6g7h8i9j0k1l2`)

---

## Step 2: Configure Environment Variables

### 2.1 Set Up Connection Details

**Windows PowerShell**:
```powershell
$env:SPLUNK_HOST = "your-splunk-server.company.com"
$env:SPLUNK_PORT = "8089"
$env:SPLUNK_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2"  # Your token from Step 1
$env:SPLUNK_USERNAME = "admin"
$env:SPLUNK_PASSWORD = "splunkpassword"

# Also set API key for the AI SOC platform
$env:XDR_API_KEY = "your-secret-api-key"
```

**Mac/Linux Bash**:
```bash
export SPLUNK_HOST="your-splunk-server.company.com"
export SPLUNK_PORT="8089"
export SPLUNK_TOKEN="a1b2c3d4e5f6g7h8i9j0k1l2"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="splunkpassword"
export XDR_API_KEY="your-secret-api-key"
```

**Create `.env` file** (easiest):
```bash
# Create file: cyb-backend/.env
SPLUNK_HOST=your-splunk-server.company.com
SPLUNK_PORT=8089
SPLUNK_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=splunkpassword
XDR_API_KEY=your-secret-api-key
```

---

## Step 3: Verify Connection

### 3.1 Start the Server

```bash
python main.py
```

### 3.2 Test Splunk Connection

```bash
curl http://localhost:8001/splunk-status
```

**Success Response**:
```json
{
  "splunk_online": true,
  "host": "your-splunk-server.company.com",
  "port": "8089",
  "auth_method": "token"
}
```

**Failed Response**:
```json
{
  "splunk_online": false
}
```

If failed, check:
- Is Splunk running?
- Is the host/port correct?
- Is the firewall allowing port 8089?
- Is the token still valid?

---

## Step 4: Fetch and Analyze Events

### 4.1 Get Raw Events from Splunk

```bash
curl "http://localhost:8001/events?earliest=-1h" \
  -H "X-API-Key: your-secret-api-key"
```

**Response**:
```json
{
  "events": [
    {
      "host": "DESKTOP-001",
      "user": "john.doe",
      "process": "powershell.exe",
      "command_line": "Get-ChildItem C:\\Users",
      "_time": 1718001234
    }
  ],
  "count": 42,
  "earliest": "-1h"
}
```

### 4.2 Run Full ML Analysis

```bash
curl "http://localhost:8001/ml-analyze?earliest=-15m" \
  -H "X-API-Key: your-secret-api-key"
```

This will:
1. Fetch events from Splunk
2. Extract features
3. Score with ML models
4. Generate alerts if score >= 65

---

## Step 5: Set Up Splunk Searches

### 5.1 Save Custom Search in Splunk

In Splunk, go to **Search & Reporting** and create a new search:

**For Ransomware Detection**:
```spl
source="ransomware.txt" OR (
  EventCode=4688 AND
  (CommandLine="*vssadmin*" OR CommandLine="*wmic*shadowcopy*" OR CommandLine="*bcdedit*")
)
| table _time host user process command_line
| head 1000
```

**For LSASS Dumping**:
```spl
EventCode=4688 AND
(CommandLine="*mimikatz*" OR CommandLine="*procdump*lsass*" OR CommandLine="*sekurlsa*")
| table _time host user process command_line
```

**For Lateral Movement**:
```spl
EventCode=4688 AND
(CommandLine="*psexec*" OR CommandLine="*wmiexec*" OR CommandLine="*winrm*")
| table _time host user command_line
```

**For PowerShell Obfuscation**:
```spl
EventCode=4688 AND process="powershell.exe" AND
(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*IEX*")
| table _time host user command_line
```

### 5.2 Send Search Results to AI SOC

After creating a search, you can:

**Option 1: Webhook Integration**
```
1. In Splunk: Alerts → Add action → Webhook
2. URL: http://your-server:8001/ingest
3. Auth: Add X-API-Key header
4. Payload: Include host, user, events
```

**Option 2: Manual API Call**
```bash
# 1. Run search in Splunk
# 2. Export results as JSON
# 3. Send to AI SOC endpoint

curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "DESKTOP-001",
    "user_id": "john.doe",
    "events": [<events from Splunk search>]
  }'
```

---

## Step 6: Create Splunk Dashboard

### 6.1 Add AI SOC Results to Dashboard

In Splunk, create a new dashboard:

```xml
<dashboard version="1.1">
  <label>AI SOC Threat Detection</label>
  <row>
    <panel>
      <title>Real-Time Threat Score</title>
      <single>
        <search>
          <query>index=_internal sourcetype=xdr_alerts
            | stats avg(score) as avg_threat</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
      </single>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Recent Alerts</title>
      <table>
        <search>
          <query>index=_internal sourcetype=xdr_alerts
            | table incident_id host_id threat score mitre
            | sort - score</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## Step 7: Splunk AI Integration (Optional)

If you have **Splunk AI Instruct** installed:

### 7.1 Enable in AI SOC

```bash
export SPLUNK_AI_ENABLED=true
```

### 7.2 The System Will Now:

1. Detect threat with ML
2. Ask Splunk AI: "Should we quarantine this?"
3. Get AI-generated remediation steps
4. Return combined response

---

## 📊 Example: End-to-End Workflow

```
Time: 10:00 AM
└─ DESKTOP-001 runs suspicious PowerShell
└─ Event logs appear in Splunk immediately
└─ Splunk forwards events to AI SOC via webhook
└─ AI SOC analyzes with ML models
└─ ML score: 78/100 (HIGH threat)
└─ Alert created and sent back to Splunk
└─ Splunk dashboard shows alert
└─ SOC analyst clicks alert
└─ Gets full explanation and recommended actions
└─ Takes action (isolate host, block account, etc.)
```

---

## 🔧 Troubleshooting

### "Splunk connection failed"

```bash
# 1. Check if Splunk is running
curl https://your-splunk-server:8000 -k

# 2. Verify port 8089 is open
telnet your-splunk-server 8089

# 3. Test token validity in Splunk:
# Settings → Tokens for Logins → check token is still valid
```

### "Authentication failed"

```bash
# Token might be expired
# 1. Go to Splunk Settings → Tokens
# 2. Create new token
# 3. Update XDR_SPLUNK_TOKEN
# 4. Restart main.py
```

### "No events returned"

```bash
# Splunk might not have any data in that time range
# 1. In Splunk, run manual search
# 2. Check earliest/latest parameters
# 3. Verify event sources are configured
```

---

## 📈 Performance Tips

### Optimize Splunk Queries

```spl
# ❌ SLOW: Searches entire index
index=* host="*" sourcetype="*" | ...

# ✅ FAST: Specifies index and filters
index=main sourcetype=WinEventLog:Security host="DESKTOP-*" EventCode=4688 | ...

# ❌ SLOW: High volume time range
earliest=-30d latest=now | ...

# ✅ FAST: Reasonable time range
earliest=-15m latest=now | ...
```

### Tune AI SOC

```bash
# Increase worker threads for faster processing
export XDR_WORKERS=8  # Default is 4

# Increase queue size if overloaded
# (in ml.py, change Queue maxsize)
```

---

## 📡 Advanced: Custom Event Format

If Splunk events have different field names, modify `_splunk_to_engine_events()` in `risk_engine.py`:

```python
def _splunk_to_engine_events(splunk_events: List[Dict]) -> List[Dict]:
    translated = []
    for e in splunk_events:
        # Map your Splunk field names to Engine format
        command = e.get("command", "") or e.get("command_line", "") or e.get("CommandLine", "")
        host = e.get("host", "unknown")
        user = e.get("user", "unknown")
        
        if command:
            translated.append({
                "event_type": "process_spawn",
                "command_line": command
            })
        # ... rest of mapping
    return translated
```

---

## 🔗 Integration Checklist

- [ ] Splunk admin access obtained
- [ ] API token created and copied
- [ ] Environment variables set
- [ ] Connection test successful (`/splunk-status`)
- [ ] Events fetched successfully (`/events`)
- [ ] ML analysis working (`/ml-analyze`)
- [ ] Alerts appearing in `/alerts`
- [ ] Dashboard created (optional)
- [ ] Splunk AI enabled (optional)
- [ ] Team trained on using the system

---

## 📚 Next Steps

1. **Set up alerts** - Have the system notify your SOC team
2. **Create runbooks** - Document response procedures
3. **Fine-tune** - Adjust thresholds based on your environment
4. **Train team** - Show analysts how to use the system
5. **Deploy** - Move to production with monitoring

---

**Questions? See README.md, QUICKSTART.md, or API_GUIDE.md**
