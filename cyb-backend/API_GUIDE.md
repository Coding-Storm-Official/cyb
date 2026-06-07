# 📡 Complete API Reference Guide

## Base URL

```
http://localhost:8001
```

(In production, replace with your server URL)

---

## Authentication

All endpoints except `/` and `/health` require an API key header:

```bash
-H "X-API-Key: your-secret-key"
```

If API key is wrong or missing:
```
HTTP 401 Unauthorized
{"detail": "Invalid or missing X-API-Key header."}
```

---

## Endpoints Overview

| Method | Path | Purpose | Auth Required |
|--------|------|---------|---|
| GET | `/` | Check if server is online | ❌ No |
| GET | `/health` | Detailed health status | ❌ No |
| GET | `/metrics` | Prometheus metrics | ❌ No |
| **POST** | **`/ingest`** | Send events for analysis | ✅ Yes |
| **GET** | **`/ml-analyze`** | Analyze Splunk events | ✅ Yes |
| **GET** | **`/alerts`** | Get recent alerts | ✅ Yes |
| **GET** | **`/explain-threat/{id}`** | Explain why something was flagged | ✅ Yes |
| POST | `/feedback-loop` | Full analysis pipeline | ✅ Yes |
| GET | `/threat-level` | Overall threat assessment | ❌ No |
| GET | `/analyze` | Risk analysis | ✅ Yes |
| GET | `/events` | Get raw Splunk events | ❌ No |
| GET | `/splunk-status` | Check Splunk connection | ❌ No |
| GET | `/qwen-status` | Check AI availability | ❌ No |

---

# 🔴 Core Endpoints

## 1. POST `/ingest` - Send Events

**What it does**: Submit security events for threat analysis

**Example Request**:
```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "LAPTOP-JOHN",
    "user_id": "john.doe@company.com",
    "events": [
      {
        "event_type": "process_spawn",
        "command_line": "powershell.exe -enc AQAB..."
      },
      {
        "event_type": "file_write",
        "path": "C:\\Users\\john\\Documents\\important.docx.locked"
      }
    ]
  }'
```

**Request Fields**:
- `host_id` (string, required) - Computer name or ID
- `user_id` (string, required) - Username
- `events` (array, required) - List of security events

**Event Types Supported**:
```
process_spawn          - New process created
file_write            - File created/written
file_rename           - File renamed
file_delete           - File deleted
access_denied         - Access denied attempt
directory_traversal   - Directory enumeration
network_connection    - Network connection
dns_query             - DNS lookup
token_elevation       - Permission level change
registry_write        - Registry modified
file_open             - File opened
file_read             - File read
```

**Event Fields** (vary by type):
```json
{
  "event_type": "process_spawn",
  "command_line": "string (process command)",
  "process": "string (process name)",
  "integrity_level": "string (Low/Medium/High/System)"
}

{
  "event_type": "file_write",
  "path": "string (file path)",
  "content_sample": "string (first 200 bytes of content, optional)"
}

{
  "event_type": "network_connection",
  "destination": "string (IP or domain)",
  "remote_address": "string (alternative field name)",
  "bytes_sent": "number (bytes)",
  "bytes_recv": "number (bytes)"
}

{
  "event_type": "registry_write",
  "registry_key": "string (registry path)"
}
```

**Success Response** (HTTP 200):
```json
{
  "status": "queued",
  "host_id": "LAPTOP-JOHN",
  "user_id": "john.doe@company.com"
}
```

**Error Response** (HTTP 400):
```json
{
  "detail": "Invalid payload format"
}
```

---

## 2. GET `/ml-analyze` - Analyze Events

**What it does**: Run ML analysis on events from Splunk or uploaded data

**Example Request**:
```bash
curl "http://localhost:8001/ml-analyze?earliest=-15m&skip_qwen=false" \
  -H "X-API-Key: your-secret-key"
```

**Query Parameters**:
- `earliest` (string, optional) - How far back to look. Examples: `-15m`, `-1h`, `-24h` (default: `-15m`)
- `skip_qwen` (boolean, optional) - Skip AI explanation (default: false)

**Response** (HTTP 200):
```json
{
  "incident_id": "ML-ABC123XYZ",
  "host_id": "LAPTOP-001",
  "user_id": "admin",
  "score": 82.5,
  "threat": "HIGH",
  "rules": ["SIG-005", "SIG-012"],
  "mitre": ["T1486", "T1490"],
  "behavior_tags": ["RANSOMWARE", "SHADOW_COPY_DELETION"],
  "actions": ["ISOLATE_HOST", "BLOCK_EGRESS", "SNAPSHOT_MEMORY"],
  "next_stage": "Impact",
  "confidence": 0.891,
  "integrity_jump": true,
  "iocs": ["185.220.101.10"],
  "feature_vector": [0.05, 0.12, 4.2, ...],  # 40 numbers
  "ai_feed": [
    {
      "type": "THREAT_ANALYSIS",
      "message": "Ransomware attack pattern detected..."
    }
  ]
}
```

**Response Fields Explained**:
- `score` - Threat score 0-100
- `threat` - Severity: LOW/MEDIUM/HIGH/CRITICAL
- `rules` - Which signature rules matched
- `mitre` - MITRE ATT&CK tactic IDs (T1486, etc.)
- `behavior_tags` - Type of attack detected
- `actions` - Recommended security actions
- `confidence` - How confident the system is (0-1)
- `feature_vector` - Raw ML data (advanced users only)

---

## 3. GET `/alerts` - Get Recent Alerts

**What it does**: Retrieve all alerts from the last N minutes

**Example Request**:
```bash
curl "http://localhost:8001/alerts?threat=HIGH&since_minutes=120" \
  -H "X-API-Key: your-secret-key"
```

**Query Parameters**:
- `threat` (string, optional) - Filter by severity: LOW, MEDIUM, HIGH, CRITICAL
- `since_minutes` (integer, optional) - Look back N minutes (default: 60)

**Success Response** (HTTP 200):
```json
{
  "count": 3,
  "alerts": [
    {
      "incident_id": "INC-ABC123",
      "host_id": "LAPTOP-001",
      "user_id": "john.doe",
      "score": 85.2,
      "threat": "HIGH",
      "rules": ["SIG-005"],
      "mitre": ["T1486"],
      "behavior_tags": ["RANSOMWARE"],
      "ts": 1718001234.567
    },
    {
      "incident_id": "INC-DEF456",
      "host_id": "SERVER-02",
      "user_id": "admin",
      "score": 72.1,
      "threat": "MEDIUM",
      "rules": ["SIG-006"],
      "mitre": ["T1059"],
      "behavior_tags": ["SUSPICIOUS_POWERSHELL"],
      "ts": 1718000987.234
    }
  ]
}
```

---

## 4. GET `/explain-threat/{incident_id}` - Explain Why Flagged

**What it does**: Get human-friendly explanation of a threat alert

**Example Request**:
```bash
curl "http://localhost:8001/explain-threat/INC-ABC123" \
  -H "X-API-Key: your-secret-key"
```

**Success Response** (HTTP 200):
```json
{
  "incident_id": "INC-ABC123",
  "summary": "Threat Score: 85.2/100 (HIGH severity)",
  "why_it_matters": "Files are being encrypted and renamed to lock them away. This looks like ransomware activity. A backdoor or persistent access mechanism is being installed.",
  "triggered_rules": ["SIG-005"],
  "behavior_patterns": ["RANSOMWARE", "PERSISTENCE_ESTABLISHED"],
  "mitre_tactics": ["T1486", "T1547"],
  "recommended_actions": ["ISOLATE_HOST", "BLOCK_EGRESS", "DEPLOY_HONEYTOKENS"],
  "next_likely_attack_stage": "Impact"
}
```

**Error Response** (HTTP 200 but with error field):
```json
{
  "error": "Alert not found",
  "incident_id": "INC-INVALID"
}
```

---

## 5. GET `/threat-level` - Overall Threat Assessment

**What it does**: Get current threat level (alternative to `/alerts`)

**Example Request**:
```bash
curl "http://localhost:8001/threat-level?earliest=-15m"
```

**Response** (HTTP 200):
```json
{
  "threat_level": "HIGH",
  "score": 72.5,
  "prediction": "Attack chain forming. Credential dumping or staging likely next.",
  "recommended_action": "Alert SOC team immediately. Prepare endpoint isolation. Increase sampling.",
  "mitre_ids": ["T1003", "T1486"],
  "ts": 1718001234.567
}
```

---

## 6. POST `/feedback-loop` - Full Analysis with Feedback

**What it does**: Complete analysis pipeline: detect → explain → hunt → refine

**Example Request**:
```bash
curl -X POST "http://localhost:8001/feedback-loop?earliest=-15m" \
  -H "X-API-Key: your-secret-key"
```

**Response** (HTTP 200):
```json
{
  "cycle_id": "LOOP-A1B2C3D4",
  "elapsed_seconds": 2.34,
  "initial_event_count": 42,
  "hunt_event_count": 15,
  "initial_score": 88.5,
  "initial_mitre": ["T1059.001", "T1486"],
  "initial_behavior_tags": ["obfuscation", "data_encryption"],
  "splunk_ai_context": "Splunk AI Instruct: Detected high entropy command execution...",
  "qwen_executive_brief": "CRITICAL RISK: A malicious PowerShell execution thread...",
  "qwen_spl_hunt_query": "search sourcetype=WinEventLog:Security...",
  "qwen_containment_steps": "1. Isolate endpoint...\n2. Invalidate AD credentials...",
  "hunt_score": 74.2,
  "hunt_mitre": ["T1486"],
  "hunt_behavior_tags": ["data_destruction"],
  "composite_score": 88.5,
  "ai_feed": [...]
}
```

---

# 🟢 Health & Status Endpoints

## GET `/` - Basic Health Check

**What it does**: Quick check that server is running

**Example Request**:
```bash
curl http://localhost:8001/
```

**Response** (HTTP 200):
```json
{
  "status": "AI SOC Backend Running",
  "version": "3.0.0",
  "splunk_online": false,
  "splunk_ai_online": false,
  "qwen_online": false,
  "engine": "ready"
}
```

---

## GET `/health` - Detailed Status

**What it does**: Detailed system health information

**Example Request**:
```bash
curl http://localhost:8001/health
```

**Response** (HTTP 200):
```json
{
  "status": "ok",
  "queue_depth": 42,
  "baseline_pool": 850,
  "attack_pool": 320,
  "model_ready": true,
  "splunk_online": false,
  "splunk_ai_online": false,
  "qwen_online": false,
  "ts": 1718001234.567
}
```

**Field Meanings**:
- `queue_depth` - Events waiting to be processed
- `baseline_pool` - Number of benign samples learned
- `attack_pool` - Number of malicious samples learned
- `model_ready` - Are ML models trained and ready?

---

## GET `/metrics` - Prometheus Metrics

**What it does**: Get system metrics (for monitoring tools)

**Example Request**:
```bash
curl http://localhost:8001/metrics
```

**Response** (plain text Prometheus format):
```
# HELP xdr_events_total Total telemetry events parsed
# TYPE xdr_events_total counter
xdr_events_total 1234

# HELP xdr_alerts_total Total security alerts published
# TYPE xdr_alerts_total counter
xdr_alerts_total 42
```

---

# 🟡 Splunk Integration Endpoints

## GET `/events` - Get Splunk Events

**What it does**: Fetch raw events from Splunk

```bash
curl "http://localhost:8001/events?earliest=-1h"
```

**Response**:
```json
{
  "events": [
    {
      "host": "DESKTOP-001",
      "user": "john.doe",
      "process": "powershell.exe",
      "command_line": "...",
      "_time": 1718001234
    }
  ],
  "count": 42,
  "earliest": "-1h"
}
```

---

## GET `/splunk-status` - Check Splunk Connection

```bash
curl http://localhost:8001/splunk-status
```

**Response**:
```json
{
  "splunk_online": true,
  "host": "splunk.company.com",
  "port": "8089",
  "auth_method": "token"
}
```

---

## GET `/analyze` - Full Risk Analysis

**What it does**: Comprehensive analysis from Splunk

```bash
curl "http://localhost:8001/analyze?earliest=-15m" \
  -H "X-API-Key: your-secret-key"
```

**Response**:
```json
{
  "earliest": "-15m",
  "event_count": 142,
  "risk_analysis": {
    "score": 65.3,
    "threat_level": "HIGH",
    "triggered_rules": ["Shadow copy deletion", "Ransomware extension"],
    "mitre_ids": ["T1486"]
  },
  "ai_feed": [...]
}
```

---

# 🔵 AI & Extended Endpoints

## GET `/qwen-status` - Check AI Availability

```bash
curl http://localhost:8001/qwen-status
```

**Response**:
```json
{
  "qwen_available": true,
  "qwen_online": true,
  "model": "qwen2.5",
  "host": "http://localhost:11434",
  "hint": "Qwen is ready."
}
```

---

## GET `/splunk-ai-status` - Check Splunk AI Instruct

```bash
curl http://localhost:8001/splunk-ai-status
```

**Response**:
```json
{
  "splunk_ai_available": true,
  "splunk_ai_online": true,
  "hint": "Splunk AI Instruct is ready."
}
```

---

## GET `/ioc-stats` - Threat Intelligence Statistics

```bash
curl "http://localhost:8001/ioc-stats" \
  -H "X-API-Key: your-secret-key"
```

**Response**:
```json
{
  "ioc_counts_by_type": {
    "ip": 234,
    "domain": 156,
    "hash": 891,
    "url": 432
  }
}
```

---

# 📋 Common Patterns

## Example 1: Send Multiple Events at Once

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "SERVER-DB-01",
    "user_id": "admin",
    "events": [
      {"event_type": "process_spawn", "command_line": "whoami /priv"},
      {"event_type": "process_spawn", "command_line": "net user /domain"},
      {"event_type": "process_spawn", "command_line": "vssadmin delete shadows /all"},
      {"event_type": "file_write", "path": "C:\\data\\records.xlsx.ryuk"},
      {"event_type": "network_connection", "destination": "185.220.101.10", "bytes_sent": 1048576}
    ]
  }'
```

## Example 2: Get All HIGH/CRITICAL Alerts

```bash
# Get HIGH severity alerts from last 8 hours
curl "http://localhost:8001/alerts?threat=HIGH&since_minutes=480" \
  -H "X-API-Key: your-secret-key" | python -m json.tool
```

## Example 3: Monitor Queue Depth

```bash
# Check if system is overloaded
curl http://localhost:8001/health | grep queue_depth
```

---

# 🚨 Error Responses

### 401 Unauthorized
```json
{"detail": "Invalid or missing X-API-Key header."}
```

### 400 Bad Request
```json
{"detail": "Invalid payload format"}
```

### 404 Not Found
```json
{"detail": "not found"}
```

### 500 Server Error
```json
{"detail": "Internal server error"}
```

---

# 💡 Tips

1. **For debugging**: Use `curl -v` to see full request/response
2. **For pretty output**: Pipe to `python -m json.tool` or `jq`
3. **For testing**: Use tools like Postman or Insomnia
4. **For production**: Use client libraries like `requests` in Python or `axios` in JavaScript

---

# 🔗 Example Client Code

### Python
```python
import requests

API_KEY = "your-secret-key"
BASE_URL = "http://localhost:8001"

# Send event
response = requests.post(
    f"{BASE_URL}/ingest",
    headers={"X-API-Key": API_KEY},
    json={
        "host_id": "LAPTOP-001",
        "user_id": "admin",
        "events": [
            {"event_type": "process_spawn", "command_line": "powershell -enc ABC..."}
        ]
    }
)
print(response.json())

# Get alerts
response = requests.get(
    f"{BASE_URL}/alerts?threat=HIGH",
    headers={"X-API-Key": API_KEY}
)
for alert in response.json()["alerts"]:
    print(f"Alert: {alert['incident_id']} - Score: {alert['score']}")
```

---

**For more examples, see EXAMPLES.md and QUICKSTART.md**
