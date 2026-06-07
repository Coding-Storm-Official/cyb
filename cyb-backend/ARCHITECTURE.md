# 🏗️ System Architecture & How It Works

## Overview

The AI SOC Platform is built around a real-time threat detection pipeline that processes security events and assigns threat scores using machine learning.

---

## High-Level Data Flow

```
┌─────────────────┐
│ Security Events │  (Process spawns, file writes, network connections)
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ FastAPI Server (main.py)│  (Receives events via HTTP, validates API key)
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Feature Extraction      │  (Converts events to 40 numerical features)
│ (ml.py - features())    │  (Process rates, entropy, file activity, etc.)
└────────┬────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 5 Machine Learning Models    │  (All vote on threat level)
│ - Isolation Forest (anomaly) │  - Weights combined for final score
│ - Random Forest              │
│ - Gradient Boosting          │
│ - Neural Network             │
│ - Linear Classifier          │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Rule Matching & IOC Check│  (Signature-based detection)
│ (15 MITRE-mapped rules)  │  (Known malware, C2, etc.)
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Behavior Classification  │  (Tags the attack: ransomware, lateral move, etc.)
│ (Attack stage prediction)│  (Predicts next likely attack phase)
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│ Alert Generation         │  (Creates incident record)
│ & Publishing             │  (Stores in DB, Kafka, webhook)
└──────────────────────────┘
```

---

## Core Components

### 1. **main.py** - FastAPI Web Server

**Purpose**: REST API for receiving events and querying alerts

**Key Endpoints**:
```
GET  /           - Health check
POST /ingest     - Send events for analysis
GET  /ml-analyze - Analyze Splunk events with ML
GET  /alerts     - Get all recent alerts
GET  /explain-threat/{id} - Explain why something was flagged
POST /feedback-loop - Full analysis cycle (Splunk→AI→Splunk)
```

**What It Does**:
- Validates API keys
- Marshals events into the Engine
- Handles Splunk integration
- Returns results in JSON

---

### 2. **ml.py** - Core Detection Engine

**Key Classes**:

#### `Engine` (Main orchestrator)
- Manages worker threads (process events in parallel)
- Buffers events per host (keeps 10,000 most recent events)
- Coordinates feature extraction, scoring, and alerting
- Stores alerts in SQLite database

#### `DetectionPipeline` (5 models voting)
- **Isolation Forest**: Finds statistical anomalies
- **Random Forest**: Pattern recognition from training data
- **Gradient Boosting**: Sequential decision making
- **MLP (Neural Net)**: Complex pattern matching
- **SGD**: Fast linear classification

Scores are weighted:
```
Final Score = (ISO×0.15) + (RF×0.30) + (GBM×0.25) + (MLP×0.20) + (SGD×0.10)
```

#### Feature Extraction (`Engine.features()`)
Builds a 40-dimensional feature vector from events:

**Process Features** (5m and 1m windows):
- `proc_rate_1m`, `proc_rate_5m` - How many new processes?
- `cmd_entropy_avg` - Are commands obfuscated?
- `cmd_avg_len` - Unusual command lengths?

**Reconnaissance Features**:
- `recon_count` - whoami, net user, nltest commands?
- `uac_hits` - UAC bypass attempts?
- `lsass_hits` - Credential dumping attempts?

**File Activity Features**:
- `file_write_rate_1m/5m` - Rapid file creation?
- `file_delete_rate_5m` - Mass deletion?
- `encrypt_ext_hits` - .locked, .ryuk, .conti extensions?
- `entropy_spike_count` - High entropy (encrypted) content?

**Network Features**:
- `net_bytes_out_mb` - Data exfiltration?
- `suspicious_dns` - Known bad domains?
- `net_unique_destinations` - How many IPs contacted?

**Advanced Features**:
- `lateral_spread` - Lateral movement attempts?
- `persistence_hits` - Registry/task scheduler modifications?
- `shadow_delete_hits` - Backup deletion attempts?
- `integrity_jump_hits` - Token elevation or privilege escalation?

#### Rule-Based Detection (`Engine.rules()`)
15 signature-based rules for known attack patterns:

```
SIG-001 (T1003): LSASS dumping patterns
SIG-002 (T1070): Event log clearing
SIG-003 (T1489): Disabling security services
SIG-004 (T1021): Lateral movement tools
SIG-005 (T1486): Ransomware file extensions
SIG-006 (T1059): Encoded PowerShell
SIG-007 (T1547): Registry persistence
SIG-008 (T1053): Scheduled task creation
SIG-009 (T1112): Registry modification
SIG-010 (T1078): Account enumeration
SIG-011 (T1055): Process injection APIs
SIG-012 (T1486): Shadow copy deletion
SIG-013 (T1041): Download/exfiltration tools
SIG-014 (T1083): Directory enumeration
SIG-015 (T1074): File staging for exfiltration
```

---

### 3. **splunk.py** - Splunk Integration

**Functions**:
```python
get_ransomware_events(earliest)  # Ransomware-specific queries
get_process_events(earliest)     # Process creation logs
get_file_events(earliest)        # File access logs
get_network_events(earliest)     # Network connection logs
get_auth_events(earliest)        # Authentication logs
get_all_events(earliest)         # Combined from all above
```

**How It Works**:
1. Uses Splunk REST API
2. Runs SPL (Splunk Search Language) queries
3. Converts Splunk field names to Engine format
4. Returns as list of dicts for analysis

---

### 4. **risk_engine.py** - Rule-Based Risk Scoring

**Alternative** to ML - uses weighted rules if Splunk data doesn't have ML fields.

**Risk Calculation**:
```python
score = 0
for each process in event:
    if process == "mimikatz.exe": score += 5
    if process == "vssadmin.exe": score += 3
    # ... etc
# Normalize to 0-100
```

**Behavior Tags**:
Converts score into readable tags:
- "RANSOMWARE" if high file activity + encryption extensions
- "LATERAL_MOVEMENT" if command execution on remote systems
- "PRIVILEGE_ESCALATION" if LSASS access or UAC bypass
- etc.

---

### 5. **qwen.py** & **splunk_ai.py** - AI Analysis

**Optional AI Enhancement**:
- Qwen 2.5 LLM for threat analysis explanations
- Splunk AI Instruct for contextual queries
- Feedback loop: detect → explain → hunt → refine

---

## Threat Scoring Algorithm

### Step 1: Feature Vector
Extract 40 numbers from events (one per feature type)

### Step 2: ML Scoring
```
iso_score = isolation_forest.anomaly_score(features)      # 0-100
rf_score = random_forest.predict_proba(features)           # 0-100
gbm_score = gradient_boosting.predict_proba(features)      # 0-100
mlp_score = neural_network.predict_proba(features)         # 0-100
sgd_score = linear_classifier.predict_proba(features)      # 0-100

ml_score = (iso×0.15) + (rf×0.30) + (gbm×0.25) + (mlp×0.20) + (sgd×0.10)
```

### Step 3: Rule Matching
If any signature rules match → boost score, add tags

### Step 4: IOC Matching
If any indicators of compromise match → boost score

### Step 5: Final Alert
```
if ml_score >= 65:
    create alert with:
    - incident_id (unique ID)
    - host_id (which computer)
    - user_id (which user)
    - score (0-100)
    - threat (LOW/MEDIUM/HIGH/CRITICAL)
    - rules (which signatures matched)
    - mitre (attack framework IDs)
    - iocs (known bad indicators found)
    - behavior_tags (what type of attack)
    - actions (recommended response)
```

---

## Database Schema (SQLite)

### Table: `alerts`
```
id TEXT PRIMARY KEY        - Unique incident ID
payload TEXT               - Full alert JSON
ts REAL                    - Unix timestamp
threat TEXT                - Threat level
score REAL                 - 0-100 threat score
```

### Table: `telemetry`
```
sig TEXT PRIMARY KEY       - Event signature (dedup key)
ts REAL                    - When seen
```

---

## Threading & Performance

**Worker Threads** (default 4):
- Each thread pulls events from queue
- Extracts features (takes ~10ms per event)
- Scores with ML (takes ~20ms per event)
- Matches rules (takes ~5ms per event)
- Stores alert if score >= threshold

**Queue**: 200,000 events max (prevents memory exhaustion)

**Buffering**: Per-host ring buffer (10,000 events per host)
- Allows 5-minute window analysis
- Enables rate calculations (processes/sec)

---

## Attack Detection: Real Example

**Scenario**: User runs ransomware

**Event Stream**:
```
1. process_spawn: "whoami /priv"              → recon_count += 1
2. process_spawn: "net user /domain"          → recon_count += 1
3. process_spawn: "vssadmin delete shadows"   → triggers SIG-012, shadow_delete_hits += 1
4. file_write: "C:\data\file.docx.ryuk"       → encrypt_ext_hits += 1
5. file_write: "C:\data\file.xlsx.ryuk"       → encrypt_ext_hits += 1
6. network_flow: "185.220.101.10" (1GB sent)  → net_bytes_out_mb = 1000
```

**Feature Vector** (40 dimensions):
```
[
  0.05,      # proc_rate_1m
  0.10,      # proc_rate_5m
  4.2,       # cmd_entropy_avg
  25.5,      # cmd_avg_len
  2,         # recon_count ← Non-zero
  0,         # encoded_ps
  0,         # service_mods
  0,         # log_clear
  0,         # lsass_hits
  0,         # uac_hits
  0,         # lateral_spread
  ...
  2,         # encrypt_ext_hits ← Non-zero
  0,         # entropy_spike_count
  1,         # shadow_delete_hits ← Non-zero
  ...
  1000,      # net_bytes_out_mb ← High!
]
```

**Scoring**:
```
ML Models vote:
  - Isolation Forest: 82/100 (anomalous behavior)
  - Random Forest: 75/100 (matches attack patterns)
  - Gradient Boosting: 88/100 (sequence is malicious)
  - Neural Net: 79/100 (pattern match)
  - Linear: 71/100 (suspicious features)

Weighted: (82×0.15) + (75×0.30) + (88×0.25) + (79×0.20) + (71×0.10) = 79.6/100
```

**Rules Match**:
```
SIG-005 triggered: Ransomware extension (.ryuk)
SIG-012 triggered: Shadow copy deletion
→ Add tags: RANSOMWARE, SHADOW_COPY_DELETION
→ Boost score to 85/100
```

**Final Alert**:
```json
{
  "incident_id": "INC-A7F3B2C1",
  "host_id": "DESKTOP-USER",
  "user_id": "user@company.com",
  "score": 85.2,
  "threat": "HIGH",
  "behavior_tags": ["RANSOMWARE", "SHADOW_COPY_DELETION"],
  "actions": ["ISOLATE_HOST", "BLOCK_EGRESS", "DEPLOY_HONEYTOKENS"],
  "mitre": ["T1486", "T1490"],
  "rules": ["SIG-005", "SIG-012"],
  "next_stage": "Impact"
}
```

---

## Drift Detection (PSI - Population Stability Index)

The system **retrains automatically** when it detects data drift:

1. Periodically compares recent events to baseline
2. Calculates PSI (Population Stability Index)
3. If PSI > 0.25 → Triggers retrain
4. Retrains all 5 models with new data
5. Updates feature distributions

This keeps the system accurate as attacker behavior evolves.

---

## Confidence & Explainability

**Three Layers of Explanation**:

1. **ML Explanation** (via `explain_score()`)
   - Which models voted HIGH vs LOW?
   - What's the consensus?

2. **Feature Explanation** (via `explain_features()`)
   - Which of the 40 features are driving the score?
   - Top 10 feature contributions

3. **Behavior Explanation** (via `/explain-threat`)
   - Plain English: "This looks like ransomware because..."
   - Human-friendly threat summary

---

## Scalability Considerations

**Current Setup**:
- Single machine, ~4 worker threads
- 200K queue size
- SQLite for storage

**To Scale Up**:
1. Add more worker threads (change `XDR_WORKERS` env var)
2. Use Kafka for distributed queue
3. Use Redis for caching
4. Switch to PostgreSQL for multi-node alerts
5. Add load balancer for multiple API servers

---

## Security Features

- **API Key Authentication**: `X-API-Key` header required
- **HMAC Signing**: Payloads signed with `XDR_SECRET`
- **Deduplication**: Same event not processed twice
- **False Positive Feedback**: Analysts can mark alerts as FP
- **Encrypted Connections**: TLS to Splunk (if configured)

---

This architecture makes the system:
- ✅ **Fast** (parallel processing, caching)
- ✅ **Accurate** (5 models voting, rules + ML)
- ✅ **Scalable** (threaded, queue-based)
- ✅ **Explainable** (shows reasoning)
- ✅ **Learnable** (retrains on drift)
