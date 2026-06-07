# 🛡️ AI SOC Platform - Automatic Threat Detection System

## What Is This? (In Plain English)

Think of this as a **24/7 Security Guard for your company's computers**.

Imagine you have thousands of computers at your company. Hackers could be attacking any of them right now. A human security team can't watch all of them at once. **This system is an AI guard that watches everything, 24/7, and immediately alerts you when something suspicious happens.**

---

## 🎯 What Can This System Do?

### It Can Detect:

1. **Ransomware Attacks** 🔒
   - When files are being encrypted and locked
   - When backups are being deleted to prevent recovery

2. **Hackers Trying to Take Over Accounts** 👤
   - Password dump attempts (stealing credentials)
   - Permission escalation (gaining admin access)

3. **Data Theft** 📤
   - When employees or hackers steal and send out company data
   - Suspicious downloads and uploads

4. **Hackers Spreading Across Your Network** 🌐
   - When someone moves from one computer to another
   - Unauthorized remote access attempts

5. **Backdoors and Persistence** 🚪
   - When hidden access points are being installed
   - Scheduled tasks or system changes that allow future access

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Install Python Packages

```bash
pip install -r requirements.txt
```

### Step 2: Start the System

```bash
python main.py
```

You'll see:
```
[Startup] Initialising XDR engine...
[Startup] Engine ready.
```

### Step 3: Test It

Open another terminal and send a test alert:

```bash
curl -X POST http://localhost:8001/ingest \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "laptop-001",
    "user_id": "john.doe",
    "events": [
      {
        "event_type": "process_spawn",
        "command_line": "powershell.exe -enc AGMAZQBUA..."
      }
    ]
  }'
```

The system will analyze it and create an alert!

---

## 📊 How Does It Work?

### The Simple Version:

1. **Collect** - Events from all computers come in
2. **Analyze** - AI checks if behavior is normal or suspicious
3. **Score** - Assigns a threat score (0-100)
4. **Alert** - If score is high, create an alert
5. **Act** - Recommend actions (isolate computer, etc.)

### The Smart Part:

The system doesn't just use one AI model. It uses **5 different AI models** working together:

- **Model 1**: Finds unusual patterns (Isolation Forest)
- **Model 2**: Learns from past attacks (Random Forest)
- **Model 3**: Detects attack sequences (Gradient Boosting)
- **Model 4**: Neural network pattern matching
- **Model 5**: Linear decision boundaries

All 5 vote on whether something is a threat. This makes false alarms much less likely.

---

## 🧬 What Does "Events" Mean?

An **event** is something that happened on a computer. For example:

```json
{
  "event_type": "process_spawn",
  "command_line": "powershell.exe -enc ABC123...",
  "host": "DESKTOP-001",
  "user": "admin"
}
```

Or:

```json
{
  "event_type": "file_write",
  "path": "C:\\Users\\admin\\Documents\\important.docx.encrypted",
  "host": "DESKTOP-001"
}
```

The system watches for **40 different types of suspicious patterns** in these events.

---

## 📈 What's a "Score"?

The system gives each suspicious activity a **threat score from 0 to 100**:

- **0-35**: Normal activity ✅
- **35-65**: Slightly suspicious ⚠️
- **65-75**: Probably a threat 🔴
- **75-90**: Very likely a threat 🔴🔴
- **90+**: Almost certainly an attack 🔴🔴🔴

---

## 🔄 The Feedback Loop

This system has a special **feedback loop**:

1. **Initial Detection**: Detects suspicious activity
2. **Splunk AI Context**: Asks Splunk "Is this really a threat?"
3. **Qwen Analysis**: Asks AI assistant "What should we do?"
4. **New Hunt Query**: Automatically searches for similar attacks
5. **Refinement**: Scores get better and better

This means it keeps getting smarter the more it sees.

---

## 📱 API Endpoints (For Developers)

### Check Health
```
GET /health
```
Returns: Is the system running? How many events in queue?

### Send Events
```
POST /ingest
```
Send events from your computers for analysis.

### Get Threat Level
```
GET /threat-level
```
Get current overall threat assessment.

### Get Alerts
```
GET /alerts
```
List all recent alerts.

### Explain a Threat
```
GET /explain-threat/{incident_id}
```
Get a human-friendly explanation of why something was flagged.

---

## 🔗 Connecting to Splunk

If you have **Splunk** installed (a security data platform):

1. Set these environment variables:
```bash
export SPLUNK_HOST=your-splunk-server.com
export SPLUNK_PORT=8089
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=yourpassword
```

2. The system will automatically pull events from Splunk

3. It will analyze them using this AI system

4. Alerts go back to Splunk for your team to see

See `SPLUNK_INTEGRATION.md` for detailed instructions.

---

## ⚙️ Configuration (Environment Variables)

```bash
# API Security
export XDR_API_KEY=your-secret-key

# Splunk Connection
export SPLUNK_HOST=localhost
export SPLUNK_PORT=8089
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=password

# Qwen AI (Optional - for threat analysis)
export QWEN_HOST=http://localhost:11434
export QWEN_MODEL=qwen2.5

# Server Settings
export HOST=0.0.0.0
export PORT=8001
```

---

## 📚 Documentation Files

- **README.md** ← You are here
- **ARCHITECTURE.md** - Technical deep dive
- **QUICKSTART.md** - Step-by-step setup guide
- **SPLUNK_INTEGRATION.md** - How to use with Splunk
- **DEPLOYMENT.md** - How to deploy to production
- **API_GUIDE.md** - Complete API reference
- **EXAMPLES.md** - Real-world attack examples

---

## 🧪 Test It Yourself

Run the built-in test:

```bash
python ml.py
```

This will simulate a real ransomware attack and show you how the system detects it.

---

## 🎓 Learning Resources

### Understand the Threat Detection

1. Read `ARCHITECTURE.md` for how it all works
2. Check `EXAMPLES.md` to see real attack patterns
3. Look at `ml.py` line-by-line (it's well-commented)

### Understand the MITRE Framework

The system uses **MITRE ATT&CK** framework - a library of real attacker tactics:

- **T1003** = Stealing credentials
- **T1486** = Ransomware encryption
- **T1021** = Lateral movement
- etc.

Each detected threat gets tagged with MITRE IDs so you know exactly what type of attack it is.

---

## 🚨 Alert Examples

When something suspicious happens, you get an alert like this:

```json
{
  "incident_id": "INC-ABC123XYZ",
  "host_id": "DESKTOP-JOHN",
  "user_id": "john.doe",
  "score": 87.5,
  "threat": "HIGH",
  "behavior_tags": ["RANSOMWARE", "SHADOW_COPY_DELETION"],
  "actions": ["ISOLATE_HOST", "BLOCK_EGRESS", "DEPLOY_HONEYTOKENS"],
  "mitre": ["T1486", "T1490"],
  "next_stage": "Impact"
}
```

In plain English:
> **Alert: John's computer (DESKTOP-JOHN) is being hit by ransomware. Threat score: 87.5/100. Recommended: Isolate the computer immediately, block outgoing connections, and prepare to trick the attacker.**

---

## ❓ FAQ

**Q: Will this create false alarms?**
A: The system uses 5 AI models voting together, plus signature-based detection, to minimize false positives. Some will still occur - that's normal. Your team can mark them as false positives to improve the system.

**Q: How many events can it handle?**
A: With default settings, about 50,000 events in the queue. Each worker thread processes events in parallel. You can scale with more threads.

**Q: Do I need Splunk?**
A: No! You can send events directly via the API. Splunk integration is optional but recommended for large deployments.

**Q: How fast is it?**
A: Threat scoring takes ~10-50ms per event. Alerts are generated in real-time.

**Q: What if I disagree with an alert?**
A: Mark it as a false positive! The system learns from your feedback and adjusts.

---

## 📞 Support

- Check `EXAMPLES.md` for common attack scenarios
- Check `SPLUNK_INTEGRATION.md` if using Splunk
- Check `API_GUIDE.md` for API details
- Read the code comments - they explain how things work

---

## 🏆 This System Wins Because:

✅ **AI-Powered**: Uses 5 machine learning models, not just rules
✅ **Explains Threats**: Not a black box - tells you WHY something is suspicious
✅ **Learns Over Time**: Gets smarter with more data
✅ **Splunk Integration**: Works seamlessly with enterprise security tools
✅ **Production-Ready**: Error handling, logging, monitoring built-in
✅ **Easy to Understand**: Documentation for non-technical people
✅ **Fast**: Real-time threat detection
✅ **Extensible**: Easy to add new detection rules or models

---

**Ready to secure your systems? Start with QUICKSTART.md!**
