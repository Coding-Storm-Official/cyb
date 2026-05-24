from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from splunk import get_ransomware_events
from risk_engine import calculate_risk
from ai_reasoning import generate_ai_feed
from ml import analyze_with_ml

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"status": "AI SOC Backend Running"}

@app.get("/events")
def get_events():
    events = get_ransomware_events()
    return {"events": events, "count": len(events)}

@app.get("/analyze")
def analyze():
    events = get_ransomware_events()
    risk = calculate_risk(events)
    ai_feed = generate_ai_feed(risk, events)
    return {
        "events": events,
        "risk_analysis": risk,
        "ai_feed": ai_feed
    }

@app.get("/threat-level")
def threat_level():
    events = get_ransomware_events()
    risk = calculate_risk(events)
    return {
        "threat_level": risk["threat_level"],
        "score": risk["score"],
        "prediction": risk["prediction"]
    }

@app.get("/ml-analyze")
def ml_analyze():
    events = get_ransomware_events()
    result = analyze_with_ml(events)
    return result
@app.get("/debug-splunk")
def debug_splunk():
    import requests
    import os
    try:
        r = requests.get(
            f"https://localhost:8089/services/search/jobs",
            auth=(os.getenv("SPLUNK_USERNAME", "admin"), os.getenv("SPLUNK_PASSWORD", "changeme")),
            verify=False,
            timeout=5
        )
        return {"status": r.status_code, "response": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}