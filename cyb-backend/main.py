from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from splunk_connector import get_ransomware_events
from risk_engine import calculate_risk
from ai_reasoning import generate_ai_feed

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