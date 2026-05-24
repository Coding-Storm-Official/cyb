def generate_ai_feed(risk_result, events):
    feed = []

    for rule in risk_result["triggered_rules"]:
        feed.append({
            "type": "AI DETECTED",
            "message": rule
        })

    feed.append({
        "type": "AI REASONING",
        "message": f"Confidence score: {risk_result['score']}/165 — {risk_result['threat_level']} threat level"
    })

    feed.append({
        "type": "PREDICTION",
        "message": risk_result["prediction"]
    })

    if risk_result["score"] >= 80:
        feed.append({
            "type": "AUTONOMOUS ACTION",
            "message": "Deploying deception credentials and isolating endpoint..."
        })
    elif risk_result["score"] >= 50:
        feed.append({
            "type": "AUTONOMOUS ACTION",
            "message": "Deploying honeytokens and increasing monitoring..."
        })

    return feed