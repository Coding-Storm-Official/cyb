import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_PATH = "ransomware_model.pkl"
SCALER_PATH = "ransomware_scaler.pkl"

NORMAL_BEHAVIOR = [
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 1],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 1],
    [0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
]

RANSOMWARE_BEHAVIOR = [
    [1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 0],
    [1, 1, 1, 0, 1, 1],
    [1, 1, 0, 1, 1, 1],
    [1, 0, 1, 1, 1, 1],
    [1, 1, 1, 1, 0, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 1, 0, 1, 1, 0],
    [1, 0, 1, 1, 0, 1],
    [1, 1, 1, 0, 1, 1],
    [0, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 0],
    [1, 1, 0, 1, 1, 1],
    [1, 0, 1, 1, 1, 0],
    [1, 1, 1, 1, 0, 1],
    [1, 1, 1, 0, 1, 1],
    [1, 1, 1, 1, 1, 1],
    [1, 0, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 0],
    [1, 1, 0, 1, 0, 1],
]


def extract_features(events):
    processes = [e.get("process", "") for e in events]
    actions = [e.get("action", "") for e in events]

    return [
        1 if "powershell.exe" in processes else 0,
        1 if "vssadmin.exe" in processes else 0,
        1 if "malware.exe" in processes else 0,
        1 if "psexec.exe" in processes else 0,
        1 if "file_write" in actions else 0,
        1 if "lateral_move" in actions else 0,
    ]


def train_model():
    X_normal = np.array(NORMAL_BEHAVIOR)
    X_attack = np.array(RANSOMWARE_BEHAVIOR)
    X_train = np.vstack([X_normal, X_attack])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.28,
        max_features=1.0,
        bootstrap=False,
        random_state=42
    )
    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("Model trained and saved.")


def load_model():
    if not os.path.exists(MODEL_PATH):
        train_model()
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler


def analyze_with_ml(events):
    model, scaler = load_model()
    features = extract_features(events)
    X = np.array([features])
    X_scaled = scaler.transform(X)

    prediction = model.predict(X_scaled)[0]
    raw_score = model.decision_function(X_scaled)[0]

    confidence = round((1 - (raw_score + 0.5)) * 100, 2)
    confidence = max(0, min(confidence, 100))

    is_anomaly = prediction == -1

    active_features = []
    feature_names = [
        "PowerShell execution",
        "Shadow copy deletion",
        "Malware process",
        "PsExec lateral movement",
        "File encryption",
        "Lateral move action"
    ]
    for i, val in enumerate(features):
        if val == 1:
            active_features.append(feature_names[i])

    if is_anomaly and confidence >= 75:
        stage = "RANSOMWARE CONFIRMED"
        action = "Emergency isolation triggered. Deception credentials deployed."
    elif is_anomaly and confidence >= 50:
        stage = "ATTACK IN PROGRESS"
        action = "Endpoint flagged. SMB disabled. Monitoring escalated."
    elif is_anomaly:
        stage = "SUSPICIOUS ACTIVITY"
        action = "Increased logging. SOC team notified."
    else:
        stage = "NORMAL BEHAVIOR"
        action = "No action required."

    return {
        "is_anomaly": is_anomaly,
        "confidence": confidence,
        "stage": stage,
        "recommended_action": action,
        "active_indicators": active_features,
        "raw_isolation_score": round(float(raw_score), 4)
    }