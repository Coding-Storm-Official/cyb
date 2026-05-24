import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8000")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "changeme")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def get_ransomware_events():
    search_query = 'search source="ransomware.txt" | table _time host user process action command type target'

    try:
        response = requests.post(
            f"{BASE_URL}/services/search/jobs",
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data={"search": search_query, "output_mode": "json"},
            verify=False
        )
        sid = response.json()["sid"]

        while True:
            status = requests.get(
                f"{BASE_URL}/services/search/jobs/{sid}",
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                params={"output_mode": "json"},
                verify=False
            ).json()
            if status["entry"][0]["content"]["dispatchState"] == "DONE":
                break
            time.sleep(0.5)

        results = requests.get(
            f"{BASE_URL}/services/search/jobs/{sid}/results",
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            params={"output_mode": "json"},
            verify=False
        ).json()

        return results.get("results", [])

    except Exception as e:
        print(f"Splunk error: {e}")
        return