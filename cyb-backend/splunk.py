from __future__ import annotations
import os
import time
import logging
import requests
import urllib3
from typing import List, Dict, Any
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("xdr.splunk")

SPLUNK_HOST     = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT     = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_TOKEN    = os.getenv("SPLUNK_TOKEN", "")
BASE_URL        = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def _auth():
    if SPLUNK_TOKEN:
        return None, {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    return (SPLUNK_USERNAME, SPLUNK_PASSWORD), {}

def _get(path: str, params: dict = None) -> dict:
    auth, headers = _auth()
    r = requests.get(
        f"{BASE_URL}{path}", auth=auth, headers=headers,
        params={**(params or {}), "output_mode": "json"},
        verify=False, timeout=15
    )
    r.raise_for_status()
    return r.json()

def _post(path: str, data: dict) -> dict:
    auth, headers = _auth()
    r = requests.post(
        f"{BASE_URL}{path}", auth=auth, headers=headers,
        data={**data, "output_mode": "json"},
        verify=False, timeout=15
    )
    r.raise_for_status()
    return r.json()

def _run_search(spl: str, earliest: str = "-15m", latest: str = "now") -> List[Dict]:
    try:
        resp = _post("/services/search/jobs", {
            "search": spl,
            "earliest_time": earliest,
            "latest_time": latest,
        })
        sid = resp["sid"]
        for _ in range(120):
            status = _get(f"/services/search/jobs/{sid}")
            state = status["entry"][0]["content"]["dispatchState"]
            if state == "DONE":
                break
            if state in ("FAILED", "CANCELED"):
                logger.error(f"[Splunk] Job {sid} ended with state: {state}")
                return []
            time.sleep(0.5)
        results = _get(f"/services/search/jobs/{sid}/results")
        return results.get("results", [])
    except Exception as e:
        logger.error(f"[Splunk] Search failed: {e}")
        return []

def get_ransomware_events(earliest: str = "-15m") -> List[Dict]:
    spl = (
        f'search earliest={earliest} source="ransomware.txt" '
        '| table _time host user process action command type target '
        '  file_path new_path bytes_sent bytes_recv remote_address '
        '  integrity_level registry_key event_type'
    )
    return _run_search(spl, earliest=earliest)

def get_process_events(earliest: str = "-15m") -> List[Dict]:
    spl = (
        f'search earliest={earliest} sourcetype=WinEventLog:Security EventCode=4688 '
        '| table _time host user process parent_process command_line integrity_level'
    )
    return _run_search(spl, earliest=earliest)

def get_file_events(earliest: str = "-15m") -> List[Dict]:
    spl = (
        f'search earliest={earliest} sourcetype=WinEventLog:Security EventCode IN (4663,4656) '
        '| table _time host user file_path action bytes_written'
    )
    return _run_search(spl, earliest=earliest)

def get_network_events(earliest: str = "-15m") -> List[Dict]:
    spl = (
        f'search earliest={earliest} sourcetype=WinEventLog:Security EventCode=5156 '
        '| table _time host user remote_address bytes_sent bytes_recv protocol'
    )
    return _run_search(spl, earliest=earliest)

def get_auth_events(earliest: str = "-15m") -> List[Dict]:
    spl = (
        f'search earliest={earliest} sourcetype=WinEventLog:Security '
        'EventCode IN (4624,4625,4648,4768,4769) '
        '| table _time host user event_code logon_type failure_reason remote_address'
    )
    return _run_search(spl, earliest=earliest)

def get_all_events(earliest: str = "-15m") -> List[Dict]:
    combined = []
    for fn in (get_ransomware_events, get_process_events, get_file_events,
               get_network_events, get_auth_events):
        try:
            combined.extend(fn(earliest=earliest))
        except Exception as e:
            logger.warning(f"[Splunk] Partial fetch error ({fn.__name__}): {e}")
    return combined

def ping() -> bool:
    try:
        _get("/services/server/info")
        return True
    except Exception:
        return False