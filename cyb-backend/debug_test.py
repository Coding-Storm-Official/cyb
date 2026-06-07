#!/usr/bin/env python3
"""Debug: Check current alerts"""
import requests
import json

response = requests.get(
    'http://localhost:8001/alerts?since_minutes=60',
    headers={'X-API-Key': 'test123'},
    timeout=10
)

print('Status:', response.status_code)
data = response.json()
print(f'Total alerts: {data.get("count", 0)}')
if data.get('alerts'):
    for i, alert in enumerate(data['alerts'][:3]):  # Show first 3
        print(f'\nAlert {i+1}:')
        print(f"  ID: {alert.get('incident_id')}")
        print(f"  Score: {alert.get('score')}")
        print(f"  Threat: {alert.get('threat')}")
        print(f"  Host: {alert.get('host_id')}")
else:
    print('No alerts found in last 60 minutes')

