import os
import requests
from dotenv import load_dotenv
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

os.chdir(r'C:\Users\18604\OneDrive\Masaüstü\blue')
load_dotenv('.env')

os_url = f"https://{os.environ.get('OPENSEARCH_HOST')}:9200"
os_user = os.environ.get('OPENSEARCH_USER')
os_pass = os.environ.get('OPENSEARCH_PASSWORD')

query = {
    "size": 2,
    "sort": [{"timestamp": {"order": "desc"}}],
    "query": {
        "range": {
            "rule.level": {"gte": 12}
        }
    }
}

requests.packages.urllib3.disable_warnings() 
response = requests.post(
    f"{os_url}/wazuh-alerts-*/_search", 
    auth=(os_user, os_pass), 
    verify=False, 
    json=query
)

hits = response.json().get('hits', {}).get('hits', [])

print("--- AI SOC ANALYST INVESTIGATION REPORT ---")
if not hits:
    print("No critical alerts found.")
else:
    for h in hits:
        s = h['_source']
        r = s.get('rule', {})
        print(f"\n=> CRITICAL ALERT: [Rule {r.get('id')}] {r.get('description')} on Agent: {s.get('agent', {}).get('name')}")
        print(f"   Severity Level: {r.get('level')}")
        print(f"   Timestamp: {s.get('timestamp')}")
        
        # Deep telemetry parsing for 'net user'
        win_data = s.get('data', {}).get('win', {})
        sys_data = win_data.get('system', {})
        event_data = win_data.get('eventData', {})
        
        if event_data:
            print(f"   Command Executed: {event_data.get('commandLine', 'N/A')}")
            print(f"   Target User: {event_data.get('targetUserName', 'N/A')}")
        
        if sys_data:
            print(f"   Subject User: {sys_data.get('securityUserID', 'N/A')}")
            
        mitre = r.get('mitre', {})
        if mitre:
            tactics = mitre.get('tactic', [])
            print(f"   Mitre Tactics: {', '.join(tactics) if isinstance(tactics, list) else tactics}")
        print("-" * 50)
