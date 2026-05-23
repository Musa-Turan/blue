import requests
import os
from dotenv import load_dotenv

load_dotenv()
import warnings
import json
warnings.filterwarnings('ignore')

url_auth = f"https://{os.environ.get('WAZUH_MANAGER_IP', '127.0.0.1')}:55000/security/user/authenticate"
auth = (os.environ.get('WAZUH_API_USER', 'wazuh-wui'), os.environ.get('WAZUH_API_PASSWORD', ''))
response = requests.post(url_auth, auth=auth, verify=False, timeout=5)
token = response.json().get('data', {}).get('token')

url_agents = f"https://{os.environ.get('WAZUH_MANAGER_IP', '127.0.0.1')}:55000/agents?limit=10"
headers = {'Authorization': f'Bearer {token}'}
resp = requests.get(url_agents, headers=headers, verify=False, timeout=5)
data = resp.json().get('data', {}).get('affected_items', [])

print("AJAN DURUMLARI:")
for agent in data:
    print(f"[{agent.get('id')}] {agent.get('name')} - Status: {agent.get('status')} - IP: {agent.get('ip')}")
