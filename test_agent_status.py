import requests
import warnings
import json
warnings.filterwarnings('ignore')

url_auth = 'https://192.168.1.38:55000/security/user/authenticate'
auth = ('wazuh-wui', '.+jSKgf3IR3janqE2pWL+USnaQ6MeWxV')
response = requests.post(url_auth, auth=auth, verify=False, timeout=5)
token = response.json().get('data', {}).get('token')

url_agents = 'https://192.168.1.38:55000/agents?limit=10'
headers = {'Authorization': f'Bearer {token}'}
resp = requests.get(url_agents, headers=headers, verify=False, timeout=5)
data = resp.json().get('data', {}).get('affected_items', [])

print("AJAN DURUMLARI:")
for agent in data:
    print(f"[{agent.get('id')}] {agent.get('name')} - Status: {agent.get('status')} - IP: {agent.get('ip')}")
