import requests
import warnings
import json
warnings.filterwarnings('ignore')

url_auth = 'https://192.168.1.38:55000/security/user/authenticate'
auth = ('wazuh-wui', '.+jSKgf3IR3janqE2pWL+USnaQ6MeWxV')
response = requests.post(url_auth, auth=auth, verify=False, timeout=5)
token = response.json().get('data', {}).get('token')

headers = {'Authorization': f'Bearer {token}'}

# Check Rules
print("--- KURAL KONTROLU (100010, 100011) ---")
url_rules = 'https://192.168.1.38:55000/rules?rule_ids=100010,100011'
resp_rules = requests.get(url_rules, headers=headers, verify=False, timeout=5)
print(json.dumps(resp_rules.json().get('data', {}).get('affected_items', []), indent=2))

# Check Agent Config
print("\n--- AJAN KONTROLU (001 - localfile) ---")
url_conf = 'https://192.168.1.38:55000/agents/001/config/localfile/localfile'
resp_conf = requests.get(url_conf, headers=headers, verify=False, timeout=5)
localfiles = resp_conf.json().get('data', {}).get('affected_items', [])
for lf in localfiles:
    if lf.get('location') == 'Security' or 'EventID=4688' in str(lf):
        print("BULUNAN SECURITY LOG KANALI:")
        print(json.dumps(lf, indent=2))
