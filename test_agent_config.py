import requests
import warnings
import json
warnings.filterwarnings('ignore')

url_auth = 'https://192.168.1.38:55000/security/user/authenticate'
auth = ('wazuh-wui', '.+jSKgf3IR3janqE2pWL+USnaQ6MeWxV')
response = requests.post(url_auth, auth=auth, verify=False, timeout=5)
token = response.json().get('data', {}).get('token')

url_conf = 'https://192.168.1.38:55000/agents/001/config/syscheck/syscheck'
headers = {'Authorization': f'Bearer {token}'}
resp_conf = requests.get(url_conf, headers=headers, verify=False, timeout=5)
print(json.dumps(resp_conf.json(), indent=2))
