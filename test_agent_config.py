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

url_conf = f"https://{os.environ.get('WAZUH_MANAGER_IP', '127.0.0.1')}:55000/agents/001/config/syscheck/syscheck"
headers = {'Authorization': f'Bearer {token}'}
resp_conf = requests.get(url_conf, headers=headers, verify=False, timeout=5)
print(json.dumps(resp_conf.json(), indent=2))
