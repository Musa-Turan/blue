import os
import requests
from dotenv import load_dotenv
import sys

sys.stdout.reconfigure(encoding='utf-8')

# os.chdir(...) removed to allow running from any directory
load_dotenv('.env')

url = f"https://{os.environ.get('WAZUH_MANAGER_IP')}:55000/security/user/authenticate"
auth = (os.environ.get('WAZUH_API_USER'), os.environ.get('WAZUH_API_PASSWORD'))

requests.packages.urllib3.disable_warnings()
res = requests.post(url, auth=auth, verify=False)

if res.status_code == 200:
    token = res.json().get('data', {}).get('token')
    headers = {'Authorization': f'Bearer {token}'}
    
    # Check if rule 100012 exists in the API
    rule_res = requests.get(f"https://{os.environ.get('WAZUH_MANAGER_IP')}:55000/rules?rule_ids=100012,100021", headers=headers, verify=False)
    data = rule_res.json().get('data', {}).get('affected_items', [])
    
    print('--- WAZUH RULE VERIFICATION ---')
    if data:
        print(f"BULDUM! Wazuh Manager {len(data)} yeni kuralı (100012 ve 100021) başarıyla aklına yazmış.")
        for r in data:
            print(f"- [Kural {r.get('id')}] {r.get('description')}")
        print("\nSonuç: Kurallar harika bir şekilde aktif!")
    else:
        print("MAALESEF: API kuralları göremedi. Wazuh Manager henüz yeniden başlatılmamış (Restart edilmemiş) olabilir mi?")
else:
    print('Auth failed', res.text)
