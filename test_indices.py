import requests
import warnings
import json
warnings.filterwarnings('ignore')

url = 'https://192.168.1.38:9200/_cat/indices/wazuh-alerts-*?v&s=index:desc'
auth = ('admin', 'WazuhAdmin2025')

try:
    response = requests.get(url, auth=auth, verify=False, timeout=5)
    print("MEVCUT INDEKSLER:")
    print(response.text)
except Exception as e:
    print('ERROR:', e)
