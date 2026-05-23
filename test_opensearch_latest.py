import requests
import os
from dotenv import load_dotenv

load_dotenv()
import warnings
import json
warnings.filterwarnings('ignore')

url = f"https://{os.environ.get('OPENSEARCH_HOST', '127.0.0.1')}:9200/wazuh-alerts-*/_search"
auth = (os.environ.get('OPENSEARCH_USER', 'admin'), os.environ.get('OPENSEARCH_PASSWORD', ''))
query = {
  'size': 5,
  'sort': [{'timestamp': {'order': 'desc'}}]
}

try:
    response = requests.post(url, auth=auth, verify=False, json=query, timeout=5)
    data = response.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'SON 5 ALARM (GENEL):')
    for h in hits:
        source = h.get('_source', {})
        agent_name = source.get('agent', {}).get('name', 'N/A')
        print(f"[{source.get('timestamp')}] Ajan: {agent_name} | Kural: {source.get('rule',{}).get('id')} - {source.get('rule',{}).get('description')}")
except Exception as e:
    print('ERROR:', e)
