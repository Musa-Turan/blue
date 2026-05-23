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
  'size': 10,
  'sort': [{'timestamp': {'order': 'desc'}}],
  'query': {
    'bool': {
      'must': [
        {'match': {'rule.id': '60103'}}
      ]
    }
  }
}
try:
    response = requests.post(url, auth=auth, verify=False, json=query, timeout=5)
    data = response.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'PARENT RULE ALARM SAYISI: {len(hits)}')
    for h in hits:
        source = h.get('_source', {})
        print(f"[{source.get('timestamp')}] Kural: {source.get('rule',{}).get('id')} - {source.get('data',{}).get('win',{}).get('system',{}).get('eventID')}")
except Exception as e:
    print('ERROR:', e)
