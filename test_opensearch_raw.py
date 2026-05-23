import requests
import warnings
import json
warnings.filterwarnings('ignore')
import os
from dotenv import load_dotenv

load_dotenv()
url = f"https://{os.environ.get('OPENSEARCH_HOST', '127.0.0.1')}:9200/wazuh-alerts-*/_search"
auth = (os.environ.get('OPENSEARCH_USER', 'admin'), os.environ.get('OPENSEARCH_PASSWORD', ''))
query = {
  'size': 20,
  'sort': [{'timestamp': {'order': 'desc'}}],
  'query': {
    'bool': {
      'must': [
        {'match': {'agent.name': 'anapc'}}
      ]
    }
  }
}
try:
    response = requests.post(url, auth=auth, verify=False, json=query, timeout=5)
    data = response.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'SON 20 ALARM (anapc):')
    for h in hits:
        source = h.get('_source', {})
        eid = source.get('data',{}).get('win',{}).get('system',{}).get('eventID', 'N/A')
        desc = source.get('rule',{}).get('description', 'N/A')
        print(f"[{source.get('timestamp')}] EventID: {eid} | Rule: {source.get('rule',{}).get('id')} | Desc: {desc[:50]}")
except Exception as e:
    print('ERROR:', e)
