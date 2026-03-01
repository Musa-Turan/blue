import requests
import warnings
import json
warnings.filterwarnings('ignore')
url = 'https://192.168.1.38:9200/wazuh-alerts-*/_search'
auth = ('admin', 'WazuhAdmin2025')
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
