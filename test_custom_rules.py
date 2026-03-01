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
      'should': [
        {'match': {'rule.id': '100010'}},
        {'match': {'rule.id': '100011'}}
      ]
    }
  }
}

try:
    response = requests.post(url, auth=auth, verify=False, json=query, timeout=5)
    data = response.json()
    hits = data.get('hits', {}).get('hits', [])
    print(f'BULUNAN OZEL ALARM SAYISI: {len(hits)}')
    for h in hits:
        source = h.get('_source', {})
        agent_name = source.get('agent', {}).get('name', 'N/A')
        print(f"[{source.get('timestamp')}] Ajan: {agent_name} | Kural: {source.get('rule',{}).get('id')} - {source.get('rule',{}).get('description')}")
except Exception as e:
    print('ERROR:', e)
