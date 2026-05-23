import requests
import os
from dotenv import load_dotenv

load_dotenv()
import warnings
import json
warnings.filterwarnings('ignore')

url = f"https://{os.environ.get('OPENSEARCH_HOST', '127.0.0.1')}:9200/_cat/indices/wazuh-alerts-*?v&s=index:desc"
auth = (os.environ.get('OPENSEARCH_USER', 'admin'), os.environ.get('OPENSEARCH_PASSWORD', ''))

try:
    response = requests.get(url, auth=auth, verify=False, timeout=5)
    print("MEVCUT INDEKSLER:")
    print(response.text)
except Exception as e:
    print('ERROR:', e)
