import requests
import json

API_KEY = "uk_wP9sfQiudWph9GX63pTFXAgYgZ27rrm1E6bI0CJU121d7985"
url = f"https://app.pentest-tools.com/api/v2/tools"
headers = {
    "Authorization": f"Bearer {API_KEY}"
}

try:
    resp = requests.get(url, headers=headers)
    data = resp.json()
    for tool in data.get('data', []):
        if 'Website Scanner' in tool.get('name', '') or 'Light' in tool.get('name', '') or tool.get('id') in [170, 171]:
            print(f"ID: {tool.get('id')} - Name: {tool.get('name')}")
except Exception as e:
    print(f"Error: {e}")
