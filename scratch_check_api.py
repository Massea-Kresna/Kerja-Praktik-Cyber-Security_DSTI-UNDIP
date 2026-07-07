import requests
import json
import sys

API_KEY = "uk_wP9sfQiudWph9GX63pTFXAgYgZ27rrm1E6bI0CJU121d7985"
url = f"https://app.pentest-tools.com/api/v2/scans"
headers = {
    "Authorization": f"Bearer {API_KEY}"
}

resp = requests.get(url, headers=headers)
data = resp.json()
print("Total scans:", len(data.get('data', [])))
for scan in data.get('data', [])[:5]:
    print(scan)
