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

for scan in data.get('data', []):
    status = scan.get('status_name')
    scan_id = scan.get('id')
    
    if status in ['running', 'waiting']:
        print(f"Cancelling scan {scan_id} (currently {status})...")
        stop_url = f"https://app.pentest-tools.com/api/v2/scans/{scan_id}/stop"
        res = requests.post(stop_url, headers=headers)
        if res.status_code != 200:
            print(f"Failed with /stop. Status: {res.status_code}. Try /cancel")
            cancel_url = f"https://app.pentest-tools.com/api/v2/scans/{scan_id}/cancel"
            res2 = requests.post(cancel_url, headers=headers)
            print(f"Cancel result: {res2.status_code}")
        else:
            print(f"Successfully stopped scan {scan_id}")
