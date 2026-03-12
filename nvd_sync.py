import os
import requests

api_key = os.getenv("NVD_API_KEY")

print("API key exists:", bool(api_key))

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "resultsPerPage": 3
}

headers = {
    "apiKey": api_key,
    "User-Agent": "nvd-test"
}

r = requests.get(url, headers=headers, params=params)

print("status:", r.status_code)

data = r.json()

print("totalResults:", data.get("totalResults"))

for v in data["vulnerabilities"]:
    print(v["cve"]["id"])