import os
import requests
import psycopg2

# NVD API KEY (PowerShell에서 설정한 환경변수 사용)
API_KEY = os.getenv("NVD_API_KEY")

headers = {
    "apiKey": API_KEY,
    "User-Agent": "nvd-crawler"
}

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# PostgreSQL 연결
conn = psycopg2.connect(
    host="localhost",
    database="cve",
    user="postgres",
    password="0000",
    port=5432
)

cur = conn.cursor()

# 테이블 생성
cur.execute("""
CREATE TABLE IF NOT EXISTS cves(
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published TIMESTAMP,
    cvss_score FLOAT
);
""")

conn.commit()

start = 0
page_size = 2000

while True:

    params = {
        "startIndex": start,
        "resultsPerPage": page_size
    }

    r = requests.get(url, headers=headers, params=params)

    if r.status_code != 200:
        print("API error:", r.status_code)
        break

    data = r.json()

    vulns = data.get("vulnerabilities", [])

    if not vulns:
        break

    print("Processing page:", start)

    for v in vulns:

        cve = v["cve"]

        cve_id = cve["id"]

        description = cve["descriptions"][0]["value"]

        published = cve["published"]

        cvss_score = None

        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        try:
            cur.execute("""
            INSERT INTO cves(cve_id, description, published, cvss_score)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (cve_id) DO NOTHING;
            """, (cve_id, description, published, cvss_score))

        except Exception as e:
            print("Insert error:", e)

    conn.commit()

    start += page_size

print("Finished collecting CVE data")

cur.close()
conn.close()