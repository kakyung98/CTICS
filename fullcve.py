from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import psycopg2
from psycopg2.extras import Json

API_KEY = os.getenv("NVD_API_KEY")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
SLEEP_SECONDS = 0.6

DB_CONFIG = {
    "host": "localhost",
    "database": "nvd_cve",
    "user": "postgres",
    "password": "pw",
    "port": 5432,
}

HEADERS = {
    "apiKey": API_KEY,
    "User-Agent": "nvd-research-db",
}

DDL = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    source_identifier TEXT,
    published TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    vuln_status TEXT,
    description TEXT,

    is_kev BOOLEAN DEFAULT FALSE,
    has_exploit_ref BOOLEAN DEFAULT FALSE,

    cvss_v40_score DOUBLE PRECISION,
    cvss_v40_severity TEXT,
    cvss_v31_score DOUBLE PRECISION,
    cvss_v31_severity TEXT,
    cvss_v30_score DOUBLE PRECISION,
    cvss_v30_severity TEXT,
    cvss_v2_score DOUBLE PRECISION,
    cvss_v2_severity TEXT,

    cwe_ids TEXT[] DEFAULT '{}',
    reference_urls TEXT[] DEFAULT '{}',
    exploit_reference_urls TEXT[] DEFAULT '{}',
    cpe_criteria TEXT[] DEFAULT '{}',

    raw_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC);
CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves(last_modified DESC);
CREATE INDEX IF NOT EXISTS idx_cves_is_kev ON cves(is_kev);
CREATE INDEX IF NOT EXISTS idx_cves_has_exploit_ref ON cves(has_exploit_ref);

CREATE INDEX IF NOT EXISTS idx_cves_cvss_v40_score ON cves(cvss_v40_score);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v31_score ON cves(cvss_v31_score);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v30_score ON cves(cvss_v30_score);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v2_score ON cves(cvss_v2_score);

CREATE INDEX IF NOT EXISTS idx_cves_cwe_ids_gin ON cves USING GIN (cwe_ids);
CREATE INDEX IF NOT EXISTS idx_cves_reference_urls_gin ON cves USING GIN (reference_urls);
CREATE INDEX IF NOT EXISTS idx_cves_exploit_reference_urls_gin ON cves USING GIN (exploit_reference_urls);
CREATE INDEX IF NOT EXISTS idx_cves_cpe_criteria_gin ON cves USING GIN (cpe_criteria);
CREATE INDEX IF NOT EXISTS idx_cves_raw_json_gin ON cves USING GIN (raw_json);

CREATE TABLE IF NOT EXISTS crawler_state (
    crawler_name TEXT PRIMARY KEY,
    last_start_index INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def ensure_env() -> None:
    if not API_KEY:
        print("NVD_API_KEY None.", file=sys.stderr)
        sys.exit(1)


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def create_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(DDL)
    conn.commit()


def get_resume_start(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT last_start_index
            FROM crawler_state
            WHERE crawler_name = %s
            """,
            ("nvd_full",),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0


def set_resume_start(conn, start_index: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO crawler_state (crawler_name, last_start_index, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (crawler_name)
            DO UPDATE SET
                last_start_index = EXCLUDED.last_start_index,
                updated_at = NOW()
            """,
            ("nvd_full", start_index),
        )
    conn.commit()


def fetch_page(start_index: int, results_per_page: int = PAGE_SIZE) -> Dict[str, Any]:
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    r = requests.get(NVD_URL, headers=HEADERS, params=params, timeout=60)

    if r.status_code != 200:
        print(f"API error: {r.status_code}", file=sys.stderr)
        print(r.text[:1000], file=sys.stderr)
        r.raise_for_status()

    return r.json()


def pick_english_description(cve: Dict[str, Any]) -> Optional[str]:
    descriptions = cve.get("descriptions", [])

    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")

    if descriptions:
        return descriptions[0].get("value")

    return None


def extract_kev_flags(cve: Dict[str, Any]) -> bool:
    return any(
        cve.get(field) is not None
        for field in ("cisaExploitAdd", "cisaActionDue", "cisaRequiredAction")
    )


def extract_references(cve: Dict[str, Any]) -> Tuple[List[str], List[str], bool]:
    reference_urls: List[str] = []
    exploit_reference_urls: List[str] = []
    has_exploit_ref = False

    for ref in cve.get("references", []):
        url = ref.get("url")
        if not url:
            continue

        reference_urls.append(url)

        tags = ref.get("tags", []) or []
        is_exploit = any(str(tag).lower() == "exploit" for tag in tags)

        if is_exploit:
            has_exploit_ref = True
            exploit_reference_urls.append(url)

    return dedupe_keep_order(reference_urls), dedupe_keep_order(exploit_reference_urls), has_exploit_ref


def extract_cwes(cve: Dict[str, Any]) -> List[str]:
    cwe_ids: List[str] = []

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                cwe_ids.append(value)

    return dedupe_keep_order(cwe_ids)


def walk_nodes(nodes: List[Dict[str, Any]]):
    for node in nodes:
        for cpe_match in node.get("cpeMatch", []):
            yield cpe_match

        child_nodes = node.get("nodes", [])
        if child_nodes:
            yield from walk_nodes(child_nodes)


def extract_cpes(cve: Dict[str, Any]) -> List[str]:
    cpe_criteria: List[str] = []

    for conf in cve.get("configurations", []):
        for match in walk_nodes(conf.get("nodes", [])):
            criteria = match.get("criteria")
            if criteria:
                cpe_criteria.append(criteria)

    return dedupe_keep_order(cpe_criteria)


def extract_best_metric(cve: Dict[str, Any], key: str) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics", {})
    items = metrics.get(key, [])

    if not items:
        return None, None

    item = items[0]
    cvss = item.get("cvssData", {})

    return cvss.get("baseScore"), cvss.get("baseSeverity")


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []

    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)

    return out


def upsert_cve(conn, vuln_item: Dict[str, Any]) -> None:
    cve = vuln_item["cve"]
    cve_id = cve["id"]

    description = pick_english_description(cve)
    is_kev = extract_kev_flags(cve)

    reference_urls, exploit_reference_urls, has_exploit_ref = extract_references(cve)
    cwe_ids = extract_cwes(cve)
    cpe_criteria = extract_cpes(cve)

    cvss_v40_score, cvss_v40_severity = extract_best_metric(cve, "cvssMetricV40")
    cvss_v31_score, cvss_v31_severity = extract_best_metric(cve, "cvssMetricV31")
    cvss_v30_score, cvss_v30_severity = extract_best_metric(cve, "cvssMetricV30")
    cvss_v2_score, cvss_v2_severity = extract_best_metric(cve, "cvssMetricV2")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cves (
                cve_id,
                source_identifier,
                published,
                last_modified,
                vuln_status,
                description,
                is_kev,
                has_exploit_ref,
                cvss_v40_score,
                cvss_v40_severity,
                cvss_v31_score,
                cvss_v31_severity,
                cvss_v30_score,
                cvss_v30_severity,
                cvss_v2_score,
                cvss_v2_severity,
                cwe_ids,
                reference_urls,
                exploit_reference_urls,
                cpe_criteria,
                raw_json
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            ON CONFLICT (cve_id)
            DO UPDATE SET
                source_identifier = EXCLUDED.source_identifier,
                published = EXCLUDED.published,
                last_modified = EXCLUDED.last_modified,
                vuln_status = EXCLUDED.vuln_status,
                description = EXCLUDED.description,
                is_kev = EXCLUDED.is_kev,
                has_exploit_ref = EXCLUDED.has_exploit_ref,
                cvss_v40_score = EXCLUDED.cvss_v40_score,
                cvss_v40_severity = EXCLUDED.cvss_v40_severity,
                cvss_v31_score = EXCLUDED.cvss_v31_score,
                cvss_v31_severity = EXCLUDED.cvss_v31_severity,
                cvss_v30_score = EXCLUDED.cvss_v30_score,
                cvss_v30_severity = EXCLUDED.cvss_v30_severity,
                cvss_v2_score = EXCLUDED.cvss_v2_score,
                cvss_v2_severity = EXCLUDED.cvss_v2_severity,
                cwe_ids = EXCLUDED.cwe_ids,
                reference_urls = EXCLUDED.reference_urls,
                exploit_reference_urls = EXCLUDED.exploit_reference_urls,
                cpe_criteria = EXCLUDED.cpe_criteria,
                raw_json = EXCLUDED.raw_json
            """,
            (
                cve_id,
                cve.get("sourceIdentifier"),
                cve.get("published"),
                cve.get("lastModified"),
                cve.get("vulnStatus"),
                description,
                is_kev,
                has_exploit_ref,
                cvss_v40_score,
                cvss_v40_severity,
                cvss_v31_score,
                cvss_v31_severity,
                cvss_v30_score,
                cvss_v30_severity,
                cvss_v2_score,
                cvss_v2_severity,
                cwe_ids,
                reference_urls,
                exploit_reference_urls,
                cpe_criteria,
                Json(vuln_item),
            ),
        )


def main() -> None:
    ensure_env()

    conn = get_conn()
    create_schema(conn)

    start = get_resume_start(conn)
    print(f"resume startIndex: {start}")

    try:
        while True:
            data = fetch_page(start, PAGE_SIZE)
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                print("done: no more data")
                break

            print(f"processing startIndex={start}, fetched={len(vulns)}, total={total}")

            for vuln_item in vulns:
                upsert_cve(conn, vuln_item)

            conn.commit()
            start += PAGE_SIZE
            set_resume_start(conn, start)
            time.sleep(SLEEP_SECONDS)

        print("finished")

    except KeyboardInterrupt:
        conn.rollback()
        print("\nstopped by user")
    except Exception as e:
        conn.rollback()
        print(f"error: {e}", file=sys.stderr)
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
