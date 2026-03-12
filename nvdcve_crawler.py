from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import psycopg2
from psycopg2.extras import Json

API_KEY = os.getenv("NVD_API_KEY")

print("API_KEY =", API_KEY)


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
SLEEP_SECONDS = 0.6

DB_CONFIG = {
    "host": "localhost",
    "database": "db",
    "user": "user",
    "password": "pw",
    "port": "port",
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
    raw_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_metrics (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    metric_type TEXT NOT NULL,
    source TEXT,
    version TEXT,
    vector_string TEXT,
    base_score DOUBLE PRECISION,
    base_severity TEXT,
    exploitability_score DOUBLE PRECISION,
    impact_score DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_cve_metrics_cve_id ON cve_metrics(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_metrics_metric_type ON cve_metrics(metric_type);

CREATE TABLE IF NOT EXISTS cve_cwes (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT,
    type TEXT,
    cwe_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_cwes_cve_id ON cve_cwes(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe_id ON cve_cwes(cwe_id);

CREATE TABLE IF NOT EXISTS cve_references (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source TEXT,
    tags JSONB,
    is_exploit BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_cve_refs_cve_id ON cve_references(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_refs_is_exploit ON cve_references(is_exploit);

CREATE TABLE IF NOT EXISTS cve_cpes (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    criteria TEXT NOT NULL,
    match_criteria_id TEXT,
    vulnerable BOOLEAN,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve_id ON cve_cpes(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_cpes_criteria ON cve_cpes(criteria);

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


def extract_references(cve: Dict[str, Any]) -> Tuple[List[Tuple[Any, ...]], bool]:
    rows: List[Tuple[Any, ...]] = []
    has_exploit_ref = False

    for ref in cve.get("references", []):
        tags = ref.get("tags", []) or []
        is_exploit = any(str(tag).lower() == "exploit" for tag in tags)
        if is_exploit:
            has_exploit_ref = True

        rows.append(
            (
                ref.get("url"),
                ref.get("source"),
                tags,
                is_exploit,
            )
        )
    return rows, has_exploit_ref


def extract_cwes(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows: List[Tuple[Any, ...]] = []

    for weakness in cve.get("weaknesses", []):
        source = weakness.get("source")
        wtype = weakness.get("type")
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                rows.append((source, wtype, value))

    return rows


def walk_nodes(nodes: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for node in nodes:
        for cpe_match in node.get("cpeMatch", []):
            yield cpe_match
        child_nodes = node.get("nodes", [])
        if child_nodes:
            yield from walk_nodes(child_nodes)


def extract_cpes(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows: List[Tuple[Any, ...]] = []

    for conf in cve.get("configurations", []):
        for m in walk_nodes(conf.get("nodes", [])):
            criteria = m.get("criteria")
            if not criteria:
                continue

            rows.append(
                (
                    criteria,
                    m.get("matchCriteriaId"),
                    m.get("vulnerable"),
                    m.get("versionStartIncluding"),
                    m.get("versionStartExcluding"),
                    m.get("versionEndIncluding"),
                    m.get("versionEndExcluding"),
                )
            )
    return rows


def extract_metrics(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    metrics = cve.get("metrics", {})
    rows: List[Tuple[Any, ...]] = []

    metric_map = {
        "cvssMetricV40": "cvss_v40",
        "cvssMetricV31": "cvss_v31",
        "cvssMetricV30": "cvss_v30",
        "cvssMetricV2": "cvss_v2",
    }

    for key, metric_type in metric_map.items():
        for item in metrics.get(key, []):
            cvss = item.get("cvssData", {})
            rows.append(
                (
                    metric_type,
                    item.get("source"),
                    cvss.get("version"),
                    cvss.get("vectorString"),
                    cvss.get("baseScore"),
                    cvss.get("baseSeverity"),
                    item.get("exploitabilityScore"),
                    item.get("impactScore"),
                )
            )

    return rows


def upsert_cve_bundle(conn, vuln_item: Dict[str, Any]) -> None:
    cve = vuln_item["cve"]
    cve_id = cve["id"]

    description = pick_english_description(cve)
    is_kev = extract_kev_flags(cve)
    refs, has_exploit_ref = extract_references(cve)
    cwes = extract_cwes(cve)
    cpes = extract_cpes(cve)
    metrics = extract_metrics(cve)

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
                raw_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id)
            DO UPDATE SET
                source_identifier = EXCLUDED.source_identifier,
                published = EXCLUDED.published,
                last_modified = EXCLUDED.last_modified,
                vuln_status = EXCLUDED.vuln_status,
                description = EXCLUDED.description,
                is_kev = EXCLUDED.is_kev,
                has_exploit_ref = EXCLUDED.has_exploit_ref,
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
                Json(vuln_item),
            ),
        )

        cur.execute("DELETE FROM cve_metrics WHERE cve_id = %s", (cve_id,))
        cur.execute("DELETE FROM cve_cwes WHERE cve_id = %s", (cve_id,))
        cur.execute("DELETE FROM cve_references WHERE cve_id = %s", (cve_id,))
        cur.execute("DELETE FROM cve_cpes WHERE cve_id = %s", (cve_id,))

        if metrics:
            cur.executemany(
                """
                INSERT INTO cve_metrics (
                    cve_id, metric_type, source, version, vector_string,
                    base_score, base_severity, exploitability_score, impact_score
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [(cve_id, *row) for row in metrics],
            )

        if cwes:
            cur.executemany(
                """
                INSERT INTO cve_cwes (cve_id, source, type, cwe_id)
                VALUES (%s, %s, %s, %s)
                """,
                [(cve_id, *row) for row in cwes],
            )

        if refs:
            cur.executemany(
                """
                INSERT INTO cve_references (cve_id, url, source, tags, is_exploit)
                VALUES (%s, %s, %s, %s, %s)
                """,
                [(cve_id, url, source, Json(tags), is_exploit) for url, source, tags, is_exploit in refs],
            )

        if cpes:
            cur.executemany(
                """
                INSERT INTO cve_cpes (
                    cve_id,
                    criteria,
                    match_criteria_id,
                    vulnerable,
                    version_start_including,
                    version_start_excluding,
                    version_end_including,
                    version_end_excluding
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [(cve_id, *row) for row in cpes],
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
                upsert_cve_bundle(conn, vuln_item)

            conn.commit()
            start += PAGE_SIZE
            set_resume_start(conn, start)
            time.sleep(SLEEP_SECONDS)

        print("finished")

    except KeyboardInterrupt:
        conn.rollback()
        print("\\nstopped by user")
    except Exception as e:
        conn.rollback()
        print(f"error: {e}", file=sys.stderr)
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()

