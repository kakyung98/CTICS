from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
import psycopg2
from psycopg2.extras import Json


API_KEY = os.getenv("NVD_API_KEY")

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_API_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

DB_CONFIG = {
    "host": "localhost",
    "database": "db",
    "user": "user",
    "password": "pw",
    "port": "port",
}

HEADERS = {
    "apiKey": API_KEY,
    "User-Agent": "nvd-incremental-updater",
}

REQUEST_TIMEOUT = 60
PAGE_SIZE = 2000
SLEEP_SECONDS = 0.6  # API 여유
INITIAL_LOOKBACK_DAYS = 7
SYNC_NAME = "nvd_cve_incremental"


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

CREATE TABLE IF NOT EXISTS cve_cwes (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT,
    type TEXT,
    cwe_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_cwes_cve_id ON cve_cwes(cve_id);

CREATE TABLE IF NOT EXISTS cve_references (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source TEXT,
    tags JSONB,
    is_exploit BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id ON cve_references(cve_id);

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

CREATE TABLE IF NOT EXISTS sync_state (
    sync_name TEXT PRIMARY KEY,
    last_change_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 변경 이벤트 원문 저장
CREATE TABLE IF NOT EXISTS cve_change_events (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL,
    change_time TIMESTAMPTZ,
    event_name TEXT,
    source TEXT,
    details JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_change_events_cve_id ON cve_change_events(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_change_events_change_time ON cve_change_events(change_time);

-- 변경 시점 스냅샷 저장
CREATE TABLE IF NOT EXISTS cve_history_snapshots (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL,
    snapshot_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_identifier TEXT,
    published TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    vuln_status TEXT,
    description TEXT,
    is_kev BOOLEAN DEFAULT FALSE,
    has_exploit_ref BOOLEAN DEFAULT FALSE,
    raw_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_history_snapshots_cve_id
ON cve_history_snapshots(cve_id);

CREATE INDEX IF NOT EXISTS idx_cve_history_snapshots_time
ON cve_history_snapshots(snapshot_time);
"""


def ensure_env() -> None:
    if not API_KEY:
        print("NVD_API_KEY 환경변수가 없습니다.", file=sys.stderr)
        sys.exit(1)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_nvd_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def create_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(DDL)
    conn.commit()


def get_last_change_at(conn) -> Optional[datetime]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT last_change_at FROM sync_state WHERE sync_name = %s",
            (SYNC_NAME,),
        )
        row = cur.fetchone()
        return row[0] if row else None


def set_last_change_at(conn, dt: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sync_state (sync_name, last_change_at, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (sync_name)
            DO UPDATE SET
                last_change_at = EXCLUDED.last_change_at,
                updated_at = NOW()
            """,
            (SYNC_NAME, dt),
        )
    conn.commit()


def nvd_get(url: str, params: Dict[str, Any]) -> requests.Response:
    r = requests.get(url, headers=HEADERS, params=params, timeout=REQUEST_TIMEOUT)
    if r.status_code == 429:
        # 간단 재시도
        time.sleep(3)
        r = requests.get(url, headers=HEADERS, params=params, timeout=REQUEST_TIMEOUT)
    return r


def fetch_changed_cve_events(change_start: datetime, change_end: datetime) -> List[Dict[str, Any]]:
    """
    cvehistory/2.0 에서 change event 원문 목록 수집
    """
    events: List[Dict[str, Any]] = []
    start_index = 0

    while True:
        params = {
            "changeStartDate": to_nvd_dt(change_start),
            "changeEndDate": to_nvd_dt(change_end),
            "startIndex": start_index,
            "resultsPerPage": PAGE_SIZE,
        }

        r = nvd_get(HISTORY_API_URL, params)
        if r.status_code != 200:
            print(f"[history] API error: {r.status_code}", file=sys.stderr)
            print(r.text[:1000], file=sys.stderr)
            r.raise_for_status()

        data = r.json()
        total = data.get("totalResults", 0)

        # 스키마 변화 대응
        items = (
            data.get("cveChanges")
            or data.get("vulnerabilities")
            or data.get("changes")
            or []
        )

        if not items:
            break

        events.extend(items)

        start_index += len(items)
        if start_index >= total:
            break

        time.sleep(SLEEP_SECONDS)

    return events


def fetch_cve_by_id(cve_id: str) -> Optional[Dict[str, Any]]:
    params = {"cveId": cve_id}
    r = nvd_get(CVE_API_URL, params)
    if r.status_code != 200:
        print(f"[cve] API error for {cve_id}: {r.status_code}", file=sys.stderr)
        print(r.text[:500], file=sys.stderr)
        return None

    data = r.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0]


def pick_english_description(cve: Dict[str, Any]) -> Optional[str]:
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return descriptions[0].get("value") if descriptions else None


def extract_kev_flags(cve: Dict[str, Any]) -> bool:
    return any(
        cve.get(field) is not None
        for field in ("cisaExploitAdd", "cisaActionDue", "cisaRequiredAction")
    )


def extract_references(cve: Dict[str, Any]) -> Tuple[List[Tuple[Any, ...]], bool]:
    rows = []
    has_exploit_ref = False

    for ref in cve.get("references", []):
        tags = ref.get("tags", []) or []
        is_exploit = any(str(tag).lower() == "exploit" for tag in tags)
        if is_exploit:
            has_exploit_ref = True

        rows.append((
            ref.get("url"),
            ref.get("source"),
            tags,
            is_exploit,
        ))

    return rows, has_exploit_ref


def extract_cwes(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows = []
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
        children = node.get("nodes", [])
        if children:
            yield from walk_nodes(children)


def extract_cpes(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows = []
    for conf in cve.get("configurations", []):
        for m in walk_nodes(conf.get("nodes", [])):
            criteria = m.get("criteria")
            if not criteria:
                continue
            rows.append((
                criteria,
                m.get("matchCriteriaId"),
                m.get("vulnerable"),
                m.get("versionStartIncluding"),
                m.get("versionStartExcluding"),
                m.get("versionEndIncluding"),
                m.get("versionEndExcluding"),
            ))
    return rows


def extract_metrics(cve: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows = []
    metrics = cve.get("metrics", {})

    metric_map = {
        "cvssMetricV40": "cvss_v40",
        "cvssMetricV31": "cvss_v31",
        "cvssMetricV30": "cvss_v30",
        "cvssMetricV2": "cvss_v2",
    }

    for key, metric_type in metric_map.items():
        for item in metrics.get(key, []):
            cvss = item.get("cvssData", {})
            rows.append((
                metric_type,
                item.get("source"),
                cvss.get("version"),
                cvss.get("vectorString"),
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
                item.get("exploitabilityScore"),
                item.get("impactScore"),
            ))

    return rows


def extract_change_event_row(
    item: Dict[str, Any]
) -> Optional[Tuple[str, Optional[str], Optional[str], Optional[str], Dict[str, Any]]]:
    """
    (cve_id, change_time, event_name, source, original_item)
    """
    cve_id = item.get("cveId")
    if not cve_id and "change" in item and isinstance(item["change"], dict):
        cve_id = item["change"].get("cveId")
    if not cve_id and "cveChange" in item and isinstance(item["cveChange"], dict):
        cve_id = item["cveChange"].get("cveId")
    if not cve_id and "cve" in item and isinstance(item["cve"], dict):
        cve_id = item["cve"].get("id")

    if not cve_id:
        return None

    change_obj = item.get("change") or item.get("cveChange") or {}

    change_time = (
        item.get("created")
        or item.get("changeTime")
        or item.get("date")
        or (change_obj.get("created") if isinstance(change_obj, dict) else None)
        or (change_obj.get("changeTime") if isinstance(change_obj, dict) else None)
        or (change_obj.get("date") if isinstance(change_obj, dict) else None)
    )

    event_name = (
        item.get("eventName")
        or item.get("event")
        or item.get("action")
        or (change_obj.get("eventName") if isinstance(change_obj, dict) else None)
        or (change_obj.get("type") if isinstance(change_obj, dict) else None)
        or (change_obj.get("event") if isinstance(change_obj, dict) else None)
    )

    source = (
        item.get("sourceIdentifier")
        or item.get("source")
        or (change_obj.get("sourceIdentifier") if isinstance(change_obj, dict) else None)
        or (change_obj.get("source") if isinstance(change_obj, dict) else None)
    )

    return (cve_id, change_time, event_name, source, item)


def insert_change_event(conn, item: Dict[str, Any]) -> None:
    row = extract_change_event_row(item)
    if not row:
        return

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_change_events (
                cve_id, change_time, event_name, source, details
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (row[0], row[1], row[2], row[3], Json(row[4])),
        )


def insert_cve_snapshot(conn, vuln_item: Dict[str, Any]) -> None:
    cve = vuln_item["cve"]
    cve_id = cve["id"]

    description = pick_english_description(cve)
    is_kev = extract_kev_flags(cve)
    _, has_exploit_ref = extract_references(cve)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_history_snapshots (
                cve_id, snapshot_time, source_identifier, published,
                last_modified, vuln_status, description,
                is_kev, has_exploit_ref, raw_json
            )
            VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s)
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


def overwrite_cve_bundle(conn, vuln_item: Dict[str, Any]) -> None:
    """
    최신 상태 테이블은 덮어쓰기
    """
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
                cve_id, source_identifier, published, last_modified, vuln_status,
                description, is_kev, has_exploit_ref, raw_json
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
                    cve_id, criteria, match_criteria_id, vulnerable,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [(cve_id, *row) for row in cpes],
            )


def main() -> None:
    ensure_env()

    conn = get_conn()
    create_schema(conn)

    last_change_at = get_last_change_at(conn)
    now_utc = utc_now()

    if last_change_at is None:
        change_start = now_utc - timedelta(days=INITIAL_LOOKBACK_DAYS)
    else:
        change_start = last_change_at - timedelta(minutes=5)

    change_end = now_utc

    print(f"change window: {to_nvd_dt(change_start)} ~ {to_nvd_dt(change_end)}")

    try:
        # 1) 변경 이벤트 원문 수집
        events = fetch_changed_cve_events(change_start, change_end)
        print(f"change events: {len(events)}")

        # 2) 이력 이벤트 저장 + CVE ID 집합 추출
        changed_ids: Set[str] = set()
        event_inserted = 0

        for item in events:
            row = extract_change_event_row(item)
            if not row:
                continue
            changed_ids.add(row[0])
            insert_change_event(conn, item)
            event_inserted += 1

        conn.commit()
        print(f"history events inserted: {event_inserted}")
        print(f"unique changed CVEs: {len(changed_ids)}")

        # 3) 상세 CVE 조회 후
        #    - 스냅샷 저장
        #    - 최신 상태 덮어쓰기
        processed = 0
        for cve_id in sorted(changed_ids):
            vuln_item = fetch_cve_by_id(cve_id)
            if vuln_item is None:
                continue

            try:
                insert_cve_snapshot(conn, vuln_item)
                overwrite_cve_bundle(conn, vuln_item)
                conn.commit()
                processed += 1
                print(f"updated: {cve_id}")
            except Exception:
                conn.rollback()
                raise

            time.sleep(SLEEP_SECONDS)

        set_last_change_at(conn, change_end)
        print(f"finished. updated={processed}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
