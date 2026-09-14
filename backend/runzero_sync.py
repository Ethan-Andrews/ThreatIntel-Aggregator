"""RunZero sync and correlation engine.

Fetches assets and vulnerabilities from the RunZero API and correlates them
against threat intel entries in Postgres.
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Iterator

import requests

from db import _connect_db, reconcile_exposure

# Matches trailing version strings like " 2.4", " 1.0.3", " v2", " 3.x"
_VERSION_SUFFIX_RE = re.compile(r"\s+v?\d[\d.x]*$", re.IGNORECASE)

logger = logging.getLogger(__name__)
# Ensure this module's logger is not silenced by a parent configuration
logging.getLogger(__name__).setLevel(logging.DEBUG)

_BASE_URL = "https://console.runzero.com/api/v1.0"
_sync_lock = threading.Lock()  # prevents concurrent sync+correlation runs


def is_configured() -> bool:
    return bool(os.environ.get("RUNZERO_API_TOKEN", ""))


_PAGE_SIZE = 500


class RunZeroClient:
    def __init__(self, api_token: str):
        self._headers = {"Authorization": f"Bearer {api_token}"}

    def _get(self, path: str, params: dict = None) -> list | dict:
        url = f"{_BASE_URL}{path}"
        for attempt in range(3):
            try:
                resp = requests.get(url, headers=self._headers, params=params, timeout=60)
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)

    def list_orgs(self) -> list:
        result = self._get("/account/orgs")
        return result if isinstance(result, list) else []

    _MAX_PAGES = 500  # hard ceiling: 500 × 500 = 250k assets/vulns per org

    def iter_assets(self, org_id: str) -> Iterator[dict]:
        """Stream assets one page at a time — never holds the full inventory in memory."""
        params = {
            "_oid": org_id,
            "fields": "id,names,addresses,os,type,alive,last_seen,service_products,site_name,tags",
            "page_size": _PAGE_SIZE,
        }
        seen_keys: set[str] = set()
        for page_num in range(1, self._MAX_PAGES + 1):
            result = self._get("/export/org/assets.json", params=params)
            if isinstance(result, list):
                yield from result
                break
            page = result.get("assets", [])
            yield from page
            next_key = result.get("next_key") or ""
            logger.debug("iter_assets org %s page %d: %d records, next_key=%r", org_id, page_num, len(page), next_key[:20] if next_key else "")
            if not next_key or len(page) < _PAGE_SIZE or next_key in seen_keys:
                break
            seen_keys.add(next_key)
            params["start_key"] = next_key
        else:
            logger.warning("iter_assets: hit MAX_PAGES=%d for org %s — stopped", self._MAX_PAGES, org_id)

    def iter_vulns(self, org_id: str) -> Iterator[dict]:
        """Stream vulns one page at a time."""
        params = {"_oid": org_id, "page_size": _PAGE_SIZE}
        seen_keys: set[str] = set()
        for page_num in range(1, self._MAX_PAGES + 1):
            result = self._get("/export/org/vulnerabilities.json", params=params)
            if isinstance(result, list):
                yield from result
                break
            page = result.get("vulnerabilities", [])
            yield from page
            next_key = result.get("next_key") or ""
            if not next_key or len(page) < _PAGE_SIZE or next_key in seen_keys:
                break
            seen_keys.add(next_key)
            params["start_key"] = next_key
        else:
            logger.warning("iter_vulns: hit MAX_PAGES=%d for org %s — stopped", self._MAX_PAGES, org_id)


def _parse_asset(asset: dict, org_name: str) -> dict:
    names = asset.get("names") or []
    hostname = names[0] if names else ""
    addresses = asset.get("addresses") or []
    raw_products = asset.get("service_products") or []
    software_names = []
    for p in raw_products:
        if isinstance(p, str):
            software_names.append(p)
        elif isinstance(p, dict):
            name = p.get("product_name") or p.get("name") or ""
            if name:
                software_names.append(name)
    raw_tags = asset.get("tags") or []
    tags = [t for t in raw_tags if isinstance(t, str)]
    return {
        "id": asset["id"],
        "org": org_name,
        "site": asset.get("site_name", ""),
        "hostname": hostname,
        "os": asset.get("os") or "",
        "addresses_json": json.dumps(addresses),
        "software_json": json.dumps(software_names),
        "tags_json": json.dumps(tags),
        "alive": 1 if asset.get("alive") else 0,
        "last_seen": asset.get("last_seen") or 0,
    }


# INSERT OR REPLACE deleted and reinserted the row; ON CONFLICT DO UPDATE
# updates in place, which is what the caller actually wants.
_INSERT_ASSET_SQL = (
    "INSERT INTO runzero_assets "
    "(id, org, site, hostname, os, addresses_json, software_json, tags_json, alive, last_seen) "
    "VALUES (:id, :org, :site, :hostname, :os, :addresses_json, :software_json, :tags_json, :alive, :last_seen) "
    "ON CONFLICT (id) DO UPDATE SET "
    "org = EXCLUDED.org, site = EXCLUDED.site, hostname = EXCLUDED.hostname, "
    "os = EXCLUDED.os, addresses_json = EXCLUDED.addresses_json, "
    "software_json = EXCLUDED.software_json, tags_json = EXCLUDED.tags_json, "
    "alive = EXCLUDED.alive, last_seen = EXCLUDED.last_seen"
)
_INSERT_VULN_SQL = (
    "INSERT INTO runzero_vulns (asset_id, cve_id, severity, vuln_name) "
    "VALUES (?, ?, ?, ?) "
    "ON CONFLICT (asset_id, cve_id) DO UPDATE SET "
    "severity = EXCLUDED.severity, vuln_name = EXCLUDED.vuln_name"
)
_COMMIT_EVERY = 500  # write to disk every N records


def sync_runzero(conn) -> tuple:
    """Stream assets and vulns from RunZero, writing to DB page by page.

    Uses paginated API calls (page_size=500) so only one page of raw JSON
    is in memory at a time — safe for large inventories.
    """
    token = os.environ.get("RUNZERO_API_TOKEN", "")
    client = RunZeroClient(token)

    orgs = client.list_orgs()
    if not orgs:
        _log_sync(conn, 0, 0, 0, "ok", "")
        return 0, 0

    logger.info("RunZero sync starting: %d org(s)", len(orgs))

    conn.execute("DELETE FROM runzero_assets")
    conn.execute("DELETE FROM runzero_vulns")
    conn.commit()

    total_assets = 0
    total_vulns = 0

    for org in orgs:
        org_name = org.get("name", org["id"])
        org_id = org["id"]

        # Stream assets — one page at a time
        org_assets = 0
        try:
            for asset in client.iter_assets(org_id):
                conn.execute(_INSERT_ASSET_SQL, _parse_asset(asset, org_name))
                org_assets += 1
                if org_assets % _COMMIT_EVERY == 0:
                    conn.commit()
                    logger.info("RunZero org '%s': %d assets so far…", org_name, org_assets)
        except Exception as exc:
            logger.warning("RunZero asset fetch failed for org '%s': %s", org_name, exc)
        conn.commit()
        total_assets += org_assets

        # Stream vulns — one page at a time
        org_vulns = 0
        org_vulns_seen = 0
        try:
            for vuln in client.iter_vulns(org_id):
                org_vulns_seen += 1
                if org_vulns_seen % _COMMIT_EVERY == 0:
                    conn.commit()
                    logger.info("RunZero org '%s': %d vulns so far…", org_name, org_vulns_seen)
                cve_id = vuln.get("vulnerability_cve", "") or ""
                if not cve_id:
                    continue
                conn.execute(_INSERT_VULN_SQL, (
                    vuln.get("vulnerability_asset_id", ""),
                    cve_id,
                    vuln.get("vulnerability_severity", "") or "",
                    vuln.get("vulnerability_name", "") or "",
                ))
                org_vulns += 1
                if org_vulns % _COMMIT_EVERY == 0:
                    conn.commit()
        except Exception as exc:
            logger.warning("RunZero vuln fetch failed for org '%s': %s", org_name, exc)
        conn.commit()
        total_vulns += org_vulns

        logger.info("RunZero org '%s' done: %d assets, %d vulns", org_name, org_assets, org_vulns)

    _log_sync(conn, len(orgs), total_assets, total_vulns, "ok", "")
    logger.info("RunZero sync complete: %d orgs, %d assets, %d vulns", len(orgs), total_assets, total_vulns)
    return total_assets, total_vulns


def run_correlation_pass(conn):
    """Recompute all RunZero<->TI entry correlations from scratch."""
    conn.execute("DELETE FROM runzero_matches")

    # Signal 1 — CVE match (confirmed)
    # Joins entries.iocs JSON array of CVEs against runzero_vulns
    conn.execute("""
        INSERT INTO runzero_matches (entry_hash, asset_id, match_type, match_detail, confidence)
        SELECT DISTINCT
            e.hash,
            rv.asset_id,
            'cve',
            j.value || CASE WHEN COALESCE(rv.vuln_name, '') != '' THEN ' — ' || rv.vuln_name ELSE '' END,
            'confirmed'
        FROM entries e
        -- Postgres will not silently tolerate malformed JSON the way SQLite
        -- did, so the cast is guarded by the shape test in the WHERE clause.
        JOIN LATERAL jsonb_array_elements_text((e.iocs::jsonb) -> 'cves') AS j(value) ON true
        JOIN runzero_vulns rv ON rv.cve_id = j.value
        JOIN runzero_assets ra ON ra.id = rv.asset_id AND ra.alive = 1
        WHERE e.severity != 'Informational'
          AND e.ai_summary IS NOT NULL
          AND e.iocs IS NOT NULL AND left(btrim(e.iocs), 1) IN ('[', '{')
        ON CONFLICT (entry_hash, asset_id, match_type) DO NOTHING
    """)

    # Signal 4 — IP match (possible)
    conn.execute("""
        INSERT INTO runzero_matches (entry_hash, asset_id, match_type, match_detail, confidence)
        SELECT DISTINCT
            e.hash,
            ra.id,
            'ip',
            'IP: ' || j.value,
            'possible'
        FROM entries e
        JOIN LATERAL jsonb_array_elements_text((e.iocs::jsonb) -> 'ips') AS j(value) ON true
        JOIN runzero_assets ra ON EXISTS (
            SELECT 1 FROM jsonb_array_elements_text(ra.addresses_json::jsonb) AS t(v)
            WHERE t.v = j.value
        )
        WHERE e.severity != 'Informational'
          AND e.ai_summary IS NOT NULL
          AND e.iocs IS NOT NULL AND left(btrim(e.iocs), 1) IN ('[', '{')
        ON CONFLICT (entry_hash, asset_id, match_type) DO NOTHING
    """)

    conn.commit()

    # Signals 2 & 3 — software name match and OS name match (both possible)
    # Done in Python because SQLite JSON functions can't do case-insensitive substring matching efficiently
    asset_count = conn.execute("SELECT COUNT(*) FROM runzero_assets WHERE alive = 1").fetchone()[0]
    entry_count = conn.execute(
        "SELECT COUNT(*) FROM entries WHERE severity != 'Informational' AND ai_summary IS NOT NULL"
    ).fetchone()[0]
    logger.info(
        "RunZero correlation: %d alive assets × %d triaged entries", asset_count, entry_count
    )
    _run_software_os_correlation(conn)

    # Update match_count in the most recent sync log row
    match_count = conn.execute("SELECT COUNT(DISTINCT entry_hash) FROM runzero_matches").fetchone()[0]
    conn.execute(
        "UPDATE runzero_sync_log SET match_count = ? WHERE id = (SELECT MAX(id) FROM runzero_sync_log)",
        (match_count,),
    )
    conn.commit()
    logger.info("RunZero correlation pass complete: %d matched entries", match_count)


_SW_OS_BATCH_SIZE = 500


def _run_software_os_correlation(conn):
    """Insert software and OS matches (possible confidence) via Python loop.

    Processes assets one at a time and flushes inserts in batches to avoid
    accumulating a potentially huge in-memory list (OOM on large inventories).
    Entry search texts are precomputed once outside the asset loop.
    """
    assets = conn.execute(
        "SELECT id, hostname, org, os, software_json FROM runzero_assets WHERE alive = 1"
    ).fetchall()

    entries = conn.execute(
        "SELECT hash, title, ai_summary FROM entries "
        "WHERE severity != 'Informational' AND ai_summary IS NOT NULL"
    ).fetchall()

    # Precompute once — not once per asset
    entry_texts = [(h, f"{t} {s}".lower()) for h, t, s in entries]

    _INSERT_SQL = (
        "INSERT INTO runzero_matches "
        "(entry_hash, asset_id, match_type, match_detail, confidence) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (entry_hash, asset_id, match_type) DO NOTHING"
    )

    batch = []

    def _flush():
        if batch:
            conn.executemany(_INSERT_SQL, batch)
            conn.commit()
            batch.clear()

    for asset_id, hostname, org, os_str, software_json_str in assets:
        try:
            software_list = json.loads(software_json_str or "[]")
        except (json.JSONDecodeError, TypeError):
            software_list = []

        # Precompute lowercased names (and version-stripped variants) once per asset
        sw_terms = []
        for product in software_list:
            if not product or len(product) < 3:
                continue
            pl = product.lower()
            base = _VERSION_SUFFIX_RE.sub("", pl).strip()
            sw_terms.append((product, pl, base if len(base) >= 3 else None))

        # Require a digit in the OS string — rejects bare "Linux", "Windows", "macOS"
        # while keeping versioned strings like "Windows 11", "Ubuntu 22.04", "RHEL 8"
        os_lower = os_str.lower() if os_str and len(os_str) > 4 and any(c.isdigit() for c in os_str) else None
        label = hostname or asset_id

        for entry_hash, search_text in entry_texts:
            # Signal 2: software name match
            for product, pl, base in sw_terms:
                if pl in search_text or (base and base in search_text):
                    batch.append((
                        entry_hash, asset_id, "software",
                        f"Installed: {product}",
                        "possible",
                    ))
                    break

            # Signal 3: OS name match
            if os_lower and os_lower in search_text:
                batch.append((
                    entry_hash, asset_id, "os",
                    f"OS: {os_str}",
                    "possible",
                ))

        if len(batch) >= _SW_OS_BATCH_SIZE:
            _flush()

    _flush()


def _log_sync(conn, org_count: int, asset_count: int, vuln_count: int, status: str, error: str):
    conn.execute(
        "INSERT INTO runzero_sync_log (synced_at, org_count, asset_count, vuln_count, match_count, status, error) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), org_count, asset_count, vuln_count, status, error),
    )
    conn.commit()


def sync_and_correlate():
    """Full sync + correlation cycle. Opens its own DB connection.

    Uses a non-blocking lock so concurrent triggers (APScheduler + manual UI sync)
    skip rather than run in parallel and double memory pressure.
    """
    if not _sync_lock.acquire(blocking=False):
        logger.info("RunZero sync already in progress — skipping duplicate trigger")
        return
    logger.info("RunZero sync_and_correlate started")
    try:
        conn = _connect_db()
        try:
            sync_runzero(conn)
        except Exception as exc:
            logger.error("RunZero sync failed: %s", exc, exc_info=True)
            _log_sync(conn, 0, 0, 0, "error", str(exc))
            return
        finally:
            conn.close()

        conn2 = _connect_db()
        try:
            run_correlation_pass(conn2)
            counts = reconcile_exposure(conn2)
            logger.info(
                "Exposure reconciliation: %d new, %d updated, %d remediated, %d reopened",
                counts["new"], counts["updated"], counts["remediated"], counts["reopened"],
            )
        except Exception as exc:
            logger.error("RunZero correlation failed: %s", exc, exc_info=True)
        finally:
            conn2.close()
    finally:
        _sync_lock.release()
        logger.info("RunZero sync_and_correlate finished")
