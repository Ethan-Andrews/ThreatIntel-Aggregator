"""Local cache of MITRE ATT&CK's own Detection Strategy + Analytic + Data
Component catalog. sync_all() (Task 5) downloads the current STIX bundle
once and upserts three local tables in full -- built for a future
scheduled cadence, not fetched per-technique on alignment_check.py's hot
path.

Walks the real STIX object graph (confirmed against attack.mitre.org's
live catalog and the ATT&CK Data Model schema docs during design, not
assumed):

    x-mitre-detection-strategy --(detects rel.)--> attack-pattern (technique)
    x-mitre-detection-strategy.x_mitre_analytic_refs[] --> x-mitre-analytic
    x-mitre-analytic.x_mitre_log_source_references[] =
        [{x_mitre_data_component_ref, name, channel}, ...]
    x_mitre_data_component_ref --> x-mitre-data-component
        .x_mitre_log_sources[] = [{name, channel}, ...]

A technique with no matching detection-strategy is a valid, cacheable
answer -- not an error -- same "decline safely, don't guess" discipline as
the rest of this pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

STIX_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


@dataclass
class ParsedAnalytic:
    id: str
    detection_strategy_id: str
    name: str
    description: str
    platform: str | None
    log_source_references: list[dict]   # [{data_component_id, name, channel}, ...]
    mutable_elements: list[dict]        # [{field, description}, ...]


@dataclass
class ParsedDataComponent:
    id: str
    name: str
    description: str
    log_sources: list[dict]             # [{name, channel}, ...]


@dataclass
class ParsedStrategy:
    id: str
    det_id: str | None
    technique_id: str
    name: str | None
    objective: str | None
    catalog_version: str | None
    analytics: list[ParsedAnalytic] = field(default_factory=list)


@dataclass
class MitreStrategy:
    """What alignment_check.py actually consumes -- the strategy plus its
    analytics, each with its data components resolved inline (name +
    channel, not just a data-component id) so the AI prompt and the
    telemetry resolver both work from the same structure."""
    technique_id: str
    det_id: str | None
    objective: str | None
    analytics: list[dict] = field(default_factory=list)
    catalog_version: str | None = None


def fetch_stix_bundle(http_client: httpx.Client | None = None) -> dict:
    """Download the current enterprise-attack STIX bundle. Raises on
    failure -- callers decide what that means (alignment_check.py treats it
    as 'partial', never fabricates aligned/diverges)."""
    client = http_client or httpx.Client(timeout=60.0)
    resp = client.get(STIX_BUNDLE_URL, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse_bundle(bundle: dict) -> tuple[list[ParsedStrategy], list[ParsedDataComponent]]:
    """Parse the whole bundle into strategies (with analytics nested) and a
    flat list of data components. Pure function -- no DB, no network."""
    objects = bundle.get("objects", [])
    catalog_version = bundle.get("x_mitre_version") or None

    attack_patterns = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    analytics_by_id = {o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic"}
    data_components = [
        ParsedDataComponent(
            id=o["id"], name=o.get("name", ""), description=o.get("description", ""),
            log_sources=[
                {"name": ls.get("name", ""), "channel": ls.get("channel", "")}
                for ls in o.get("x_mitre_log_sources", []) or []
            ],
        )
        for o in objects if o.get("type") == "x-mitre-data-component"
    ]

    # detects relationship: source_ref = detection-strategy, target_ref = attack-pattern (technique)
    detects_by_strategy = {
        r["source_ref"]: r["target_ref"]
        for r in objects
        if r.get("type") == "relationship" and r.get("relationship_type") == "detects"
        and str(r.get("source_ref", "")).startswith("x-mitre-detection-strategy--")
    }

    strategies: list[ParsedStrategy] = []
    for obj in objects:
        if obj.get("type") != "x-mitre-detection-strategy":
            continue
        technique_ref = detects_by_strategy.get(obj["id"])
        technique_obj = attack_patterns.get(technique_ref) if technique_ref else None
        technique_id = _external_id(technique_obj) if technique_obj else None
        if technique_id is None:
            continue  # a detection-strategy with no resolvable technique isn't usable to us

        analytics = []
        for ref in obj.get("x_mitre_analytic_refs", []) or []:
            an = analytics_by_id.get(ref)
            if an is None:
                continue
            platforms = an.get("x_mitre_platforms", []) or []
            analytics.append(ParsedAnalytic(
                id=an["id"], detection_strategy_id=obj["id"],
                name=an.get("name", ""), description=an.get("description", ""),
                platform=platforms[0] if platforms else None,
                log_source_references=[
                    {
                        "data_component_id": lsr.get("x_mitre_data_component_ref", ""),
                        "name": lsr.get("name", ""),
                        "channel": lsr.get("channel", ""),
                    }
                    for lsr in an.get("x_mitre_log_source_references", []) or []
                ],
                mutable_elements=[
                    {"field": me.get("field", ""), "description": me.get("description", "")}
                    for me in an.get("x_mitre_mutable_elements", []) or []
                ],
            ))

        strategies.append(ParsedStrategy(
            id=obj["id"], det_id=_external_id(obj), technique_id=technique_id,
            name=obj.get("name"), objective=obj.get("description"),
            catalog_version=catalog_version, analytics=analytics,
        ))

    return strategies, data_components


def extract_strategy(bundle: dict, technique_id: str) -> MitreStrategy:
    """Convenience wrapper: parse the whole bundle and project one
    technique's strategy into the flattened shape alignment_check.py and
    the DB cache (Task 5) both use. Not the primary sync path -- that's
    sync_all()."""
    strategies, data_components = parse_bundle(bundle)
    dc_by_id = {dc.id: dc for dc in data_components}

    strategy = next((s for s in strategies if s.technique_id == technique_id), None)
    catalog_version = bundle.get("x_mitre_version") or None
    if strategy is None:
        return MitreStrategy(technique_id=technique_id, det_id=None, objective=None,
                              catalog_version=catalog_version)

    analytics_out = []
    for an in strategy.analytics:
        log_sources = []
        for lsr in an.log_source_references:
            dc = dc_by_id.get(lsr["data_component_id"])
            log_sources.append({
                "data_component": dc.name if dc else lsr["data_component_id"],
                "name": lsr["name"],
                "channel": lsr["channel"],
            })
        analytics_out.append({
            "name": an.name, "description": an.description, "platform": an.platform,
            "log_sources": log_sources, "mutable_elements": an.mutable_elements,
        })

    return MitreStrategy(
        technique_id=technique_id, det_id=strategy.det_id, objective=strategy.objective,
        analytics=analytics_out, catalog_version=strategy.catalog_version,
    )


def sync_all(conn, http_client: httpx.Client | None = None) -> dict:
    """Full-catalog cadence sync: one bundle download, upsert all three
    local tables in full. Idempotent -- safe to call repeatedly, e.g. from
    a future scheduled job (see design doc's 'Out of scope'). Returns
    counts for logging.

    The write phase is wrapped in its own try/except/rollback rather than
    relying on caller connection-teardown behavior: pgcompat.PgConnection
    .close() unconditionally commits (it only rolls back if the commit
    itself raises), so without this, an exception partway through the
    write loop -- e.g. a schema-drift bug against the real live catalog --
    would leave a partial write to survive to the next close() and commit
    silently. Combined with _has_synced_before()'s binary "any row exists"
    check, that would permanently and silently mark the cache as
    populated while every technique outside the partial batch returns a
    confident det_id=None -- indistinguishable from "MITRE genuinely has
    no strategy for this," which alignment_check.py treats as ground
    truth. So sync_all() must guarantee its own atomicity."""
    bundle = fetch_stix_bundle(http_client)
    strategies, data_components = parse_bundle(bundle)

    try:
        for dc in data_components:
            conn.execute(
                "INSERT INTO mitre_data_components (id, name, description, log_sources, synced_at) "
                "VALUES (?, ?, ?, ?, now()) "
                "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "
                "description = EXCLUDED.description, log_sources = EXCLUDED.log_sources, "
                "synced_at = now()",
                (dc.id, dc.name, dc.description, json.dumps(dc.log_sources)),
            )

        for strategy in strategies:
            conn.execute(
                "INSERT INTO mitre_detection_strategies "
                "(id, det_id, technique_id, name, objective, synced_at, catalog_version) "
                "VALUES (?, ?, ?, ?, ?, now(), ?) "
                "ON CONFLICT (id) DO UPDATE SET det_id = EXCLUDED.det_id, "
                "technique_id = EXCLUDED.technique_id, name = EXCLUDED.name, "
                "objective = EXCLUDED.objective, synced_at = now(), "
                "catalog_version = EXCLUDED.catalog_version",
                (strategy.id, strategy.det_id, strategy.technique_id, strategy.name,
                 strategy.objective, strategy.catalog_version),
            )
            for an in strategy.analytics:
                conn.execute(
                    "INSERT INTO mitre_analytics "
                    "(id, detection_strategy_id, name, description, platform, "
                    "log_source_references, mutable_elements, synced_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, now()) "
                    "ON CONFLICT (id) DO UPDATE SET "
                    "detection_strategy_id = EXCLUDED.detection_strategy_id, "
                    "name = EXCLUDED.name, description = EXCLUDED.description, "
                    "platform = EXCLUDED.platform, "
                    "log_source_references = EXCLUDED.log_source_references, "
                    "mutable_elements = EXCLUDED.mutable_elements, synced_at = now()",
                    (an.id, an.detection_strategy_id, an.name, an.description, an.platform,
                     json.dumps(an.log_source_references), json.dumps(an.mutable_elements)),
                )

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return {"strategies": len(strategies), "data_components": len(data_components)}


def _as_list(value) -> list:
    """psycopg3 may return jsonb as an already-decoded list/dict or as a
    raw string depending on connection setup -- handle both without
    assuming one."""
    if isinstance(value, list):
        return value
    return json.loads(value or "[]")


def _has_synced_before(conn) -> bool:
    return conn.execute("SELECT 1 FROM mitre_detection_strategies LIMIT 1").fetchone() is not None


def get_cached_strategy(conn, technique_id: str) -> MitreStrategy:
    """Read-only lookup against whatever's currently cached -- never
    triggers a sync. A technique_id with no matching row is a genuine
    'MITRE has no strategy for this' result once at least one sync_all()
    has run. Callers that need to distinguish that from 'never synced at
    all' should call get_mitre_strategy() instead."""
    strategy_row = conn.execute(
        "SELECT id, det_id, technique_id, objective, catalog_version "
        "FROM mitre_detection_strategies WHERE technique_id = ?",
        (technique_id,),
    ).fetchone()
    if strategy_row is None:
        return MitreStrategy(technique_id=technique_id, det_id=None, objective=None)

    analytic_rows = conn.execute(
        "SELECT name, description, platform, log_source_references, mutable_elements "
        "FROM mitre_analytics WHERE detection_strategy_id = ?",
        (strategy_row["id"],),
    ).fetchall()

    # Resolve every referenced data_component_id in one batched query rather
    # than one SELECT per log-source-reference -- this is the hot path
    # get_mitre_strategy() runs once per technique across a whole
    # alignment_check.py re-review sweep, so an N+1 query pattern here scales
    # badly. Collect the distinct ids first, look them all up via
    # WHERE id = ANY(?) (existing convention -- see db.py's REQUIRED_TABLES
    # check), then assemble the per-analytic output in Python.
    log_source_refs_by_row = [_as_list(row["log_source_references"]) for row in analytic_rows]
    dc_ids = {
        lsr.get("data_component_id")
        for refs in log_source_refs_by_row for lsr in refs
        if lsr.get("data_component_id")
    }
    dc_name_by_id: dict = {}
    if dc_ids:
        dc_rows = conn.execute(
            "SELECT id, name FROM mitre_data_components WHERE id = ANY(?)",
            (list(dc_ids),),
        ).fetchall()
        dc_name_by_id = {r["id"]: r["name"] for r in dc_rows}

    analytics_out = []
    for row, refs in zip(analytic_rows, log_source_refs_by_row):
        resolved = [
            {
                "data_component": dc_name_by_id.get(lsr.get("data_component_id"), lsr.get("data_component_id")),
                "name": lsr.get("name"), "channel": lsr.get("channel"),
            }
            for lsr in refs
        ]
        analytics_out.append({
            "name": row["name"], "description": row["description"], "platform": row["platform"],
            "log_sources": resolved, "mutable_elements": _as_list(row["mutable_elements"]),
        })

    return MitreStrategy(
        technique_id=technique_id, det_id=strategy_row["det_id"], objective=strategy_row["objective"],
        analytics=analytics_out, catalog_version=strategy_row["catalog_version"],
    )


def get_mitre_strategy(conn, technique_id: str, http_client: httpx.Client | None = None) -> MitreStrategy:
    """What alignment_check.py calls. Triggers exactly one sync_all() if
    the local cache has never been populated at all; otherwise reads
    whatever's cached, even if stale -- freshness is a scheduled job's
    concern (sync_all(), run on a future cadence), not this hot path's."""
    if not _has_synced_before(conn):
        sync_all(conn, http_client)
    return get_cached_strategy(conn, technique_id)
