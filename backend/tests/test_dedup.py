import pytest
import sqlite3
import os
import sys
import importlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pg_helpers import pg_test_conn as _pg_test_conn, table_columns

# Import and reload db to get the real module (test_feed_poll may have stubbed it)
import db as db_module
importlib.reload(db_module)


def test_schema_has_group_id_and_normalized_title(db_conn):
    """init_db must add group_id and normalized_title columns to entries."""
    db_module.init_db()
    cols = table_columns(db_conn, "entries")
    assert "group_id" in cols
    assert "normalized_title" in cols


# ── dedup module tests ────────────────────────────────────────────────────────
import importlib.util as _ilu, pathlib as _pl


def _load_dedup():
    spec = _ilu.spec_from_file_location(
        "dedup", _pl.Path(__file__).parent.parent / "dedup.py"
    )
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_title_strips_punctuation_and_lowercases():
    d = _load_dedup()
    assert d.normalize_title("CVE-2024-1234: Foo's Bar!") == "cve20241234 foos bar"


def test_normalize_title_collapses_whitespace():
    d = _load_dedup()
    result = d.normalize_title("  Hello   World  ")
    assert result == "hello   world"


def test_title_jaccard_identical_titles():
    d = _load_dedup()
    t = "ransomware group targets healthcare sector"
    assert d.title_jaccard(t, t) == 1.0


def test_title_jaccard_completely_different():
    d = _load_dedup()
    assert d.title_jaccard("python snake reptile", "cloud deploy azure") == 0.0


def test_title_jaccard_partial_overlap():
    d = _load_dedup()
    score = d.title_jaccard(
        "critical vulnerability in healthcare systems",
        "critical flaw found in healthcare software",
    )
    assert 0.2 < score < 0.4


def test_title_jaccard_above_threshold_for_same_story():
    d = _load_dedup()
    # Two headlines covering the same story with near-identical key terms.
    # Expected score ~0.78 (7 shared / 9 union): well above the 0.55 threshold.
    score = d.title_jaccard(
        "critical apache log4j vulnerability allows remote code execution",
        "critical vulnerability in apache log4j enables remote code execution",
    )
    assert score >= 0.55


def test_ioc_overlap_cve_match():
    d = _load_dedup()
    iocs_a = {"cves": ["CVE-2024-1234"], "ips": [], "hashes": [], "domains": []}
    iocs_b = {"cves": ["CVE-2024-1234"], "ips": [], "hashes": [], "domains": []}
    assert d._ioc_overlap(iocs_a, iocs_b) is True


def test_ioc_overlap_two_ips():
    d = _load_dedup()
    iocs_a = {"cves": [], "ips": ["1.2.3.4", "5.6.7.8"], "hashes": [], "domains": []}
    iocs_b = {"cves": [], "ips": ["1.2.3.4", "5.6.7.8"], "hashes": [], "domains": []}
    assert d._ioc_overlap(iocs_a, iocs_b) is True


def test_ioc_overlap_one_ip_only_no_match():
    d = _load_dedup()
    iocs_a = {"cves": [], "ips": ["1.2.3.4"], "hashes": [], "domains": []}
    iocs_b = {"cves": [], "ips": ["1.2.3.4"], "hashes": [], "domains": []}
    assert d._ioc_overlap(iocs_a, iocs_b) is False


def test_ioc_overlap_no_shared():
    d = _load_dedup()
    iocs_a = {"cves": ["CVE-2024-0001"], "ips": [], "hashes": [], "domains": []}
    iocs_b = {"cves": ["CVE-2024-9999"], "ips": [], "hashes": [], "domains": []}
    assert d._ioc_overlap(iocs_a, iocs_b) is False


def _seed_one(conn, title="94 of organizations report cloud breaches",
              source="CrowdStrike Blog", published="2026-06-22T10:00:00Z"):
    """Insert one entry, using the literal title as its normalized_title too
    (is_exact_duplicate compares against normalized_title directly, and
    these titles are already lowercase/punctuation-free enough to stand in
    for their own normalized form)."""
    conn.execute(
        "INSERT INTO entries (hash, source, title, normalized_title, published, iocs, group_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("abc", source, title, title, published, "{}", None),
    )
    conn.commit()


def test_is_exact_duplicate_same_title_same_day():
    d = _load_dedup()
    conn = _pg_test_conn()
    _seed_one(conn)
    assert d.is_exact_duplicate(
        conn, "CrowdStrike Blog", "94 of organizations report cloud breaches", "2026-06-22T10:00:00Z"
    ) is True


def test_is_exact_duplicate_different_source():
    d = _load_dedup()
    conn = _pg_test_conn()
    _seed_one(conn)
    assert d.is_exact_duplicate(
        conn, "TheHackerNews", "94 of organizations report cloud breaches", "2026-06-22T10:00:00Z"
    ) is False


def test_is_exact_duplicate_different_day():
    d = _load_dedup()
    conn = _pg_test_conn()
    _seed_one(conn)
    assert d.is_exact_duplicate(
        conn, "CrowdStrike Blog", "94 of organizations report cloud breaches", "2026-06-23T10:00:00Z"
    ) is False


import uuid


def _seed_entries(conn, rows):
    """rows: list of (hash, source, title, published, iocs, group_id)"""
    import dedup as _d
    for h, src, title, pub, iocs, gid in rows:
        import json as _json
        conn.execute(
            "INSERT INTO entries (hash, source, title, normalized_title, published, iocs, group_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (hash) DO NOTHING",
            (h, src, title, _d.normalize_title(title), pub, _json.dumps(iocs), gid),
        )
    conn.commit()


def test_run_dedup_pass_groups_similar_titles():
    from dedup import run_dedup_pass
    conn = _pg_test_conn()
    _seed_entries(conn, [
        ("h1", "CrowdStrike", "critical apache log4j vulnerability allows remote code execution",
         "2026-06-22T10:00:00Z", {}, None),
        ("h2", "TheHackerNews", "critical vulnerability in apache log4j enables remote code execution",
         "2026-06-22T12:00:00Z", {}, None),
    ])
    run_dedup_pass(conn, ["h1", "h2"])
    rows = {r[0]: r[1] for r in conn.execute("SELECT hash, group_id FROM entries")}
    assert rows["h1"] is not None
    assert rows["h1"] == rows["h2"], "Both entries should share a group_id"


def test_run_dedup_pass_no_group_for_unrelated():
    from dedup import run_dedup_pass
    conn = _pg_test_conn()
    _seed_entries(conn, [
        ("h1", "CrowdStrike", "ransomware targets healthcare sector",
         "2026-06-22T10:00:00Z", {}, None),
        ("h2", "TheHackerNews", "new python release with performance improvements",
         "2026-06-22T12:00:00Z", {}, None),
    ])
    run_dedup_pass(conn, ["h1", "h2"])
    rows = {r[0]: r[1] for r in conn.execute("SELECT hash, group_id FROM entries")}
    assert rows["h1"] is None
    assert rows["h2"] is None


def test_run_dedup_pass_joins_existing_group():
    from dedup import run_dedup_pass
    conn = _pg_test_conn()
    existing_gid = str(uuid.uuid4())
    _seed_entries(conn, [
        ("h1", "CrowdStrike", "critical apache log4j vulnerability allows remote code execution",
         "2026-06-22T10:00:00Z", {}, existing_gid),
        ("h2", "Talos", "critical vulnerability in apache log4j enables remote code execution",
         "2026-06-22T11:00:00Z", {}, None),
    ])
    run_dedup_pass(conn, ["h2"])
    rows = {r[0]: r[1] for r in conn.execute("SELECT hash, group_id FROM entries")}
    assert rows["h2"] == existing_gid


def test_backfill_dedup_groups_is_idempotent():
    from dedup import backfill_dedup_groups
    conn = _pg_test_conn()
    _seed_entries(conn, [
        ("h1", "CrowdStrike", "critical apache log4j vulnerability allows remote code execution",
         "2026-06-22T10:00:00Z", {}, None),
        ("h2", "TheHackerNews", "critical vulnerability in apache log4j enables remote code execution",
         "2026-06-22T12:00:00Z", {}, None),
    ])
    backfill_dedup_groups(conn)
    rows_first = {r[0]: r[1] for r in conn.execute("SELECT hash, group_id FROM entries")}
    backfill_dedup_groups(conn)
    rows_second = {r[0]: r[1] for r in conn.execute("SELECT hash, group_id FROM entries")}
    assert rows_first == rows_second
    assert rows_first["h1"] is not None
    assert rows_first["h1"] == rows_first["h2"]


def test_get_entries_returns_only_canonical():
    """get_entries must return only the canonical (best severity) entry per group."""
    import uuid

    conn = _pg_test_conn()

    gid = str(uuid.uuid4())
    conn.executemany(
        """INSERT INTO entries
           (hash, source, title, normalized_title, published, severity, priority_score, group_id, triaged, archived)
           VALUES (?,?,?,?,?,?,?,?,0,0)""",
        [
            ("h_high", "CrowdStrike", "Cloud Breach Survey", "cloud breach survey",
             "2026-06-22T10:00:00Z", "High", 0.8, gid),
            ("h_low",  "TheHackerNews", "Cloud Breach Survey 2024",
             "cloud breach survey 2024", "2026-06-22T11:00:00Z", "Low", 0.5, gid),
        ],
    )
    conn.commit()
    conn.close()

    rows = db_module.get_entries(date_window="all")
    hashes = [r["hash"] for r in rows]
    assert "h_high" in hashes, "Canonical (High severity) entry must appear"
    assert "h_low" not in hashes, "Non-canonical (Low severity) entry must be suppressed"
    canonical = next(r for r in rows if r["hash"] == "h_high")
    assert canonical["duplicate_count"] == 1


def test_get_entry_group_returns_all_members():
    """get_entry_group must return all entries in the group, canonical-first."""
    import uuid

    conn = _pg_test_conn()

    gid = str(uuid.uuid4())
    conn.executemany(
        """INSERT INTO entries
           (hash, source, title, normalized_title, published, severity, priority_score, group_id, triaged, archived)
           VALUES (?,?,?,?,?,?,?,?,0,0)""",
        [
            ("h1", "CrowdStrike", "Log4j RCE", "log4j rce",
             "2026-06-22T10:00:00Z", "Critical", 0.9, gid),
            ("h2", "TheHackerNews", "Log4j Exploit", "log4j exploit",
             "2026-06-22T11:00:00Z", "High", 0.7, gid),
        ],
    )
    conn.commit()
    conn.close()

    group = db_module.get_entry_group("h1")
    assert len(group) == 2
    assert group[0]["hash"] == "h1"  # Critical comes first
    assert group[1]["hash"] == "h2"

    # Returns empty list for ungrouped entry
    empty = db_module.get_entry_group("nonexistent")
    assert empty == []


def _load_feed_manager_fresh(name="feed_manager_test"):
    """Load feed_manager with stubs, bypassing any cached stubbed version.

    Restores every sys.modules entry it touches afterward -- it used to
    leave stubs (in particular ioc_finder.find_iocs -> {}) permanently
    installed, which silently broke any later test in the same pytest
    session that needed the real ioc_finder to actually extract IOCs (e.g.
    test_ioc_extraction.py, when collected after this file)."""
    import importlib.util as _ilu, pathlib as _pl, sys, types
    spec = _ilu.spec_from_file_location(name, _pl.Path(__file__).parent.parent / "feed_manager.py")
    fm = _ilu.module_from_spec(spec)

    touched = ["anthropic", "apscheduler", "apscheduler.schedulers",
               "apscheduler.schedulers.background", "feedparser",
               "ioc_finder", "db", "enrichment", "httpx"]
    originals = {mod: sys.modules.get(mod) for mod in touched}
    try:
        for mod in touched:
            if mod not in sys.modules:
                sys.modules[mod] = types.ModuleType(mod)
        # Always provide a proper httpx stub — test_feed_poll may leave one without .Client
        httpx_stub = types.ModuleType("httpx")
        class _Client:
            def __init__(self, *a, **k): pass
        httpx_stub.Client = _Client
        httpx_stub.get = lambda *a, **k: None
        sys.modules["httpx"] = httpx_stub
        bgsched = sys.modules["apscheduler.schedulers.background"]
        if not hasattr(bgsched, "BackgroundScheduler"):
            bgsched.BackgroundScheduler = object
        anth = sys.modules["anthropic"]
        if not hasattr(anth, "Anthropic"):
            class _AI:
                def __init__(self, *a, **k): pass
            anth.Anthropic = _AI
        db_stub = sys.modules["db"]
        for fn in ["_connect_db", "reconcile_exposure", "get_pending_triage", "get_triaged_for_retriage", "get_entries_by_hashes",
                   "apply_triage", "deduplicate_cves", "archive_old_entries",
                   "persist_runtime_db", "upsert_ioc_ledger"]:
            if not hasattr(db_stub, fn):
                setattr(db_stub, fn, lambda *a, **k: [])
        if not hasattr(db_stub, "DB_PATH"):
            db_stub.DB_PATH = ":memory:"
        enrich = sys.modules["enrichment"]
        for fn in ["run_enrichment", "refresh_kev_cache", "refresh_and_reenrich"]:
            if not hasattr(enrich, fn):
                setattr(enrich, fn, lambda *a, **k: None)
        ioc = sys.modules["ioc_finder"]
        if not hasattr(ioc, "find_iocs"):
            ioc.find_iocs = lambda text: {}
        spec.loader.exec_module(fm)
    finally:
        for mod, original in originals.items():
            if original is None:
                sys.modules.pop(mod, None)
            else:
                sys.modules[mod] = original

    return fm


def test_new_strict_intel_sources_present():
    """New sources added to _STRICT_INTEL_SOURCES must be present."""
    fm = _load_feed_manager_fresh("fm_sources_test")
    for source in ["Invicti Web Security", "Tech Republic", "Seqrite",
                   "Semgrep Blog", "Schneier", "Dark Reading"]:
        assert source in fm._STRICT_INTEL_SOURCES, \
            f"{source!r} should be in _STRICT_INTEL_SOURCES"


def test_new_promo_patterns_present():
    """New _PROMO_PATTERNS entries must be present."""
    fm = _load_feed_manager_fresh("fm_patterns_test")
    required = [
        r"\bstate of\b", r"\bsurvey\b", r"\broundup\b", r"\bwhat is\b",
        r"\bbest practices\b", r"\bbenchmark\b", r"\bpredictions?\b",
        r"\bbuyer'?s? guide\b", r"\bweek in\b", r"\binvestment\b",
    ]
    for pattern in required:
        assert any(p == pattern for p in fm._PROMO_PATTERNS), \
            f"Pattern {pattern!r} missing from _PROMO_PATTERNS"
