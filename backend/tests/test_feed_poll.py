import importlib, sys, types, os
import pathlib
import importlib.util

# ── Stub heavy deps before importing feed_manager ──────────────────────────
# feed_manager.py only ever binds these via top-level `import`/`from X
# import Y`, so once exec_module() below returns, fm's own namespace
# already holds everything it needs -- the stubs are restored/removed from
# sys.modules right after, so this doesn't leak into other test files
# collected in the same pytest session (previously it did: any later test
# needing the real `db` module, e.g. test_alignment_check.py's db_conn
# fixture, silently got this stub instead).
_STUBBED_MODULES = ["anthropic", "apscheduler", "apscheduler.schedulers",
                    "apscheduler.schedulers.background", "feedparser",
                    "httpx", "ioc_finder", "db", "enrichment"]
_originals = {mod: sys.modules.get(mod) for mod in _STUBBED_MODULES}

for mod in ["anthropic", "apscheduler", "apscheduler.schedulers",
            "apscheduler.schedulers.background"]:
    sys.modules.setdefault(mod, types.ModuleType(mod))
sys.modules["apscheduler.schedulers.background"].BackgroundScheduler = object

class _AnyInit:
    def __init__(self, *a, **k): pass

sys.modules["anthropic"].Anthropic = _AnyInit

os.environ.setdefault("ANTHROPIC_API_KEY", "test")

# Stub feedparser
feedparser_stub = types.ModuleType("feedparser")
sys.modules["feedparser"] = feedparser_stub

# Stub httpx (will be replaced per-test)
httpx_stub = types.ModuleType("httpx")
sys.modules["httpx"] = httpx_stub

# Stub ioc_finder
ioc_finder_stub = types.ModuleType("ioc_finder")
ioc_finder_stub.find_iocs = lambda text: {}
sys.modules["ioc_finder"] = ioc_finder_stub

# Stub db
db_stub = types.ModuleType("db")
db_stub.DB_PATH = ":memory:"
for fn in ["_connect_db", "reconcile_exposure", "get_pending_triage", "get_triaged_for_retriage", "get_entries_by_hashes",
           "apply_triage", "deduplicate_cves", "archive_old_entries",
           "persist_runtime_db", "upsert_ioc_ledger"]:
    setattr(db_stub, fn, lambda *a, **k: [])
sys.modules["db"] = db_stub

# Stub enrichment
enrich_stub = types.ModuleType("enrichment")
for fn in ["run_enrichment", "refresh_kev_cache", "refresh_and_reenrich"]:
    setattr(enrich_stub, fn, lambda *a, **k: None)
sys.modules["enrichment"] = enrich_stub

# Load feed_manager
spec = importlib.util.spec_from_file_location(
    "feed_manager",
    pathlib.Path(__file__).parent.parent / "feed_manager.py",
)
fm = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(fm)
finally:
    for mod, original in _originals.items():
        if original is None:
            sys.modules.pop(mod, None)
        else:
            sys.modules[mod] = original


def test_fetch_feed_success_returns_entries(monkeypatch):
    """_fetch_feed returns (feed_meta, entries) when HTTP fetch succeeds."""
    feed_meta = {"name": "TestFeed", "url": "https://example.com/feed.xml", "tier": 1}
    fake_content = b"<rss><channel><item><title>Test</title></item></channel></rss>"

    raise_for_status_called = []
    mock_response = types.SimpleNamespace(
        content=fake_content,
        raise_for_status=lambda: raise_for_status_called.append(True),
    )

    fake_entry = types.SimpleNamespace(title="Test Entry")
    captured = {}

    class _FakeHTTPX:
        @staticmethod
        def get(url, **kwargs):
            captured["url"] = url
            captured["timeout"] = kwargs.get("timeout")
            captured["follow_redirects"] = kwargs.get("follow_redirects")
            captured["headers"] = kwargs.get("headers") or {}
            return mock_response

        TimeoutException = Exception
        HTTPError = Exception
        RequestError = Exception

    parsed_content = []

    class _FakeFeedparser:
        @staticmethod
        def parse(content):
            parsed_content.append(content)
            return types.SimpleNamespace(entries=[fake_entry])

    monkeypatch.setattr(fm, "httpx", _FakeHTTPX)
    monkeypatch.setattr(fm, "feedparser", _FakeFeedparser)

    result_meta, result_entries, result_error = fm._fetch_feed(feed_meta)

    assert captured["url"] == "https://example.com/feed.xml"
    assert captured["timeout"] == 30
    assert captured["follow_redirects"] is True
    assert "Chrome/" in captured["headers"].get("User-Agent", "")
    assert "application/rss+xml" in captured["headers"].get("Accept", "")
    assert parsed_content == [fake_content], "feedparser.parse must receive response.content"
    assert raise_for_status_called, "_fetch_feed must call raise_for_status()"
    assert result_meta is feed_meta
    assert result_entries == [fake_entry]
    assert result_error == ""


def test_fetch_feed_timeout_returns_empty(monkeypatch):
    """_fetch_feed catches timeouts and returns empty entry list."""
    feed_meta = {"name": "SlowFeed", "url": "https://slow.example.com/feed.xml", "tier": 2}

    class _TimeoutHTTPX:
        class TimeoutException(Exception): pass
        class HTTPError(Exception): pass
        class RequestError(Exception): pass

        @staticmethod
        def get(url, **kwargs):
            raise _TimeoutHTTPX.TimeoutException("timed out")

    monkeypatch.setattr(fm, "httpx", _TimeoutHTTPX)

    result_meta, result_entries, result_error = fm._fetch_feed(feed_meta)

    assert result_meta is feed_meta
    assert result_entries is None
    assert result_error


def test_fetch_feed_http_error_returns_empty(monkeypatch):
    """_fetch_feed catches HTTP errors and returns empty entry list."""
    feed_meta = {"name": "BrokenFeed", "url": "https://broken.example.com/feed.xml", "tier": 3}

    class _ErrHTTPX:
        class TimeoutException(Exception): pass
        class HTTPError(Exception): pass
        class RequestError(Exception): pass

        @staticmethod
        def get(url, **kwargs):
            raise _ErrHTTPX.HTTPError("404 Not Found")

    monkeypatch.setattr(fm, "httpx", _ErrHTTPX)

    result_meta, result_entries, result_error = fm._fetch_feed(feed_meta)

    assert result_meta is feed_meta
    assert result_entries is None
    assert result_error


def test_poll_all_feeds_fetches_every_feed():
    """poll_all_feeds must call _fetch_feed once for each feed in FEEDS."""
    from pg_helpers import pg_test_conn as _pg_test_conn
    import db as _real_db

    fetched_names = []

    def fake_fetch(feed_meta):
        fetched_names.append(feed_meta["name"])
        return feed_meta, [], ""

    # Patch _fetch_feed and the DB so no real I/O happens. fm's own
    # _connect_db binding was captured from the stubbed db module at
    # feed_manager.py load time (see the module-level stub/restore dance at
    # the top of this file) -- it doesn't track later changes to sys.modules
    # ["db"], so it has to be repointed here explicitly, same as any other
    # test in this file that needs poll_all_feeds() to do real DB work.
    original_fetch = fm._fetch_feed
    original_connect_db = fm._connect_db
    try:
        fm._fetch_feed = fake_fetch
        _pg_test_conn().close()  # truncate once; poll_all_feeds() connects twice itself
        fm._connect_db = _real_db._connect_db

        fm.poll_all_feeds()
    finally:
        fm._fetch_feed = original_fetch
        fm._connect_db = original_connect_db

    expected_names = {f["name"] for f in fm.FEEDS}
    assert set(fetched_names) == expected_names, (
        f"Missing feeds: {expected_names - set(fetched_names)}"
    )


def test_poll_all_feeds_writes_entries_from_successful_feeds():
    """A feed that returns [] (e.g. timed out) doesn't block entries from other feeds."""
    from pg_helpers import pg_test_conn as _pg_test_conn
    import db as _real_db

    GOOD_FEED = fm.FEEDS[0]   # first feed in the list

    def fake_fetch(feed_meta):
        if feed_meta["name"] == GOOD_FEED["name"]:
            entry = types.SimpleNamespace(
                id="test-id-1",
                link="https://example.com/article1",
                title="Critical CVE-2025-9999 Exploited in the Wild",
                get=lambda k, d="": {
                    "title": "Critical CVE-2025-9999 Exploited in the Wild",
                    "link": "https://example.com/article1",
                    "summary": "CVE-2025-9999 is being actively exploited.",
                    "content": [],
                    "tags": [],
                    "id": "test-id-1",
                }.get(k, d),
            )
            return feed_meta, [entry], ""
        return feed_meta, [], ""  # simulates timeout / error: no new entries

    original_fetch = fm._fetch_feed
    original_connect_db = fm._connect_db
    try:
        fm._fetch_feed = fake_fetch
        _pg_test_conn().close()  # truncate once; poll_all_feeds() connects twice itself
        fm._connect_db = _real_db._connect_db
        fm.poll_all_feeds()
    finally:
        fm._fetch_feed = original_fetch
        fm._connect_db = original_connect_db

    conn = _real_db._connect_db()
    written = conn.execute(
        "SELECT hash FROM entries WHERE link = 'https://example.com/article1'"
    ).fetchall()
    conn.close()
    assert len(written) >= 1, "Expected at least one entry written from the good feed"


def test_feed_url_fixes_and_retired_sources():
    """Working replacements stay in FEEDS; dead MSRC blog RSS is not polled."""
    by_name = {f["name"]: f for f in fm.FEEDS}
    assert by_name["CISA"]["url"] == "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    assert by_name["Sekoia"]["url"] == "https://www.sekoia.com/blog/rss.xml"
    assert by_name["Cymulate"]["url"] == "https://cymulate.com/feed/?post_type=blog"
    assert by_name["Securonix"]["url"] == "https://www.securonix.com/feed/?post_type=blog"
    assert by_name["Sophos (Security Operations)"]["url"].startswith(
        "https://www.sophos.com/en-us/category/security-operations/feed"
    )
    assert by_name["Sophos (Threat Research)"]["url"].startswith(
        "https://www.sophos.com/en-us/category/threat-research/feed"
    )
    assert by_name["Microsoft MSRC"]["url"] == "https://api.msrc.microsoft.com/update-guide/rss"
    assert by_name["Microsoft MSRC"]["ingest"] == "delta"
    assert "Chrome/" in fm._FEED_USER_AGENT
    assert "application/rss+xml" in fm._FEED_ACCEPT


def _delta_sqlite(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.setenv("FEED_DELTA_DIR", str(tmp_path))
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE entries (
            hash TEXT PRIMARY KEY,
            source TEXT,
            title TEXT,
            summary TEXT,
            published TEXT,
            triaged INTEGER DEFAULT 0,
            enriched INTEGER DEFAULT 0,
            ai_summary TEXT DEFAULT '',
            ttps TEXT DEFAULT ''
        )"""
    )
    return conn


def _delta_items(feed_name="Microsoft MSRC"):
    return fm._load_delta_store(feed_name).get("items") or {}


def _msrc_entry(cve, title_rest, published, summary="desc"):
    title = f"{cve} {title_rest}"
    link = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
    return {
        "id": link,
        "title": title,
        "link": link,
        "summary": summary,
        "published": published,
        "updated": published,
        "content": [],
        "tags": [],
    }


def test_delta_item_id_prefers_cve():
    entry = _msrc_entry("CVE-2026-24301", "Copilot Info Disclosure", "Tue, 18 Aug 2026 07:00:00 -0700")
    assert fm._delta_item_id(entry) == "CVE-2026-24301"


def test_delta_baseline_remembers_all_and_seeds_recent(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    entries = [
        _msrc_entry("CVE-2026-24301", "Copilot", "Tue, 18 Aug 2026 07:00:00 -0700"),
        _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700"),
    ]
    kept = fm._filter_delta_entries(conn, feed, entries, now)
    items = _delta_items()
    assert sorted(items) == ["CVE-2026-10001", "CVE-2026-24301"]
    assert [fm._delta_item_id(e) for e in kept] == ["CVE-2026-24301"]
    assert items["CVE-2026-24301"]["ingested"] == 1
    assert items["CVE-2026-10001"]["ingested"] == 0


def test_delta_second_poll_skips_unchanged(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    entries = [
        _msrc_entry("CVE-2026-24301", "Copilot", "Tue, 18 Aug 2026 07:00:00 -0700"),
        _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700"),
    ]
    fm._filter_delta_entries(conn, feed, entries, now)
    kept = fm._filter_delta_entries(conn, feed, entries, now)
    assert kept == []


def test_delta_new_cve_is_ingested_after_baseline(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    baseline = [
        _msrc_entry("CVE-2026-24301", "Copilot", "Tue, 18 Aug 2026 07:00:00 -0700"),
        _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700"),
    ]
    fm._filter_delta_entries(conn, feed, baseline, now)
    later = datetime(2026, 8, 19, 20, 0, tzinfo=timezone.utc)
    plus_new = baseline + [
        _msrc_entry("CVE-2026-99999", "Brand new", "Wed, 19 Aug 2026 07:00:00 -0700"),
    ]
    kept = fm._filter_delta_entries(conn, feed, plus_new, later)
    assert [fm._delta_item_id(e) for e in kept] == ["CVE-2026-99999"]


def test_delta_content_change_requeues_unseeded_item(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    old = _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700", summary="original")
    fm._filter_delta_entries(conn, feed, [old], now)
    revised = _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700", summary="now exploited in the wild")
    kept = fm._filter_delta_entries(conn, feed, [revised], now)
    assert [fm._delta_item_id(e) for e in kept] == ["CVE-2026-10001"]
    assert _delta_items()["CVE-2026-10001"]["ingested"] == 1


def test_delta_prepopulated_file_skips_catalog_and_keeps_new(tmp_path, monkeypatch):
    """A snapshot file is not a first-poll baseline: unchanged CVEs stay out."""
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    old = _msrc_entry("CVE-2026-10001", "Old one", "Wed, 20 May 2026 01:01:33 -0700")
    fm._save_delta_store("Microsoft MSRC", {
        "source": "Microsoft MSRC",
        "updated": now.isoformat(),
        "items": {
            "CVE-2026-10001": {
                "content_hash": fm._delta_content_hash(old),
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "ingested": 0,
            }
        },
    })
    kept = fm._filter_delta_entries(conn, feed, [old], now)
    assert kept == []
    plus_new = [
        old,
        _msrc_entry("CVE-2026-99999", "Brand new", "Tue, 18 Aug 2026 07:00:00 -0700"),
    ]
    kept = fm._filter_delta_entries(conn, feed, plus_new, now)
    assert [fm._delta_item_id(e) for e in kept] == ["CVE-2026-99999"]


def test_delta_keeps_newest_revision_per_cve(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    older = _msrc_entry("CVE-2026-40400", "PowerShell", "Tue, 14 Jul 2026 07:00:00 -0700", summary="orig")
    newer = _msrc_entry("CVE-2026-40400", "PowerShell", "Mon, 17 Aug 2026 07:00:00 -0700", summary="ack updated")
    kept = fm._filter_delta_entries(conn, feed, [newer, older], now)
    items = _delta_items()
    assert list(items) == ["CVE-2026-40400"]
    assert items["CVE-2026-40400"]["content_hash"] == fm._delta_content_hash(newer)
    assert [fm._delta_item_id(e) for e in kept] == ["CVE-2026-40400"]
    assert fm._filter_delta_entries(conn, feed, [older, newer], now) == []


def test_delta_content_change_updates_already_ingested_entry(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    conn = _delta_sqlite(tmp_path, monkeypatch)
    now = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    feed = {"name": "Microsoft MSRC", "ingest": "delta", "delta_seed_hours": 48}
    entry = _msrc_entry("CVE-2026-24301", "Copilot", "Tue, 18 Aug 2026 07:00:00 -0700", summary="first")
    kept = fm._filter_delta_entries(conn, feed, [entry], now)
    assert len(kept) == 1
    h = fm._entry_hash(entry)
    conn.execute(
        "INSERT INTO entries (hash, source, title, summary, published, triaged, enriched) "
        "VALUES (?, 'Microsoft MSRC', ?, 'first', 'x', 1, 1)",
        (h, entry["title"]),
    )
    revised = _msrc_entry("CVE-2026-24301", "Copilot", "Tue, 18 Aug 2026 07:00:00 -0700", summary="updated advisory")
    kept2 = fm._filter_delta_entries(conn, feed, [revised], now)
    assert kept2 == []
    row = conn.execute("SELECT summary, triaged, enriched FROM entries WHERE hash=?", (h,)).fetchone()
    assert row["summary"] == "updated advisory"
    assert row["triaged"] == 0
    assert row["enriched"] == 0
