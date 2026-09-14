import importlib, sys, types, uuid

# Stub heavy deps so we can import feed_manager without real AI/DB
# feed_manager.py only ever binds these via top-level `import`/`from X
# import Y`, so once exec_module() below returns, fm's own namespace
# already holds everything it needs -- the stubs are restored/removed from
# sys.modules right after, so this doesn't leak into other test files
# collected in the same pytest session (previously it did: any later test
# needing the real `db` module, e.g. test_alignment_check.py's db_conn
# fixture, silently got this stub instead).
_STUBBED_MODULES = ["anthropic", "feedparser", "apscheduler", "apscheduler.schedulers",
                    "apscheduler.schedulers.background", "db", "enrichment"]
_originals = {mod: sys.modules.get(mod) for mod in _STUBBED_MODULES}

for mod in ["anthropic", "feedparser", "apscheduler", "apscheduler.schedulers",
            "apscheduler.schedulers.background"]:
    sys.modules.setdefault(mod, types.ModuleType(mod))
sys.modules["apscheduler.schedulers.background"].BackgroundScheduler = object

class _AnyInit:
    def __init__(self, *a, **k): pass

sys.modules["anthropic"].Anthropic = _AnyInit

import importlib.util, pathlib, os
os.environ.setdefault("ANTHROPIC_API_KEY", "test")

spec = importlib.util.spec_from_file_location("feed_manager",
       pathlib.Path(__file__).parent.parent / "feed_manager.py")
fm = importlib.util.module_from_spec(spec)

# Stub db imports
db_stub = types.ModuleType("db")
db_stub.DB_PATH = ":memory:"
for fn in ["_connect_db", "reconcile_exposure", "get_pending_triage","get_triaged_for_retriage","get_entries_by_hashes",
           "apply_triage","deduplicate_cves","archive_old_entries","persist_runtime_db",
           "upsert_ioc_ledger"]:
    setattr(db_stub, fn, lambda *a, **k: [])
enrich_stub = types.ModuleType("enrichment")
for fn in ["run_enrichment","refresh_kev_cache","refresh_and_reenrich"]:
    setattr(enrich_stub, fn, lambda *a, **k: None)
sys.modules["db"] = db_stub
sys.modules["enrichment"] = enrich_stub

try:
    spec.loader.exec_module(fm)
finally:
    for mod, original in _originals.items():
        if original is None:
            sys.modules.pop(mod, None)
        else:
            sys.modules[mod] = original


def test_create_job_returns_id():
    job_id = fm.create_job(total=10)
    assert isinstance(job_id, str)
    assert len(job_id) > 0
    job = fm.get_job(job_id)
    assert job["status"] == "running"
    assert job["total"] == 10
    assert job["completed"] == 0


def test_get_job_unknown_returns_none():
    assert fm.get_job("not-a-real-id") is None


def test_list_jobs_returns_last_20():
    for _ in range(25):
        fm.create_job(total=1)
    jobs = fm.list_jobs()
    assert len(jobs) <= 20


def test_job_cap_at_100():
    # Fill registry to 100 then add one more — oldest should be evicted
    for _ in range(100):
        fm.create_job(total=1)
    new_id = fm.create_job(total=1)
    assert new_id in fm._jobs
    assert len(fm._jobs) <= 100
