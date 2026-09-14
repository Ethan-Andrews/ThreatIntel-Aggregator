import sys
import types
import os
import pytest

# Stub heavy deps so feed_manager can be loaded without real AI/DB/scheduler.
# Use module scope to restore sys.modules after all tests in this file finish.

_ORIGINAL_MODULES = {}
_STUB_KEYS = []


@pytest.fixture(scope="module", autouse=True)
def _stub_feed_manager_deps():
    """Install lightweight stubs before loading feed_manager, restore after."""
    import importlib.util
    import pathlib

    stub_specs = {
        "anthropic": {"Anthropic": type("Anthropic", (), {"__init__": lambda s, *a, **k: None})},
        "feedparser": {},
        "apscheduler": {},
        "apscheduler.schedulers": {},
        "apscheduler.schedulers.background": {
            "BackgroundScheduler": type("BackgroundScheduler", (), {"__init__": lambda s, *a, **k: None})
        },
        "db": {
            "DB_PATH": ":memory:",
            **{fn: lambda *a, **k: [] for fn in [
                "_connect_db", "get_pending_triage", "get_triaged_for_retriage", "get_entries_by_hashes",
                "apply_triage", "deduplicate_cves", "archive_old_entries", "persist_runtime_db",
                "get_failed_triage", "upsert_ioc_ledger",
            ]},
        },
        "enrichment": {
            **{fn: lambda *a, **k: None for fn in [
                "run_enrichment", "refresh_kev_cache", "refresh_and_reenrich"
            ]},
        },
    }

    originals = {}
    for key, attrs in stub_specs.items():
        originals[key] = sys.modules.get(key)
        mod = types.ModuleType(key)
        for attr, val in attrs.items():
            setattr(mod, attr, val)
        sys.modules[key] = mod

    os.environ.setdefault("ANTHROPIC_API_KEY", "test")

    # Load feed_manager fresh under an isolated name
    fm_path = pathlib.Path(__file__).parent.parent / "feed_manager.py"
    spec = importlib.util.spec_from_file_location("_feed_manager_test_isolated", fm_path)
    fm = importlib.util.module_from_spec(spec)
    sys.modules["_feed_manager_test_isolated"] = fm
    originals["_feed_manager_test_isolated"] = None
    spec.loader.exec_module(fm)

    yield fm

    # Restore all original modules
    for key, original in originals.items():
        if original is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = original


def test_extract_iocs_finds_ip(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("Test", "Attack originated from 192.168.1.100", "")
    assert "192.168.1.100" in result["ips"]


def test_extract_iocs_finds_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("C2 at evil.com", "", "")
    assert "evil.com" in result["domains"]


def test_extract_iocs_finds_url(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("Payload", "Download from http://evil.com/payload.exe", "")
    assert any("evil.com" in u for u in result["urls"])


def test_extract_iocs_finds_cve(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("CVE-2021-44228 exploited", "", "")
    assert "CVE-2021-44228" in result["cves"]


def test_extract_iocs_finds_sha256(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    sha = "a" * 64
    result = fm._extract_iocs("Hash found", sha, "")
    assert sha in result["hashes"]


def test_extract_iocs_prefers_content_over_summary(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("Title", "no iocs here", "Attack from 10.0.0.1")
    assert "10.0.0.1" in result["ips"]


def test_extract_iocs_handles_defanged(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("C2", "evil[.]com and hxxp://bad[.]com/path", "")
    domains_and_urls = result["domains"] + result["urls"]
    assert any("evil" in v for v in domains_and_urls)


def test_extract_iocs_returns_empty_on_clean_text(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("Blog post", "This is a general security article with no IOCs.", "")
    assert result["ips"] == []
    assert result["cves"] == []


def test_extract_iocs_caps_ips(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    ips_text = " ".join(f"1.2.3.{i}" for i in range(40))
    result = fm._extract_iocs("Many IPs", ips_text, "")
    assert len(result["ips"]) <= fm._MAX_IPS
    assert len(result["ips"]) < 40


def test_extract_iocs_all_keys_present(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("", "", "")
    assert set(result.keys()) == {"ips", "hashes", "cves", "domains", "urls"}


def test_extract_iocs_excludes_source_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Threatpost article",
        "C2 at evil.com. Also see threatpost.com/news",
        "",
        exclude_domain="threatpost.com",
    )
    assert "threatpost.com" not in result["domains"]
    assert not any("threatpost.com" in u for u in result["urls"])
    assert "evil.com" in result["domains"]


def test_extract_iocs_excludes_subdomain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Article",
        "Visit www.example.com and also evil.com",
        "",
        exclude_domain="example.com",
    )
    assert "www.example.com" not in result["domains"]
    assert "example.com" not in result["domains"]
    assert "evil.com" in result["domains"]


def test_extract_iocs_empty_exclude_unchanged(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs("C2 at evil.com", "", "", exclude_domain="")
    assert "evil.com" in result["domains"]


def test_extract_iocs_does_not_filter_unrelated_domain_with_substring(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Article from example.com",
        "Download http://notexample.com/evil.exe",
        "",
        exclude_domain="example.com",
    )
    assert any("notexample.com" in u for u in result["urls"])


def test_extract_iocs_excludes_source_domain_case_insensitive(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Article",
        "C2 at evil.com. Also see ThreatPost.com/news",
        "",
        exclude_domain="ThreatPost.com",
    )
    assert not any("threatpost.com" in d.lower() for d in result["domains"])
    assert not any("threatpost.com" in u.lower() for u in result["urls"])
    assert "evil.com" in result["domains"]


# --- Benign vendor/infra/media apex domain false positives ------------------

def test_extract_iocs_filters_microsoft_com(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Patch Tuesday",
        "Users should update via microsoft.com to receive the fix. C2 at evil.com.",
        "",
    )
    assert "microsoft.com" not in result["domains"]
    assert "evil.com" in result["domains"]


def test_extract_iocs_filters_benign_vendor_subdomain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Advisory",
        "See support.microsoft.com/help and download.microsoft.com for details.",
        "",
    )
    combined = result["domains"] + result["urls"]
    assert not any("microsoft.com" in v.lower() for v in combined)


def test_extract_iocs_filters_benign_vendor_url(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Advisory",
        "Read more at https://www.microsoft.com/security/blog/advisory and download the payload from http://evil.com/payload.exe",
        "",
    )
    assert not any("microsoft.com" in u for u in result["urls"])
    assert any("evil.com" in u for u in result["urls"])


def test_extract_iocs_filters_google_and_github(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Report",
        "The sample was uploaded to virustotal.com and referenced a github.com repo, "
        "while beaconing to malicious-c2.net.",
        "",
    )
    assert "virustotal.com" not in result["domains"]
    assert "github.com" not in result["domains"]
    assert "malicious-c2.net" in result["domains"]


def test_extract_iocs_filters_security_news_and_vendor_domains(_stub_feed_manager_deps):
    """News outlets and security vendors are routinely the *source* or a
    cross-reference in a write-up, not attacker infrastructure — expanded
    denylist coverage beyond the original ~35-domain set."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Weekly roundup",
        "Coverage from bleepingcomputer.com and krebsonsecurity.com cited analysis "
        "from crowdstrike.com and mandiant.com regarding a sample submitted to "
        "any.run, while the actual dropper beaconed to real-attacker-c2.biz.",
        "",
    )
    for benign in ("bleepingcomputer.com", "krebsonsecurity.com", "crowdstrike.com",
                   "mandiant.com", "any.run"):
        assert benign not in result["domains"], f"{benign!r} should have been filtered"
    assert "real-attacker-c2.biz" in result["domains"]


# --- Filename-mislabeled-as-domain false positives --------------------------

def test_extract_iocs_does_not_label_python_script_as_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Dropper analysis",
        "The dropper writes a script named dropper.py to disk and executes it, "
        "then contacts evil-c2.com for tasking.",
        "",
    )
    assert "dropper.py" not in result["domains"]
    assert "evil-c2.com" in result["domains"]


def test_extract_iocs_does_not_label_shell_script_as_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Linux malware",
        "It drops install.sh and run.sh in /tmp before beaconing to badhost.net.",
        "",
    )
    assert "install.sh" not in result["domains"]
    assert "run.sh" not in result["domains"]
    assert "badhost.net" in result["domains"]


def test_extract_iocs_keeps_filename_like_domain_when_used_as_url_host(_stub_feed_manager_deps):
    """A 'name.tld' host is not filtered as a filename when it is corroborated
    by appearing as the host of an actual extracted URL."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "C2 report",
        "Malware beacons to http://evil.sh/gate.php for tasking.",
        "",
    )
    assert any("evil.sh" in u for u in result["urls"])
    if result["domains"]:
        assert "evil.sh" in result["domains"]


def test_extract_iocs_keeps_filename_like_domain_with_subdomain(_stub_feed_manager_deps):
    """A 'sub.name.tld' match has a subdomain structure atypical of a filename,
    so it is kept even without URL corroboration."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "C2 report",
        "Beacons observed to c2.malicious-actor.sh over HTTPS.",
        "",
    )
    assert "c2.malicious-actor.sh" in result["domains"]


def test_extract_iocs_does_not_drop_dotapp_or_dotdev_c2_domains(_stub_feed_manager_deps):
    """Regression guard: '.app' and '.dev' are actively-abused gTLDs for real
    C2 infrastructure (confirmed against live public feed data), not filenames
    — they must never be added back to the filename-TLD denylist."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Campaign report",
        "The malware beacons to somakop.app and a second payload calls out to "
        "getcloudsolutions.dev for tasking.",
        "",
    )
    assert "somakop.app" in result["domains"]
    assert "getcloudsolutions.dev" in result["domains"]


# --- Direct unit tests for the new helper predicates ------------------------
# These pin down exact filter behavior independent of ioc-finder's own
# domain/URL parsing quirks (e.g. whether a URL-embedded host also surfaces
# in the bare "domains" list).

def test_is_benign_apex_matches_exact_and_subdomain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._is_benign_apex("microsoft.com") is True
    assert fm._is_benign_apex("support.microsoft.com") is True
    assert fm._is_benign_apex("www.github.com") is True


def test_is_benign_apex_does_not_match_unrelated_or_substring_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._is_benign_apex("evil.com") is False
    assert fm._is_benign_apex("notmicrosoft.com") is False
    assert fm._is_benign_apex("") is False


def test_looks_like_filename_flags_bare_dual_use_tld(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._looks_like_filename("dropper.py", set()) is True
    assert fm._looks_like_filename("install.sh", set()) is True


def test_looks_like_filename_spares_ordinary_domain(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._looks_like_filename("evil.com", set()) is False


def test_looks_like_filename_spares_subdomain_structure(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._looks_like_filename("c2.malicious-actor.sh", set()) is False


def test_looks_like_filename_spares_domain_corroborated_by_url_host(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    assert fm._looks_like_filename("evil.sh", {"evil.sh"}) is False


def test_looks_like_filename_does_not_flag_app_dev_zip(_stub_feed_manager_deps):
    """.app/.dev/.zip must never be treated as filename-shaped TLDs — see the
    _FILE_EXTENSION_TLDS docstring for why."""
    fm = _stub_feed_manager_deps
    assert fm._looks_like_filename("somakop.app", set()) is False
    assert fm._looks_like_filename("getcloudsolutions.dev", set()) is False
    assert fm._looks_like_filename("invoice.zip", set()) is False


# --- Deterministic truncation (regression: non-deterministic set ordering) --

def test_dedupe_preserve_order_keeps_first_seen_order(_stub_feed_manager_deps):
    fm = _stub_feed_manager_deps
    values = ["c.com", "a.com", "b.com", "a.com", "c.com"]
    assert fm._dedupe_preserve_order(values) == ["c.com", "a.com", "b.com"]


def test_extract_iocs_truncation_is_deterministic_across_runs(_stub_feed_manager_deps):
    """Regression test for a real bug: the pre-fix implementation deduped
    domains through a plain `set()` before truncating to the cap, so which
    domains survived a report with more distinct domains than the cap was
    dependent on Python's randomized string hashing — the exact same input
    could pass or fail from run to run. Running extraction twice on identical
    input (in-process, so any hash-seed effect would apply equally to both
    calls) must yield identical, order-stable output either way; running it
    across fresh subprocesses (a different PYTHONHASHSEED each time) pins
    down that the result no longer depends on hash seed at all.
    """
    fm = _stub_feed_manager_deps
    domains = [f"malicious-{i:02d}.com" for i in range(30)]
    body = " ".join(f"C2 node {d} was observed." for d in domains)

    result_a = fm._extract_iocs("Campaign report", body, "")
    result_b = fm._extract_iocs("Campaign report", body, "")
    assert result_a["domains"] == result_b["domains"]
    # First-seen order should be preserved up to the cap, not re-ordered.
    assert result_a["domains"] == domains[: fm._MAX_DOMAINS]


def test_extract_iocs_truncation_deterministic_across_hash_seeds():
    """Same as above, but actually varies PYTHONHASHSEED across subprocesses
    to prove the result is independent of hash randomization, not just
    stable within one already-seeded process."""
    import subprocess
    import sys as _sys

    script = (
        "import sys, types, os\n"
        "stub_specs = {\n"
        "    'anthropic': {'Anthropic': type('Anthropic', (), {'__init__': lambda s,*a,**k: None})},\n"
        "    'feedparser': {}, 'apscheduler': {}, 'apscheduler.schedulers': {},\n"
        "    'apscheduler.schedulers.background': {'BackgroundScheduler': type('B', (), {'__init__': lambda s,*a,**k: None})},\n"
        "    'db': {'DB_PATH': ':memory:'},\n"
        "    'enrichment': {},\n"
        "}\n"
        "for k, attrs in stub_specs.items():\n"
        "    m = types.ModuleType(k)\n"
        "    for a, v in attrs.items():\n"
        "        setattr(m, a, v)\n"
        "    sys.modules[k] = m\n"
        "for fn in ['_connect_db','get_pending_triage','get_triaged_for_retriage','get_entries_by_hashes','apply_triage','deduplicate_cves','archive_old_entries','persist_runtime_db','get_failed_triage','upsert_ioc_ledger']:\n"
        "    setattr(sys.modules['db'], fn, lambda *a,**k: [])\n"
        "for fn in ['run_enrichment','refresh_kev_cache','refresh_and_reenrich']:\n"
        "    setattr(sys.modules['enrichment'], fn, lambda *a,**k: None)\n"
        "os.environ.setdefault('ANTHROPIC_API_KEY', 'test')\n"
        "import importlib.util, pathlib\n"
        "fm_path = pathlib.Path.cwd() / 'feed_manager.py'\n"
        "spec = importlib.util.spec_from_file_location('_fm_hashseed_check', fm_path)\n"
        "fm = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(fm)\n"
        "domains = [f'malicious-{i:02d}.com' for i in range(30)]\n"
        "body = ' '.join(f'C2 node {d} was observed.' for d in domains)\n"
        "result = fm._extract_iocs('Campaign report', body, '')\n"
        "print(','.join(result['domains']))\n"
    )
    outputs = set()
    for seed in ("0", "1", "42"):
        proc = subprocess.run(
            [_sys.executable, "-c", script],
            cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        outputs.add(proc.stdout.strip())
    assert len(outputs) == 1, f"truncated domain list varies by PYTHONHASHSEED: {outputs}"
