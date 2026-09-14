"""Regression tests for _extract_iocs() driven by real public threat-intel feeds.

Domains below are frozen snapshots of GENUINE, currently/recently active
malicious indicators pulled from two free, public, community-maintained feeds
on GitHub (fetched 2026-08-31):

  - stamparm/blackbook (public domain historical malware C2 blacklist,
    aggregated from URLhaus/CyberCrime-Tracker/ScumBots/Benkow/ViriBack):
    https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt

  - mitchellkrogza/Phishing.Database (community-maintained active phishing
    domain/link feed, updated continuously):
    https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt

These are snapshotted (not fetched live in CI) so the suite stays hermetic
and deterministic, while still exercising the extractor against real-world
data quality problems instead of hand-crafted "evil.com" strings.

The entries `somakop.app`, `musarno.app`, `softkey.app`, `getcloudsolutions.dev`,
`gammaproject.dev`, and `topgamecheats.dev` pin a real false-negative bug
found during this work: ".app" and ".dev" are actively-sold gTLDs that
legitimate and malicious infrastructure both use, so treating a bare
"name.app"/"name.dev" match as "probably a filename" silently dropped
genuine C2 domains. They guard against that regression coming back.
"""

import os

import pytest


# A representative sample of genuinely malicious C2 domains, taken verbatim
# from stamparm/blackbook (public domain).
_REAL_MALICIOUS_C2_DOMAINS = [
    "statsrvv.com",
    "kaspersky-secure.ru",
    "werdotx.shop",
    "sodiumlaurethsulfatedesyroyer.com",
    "simple-updatereport.com",
    "ulysse-cazabonne.cam",
    "cncdevelopment.org",
    # .app / .dev bare two-label domains — regression guard, see module docstring.
    "somakop.app",
    "musarno.app",
    "softkey.app",
    "getcloudsolutions.dev",
    "gammaproject.dev",
    "topgamecheats.dev",
]

# A representative sample of genuinely active phishing domains, taken
# verbatim from mitchellkrogza/Phishing.Database.
_REAL_PHISHING_DOMAINS = [
    "000717-coinbase.com",
    "societegeneral-securedaccount.fr",
    "boutique-dofus.fr",
    "000-845int283-000.xyz",
    "000dmobilt9034.com",
    "cryptolvl-rsa-check.com",
]

_ALL_REAL_MALICIOUS_DOMAINS = _REAL_MALICIOUS_C2_DOMAINS + _REAL_PHISHING_DOMAINS


@pytest.fixture(scope="module", autouse=True)
def _stub_feed_manager_deps():
    """Reuse the same stubbing strategy as test_ioc_extraction.py so this
    module can load feed_manager standalone without real AI/DB/scheduler."""
    import importlib.util
    import pathlib
    import sys
    import types

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

    fm_path = pathlib.Path(__file__).parent.parent / "feed_manager.py"
    spec = importlib.util.spec_from_file_location("_feed_manager_test_isolated_pubfeed", fm_path)
    fm = importlib.util.module_from_spec(spec)
    sys.modules["_feed_manager_test_isolated_pubfeed"] = fm
    originals["_feed_manager_test_isolated_pubfeed"] = None
    spec.loader.exec_module(fm)

    yield fm

    for key, original in originals.items():
        if original is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = original


# --- No false negatives: every real malicious domain must survive extraction

@pytest.mark.parametrize("domain", _ALL_REAL_MALICIOUS_DOMAINS)
def test_real_malicious_domain_bare_is_extracted(_stub_feed_manager_deps, domain):
    """Each real malicious domain, mentioned bare in prose, must be extracted."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Malware campaign analysis",
        f"Analysts observed beaconing traffic to {domain} during the intrusion.",
        "",
    )
    assert domain in result["domains"], f"real malicious domain {domain!r} was filtered out"


@pytest.mark.parametrize("domain", _ALL_REAL_MALICIOUS_DOMAINS)
def test_real_malicious_domain_as_url_is_extracted(_stub_feed_manager_deps, domain):
    """Each real malicious domain, used as a URL host, must be extracted."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Malware campaign analysis",
        f"The payload was retrieved from http://{domain}/gate.php during the intrusion.",
        "",
    )
    assert any(domain in u for u in result["urls"]), f"real malicious URL host {domain!r} was filtered out"


def test_real_malicious_domains_survive_together_in_one_report(_stub_feed_manager_deps):
    """A single realistic write-up mentioning many real malicious domains at
    once must retain all of them (no cross-suppression, no cap regressions
    for a report of this size — see _MAX_DOMAINS and _dedupe_preserve_order
    in feed_manager.py for the truncation-cap and ordering fix this pins)."""
    fm = _stub_feed_manager_deps
    body = " ".join(
        f"C2 node {d} was active." for d in _ALL_REAL_MALICIOUS_DOMAINS
    )
    result = fm._extract_iocs("Campaign report", body, "")
    assert len(_ALL_REAL_MALICIOUS_DOMAINS) <= fm._MAX_DOMAINS, (
        "test fixture grew larger than _MAX_DOMAINS — this assertion would "
        "start failing for a reason unrelated to what this test checks"
    )
    for d in _ALL_REAL_MALICIOUS_DOMAINS:
        assert d in result["domains"], f"{d!r} dropped when co-occurring with other real IOCs"


# --- No false positives: realistic prose citing real benign vendor context
# alongside real malicious infrastructure must only keep the malicious side.

def test_real_report_style_text_filters_vendor_noise_keeps_real_c2(_stub_feed_manager_deps):
    """Mimics a real advisory: legitimate vendor/reference links mixed with
    genuine C2 domains from the public feed snapshot. Only the malicious
    domains should survive."""
    fm = _stub_feed_manager_deps
    summary = (
        "Microsoft (see https://www.microsoft.com/security/blog/advisory) disclosed a "
        "vulnerability actively exploited in the wild. Proof-of-concept code was published "
        "on github.com and the CVE record is tracked at nist.gov. Coverage from "
        "bleepingcomputer.com noted CrowdStrike (crowdstrike.com) attributed the activity. "
        "During incident response, the compromised host was observed beaconing to "
        "statsrvv.com and kaspersky-secure.ru, and later dropped a secondary payload "
        "contacting getcloudsolutions.dev for tasking. A related phishing kit hosted at "
        "societegeneral-securedaccount.fr harvested credentials from victims who followed "
        "a link shared over google.com search ads."
    )
    result = fm._extract_iocs("Advisory: active exploitation observed", summary, "")

    for benign in ("microsoft.com", "github.com", "nist.gov", "google.com",
                   "bleepingcomputer.com", "crowdstrike.com"):
        assert not any(benign in d.lower() for d in result["domains"]), \
            f"benign vendor domain {benign!r} leaked into domains"
        assert not any(benign in u.lower() for u in result["urls"]), \
            f"benign vendor domain {benign!r} leaked into urls"

    for malicious in ("statsrvv.com", "kaspersky-secure.ru", "getcloudsolutions.dev",
                       "societegeneral-securedaccount.fr"):
        assert malicious in result["domains"], f"real malicious domain {malicious!r} was filtered out"


def test_real_phishing_url_path_brand_mentions_do_not_leak_as_domains(_stub_feed_manager_deps):
    """Real Phishing.Database entries embed brand names in the URL *path*
    (e.g. .../banks/cibc, .../santanderbanco.es/...) to impersonate banks.
    Path segments must not be misread as extra domains distinct from the
    actual malicious host."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Phishing kit analysis",
        "The kit was served from http://000dmobilt9034.com/finance/atb/details.php "
        "and mimicked a banking login page.",
        "",
    )
    assert "000dmobilt9034.com" in result["domains"]
    assert result["domains"] == ["000dmobilt9034.com"]


def test_real_source_article_domain_excluded_when_also_a_known_phishing_host(_stub_feed_manager_deps):
    """exclude_domain (the article's own link) must still take priority even
    when the excluded host happens to share a name pattern with unrelated
    real malicious domains in the same text."""
    fm = _stub_feed_manager_deps
    result = fm._extract_iocs(
        "Report from boutique-dofus.fr mirror",
        "This copycat site at boutique-dofus.fr impersonates a legitimate retailer, while the "
        "real attacker infrastructure at statsrvv.com remained active.",
        "",
        exclude_domain="boutique-dofus.fr",
    )
    assert "boutique-dofus.fr" not in result["domains"]
    assert "statsrvv.com" in result["domains"]
