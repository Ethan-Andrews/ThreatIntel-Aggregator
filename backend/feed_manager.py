import feedparser
import hashlib
import httpx
import httpx2
import logging
import time
import json
import os
import re
import anthropic
from ioc_finder import find_iocs as _find_iocs
from apscheduler.schedulers.background import BackgroundScheduler
from db import _connect_db, get_pending_triage, get_triaged_for_retriage, get_entries_by_hashes, apply_triage, deduplicate_cves, archive_old_entries, persist_runtime_db, upsert_ioc_ledger
from enrichment import run_enrichment, refresh_kev_cache, refresh_and_reenrich
from dedup import normalize_title, is_exact_duplicate, run_dedup_pass
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse
from pathlib import Path
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

_PROMO_PATTERNS = [
    r"\bwebinar\b",
    r"\bregister now\b",
    r"\bjoin us\b",
    r"\bproduct update\b",
    r"\bnew feature\b",
    r"\bhow to\b",
    r"\btutorial\b",
    r"\bgetting started\b",
    r"\bcase study\b",
    r"\bon-demand\b",
    r"\bdemo\b",
    r"\bannouncement\b",
    r"\blaunch\b",
    r"\bnamed a leader\b",
    r"\bmagic quadrant\b",
    r"\bforrester wave\b",
    r"\bpartner(?:ship)?\b",
    r"\bintegration\b",
    r"\bopen-sourc(?:e|ing)\b",
    r"\bpasskeys?\b",
    r"\bcompliance\b",
    r"\bgovernance\b",
    r"\bexecutive order\b",
    r"\bpublic comment\b",
    r"\bbudget\b",
    r"\bstrategy\b",
    r"\bkpi\b",
    r"\bleadership\b",
    r"\bopinion\b",
    r"\bstate of\b",
    r"\bsurvey\b",
    r"\broundup\b",
    r"\bwhat is\b",
    r"\bbest practices\b",
    r"\bbenchmark\b",
    r"\bpredictions?\b",
    r"\bbuyer'?s? guide\b",
    r"\bweek in\b",
    r"\binvestment\b",
]

_THREAT_SIGNAL_TERMS = [
    "cve-",
    "exploit",
    "ransomware",
    "malware",
    "campaign",
    "apt",
    "vulnerability",
    "breach",
    "ioc",
    "zero-day",
    "botnet",
    "phishing",
    "threat actor",
    "ttp",
    "intrusion",
    "compromise",
    "payload",
    "backdoor",
    "wiper",
    "c2",
    "command and control",
    "incident response",
    "forensics",
]

_STRICT_INTEL_SOURCES = {
    "CrowdStrike Blog",
    "MalwareTech",
    "Hexacorn",
    "Objective-See",
    "TrustedSec",
    "Scott Helme",
    "Industrial Cyber",
    "Snyk Blog",
    # Added per Informational-trends.txt analysis (2026-06-25)
    "Invicti Web Security",   # 100% "How to…" / AppSec tutorial content
    "Tech Republic",          # general tech news, product launches, business
    "Seqrite",                # educational guides and definitions
    "Semgrep Blog",           # developer tooling, benchmarks, marketing
    "Schneier",               # opinion, policy, general security commentary
    "Dark Reading",           # workforce / opinion pieces
}


# Common, high-traffic vendor/infra/media apex domains that are near-never
# genuine malicious indicators. They show up constantly in threat-intel prose
# as incidental context (patch links, cloud hosting, CDN edge nodes, standards
# bodies, sandbox/analysis tooling, security news coverage) rather than as
# attacker infrastructure, and including them as IOCs produces low-quality
# noise. Matches the apex domain itself or any subdomain.
#
# This is necessarily a curated, non-exhaustive list — it cannot catch every
# benign domain that could appear in a report, only the ones common enough in
# real threat-intel writeups to be worth hard-filtering. It is a precision
# aid layered on top of (not a replacement for) exclude_domain and the
# filename heuristic below.
_BENIGN_APEX_DOMAINS = frozenset({
    # Microsoft
    "microsoft.com", "windows.com", "office.com", "live.com", "outlook.com",
    "msn.com", "azure.com", "windowsupdate.com", "microsoftonline.com",
    "sharepoint.com", "msftconnecttest.com",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "android.com",
    "googleusercontent.com", "goo.gl", "googleblog.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon
    "amazon.com", "amazonaws.com",
    # GitHub / dev tooling
    "github.com", "githubusercontent.com", "githubassets.com", "npmjs.com",
    "gitlab.com", "bitbucket.org", "readthedocs.io", "pypi.org", "docker.com",
    "python.org",
    # CDN / infra
    "cloudflare.com", "cloudflare.net", "akamai.net", "akamaized.net",
    "akamaitechnologies.com", "fastly.net", "jsdelivr.net", "unpkg.com",
    # Social / general web
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "instagram.com",
    "reddit.com", "wikipedia.org", "mozilla.org", "archive.org",
    # Enterprise vendors that show up as patch/advisory links, not C2
    "adobe.com", "oracle.com", "ibm.com", "cisco.com", "redhat.com",
    "ubuntu.com", "debian.org", "vmware.com", "sap.com", "salesforce.com",
    "wordpress.com", "wordpress.org", "atlassian.com", "slack.com",
    "zoom.us",
    # Standards bodies / government / CERT
    "w3.org", "schema.org", "ietf.org", "rfc-editor.org", "nist.gov",
    "cisa.gov", "mitre.org", "us-cert.gov", "cve.org", "first.org",
    "enisa.europa.eu",
    # Threat-intel platforms, sandboxes, and analysis services — routinely
    # cited as *where a sample was submitted/analyzed*, not as attacker infra
    "virustotal.com", "hybrid-analysis.com", "any.run", "urlscan.io",
    "abuse.ch", "malwarebazaar.abuse.ch", "shodan.io", "censys.io",
    "greynoise.io", "otx.alienvault.com", "alienvault.com",
    "talosintelligence.com", "threatminer.org", "misp-project.org",
    # Security vendors — routinely self-cited or cross-cited in advisories
    "crowdstrike.com", "mandiant.com", "fireeye.com", "trellix.com",
    "paloaltonetworks.com", "sentinelone.com", "trendmicro.com",
    "symantec.com", "broadcom.com", "sophos.com", "eset.com",
    "kaspersky.com", "malwarebytes.com", "checkpoint.com", "fortinet.com",
    "recordedfuture.com", "rapid7.com", "tenable.com", "qualys.com",
    # Security / infosec news and research outlets — routinely cited as the
    # *source* of a writeup, not an indicator within it
    "threatpost.com", "bleepingcomputer.com", "thehackernews.com",
    "krebsonsecurity.com", "darkreading.com", "securityweek.com",
    "welivesecurity.com", "sans.org", "csoonline.com", "infosecurity-magazine.com",
})

# TLDs that double as extremely common file extensions in threat-intel
# writeups (script/binary/document names like "dropper.py", "run.sh",
# "notes.md"). All are also valid, registrable public TLDs, so ioc-finder
# happily matches "name.ext" as a domain. A bare two-label match on one of
# these is treated as a probable filename rather than a domain, unless it is
# corroborated by appearing as the host of an actual extracted URL (i.e. used
# with a scheme, proving real domain context) or has a subdomain structure.
#
# Deliberately EXCLUDES "app", "dev", and "zip": these are actively-sold,
# widely-used gTLDs, and "app"/"dev" domains were confirmed as genuine C2
# infrastructure in a real public feed (stamparm/blackbook, e.g.
# "somakop.app", "getcloudsolutions.dev") during testing — treating them as
# filenames would silently drop real malicious indicators. ".zip" is
# excluded for the same reason plus a documented, more severe risk: security
# researchers flagged Google's ".zip"/".mov" gTLDs specifically because
# attackers register "invoice.zip"-style domains BECAUSE they visually
# resemble filenames, so filtering them as "probably a filename" would hide
# exactly the indicators this heuristic most needs to catch.
_FILE_EXTENSION_TLDS = frozenset({
    "py", "sh", "md", "exe", "dll", "bat", "ps1",
    "bin", "doc", "docx", "pdf", "xls", "xlsx", "jar", "msi", "dat",
    "tmp", "log", "ini", "cfg", "conf", "json", "yml", "yaml", "csv",
    "rb", "cpp", "java", "class", "vbs", "scr", "ico", "dmg", "pkg",
    "deb", "rpm", "js", "go", "cs", "txt", "db", "sql", "xml", "htm",
    "html", "css", "asp", "aspx", "php", "jsp", "ps",
})


# Per-category truncation caps. These exist to bound storage/UI size against
# runaway or garbage extraction (e.g. a page full of version-number-shaped
# false IP matches), not to arbitrarily cut off real indicators. Raised from
# the original 15/15/10/10/10 (2026-08-31): a real multi-indicator threat
# report routinely lists more than 15 distinct malicious domains, and with
# benign-noise filtering already applied above, truncating below what a
# dense-but-legitimate report contains defeats the "no false negatives"
# goal — see _dedupe_preserve_order's docstring for how truncation order was
# also made deterministic as part of the same fix.
_MAX_IPS = 25
_MAX_DOMAINS = 40
_MAX_URLS = 25
_MAX_CVES = 20
_MAX_HASHES = 25


def _dedupe_preserve_order(values) -> list:
    """Dedupe while keeping first-seen order.

    Using a plain `set()` for dedup makes iteration order depend on Python's
    per-process hash randomization, which is invisible until a report has
    more distinct values than the truncation cap below — at which point
    *which* values survive the `[:N]` slice becomes arbitrary and can vary
    from run to run on the exact same input, silently dropping real IOCs.
    Preserving insertion order keeps truncation deterministic and reviewable.
    """
    return list(dict.fromkeys(values))


def _url_host(u: str) -> str:
    parsed = urlparse(u)
    return (parsed.hostname or parsed.path.split("/")[0] or "").lower()


def _is_benign_apex(host: str) -> bool:
    """True if host is (or is a subdomain of) a known-benign vendor/infra apex."""
    h = (host or "").lower()
    if not h:
        return False
    return any(h == apex or h.endswith("." + apex) for apex in _BENIGN_APEX_DOMAINS)


def _looks_like_filename(domain: str, url_hosts: set) -> bool:
    """True if a bare 'name.ext' domain match is more likely a filename."""
    labels = domain.lower().split(".")
    if len(labels) != 2:
        return False
    if labels[-1] not in _FILE_EXTENSION_TLDS:
        return False
    return domain.lower() not in url_hosts


def _extract_iocs(title: str, summary: str, content: str = "", exclude_domain: str = "") -> dict:
    """Extract IOC candidates from feed entry text using ioc-finder.

    Beyond the raw ioc-finder output, this applies quality filters so the
    result is fit for a threat-intel feed:
    - drops common benign vendor/infra/media domains (e.g. microsoft.com,
      virustotal.com, bleepingcomputer.com) that are near-never genuine
      malicious indicators
    - drops bare "name.ext" matches that are almost certainly filenames
      (e.g. "dropper.py", "notes.md") rather than real domains, unless
      corroborated by an actual URL using that host
    - excludes the source article's own domain/subdomain (case-insensitive)
    - dedupes and truncates deterministically (first-seen order), so which
      IOCs survive a busy report is stable and reviewable rather than
      dependent on set hash ordering
    """
    text_body = content or summary or ""
    text_body = re.sub(r"<[^>]+>", "", text_body)
    text = ((title or "") + " " + text_body).strip()
    try:
        raw = _find_iocs(text)
    except Exception:
        return {"ips": [], "hashes": [], "cves": [], "domains": [], "urls": []}

    ips  = _dedupe_preserve_order(raw.get("ipv4s") or [])[:_MAX_IPS]
    doms_raw = _dedupe_preserve_order(raw.get("domains") or [])
    urls_raw = _dedupe_preserve_order(raw.get("urls") or [])
    cves = _dedupe_preserve_order(v.upper() for v in (raw.get("cves") or []))[:_MAX_CVES]
    hashes = _dedupe_preserve_order(
        list(raw.get("sha256s") or []) +
        list(raw.get("sha1s") or []) +
        list(raw.get("md5s") or [])
    )[:_MAX_HASHES]

    url_hosts = {_url_host(u) for u in urls_raw}

    doms = [
        d for d in doms_raw
        if not _is_benign_apex(d) and not _looks_like_filename(d, url_hosts)
    ][:_MAX_DOMAINS]
    urls = [u for u in urls_raw if not _is_benign_apex(_url_host(u))][:_MAX_URLS]

    if exclude_domain:
        exclude_lower = exclude_domain.lower()
        doms = [d for d in doms
                if d.lower() != exclude_lower and not d.lower().endswith("." + exclude_lower)]
        urls = [u for u in urls
                if not (_url_host(u) == exclude_lower or
                        _url_host(u).endswith("." + exclude_lower))]

    return {"ips": ips, "hashes": hashes, "cves": cves, "domains": doms, "urls": urls}

@dataclass
class TriageJob:
    job_id:      str
    status:      Literal["running", "completed", "failed"]
    total:       int
    completed:   int = 0
    failed:      int = 0
    started_at:  float = field(default_factory=time.time)
    finished_at: float | None = None


_jobs: dict[str, TriageJob] = {}
_jobs_lock = threading.Lock()
_JOB_CAP = 100


def create_job(total: int) -> str:
    job_id = str(uuid.uuid4())[:8]
    job = TriageJob(job_id=job_id, status="running", total=total)
    with _jobs_lock:
        if len(_jobs) >= _JOB_CAP:
            oldest = next(iter(_jobs))
            del _jobs[oldest]
        _jobs[job_id] = job
    return job_id


def get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        return {
            "job_id":      job.job_id,
            "status":      job.status,
            "total":       job.total,
            "completed":   job.completed,
            "failed":      job.failed,
            "started_at":  job.started_at,
            "finished_at": job.finished_at,
        }


def list_jobs() -> list[dict]:
    with _jobs_lock:
        recent = list(_jobs.values())[-20:]
        return [
            {
                "job_id":      j.job_id,
                "status":      j.status,
                "total":       j.total,
                "completed":   j.completed,
                "failed":      j.failed,
                "started_at":  j.started_at,
                "finished_at": j.finished_at,
            }
            for j in reversed(recent)
        ]


FEEDS = [
    {"name": "Fortinet Threat Signal", "url": "https://filestore.fortinet.com/fortiguard/rss/threatsignal.xml", "tier": 1},
    {"name": "Cisco Talos",      "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "tier": 1},
    {"name": "CISA",             "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",         "tier": 1},
    # NVD CVE XML feeds retired by NIST in 2024; no RSS replacement available
    {"name": "Oracle",    "url": "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml", "tier": 1},
    # MSRC blog RSS is gone (301s to HTML with no rel=alternate). The
    # update-guide RSS lists ~4900 items but many are CVE revisions; ingest=delta
    # tracks unique CVEs in backend/data/feed_delta/microsoft_msrc.json and only
    # writes new/changed items after that. Override the directory with FEED_DELTA_DIR.
    {
        "name": "Microsoft MSRC",
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "tier": 1,
        "ingest": "delta",
        "delta_seed_hours": 48,
        "timeout": 60,
    },
    {"name": "Malpedia",         "url": "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest",     "tier": 2},
    {"name": "Recorded Future",  "url": "https://www.recordedfuture.com/feed",                           "tier": 2},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml",                         "tier": 2},
    {"name": "Securelist",       "url": "https://securelist.com/feed/",                                  "tier": 2},
    {"name": "Unit42",           "url": "https://unit42.paloaltonetworks.com/feed/",                     "tier": 2},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/",                        "tier": 3},
    {"name": "Krebs",            "url": "https://krebsonsecurity.com/feed/",                             "tier": 3},
    {"name": "Schneier",         "url": "https://www.schneier.com/feed/atom/",                           "tier": 3},
    {"name": "TheHackerNews",    "url": "https://feeds.feedburner.com/TheHackersNews",                   "tier": 3},
    {"name": "Tech Republic",    "url": "https://www.techrepublic.com/rssfeeds/topic/security/?feedType=rssfeeds", "tier": 3},
    {"name": "Sophos (Security Operations)", "url": "https://www.sophos.com/en-us/category/security-operations/feed", "tier": 3},
    {"name": "Sophos (Threat Research)",    "url": "https://www.sophos.com/en-us/category/threat-research/feed",    "tier": 3},
    # --- Tier 1: premium threat intelligence ---
    {"name": "ESET WeLiveSecurity",      "url": "https://www.welivesecurity.com/en/rss/feed/",                             "tier": 1},
    {"name": "The DFIR Report",          "url": "https://thedfirreport.com/feed/",                                         "tier": 1},
    {"name": "Check Point Research",     "url": "https://research.checkpoint.com/feed/",                                   "tier": 1},
    {"name": "Talos Intelligence Blog",  "url": "https://blog.talosintelligence.com/rss/",                                  "tier": 1},
    {"name": "Microsoft Security Blog",  "url": "https://www.microsoft.com/en-us/security/blog/feed/",                     "tier": 1},
    # --- Tier 2: strong secondary TI ---
    {"name": "ReversingLabs",            "url": "https://www.reversinglabs.com/blog/rss.xml",                              "tier": 2},
    {"name": "Sekoia",                   "url": "https://www.sekoia.com/blog/rss.xml",                                     "tier": 2},
    {"name": "Datadog Security Labs",    "url": "https://securitylabs.datadoghq.com/rss/feed.xml",                         "tier": 2},
    {"name": "Wiz Blog",                 "url": "https://www.wiz.io/feed/rss.xml",                                         "tier": 2},
    # Bitdefender Labs removed their RSS feed (site redesign ~2025); no replacement
    {"name": "Malwarebytes TI",          "url": "https://www.malwarebytes.com/blog/feed/",                                 "tier": 2},
    # CYFIRMA RSS returns 500; no confirmed replacement URL
    {"name": "Cyble",                    "url": "https://cyble.com/blog/feed/",                                            "tier": 2},
    {"name": "Google Cloud TI",          "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",        "tier": 2},
    {"name": "Proofpoint TI",            "url": "https://www.proofpoint.com/us/threat-insight-blog.xml",                  "tier": 2},
    # Zscaler ThreatLabz: no working RSS URL found; feeds.zscaler.com returns 502
    # Trend Micro Research: FeedBurner URL has SSL issues; no alternative found
    # Fortinet Threat Research: blog RSS URL returns 404; no confirmed replacement
    {"name": "ANY.RUN Blog",             "url": "https://any.run/cybersecurity-blog/rss/",                                 "tier": 2},
    # --- Tier 3: supplementary vendor blogs ---
    # Posts are CPT `blog`, not WP `post`, so /blog/feed 404s and /feed/ is empty.
    {"name": "Cymulate",                 "url": "https://cymulate.com/feed/?post_type=blog",                               "tier": 3},
    {"name": "Cybereason",               "url": "https://www.cybereason.com/blog/rss.xml",                                 "tier": 3},
    # CloudSEK: no working RSS URL found
    # /blog/feed is the comments channel; posts are CPT `blog`.
    {"name": "Securonix",                "url": "https://www.securonix.com/feed/?post_type=blog",                          "tier": 3},
    {"name": "Darktrace",                "url": "https://www.darktrace.com/blog/rss.xml",                                  "tier": 3},
    {"name": "Seqrite",                  "url": "https://www.seqrite.com/blog/feed/",                                      "tier": 3},
    {"name": "Picus Security",           "url": "https://www.picussecurity.com/resource/rss.xml",                          "tier": 3},
    # eSentire Blog: no working RSS URL found
    {"name": "ZeroSalarium",             "url": "https://www.zerosalarium.com/feeds/posts/default?alt=rss",               "tier": 3},
    {"name": "Acronis TRU",              "url": "https://www.acronis.com/en-us/tru/feed.xml",                              "tier": 3},

    # --- Reviewed additions (2026-06-04) ---
    {"name": "Ironscales Threat Intelligence", "url": "https://ironscales.com/threat-intelligence/rss.xml", "tier": 2},
    {"name": "Dark Reading",                   "url": "https://www.darkreading.com/rss.xml",                  "tier": 3},
    {"name": "Qualys Security Blog",           "url": "https://blog.qualys.com/feed",                         "tier": 2},
    {"name": "SecurityWeek",                   "url": "https://www.securityweek.com/feed/",                   "tier": 3},
    {"name": "CrowdStrike Blog",               "url": "https://www.crowdstrike.com/en-us/blog/feed",         "tier": 2},
    {"name": "SentinelOne Labs",               "url": "https://www.sentinelone.com/labs/feed/",              "tier": 1},
    {"name": "Google Project Zero",            "url": "https://projectzero.google/feed.xml",                  "tier": 1},
    {"name": "Zero Day Initiative",            "url": "https://www.thezdi.com/blog?format=rss",              "tier": 1},
    {"name": "Acunetix Blog",                  "url": "https://www.acunetix.com/blog/feed/",                 "tier": 3},
    {"name": "Invicti Web Security",           "url": "https://www.invicti.com/blog/web-security/rss.xml",   "tier": 3},
    {"name": "Aqua Security",                  "url": "https://blog.aquasec.com/rss.xml",                    "tier": 2},
    {"name": "Orca Security",                  "url": "https://orca.security/resources/blog/feed/",           "tier": 2},
    {"name": "TrustedSec",                     "url": "https://trustedsec.com/feed.rss",                     "tier": 2},
    {"name": "Snyk Blog",                      "url": "https://snyk.io/blog/feed/",                          "tier": 3},
    {"name": "Semgrep Blog",                   "url": "https://semgrep.dev/blog/rss/",                       "tier": 3},
    {
        "name": "Netskope",
        "url": "https://www.netskope.com/feed",
        "tier": 2,
        "include_categories": ["threat research", "threat labs", "research"],
        "include_terms": ["threat", "research", "campaign", "malware", "ransomware", "apt"],
    },
    {"name": "IS Decisions",                   "url": "https://www.isdecisions.com/en/blog/feed",            "tier": 3},
    {"name": "Industrial Cyber",               "url": "https://industrialcyber.co/feed/",                    "tier": 3},
    {"name": "Objective-See",                  "url": "https://objective-see.org/rss.xml",                   "tier": 2},
    {"name": "MalwareTech",                    "url": "https://www.malwaretech.com/feed",                    "tier": 2},
    {"name": "Hexacorn",                       "url": "https://www.hexacorn.com/blog/feed/",                 "tier": 2},
    {"name": "Scott Helme",                    "url": "https://scotthelme.co.uk/rss/",                       "tier": 3},
    # --- Reviewed additions (2026-06-17) ---
    {"name": "JFrog Security Research",        "url": "https://jfrog.com/blog/tag/security-research/feed/",  "tier": 2},
    {"name": "SafeDep",                        "url": "https://safedep.io/rss.xml",                          "tier": 2},

]


def _validate_feed_config(feeds):
    """Fail fast if any feed is missing required metadata or has invalid tier."""
    for idx, feed in enumerate(feeds, start=1):
        name = feed.get("name", f"<feed-{idx}>")
        if not feed.get("url"):
            raise ValueError(f"Feed '{name}' is missing URL")
        if "tier" not in feed:
            raise ValueError(f"Feed '{name}' is missing tier")
        if feed["tier"] not in (1, 2, 3):
            raise ValueError(f"Feed '{name}' has invalid tier: {feed['tier']!r}")
        ingest = feed.get("ingest")
        if ingest is not None and ingest not in ("delta",):
            raise ValueError(f"Feed '{name}' has invalid ingest: {ingest!r}")


# CISA (and several vendor WAFs) 403 the historical feedparser UA. Chrome token
# is required — Mozilla/5.0 alone is not enough.
_FEED_USER_AGENT = (
    "Mozilla/5.0 (compatible; TI-RSS-Feed/1.1) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
_FEED_ACCEPT = (
    "application/rss+xml, application/atom+xml, application/xml;q=0.9, "
    "text/xml;q=0.8, */*;q=0.5"
)

_validate_feed_config(FEEDS)


def _entry_passes_feed_filters(feed_meta, entry):
    """Apply optional per-feed category/content filters to reduce noisy feeds."""
    include_categories = [c.lower() for c in feed_meta.get("include_categories", [])]
    include_terms = [t.lower() for t in feed_meta.get("include_terms", [])]

    if not include_categories and not include_terms:
        return True

    tags = entry.get("tags", []) or []
    category_terms = []
    for tag in tags:
        if isinstance(tag, dict):
            term = (tag.get("term") or "").strip().lower()
            if term:
                category_terms.append(term)

    text = " ".join([
        str(entry.get("title", "") or "").lower(),
        str(entry.get("summary", "") or "").lower(),
    ])

    category_ok = False
    if include_categories:
        category_ok = any(
            expected in category
            for expected in include_categories
            for category in category_terms
        )

    terms_ok = False
    if include_terms:
        terms_ok = any(
            term in text or any(term in category for category in category_terms)
            for term in include_terms
        )

    if include_categories and include_terms:
        return category_ok or terms_ok
    if include_categories:
        return category_ok
    return terms_ok

_ai_provider = os.environ.get("AI_PROVIDER", "anthropic").lower()

if _ai_provider == "azure":
    # Azure AI Services exposes an Anthropic-compatible endpoint at
    # {resource}/anthropic/v1/messages.  The SDK base_url should be
    # {resource}/anthropic (SDK appends /v1/messages automatically).
    # Auth uses "Authorization: Bearer <key>" — set via auth_token.
    _az_endpoint = os.environ.get("AZURE_FOUNDRY_ENDPOINT", "").rstrip("/")
    _az_key      = os.environ.get("AZURE_FOUNDRY_API_KEY", "")
    _az_version  = os.environ.get("AZURE_FOUNDRY_API_VERSION", "2025-05-01")
    _ai_client = anthropic.Anthropic(
        base_url=_az_endpoint,
        auth_token=_az_key,
        default_headers={"anthropic-version": "2023-06-01"},
        # anthropic>=1.0's HTTP layer is httpx2 (its maintained httpx fork) --
        # an http_client= built from plain httpx now raises TypeError at
        # construction. This is the only httpx object handed to the SDK in
        # this file; httpx.get() below talks to an unrelated feed URL and is
        # untouched.
        http_client=httpx2.Client(
            params={"api-version": _az_version},
        ),
    )
else:
    _ai_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))


def _ai_configured() -> bool:
    """Return True if the active provider has a key/endpoint configured."""
    if _ai_provider == "azure":
        return bool(os.environ.get("AZURE_FOUNDRY_API_KEY"))
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]

# ── STIX-aligned tag vocabularies ──
VALID_INDICATOR_TYPES    = ["malicious-activity", "compromised", "anonymization",
                            "attribution", "anomalous-activity", "benign", "unknown"]

VALID_MALWARE_TYPES      = ["ransomware", "trojan", "backdoor", "wiper", "rootkit",
                            "spyware", "botnet", "dropper", "worm", "keylogger",
                            "exploit-kit", "downloader", "webshell", "adware",
                            "remote-access-trojan", "resource-exploitation"]

VALID_ACTOR_TYPES        = ["nation-state", "crime-syndicate", "hacker", "activist",
                            "insider", "terrorist", "competitor", "spy"]

VALID_SECTORS            = ["energy", "finance", "healthcare", "government", "technology",
                            "education", "defense", "retail", "transportation",
                            "telecommunications", "manufacturing", "critical-infrastructure"]

VALID_PLATFORMS          = ["windows", "linux", "macos", "android", "ios",
                            "network", "cloud", "ics-scada", "containers"]

TRIAGE_SYSTEM_PROMPT = """You are a threat intelligence analyst producing STIX 2.1-aligned indicator enrichment.

Given a feed entry title and summary, return ONLY a JSON object with these exact keys.
No preamble. No markdown fences. No extra keys.

{
  "severity": "Critical|High|Medium|Low|Informational",
  "ttps": ["T1190"],
  "ai_summary": "One plain-English sentence under 120 characters describing the threat.",
  "threat_actors": [],
  "tags": {
    "indicator_types":    [],
    "malware_types":      [],
    "threat_actor_types": [],
    "target_sectors":     [],
    "platforms":          []
  }
}

SEVERITY:
- Critical: Active exploitation, ransomware deployed, zero-day unpatched, widespread impact
- High: Public exploit exists, confirmed breach, active APT campaign, critical CVE patched
- Medium: Vulnerability without public exploit, suspicious campaign, patch advisory
- Low: Informational patch, hardening guidance, threat research without active exploitation
- Informational: News, policy, opinion, no direct threat indicator

TAGS — only include values that are clearly supported by the content. Empty arrays are fine.

indicator_types (pick 1-2 max):
  malicious-activity  → direct threat, IOC, active attack
  compromised         → breached infrastructure, hijacked account/domain
  anonymization       → VPN, Tor, proxy abuse
  attribution         → links content to a known actor or group
  anomalous-activity  → unusual behavior without confirmed malice
  benign              → explicitly safe or false positive

malware_types (only if malware is clearly discussed):
  ransomware, trojan, backdoor, wiper, rootkit, spyware, botnet,
  dropper, worm, keylogger, exploit-kit, downloader, webshell,
  adware, remote-access-trojan, resource-exploitation

threat_actor_types (only if an actor type is clearly identifiable):
  nation-state, crime-syndicate, hacker, activist,
  insider, terrorist, competitor, spy

target_sectors (industries explicitly mentioned as targeted):
  energy, finance, healthcare, government, technology, education,
  defense, retail, transportation, telecommunications,
  manufacturing, critical-infrastructure

platforms (systems explicitly mentioned as affected):
  windows, linux, macos, android, ios, network, cloud, ics-scada, containers

ttps: MITRE ATT&CK technique IDs only (e.g. T1190, T1059.003). Empty array if none.
ai_summary: Start with the subject. Plain English. No jargon abbreviations spelled out.
threat_actors: Named threat actor groups explicitly mentioned (APT groups, crime orgs, nation-state actors).
  Examples: "Lazarus Group", "APT28", "LockBit", "Scattered Spider", "Volt Typhoon", "Cl0p"
  Leave empty if no specific named group is explicitly mentioned.
"""


# ── LLM prompt injection guard (OWASP LLM01, MITRE ATLAS AML.T0051) ──────────
_INJECTION_PATTERNS = [
    # Direct instruction override
    r'ignore previous instructions',
    r'disregard.*?system prompt',
    r'\byou are now\b',
    r'new instructions\s*:',
    r'forget.*?instructions',
    r'override.*?instructions',
    r'repeat after me',
    r'output.*?verbatim',
    r'print.*?system prompt',
    r'reveal.*?instructions',
    r'jailbreak',
    # LLM special tokens (chat-template boundary injection)
    r'<\|system\|>',
    r'<\|im_start\|>',
    r'<\|im_end\|>',
    r'\[INST\]',
    r'</s>',
    # Role/persona injection
    r'act as\s+(?:an?\s+)?(?:jailbreak|dan|evil|unrestricted)',
    r'pretend\s+(?:you\s+are|to\s+be)',
    r'\bDAN\b',
    r'do\s+anything\s+now',
    r'simulate\s+(?:an?\s+)?(?:uncensored|unfiltered)',
    # Header/section boundary injection
    r'\[system\]',
    r'###\s*system',
    r'###\s*instruction',
    r'system\s*message\s*:',
    r'end\s+(?:of\s+)?(?:system\s+prompt|instructions)',
    r'---+\s*(?:user|assistant|system)\s*:',
]

def _sanitize_for_llm(text: str, max_length: int = 500) -> str:
    """Strip prompt-injection patterns from external feed content before LLM use."""
    sanitized = text
    for pattern in _INJECTION_PATTERNS:
        sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE)
    return sanitized[:max_length]


def _has_real_intel_signal(title: str, summary: str) -> bool:
    """Return True when content has concrete threat intel indicators worth full triage."""
    plain_summary = re.sub(r"<[^>]+>", " ", summary or "")
    text = ((title or "") + " " + plain_summary).lower()

    ioc_data = _extract_iocs(title or "", summary or "")
    has_iocs = any(ioc_data[k] for k in ("ips", "hashes", "cves", "domains", "urls"))
    if has_iocs:
        return True

    return any(term in text for term in _THREAT_SIGNAL_TERMS)


def _is_low_value_informational(title: str, summary: str, source: str = "") -> bool:
    """Return True for informational/promotional content with low threat-intel value."""
    if _has_real_intel_signal(title, summary):
        return False

    plain_summary = re.sub(r"<[^>]+>", " ", summary or "")
    text = ((title or "") + " " + plain_summary).lower()
    has_promo_pattern = any(re.search(pattern, text) for pattern in _PROMO_PATTERNS)

    # For noisy blog-style sources, require concrete intel signal; otherwise filter.
    if source in _STRICT_INTEL_SOURCES:
        return True

    return has_promo_pattern


# A momentary network blip or upstream 5xx is common and self-corrects on
# its own -- retrying a couple of times with a short backoff before giving
# up means a transient failure doesn't have to wait for the next full
# scheduled poll cycle (which may be hours away) to recover. A feed that's
# actually down (dead URL, permanently changed format) still ends up
# logged as failed with the real error, just after this many attempts
# instead of one.
_FETCH_RETRY_ATTEMPTS = 3
_FETCH_RETRY_BACKOFF_SECONDS = (1, 3)  # delay before attempt 2, before attempt 3


def _fetch_feed(feed_meta: dict) -> tuple[dict, list | None, str]:
    """Download one feed with a hard HTTP timeout, retrying transient
    failures with a short backoff before giving up.

    Returns (feed_meta, entries, error_str).
    - Success: (feed_meta, entries_list, "")  — entries_list may be empty
    - Failure: (feed_meta, None, "error description") after
      _FETCH_RETRY_ATTEMPTS attempts have all failed.

    Never raises — any failure is logged and returned as error_str so one
    bad feed never blocks the others.
    """
    last_error = ""
    for attempt in range(_FETCH_RETRY_ATTEMPTS):
        try:
            response = httpx.get(
                feed_meta["url"],
                timeout=feed_meta.get("timeout", 30),
                follow_redirects=True,
                headers={"User-Agent": _FEED_USER_AGENT, "Accept": _FEED_ACCEPT},
            )
            response.raise_for_status()
            parsed = feedparser.parse(response.content)
            return feed_meta, parsed.entries, ""
        except Exception as exc:
            last_error = str(exc)[:500]
            if attempt < _FETCH_RETRY_ATTEMPTS - 1:
                logger.info(
                    "Feed %s fetch attempt %d/%d failed, retrying: %s",
                    feed_meta["name"], attempt + 1, _FETCH_RETRY_ATTEMPTS, exc,
                )
                time.sleep(_FETCH_RETRY_BACKOFF_SECONDS[attempt])
    logger.warning(
        "Feed %s fetch failed after %d attempts: %s",
        feed_meta["name"], _FETCH_RETRY_ATTEMPTS, last_error,
    )
    return feed_meta, None, last_error


def _filtered_triage_payload(reason: str) -> dict:
    return {
        "severity": "Informational",
        "ttps": "",
        "ai_summary": reason,
        "tags": json.dumps({
            "indicator_types": [],
            "malware_types": [],
            "threat_actor_types": [],
            "target_sectors": [],
            "platforms": [],
        }),
        "iocs": json.dumps({"threat_actors": [], "ips": [], "hashes": [], "cves": [], "domains": [], "urls": []}),
    }


def _triage_entry(title, summary, content="", link=""):
    clean_summary = _sanitize_for_llm(
        re.sub(r"<[^>]+>", "", summary or "").strip()
    )
    safe_title = _sanitize_for_llm(
        re.sub(r"<[^>]+>", "", title or "").strip(), max_length=300
    )

    empty_tags = {
        "indicator_types": [], "malware_types": [],
        "threat_actor_types": [], "target_sectors": [], "platforms": [],
    }

    _exclude = urlparse(link).hostname or "" if link else ""

    try:
        if _ai_provider == "azure":
            # Azure endpoint uses the Anthropic SDK but needs model name
            # from the deployment env var.
            response = _ai_client.messages.create(
                model=os.environ.get("AZURE_FOUNDRY_DEPLOYMENT", "claude-haiku-4-5"),
                max_tokens=512,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": "Title: " + safe_title + "\nSummary: " + clean_summary,
                }]
            )
            raw = response.content[0].text.strip()
        else:
            response = _ai_client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": "Title: " + safe_title + "\nSummary: " + clean_summary,
                }]
            )
            raw = response.content[0].text.strip()
        raw    = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw)

        severity = parsed.get("severity", "Unknown")
        if severity not in SEVERITY_LEVELS:
            severity = "Unknown"

        ttps = parsed.get("ttps", [])
        if not isinstance(ttps, list):
            ttps = []
        ttps = [t for t in ttps if isinstance(t, str) and t.startswith("T")]

        raw_tags = parsed.get("tags", {})
        if not isinstance(raw_tags, dict):
            raw_tags = {}

        def filter_vocab(key, vocab):
            vals = raw_tags.get(key, [])
            if not isinstance(vals, list):
                return []
            return [v for v in vals if isinstance(v, str) and v in vocab]

        tags = {
            "indicator_types":    filter_vocab("indicator_types",    VALID_INDICATOR_TYPES),
            "malware_types":      filter_vocab("malware_types",      VALID_MALWARE_TYPES),
            "threat_actor_types": filter_vocab("threat_actor_types", VALID_ACTOR_TYPES),
            "target_sectors":     filter_vocab("target_sectors",     VALID_SECTORS),
            "platforms":          filter_vocab("platforms",          VALID_PLATFORMS),
        }

        # Rendered as plain JSX text ({triage.ai_summary}) in FeedCard, never
        # dangerouslySetInnerHTML -- React already escapes text nodes, so
        # HTML-escaping here has no XSS benefit and only corrupts apostrophes/
        # ampersands into visible "&#39;"-style entities in the UI.
        ai_summary = str(parsed.get("ai_summary", ""))[:2000]

        threat_actors = parsed.get("threat_actors", [])
        if not isinstance(threat_actors, list):
            threat_actors = []
        threat_actors = [
            ta for ta in threat_actors
            if isinstance(ta, str) and 2 <= len(ta) <= 80
        ][:10]

        ioc_data = _extract_iocs(title, summary, content, exclude_domain=_exclude)
        iocs = {
            "threat_actors": threat_actors,
            "ips":           ioc_data["ips"],
            "hashes":        ioc_data["hashes"],
            "cves":          ioc_data["cves"],
            "domains":       ioc_data["domains"],
            "urls":          ioc_data["urls"],
        }

        return {
            "severity":   severity,
            "ttps":       ",".join(ttps),
            "ai_summary": ai_summary,
            "tags":       json.dumps(tags),
            "iocs":       json.dumps(iocs),
        }

    except Exception as exc:
        logger.warning("Triage failed for '%s': %s", title[:60], exc)
        ioc_data = _extract_iocs(title, summary, content, exclude_domain=_exclude)
        return {
            "severity":   "Unknown",
            "ttps":       "",
            "ai_summary": "",
            "tags":       json.dumps(empty_tags),
            "iocs":       json.dumps({"threat_actors": [], **ioc_data}),
        }


def retriage_selected_batch(job_id: str, hashes: list[str]) -> None:
    """Background thread: retriage a specific list of entries by hash."""
    final_status = "completed"
    try:
        rows = get_entries_by_hashes(hashes)
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].total = len(rows)
        for row in rows:
            try:
                title = row["title"] or ""
                summary = row["summary"] or ""
                if _is_low_value_informational(title, summary, row.get("source") or ""):
                    result = _filtered_triage_payload(
                        "Filtered low-value informational content with no threat signal or IOCs."
                    )
                else:
                    result = _triage_entry(title, summary, content=row.get("content", ""), link=row.get("link", ""))
                apply_triage(
                    hash=row["hash"],
                    severity=result["severity"],
                    ttps=result["ttps"],
                    ai_summary=result["ai_summary"],
                    tags=result["tags"],
                    iocs=result.get("iocs", "{}"),
                )
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].completed += 1
            except Exception:
                logger.exception("retriage_selected_batch: error on hash %s", row.get("hash"))
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].failed += 1
        with _jobs_lock:
            if job_id in _jobs:
                job = _jobs[job_id]
                if job.completed == 0 and job.failed > 0:
                    final_status = "failed"
    except Exception:
        logger.exception("retriage_selected_batch: fatal error for job %s", job_id)
        final_status = "failed"
    finally:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = final_status
                _jobs[job_id].finished_at = time.time()


def retriage_failed_batch(job_id: str, rows: list) -> None:
    """Background thread: retriage entries that previously failed (Unknown severity, no TTPs)."""
    final_status = "completed"
    try:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].total = len(rows)
        for row in rows:
            try:
                title = row["title"] or ""
                summary = row["summary"] or ""
                if _is_low_value_informational(title, summary, row.get("source") or ""):
                    result = _filtered_triage_payload(
                        "Filtered low-value informational content with no threat signal or IOCs."
                    )
                else:
                    result = _triage_entry(title, summary, content=row.get("content", ""), link=row.get("link", ""))
                apply_triage(
                    hash=row["hash"],
                    severity=result["severity"],
                    ttps=result["ttps"],
                    ai_summary=result["ai_summary"],
                    tags=result["tags"],
                    iocs=result.get("iocs", "{}"),
                )
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].completed += 1
            except Exception:
                logger.exception("retriage_failed_batch: error on hash %s", row.get("hash"))
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].failed += 1
        with _jobs_lock:
            if job_id in _jobs:
                job = _jobs[job_id]
                if job.completed == 0 and job.failed > 0:
                    final_status = "failed"
    except Exception:
        logger.exception("retriage_failed_batch: fatal error for job %s", job_id)
        final_status = "failed"
    finally:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = final_status
                _jobs[job_id].finished_at = time.time()


def retriage_batch(job_id: str, count: int, order: str = "newest") -> None:
    """Background thread: retriage up to `count` already-triaged entries."""
    final_status = "completed"
    try:
        rows = get_triaged_for_retriage(count, order)
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].total = len(rows)
        for row in rows:
            try:
                title = row["title"] or ""
                summary = row["summary"] or ""
                if _is_low_value_informational(title, summary, row.get("source") or ""):
                    result = _filtered_triage_payload(
                        "Filtered low-value informational content with no threat signal or IOCs."
                    )
                else:
                    result = _triage_entry(title, summary, content=row.get("content", ""), link=row.get("link", ""))
                apply_triage(
                    hash=row["hash"],
                    severity=result["severity"],
                    ttps=result["ttps"],
                    ai_summary=result["ai_summary"],
                    tags=result["tags"],
                    iocs=result.get("iocs", "{}"),
                )
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].completed += 1
            except Exception:
                logger.exception("retriage_batch: error on hash %s", row.get("hash"))
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].failed += 1
        with _jobs_lock:
            if job_id in _jobs:
                job = _jobs[job_id]
                if job.completed == 0 and job.failed > 0:
                    final_status = "failed"
    except Exception:
        logger.exception("retriage_batch: fatal error for job %s", job_id)
        final_status = "failed"
    finally:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = final_status
                _jobs[job_id].finished_at = time.time()


def triage_pending():
    try:
        if not _ai_configured():
            return

        batch = get_pending_triage(batch_size=20)
        if not batch:
            return

        logger.info("Triaging %d pending entries...", len(batch))

        filtered_count = 0

        for entry in batch:
            title = entry["title"] or ""
            summary = entry["summary"] or ""
            source = entry.get("source") or ""

            if _is_low_value_informational(title, summary, source):
                result = _filtered_triage_payload(
                    "Filtered low-value informational content with no threat signal or IOCs."
                )
                apply_triage(
                    hash=entry["hash"],
                    severity=result["severity"],
                    ttps=result["ttps"],
                    ai_summary=result["ai_summary"],
                    tags=result["tags"],
                    iocs=result["iocs"],
                )
                filtered_count += 1
                continue

            result = _triage_entry(title, summary, content=entry.get("content", ""), link=entry.get("link", ""))
            apply_triage(
                hash=entry["hash"],
                severity=result["severity"],
                ttps=result["ttps"],
                ai_summary=result["ai_summary"],
                tags=result["tags"],
                iocs=result.get("iocs", "{}"),
            )
            time.sleep(0.5)

        logger.info("Triage batch complete. Filtered %d low-value informational entries.", filtered_count)
        run_enrichment()
    except Exception:
        logger.warning("STORAGE_RUNTIME_UNAVAILABLE: Exception during triage")
        return


def _entry_hash(entry):
    raw = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha256(raw.encode()).hexdigest()


def _entry_published(entry, max_dt=None):
    """Best-effort publication timestamp extraction from RSS/Atom variants.

    max_dt: datetime (UTC-aware) — clamp result to this value if provided.
    Prevents future-dated entries from floating to the top of published sort.
    """
    result = ""
    # Prefer explicit text fields when present and parseable.
    for key in ("published", "updated", "created", "issued"):
        value = (entry.get(key) or "").strip()
        if not value:
            continue
        try:
            dt = parsedate_to_datetime(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            result = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            break
        except Exception:
            continue  # try next text field or fall through to struct_time fields

    if not result:
        # Fall back to parsed struct_time fields.
        for key in ("published_parsed", "updated_parsed", "created_parsed"):
            value = entry.get(key)
            if not value:
                continue
            try:
                dt = datetime(
                    value.tm_year,
                    value.tm_mon,
                    value.tm_mday,
                    value.tm_hour,
                    value.tm_min,
                    value.tm_sec,
                    tzinfo=timezone.utc,
                )
                result = dt.isoformat().replace("+00:00", "Z")
                break
            except Exception:
                continue

    if result and max_dt is not None:
        try:
            parsed_dt = datetime.fromisoformat(result.replace("Z", "+00:00"))
            if parsed_dt > max_dt:
                result = max_dt.isoformat().replace("+00:00", "Z")
        except Exception:
            pass

    return result


_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_delta_lock = threading.Lock()


def _delta_dir() -> Path:
    raw = os.environ.get("FEED_DELTA_DIR")
    if raw:
        return Path(raw)
    # backend/Dockerfile creates /data (not /app/data) writable by appuser
    # and leaves /app itself root-owned, so a default relative to this
    # module's location resolves to an unwritable path in the deployed
    # container (confirmed live 2026-09-01: "Permission denied: '/app/data'"
    # on every Microsoft MSRC poll). Prefer the container's writable /data
    # when present; fall back to the old source-relative path for local
    # dev/bare-metal runs where /data doesn't exist.
    container_data_dir = Path("/data")
    if container_data_dir.is_dir() and os.access(container_data_dir, os.W_OK):
        return container_data_dir / "feed_delta"
    return Path(__file__).resolve().parent / "data" / "feed_delta"


def _delta_file_path(feed_name: str) -> Path:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", feed_name).strip("_").lower()
    return _delta_dir() / f"{slug}.json"


def _load_delta_store(feed_name: str) -> dict:
    path = _delta_file_path(feed_name)
    if not path.is_file():
        return {"source": feed_name, "updated": "", "items": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Delta store unreadable path=%s", path)
        return {"source": feed_name, "updated": "", "items": {}}
    if not isinstance(data, dict):
        return {"source": feed_name, "updated": "", "items": {}}
    items = data.get("items")
    if not isinstance(items, dict):
        data["items"] = {}
    return data


def _save_delta_store(feed_name: str, store: dict) -> None:
    path = _delta_file_path(feed_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    store["source"] = feed_name
    store["count"] = len(store.get("items") or {})
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(store, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def _touch_delta_item(items: dict, item_id: str, content_hash: str,
                      now_iso: str, ingested: int) -> None:
    prev = items.get(item_id) or {}
    already = int(prev.get("ingested") or 0)
    items[item_id] = {
        "content_hash": content_hash,
        "first_seen": prev.get("first_seen") or now_iso,
        "last_seen": now_iso,
        "ingested": 1 if already or ingested else 0,
    }


def _delta_item_id(entry) -> str:
    """Stable identity for a catalog item — CVE id when present, else guid/link."""
    title = entry.get("title") or ""
    guid = entry.get("id") or ""
    link = entry.get("link") or ""
    for text in (title, guid, link):
        match = _CVE_ID_RE.search(text)
        if match:
            return match.group(0).upper()
    return (guid or link or title)[:512]


def _delta_published_sort_key(entry) -> float:
    published = entry.get("published") or entry.get("updated") or ""
    if not published:
        return 0.0
    try:
        pub_dt = parsedate_to_datetime(published)
        if pub_dt.tzinfo is None:
            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        return pub_dt.timestamp()
    except Exception:
        return 0.0


def _newest_delta_entries(entries: list) -> list:
    """MSRC update-guide RSS repeats CVEs for each revision. Keep the newest."""
    best: dict[str, tuple[float, object]] = {}
    order: list[str] = []
    for entry in entries:
        item_id = _delta_item_id(entry)
        if not item_id:
            continue
        key = _delta_published_sort_key(entry)
        prev = best.get(item_id)
        if prev is None:
            order.append(item_id)
            best[item_id] = (key, entry)
        elif key > prev[0]:
            best[item_id] = (key, entry)
    return [best[i][1] for i in order]


def _delta_content_hash(entry) -> str:
    title = entry.get("title") or ""
    published = entry.get("published") or entry.get("updated") or ""
    summary = entry.get("summary") or ""
    raw = f"{title}\n{published}\n{summary}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _delta_in_seed_window(entry, now_dt: datetime, seed_hours: float) -> bool:
    if seed_hours <= 0:
        return False
    published = _entry_published(entry, max_dt=now_dt)
    if not published:
        return False
    try:
        pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except Exception:
        return False
    age_hours = (now_dt - pub_dt).total_seconds() / 3600.0
    return 0 <= age_hours <= seed_hours


def _filter_delta_entries(conn, feed_meta: dict, entries: list, now_dt: datetime) -> list:
    """Keep only catalog items that are new or whose content changed.

    Watermark is a JSON file (default backend/data/feed_delta/<feed>.json),
    not a database table. First poll with an empty file remembers every
    item_id and only returns entries inside delta_seed_hours (default 48).
    Later polls return unseen ids and content-hash changes. Already-ingested
    revisions are updated in place and re-queued for triage.
    """
    feed_name = feed_meta["name"]
    seed_hours = float(feed_meta.get("delta_seed_hours", 48))
    now_iso = now_dt.isoformat().replace("+00:00", "Z")
    entries = _newest_delta_entries(entries)

    with _delta_lock:
        store = _load_delta_store(feed_name)
        items = store.setdefault("items", {})
        baseline = not items

        to_insert = []
        new_ids = 0
        changed = 0
        seeded = 0

        for entry in entries:
            item_id = _delta_item_id(entry)
            if not item_id:
                continue
            content_hash = _delta_content_hash(entry)
            prev = items.get(item_id)

            if baseline:
                ingest_now = _delta_in_seed_window(entry, now_dt, seed_hours)
                _touch_delta_item(items, item_id, content_hash, now_iso, 1 if ingest_now else 0)
                if ingest_now:
                    to_insert.append(entry)
                    seeded += 1
                continue

            if prev is None:
                _touch_delta_item(items, item_id, content_hash, now_iso, 1)
                to_insert.append(entry)
                new_ids += 1
                continue

            prev_hash = prev.get("content_hash") or ""
            already_ingested = int(prev.get("ingested") or 0)
            if prev_hash == content_hash:
                continue

            changed += 1
            if already_ingested:
                h = _entry_hash(entry)
                published = _entry_published(entry, max_dt=now_dt)
                conn.execute(
                    """UPDATE entries
                       SET title = ?, summary = ?, published = ?,
                           triaged = 0, enriched = 0, ai_summary = '', ttps = ''
                       WHERE hash = ? AND source = ?""",
                    (
                        (entry.get("title") or "")[:512],
                        (entry.get("summary") or "")[:2048],
                        published,
                        h,
                        feed_name,
                    ),
                )
                _touch_delta_item(items, item_id, content_hash, now_iso, 1)
            else:
                _touch_delta_item(items, item_id, content_hash, now_iso, 1)
                to_insert.append(entry)

        if baseline or new_ids or changed or seeded:
            store["updated"] = now_iso
            _save_delta_store(feed_name, store)

    if baseline:
        logger.info(
            "Delta baseline feed=%s file=%s remembered=%d seed_ingest=%d seed_hours=%s",
            feed_name, _delta_file_path(feed_name), len(items), seeded, seed_hours,
        )
    elif new_ids or changed:
        logger.info(
            "Delta feed=%s new=%d changed=%d insert=%d",
            feed_name, new_ids, changed, len(to_insert),
        )
    return to_insert


def _write_feed_entries(conn, feed_meta: dict, entries: list, now_dt: datetime) -> tuple[int, int, list]:
    """Write one feed's already-fetched entries into `entries`, applying the
    same delta-filter/dedup/backfill rules poll_all_feeds() has always used.
    Shared by poll_all_feeds() (looped over every feed) and
    poll_single_feed() (one feed, triggered on demand from the admin
    "Retry Now" action) so the two ingest paths can't silently drift apart.

    Returns (new_count, backfill_count, new_hashes).
    """
    new_count = 0
    backfill_count = 0
    new_hashes = []

    if feed_meta.get("ingest") == "delta":
        entries = _filter_delta_entries(conn, feed_meta, entries, now_dt)
    for entry in entries:
        if not _entry_passes_feed_filters(feed_meta, entry):
            continue
        h         = _entry_hash(entry)
        published = _entry_published(entry, max_dt=now_dt)
        title_raw = entry.get("title", "")[:512]
        norm_title = normalize_title(title_raw)

        # ── Exact reingest guard ──────────────────────────────────
        if norm_title and is_exact_duplicate(conn, feed_meta["name"], norm_title, published or ""):
            logger.debug("Exact-dedup skip: source=%s title=%s", feed_meta["name"], title_raw[:80])
            continue

        content_val = ""
        content_list = entry.get("content") or []
        if content_list and isinstance(content_list, list):
            raw_content = (
                (content_list[0].get("value") or "")
                if isinstance(content_list[0], dict)
                else ""
            )
            content_val = re.sub(r"<[^>]+>", "", raw_content)[:8192]
        insert_result = conn.execute(
            """INSERT INTO entries
               (hash, source, title, link, published, summary,
                content, tags, triaged, normalized_title)
               VALUES (?,?,?,?,?,?,?,?,0,?)
               ON CONFLICT (hash) DO NOTHING""",
            (
                h,
                feed_meta["name"],
                title_raw,
                entry.get("link", ""),
                published,
                entry.get("summary", "")[:2048],
                content_val,
                "{}",
                norm_title,
            ),
        )
        if insert_result.rowcount:
            new_count += 1
            new_hashes.append(h)

        if insert_result.rowcount == 0 and published:
            update_result = conn.execute(
                """
                UPDATE entries
                SET published = ?
                WHERE hash = ? AND source = ?
                  AND (published IS NULL OR published = '' OR published != ?)
                """,
                (published, h, feed_meta["name"], published),
            )
            backfill_count += update_result.rowcount

    return new_count, backfill_count, new_hashes


def poll_all_feeds():
    logger.info("Polling %d feeds...", len(FEEDS))

    # ── Phase 1: concurrent fetch — 30s per-feed httpx timeout ───────────
    feed_results: list[tuple[dict, list]] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_fetch_feed, feed_meta): feed_meta for feed_meta in FEEDS}
        done, not_done = wait(futures, timeout=800)
        for future in not_done:
            logger.warning(
                "Feed fetch exceeded 800s collection window (thread may still be running): %s",
                futures[future]["name"],
            )
            future.cancel()
        for future in done:
            try:
                feed_results.append(future.result())
            except Exception as exc:
                logger.warning("Feed future raised unexpectedly: %s", exc)

    # ── Phase 1b: write fetch log ─────────────────────────────────────────
    now_iso = datetime.now(timezone.utc).isoformat()
    _INSERT_FETCH_LOG = (
        "INSERT INTO feed_fetch_log "
        "(feed_name, polled_at, success, items_fetched, error_msg) "
        "VALUES (?, ?, ?, ?, ?)"
    )
    log_rows = []
    for feed_meta, entries, error in feed_results:
        success = 0 if entries is None else 1
        items   = len(entries) if entries is not None else 0
        log_rows.append((feed_meta["name"], now_iso, success, items, error))
    try:
        conn_log = _connect_db()
        conn_log.executemany(_INSERT_FETCH_LOG, log_rows)
        conn_log.commit()
        conn_log.close()
    except Exception as exc:
        logger.warning("Feed fetch log write failed: %s", exc)

    # ── Phase 2: serial DB writes ─────────────────────────────────────────
    conn      = _connect_db()
    new_count = 0
    backfill_count = 0
    new_hashes = []
    now_dt = datetime.now(timezone.utc)

    for feed_meta, entries, _error in feed_results:
        if entries is None:
            continue  # fetch failed; already logged in Phase 1b
        try:
            n, b, hashes = _write_feed_entries(conn, feed_meta, entries, now_dt)
            new_count += n
            backfill_count += b
            new_hashes.extend(hashes)
        except Exception as exc:
            logger.warning("Feed %s write failed: %s", feed_meta["name"], exc)

    conn.commit()

    # ── Phase 3: cross-source dedup pass ─────────────────────────────────
    if new_hashes:
        try:
            run_dedup_pass(conn, new_hashes)
        except Exception as exc:
            logger.warning("Dedup pass failed: %s", exc)

    conn.close()
    if new_count or backfill_count:
        persist_runtime_db()
    logger.info(
        "Poll complete — %d new entries queued for triage, "
        "%d existing entries had published dates backfilled.",
        new_count,
        backfill_count,
    )

    if new_count > 0:
        dupes = deduplicate_cves()
        if dupes:
            logger.info("Dedup: marked %d entries as CVE duplicates.", dupes)


def poll_single_feed(feed_name: str) -> dict:
    """Immediately fetch and ingest one feed by name, bypassing the normal
    schedule. Backs the admin "Retry Now" action so a feed that's been
    failing doesn't have to wait for the next scheduled poll cycle to
    recover.

    Raises ValueError if feed_name isn't a known feed (in FEEDS).
    Returns {"success": bool, "error": str, "items_fetched": int,
    "new_entries": int} -- never raises for a fetch/write failure, matching
    _fetch_feed()'s own never-raises contract.
    """
    feed_meta = next((f for f in FEEDS if f["name"] == feed_name), None)
    if feed_meta is None:
        raise ValueError(f"Unknown feed: {feed_name}")

    _, entries, error = _fetch_feed(feed_meta)
    now_iso = datetime.now(timezone.utc).isoformat()
    success = 0 if entries is None else 1
    items   = len(entries) if entries is not None else 0

    new_count = 0
    new_hashes = []
    conn = _connect_db()
    try:
        conn.execute(
            "INSERT INTO feed_fetch_log "
            "(feed_name, polled_at, success, items_fetched, error_msg) "
            "VALUES (?, ?, ?, ?, ?)",
            (feed_name, now_iso, success, items, error),
        )
        if entries is not None:
            new_count, _backfill, new_hashes = _write_feed_entries(
                conn, feed_meta, entries, datetime.now(timezone.utc)
            )
        conn.commit()

        if new_hashes:
            try:
                run_dedup_pass(conn, new_hashes)
            except Exception as exc:
                logger.warning("Dedup pass failed for %s retry: %s", feed_name, exc)
    finally:
        conn.close()

    if new_count:
        persist_runtime_db()
        dupes = deduplicate_cves()
        if dupes:
            logger.info("Dedup: marked %d entries as CVE duplicates.", dupes)

    return {
        "success": bool(success),
        "error": error,
        "items_fetched": items,
        "new_entries": new_count,
    }


def archive_feeds():
    """Archive entries older than ARCHIVE_AFTER_DAYS (default 90, 0 = disabled)."""
    days = int(os.environ.get("ARCHIVE_AFTER_DAYS", "90"))
    if days <= 0:
        return
    count = archive_old_entries(days)
    if count:
        logger.info("Archived %d entries older than %d days.", count, days)


def _initial_startup_tasks():
    """Run the first poll/triage/enrichment pass in a background thread so
    uvicorn can finish startup (bind port 8000) immediately."""
    try:
        refresh_kev_cache()
        poll_all_feeds()
        triage_pending()
        run_enrichment()
    except Exception:
        logger.exception("Error during initial startup tasks")


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(poll_all_feeds,       "interval", minutes=15, id="feed_poll")
    scheduler.add_job(triage_pending,       "interval", minutes=5,  id="triage")
    scheduler.add_job(run_enrichment,       "interval", minutes=15, id="enrichment")
    scheduler.add_job(refresh_and_reenrich, "cron",     hour=3, minute=0, id="kev_refresh")
    scheduler.add_job(archive_feeds,        "cron",     hour=0, minute=0, id="archive")
    scheduler.start()
    # Run initial tasks in a daemon thread — do NOT block the lifespan startup
    # or uvicorn will not bind port 8000 until all configured feeds are fetched.
    import threading
    t = threading.Thread(target=_initial_startup_tasks, daemon=True, name="startup-tasks")
    t.start()
    return scheduler


def reextract_iocs_job(job_id: str) -> None:
    """Re-run ioc-finder on all triaged entries and upsert results into ioc_ledger.
    No AI/Anthropic calls. Preserves threat_actors from existing iocs JSON."""

    final_status = "completed"
    try:
        conn = _connect_db()
        rows = conn.execute(
            "SELECT hash, title, summary, content, iocs, ingested, link FROM entries "
            "WHERE triaged = 1"
        ).fetchall()
        conn.close()

        total = len(rows)
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].total = total

        for hash_, title, summary, content, iocs_str, ingested, link in rows:
            try:
                existing = json.loads(iocs_str) if iocs_str else {}
                _exclude = urlparse(link or "").hostname or ""
                new_iocs = _extract_iocs(title or "", summary or "", content or "", exclude_domain=_exclude)
                merged = {**new_iocs, "threat_actors": existing.get("threat_actors", [])}

                conn = _connect_db()
                try:
                    conn.execute(
                        "UPDATE entries SET iocs = ? WHERE hash = ?",
                        (json.dumps(merged), hash_),
                    )
                    conn.commit()
                finally:
                    conn.close()

                upsert_ioc_ledger(merged, hash_, ingested or "")

                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].completed += 1
            except Exception:
                logger.exception("reextract_iocs_job: error on entry %s", hash_)
                with _jobs_lock:
                    if job_id in _jobs:
                        _jobs[job_id].failed += 1

    except Exception:
        logger.exception("reextract_iocs_job: fatal error for job %s", job_id)
        final_status = "failed"
    finally:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = final_status
                _jobs[job_id].finished_at = time.time()