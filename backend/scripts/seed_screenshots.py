"""Seed a fresh Postgres database with entirely synthetic threat-intel data,
for capturing public README screenshots (docs/superpowers/plans/2026-09-14-
public-release-parity-and-local-detections.md, Task 7) without ever touching
real org/customer data.

Populates every tab/sub-tab the frontend has -- feed entries, RunZero assets/
matches/exposure, IOC ledger, and the full detections pipeline (AI-generated
analytics/hunts, alignment reviews, disposition alerts, Sentinel hunt/
analytics-rule inventory) -- with fake org names, RFC 5737 example IPs,
`.example` domains, and fictional threat-actor names. Real MITRE ATT&CK
technique IDs (T1059, T1053.005, ...) are used since that's public taxonomy,
not identifying data.

Does NOT seed Local Detections Import content -- that's exercised for real
by pointing LOCAL_IMPORT_DIR at a folder containing a couple of real fixture
files (see backend/tests/fixtures/local_import/) and triggering an import
via the UI or POST /api/detections/local-import, so the screenshot reflects
the actual static-gate/cataloging pipeline rather than a hand-faked result.

Usage:
    createdb -h 127.0.0.1 -U postgres tiagg_screenshots
    # apply backend/pg_schema.sql + the root pg_*.sql migrations first --
    # see backend/tests/conftest.py's DETECTION_PIPELINE_SCHEMA_PATHS for
    # the exact ordered list.
    PG_DSN=postgresql://postgres@127.0.0.1:5432/tiagg_screenshots \
        python3 backend/scripts/seed_screenshots.py

Safe to re-run: every insert is idempotent (ON CONFLICT DO NOTHING/UPDATE or
a get-or-create lookup), so re-running just refreshes timestamps rather than
duplicating rows. Never point PG_DSN at a database you care about -- this
script does not truncate anything itself, but it's meant for a disposable
scratch database, not a real deployment's.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("PG_DSN", "postgresql://postgres@127.0.0.1:5432/tiagg_screenshots")

BACKEND_DIR = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, BACKEND_DIR)

import db  # noqa: E402
import pgcompat  # noqa: E402
from detection_pipeline import hunts as hunts_module  # noqa: E402

now = datetime.now(timezone.utc)


def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def ts(days_ago: float, hours_ago: float = 0) -> str:
    dt = now - timedelta(days=days_ago, hours=hours_ago)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Sources / feed health
# ---------------------------------------------------------------------------
SOURCES = [
    ("CISA", 92, 1), ("Cisco Talos", 88, 1), ("Fortinet Threat Signal", 81, 1),
    ("The DFIR Report", 85, 1), ("Google Project Zero", 90, 1),
    ("SentinelOne Labs", 76, 1), ("Check Point Research", 74, 1),
    ("Recorded Future", 70, 2), ("SANS ISC", 68, 2), ("Unit42", 72, 2),
    ("Securelist", 65, 2), ("Malpedia", 60, 2), ("Wiz Blog", 58, 2),
    ("BleepingComputer", 45, 3), ("Krebs", 50, 3), ("TheHackerNews", 40, 3),
    ("Dark Reading", 42, 3), ("Schneier", 38, 3),
]

conn = pgcompat.connect()

for name, score, tier in SOURCES:
    conn.execute(
        "INSERT INTO sources (name, score, tier) VALUES (?, ?, ?) "
        "ON CONFLICT (name) DO UPDATE SET score = EXCLUDED.score, tier = EXCLUDED.tier",
        (name, score, tier),
    )
conn.commit()

# feed_fetch_log: mostly healthy, a couple of feeds with an active failure streak
FETCH_LOG = []
for i, (name, _score, _tier) in enumerate(SOURCES):
    for d in range(3, 0, -1):
        FETCH_LOG.append((name, ts(d), 1, 6 + (i % 5), ""))
    if name in ("Dark Reading", "Schneier"):
        FETCH_LOG.append((name, ts(0.2), 0, 0, "HTTP 503 from feed host after 3 retries"))
        FETCH_LOG.append((name, ts(0.5), 0, 0, "HTTP 503 from feed host after 3 retries"))
    else:
        FETCH_LOG.append((name, ts(0.2), 1, 4 + (i % 6), ""))

for name, polled_at, success, items, err in FETCH_LOG:
    conn.execute(
        "INSERT INTO feed_fetch_log (feed_name, polled_at, success, items_fetched, error_msg) "
        "VALUES (?, ?, ?, ?, ?)",
        (name, polled_at, success, items, err),
    )
conn.commit()

# ---------------------------------------------------------------------------
# Entries (Feed / Dashboard / MITRE / IOCs)
# ---------------------------------------------------------------------------
SEVERITIES = ["Critical", "High", "High", "Medium", "Medium", "Low", "Informational"]
TTP_SETS = [
    "T1059,T1059.001", "T1053.005", "T1021.001,T1021", "T1071.001",
    "T1105", "T1140", "T1547.001", "T1055", "T1003", "T1486",
    "T1190", "T1566.001", "T1078", "T1027",
]
MALWARE = ["Ransomware", "Infostealer", "Botnet", "RAT", "Wiper", "Loader"]
ACTOR_TYPES = ["Nation-State", "Cybercriminal", "Hacktivist"]
SECTORS = ["Healthcare", "Financial Services", "Manufacturing", "Education", "Retail", "Government"]
PLATFORMS = ["Windows", "Linux", "Cloud", "macOS", "Network Appliance"]
INDICATOR_TYPES = ["IP Address", "Domain", "File Hash", "URL", "CVE"]
FAKE_ACTORS = ["Shadow Marmot", "Crimson Loom", "Glass Adder", "Violet Ferret", "Ashen Kestrel"]

TITLES = [
    "Novel {mal} campaign targets {sector} organizations via phishing",
    "{actor} exploits internet-facing VPN appliances in {sector} sector",
    "Critical remote code execution flaw disclosed in widely-used {plat} service",
    "Supply-chain compromise delivers {mal} through trojanized update package",
    "Living-off-the-land technique observed in {sector} intrusion",
    "{actor} deploys custom {mal} against {plat} endpoints",
    "Mass scanning activity precedes exploitation of edge device CVE",
    "Threat actors abuse legitimate cloud storage for C2 in {sector} attacks",
    "New {mal} variant adds anti-analysis and lateral movement capability",
    "Advisory: actively exploited zero-day affecting {plat} systems",
]

entries = []
for i in range(42):
    sev = SEVERITIES[i % len(SEVERITIES)]
    source = SOURCES[i % len(SOURCES)][0]
    mal = MALWARE[i % len(MALWARE)]
    sector = SECTORS[i % len(SECTORS)]
    plat = PLATFORMS[i % len(PLATFORMS)]
    actor = FAKE_ACTORS[i % len(FAKE_ACTORS)]
    title_tpl = TITLES[i % len(TITLES)]
    title = title_tpl.format(mal=mal, sector=sector, plat=plat, actor=actor)
    link = f"https://example.com/advisories/{i:03d}"
    published = ts(i * 0.6 + 0.1)
    summary = (
        f"{actor} was observed leveraging {mal.lower()} tooling against {sector.lower()} "
        f"sector targets running {plat}. Indicators include traffic to 198.51.100.{10+i%200} "
        f"and lookalike domain threat-report-{i}.example."
    )
    hash_ = h(f"entry-{i}-{title}")
    entries.append({
        "hash": hash_, "source": source, "title": title, "link": link,
        "published": published, "summary": summary, "sev": sev,
        "ttps": TTP_SETS[i % len(TTP_SETS)], "mal": mal, "sector": sector,
        "plat": plat, "actor": actor, "idx": i,
    })

for e in entries:
    conn.execute(
        "INSERT INTO entries (hash, source, title, link, published, summary, content, "
        "tags, triaged, normalized_title, ingested) "
        "VALUES (?,?,?,?,?,?,?,?,0,?,?) ON CONFLICT (hash) DO NOTHING",
        (e["hash"], e["source"], e["title"], e["link"], e["published"], e["summary"],
         e["summary"], "{}", e["title"].lower(), e["published"]),
    )
conn.commit()

for e in entries:
    i = e["idx"]
    cve = f"CVE-2026-{10000+i}"
    ip = f"198.51.100.{10 + i % 200}"
    ip2 = f"203.0.113.{5 + i % 200}"
    domain = f"threat-report-{i}.example"
    url = f"http://{domain}/payload"
    file_hash = h(f"payload-{i}")
    tags = {
        "indicator_types": [INDICATOR_TYPES[i % len(INDICATOR_TYPES)], INDICATOR_TYPES[(i + 1) % len(INDICATOR_TYPES)]],
        "malware_types": [e["mal"]],
        "threat_actor_types": [ACTOR_TYPES[i % len(ACTOR_TYPES)]],
        "target_sectors": [e["sector"]],
        "platforms": [e["plat"]],
    }
    iocs = {
        "ips": [ip, ip2] if i % 3 == 0 else [ip],
        "domains": [domain],
        "urls": [url] if i % 2 == 0 else [],
        "cves": [cve] if i % 4 != 3 else [],
        "threat_actors": [e["actor"]],
        "hashes": [file_hash] if i % 2 == 1 else [],
    }
    ai_summary = (
        f"{e['actor']} used {e['mal'].lower()} to target {e['sector'].lower()} organizations. "
        f"Observed C2 infrastructure at {ip} and {domain}. Recommend blocking associated "
        f"indicators and patching {e['plat']} systems referenced in {cve}."
    )
    db.apply_triage(
        e["hash"], e["sev"], e["ttps"], ai_summary,
        tags=json.dumps(tags), iocs=json.dumps(iocs), persist=False,
    )

# Mark a few as duplicates / archived for dashboard stat variety
dup_conn = pgcompat.connect()
for e in entries[-4:]:
    dup_conn.execute("UPDATE entries SET is_duplicate = 1 WHERE hash = ?", (e["hash"],))
for e in entries[:3]:
    dup_conn.execute("UPDATE entries SET archived = 1, archived_at = ? WHERE hash = ?", (ts(95), e["hash"]))
# A couple of untriaged / pending entries
for e in entries[20:23]:
    dup_conn.execute(
        "UPDATE entries SET triaged = 0, severity = 'Unknown', ttps = '' WHERE hash = ?",
        (e["hash"],),
    )
dup_conn.commit()

# KEV flag + priority score on a handful for realism
for e in entries[:6]:
    dup_conn.execute(
        "UPDATE entries SET kev_flag = 1, epss_score = ?, priority_score = ?, enriched = 1 WHERE hash = ?",
        (0.87, 92.5, e["hash"]),
    )
dup_conn.commit()
dup_conn.close()

print(f"Seeded {len(entries)} entries, {len(SOURCES)} sources, {len(FETCH_LOG)} feed_fetch_log rows")

# ---------------------------------------------------------------------------
# Stack items (Your Stack)
# ---------------------------------------------------------------------------
STACK = [
    ("Endpoint", "Windows Server 2022", ["windows server", "win server"]),
    ("Endpoint", "Ubuntu Linux 22.04", ["ubuntu", "linux"]),
    ("Cloud", "Microsoft Azure", ["azure", "entra"]),
    ("Cloud", "Amazon Web Services", ["aws", "amazon web services"]),
    ("Firewall / Network", "Fortinet FortiGate", ["fortigate", "fortios"]),
    ("Identity", "Okta", ["okta"]),
    ("SaaS", "Microsoft 365", ["microsoft 365", "office 365", "m365"]),
]
for cat, name, keywords in STACK:
    try:
        db.add_stack_item(cat, name, keywords)
    except ValueError:
        pass
print(f"Seeded {len(STACK)} stack items")

# ---------------------------------------------------------------------------
# RunZero assets / vulns / matches / exposure
# ---------------------------------------------------------------------------
ORGS = ["Acme Threat Intel", "Northwind Security Team"]
conn2 = pgcompat.connect()

assets = []
for i in range(10):
    org = ORGS[i % len(ORGS)]
    asset_id = f"asset-{i:03d}"
    hostname = f"host-{i:03d}.example"
    ip = f"192.0.2.{20 + i}"
    os_name = ["Windows Server 2022", "Ubuntu 22.04", "Windows 11 Enterprise"][i % 3]
    assets.append({"id": asset_id, "org": org, "hostname": hostname, "ip": ip, "os": os_name})
    conn2.execute(
        "INSERT INTO runzero_assets (id, org, site, hostname, os, addresses_json, "
        "software_json, alive, last_seen, tags_json) "
        "VALUES (?,?,?,?,?,?,?,1,?,?) ON CONFLICT (id) DO NOTHING",
        (asset_id, org, "HQ" if i % 2 == 0 else "Branch Office", hostname, os_name,
         json.dumps([ip]), json.dumps(["FortiGate" if i % 3 == 0 else "OpenSSH"]),
         int(now.timestamp()), json.dumps(["prod"] if i % 2 == 0 else ["staging"])),
    )
    if i % 3 == 0:
        conn2.execute(
            "INSERT INTO runzero_vulns (asset_id, cve_id, severity, vuln_name) "
            "VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
            (asset_id, f"CVE-2026-{10000+i}", "Critical", "Remote Code Execution"),
        )
conn2.commit()

match_entries = entries[:10]
for i, (asset, e) in enumerate(zip(assets, match_entries)):
    confidence = "confirmed" if i % 2 == 0 else "possible"
    conn2.execute(
        "INSERT INTO runzero_matches (entry_hash, asset_id, match_type, match_detail, confidence) "
        "VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
        (e["hash"], asset["id"], "cve", f"CVE-2026-{10000+e['idx']}", confidence),
    )
conn2.commit()

conn2.execute(
    "INSERT INTO runzero_sync_log (synced_at, org_count, asset_count, vuln_count, match_count, status, error) "
    "VALUES (?,?,?,?,?,?,?)",
    (ts(0.1), len(ORGS), len(assets), 4, len(match_entries), "ok", ""),
)
conn2.commit()

# exposure_items: mix of active/acknowledged/remediated
statuses = ["active", "active", "acknowledged", "remediated"]
for i, (asset, e) in enumerate(zip(assets, match_entries)):
    status = statuses[i % len(statuses)]
    first_seen = (now - timedelta(days=10 - i)).isoformat()
    last_seen = (now - timedelta(hours=i)).isoformat()
    remediated_at = (now - timedelta(hours=2)).isoformat() if status == "remediated" else None
    conn2.execute(
        "INSERT INTO exposure_items (asset_id, entry_hash, status, notes, assigned_to, "
        "first_seen, last_seen, remediated_at) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT (asset_id, entry_hash) DO NOTHING",
        (asset["id"], e["hash"], status, "Reviewed by security team" if status != "active" else "",
         "j.rivera@example.com" if status == "acknowledged" else None,
         first_seen, last_seen, remediated_at),
    )
conn2.commit()
print(f"Seeded {len(assets)} runzero assets, {len(match_entries)} matches, exposure items")
conn2.close()

# ---------------------------------------------------------------------------
# Detections: strategies / analytics / hunts / alignment / disposition
# ---------------------------------------------------------------------------
conn3 = pgcompat.connect()

STRATEGIES = [
    ("T1059.001", "Command and Scripting Interpreter: PowerShell",
     "Adversaries abuse PowerShell for execution, evading traditional AV via in-memory execution."),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task",
     "Adversaries abuse the Windows Task Scheduler to establish persistence."),
    ("T1021.001", "Remote Services: Remote Desktop Protocol",
     "Adversaries use RDP to move laterally between hosts on a compromised network."),
    ("T1071.001", "Application Layer Protocol: Web Protocols",
     "Adversaries use HTTP/HTTPS for command-and-control to blend in with normal traffic."),
    ("T1140", "Deobfuscate/Decode Files or Information",
     "Adversaries decode obfuscated payloads (e.g. via certutil) to evade detection."),
    ("T1003", "OS Credential Dumping",
     "Adversaries dump credentials from LSASS memory or the SAM database."),
]

strategy_ids = {}
for tid, tname, objective in STRATEGIES:
    row = conn3.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, status) "
        "VALUES (?,?,?,'active') "
        "ON CONFLICT (technique_id) DO UPDATE SET technique_name = EXCLUDED.technique_name "
        "RETURNING id",
        (tid, tname, objective),
    ).fetchone()
    strategy_ids[tid] = row[0]
conn3.commit()

# analytics: a spread of review states / gate verdicts / dispositions / targets
ANALYTIC_DEFS = [
    ("T1059.001", "Suspicious Encoded PowerShell Command Line", "sentinel", "pass", 0.91, "clean", "approved"),
    ("T1053.005", "New Scheduled Task Created by Office Process", "sentinel", "pass", 0.85, "clean", "approved"),
    ("T1021.001", "Anomalous RDP Login from External IP", "sentinel", "pass", 0.78, "tunable", "pending"),
    ("T1071.001", "Beaconing to Newly Registered Domain", "sentinel", "pass", 0.82, "clean", "approved"),
    ("T1140", "Certutil Decode Abuse", "mde", "pass", 0.88, "clean", "approved"),
    ("T1003", "LSASS Memory Access via Uncommon Process", "mde", "reject", 0.41, "needs_tuning", "pending"),
    ("T1059.001", "PowerShell Download Cradle", "sentinel", "pass", 0.73, "needs_tuning", "pending"),
    ("T1053.005", "Scheduled Task Persistence via schtasks.exe", "mde", "pass", 0.80, "clean", "approved"),
]

analytic_ids = []
for i, (tid, name, target, verdict, durability, disposition, review_state) in enumerate(ANALYTIC_DEFS):
    kql = (
        f"DeviceProcessEvents\n| where ProcessCommandLine has \"{name.split()[0].lower()}\"\n"
        f"| where Timestamp > ago(1d)\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine"
    )
    row = conn3.execute(
        "INSERT INTO analytics (strategy_id, artifact_id, source_entry_hash, kql_body, "
        "static_gate_durability, backtest_disposition, review_state, name, description, "
        "static_gate_verdict, static_gate_findings, control_probe_result, origin, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'ai_generated',?) RETURNING id",
        (strategy_ids[tid], f"artifact-{i:04d}", entries[i % len(entries)]["hash"], kql,
         durability, disposition, review_state, name,
         f"Detects {name.lower()} indicative of technique {tid}.",
         verdict,
         json.dumps([{"finding": "hash_predicate_only", "detail": "matches a single literal value"}]) if verdict == "reject" else json.dumps([]),
         json.dumps({"target": target}),
         ts(20 - i)),
    ).fetchone()
    analytic_ids.append(row[0])
conn3.commit()

# Group the first 5 analytics into 2 hunts (Generated Hunts tab)
hunt_defs = [
    (entries[0]["hash"], "PowerShell and Scheduled Task Persistence Campaign",
     "Detections generated in response to a campaign combining PowerShell abuse and scheduled-task persistence.",
     entries[0], analytic_ids[0:2]),
    (entries[1]["hash"], "RDP Lateral Movement and C2 Beaconing",
     "Detections covering lateral movement via RDP alongside HTTP-based command-and-control beaconing.",
     entries[1], analytic_ids[2:4]),
]
hunt_ids = []
for source_hash, title, desc, src_entry, aids in hunt_defs:
    hid = hunts_module.get_or_create_hunt(
        conn3, source_hash, title, description=desc,
        source_title=src_entry["title"], source_link=src_entry["link"],
        source_name=src_entry["source"], source_severity=src_entry["sev"],
    )
    hunt_ids.append(hid)
    for aid in aids:
        conn3.execute("UPDATE analytics SET hunt_id = ? WHERE id = ?", (hid, aid))
conn3.commit()

# Mark one hunt successfully synced to Sentinel, one with a sync error (audit log needs this)
conn3.execute(
    "UPDATE hunts SET sentinel_hunt_id = ?, sentinel_synced_at = ? WHERE id = ?",
    ("8f3a2b10-aaaa-4c3d-9e21-1a2b3c4d5e6f", ts(1), hunt_ids[0]),
)
conn3.execute(
    "UPDATE hunts SET sentinel_sync_error = ? WHERE id = ?",
    ("ARM PUT failed: 403 Forbidden -- missing Microsoft Sentinel Contributor role", hunt_ids[1]),
)
conn3.commit()

print(f"Seeded {len(STRATEGIES)} strategies, {len(analytic_ids)} analytics, {len(hunt_ids)} hunts")

# alignment_reviews (Alignment Reviews tab)
conn3.execute(
    "UPDATE detection_strategies SET mitre_alignment_status = 'aligned', "
    "mitre_alignment_checked_at = ? WHERE technique_id IN ('T1059.001','T1071.001','T1140')",
    (ts(2),),
)
conn3.execute(
    "UPDATE detection_strategies SET mitre_alignment_status = 'diverges', "
    "mitre_alignment_checked_at = ? WHERE technique_id = 'T1003'",
    (ts(2),),
)
conn3.execute(
    "UPDATE detection_strategies SET mitre_alignment_status = 'partial', "
    "mitre_alignment_checked_at = ? WHERE technique_id = 'T1053.005'",
    (ts(2),),
)
conn3.commit()

conn3.execute(
    "INSERT INTO alignment_reviews (strategy_id, analytic_id, verdict, ai_reasoning, "
    "suggested_kql, validation_result, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
    (strategy_ids["T1003"], analytic_ids[5], "diverges",
     "The analytic only alerts on a single named process accessing LSASS memory. MITRE's "
     "description of T1003 covers a broad set of credential-dumping tools and techniques "
     "(comsvcs.dll MiniDump, Task Manager dumps, procdump, direct API calls); this rule would "
     "miss the majority of real-world OS credential dumping activity.",
     "DeviceProcessEvents\n| where FileName in~ (\"procdump.exe\",\"comsvcs.dll\",\"taskmgr.exe\")\n"
     "| where ProcessCommandLine has \"lsass\"",
     json.dumps({"static_gate_verdict": "pass", "static_gate_durability": 0.79}),
     "pending_review", ts(1.5)),
)
conn3.execute(
    "INSERT INTO alignment_reviews (strategy_id, analytic_id, verdict, ai_reasoning, "
    "suggested_kql, validation_result, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
    (strategy_ids["T1053.005"], analytic_ids[7], "partial",
     "The analytic covers scheduled tasks created via schtasks.exe, but MITRE's Detection "
     "Strategy for this technique also calls out tasks created directly via the Task "
     "Scheduler COM API (ITaskService), which this rule would not catch.",
     None,
     json.dumps({"note": "no fix attempted -- unmapped telemetry for COM-based task creation"}),
     "queued_for_rereview", ts(3)),
)
conn3.commit()
print("Seeded 2 alignment reviews")

# disposition_checks (Disposition Alerts tab) -- rot on already-approved analytics
DISPOSITION_DEFS = [
    (analytic_ids[0], "now_firing", 143, 24, "firing", "clean",
     {"note": "Started firing after a legitimate internal admin tool began matching the same command-line pattern."}),
    (analytic_ids[3], "telemetry_decayed", 0, 24, "no_data", "clean",
     {"note": "Underlying DeviceNetworkEvents table has had zero rows for 6 days -- ingestion appears to have stopped."}),
]
for aid, outcome, hits, window_hours, probe_disp, backtest_disp, detail in DISPOSITION_DEFS:
    conn3.execute(
        "INSERT INTO disposition_checks (analytic_id, checked_at, hits, window_hours, "
        "control_probe_disposition, backtest_disposition, outcome, detail) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (aid, ts(0.3), hits, window_hours, probe_disp, backtest_disp, outcome, json.dumps(detail)),
    )
conn3.commit()
print(f"Seeded {len(DISPOSITION_DEFS)} disposition checks")

# ---------------------------------------------------------------------------
# Sentinel Hunts + Sentinel Hunt Queries (native Sentinel inventory)
# ---------------------------------------------------------------------------
SENTINEL_HUNTS = [
    ("hunt-guid-0001", "In the News V2", "Curated hunt tracking techniques covered in recent public threat reporting.",
     "Active", "investigating", ["Execution", "Persistence"], ["T1059.001", "T1053.005"]),
    ("hunt-guid-0002", "Lateral Movement Sweep", "Ongoing hunt for lateral-movement indicators across the fleet.",
     "Active", "in_progress", ["Lateral Movement"], ["T1021.001"]),
]
sentinel_hunt_ids = []
for sid, name, desc, status, hyp, tactics, techniques in SENTINEL_HUNTS:
    row = conn3.execute(
        "INSERT INTO sentinel_hunts (sentinel_hunt_id, display_name, description, status, "
        "hypothesis_status, attack_tactics, attack_techniques, query_count, synced_at) "
        "VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT (sentinel_hunt_id) DO UPDATE SET display_name = EXCLUDED.display_name "
        "RETURNING id",
        (sid, name, desc, status, hyp, json.dumps(tactics), json.dumps(techniques), 2, ts(0.5)),
    ).fetchone()
    sentinel_hunt_ids.append(row[0])
conn3.commit()

SENTINEL_QUERIES = [
    (sentinel_hunt_ids[0], "saved-search-0001", "PowerShell EncodedCommand Sweep",
     "DeviceProcessEvents\n| where ProcessCommandLine has \"-EncodedCommand\"\n| where Timestamp > ago(7d)",
     "approved", {"gate_verdict": "pass"}, "clean"),
    (sentinel_hunt_ids[0], "saved-search-0002", "Scheduled Task Anomaly Sweep",
     "DeviceEvents\n| where ActionType == \"ScheduledTaskCreated\"\n| where Timestamp > ago(7d)",
     "pending", {"gate_verdict": "pass"}, "tunable"),
    (sentinel_hunt_ids[1], "saved-search-0003", "External RDP Session Sweep",
     "DeviceLogonEvents\n| where LogonType == \"RemoteInteractive\"\n| where isnotempty(RemoteIP)",
     "pending", {"gate_verdict": "reject", "gate_findings": [{"finding": "no_time_bound"}]}, "needs_tuning"),
]
for hunt_id, ssid, name, kql, review_state, probe, backtest in SENTINEL_QUERIES:
    conn3.execute(
        "INSERT INTO sentinel_hunt_queries (hunt_id, sentinel_saved_search_id, display_name, "
        "kql_body, description, tags, review_state, control_probe_result, backtest_disposition, "
        "last_tested_at, synced_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT (sentinel_saved_search_id) DO NOTHING",
        (hunt_id, ssid, name, kql, f"Hunting query: {name}", json.dumps(["hunting"]),
         review_state, json.dumps(probe), backtest, ts(0.4), ts(0.5)),
    )
conn3.commit()
print(f"Seeded {len(sentinel_hunt_ids)} sentinel hunts, {len(SENTINEL_QUERIES)} sentinel hunt queries")

# ---------------------------------------------------------------------------
# Sentinel Analytics Rules
# ---------------------------------------------------------------------------
SENTINEL_RULES = [
    ("rule-guid-0001", "Suspicious Certutil Decode Activity",
     "Alerts when certutil.exe is used with decode arguments, a common LOLBin technique.",
     "Scheduled", "Medium",
     "DeviceProcessEvents\n| where FileName == \"certutil.exe\"\n| where ProcessCommandLine has \"-decode\"",
     True, ["Defense Evasion"], ["T1140"], "approved",
     {"gate_verdict": "pass"}, "clean"),
    ("rule-guid-0002", "Mass Credential Dumping via LSASS Access",
     "Alerts on processes accessing LSASS memory in a pattern consistent with credential dumping.",
     "Scheduled", "High",
     "DeviceProcessEvents\n| where ProcessCommandLine has \"lsass\"",
     True, ["Credential Access"], ["T1003"], "pending",
     {"gate_verdict": "reject", "gate_findings": [{"finding": "hash_predicate_only"}]}, "needs_tuning"),
    ("rule-guid-0003", "Fusion: Multi-Stage Ransomware Attack",
     "Fusion correlation rule combining multiple weak signals into a high-confidence ransomware alert.",
     "Fusion", "Critical", "",
     True, ["Impact"], ["T1486"], "pending", None, None),
]
for sid, name, desc, kind, sev, kql, enabled, tactics, techniques, review_state, probe, backtest in SENTINEL_RULES:
    conn3.execute(
        "INSERT INTO sentinel_analytics_rules (sentinel_rule_id, display_name, description, "
        "kind, severity, kql_body, enabled, tactics, techniques, review_state, "
        "control_probe_result, backtest_disposition, last_tested_at, synced_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT (sentinel_rule_id) DO NOTHING",
        (sid, name, desc, kind, sev, kql, enabled, json.dumps(tactics), json.dumps(techniques),
         review_state, json.dumps(probe) if probe else None, backtest,
         ts(0.4) if probe else None, ts(0.5)),
    )
conn3.commit()
print(f"Seeded {len(SENTINEL_RULES)} sentinel analytics rules")

# audit_annotations: annotate one failing item as acknowledged so the Audit
# Log tab shows the annotation workflow, not just raw failures.
conn3.execute(
    "INSERT INTO audit_annotations (source, source_id, status, notes, updated_by) "
    "VALUES ('detection', ?, 'acknowledged', ?, ?) "
    "ON CONFLICT (source, source_id) DO NOTHING",
    (analytic_ids[5], "Known limitation -- re-scoping to cover more LSASS access vectors.", "admin@example.com"),
)
conn3.commit()

conn3.close()
print("Seed complete.")
