import json
import os
import unittest
from unittest.mock import MagicMock, patch

# Ensure the backend directory is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pg_helpers import pg_test_conn as _pg_test_conn

from runzero_sync import (
    RunZeroClient,
    _parse_asset,
    _run_software_os_correlation,
    is_configured,
    run_correlation_pass,
    sync_runzero,
)


def _make_db():
    """Freshly-truncated connection against the real Postgres schema --
    replaces the old hand-rolled sqlite in-memory schema, which couldn't
    parse run_correlation_pass()'s JOIN LATERAL (genuinely Postgres-only
    syntax, correct for production) and defaulted entries.source to '' where
    the real schema has no default at all."""
    return _pg_test_conn()


class TestIsConfigured(unittest.TestCase):
    def test_returns_false_when_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("RUNZERO_API_TOKEN", None)
            self.assertFalse(is_configured())

    def test_returns_true_when_set(self):
        with patch.dict(os.environ, {"RUNZERO_API_TOKEN": "CTxxxxxx"}):
            self.assertTrue(is_configured())


class TestParseAsset(unittest.TestCase):
    def test_full_asset(self):
        raw = {
            "id": "asset-1",
            "names": ["CORP-WEB-001"],
            "addresses": ["10.0.0.1", "192.168.1.10"],
            "os": "Windows Server 2022",
            "alive": True,
            "last_seen": 1700000000,
            "service_products": ["Apache HTTP Server 2.4", "OpenSSL 3.0"],
            "site_name": "HQ",
        }
        result = _parse_asset(raw, "FSC Corp")
        self.assertEqual(result["id"], "asset-1")
        self.assertEqual(result["hostname"], "CORP-WEB-001")
        self.assertEqual(result["org"], "FSC Corp")
        self.assertEqual(result["site"], "HQ")
        self.assertEqual(result["os"], "Windows Server 2022")
        self.assertEqual(json.loads(result["addresses_json"]), ["10.0.0.1", "192.168.1.10"])
        self.assertEqual(json.loads(result["software_json"]), ["Apache HTTP Server 2.4", "OpenSSL 3.0"])
        self.assertEqual(result["alive"], 1)

    def test_minimal_asset(self):
        raw = {"id": "asset-2", "names": [], "addresses": [], "alive": False}
        result = _parse_asset(raw, "Test Org")
        self.assertEqual(result["hostname"], "")
        self.assertEqual(result["alive"], 0)
        self.assertEqual(result["os"], "")


class TestSyncRunzero(unittest.TestCase):
    def test_sync_writes_assets_and_vulns(self):
        conn = _make_db()
        mock_client = MagicMock()
        mock_client.list_orgs.return_value = [{"id": "org-1", "name": "FSC Corp"}]
        mock_client.iter_assets.return_value = iter([{
            "id": "asset-1", "names": ["HOST-001"], "addresses": ["10.0.0.1"],
            "os": "Windows 11", "alive": True, "last_seen": 1700000000,
            "service_products": ["Chrome 120"], "site_name": "HQ",
        }])
        mock_client.iter_vulns.return_value = iter([{
            "vulnerability_asset_id": "asset-1", "vulnerability_cve": "CVE-2024-1234",
            "vulnerability_severity": "High", "vulnerability_name": "Test CVE",
        }])

        with patch("runzero_sync.RunZeroClient", return_value=mock_client), \
             patch.dict(os.environ, {"RUNZERO_API_TOKEN": "CT-test"}):
            asset_count, vuln_count = sync_runzero(conn)

        self.assertEqual(asset_count, 1)
        self.assertEqual(vuln_count, 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM runzero_assets").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM runzero_vulns").fetchone()[0], 1)
        log_row = conn.execute("SELECT status FROM runzero_sync_log ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(log_row[0], "ok")
        conn.close()

    def test_sync_skips_vulns_without_cve(self):
        conn = _make_db()
        mock_client = MagicMock()
        mock_client.list_orgs.return_value = [{"id": "org-1", "name": "FSC"}]
        mock_client.iter_assets.return_value = iter([
            {"id": "asset-1", "names": [], "addresses": [], "alive": True, "last_seen": 0}
        ])
        mock_client.iter_vulns.return_value = iter([
            {"vulnerability_asset_id": "asset-1", "vulnerability_cve": "", "vulnerability_severity": "High", "vulnerability_name": "No CVE"},
            {"vulnerability_asset_id": "asset-1", "vulnerability_cve": None, "vulnerability_severity": "Low", "vulnerability_name": "Also No CVE"},
        ])

        with patch("runzero_sync.RunZeroClient", return_value=mock_client), \
             patch.dict(os.environ, {"RUNZERO_API_TOKEN": "CT-test"}):
            _, vuln_count = sync_runzero(conn)

        self.assertEqual(vuln_count, 0)
        conn.close()


class TestRunCorrelationPass(unittest.TestCase):
    def _setup_cve_scenario(self):
        conn = _make_db()
        conn.execute(
            "INSERT INTO runzero_assets (id, org, hostname, alive) VALUES ('a1', 'FSC', 'HOST-001', 1)"
        )
        conn.execute(
            "INSERT INTO runzero_vulns (asset_id, cve_id, severity) VALUES ('a1', 'CVE-2024-1234', 'High')"
        )
        conn.execute(
            "INSERT INTO entries (hash, title, source, severity, iocs, ai_summary) "
            "VALUES ('hash1', 'Critical RCE CVE-2024-1234', 'S', 'High', "
            "'{\"cves\": [\"CVE-2024-1234\"], \"ips\": []}', 'Summary text')"
        )
        conn.execute(
            "INSERT INTO runzero_sync_log (synced_at, status) VALUES ('2026-01-01T00:00:00Z', 'ok')"
        )
        conn.commit()
        return conn

    def test_cve_match_produces_confirmed(self):
        conn = self._setup_cve_scenario()
        run_correlation_pass(conn)
        row = conn.execute(
            "SELECT confidence FROM runzero_matches WHERE entry_hash = 'hash1' AND match_type = 'cve'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "confirmed")
        conn.close()

    def test_informational_entries_excluded(self):
        conn = _make_db()
        conn.execute(
            "INSERT INTO runzero_assets (id, org, hostname, alive) VALUES ('a1', 'FSC', 'HOST-001', 1)"
        )
        conn.execute(
            "INSERT INTO runzero_vulns (asset_id, cve_id, severity) VALUES ('a1', 'CVE-2024-9999', 'Low')"
        )
        conn.execute(
            "INSERT INTO entries (hash, title, source, severity, iocs, ai_summary) "
            "VALUES ('info-hash', 'Informational post', 'S', 'Informational', "
            "'{\"cves\": [\"CVE-2024-9999\"], \"ips\": []}', 'Some summary')"
        )
        conn.execute(
            "INSERT INTO runzero_sync_log (synced_at, status) VALUES ('2026-01-01T00:00:00Z', 'ok')"
        )
        conn.commit()
        run_correlation_pass(conn)
        count = conn.execute("SELECT COUNT(*) FROM runzero_matches WHERE entry_hash = 'info-hash'").fetchone()[0]
        self.assertEqual(count, 0)
        conn.close()

    def test_software_match_produces_possible(self):
        conn = _make_db()
        conn.execute(
            "INSERT INTO runzero_assets (id, org, hostname, os, alive, software_json) "
            "VALUES ('a1', 'FSC', 'HOST-001', 'Windows 11', 1, ?)",
            (json.dumps(["Apache HTTP Server 2.4"]),),
        )
        conn.execute(
            "INSERT INTO entries (hash, title, source, severity, iocs, ai_summary) "
            "VALUES ('hash2', 'Apache vulnerability', 'S', 'High', '{\"cves\": [], \"ips\": []}', 'Apache HTTP Server exploit')"
        )
        conn.execute(
            "INSERT INTO runzero_sync_log (synced_at, status) VALUES ('2026-01-01T00:00:00Z', 'ok')"
        )
        conn.commit()
        run_correlation_pass(conn)
        row = conn.execute(
            "SELECT confidence FROM runzero_matches WHERE entry_hash = 'hash2' AND match_type = 'software'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "possible")
        conn.close()


class TestTagsSync(unittest.TestCase):
    def test_tags_stored_in_asset(self):
        conn = _make_db()
        mock_client = MagicMock()
        mock_client.list_orgs.return_value = [{"id": "org-1", "name": "FSC"}]
        mock_client.iter_assets.return_value = iter([{
            "id": "asset-1", "names": ["HOST-001"], "addresses": ["10.0.0.1"],
            "os": "Windows 11", "alive": True, "last_seen": 1700000000,
            "service_products": [], "site_name": "HQ",
            "tags": ["production", "windows"],
        }])
        mock_client.iter_vulns.return_value = iter([])

        with patch("runzero_sync.RunZeroClient", return_value=mock_client), \
             patch.dict(os.environ, {"RUNZERO_API_TOKEN": "CT-test"}):
            sync_runzero(conn)

        tags_json = conn.execute(
            "SELECT tags_json FROM runzero_assets WHERE id = 'asset-1'"
        ).fetchone()[0]
        self.assertEqual(json.loads(tags_json), ["production", "windows"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
