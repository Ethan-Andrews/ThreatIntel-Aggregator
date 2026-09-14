"""register_analytic() must persist the detection's name/description (from
detections.ai's Detection.title/description at generation time) so every
downstream consumer -- disposition alerts, alignment review, the detections
catalog, hunts -- can identify a row by more than its shared MITRE technique.
See pg_analytics_name_description.sql for why these columns were missing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import coverage_ledger
import hunts


def _seed_strategy(conn, technique_id="T1053.005"):
    row = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Scheduled Task", "Detect scheduled task creation", []),
    ).fetchone()
    conn.commit()
    return row["id"]


def test_register_analytic_persists_name_and_description(db_conn):
    strategy_id = _seed_strategy(db_conn)
    analytic_id = coverage_ledger.register_analytic(
        db_conn, strategy_id, source_entry_hash="hash-1",
        kql_body="DeviceProcessEvents | take 1",
        name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
    )
    row = db_conn.execute(
        "SELECT name, description FROM analytics WHERE id = ?", (analytic_id,)
    ).fetchone()
    assert row["name"] == "Suspicious Scheduled Task Creation"
    assert row["description"] == "Flags schtasks.exe creating a new scheduled task."


def test_register_analytic_defaults_name_and_description_to_none(db_conn):
    """Existing call sites that don't pass name/description (there shouldn't
    be any left after this change, but defensively) must not break."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = coverage_ledger.register_analytic(
        db_conn, strategy_id, source_entry_hash="hash-2",
        kql_body="DeviceProcessEvents | take 1",
    )
    row = db_conn.execute(
        "SELECT name, description FROM analytics WHERE id = ?", (analytic_id,)
    ).fetchone()
    assert row["name"] is None
    assert row["description"] is None


def test_register_analytic_persists_hunt_id(db_conn):
    strategy_id = _seed_strategy(db_conn)
    hunt_id = hunts.get_or_create_hunt(db_conn, "hash-hunt-1", title="Some hunt")

    analytic_id = coverage_ledger.register_analytic(
        db_conn, strategy_id, source_entry_hash="hash-hunt-1",
        kql_body="DeviceProcessEvents | take 1", hunt_id=hunt_id,
    )
    row = db_conn.execute("SELECT hunt_id FROM analytics WHERE id = ?", (analytic_id,)).fetchone()
    assert row["hunt_id"] == hunt_id


def test_register_analytic_treats_empty_string_name_as_none(db_conn):
    """detections.ai returns null for description on some artifacts
    (detections_client.py's get_detection() already coerces that to ''); an
    empty string is not a real name and should store as NULL, not as a
    visible-but-blank value that would render as an empty label."""
    strategy_id = _seed_strategy(db_conn)
    analytic_id = coverage_ledger.register_analytic(
        db_conn, strategy_id, source_entry_hash="hash-3",
        kql_body="DeviceProcessEvents | take 1",
        name="", description="",
    )
    row = db_conn.execute(
        "SELECT name, description FROM analytics WHERE id = ?", (analytic_id,)
    ).fetchone()
    assert row["name"] is None
    assert row["description"] is None
