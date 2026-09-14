"""Tests for analytics_catalog.py -- the general read-only listing that
backs GET /api/detections and GET /api/detections/disposition-alerts."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import hunts
import analytics_catalog


def _seed(conn, technique_id, disposition=None, review_state="pending",
          name=None, description=None, kql_body="SomeTable | take 1",
          target=None, hunt_id=None):
    import json
    strategy = conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (technique_id, "Some Technique", "Detect it", []),
    ).fetchone()
    control_probe_result = json.dumps({"target": target}) if target else None
    analytic = conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, "
        " backtest_disposition, review_state, name, description, "
        " control_probe_result, hunt_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (strategy["id"], "hash-" + technique_id, kql_body,
         disposition, review_state, name, description,
         control_probe_result, hunt_id),
    ).fetchone()
    conn.commit()
    return strategy["id"], analytic["id"]


# --- objective_is_fallback() -------------------------------------------------

def test_objective_is_fallback_true_when_exact_match():
    assert analytics_catalog.objective_is_fallback("Phishing", "Phishing") is True


def test_objective_is_fallback_true_when_technique_name_is_a_prefix():
    # register_strategy() stores (mitre.objective or technique_name)[:500] --
    # a length-capped objective can be technique_name plus nothing, or
    # technique_name itself truncated; either way this is the "no real
    # MITRE content" case, not just a bare equality check.
    assert analytics_catalog.objective_is_fallback("Phishing: Spearphishing", "Phishing: Spearphishing") is True


def test_objective_is_fallback_false_for_a_real_mitre_objective():
    assert analytics_catalog.objective_is_fallback(
        "Detect scripted execution of an unsigned binary via rundll32", "Phishing",
    ) is False


def test_objective_is_fallback_true_when_objective_is_null():
    assert analytics_catalog.objective_is_fallback(None, "Phishing") is True


def test_list_analytics_flags_fallback_vs_real_objective(db_conn):
    strategy_a = db_conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1566.001", "Spearphishing Attachment", "Spearphishing Attachment", []),
    ).fetchone()
    strategy_b = db_conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1059", "Command and Scripting Interpreter",
         "Detect anomalous command-line interpreter usage", []),
    ).fetchone()
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body) VALUES (?, ?, ?)",
        (strategy_a["id"], "hash-a", "SomeTable | take 1"),
    )
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body) VALUES (?, ?, ?)",
        (strategy_b["id"], "hash-b", "SomeTable | take 1"),
    )
    db_conn.commit()

    result = analytics_catalog.list_analytics(db_conn)
    by_technique = {item["technique_id"]: item for item in result["items"]}
    assert by_technique["T1566.001"]["objective_is_fallback"] is True
    assert by_technique["T1059"]["objective_is_fallback"] is False


def test_list_analytics_returns_all_by_default(db_conn):
    _seed(db_conn, "T1053.001", disposition="clean")
    _seed(db_conn, "T1053.002", disposition="needs_tuning")
    result = analytics_catalog.list_analytics(db_conn)
    assert result["total"] == 2
    assert len(result["items"]) == 2


def test_list_analytics_filters_by_technique_id(db_conn):
    _seed(db_conn, "T1053.001", disposition="clean")
    _seed(db_conn, "T1053.002", disposition="clean")
    result = analytics_catalog.list_analytics(db_conn, technique_id="T1053.001")
    assert result["total"] == 1
    assert result["items"][0]["technique_id"] == "T1053.001"


def test_list_analytics_filters_by_disposition(db_conn):
    _seed(db_conn, "T1053.001", disposition="clean")
    _seed(db_conn, "T1053.002", disposition="needs_tuning")
    result = analytics_catalog.list_analytics(db_conn, disposition="needs_tuning")
    assert result["total"] == 1
    assert result["items"][0]["backtest_disposition"] == "needs_tuning"


def test_list_analytics_filters_by_review_state(db_conn):
    _seed(db_conn, "T1053.001", review_state="rejected")
    _seed(db_conn, "T1053.002", review_state="pending")
    result = analytics_catalog.list_analytics(db_conn, review_state="rejected")
    assert result["total"] == 1
    assert result["items"][0]["review_state"] == "rejected"


def test_list_analytics_search_matches_technique_id_substring(db_conn):
    _seed(db_conn, "T1053.001", name="Suspicious Scheduled Task Creation")
    _seed(db_conn, "T1059.001", name="Malicious PowerShell Download")
    result = analytics_catalog.list_analytics(db_conn, search="1053")
    assert result["total"] == 1
    assert result["items"][0]["technique_id"] == "T1053.001"


def test_list_analytics_search_matches_name_substring_case_insensitively(db_conn):
    _seed(db_conn, "T1053.001", name="Suspicious Scheduled Task Creation")
    _seed(db_conn, "T1059.001", name="Malicious PowerShell Download")
    result = analytics_catalog.list_analytics(db_conn, search="powershell")
    assert result["total"] == 1
    assert result["items"][0]["technique_id"] == "T1059.001"


def test_list_analytics_search_finds_nothing_for_an_unnamed_legacy_row_by_name(db_conn):
    # Pre-pg_analytics_name_description.sql rows have name=NULL -- a name
    # search can't match them (only a technique_id search still can), same
    # as the UI's own "Unnamed -- <technique_id>" fallback label implies.
    _seed(db_conn, "T1053.001", name=None)
    result = analytics_catalog.list_analytics(db_conn, search="scheduled task")
    assert result["total"] == 0


def test_list_analytics_filters_by_detection_type_sentinel_vs_mde(db_conn):
    _seed(db_conn, "T1053.001", target="sentinel")
    _seed(db_conn, "T1053.002", target="mde")
    _seed(db_conn, "T1053.003")  # never control-probed -- no target at all

    sentinel_result = analytics_catalog.list_analytics(db_conn, detection_type="sentinel")
    assert sentinel_result["total"] == 1
    assert sentinel_result["items"][0]["technique_id"] == "T1053.001"
    assert sentinel_result["items"][0]["detection_type"] == "sentinel"

    mde_result = analytics_catalog.list_analytics(db_conn, detection_type="mde")
    assert mde_result["total"] == 1
    assert mde_result["items"][0]["technique_id"] == "T1053.002"


def test_list_analytics_filters_by_detection_type_hunt(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "hash-hunt-dt", title="Some hunt")
    _seed(db_conn, "T1053.001", hunt_id=hunt_id)
    _seed(db_conn, "T1053.002")  # no hunt

    result = analytics_catalog.list_analytics(db_conn, detection_type="hunt")
    assert result["total"] == 1
    assert result["items"][0]["technique_id"] == "T1053.001"
    assert result["items"][0]["hunt_id"] == hunt_id


def test_list_analytics_invalid_detection_type_is_ignored_not_erroring(db_conn):
    _seed(db_conn, "T1053.001", target="sentinel")
    # Callers are expected to reject an invalid value before this layer
    # (see main.py's own 400), but the DB layer itself should degrade to
    # "no filter" rather than raise on garbage input.
    result = analytics_catalog.list_analytics(db_conn, detection_type="bogus")
    assert result["total"] == 1


def test_get_disposition_alerts_only_returns_flagged_outcomes(db_conn):
    _, analytic_id = _seed(db_conn, "T1053.001", disposition="clean")
    db_conn.execute(
        "INSERT INTO disposition_checks (analytic_id, control_probe_disposition, outcome) "
        "VALUES (?, 'ok', 'still_clean')",
        (analytic_id,),
    )
    db_conn.execute(
        "INSERT INTO disposition_checks (analytic_id, control_probe_disposition, outcome) "
        "VALUES (?, 'ok', 'now_firing')",
        (analytic_id,),
    )
    db_conn.commit()

    result = analytics_catalog.get_disposition_alerts(db_conn)
    assert result["total"] == 1
    assert result["items"][0]["outcome"] == "now_firing"
    assert result["items"][0]["technique_id"] == "T1053.001"


def test_get_disposition_alerts_filters_by_detection_type(db_conn):
    hunt_id = hunts.get_or_create_hunt(db_conn, "hash-hunt-da", title="Some hunt")
    _, sentinel_analytic = _seed(db_conn, "T1053.001", target="sentinel")
    _, hunt_analytic = _seed(db_conn, "T1053.002", hunt_id=hunt_id)
    for analytic_id in (sentinel_analytic, hunt_analytic):
        db_conn.execute(
            "INSERT INTO disposition_checks (analytic_id, control_probe_disposition, outcome) "
            "VALUES (?, 'ok', 'now_firing')",
            (analytic_id,),
        )
    db_conn.commit()

    sentinel_result = analytics_catalog.get_disposition_alerts(db_conn, detection_type="sentinel")
    assert sentinel_result["total"] == 1
    assert sentinel_result["items"][0]["technique_id"] == "T1053.001"

    hunt_result = analytics_catalog.get_disposition_alerts(db_conn, detection_type="hunt")
    assert hunt_result["total"] == 1
    assert hunt_result["items"][0]["technique_id"] == "T1053.002"
    assert hunt_result["items"][0]["hunt_id"] == hunt_id


# --- Detection name/description/KQL surfaced everywhere (name-in-alerts fix) -

def test_list_analytics_includes_name_description_and_kql(db_conn):
    _seed(db_conn, "T1053.001", name="Suspicious Scheduled Task Creation",
          description="Flags schtasks.exe creating a new scheduled task.",
          kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'")
    result = analytics_catalog.list_analytics(db_conn)
    item = result["items"][0]
    assert item["name"] == "Suspicious Scheduled Task Creation"
    assert item["description"] == "Flags schtasks.exe creating a new scheduled task."
    assert item["kql_body"] == "DeviceProcessEvents | where FileName == 'schtasks.exe'"


def test_list_analytics_name_is_none_when_not_stored(db_conn):
    """Rows created before the name/description migration have neither --
    callers must handle None, not assume every row has a name."""
    _seed(db_conn, "T1053.001")
    result = analytics_catalog.list_analytics(db_conn)
    assert result["items"][0]["name"] is None
    assert result["items"][0]["description"] is None


def test_get_disposition_alerts_includes_name_description_and_kql(db_conn):
    """The whole point of this fix: a disposition alert must carry the
    detection's actual name, not just the shared MITRE technique, so an
    analyst can triage off the alert alone."""
    _, analytic_id = _seed(
        db_conn, "T1053.001", disposition="clean",
        name="Suspicious Scheduled Task Creation",
        description="Flags schtasks.exe creating a new scheduled task.",
        kql_body="DeviceProcessEvents | where FileName == 'schtasks.exe'",
    )
    db_conn.execute(
        "INSERT INTO disposition_checks (analytic_id, control_probe_disposition, outcome) "
        "VALUES (?, 'ok', 'now_firing')",
        (analytic_id,),
    )
    db_conn.commit()

    result = analytics_catalog.get_disposition_alerts(db_conn)
    item = result["items"][0]
    assert item["name"] == "Suspicious Scheduled Task Creation"
    assert item["description"] == "Flags schtasks.exe creating a new scheduled task."
    assert item["kql_body"] == "DeviceProcessEvents | where FileName == 'schtasks.exe'"


# --- tuning_suggestion surfacing (apply/dismiss button show/hide) ----------

def test_list_analytics_tuning_suggestion_is_none_when_never_tuned(db_conn):
    _seed(db_conn, "T1053.001")
    result = analytics_catalog.list_analytics(db_conn)
    assert result["items"][0]["tuning_suggestion"] is None


def test_list_analytics_tuning_suggestion_pending_when_final_body_present(db_conn):
    strategy = db_conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1053.001", "Some Technique", "Detect it", []),
    ).fetchone()
    import json
    db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, tune_history) "
        "VALUES (?, ?, ?, ?)",
        (strategy["id"], "hash-T1053.001", "SomeTable | take 1",
         json.dumps({"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""})),
    )
    db_conn.commit()

    result = analytics_catalog.list_analytics(db_conn)
    suggestion = result["items"][0]["tuning_suggestion"]
    assert suggestion["pending"] is True
    assert suggestion["final_body"] == "SomeTable | where X != @\"bob\""
    assert suggestion["action"] is None


def test_list_analytics_tuning_suggestion_not_pending_once_actioned(db_conn):
    import json
    strategy = db_conn.execute(
        "INSERT INTO detection_strategies (technique_id, technique_name, objective, chokepoint_tables) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        ("T1053.001", "Some Technique", "Detect it", []),
    ).fetchone()
    analytic = db_conn.execute(
        "INSERT INTO analytics (strategy_id, source_entry_hash, kql_body, tune_history) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (strategy["id"], "hash-T1053.001", "SomeTable | take 1",
         json.dumps({"disposition": "tuned", "final_body": "SomeTable | where X != @\"bob\""})),
    ).fetchone()
    db_conn.execute(
        "INSERT INTO tuning_suggestion_actions (analytic_id, suggested_kql_body, action, performed_by) "
        "VALUES (?, ?, 'dismissed', 'alice')",
        (analytic["id"], "SomeTable | where X != @\"bob\""),
    )
    db_conn.commit()

    result = analytics_catalog.list_analytics(db_conn)
    suggestion = result["items"][0]["tuning_suggestion"]
    assert suggestion["pending"] is False
    assert suggestion["action"] == "dismissed"
    assert suggestion["performed_by"] == "alice"


def test_get_analytics_for_tuning_returns_fields_keyed_by_id(db_conn):
    _, analytic_id = _seed(db_conn, "T1053.001", name="Some Name", description="desc")
    result = analytics_catalog.get_analytics_for_tuning(db_conn, [analytic_id])
    assert result[analytic_id]["name"] == "Some Name"
    assert result[analytic_id]["technique_id"] == "T1053.001"


def test_get_analytics_for_tuning_empty_ids_returns_empty_dict(db_conn):
    assert analytics_catalog.get_analytics_for_tuning(db_conn, []) == {}
