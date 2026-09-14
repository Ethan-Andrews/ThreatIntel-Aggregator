"""Smoke test: the detection-pipeline schema files are applied to the test DB."""


def test_detection_strategies_tables_exist(db_conn):
    for table in ("detection_strategies", "analytics", "coverage_evidence", "hit_baseline"):
        db_conn.execute(f"SELECT 1 FROM {table} LIMIT 0")


def test_detection_strategies_has_alignment_columns(db_conn):
    db_conn.execute(
        "SELECT mitre_alignment_status, mitre_alignment_checked_at, "
        "mitre_alignment_reasoning FROM detection_strategies LIMIT 0"
    )


def test_mitre_and_alignment_review_tables_exist(db_conn):
    for table in ("mitre_detection_strategies", "alignment_reviews"):
        db_conn.execute(f"SELECT 1 FROM {table} LIMIT 0")


def test_analytics_has_validation_columns(db_conn):
    db_conn.execute(
        "SELECT static_gate_verdict, static_gate_findings, control_probe_result "
        "FROM analytics LIMIT 0"
    )


def test_disposition_checks_table_exists(db_conn):
    db_conn.execute(
        "SELECT analytic_id, checked_at, hits, window_hours, "
        "control_probe_disposition, backtest_disposition, outcome, detail "
        "FROM disposition_checks LIMIT 0"
    )


def test_detection_pipeline_attempts_table_exists(db_conn):
    db_conn.execute(
        "SELECT entry_hash, attempts, last_error, last_attempt "
        "FROM detection_pipeline_attempts LIMIT 0"
    )


def test_orchestrator_settings_table_exists(db_conn):
    db_conn.execute(
        "SELECT id, enabled, updated_by, updated_at "
        "FROM orchestrator_settings LIMIT 0"
    )
