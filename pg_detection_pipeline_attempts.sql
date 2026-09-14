-- Per-entry retry bookkeeping for the detection pipeline's outbox loop.
-- Previously created ad hoc by orchestrator.py issuing CREATE TABLE IF NOT
-- EXISTS on every _record_failure()/_clear_failures() call -- that required
-- the app role to hold CREATE on schema public just to run a statement that,
-- once the table exists, only ever inserts/updates/deletes rows in it.
-- Moved here to match every other table's pattern: DDL runs once as pgadmin,
-- the app role gets DML only.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS detection_pipeline_attempts (
    entry_hash   TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    last_attempt TEXT
);

GRANT SELECT, INSERT, UPDATE, DELETE ON detection_pipeline_attempts TO tiapp;
