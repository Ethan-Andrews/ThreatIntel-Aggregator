-- Cache of the real table catalog available in the connected Sentinel/Log
-- Analytics workspace -- replaces static_gate.py's hand-maintained
-- DEFAULT_MDE_TABLES allowlist as the primary source once populated (that
-- allowlist becomes the fallback for an empty/never-synced cache instead
-- of the only source of truth). MDE/Defender tables are already included:
-- Device*/Email*/Identity* etc. land in the same Log Analytics workspace
-- as Sentinel-native tables (see telemetry_resolver.py's
-- SentinelTelemetryResolver), so one Tables-List ARM call covers both.
--
-- Not deleted-and-reinserted on each sync -- a table that stops appearing
-- in a later sync just stops getting its synced_at bumped, mirroring
-- mitre_detection_strategies' own append/update convention, so a future
-- "haven't seen this table in N days" signal is available if ever needed.
--
-- Single reference table, not a singleton row like orchestrator_settings.
-- The app user (tiapp) needs SELECT/INSERT/UPDATE (re-synced periodically,
-- not append-only). Applied by hand via pgadmin, per this repo's DML-only
-- app-role convention. Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS sentinel_workspace_tables (
    name       text        PRIMARY KEY,
    synced_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON sentinel_workspace_tables TO tiapp;
