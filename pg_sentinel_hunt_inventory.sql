-- Sentinel-native hunt/query inventory: the actual hunts and stored hunting
-- queries that already exist in the Microsoft Sentinel workspace, pulled
-- read-only via detection_pipeline/sentinel_hunt_sync.py.
--
-- Deliberately a SEPARATE concept from `hunts` (pg_hunts.sql, one row per
-- originating TI article, grouping this app's own AI-generated `analytics`
-- rows) -- that table has never read anything back from Sentinel,
-- sentinel_hunting.py only ever pushes to it. This table is the read path:
-- one row per Microsoft.SecurityInsights/hunts object that already exists
-- in the workspace, regardless of what created it (a human analyst, another
-- tool, or this app's own sync of a `hunts` row).
--
-- Unlike `analytics` (INSERT-only for tiapp -- an immutable audit trail of
-- what was generated when), these rows are periodically re-synced from
-- Sentinel and their review/test/tune state changes in place over time, so
-- idempotent UPSERT and later UPDATEs are both load-bearing here -- tiapp
-- genuinely needs UPDATE, not just SELECT/INSERT.

CREATE TABLE IF NOT EXISTS sentinel_hunts (
    id                  bigserial   PRIMARY KEY,
    -- The ARM resource name (a GUID, see sentinel_hunting.arm_safe_id for
    -- the write-side equivalent) -- the sync identity. Unique so a re-sync
    -- upserts the same row instead of duplicating it.
    sentinel_hunt_id    text        NOT NULL UNIQUE,
    display_name        text        NOT NULL,
    description         text,
    status              text,
    hypothesis_status   text,
    attack_tactics      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    attack_techniques   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- Denormalized at sync time so the list view's rollup doesn't need a
    -- COUNT(*) JOIN per row across a workspace that can carry 800+ queries
    -- under a single hunt.
    query_count         integer     NOT NULL DEFAULT 0,
    synced_at           timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sentinel_hunt_queries (
    id                       bigserial   PRIMARY KEY,
    hunt_id                  bigint      NOT NULL REFERENCES sentinel_hunts(id) ON DELETE CASCADE,
    -- The linked savedSearches resource's ARM resource name -- the sync
    -- identity for one query, unique across the whole workspace (savedSearch
    -- ids aren't scoped per-hunt).
    sentinel_saved_search_id text        NOT NULL UNIQUE,
    display_name             text        NOT NULL,
    kql_body                 text        NOT NULL,
    description              text,
    tags                     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- Same review/test/tune shape as analytics, deliberately -- this feeds
    -- the same pipeline (control_probe.py/backtest.py/tune.py), just against
    -- an externally-sourced query instead of an AI-generated one. See
    -- detection_pipeline/sentinel_hunt_test.py.
    review_state             text        NOT NULL DEFAULT 'pending'
                             CHECK (review_state IN ('pending', 'approved', 'rejected')),
    control_probe_result     jsonb,
    backtest_disposition     text,
    tune_history             jsonb,
    last_tested_at           timestamptz,
    synced_at                timestamptz NOT NULL DEFAULT now(),
    created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sentinel_hunt_queries_hunt_id ON sentinel_hunt_queries (hunt_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_hunt_queries_review_state ON sentinel_hunt_queries (review_state);

GRANT SELECT, INSERT, UPDATE ON sentinel_hunts TO tiapp;
GRANT SELECT, INSERT, UPDATE ON sentinel_hunt_queries TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE sentinel_hunts_id_seq TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE sentinel_hunt_queries_id_seq TO tiapp;
