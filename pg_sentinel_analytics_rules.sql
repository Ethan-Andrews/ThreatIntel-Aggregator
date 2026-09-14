-- Sentinel Analytics Rules inventory: the actual Microsoft.SecurityInsights/
-- alertRules objects that already exist in the Sentinel workspace, pulled
-- read-only via detection_pipeline/sentinel_analytics_rules_sync.py.
--
-- A distinct Azure resource type from Hunting's savedSearches/hunts
-- (confirmed against Microsoft's own REST API reference, learn.microsoft.com/
-- rest/api/securityinsights/alert-rules/list, fetched 2026-09-02) -- this is
-- Sentinel's actual "Analytics Rules" feature (what creates incidents/alerts
-- on a schedule), not a hunting query. Only `kind == "Scheduled"` rules carry
-- a raw KQL `query` property this app's static_gate/control_probe/backtest/
-- tune pipeline can evaluate -- Fusion/MicrosoftSecurityIncidentCreation/ML/
-- NRT rule kinds have no equivalent field and are not synced here.
--
-- Flat, unlike sentinel_hunts/sentinel_hunt_queries' two-level hunt->query
-- model -- analytics rules aren't grouped into a parent container in
-- Sentinel, each is independently addressable by its own ARM resource id.
--
-- Same review/test/tune shape as sentinel_hunt_queries deliberately: this
-- feeds the exact same pipeline (detection_pipeline/sentinel_hunt_test.py's
-- run_query_check()/run_query_tune() are already generic over kql/title/
-- artifact_id, not hunt-specific, so they're reused as-is here).
--
-- UPDATE is load-bearing (re-synced periodically, review/test/tune state
-- changes in place) -- same tiapp grant shape as sentinel_hunt_queries, not
-- analytics' INSERT-only convention.

CREATE TABLE IF NOT EXISTS sentinel_analytics_rules (
    id                  bigserial   PRIMARY KEY,
    -- The ARM resource name (a GUID or a human-chosen slug, both occur in
    -- practice -- confirmed in the REST API's own example response, which
    -- shows both a GUID-named and a slug-named rule side by side). Unique
    -- so a re-sync upserts the same row instead of duplicating it.
    sentinel_rule_id    text        NOT NULL UNIQUE,
    display_name        text        NOT NULL,
    description         text,
    kind                text        NOT NULL DEFAULT 'Scheduled',
    severity            text,
    kql_body            text        NOT NULL,
    enabled             boolean     NOT NULL DEFAULT true,
    tactics             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    techniques          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    review_state        text        NOT NULL DEFAULT 'pending'
                        CHECK (review_state IN ('pending', 'approved', 'rejected')),
    control_probe_result jsonb,
    backtest_disposition text,
    tune_history        jsonb,
    last_tested_at      timestamptz,
    synced_at           timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sentinel_analytics_rules_review_state ON sentinel_analytics_rules (review_state);

GRANT SELECT, INSERT, UPDATE ON sentinel_analytics_rules TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE sentinel_analytics_rules_id_seq TO tiapp;
