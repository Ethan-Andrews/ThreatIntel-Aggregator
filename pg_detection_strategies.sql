-- Technique-indexed coverage ledger.
--
-- Implements the two-tier model MITRE ATT&CK v18 formalized in place of the
-- old flat Data Sources layer: a Detection Strategy is one stable row per
-- technique (the adversary's OBJECTIVE, tool-independent), and Analytics are
-- the many tunable implementations underneath it (the specific KQL, the
-- specific telemetry, the specific thresholds -- what stages 6/7 already
-- produce).
--
-- Deliberately indexed at TECHNIQUE granularity (T1053.005), not tactic
-- (Persistence). "We're covered in Persistence" is enumeration wearing a
-- behavioral costume -- the same false-confidence failure mode this whole
-- ledger exists to avoid. "We're covered for T1053.005 specifically" is a
-- claim that can actually be checked against a new article's specifics.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

CREATE TABLE IF NOT EXISTS detection_strategies (
    id                bigserial PRIMARY KEY,
    technique_id      text        NOT NULL UNIQUE,  -- e.g. 'T1053.005'
    technique_name    text        NOT NULL,          -- e.g. 'Scheduled Task/Job: Scheduled Task'
    objective         text        NOT NULL,          -- the behavior/chokepoint, not the tool
    chokepoint_tables text[]      NOT NULL DEFAULT '{}',
    status            text        NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'needs_review', 'deprecated')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analytics (
    id                     bigserial PRIMARY KEY,
    strategy_id            bigint      NOT NULL REFERENCES detection_strategies(id),
    artifact_id            text,                     -- detections.ai artifact id, if known
    source_entry_hash      text        NOT NULL,      -- the TI article this analytic came from
    kql_body               text        NOT NULL,
    static_gate_durability numeric(4,3),              -- reuse static_gate.py's score, not a copy
    backtest_disposition   text,                      -- clean | tunable | needs_tuning | backtest_error
    tune_history           jsonb,                     -- TuneResult.to_row(), verbatim
    review_state           text        NOT NULL DEFAULT 'pending'
                          CHECK (review_state IN ('pending', 'approved', 'rejected')),
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_analytics_strategy ON analytics (strategy_id);

-- One row per (new article, existing strategy) coverage check. This is the
-- table the "does it still generalize" judgment writes to -- currently a
-- human call every time (verdict + reasoning entered by the reviewer);
-- exists now so that judgment has a durable, queryable home the moment it's
-- automated, without a schema change later. See Ethan's standing research
-- goal: automating this specific judgment is the open problem this ledger
-- is built to eventually support, not solve on day one.
CREATE TABLE IF NOT EXISTS coverage_evidence (
    id               bigserial PRIMARY KEY,
    strategy_id      bigint      NOT NULL REFERENCES detection_strategies(id),
    source_entry_hash text       NOT NULL,
    verdict          text        NOT NULL
                     CHECK (verdict IN ('corroborates', 'gap_new_analytic', 'uncertain')),
    reasoning        text,
    reviewed_by       text,                            -- null until automated; human name until then
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_coverage_evidence_strategy ON coverage_evidence (strategy_id);

GRANT SELECT, INSERT, UPDATE ON detection_strategies TO tiapp;
GRANT SELECT, INSERT ON analytics TO tiapp;
GRANT SELECT, INSERT ON coverage_evidence TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE detection_strategies_id_seq TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE analytics_id_seq TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE coverage_evidence_id_seq TO tiapp;

-- UPDATE is granted only on detection_strategies (status transitions,
-- e.g. active -> needs_review). analytics and coverage_evidence are
-- append-only from the app's perspective, matching telemetry_baseline's
-- convention -- corrections happen from an admin session, not the pipeline.
