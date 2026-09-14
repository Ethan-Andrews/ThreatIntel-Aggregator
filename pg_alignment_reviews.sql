-- The human review queue for MITRE alignment checks (see alignment_check.py).
--
-- A 'diverges' verdict means the AI's suggested KQL has already been
-- through the telemetry gate and (if it survived that) static_gate/
-- control_query/backtest -- validation_result holds that outcome verbatim,
-- so a reviewer always sees either "AI thinks this diverges, and here's
-- why a fix couldn't even be attempted" (unmapped or absent telemetry) or
-- "...and here is its attempted fix's own validation result" -- never a
-- blind suggestion. 'aligned' verdicts never create a row here; they write
-- straight to detection_strategies.mitre_alignment_status since there's
-- nothing for a human to act on.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

ALTER TABLE detection_strategies
    ADD COLUMN IF NOT EXISTS mitre_alignment_status     text,
    ADD COLUMN IF NOT EXISTS mitre_alignment_checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS mitre_alignment_reasoning  text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_mitre_alignment_status'
    ) THEN
        ALTER TABLE detection_strategies
            ADD CONSTRAINT chk_mitre_alignment_status
            CHECK (mitre_alignment_status IN ('aligned', 'diverges', 'partial')
                   OR mitre_alignment_status IS NULL);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS alignment_reviews (
    id                bigserial PRIMARY KEY,
    strategy_id       bigint      NOT NULL REFERENCES detection_strategies(id),
    analytic_id       bigint      REFERENCES analytics(id),
    verdict           text        NOT NULL CHECK (verdict IN ('diverges', 'partial')),
    ai_reasoning      text,
    suggested_kql     text,
    validation_result jsonb,
    status            text        NOT NULL DEFAULT 'pending_review'
                      CHECK (status IN ('pending_review', 'accepted', 'rejected',
                                        'queued_for_rereview', 'rereview_resolved')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    reviewed_at       timestamptz,
    reviewed_by       text
);

CREATE INDEX IF NOT EXISTS ix_alignment_reviews_status ON alignment_reviews (status);
CREATE INDEX IF NOT EXISTS ix_alignment_reviews_strategy ON alignment_reviews (strategy_id);

-- UPDATE is granted (unlike the append-only analytics/coverage_evidence
-- convention) because accept/reject and the re-review sweep both
-- legitimately transition an existing row's status after insert.
GRANT SELECT, INSERT, UPDATE ON alignment_reviews TO tiapp;
GRANT USAGE, SELECT ON SEQUENCE alignment_reviews_id_seq TO tiapp;
