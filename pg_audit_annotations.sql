-- Admin annotations on audit_log.py's synthesized `combined` rows
-- (Workstream C, docs/superpowers/specs/2026-09-04-live-feedback-round-6-
-- design.md). Audit rows aren't real persisted entities -- they're
-- synthesized fresh on every call by audit_log._BASE_QUERY's UNION ALL --
-- so there's no `audit_entries` row to UPDATE a status onto. This table
-- is annotated separately and LEFT JOIN'd back onto `combined` by
-- (source, source_id), which matches _row_to_item()'s existing natural
-- key exactly: 'detection'|'hunt_sync'|'sentinel_query'|'analytic_rule'
-- plus the real underlying table's own PK (a.id/h.id/q.id/r.id).
--
-- Confirmed with the user (2026-09-04): an annotated row (any of the
-- three statuses) drops out of the failing count and out of the trend
-- buckets entirely -- it's no longer "currently failing," it's "handled."
-- "Fixed" is a manual close-out with no auto-clear tied to a re-check.
--
-- DELETE grant included so clearing an annotation (reverting to
-- unannotated) is a real operation, not a fourth pseudo-status.

CREATE TABLE IF NOT EXISTS audit_annotations (
    source      text        NOT NULL,
    source_id   bigint      NOT NULL,
    status      text        NOT NULL,
    notes       text        NOT NULL DEFAULT '',
    updated_by  text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, source_id),
    CONSTRAINT chk_audit_annotations_source
        CHECK (source IN ('detection', 'hunt_sync', 'sentinel_query', 'analytic_rule')),
    CONSTRAINT chk_audit_annotations_status
        CHECK (status IN ('acknowledged', 'not_applicable', 'fixed'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON audit_annotations TO tiapp;
