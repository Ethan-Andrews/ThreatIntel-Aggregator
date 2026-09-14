-- Apply/dismiss bookkeeping for a Sentinel Analytics Rule's tune suggestion
-- (tune_history.final_body, already on sentinel_analytics_rules -- see
-- pg_sentinel_analytics_rules.sql). Mirrors
-- pg_sentinel_hunt_queries_tune_action.sql exactly, same rationale: columns
-- on the row itself, not a separate audit table -- a sentinel_analytics_rules
-- row is already mutable (review_state/tune_history updated in place on
-- re-sync/re-test), and every consumer (get_rule_detail(), the Apply/Dismiss
-- UI) only ever needs the latest action, never a history of prior ones.
ALTER TABLE sentinel_analytics_rules
    ADD COLUMN IF NOT EXISTS tune_action        text
                              CHECK (tune_action IN ('applied', 'dismissed')),
    ADD COLUMN IF NOT EXISTS tune_action_by      text,
    ADD COLUMN IF NOT EXISTS tune_action_at      timestamptz,
    ADD COLUMN IF NOT EXISTS tune_push_result    jsonb;
