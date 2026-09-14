-- Apply/dismiss bookkeeping for a Sentinel Hunts query's tune suggestion
-- (tune_history.final_body, already on sentinel_hunt_queries -- see
-- pg_sentinel_hunt_inventory.sql). Deliberately columns on the row itself,
-- not a separate audit table like tuning_suggestion_actions: unlike
-- `analytics`, a sentinel_hunt_queries row is already mutable (its own
-- review_state/tune_history are updated in place on re-sync/re-test), so
-- there's no immutability property to preserve here, and every consumer
-- (get_query_detail(), the Apply/Dismiss UI) only ever needs the latest
-- action, never a history of prior ones on the same query.
ALTER TABLE sentinel_hunt_queries
    ADD COLUMN IF NOT EXISTS tune_action        text
                              CHECK (tune_action IN ('applied', 'dismissed')),
    ADD COLUMN IF NOT EXISTS tune_action_by      text,
    ADD COLUMN IF NOT EXISTS tune_action_at      timestamptz,
    ADD COLUMN IF NOT EXISTS tune_push_result    jsonb;
