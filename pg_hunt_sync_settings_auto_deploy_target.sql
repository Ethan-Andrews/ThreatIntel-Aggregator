-- Admin-configurable default Sentinel Hunt target for the auto-sync path
-- (hunt_sync_settings.mode == 'auto'), per the user's live-feedback ask
-- (2026-09-04, after round 6 shipped): "specify which hunt to auto
-- deploy into or create new each time."
--
--   auto_deploy_target_sentinel_hunt_id -- ARM resource name (GUID) of the
--       Sentinel Hunt auto-sync should link new detections into, when the
--       owning `hunts` row has no per-hunt override of its own (hunts.
--       target_sentinel_hunt_id, set via hunts.set_hunt_target() -- that
--       per-hunt override still takes precedence over this default when
--       both are set, unchanged). NULL (the default) preserves today's
--       original behavior exactly: each TI article gets its own dedicated
--       Sentinel Hunt.
--
-- No display-name/query-count columns here deliberately -- sentinel_hunts
-- (pg_sentinel_hunt_inventory.sql), already kept fresh by sentinel_hunt_
-- sync.py's periodic inventory sync, is the source of truth for both; this
-- column only stores which one is currently the active default. See
-- sentinel_hunting.resolve_auto_deploy_target() for the 975-query rollover
-- that keeps this value current automatically as a target hunt fills up.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent.

ALTER TABLE hunt_sync_settings
    ADD COLUMN IF NOT EXISTS auto_deploy_target_sentinel_hunt_id text;
