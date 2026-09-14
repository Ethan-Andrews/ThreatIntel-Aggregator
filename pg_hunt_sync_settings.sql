-- Admin-controlled Sentinel Hunt sync mode, exposed via Settings > Hunt
-- Sentinel Sync in the UI (GET/PATCH /api/settings/hunt-sync, require_admin).
-- See hunt_sync_settings.py.
--
-- Three modes:
--   'off'    (default) -- nothing is ever pushed to Sentinel, automatically
--             or manually. This is the safe starting state before the real
--             RBAC grant has been tested against a live workspace.
--   'manual' -- orchestrator.py never auto-syncs; a human reviews a hunt in
--             the UI and clicks "Deploy to Sentinel" (POST
--             /api/detections/hunts/{id}/deploy), which pushes every
--             detection in that hunt that has a passing static gate and a
--             clean backtest.
--   'auto'   -- orchestrator.py automatically syncs a hunt's eligible
--             detections (same static-gate + backtest bar as manual, plus
--             a MITRE-aligned parent strategy when require_alignment is
--             true) right after generating them, with no human in the loop.
--
-- This is layered on top of, not a replacement for,
-- SENTINEL_HUNTING_SYNC_ENABLED (sentinel_hunting.py's master kill switch --
-- still required for either 'manual' or 'auto' to actually reach Azure).
--
-- Single row (id=1), UPDATE in place -- mirrors pg_orchestrator_settings.sql.
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent.

CREATE TABLE IF NOT EXISTS hunt_sync_settings (
    id                smallint     PRIMARY KEY DEFAULT 1,
    mode              text         NOT NULL DEFAULT 'off',
    require_alignment boolean      NOT NULL DEFAULT true,
    updated_by        text,
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_hunt_sync_settings_singleton CHECK (id = 1),
    CONSTRAINT chk_hunt_sync_settings_mode CHECK (mode IN ('off', 'manual', 'auto'))
);

INSERT INTO hunt_sync_settings (id, mode, require_alignment)
VALUES (1, 'off', true)
ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON hunt_sync_settings TO tiapp;
