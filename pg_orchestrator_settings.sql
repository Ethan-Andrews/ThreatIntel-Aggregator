-- Admin-controlled soft on/off switch for job-tiagg-orchestrator, exposed via
-- Settings > API Settings in the UI (GET/PATCH /api/settings/orchestrator,
-- require_admin). See orchestrator_settings.py.
--
-- Defaults to false (opt-in): this orchestrator makes real vendor API
-- (detections.ai) and Sentinel calls, so it should never run before an
-- admin has actually configured and explicitly enabled it, matching
-- hunt_sync_settings.sql's own 'off'-by-default convention for the same
-- reason. A fresh install with no DETECTIONS_AI_API_KEY configured is
-- harmless either way (orchestrator.py's decoupling seam makes it a
-- sweep-only no-op with no provider), but the default should still say
-- "off" rather than rely on that fallback.
--
-- IMPORTANT: this does NOT change Azure's own Schedule trigger on the
-- Container Apps Job -- it still fires on its fixed cron
-- (infra/apps.bicep's orchestratorSchedule param) regardless of this flag.
-- There is no native pause/resume for a Container Apps Job's schedule
-- trigger in any ARM API version checked (2024-03-01 through
-- 2025-10-02-preview) -- only cronExpression, parallelism, and
-- replicaCompletionCount are settable, and Stop-AzContainerAppJobExecution
-- only terminates an already-running execution, not future triggers.
-- Disabling here makes orchestrator.run() exit immediately without claiming
-- any candidates or making any AI/Sentinel calls -- the container still
-- starts on schedule but does no work and exits in well under a second.
--
-- Single row (id=1), UPDATE in place -- not append-only like
-- disposition_checks. The app user (tiapp) is DML only, so this runs as
-- pgadmin. Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS orchestrator_settings (
    id          smallint     PRIMARY KEY DEFAULT 1,
    enabled     boolean      NOT NULL DEFAULT false,
    updated_by  text,
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_orchestrator_settings_singleton CHECK (id = 1)
);

INSERT INTO orchestrator_settings (id, enabled)
VALUES (1, false)
ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON orchestrator_settings TO tiapp;
