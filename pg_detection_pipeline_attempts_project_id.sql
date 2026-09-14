-- Adds project_id so a candidate that fails downstream of project creation
-- (validation, DB write, alignment check) resumes the same detections.ai
-- project on retry instead of creating a duplicate. detections.ai titles are
-- unique per team, so a blind retry collides and gets retitled with a fresh
-- timestamp every time -- confirmed live in prod (2026-08-20): one TI entry
-- (hash a6a828c98772...) spawned 9+ duplicate projects across a few hours
-- because process_one() kept failing after project creation but before
-- outbox.mark_emitted(), and every retry re-created the project from scratch.
--
-- The app user (tiapp) is DML only, so this runs as pgadmin. Idempotent:
-- safe to re-run.

ALTER TABLE detection_pipeline_attempts ADD COLUMN IF NOT EXISTS project_id TEXT;
