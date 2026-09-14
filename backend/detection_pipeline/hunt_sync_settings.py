"""Admin-controlled Sentinel Hunt sync mode ('off' | 'manual' | 'auto'),
plus (Workstream E, docs/superpowers/specs/2026-09-04-live-feedback-
round-6-design.md) a severity gate and an interval/window/day-of-week
cadence layered on top -- both applied only to the 'auto' mode's
automatic push, never to a human's manual "Deploy to Sentinel" click.

Backs GET/PATCH /api/settings/hunt-sync (+ /schedule) in main.py,
orchestrator.py's auto-sync gate, and the "Deploy to Sentinel" manual
action's mode check. See pg_hunt_sync_settings.sql for the mode
semantics and pg_hunt_sync_settings_severity_cadence.sql for the
severity/cadence columns.

The cadence columns are deliberately the same shape as orchestrator_
settings.py's own interval_minutes/window_start_minute/window_end_minute/
days_of_week -- is_due() is reused as-is from that module rather than
reimplementing the identical interval/window/day-of-week algorithm a
second time here.
"""

from __future__ import annotations

_VALID_MODES = ("off", "manual", "auto")
_VALID_SEVERITIES = ("critical", "high", "medium", "low")


def get_settings(conn) -> dict:
    """Current mode/require_alignment/severities/cadence/auto-deploy-target/
    updated-by state. Fails open to the safest state ('off',
    require_alignment=True, no severity/cadence restriction, no auto-deploy
    target) if a migration hasn't been applied yet or the singleton row is
    missing -- matches the pipeline's behavior before these settings
    existed (never auto-synced)."""
    row = conn.execute(
        "SELECT mode, require_alignment, severities, interval_minutes, "
        "window_start_minute, window_end_minute, days_of_week, last_run_at, "
        "auto_deploy_target_sentinel_hunt_id, updated_by, updated_at "
        "FROM hunt_sync_settings WHERE id = 1"
    ).fetchone()
    if not row:
        return {
            "mode": "off", "require_alignment": True,
            "severities": None, "interval_minutes": 30,
            "window_start_minute": None, "window_end_minute": None,
            "days_of_week": None, "last_run_at": None,
            "auto_deploy_target_sentinel_hunt_id": None,
            "updated_by": None, "updated_at": None,
        }
    return dict(row)


def set_settings(conn, mode: str, require_alignment: bool, updated_by: str) -> dict:
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
    conn.execute(
        "INSERT INTO hunt_sync_settings (id, mode, require_alignment, updated_by, updated_at) "
        "VALUES (1, ?, ?, ?, now()) "
        "ON CONFLICT (id) DO UPDATE SET mode = ?, require_alignment = ?, "
        "updated_by = ?, updated_at = now()",
        (mode, require_alignment, updated_by, mode, require_alignment, updated_by),
    )
    conn.commit()
    return get_settings(conn)


def set_schedule(
    conn,
    severities: list[str] | None,
    interval_minutes: int,
    window_start_minute: int | None,
    window_end_minute: int | None,
    days_of_week: list[int] | None,
    updated_by: str,
) -> dict:
    """Update the severity-gate/cadence columns. Validation beyond the
    severities allowlist (positive interval, both-or-neither window
    bounds, days_of_week within 0-6) is the caller's responsibility
    (main.py's Pydantic model) -- mirrors orchestrator_settings.set_
    interval()'s INSERT-ON-CONFLICT shape so it works whether or not the
    singleton row already exists."""
    if severities is not None:
        bad = [s for s in severities if s not in _VALID_SEVERITIES]
        if bad:
            raise ValueError(f"severities must be a subset of {_VALID_SEVERITIES}, got {bad!r}")
    conn.execute(
        "INSERT INTO hunt_sync_settings "
        "(id, severities, interval_minutes, window_start_minute, window_end_minute, "
        " days_of_week, updated_by, updated_at) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (id) DO UPDATE SET severities = ?, interval_minutes = ?, "
        "window_start_minute = ?, window_end_minute = ?, days_of_week = ?, "
        "updated_by = ?, updated_at = now()",
        (
            severities, interval_minutes, window_start_minute, window_end_minute,
            days_of_week, updated_by,
            severities, interval_minutes, window_start_minute, window_end_minute,
            days_of_week, updated_by,
        ),
    )
    conn.commit()
    return get_settings(conn)


def set_auto_deploy_target(conn, sentinel_hunt_id: str | None, updated_by: str) -> dict:
    """Point the 'auto' mode's default sync target at an existing Sentinel
    Hunt (an ARM resource name/GUID, from sentinel_hunting.list_existing_
    hunts() -- same picker main.py's HuntTargetUpdate endpoint already
    uses for the per-hunt override), or pass None to go back to "create a
    new dedicated hunt per TI article" (today's original default).

    Only affects hunts with no per-hunt target of their own (hunts.
    target_sentinel_hunt_id) -- see sentinel_hunting.resolve_auto_deploy_
    target(), which orchestrator.py's auto-sync block calls as the
    fallback when a hunt's own per-hunt override is unset. Same INSERT-
    ON-CONFLICT-if-missing shape as set_settings()/set_schedule() so it
    works whether or not the singleton row already exists.

    Called by resolve_auto_deploy_target() itself too (updated_by=
    "system:rollover") when the configured target fills up and a new
    "In The News: Hunts vN" hunt gets auto-provisioned -- not just from
    the admin-facing PATCH endpoint."""
    conn.execute(
        "INSERT INTO hunt_sync_settings (id, auto_deploy_target_sentinel_hunt_id, updated_by, updated_at) "
        "VALUES (1, ?, ?, now()) "
        "ON CONFLICT (id) DO UPDATE SET auto_deploy_target_sentinel_hunt_id = ?, "
        "updated_by = ?, updated_at = now()",
        (sentinel_hunt_id, updated_by, sentinel_hunt_id, updated_by),
    )
    conn.commit()
    return get_settings(conn)


def mark_run_started(conn) -> None:
    """Records that hunt auto-sync is actually attempting a push right
    now -- called right before sync_hunt() in orchestrator.py's auto-sync
    block, not after, so a slow sync doesn't skew the next fire's
    elapsed-time check. Same INSERT-ON-CONFLICT-if-missing shape as
    set_settings()/set_schedule()."""
    conn.execute(
        "INSERT INTO hunt_sync_settings (id, last_run_at) VALUES (1, now()) "
        "ON CONFLICT (id) DO UPDATE SET last_run_at = now()"
    )
    conn.commit()
