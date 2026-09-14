"""Admin-controlled soft on/off switch, plus a configurable
interval/daily-window/day-of-week schedule, for job-tiagg-orchestrator.

Backs GET/PATCH /api/settings/orchestrator in main.py and the guard
orchestrator.run() checks before claiming any candidates. See
pg_orchestrator_settings.sql for why this is a soft, DB-driven gate rather
than an Azure-side pause: Container Apps Jobs have no native suspend/resume
for a schedule trigger. See pg_orchestrator_settings_interval.sql for the
interval/window/day-of-week columns this module also manages -- a DB-driven
"effective interval" can only ever be a multiple of Azure's own outer cron
(infra/apps.bicep's orchestratorSchedule), never shorter than it.
"""

from __future__ import annotations

from datetime import datetime

_DOW_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

_DEFAULTS = {
    "enabled": False,
    "interval_minutes": 30,
    "window_start_minute": None,
    "window_end_minute": None,
    "days_of_week": None,
    "last_run_at": None,
    "updated_by": None,
    "updated_at": None,
}


def get_settings(conn) -> dict:
    """Current enabled/interval/window/day-of-week/updated-by state. Fails
    closed (enabled=False) if the migration hasn't been applied yet or the
    singleton row is missing -- this orchestrator makes real vendor
    (detections.ai) and Sentinel calls, so an ambiguous/unmigrated state
    must never be treated as "on". Matches pg_orchestrator_settings.sql's
    own default and hunt_sync_settings.sql's 'off'-by-default convention
    for the same reason."""
    row = conn.execute(
        "SELECT enabled, interval_minutes, window_start_minute, window_end_minute, "
        "days_of_week, last_run_at, updated_by, updated_at "
        "FROM orchestrator_settings WHERE id = 1"
    ).fetchone()
    if not row:
        return dict(_DEFAULTS)
    return dict(row)


def set_enabled(conn, enabled: bool, updated_by: str) -> dict:
    conn.execute(
        "INSERT INTO orchestrator_settings (id, enabled, updated_by, updated_at) "
        "VALUES (1, ?, ?, now()) "
        "ON CONFLICT (id) DO UPDATE SET enabled = ?, updated_by = ?, updated_at = now()",
        (enabled, updated_by, enabled, updated_by),
    )
    conn.commit()
    return get_settings(conn)


def set_interval(
    conn,
    interval_minutes: int,
    window_start_minute: int | None,
    window_end_minute: int | None,
    days_of_week: list[int] | None,
    updated_by: str,
) -> dict:
    """Update the interval/window/day-of-week columns. Validation (positive
    interval, both-or-neither window bounds, days_of_week within 0-6) is
    the caller's responsibility (main.py's Pydantic model) -- this mirrors
    set_enabled()'s INSERT-or-UPDATE shape so it works whether or not the
    singleton row already exists."""
    conn.execute(
        "INSERT INTO orchestrator_settings "
        "(id, interval_minutes, window_start_minute, window_end_minute, days_of_week, updated_by, updated_at) "
        "VALUES (1, ?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (id) DO UPDATE SET interval_minutes = ?, window_start_minute = ?, "
        "window_end_minute = ?, days_of_week = ?, updated_by = ?, updated_at = now()",
        (
            interval_minutes, window_start_minute, window_end_minute, days_of_week, updated_by,
            interval_minutes, window_start_minute, window_end_minute, days_of_week, updated_by,
        ),
    )
    conn.commit()
    return get_settings(conn)


def mark_run_started(conn) -> None:
    """Records that the orchestrator is actually doing work right now --
    called once is_due() has cleared the batch, before the candidate loop
    starts (not after it finishes), so a long-running batch doesn't skew
    the next fire's elapsed-time check. INSERT-ON-CONFLICT, same as
    set_enabled()/set_interval(), so this works even if the singleton row
    doesn't exist yet -- a bare UPDATE would silently affect zero rows."""
    conn.execute(
        "INSERT INTO orchestrator_settings (id, last_run_at) VALUES (1, now()) "
        "ON CONFLICT (id) DO UPDATE SET last_run_at = now()"
    )
    conn.commit()


def db_now(conn) -> datetime:
    """The database's own clock, for is_due()'s elapsed-time comparison --
    consistent with every other timestamp column in this schema rather
    than the app server's own wall clock."""
    return conn.execute("SELECT now()").fetchone()[0]


def _pg_dow(dt: datetime) -> int:
    """Postgres's own date_part('dow', ...) numbering: 0=Sunday..6=Saturday.
    Python's datetime.weekday() is 0=Monday..6=Sunday -- convert here once
    so days_of_week (populated straight from the frontend's day picker,
    stored using Postgres's own numbering per pg_orchestrator_settings_
    interval.sql) needs no separate translation layer anywhere else."""
    return (dt.weekday() + 1) % 7


def is_due(settings: dict, now: datetime) -> tuple[bool, str]:
    """Whether the orchestrator should actually do work right now, given
    the admin-configured interval/window/day-of-week settings. Assumes the
    caller has already checked settings['enabled'] separately -- this only
    covers the richer condition layered on top of that on/off switch.
    Returns (True, "") when due, or (False, <human-readable reason>) for
    the same RUN_SKIPPED-style log line the enabled-gate already uses.
    """
    days_of_week = settings.get("days_of_week")
    if days_of_week:
        today = _pg_dow(now)
        if today not in days_of_week:
            return False, f"not a configured day (today is {_DOW_NAMES[today]})"

    window_start = settings.get("window_start_minute")
    window_end = settings.get("window_end_minute")
    if window_start is not None and window_end is not None:
        minute_of_day = now.hour * 60 + now.minute
        if window_start <= window_end:
            in_window = window_start <= minute_of_day <= window_end
        else:
            # Spans midnight, e.g. a 22:00-02:00 window.
            in_window = minute_of_day >= window_start or minute_of_day <= window_end
        if not in_window:
            return False, (
                "outside configured window "
                f"({window_start // 60:02d}:{window_start % 60:02d}-"
                f"{window_end // 60:02d}:{window_end % 60:02d} UTC)"
            )

    last_run_at = settings.get("last_run_at")
    interval_minutes = settings.get("interval_minutes") or 30
    if last_run_at is not None:
        elapsed_minutes = (now - last_run_at).total_seconds() / 60
        if elapsed_minutes < interval_minutes:
            return False, f"{elapsed_minutes:.0f} of {interval_minutes} minutes since last run"

    return True, ""
