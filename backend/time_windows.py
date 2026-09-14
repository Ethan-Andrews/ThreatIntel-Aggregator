"""Shared time-window resolution for the 1D/7D/30D/90D/All/Custom toggle
used by the Dashboard (Workstream D), Audit Log trend (Workstream B), and
RunZero Metrics (Workstream F) -- see docs/superpowers/specs/2026-09-04-
live-feedback-round-6-design.md's "Cross-cutting notes" for why this is one
shared helper rather than three slightly different parsers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_WINDOW_DAYS = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}


class InvalidWindowError(ValueError):
    """Raised on an unrecognized window value or an unparseable custom
    from/to timestamp -- callers (main.py) turn this into a 400, never a
    500, since it's always caller-supplied input."""


def window_to_range(
    window: str, from_: str | None = None, to_: str | None = None,
) -> tuple[str | None, str | None]:
    """Resolve a window selector into a (since, until) pair of ISO-8601
    UTC strings, or (None, None) for 'all' -- the caller's existing
    all-time query path with no added WHERE clause. 'custom' passes
    from_/to_ through after validating they parse as timestamps.

    Deliberately returns strings, not datetime objects: every timestamp
    column this feeds (entries.ingested, and every checked_at column in
    audit_log.py's _BASE_QUERY) is compared via plain bind params, and
    psycopg already adapts a datetime cleanly, but a string return type
    keeps this helper's contract identical regardless of which caller's
    column happens to be TEXT (entries.ingested) vs timestamptz (audit_
    log.py's checked_at columns) -- the SQL comparison works either way
    since entries.ingested's own format ('YYYY-MM-DD HH24:MI:SS' UTC) is
    lexically comparable to an ISO string's leading portion.
    """
    if window == "all":
        return None, None
    if window in _WINDOW_DAYS:
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=_WINDOW_DAYS[window])
        return since.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")
    if window == "custom":
        if not from_ or not to_:
            raise InvalidWindowError("custom window requires both from and to")
        for value in (from_, to_):
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise InvalidWindowError(f"could not parse timestamp: {value!r}") from exc
        # A bare date (the frontend's <input type="date"> sends "YYYY-MM-DD",
        # no time component) used as `to_` unmodified would lexically compare
        # as LESS than every real timestamp on that same day (e.g.
        # "2026-02-01" < "2026-02-01 00:00:01"), silently excluding the
        # entire end day from an inclusive "<= until" comparison -- a real,
        # silent-wrong-data bug, not a hypothetical. Normalize a bare date's
        # end-of-day explicitly; a `from_` bare date already sorts correctly
        # as a day's start with no adjustment needed.
        if len(to_) == 10:  # "YYYY-MM-DD", nothing else is this length
            to_ = f"{to_} 23:59:59"
        return from_, to_
    raise InvalidWindowError(
        f"window must be one of {sorted(_WINDOW_DAYS)} | 'all' | 'custom', got {window!r}"
    )
