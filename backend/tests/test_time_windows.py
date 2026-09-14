"""Tests for time_windows.py -- the shared 1D/7D/30D/90D/All/Custom
resolver used by Dashboard, Audit trend, and RunZero Metrics."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time_windows


def test_all_returns_no_bounds():
    assert time_windows.window_to_range("all") == (None, None)


@pytest.mark.parametrize("window,days", [("1d", 1), ("7d", 7), ("30d", 30), ("90d", 90)])
def test_fixed_windows_resolve_to_since_before_until(window, days):
    since, until = time_windows.window_to_range(window)
    assert since is not None and until is not None
    assert since < until


def test_custom_passes_through_valid_timestamps():
    since, until = time_windows.window_to_range(
        "custom", from_="2026-01-01T00:00:00Z", to_="2026-02-01T00:00:00Z",
    )
    assert since == "2026-01-01T00:00:00Z"
    assert until == "2026-02-01T00:00:00Z"


def test_custom_bare_date_to_is_normalized_to_end_of_day():
    """A bare date-only `to` (the frontend's <input type="date"> sends
    "YYYY-MM-DD") must not lexically exclude its own day from an
    inclusive <= comparison."""
    since, until = time_windows.window_to_range("custom", from_="2026-01-01", to_="2026-02-01")
    assert since == "2026-01-01"
    assert until == "2026-02-01 23:59:59"
    assert "2026-02-01 12:00:00" <= until


def test_custom_without_both_bounds_raises():
    with pytest.raises(time_windows.InvalidWindowError):
        time_windows.window_to_range("custom", from_="2026-01-01T00:00:00Z", to_=None)
    with pytest.raises(time_windows.InvalidWindowError):
        time_windows.window_to_range("custom")


def test_custom_with_unparseable_timestamp_raises():
    with pytest.raises(time_windows.InvalidWindowError):
        time_windows.window_to_range("custom", from_="not a date", to_="2026-02-01T00:00:00Z")


def test_unrecognized_window_raises():
    with pytest.raises(time_windows.InvalidWindowError):
        time_windows.window_to_range("bogus")
