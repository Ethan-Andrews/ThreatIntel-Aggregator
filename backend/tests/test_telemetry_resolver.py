"""Pure-logic tests for telemetry_resolver.py -- no DB, no network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_pipeline"))

import telemetry_resolver


def test_sentinel_resolver_resolves_known_sysmon_process_creation():
    resolver = telemetry_resolver.SentinelTelemetryResolver()
    result = resolver.resolve("Process Creation", "sysmon", "1", "Windows")

    assert result is not None
    assert result.table == "DeviceProcessEvents"
    assert result.platform == "Windows"


def test_sentinel_resolver_resolves_case_insensitively():
    resolver = telemetry_resolver.SentinelTelemetryResolver()
    result = resolver.resolve("Process Creation", "Sysmon", "1", "windows")

    assert result is not None
    assert result.table == "DeviceProcessEvents"


def test_sentinel_resolver_declines_unknown_log_source():
    resolver = telemetry_resolver.SentinelTelemetryResolver()
    result = resolver.resolve("Command Execution", "auditd", "SYSCALL", "Linux")

    assert result is None


def test_sentinel_resolver_declines_non_windows_platform_even_if_channel_matches():
    resolver = telemetry_resolver.SentinelTelemetryResolver()
    result = resolver.resolve("Process Creation", "sysmon", "1", "Linux")

    assert result is None


def test_get_resolver_returns_sentinel_for_windows():
    resolver = telemetry_resolver.get_resolver("Windows")
    assert isinstance(resolver, telemetry_resolver.SentinelTelemetryResolver)


def test_get_resolver_returns_none_for_unregistered_platform():
    assert telemetry_resolver.get_resolver("Linux") is None
    assert telemetry_resolver.get_resolver("macOS") is None


def test_get_resolver_returns_none_for_missing_platform():
    assert telemetry_resolver.get_resolver(None) is None
    assert telemetry_resolver.get_resolver("") is None


def test_sentinel_resolver_declines_none_log_source_fields():
    resolver = telemetry_resolver.SentinelTelemetryResolver()

    assert resolver.resolve("X", None, "1", "Windows") is None
    assert resolver.resolve("X", "sysmon", None, "Windows") is None
