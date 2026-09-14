"""Translates a MITRE data component's log source (name + channel) into a
candidate table in *our* telemetry, for whichever backend(s) we have a
resolver for. This is the one place Sentinel/Defender-XDR-specific
knowledge lives -- alignment_check.py only ever calls get_resolver() and
.resolve(), so a Linux/auditd or macOS resolver can be added later without
touching it. That's deliberate: MITRE's own analytic catalog is genuinely
cross-platform (Windows, Linux, macOS, ESXi, network devices -- see e.g.
DET0384's four platform-specific analytics), and this seam is what makes
"detections in multiple languages for different device types" realistic
without a rewrite. Ships with exactly one concrete resolver today: this
pipeline is a Microsoft Sentinel/Defender XDR shop.

Decline safely, never guess: an unrecognized (log_source_name, channel)
pair, or an unregistered platform, returns None -- same discipline as this
pipeline's other "unknown table gets no metric, not a guessed one" checks
(see coverage_ledger.py's table-family entity resolution).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ResolvedTelemetry:
    table: str
    filter_hint: str | None
    platform: str


class TelemetryResolver(Protocol):
    def resolve(self, data_component: str, log_source_name: str,
                log_source_channel: str, platform: str) -> ResolvedTelemetry | None:
        ...


class SentinelTelemetryResolver:
    """Windows/Defender XDR only. Matches this pipeline's own documented
    'Telemetry Conventions' table list (see the AI Assistant Settings
    section of DetectionsAI-Dev-Context/ti-detection-pipeline-summarized.md).
    Deliberately starts narrow -- see the design doc's open question on
    growing this table from real diverges verdicts rather than
    pre-populating every known Sysmon/Security event ID up front."""

    PLATFORM = "Windows"

    # (log_source_name, channel), both lowercased -> (table, filter_hint)
    _KNOWN: dict[tuple[str, str], tuple[str, str | None]] = {
        ("sysmon", "1"):  ("DeviceProcessEvents", None),
        ("sysmon", "3"):  ("DeviceNetworkEvents", None),
        ("sysmon", "7"):  ("DeviceImageLoadEvents", None),
        ("sysmon", "11"): ("DeviceFileEvents", None),
        ("sysmon", "13"): ("DeviceRegistryEvents", None),
        ("security", "4624"): ("DeviceLogonEvents", "LogonType"),
        ("security", "4661"): ("DeviceRegistryEvents", None),
        ("security", "4688"): ("DeviceProcessEvents", None),
        ("azure ad", "signinlogs"): ("SigninLogs", None),
        ("azure ad", "auditlogs"):  ("AuditLogs", None),
    }

    def resolve(self, data_component: str, log_source_name: str,
                log_source_channel: str, platform: str) -> ResolvedTelemetry | None:
        if not platform or platform.strip().lower() != "windows":
            return None
        key = ((log_source_name or "").strip().lower(), (log_source_channel or "").strip().lower())
        match = self._KNOWN.get(key)
        if match is None:
            return None
        table, filter_hint = match
        return ResolvedTelemetry(table=table, filter_hint=filter_hint, platform=self.PLATFORM)


_RESOLVERS: dict[str, TelemetryResolver] = {
    "windows": SentinelTelemetryResolver(),
}


def get_resolver(platform: str | None) -> TelemetryResolver | None:
    """None for an unrecognized, unregistered, or missing platform --
    decline safely rather than guess which resolver might apply."""
    if not platform:
        return None
    return _RESOLVERS.get(platform.strip().lower())
