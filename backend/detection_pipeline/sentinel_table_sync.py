"""Cache the real table catalog available in the connected Sentinel/Log
Analytics workspace, so static_gate.py's table-recognition check can stop
relying solely on the hand-maintained DEFAULT_MDE_TABLES allowlist -- the
same architectural pattern mitre_sync.py already established for MITRE's
own Detection Strategy catalog (sync_all() full fetch, a cache table,
get_cached_tables() read-only lookup, DEFAULT_MDE_TABLES as the fallback
for an empty/never-synced cache rather than the only source of truth).

Confirmed against Microsoft's own ARM template reference
(learn.microsoft.com/azure/templates/microsoft.operationalinsights/
workspaces/tables) during design: `Microsoft.OperationalInsights/
workspaces/tables` is a real resource collection with a standard ARM List
operation (GET on the collection, distinct from GET on one named table),
and each item's plain `name` field is the table name -- exactly the
allowlist-membership value static_gate.py's extract_tables() already
compares against. MDE/Defender tables (Device*, Email*, Identity*, ...)
are already included: that data lands in the same Log Analytics workspace
as Sentinel-native tables (see telemetry_resolver.py's
SentinelTelemetryResolver), so this one call covers both -- no separate
mechanism needed for MDE specifically.

Same ARM control-plane auth as sentinel_hunt_sync.py/sentinel_hunting.py
(subscription id + resource group + workspace *name*, not the data-plane
customer-id GUID) -- deliberately reuses those modules' env vars
(AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME) and
SENTINEL_HUNTING_SYNC_ENABLED gate rather than adding a new config
surface, since every ARM-calling client in this app always targets the
same workspace.
"""

from __future__ import annotations

import logging
import os
import time

import httpx

try:
    from azure.identity import DefaultAzureCredential
except ImportError:  # pragma: no cover
    DefaultAzureCredential = None

logger = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
TABLES_API_VERSION = "2023-09-01"
LIST_PAGE_SIZE = 100


def is_enabled() -> bool:
    return os.environ.get("SENTINEL_HUNTING_SYNC_ENABLED", "").strip().lower() in (
        "1", "true", "yes",
    )


class SentinelTableSyncError(RuntimeError):
    """Any failure listing the workspace's table catalog from ARM."""


class SentinelTableReadClient:
    def __init__(self, subscription_id: str | None = None,
                 resource_group: str | None = None,
                 workspace_name: str | None = None,
                 credential=None, timeout: float = 30.0) -> None:
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        self.resource_group = resource_group or os.environ.get("AZURE_RESOURCE_GROUP", "")
        self.workspace_name = workspace_name or os.environ.get("SENTINEL_WORKSPACE_NAME", "")
        missing = [
            name for name, value in (
                ("AZURE_SUBSCRIPTION_ID", self.subscription_id),
                ("AZURE_RESOURCE_GROUP", self.resource_group),
                ("SENTINEL_WORKSPACE_NAME", self.workspace_name),
            ) if not value
        ]
        if missing:
            raise SentinelTableSyncError(
                f"missing required config for Sentinel table catalog sync: {', '.join(missing)}"
            )
        if credential is None:
            if DefaultAzureCredential is None:
                raise SentinelTableSyncError(
                    "azure-identity is not installed: pip install azure-identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._client = httpx.Client(timeout=timeout)
        self._token = None
        self._token_expires = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelTableReadClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        try:
            tok = self._credential.get_token(ARM_SCOPE)
        except Exception as exc:  # credential types vary too much to narrow
            raise SentinelTableSyncError(f"could not acquire an ARM token: {exc}") from exc
        self._token = tok.token
        self._token_expires = float(tok.expires_on)
        return self._token

    def _workspace_resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    def list_tables(self) -> list[dict]:
        """Every table in the workspace -- same absolute-nextLink paging
        convention as sentinel_hunt_sync.py's _get_paginated(), though a
        real workspace's table count is unlikely to ever need a second
        page in practice."""
        path = f"{self._workspace_resource_id()}/tables"
        items: list[dict] = []
        resp = self._client.get(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": TABLES_API_VERSION, "$top": LIST_PAGE_SIZE},
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelTableSyncError(f"GET {path} failed: {resp.status_code} {resp.text[:500]}")
        payload = resp.json() if resp.content else {}
        items.extend(payload.get("value") or [])
        next_link = payload.get("nextLink")
        while next_link:
            resp = self._client.get(next_link, headers={"Authorization": f"Bearer {self._bearer()}"})
            if resp.status_code >= 400:
                raise SentinelTableSyncError(f"GET {next_link} failed: {resp.status_code} {resp.text[:500]}")
            payload = resp.json() if resp.content else {}
            items.extend(payload.get("value") or [])
            next_link = payload.get("nextLink")
        return items


def get_cached_tables(conn) -> set[str]:
    """Read-only lookup for static_gate.py -- the current cached table
    names, or an empty set if never synced (callers fall back to
    DEFAULT_MDE_TABLES in that case, same pattern as mitre_sync.py's
    get_cached_strategy())."""
    rows = conn.execute("SELECT name FROM sentinel_workspace_tables").fetchall()
    return {r["name"] for r in rows}


def _has_synced_before(conn) -> bool:
    return conn.execute("SELECT 1 FROM sentinel_workspace_tables LIMIT 1").fetchone() is not None


def get_tables_for_gate(conn) -> set[str]:
    """What the gate's callers (orchestrator.py, sentinel_hunt_test.py)
    actually want: the cached table catalog, auto-syncing exactly once if
    the cache has never been populated at all -- the same "sync once, then
    read cached even if stale" shape as mitre_sync.py's
    get_mitre_strategy(). Safe to call on every batch even when Sentinel
    isn't configured at all: a disabled sync (SENTINEL_HUNTING_SYNC_ENABLED
    unset) makes sync_all() short-circuit to a cheap no-op with no network
    call, so this never adds real latency/risk to the hot path in that
    (common, today's default) case."""
    if not _has_synced_before(conn):
        sync_all(conn)
    return get_cached_tables(conn)


def sync_all(conn) -> dict:
    """Pull the real table catalog from the connected workspace and upsert
    it into sentinel_workspace_tables. Never raises -- disabled (the
    common case today, same gate as sentinel_hunt_sync.py) is a silent
    no-op; any other failure is logged and returned in the result rather
    than propagated, same non-fatal-sweep discipline as every other
    Sentinel-backed stage in this pipeline."""
    if not is_enabled():
        return {"enabled": False, "tables_synced": 0, "error": None}

    try:
        with SentinelTableReadClient() as client:
            tables = client.list_tables()
    except Exception as exc:
        logger.warning("SENTINEL_TABLE_SYNC_FAILED: %s", exc)
        return {"enabled": True, "tables_synced": 0, "error": str(exc)}

    synced = 0
    for table in tables:
        name = table.get("name")
        if not name:
            continue
        conn.execute(
            "INSERT INTO sentinel_workspace_tables (name, synced_at) VALUES (?, now()) "
            "ON CONFLICT (name) DO UPDATE SET synced_at = now()",
            (name,),
        )
        synced += 1
    conn.commit()
    return {"enabled": True, "tables_synced": synced, "error": None}
