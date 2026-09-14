"""Read-only ARM client that pulls Microsoft Sentinel's actual Analytics
Rules (Microsoft.SecurityInsights/alertRules) into this app's database
(pg_sentinel_analytics_rules.sql).

A distinct Sentinel resource from Hunting's hunts/savedSearches --
confirmed against Microsoft's own REST API reference (learn.microsoft.com/
rest/api/securityinsights/alert-rules/list, fetched 2026-09-02): Analytics
Rules are what actually creates incidents/alerts on a schedule, addressed
directly under the workspace (no parent "hunt" container the way a hunting
query is linked into a Hunt). `kind` varies (Scheduled, Fusion,
MicrosoftSecurityIncidentCreation, MLBehaviorAnalytics, ThreatIntelligence,
NRT) -- only `Scheduled` carries a raw KQL `query` property this app's
static_gate/control_probe/backtest/tune pipeline can evaluate, so every
other kind is skipped at sync time rather than stored with an empty body.

Same ARM control-plane auth and env vars as sentinel_hunting.py/
sentinel_hunt_sync.py (AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP,
SENTINEL_WORKSPACE_NAME, gated by SENTINEL_HUNTING_SYNC_ENABLED) --
deliberately reused rather than adding a third flag/config surface for
what is still the same workspace and the same underlying question ("is
Sentinel ARM sync turned on").
"""

from __future__ import annotations

import json
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
ALERT_RULES_API_VERSION = "2023-12-01-preview"
LIST_PAGE_SIZE = 100

# Only these rule kinds carry a raw KQL `query` property in the ARM schema
# (confirmed against the REST API reference's own per-kind property
# tables) -- Fusion/MicrosoftSecurityIncidentCreation/MLBehaviorAnalytics/
# ThreatIntelligence/NRT rules have no equivalent field.
_TESTABLE_KINDS = {"Scheduled"}


def is_enabled() -> bool:
    return os.environ.get("SENTINEL_HUNTING_SYNC_ENABLED", "").strip().lower() in (
        "1", "true", "yes",
    )


class SentinelAnalyticsRulesSyncError(RuntimeError):
    """Any failure listing alert rules from Sentinel."""


class SentinelAnalyticsRulesReadClient:
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
            raise SentinelAnalyticsRulesSyncError(
                f"missing required config for Sentinel Analytics Rules sync: {', '.join(missing)}"
            )
        if credential is None:
            if DefaultAzureCredential is None:
                raise SentinelAnalyticsRulesSyncError(
                    "azure-identity is not installed: pip install azure-identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._client = httpx.Client(timeout=timeout)
        self._token = None
        self._token_expires = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelAnalyticsRulesReadClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        try:
            tok = self._credential.get_token(ARM_SCOPE)
        except Exception as exc:
            raise SentinelAnalyticsRulesSyncError(f"could not acquire an ARM token: {exc}") from exc
        self._token = tok.token
        self._token_expires = float(tok.expires_on)
        return self._token

    def _workspace_resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    def list_alert_rules(self) -> list[dict]:
        """Every alert rule in the workspace, following nextLink -- same
        trust-the-absolute-URL paging convention as sentinel_hunt_sync.py's
        _get_paginated(), not a hand-reconstructed $skipToken."""
        path = f"{self._workspace_resource_id()}/providers/Microsoft.SecurityInsights/alertRules"
        items: list[dict] = []
        resp = self._client.get(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": ALERT_RULES_API_VERSION, "$top": LIST_PAGE_SIZE},
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelAnalyticsRulesSyncError(
                f"GET {path} failed: {resp.status_code} {resp.text[:500]}"
            )
        payload = resp.json() if resp.content else {}
        items.extend(payload.get("value") or [])
        next_link = payload.get("nextLink")
        while next_link:
            resp = self._client.get(next_link, headers={"Authorization": f"Bearer {self._bearer()}"})
            if resp.status_code >= 400:
                raise SentinelAnalyticsRulesSyncError(
                    f"GET {next_link} failed: {resp.status_code} {resp.text[:500]}"
                )
            payload = resp.json() if resp.content else {}
            items.extend(payload.get("value") or [])
            next_link = payload.get("nextLink")
        return items

    def get_alert_rule(self, rule_id: str) -> dict:
        """GET one alert rule's full current live body (kind + etag +
        properties). Always called immediately before update_alert_rule_
        query() -- see that method's docstring for why a fresh GET, not
        locally-stored columns, is the only safe source for everything
        besides the one field being changed."""
        path = (
            f"{self._workspace_resource_id()}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        )
        resp = self._client.get(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": ALERT_RULES_API_VERSION},
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelAnalyticsRulesSyncError(
                f"GET {path} failed: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json() if resp.content else {}

    def update_alert_rule_query(self, rule_id: str, query: str) -> dict:
        """Read-modify-write, deliberately never a locally-reconstructed
        PUT: pg_sentinel_analytics_rules.sql doesn't store queryFrequency/
        queryPeriod/triggerOperator/triggerThreshold/suppressionDuration/
        suppressionEnabled/entityMappings, so building a full PUT body from
        this app's own database would silently revert any of those to
        whatever they were at last sync -- possibly stale by the time a
        tune suggestion gets applied. Instead: GET the rule's current live
        body right before writing, mutate only properties.query, PUT the
        exact same body back (kind/etag/properties only -- id/name/type/
        systemData are never sent back, matching ARM's own PUT examples).
        Same never-a-partial-PUT discipline as sentinel_hunting.py's
        upsert_saved_search(), just applied as read-then-write instead of
        write-from-scratch since alertRules carries fields this app has no
        other source of truth for."""
        current = self.get_alert_rule(rule_id)
        kind = current.get("kind")
        if kind not in _TESTABLE_KINDS:
            raise SentinelAnalyticsRulesSyncError(
                f"rule {rule_id} is kind={kind!r}, not a rule this app can tune"
            )
        properties = dict(current.get("properties") or {})
        properties["query"] = query
        body: dict = {"kind": kind, "properties": properties}
        if current.get("etag"):
            body["etag"] = current["etag"]
        path = (
            f"{self._workspace_resource_id()}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        )
        resp = self._client.put(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": ALERT_RULES_API_VERSION},
            json=body,
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelAnalyticsRulesSyncError(
                f"PUT {path} failed: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json() if resp.content else {}


def sync_all(conn) -> dict:
    """Pull every Scheduled analytics rule from Sentinel, upsert into
    sentinel_analytics_rules. Never raises -- disabled is a silent no-op;
    any other failure is logged and returned in the result, same non-fatal
    convention as sentinel_hunt_sync.sync_all()."""
    if not is_enabled():
        return {"enabled": False, "rules_synced": 0, "skipped_kinds": 0, "errors": []}

    errors: list[str] = []
    rules_synced = 0
    skipped_kinds = 0

    try:
        with SentinelAnalyticsRulesReadClient() as client:
            rules = client.list_alert_rules()
            for rule in rules:
                kind = rule.get("kind")
                if kind not in _TESTABLE_KINDS:
                    skipped_kinds += 1
                    continue
                rule_id = rule.get("name") or ""
                if not rule_id:
                    continue
                try:
                    _upsert_rule(conn, rule_id, rule.get("properties") or {})
                    rules_synced += 1
                except Exception as exc:
                    errors.append(f"rule {rule_id}: {exc}")
    except Exception as exc:
        logger.warning("SENTINEL_ANALYTICS_RULES_SYNC_FAILED: %s", exc)
        errors.append(str(exc))

    return {
        "enabled": True, "rules_synced": rules_synced,
        "skipped_kinds": skipped_kinds, "errors": errors,
    }


def _upsert_rule(conn, sentinel_rule_id: str, props: dict) -> None:
    conn.execute(
        "INSERT INTO sentinel_analytics_rules "
        "(sentinel_rule_id, display_name, description, kind, severity, kql_body, "
        " enabled, tactics, techniques, synced_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (sentinel_rule_id) DO UPDATE SET "
        "  display_name = EXCLUDED.display_name, description = EXCLUDED.description, "
        "  kind = EXCLUDED.kind, severity = EXCLUDED.severity, kql_body = EXCLUDED.kql_body, "
        "  enabled = EXCLUDED.enabled, tactics = EXCLUDED.tactics, "
        "  techniques = EXCLUDED.techniques, synced_at = now()",
        (
            sentinel_rule_id,
            props.get("displayName") or sentinel_rule_id,
            props.get("description"),
            "Scheduled",
            props.get("severity"),
            props.get("query") or "",
            bool(props.get("enabled", True)),
            json.dumps(props.get("tactics") or []),
            json.dumps(props.get("techniques") or []),
        ),
    )
    conn.commit()
