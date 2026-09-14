"""Read-only ARM client that pulls Microsoft Sentinel's own hunt/query
inventory into this app's database (pg_sentinel_hunt_inventory.sql).

sentinel_hunting.py only ever writes (PUT) our AI-generated detections up
into Sentinel's Hunts/savedSearches. Nothing in this codebase read them
back before this module -- a workspace's real hunts, however they got
there (a human analyst in the Sentinel UI, another tool, or this app's own
sync of a `hunts` row), were invisible to the app. This module closes that
gap: list every Hunt, list every hunt's query relations, and cross-
reference against the workspace's saved searches to get each query's
actual KQL body -- see docs/superpowers/specs/2026-09-01-sentinel-hunt-
inventory-design.md for the full design and the Microsoft Learn sources
each API shape below was confirmed against (fetched 2026-09-01).

Same ARM control-plane auth as sentinel_hunting.py (subscription id +
resource group + workspace *name*, not the data-plane customer-id GUID) --
deliberately reuses that module's env vars (AZURE_SUBSCRIPTION_ID,
AZURE_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME) rather than adding a new
config surface, since a read client and the existing write client always
target the same workspace.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone

import httpx

try:
    from azure.identity import DefaultAzureCredential
except ImportError:  # pragma: no cover
    DefaultAzureCredential = None

logger = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
HUNTS_API_VERSION = "2023-12-01-preview"
SAVED_SEARCHES_API_VERSION = "2020-08-01"

# ARM list responses cap out well under this per page in practice, but pass
# an explicit $top anyway so a single sync doesn't rely on the service's
# undocumented default page size -- a workspace with 800+ queries in one
# hunt is exactly the case that needs paging to actually happen.
LIST_PAGE_SIZE = 100


def is_enabled() -> bool:
    return os.environ.get("SENTINEL_HUNTING_SYNC_ENABLED", "").strip().lower() in (
        "1", "true", "yes",
    )


class SentinelHuntSyncError(RuntimeError):
    """Any failure listing hunts/relations/saved searches from Sentinel."""


class SentinelHuntReadClient:
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
            raise SentinelHuntSyncError(
                f"missing required config for Sentinel Hunt inventory sync: {', '.join(missing)}"
            )
        if credential is None:
            if DefaultAzureCredential is None:
                raise SentinelHuntSyncError(
                    "azure-identity is not installed: pip install azure-identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._client = httpx.Client(timeout=timeout)
        self._token = None
        self._token_expires = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelHuntReadClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        try:
            tok = self._credential.get_token(ARM_SCOPE)
        except Exception as exc:  # credential types vary too much to narrow
            raise SentinelHuntSyncError(f"could not acquire an ARM token: {exc}") from exc
        self._token = tok.token
        self._token_expires = float(tok.expires_on)
        return self._token

    def _workspace_resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    def _get(self, path: str, api_version: str, params: dict | None = None) -> dict:
        resp = self._client.get(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": api_version, **(params or {})},
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelHuntSyncError(
                f"GET {path} failed: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json() if resp.content else {}

    def _get_paginated(self, path: str, api_version: str, params: dict | None = None) -> list[dict]:
        """Walk every page of an ARM list response via its own absolute
        nextLink, not by re-deriving the skipToken ourselves -- nextLink is
        already a complete, correctly-authenticated-once-we-add-the-header
        URL per the ARM paging convention, so trust it rather than
        reconstructing query params by hand."""
        items: list[dict] = []
        payload = self._get(path, api_version, params)
        items.extend(payload.get("value") or [])
        next_link = payload.get("nextLink")
        while next_link:
            resp = self._client.get(
                next_link, headers={"Authorization": f"Bearer {self._bearer()}"},
            )
            if resp.status_code >= 400:
                raise SentinelHuntSyncError(
                    f"GET {next_link} failed: {resp.status_code} {resp.text[:500]}"
                )
            payload = resp.json() if resp.content else {}
            items.extend(payload.get("value") or [])
            next_link = payload.get("nextLink")
        return items

    def list_hunts(self) -> list[dict]:
        path = f"{self._workspace_resource_id()}/providers/Microsoft.SecurityInsights/hunts"
        return self._get_paginated(path, HUNTS_API_VERSION, {"$top": LIST_PAGE_SIZE})

    def list_hunt_relations(self, hunt_id: str) -> list[dict]:
        path = (
            f"{self._workspace_resource_id()}/providers/Microsoft.SecurityInsights"
            f"/hunts/{hunt_id}/relations"
        )
        return self._get_paginated(path, HUNTS_API_VERSION, {"$top": LIST_PAGE_SIZE})

    def list_saved_searches(self) -> list[dict]:
        """Every saved search in the workspace, one call -- this ARM
        operation (SavedSearchesOperations.list_by_workspace) does not
        support server-side paging, so there is nothing to walk here.
        Fetched once per sync and matched locally against each hunt's
        relations by ARM resource id, rather than GETting each query
        individually -- one call instead of up to 800+ per hunt."""
        path = f"{self._workspace_resource_id()}/savedSearches"
        payload = self._get(path, SAVED_SEARCHES_API_VERSION)
        return payload.get("value") or []


def _saved_search_lookup(saved_searches: list[dict]) -> dict[str, dict]:
    """ARM resource id (lowercased -- ARM ids are case-insensitive but not
    always case-consistent between the hunts/relations response and the
    savedSearches response) -> saved search object."""
    return {s["id"].lower(): s for s in saved_searches if s.get("id")}


def sync_all(conn) -> dict:
    """Pull every hunt and every hunt's queries from Sentinel, upsert into
    sentinel_hunts/sentinel_hunt_queries, then sweep away any DB row no
    longer present in Sentinel's own live set. Never raises -- disabled
    (the common case today, same gate as sentinel_hunting.py) is a silent
    no-op; any other failure is logged and returned in the result rather
    than propagated, same non-fatal-sweep discipline as every other
    Sentinel-backed stage in this pipeline.

    One hunt's relations/matching failing does not abort the rest of the
    sync -- a single bad hunt shouldn't hide every other hunt's queries.

    The sweep (added for the "detect removed hunts/queries" ask -- see
    docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md,
    Workstream H) is deliberately conservative about when it's allowed to
    delete anything, since a naive "delete whatever we didn't see this
    run" is a real footgun here: a transient fetch failure must never be
    mistaken for "Sentinel says this is gone now."
      - The HUNT-level sweep only runs if the entire top-to-bottom pass
        (both top-level list_hunts()/list_saved_searches() calls, and
        every hunt's own upsert) completed with no uncaught exception --
        tracked via `sync_completed`, set True only at the very end of the
        try block. A hunt whose *relations* fetch failed is still caught
        inline (as before) and does not prevent this flag from being set;
        that hunt itself is still counted as "seen" (it exists in
        Sentinel, we just couldn't read its query list this cycle) so its
        own sentinel_hunts row is never swept just because of a relations
        failure.
      - The QUERY-level sweep for one hunt only runs if that specific
        hunt's own relations fetch succeeded this run. A hunt whose
        relations fetch failed is recorded in `sweep_skipped_hunts` and
        its existing queries are left untouched -- otherwise a transient
        ARM error on one hunt would read as "every one of its queries was
        deleted from Sentinel," and delete them all locally too.
      - An empty-but-successful fetch (a workspace that genuinely has zero
        hunts, or one hunt with genuinely zero queries) still sweeps
        correctly -- the guards above are about distinguishing "fetch
        failed" from "fetch succeeded and returned nothing," not about
        refusing to ever delete anything.
    """
    if not is_enabled():
        return {
            "enabled": False, "hunts_synced": 0, "queries_synced": 0, "errors": [],
            "hunts_removed": 0, "queries_removed": 0, "sweep_skipped_hunts": [],
        }

    errors: list[str] = []
    hunts_synced = 0
    queries_synced = 0
    hunts_removed = 0
    queries_removed = 0
    sweep_skipped_hunts: list[str] = []
    seen_hunt_ids: list[str] = []
    sync_completed = False

    try:
        with SentinelHuntReadClient() as client:
            hunts = client.list_hunts()
            saved_searches = client.list_saved_searches()
            lookup = _saved_search_lookup(saved_searches)

            for hunt in hunts:
                hunt_arm_id = hunt.get("name") or ""
                if not hunt_arm_id:
                    continue
                seen_hunt_ids.append(hunt_arm_id)
                props = hunt.get("properties") or {}
                relations_fetch_ok = True
                try:
                    relations = client.list_hunt_relations(hunt_arm_id)
                except Exception as exc:
                    errors.append(f"hunt {hunt_arm_id}: relations fetch failed: {exc}")
                    relations = []
                    relations_fetch_ok = False

                queries = []
                for rel in relations:
                    rel_props = rel.get("properties") or {}
                    # Confirmed live 2026-09-01 against a real workspace: the
                    # GET response for hunts/relations does NOT echo back
                    # relatedResourceKind (the field the write path's PUT body
                    # sends, per sentinel_hunting.upsert_saved_search's own
                    # relatedResourceKind param) -- it carries
                    # relatedResourceType instead, valued
                    # "Microsoft.OperationalInsights/SavedSearches". Checking
                    # only relatedResourceKind meant this condition was never
                    # true for any real relation, so every hunt's query list
                    # silently read back empty regardless of how many queries
                    # were actually linked in Sentinel. Check both: whichever
                    # field a given relation actually carries.
                    kind = rel_props.get("relatedResourceKind")
                    rtype = rel_props.get("relatedResourceType")
                    if kind != "SavedSearch" and rtype != "Microsoft.OperationalInsights/SavedSearches":
                        continue
                    related_id = (rel_props.get("relatedResourceId") or "").lower()
                    saved_search = lookup.get(related_id)
                    if saved_search is None:
                        continue
                    queries.append(saved_search)

                _upsert_hunt(conn, hunt_arm_id, props, query_count=len(queries))
                hunts_synced += 1
                seen_query_ids: list[str] = []
                for saved_search in queries:
                    _upsert_query(conn, hunt_arm_id, saved_search)
                    queries_synced += 1
                    q_id = saved_search.get("name") or saved_search.get("id") or ""
                    if q_id:
                        seen_query_ids.append(q_id)

                if relations_fetch_ok:
                    queries_removed += _sweep_hunt_queries(conn, hunt_arm_id, seen_query_ids)
                else:
                    sweep_skipped_hunts.append(hunt_arm_id)

            sync_completed = True
    except Exception as exc:
        logger.warning("SENTINEL_HUNT_INVENTORY_SYNC_FAILED: %s", exc)
        errors.append(str(exc))

    if sync_completed:
        hunts_removed = _sweep_hunts(conn, seen_hunt_ids)

    return {
        "enabled": True, "hunts_synced": hunts_synced,
        "queries_synced": queries_synced, "errors": errors,
        "hunts_removed": hunts_removed, "queries_removed": queries_removed,
        "sweep_skipped_hunts": sweep_skipped_hunts,
    }


def _sweep_hunts(conn, seen_hunt_ids: list[str]) -> int:
    """Delete any sentinel_hunts row not present in this run's live set.
    Only called by sync_all() when the entire top-to-bottom pass completed
    without an uncaught exception (see its own `sync_completed` guard) --
    never against a partial/unknown "seen" set. `!= ALL(?)` against an
    empty list is vacuously true for every row, which is correct for a
    genuinely empty (but successfully fetched) workspace. CASCADE removes
    that hunt's own queries too (pg_sentinel_hunt_inventory.sql's ON
    DELETE CASCADE) -- no separate query cleanup needed here."""
    rows = conn.execute(
        "DELETE FROM sentinel_hunts WHERE sentinel_hunt_id != ALL(?) RETURNING id",
        (seen_hunt_ids,),
    ).fetchall()
    conn.commit()
    return len(rows)


def _sweep_hunt_queries(conn, sentinel_hunt_id: str, seen_query_ids: list[str]) -> int:
    """Delete any sentinel_hunt_queries row under this hunt not present in
    this run's live relations set. Only called by sync_all() for a hunt
    whose own relations fetch succeeded this run -- a hunt with a failed
    relations fetch must never reach here, since its `seen_query_ids`
    would be an artifact of the failure, not Sentinel's real state."""
    hunt_row = conn.execute(
        "SELECT id FROM sentinel_hunts WHERE sentinel_hunt_id = ?", (sentinel_hunt_id,)
    ).fetchone()
    if hunt_row is None:
        return 0
    rows = conn.execute(
        "DELETE FROM sentinel_hunt_queries WHERE hunt_id = ? "
        "AND sentinel_saved_search_id != ALL(?) RETURNING id",
        (hunt_row["id"], seen_query_ids),
    ).fetchall()
    conn.commit()
    return len(rows)


_HTML_TAG = re.compile(r"<[^>]+>")
_WHITESPACE_RUN = re.compile(r"\s+")


def _strip_html(text: str | None) -> str | None:
    """Strip HTML tags from a Sentinel-sourced description.

    Sentinel's own portal stores Hunt/query `description` as rich-text HTML
    (e.g. `<p><span>...</span></p>`), not plain text -- confirmed live via a
    screenshot showing the raw tags rendered as literal on-screen text,
    since React auto-escapes and this app never parses HTML for display
    (see ai-security.md's HTML-escape convention, already applied to
    ai_summary elsewhere). Stripped at sync time, once, here -- not per
    frontend render site -- since the storage layer shouldn't need every
    consumer to make the same trust decision independently. This is
    decorative markup from Sentinel's rich-text editor, not meaningful
    structure worth preserving, so a plain tag-strip is sufficient.
    """
    if not text:
        return text
    stripped = _HTML_TAG.sub(" ", text)
    return _WHITESPACE_RUN.sub(" ", stripped).strip()


def _upsert_hunt(conn, sentinel_hunt_id: str, props: dict, query_count: int) -> int:
    import json
    row = conn.execute(
        "INSERT INTO sentinel_hunts "
        "(sentinel_hunt_id, display_name, description, status, hypothesis_status, "
        " attack_tactics, attack_techniques, query_count, synced_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (sentinel_hunt_id) DO UPDATE SET "
        "  display_name = EXCLUDED.display_name, description = EXCLUDED.description, "
        "  status = EXCLUDED.status, hypothesis_status = EXCLUDED.hypothesis_status, "
        "  attack_tactics = EXCLUDED.attack_tactics, attack_techniques = EXCLUDED.attack_techniques, "
        "  query_count = EXCLUDED.query_count, synced_at = now() "
        "RETURNING id",
        (
            sentinel_hunt_id,
            props.get("displayName") or sentinel_hunt_id,
            _strip_html(props.get("description")),
            props.get("status"),
            props.get("hypothesisStatus"),
            json.dumps(props.get("attackTactics") or []),
            json.dumps(props.get("attackTechniques") or []),
            query_count,
        ),
    ).fetchone()
    conn.commit()
    return row["id"]


def _upsert_query(conn, sentinel_hunt_id: str, saved_search: dict) -> None:
    import json
    hunt_row = conn.execute(
        "SELECT id FROM sentinel_hunts WHERE sentinel_hunt_id = ?", (sentinel_hunt_id,)
    ).fetchone()
    if hunt_row is None:
        return
    saved_search_id = saved_search.get("name") or saved_search.get("id") or ""
    if not saved_search_id:
        return
    props = saved_search.get("properties") or {}
    conn.execute(
        "INSERT INTO sentinel_hunt_queries "
        "(hunt_id, sentinel_saved_search_id, display_name, kql_body, description, tags, synced_at) "
        "VALUES (?, ?, ?, ?, ?, ?, now()) "
        "ON CONFLICT (sentinel_saved_search_id) DO UPDATE SET "
        "  hunt_id = EXCLUDED.hunt_id, display_name = EXCLUDED.display_name, "
        "  kql_body = EXCLUDED.kql_body, description = EXCLUDED.description, "
        "  tags = EXCLUDED.tags, synced_at = now()",
        (
            hunt_row["id"],
            saved_search_id,
            props.get("displayName") or saved_search_id,
            props.get("query") or "",
            _strip_html(next(
                (t["Value"] for t in (props.get("tags") or []) if t.get("Name") == "description"),
                None,
            )),
            json.dumps(props.get("tags") or []),
        ),
    )
    conn.commit()
