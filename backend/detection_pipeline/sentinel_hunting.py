"""ARM (control-plane) client for syncing generated hunts/detections into
Microsoft Sentinel's real Hunts feature and its underlying hunting-query
saved searches. Built and unit-tested (mocked HTTP) ahead of the real RBAC
grant being available -- see is_enabled()/SENTINEL_HUNTING_SYNC_ENABLED and
this module's "Deploying" note below for exactly what to grant once ready.

Two Sentinel resources are involved, confirmed against Microsoft's own
documentation (learn.microsoft.com, fetched 2026-08-31):

  - Microsoft.OperationalInsights/workspaces/savedSearches (GA since
    2015-03-20, current stable api-version 2020-08-01): a single hunting
    query. Microsoft's own doc example uses `properties.category =
    "Hunting Queries"` for the general Hunting > Queries library tab, but a
    query meant to live inside a specific Hunt needs `category = "Hunt
    Queries"` (note: singular "Hunt", not "Hunting") plus `version = 2` --
    confirmed live 2026-09-01 from the Sentinel portal's own network
    traffic while manually linking a query to a hunt. Getting this wrong
    doesn't error or even fail visibly: the saved search still gets created
    and its hunts/relations link still gets made (so relation counts and
    read-only rollups look correct everywhere), it just never appears in
    the Hunt's own Queries sub-tab in the Sentinel portal.
  - Microsoft.SecurityInsights/hunts (public preview, api-version
    2023-12-01-preview): the actual "Hunt" container object -- a
    name/description/status/hypothesisStatus grouping, with its own
    Queries/Bookmarks/Entities tabs in the Sentinel UI
    (learn.microsoft.com/azure/sentinel/hunts). A saved search is linked
    into a hunt via a Microsoft.SecurityInsights/hunts/relations
    sub-resource, whose `relatedResourceId` is the saved search's full ARM
    resource id.

This mirrors our own architecture closely: one `hunts` row (pg_hunts.sql)
per originating TI article maps to one Microsoft.SecurityInsights/hunts
object, and each child `analytics` row maps to one savedSearches object
linked into that hunt -- so syncing is a 1:1 walk of data we already have,
not a redesign.

Deliberately a separate client from sentinel.py's SentinelClient: that one
talks to the Log Analytics *data* plane (query execution, workspace
addressed by its customer id/GUID) for backtesting. This one talks to the
ARM *control* plane (resource CRUD, workspace addressed by subscription id
+ resource group + workspace *name*) to create/update Sentinel-side
resources -- a materially different permission surface (a workspace Reader
can query data but can't write ARM resources), so it's kept as its own
client rather than widening SentinelClient's scope.

Deploying (once RBAC is granted -- see root CLAUDE.md's Azure resource
reference for existing resource names):
  1. Grant the app's/job's managed identity (id-tiagg-api / id-job-tiagg-
     orchestrator) either the built-in "Microsoft Sentinel Contributor"
     role, or a custom role scoped to
     Microsoft.SecurityInsights/hunts/write,
     Microsoft.SecurityInsights/hunts/relations/write, and
     Microsoft.OperationalInsights/workspaces/savedSearches/write on the
     Sentinel workspace resource.
  2. Set AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME
     (the workspace's ARM *resource name*, NOT the customer-id GUID
     SENTINEL_WORKSPACE_ID uses for the data plane -- see sentinel.py).
  3. Set SENTINEL_HUNTING_SYNC_ENABLED=true.
  4. Trigger one orchestrator run and confirm a hunt actually appears in
     Sentinel's Hunting > Hunts (Preview) tab -- a non-fatal sync failure
     only shows up in hunts.sentinel_sync_error and the job's own logs
     (WARNING SENTINEL_HUNTING_SYNC_FAILED), never as a job failure, so
     check those explicitly rather than trusting "Succeeded" (same caution
     CLAUDE.md already gives for every other Sentinel-backed stage).
"""

from __future__ import annotations

import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone

import httpx

try:
    from azure.identity import DefaultAzureCredential
except ImportError:  # pragma: no cover
    DefaultAzureCredential = None

from detection_pipeline import mitre_tactics

logger = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
HUNTS_API_VERSION = "2023-12-01-preview"
SAVED_SEARCHES_API_VERSION = "2020-08-01"

# ARM segment names have to be stable, URL-safe identifiers. detections.ai's
# artifact_id format isn't ours to rely on, so every ARM-facing id is
# deterministically derived from a value we already control, rather than
# passed through directly.
_UUID_NAMESPACE = uuid.UUID("6f2a9f2e-6c62-4f0b-9a1a-1f7f9f6a6b7a")


def arm_safe_id(*parts: str) -> str:
    """A stable, ARM-safe (GUID) id derived from arbitrary input strings."""
    return str(uuid.uuid5(_UUID_NAMESPACE, "|".join(parts)))


# Each group is one entity *instance* of entity_type, described by one or
# more (column_name, identifier) pairs that share the same {N} index --
# e.g. a file's Name and Directory both describe entity index 0 of type
# File, not two separate File entities. Two groups of the same entity_type
# (the two Process groups below) get separate, incrementing indices.
# Sentinel's Hunting UI infers a hunting query's entity mappings purely
# from this column-naming convention in the query's own output
# ({EntityType}_{N}_{Identifier}), NOT from any separate API field or tag.
# Confirmed live 2026-08-31 by inspecting a real hunting query's actual KQL
# body, which ends in exactly this pattern:
#   | extend Account_0_Name = AccountName
#   | extend Host_0_HostName = DeviceName
#   | extend File_0_Name = InitiatingProcessFileName
#   | extend File_0_Directory = InitiatingProcessFolderPath
#   | extend Process_0_CommandLine = ProcessCommandLine
#   | extend Process_1_CommandLine = InitiatingProcessCommandLine
_ENTITY_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Account", [("AccountName", "Name")]),
    ("Host", [("DeviceName", "HostName")]),
    ("File", [("InitiatingProcessFileName", "Name"), ("InitiatingProcessFolderPath", "Directory")]),
    # A second, independent File group for the file the event is actually
    # ABOUT (e.g. DeviceFileEvents' own FileName/FolderPath), as opposed to
    # the initiating process's own file above -- same "two groups of one
    # entity_type get separate indices" pattern as the two Process groups
    # below. Added 2026-09-02 after a live saved search whose query's
    # subject was a file (not a process) errored out in the Hunting UI:
    # neither raw column matched the InitiatingProcess-prefixed pair above,
    # so the file never got entity-mapped at all.
    ("File", [("FileName", "Name"), ("FolderPath", "Directory")]),
    ("Process", [("ProcessCommandLine", "CommandLine")]),
    ("Process", [("InitiatingProcessCommandLine", "CommandLine")]),
]

# A `summarize`/plain `project` pipe stage can drop or rename a column out
# of the query's final output schema -- `project-rename`/`project-away`/
# `project-keep` are deliberately excluded (they don't erase a column's
# ability to still be reasoned about the same simple way a plain `project`
# does, and modeling their exact keep/drop semantics generically isn't
# worth it here). Matches the literal `project` keyword, not any hyphenated
# variant.
_SCHEMA_NARROWING = re.compile(r"\|\s*(?:summarize|project)(?!-)\b", re.I)


def append_entity_mapping_extends(kql_body: str) -> str:
    """Best-effort: append entity-mapping extend lines for any of this
    pipeline's common output columns that actually appear in the query, so
    the Hunting UI can auto-detect entities the same way a human-authored
    query does.

    Deliberately conservative: only appends an extend for a column name
    found as a whole word somewhere in the existing query text. Appending
    an extend against a column that isn't actually in the result set breaks
    the query outright at run time (a "column not found" KQL error) --
    worse than the entity mapping simply being absent -- so an empty/blank
    body, or one where no known column name matches, is returned unchanged
    rather than guessed at.

    A column can appear in the query text (e.g. a `where` filter) yet not
    survive to the final output if a later `summarize`/`project` stage
    doesn't carry it through -- confirmed live 2026-09-02: a saved search
    whose FileName/FolderPath were only used in an early `where` clause,
    then dropped by a later `summarize`, errored out in the Hunting UI with
    exactly the "column not found" failure this function's own docstring
    warned about, because a match anywhere in the whole body was treated as
    good enough. Only the text AFTER the last such narrowing stage (or the
    whole body, if there isn't one) is searched now."""
    if not kql_body or not kql_body.strip():
        return kql_body
    narrowing_matches = list(_SCHEMA_NARROWING.finditer(kql_body))
    search_region = kql_body[narrowing_matches[-1].end():] if narrowing_matches else kql_body
    counts: dict[str, int] = {}
    extend_lines = []
    for entity_type, fields in _ENTITY_GROUPS:
        matched = [
            (column_name, identifier) for column_name, identifier in fields
            if re.search(rf"\b{re.escape(column_name)}\b", search_region)
        ]
        if not matched:
            continue
        n = counts.get(entity_type, 0)
        for column_name, identifier in matched:
            extend_lines.append(f"| extend {entity_type}_{n}_{identifier} = {column_name}")
        counts[entity_type] = n + 1
    if not extend_lines:
        return kql_body
    return kql_body.rstrip() + "\n" + "\n".join(extend_lines)


def is_enabled() -> bool:
    return os.environ.get("SENTINEL_HUNTING_SYNC_ENABLED", "").strip().lower() in (
        "1", "true", "yes",
    )


class SentinelHuntingError(RuntimeError):
    """Any failure creating/updating a Sentinel-side hunt or saved search."""


class SentinelHuntingClient:
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
            raise SentinelHuntingError(
                f"missing required config for Sentinel Hunting sync: {', '.join(missing)}"
            )
        if credential is None:
            if DefaultAzureCredential is None:
                raise SentinelHuntingError(
                    "azure-identity is not installed: pip install azure-identity"
                )
            credential = DefaultAzureCredential()
        self._credential = credential
        self._client = httpx.Client(timeout=timeout)
        self._token = None
        self._token_expires = 0.0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelHuntingClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        try:
            tok = self._credential.get_token(ARM_SCOPE)
        except Exception as exc:  # credential types vary too much to narrow
            raise SentinelHuntingError(f"could not acquire an ARM token: {exc}") from exc
        self._token = tok.token
        self._token_expires = float(tok.expires_on)
        return self._token

    def _workspace_resource_id(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    def _put(self, path: str, api_version: str, body: dict) -> dict:
        resp = self._client.put(
            f"{ARM_ENDPOINT}{path}",
            params={"api-version": api_version},
            json=body,
            headers={"Authorization": f"Bearer {self._bearer()}"},
        )
        if resp.status_code >= 400:
            raise SentinelHuntingError(
                f"PUT {path} failed: {resp.status_code} {resp.text[:500]}"
            )
        return resp.json() if resp.content else {}

    def list_hunts(self) -> list[dict]:
        """Every Sentinel Hunt already in the workspace -- both ones this
        pipeline created and ones that existed already (e.g. an analyst's
        own "In the News V2"), for the "deploy into an existing hunt"
        picker. Standard ARM collection GET on the same resource type
        upsert_hunt() writes to; id/displayName are all the picker needs.
        Follows nextLink so a workspace with more hunts than fit on one
        page doesn't silently drop the rest from the picker."""
        results: list[dict] = []
        url = (
            f"{ARM_ENDPOINT}{self._workspace_resource_id()}"
            f"/providers/Microsoft.SecurityInsights/hunts"
        )
        params = {"api-version": HUNTS_API_VERSION}
        while url:
            resp = self._client.get(
                url, params=params,
                headers={"Authorization": f"Bearer {self._bearer()}"},
            )
            if resp.status_code >= 400:
                raise SentinelHuntingError(
                    f"GET {url} failed: {resp.status_code} {resp.text[:500]}"
                )
            data = resp.json() if resp.content else {}
            results.extend(
                {
                    # ARM resource `name` is the GUID segment upsert_hunt()/
                    # link_query_to_hunt() take as hunt_id -- not the full
                    # resource id path.
                    "id": item.get("name", ""),
                    "display_name": (item.get("properties") or {}).get("displayName", ""),
                }
                for item in (data.get("value") or [])
            )
            url = data.get("nextLink") or None
            params = None  # nextLink already carries its own query string
        return results

    def upsert_saved_search(self, saved_search_id: str, display_name: str, query: str,
                            description: str = "", tactics: list[str] | None = None,
                            techniques: list[str] | None = None,
                            created_by: str | None = None,
                            created_time_utc: str | None = None) -> str:
        """Create/update a Sentinel hunting-query saved search. Returns its
        full ARM resource id, for use as a hunts/relations relatedResourceId.

        Tag names are lowercase ("description"/"tactics"/"techniques"/
        "createdBy"/"createdTimeUtc"), matching a real Content-Hub-authored
        hunting query's actual tags in this workspace (confirmed live
        2026-08-31 via a direct GET, not the PascalCase shown in Microsoft's
        own REST API doc example) -- the Hunting page's Techniques/Created
        by/Created time columns and MITRE tactic/technique filters all read
        these specific tag names, and every one of them was blank for every
        query this pipeline had created until this fix.

        category="Hunt Queries" and version=2 confirmed live 2026-09-01 by
        capturing the Sentinel portal's own network traffic while manually
        adding a query to a Hunt (portal.azure.com's HuntQueryClient PUT to
        this exact savedSearches endpoint, immediately followed by a
        HuntRelationClient batch call). The portal sent "Category": "Hunt
        Queries" and "Version": 2 -- this module previously sent
        category="Hunting Queries" (the value Microsoft's own hunting-query
        REST API doc uses for the *general* Hunting > Queries library, not
        a Hunt-linked query specifically) and no version at all. Matches
        the user's exact symptom: our synced queries showed up with the
        right count in Sentinel's flat Hunting > Queries tab and in our own
        app's Sentinel Hunts view (both count relations/saved searches
        directly, category-agnostic), but not inside the Hunt's own Queries
        sub-tab in the Sentinel portal, which is the one place a category
        mismatch would actually matter."""
        # 256: confirmed live 2026-08-31 -- ARM 400s ANY savedSearches Tag
        # value beyond this length ("invalid according to its datatype
        # 'TagValue'"), even though no length constraint is documented on the
        # Tag schema itself. Applies uniformly to every tag, not just
        # description -- a hunt (#44) whose tactics tag carried a corrupted,
        # multi-hundred-char technique_name (an embedded YARA rule from a
        # separate upstream data-quality bug) hit the identical error on the
        # tactics tag once description alone was truncated.
        _TAG_VALUE_LIMIT = 256
        tags = []
        if description:
            tags.append({"Name": "description", "Value": description[:_TAG_VALUE_LIMIT]})
        if tactics:
            tags.append({"Name": "tactics", "Value": ",".join(tactics)[:_TAG_VALUE_LIMIT]})
        if techniques:
            tags.append({"Name": "techniques", "Value": ",".join(techniques)[:_TAG_VALUE_LIMIT]})
        if created_by:
            tags.append({"Name": "createdBy", "Value": created_by[:_TAG_VALUE_LIMIT]})
        if created_time_utc:
            tags.append({"Name": "createdTimeUtc", "Value": created_time_utc[:_TAG_VALUE_LIMIT]})
        path = f"{self._workspace_resource_id()}/savedSearches/{saved_search_id}"
        self._put(path, SAVED_SEARCHES_API_VERSION, {
            "properties": {
                "category": "Hunt Queries",
                "displayName": display_name[:200] if display_name else saved_search_id,
                "query": query,
                "version": 2,
                "tags": tags,
            },
        })
        return path

    def upsert_hunt(self, hunt_id: str, display_name: str, description: str,
                    attack_techniques: list[str] | None = None,
                    attack_tactics: list[str] | None = None,
                    status: str = "New") -> str:
        """Create/update a Sentinel Hunt container. Returns its full ARM
        resource id, for use as a hunts/relations parent path.

        attack_tactics must cover every attack_techniques entry (each
        technique has to belong to at least one listed tactic) or ARM 400s
        the whole request with "no valid AttackTactic for the
        AttackTechniques provided" -- confirmed live 2026-08-31. Callers
        should derive both from mitre_tactics.tactics_for_techniques()
        rather than passing attack_techniques alone.

        displayName must be under 100 chars -- confirmed live 2026-09-02
        via a real ARM 400 ("displayName must have length < 100") on a
        hunt whose title exceeded it; the 200-char cap this used to share
        with upsert_saved_search() was never actually validated against
        the hunts endpoint specifically, only assumed to match. A hunt's
        display_name (the source TI article's title) routinely exceeds
        100 chars, so this was silently failing sync for any sufficiently
        long-titled article -- see the SENTINEL_HUNTING_SYNC_FAILED /
        audit-log entry this produced."""
        path = (
            f"{self._workspace_resource_id()}"
            f"/providers/Microsoft.SecurityInsights/hunts/{hunt_id}"
        )
        self._put(path, HUNTS_API_VERSION, {
            "properties": {
                "displayName": display_name[:99] if display_name else hunt_id,
                "description": description or display_name or hunt_id,
                "attackTechniques": attack_techniques or [],
                "attackTactics": attack_tactics or [],
                "status": status,
                "hypothesisStatus": "Unknown",
            },
        })
        return path

    def link_query_to_hunt(self, hunt_id: str, relation_id: str,
                           related_resource_id: str,
                           related_resource_kind: str = "SavedSearch",
                           labels: list[str] | None = None) -> None:
        """Link a saved search into a hunt via
        Microsoft.SecurityInsights/hunts/relations.

        relatedResourceKind is optional per the ARM schema but load-bearing
        in practice: without it the relation is created (it counts toward
        the hunt's total relation count, shown in the Hunting list view's
        side panel) but the Hunting portal's own Queries tab -- which
        filters relations by kind to bucket them into Queries/Bookmarks/
        Entities -- never surfaces it, showing "No queries were found"
        despite the hunt's own summary reporting the right count. Confirmed
        live 2026-08-31 against hunts 44/50/92."""
        path = (
            f"{self._workspace_resource_id()}/providers/Microsoft.SecurityInsights"
            f"/hunts/{hunt_id}/relations/{relation_id}"
        )
        self._put(path, HUNTS_API_VERSION, {
            "properties": {
                "relatedResourceId": related_resource_id,
                "relatedResourceKind": related_resource_kind,
                "labels": labels or [],
            },
        })


def list_existing_hunts() -> dict:
    """Best-effort listing of every Sentinel Hunt already in the workspace,
    for the "deploy into an existing hunt" picker (frontend: HuntsPanel.js's
    deploy-target dropdown). Mirrors sync_hunt()'s own never-raise
    discipline -- a listing failure (RBAC not granted yet, ARM hiccup)
    degrades to an empty list with the reason in `error`, not a 500 that
    blocks the rest of the Hunts tab from loading."""
    if not is_enabled():
        return {"enabled": False, "hunts": [], "error": None}
    try:
        with SentinelHuntingClient() as client:
            return {"enabled": True, "hunts": client.list_hunts(), "error": None}
    except Exception as exc:
        logger.warning("SENTINEL_HUNTING_LIST_HUNTS_FAILED: %s", exc)
        return {"enabled": True, "hunts": [], "error": str(exc)}


def sync_hunt(conn, hunt_id: int, *, hunt_title: str, hunt_description: str,
             detections: list[dict], target_sentinel_hunt_id: str | None = None) -> None:
    """Best-effort: create/update the Sentinel-side Hunt and its child saved
    searches for one hunt. `detections` is a list of dicts with
    artifact_id/name/description/kql_body/technique_id/technique_name.

    target_sentinel_hunt_id (hunts.target_sentinel_hunt_id, set via
    hunts.set_hunt_target()): when given, queries are linked into that
    already-existing Sentinel Hunt instead of the dedicated one this
    function would otherwise create/manage -- upsert_hunt() is skipped
    entirely so an admin's own hunt (title, description, status,
    hypothesis) is never overwritten with ours. When absent (the default,
    NULL), behavior is unchanged from before this option existed: a
    dedicated Sentinel Hunt derived from our own hunt_id.

    Never raises -- disabled (the common case today) is a silent no-op;
    any failure once enabled is logged and recorded via
    hunts.mark_hunt_synced(), same non-fatal-sweep convention as every
    other Sentinel-backed stage in this pipeline (see orchestrator.py).
    """
    # Local import (not a hard circular dependency -- hunts.py never imports
    # this module back): package-relative, not bare `import hunts`. A bare
    # import only resolves when detection_pipeline/ itself happens to be on
    # sys.path, which is true when this runs as orchestrator.py's own script
    # process but NOT when it runs inside main.py's FastAPI process (the
    # manual "Deploy to Sentinel" path) -- that raised an uncaught
    # ModuleNotFoundError there, a 500 on every deploy attempt, confirmed
    # live 2026-08-31.
    from detection_pipeline import hunts as hunts_module

    if not is_enabled():
        return

    sentinel_hunt_id = target_sentinel_hunt_id or arm_safe_id("hunt", str(hunt_id))
    try:
        with SentinelHuntingClient() as client:
            if not target_sentinel_hunt_id:
                techniques = sorted({d["technique_id"] for d in detections if d.get("technique_id")})
                mapped_techniques, tactics = mitre_tactics.tactics_for_techniques(techniques)
                client.upsert_hunt(
                    sentinel_hunt_id, display_name=hunt_title,
                    description=hunt_description, attack_techniques=mapped_techniques,
                    attack_tactics=tactics,
                )

            # Each detection gets its own try/except -- confirmed live
            # 2026-09-01: this used to be one try/except around the whole
            # loop, so a single detection's upsert_saved_search()/
            # link_query_to_hunt() failure (a transient network blip, a
            # 400 on one bad query) aborted every remaining detection in
            # the hunt too, leaving the Sentinel-side Hunt container
            # created but with zero (or only the first few) queries ever
            # linked, and the rest of the batch silently never attempted
            # at all -- not even upsert_saved_search(), so those
            # detections had no Sentinel-side representation whatsoever.
            # Isolating per-detection means one bad query can't take out
            # every other query in the same hunt, same discipline as
            # tuning_suggestions.py's apply/dismiss batch endpoints.
            _now = datetime.now(timezone.utc)
            synced_at = _now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{_now.microsecond // 1000:03d}Z"
            detection_errors: list[tuple] = []
            for det in detections:
                try:
                    saved_search_id = arm_safe_id("query", str(hunt_id), str(det["id"]))
                    det_technique_id = det.get("technique_id")
                    det_tactics = (
                        mitre_tactics.tactics_for_techniques([det_technique_id])[1]
                        if det_technique_id else []
                    )
                    # det["name"] comes from register_analytic()'s own
                    # `name` param, ultimately orchestrator.py's det.title --
                    # null for detections whose generation didn't parse a
                    # title (a real, separate upstream gap, not something
                    # fixed here). Confirmed live 2026-09-01: falling back to
                    # bare technique_id produced saved searches literally
                    # named "T1005"/"T1087.004" with no way to tell them
                    # apart in Sentinel's UI. technique_name (e.g. "Data from
                    # Local System") is a real, human-readable value already
                    # present on every det dict and a meaningfully better
                    # fallback, even though it isn't unique either -- unique
                    # naming needs the upstream title gap fixed, not this.
                    saved_search_resource_id = client.upsert_saved_search(
                        saved_search_id,
                        display_name=(
                            det.get("name") or det.get("technique_name")
                            or det.get("technique_id") or saved_search_id
                        ),
                        query=append_entity_mapping_extends(det.get("kql_body") or ""),
                        description=det.get("description") or "",
                        tactics=det_tactics,
                        # Base technique id (sub-technique suffix stripped) --
                        # matches the real "techniques" tag convention confirmed
                        # live 2026-08-31 (e.g. "T1110,T1021", not "T1110.003").
                        techniques=(
                            [mitre_tactics.base_technique(det_technique_id)]
                            if det_technique_id else None
                        ),
                        created_by="Threat Intel Aggregator",
                        created_time_utc=synced_at,
                    )
                    client.link_query_to_hunt(
                        sentinel_hunt_id,
                        relation_id=arm_safe_id("relation", str(hunt_id), str(det["id"])),
                        related_resource_id=saved_search_resource_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "SENTINEL_HUNTING_SYNC_DETECTION_FAILED hunt_id=%s detection_id=%s: %s",
                        hunt_id, det.get("id"), exc,
                    )
                    detection_errors.append((det.get("id"), str(exc)))
    except Exception as exc:
        # A failure here (client construction, or upsert_hunt itself) means
        # the Hunt container never got created at all -- nothing to link
        # detections into, so this genuinely is a whole-sync failure, unlike
        # a per-detection one above.
        logger.warning("SENTINEL_HUNTING_SYNC_FAILED hunt_id=%s: %s", hunt_id, exc)
        hunts_module.mark_hunt_synced(conn, hunt_id, sentinel_hunt_id=None, error=str(exc))
        return

    error = (
        f"{len(detection_errors)}/{len(detections)} detection(s) failed to sync: "
        + "; ".join(f"id={det_id}: {msg}" for det_id, msg in detection_errors)
        if detection_errors else None
    )
    hunts_module.mark_hunt_synced(conn, hunt_id, sentinel_hunt_id=sentinel_hunt_id, error=error)


def deploy_all_hunts(conn) -> dict:
    """Bulk "Deploy All" for Generated Hunts: push every hunt that
    hunts.list_hunts_needing_deploy() flags as never-synced or needing a
    resync, one hunt at a time, isolated the same way sync_hunt() already
    isolates one detection's failure from the rest of its own hunt -- a
    single hunt's ARM failure (or having nothing eligible yet) must not
    abort the batch.

    Mirrors sentinel_hunt_sync.sync_all()'s {"enabled": False, ...}
    early-return convention when SENTINEL_HUNTING_SYNC_ENABLED is off:
    sync_hunt() itself would otherwise silently no-op for every hunt in
    the batch (no mark_hunt_synced() call at all), which would misreport
    every hunt as neither succeeded nor failed instead of plainly saying
    sync is disabled.
    """
    from detection_pipeline import hunts as hunts_module

    if not is_enabled():
        return {"enabled": False, "total": 0, "succeeded": 0, "failed": []}

    candidates = hunts_module.list_hunts_needing_deploy(conn)
    succeeded = 0
    failed: list[dict] = []
    for hunt in candidates:
        hunt_id = hunt["id"]
        try:
            eligible = hunts_module.get_sync_eligible_detections(
                conn, hunt_id, require_alignment=False,
            )
            if not eligible:
                failed.append({
                    "hunt_id": hunt_id,
                    "reason": "no detections in this hunt have passed both the static gate and backtest yet",
                })
                continue
            sync_hunt(
                conn, hunt_id, hunt_title=hunt["title"] or hunt["source_title"] or "",
                hunt_description=hunt["description"] or "", detections=eligible,
                target_sentinel_hunt_id=hunt.get("target_sentinel_hunt_id"),
            )
            outcome = conn.execute(
                "SELECT sentinel_sync_error FROM hunts WHERE id = ?", (hunt_id,)
            ).fetchone()
            if outcome and outcome["sentinel_sync_error"]:
                failed.append({"hunt_id": hunt_id, "reason": outcome["sentinel_sync_error"]})
            else:
                succeeded += 1
        except Exception as exc:
            logger.warning(
                "SENTINEL_HUNTING_DEPLOY_ALL_HUNT_FAILED hunt_id=%s: %s", hunt_id, exc,
            )
            failed.append({"hunt_id": hunt_id, "reason": str(exc)})

    return {"enabled": True, "total": len(candidates), "succeeded": succeeded, "failed": failed}


# ── Auto-deploy default target + rollover ────────────────────────────────
# User ask (2026-09-04, after live-feedback round 6 shipped): let an admin
# pick one existing Sentinel Hunt as the default the 'auto' mode's
# automatic push targets (instead of always creating a dedicated hunt per
# TI article), and auto-provision the next "In The News: Hunts vN" when
# that target fills up -- the same rollover an admin had done by hand
# between v1 (974 queries, confirmed live 2026-09-01) and v2 (currently
# ~305, confirmed live 2026-09-04) before this existed.
#
# Sentinel's real cap on relations/queries under one Hunt is close to
# 1000, but some relations silently fail to appear in the Hunt's own
# Queries tab (a category/version mismatch, e.g.) while still occupying a
# slot -- "ghost" entries the portal's own count doesn't show. 975 leaves
# headroom below the real cap for those before ARM starts rejecting new
# relations outright.
_AUTO_DEPLOY_ROLLOVER_THRESHOLD = 975
_AUTO_DEPLOY_TITLE_RE = re.compile(r"^In The News: Hunts(?: v(\d+))?$")
_AUTO_DEPLOY_TITLE_BASE = "In The News: Hunts"


def resolve_auto_deploy_target(conn) -> str | None:
    """The Sentinel Hunt id the 'auto' mode's automatic push should target
    when the owning `hunts` row has no per-hunt override of its own
    (hunts.target_sentinel_hunt_id -- that override always wins over this
    default, unchanged). None means "create a new dedicated hunt per TI
    article," today's original default, preserved when hunt_sync_
    settings.auto_deploy_target_sentinel_hunt_id is unset.

    When the configured target's local query_count (sentinel_hunts,
    pg_sentinel_hunt_inventory.sql -- kept fresh by sentinel_hunt_sync.py's
    periodic inventory sync, so this can lag the real ARM count between
    syncs) has reached _AUTO_DEPLOY_ROLLOVER_THRESHOLD, auto-provisions
    the next "In The News: Hunts vN" hunt and persists it as the new
    default before returning it.

    Never raises -- same non-fatal discipline as sync_hunt() itself. A
    rollover failure here just means the caller's sync_hunt() attempts the
    stale/original (at-or-over-capacity but still valid) target instead;
    that either still succeeds (undercounted local inventory) or the one
    detection's link_query_to_hunt() call fails, which sync_hunt() already
    isolates and logs per detection, not a whole-sync failure.
    """
    from detection_pipeline import hunt_sync_settings as hss

    settings = hss.get_settings(conn)
    target = settings.get("auto_deploy_target_sentinel_hunt_id")
    if not target:
        return None

    row = conn.execute(
        "SELECT query_count FROM sentinel_hunts WHERE sentinel_hunt_id = ?", (target,)
    ).fetchone()
    if not row or row["query_count"] < _AUTO_DEPLOY_ROLLOVER_THRESHOLD:
        return target

    try:
        return _rotate_auto_deploy_target(conn, target)
    except Exception as exc:
        logger.warning(
            "HUNT_AUTO_DEPLOY_ROLLOVER_FAILED current_target=%s query_count=%s: %s",
            target, row["query_count"], exc,
        )
        return target


def _next_auto_deploy_title(conn) -> str:
    """Next unused "In The News: Hunts vN" title, scanning the local
    sentinel_hunts inventory (not a live ARM list -- this only needs to
    avoid colliding with a name already known locally; a genuinely new
    hunt from this exact rollover is what fills that inventory in the
    first place). A bare "In The News: Hunts" (no " vN" suffix) counts as
    v1, matching the real hunt that existed before this versioning
    convention started."""
    rows = conn.execute("SELECT display_name FROM sentinel_hunts").fetchall()
    max_version = 1
    for r in rows:
        m = _AUTO_DEPLOY_TITLE_RE.match((r["display_name"] or "").strip())
        if m:
            version = int(m.group(1)) if m.group(1) else 1
            max_version = max(max_version, version)
    return f"{_AUTO_DEPLOY_TITLE_BASE} v{max_version + 1}"


def _rotate_auto_deploy_target(conn, current_target_id: str) -> str:
    """Create the next "In The News: Hunts vN" Sentinel Hunt, persist it as
    the new hunt_sync_settings.auto_deploy_target_sentinel_hunt_id, and
    return its id. Can raise (ARM failure, client construction) --
    resolve_auto_deploy_target() is the caller and catches it."""
    from detection_pipeline import hunt_sync_settings as hss

    next_title = _next_auto_deploy_title(conn)
    next_id = arm_safe_id("auto-deploy-target", next_title)

    with SentinelHuntingClient() as client:
        client.upsert_hunt(next_id, display_name=next_title, description=next_title)

    hss.set_auto_deploy_target(conn, next_id, updated_by="system:rollover")
    logger.warning(
        "HUNT_AUTO_DEPLOY_ROLLED_OVER from=%s to=%s title=%r",
        current_target_id, next_id, next_title,
    )
    return next_id
