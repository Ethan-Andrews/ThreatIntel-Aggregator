"""detections.ai public API client (v1-beta) for the TI-to-detection pipeline.

Wraps the project -> intel -> generate -> coverage-report -> detection flow.
Two asynchronous waits are unavoidable and are handled here rather than by the
caller:

  1. Intel preprocessing. Adding intel returns immediately with
     preprocessing_status "pending"; generation cannot start until the readiness
     endpoint reports generation_ready.
  2. Generation itself. POST /generate returns 202 with a task_id; the artifacts
     only exist once GET /tasks/{id} reaches "completed".

Deliberately scoped to reads and generation. The API has no write-back surface:
nothing here saves, exports or publishes. Staging a detection for review is the
pipeline's own job, via a pull request.

Environment:
    DETECTIONS_AI_API_KEY       required
    DETECTIONS_AI_BASE_URL      default https://detections.ai
    DETECTIONS_AI_API_VERSION   default v1-beta
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://detections.ai"
DEFAULT_API_VERSION = "v1-beta"

# Preprocessing is terminal in these states: the intel will never become ready.
TERMINAL_PREPROCESSING = {"failed", "skipped"}
TERMINAL_TASK = {"completed", "failed"}

# Project titles are capped at 100 characters server-side (undocumented; the
# API returns 400 invalid_request with code "too_big"). The check is Zod-side,
# so it counts UTF-16 code units rather than Python code points.
TITLE_MAX = 100

# Trailing punctuation left behind by mid-word truncation. Escapes keep this
# source ASCII while still catching en/em dashes common in feed titles.
_TRAILING = " \t-:;,.\u2013\u2014"


def _utf16_len(s: str) -> int:
    """Length as the server counts it: UTF-16 code units, matching JS .length."""
    return len(s.encode("utf-16-le")) // 2


def _truncate_utf16(s: str, limit: int) -> str:
    """Truncate to `limit` UTF-16 code units without splitting a surrogate pair."""
    if limit <= 0:
        return ""
    if _utf16_len(s) <= limit:
        return s
    out: list[str] = []
    used = 0
    for ch in s:
        cost = 2 if ord(ch) > 0xFFFF else 1
        if used + cost > limit:
            break
        out.append(ch)
        used += cost
    return "".join(out)


def _fit_title(stem: str, tail: str) -> str:
    """Compose stem + tail within TITLE_MAX, trimming only the stem.

    The tail carries the disambiguators (article hash prefix, and a UTC stamp on
    a 409 retry). Those are what make re-runs resolve, so they are never
    trimmed; the article title loses characters instead.
    """
    budget = TITLE_MAX - _utf16_len(tail)
    if budget <= 0:
        # Pathological: disambiguators alone exceed the cap. Keep them and drop
        # the stem rather than emitting a title the server will reject.
        return _truncate_utf16(tail.strip(), TITLE_MAX)
    return _truncate_utf16(stem, budget).rstrip(_TRAILING) + tail


class DetectionsAIError(RuntimeError):
    """Any non-retryable failure from the API."""


class PreprocessingFailed(DetectionsAIError):
    """Intel reached a terminal state without becoming generation-ready."""


class GenerationFailed(DetectionsAIError):
    """The generation task reported status 'failed'."""


class PollTimeout(DetectionsAIError):
    """A poll loop exhausted its budget without reaching a terminal state."""


@dataclass
class CoverageItem:
    """One opportunity from the coverage report."""

    opportunity_title: str
    primary_mitre_attack_id: str
    mitre_attack_ids: list[str]
    data_source: str
    status: str  # covered | gap | unable_to_determine
    matched_rules: list[dict] = field(default_factory=list)

    @property
    def is_gap(self) -> bool:
        # Exactly "gap". unable_to_determine is a separate bucket and must not
        # be treated as a gap: acting on it would generate detections for
        # coverage that may already exist.
        return self.status == "gap"


@dataclass
class CoverageReport:
    items: list[CoverageItem]
    summary: dict

    @property
    def gaps(self) -> list[CoverageItem]:
        return [i for i in self.items if i.is_gap]

    @property
    def undetermined(self) -> list[CoverageItem]:
        return [i for i in self.items if i.status == "unable_to_determine"]


@dataclass
class Detection:
    artifact_id: str
    title: str
    description: str
    content: str


class DetectionsAIClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        api_version: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("DETECTIONS_AI_API_KEY", "")
        if not self.api_key:
            raise DetectionsAIError("DETECTIONS_AI_API_KEY is not set")

        base = (base_url or os.environ.get("DETECTIONS_AI_BASE_URL")
                or DEFAULT_BASE_URL).rstrip("/")
        version = (api_version or os.environ.get("DETECTIONS_AI_API_VERSION")
                   or DEFAULT_API_VERSION)
        self._root = f"{base}/api/{version}"

        self._client = httpx.Client(
            timeout=timeout,
            headers={"X-API-Key": self.api_key, "Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "DetectionsAIClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ transport

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """Issue a request and unwrap the {"data": ...} envelope."""
        url = f"{self._root}{path}"
        try:
            resp = self._client.request(method, url, **kwargs)
        except httpx.RequestError as exc:
            raise DetectionsAIError(f"{method} {path} failed: {exc}") from exc

        if resp.status_code >= 400:
            body = resp.text[:400]
            raise DetectionsAIError(
                f"{method} {path} -> HTTP {resp.status_code}: {body}"
            )

        if not resp.content:
            return None
        payload = resp.json()
        # Every documented success body is enveloped; tolerate a bare body
        # rather than crashing if that ever changes.
        return payload.get("data", payload) if isinstance(payload, dict) else payload

    # ----------------------------------------------------------------- auth

    def whoami(self) -> dict:
        """Validate the key and resolve the team. Use as a startup probe."""
        return self._request("GET", "/whoami")

    # ------------------------------------------------------------- projects

    def create_project(self, title: str, description: str = "",
                       suffix: str = "") -> str:
        """Create a project.

        Titles are unique per team server-side: a duplicate returns
        409 project_title_conflict. Re-running the same article therefore always
        collides, so an explicit suffix (the article hash prefix) disambiguates.
        If that still collides, a UTC timestamp is appended, because a caller
        that has deliberately asked to re-run should not be blocked by a name.

        Titles are also capped at 100 characters. Both the suffix and the retry
        stamp are reserved out of that budget before the caller's title is
        truncated, so the retry path cannot overflow the way it previously did.
        """
        def _create(t: str) -> str:
            over = _utf16_len(t) - TITLE_MAX
            if over > 0:
                # Unreachable via _fit_title; guards against a future caller
                # bypassing it, and fails with a readable message not a 400.
                raise DetectionsAIError(
                    f"project title exceeds {TITLE_MAX} chars by {over}: {t[:60]}"
                )
            body = {"title": t}
            if description:
                body["description"] = description
            return self._request("POST", "/projects", json=body)["id"]

        tail = f" [{suffix}]" if suffix else ""
        full = _fit_title(title, tail)
        try:
            return _create(full)
        except DetectionsAIError as exc:
            if "project_title_conflict" not in str(exc):
                raise
            stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            retitled = _fit_title(title, f"{tail} {stamp}")
            logger.info("PROJECT_TITLE_CONFLICT retrying as %s", retitled)
            return _create(retitled)

    # ---------------------------------------------------------------- intel

    def add_intel_url(self, project_id: str, url: str) -> str:
        # http(s) only, no embedded credentials, 2048 char ceiling. Validate
        # here so a bad article URL fails with a clear message rather than an
        # opaque 400.
        if not url.startswith(("http://", "https://")):
            raise DetectionsAIError(f"intel URL must be http(s): {url[:80]}")
        if "@" in url.split("://", 1)[1].split("/", 1)[0]:
            raise DetectionsAIError("intel URL must not embed credentials")
        if len(url) > 2048:
            raise DetectionsAIError(f"intel URL exceeds 2048 chars ({len(url)})")

        data = self._request(
            "POST", f"/projects/{project_id}/intel",
            json={"type": "url", "url": url},
        )
        return data["id"]

    def add_intel_text(self, project_id: str, text: str) -> str:
        if not text or not text.strip():
            raise DetectionsAIError("intel text must be non-blank")
        data = self._request(
            "POST", f"/projects/{project_id}/intel",
            json={"type": "text", "text": text},
        )
        return data["id"]

    def list_intel(self, project_id: str) -> list[dict]:
        return self._request(
            "GET", f"/projects/{project_id}/intel",
            params={"page": 1, "page_size": 100},
        )

    def wait_for_intel(
        self,
        project_id: str,
        intel_id: str,
        timeout: float = 300.0,
        interval: float = 5.0,
    ) -> None:
        """Block until the intel is generation_ready, or fail.

        generation_ready is true only when preprocessing_status is "completed".
        "failed" and "skipped", and any item marked unavailable, are terminal:
        polling past them wastes the whole budget waiting for a state that will
        never arrive.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for item in self.list_intel(project_id):
                if item.get("id") != intel_id:
                    continue

                if item.get("generation_ready"):
                    logger.info("INTEL_READY project=%s intel=%s", project_id, intel_id)
                    return

                if item.get("availability") == "unavailable":
                    raise PreprocessingFailed(
                        f"intel {intel_id} is unavailable (terminal)"
                    )

                status = item.get("preprocessing_status")
                if status in TERMINAL_PREPROCESSING:
                    failure = item.get("preprocessing_failure") or {}
                    raise PreprocessingFailed(
                        f"intel {intel_id} preprocessing {status}"
                        f" ({failure.get('code', 'no code')})"
                    )
                break
            time.sleep(interval)

        raise PollTimeout(
            f"intel {intel_id} not ready after {timeout:.0f}s"
        )

    # ------------------------------------------------------------- generate

    def generate(
        self, project_id: str, operation_id: str, language: str = "kql"
    ) -> str:
        """Start generation and return the task id.

        operation_id is the server-side idempotency key. Pass a value derived
        from the source article (the aggregator's entries.hash) so a retry after
        a crash resumes rather than paying for a second generation.

        language defaults to "sigma" server-side. Always pass "kql" explicitly:
        a model translating Sigma to KQL afterwards is a needless source of
        error when the API emits KQL natively.
        """
        data = self._request(
            "POST", f"/projects/{project_id}/generate",
            json={"operation_id": operation_id, "language": language},
        )
        return data["task_id"]

    def wait_for_task(
        self, task_id: str, timeout: float = 900.0, interval: float = 10.0
    ) -> dict:
        """Block until the generation task is terminal. Returns the task body."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            task = self._request("GET", f"/tasks/{task_id}")
            status = task.get("status")

            if status == "completed":
                logger.info("TASK_COMPLETED task=%s", task_id)
                return task

            if status == "failed":
                err = task.get("error") or {}
                raise GenerationFailed(
                    f"task {task_id} failed: {err.get('code', '?')}"
                    f" {err.get('message', '')}"
                    f" (retryable={err.get('retryable')})"
                )

            time.sleep(interval)

        raise PollTimeout(f"task {task_id} still running after {timeout:.0f}s")

    # ------------------------------------------------------------- coverage

    def coverage_report(self, project_id: str) -> CoverageReport:
        """Fetch the coverage report.

        This is the redundant-TTP check. With the existing rule corpus imported,
        the platform already knows which techniques are covered, so the pipeline
        never needs its own deduplication logic.
        """
        data = self._request("GET", f"/projects/{project_id}/coverage-report")
        items = [
            CoverageItem(
                opportunity_title=i.get("opportunity_title", ""),
                primary_mitre_attack_id=i.get("primary_mitre_attack_id", ""),
                mitre_attack_ids=i.get("mitre_attack_ids") or [],
                data_source=i.get("data_source", ""),
                status=i.get("status", ""),
                matched_rules=i.get("matched_rules") or [],
            )
            for i in (data.get("items") or [])
        ]
        return CoverageReport(items=items, summary=data.get("summary") or {})

    # ----------------------------------------------------------- detections

    def list_detections(self, project_id: str, saved_state: str = "all") -> list[dict]:
        # saved_state defaults to "unsaved" server-side, which silently omits
        # anything saved in the web app. "all" is the safe default here.
        return self._request(
            "GET", f"/projects/{project_id}/detections",
            params={"page": 1, "page_size": 100, "saved_state": saved_state},
        )

    def get_detection(self, project_id: str, artifact_id: str) -> Detection:
        data = self._request(
            "GET", f"/projects/{project_id}/detections/{artifact_id}"
        )

        def _s(key: str) -> str:
            # The API returns null for description on some artifacts, and .get
            # with a default does not cover a present-but-null key.
            v = data.get(key)
            return v if isinstance(v, str) else ""

        return Detection(
            artifact_id=data.get("id") or artifact_id,
            title=_s("title"),
            description=_s("description"),
            content=_s("content"),
        )

    # -------------------------------------------------------- orchestration

    def generate_from_project(
        self,
        project_id: str,
        url: str,
        operation_id: str,
        language: str = "kql",
    ) -> tuple[str, CoverageReport, list[Detection]]:
        """Intel -> generate -> artifacts against an already-created project.

        Split out from generate_from_url() so a caller resuming a project
        from a prior, later-failed run doesn't pay for a second one --
        detections.ai titles are unique per team, so blindly re-creating on
        every retry collides and gets retitled with a fresh timestamp each
        time (confirmed live in prod: one TI entry spawned 9+ duplicate
        projects across a few hours before orchestrator.py started reusing a
        saved project_id instead of calling create_project() again).

        Skips add_intel_url when the project already has intel attached, so
        resuming a project that failed after intel was added doesn't attach
        it twice.
        """
        existing_intel = self.list_intel(project_id)
        intel_id = existing_intel[0]["id"] if existing_intel else self.add_intel_url(project_id, url)
        self.wait_for_intel(project_id, intel_id)

        # operation_id is the server-side idempotency key. Scope it to this
        # project rather than to the article alone: an article-only key is
        # consumed by the first successful generation, so a deliberate re-run
        # against a fresh project is rejected as a replay. Including the
        # project id keeps a crash-and-retry against the SAME project
        # idempotent (same project, same key) while allowing a re-run against
        # a fresh project to proceed.
        scoped_operation_id = f"{operation_id}-{project_id[:8]}"

        task_id = self.generate(project_id, operation_id=scoped_operation_id,
                                language=language)
        logger.info("GENERATION_STARTED project=%s task=%s op=%s",
                    project_id, task_id, scoped_operation_id)
        task = self.wait_for_task(task_id)

        report = self.coverage_report(project_id)
        logger.info(
            "COVERAGE project=%s gaps=%d covered=%d undetermined=%d",
            project_id,
            len(report.gaps),
            report.summary.get("covered", 0),
            len(report.undetermined),
        )

        artifact_ids = (task.get("resource") or {}).get("detection_artifact_ids") or []
        detections = [self.get_detection(project_id, a) for a in artifact_ids]

        return project_id, report, detections

    def generate_from_url(
        self,
        title: str,
        url: str,
        operation_id: str,
        description: str = "",
        language: str = "kql",
        title_suffix: str = "",
    ) -> tuple[str, CoverageReport, list[Detection]]:
        """Full flow for one article: project -> intel -> generate -> artifacts.

        Returns (project_id, coverage_report, detections). The project_id is
        retained so a human can open {base}/projects/{project_id} to review the
        result in the web app, which is the only place detections can be saved.

        Always creates a fresh project -- callers that need to resume a
        project from a prior failed run should call create_project() once,
        persist the id, and use generate_from_project() on retry instead.
        """
        project_id = self.create_project(title=title, description=description,
                                         suffix=title_suffix)
        logger.info("PROJECT_CREATED project=%s title=%s", project_id, title[:80])
        return self.generate_from_project(project_id, url, operation_id, language=language)
