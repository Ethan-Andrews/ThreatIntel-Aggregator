"""Local Detections Import: catalog a folder of hand-written or exported
detection files into the same hunts/analytics data model orchestrator.py's
AI-generation path uses -- no Sentinel connection and no draft provider
(DETECTIONS_AI_API_KEY/DraftProvider, see draft_provider.py) required.

The goal (see docs/superpowers/plans/2026-09-14-public-release-parity-and-
local-detections.md, Task 5): an OSS user with their own existing KQL rules
(hand-written, pulled from a public Sentinel/Sigma rule repo, exported from
their own tenant) gets real cataloging/MITRE-tagging/static-validation/
review-workflow value from this app without ever configuring Sentinel or an
AI provider.

Reuses the existing write paths rather than a parallel data model:
- hunts.get_or_create_hunt() -- one hunt per imported file, idempotent by a
  synthesized source_entry_hash so re-running an import reuses the same
  hunt rather than duplicating it.
- coverage_ledger.register_analytic()/register_strategy() -- the same
  strategy/analytic tables the AI-generation path writes, tagged
  origin='local_import' (pg_analytics_hunts_origin.sql).
- static_gate.evaluate() -- only for language == "kql"; every other
  recognized language (yara/suricata/sigma/spl) still gets cataloged (so
  it's browsable, MITRE-tagged, reviewable) but explicitly skips KQL-
  specific static analysis rather than mis-scoring non-KQL content as a
  failing KQL rule. "unrecognized" content is rejected for that file with
  a clear per-file error rather than guessed at or silently skipped.
- control_query.build_plan() -- informational only (which tables/columns
  this rule would need populated to backtest), never executed against a
  live Sentinel workspace. Not persisted; returned in the job's per-file
  result only.
- alignment_check.check_alignment() -- only when a static-gate pass and
  an AI provider (any provider feed_manager._ai_configured() recognizes,
  independent of whether a draft provider or Sentinel connection exists)
  is actually available; otherwise mitre_alignment_status stays at its
  schema default ("not yet checked"), which the UI already renders
  natively. Never fatal to the import on failure.

Everything Sentinel-dependent (control_probe/backtest/tune/disposition
tracking) is out of scope for an imported file: those fields stay NULL,
which the schema and UI already render as "not yet checked"/"no Sentinel
connection configured" -- no new state needed.

Path safety (CWE-22, OWASP A01:2025, per backend/CLAUDE.md): an admin
configures a base import directory once via LOCAL_IMPORT_DIR. Every
resolved path -- the sub-path passed to import_folder(), and every sidecar
`file` reference -- is checked with the same
`requested.is_relative_to(root)` pattern backend/CLAUDE.md documents.
Path.resolve() follows symlinks, so a symlink planted inside the
configured root that points outside it is caught by the same check, not
just a literal `../` sequence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

import pgcompat
from detection_pipeline import coverage_ledger, hunts as hunts_module, mitre_sync
from detection_pipeline import sentinel_table_sync
from detection_pipeline import static_gate
from detection_pipeline.alignment_check import check_alignment
from detection_pipeline.control_query import build_plan

logger = logging.getLogger("detection_pipeline")

# Recognized-but-not-KQL languages still get cataloged; "unrecognized" and
# "unknown" (empty/comments-only) do not produce an analytics row at all.
_RECOGNIZED_LANGUAGES = {"kql", "yara", "suricata", "sigma", "spl"}

# A detection rule is always a small text file. 1 MiB is generous headroom
# over any real-world rule while still bounding a pathological/malicious
# upload -- resource exhaustion sanity check, not a correctness one.
MAX_FILE_BYTES = 1024 * 1024

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.I)

# Shared, stable technique_id for every import with no resolvable MITRE
# technique -- get-or-created once via the same check_coverage() path a
# real technique uses, then reused, rather than blocking the import.
_UNCATEGORIZED_TECHNIQUE_ID = "UNCATEGORIZED-LOCAL-IMPORT"

# Only Scheduled-kind rules carry a raw KQL query property this pipeline
# can evaluate -- same set sentinel_analytics_rules_sync.py's live sync
# already uses (pg_sentinel_analytics_rules.sql's own docstring).
_TESTABLE_KINDS = {"Scheduled"}


class LocalImportError(Exception):
    """Any failure that should abort the whole import (bad configuration,
    a path that escapes the configured root) -- distinct from a per-file
    error, which is recorded in the job's results and does not stop the
    rest of the folder from being processed."""


class ImportSidecar(BaseModel):
    """Companion metadata for a raw rule file (`.kql`, `.txt`, `.yar`,
    `.spl`, or any other extension detect_language() can classify).
    `file` is required and resolved relative to the sidecar's own
    directory -- sidecars are matched by explicit reference, not by
    same-stem convention, so a stray unrelated JSON/YAML file in the
    folder (someone's package.json) is never misinterpreted as one: it
    simply fails this validation (no `file` field) and is skipped.
    Extra fields are rejected outright rather than silently accepted into
    an untyped dict, per backend/CLAUDE.md's strict input-validation rule.
    """

    model_config = ConfigDict(extra="forbid")

    file: str
    title: str | None = None
    description: str | None = None
    technique_id: str | None = None


@dataclass
class FileResult:
    path: str
    status: str  # imported | skipped | error
    language: str | None = None
    hunt_id: int | None = None
    analytic_id: int | None = None
    technique_id: str | None = None
    static_gate_verdict: str | None = None
    static_gate_durability: float | None = None
    static_gate_findings: list[dict] | None = None
    control_plan: dict | None = None
    detail: str = ""


@dataclass
class ImportJob:
    job_id: str
    status: str = "running"  # running | completed | failed
    total: int = 0
    completed: int = 0
    failed: int = 0
    # A flagged file is NOT a failure -- it was successfully imported and
    # is fully browsable, just with a static-gate reject verdict recorded
    # against it (invalid/suspicious KQL syntax or content). Tracked
    # separately from `failed` so a caller can build a prominent "N files
    # need attention" summary without having to scan every result for
    # static_gate_verdict == "reject" itself.
    flagged: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    results: list[FileResult] = field(default_factory=list)


_jobs: dict[str, ImportJob] = {}
_jobs_lock = threading.Lock()
_JOB_CAP = 50


def create_job() -> str:
    job_id = str(uuid.uuid4())[:8]
    with _jobs_lock:
        if len(_jobs) >= _JOB_CAP:
            oldest = next(iter(_jobs))
            del _jobs[oldest]
        _jobs[job_id] = ImportJob(job_id=job_id)
    return job_id


def _job_to_dict(job: ImportJob) -> dict:
    return {
        "job_id": job.job_id,
        "status": job.status,
        "total": job.total,
        "completed": job.completed,
        "failed": job.failed,
        "flagged": job.flagged,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "results": [
            {
                "path": r.path, "status": r.status, "language": r.language,
                "hunt_id": r.hunt_id, "analytic_id": r.analytic_id,
                "technique_id": r.technique_id,
                "static_gate_verdict": r.static_gate_verdict,
                "static_gate_durability": r.static_gate_durability,
                "static_gate_findings": r.static_gate_findings,
                "control_plan": r.control_plan, "detail": r.detail,
            }
            for r in job.results
        ],
    }


def get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return _job_to_dict(job) if job is not None else None


def list_jobs() -> list[dict]:
    with _jobs_lock:
        recent = list(_jobs.values())[-20:]
        return [_job_to_dict(j) for j in reversed(recent)]


# --------------------------------------------------------------- security

def import_root() -> Path:
    """The admin-configured base directory every import is confined to.
    Resolved fresh on every call (not cached at import time) so a changed
    env var takes effect without a restart during local development."""
    raw = os.environ.get("LOCAL_IMPORT_DIR", "").strip()
    if not raw:
        raise LocalImportError("LOCAL_IMPORT_DIR is not configured")
    root = Path(raw).resolve()
    if not root.is_dir():
        raise LocalImportError(f"LOCAL_IMPORT_DIR does not exist or is not a directory: {root}")
    return root


def _build_ai_client():
    """Same helper orchestrator.py uses -- reuses feed_manager's already-
    configured AI client (ANTHROPIC_API_KEY or AI_PROVIDER=azure) rather
    than building a second one. None when neither is configured, in which
    case alignment checking is simply skipped for this import (see
    _import_content()) -- an independent axis from whether a draft
    provider or Sentinel connection exists."""
    from feed_manager import _ai_client, _ai_configured
    return _ai_client if _ai_configured() else None


def resolve_import_path(sub_path: str = "") -> Path:
    """Resolve an admin-chosen sub-path under the configured root, refusing
    anything that escapes it -- a literal `../` sequence or a symlink
    planted inside the root that points outside it alike, since
    Path.resolve() follows symlinks before the is_relative_to() check
    runs. Mirrors backend/CLAUDE.md's documented safe_db_path() pattern
    exactly."""
    root = import_root()
    requested = (root / sub_path).resolve() if sub_path else root
    if not requested.is_relative_to(root):
        raise LocalImportError("path escapes the configured import root")
    if not requested.is_dir():
        raise LocalImportError(f"not a directory: {sub_path or '.'}")
    return requested


# ------------------------------------------------------------- detection

def _looks_like_native_export(data: object) -> tuple[bool, str | None, dict | None]:
    """True if `data` is shaped like Microsoft's own exported Analytics
    Rule / Hunting Query JSON (the same kind/properties ARM resource shape
    sentinel_analytics_rules_sync.py's live sync already understands) --
    (is_native_export, kind, properties). A rule of any kind is
    recognized as a native export (so a non-Scheduled kind is reported to
    the user rather than silently mistaken for an unrelated JSON file),
    but only a Scheduled kind carries a query this pipeline can evaluate.
    """
    if not isinstance(data, dict):
        return False, None, None
    kind = data.get("kind")
    properties = data.get("properties")
    if not isinstance(kind, str) or not isinstance(properties, dict):
        return False, None, None
    if "displayName" not in properties:
        return False, None, None
    return True, kind, properties


def _read_text(path: Path) -> str | None:
    """None (not raised) on anything that makes this file unimportable as
    text -- oversized, unreadable, or not valid UTF-8 (a real binary file,
    or text in some other encoding). Callers turn None into a per-file
    error rather than letting an exception abort the whole batch."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _strip_bom(text: str) -> str:
    return text[1:] if text and text[0] == "﻿" else text


# ---------------------------------------------------------- registration

def _resolve_strategy(conn, technique_id: str | None) -> tuple[int, str | None]:
    """Returns (strategy_id, resolved_technique_id | None). Reuses an
    existing active strategy for a real technique via the same
    check_coverage() gap-check orchestrator.py's own AI-generation path
    uses -- local-imported and AI-generated analytics for the same
    technique share one strategy row, exactly as intended. A missing,
    malformed, or unresolvable technique_id falls back to one shared
    "Uncategorized" strategy, get-or-created once via the same path,
    rather than blocking the import."""
    normalized = technique_id.strip().upper() if technique_id else ""
    if normalized and _TECHNIQUE_ID_RE.match(normalized):
        existing = coverage_ledger.check_coverage(conn, normalized)
        if existing is not None:
            return existing.strategy_id, normalized
        mitre = mitre_sync.get_mitre_strategy(conn, normalized)
        strategy_id = coverage_ledger.register_strategy(
            conn, normalized, technique_name="", objective=mitre.objective or "",
            chokepoint_tables=[],
        )
        return strategy_id, normalized

    existing = coverage_ledger.check_coverage(conn, _UNCATEGORIZED_TECHNIQUE_ID)
    if existing is not None:
        return existing.strategy_id, None
    strategy_id = coverage_ledger.register_strategy(
        conn, _UNCATEGORIZED_TECHNIQUE_ID, technique_name="Uncategorized (local import)",
        objective="No MITRE technique declared for this imported file.",
        chokepoint_tables=[],
    )
    return strategy_id, None


def _import_content(conn, root: Path, path: Path, text: str,
                    sidecar: ImportSidecar | None, available_tables: set[str]) -> FileResult:
    relative = str(path.relative_to(root))
    text = _strip_bom(text)
    language = static_gate.detect_language(text)

    if language == "unknown":
        return FileResult(path=relative, status="skipped", language=language,
                          detail="empty file (comments only or blank) -- nothing to import")
    if language == "unrecognized":
        return FileResult(path=relative, status="error", language=language,
                          detail="could not classify this file as any recognized detection "
                                 "format (KQL, YARA, Suricata, Sigma, SPL) -- not imported")

    title = (sidecar.title if sidecar and sidecar.title else path.stem)
    description = (sidecar.description or "") if sidecar else ""
    technique_id = sidecar.technique_id if sidecar else None

    source_entry_hash = hashlib.sha256(f"local-import:{relative}".encode()).hexdigest()
    hunt_id = hunts_module.get_or_create_hunt(
        conn, source_entry_hash, title=title, description=description,
        source_name="local-import", origin="local_import",
    )
    strategy_id, resolved_technique = _resolve_strategy(conn, technique_id)

    gate_verdict = None
    gate_durability = None
    gate_findings = None
    control_plan = None
    review_state = "pending"
    detail = ""

    if language == "kql":
        gate = static_gate.evaluate(
            text, artifact_id=f"local-import:{relative}", title=title,
            available_tables=available_tables,
        )
        gate_verdict = gate.verdict
        gate_durability = gate.durability
        gate_findings = [
            {"code": f.code, "detail": f.detail} for f in gate.findings
        ]
        review_state = "rejected" if gate.verdict == "reject" else "pending"
        # A reject verdict is never a reason to skip the import -- the file
        # still becomes a browsable hunt/analytics row (review_state=
        # 'rejected' records that outcome), but the *why* must be visible
        # in the job result, not just implied by the verdict badge. Every
        # finding's own human-readable detail, joined -- not just the
        # bare "reject" verdict a caller would otherwise have to cross-
        # reference against static_gate_findings (which isn't even part
        # of FileResult) to understand.
        if gate.verdict == "reject" and gate.findings:
            detail = "Static analysis flagged this as invalid: " + "; ".join(
                f.detail for f in gate.findings
            )
        plan = build_plan(text, artifact_id=f"local-import:{relative}", title=title)
        control_plan = {
            "target": plan.target,
            "backtestable": plan.backtestable,
            "tables": [p.table for p in plan.probes],
            "columns_needed": sorted({c for p in plan.probes for c in p.columns}),
            "warnings": plan.warnings,
        }
    else:
        detail = f"static analysis not available for {language}"

    analytic_id = coverage_ledger.register_analytic(
        conn, strategy_id=strategy_id, source_entry_hash=source_entry_hash,
        kql_body=text, artifact_id=f"local-import:{relative}",
        durability=gate_durability, static_gate_verdict=gate_verdict,
        static_gate_findings=gate_findings, review_state=review_state,
        name=title, description=description, hunt_id=hunt_id,
        origin="local_import",
    )

    # Same gating orchestrator.py's own AI-generation path uses: only a
    # passing static gate is worth an alignment check, and only when an
    # AI provider is actually configured -- this is an independent axis
    # from the draft-provider/Sentinel ones (an operator can have a draft
    # provider with no AI-alignment key, or vice versa, or neither).
    # sentinel_client is deliberately always None here: it's only used on
    # a 'diverges' verdict to probe the suggested fix's telemetry (a
    # Sentinel-dependent axis explicitly out of scope for local import),
    # and check_alignment()'s own docstring documents None as safe when
    # the call can only resolve aligned/partial. Never fatal to the
    # import -- an alignment-check failure just leaves
    # mitre_alignment_status at its default, same as orchestrator.py.
    if gate_verdict == "pass":
        ai_client = _build_ai_client()
        if ai_client is not None:
            try:
                check_alignment(ai_client, None, conn, strategy_id, analytic_id=analytic_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ALIGNMENT_CHECK_FAILED path=%s strategy=%s analytic=%s: %s",
                    relative, strategy_id, analytic_id, exc,
                )

    return FileResult(
        path=relative, status="imported", language=language, hunt_id=hunt_id,
        analytic_id=analytic_id, technique_id=resolved_technique,
        static_gate_verdict=gate_verdict, static_gate_durability=gate_durability,
        static_gate_findings=gate_findings, control_plan=control_plan, detail=detail,
    )


def _import_native_export(conn, root: Path, path: Path, kind: str,
                          properties: dict, available_tables: set[str]) -> FileResult:
    relative = str(path.relative_to(root))
    if kind not in _TESTABLE_KINDS:
        return FileResult(
            path=relative, status="skipped", language="native-export",
            detail=f"kind={kind!r} rules don't carry a raw KQL query this pipeline "
                   f"can evaluate (only {sorted(_TESTABLE_KINDS)} do) -- not imported",
        )
    query = properties.get("query")
    if not isinstance(query, str) or not query.strip():
        return FileResult(path=relative, status="error", language="native-export",
                          detail="Scheduled rule export has no properties.query")

    title = properties.get("displayName") or path.stem
    description = properties.get("description") or ""
    techniques = properties.get("techniques") or []
    technique_id = techniques[0] if techniques and isinstance(techniques[0], str) else None

    sidecar = ImportSidecar(file=path.name, title=title, description=description,
                            technique_id=technique_id)
    return _import_content(conn, root, path, query, sidecar, available_tables)


def _classify_json_or_yaml(root: Path, path: Path) -> tuple[str, object]:
    """Classify a single .json/.yaml/.yml file in isolation (no DB writes,
    no side effects) -- pass 1 of the two-pass walk. Returns one of:
      ("native_export", (kind, properties))
      ("sigma", text)                          -- standalone Sigma content
      ("sidecar", (target_path, ImportSidecar))
      ("error", FileResult)                    -- unreadable, invalid JSON,
                                                   or a sidecar whose `file`
                                                   reference is bad
      ("ignore", None)                         -- not recognized as
                                                   anything (e.g. a stray
                                                   package.json); silently
                                                   skipped, no result at all
    Splitting classification from execution is what prevents a sidecar's
    target file from being imported twice -- once via the sidecar and
    once again when the walk reaches that file directly.
    """
    relative = str(path.relative_to(root))
    text = _read_text(path)
    if text is None:
        return "error", FileResult(
            path=relative, status="error",
            detail=f"could not read as UTF-8 text (binary file, or over {MAX_FILE_BYTES} bytes)",
        )

    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(_strip_bom(text))
        except json.JSONDecodeError as exc:
            return "error", FileResult(path=relative, status="error", detail=f"invalid JSON: {exc}")
        is_native, kind, properties = _looks_like_native_export(data)
        if is_native:
            return "native_export", (kind, properties)
    else:
        if static_gate.detect_language(text) == "sigma":
            return "sigma", text
        try:
            data = yaml.safe_load(_strip_bom(text))
        except yaml.YAMLError:
            return "ignore", None
        if not isinstance(data, dict):
            return "ignore", None

    try:
        sidecar = ImportSidecar.model_validate(data)
    except ValidationError:
        return "ignore", None  # neither a native export nor a valid sidecar -- e.g. package.json

    target = (path.parent / sidecar.file).resolve()
    if not target.is_relative_to(root):
        return "error", FileResult(
            path=relative, status="error",
            detail=f"sidecar's file field escapes the import root: {sidecar.file!r}",
        )
    if not target.is_file():
        return "error", FileResult(
            path=relative, status="error",
            detail=f"sidecar references a file that doesn't exist: {sidecar.file!r}",
        )
    return "sidecar", (target, sidecar)


def import_folder(job_id: str, sub_path: str = "") -> None:
    """Background task: walk the configured (sub-)folder and import every
    file it recognizes. Never raises out to the caller -- every failure
    mode (bad path, a bad file, a DB error mid-batch) is recorded on the
    job instead, matching the existing retriage_batch()/orchestrator.run()
    convention that one bad item must not abort the whole run."""
    final_status = "completed"
    try:
        root = resolve_import_path(sub_path)
    except LocalImportError as exc:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = "failed"
                _jobs[job_id].finished_at = time.time()
                _jobs[job_id].results.append(
                    FileResult(path=sub_path or ".", status="error", detail=str(exc))
                )
        return

    conn = pgcompat.connect()
    try:
        available_tables = sentinel_table_sync.get_tables_for_gate(conn)
        paths = sorted(p for p in root.rglob("*") if p.is_file())

        # Pass 1: classify every .json/.yaml/.yml file without touching the
        # DB. A sidecar's target file must be imported exactly once, with
        # the sidecar's metadata attached -- resolving every sidecar
        # before pass 2 starts means the walk below never has to guess
        # whether a given file already has (or will have) a sidecar
        # pointing at it.
        json_yaml_results: dict[Path, FileResult] = {}
        sidecar_by_target: dict[Path, ImportSidecar] = {}
        native_export_by_path: dict[Path, tuple[str, dict]] = {}
        skip_in_pass_two: set[Path] = set()  # sidecar files themselves --
                                              # represented by their target's
                                              # result, not their own

        for path in paths:
            if path.suffix.lower() not in (".json", ".yaml", ".yml"):
                continue
            kind, payload = _classify_json_or_yaml(root, path)
            if kind == "error":
                json_yaml_results[path] = payload
            elif kind == "sidecar":
                target, sidecar = payload
                sidecar_by_target[target] = sidecar
                skip_in_pass_two.add(path)
            elif kind == "native_export":
                native_export_by_path[path] = payload
            elif kind == "ignore":
                skip_in_pass_two.add(path)  # silently skipped -- no result at all
            # "sigma" falls through to pass 2 as ordinary content, nothing
            # to precompute -- detect_language() runs there too.

        # json_yaml_results (classification errors) are deliberately not in
        # skip_in_pass_two, so they're already counted here -- pass 2 below
        # still needs to walk them once to surface the recorded error.
        importable = [p for p in paths if p not in skip_in_pass_two]
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].total = len(importable)

        for path in paths:
            if path in skip_in_pass_two:
                continue
            try:
                if path in json_yaml_results:
                    result = json_yaml_results[path]
                elif path in native_export_by_path:
                    kind_val, properties = native_export_by_path[path]
                    result = _import_native_export(conn, root, path, kind_val, properties,
                                                    available_tables)
                else:
                    text = _read_text(path)
                    if text is None:
                        result = FileResult(
                            path=str(path.relative_to(root)), status="error",
                            detail="could not read as UTF-8 text (binary file, or over "
                                   f"{MAX_FILE_BYTES} bytes)",
                        )
                    else:
                        sidecar = sidecar_by_target.get(path)
                        result = _import_content(conn, root, path, text, sidecar, available_tables)
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                logger.exception("import_folder: error on %s", path)
                conn.rollback()
                result = FileResult(path=str(path.relative_to(root)), status="error",
                                    detail=f"unhandled error: {exc}")

            with _jobs_lock:
                if job_id in _jobs:
                    job = _jobs[job_id]
                    job.results.append(result)
                    if result.status == "error":
                        job.failed += 1
                    else:
                        job.completed += 1
                        if result.status == "imported" and result.static_gate_verdict == "reject":
                            job.flagged += 1
    except Exception:
        logger.exception("import_folder: fatal error for job %s", job_id)
        final_status = "failed"
    finally:
        conn.close()
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].status = final_status
                _jobs[job_id].finished_at = time.time()
