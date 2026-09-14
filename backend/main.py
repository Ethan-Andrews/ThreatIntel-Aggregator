from fastapi import FastAPI, Query, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Literal, Optional, List
import logging
import math
import os
import time
from dotenv import load_dotenv

# Must run before any local module import below: auth.py reads
# JWT_SECRET_KEY/AZURE_AD_CLIENT_ID/AZURE_AD_TENANT_ID at module import
# time, so a load_dotenv() call placed after those imports never takes
# effect for values that only exist in .env (not already exported in the
# shell) -- confirmed live: JWT signing/verification silently used ""
# instead of .env's JWT_SECRET_KEY until this was reordered.
load_dotenv()

from pydantic import BaseModel, Field, field_validator, model_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from auth import (
    require_auth, require_admin, validate_entra_token, create_app_token, AuthError,
    AUTH_MODE, verify_local_api_key,
)
from db import (
    init_db, get_entries, count_entries, get_sources, update_source_score,
    seed_sources, apply_triage, get_triage_status,
    get_dashboard_stats, get_mitre_coverage,
    archive_old_entries, purge_archived_entries, get_archive_stats,
    deduplicate_cves, get_enrichment_stats, get_entry_by_hash,
    get_failed_triage,
    get_stack_items, add_stack_item, delete_stack_item,
    get_user_by_oid, upsert_user, list_users, update_user_role, count_active_admins,
    DATE_WINDOW_HOURS,
    DbReadinessError, ensure_db_ready, _connect_db, close_pool,
    get_iocs, count_iocs, get_ioc_by_id, get_ioc_entries,
    delete_ioc, remove_ioc_entry, set_ioc_benign,
    get_entry_group,
    get_runzero_status, get_runzero_matches,
    get_org_exposure,
    get_feed_health,
    get_exposure_summary,
    get_exposure_items,
    get_exposure_metrics,
    patch_exposure_item,
    get_exposure_audit,
    list_active_display_names,
)
from feed_manager import start_scheduler, FEEDS, _triage_entry, triage_pending, retriage_batch, retriage_selected_batch, retriage_failed_batch, create_job, get_job, list_jobs, reextract_iocs_job, poll_single_feed
from enrichment import run_enrichment, refresh_and_reenrich, is_rematch_running, run_stack_rematch

from stack_presets import STACK_PRESETS
from ioc_export import iocs_to_csv, iocs_to_stix_bundle
import runzero_sync
import pgcompat
import time_windows
from detection_pipeline import alignment_reviews as alignment_reviews_db
from detection_pipeline import analytics_catalog
from detection_pipeline import hunts
from detection_pipeline import hunt_sync_settings
from detection_pipeline import sentinel_hunting
from detection_pipeline import sentinel_hunt_queries
from detection_pipeline import sentinel_hunt_sync
from detection_pipeline import sentinel_table_sync
from detection_pipeline import sentinel_hunt_test
from detection_pipeline import sentinel_hunt_tuning
from detection_pipeline import orchestrator_settings
from detection_pipeline import tuning_suggestions
from detection_pipeline import audit_log
from detection_pipeline import sentinel_analytics_rules
from detection_pipeline import sentinel_analytics_rules_sync
from detection_pipeline import sentinel_analytics_rules_tuning
from detection_pipeline import connections_status
from detection_pipeline import local_import

_persist_ok: bool = False

_security_logger = logging.getLogger("security")
logging.basicConfig(level=logging.INFO)

class ScoreUpdate(BaseModel):
    score: int = Field(..., ge=0, le=100)


class TriageRunRequest(BaseModel):
    count: int = Field(20, ge=1, le=500)


class ArchiveRunRequest(BaseModel):
    days: int = Field(90, ge=1, le=3650)


class OrchestratorSettingsUpdate(BaseModel):
    enabled: bool


class OrchestratorScheduleUpdate(BaseModel):
    # Bounded to one week -- matches pg_orchestrator_settings_interval.sql's
    # own CHECK constraint, enforced again here so a bad value 400s before
    # it ever reaches the database.
    interval_minutes: int = Field(..., gt=0, le=10080)
    window_start_minute: int | None = Field(None, ge=0, le=1439)
    window_end_minute: int | None = Field(None, ge=0, le=1439)
    # 0=Sunday..6=Saturday, matching Postgres's own date_part('dow', ...)
    # numbering -- see orchestrator_settings.py's is_due().
    days_of_week: list[int] | None = Field(None, max_length=7)

    @field_validator("days_of_week")
    @classmethod
    def _validate_days_of_week(cls, v):
        if v is not None and any(d < 0 or d > 6 for d in v):
            raise ValueError("days_of_week values must be between 0 (Sunday) and 6 (Saturday)")
        return v

    @model_validator(mode="after")
    def _validate_window(self):
        if (self.window_start_minute is None) != (self.window_end_minute is None):
            raise ValueError("window_start_minute and window_end_minute must be set together")
        return self


class HuntSyncSettingsUpdate(BaseModel):
    mode: Literal["off", "manual", "auto"]
    require_alignment: bool = True


class HuntSyncScheduleUpdate(BaseModel):
    # Same shape as OrchestratorScheduleUpdate -- see hunt_sync_settings.
    # set_schedule()'s own docstring for why the cadence semantics are
    # deliberately identical, not reimplemented.
    severities: list[Literal["critical", "high", "medium", "low"]] | None = Field(None, max_length=4)
    interval_minutes: int = Field(..., gt=0, le=10080)
    window_start_minute: int | None = Field(None, ge=0, le=1439)
    window_end_minute: int | None = Field(None, ge=0, le=1439)
    days_of_week: list[int] | None = Field(None, max_length=7)

    @field_validator("days_of_week")
    @classmethod
    def _validate_days_of_week(cls, v):
        if v is not None and any(d < 0 or d > 6 for d in v):
            raise ValueError("days_of_week values must be between 0 (Sunday) and 6 (Saturday)")
        return v

    @model_validator(mode="after")
    def _validate_window(self):
        if (self.window_start_minute is None) != (self.window_end_minute is None):
            raise ValueError("window_start_minute and window_end_minute must be set together")
        return self


class HuntTargetUpdate(BaseModel):
    # An ARM resource name (GUID) from sentinel_hunting.list_existing_hunts(),
    # or null to go back to the default dedicated-per-hunt sync.
    target_sentinel_hunt_id: str | None = Field(default=None, max_length=200)


class AutoDeployTargetUpdate(BaseModel):
    # Same picker/shape as HuntTargetUpdate, but sets the 'auto' mode's
    # default target (hunt_sync_settings.auto_deploy_target_sentinel_
    # hunt_id) rather than one specific hunt's override -- null means
    # "create a new dedicated hunt per TI article."
    target_sentinel_hunt_id: str | None = Field(default=None, max_length=200)


class TuningSuggestionActionRequest(BaseModel):
    analytic_ids: list[int] = Field(..., min_length=1, max_length=100)


class SentinelHuntQueryReviewRequest(BaseModel):
    review_state: Literal["pending", "approved", "rejected"]


class SentinelAnalyticsRuleReviewRequest(BaseModel):
    review_state: Literal["pending", "approved", "rejected"]


class RetriagedRunRequest(BaseModel):
    count: int = Field(20, ge=1, le=500)
    order: Literal["newest", "oldest"] = "newest"


class RetriagedSelectedRequest(BaseModel):
    hashes: List[str]


class LocalImportRunRequest(BaseModel):
    # Relative to LOCAL_IMPORT_DIR -- "" imports the configured root
    # itself. Validated for real against the filesystem (existence,
    # containment) in local_import.resolve_import_path(), not here; this
    # bound just keeps a pathologically long value from reaching that.
    sub_path: str = Field("", max_length=1000)


class StackItemCreate(BaseModel):
    category: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=200)
    keywords: List[str] = Field(..., min_length=1, max_length=50)

    @field_validator("keywords", mode="before")
    @classmethod
    def validate_keywords(cls, v):
        for kw in v:
            if not isinstance(kw, str) or len(kw) > 100:
                raise ValueError("Each keyword must be a string of 100 characters or fewer")
        return [k.strip() for k in v]


class RoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|viewer)$")


class BenignRequest(BaseModel):
    benign: bool
    reason: str = Field("", max_length=500)


class ExposureItemPatch(BaseModel):
    status:      str | None = None
    notes:       str | None = None
    assigned_to: str | None = None
    unassign:    bool       = False


class AuditAnnotationRequest(BaseModel):
    status: Literal["acknowledged", "not_applicable", "fixed"]
    notes:  str = Field("", max_length=2000)


def run_triage_batches(count: int):
    BATCH_SIZE          = 20
    BETWEEN_BATCH_PAUSE = 2.0
    batches_needed      = math.ceil(count / BATCH_SIZE)
    for i in range(batches_needed):
        triage_pending()
        if i < batches_needed - 1:
            time.sleep(BETWEEN_BATCH_PAUSE)
    if runzero_sync.is_configured():
        try:
            _conn = _connect_db()
            try:
                runzero_sync.run_correlation_pass(_conn)
            finally:
                _conn.close()
        except Exception as _exc:
            _app_logger.warning("Post-triage RunZero correlation failed: %s", _exc)


def bootstrap_runtime():
    """Initialize database, seed sources, and start scheduler; return scheduler or None on failure."""
    global _persist_ok
    _persist_ok = True  # durability is Postgres's job now
    try:
        ensure_db_ready()
        init_db()
        from dedup import backfill_dedup_groups
        _bfconn = _connect_db()
        try:
            backfill_dedup_groups(_bfconn)
        finally:
            _bfconn.close()
        seed_sources(FEEDS)
        if os.environ.get("ENABLE_SCHEDULER", "true").strip().lower() not in ("1", "true", "yes"):
            _app_logger.info("SCHEDULER_DISABLED reason=ENABLE_SCHEDULER")
            return None
        scheduler = start_scheduler()
        # Every test module stubs start_scheduler() to return None (to avoid
        # spinning up real background jobs under pytest) -- guard against that
        # here so a locally-configured RUNZERO_API_TOKEN doesn't crash the
        # whole suite with AttributeError on a None scheduler.
        if scheduler is not None and runzero_sync.is_configured():
            scheduler.add_job(
                runzero_sync.sync_and_correlate,
                "interval",
                hours=6,
                id="runzero_sync",
            )
            _app_logger.info("RunZero sync scheduled every 6 hours (first run in 6 h)")
        else:
            _app_logger.info("RUNZERO_API_TOKEN not set — RunZero sync disabled")
        return scheduler
    except DbReadinessError as e:
        _app_logger.error("DB_READINESS_FAILED", extra={"error": str(e)})
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = bootstrap_runtime()
    app.state.scheduler = scheduler
    yield
    if scheduler is not None:
        scheduler.shutdown()
    close_pool()


_limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="TI Feed Aggregator", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Container probes.
#
# Liveness must not touch the database: a slow query would restart a healthy
# container. Readiness does check the pool, so a replica with no database is
# pulled out of rotation without being killed.
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    """Liveness. No I/O."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Readiness. Verifies a pooled connection can round-trip."""
    try:
        conn = _connect_db()
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
    except Exception as exc:
        _app_logger.warning("READYZ_FAILED error=%s", exc)
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready"}
app.state.limiter = _limiter

_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "PATCH", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Global exception handler (OWASP A10:2025) ────────────────────────────────
_app_logger = logging.getLogger("app")

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded — too many requests"})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    _app_logger.exception("Unhandled exception on %s: %s", request.url.path, exc)
    response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
    # A handler registered for the bare Exception class is dispatched by
    # Starlette's ServerErrorMiddleware, which sits OUTSIDE CORSMiddleware
    # (unlike HTTPException-based errors, which go through the inner
    # ExceptionMiddleware and pick up CORS headers normally) -- so this
    # response never passes back through CORSMiddleware's header injection.
    # Without this, any unhandled backend exception on a cross-origin
    # request (this app's actual deployed topology) shows up in the
    # browser as an opaque, undebuggable CORS failure instead of the real
    # 500 -- confirmed live: a 500 from this handler had no
    # Access-Control-Allow-Origin header while an HTTPException-based 401/404
    # from the same origin did. Set it here explicitly, only for an
    # already-allowed origin.
    origin = request.headers.get("origin")
    if origin in _origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


@app.post("/api/auth/login")
@_limiter.limit("10/minute")
async def auth_login(request: Request):
    """
    Exchange a Microsoft Entra id_token for an app JWT.
    No Bearer auth required — this IS the login endpoint.
    """
    body = await request.json()
    id_token = body.get("id_token", "")
    if not id_token:
        raise HTTPException(status_code=400, detail="id_token required")

    try:
        claims = await validate_entra_token(id_token)
    except AuthError as exc:
        _security_logger.warning(
            "ENTRA_TOKEN_INVALID",
            extra={"code": exc.code, "ip": getattr(request.client, "host", "unknown")},
        )
        raise HTTPException(status_code=401, detail="Invalid identity token")

    entra_oid    = claims.get("oid") or claims.get("sub")
    email        = claims.get("email") or claims.get("preferred_username", "")
    display_name = claims.get("name", email)

    if not entra_oid:
        raise HTTPException(status_code=401, detail="Invalid identity token")

    # Determine role: first user ever → admin; everyone else → viewer
    try:
        existing = get_user_by_oid(entra_oid)
        if existing:
            role = existing["role"]
            if not existing["is_active"]:
                raise HTTPException(status_code=401, detail="Not authenticated")
        else:
            role = "admin" if count_active_admins() == 0 else "viewer"

        upsert_user(entra_oid, email, display_name, role)
    except DbReadinessError:
        _security_logger.warning(
            "AUTH_STORAGE_UNAVAILABLE",
            extra={"ip": getattr(request.client, "host", "unknown")},
        )
        raise HTTPException(status_code=503, detail="Authentication unavailable")
    except Exception as e:
        if "database is locked" in str(e).lower():
            _security_logger.warning(
                "AUTH_STORAGE_LOCKED",
                extra={"ip": getattr(request.client, "host", "unknown")},
            )
            raise HTTPException(status_code=503, detail="Authentication unavailable")
        raise

    app_token = create_app_token(entra_oid, email, display_name, role)
    _security_logger.info("LOGIN_SUCCESS ip=%s oid=%s", getattr(request.client, "host", "unknown"), entra_oid)
    return {"access_token": app_token, "token_type": "bearer"}


@app.get("/api/auth/mode")
def auth_mode():
    """
    Which login flow the frontend should render. No Bearer auth required —
    the frontend needs this before it has a token.
    """
    return {"mode": AUTH_MODE}


@app.post("/api/auth/local-login")
@_limiter.limit("10/minute")
async def auth_local_login(request: Request):
    """
    Exchange the shared LOCAL_API_KEY for an app JWT. Only meaningful when
    AUTH_MODE == "local" (no Entra tenant configured). Anyone with the key
    gets admin access — there is no per-user distinction in local mode.
    """
    if AUTH_MODE != "local":
        raise HTTPException(status_code=404, detail="Not found")

    body = await request.json()
    key = body.get("api_key", "")

    if not verify_local_api_key(key):
        _security_logger.warning(
            "LOCAL_AUTH_FAILURE ip=%s", getattr(request.client, "host", "unknown"),
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    oid, email, display_name, role = "local-admin", "admin@local", "Local Admin", "admin"
    try:
        upsert_user(oid, email, display_name, role)
    except DbReadinessError:
        _security_logger.warning(
            "AUTH_STORAGE_UNAVAILABLE", extra={"ip": getattr(request.client, "host", "unknown")},
        )
        raise HTTPException(status_code=503, detail="Authentication unavailable")

    app_token = create_app_token(oid, email, display_name, role)
    _security_logger.info("LOCAL_LOGIN_SUCCESS ip=%s", getattr(request.client, "host", "unknown"))
    return {"access_token": app_token, "token_type": "bearer"}


@app.get("/api/users", dependencies=[Depends(require_admin)])
def get_users():
    """List all users. Admin only."""
    return {"users": list_users()}


@app.get("/api/users/names")
def get_user_names(auth=Depends(require_auth)):
    """Return display names of all active users. Requires auth (not admin)."""
    return {"names": list_active_display_names()}


@app.patch("/api/users/{oid}/role", dependencies=[Depends(require_admin)])
def patch_user_role(oid: str, body: RoleUpdate):
    """Change a user's role. Admin only. Protects against removing last admin."""
    user = get_user_by_oid(oid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role == "viewer" and user["role"] == "admin":
        if count_active_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    update_user_role(oid, body.role)
    return {"oid": oid, "role": body.role}


_FRONTEND_SORT_MAP = {
    "ingested":  "ingested",
    "published": "published",
    "priority":  "priority_score",
    "source":    "source",
    # "trust" is client-side only — falls back to ingested
}

@app.get("/api/entries", dependencies=[Depends(require_auth)])
def entries(
    source:             List[str]    = Query(default=[]),
    severity:           List[str]    = Query(default=[]),
    tag_category:       List[str]    = Query(default=[]),
    tag_value:          List[str]    = Query(default=[]),
    ttp:                List[str]    = Query(default=[]),
    ioc_category:       List[str]    = Query(default=[]),
    ioc_value:          List[str]    = Query(default=[]),
    search:             Optional[str]= Query(None),
    limit:              int          = Query(100, ge=1, le=500),
    offset:             int          = Query(0, ge=0),
    include_duplicates: bool         = Query(False),
    date_window:        str          = Query("24h"),
    sort_by:            str          = Query("ingested"),
    sort_dir:           str          = Query("desc"),
):
    if len(tag_category) != len(tag_value):
        raise HTTPException(status_code=422,
                            detail="tag_category and tag_value lists must be the same length")
    if len(ioc_category) != len(ioc_value):
        raise HTTPException(status_code=422,
                            detail="ioc_category and ioc_value lists must be the same length")
    if date_window not in DATE_WINDOW_HOURS:
        raise HTTPException(
            status_code=422,
            detail=f"date_window must be one of: {', '.join(DATE_WINDOW_HOURS.keys())}",
        )
    db_sort_by  = _FRONTEND_SORT_MAP.get(sort_by, "ingested")
    db_sort_dir = "asc" if sort_dir == "asc" else "desc"
    tag_filters = list(zip(tag_category, tag_value))
    ioc_filters = list(zip(ioc_category, ioc_value))
    kwargs = dict(
        sources=source, severities=severity,
        tag_filters=tag_filters, ttps=ttp, search=search,
        include_duplicates=include_duplicates,
        ioc_filters=ioc_filters,
        date_window=date_window,
    )
    rows  = get_entries(**kwargs, limit=limit, offset=offset, sort_by=db_sort_by, sort_dir=db_sort_dir)
    total = count_entries(**kwargs)
    if include_duplicates:
        hidden_dupes = 0
    else:
        total_with   = count_entries(**{**kwargs, "include_duplicates": True})
        hidden_dupes = total_with - total
    return {
        "entries":      rows,
        "total":        total,
        "offset":       offset,
        "limit":        limit,
        "hidden_dupes": hidden_dupes,
    }


@app.get("/api/sources", dependencies=[Depends(require_auth)])
def sources():
    return {"sources": get_sources()}


@app.get("/api/triage/status", dependencies=[Depends(require_auth)])
def triage_status():
    return get_triage_status()


@app.post("/api/triage/run", dependencies=[Depends(require_admin)])
@_limiter.limit("5/minute")
def triage_run(request: Request, body: TriageRunRequest, background_tasks: BackgroundTasks):
    status  = get_triage_status()
    pending = status.get("pending", 0)

    if pending == 0:
        return {"status": "nothing_pending", "entries_queued": 0, "batches": 0, "est_seconds": 0}

    effective_count = min(body.count, pending)
    batches_needed  = math.ceil(effective_count / 20)
    est_seconds     = (effective_count * 0.5) + ((batches_needed - 1) * 2)

    background_tasks.add_task(run_triage_batches, effective_count)

    return {
        "status":         "started",
        "entries_queued": effective_count,
        "batches":        batches_needed,
        "est_seconds":    round(est_seconds),
    }


@app.post("/api/retriage/batch", dependencies=[Depends(require_admin)])
@_limiter.limit("5/minute")
def retriage_run(request: Request, body: RetriagedRunRequest, background_tasks: BackgroundTasks):
    status  = get_triage_status()
    triaged = status.get("triaged", 0)
    if triaged == 0:
        raise HTTPException(status_code=422, detail="No triaged entries to retriage")
    effective_count = min(body.count, triaged)
    job_id = create_job(total=effective_count)
    background_tasks.add_task(retriage_batch, job_id, effective_count, body.order)
    return {"job_id": job_id}


@app.post("/api/retriage/failed", dependencies=[Depends(require_admin)])
@_limiter.limit("5/minute")
def retriage_failed_run(request: Request, background_tasks: BackgroundTasks):
    rows = get_failed_triage(batch_size=500)
    if not rows:
        return {"status": "nothing_to_retriage", "count": 0}
    job_id = create_job(total=len(rows))
    background_tasks.add_task(retriage_failed_batch, job_id, rows)
    return {"job_id": job_id, "count": len(rows)}


@app.post("/api/retriage/selected", dependencies=[Depends(require_admin)])
@_limiter.limit("10/minute")
def retriage_selected_endpoint(request: Request, body: RetriagedSelectedRequest, background_tasks: BackgroundTasks):
    if not body.hashes:
        raise HTTPException(status_code=422, detail="No hashes provided")
    hashes = body.hashes[:500]
    job_id = create_job(total=len(hashes))
    background_tasks.add_task(retriage_selected_batch, job_id, hashes)
    return {"job_id": job_id}


@app.get("/api/retriage/jobs/{job_id}", dependencies=[Depends(require_auth)])
def get_retriage_job(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/retriage/jobs", dependencies=[Depends(require_auth)])
def list_retriage_jobs():
    return {"jobs": list_jobs()}


@app.get("/api/detections/local-import/status", dependencies=[Depends(require_auth)])
def local_import_status():
    """Whether LOCAL_IMPORT_DIR is configured at all -- lets the frontend
    render "not configured" rather than a broken import form. Admin-only
    feature (same trust tier as hunt-sync settings/orchestrator on-off),
    but this particular GET is read-only status, not a filesystem read,
    so require_auth (not require_admin) is enough here; the actual import
    trigger below is require_admin."""
    try:
        root = local_import.import_root()
        return {"configured": True, "root": str(root)}
    except local_import.LocalImportError as exc:
        return {"configured": False, "detail": str(exc)}


@app.post("/api/detections/local-import", dependencies=[Depends(require_admin)])
@_limiter.limit("5/minute")
def run_local_import(request: Request, body: LocalImportRunRequest,
                     background_tasks: BackgroundTasks):
    # Fail fast on a bad path before even creating a job -- resolve_import_path()
    # raises the same LocalImportError either way, but there's no reason to
    # hand back a job_id for a job that's guaranteed to fail at its first step.
    try:
        local_import.resolve_import_path(body.sub_path)
    except local_import.LocalImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    job_id = local_import.create_job()
    background_tasks.add_task(local_import.import_folder, job_id, body.sub_path)
    return {"job_id": job_id}


@app.get("/api/detections/local-import/jobs/{job_id}", dependencies=[Depends(require_auth)])
def get_local_import_job(job_id: str):
    job = local_import.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/detections/local-import/jobs", dependencies=[Depends(require_auth)])
def list_local_import_jobs():
    return {"jobs": local_import.list_jobs()}


def _resolve_time_window(
    window: str | None, from_: str | None, to_: str | None,
) -> tuple[str | None, str | None]:
    """Shared by every endpoint that accepts the 1D/7D/30D/90D/All/Custom
    toggle (Dashboard, Audit trend/summary/failures/breakdown, RunZero
    Metrics) -- window=None (the default) means "no window filter," never
    resolved through time_windows at all, so an endpoint with no window
    param supplied behaves exactly as it did before this feature existed.
    """
    if window is None:
        return None, None
    try:
        return time_windows.window_to_range(window, from_, to_)
    except time_windows.InvalidWindowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/dashboard/stats", dependencies=[Depends(require_auth)])
def dashboard_stats(
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
):
    since, until = _resolve_time_window(window, from_, to_)
    return get_dashboard_stats(since=since, until=until)


@app.get("/api/mitre/coverage", dependencies=[Depends(require_auth)])
def mitre_coverage(
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
):
    since, until = _resolve_time_window(window, from_, to_)
    return get_mitre_coverage(since=since, until=until)


@app.patch("/api/sources/{name}/score", dependencies=[Depends(require_admin)])
def set_score(name: str, body: ScoreUpdate):
    all_sources = [s["name"] for s in get_sources()]
    if name not in all_sources:
        raise HTTPException(status_code=404, detail="Source not found")
    update_source_score(name, body.score)
    return {"name": name, "score": body.score}


@app.post("/api/entries/{hash}/retriage", dependencies=[Depends(require_admin)])
@_limiter.limit("20/minute")
def retriage_entry(request: Request, hash: str):
    row = get_entry_by_hash(hash)
    if not row:
        raise HTTPException(status_code=404, detail="Entry not found")
    result = _triage_entry(row["title"] or "", row["summary"] or "")
    apply_triage(
        hash=hash, severity=result["severity"], ttps=result["ttps"],
        ai_summary=result["ai_summary"], tags=result["tags"],
        iocs=result.get("iocs", "{}"),
    )
    return {
        "hash":       hash,
        "severity":   result["severity"],
        "ttps":       result["ttps"],
        "ai_summary": result["ai_summary"],
        "tags":       result["tags"],
        "iocs":       result.get("iocs", "{}"),
    }


@app.get("/api/entries/{entry_hash}/group")
def get_entry_group_endpoint(
    entry_hash: str,
    _auth=Depends(require_auth),
):
    return get_entry_group(entry_hash)


# ── Archive endpoints ─────────────────────────────────────────────────────────

@app.get("/api/archive/stats", dependencies=[Depends(require_auth)])
def archive_stats():
    return get_archive_stats()


@app.post("/api/archive/run", dependencies=[Depends(require_admin)])
def archive_run(body: ArchiveRunRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(archive_old_entries, body.days)
    return {"status": "started", "days": body.days}


@app.post("/api/archive/purge", dependencies=[Depends(require_admin)])
def archive_purge(background_tasks: BackgroundTasks):
    background_tasks.add_task(purge_archived_entries)
    return {"status": "purge_queued"}


@app.post("/api/archive/dedup", dependencies=[Depends(require_admin)])
def archive_dedup(background_tasks: BackgroundTasks):
    """Manually trigger a CVE deduplication pass."""
    background_tasks.add_task(deduplicate_cves)
    return {"status": "dedup_queued"}


# ── Enrichment endpoints ──────────────────────────────────────────────────────

@app.get("/api/enrichment/stats", dependencies=[Depends(require_auth)])
def enrichment_stats():
    return get_enrichment_stats()


@app.post("/api/enrichment/run", dependencies=[Depends(require_admin)])
def enrichment_run(background_tasks: BackgroundTasks):
    """Enrich all un-enriched (or re-triaged) entries with KEV/EPSS/priority scores."""
    background_tasks.add_task(run_enrichment)
    return {"status": "started"}


@app.post("/api/enrichment/kev-refresh", dependencies=[Depends(require_admin)])
def enrichment_kev_refresh(background_tasks: BackgroundTasks):
    """Force a KEV catalog download and full re-enrichment of all active entries."""
    background_tasks.add_task(refresh_and_reenrich)
    return {"status": "started"}


# ── Stack endpoints ───────────────────────────────────────────────────────────

@app.get("/api/stack/categories", dependencies=[Depends(require_auth)])
def stack_categories():
    return STACK_PRESETS


@app.get("/api/stack", dependencies=[Depends(require_auth)])
def stack_list():
    """Return the user's current stack grouped by category."""
    return get_stack_items()


@app.post("/api/stack", dependencies=[Depends(require_admin)])
def stack_add(body: StackItemCreate):
    """Add a vendor/product to the user's stack."""
    try:
        new_id = add_stack_item(body.category, body.name, body.keywords)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"id": new_id, "category": body.category, "name": body.name, "keywords": body.keywords}


@app.delete("/api/stack/{item_id}", dependencies=[Depends(require_admin)])
def stack_delete(item_id: int):
    """Remove a vendor/product from the user's stack."""
    deleted = delete_stack_item(item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Stack item not found")
    return {"deleted": item_id}


@app.post("/api/stack/rematch", dependencies=[Depends(require_admin)])
def stack_rematch(background_tasks: BackgroundTasks):
    """Trigger a background re-evaluation of all feed entries against the current stack."""
    if is_rematch_running():
        return {"status": "already_running"}
    background_tasks.add_task(run_stack_rematch)
    return {"status": "started"}


# ── IOC Ledger ────────────────────────────────────────────────────────────────

_VALID_IOC_TYPES = {
    "ipv4-addr", "domain-name", "url", "file", "vulnerability", "threat-actor"
}
_VALID_IOC_SORTS = {"last_seen", "occurrence_count", "value"}


@app.get("/api/iocs", dependencies=[Depends(require_auth)])
def list_iocs(
    type:           Optional[str] = Query(None),
    search:         Optional[str] = Query(None),
    sort_by:        str           = Query("last_seen"),
    sort_dir:       str           = Query("desc"),
    limit:          int           = Query(100, ge=1, le=500),
    offset:         int           = Query(0, ge=0),
    include_benign: bool          = Query(False),
):
    if type and type not in _VALID_IOC_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid type: {type}")
    if sort_by not in _VALID_IOC_SORTS:
        sort_by = "last_seen"
    db_sort_dir = "asc" if sort_dir == "asc" else "desc"
    rows  = get_iocs(type_filter=type, search=search, sort_by=sort_by,
                     sort_dir=db_sort_dir, limit=limit, offset=offset,
                     include_benign=include_benign)
    total = count_iocs(type_filter=type, search=search, include_benign=include_benign)
    return {"iocs": rows, "total": total}


@app.get("/api/iocs/export", dependencies=[Depends(require_auth)])
def export_iocs(
    ids:    str = Query(..., description="Comma-separated ioc_ledger ids"),
    format: str = Query("csv"),
):
    try:
        id_list = [int(i.strip()) for i in ids.split(",") if i.strip()]
    except ValueError:
        raise HTTPException(status_code=422, detail="ids must be comma-separated integers")
    if not id_list or len(id_list) > 500:
        raise HTTPException(status_code=422, detail="ids must contain 1–500 values")

    rows = []
    for ioc_id in id_list:
        row = get_ioc_by_id(ioc_id)
        if row:
            rows.append(row)

    if format == "stix":
        from fastapi.responses import JSONResponse as _JSONResponse
        bundle = iocs_to_stix_bundle(rows)
        return _JSONResponse(content=bundle, media_type="application/json")

    from fastapi.responses import PlainTextResponse
    csv_data = iocs_to_csv(rows)
    return PlainTextResponse(content=csv_data, media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="iocs.csv"'})


@app.get("/api/iocs/{ioc_id}/entries", dependencies=[Depends(require_auth)])
def ioc_entries(ioc_id: int):
    ioc = get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    rows = get_ioc_entries(ioc_id)
    return {"entries": rows, "total": len(rows)}


@app.post("/api/iocs/reextract", dependencies=[Depends(require_admin)])
def reextract_iocs_endpoint(background_tasks: BackgroundTasks):
    job_id = create_job(0)
    background_tasks.add_task(reextract_iocs_job, job_id)
    return {"job_id": job_id}


@app.delete("/api/iocs/{ioc_id}", dependencies=[Depends(require_admin)])
def delete_ioc_endpoint(ioc_id: int):
    if not delete_ioc(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found")
    return {"deleted": True}


@app.delete("/api/iocs/{ioc_id}/entries/{entry_hash}", dependencies=[Depends(require_admin)])
def remove_ioc_entry_endpoint(ioc_id: int, entry_hash: str):
    if not get_ioc_by_id(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found")
    result = remove_ioc_entry(ioc_id, entry_hash)
    return result


@app.patch("/api/iocs/{ioc_id}/benign", dependencies=[Depends(require_admin)])
def set_ioc_benign_endpoint(ioc_id: int, body: BenignRequest):
    if not get_ioc_by_id(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found")
    set_ioc_benign(ioc_id, body.benign, body.reason)
    return {"benign": body.benign}


# ── RunZero integration endpoints ────────────────────────────────────────────

@app.get("/api/integrations/connections")
def get_connections_status_endpoint(auth=Depends(require_auth)):
    """Sentinel + Defender + RunZero connection/sync status in one call --
    backs the Integrations tab's connector overview cards."""
    conn = pgcompat.connect()
    try:
        return connections_status.get_connections_status(conn)
    finally:
        conn.close()


@app.get("/api/integrations/runzero/status")
def get_runzero_status_endpoint(auth=Depends(require_auth)):
    status = get_runzero_status()
    return status


@app.get("/api/integrations/runzero/matches")
def get_runzero_matches_endpoint(
    confidence: str = None,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    asset_search: str = None,
    org: str = None,
    severity: List[str] = Query(default=[]),
    date_from: str = None,
    date_to: str = None,
    kev_only: bool = False,
    auth=Depends(require_auth),
):
    """asset_search matches the threat intel entry's own title as well as
    asset hostname/org -- searchable by threat intel name, not just asset
    identity. severity/date_from/date_to filter independently, alongside
    the existing confirmed/possible confidence filter. kev_only
    (Workstream G) filters to entries with a confirmed CISA KEV CVE."""
    if limit > 200:
        limit = 200
    total, matches = get_runzero_matches(
        confidence=confidence,
        limit=limit,
        offset=offset,
        asset_search=asset_search,
        org=org,
        severity=severity or None,
        date_from=date_from,
        date_to=date_to,
        kev_only=kev_only,
    )
    return {"total": total, "matches": matches}


@app.get("/api/integrations/runzero/exposure")
def get_org_exposure_endpoint(auth=Depends(require_auth)):
    return {"orgs": get_org_exposure()}


@app.get("/api/feeds/health")
def get_feeds_health_endpoint(auth=Depends(require_auth)):
    return {"feeds": get_feed_health(FEEDS)}


@app.post("/api/feeds/{feed_name}/retry", dependencies=[Depends(require_admin)])
@_limiter.limit("10/minute")
def retry_feed_endpoint(request: Request, feed_name: str):
    """Immediately re-fetch and ingest one feed, outside the normal 30-min
    schedule. Backs the Feed Health "Retry" button so a failing feed can
    be nudged back to healthy without waiting for the next scheduled poll."""
    try:
        result = poll_single_feed(feed_name)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown feed: {feed_name}")
    return result


@app.post("/api/integrations/runzero/sync")
@_limiter.limit("1/minute")
def trigger_runzero_sync(
    request: Request,
    background_tasks: BackgroundTasks,
    auth=Depends(require_admin),
):
    if not runzero_sync.is_configured():
        raise HTTPException(status_code=400, detail="RunZero not configured")
    background_tasks.add_task(runzero_sync.sync_and_correlate)
    return {"status": "started"}


@app.get("/api/health")
def health():
    return {"status": "ok", "persistence": "ok" if _persist_ok else "unavailable"}


# ── Exposure Remediation Tracking ────────────────────────────────────────────

@app.get("/api/exposure/summary")
def exposure_summary(auth=Depends(require_auth)):
    return {"orgs": get_exposure_summary()}


@app.get("/api/exposure/metrics")
def exposure_metrics(
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
    org: str | None = None,
    auth=Depends(require_auth),
):
    since, until = _resolve_time_window(window, from_, to_)
    return get_exposure_metrics(since=since, until=until, org=org)


@app.get("/api/exposure/items")
def exposure_items(
    org: str,
    status: str = "active",
    limit: int = 50,
    offset: int = Query(0, ge=0),
    kev_only: bool = False,
    auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    result = get_exposure_items(org=org, status=status, limit=limit, offset=offset, kev_only=kev_only)
    return result


@app.patch("/api/exposure/items/{item_id}")
def patch_exposure(
    item_id: int,
    body: ExposureItemPatch,
    request: Request,
    auth=Depends(require_auth),
):
    actor = request.state.user.get("name", "api")
    assigned_to = None if body.unassign else (... if body.assigned_to is None else body.assigned_to)
    try:
        updated = patch_exposure_item(
            item_id,
            actor=actor,
            status=body.status,
            notes=body.notes,
            assigned_to=assigned_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return updated


@app.get("/api/exposure/items/{item_id}/audit")
def exposure_audit(item_id: int, auth=Depends(require_auth)):
    return {"log": get_exposure_audit(item_id)}


# ── Detections: general analytics catalog + stage 9 disposition alerts ──────

_VALID_DETECTION_TYPES_CATALOG = {"sentinel", "mde", "unbounded"}
_VALID_DETECTION_TYPES_WITH_HUNT = {"sentinel", "mde", "unbounded", "hunt"}
_VALID_BACKTEST_DISPOSITIONS = {"clean", "tunable", "needs_tuning", "backtest_error"}


@app.get("/api/detections")
def list_detections_endpoint(
    technique_id: str | None = None,
    disposition: str | None = None,
    review_state: str | None = None,
    detection_type: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    auth=Depends(require_auth),
):
    """General, read-only listing of every registered analytic -- not just
    the alignment_reviews subset /api/detections/alignment/* serves.
    detection_type: 'sentinel' (Analytics Rule) | 'mde' (Defender custom
    detection) | 'unbounded' -- 'hunt' is deliberately not valid here,
    unlike the alignment/disposition endpoints below, since this tab has
    no "include hunts as a category" ask. search: case-insensitive
    substring match on technique_id OR the stored detection name."""
    if limit > 200:
        limit = 200
    if disposition and disposition not in _VALID_BACKTEST_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="invalid disposition")
    if review_state and review_state not in {"pending", "approved", "rejected"}:
        raise HTTPException(status_code=400, detail="invalid review_state")
    if detection_type and detection_type not in _VALID_DETECTION_TYPES_CATALOG:
        raise HTTPException(status_code=400, detail="invalid detection_type")
    conn = pgcompat.connect()
    try:
        return analytics_catalog.list_analytics(
            conn, technique_id=technique_id, disposition=disposition,
            review_state=review_state, detection_type=detection_type,
            search=search, limit=limit, offset=offset,
        )
    finally:
        conn.close()


@app.get("/api/detections/disposition-alerts")
def disposition_alerts_endpoint(
    detection_type: str | None = None,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    auth=Depends(require_auth),
):
    """Stage 9's surfacing queue -- previously-clean analytics that started
    firing or lost their telemetry, most recently checked first."""
    if limit > 200:
        limit = 200
    if detection_type and detection_type not in _VALID_DETECTION_TYPES_WITH_HUNT:
        raise HTTPException(status_code=400, detail="invalid detection_type")
    conn = pgcompat.connect()
    try:
        return analytics_catalog.get_disposition_alerts(
            conn, detection_type=detection_type, limit=limit, offset=offset,
        )
    finally:
        conn.close()


@app.get("/api/detections/hunts")
def list_hunts_endpoint(
    technique_id: str | None = None,
    ready_only: bool = False,
    search: str | None = None,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    auth=Depends(require_auth),
):
    """Hunts -- one per originating TI article/detections.ai project,
    grouping every detection/query generated from it. Mirrors Microsoft
    Sentinel's own Hunts container concept (see hunts.py's module
    docstring); each row here can additionally be synced into a real
    Sentinel Hunt once SENTINEL_HUNTING_SYNC_ENABLED is on (see
    sentinel_hunting.py). ready_only=true restricts to hunts with at least
    one detection that already passed the static gate and backtest (the
    same bar the manual Deploy action uses). search: case-insensitive
    substring match on the hunt's own title."""
    if limit > 200:
        limit = 200
    conn = pgcompat.connect()
    try:
        return hunts.list_hunts(conn, technique_id=technique_id, ready_only=ready_only,
                                search=search, limit=limit, offset=offset)
    finally:
        conn.close()


@app.get("/api/detections/hunts/sentinel-targets")
def list_sentinel_hunt_targets_endpoint(auth=Depends(require_admin)):
    """Existing Sentinel Hunts in the workspace, for the "deploy into an
    existing hunt" picker (e.g. an analyst's own "In the News V2") -- see
    sentinel_hunting.list_existing_hunts()'s docstring for the never-raise
    contract this relies on.

    Registered before GET /api/detections/hunts/{hunt_id} deliberately --
    Starlette matches routes in registration order, and "sentinel-targets"
    parsed as {hunt_id}: int 422s instead of ever reaching this route if
    that one comes first (confirmed while writing this endpoint's own
    tests)."""
    return sentinel_hunting.list_existing_hunts()


@app.get("/api/detections/hunts/{hunt_id}")
def get_hunt_detail_endpoint(hunt_id: int, auth=Depends(require_auth)):
    """Drill-down: one hunt plus every detection/query registered under it."""
    conn = pgcompat.connect()
    try:
        detail = hunts.get_hunt_detail(conn, hunt_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="hunt not found")
        return detail
    finally:
        conn.close()


@app.post("/api/detections/hunts/{hunt_id}/deploy")
def deploy_hunt_endpoint(hunt_id: int, auth=Depends(require_admin)):
    """Manually push one hunt's already-validated detections into Sentinel.

    Only allowed when hunt_sync_settings.mode is 'manual' or 'auto' -- 'off'
    (the default) means Sentinel is never touched, automatically or by
    hand. Always uses require_alignment=False for the eligibility filter: a
    human is reviewing the hunt in the UI before clicking this, so alignment
    status is informative context for them rather than a hard gate (unlike
    the 'auto' mode's automatic sync, which has no human in the loop)."""
    conn = pgcompat.connect()
    try:
        hunt = hunts.get_hunt_detail(conn, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail="hunt not found")

        settings = hunt_sync_settings.get_settings(conn)
        if settings["mode"] == "off":
            raise HTTPException(
                status_code=400,
                detail="Hunt Sentinel sync is off -- enable manual or auto mode in Settings first.",
            )

        eligible = hunts.get_sync_eligible_detections(conn, hunt_id, require_alignment=False)
        if not eligible:
            raise HTTPException(
                status_code=400,
                detail="No detections in this hunt have passed both the static gate and backtest yet.",
            )

        sentinel_hunting.sync_hunt(
            conn, hunt_id, hunt_title=hunt["title"] or hunt["source_title"] or "",
            hunt_description=hunt["description"] or "", detections=eligible,
            target_sentinel_hunt_id=hunt.get("target_sentinel_hunt_id"),
        )
        return hunts.get_hunt_detail(conn, hunt_id)
    finally:
        conn.close()


@app.patch("/api/detections/hunts/{hunt_id}/target")
def set_hunt_target_endpoint(hunt_id: int, body: HuntTargetUpdate, auth=Depends(require_admin)):
    """Point a hunt at an existing Sentinel Hunt (target_sentinel_hunt_id
    non-null) or back to the default dedicated-per-hunt sync (null) --
    takes effect on the next Deploy/Deploy All for this hunt, doesn't
    itself talk to Sentinel."""
    conn = pgcompat.connect()
    try:
        hunt = hunts.get_hunt_detail(conn, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail="hunt not found")
        hunts.set_hunt_target(conn, hunt_id, body.target_sentinel_hunt_id)
        return hunts.get_hunt_detail(conn, hunt_id)
    finally:
        conn.close()


@app.post("/api/detections/hunts/deploy-all")
def deploy_all_hunts_endpoint(auth=Depends(require_admin)):
    """Bulk "Deploy All" for Generated Hunts: pushes every hunt that's
    never been synced to Sentinel, plus every hunt that needs a resync (its
    last sync attempt failed, or a detection was added since its last
    successful sync) -- see hunts.list_hunts_needing_deploy() for the exact
    eligibility query. Needed in every hunt_sync_settings.mode: 'auto'
    mode's own cadence only ever covers hunts going forward, so a hunt that
    existed before 'auto' was turned on (or was created while sync was
    'off'/'manual') still needs a one-time manual catch-up.

    Same 'off' mode gate as the single-hunt deploy endpoint above. Never
    404s and never fails the whole batch on one bad hunt -- see
    sentinel_hunting.deploy_all_hunts()'s per-hunt isolation."""
    conn = pgcompat.connect()
    try:
        settings = hunt_sync_settings.get_settings(conn)
        if settings["mode"] == "off":
            raise HTTPException(
                status_code=400,
                detail="Hunt Sentinel sync is off -- enable manual or auto mode in Settings first.",
            )
        return sentinel_hunting.deploy_all_hunts(conn)
    finally:
        conn.close()


# ── Tuning suggestions: apply/dismiss stage-7's proposed narrowed KQL ───────
# Shared by both the Hunts view and the flat Detections/Analytics-Rules
# catalog -- they render the same `analytics` rows, just grouped
# differently, so one pair of endpoints (accepting a list of one or more
# analytic_ids) covers both the single-row and multi-select batch cases in
# both panels. See tuning_suggestions.py/tuning_actions.py.

@app.post("/api/detections/tuning-suggestions/apply")
def apply_tuning_suggestions_endpoint(
    body: TuningSuggestionActionRequest, request: Request, auth=Depends(require_admin),
):
    """Push each id's tune.py-proposed KQL to its analytic's Sentinel saved
    search, re-sending every attribute (never a partial PUT). A batch is
    never all-or-nothing: each id's outcome is independent, and every
    attempted push -- success or failure -- is recorded in
    tuning_suggestion_actions regardless of how the rest of the batch goes."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return {"results": tuning_suggestions.apply_suggestions(
            conn, body.analytic_ids, performed_by=performed_by,
        )}
    finally:
        conn.close()


@app.post("/api/detections/tuning-suggestions/dismiss")
def dismiss_tuning_suggestions_endpoint(
    body: TuningSuggestionActionRequest, request: Request, auth=Depends(require_admin),
):
    """Record "reviewed, not applying" for each id -- distinguishes "never
    looked at" (no row at all) from "looked at, declined" in the audit
    trail. Never touches Sentinel."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return {"results": tuning_suggestions.dismiss_suggestions(
            conn, body.analytic_ids, performed_by=performed_by,
        )}
    finally:
        conn.close()


# ── Sentinel-native hunt/query inventory ────────────────────────────────────
# The actual hunts and stored hunting queries that already exist in the
# Sentinel workspace (pulled read-only by sentinel_hunt_sync.py), as opposed
# to `hunts`/HuntsPanel.js above, which is this app's own AI-generated
# detections grouped by originating TI article. Some hunts carry 800+
# queries, so both list endpoints below are paginated -- see
# docs/superpowers/specs/2026-09-01-sentinel-hunt-inventory-design.md.

@app.get("/api/sentinel-hunts")
def list_sentinel_hunts_endpoint(
    limit: int = 50, offset: int = Query(0, ge=0), search: str | None = None,
    auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    conn = pgcompat.connect()
    try:
        return sentinel_hunt_queries.list_sentinel_hunts(conn, limit=limit, offset=offset, search=search)
    finally:
        conn.close()


@app.get("/api/sentinel-hunts/{hunt_id}")
def get_sentinel_hunt_endpoint(hunt_id: int, auth=Depends(require_auth)):
    """Hunt metadata only -- see get_sentinel_hunt_queries_endpoint for its
    (paginated) query list."""
    conn = pgcompat.connect()
    try:
        hunt = sentinel_hunt_queries.get_sentinel_hunt(conn, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail="sentinel hunt not found")
        return hunt
    finally:
        conn.close()


@app.get("/api/sentinel-hunts/{hunt_id}/queries")
def list_sentinel_hunt_queries_endpoint(
    hunt_id: int, limit: int = 50, offset: int = Query(0, ge=0),
    review_state: str | None = None, disposition: str | None = None,
    search: str | None = None, auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    if disposition and disposition not in _VALID_BACKTEST_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="invalid disposition")
    conn = pgcompat.connect()
    try:
        if sentinel_hunt_queries.get_sentinel_hunt(conn, hunt_id) is None:
            raise HTTPException(status_code=404, detail="sentinel hunt not found")
        return sentinel_hunt_queries.list_hunt_queries(
            conn, hunt_id, limit=limit, offset=offset, review_state=review_state,
            disposition=disposition, search=search,
        )
    finally:
        conn.close()


@app.get("/api/sentinel-hunts/queries/{query_id}")
def get_sentinel_hunt_query_endpoint(query_id: int, auth=Depends(require_auth)):
    """One query's full detail, including kql_body and every pipeline
    result -- the drill-down behind expanding a row in the paginated list."""
    conn = pgcompat.connect()
    try:
        query = sentinel_hunt_queries.get_query_detail(conn, query_id)
        if query is None:
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")
        return query
    finally:
        conn.close()


@app.post("/api/sentinel-hunts/sync")
def sync_sentinel_hunts_endpoint(auth=Depends(require_admin)):
    """Pull every hunt and every hunt's queries from the Sentinel workspace
    into sentinel_hunts/sentinel_hunt_queries. A no-op result (enabled=false)
    means SENTINEL_HUNTING_SYNC_ENABLED isn't on -- same gate
    sentinel_hunting.py's write path already uses, reused here rather than
    adding a second flag."""
    conn = pgcompat.connect()
    try:
        return sentinel_hunt_sync.sync_all(conn)
    finally:
        conn.close()


@app.post("/api/settings/sentinel-tables/sync")
def sync_sentinel_tables_endpoint(auth=Depends(require_admin)):
    """Admin-triggered refresh of the cached Sentinel/MDE table catalog
    static_gate.py's table-recognition check consults (sentinel_table_sync.
    get_cached_tables()) -- an inventory pull, not part of the automatic
    per-candidate pipeline, same shape as the Sentinel Hunts sync above. A
    no-op result (enabled=false) means SENTINEL_HUNTING_SYNC_ENABLED isn't
    on, the same gate every other ARM-calling sync in this app uses."""
    conn = pgcompat.connect()
    try:
        return sentinel_table_sync.sync_all(conn)
    finally:
        conn.close()


@app.post("/api/sentinel-hunts/queries/{query_id}/test")
def test_sentinel_hunt_query_endpoint(query_id: int, auth=Depends(require_admin)):
    """Stages 6-8 (static gate, control probe, backtest) against this one
    query's stored KQL, same as orchestrator.py runs for AI-generated
    detections. Persists the result regardless of outcome, including a
    gate rejection or a missing Sentinel client, so the UI can show exactly
    why a query didn't clear rather than just a generic failure."""
    conn = pgcompat.connect()
    try:
        query = sentinel_hunt_queries.get_query_detail(conn, query_id)
        if query is None:
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")

        sentinel_client = sentinel_hunt_test.build_sentinel_client()
        try:
            result = sentinel_hunt_test.run_query_check(
                sentinel_client, query["kql_body"],
                artifact_id=query["sentinel_saved_search_id"], title=query["display_name"],
                available_tables=sentinel_table_sync.get_tables_for_gate(conn),
            )
        finally:
            if sentinel_client is not None:
                sentinel_client.close()

        control_probe_result = {
            "gate_verdict": result.gate_verdict,
            "gate_findings": result.gate_findings,
            "backtest_hits": result.backtest_hits,
            **(result.control_probe_result or {}),
        }
        if result.error:
            control_probe_result["error"] = result.error
        sentinel_hunt_queries.record_query_test_result(
            conn, query_id, control_probe_result, result.backtest_disposition,
        )
        return sentinel_hunt_queries.get_query_detail(conn, query_id)
    finally:
        conn.close()


@app.post("/api/sentinel-hunts/queries/{query_id}/tune")
def tune_sentinel_hunt_query_endpoint(query_id: int, auth=Depends(require_admin)):
    """Stage 9: bounded narrowing loop. Only meaningful after a /test call
    already reported backtest_disposition == 'needs_tuning' -- returns 400
    otherwise rather than silently no-op'ing, since running it against a
    query that hasn't been tested yet (or was already clean) wastes
    Sentinel query budget for no usable result."""
    conn = pgcompat.connect()
    try:
        query = sentinel_hunt_queries.get_query_detail(conn, query_id)
        if query is None:
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")
        if query["backtest_disposition"] != "needs_tuning":
            raise HTTPException(
                status_code=400,
                detail="Run /test first; tuning only applies to a query whose "
                       "backtest reported needs_tuning.",
            )

        sentinel_client = sentinel_hunt_test.build_sentinel_client()
        if sentinel_client is None:
            raise HTTPException(status_code=400, detail="No Sentinel client configured.")
        try:
            control_result = query["control_probe_result"] or {}
            backtest_hits = control_result.get("backtest_hits")
            tune_history = sentinel_hunt_test.run_query_tune(
                sentinel_client, query["kql_body"],
                artifact_id=query["sentinel_saved_search_id"], title=query["display_name"],
                backtest_hits=backtest_hits or 0, control_probe_result=control_result,
            )
        finally:
            sentinel_client.close()

        if tune_history is None:
            raise HTTPException(
                status_code=400,
                detail="No probed table available to narrow against -- re-run /test first.",
            )
        sentinel_hunt_queries.record_query_tune_result(conn, query_id, tune_history)
        return sentinel_hunt_queries.get_query_detail(conn, query_id)
    finally:
        conn.close()


@app.post("/api/sentinel-hunts/queries/{query_id}/tuning-suggestion/apply")
def apply_sentinel_hunt_query_tune_suggestion_endpoint(
    query_id: int, request: Request, auth=Depends(require_admin),
):
    """Push this query's stage-9 tune suggestion (tune_history.final_body)
    back to the exact Sentinel saved search it was synced from -- see
    sentinel_hunt_tuning.py for why this is simpler than the equivalent
    for AI-generated detections."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        result = sentinel_hunt_tuning.apply_query_tune_suggestion(conn, query_id, performed_by)
        if not result["success"] and result["reason"] == "query not found":
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")
        return {"result": result, "query": sentinel_hunt_queries.get_query_detail(conn, query_id)}
    finally:
        conn.close()


@app.post("/api/sentinel-hunts/queries/{query_id}/tuning-suggestion/dismiss")
def dismiss_sentinel_hunt_query_tune_suggestion_endpoint(
    query_id: int, request: Request, auth=Depends(require_admin),
):
    """Record "reviewed, not applying" -- never touches Sentinel."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        result = sentinel_hunt_tuning.dismiss_query_tune_suggestion(conn, query_id, performed_by)
        if not result["success"] and result["reason"] == "query not found":
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")
        return {"result": result, "query": sentinel_hunt_queries.get_query_detail(conn, query_id)}
    finally:
        conn.close()


@app.patch("/api/sentinel-hunts/queries/{query_id}/review")
def review_sentinel_hunt_query_endpoint(
    query_id: int, body: SentinelHuntQueryReviewRequest, auth=Depends(require_admin),
):
    conn = pgcompat.connect()
    try:
        ok = sentinel_hunt_queries.set_query_review_state(conn, query_id, body.review_state)
        if not ok:
            raise HTTPException(status_code=404, detail="sentinel hunt query not found")
        return sentinel_hunt_queries.get_query_detail(conn, query_id)
    finally:
        conn.close()


# ── Sentinel Analytics Rules (read-only inventory + same test/tune pipeline) ─

@app.get("/api/sentinel-analytics-rules")
def list_sentinel_analytics_rules_endpoint(
    limit: int = 50, offset: int = Query(0, ge=0),
    review_state: str | None = None, disposition: str | None = None,
    search: str | None = None, auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    if disposition and disposition not in _VALID_BACKTEST_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="invalid disposition")
    conn = pgcompat.connect()
    try:
        return sentinel_analytics_rules.list_analytics_rules(
            conn, limit=limit, offset=offset, review_state=review_state,
            disposition=disposition, search=search,
        )
    finally:
        conn.close()


@app.get("/api/sentinel-analytics-rules/{rule_id}")
def get_sentinel_analytics_rule_endpoint(rule_id: int, auth=Depends(require_auth)):
    conn = pgcompat.connect()
    try:
        rule = sentinel_analytics_rules.get_rule_detail(conn, rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")
        return rule
    finally:
        conn.close()


@app.post("/api/sentinel-analytics-rules/sync")
def sync_sentinel_analytics_rules_endpoint(auth=Depends(require_admin)):
    """Pull every Scheduled analytics rule from the Sentinel workspace into
    sentinel_analytics_rules. A no-op result (enabled=false) means
    SENTINEL_HUNTING_SYNC_ENABLED isn't on -- same gate every other
    Sentinel ARM sync in this app uses."""
    conn = pgcompat.connect()
    try:
        return sentinel_analytics_rules_sync.sync_all(conn)
    finally:
        conn.close()


@app.post("/api/sentinel-analytics-rules/{rule_id}/test")
def test_sentinel_analytics_rule_endpoint(rule_id: int, auth=Depends(require_admin)):
    """Stages 6-8 (static gate, control probe, backtest) against this
    rule's stored KQL -- the exact same sentinel_hunt_test.py sequence
    Sentinel Hunts queries and AI-generated detections both already run,
    since run_query_check() is generic over kql/title/artifact_id, not
    hunt-specific."""
    conn = pgcompat.connect()
    try:
        rule = sentinel_analytics_rules.get_rule_detail(conn, rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")

        sentinel_client = sentinel_hunt_test.build_sentinel_client()
        try:
            result = sentinel_hunt_test.run_query_check(
                sentinel_client, rule["kql_body"],
                artifact_id=rule["sentinel_rule_id"], title=rule["display_name"],
                available_tables=sentinel_table_sync.get_tables_for_gate(conn),
            )
        finally:
            if sentinel_client is not None:
                sentinel_client.close()

        control_probe_result = {
            "gate_verdict": result.gate_verdict,
            "gate_findings": result.gate_findings,
            "backtest_hits": result.backtest_hits,
            **(result.control_probe_result or {}),
        }
        if result.error:
            control_probe_result["error"] = result.error
        sentinel_analytics_rules.record_rule_test_result(
            conn, rule_id, control_probe_result, result.backtest_disposition,
        )
        return sentinel_analytics_rules.get_rule_detail(conn, rule_id)
    finally:
        conn.close()


@app.post("/api/sentinel-analytics-rules/{rule_id}/tune")
def tune_sentinel_analytics_rule_endpoint(rule_id: int, auth=Depends(require_admin)):
    conn = pgcompat.connect()
    try:
        rule = sentinel_analytics_rules.get_rule_detail(conn, rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")
        if rule["backtest_disposition"] != "needs_tuning":
            raise HTTPException(
                status_code=400,
                detail="Run /test first; tuning only applies to a rule whose "
                       "backtest reported needs_tuning.",
            )

        sentinel_client = sentinel_hunt_test.build_sentinel_client()
        if sentinel_client is None:
            raise HTTPException(status_code=400, detail="No Sentinel client configured.")
        try:
            control_result = rule["control_probe_result"] or {}
            backtest_hits = control_result.get("backtest_hits")
            tune_history = sentinel_hunt_test.run_query_tune(
                sentinel_client, rule["kql_body"],
                artifact_id=rule["sentinel_rule_id"], title=rule["display_name"],
                backtest_hits=backtest_hits or 0, control_probe_result=control_result,
            )
        finally:
            sentinel_client.close()

        if tune_history is None:
            raise HTTPException(
                status_code=400,
                detail="No probed table available to narrow against -- re-run /test first.",
            )
        sentinel_analytics_rules.record_rule_tune_result(conn, rule_id, tune_history)
        return sentinel_analytics_rules.get_rule_detail(conn, rule_id)
    finally:
        conn.close()


@app.post("/api/sentinel-analytics-rules/{rule_id}/tuning-suggestion/apply")
def apply_sentinel_analytics_rule_tune_suggestion_endpoint(
    rule_id: int, request: Request, auth=Depends(require_admin),
):
    """Push this rule's stage-9 tune suggestion (tune_history.final_body)
    back to the live Sentinel alert rule via a read-modify-write -- see
    sentinel_analytics_rules_tuning.py for why this can't just re-PUT a
    locally-reconstructed body the way Sentinel Hunts queries can."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        result = sentinel_analytics_rules_tuning.apply_rule_tune_suggestion(conn, rule_id, performed_by)
        if not result["success"] and result["reason"] == "rule not found":
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")
        return {"result": result, "rule": sentinel_analytics_rules.get_rule_detail(conn, rule_id)}
    finally:
        conn.close()


@app.post("/api/sentinel-analytics-rules/{rule_id}/tuning-suggestion/dismiss")
def dismiss_sentinel_analytics_rule_tune_suggestion_endpoint(
    rule_id: int, request: Request, auth=Depends(require_admin),
):
    """Record "reviewed, not applying" -- never touches Sentinel."""
    performed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        result = sentinel_analytics_rules_tuning.dismiss_rule_tune_suggestion(conn, rule_id, performed_by)
        if not result["success"] and result["reason"] == "rule not found":
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")
        return {"result": result, "rule": sentinel_analytics_rules.get_rule_detail(conn, rule_id)}
    finally:
        conn.close()


@app.patch("/api/sentinel-analytics-rules/{rule_id}/review")
def review_sentinel_analytics_rule_endpoint(
    rule_id: int, body: SentinelAnalyticsRuleReviewRequest, auth=Depends(require_admin),
):
    conn = pgcompat.connect()
    try:
        ok = sentinel_analytics_rules.set_rule_review_state(conn, rule_id, body.review_state)
        if not ok:
            raise HTTPException(status_code=404, detail="sentinel analytics rule not found")
        return sentinel_analytics_rules.get_rule_detail(conn, rule_id)
    finally:
        conn.close()


# ── Audit (admin-only, all pipeline check outcomes) ─────────────────────────

_VALID_AUDIT_STATUS_FILTERS = {"unannotated", "acknowledged", "not_applicable", "fixed", "all"}
_VALID_AUDIT_SOURCES = {"detection", "hunt_sync", "sentinel_query", "analytics_rule"}




@app.get("/api/audit/summary", dependencies=[Depends(require_admin)])
def audit_summary_endpoint(
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
):
    since, until = _resolve_time_window(window, from_, to_)
    conn = pgcompat.connect()
    try:
        return audit_log.get_audit_summary(conn, since=since, until=until)
    finally:
        conn.close()


@app.get("/api/audit/failures", dependencies=[Depends(require_admin)])
def audit_failures_endpoint(
    outcome: str | None = None, category: str | None = None, status: str | None = None,
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
    limit: int = 50, offset: int = Query(0, ge=0),
):
    if outcome not in ("failing", "passing"):
        outcome = None
    if status is not None and status not in _VALID_AUDIT_STATUS_FILTERS:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(_VALID_AUDIT_STATUS_FILTERS)}",
        )
    since, until = _resolve_time_window(window, from_, to_)
    if limit > 200:
        limit = 200
    conn = pgcompat.connect()
    try:
        return audit_log.list_audit_entries(
            conn, outcome=outcome, category=category, status=status,
            since=since, until=until, limit=limit, offset=offset,
        )
    finally:
        conn.close()


@app.get("/api/audit/failure-breakdown", dependencies=[Depends(require_admin)])
def audit_failure_breakdown_endpoint(
    window: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
):
    since, until = _resolve_time_window(window, from_, to_)
    conn = pgcompat.connect()
    try:
        return {"categories": audit_log.get_audit_failure_breakdown(conn, since=since, until=until)}
    finally:
        conn.close()


@app.get("/api/audit/trend", dependencies=[Depends(require_admin)])
def audit_trend_endpoint(
    window: str = "30d",
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
    bucket: str | None = None,
):
    since, until = _resolve_time_window(window, from_, to_)
    if bucket not in ("day", "week", None):
        raise HTTPException(status_code=400, detail="bucket must be 'day' or 'week'")
    conn = pgcompat.connect()
    try:
        return {"trend": audit_log.get_audit_trend(conn, since=since, until=until, bucket=bucket)}
    finally:
        conn.close()


@app.patch("/api/audit/{source}/{source_id}")
def annotate_audit_entry_endpoint(
    source: str, source_id: int, body: AuditAnnotationRequest,
    request: Request, auth=Depends(require_admin),
):
    if source not in _VALID_AUDIT_SOURCES:
        raise HTTPException(
            status_code=400, detail=f"source must be one of {sorted(_VALID_AUDIT_SOURCES)}",
        )
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return audit_log.record_annotation(
            conn, source, source_id, body.status, body.notes, updated_by,
        )
    finally:
        conn.close()


@app.delete("/api/audit/{source}/{source_id}")
def clear_audit_annotation_endpoint(
    source: str, source_id: int, auth=Depends(require_admin),
):
    if source not in _VALID_AUDIT_SOURCES:
        raise HTTPException(
            status_code=400, detail=f"source must be one of {sorted(_VALID_AUDIT_SOURCES)}",
        )
    conn = pgcompat.connect()
    try:
        audit_log.clear_annotation(conn, source, source_id)
        return {"cleared": True}
    finally:
        conn.close()


# ── Orchestrator settings ────────────────────────────────────────────────────
# Soft on/off switch for job-tiagg-orchestrator (the Container Apps Job that
# runs detection_pipeline/orchestrator.py). Does NOT change Azure's own
# schedule trigger -- see pg_orchestrator_settings.sql for why.

@app.get("/api/settings/orchestrator")
def get_orchestrator_settings_endpoint(auth=Depends(require_admin)):
    conn = pgcompat.connect()
    try:
        return orchestrator_settings.get_settings(conn)
    finally:
        conn.close()


@app.patch("/api/settings/orchestrator")
def update_orchestrator_settings_endpoint(
    body: OrchestratorSettingsUpdate, request: Request, auth=Depends(require_admin),
):
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return orchestrator_settings.set_enabled(conn, body.enabled, updated_by)
    finally:
        conn.close()


@app.patch("/api/settings/orchestrator/schedule")
def update_orchestrator_schedule_endpoint(
    body: OrchestratorScheduleUpdate, request: Request, auth=Depends(require_admin),
):
    """Admin-configurable run interval/daily-window/day-of-week, layered on
    top of the plain enabled/disabled switch above. See orchestrator_
    settings.py's is_due() and pg_orchestrator_settings_interval.sql for
    why this can only ever lengthen the effective interval beyond Azure's
    own outer cron, never shorten it."""
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return orchestrator_settings.set_interval(
            conn,
            interval_minutes=body.interval_minutes,
            window_start_minute=body.window_start_minute,
            window_end_minute=body.window_end_minute,
            days_of_week=body.days_of_week,
            updated_by=updated_by,
        )
    finally:
        conn.close()


# ── Hunt Sentinel sync settings ──────────────────────────────────────────────
# Controls whether/how generated hunts get pushed into a real Microsoft
# Sentinel workspace -- 'off' (default, nothing touches Sentinel), 'manual'
# (a human clicks Deploy per hunt), or 'auto' (orchestrator.py pushes
# eligible detections automatically). See pg_hunt_sync_settings.sql.

@app.get("/api/settings/hunt-sync")
def get_hunt_sync_settings_endpoint(auth=Depends(require_admin)):
    conn = pgcompat.connect()
    try:
        return hunt_sync_settings.get_settings(conn)
    finally:
        conn.close()


@app.patch("/api/settings/hunt-sync")
def update_hunt_sync_settings_endpoint(
    body: HuntSyncSettingsUpdate, request: Request, auth=Depends(require_admin),
):
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return hunt_sync_settings.set_settings(conn, body.mode, body.require_alignment, updated_by)
    finally:
        conn.close()


@app.patch("/api/settings/hunt-sync/schedule")
def update_hunt_sync_schedule_endpoint(
    body: HuntSyncScheduleUpdate, request: Request, auth=Depends(require_admin),
):
    """Admin-configurable severity gate + interval/daily-window/day-of-week
    cadence for the 'auto' mode's automatic push -- layered on top of the
    plain mode/require_alignment switch above, mirroring /api/settings/
    orchestrator/schedule's shape exactly (kept as a separate endpoint for
    the same reason: avoids mixed required/optional fields on one PATCH)."""
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return hunt_sync_settings.set_schedule(
            conn,
            severities=body.severities,
            interval_minutes=body.interval_minutes,
            window_start_minute=body.window_start_minute,
            window_end_minute=body.window_end_minute,
            days_of_week=body.days_of_week,
            updated_by=updated_by,
        )
    finally:
        conn.close()


@app.patch("/api/settings/hunt-sync/auto-deploy-target")
def update_hunt_sync_auto_deploy_target_endpoint(
    body: AutoDeployTargetUpdate, request: Request, auth=Depends(require_admin),
):
    """The 'auto' mode's default Sentinel Hunt target -- used only for
    hunts with no per-hunt override of their own (see hunts.set_hunt_
    target()/PATCH .../target, unaffected by this endpoint). Pass null to
    go back to "create a new dedicated hunt per TI article." Picker options
    come from the same GET /api/detections/hunts/sentinel-targets this
    endpoint's per-hunt sibling already uses."""
    updated_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return hunt_sync_settings.set_auto_deploy_target(
            conn, body.target_sentinel_hunt_id, updated_by,
        )
    finally:
        conn.close()


# ── MITRE Detection Strategy Alignment ───────────────────────────────────────

@app.get("/api/detections/alignment/pending")
def get_pending_alignment_reviews_endpoint(
    detection_type: str | None = None,
    ready_only: bool = False,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    if detection_type and detection_type not in _VALID_DETECTION_TYPES_WITH_HUNT:
        raise HTTPException(status_code=400, detail="invalid detection_type")
    conn = pgcompat.connect()
    try:
        return alignment_reviews_db.get_pending_reviews(
            conn, detection_type=detection_type, limit=limit, offset=offset,
            ready_only=ready_only,
        )
    finally:
        conn.close()


@app.get("/api/detections/alignment/partial")
def get_partial_alignment_reviews_endpoint(
    detection_type: str | None = None,
    ready_only: bool = False,
    limit: int = 50,
    offset: int = Query(0, ge=0),
    auth=Depends(require_auth),
):
    if limit > 200:
        limit = 200
    if detection_type and detection_type not in _VALID_DETECTION_TYPES_WITH_HUNT:
        raise HTTPException(status_code=400, detail="invalid detection_type")
    conn = pgcompat.connect()
    try:
        return alignment_reviews_db.get_partial_reviews(
            conn, detection_type=detection_type, limit=limit, offset=offset,
            ready_only=ready_only,
        )
    finally:
        conn.close()


@app.post("/api/detections/alignment/{review_id}/accept")
def accept_alignment_review_endpoint(
    review_id: int, request: Request, auth=Depends(require_admin),
):
    reviewed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return alignment_reviews_db.accept_review(conn, review_id, reviewed_by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()


@app.post("/api/detections/alignment/{review_id}/reject")
def reject_alignment_review_endpoint(
    review_id: int, request: Request, auth=Depends(require_admin),
):
    reviewed_by = request.state.user.get("name", "api")
    conn = pgcompat.connect()
    try:
        return alignment_reviews_db.reject_review(conn, review_id, reviewed_by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()
