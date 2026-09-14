#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# setup-basic.sh — Basic tier: TI feed only, no AI triage, no cloud.
#
# What this sets up:
#   - A local Postgres 16 container (Docker), schema applied
#   - backend/.env with local auth (LOCAL_API_KEY) and no AI provider
#   - frontend/.env.local pointed at the local backend
#
# What it does NOT set up:
#   - AI-assisted triage (see setup-basic-api.sh for that)
#   - Any Azure resource (see setup-azure.ps1 for the full SIEM-integrated tier)
#   - Running the dev servers themselves (printed as manual steps at the end)
#
# Safe to re-run: skips the Postgres container and .env files if they
# already exist, and every schema statement is idempotent (CREATE ... IF
# NOT EXISTS / matching guards).
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PG_CONTAINER="ti-postgres"
PG_DB="tiaggregator"
PG_USER="postgres"
PG_PORT="5432"

echo "==> Checking for Docker"
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required (used to run local Postgres). Install it and re-run." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but not running. Start Docker and re-run." >&2
    exit 1
fi

gen_secret() {
    python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
        || python -c "import secrets; print(secrets.token_hex(32))"
}

echo "==> Setting up local Postgres container ($PG_CONTAINER)"
if docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
    echo "    Container already exists, starting it if stopped"
    docker start "$PG_CONTAINER" >/dev/null
    PG_PASSWORD="$(docker exec "$PG_CONTAINER" printenv POSTGRES_PASSWORD)"
else
    PG_PASSWORD="$(gen_secret)"
    docker run -d \
        --name "$PG_CONTAINER" \
        -e POSTGRES_DB="$PG_DB" \
        -e POSTGRES_USER="$PG_USER" \
        -e POSTGRES_PASSWORD="$PG_PASSWORD" \
        -p "${PG_PORT}:5432" \
        postgres:16 >/dev/null
    echo "    Created and started $PG_CONTAINER"
fi

echo "==> Waiting for Postgres to accept connections"
for i in $(seq 1 30); do
    if docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Postgres did not become ready in time." >&2
        exit 1
    fi
    sleep 1
done

echo "==> Applying schema"
# The pg_*.sql migration files GRANT to a 'tiapp' role that a real deployment
# provisions separately (see MIGRATION_RUNBOOK.md). Locally we just connect
# as the postgres superuser, so this role only needs to exist as a target
# for those GRANTs -- it's never logged into.
docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 -c \
    "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tiapp') THEN CREATE ROLE tiapp; END IF; END \$\$;" \
    >/dev/null

# Order matches backend/tests/conftest.py's DETECTION_PIPELINE_SCHEMA_PATHS,
# the authoritative list -- later files ALTER tables earlier ones create
# (pg_coverage_ledger_v2/v3 alter pg_detection_strategies' table, etc.).
SCHEMA_FILES=(
    "backend/pg_schema.sql"
    "pg_detection_strategies.sql"
    "pg_coverage_ledger_v2.sql"
    "pg_coverage_ledger_v3.sql"
    "pg_hit_baseline.sql"
    "pg_mitre_detection_strategies.sql"
    "pg_alignment_reviews.sql"
    "pg_analytics_validation_columns.sql"
    "pg_disposition_checks.sql"
    "pg_detection_pipeline_attempts.sql"
    "pg_detection_pipeline_attempts_project_id.sql"
    "pg_orchestrator_settings.sql"
    "pg_orchestrator_settings_interval.sql"
    "pg_sentinel_workspace_tables.sql"
    "pg_analytics_name_description.sql"
    "pg_hunts.sql"
    "pg_hunts_target_sentinel_hunt.sql"
    "pg_hunt_sync_settings.sql"
    "pg_entries_emitted_at.sql"
    "pg_tuning_suggestion_actions.sql"
    "pg_sentinel_hunt_inventory.sql"
    "pg_analytics_artifact_id_unique.sql"
    "pg_sentinel_analytics_rules.sql"
    "pg_sentinel_hunt_queries_tune_action.sql"
    "pg_sentinel_analytics_rules_tune_action.sql"
    "pg_audit_annotations.sql"
    "pg_hunt_sync_settings_severity_cadence.sql"
    "pg_hunt_sync_settings_auto_deploy_target.sql"
    "pg_analytics_hunts_origin.sql"
    # Independent of every table above (its own telemetry_baseline table,
    # no ALTERs) -- included here even though master's own setup-basic.sh
    # still omits it (see docs/superpowers/handoff-public-release-parity-
    # 2026-09-14.md).
    "backend/pg_telemetry_baseline.sql"
)
for f in "${SCHEMA_FILES[@]}"; do
    if [ -f "$f" ]; then
        echo "    Applying $f"
        docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 < "$f" >/dev/null
    fi
done

PG_DSN="postgresql://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/${PG_DB}"

echo "==> Writing backend/.env"
if [ -f backend/.env ]; then
    echo "    backend/.env already exists, leaving it alone (delete it first to regenerate)"
else
    LOCAL_API_KEY="$(gen_secret)"
    JWT_SECRET_KEY="$(gen_secret)"
    cat > backend/.env <<EOF
# Generated by scripts/setup-basic.sh
PG_DSN=${PG_DSN}

# Local auth mode: no Azure/Entra dependency. Anyone with this key gets
# admin access. Share it only with people you trust with the whole app.
LOCAL_API_KEY=${LOCAL_API_KEY}
JWT_SECRET_KEY=${JWT_SECRET_KEY}

ENABLE_SCHEDULER=true
ALLOWED_ORIGINS=http://localhost:3000

# No AI provider configured -- triage runs in "skipped" mode.
# See setup-basic-api.sh to add AI-assisted triage.
EOF
    echo "    Wrote backend/.env (LOCAL_API_KEY: ${LOCAL_API_KEY})"
fi

echo "==> Writing frontend/.env.local"
if [ -f frontend/.env.local ]; then
    echo "    frontend/.env.local already exists, leaving it alone"
else
    cat > frontend/.env.local <<'EOF'
# Generated by scripts/setup-basic.sh
NEXT_PUBLIC_API_URL=http://localhost:8000
EOF
    echo "    Wrote frontend/.env.local"
fi

echo ""
echo "==> Setup complete. Next steps:"
echo "    cd backend  && pip install -r requirements.txt && uvicorn main:app --reload --port 8000"
echo "    cd frontend && npm install && npm run dev"
echo ""
echo "    Then open http://localhost:3000 and sign in with the LOCAL_API_KEY"
echo "    printed above (also saved in backend/.env)."
