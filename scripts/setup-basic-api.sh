#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# setup-basic-api.sh — Basic + API tier: TI feed plus AI-assisted triage,
# still no cloud dependency.
#
# Runs setup-basic.sh (local Postgres, local auth) and then adds a direct
# Anthropic API key for triage. Everything stays local -- this tier never
# talks to Azure.
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

"$REPO_ROOT/scripts/setup-basic.sh"

echo ""
echo "==> Adding AI-assisted triage (Anthropic, direct)"

if grep -q '^ANTHROPIC_API_KEY=' backend/.env 2>/dev/null && \
   [ -n "$(grep '^ANTHROPIC_API_KEY=' backend/.env | cut -d= -f2-)" ]; then
    echo "    backend/.env already has ANTHROPIC_API_KEY set, leaving it alone"
    exit 0
fi

echo "    Get a key at https://console.anthropic.com/settings/keys"
read -r -p "    Paste your Anthropic API key (leave blank to skip): " ANTHROPIC_API_KEY

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "    Skipped -- triage will run in 'skipped' mode until you add one to backend/.env"
    exit 0
fi

# Remove any prior placeholder lines for these keys, then append fresh ones --
# simpler and less error-prone than trying to edit them in place with sed.
grep -v -E '^(AI_PROVIDER|ANTHROPIC_API_KEY)=' backend/.env > backend/.env.tmp || true
mv backend/.env.tmp backend/.env
{
    echo ""
    echo "# Added by scripts/setup-basic-api.sh"
    echo "AI_PROVIDER=anthropic"
    echo "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}"
} >> backend/.env

echo "    Wrote ANTHROPIC_API_KEY to backend/.env"
echo ""
echo "==> Setup complete. Next steps:"
echo "    cd backend  && pip install -r requirements.txt && uvicorn main:app --reload --port 8000"
echo "    cd frontend && npm install && npm run dev"
