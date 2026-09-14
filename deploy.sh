#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# deploy.sh — Build via ACR, deploy backend + frontend to separate ACI instances
#
# Required env vars (export before running, or set inline):
#   API_SECRET_KEY          — Bearer token for the API
#   AZURE_FOUNDRY_API_KEY   — Azure AI Foundry API key
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────
RG=""
ACR=""
LOCATION="centralus"

BACKEND_ACI="ti-rss-feed-backend"
BACKEND_DNS="ti-rss-backend-001"
BACKEND_IMAGE="${ACR}.azurecr.io/ti-rss-feed-backend:latest"
BACKEND_FQDN="${BACKEND_DNS}.${LOCATION}.azurecontainer.io"

FRONTEND_ACI="ti-rss-feed-frontend"
FRONTEND_DNS="ti-rss-frontend-001"
FRONTEND_IMAGE="${ACR}.azurecr.io/ti-rss-feed-frontend:latest"

STORAGE_ACCOUNT=""
STORAGE_SHARE="ti-data"
STORAGE_MOUNT="/data"

AI_PROVIDER="azure"
AZURE_FOUNDRY_ENDPOINT="https://xxxxx-resource.services.ai.azure.com/anthropic"
AZURE_FOUNDRY_DEPLOYMENT="claude-haiku-4-5"
AZURE_FOUNDRY_API_VERSION="2025-05-01"

# ── Guard: secrets must be set in the caller's environment ────────────────
: "${API_SECRET_KEY:?Export API_SECRET_KEY before running deploy.sh}"
: "${AZURE_FOUNDRY_API_KEY:?Export AZURE_FOUNDRY_API_KEY before running deploy.sh}"

# ── Fetch Azure credentials ─────────────────────────────────────────────
echo "==> Fetching ACR credentials..."
ACR_USER=$(az acr credential show --name "$ACR" --query username -o tsv)
ACR_PASS=$(az acr credential show --name "$ACR" --query "passwords[0].value" -o tsv)

echo "==> Fetching storage key..."
STORAGE_KEY=$(az storage account keys list -g "$RG" -n "$STORAGE_ACCOUNT" --query "[0].value" -o tsv)

# ── Build backend (cloud build via ACR — avoids local Docker/Windows issues) ──
echo "==> Building backend image via ACR..."
az acr build \
  --registry "$ACR" \
  --image "ti-rss-feed-backend:latest" \
  ./backend

# ── Deploy backend ACI ───────────────────────────────────────────────────────
echo "==> Deleting existing backend ACI if present..."
az container delete --resource-group "$RG" --name "$BACKEND_ACI" --yes 2>/dev/null || true

echo "==> Deploying backend ACI..."
az container create \
  --resource-group "$RG" \
  --name "$BACKEND_ACI" \
  --image "$BACKEND_IMAGE" \
  --registry-login-server "${ACR}.azurecr.io" \
  --registry-username "$ACR_USER" \
  --registry-password "$ACR_PASS" \
  --os-type Linux \
  --ports 8000 \
  --ip-address Public \
  --dns-name-label "$BACKEND_DNS" \
  --location "$LOCATION" \
  --cpu 1 \
  --memory 1.5 \
  --azure-file-volume-account-name "$STORAGE_ACCOUNT" \
  --azure-file-volume-account-key "$STORAGE_KEY" \
  --azure-file-volume-share-name "$STORAGE_SHARE" \
  --azure-file-volume-mount-path "$STORAGE_MOUNT" \
  --environment-variables \
    AI_PROVIDER="$AI_PROVIDER" \
    AZURE_FOUNDRY_ENDPOINT="$AZURE_FOUNDRY_ENDPOINT" \
    AZURE_FOUNDRY_DEPLOYMENT="$AZURE_FOUNDRY_DEPLOYMENT" \
    AZURE_FOUNDRY_API_VERSION="$AZURE_FOUNDRY_API_VERSION" \
  --secure-environment-variables \
    API_SECRET_KEY="$API_SECRET_KEY" \
    AZURE_FOUNDRY_API_KEY="$AZURE_FOUNDRY_API_KEY" \
  --restart-policy Always

# ── Build frontend via ACR with backend URL baked in ────────────────────────
# NEXT_PUBLIC_API_URL is a Next.js build-time constant; it must be passed
# as a build-arg (not a runtime env var) so the browser bundle contains it.
echo "==> Building frontend image via ACR (backend URL: https://${BACKEND_FQDN})..."
az acr build \
  --registry "$ACR" \
  --image "ti-rss-feed-frontend:latest" \
  --file frontend/Dockerfile \
  --platform linux/amd64 \
  --build-arg "NEXT_PUBLIC_API_URL=https://${BACKEND_FQDN}" \
  ./frontend

# ── Deploy frontend ACI ───────────────────────────────────────────────────────
echo "==> Deleting existing frontend ACI if present..."
az container delete --resource-group "$RG" --name "$FRONTEND_ACI" --yes 2>/dev/null || true

echo "==> Deploying frontend ACI..."
az container create \
  --resource-group "$RG" \
  --name "$FRONTEND_ACI" \
  --image "$FRONTEND_IMAGE" \
  --registry-login-server "${ACR}.azurecr.io" \
  --registry-username "$ACR_USER" \
  --registry-password "$ACR_PASS" \
  --os-type Linux \
  --ports 3000 \
  --ip-address Public \
  --dns-name-label "$FRONTEND_DNS" \
  --location "$LOCATION" \
  --cpu 0.5 \
  --memory 1.0 \
  --restart-policy Always

echo ""
echo "==> Deploy complete."
echo "    Frontend : http://${FRONTEND_DNS}.${LOCATION}.azurecontainer.io:3000"
echo "    Backend  : https://${BACKEND_FQDN}"
echo "    Health   : https://${BACKEND_FQDN}/api/health"
