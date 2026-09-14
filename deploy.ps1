#Requires -Version 5.1
# ─────────────────────────────────────────────────────────────
# deploy.ps1 — Build via ACR, deploy backend + frontend to separate ACI instances
#
# Secrets are read from backend\.env automatically.
# Run from the repo root:
#   .\deploy.ps1
# ─────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"

# ── Config ────────────────────────────────────────────────────
$RG = "my-resource-group"
$ACR = "myacrname"
$LOCATION = "centralus"

$BACKEND_ACI = "ti-rss-feed-backend"
$BACKEND_DNS = "ti-rss-backend-001"
$BACKEND_IMAGE = "${ACR}.azurecr.io/ti-rss-feed-backend:latest"
$BACKEND_FQDN = "${BACKEND_DNS}.${LOCATION}.azurecontainer.io"

$FRONTEND_ACI = "ti-rss-feed-frontend"
$FRONTEND_DNS = "ti-rss-frontend-001"
$FRONTEND_IMAGE = "${ACR}.azurecr.io/ti-rss-feed-frontend:latest"

$STORAGE_ACCOUNT = "mystorageaccount"
$STORAGE_SHARE = "ti-data"
$STORAGE_MOUNT = "/data"

$AI_PROVIDER = "azure"
$AZURE_FOUNDRY_ENDPOINT = "https://admineta-1732-resource.services.ai.azure.com/anthropic"
$AZURE_FOUNDRY_DEPLOYMENT = "claude-haiku-4-5"
$AZURE_FOUNDRY_API_VERSION = "2025-05-01"

# ── Load secrets from backend\.env ───────────────────────────
$envFile = Join-Path $PSScriptRoot "backend\.env"
if (-not (Test-Path $envFile)) {
    Write-Error "backend\.env not found. Cannot read secrets."
    exit 1
}
$AZURE_AD_CLIENT_ID     = $null
$AZURE_AD_TENANT_ID     = $null
$AZURE_AD_CLIENT_SECRET = $null
$JWT_SECRET_KEY         = $null
$NEXTAUTH_SECRET        = $null
$AZURE_FOUNDRY_API_KEY  = $null
foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*AZURE_AD_CLIENT_ID\s*=\s*(.+)$')     { $AZURE_AD_CLIENT_ID     = $Matches[1].Trim() }
    if ($line -match '^\s*AZURE_AD_TENANT_ID\s*=\s*(.+)$')     { $AZURE_AD_TENANT_ID     = $Matches[1].Trim() }
    if ($line -match '^\s*AZURE_AD_CLIENT_SECRET\s*=\s*(.+)$') { $AZURE_AD_CLIENT_SECRET = $Matches[1].Trim() }
    if ($line -match '^\s*JWT_SECRET_KEY\s*=\s*(.+)$')         { $JWT_SECRET_KEY         = $Matches[1].Trim() }
    if ($line -match '^\s*NEXTAUTH_SECRET\s*=\s*(.+)$')        { $NEXTAUTH_SECRET        = $Matches[1].Trim() }
    if ($line -match '^\s*AZURE_FOUNDRY_API_KEY\s*=\s*(.+)$')  { $AZURE_FOUNDRY_API_KEY  = $Matches[1].Trim() }
}
if (-not $AZURE_AD_CLIENT_ID)     { Write-Error "AZURE_AD_CLIENT_ID not found in backend\.env";     exit 1 }
if (-not $AZURE_AD_TENANT_ID)     { Write-Error "AZURE_AD_TENANT_ID not found in backend\.env";     exit 1 }
if (-not $AZURE_AD_CLIENT_SECRET) { Write-Error "AZURE_AD_CLIENT_SECRET not found in backend\.env"; exit 1 }
if (-not $JWT_SECRET_KEY)         { Write-Error "JWT_SECRET_KEY not found in backend\.env";         exit 1 }
if (-not $NEXTAUTH_SECRET)        { Write-Error "NEXTAUTH_SECRET not found in backend\.env";        exit 1 }
if (-not $AZURE_FOUNDRY_API_KEY)  { Write-Error "AZURE_FOUNDRY_API_KEY not found in backend\.env"; exit 1 }

# ── Azure login ───────────────────────────────────────────────
Write-Host "==> Logging into Azure (device code)..." -ForegroundColor Cyan
az login --use-device-code
if ($LASTEXITCODE -ne 0) { Write-Error "Azure login failed"; exit 1 }

# ── Fetch Azure credentials ───────────────────────────────────
Write-Host "==> Fetching ACR credentials..." -ForegroundColor Cyan
$ACR_USER = az acr credential show --name $ACR --query username -o tsv
$ACR_PASS = az acr credential show --name $ACR --query "passwords[0].value" -o tsv

Write-Host "==> Fetching storage key..." -ForegroundColor Cyan
$STORAGE_KEY = az storage account keys list -g $RG -n $STORAGE_ACCOUNT --query "[0].value" -o tsv

# ── Build backend via ACR (cloud build — no local Docker needed) ──
Write-Host "==> Building backend image via ACR..." -ForegroundColor Cyan
az acr build --registry $ACR --image "ti-rss-feed-backend:latest" ./backend
if ($LASTEXITCODE -ne 0) { Write-Error "Backend ACR build failed"; exit 1 }

# ── Deploy backend ACI ────────────────────────────────────────
Write-Host "==> Deleting existing backend ACI if present..." -ForegroundColor Cyan
az container delete --resource-group $RG --name $BACKEND_ACI --yes 2>$null
# ignore exit code — container may not exist

Write-Host "==> Deploying backend ACI..." -ForegroundColor Cyan
az container create `
    --resource-group $RG `
    --name $BACKEND_ACI `
    --image $BACKEND_IMAGE `
    --registry-login-server "${ACR}.azurecr.io" `
    --registry-username $ACR_USER `
    --registry-password $ACR_PASS `
    --os-type Linux `
    --ports 8000 `
    --ip-address Public `
    --dns-name-label $BACKEND_DNS `
    --dns-name-label-reuse-policy ResourceGroupReuse `
    --location $LOCATION `
    --cpu 1 `
    --memory 1.5 `
    --azure-file-volume-account-name $STORAGE_ACCOUNT `
    --azure-file-volume-account-key $STORAGE_KEY `
    --azure-file-volume-share-name $STORAGE_SHARE `
    --azure-file-volume-mount-path $STORAGE_MOUNT `
    --environment-variables `
    "AI_PROVIDER=$AI_PROVIDER" `
    "AZURE_FOUNDRY_ENDPOINT=$AZURE_FOUNDRY_ENDPOINT" `
    "AZURE_FOUNDRY_DEPLOYMENT=$AZURE_FOUNDRY_DEPLOYMENT" `
    "AZURE_FOUNDRY_API_VERSION=$AZURE_FOUNDRY_API_VERSION" `
    --secure-environment-variables `
    "AZURE_AD_CLIENT_ID=$AZURE_AD_CLIENT_ID" `
    "AZURE_AD_TENANT_ID=$AZURE_AD_TENANT_ID" `
    "AZURE_AD_CLIENT_SECRET=$AZURE_AD_CLIENT_SECRET" `
    "JWT_SECRET_KEY=$JWT_SECRET_KEY" `
    "AZURE_FOUNDRY_API_KEY=$AZURE_FOUNDRY_API_KEY" `
    --restart-policy Always
if ($LASTEXITCODE -ne 0) { Write-Error "Backend ACI deployment failed"; exit 1 }

# ── Build frontend via ACR with backend URL baked in ─────────
# NEXT_PUBLIC_API_URL is a Next.js build-time constant baked into the JS bundle.
Write-Host "==> Building frontend image via ACR (backend: http://${BACKEND_FQDN}:8000)..." -ForegroundColor Cyan
az acr build `
    --registry $ACR `
    --image "ti-rss-feed-frontend:latest" `
    --file frontend/Dockerfile `
    --platform linux/amd64 `
    --build-arg "NEXT_PUBLIC_API_URL=http://${BACKEND_FQDN}:8000" `
    ./frontend
if ($LASTEXITCODE -ne 0) { Write-Error "Frontend ACR build failed"; exit 1 }

# ── Deploy frontend ACI ───────────────────────────────────────
Write-Host "==> Deleting existing frontend ACI if present..." -ForegroundColor Cyan
az container delete --resource-group $RG --name $FRONTEND_ACI --yes 2>$null

Write-Host "==> Deploying frontend ACI..." -ForegroundColor Cyan
az container create `
    --resource-group $RG `
    --name $FRONTEND_ACI `
    --image $FRONTEND_IMAGE `
    --registry-login-server "${ACR}.azurecr.io" `
    --registry-username $ACR_USER `
    --registry-password $ACR_PASS `
    --os-type Linux `
    --ports 3000 `
    --ip-address Public `
    --dns-name-label $FRONTEND_DNS `
    --dns-name-label-reuse-policy ResourceGroupReuse `
    --location $LOCATION `
    --cpu 0.5 `
    --memory 1.0 `
    --environment-variables `
    "NEXTAUTH_URL=http://${FRONTEND_DNS}.${LOCATION}.azurecontainer.io:3000" `
    "BACKEND_URL=http://${BACKEND_FQDN}:8000" `
    "AZURE_AD_CLIENT_ID=$AZURE_AD_CLIENT_ID" `
    "AZURE_AD_TENANT_ID=$AZURE_AD_TENANT_ID" `
    --secure-environment-variables `
    "AZURE_AD_CLIENT_SECRET=$AZURE_AD_CLIENT_SECRET" `
    "NEXTAUTH_SECRET=$NEXTAUTH_SECRET" `
    --restart-policy Always
if ($LASTEXITCODE -ne 0) { Write-Error "Frontend ACI deployment failed"; exit 1 }

Write-Host ""
Write-Host "==> Deploy complete." -ForegroundColor Green
Write-Host "    Frontend : http://${FRONTEND_DNS}.${LOCATION}.azurecontainer.io:3000" -ForegroundColor Green
Write-Host "    Backend  : http://${BACKEND_FQDN}:8000" -ForegroundColor Green
Write-Host "    Health   : http://${BACKEND_FQDN}:8000/api/health" -ForegroundColor Green
