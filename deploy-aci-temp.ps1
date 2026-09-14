#Requires -Version 5.1
# ─────────────────────────────────────────────────────────────────────────────
# deploy-aci-temp.ps1  TEMPORARY ACI deployment with Caddy HTTPS reverse proxy
#
# Use this until Microsoft.App (Container Apps) provider is registered (~Friday).
# Caddy automatically provisions a TLS certificate via ACME so Entra ID's
# HTTPS requirement is satisfied.  All three containers share localhost networking:
#
#   Internet → Caddy (:443) → /api/auth/*  → Next.js  (:3000)
#                           → /api/*       → FastAPI  (:8000)
#                           → /*           → Next.js  (:3000)
#
# NOTE: this temporary ACI path uses local container storage for the live
# SQLite file, and Azure Files for persisted snapshots across redeploys.
#
# Usage:
#   .\deploy-aci-temp.ps1              # build images + deploy
#   .\deploy-aci-temp.ps1 -SkipBuild   # skip ACR builds (reuse existing images)
#
# After deploy:
#   Update the Entra ID redirect URI shown at the end of this script's output.
#   Delete this script after migrating to Container Apps (deploy.ps1) on Friday.
# ─────────────────────────────────────────────────────────────────────────────
param(
  [switch]$SkipBuild,
  [string]$DnsLabel = 'ti-rss-feed-v5'
)
$ErrorActionPreference = 'Stop'

# ── Config ────────────────────────────────────────────────────────────────────
$RG = 'my-resource-group'
$ACR = 'myacrname'
$LOCATION = 'centralus'
$ACI_NAME = 'ti-rss-feed-aci'
$DNS_LABEL = $DnsLabel
$ACI_FQDN = "${DNS_LABEL}.${LOCATION}.azurecontainer.io"

$BACKEND_IMAGE = "${ACR}.azurecr.io/ti-rss-feed-backend:latest"
$FRONTEND_IMAGE = "${ACR}.azurecr.io/ti-rss-feed-frontend:latest"
$STORAGE_ACCOUNT = 'mystorageaccount'
$STORAGE_SHARE = 'ti-data'
$CADDY_SHARE = 'caddy-data'

$AZ_FOUNDRY_ENDPOINT = 'https://admineta-1732-resource.services.ai.azure.com/anthropic'
$AZ_FOUNDRY_DEPLOYMENT = 'claude-haiku-4-5'
$AZ_FOUNDRY_API_VER = '2025-05-01'

# ── Load secrets from backend\.env ────────────────────────────────────────────
$envFile = Join-Path $PSScriptRoot 'backend\.env'
if (-not (Test-Path $envFile)) { Write-Error 'backend\.env not found'; exit 1 }

$AZURE_AD_CLIENT_ID = $null
$AZURE_AD_TENANT_ID = $null
$AZURE_AD_CLIENT_SECRET = $null
$JWT_SECRET_KEY = $null
$NEXTAUTH_SECRET = $null
$AZURE_FOUNDRY_API_KEY = $null
$RUNZERO_API_TOKEN = $null

foreach ($line in Get-Content $envFile) {
  if ($line -match '^\s*AZURE_AD_CLIENT_ID\s*=\s*(.+)$') { $AZURE_AD_CLIENT_ID = $Matches[1].Trim() }
  if ($line -match '^\s*AZURE_AD_TENANT_ID\s*=\s*(.+)$') { $AZURE_AD_TENANT_ID = $Matches[1].Trim() }
  if ($line -match '^\s*AZURE_AD_CLIENT_SECRET\s*=\s*(.+)$') { $AZURE_AD_CLIENT_SECRET = $Matches[1].Trim() }
  if ($line -match '^\s*JWT_SECRET_KEY\s*=\s*(.+)$') { $JWT_SECRET_KEY = $Matches[1].Trim() }
  if ($line -match '^\s*NEXTAUTH_SECRET\s*=\s*(.+)$') { $NEXTAUTH_SECRET = $Matches[1].Trim() }
  if ($line -match '^\s*AZURE_FOUNDRY_API_KEY\s*=\s*(.+)$') { $AZURE_FOUNDRY_API_KEY = $Matches[1].Trim() }
  if ($line -match '^\s*RUNZERO_API_TOKEN\s*=\s*(.+)$') { $RUNZERO_API_TOKEN = $Matches[1].Trim() }
}

$required = @{
  AZURE_AD_CLIENT_ID = $AZURE_AD_CLIENT_ID
  AZURE_AD_TENANT_ID = $AZURE_AD_TENANT_ID
  AZURE_AD_CLIENT_SECRET = $AZURE_AD_CLIENT_SECRET
  JWT_SECRET_KEY = $JWT_SECRET_KEY
  NEXTAUTH_SECRET = $NEXTAUTH_SECRET
  AZURE_FOUNDRY_API_KEY = $AZURE_FOUNDRY_API_KEY
}
foreach ($kv in $required.GetEnumerator()) {
  if (-not $kv.Value) { Write-Error "$($kv.Key) not found in backend\.env"; exit 1 }
}

# ── Azure login ───────────────────────────────────────────────────────────────
Write-Host '==> Logging into Azure (device code)...' -ForegroundColor Cyan
az login --use-device-code
if ($LASTEXITCODE -ne 0) { Write-Error 'Azure login failed'; exit 1 }

# ── Fetch credentials ─────────────────────────────────────────────────────────
Write-Host '==> Fetching ACR credentials...' -ForegroundColor Cyan
$ACR_USER = az acr credential show --name $ACR --query username -o tsv
$ACR_PASS = az acr credential show --name $ACR --query 'passwords[0].value' -o tsv
if (-not $ACR_USER -or -not $ACR_PASS) { Write-Error 'Could not fetch ACR credentials'; exit 1 }

Write-Host '==> Fetching storage key...' -ForegroundColor Cyan
$STORAGE_KEY = az storage account keys list -g $RG -n $STORAGE_ACCOUNT --query '[0].value' -o tsv
if (-not $STORAGE_KEY) { Write-Error 'Could not fetch storage account key'; exit 1 }

Write-Host "==> Ensuring file share '$STORAGE_SHARE' exists..." -ForegroundColor Cyan
az storage share-rm create --resource-group $RG --storage-account $STORAGE_ACCOUNT --name $STORAGE_SHARE --quota 100 1>$null
if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to create/verify Azure File share'; exit 1 }

Write-Host "==> Ensuring file share '$CADDY_SHARE' exists..." -ForegroundColor Cyan
az storage share-rm create --resource-group $RG --storage-account $STORAGE_ACCOUNT --name $CADDY_SHARE --quota 10 1>$null
if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to create/verify Caddy File share'; exit 1 }

# ── Build images via ACR ──────────────────────────────────────────────────────
# Import Caddy into ACR so ACI never touches Docker Hub (rate-limited).
$CADDY_IMAGE = "${ACR}.azurecr.io/caddy:2"
Write-Host '==> Importing caddy:2 into ACR (skipped if already present)...' -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
$_caddyOut = az acr import --name $ACR --source 'docker.io/library/caddy:2' --image 'caddy:2' 2>&1
$_caddyExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($_caddyExit -ne 0) {
  if ("$_caddyOut" -match 'already exists') {
    Write-Host '==> caddy:2 already in ACR, skipping.' -ForegroundColor Green
  } else {
    Write-Error "Failed to import caddy:2 into ACR: $_caddyOut"; exit 1
  }
} else {
  Write-Host '==> caddy:2 imported successfully.' -ForegroundColor Green
}

if (-not $SkipBuild) {
  Write-Host '==> Building backend image via ACR...' -ForegroundColor Cyan
  az acr build --registry $ACR --image 'ti-rss-feed-backend:latest' ./backend
  if ($LASTEXITCODE -ne 0) { Write-Error 'Backend ACR build failed'; exit 1 }

  Write-Host '==> Building frontend image via ACR...' -ForegroundColor Cyan
  az acr build --registry $ACR --image 'ti-rss-feed-frontend:latest' `
    --file frontend/Dockerfile --platform linux/amd64 ./frontend
  if ($LASTEXITCODE -ne 0) { Write-Error 'Frontend ACR build failed'; exit 1 }
}
else {
  Write-Host '==> -SkipBuild specified — reusing existing ACR images.' -ForegroundColor Yellow
}

# ── Remove existing container group ──────────────────────────────────────────
Write-Host '==> Checking for existing container group...' -ForegroundColor Cyan
# Temporarily suppress Stop so a 404 from az container show doesn't throw.
$ErrorActionPreference = 'Continue'
$existingId = az container show -g $RG -n $ACI_NAME --query id -o tsv 2>$null
$showExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($showExitCode -eq 0 -and $existingId) {
  Write-Host '==> Deleting existing container group (takes ~30s)...' -ForegroundColor Yellow
  az container delete -g $RG -n $ACI_NAME --yes
  if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to delete existing container group'; exit 1 }

  Write-Host '==> Waiting for container group deletion to complete...' -ForegroundColor Cyan
  $deletionComplete = $false
  for ($i = 0; $i -lt 24; $i++) {
    $ErrorActionPreference = 'Continue'
    $remainingId = az container show -g $RG -n $ACI_NAME --query id -o tsv 2>$null
    $remainingExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($remainingExit -ne 0 -or -not $remainingId) {
      $deletionComplete = $true
      break
    }
    Start-Sleep -Seconds 5
  }

  if (-not $deletionComplete) {
    Write-Error 'Timed out waiting for existing container group to finish deleting'
    exit 1
  }
}

# ── Escape values for YAML double-quoted scalars ──────────────────────────────
# Only \ and " need escaping inside YAML dq-scalars.
function EscYaml([string]$v) {
  return $v.Replace('\', '\\').Replace('"', '\"')
}

$Y_ACR_PASS = EscYaml $ACR_PASS
$Y_STORAGE_KEY = EscYaml $STORAGE_KEY
$Y_JWT_SECRET = EscYaml $JWT_SECRET_KEY
$Y_FOUNDRY_API_KEY = EscYaml $AZURE_FOUNDRY_API_KEY
$Y_NEXTAUTH_SECRET = EscYaml $NEXTAUTH_SECRET
$Y_AD_CLIENT_SECRET = EscYaml $AZURE_AD_CLIENT_SECRET
$Y_AD_CLIENT_ID = EscYaml $AZURE_AD_CLIENT_ID
$Y_RUNZERO_TOKEN = if ($RUNZERO_API_TOKEN) { EscYaml $RUNZERO_API_TOKEN } else { '' }

# ── Generate ACI container group YAML ────────────────────────────────────────
# Caddy is configured with a YAML | literal block scalar so \n sequences pass
# through unprocessed by YAML and are then interpreted by printf as newlines.
#
# Routing:
#   /api/auth  /api/auth/* → Next.js (NextAuth must be handled by Next.js)
#   /api/*                 → FastAPI (feed data, entries, triage, etc.)
#   /*                     → Next.js (app pages + static assets)
$CADDY_PRINTF = "printf '${ACI_FQDN} {\n  @nextauth path /api/auth /api/auth/*\n  handle @nextauth {\n    reverse_proxy localhost:3000\n  }\n  @backend path /api/*\n  handle @backend {\n    reverse_proxy localhost:8000\n  }\n  handle {\n    reverse_proxy localhost:3000\n  }\n}\n' > /etc/caddy/Caddyfile"

$YAML_PATH = Join-Path $PSScriptRoot 'infra\aci-temp.yaml'

# Note: PowerShell @"..."@ expands $variables. The $CADDY_PRINTF value contains
# \n (literal backslash-n from PowerShell) which the YAML | block passes through
# as-is to the shell, where printf interprets them as newlines.
@"
apiVersion: '2023-05-01'
location: $LOCATION
name: $ACI_NAME
properties:
  containers:
  - name: caddy
    properties:
      image: "$CADDY_IMAGE"
      command:
        - /bin/sh
        - -c
        - |
          $CADDY_PRINTF
          caddy run --config /etc/caddy/Caddyfile
      resources:
        requests:
          cpu: 0.5
          memoryInGb: 0.5
      ports:
        - port: 80
          protocol: TCP
        - port: 443
          protocol: TCP
      volumeMounts:
        - name: caddy-data
          mountPath: /data
  - name: backend
    properties:
      image: "$BACKEND_IMAGE"
      environmentVariables:
        - name: DB_PATH
          value: "/tmp/ti_feeds.db"
        - name: AZURE_STORAGE_ACCOUNT_NAME
          value: "$STORAGE_ACCOUNT"
        - name: AZURE_BLOB_CONTAINER_NAME
          value: "ti-db-persist"
        - name: AZURE_STORAGE_ACCOUNT_KEY
          secureValue: "$Y_STORAGE_KEY"
        - name: AI_PROVIDER
          value: azure
        - name: AZURE_FOUNDRY_ENDPOINT
          value: "$AZ_FOUNDRY_ENDPOINT"
        - name: AZURE_FOUNDRY_DEPLOYMENT
          value: "$AZ_FOUNDRY_DEPLOYMENT"
        - name: AZURE_FOUNDRY_API_VERSION
          value: "$AZ_FOUNDRY_API_VER"
        - name: ALLOWED_ORIGINS
          value: "https://$ACI_FQDN"
        - name: AZURE_AD_TENANT_ID
          value: "$AZURE_AD_TENANT_ID"
        - name: AZURE_AD_CLIENT_ID
          value: "$AZURE_AD_CLIENT_ID"
        - name: API_SECRET_KEY
          secureValue: "$Y_JWT_SECRET"
        - name: JWT_SECRET_KEY
          secureValue: "$Y_JWT_SECRET"
        - name: AZURE_FOUNDRY_API_KEY
          secureValue: "$Y_FOUNDRY_API_KEY"
        - name: RUNZERO_API_TOKEN
          secureValue: "$Y_RUNZERO_TOKEN"
      resources:
        requests:
          cpu: 2.0
          memoryInGb: 4.0
      ports:
        - port: 8000
          protocol: TCP
  - name: frontend
    properties:
      image: "$FRONTEND_IMAGE"
      environmentVariables:
        - name: NEXTAUTH_URL
          value: "https://$ACI_FQDN"
        - name: NEXTAUTH_TRUST_HOST
          value: "true"
        - name: AZURE_AD_TENANT_ID
          value: "$AZURE_AD_TENANT_ID"
        - name: BACKEND_URL
          value: "http://localhost:8000"
        - name: NEXTAUTH_SECRET
          secureValue: "$Y_NEXTAUTH_SECRET"
        - name: AZURE_AD_CLIENT_ID
          secureValue: "$Y_AD_CLIENT_ID"
        - name: AZURE_AD_CLIENT_SECRET
          secureValue: "$Y_AD_CLIENT_SECRET"
      resources:
        requests:
          cpu: 1.0
          memoryInGb: 1.0
      ports:
        - port: 3000
          protocol: TCP
  imageRegistryCredentials:
  - server: ${ACR}.azurecr.io
    username: "$ACR_USER"
    password: "$Y_ACR_PASS"
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    dnsNameLabel: $DNS_LABEL
    ports:
      - port: 80
        protocol: TCP
      - port: 443
        protocol: TCP
  volumes:
  - name: caddy-data
    emptyDir: {}
type: Microsoft.ContainerInstance/containerGroups
"@ | Set-Content -Path $YAML_PATH -Encoding utf8

Write-Host "==> Generated ACI YAML at: $YAML_PATH" -ForegroundColor Cyan

# ── Deploy ────────────────────────────────────────────────────────────────────
Write-Host '==> Opening ACR firewall (Allow all) for image pull...' -ForegroundColor Yellow
az acr update --name $ACR --default-action Allow
if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to open ACR firewall'; exit 1 }

# ACI containers have no static IPs, so the storage account firewall must be
# opened during deployment for ACI to mount the Azure Files volumes.  We restore
# the deny default after the container group is running (the established SMB
# connections persist without the firewall needing to remain open).
# Blob persistence uses HTTPS (port 443) — storage account must remain open during container lifetime.
# We open it here and leave it open; the account key provides authentication.
Write-Host '==> Opening storage account firewall (Allow all) for blob persistence...' -ForegroundColor Yellow
az storage account update -g $RG -n $STORAGE_ACCOUNT --default-action Allow --bypass AzureServices 1>$null
if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to open storage account firewall'; exit 1 }

# ACR firewall rule changes take up to 60s to propagate before ACI can pull images.
Write-Host '==> Waiting 60s for ACR firewall rule to propagate...' -ForegroundColor Cyan
Start-Sleep -Seconds 60

Write-Host '==> Deploying container group (3-5 min)...' -ForegroundColor Cyan
az container create -g $RG --file $YAML_PATH
if ($LASTEXITCODE -ne 0) { Write-Error 'ACI deployment failed'; exit 1 }

# ACR firewall restore happens AFTER containers are Running — ACI pulls images
# asynchronously after az container create returns, so closing the firewall
# immediately would block the image pull.
Write-Host '==> Waiting for all containers to reach Running state (max 5 min)...' -ForegroundColor Cyan
$maxAttempts = 20
$attempt = 0
$allRunning = $false

while ($attempt -lt $maxAttempts) {
  $attempt++
  $ErrorActionPreference = 'Continue'
  $statesRaw = az container show -g $RG -n $ACI_NAME `
    --query 'containers[].instanceView.currentState.state' -o tsv 2>$null
  $ErrorActionPreference = 'Stop'

  $states = ($statesRaw -split "`n" | Where-Object { $_ -ne '' })
  Write-Host "  Attempt $attempt/$maxAttempts - states: $($states -join ', ')"

  if ($states | Where-Object { $_ -eq 'Terminated' }) {
    Write-Warning "One or more containers terminated: $($states -join ', ')"
    break
  }

  if ($states.Count -eq 3 -and ($states | Where-Object { $_ -ne 'Running' }).Count -eq 0) {
    $allRunning = $true
    break
  }

  Start-Sleep -Seconds 15
}

if (-not $allRunning) {
  Write-Error "Containers did not all reach Running state within $($maxAttempts * 15)s. Investigate with: az container logs -g $RG -n $ACI_NAME --container-name backend"
  exit 1
}

Write-Host '==> Restoring ACR firewall (Deny by default)...' -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
az acr update --name $ACR --default-action Deny
if ($LASTEXITCODE -ne 0) {
  Write-Warning "ACR firewall restore FAILED - run manually: az acr update --name $ACR --default-action Deny"
} else {
  Write-Host '==> ACR firewall restored to Deny.' -ForegroundColor Green
}
$ErrorActionPreference = 'Stop'

# ── Done ──────────────────────────────────────────────────────────────────────
$HTTPS_URL = "https://$ACI_FQDN"
Write-Host ''
Write-Host '==> Deployment complete.' -ForegroundColor Green
Write-Host "    URL    : $HTTPS_URL" -ForegroundColor Green
Write-Host "    Health : $HTTPS_URL/api/health" -ForegroundColor Green
Write-Host ''
Write-Host 'NOTE: Caddy auto-provisions a TLS cert via ACME on first start.' -ForegroundColor Cyan
Write-Host '      The first HTTPS request may take ~30s while the cert is issued.' -ForegroundColor Cyan
Write-Host '      Port 80 must remain open for the ACME HTTP-01 challenge.' -ForegroundColor Cyan
Write-Host "      SQLite runs locally; snapshots persist to Azure Blob Storage (ti-db-persist/ti_feeds.db)." -ForegroundColor Cyan
Write-Host ''
Write-Host 'ACTION REQUIRED: Update Entra ID app registration redirect URI to:' -ForegroundColor Yellow
Write-Host "    $HTTPS_URL/api/auth/callback/azure-ad" -ForegroundColor Yellow
Write-Host ''
Write-Host 'Portal: Entra ID -> App registrations -> 95d2a98b-... -> Authentication' -ForegroundColor Yellow
