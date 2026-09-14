# HTTPS & Authentication Fix Guide

## Problem Summary

Two related issues were preventing the frontend from authenticating:

1. **npm lock file sync error** (FIXED ✅)
   - `npm ci` failed during Docker build due to outdated package-lock.json
   - **Status**: Updated to sync with package.json

2. **AADSTS500117 — HTTPS Required** (ACTION REQUIRED)
   - Azure Entra ID rejects OAuth redirect URIs using HTTP (except localhost)
   - All non-localhost reply URIs must use HTTPS
   - **Root cause**: Infrastructure was using HTTP for the frontend Container App

---

## What Changed

### Infrastructure Updates (Bicep)

**main.bicep**:
- Removed hardcoded HTTP frontend URL parameter
- Added new secure parameters for NextAuth and Azure AD credentials:
  - `nextAuthSecret` — required by NextAuth
  - `azureAdClientId` — from Entra ID app registration
  - `azureAdClientSecret` — from Entra ID app registration
  - `azureAdTenantId` — your Entra ID tenant ID

**containerApps.bicep**:
- Frontend Container App now receives HTTPS NEXTAUTH_URL automatically
- NEXTAUTH_URL is constructed from the container app's FQDN
- Backend ALLOWED_ORIGINS now uses HTTPS
- All Azure AD credentials passed as secrets to the container

**main.parameters.json.example**:
- Updated with all required new parameters
- Shows where to get each value

---

## Step 1: Generate Secrets

Before deploying, generate the required secrets:

### NEXTAUTH_SECRET

```powershell
# PowerShell
[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString() + [System.Guid]::NewGuid().ToString())) | Out-String
```

Or use Python:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## Step 2: Update Entra ID App Registration

### 2.1 Get Your Frontend HTTPS URL

After deploying the infrastructure (or after the build succeeds), you'll have:

```
https://<frontend-container-app-fqdn>
```

The FQDN follows this pattern: `https://<frontendContainerAppName>.<location>.azurecontainerapps.io`

For example:
```
https://ti-rss-feed-frontend.centralus.azurecontainerapps.io
```

### 2.2 Update Reply URIs

1. Go to **Azure Portal** → **Entra ID** → **App registrations**
2. Find your NextAuth app registration (search for "ti-rss-feed" or similar)
3. Click **Authentication** in the left sidebar
4. Under **Redirect URIs**, find and **remove** any HTTP entries (e.g., `http://localhost:3000/api/auth/callback/azure-ad`)
5. Click **Add URI** and add:
   ```
   https://<your-frontend-fqdn>/api/auth/callback/azure-ad
   ```
   Example:
   ```
   https://ti-rss-feed-frontend.centralus.azurecontainerapps.io/api/auth/callback/azure-ad
   ```
6. Click **Save**

### 2.3 Verify Client Secret Validity

1. Go to **Certificates & secrets**
2. Check that you have a valid **Client Secret** (not expired)
3. If expired, create a new one:
   - Click **New client secret**
   - Set expiration (recommended: 24 months)
   - Copy the **Value** (not the ID)
   - **⚠️ Save this immediately — you can't view it again**

---

## Step 3: Prepare Deployment Parameters

Create your `main.parameters.json` file with the required values:

```json
{
    "location": {
        "value": "centralus"
    },
    "environment": {
        "value": "prod"
    },
    "projectName": {
        "value": "ti-rss-feed"
    },
    "nextAuthSecret": {
        "value": "<generated-secret-from-step-1>"
    },
    "azureAdClientId": {
        "value": "<from-entra-id-app-registration-overview>"
    },
    "azureAdClientSecret": {
        "value": "<from-entra-id-certificates-and-secrets>"
    },
    "azureAdTenantId": {
        "value": "<your-entra-id-tenant-id>"
    },
    "apiSecretKey": {
        "value": "<your-existing-api-secret-key>"
    },
    "azureFoundryApiKey": {
        "value": "<your-existing-foundry-key>"
    },
    "azureFoundryEndpoint": {
        "value": "https://<resource>.services.ai.azure.com/anthropic"
    }
}
```

### Where to Find These Values

**azureAdClientId** & **azureAdTenantId**:
1. Entra ID → App registrations → Your app
2. Copy from **Overview** page:
   - Application (client) ID
   - Directory (tenant) ID

**azureAdClientSecret**:
1. Entra ID → App registrations → Your app
2. Go to **Certificates & secrets**
3. Under **Client secrets**, copy the **Value** of an active secret

---

## Step 4: Deploy

Deploy using Azure CLI or PowerShell:

```bash
# Azure CLI
az deployment group create \
  --resource-group <your-rg> \
  --template-file infra/main.bicep \
  --parameters infra/main.parameters.json
```

Or use your existing deploy script after updating parameters.

---

## Step 5: Verify HTTPS Redirect

After deployment:

1. Get the frontend FQDN from deployment output:
   ```bash
   az deployment group show \
     --resource-group <your-rg> \
     --name <deployment-name> \
     --query properties.outputs.frontendContainerAppUrl.value
   ```

2. Visit the frontend in a browser:
   ```
   https://<frontend-fqdn>
   ```

3. Click **Sign in** and verify:
   - ✅ No cert errors (HTTPS working)
   - ✅ Redirects to Microsoft login (Entra ID callback working)
   - ✅ Returns to frontend without AADSTS errors (reply URI registered)

---

## Troubleshooting

### Still getting AADSTS500117?

1. **Verify the reply URI is exactly correct**:
   - No `http://` (must be `https://`)
   - Includes `/api/auth/callback/azure-ad` path
   - Domain matches your container app FQDN
   - No typos or trailing slashes

2. **Wait for Entra ID to sync**:
   - Changes can take 1-2 minutes
   - Try incognito/private browsing to avoid cache

3. **Check NEXTAUTH_URL env var**:
   - Verify in Container App → Environment variables
   - Must be `https://` (matching the reply URI)

### Frontend build failing?

- Ensure `npm install` ran successfully (fixes package-lock.json)
- Check Docker build logs in ACR

### Backend can't reach frontend (CORS)?

- Verify `ALLOWED_ORIGINS` in backend container app
- Should be `https://<frontend-fqdn>` (set automatically by Bicep)

---

## Reference: NextAuth Configuration

The `[...nextauth].js` is configured to:

1. Use Azure AD provider with your credentials
2. Exchange Entra ID tokens for app JWT on login
3. Store JWT in session
4. Return user role/email to frontend

**Key environment variables** (now injected by Container App):
- `AZURE_AD_CLIENT_ID` — OAuth client ID
- `AZURE_AD_CLIENT_SECRET` — OAuth client secret  
- `AZURE_AD_TENANT_ID` — Entra ID tenant
- `NEXTAUTH_URL` — NextAuth callback base URL (MUST be HTTPS)
- `NEXTAUTH_SECRET` — Session encryption key

---

## Summary of Changes

| Component | Before | After |
|-----------|--------|-------|
| Frontend URL | HTTP (broken) | HTTPS Container App FQDN |
| NEXTAUTH_URL env | Not set | Auto-configured HTTPS |
| Entra ID reply URI | HTTP (rejected) | HTTPS (required) |
| Backend CORS | HTTP frontend URL | HTTPS frontend URL |
| NextAuth secret | Not configured | Bicep parameter → secret |

---

For questions or issues, check:
1. Azure Portal → Container Apps → Logs
2. Azure Portal → Entra ID → App registration → Authentication tab
3. Browser console for client-side NextAuth errors
