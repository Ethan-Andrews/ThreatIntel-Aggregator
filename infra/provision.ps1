#Requires -Version 7
<#
.SYNOPSIS
    Provisions a migration onto Azure Container Apps from a migration.psd1 manifest.
.DESCRIPTION
    Order:
      1. Load manifest; interactively resolve missing core decisions (persisted back)
      2. az session check
      3. Platform: what-if + confirm + apply (idempotent - safe on existing platforms)
      4. App stack: what-if + confirm + apply (vault, identities, roles, storage)
      5. Ensure Key Vault secrets (prompted or -GenerateMissingSecrets)
      6. Easy Auth app registration + delegated scopes + tenant admin consent (if any app uses it)
      7. Import images into the shared ACR
      8. Apps: what-if + confirm + apply
      9. Easy Auth post-steps: redirect URIs (callback + app root for My Apps), homepage
     10. Post-checks
    Idempotent: safe to re-run.
.NOTES
    Requires: Contributor + User Access Administrator (or Owner) on the resource group,
    and for Easy Auth an Entra role able to create app registrations and grant
    tenant-wide admin consent (Application Administrator or higher).
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = './migration.psd1',
    [string]$SubscriptionId = '',
    [switch]$GenerateMissingSecrets,
    [switch]$SkipImageImport
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. "$PSScriptRoot/lib.ps1"

# ---------- 1. Manifest + interactive core decisions ----------
if (-not (Test-Path $ManifestPath)) {
    Copy-Item "$PSScriptRoot/migration.psd1.example" $ManifestPath
    Write-Host "Created $ManifestPath from the example. Fill in the Apps entries (and apps.bicep), then re-run." -ForegroundColor Yellow
    exit 1
}
$m = Import-PowerShellDataFile $ManifestPath

$updated = $false
if ([string]::IsNullOrWhiteSpace($m.ResourceGroup)) {
    $m.ResourceGroup = Read-WithDefault 'Resource group' 'my-resource-group'; $updated = $true
}
if ([string]::IsNullOrWhiteSpace($m.Location)) {
    $m.Location = Read-WithDefault 'Location' 'centralus'; $updated = $true
}
if ($null -eq $m.Platform) { $m.Platform = @{}; $updated = $true }
if ([string]::IsNullOrWhiteSpace($m.Platform.ResourceGroup)) {
    $m.Platform.ResourceGroup = $m.ResourceGroup; $updated = $true
}
if ([string]::IsNullOrWhiteSpace($m.Platform.Prefix)) {
    $m.Platform.Prefix = Read-WithDefault 'Platform prefix (lowercase alphanumeric, max 8 chars)' 'myplat'; $updated = $true
}
if ($null -eq $m.Platform.LogAnalytics) {
    $reuse = Read-WithDefault 'Reuse an existing Log Analytics workspace? (y/n)' 'y'
    $law = @{ UseExisting = ($reuse -eq 'y'); Name = ''; ResourceGroup = '' }
    if ($law.UseExisting) {
        $law.Name = Read-WithDefault 'Existing workspace name' ''
        $law.ResourceGroup = Read-WithDefault 'Workspace resource group' $m.Platform.ResourceGroup
    }
    $m.Platform.LogAnalytics = $law; $updated = $true
} elseif ($m.Platform.LogAnalytics.UseExisting -and [string]::IsNullOrWhiteSpace($m.Platform.LogAnalytics.Name)) {
    $m.Platform.LogAnalytics.Name = Read-WithDefault 'Existing Log Analytics workspace name' ''
    if ([string]::IsNullOrWhiteSpace($m.Platform.LogAnalytics.ResourceGroup)) {
        $m.Platform.LogAnalytics.ResourceGroup = Read-WithDefault 'Workspace resource group' $m.Platform.ResourceGroup
    }
    $updated = $true
}

# v1 constraint: platform and apps share a resource group (cross-RG environment
# storage would require module-scoped deployments - out of scope).
if ($m.Platform.ResourceGroup -ne $m.ResourceGroup) {
    throw "Platform.ResourceGroup ('$($m.Platform.ResourceGroup)') must equal ResourceGroup ('$($m.ResourceGroup)') in this version."
}
if (-not $m.Apps -or @($m.Apps).Count -eq 0) { throw 'Manifest has no Apps entries.' }
foreach ($app in $m.Apps) {
    foreach ($field in 'Name', 'Image', 'TargetPort') {
        if (-not $app[$field]) { throw "App entry missing required field '$field'." }
    }
}
$easyAuthApps = @($m.Apps | Where-Object { $_.EasyAuth })
if ($easyAuthApps.Count -gt 0 -and [string]::IsNullOrWhiteSpace($m.AppRegistrationName)) {
    $m.AppRegistrationName = Read-WithDefault 'Entra app registration name for Easy Auth' "$($m.AppPrefix)-auth"
    $updated = $true
}

if ($updated) {
    Set-Content -Path $ManifestPath -Value (ConvertTo-Psd1 -Value $m)
    Write-Host "Saved resolved decisions back to $ManifestPath" -ForegroundColor Yellow
}

Write-Host "`nResolved configuration:" -ForegroundColor Cyan
Write-Host "  Resource group : $($m.ResourceGroup)  ($($m.Location))"
Write-Host "  Platform prefix: $($m.Platform.Prefix)"
Write-Host "  Log Analytics  : $(if ($m.Platform.LogAnalytics.UseExisting) { "existing '$($m.Platform.LogAnalytics.Name)'" } else { 'new workspace' })"
Write-Host "  Apps           : $(@($m.Apps).Name -join ', ')"

# ---------- 2. Session ----------
Write-Host '==> Checking Azure CLI session' -ForegroundColor Cyan
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Invoke-Az login | Out-Null
    $account = Invoke-Az account show | ConvertFrom-Json
}
if ($SubscriptionId) {
    Invoke-Az account set --subscription $SubscriptionId | Out-Null
    $account = Invoke-Az account show | ConvertFrom-Json
}
Write-Host "    Subscription: $($account.name) ($($account.id))"
$operatorObjectId = (Invoke-Az ad signed-in-user show --query id -o tsv).Trim()

Invoke-Az group create --name $m.ResourceGroup --location $m.Location | Out-Null

# ---------- 3. Platform ----------
$lawName = if ($m.Platform.LogAnalytics.UseExisting) { $m.Platform.LogAnalytics.Name } else { '' }
$lawRg = if ($m.Platform.LogAnalytics.UseExisting -and $m.Platform.LogAnalytics.ResourceGroup) { $m.Platform.LogAnalytics.ResourceGroup } else { $m.Platform.ResourceGroup }
$platformParams = @(
    "platformPrefix=$($m.Platform.Prefix)"
    "existingLogAnalyticsName=$lawName"
    "existingLogAnalyticsResourceGroup=$lawRg"
)
Write-Host '==> Platform what-if' -ForegroundColor Cyan
az deployment group what-if --resource-group $m.ResourceGroup --template-file platform.bicep --parameters @platformParams
if ($LASTEXITCODE -ne 0) { throw 'platform what-if failed' }
Confirm-WhatIf -Stage 'platform'
$platform = (Invoke-Az deployment group create --resource-group $m.ResourceGroup --name "$($m.AppPrefix)-platform" `
    --template-file platform.bicep --parameters @platformParams -o json | ConvertFrom-Json).properties.outputs
$acrName = $platform.acrName.value
$acrLoginServer = $platform.acrLoginServer.value
$envName = $platform.envName.value

# ---------- 4. App stack ----------
$appNames = @($m.Apps | ForEach-Object { $_.Name })
$fileShares = @($m.Apps | Where-Object { $_.VolumeShare } | ForEach-Object { $_.VolumeShare } | Select-Object -Unique)
$stackParamsFile = Join-Path $env:TEMP "$($m.AppPrefix)-stack-params.json"
@{
    appPrefix = @{ value = $m.AppPrefix }
    appNames = @{ value = $appNames }
    acrName = @{ value = $acrName }
    envName = @{ value = $envName }
    fileShares = @{ value = $fileShares }
    operatorObjectId = @{ value = $operatorObjectId }
} | ConvertTo-Json -Depth 5 | Set-Content $stackParamsFile

Write-Host '==> App stack what-if' -ForegroundColor Cyan
az deployment group what-if --resource-group $m.ResourceGroup --template-file app-stack.bicep --parameters "@$stackParamsFile"
if ($LASTEXITCODE -ne 0) { throw 'app-stack what-if failed' }
Confirm-WhatIf -Stage 'app stack'
$stack = (Invoke-Az deployment group create --resource-group $m.ResourceGroup --name "$($m.AppPrefix)-stack" `
    --template-file app-stack.bicep --parameters "@$stackParamsFile" -o json | ConvertFrom-Json).properties.outputs
$kvName = $stack.keyVaultName.value
$identityIds = @($stack.identityIds.value)

# ---------- 5. Key Vault secrets ----------
Write-Host '==> Ensuring Key Vault secrets' -ForegroundColor Cyan
$deployOrchestratorJob = [bool]($m.Orchestrator -and $m.Orchestrator.Enabled)
$secretNames = @($m.Apps | ForEach-Object { if ($_.SecretEnv) { $_.SecretEnv.Values } }) | Where-Object { $_ } | Select-Object -Unique
if ($deployOrchestratorJob) {
    # Vendor-issued key. Same caveat as azure-foundry-api-key/runzero-api-token
    # above: -GenerateMissingSecrets will happily fabricate a random value for
    # this too, which is wrong for anything issued by an external provider.
    # Don't pass -GenerateMissingSecrets on a first run that includes these.
    $secretNames = @($secretNames) + 'DETECTIONSAIAPIKEY' | Select-Object -Unique
}
foreach ($secretName in $secretNames) {
    $exists = az keyvault secret show --vault-name $kvName --name $secretName --query id -o tsv 2>$null
    if ($exists) { Write-Host "    $secretName : already present"; continue }
    if ($GenerateMissingSecrets) {
        $value = New-RandomSecret
        Write-Host "    $secretName : generated"
    } else {
        $sec = Read-Host "    Value for Key Vault secret '$secretName'" -AsSecureString
        $value = [System.Net.NetworkCredential]::new('', $sec).Password
    }
    Set-KvSecretWithRetry -VaultName $kvName -Name $secretName -Value $value
}

# ---------- 6. Easy Auth app registration ----------
$appId = ''
if ($easyAuthApps.Count -gt 0) {
    Write-Host '==> Ensuring Entra app registration for Easy Auth' -ForegroundColor Cyan
    $appId = (az ad app list --display-name $m.AppRegistrationName --query '[0].appId' -o tsv 2>$null)
    if (-not $appId) {
        $appId = (Invoke-Az ad app create --display-name $m.AppRegistrationName `
            --sign-in-audience AzureADMyOrg --enable-id-token-issuance true --query appId -o tsv).Trim()
        Write-Host "    Created app registration $appId"
    } else {
        Write-Host "    Reusing app registration $appId"
    }

    # Delegated Graph sign-in scopes; tenant-wide admin consent avoids the
    # "Approval required" wall in tenants with user consent disabled.
    $graphApi = '00000003-0000-0000-c000-000000000000'
    $signInScopeIds = @(
        '37f7f235-527c-4136-accd-4a02d197296e' # openid
        '14dad69e-099b-42c9-810b-d002981feec1' # profile
        '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0' # email
        '7427e0e9-2fba-42fe-b0c0-848c9e6a8182' # offline_access
        'e1fe6dd8-ba31-4d61-89e7-88639da4683d' # User.Read
    )
    foreach ($scopeId in $signInScopeIds) {
        az ad app permission add --id $appId --api $graphApi --api-permissions "$scopeId=Scope" --only-show-errors 2>$null
    }
    az ad app permission admin-consent --id $appId --only-show-errors 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host '    Tenant-wide admin consent granted'
    } else {
        Write-Warning ("    Could not grant tenant-wide admin consent (needs Application Administrator or higher). " +
            "Manual command: az ad app permission admin-consent --id $appId")
    }

    $exists = az keyvault secret show --vault-name $kvName --name easyauth-client-secret --query id -o tsv 2>$null
    if (-not $exists) {
        $clientSecret = (Invoke-Az ad app credential reset --id $appId --append `
            --display-name 'aca-easyauth' --years 2 --query password -o tsv).Trim()
        Set-KvSecretWithRetry -VaultName $kvName -Name easyauth-client-secret -Value $clientSecret
        Write-Host '    easyauth-client-secret: generated and stored'
    } else {
        Write-Host '    easyauth-client-secret: already present'
    }
}

# ---------- 7. Image import ----------
if (-not $SkipImageImport) {
    Write-Host '==> Importing images into the shared ACR' -ForegroundColor Cyan
    foreach ($app in $m.Apps) {
        if (-not $app.Source) { Write-Host "    $($app.Name): image already in ACR, skipping"; continue }
        $importArgs = @('acr', 'import', '--name', $acrName, '--force', '--source', $app.Source, '--image', $app.Image)
        if ($app.SourceAuth) {
            $user = Read-Host "    Registry username for $($app.Source)"
            $sec = Read-Host '    Registry password/PAT' -AsSecureString
            $importArgs += @('--username', $user, '--password', [System.Net.NetworkCredential]::new('', $sec).Password)
        }
        Invoke-Az @importArgs | Out-Null
        Write-Host "    Imported $($app.Source) -> $($app.Image)"
    }
}

# ---------- 8. Apps ----------
$appsParamsFile = Join-Path $env:TEMP "$($m.AppPrefix)-apps-params.json"
$appsParams = @{
    envName = @{ value = $envName }
    acrLoginServer = @{ value = $acrLoginServer }
    keyVaultName = @{ value = $kvName }
    identityIds = @{ value = $identityIds }
    aadClientId = @{ value = $appId }
}
if ($deployOrchestratorJob) {
    $appsParams.deployOrchestratorJob = @{ value = $true }
    if ($m.Orchestrator.SentinelWorkspaceId) {
        $appsParams.sentinelWorkspaceId = @{ value = $m.Orchestrator.SentinelWorkspaceId }
    }
    if ($m.Orchestrator.Schedule) {
        $appsParams.orchestratorSchedule = @{ value = $m.Orchestrator.Schedule }
    }
}
$appsParams | ConvertTo-Json -Depth 5 | Set-Content $appsParamsFile

Write-Host '==> Apps what-if' -ForegroundColor Cyan
az deployment group what-if --resource-group $m.ResourceGroup --template-file apps.bicep --parameters "@$appsParamsFile"
if ($LASTEXITCODE -ne 0) { throw 'apps what-if failed' }
Confirm-WhatIf -Stage 'apps'
$apps = (Invoke-Az deployment group create --resource-group $m.ResourceGroup --name "$($m.AppPrefix)-apps" `
    --template-file apps.bicep --parameters "@$appsParamsFile" -o json | ConvertFrom-Json).properties.outputs
$fqdns = @($apps.appFqdns.value)

# ---------- 9. Easy Auth post-steps ----------
if ($easyAuthApps.Count -gt 0) {
    Write-Host '==> Easy Auth redirect URIs + homepage' -ForegroundColor Cyan
    $redirects = @()
    $homepage = ''
    for ($i = 0; $i -lt @($m.Apps).Count; $i++) {
        $app = @($m.Apps)[$i]
        if (-not $app.EasyAuth) { continue }
        $root = "https://$($fqdns[$i])"
        # Both URIs: the Easy Auth callback AND the app root - the My Apps
        # launcher uses the homepage as a redirect target.
        $redirects += "$root/.auth/login/aad/callback"
        $redirects += $root
        if (-not $homepage) { $homepage = $root }
    }
    Invoke-Az ad app update --id $appId --web-redirect-uris @redirects --web-home-page-url $homepage | Out-Null
}

# ---------- 10. Post-checks ----------
Write-Host "`n==> Post-checks" -ForegroundColor Cyan
for ($i = 0; $i -lt @($m.Apps).Count; $i++) {
    $app = @($m.Apps)[$i]
    $fqdn = $fqdns[$i]
    $state = (az containerapp show -g $m.ResourceGroup -n $app.Name --query properties.provisioningState -o tsv 2>$null)
    if ($state -eq 'Succeeded') {
        Write-Host "    [PASS] $($app.Name): provisioning Succeeded"
    } else {
        Write-Warning "    [CHECK] $($app.Name): provisioningState = $state (Key Vault reference failures surface here)"
    }
    if ($app.External) {
        try {
            $resp = Invoke-WebRequest -Uri "https://$fqdn" -MaximumRedirection 0 -SkipHttpErrorCheck -TimeoutSec 15
            if ($app.EasyAuth) {
                if ($resp.StatusCode -in 301, 302 -and "$($resp.Headers.Location)" -like '*login.microsoftonline.com*') {
                    Write-Host "    [PASS] $($app.Name): anonymous request redirects to Entra sign-in"
                } else {
                    Write-Warning "    [CHECK] $($app.Name): returned $($resp.StatusCode), expected Entra redirect"
                }
            } elseif ($resp.StatusCode -lt 400) {
                Write-Host "    [PASS] $($app.Name): responds ($($resp.StatusCode))"
            } else {
                Write-Warning "    [CHECK] $($app.Name): returned $($resp.StatusCode)"
            }
        } catch {
            Write-Warning "    [CHECK] $($app.Name): could not probe - $_"
        }
    } else {
        try {
            Invoke-WebRequest -Uri "https://$fqdn" -TimeoutSec 10 | Out-Null
            Write-Warning "    [FAIL] $($app.Name): responded from the internet - should be internal-only!"
        } catch {
            Write-Host "    [PASS] $($app.Name): not reachable from the internet"
        }
    }
}

Write-Host "`nProvisioning complete." -ForegroundColor Green
for ($i = 0; $i -lt @($m.Apps).Count; $i++) {
    Write-Host "  $(@($m.Apps)[$i].Name) : https://$($fqdns[$i])$(if (-not @($m.Apps)[$i].External) { ' (internal only)' })"
}
Write-Host "  Key Vault : $kvName"
Write-Host "  ACR       : $acrName"
