// ti-aggregator container apps, self-contained.
//
// Creates the user-assigned identities, grants them AcrPull and Key Vault
// Secrets User, and deploys both apps. No modules, so there are no missing
// files and no ordering problem between identity creation and app deployment.
//
// Assumes platform-vnet.bicep has already created the environment, ACR and
// private DNS zone, and that the Key Vault already holds the secrets listed at
// the bottom of this file.

@description('Region')
param location string = resourceGroup().location

@description('Container Apps environment name from the platform deployment')
param envName string

@description('ACR name (not the login server), e.g. acrmyplatxxxxxxxxxxxx')
param acrName string

@description('Existing Key Vault name holding the application secrets')
param keyVaultName string

@description('Entra tenant ID, used by NextAuth and by the API for token validation')
param aadTenantId string

@description('''
Entra application (client) ID. MUST be a GUID such as
12345678-90ab-cdef-1234-567890abcdef. A secret value here produces
AADSTS90112 at sign-in. Never pass a secret as a deployment parameter:
parameters are stored in ARM deployment history in plaintext.
''')
param aadClientId string

@description('Azure AI Foundry endpoint for triage')
param foundryEndpoint string

@description('Foundry deployment name, e.g. claude-haiku-4-5')
param foundryDeployment string

@description('Foundry API version')
param foundryApiVersion string

@description('''
Exactly one replica may run APScheduler. Postgres removed the data-loss risk of
multiple replicas but not the scheduler risk: N replicas means N schedulers, 63
feeds polled N times every 15 minutes, and N times the triage spend. This
constraint lifts only when the scheduler moves to a Container Apps Job.
''')
param enableScheduler bool = true

@description('Backend image tag')
param apiImageTag string = 'latest'

@description('Frontend image tag')
param uiImageTag string = 'latest'

@description('''
Deploy the detections.ai pipeline orchestrator (backend/detection_pipeline/orchestrator.py)
as a scheduled Container Apps Job. Off by default -- this is the Azure+API tier's
opt-in vendor pipeline, separate from the always-on api/ui apps above. Requires
a "DETECTIONSAIAPIKEY" secret in the Key Vault; if sentinelWorkspaceId is set,
also grant the job identity Log Analytics Reader on that workspace out of band
(different resource group, so not wired here).
''')
param deployOrchestratorJob bool = false

@description('Sentinel/Log Analytics workspace customer id (a GUID, not the resource name). Leave blank to skip Sentinel-backed backtesting.')
param sentinelWorkspaceId string = ''

@description('Cron schedule (UTC) for the orchestrator job.')
param orchestratorSchedule string = '*/30 * * * *'

// ---------------------------------------------------------------- existing

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: envName
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

var acrLoginServer = acr.properties.loginServer
var uiName = 'ca-tiagg-ui'
var apiName = 'ca-tiagg-api'

// FQDNs are derived from the environment default domain rather than from
// resource references. The API needs the UI FQDN for ALLOWED_ORIGINS and the UI
// needs the API FQDN for BACKEND_URL; referencing both ways would be circular.
//
// api's ingress is external: false (see below), and Azure Container Apps
// gives internal-only apps a DIFFERENT FQDN pattern than external ones --
// '<name>.internal.<defaultDomain>', not '<name>.<defaultDomain>'. Omitting
// the internal. segment here produced a BACKEND_URL that pointed at a
// hostname no container app has ever had, silently breaking the same-origin
// API proxy (frontend/pages/api/[...proxy].js in the prod repo) from the
// day it was added -- confirmed live in prod (2026-08-20): every /api/*
// request came back with Azure's own "Container App is stopped or does not
// exist" page, forwarded verbatim by the proxy since it just relays
// whatever fetch(BACKEND_URL) returns. ui's own FQDN needs no such prefix
// since ui's ingress is external: true.
var uiFqdn = '${uiName}.${cae.properties.defaultDomain}'
var apiFqdn = '${apiName}.internal.${cae.properties.defaultDomain}'

// -------------------------------------------------------------- identities

resource uiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${uiName}'
  location: location
}

resource apiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${apiName}'
  location: location
}

resource orchestratorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployOrchestratorJob) {
  name: 'id-job-tiagg-orchestrator'
  location: location
}

// AcrPull, so neither app needs the registry admin password.
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
// Key Vault Secrets User, for secret references at container start.
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource uiAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, uiIdentity.id, acrPullRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: uiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, apiIdentity.id, acrPullRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource uiKvSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, uiIdentity.id, kvSecretsUserRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: uiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiKvSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, apiIdentity.id, kvSecretsUserRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: apiIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource orchestratorAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployOrchestratorJob) {
  scope: acr
  name: guid(acr.id, orchestratorIdentity.id, acrPullRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: orchestratorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource orchestratorKvSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployOrchestratorJob) {
  scope: kv
  name: guid(kv.id, orchestratorIdentity.id, kvSecretsUserRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: orchestratorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ----------------------------------------------------- backend, internal

resource api 'Microsoft.App/containerApps@2024-03-01' = {
  name: apiName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${apiIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false
        targetPort: 8000
        transport: 'auto'
        // Siblings call this over plain HTTP inside the environment; the
        // wildcard certificate does not cover internal FQDNs.
        allowInsecure: true
      }
      registries: [
        {
          server: acrLoginServer
          identity: apiIdentity.id
        }
      ]
      secrets: [
        {
          name: 'pg-dsn'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/pg-dsn'
          identity: apiIdentity.id
        }
        {
          name: 'jwt-secret-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/jwt-secret-key'
          identity: apiIdentity.id
        }
        {
          name: 'runzero-api-token'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/runzero-api-token'
          identity: apiIdentity.id
        }
        {
          name: 'azure-foundry-api-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/azure-foundry-api-key'
          identity: apiIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: apiName
          image: '${acrLoginServer}/tiagg-api:${apiImageTag}'
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          env: [
            { name: 'PG_DSN', secretRef: 'pg-dsn' }
            { name: 'JWT_SECRET_KEY', secretRef: 'jwt-secret-key' }
            { name: 'RUNZERO_API_TOKEN', secretRef: 'runzero-api-token' }
            { name: 'AZURE_FOUNDRY_API_KEY', secretRef: 'azure-foundry-api-key' }
            { name: 'ENABLE_SCHEDULER', value: string(enableScheduler) }
            { name: 'ALLOWED_ORIGINS', value: 'https://${uiFqdn}' }
            { name: 'AZURE_AD_CLIENT_ID', value: aadClientId }
            { name: 'AZURE_AD_TENANT_ID', value: aadTenantId }
            { name: 'AI_PROVIDER', value: 'azure' }
            { name: 'AZURE_FOUNDRY_ENDPOINT', value: foundryEndpoint }
            { name: 'AZURE_FOUNDRY_DEPLOYMENT', value: foundryDeployment }
            { name: 'AZURE_FOUNDRY_API_VERSION', value: foundryApiVersion }
            { name: 'PG_POOL_MIN', value: '1' }
            { name: 'PG_POOL_MAX', value: '10' }
            // DefaultAzureCredential (SentinelClient, detection_pipeline/sentinel.py) can't pick
            // a user-assigned identity on its own -- with no system-assigned identity attached,
            // ManagedIdentityCredential fails "(invalid_scope) 400, Unable to load the proper
            // Managed Identity" unless told which client ID to use. azure-identity reads
            // AZURE_CLIENT_ID as a fallback for exactly this. Confirmed live in prod
            // (2026-08-20): control-probe calls failed with this error until the env var was set.
            { name: 'AZURE_CLIENT_ID', value: apiIdentity.properties.clientId }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: { path: '/healthz', port: 8000 }
              initialDelaySeconds: 10
              periodSeconds: 5
              failureThreshold: 24 // 120s budget for schema verification
            }
            {
              type: 'Liveness'
              // No database access: a slow query must not restart a healthy
              // container. Readiness at /readyz does check the pool.
              httpGet: { path: '/healthz', port: 8000 }
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: { path: '/readyz', port: 8000 }
              periodSeconds: 15
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        // Fixed at 1 while APScheduler runs inside the API process.
        maxReplicas: 1
      }
    }
  }
  dependsOn: [ apiAcrPull, apiKvSecrets ]
}

// -------------------------------------------------------- frontend, public

resource ui 'Microsoft.App/containerApps@2024-03-01' = {
  name: uiName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uiIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
      }
      registries: [
        {
          server: acrLoginServer
          identity: uiIdentity.id
        }
      ]
      secrets: [
        {
          name: 'nextauth-secret'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/nextauth-secret'
          identity: uiIdentity.id
        }
        {
          name: 'azure-ad-client-secret'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/azure-ad-client-secret'
          identity: uiIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: uiName
          image: '${acrLoginServer}/tiagg-ui:${uiImageTag}'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'NEXTAUTH_SECRET', secretRef: 'nextauth-secret' }
            { name: 'AZURE_AD_CLIENT_SECRET', secretRef: 'azure-ad-client-secret' }
            { name: 'NEXTAUTH_URL', value: 'https://${uiFqdn}' }
            { name: 'AZURE_AD_CLIENT_ID', value: aadClientId }
            { name: 'AZURE_AD_TENANT_ID', value: aadTenantId }
            // http, not https: the environment wildcard certificate does not
            // cover internal FQDNs.
            { name: 'BACKEND_URL', value: 'http://${apiFqdn}' }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2 // stateless, safe to scale
      }
    }
  }
  dependsOn: [ uiAcrPull, uiKvSecrets ]
}

// ------------------------------------------------- detections.ai orchestrator
// Opt-in, Azure+API tier only. Same image as the api app; overrides the
// entrypoint to run the pipeline once and exit, on a cron schedule, rather
// than serving HTTP. See backend/detection_pipeline/orchestrator.py's module
// docstring for the env vars it reads.

resource orchestratorJob 'Microsoft.App/jobs@2024-03-01' = if (deployOrchestratorJob) {
  name: 'job-tiagg-orchestrator'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentity.id}': {}
    }
  }
  properties: {
    environmentId: cae.id
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: orchestratorSchedule
        parallelism: 1
        replicaCompletionCount: 1
      }
      replicaTimeout: 1800
      replicaRetryLimit: 1
      registries: [
        {
          server: acrLoginServer
          identity: orchestratorIdentity.id
        }
      ]
      secrets: [
        {
          name: 'pg-dsn'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/pg-dsn'
          identity: orchestratorIdentity.id
        }
        {
          name: 'detections-ai-api-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/DETECTIONSAIAPIKEY'
          identity: orchestratorIdentity.id
        }
        {
          name: 'azure-foundry-api-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/azure-foundry-api-key'
          identity: orchestratorIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'orchestrator'
          image: '${acrLoginServer}/tiagg-api:${apiImageTag}'
          command: [ 'python', 'detection_pipeline/orchestrator.py' ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'PG_DSN', secretRef: 'pg-dsn' }
            { name: 'DETECTIONS_AI_API_KEY', secretRef: 'detections-ai-api-key' }
            { name: 'AI_PROVIDER', value: 'azure' }
            { name: 'AZURE_FOUNDRY_API_KEY', secretRef: 'azure-foundry-api-key' }
            { name: 'AZURE_FOUNDRY_ENDPOINT', value: foundryEndpoint }
            { name: 'AZURE_FOUNDRY_DEPLOYMENT', value: foundryDeployment }
            { name: 'AZURE_FOUNDRY_API_VERSION', value: foundryApiVersion }
            { name: 'SENTINEL_WORKSPACE_ID', value: sentinelWorkspaceId }
            // Same DefaultAzureCredential managed-identity-selection issue as ca-tiagg-api above
            // -- job-tiagg-orchestrator only has orchestratorIdentity attached, no
            // system-assigned identity, so ManagedIdentityCredential needs an explicit client ID.
            { name: 'AZURE_CLIENT_ID', value: orchestratorIdentity.properties.clientId }
          ]
        }
      ]
    }
  }
  dependsOn: [ orchestratorAcrPull, orchestratorKvSecrets ]
}

output uiUrl string = 'https://${ui.properties.configuration.ingress.fqdn}'
output apiInternalFqdn string = apiFqdn
output uiIdentityPrincipalId string = uiIdentity.properties.principalId
output apiIdentityPrincipalId string = apiIdentity.properties.principalId

// Key Vault secrets this template expects:
//   pg-dsn                  (already stored)
//   jwt-secret-key
//   runzero-api-token
//   azure-foundry-api-key
//   nextauth-secret
//   azure-ad-client-secret
//   DETECTIONSAIAPIKEY      (only if deployOrchestratorJob = true; local alias 'detections-ai-api-key' above)
//
// If deployOrchestratorJob = true and sentinelWorkspaceId is set, the job's
// managed identity (output: orchestratorIdentityPrincipalId) also needs
// "Log Analytics Reader" on that workspace, granted out of band -- the
// workspace usually lives in a different resource group than this stack:
//   az role assignment create --assignee <orchestratorIdentityPrincipalId> \
//     --role "Log Analytics Reader" --scope <workspace-resource-id>

output orchestratorIdentityPrincipalId string = deployOrchestratorJob ? orchestratorIdentity.properties.principalId : ''
