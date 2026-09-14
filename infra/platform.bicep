// Shared platform, provisioned ONCE and reused by every migration:
//   Log Analytics (reuse existing - e.g. the Sentinel workspace - or create new),
//   Container Apps environment, shared ACR (Standard, admin account disabled).
// Idempotent: re-running with the same parameters is a no-op.

@description('Region')
param location string = resourceGroup().location

@description('Short lowercase alphanumeric prefix for platform resources')
@maxLength(8)
param platformPrefix string = 'myplat'

@description('Existing Log Analytics workspace name. Empty = create a new workspace.')
param existingLogAnalyticsName string = ''

@description('Resource group of the existing workspace (defaults to this resource group)')
param existingLogAnalyticsResourceGroup string = resourceGroup().name

@description('Retention in days for a newly created workspace')
param logRetentionDays int = 30

var suffix = uniqueString(resourceGroup().id, platformPrefix)
var useExistingLaw = existingLogAnalyticsName != ''

resource lawExisting 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (useExistingLaw) {
  name: existingLogAnalyticsName
  scope: resourceGroup(existingLogAnalyticsResourceGroup)
}

resource lawNew 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (!useExistingLaw) {
  name: 'log-${platformPrefix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: 'acr${platformPrefix}${suffix}'
  location: location
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
  }
}

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${platformPrefix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        // Safe despite BCP318/BCP422: each ternary branch is guarded by the same
        // condition that creates its resource, and ARM only evaluates the taken branch.
        #disable-next-line BCP318
        customerId: useExistingLaw ? lawExisting.properties.customerId : lawNew.properties.customerId
        #disable-next-line BCP422
        sharedKey: useExistingLaw ? lawExisting.listKeys().primarySharedKey : lawNew.listKeys().primarySharedKey
      }
    }
  }
}

output envName string = cae.name
output envId string = cae.id
output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
