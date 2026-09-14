// Per-app isolation layer (one deployment per migration):
//   Key Vault (one per app per environment, per the azure-key-vault skill),
//   one user-assigned managed identity per container app,
//   least-privilege role assignments (AcrPull + Key Vault Secrets User),
//   optional Azure Files shares registered as environment storage.
// Requires the shared platform (ACR + environment) in the SAME resource group.

@description('Region')
param location string = resourceGroup().location

@description('Short lowercase alphanumeric prefix for this app\'s resources')
@maxLength(10)
param appPrefix string

@description('Container app names, one user-assigned identity is created per name. Order matters: outputs.identityIds matches this order.')
param appNames array

@description('Shared ACR name (same resource group, from platform outputs)')
param acrName string

@description('Container Apps environment name (same resource group, from platform outputs)')
param envName string

@description('Azure Files share names to create and register as environment storage. Empty = no storage.')
param fileShares array = []

@description('Object ID of the operator running provision.ps1 - granted Key Vault Secrets Officer')
param operatorObjectId string

var suffix = uniqueString(resourceGroup().id, appPrefix)
var needsStorage = !empty(fileShares)

var acrPullRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d') // AcrPull
var kvSecretsUserRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6') // Key Vault Secrets User
var kvSecretsOfficerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7') // Key Vault Secrets Officer

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: envName
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('kv-${appPrefix}-${suffix}', 24)
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
  }
}

resource mis 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = [for appName in appNames: {
  name: 'id-${appName}'
  location: location
}]

resource acrPulls 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (appName, i) in appNames: {
  name: guid(acr.id, appName, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: acrPullRoleId
    principalId: mis[i].properties.principalId
    principalType: 'ServicePrincipal'
  }
}]

resource kvReads 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (appName, i) in appNames: {
  name: guid(kv.id, appName, kvSecretsUserRoleId)
  scope: kv
  properties: {
    roleDefinitionId: kvSecretsUserRoleId
    principalId: mis[i].properties.principalId
    principalType: 'ServicePrincipal'
  }
}]

resource operatorKvWrite 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, operatorObjectId, kvSecretsOfficerRoleId)
  scope: kv
  properties: {
    roleDefinitionId: kvSecretsOfficerRoleId
    principalId: operatorObjectId
    principalType: 'User'
  }
}

resource st 'Microsoft.Storage/storageAccounts@2023-05-01' = if (needsStorage) {
  name: take('st${appPrefix}${suffix}', 24)
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = if (needsStorage) {
  parent: st
  name: 'default'
}

resource shares 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = [for share in fileShares: {
  parent: fileService
  name: share
  properties: {
    shareQuota: 100
  }
}]

resource envStorages 'Microsoft.App/managedEnvironments/storages@2024-03-01' = [for (share, i) in fileShares: {
  parent: cae
  name: share
  dependsOn: [shares[i]]
  properties: {
    azureFile: {
      accountName: st.name
      // Safe despite BCP422: this loop only runs when needsStorage is true, the same
      // condition that creates `st`, so ARM only evaluates this branch when `st` exists.
      #disable-next-line BCP422
      accountKey: st.listKeys().keys[0].value
      shareName: share
      accessMode: 'ReadWrite'
    }
  }
}]

output keyVaultName string = kv.name
output identityIds array = [for (appName, i) in appNames: mis[i].id]
output storageAccountName string = needsStorage ? st.name : ''
