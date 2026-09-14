param location string
param keyVaultName string
param tags object = {}

@secure()
param apiSecretKey string

@secure()
param azureFoundryApiKey string

var tenantId = subscription().tenantId

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    accessPolicies: []
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
  }
}

resource apiSecretKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'ApiSecretKey'
  properties: {
    value: apiSecretKey
  }
}

resource azureFoundryApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'AzureFoundryApiKey'
  properties: {
    value: azureFoundryApiKey
  }
}

output keyVaultUrl string = keyVault.properties.vaultUri
output keyVaultName string = keyVault.name
output apiSecretKeySecretId string = apiSecretKeySecret.id
output azureFoundryApiKeySecretId string = azureFoundryApiKeySecret.id
