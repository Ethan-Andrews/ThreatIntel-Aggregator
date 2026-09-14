targetScope = 'resourceGroup'

param location string = 'centralus'
param environment string = 'prod'
param projectName string = 'ti-rss-feed'

var deploymentTags = {
  environment: environment
  project: projectName
}

// Container Registry
param acrName string = 'acrti${uniqueString(subscription().id)}'
param acrSku string = 'Premium'

// Storage Account
param storageAccountName string = 'stiti${uniqueString(subscription().id)}'
param storageShareName string = 'ti-data'

// Key Vault
param keyVaultName string = 'kv-ti-${uniqueString(subscription().id)}'

// Container Apps
param containerAppEnvName string = '${projectName}-env'
param backendContainerAppName string = '${projectName}-backend'
param frontendContainerAppName string = '${projectName}-frontend'
param containerImage_Backend string = '${acrName}.azurecr.io/${projectName}-backend:latest'
param containerImage_Frontend string = '${acrName}.azurecr.io/${projectName}-frontend:latest'

// Secrets from .env - must be provided during deployment
@secure()
param apiSecretKey string

@secure()
param azureFoundryApiKey string

param azureFoundryEndpoint string = 'https://admineta-1732-resource.services.ai.azure.com/anthropic'
param azureFoundryDeployment string = 'claude-haiku-4-5'
param azureFoundryApiVersion string = '2025-05-01'

// NextAuth & Azure AD - must be provided during deployment
@secure()
param nextAuthSecret string

@secure()
param azureAdClientId string

@secure()
param azureAdClientSecret string

param azureAdTenantId string

// Container Registry
module acr 'containerRegistry.bicep' = {
  name: 'acrDeployment'
  params: {
    location: location
    acrName: acrName
    acrSku: acrSku
    tags: deploymentTags
  }
}

// Storage Account with File Share
module storage 'storageAccount.bicep' = {
  name: 'storageDeployment'
  params: {
    location: location
    storageAccountName: storageAccountName
    storageShareName: storageShareName
    tags: deploymentTags
  }
}

// Key Vault
module keyVault 'keyVault.bicep' = {
  name: 'keyVaultDeployment'
  params: {
    location: location
    keyVaultName: keyVaultName
    apiSecretKey: apiSecretKey
    azureFoundryApiKey: azureFoundryApiKey
    tags: deploymentTags
  }
}

// Container Apps Environment + Apps
module containerApps 'containerApps.bicep' = {
  name: 'containerAppsDeployment'
  params: {
    location: location
    containerAppEnvName: containerAppEnvName
    backendContainerAppName: backendContainerAppName
    frontendContainerAppName: frontendContainerAppName
    containerImage_Backend: containerImage_Backend
    containerImage_Frontend: containerImage_Frontend
    acrLoginServer: acr.outputs.loginServer
    acrPassword: acr.outputs.adminPassword
    storageAccountName: storage.outputs.storageAccountName
    storageAccountKey: storage.outputs.storageAccountKey
    storageShareName: storageShareName
    azureFoundryEndpoint: azureFoundryEndpoint
    azureFoundryDeployment: azureFoundryDeployment
    azureFoundryApiVersion: azureFoundryApiVersion
    apiSecretKeyValue: apiSecretKey
    azureFoundryApiKeyValue: azureFoundryApiKey
    nextAuthSecretValue: nextAuthSecret
    azureAdClientIdValue: azureAdClientId
    azureAdClientSecretValue: azureAdClientSecret
    azureAdTenantId: azureAdTenantId
    tags: deploymentTags
  }
}

output resourceGroupName string = resourceGroup().name
output acrLoginServer string = acr.outputs.loginServer
output containerAppEnvironmentName string = containerAppEnvName
output backendContainerAppUrl string = containerApps.outputs.backendUrl
output frontendContainerAppUrl string = containerApps.outputs.frontendUrl
output keyVaultName string = keyVault.outputs.keyVaultName
