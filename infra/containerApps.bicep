param location string
param containerAppEnvName string
param backendContainerAppName string
param frontendContainerAppName string
param containerImage_Backend string
param containerImage_Frontend string
param acrLoginServer string
@secure()
param acrPassword string
param storageAccountName string
@secure()
param storageAccountKey string
param storageShareName string
param azureFoundryEndpoint string
param azureFoundryDeployment string
param azureFoundryApiVersion string
@secure()
param apiSecretKeyValue string
@secure()
param azureFoundryApiKeyValue string
@secure()
param nextAuthSecretValue string
@secure()
param azureAdClientIdValue string
@secure()
param azureAdClientSecretValue string
param azureAdTenantId string
param tags object = {}

var backendFqdn  = '${backendContainerAppName}.${containerAppEnvironment.properties.defaultDomain}'
var frontendFqdn = '${frontendContainerAppName}.${containerAppEnvironment.properties.defaultDomain}'

// Container Apps Environment
resource containerAppEnvironment 'Microsoft.App/managedEnvironments@2023-04-01-preview' = {
  name: containerAppEnvName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
    }
  }
}

// Azure Files storage credential for container app mounting
resource storageCredential 'Microsoft.App/managedEnvironments/storages@2023-04-01-preview' = {
  parent: containerAppEnvironment
  name: 'azure-file-share'
  properties: {
    azureFile: {
      accountName: storageAccountName
      accountKey: storageAccountKey
      shareName: storageShareName
      accessMode: 'ReadWrite'
    }
  }
}

// Backend Container App
resource backendContainerApp 'Microsoft.App/containerApps@2023-04-01-preview' = {
  name: backendContainerAppName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnvironment.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8000
        transport: 'auto'
      }
      registries: [
        {
          server: acrLoginServer
          username: 'admin'
          passwordSecretRef: 'registry-password'
        }
      ]
      secrets: [
        {
          name: 'registry-password'
          value: acrPassword
        }
        {
          name: 'api-secret-key'
          value: apiSecretKeyValue
        }
        {
          name: 'azure-foundry-api-key'
          value: azureFoundryApiKeyValue
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'backend'
          image: containerImage_Backend
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'AI_PROVIDER'
              value: 'azure'
            }
            {
              name: 'AZURE_FOUNDRY_ENDPOINT'
              value: azureFoundryEndpoint
            }
            {
              name: 'AZURE_FOUNDRY_DEPLOYMENT'
              value: azureFoundryDeployment
            }
            {
              name: 'AZURE_FOUNDRY_API_VERSION'
              value: azureFoundryApiVersion
            }
            {
              name: 'API_SECRET_KEY'
              secretRef: 'api-secret-key'
            }
            {
              name: 'AZURE_FOUNDRY_API_KEY'
              secretRef: 'azure-foundry-api-key'
            }
            {
              name: 'ALLOWED_ORIGINS'
              value: 'https://${frontendFqdn}'
            }
          ]
          volumeMounts: [
            {
              mountPath: '/data'
              volumeName: 'ti-data'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'ti-data'
          storageType: 'AzureFile'
          storageName: 'azure-file-share'
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
      }
    }
  }
  dependsOn: [
    storageCredential
  ]
}

// Frontend Container App
resource frontendContainerApp 'Microsoft.App/containerApps@2023-04-01-preview' = {
  name: frontendContainerAppName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnvironment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          username: 'admin'
          passwordSecretRef: 'registry-password'
        }
      ]
      secrets: [
        {
          name: 'registry-password'
          value: acrPassword
        }
        {
          name: 'nextauth-secret'
          value: nextAuthSecretValue
        }
        {
          name: 'azure-ad-client-id'
          value: azureAdClientIdValue
        }
        {
          name: 'azure-ad-client-secret'
          value: azureAdClientSecretValue
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'frontend'
          image: containerImage_Frontend
          resources: {
            cpu: json('0.5')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'NEXTAUTH_URL'
              value: 'https://${frontendFqdn}'
            }
            {
              name: 'NEXTAUTH_SECRET'
              secretRef: 'nextauth-secret'
            }
            {
              name: 'AZURE_AD_CLIENT_ID'
              secretRef: 'azure-ad-client-id'
            }
            {
              name: 'AZURE_AD_CLIENT_SECRET'
              secretRef: 'azure-ad-client-secret'
            }
            {
              name: 'AZURE_AD_TENANT_ID'
              value: azureAdTenantId
            }
            {
              name: 'BACKEND_URL'
              value: 'https://${backendFqdn}'
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
}

output containerAppEnvironmentId string = containerAppEnvironment.id
output containerAppEnvironmentName string = containerAppEnvironment.name
output backendUrl string = 'https://${backendFqdn}'
output frontendUrl string = 'https://${frontendFqdn}'
