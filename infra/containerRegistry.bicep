param location string
param acrName string
param acrSku string = 'Premium'
param tags object = {}

resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: acrName
  location: location
  tags: tags
  sku: {
    name: acrSku
  }
  properties: {
    adminUserEnabled: true
    publicNetworkAccess: 'Enabled'
    networkRuleBypassOptions: 'AzureServices'
  }
}

output loginServer string = containerRegistry.properties.loginServer
output registryId string = containerRegistry.id
output registryName string = containerRegistry.name
@description('ACR admin password — consumed only within Bicep module, never exposed as a deployment output.')
#disable-next-line outputs-should-not-contain-secrets
output adminPassword string = containerRegistry.listCredentials().passwords[0].value
