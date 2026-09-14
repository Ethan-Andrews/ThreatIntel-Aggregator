// Entra ID built-in authentication (Easy Auth) for a container app.
// The app MUST declare an extraSecrets entry named
// 'microsoft-provider-authentication-secret' pointing at the Key Vault secret
// holding the app registration's client secret (see container-app.bicep).

@description('Name of the existing container app to protect')
param containerAppName string

@description('Entra app registration (client) ID')
param aadClientId string

resource app 'Microsoft.App/containerApps@2024-03-01' existing = {
  name: containerAppName
}

resource auth 'Microsoft.App/containerApps/authConfigs@2024-03-01' = {
  parent: app
  name: 'current'
  properties: {
    platform: {
      enabled: true
    }
    globalValidation: {
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
    }
    identityProviders: {
      azureActiveDirectory: {
        registration: {
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
          clientId: aadClientId
          clientSecretSettingName: 'microsoft-provider-authentication-secret'
        }
        validation: {
          allowedAudiences: [
            aadClientId
            'api://${aadClientId}'
          ]
        }
      }
    }
  }
}
