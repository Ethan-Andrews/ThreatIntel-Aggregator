// Reusable container app. One module call per app in apps.bicep.
// Encodes the patterns proven in the Shadowbroker migration:
//   - internal apps get allowInsecure so siblings can call plain HTTP in-environment
//   - Key Vault secret references ride the same user-assigned identity as registry pull
//   - probes derived from a single path (startup with 120s budget + liveness)

@description('Container app name, e.g. ca-myapp-web')
param name string

@description('Region')
param location string

@description('Resource ID of the Container Apps environment')
param environmentId string

@description('Full image reference, e.g. myacr.azurecr.io/myapp:latest')
param image string

@description('Registry login server, e.g. myacr.azurecr.io')
param registryServer string

@description('Resource ID of the user-assigned identity (registry pull + Key Vault refs)')
param identityId string

@description('Key Vault name for secret references. Empty only if the app has no secrets.')
param keyVaultName string = ''

@description('true = public HTTPS ingress; false = environment-internal only')
param external bool

param targetPort int

@description('vCPU as a string, e.g. \'0.5\' or \'2.0\'')
param cpu string = '0.5'

@description('Memory, e.g. \'1Gi\' (must be a valid pair with cpu)')
param memory string = '1Gi'

param minReplicas int = 1
param maxReplicas int = 1

@description('Plain env vars: array of { name, value }')
param envVars array = []

@description('Secret-backed env vars: array of { envName, secretName } where secretName is the Key Vault secret name')
param secretEnv array = []

@description('Extra app secrets not surfaced as env vars (e.g. Easy Auth provider secret): array of { name, keyVaultSecretName }')
param extraSecrets array = []

@description('Environment storage name for an Azure Files volume. Empty = no volume.')
param storageName string = ''

@description('Mount path when storageName is set')
param mountPath string = '/app/data'

@description('SMB mount options for the Azure Files volume. Default nobrl keeps byte-range locks client-local - required for SQLite on Azure Files, safe for single-replica apps.')
param volumeMountOptions string = 'nobrl'

@description('HTTP GET path for startup + liveness probes. Empty = no probes.')
param probePath string = ''

var kvUri = keyVaultName == '' ? '' : 'https://${keyVaultName}${environment().suffixes.keyvaultDns}'

var secretDefs = [for s in secretEnv: {
  name: toLower(s.secretName)
  keyVaultUrl: '${kvUri}/secrets/${s.secretName}'
  identity: identityId
}]

var extraSecretDefs = [for s in extraSecrets: {
  name: s.name
  keyVaultUrl: '${kvUri}/secrets/${s.keyVaultSecretName}'
  identity: identityId
}]

var plainEnvDefs = [for e in envVars: {
  name: e.name
  value: e.value
}]

var secretEnvDefs = [for s in secretEnv: {
  name: s.envName
  secretRef: toLower(s.secretName)
}]

var probes = probePath == '' ? [] : [
  {
    type: 'Startup'
    httpGet: { path: probePath, port: targetPort }
    periodSeconds: 10
    failureThreshold: 12 // up to 120s to come up
  }
  {
    type: 'Liveness'
    httpGet: { path: probePath, port: targetPort }
    periodSeconds: 15
    failureThreshold: 5
  }
]

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    environmentId: environmentId
    configuration: {
      ingress: {
        external: external
        targetPort: targetPort
        transport: 'auto'
        // Internal apps accept plain HTTP from siblings inside the environment;
        // the wildcard TLS cert does not cover *.internal two-level FQDNs.
        allowInsecure: !external
      }
      registries: [
        {
          server: registryServer
          identity: identityId
        }
      ]
      secrets: concat(secretDefs, extraSecretDefs)
    }
    template: {
      containers: [
        {
          name: 'main'
          image: image
          resources: {
            cpu: json(cpu)
            memory: memory
          }
          env: concat(plainEnvDefs, secretEnvDefs)
          volumeMounts: storageName == '' ? [] : [
            {
              volumeName: 'appdata'
              mountPath: mountPath
            }
          ]
          probes: probes
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
      volumes: storageName == '' ? [] : [
        {
          name: 'appdata'
          storageType: 'AzureFile'
          storageName: storageName
          mountOptions: volumeMountOptions
        }
      ]
    }
  }
}

output fqdn string = app.properties.configuration.ingress.fqdn
output appName string = app.name
