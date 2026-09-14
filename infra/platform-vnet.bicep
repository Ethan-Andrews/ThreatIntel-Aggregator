// Shared platform for ti-aggregator, provisioned once.
//
// Adds two subnets to the EXISTING SentinelLogForwarder-vnet rather than
// creating a new virtual network, then builds:
//
//   Container Apps environment, workload profiles, VNet integrated
//   Private DNS zone for the Postgres private endpoint, linked to the VNet
//   Log Analytics (reuse the Sentinel workspace, or create new)
//   Shared ACR (Standard, admin account disabled)
//
// WHY SUBNETS ARE CHILD RESOURCES
//
// The parent virtualNetworks resource is referenced with `existing` and never
// redeclared. Declaring a virtualNetworks resource with a `subnets` array would
// REPLACE the subnet collection, silently deleting the Sentinel log forwarder
// subnet and breaking that VM. Child subnet resources are additive.
//
// Neither the Container Apps network type nor its subnet size can be changed
// after the environment is created.

@description('Region. Must match the existing VNet region.')
param location string = resourceGroup().location

@description('Short lowercase alphanumeric prefix for platform resources')
@maxLength(8)
param platformPrefix string = 'fs'

// ---------------------------------------------------------------- networking

@description('Name of the existing virtual network to extend')
param existingVnetName string = 'SentinelLogForwarder-vnet'

@description('''
Subnet for Container Apps infrastructure. Delegated to Microsoft.App/environments
and dedicated to that environment; no other resource may use it.

Minimum /27 for a workload profile environment. /24 is used here because the size
is permanent for the life of the environment, and a /27 leaves only 18 usable
addresses which single-revision deployments temporarily double.

MUST NOT overlap the existing Sentinel log forwarder subnet. Verify with:
  az network vnet subnet list -g <rg> --vnet-name <vnet> -o table
''')
param acaSubnetPrefix string = '10.0.10.0/24'

@description('''
Subnet for private endpoints: Postgres now, possibly Key Vault or storage later.
An ordinary subnet with no delegation, unlike the Container Apps subnet.
''')
param privateEndpointSubnetPrefix string = '10.0.11.0/26'

@description('''
false: the environment gets a public IP and external ingress works, matching
the current ACI deployment where the UI is reachable from the corporate network
and protected by Entra sign-in.

true: internal only. The UI becomes reachable solely from inside the VNet or
over VPN or ExpressRoute. Cannot be changed after creation.
''')
param internalOnly bool = false

// ------------------------------------------------------------ log analytics

@description('Existing Log Analytics workspace name. Empty = create a new one.')
param existingLogAnalyticsName string = ''

@description('Resource group of the existing workspace (defaults to this resource group)')
param existingLogAnalyticsResourceGroup string = resourceGroup().name

@description('Retention in days for a newly created workspace')
param logRetentionDays int = 30

// ---------------------------------------------------------------- resources

var suffix = uniqueString(resourceGroup().id, platformPrefix)
var useExistingLaw = existingLogAnalyticsName != ''

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  name: existingVnetName
}

resource acaSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: vnet
  name: 'snet-aca-infra'
  properties: {
    addressPrefix: acaSubnetPrefix
    delegations: [
      {
        name: 'aca-delegation'
        properties: {
          serviceName: 'Microsoft.App/environments'
        }
      }
    ]
  }
}

resource peSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: vnet
  name: 'snet-private-endpoints'
  properties: {
    addressPrefix: privateEndpointSubnetPrefix
    // Private endpoint NICs need no delegation, and network policies must allow
    // the endpoint to be created.
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
  // Azure serialises writes to a virtual network. Two subnet creations issued in
  // parallel against the same VNet fail with a conflict, so this one waits.
  dependsOn: [ acaSubnet ]
}

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
    vnetConfiguration: {
      infrastructureSubnetId: acaSubnet.id
      internal: internalOnly
    }
    // Declaring a workload profile makes this a workload profiles environment
    // rather than the legacy Consumption-only type. Required for private
    // endpoints, user defined routes, and NAT gateway egress, and it is why the
    // subnet minimum is /27 rather than /23.
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

// Private DNS zone for the Postgres private endpoint. The name is fixed:
// automatic DNS configuration only fires on this exact zone name.
resource pgDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.postgres.database.azure.com'
  location: 'global'
}

resource pgDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: pgDnsZone
  name: 'link-${existingVnetName}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

output envName string = cae.name
output envId string = cae.id
output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output vnetName string = vnet.name
output vnetId string = vnet.id
output acaSubnetId string = acaSubnet.id
output privateEndpointSubnetId string = peSubnet.id
output privateEndpointSubnetName string = peSubnet.name
output pgDnsZoneName string = pgDnsZone.name
output defaultDomain string = cae.properties.defaultDomain
output staticIp string = cae.properties.staticIp
