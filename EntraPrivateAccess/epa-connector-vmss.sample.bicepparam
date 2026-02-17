using 'epa-Connector-vmss.bicep'

// ====================================================================================
// Sample parameters file for deploying the EPNC VMSS.
//
// Secrets (adminPassword, domainJoinPassword) are pulled from Key Vault at deployment
// time via az.getSecret(). The deploying principal never sees the plaintext values.
//
// Key Vault coordinates are defined once as variables and reused for both secret
// retrieval and parameter values. Requires Bicep CLI 0.21.x or later.
//
// Prerequisites:
//   - The Key Vault must have 'enabledForTemplateDeployment' set to true:
//       az keyvault update --name <vault> --enabled-for-template-deployment true
//   - The deploying principal needs 'Microsoft.KeyVault/vaults/deploy/action' permission
//     on the Key Vault (granted by Owner or Contributor roles).
//   - The deployment automatically creates the UAMI (if it doesn't exist) and grants
//     Key Vault access via both RBAC and classic access policy (works regardless of
//     which permission model the Key Vault uses). If using storageAccount script source,
//     it also assigns 'Storage Blob Data Reader' on the storage account.
//   - The deploying principal needs Owner or User Access Administrator on the Key Vault
//     resource group (to create role assignments and access policies).
//
// Deploy with:
//   az deployment group create \
//     --resource-group <rg> \
//     --template-file epa-Connector-vmss.bicep \
//     --parameters epa-connector-vmss.sample.bicepparam
// ====================================================================================

// ---- Key Vault coordinates (fill in once, reused for secrets and params) ----
var kvSubscriptionId = '<subscription-id>'
var kvResourceGroup  = '<resource-group>'
var kvName           = '<vault-name>'

// Key Vault secrets -- coordinates defined above; only secret names differ
param adminPassword      = az.getSecret(kvSubscriptionId, kvResourceGroup, kvName, 'vmss-adminPassword')
param domainJoinPassword = az.getSecret(kvSubscriptionId, kvResourceGroup, kvName, 'domainJoin-password')

// Networking
param vnetResourceGroupName = 'rg-networking'
param vnetName = 'vnet-hub'
param subnetName = 'snet-epac'

// AD Domain Join
param domainJoinFqdn = 'corp.contoso.com'
param domainJoinOuPath = 'OU=Servers,DC=corp,DC=contoso,DC=com'
param domainJoinUsername = 'svc-domainjoin@corp.contoso.com'

// Key Vault & Registration -- reuse the vars above
param keyVaultName = kvName
param keyVaultResourceGroupName = kvResourceGroup
// param registrationUserSecretName = 'epaReg-username'       // default
// param registrationPasswordSecretName = 'epaReg-password'   // default

// ---- Script Source ----
// Option A: GitHub (community/dev) -- this is the default
param scriptSource = 'github'

// Option B: Storage account (production/air-gapped) -- uncomment and configure:
// param scriptSource = 'storageAccount'
// param scriptStorageBlobUri = 'https://stbootstrap.blob.core.windows.net/scripts/epa-bootstrapper.ps1'
// param scriptStorageAccountName = 'stbootstrap'
// param scriptStorageAccountResourceGroupName = 'rg-bootstrap'  // if in a different RG

// ---- Optional: Connector Group ----
// param connectorGroupName = 'EPA-WestUS2'

// ---- Optional: Override defaults ----
// param vmssName = 'vmss-epac'
// param vmSize = 'Standard_B2ms'
// param adminUsername = 'azAdministrator'
// param uamiName = 'uami-entraprivateconnector'
// param minInstanceCount = 2
// param maxInstanceCount = 10
// param autoscaleTimeZone = 'UTC'   // Windows time zone for the 04:00–04:30 maintenance window
// param healthPort = 8443
