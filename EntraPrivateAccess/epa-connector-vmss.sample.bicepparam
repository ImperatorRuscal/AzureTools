using 'epa-Connector-vmss.bicep'

// ====================================================================================
// Sample parameters file for deploying the EPNC VMSS.
//
// Secrets (adminPassword, domainJoinPassword) are pulled from Key Vault at deployment
// time via az.getSecret(). The deploying principal never sees the plaintext values.
//
// Prerequisites:
//   - The Key Vault must have 'enabledForTemplateDeployment' set to true:
//       az keyvault update --name <vault> --enabled-for-template-deployment true
//   - The deploying principal needs 'Microsoft.KeyVault/vaults/deploy/action' permission
//     on the Key Vault (granted by Owner or Contributor roles).
//   - The deployment automatically creates the UAMI (if it doesn't exist) and assigns
//     'Key Vault Secrets User' on the Key Vault. If using storageAccount script source,
//     it also assigns 'Storage Blob Data Reader' on the storage account.
//   - The deploying principal needs Owner or User Access Administrator on the Key Vault
//     resource group (to create role assignments).
//
// Deploy with:
//   az deployment group create \
//     --resource-group <rg> \
//     --template-file epa-Connector-vmss.bicep \
//     --parameters epa-connector-vmss.sample.bicepparam
// ====================================================================================

// ---- Replace these placeholder values with your environment specifics ----

// Key Vault secrets -- replace <subscription-id>, <rg>, and <vault-name> with your values
param adminPassword = az.getSecret('<subscription-id>', '<resource-group>', '<vault-name>', 'vmss-adminPassword')
param domainJoinPassword = az.getSecret('<subscription-id>', '<resource-group>', '<vault-name>', 'domainJoin-password')

// Networking
param vnetResourceGroupName = 'rg-networking'
param vnetName = 'vnet-hub'
param subnetName = 'snet-epac'

// AD Domain Join
param domainJoinFqdn = 'corp.contoso.com'
param domainJoinOuPath = 'OU=Servers,DC=corp,DC=contoso,DC=com'
param domainJoinUsername = 'svc-domainjoin@corp.contoso.com'

// Key Vault & Registration
param keyVaultName = 'kv-epac-secrets'
// param keyVaultResourceGroupName = 'rg-keyvault'  // if KV is in a different RG
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
// param healthPort = 8443
