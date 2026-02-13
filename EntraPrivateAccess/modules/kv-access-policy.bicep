// Adds a classic Key Vault access policy granting Secret Get to a principal.
// Deployed as a module so it can target a Key Vault in any resource group.
//
// Uses the 'add' operation, which appends to existing policies without disturbing them.
// If the Key Vault is configured with Azure RBAC, access policies are silently ignored.

param keyVaultName string
param principalId string
param tenantId string

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource accessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-07-01' = {
  parent: kv
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: tenantId
        objectId: principalId
        permissions: {
          secrets: [
            'get'
          ]
        }
      }
    ]
  }
}
