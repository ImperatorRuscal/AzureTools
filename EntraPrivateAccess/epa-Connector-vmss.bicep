// =====================================================================================
// Entra Private Access Connector -- VMSS (Flexible, Rolling)
//
// Deploys a VM Scale Set whose instances automatically:
//   1. Join an AD domain           (JsonADDomainExtension)
//   2. Install & register EPNC     (CustomScriptExtension + epa-bootstrapper.ps1)
//   3. Report connector health     (ApplicationHealthWindows on HTTP :8443/health)
//
// The deployment also ensures the UAMI exists and has Key Vault access via both
// RBAC role assignment and classic access policy (works regardless of which
// permission model the Key Vault uses). Optionally grants Storage Account access
// for script hosting.
//
// Secrets are never stored in tags or visible extension settings.
// Use a .bicepparam file or JSON parameters file with Key Vault references for
// adminPassword and domainJoinPassword.
// =====================================================================================

// ---- VM Scale Set ----
@description('Name of the VM Scale Set')
param vmssName string = 'vmss-epac'

@description('SKU of the Windows version to install/image from')
param winImageSku string = '2025-datacenter-azure-edition-core'

@description('Windows local administrator username')
param adminUsername string = 'azAdministrator'

@description('Windows local administrator password (use Key Vault reference in your parameters file)')
@secure()
param adminPassword string

@description('VM size for instances')
param vmSize string = 'Standard_B2ms'

// ---- Managed Identity ----
@description('Name of the User Assigned Managed Identity (created if it does not exist, idempotent if it does)')
param uamiName string = 'uami-entraprivateconnector'

// ---- Networking ----
@description('Resource group NAME that contains the vNet')
param vnetResourceGroupName string

@description('Existing Virtual Network NAME')
param vnetName string

@description('Subnet NAME within the vNet')
param subnetName string

// ---- AD Domain Join ----
@description('AD domain FQDN to join (e.g. corp.contoso.com)')
param domainJoinFqdn string

@description('AD Organizational Unit path for the computer account. Leave empty for default Computers container.')
param domainJoinOuPath string = ''

@description('UPN or DOMAIN\\user of the domain join service account')
param domainJoinUsername string

@description('Password for the domain join account (use Key Vault reference in your parameters file)')
@secure()
param domainJoinPassword string

// ---- Key Vault & Registration ----
@description('Name of the Key Vault that holds the EPNC registration credentials')
param keyVaultName string

@description('Resource group of the Key Vault (leave empty to use the deployment resource group)')
param keyVaultResourceGroupName string = ''

@description('Key Vault secret name for the EPNC registration username')
param registrationUserSecretName string = 'epaReg-username'

@description('Key Vault secret name for the EPNC registration password')
param registrationPasswordSecretName string = 'epaReg-password'

// ---- Script Source ----
@description('Where to download the bootstrapper script from: "github" (public URL) or "storageAccount" (blob + managed identity)')
@allowed([
  'github'
  'storageAccount'
])
param scriptSource string = 'github'

@description('When scriptSource is "github": raw URL to epa-bootstrapper.ps1')
param scriptGitHubUrl string = 'https://raw.githubusercontent.com/ImperatorRuscal/AzureTools/main/EntraPrivateAccess/epa-bootstrapper.ps1'

@description('When scriptSource is "storageAccount": full blob URI to epa-bootstrapper.ps1')
param scriptStorageBlobUri string = ''

@description('When scriptSource is "storageAccount": storage account name (for RBAC role assignment)')
param scriptStorageAccountName string = ''

@description('Resource group of the storage account (leave empty to use the deployment resource group)')
param scriptStorageAccountResourceGroupName string = ''

// ---- Connector Group (optional) ----
@description('Optional EPNC connector group name to assign after registration. Leave empty to use the default group.')
param connectorGroupName string = ''

// ---- Scaling ----
@description('Minimum number of VMSS instances (2+ recommended for high availability)')
@minValue(1)
param minInstanceCount int = 2

@description('Maximum number of VMSS instances')
@minValue(1)
param maxInstanceCount int = 10

// ---- Health ----
@description('Port for the health HTTP listener on each instance')
param healthPort int = 8443


// =====================================================================================
// Variables
// =====================================================================================

var imagePublisher = 'MicrosoftWindowsServer'
var imageOffer     = 'WindowsServer'
var imageSku       = winImageSku
var imageVersion   = 'latest'

var scriptFileName = 'epa-bootstrapper.ps1'

// Build the commandToExecute string with all required parameters for the bootstrapper.
// This goes into protectedSettings so it is encrypted and not visible in the portal.
var connectorGroupArg = connectorGroupName != '' ? ' -ConnectorGroupName "${connectorGroupName}"' : ''
var commandToExecute = 'powershell -ExecutionPolicy Bypass -File .\\${scriptFileName} -KeyVaultName "${keyVaultName}" -RegistrationUserSecretName "${registrationUserSecretName}" -RegistrationPasswordSecretName "${registrationPasswordSecretName}" -UamiClientId "${uami.properties.clientId}" -HealthPort ${healthPort}${connectorGroupArg}'

// Conditional CSE settings based on script source
var useStorageAccount = scriptSource == 'storageAccount'

var cseSettingsGitHub = {
  fileUris: [
    scriptGitHubUrl
  ]
}
var cseProtectedSettingsGitHub = {
  commandToExecute: commandToExecute
}

var cseSettingsStorage = {}
var cseProtectedSettingsStorage = {
  fileUris: [
    scriptStorageBlobUri
  ]
  commandToExecute: commandToExecute
  managedIdentity: {
    clientId: uami.properties.clientId
  }
}

var cseSettings          = scriptSource == 'github' ? cseSettingsGitHub : cseSettingsStorage
var cseProtectedSettings = scriptSource == 'github' ? cseProtectedSettingsGitHub : cseProtectedSettingsStorage

// Effective resource groups (empty string = same as deployment RG)
var effectiveKvResourceGroup      = !empty(keyVaultResourceGroupName) ? keyVaultResourceGroupName : resourceGroup().name
var effectiveStorageResourceGroup = !empty(scriptStorageAccountResourceGroupName) ? scriptStorageAccountResourceGroupName : resourceGroup().name

// Well-known Azure built-in role definition IDs
var keyVaultSecretsUserRoleId   = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var storageBlobDataReaderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')


// =====================================================================================
// Managed Identity (create-or-update, idempotent)
// =====================================================================================

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: resourceGroup().location
}


// =====================================================================================
// Existing Resources
// =====================================================================================

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  scope: resourceGroup(vnetResourceGroupName)
  name: vnetName
}

resource subnetRes 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' existing = {
  parent: vnet
  name: subnetName
}

// =====================================================================================
// Role Assignments (deployed via modules to support cross-resource-group scoping)
// =====================================================================================

// Grant the UAMI "Key Vault Secrets User" on the Key Vault so the bootstrapper
// can retrieve registration credentials at runtime via Managed Identity.
module kvRoleAssignment './modules/kv-role-assignment.bicep' = {
  name: '${vmssName}-kv-role-assignment'
  scope: resourceGroup(effectiveKvResourceGroup)
  params: {
    keyVaultName: keyVaultName
    principalId: uami.properties.principalId
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

// Also grant a classic access policy (Secret Get) for Key Vaults that use the
// "Vault access policy" permission model. The 'add' operation is idempotent and
// has no effect on Key Vaults that use RBAC mode.
module kvAccessPolicy './modules/kv-access-policy.bicep' = {
  name: '${vmssName}-kv-access-policy'
  scope: resourceGroup(effectiveKvResourceGroup)
  params: {
    keyVaultName: keyVaultName
    principalId: uami.properties.principalId
    tenantId: tenant().tenantId
  }
}

// When using a storage account for the bootstrapper script, grant the UAMI
// "Storage Blob Data Reader" so the CustomScriptExtension can download the script.
module storageRoleAssignment './modules/storage-role-assignment.bicep' = if (useStorageAccount) {
  name: '${vmssName}-storage-role-assignment'
  scope: resourceGroup(effectiveStorageResourceGroup)
  params: {
    storageAccountName: scriptStorageAccountName
    principalId: uami.properties.principalId
    roleDefinitionId: storageBlobDataReaderRoleId
  }
}


// =====================================================================================
// VM Scale Set (Flexible orchestration, Rolling upgrades)
// =====================================================================================

resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2024-07-01' = {
  name: vmssName
  location: resourceGroup().location
  sku: {
    name: vmSize
    tier: 'Standard'
    capacity: minInstanceCount
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  tags: {
    application: 'EntraPrivateAccessConnector'
  }
  properties: {
    orchestrationMode: 'Flexible'
    platformFaultDomainCount: 1
    upgradePolicy: {
      mode: 'Rolling'
      rollingUpgradePolicy: {
        maxBatchInstancePercent: 20
        maxUnhealthyInstancePercent: 20
        maxUnhealthyUpgradedInstancePercent: 20
        pauseTimeBetweenBatches: 'PT0S'
        prioritizeUnhealthyInstances: true
      }
    }
    scaleInPolicy: {
      rules: [
        'OldestVM'
      ]
    }
    automaticRepairsPolicy: {
      enabled: true
      gracePeriod: 'PT30M'
      repairAction: 'Replace'
    }
    virtualMachineProfile: {
      securityProfile: {
        securityType: 'TrustedLaunch'
        uefiSettings: {
          secureBootEnabled: true
          vTpmEnabled: true
        }
      }
      storageProfile: {
        imageReference: {
          publisher: imagePublisher
          offer: imageOffer
          sku: imageSku
          version: imageVersion
        }
        osDisk: {
          createOption: 'FromImage'
          caching: 'ReadWrite'
          managedDisk: {
            storageAccountType: 'Premium_LRS'
          }
        }
      }
      osProfile: {
        computerNamePrefix: 'epac-'
        adminUsername: adminUsername
        adminPassword: adminPassword
        windowsConfiguration: {
          provisionVMAgent: true
          enableAutomaticUpdates: true
          patchSettings: {
            patchMode: 'AutomaticByPlatform'
            enableHotpatching: true
          }
        }
      }
      networkProfile: {
        networkApiVersion: '2022-11-01'
        networkInterfaceConfigurations: [
          {
            name: 'nic-epac'
            properties: {
              primary: true
              deleteOption: 'Delete'
              ipConfigurations: [
                {
                  name: 'ipconfig-epac'
                  properties: {
                    primary: true
                    subnet: {
                      id: subnetRes.id
                    }
                  }
                }
              ]
            }
          }
        ]
      }
      extensionProfile: {
        extensions: [
          // 1) Join the AD domain. Handles reboot automatically.
          {
            name: 'joinDomain'
            properties: {
              publisher: 'Microsoft.Compute'
              type: 'JsonADDomainExtension'
              typeHandlerVersion: '1.3'
              autoUpgradeMinorVersion: true
              settings: {
                Name: domainJoinFqdn
                OUPath: domainJoinOuPath
                User: domainJoinUsername
                Restart: 'true'
                Options: 3 // NETSETUP_JOIN_DOMAIN | NETSETUP_ACCT_CREATE
              }
              protectedSettings: {
                Password: domainJoinPassword
              }
            }
          }
          // 2) Install and register the EPNC connector. Runs after domain join + reboot.
          {
            name: 'customScript'
            properties: {
              publisher: 'Microsoft.Compute'
              type: 'CustomScriptExtension'
              typeHandlerVersion: '1.10'
              autoUpgradeMinorVersion: true
              provisionAfterExtensions: [
                'joinDomain'
              ]
              settings: cseSettings
              protectedSettings: cseProtectedSettings
            }
          }
          // 3) Health probe -- checks the EPNC connector service (WAPCSvc) via HTTP.
          {
            name: 'appHealth'
            properties: {
              publisher: 'Microsoft.ManagedServices'
              type: 'ApplicationHealthWindows'
              typeHandlerVersion: '2.0'
              autoUpgradeMinorVersion: true
              provisionAfterExtensions: [
                'customScript'
              ]
              settings: {
                protocol: 'http'
                port: healthPort
                requestPath: '/health'
                intervalInSeconds: 30
                numberOfProbes: 2
                gracePeriod: 600
              }
            }
          }
        ]
      }
      diagnosticsProfile: {
        bootDiagnostics: {
          enabled: true
        }
      }
      scheduledEventsProfile: {
        terminateNotificationProfile: {
          enable: true
          notBeforeTimeout: 'PT5M'
        }
      }
    }
  }
  dependsOn: [
    kvRoleAssignment    // Ensure UAMI has KV access before instances try to read secrets
    kvAccessPolicy      // Ditto for vaults using the access policy permission model
  ]
}


// =====================================================================================
// Autoscale (CPU-based)
// =====================================================================================

resource autoscale 'Microsoft.Insights/autoscalesettings@2022-10-01' = {
  name: '${vmssName}-autoscale'
  location: resourceGroup().location
  properties: {
    name: '${vmssName}-autoscale'
    enabled: true
    targetResourceUri: vmss.id
    profiles: [
      {
        name: 'cpu-based'
        capacity: {
          minimum: '${minInstanceCount}'
          maximum: '${maxInstanceCount}'
          default: '2'
        }
        rules: [
          // Scale OUT: average CPU > 70% for 10 minutes
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricNamespace: 'Microsoft.Compute/virtualMachineScaleSets'
              metricResourceUri: vmss.id
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT10M'
              timeAggregation: 'Average'
              operator: 'GreaterThan'
              threshold: 70
              dividePerInstance: false
            }
            scaleAction: {
              direction: 'Increase'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT5M'
            }
          }
          // Scale IN: average CPU <= 50% for 10 minutes
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricNamespace: 'Microsoft.Compute/virtualMachineScaleSets'
              metricResourceUri: vmss.id
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT10M'
              timeAggregation: 'Average'
              operator: 'LessThanOrEqual'
              threshold: 50
              dividePerInstance: false
            }
            scaleAction: {
              direction: 'Decrease'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT5M'
            }
          }
        ]
      }
    ]
  }
}


// =====================================================================================
// Outputs
// =====================================================================================

output vmssId string = vmss.id
output uamiResourceId string = uami.id
output uamiClientId string = uami.properties.clientId
output uamiPrincipalId string = uami.properties.principalId
output subnetId string = subnetRes.id
