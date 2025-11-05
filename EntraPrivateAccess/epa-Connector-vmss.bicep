@description('Name of the VM Scale Set')
param vmssName string = 'vmss-epac'

@description('Windows local administrator username')
param adminUsername string = 'azAdministrator'

@description('Name of the Key Vault that holds the admin password and other secrets')
param keyVaultName string

@description('Secret name in Key Vault for the local administrator password')
param adminPasswordSecretName string

@description('Existing UAMI NAME (in the same resource group as this deployment)')
param uamiName string ='uami-entraprivateconnector'

@description('Existing Virtual Network NAME (in a different resource group)')
param vnetName string

@description('Resource group NAME that contains the vNet')
param vnetResourceGroupName string

@description('Subnet NAME within the vNet')
param subnetName string

@description('VM size for instances')
param vmSize string = 'Standard_B2ms'

@description('Custom script URL to run during initialization')
param initScriptUrl string

@description('Command to execute after the file is downloaded')
param initCommandToExecute string = 'powershell -ExecutionPolicy Bypass -File .\\init.ps1'

@description('Resource group NAME that contains the Key Vault')
param keyVaultResourceGroupName string

@description('Tags: epa_KeyVault_Name')
param tag_epa_KeyVault_Name string

@description('Tags: epa_KeyVault_ADJoinUser_SecretName')
param tag_epa_KeyVault_ADJoinUser_SecretName string

@description('Tags: epa_KeyVault_ADJoinPassword_SecretName')
param tag_epa_KeyVault_ADJoinPassword_SecretName string

@description('Tags: epa_KeyVault_RegistrationUser_SecretName')
param tag_epa_KeyVault_RegistrationUser_SecretName string

@description('Tags: epa_KeyVault_RegistrationPassword_SecretName')
param tag_epa_KeyVault_RegistrationPassword_SecretName string

// ---- Image definition (Windows Server 2025 Datacenter Azure Edition Core) ----
var imagePublisher = 'MicrosoftWindowsServer'
var imageOffer     = 'WindowsServer'
var imageSku       = '2025-datacenter-azure-edition-core' // adjust if your region exposes a variant
var imageVersion   = 'latest'

// ------- Existing resources -------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' existing = {
  name: uamiName
}

resource kv 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  scope: resourceGroup(keyVaultResourceGroupName)
  name: keyVaultName
}

// vNet/Subnet exist in a different resource group
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  scope: resourceGroup(vnetResourceGroupName)
  name: vnetName
}

resource subnetRes 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' existing = {
  parent: vnet
  name: subnetName
}

// Pull the admin password securely from Key Vault at deployment time
// (Requires the vault to allow template deployment / access policy for the deployer)
var adminPasswordRef = reference(
  format('{0}/secrets/{1}', kv.id, adminPasswordSecretName),
  '2021-10-01'
)

// ----------------------- VM Scale Set (Flexible, Rolling) -----------------------
resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2024-07-01' = {
  name: vmssName
  location: resourceGroup().location
  sku: {
    name: vmSize
    tier: 'Standard'
    capacity: 1 // initial; autoscale manages 1..10
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uami.id}': {}
    }
  }
  tags: {
    epa_KeyVault_Name: tag_epa_KeyVault_Name
    epa_KeyVault_ADJoinUser_SecretName: tag_epa_KeyVault_ADJoinUser_SecretName
    epa_KeyVault_ADJoinPassword_SecretName: tag_epa_KeyVault_ADJoinPassword_SecretName
    epa_KeyVault_RegistrationUser_SecretName: tag_epa_KeyVault_RegistrationUser_SecretName
    epa_KeyVault_RegistrationPassword_SecretName: tag_epa_KeyVault_RegistrationPassword_SecretName
  }
  properties: {
    orchestrationMode: 'Flexible'
    upgradePolicy: {
      mode: 'Rolling'
      rollingUpgradePolicy: {
        // Tune as you like; these are conservative defaults
        maxBatchInstancePercent: 20
        maxUnhealthyInstancePercent: 20
        maxUnhealthyUpgradedInstancePercent: 20
        pauseTimeBetweenBatches: 'PT0S'
        enableCrossZoneUpgrade: false
        prioritizeUnhealthyInstances: true
      }
    }
    platformFaultDomainCount: 1

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
        adminPassword: adminPasswordRef.value
        windowsConfiguration: {
          provisionVMAgent: true
          enableAutomaticUpdates: true
          patchSettings: {
            patchMode: 'AutomaticByOS'
          }
        }
      }
      networkProfile: {
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
          {
            name: 'customScript'
            properties: {
              publisher: 'Microsoft.Compute'
              type: 'CustomScriptExtension'
              typeHandlerVersion: '1.10'
              autoUpgradeMinorVersion: true
              settings: {
                fileUris: [
                  initScriptUrl
                ]
                commandToExecute: initCommandToExecute
              }
            }
          }
        ]
      }
    }
  }
}

// ----------------------- Autoscale (1..10, CPU-based) -----------------------
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
          minimum: '1'
          maximum: '10'
          default: '1'
        }
        rules: [
          // Scale OUT: CPU > 80% for 10 minutes
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
              threshold: 80
              dividePerInstance: false
            }
            scaleAction: {
              direction: 'Increase'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT5M'
            }
          }
          // Scale IN: CPU <= 60% for 10 minutes
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
              threshold: 60
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

// ----------------------- Outputs -----------------------
output vmssId string = vmss.id
output uamiResourceId string = uami.id
output subnetId string = subnetRes.id
