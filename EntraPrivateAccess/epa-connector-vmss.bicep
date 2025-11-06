@description('Name of the VM Scale Set')
param vmssName string = 'vmss-epac'

@description('SKU of the Windows version to install/image from')
param winImageSku string = '2025-datacenter-azure-edition-core' // adjust if your region exposes a variant

@description('Windows local administrator username')
param adminUsername string = 'azAdministrator'

@description('The local admin account password')
@secure()
param adminPassword string

@description('Existing UAMI NAME (in the same resource group as this deployment)')
param uamiName string ='uami-entraprivateconnector'

@description('Resource group NAME that contains the vNet')
param vnetResourceGroupName string

@description('Existing Virtual Network NAME (in a different resource group)')
param vnetName string

@description('Subnet NAME within the vNet')
param subnetName string

@description('VM size for instances')
param vmSize string = 'Standard_B2ms'

@description('Custom script URL to run during initialization')
param initScriptUrl string = 'https://raw.githubusercontent.com/ImperatorRuscal/AzureTools/main/EntraPrivateAccess/epa-bootstrapper.ps1'

@description('Command to execute after the file is downloaded')
param initCommandToExecute string = 'powershell -ExecutionPolicy Bypass -File .\\epa-bootstrapper.ps1'

@description('Name of the Key Vault that holds the admin password and other secrets')
param keyVaultName string

@description('Tags: epa_AD_FQDN')
param tag_epa_AD_FQDN string

@description('Tags: epa_AD_OU')
param tag_epa_AD_OU string = 'CN=Computers,DC=domain,DC=local'

@description('Tags: epa_KeyVault_ADJoinUser_SecretName')
param tag_epa_KeyVault_ADJoinUser_SecretName string = 'domainJoin-username'

@description('Tags: epa_KeyVault_ADJoinPassword_SecretName')
param tag_epa_KeyVault_ADJoinPassword_SecretName string = 'domainJoin-password'

@description('Tags: epa_KeyVault_RegistrationUser_SecretName')
param tag_epa_KeyVault_RegistrationUser_SecretName string = 'epaReg-username'

@description('Tags: epa_KeyVault_RegistrationPassword_SecretName')
param tag_epa_KeyVault_RegistrationPassword_SecretName string = 'epaReg-password'


// ---- Image definition (Windows Server 2025 Datacenter Azure Edition Core) ----
var imagePublisher = 'MicrosoftWindowsServer'
var imageOffer     = 'WindowsServer'
var imageSku       = winImageSku
var imageVersion   = 'latest'


// ------- Existing resources -------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2018-11-30' existing = {
  name: uamiName
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
    epa_KeyVault_Name: keyVaultName
    epa_KeyVault_ADJoinUser_SecretName: tag_epa_KeyVault_ADJoinUser_SecretName
    epa_KeyVault_ADJoinPassword_SecretName: tag_epa_KeyVault_ADJoinPassword_SecretName
	epa_AD_FQDN : tag_epa_AD_FQDN
	epa_AD_OU : tag_epa_AD_OU
    epa_KeyVault_RegistrationUser_SecretName: tag_epa_KeyVault_RegistrationUser_SecretName
    epa_KeyVault_RegistrationPassword_SecretName: tag_epa_KeyVault_RegistrationPassword_SecretName
  }
  properties: {
    orchestrationMode: 'Flexible'
	platformFaultDomainCount: 1 
    upgradePolicy: {
      mode: 'Rolling'
      rollingUpgradePolicy: {
        // Tune as you like; these are conservative defaults
        maxBatchInstancePercent: 20
        maxUnhealthyInstancePercent: 20
        maxUnhealthyUpgradedInstancePercent: 20
        pauseTimeBetweenBatches: 'PT0S'
        // enableCrossZoneUpgrade: false
        prioritizeUnhealthyInstances: true
      }
    }
	scaleInPolicy: {
		rules: [
			'OldestVM'
		]
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
        adminPassword: adminPassword  // adminPasswordRef.value
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
			},{
				name: 'appHealth'
				properties: {
					publisher: 'Microsoft.ManagedServices'
					type: 'ApplicationHealthWindows'
					typeHandlerVersion: '2.0'              // Rich Health States (use 1.0 for Binary if you prefer)
					autoUpgradeMinorVersion: true
					// If your custom script must run before health is evaluated, keep this dependency:
					provisionAfterExtensions: [ 'customScript' ]
					settings: {
						protocol: 'tcp'                      // tcp | http | https
						port: 5985                           // WinRM; simple built-in TCP listener
						// Optional for v2.0 (rich): give the app time before first probe counts
						gracePeriod: 600                     // seconds
						// For http/https you would add: requestPath: "/healthz"
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
  dependsOn: [ vmss ]
}

// ----------------------- Outputs -----------------------
output vmssId string = vmss.id
output uamiResourceId string = uami.id
output subnetId string = subnetRes.id
