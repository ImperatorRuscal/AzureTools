@description('Base name for the VM Scale Set')
param vmssName string = 'vmss-EPAC'
@description('Initial instance count')
param instanceCount int = 1

@description('Windows SKU for connector servers')
param vmSku string = 'Standard_B2ms'

@description('Virtual network subnet resource ID where the scale set NICs will land')
param subnetId string

@description('The keyvault that holds secured/secret values')
param kvName string

@description('Admin username (used only to satisfy Windows image; connector is unattended)')
param adminUsername string = 'azAdministrator'
@description('KeyVault secret that stores the password for the local admin user')
param adminPasswordSecretName string = 'azAdministrator-pwd'

@description('KeyVault secret that stores the FQDN of the AD Domain to join')
param domainJoinDomainSecretName string = 'domainJoin-fqdn'
@description('KeyVault secret that stores the CN/DN of the organizational unit in which to place the new computer object')
param domainJoinOUSecretName string = 'domainJoin-ou'
@description('KeyVault secret that stores the AD Domain username used to join the server to the domain')
param domainJoinUserSecretName string = 'domainJoin-username'
@description('KeyVault secret that stores the AD Domain password used to join the server to the domain')
param domainJoinPasswordSecretName string = 'domainJoin-password'

@description('URI to the bootstrap PowerShell script (e.g., blob SAS URL)')
param bootstrapScriptUri string

@description('Tenant ID (GUID) where you register the connector')
param tenantId string

@description('Display name of the connector group to join (must already exist)')
param connectorGroupName string = 'Default'

@description('Authentication mode for registration: Token or Credentials')
param registrationMode string = 'Token'

@description('KeyVault secret that stores the EAP registration token (if registrationMode = Token). If using credentials, set credUserSecret & credPassSecret instead.')
param tokenSecretName string = 'entraPrivateAccess-Connector-RegistrationToken'

@description('KeyVault secret that stores the credential user (if registrationMode = Credentials)')
param credUserSecret string = 'entraPrivateAccess-Connector-User'
@description('KeyVault secret that stores the credential password (if registrationMode = Credentials)')
param credPassSecret string = 'entraPrivateAccess-Connector-Password'

@description('VM image reference')
param imagePublisher string = 'MicrosoftWindowsServer'
param imageOffer string = 'WindowsServer'
param imageSku string = '2025-Datacenter-Azure-Edition-Core'
param imageVersion string = 'latest'

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: kvName
}

var keyVaultUri = format('https://{0}.vault.azure.net/', kvName)

var adminPassword = listSecret(
  resourceId('Microsoft.KeyVault/vaults/secrets', kv.name, adminPasswordSecretName),
  '2016-10-01'
).value

var domainJoinDomain = listSecret(
  resourceId('Microsoft.KeyVault/vaults/secrets', kv.name, domainJoinDomainSecretName),
  '2016-10-01'
).value

var domainJoinOU = listSecret(
  resourceId('Microsoft.KeyVault/vaults/secrets', kv.name, domainJoinOUSecretName),
  '2016-10-01'
).value

var domainJoinUser = listSecret(
  resourceId('Microsoft.KeyVault/vaults/secrets', kv.name, domainJoinUserSecretName),
  '2016-10-01'
).value

var domainJoinPassword = listSecret(
  resourceId('Microsoft.KeyVault/vaults/secrets', kv.name, domainJoinPasswordSecretName),
  '2016-10-01'
).value


resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2024-03-01' = {
  name: vmssName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: vmSku
    capacity: instanceCount
    tier: 'Standard'
  }
  properties: {
    upgradePolicy: { mode: 'Automatic' }
    overprovision: true
    virtualMachineProfile: {
      storageProfile: {
        imageReference: {
          publisher: imagePublisher
          offer: imageOffer
          sku: imageSku
          version: imageVersion
        }
        osDisk: {
          createOption: 'FromImage'
          managedDisk: { storageAccountType: 'Premium_LRS' }
        }
      }
      osProfile: {
        computerNamePrefix: take(vmssName, 15)
        adminUsername: adminUsername
        adminPassword: adminPassword
      }
      networkProfile: {
        networkInterfaceConfigurations: [{
          name: 'nic'
          properties: {
            primary: true
            ipConfigurations: [{
              name: 'ipcfg'
              properties: {
                subnet: { id: subnetId }
              }
            }]
          }
        }]
      }
      extensionProfile: {
        extensions: [
          {
			  name: 'joindomain'
			  properties: {
				publisher: 'Microsoft.Compute'
				type: 'JsonADDomainExtension'
				typeHandlerVersion: '1.3'
				autoUpgradeMinorVersion: true
				settings: {
				  Name: domainJoinDomain 
				  OUPath: domainJoinOU
				  User: domainJoinUser
				  Restart: 'true'                    // allow reboot if needed
				  Options: 3                         // 1=JoinWithNewName, 3=+AccountCreate, etc.
				}
				protectedSettings: {
				  Password: domainJoinPassword
				}
			  }
			},{
            name: 'CustomScript'
			properties: {
				publisher: 'Microsoft.Compute'
				type: 'CustomScriptExtension'
				typeHandlerVersion: '1.10'
				autoUpgradeMinorVersion: true
				provisionAfterExtensions: [
					'joindomain'
				]
				settings: {
					fileUris: [
						bootstrapScriptUri
					]
				}
				protectedSettings: {
					commandToExecute: '''
					powershell -ExecutionPolicy Bypass -File .\bootstrap-epa-connector.ps1 `
                    -TenantId ${tenantId} `
                    -ConnectorGroupName "${connectorGroupName}" `
                    -RegistrationMode ${registrationMode} `
                    -KeyVaultName ${kvName} `
                    -TokenSecretName ${tokenSecretName} `
                    -CredUserSecret ${credUserSecret} `
                    -CredPassSecret ${credPassSecret}
                '''
              }
            }
          }
        ]
      }
    }
  }
}

@description('Autoscale settings (CPU-based, safe defaults)')
resource autoscale 'Microsoft.Insights/autoscalesettings@2022-10-01' = {
  name: '${vmssName}-autoscale'
  location: resourceGroup().location
  properties: {
    profiles: [
      {
        name: 'DefaultProfile'
        capacity: {
          minimum: '1'
          maximum: '10'
          default: string(instanceCount)
        }
        rules: [
          // Scale out: Average CPU > 60% for 10 minutes
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricNamespace: 'microsoft.compute/virtualmachinescalesets'
              metricResourceUri: vmss.id
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT10M'
              timeAggregation: 'Average'
              operator: 'GreaterThan'
              threshold: 60
              dividePerInstance: false
            }
            scaleAction: {
              direction: 'Increase'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT15M'
            }
          },
          // Scale in: Average CPU < 30% for 30 minutes
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricNamespace: 'microsoft.compute/virtualmachinescalesets'
              metricResourceUri: vmss.id
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT30M'
              timeAggregation: 'Average'
              operator: 'LessThan'
              threshold: 30
              dividePerInstance: false
            }
            scaleAction: {
              direction: 'Decrease'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT20M'
            }
          }
        ]
      }
    ]
    enabled: true
    targetResourceUri: vmss.id
  }
}
