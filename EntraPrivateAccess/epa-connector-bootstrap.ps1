param(
  [Parameter(Mandatory)] [string] $TenantId,
  [Parameter(Mandatory)] [string] $ConnectorGroupName,
  [Parameter(Mandatory)] [ValidateSet('Token','Credentials')] [string] $RegistrationMode,
  [Parameter(Mandatory)] [string] $KeyVaultName,
  [string] $TokenSecretName = 'entraPrivateAccess-Connector-RegistrationToken',
  [string] $CredUserSecret = 'entraPrivateAccess-Connector-User',
  [string] $CredPassSecret = 'entraPrivateAccess-Connector-Password'
)

$ErrorActionPreference = 'Stop'

# Helper: install modules if missing
function Ensure-Module($name, $minVer) {
  if (-not (Get-Module -ListAvailable -Name $name | Where-Object {$_.Version -ge [version]$minVer})) {
    Install-PackageProvider -Name NuGet -Force | Out-Null
    Install-Module $name -Force -Scope AllUsers -MinimumVersion $minVer
  }
}

Ensure-Module -name Az.Accounts -minVer '2.11.0'
Ensure-Module -name Az.KeyVault -minVer '5.3.0'
Ensure-Module -name Microsoft.Graph.Beta.Applications -minVer '2.20.0'
Ensure-Module -name Microsoft.Graph.Beta.Authentication -minVer '2.20.0'

Write-Host "==> Connecting with Managed Identity"
Connect-AzAccount -Identity -Tenant $TenantId | Out-Null

# Fetch registration secret(s) from Key Vault using MI
if ($RegistrationMode -eq 'Token') {
  $regToken = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $TokenSecretName).SecretValueText
} else {
  $regUser = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CredUserSecret).SecretValueText
  $regPass = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CredPassSecret).SecretValue
  $credential = New-Object System.Management.Automation.PSCredential($regUser, $regPass)
}

# 1) Download latest connector installer (from MS doc link) or ship the EXE alongside this script.
# For production, you may prefer to pin a version from the release notes.
$installer = "$env:TEMP\MicrosoftEntraPrivateNetworkConnectorInstaller.exe"
# https://download.msappproxy.net/connectorinstaller/MicrosoftEntraPrivateNetworkConnectorInstaller.exe
# https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller
Invoke-WebRequest -Uri "https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller" -OutFile $installer

# 2) Install quietly, WITHOUT kicking off registration
Start-Process -FilePath $installer -ArgumentList 'REGISTERCONNECTOR="false" REBOOT=ReallySuppress /qn' -Wait

# 3) Unattended registration
$regScript = "$env:ProgramFiles\Microsoft Entra private network connector\RegisterConnector.ps1"
$modulePath = "$env:ProgramFiles\Microsoft Entra private network connector\Modules\"
$moduleName = "MicrosoftEntraPrivateNetworkConnectorPSModule"

if ($RegistrationMode -eq 'Token') {
  & $regScript -modulePath $modulePath -moduleName $moduleName `
    -Authenticationmode Token -Token $regToken -TenantId $TenantId -Feature ApplicationProxy
} else {
  & $regScript -modulePath $modulePath -moduleName $moduleName `
    -Authenticationmode Credentials -Credential $credential -TenantId $TenantId -Feature ApplicationProxy
}

# 4) Wait for the connector object to appear (match MachineName)
Start-Sleep -Seconds 10

Import-Module Microsoft.Graph.Beta.Applications -ErrorAction Stop
# Managed Identity to Graph (use workload identity token)
Connect-MgGraph -TenantId $TenantId -Identity -NoWelcome -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All" | Out-Null
Select-MgProfile -Name beta

$me = $env:COMPUTERNAME
# Find the connector and target group
$connector = Get-MgBetaOnPremisesPublishingProfileConnector -OnPremisesPublishingProfileId 'applicationProxy' -All `
  | Where-Object { $_.MachineName -eq $me } | Select-Object -First 1

if (-not $connector) {
  Write-Error "Connector object for $me not found in Graph."
}

$cg = Get-MgBetaOnPremisesPublishingProfileConnectorGroup -OnPremisesPublishingProfileId 'applicationProxy' -Filter "displayName eq '$ConnectorGroupName'" `
  | Select-Object -First 1

if (-not $cg) {
  Write-Error "Connector group '$ConnectorGroupName' not found."
}

# Add this connector to the group (POST .../connectorGroups/{id}/members/$ref)
$params = @{ '@odata.id' = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectors/$($connector.Id)" }
New-MgBetaOnPremisesPublishingProfileConnectorGroupMemberByRef -OnPremisesPublishingProfileId 'applicationProxy' -ConnectorGroupId $cg.Id -BodyParameter $params

Write-Host "==> Connector $($connector.Id) added to group '$ConnectorGroupName'."
