[CmdletBinding(SupportsShouldProcess)]
param(
  [string] $KeyVaultName,                       # Optional override; else from tag epa_KeyVault_Name
  [string] $KeyVaultRegUserSecretName,          # Optional override; else tag epa_KeyVault_RegistrationUser_SecretName
  [string] $KeyVaultRegPasswordSecretName,      # Optional override; else tag epa_KeyVault_RegistrationPassword_SecretName
  [string] $InstallerUrl = 'https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller',
  [string] $InstallerFileName = 'MicrosoftEntraPrivateNetworkConnectorInstaller.exe'
)

$regScript = "$env:ProgramFiles\Microsoft Entra private network connector\RegisterConnector.ps1"
$modPath  = "$env:ProgramFiles\Microsoft Entra private network connector\Modules\"
$modName  = "MicrosoftEntraPrivateNetworkConnectorPSModule"

if (Test-Path $regScript) {
  break
}
$ErrorActionPreference = 'Stop'

function Write-Stamp([string]$msg,[string]$level='INFO'){
  $ts = (Get-Date).ToString('s')
  Write-Host "[$ts][$level] $msg"
}

function Get-IMDSJson($path, $apiVersion){
  $uri = "http://169.254.169.254/metadata/$path`?api-version=$apiVersion"
  return Invoke-RestMethod -Headers @{Metadata='true'} -Uri $uri -Method GET
}

$psGallery = $null
function Ensure-Module($name, $minVer="0.0.0.0") {
    if(-not $psGallery)
    {
        $nuget = get-packageprovider -name NuGet -ErrorAction SilentlyContinue
        if((-not $nuget) -or ($nuget.version -lt [version]"2.8.5.201")){Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null}
    }
    if (-not $psGallery) {$psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue}
    if (-not $psGallery) { Register-PSRepository -Default | Out-Null }
    if ($psGallery.InstallationPolicy -ne 'Trusted') {Set-PSRepository -Name PSGallery -InstallationPolicy Trusted}
    if (-not (Get-Module -ListAvailable -Name $name | Where-Object {$_.Version -ge [version]$minVer})) {
        Write-Stamp "Installing PS Module :: $name"
        Install-Module $name -Force -AllowClobber -Scope AllUsers -MinimumVersion $minVer
    }
}

function Get-PlainText {
    param([System.Security.SecureString] $Secure)
    if (-not $Secure) { return $null }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# -------- 0) Gather config (IMDS tags + param overrides) ----------
Write-Stamp "Reading instance metadata and tags"
$compute = Get-IMDSJson -path 'instance/compute' -apiVersion '2021-02-01'
$tags = @{}
if ($compute.tagsList) { foreach($t in $compute.tagsList){ $tags[$t.name] = $t.value } }

if (-not $KeyVaultName)                  { $KeyVaultName                  = $tags['epa_KeyVault_Name'] }
if (-not $KeyVaultRegUserSecretName)     { $KeyVaultRegUserSecretName     = $tags['epa_KeyVault_RegistrationUser_SecretName'] }
if (-not $KeyVaultRegPasswordSecretName) { $KeyVaultRegPasswordSecretName = $tags['epa_KeyVault_RegistrationPassword_SecretName'] }

foreach($pair in @(
  @{Name='KeyVaultName';Value=$KeyVaultName},
  @{Name='KeyVaultRegUserSecretName';Value=$KeyVaultRegUserSecretName},
  @{Name='KeyVaultRegPasswordSecretName';Value=$KeyVaultRegPasswordSecretName}
)){
  if(-not $pair.Value){ throw "Missing required value for $($pair.Name). Supply via parameter or VM tag." }
}

# -------- 1) Ensure modules (PS 5.1 friendly) ----------
Ensure-Module -name Az.Accounts
Ensure-Module -name Az.KeyVault

# -------- 2) Connect to Azure & Key Vault (Managed Identity) ----------
Write-Stamp "Connecting to Azure (Managed Identity)"
$azCon = Connect-AzAccount -Identity

Write-Stamp "Fetching registration credentials from Key Vault '$KeyVaultName'"
$regUser = Get-PlainText (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultRegUserSecretName).SecretValue
$regPass = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultRegPasswordSecretName).SecretValue
$cred = New-Object System.Management.Automation.PSCredential($regUser,$regPass)

# -------- 3) Download and install connector (reboot suppressed) ----------
Write-Stamp "Downloading connector installer"
$installerPath = Join-Path ([IO.Path]::GetTempPath()) $InstallerFileName
Invoke-WebRequest -Uri $InstallerUrl -Method Get -OutFile $installerPath
Write-Stamp "Installer saved at $installerPath"

$installArgs = 'REGISTERCONNECTOR="false" REBOOT=ReallySuppress /qn'
Write-Stamp "Installing connector (quiet, no reboot) -> $installerPath"
$proc = Start-Process -FilePath $installerPath -ArgumentList $installArgs -PassThru -Wait
if ($proc.ExitCode -ne 0) { throw "Connector installer exited with code $($proc.ExitCode)" }

# -------- 4) Register connector using credentials ----------
# Grab the Tenant ID from the AzConnect result
try {
    $TenantId = $azcon.Context.Tenant.Id
    Write-Stamp "Discovered TenantId: $TenantId"
} catch { Write-Stamp "Could not derive TenantId from MSI token (continuing): $_" 'WARN' }

Write-Stamp "Registering connector (AuthenticationMode=Credentials) for tenant $TenantId"
& $regScript -ModulePath $modPath -ModuleName $modName -AuthenticationMode Credentials -Credential $cred -TenantId $TenantId -Feature ApplicationProxy

Write-Stamp "Bootstrap complete."
Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
