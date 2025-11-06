[CmdletBinding()]
param(
  [string] $KeyVaultName,                       # Optional override; else from tag epa_KeyVault_Name
  [string] $KeyVaultADUserSecretName,           # Optional override; else tag epa_KeyVault_ADJoinUser_SecretName
  [string] $KeyVaultADPasswordSecretName,       # Optional override; else tag epa_KeyVault_ADJoinPassword_SecretName
  [string] $KeyVaultRegUserSecretName,          # Optional override; else tag epa_KeyVault_RegistrationUser_SecretName
  [string] $KeyVaultRegPasswordSecretName,      # Optional override; else tag epa_KeyVault_RegistrationPassword_SecretName
  [string] $InstallerUrl = 'https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller',
  [string] $InstallerFileName = 'MicrosoftEntraPrivateNetworkConnectorInstaller.exe'
)

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "Run elevated (Administrator)."; exit 1 }

$ErrorActionPreference = 'Stop'
#try{

    #region "Statics"

        if(-not $MyInvocation.MyCommand.Name){$bootStrapName='epa-bootstrapper.ps1'}else{$bootStrapName=$MyInvocation.MyCommand.Name}
        $bootStrapperPath  = Join-Path $env:SystemDrive 'Scripts'
        $bootStrapperFull  = Join-Path $bootStrapperPath $bootStrapName
        $bootStrapTaskName = 'Entra Private Access Connector Bootstrapper'

        $regScript         = "$env:ProgramFiles\Microsoft Entra private network connector\RegisterConnector.ps1"
        $modPath           = "$env:ProgramFiles\Microsoft Entra private network connector\Modules\"
        $modName           = "MicrosoftEntraPrivateNetworkConnectorPSModule"
    
    #endregion

    #region "Make sure the C:\Scripts folder exists, and start logging there"
    
        function Write-Stamp([string]$msg,[string]$level='INFO'){
          $ts = (Get-Date).ToString('s')
          Write-Host "[$ts][$level] $msg"
        }
    
        Write-Stamp 'Checking if this script is running from the preferred "\Scripts" path'
        if($bootStrapperPath -ine $PSScriptRoot)
        {
            Write-Stamp 'Running from a location other than the preferred path, moving this into the preferred path.'
            if(-not (Test-Path $bootStrapperPath)){New-Item -Path $bootStrapperPath -ItemType Directory | Out-Null}
            Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $bootStrapperFull -Force
        }
        Start-Transcript -Path "$bootStrapperFull.log" -IncludeInvocationHeader -Force

    #endregion

    #region "Helper Functions"

        function Invoke-WithRetry([scriptblock]$op,[int]$retries=5,[int]$delay=2){
          for($i=1;$i -le $retries;$i++){
            try { return & $op } catch { if($i -eq $retries){ throw } ; Start-Sleep -Seconds $delay }
          }
        }

        function Get-IMDSJson($path, $apiVersion){
          $uri = "http://169.254.169.254/metadata/$path`?api-version=$apiVersion"
          return Invoke-WithRetry { Invoke-RestMethod -Headers @{Metadata='true'} -Uri $uri -Method GET -TimeoutSec 20 }
        }

        $psGallery = $null
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        function Ensure-Module($name, $minVer="0.0.0.0") {
            Write-Stamp "Ensuring availability of module $name"
            if(-not $psGallery)
            {
		Write-Stamp 'Setting up PS Gallery'

		$pmMin = [Version]'1.4.8.1'
		$pgMin = [Version]'2.2.5'

		$pm    = Get-Module PackageManagement -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
		$pg    = Get-Module PowerShellGet      -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

        #$nuget = get-packageprovider -name NuGet -ErrorAction SilentlyContinue
        if((-not $nuget) -or ($nuget.version -lt [version]"2.8.5.201")){
            Write-Stamp 'Installing NuGet'
			## Doesn't work unattended
            ## Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Confirm:$False -Scope AllUsers | Out-Null
            $nugetVer     = '2.8.5.208'
            $dllName      = 'Microsoft.PackageManagement.NuGetProvider.dll'
            $providerRoot = Join-Path $env:ProgramFiles 'PackageManagement\ProviderAssemblies\nuget'
            $providerDir  = Join-Path $providerRoot   $nugetVer
            New-Item -ItemType Directory -Force -Path $providerDir | Out-Null

            # Official CDN path (mirrors the prompt’s URL). If your enterprise blocks this, host it internally and change the URL.
            $url  = 'https://onegetcdn.azureedge.net/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll'
            $dest = Join-Path $providerDir $dllName
try {
            Write-Stamp 'Looking at Cert Trust'
            Write-Stamp ([System.Net.ServicePointManager]::CertificatePolicy)
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                      WebRequest request, int certificateProblem) { return true; }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
			Write-Stamp ([System.Net.ServicePointManager]::CertificatePolicy)
            Write-Stamp 'Cert trust updated'

            Invoke-WithRetry { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing }
            Write-Stamp 'Nuget downloaded'
            # Also copy to the user cache location to satisfy older loaders
            $userCacheDir = Join-Path $env:LOCALAPPDATA "PackageManagement\ProviderAssemblies\nuget\$nugetVer"
            New-Item -ItemType Directory -Force -Path $userCacheDir | Out-Null
            Copy-Item $dest (Join-Path $userCacheDir $dllName) -Force
} catch {}

		}

		if (-not $pm -or $pm.Version -lt $pmMin) {
			    Write-Stamp 'Installing PackageManagement'
		    	Install-Module PackageManagement -MinimumVersion $pmMin -Force -AllowClobber -Confirm:$false -Scope AllUsers
		}
		if (-not $pg -or $pg.Version -lt $pgMin) {
			Write-Stamp 'Installing PowerShellGet'
			Install-Module PowerShellGet -MinimumVersion $pgMin -Force -AllowClobber -Confirm:$false -Scope AllUsers
		}

		try {
		    if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
			    Write-Stamp 'Trusting the repo'
		        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		    }
		} catch {}

		# IMPORTANT: reload the updated modules in the current process
		Remove-Module PackageManagement,PowerShellGet -ErrorAction SilentlyContinue
		Import-Module  PackageManagement
		Import-Module  PowerShellGet

                $nuget = get-packageprovider -name NuGet -ErrorAction SilentlyContinue
                if((-not $nuget) -or ($nuget.version -lt [version]"2.8.5.201")){Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Confirm:$False | Out-Null}
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

        function Test-DomainReachable {
            param([string]$Domain)
            Write-Stamp "Testing if we can reach the '$Domain' domain."
            try {
                $srv = Resolve-DnsName -Type SRV -Name ("_ldap._tcp.dc._msdcs.{0}" -f $Domain) -ErrorAction Stop
                return ($srv | Measure-Object).Count -gt 0
            } catch {
                return $false
            }
        }

        function Get-CurrentDomainState {
            Write-Stamp 'Testing if we are already a member of a domain.'
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            [pscustomobject]@{
                PartOfDomain = [bool]$cs.PartOfDomain
                Domain       = if ($cs.PartOfDomain) { $cs.Domain } else { $null }
            }
        }

    #endregion

    #region "If this isn't running as a scheduled task (on-startup) then setup the scheduled task"
    
        Write-Stamp 'Checking if a scheduled task exists to launch this script at system startup'
        if(-not (Get-ScheduledTask -TaskName $bootStrapTaskName -TaskPath '\' -ErrorAction SilentlyContinue))
        {
            Write-Stamp 'Creating an on-startup scheduled task'
            $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$bootStrapperFull`"" -WorkingDirectory $bootStrapperPath
            $trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $bootStrapTaskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings
            Write-Stamp "Created scheduled task `"\$bootStrapTaskName`""
        }

    #endregion

    #region "Get Azure Tags for VM"

        # -------- 0) Gather config (IMDS tags + param overrides) ----------
        Write-Stamp "Reading instance metadata and tags"
        $compute = Get-IMDSJson -path 'instance/compute' -apiVersion '2021-02-01'
        $tags = @{}
        if ($compute.tagsList) { foreach($t in $compute.tagsList){ $tags[$t.name] = $t.value } }

        if (-not $KeyVaultName)                  { $KeyVaultName                  = $tags['epa_KeyVault_Name'] }
        if (-not $KeyVaultADUserSecretName)      { $KeyVaultADUserSecretName      = $tags['epa_KeyVault_ADJoinUser_SecretName'] }
        if (-not $KeyVaultADPasswordSecretName)  { $KeyVaultADPasswordSecretName  = $tags['epa_KeyVault_ADJoinPassword_SecretName'] }
        if (-not $adFQDN)                        { $adFQDN                        = $tags['epa_AD_FQDN'] }
        if (-not $adOU)                          { $adOU                          = $tags['epa_AD_OU'] }
        if (-not $KeyVaultRegUserSecretName)     { $KeyVaultRegUserSecretName     = $tags['epa_KeyVault_RegistrationUser_SecretName'] }
        if (-not $KeyVaultRegPasswordSecretName) { $KeyVaultRegPasswordSecretName = $tags['epa_KeyVault_RegistrationPassword_SecretName'] }

        foreach($pair in @(
          @{Name='KeyVaultName';Value=$KeyVaultName},
          @{Name='adFQDN';Value=$adFQDN},
          @{Name='KeyVaultADUserSecretName';Value=$KeyVaultADUserSecretName},
          @{Name='KeyVaultADPasswordSecretName';Value=$KeyVaultADPasswordSecretName},
          @{Name='KeyVaultRegUserSecretName';Value=$KeyVaultRegUserSecretName},
          @{Name='KeyVaultRegPasswordSecretName';Value=$KeyVaultRegPasswordSecretName}
        )){
          if(-not $pair.Value){ throw "Missing required value for $($pair.Name). Supply via parameter or VM tag." }
        }

    #endregion

    #region "Connect to Az (for Keyvault Access=)"

        Ensure-Module -name Az.Accounts
        Ensure-Module -name Az.KeyVault

        Write-Stamp "Connecting to Azure (Managed Identity)"
        $azCon = Connect-AzAccount -Identity

    #endregion

    #region "Check if the machine is already domain joined (and repair trust if necessary)"

        Write-Stamp "Fetching AD Join credentials from Key Vault '$KeyVaultName'"
        $adUser = Get-PlainText (Invoke-WithRetry {Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultADUserSecretName}).SecretValue
        $adPass = (Invoke-WithRetry {Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultADPasswordSecretName}).SecretValue
        $adCred = New-Object System.Management.Automation.PSCredential($adUser,$adPass)
    
        Write-Stamp "==> Checking DNS/DC reachability for $adFQDN..."
        if (-not (Test-DomainReachable -Domain $adFQDN)) {
            throw "Cannot resolve DC SRV records for $adFQDN. Ensure VM DNS points to domain DNS and network allows access to DCs."
        }

        $needsAdJoin = $true

        $state = Get-CurrentDomainState
        Write-Stamp "==> Current state: PartOfDomain=$($state.PartOfDomain); Domain='$($state.Domain)'"
    
        if ($state.PartOfDomain -and ($state.Domain -ieq $adFQDN)) {
            Write-Stamp "==> Already joined to $adFQDN. Verifying secure channel..."
            try {
                if (-not (Test-ComputerSecureChannel -Verbose)) {
                    Write-Warning "Secure channel broken; attempting repair..."
                    if (-not (Test-ComputerSecureChannel -Repair -Credential $adCred -Verbose)) {
                        throw "Secure channel repair failed"
                    }
                    Write-Stamp "==> Secure channel repaired."
                } else {
                    Write-Stamp "==> Secure channel is healthy."
                }
            } catch {
                throw "Secure channel check/repair failed: $($_.Exception.Message)"
            }
            $needsAdJoin = $false
        }

        if ($state.PartOfDomain -and ($state.Domain -ine $adFQDN)) {
            throw "Machine is already joined to a different domain '$($state.Domain)'. Manually unjoin/workgroup or handle migration logic before proceeding."
        }

    #endregion

    #region "Join the AD Domain (if required)"

        if($needsAdJoin)
        {
            $joinParams = @{
                DomainName = $adFQDN
                Credential = $adCred
                Options    = 'JoinWithNewName','AccountCreate'  # typical; omit AccountCreate if pre-staging accounts
                Force      = $true
                ErrorAction= 'Stop'
            }
            if ($adOU) { $joinParams['OUPath'] = $adOU }

            try
            {
                Add-Computer @joinParams
            } catch {
                if ($_.Exception.Message -match 'already exists|object.*exists')
                {
                  Write-Stamp "Computer account exists; retrying without AccountCreate" 'WARN'
                  $joinParams.Options = 'JoinWithNewName'
                  Add-Computer @joinParams
                } else { throw $_.Exception }
            }

            Write-Stamp "==> Join succeeded."
            Write-Stamp "==> Restarting to complete domain join..."
            Start-Sleep -Seconds 40
            Restart-Computer -Force
        }

    #endregion

    #region "Download the connector installer from MS, then do a silent install"

        if (-not (Test-Path $regScript)) {
            Write-Stamp "Downloading connector installer"
            $installerPath = Join-Path ([IO.Path]::GetTempPath()) $InstallerFileName
            Invoke-WithRetry { Invoke-WebRequest -Uri $InstallerUrl -Method Get -OutFile $installerPath -UseBasicParsing -TimeoutSec 100 }
            Write-Stamp "Installer saved at $installerPath"

            $auth = Get-AuthenticodeSignature -FilePath $installerPath
            if ($auth.Status -ne 'Valid') { throw "Installer signature invalid: $($auth.Status)" } else { Write-Stamp 'Installer signature verified' }

            $installArgs = 'REGISTERCONNECTOR="false" REBOOT=ReallySuppress /q'
            Write-Stamp "Installing connector (quiet, no reboot) -> $installerPath"
            $proc = Start-Process -FilePath $installerPath -ArgumentList $installArgs -PassThru -Wait
            if ($proc.ExitCode -ne 0) { throw "Connector installer exited with code $($proc.ExitCode)" }
        }

    #endregion

    #region "Register the Entra Private Access Connector (using credentials from the KeyVault)"

        Write-Stamp "Fetching registration credentials from Key Vault '$KeyVaultName'"
        $regUser = Get-PlainText (Invoke-WithRetry {Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultRegUserSecretName}).SecretValue
        $regPass = (Invoke-WithRetry {Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultRegPasswordSecretName}).SecretValue
        $epaCred = New-Object System.Management.Automation.PSCredential($regUser,$regPass)

        # Grab the Tenant ID from the AzConnect result
        try {
            $TenantId = $azcon.Context.Tenant.Id
            Write-Stamp "Discovered TenantId: $TenantId"
        } catch { Write-Stamp "Could not derive TenantId from MSI token (continuing): $_" 'WARN' }

        Write-Stamp "Registering connector (AuthenticationMode=Credentials) for tenant $TenantId"
        if($TenantId)
        {
            & $regScript -ModulePath $modPath -ModuleName $modName -AuthenticationMode Credentials -UserCredentials $epaCred -TenantId $TenantId -Feature ApplicationProxy
        }else{
            & $regScript -ModulePath $modPath -ModuleName $modName -AuthenticationMode Credentials -UserCredentials $epaCred -Feature ApplicationProxy
        }

    #endregion

    #region "Cleanup"

        Write-Stamp "Bootstrap complete."
        Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
        Write-Stamp "Disabling startup task '$bootStrapTaskName' to avoid re-running each boot."
        Disable-ScheduledTask -TaskName $bootStrapTaskName -TaskPath '\' -ErrorAction SilentlyContinue | Out-Null

    #endregion

#}catch{
#    Write-Stamp 'Ejecting due to uncaught failure' 'ERR '
#    Write-Host $_.Exception.ToString()
#finally
#{
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
#}


