[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $KeyVaultName,
    [Parameter(Mandatory)] [string] $RegistrationUserSecretName,
    [Parameter(Mandatory)] [string] $RegistrationPasswordSecretName,
    [string] $ConnectorGroupName = '',
    [string] $InstallerUrl = 'https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller',
    [string] $InstallerFileName = 'MicrosoftEntraPrivateNetworkConnectorInstaller.exe',
    [string] $NugetUrl = 'https://onegetcdn.azureedge.net/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll',
    [int]    $HealthPort = 8443
)

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "Run elevated (Administrator)."; exit 1 }

$ErrorActionPreference = 'Stop'

#region "Statics"

    $regScript = "$env:ProgramFiles\Microsoft Entra private network connector\RegisterConnector.ps1"
    $modPath   = "$env:ProgramFiles\Microsoft Entra private network connector\Modules\"
    $modName   = 'MicrosoftEntraPrivateNetworkConnectorPSModule'

#endregion

#region "Start logging"

    $logDir = Join-Path $env:SystemDrive 'Scripts'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
    Start-Transcript -Path (Join-Path $logDir 'epa-bootstrapper.ps1.log') -IncludeInvocationHeader -Force

#endregion

#region "Helper Functions"

    function Write-Stamp([string]$msg, [string]$level = 'INFO') {
        $ts = (Get-Date).ToString('s')
        Write-Host "[$ts][$level] $msg"
    }

    function Invoke-WithRetry([scriptblock]$op, [int]$retries = 5, [int]$delay = 2) {
        for ($i = 1; $i -le $retries; $i++) {
            try { return & $op } catch { if ($i -eq $retries) { throw }; Start-Sleep -Seconds $delay }
        }
    }

    function Get-PlainText {
        param([System.Security.SecureString] $Secure)
        if (-not $Secure) { return $null }
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        try   { [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }

    # Enable TLS 1.2 for all .NET HTTP clients in this session
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Stamp 'TLS 1.2 enabled'

    # Enable strong cryptography for .NET Framework (permanent fix for TLS issues)
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
    )
    foreach ($p in $regPaths) {
        if (Test-Path $p) {
            Set-ItemProperty -Path $p -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
        }
    }
    Write-Stamp 'Strong crypto registry keys set'

    $script:psGallery = $null

    function Ensure-Module($name, $minVer = "0.0.0.0") {
        Write-Stamp "Ensuring availability of module $name"
        if (-not $script:psGallery) {
            Write-Stamp 'Setting up PS Gallery'

            try { $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue } catch {}
            if ((-not $nuget) -or ($nuget.Version -lt [version]"2.8.5.201")) {
                Write-Stamp 'Installing NuGet provider'
                $nugetVer    = '2.8.5.208'
                $dllName     = 'Microsoft.PackageManagement.NuGetProvider.dll'
                $providerRoot = Join-Path $env:ProgramFiles 'PackageManagement\ProviderAssemblies\nuget'
                $providerDir  = Join-Path $providerRoot $nugetVer
                New-Item -ItemType Directory -Force -Path $providerDir | Out-Null

                $dest = Join-Path $providerDir $dllName
                try {
                    Invoke-WithRetry { Invoke-WebRequest -Uri $NugetUrl -OutFile $dest -UseBasicParsing }
                    Write-Stamp 'NuGet provider downloaded'
                    $userCacheDir = Join-Path $env:LOCALAPPDATA "PackageManagement\ProviderAssemblies\nuget\$nugetVer"
                    New-Item -ItemType Directory -Force -Path $userCacheDir | Out-Null
                    Copy-Item $dest (Join-Path $userCacheDir $dllName) -Force
                } catch {
                    Write-Stamp "NuGet download failed: $_" 'WARN'
                }
            }

            $pmMin = [Version]'1.4.8.1'
            $pgMin = [Version]'2.2.5'
            $pm = Get-Module PackageManagement -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
            $pg = Get-Module PowerShellGet    -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

            if (-not $pm -or $pm.Version -lt $pmMin) {
                Write-Stamp 'Installing PackageManagement'
                Install-Module PackageManagement -MinimumVersion $pmMin -Force -AllowClobber -Confirm:$false -Scope AllUsers
            }
            if (-not $pg -or $pg.Version -lt $pgMin) {
                Write-Stamp 'Installing PowerShellGet'
                Install-Module PowerShellGet -MinimumVersion $pgMin -Force -AllowClobber -Confirm:$false -Scope AllUsers
            }

            Remove-Module PackageManagement, PowerShellGet -ErrorAction SilentlyContinue
            Import-Module PackageManagement
            Import-Module PowerShellGet

            try {
                if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
                    Write-Stamp 'Trusting PSGallery'
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                }
            } catch {}

            $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
            if ((-not $nuget) -or ($nuget.Version -lt [version]"2.8.5.201")) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Confirm:$false | Out-Null
            }
        }
        if (-not $script:psGallery) { $script:psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue }
        if (-not $script:psGallery) { Register-PSRepository -Default | Out-Null; $script:psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue }
        if ($script:psGallery.InstallationPolicy -ne 'Trusted') { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
        if (-not (Get-Module -ListAvailable -Name $name | Where-Object { $_.Version -ge [version]$minVer })) {
            Write-Stamp "Installing PS Module :: $name"
            Install-Module $name -Force -AllowClobber -Scope AllUsers -MinimumVersion $minVer
        }
    }

#endregion

#region "Connect to Azure and retrieve registration credentials"

    Ensure-Module -name Az.Accounts
    Ensure-Module -name Az.KeyVault

    Write-Stamp "Connecting to Azure (Managed Identity)"
    $azCon = Connect-AzAccount -Identity

    Write-Stamp "Fetching registration credentials from Key Vault '$KeyVaultName'"
    $regUser = Get-PlainText (Invoke-WithRetry { Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $RegistrationUserSecretName }).SecretValue
    $regPass = (Invoke-WithRetry { Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $RegistrationPasswordSecretName }).SecretValue
    $epaCred = New-Object System.Management.Automation.PSCredential($regUser, $regPass)

    $TenantId = $azCon.Context.Tenant.Id
    Write-Stamp "Discovered TenantId: $TenantId"

#endregion

#region "Download and install the EPNC connector"

    if (-not (Test-Path $regScript)) {
        Write-Stamp "Downloading connector installer"
        $installerPath = Join-Path ([IO.Path]::GetTempPath()) $InstallerFileName
        Invoke-WithRetry { Invoke-WebRequest -Uri $InstallerUrl -Method Get -OutFile $installerPath -UseBasicParsing -TimeoutSec 100 }
        Write-Stamp "Installer saved at $installerPath"

        $auth = Get-AuthenticodeSignature -FilePath $installerPath
        if ($auth.Status -ne 'Valid') { throw "Installer signature invalid: $($auth.Status)" }
        Write-Stamp 'Installer signature verified'
        if ($auth.SignerCertificate.Subject -notlike "CN=Microsoft Corporation,*") { throw "Installer signature not by Microsoft: $($auth.SignerCertificate.Subject)" }
        Write-Stamp 'Installer signed by Microsoft'

        $installArgs = 'REGISTERCONNECTOR="false" REBOOT=ReallySuppress /q'
        Write-Stamp "Installing connector (quiet, no reboot) -> $installerPath"
        $proc = Start-Process -FilePath $installerPath -ArgumentList $installArgs -PassThru -Wait
        if ($proc.ExitCode -ne 0) { throw "Connector installer exited with code $($proc.ExitCode)" }
        Write-Stamp "Connector installed successfully"
    } else {
        Write-Stamp "Connector already installed (RegisterConnector.ps1 exists)"
    }

#endregion

#region "Register the EPNC connector"

    Write-Stamp "Registering connector (AuthenticationMode=Credentials) for tenant $TenantId"
    & $regScript -ModulePath $modPath -ModuleName $modName -AuthenticationMode Credentials -UserCredentials $epaCred -TenantId $TenantId -Feature ApplicationProxy
    Write-Stamp "Connector registered successfully"

#endregion

#region "Connector Group Assignment (optional)"

    if ($ConnectorGroupName) {
        Write-Stamp "Connector group assignment requested: '$ConnectorGroupName'"

        # TODO: Implement connector group assignment via Microsoft Graph Beta API.
        #
        # Prerequisites:
        #   - The UAMI assigned to this VMSS must have the 'NetworkAccess.ReadWrite.All' Microsoft Graph
        #     application permission. This must be granted via PowerShell (cannot be done in Bicep):
        #
        #       $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
        #       $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq 'NetworkAccess.ReadWrite.All' }
        #       $uamiSp  = Get-MgServicePrincipal -Filter "displayName eq 'uami-entraprivateconnector'"
        #       New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $uamiSp.Id `
        #           -PrincipalId $uamiSp.Id -ResourceId $graphSp.Id -AppRoleId $appRole.Id
        #
        #   - Install module on the VM: Microsoft.Graph.Beta.Applications
        #
        # Implementation steps:
        #   1. Connect-MgGraph -Identity
        #   2. Find this connector by machine name:
        #      $connectors = Get-MgBetaOnPremisePublishingProfileConnector -OnPremisesPublishingProfileId 'applicationProxy'
        #      $thisConnector = $connectors | Where-Object { $_.MachineName -eq $env:COMPUTERNAME }
        #   3. Find or create the target connector group:
        #      $groups = Get-MgBetaOnPremisePublishingProfileConnectorGroup -OnPremisesPublishingProfileId 'applicationProxy'
        #      $targetGroup = $groups | Where-Object { $_.Name -eq $ConnectorGroupName }
        #      if (-not $targetGroup) {
        #          $targetGroup = New-MgBetaOnPremisePublishingProfileConnectorGroup `
        #              -OnPremisesPublishingProfileId 'applicationProxy' -BodyParameter @{ name = $ConnectorGroupName }
        #      }
        #   4. Assign connector to group:
        #      $body = @{ '@odata.id' = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($targetGroup.Id)" }
        #      New-MgBetaOnPremisePublishingProfileConnectorMemberOfByRef `
        #          -OnPremisesPublishingProfileId 'applicationProxy' `
        #          -ConnectorId $thisConnector.Id -BodyParameter $body

        Write-Warning "Connector group assignment is not yet implemented. The connector has been registered to the default group. Assign it manually or implement the Graph API steps documented in this script."
    }

#endregion

#region "Start health HTTP listener"

    Write-Stamp "Setting up health HTTP listener on port $HealthPort"

    $healthScriptPath = Join-Path $logDir 'epa-health-listener.ps1'
    $healthTaskName   = 'EPA-HealthListener'

    # Write the health listener script to disk
    $healthScriptContent = @"
`$ErrorActionPreference = 'Continue'
`$listener = [System.Net.HttpListener]::new()
`$listener.Prefixes.Add("http://+:$HealthPort/health/")
`$listener.Start()

while (`$listener.IsListening) {
    try {
        `$context  = `$listener.GetContext()
        `$response = `$context.Response

        `$svc = Get-Service -Name 'WAPCSvc' -ErrorAction SilentlyContinue
        if (`$svc -and `$svc.Status -eq 'Running') {
            `$response.StatusCode = 200
            `$body = '{"status":"Healthy","service":"WAPCSvc","state":"Running"}'
        } else {
            `$response.StatusCode = 503
            `$state = if (`$svc) { `$svc.Status.ToString() } else { 'NotFound' }
            `$body = '{"status":"Unhealthy","service":"WAPCSvc","state":"' + `$state + '"}'
        }

        `$response.ContentType    = 'application/json'
        `$buffer                  = [System.Text.Encoding]::UTF8.GetBytes(`$body)
        `$response.ContentLength64 = `$buffer.Length
        `$response.OutputStream.Write(`$buffer, 0, `$buffer.Length)
        `$response.OutputStream.Close()
    } catch {
        Start-Sleep -Seconds 1
    }
}
"@
    Set-Content -Path $healthScriptPath -Value $healthScriptContent -Force

    # Reserve the URL for non-admin listeners (the task runs as SYSTEM, but this ensures clean operation)
    netsh http add urlacl url="http://+:$HealthPort/health/" user="NT AUTHORITY\SYSTEM" | Out-Null

    # Open the firewall for the health port
    New-NetFirewallRule -DisplayName 'EPA Health Listener' -Direction Inbound -Protocol TCP -LocalPort $HealthPort -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Stamp "Firewall rule added for port $HealthPort"

    # Register as a scheduled task that starts at boot and runs persistently
    if (-not (Get-ScheduledTask -TaskName $healthTaskName -TaskPath '\' -ErrorAction SilentlyContinue)) {
        $action    = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
                        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$healthScriptPath`""
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $healthTaskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Write-Stamp "Health listener scheduled task registered"
    }

    # Start the task immediately
    Start-ScheduledTask -TaskName $healthTaskName -TaskPath '\'
    Write-Stamp "Health listener started on port $HealthPort"

#endregion

#region "Cleanup"

    Write-Stamp "Bootstrap complete."
    Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue

#endregion

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
