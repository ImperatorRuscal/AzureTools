[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $KeyVaultName,
    [Parameter(Mandatory)] [string] $RegistrationUserSecretName,
    [Parameter(Mandatory)] [string] $RegistrationPasswordSecretName,
    [Parameter(Mandatory)] [string] $UamiClientId,
    [string] $ConnectorGroupName = '',
    [string] $InstallerUrl = 'https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller',
    [string] $InstallerFileName = 'MicrosoftEntraPrivateNetworkConnectorInstaller.exe',
    [int]    $HealthPort = 8443
)

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "Run elevated (Administrator)."; exit 1 }

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Progress bars slow Invoke-WebRequest to a crawl in non-interactive sessions

# Suppress all Az module interactive prompts (telemetry, surveys, breaking-change warnings)
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
$env:Azure_PS_Data_Collection                      = 'true'

#region "Statics"

    $ScriptVersion = '2.1.0'   # Bump on each meaningful change to aid log-based troubleshooting

    $regScript = "$env:ProgramFiles\Microsoft Entra private network connector\RegisterConnector.ps1"
    $modPath   = "$env:ProgramFiles\Microsoft Entra private network connector\Modules\"
    $modName   = 'MicrosoftEntraPrivateNetworkConnectorPSModule'

#endregion

#region "Start logging"

    $logDir = Join-Path $env:SystemDrive 'Scripts'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
    Start-Transcript -Path (Join-Path $logDir 'epa-bootstrapper.ps1.log') -IncludeInvocationHeader -Force
    Write-Host "epa-bootstrapper.ps1 v$ScriptVersion"

#endregion

#region "Helper Functions"

    function Write-Stamp([string]$msg, [string]$level = 'INFO') {
        $ts = (Get-Date).ToString('s')
        Write-Host "[$ts][$level] $msg"
    }

    Write-Stamp "epa-bootstrapper.ps1 v$ScriptVersion"

    function Invoke-WithRetry([scriptblock]$op, [int]$retries = 5, [int]$delay = 2) {
        for ($i = 1; $i -le $retries; $i++) {
            try { return & $op } catch { if ($i -eq $retries) { throw }; Start-Sleep -Seconds $delay }
        }
    }

    # Retry with exponential back-off for operations affected by Azure RBAC
    # propagation delays (up to 10 minutes). Only retries errors matching
    # $retryablePattern; throws immediately for non-retryable failures.
    function Invoke-WithRetryBackoff {
        param(
            [Parameter(Mandatory)] [scriptblock] $Op,
            [int]    $MaxAttempts     = 10,
            [int]    $InitialDelay    = 15,
            [int]    $MaxDelay        = 60,
            [string] $RetryablePattern = 'Forbidden|throttled|429|503'
        )
        $delay = $InitialDelay
        for ($i = 1; $i -le $MaxAttempts; $i++) {
            try {
                return & $Op
            } catch {
                if ($i -eq $MaxAttempts) { throw }
                if ($_.Exception.Message -notmatch $RetryablePattern) { throw }
                $errMsg = ($_.Exception.Message -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(200, $_.Exception.Message.Length))
                Write-Stamp "Attempt $i failed ($errMsg), retrying in ${delay}s..." 'WARN'
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, $MaxDelay)
            }
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

    # Install a module by downloading its .nupkg directly from PSGallery.
    # This bypasses NuGet provider, PackageManagement, PowerShellGet, and
    # PSGallery trust — eliminating all interactive prompts that can hang
    # in non-interactive contexts like CustomScriptExtension.
    function Install-ModuleFromGallery {
        param(
            [Parameter(Mandatory)] [string]   $Name,
            [string] $MinimumVersion = '0.0.0.0'
        )

        # Skip if already available
        if (Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -ge [version]$MinimumVersion }) {
            Write-Stamp "Module $Name already installed (>= $MinimumVersion)"
            return
        }

        Write-Stamp "Installing module $Name from PSGallery (direct download)"

        $galleryApi = "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='$Name'&`$orderby=Version desc&`$top=1"
        $feedXml    = Invoke-WithRetry {
            [xml](Invoke-WebRequest -Uri $galleryApi -UseBasicParsing -TimeoutSec 30).Content
        }
        $entry      = $feedXml.feed.entry
        $packageUrl = $entry.content.src
        $version    = $entry.properties.Version

        if ([version]$version -lt [version]$MinimumVersion) {
            throw "Latest $Name version ($version) is below required minimum ($MinimumVersion)"
        }

        Write-Stamp "Downloading $Name $version"
        $nupkgPath = Join-Path ([IO.Path]::GetTempPath()) "$Name.$version.nupkg"
        Invoke-WithRetry { Invoke-WebRequest -Uri $packageUrl -OutFile $nupkgPath -UseBasicParsing -TimeoutSec 60 }

        $installDir = Join-Path "$env:ProgramFiles\WindowsPowerShell\Modules" "$Name\$version"
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null

        Write-Stamp "Extracting $Name to $installDir"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($nupkgPath)
        try {
            foreach ($zipEntry in $zip.Entries) {
                # Skip NuGet packaging metadata — only extract module files
                if ($zipEntry.FullName -match '^\[Content_Types\]|^_rels/|^package/|\.nuspec$') { continue }
                $destPath = Join-Path $installDir $zipEntry.FullName
                $destDir  = Split-Path $destPath -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
                if ($zipEntry.Name) {
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($zipEntry, $destPath, $true)
                }
            }
        } finally {
            $zip.Dispose()
        }

        Remove-Item $nupkgPath -Force -ErrorAction SilentlyContinue
        Write-Stamp "Module $Name $version installed"
    }

#endregion

#region "Connect to Azure and retrieve registration credentials"

    Install-ModuleFromGallery -Name Az.Accounts
    Install-ModuleFromGallery -Name Az.KeyVault

    Write-Stamp "Connecting to Azure (Managed Identity: $UamiClientId)"
    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
    $azCon = Connect-AzAccount -Identity -AccountId $UamiClientId -SkipContextPopulation

    Write-Stamp "Fetching registration credentials from Key Vault '$KeyVaultName'"
    $regUser = Get-PlainText (Invoke-WithRetryBackoff -Op { Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $RegistrationUserSecretName }).SecretValue
    $regPass = (Invoke-WithRetryBackoff -Op { Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $RegistrationPasswordSecretName }).SecretValue
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
        $proc = Start-Process -FilePath $installerPath -ArgumentList $installArgs -PassThru
        $timeoutMs = 10 * 60 * 1000  # 10 minutes
        if (-not $proc.WaitForExit($timeoutMs)) {
            $proc.Kill()
            throw "Connector installer timed out after 10 minutes"
        }
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
    New-NetFirewallRule -DisplayName 'EPA Health Listener' -Direction Inbound -Protocol TCP -LocalPort $HealthPort -Action Allow -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
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

    # Start the task immediately and verify it's running
    Start-ScheduledTask -TaskName $healthTaskName -TaskPath '\'
    Start-Sleep -Seconds 2
    $taskInfo = Get-ScheduledTask -TaskName $healthTaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($taskInfo.State -ne 'Running') {
        Write-Stamp "Health listener task state: $($taskInfo.State) (expected Running)" 'WARN'
    } else {
        Write-Stamp "Health listener started on port $HealthPort"
    }

#endregion

#region "Cleanup"

    Write-Stamp "Bootstrap complete."
    Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue

#endregion

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
