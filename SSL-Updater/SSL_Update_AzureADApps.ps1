#region Get Parameters

    Param(
        [Parameter(Mandatory,HelpMessage='The name of the Resource Group that contains the Storage Account that holds the Blob with the PoSh-ACME settings file.')]
        [string]$storageResourceGroup,

        [Parameter(Mandatory,HelpMessage='Name of the Storage Account that holds the Blob container with the PoSh-ACME settings file.')]
        [string]$storageAccountName,

        [Parameter(Mandatory,HelpMessage='The name of the Storage Container that holds the Blob with the PoSh-ACME settigns file.')]
        [String]$storageContainer,

        [Parameter(Mandatory,HelpMessage='The azure Key Vault that will hold the plugin arguments, PFX password, and the exported PFX files for created certificates.')]
        [string]$keyVault,

        [Parameter(Mandatory,HelpMessage='The name of the Secret in the Key Vault that holds the password used to encrypt the PFX files created by PoSh-ACME')]
        [string]$pfxSecretName,

        [Parameter(Mandatory,HelpMessage='The name of Secret in the Key Vault that is storing the API Key Name (or username, or the otherwise unencrypted part of the login pair) for the DNS plugin''s login.')]
        [string]$DnsApiKeyName,

        [Parameter(Mandatory,HelpMessage='The name of Secret in the Key Vault that is storing the API Secret (or password, or the otherwise encrypted part of the login pair) for the DNS plugin''s login.')]
        [string]$DnsApiSecretName,

        [Parameter(HelpMessage='The DNS provider you use.  Used to select the appropriate DNS Plugin for PoSh-ACME')]
        [ValidateSet('Aliyun','All-Inkl','Cloudflare','Combell','Constellix','DnsMadeEasy','DNSPod','DNSimple','DigitalOcean','deSEC','DomainOffensive','Domeneshop','GoDaddy','Rackspace',IgnoreCase = $true)]
        [string]$DnsProvider='DNSMadeEasy',

		[Parameter(HelpMessage='The CNAME to use for the ACME validation when the $subject domain isn''t accessible to by your standard DNS API.')]
		[string]$DnsAlias='',

        [Parameter(HelpMessage='Time (in seconds) that the process should wait for DNS records to propogate, prior to having the ACME server attempt the record lookup for validation.')]
        [int]$DnsSleep=120,

        [Parameter(HelpMessage='Time (in seconds) that the client should wait for a validation result from the ACME server.  If positive validation is not received in this time, the client assumes that validation has failed.')]
        [int]$ValidationTimeout=60,

        [Parameter(HelpMessage='A regular expression that will match the subject of certificates that shouldn''t be updated/renewed by this script.  Original intent was to match on subjects for EV certificates that we''re still going to be purchasing.')]
        [string]$RegExDontUpdateTheseCerts='^$',

        [Parameter(HelpMessage='The minimum number of days left before the cert should be forced to renew.')]
        [ValidateRange(1,50)]
        [int]$daysLeftWhenRenewing = 16,

        [Parameter(HelpMessage='Email address used for the certificate registration account.  Any notcies that are created for the account/orders will be sent to this address.')]
        [string]$CertContact,

        [Parameter(HelpMessage='Which ACME server will get the requests.  Defaults to LE_Prod.  Use LE_STAGE for testing.')]
        [ValidateSet('LE_Prod','LE_STAGE',IgnoreCase = $true)]
        $AcmeCertServer='LE_PROD',

        [Parameter(HelpMessage='Do you want to save a copy of the certificate back to the Key Vault?  Default: TRUE')]
        [bool]$SaveCertificateToKeyVault = $true,

        [Parameter(HelpMessage='Process Application Gateway listeners for certificate renewal.')]
        [switch]$WorkOnApplicationGateways,

        [Parameter(HelpMessage='Process App Service Plan web apps for certificate renewal.')]
        [switch]$WorkOnAppServicePlans,

        [Parameter(HelpMessage='List which certs would be renewed without actually generating or applying certificates.')]
        [switch]$DryRun
    )

#endregion

#region Helper Functions

    function New-AcmeCertificateWithFallback {
        param(
            [string[]]$Subject,
            [string]$FriendlyName,
            [string]$Plugin,
            [hashtable]$PluginArgs,
            [System.Security.SecureString]$PfxPassword,
            [int]$Sleep,
            [int]$Timeout,
            [string]$Alias
        )
        try {
            Write-Output "                with a direct TXT record on the A-record"
            $cert = New-PACertificate -Domain $Subject -DnsPlugin $Plugin -PluginArgs $PluginArgs -FriendlyName $FriendlyName -PfxPassSecure $PfxPassword -Force -Verbose -DnsSleep $Sleep -ValidationTimeout $Timeout
        } catch {
            if ($Alias) {
                Write-Output "                with an indirect TXT record on the CNAME"
                $cert = New-PACertificate -Domain $Subject -DnsAlias $Alias -DnsPlugin $Plugin -PluginArgs $PluginArgs -FriendlyName $FriendlyName -PfxPassSecure $PfxPassword -Force -Verbose -DnsSleep $Sleep -ValidationTimeout $Timeout
            } else {
                throw
            }
        }
        return $cert
    }

    function Remove-AcmeSensitiveFiles {
        param([string]$CertKeyFile)
        if (-not $CertKeyFile) { return }
        $cleanupPath = $CertKeyFile.Substring(0, $CertKeyFile.LastIndexOf('\'))
        foreach ($filter in @('*.bak','*.csr','*.key','*.cer','*.pfx','pluginargs.json')) {
            Get-ChildItem -Path $cleanupPath -File -Filter $filter -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }

    function Save-CertToKeyVault {
        param(
            [string]$VaultName,
            [string]$SubjectName,
            [string]$PfxPath,
            [System.Security.SecureString]$PfxPassword
        )
        Write-Output "        saving a copy of the PFX to the keyvault"
        $kvName = $SubjectName.Replace('.','-')
        Import-AzKeyVaultCertificate -VaultName $VaultName -Name $kvName -FilePath $PfxPath -Password $PfxPassword | Out-Null
        Write-Output "        saved $kvName to $VaultName"
    }

    function Get-AzAppGWCert {
        param(
            [string]$RG,
            [string]$AppGWName,
            [switch]$Details,
            [switch]$Export
        )

        if ($AppGWName -and $RG) {
            $AppGWs = Get-AzApplicationGateway -ResourceGroupName $RG -Name $AppGWName
        } elseif ($RG) {
            $AppGWs = Get-AzApplicationGateway -ResourceGroupName $RG
        } elseif ($AppGWName) {
            throw "-AppGWName requires parameter -RG (ResourceGroup)"
        } else {
            $AppGWs = Get-AzApplicationGateway
        }

        $TemplateObject = New-Object PSObject | Select-Object AppGWName,ResourceGroupName,ListenerName,Subject,Issuer,SerialNumber,Thumbprint,NotBefore,NotAfter
        $TemplateObjectBackEnd = New-Object PSObject | Select-Object AppGWName,ResourceGroupName,HTTPSetting,RuleName,BackendCertName,Subject,Issuer,SerialNumber,Thumbprint,NotBefore,NotAfter

        foreach ($AppGW in $AppGWs) {
            $httpsListeners = $AppGW.HttpListeners | Where-Object { $_.Protocol -eq "HTTPS" }
            foreach ($httpsListener in $httpsListeners) {
                $httpsListenerSSLCert = ($AppGW.SslCertificatesText | ConvertFrom-Json) | Where-Object { $_.Id -eq $httpsListener.SslCertificate.Id }
                $httpsListenerSSLCertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($httpsListenerSSLCert.PublicCertData.Substring(60, $httpsListenerSSLCert.PublicCertData.Length - 60)))

                $WorkingObject = $TemplateObject | Select-Object *
                $WorkingObject.AppGWName = $AppGW.Name
                $WorkingObject.ResourceGroupName = $AppGW.ResourceGroupName
                $WorkingObject.ListenerName = $httpsListener.Name
                $WorkingObject.Subject = $httpsListenerSSLCertObj.Subject
                $WorkingObject.Issuer = $httpsListenerSSLCertObj.Issuer
                $WorkingObject.SerialNumber = $httpsListenerSSLCertObj.SerialNumber
                $WorkingObject.Thumbprint = $httpsListenerSSLCertObj.Thumbprint
                $WorkingObject.NotBefore = $httpsListenerSSLCertObj.NotBefore
                $WorkingObject.NotAfter = $httpsListenerSSLCertObj.NotAfter
                $WorkingObject

                if ($Details) {
                    $httpsListenerSSLCertObj | Select-Object *
                }
                if ($Export) {
                    [System.IO.File]::WriteAllBytes((Join-Path (Resolve-Path .\).Path "$($AppGW.Name)-$($AppGW.ResourceGroupName)-$($httpsListener.Name).cer"), $httpsListenerSSLCertObj.RawData)
                }
            }

            $Rules = ($AppGW.RequestRoutingRulesText | ConvertFrom-Json)

            foreach ($rule in $Rules) {
                $RuleHttpSettingsID = $rule.BackendHttpSettings.ID
                $BackendHttpSettings = ($AppGW.BackendHttpSettingsCollectionText | ConvertFrom-Json) | Where-Object { $_.Id -eq $RuleHttpSettingsID } | Where-Object { $_.Protocol -eq "HTTPS" }
                if ($null -ne $BackendHttpSettings) {
                    $BackendHttpSettingsCerts = $BackendHttpSettings.AuthenticationCertificates
                    foreach ($BackendHttpSettingsCert in $BackendHttpSettingsCerts) {
                        $BackendCerts = ($AppGW.AuthenticationCertificatesText | ConvertFrom-Json) | Where-Object { $_.Id -eq $BackendHttpSettingsCert.Id }
                        foreach ($BackendCert in $BackendCerts) {
                            $BackendCertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($BackendCert.Data))

                            $WorkingObjectBackEnd = $TemplateObjectBackEnd | Select-Object *
                            $WorkingObjectBackEnd.AppGWName = $AppGW.Name
                            $WorkingObjectBackEnd.ResourceGroupName = $AppGW.ResourceGroupName
                            $WorkingObjectBackEnd.RuleName = $rule.Name
                            $WorkingObjectBackEnd.HTTPSetting = $BackendHttpSettings.Name
                            $WorkingObjectBackEnd.BackendCertName = $BackendCert.Name
                            $WorkingObjectBackEnd.Subject = $BackendCertObj.Subject
                            $WorkingObjectBackEnd.Issuer = $BackendCertObj.Issuer
                            $WorkingObjectBackEnd.SerialNumber = $BackendCertObj.SerialNumber
                            $WorkingObjectBackEnd.Thumbprint = $BackendCertObj.Thumbprint
                            $WorkingObjectBackEnd.NotBefore = $BackendCertObj.NotBefore
                            $WorkingObjectBackEnd.NotAfter = $BackendCertObj.NotAfter
                            $WorkingObjectBackEnd
                            if ($Details) {
                                $BackendCertObj | Select-Object *
                            }
                            if ($Export) {
                                [System.IO.File]::WriteAllBytes((Join-Path (Resolve-Path .\).Path "$($AppGW.Name)-$($AppGW.ResourceGroupName)-$($rule.Name)-$($BackendHttpSettings.Name)-$($BackendCert.Name).cer"), $BackendCertObj.RawData)
                            }
                        }
                    }
                }
            }
        }
    }

#endregion

#region Connect
    Write-Output "Getting Az Connection"
	$AzConnect = Connect-AzAccount -Identity
	Write-Output "     Az Connection completed"

    $context = Get-AzContext

    Write-Output "     The context account is: $($context.Account.Id)"
    Write-Output "     The Tenant ID is: $($context.Tenant.Id)"
    Write-Output "     The subscription is: $($context.Subscription.Name)"

    Import-Module Microsoft.Graph.Beta.Applications
    $MgConnect = Connect-MgGraph -Identity -NoWelcome

	Write-Output "     Microsoft Graph connection completed"
#endregion

#region Check if WriteLock is in place and try 3 more time
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $storageResourceGroup -Name $storageAccountName
    Remove-Variable writeLock -ErrorAction SilentlyContinue
    $i = 0
    $writeLock = Get-AzStorageBlob -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.settings.lock" -ErrorAction SilentlyContinue
    while(($WriteLock.count -gt 0) -and ($i -le 3))
    {
        $i++
        Write-Output "PoSh-ACME profile is currently locked ($i/3)"
        $writeLock | Get-AzStorageBlobContent -Force
        if((Get-Date (Get-Content $writeLock.Name)[0]) -lt ((Get-Date).AddHours(-20)))
        {
            Write-Output 'The lock is over 20 hours old -- lets forceably clean that up'
            Copy-AzStorageBlob -Context $storageAccount.Context -SrcContainer $storageContainer -SrcBlob "posh-acme.settings.lock" -DestContext $storageAccount.Context -DestContainer $storageContainer -DestBlob "posh-acme.settings.$((Get-Date).toString("yyyyMMddThhmm")).unlocked" -ErrorAction SilentlyContinue
            Remove-AzStorageBlob -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.settings.lock" -Force
        }
        $WaitPeriod = Get-Random -Minimum 30 -Maximum 120
        Write-Output "Wait for $WaitPeriod seconds and try again"
        Start-Sleep -Seconds $WaitPeriod
        $writeLock = Get-AzStorageBlob -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.settings.lock" -ErrorAction SilentlyContinue
    }
    if ($WriteLock.Count -gt 0)
    {
        Write-Output "Cannot get write access to the config profile"
        throw "Cannot get write access to config profile!"
    }
    # Set WriteLock to true
    "$(Get-Date)`r`n$env:COMPUTERNAME`r`n$PSCommandPath`r`n`r`nAutomation RunBook`r`nSSL_Update_AzureADApps.ps1" | Out-File -FilePath "posh-acme.setting.lock" -Force
    Set-AzStorageBlobContent -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.settings.lock" -BlobType Block -File "posh-acme.setting.lock" -Force | Out-Null
#endregion

#region Get the ACME Client profile from the storage account
    $workingDirectory = Join-Path -Path "." -ChildPath "posh-acme"
    try
    {
		Write-Output "Attempting to download the posh-acme configuration file"
        # Download posh-acme configuration zip
        Get-AzStorageBlobContent -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.zip" -Destination . -ErrorAction Stop | Out-Null
        # Expand zip file
        Expand-Archive ".\posh-acme.zip" -DestinationPath .
        Remove-Item -Force .\posh-acme.zip | Out-Null
        Write-Output "Downloaded and expanded ZIP file with posh-acme configuration"
    } catch {
        $_
        # Storage blob not found, create new folder
        New-Item -Path $workingDirectory -ItemType Directory | Out-Null
        Write-Output "Use new configuration directory, no posh-acme configuration found"
    }
#endregion

#region Set posh-acme working directory to downloaded configuration
	Write-Output "Setting the posh-acme config directory, and loading the module"
    $env:POSHACME_HOME = $workingDirectory
    Import-Module Posh-ACME -Force
#endregion

#region Setup the posh-acme settings
	Write-Output "Configuring the ACME account"
    Set-PAServer $AcmeCertServer  # Use the Lets Encrypt Production server
    if($null -eq (Get-PAAccount -List -Status valid -Refresh))
    {
        New-PAAccount -AcceptTOS -Contact $CertContact
    }
    $account = (Get-PAAccount -List -Status valid)[0] # Get the user account by ID (variable up top)
    Set-PAAccount -ID $account.id # Set that account as the active one

	Write-Output "Getting PFX password from the Key Vault"
    $CertPassword = Get-AzKeyVaultSecret -VaultName $keyVault -Name $pfxSecretName

###### TODO -- put in a case statement that uses $DnsProvider to set the plugin name and parameter key names -- needs continuation     https://poshac.me/docs/v4/Plugins/

	# Get DNS API parameters from the Azure KeyVault
    Remove-Variable AcmePlugin,AcmePluginArgs -ErrorAction SilentlyContinue
	Write-Output "Setting up the DNS API parameters for [$DnsProvider]"
    switch($DnsProvider.ToLower().Replace(' ',''))
    {
        'aliyun' {
            $AcmePlugin = 'Aliyun'
            $AcmePluginArgs = @{ AliKeyId=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); AliSecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'all-inkl' {
            $AcmePlugin = 'All-Inkl'
            $AcmePluginArgs = @{ KasUsername=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); KasPwd=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'cloudflare' {
            $AcmePlugin = 'Cloudflare'
            $AcmePluginArgs = @{ CFAuthEmail=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); CFAuthKeySecure=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'combell' {
            $AcmePlugin = 'Combell'
            $AcmePluginArgs = @{ CombellApiKey=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); CombellApiSecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'constellix' {
            $AcmePlugin = 'Constellix'
            $AcmePluginArgs = @{ ConstellixKey=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); ConstellixSecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'dnsmadeeasy' {
            $AcmePlugin = 'DMEasy'
            $AcmePluginArgs = @{ DMEKey=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); DMESecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'dnspod' {
            $AcmePlugin = 'DNSPod'
            $AcmePluginArgs = @{ DNSPodKeyID=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); DNSPodToken=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'godaddy' {
            $AcmePlugin = 'GoDaddy'
            $AcmePluginArgs = @{ GDKey=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); GDSecretSecure=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'rackspace' {
            $AcmePlugin = 'Rackspace'
            $AcmePluginArgs = @{ RSUsername=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); RSApiKey=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'dnsimple' {
            $AcmePlugin = 'DNSimple'
            $AcmePluginArgs = @{ DSToken=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'digitalocean' {
            $AcmePlugin = 'DOcean'
            $AcmePluginArgs = @{ DOTokenSecure=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'desec' {
            $AcmePlugin = 'DeSEC'
            $AcmePluginArgs = @{ DSCToken=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'domainoffensive' {
            $AcmePlugin = 'DomainOffensive'
            $AcmePluginArgs = @{ DomOffToken=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        'domeneshop' {
            $AcmePlugin = 'Domeneshop'
            $AcmePluginArgs = @{ DomeneshopToken=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); DomeneshopSecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
        default {
            $AcmePlugin = 'DMEasy'
            $AcmePluginArgs = @{ DMEKey=(Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiKeyName -AsPlainText); DMESecret=((Get-AzKeyVaultSecret -VaultName $keyVault -Name $DnsApiSecretName).SecretValue) }
        }
    }
	Write-Output "        using plugin [$AcmePlugin]"
#endregion

#region Get all of the applications in the directory
    Write-Output "Reading service principals."
    $aadapServPrinc = Get-MgBetaServicePrincipal -Top 100000 | Where-Object { $_.Tags -contains "WindowsAzureActiveDirectoryOnPremApp" }

    Write-Output "Reading proxy applications..."
    $aadapApp = @()
    $aadapServPrinc | Sort-Object DisplayName | ForEach-Object { $aadapApp += Get-MgBetaApplication -Filter "AppID eq '$($_.AppId)'" }
#endregion

#region Cycle through all the apps, look for one with a cert near expiry, and update it.
    for($i=0; $i -lt $aadapApp.Count; $i++)
    {
        Write-Progress -CurrentOperation $aadapApp[$i].DisplayName -PercentComplete ((100*$i)/$aadapApp.Count) -Activity "Getting App Proxy Configs"

        $onPrem = Get-MgBetaApplication -ApplicationId $aadapApp[$i].Id -Select OnPremisesPublishing | Select-Object -ExpandProperty OnPremisesPublishing
        $certMeta = (Get-MgBetaApplication -ApplicationId $aadapApp[$i].Id -Select OnPremisesPublishing | Select-Object -ExpandProperty OnPremisesPublishing | Select-Object -ExpandProperty verifiedCustomDomainCertificatesMetadata)

        try
        {
            $subject = @()
            $needsUpdating = $false
            try
            {
                # Don't try updating a cert if it isn't SSL-ed or if it is from Microsoft's domain
                if((-not $onPrem.ExternalUrl.StartsWith('https://')) -or ($onPrem.ExternalUrl.EndsWith('.msappproxy.net/'))){Continue}

                # Don't even bother with an update until there is 50 days or less remaining.
                # We'll make an exception for anything on a wildcard (we want to get our certs to individually named)
                if(($certMeta.ExpiryDate.Subtract((Get-Date)).Days -gt 50) -and ($certMeta.SubjectName -notmatch '\*\.'))
                {
                    $needsUpdating = $false
                }
                else
                {
                    # Use a random distributor to keep all the certs from expiring/renewing on the same day (to try and avoid the "only 50 certs per week" rate limiting.
                    try
                    {
                        $luckyDay = ((Get-Random -Minimum 0 -Maximum ($certMeta.ExpiryDate.Subtract((Get-Date)).Days)) -le $daysLeftWhenRenewing)
                    } catch {
                        $luckyDay = $true
                    }
                    # And make sure it isn't a protected subject that we aren't doing with LE certs
                    $needsUpdating = ($luckyDay) -and ($certMeta.SubjectName -notmatch $RegExDontUpdateTheseCerts)
                }
                #Reuse the subject from the current certificate
                $subject += $certMeta.SubjectName.Replace(' ','').Split(',')
            } catch {
                # If there was an error in any of the stuff above, assume that means the cert is broken and it needs a new cert
                $needsUpdating = $true
            }
            if($needsUpdating)
            {
                try
                {
                    Write-Output "$($aadapApp[$i].DisplayName) [$i] ($($onPrem.ExternalUrl)) will expire in $(($certMeta.ExpiryDate.Subtract((Get-Date)).Days)-1) days -- UPDATING" -ErrorAction SilentlyContinue
                } catch {
                    Write-Output "$($aadapApp[$i].DisplayName) Has no valid certificate -- UPDATING" -ErrorAction SilentlyContinue
                }
                # Ensure the external URL hostname is in the subject list
                $externalHost = ([Uri]$onPrem.ExternalUrl).Host
                if(-not $subject.contains($externalHost))
                {
                    $subject += $externalHost
                }
                # Only submit subjects that are FQDN formatted (no orgs/etc)
                $subject = [string[]]($subject | Where-Object { $_.contains(".") })

                if($DryRun)
                {
                    Write-Output "        [DRY RUN] Would generate and apply certificate for: $($subject -join ', ')"
                }
                else
                {
                    try
                    {
					    Write-Output "        generating new certificate"
                        $AcmeCert = New-AcmeCertificateWithFallback -Subject $subject -FriendlyName "$($aadapApp[$i].DisplayName) LetsEncrypt $((Get-Date).ToString("yyyy-MM-dd"))" -Plugin $AcmePlugin -PluginArgs $AcmePluginArgs -PfxPassword $CertPassword.SecretValue -Sleep $DnsSleep -Timeout $ValidationTimeout -Alias $DnsAlias

					    Write-Output "        setting the certificate to AAD"
                        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPassword.SecretValue)
                        try {
                            $plainPfxPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                        } finally {
                            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        }
                        $params = @{
                          onPremisesPublishing = @{
                            verifiedCustomDomainKeyCredential = @{
                              type  = "X509CertAndPassword"
                              value = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($AcmeCert.PfxFullChain))
                            }
                            verifiedCustomDomainPasswordCredential = @{
                              value = $plainPfxPassword
                            }
                          }
                        }
                        $plainPfxPassword = $null
                        Update-MgBetaApplication -ApplicationId $aadapApp[$i].Id -BodyParameter $params

					    Write-Output "        certificate replaced"
                        if($SaveCertificateToKeyVault)
                        {
                            Save-CertToKeyVault -VaultName $keyVault -SubjectName $subject[0] -PfxPath $AcmeCert.PfxFullChain -PfxPassword $CertPassword.SecretValue
                        }
				    } catch {
                        Write-Output "!!! ERROR !!! Unable to set the certificate for $($onPrem.ExternalUrl)"
                        Write-Output "        $($Error[0].Exception)"
                        break
                    }
                    # Cleanup private keys so they aren't hanging about on unsecured machines
                    Remove-AcmeSensitiveFiles -CertKeyFile $AcmeCert.KeyFile
                }
            }
        } catch {}
    }
    Write-Progress -CurrentOperation Finished -PercentComplete 100 -Activity "Getting App Proxy Configs" -Completed
#endregion

#region Now update the WebApps published through App Service Plans
    if($WorkOnAppServicePlans)
    {
        Write-Output "Getting App Service Plan based AzWebApps"
        $webApps = Get-AzWebApp
        $webAppCerts = Get-AzWebAppCertificate
        foreach($webApp in $webApps)
        {
            foreach($hostname in $webApp.HostNames)
            {
                $cert = $null
                if($hostname.EndsWith("azurewebsites.net")){continue}
                $cert = $webAppCerts | Where-Object { $_.HostNames.Contains($hostname) }
                if($null -ne $cert)
                {
                    try
                    {
                        $luckyDay = (Get-Random -Minimum 0 -Maximum ((Get-Date $cert.ExpirationDate).Subtract((Get-Date)).Days)) -le $daysLeftWhenRenewing
                    } catch {
                        $luckyDay = $true
                    }
                    if($luckyDay)
                    {
                        Write-Output "$($webApp.Name) ($($webapp.Hostnames)) will expire in $(((Get-Date $cert.ExpirationDate).Subtract((Get-Date)).Days)-1) days -- UPDATING"
                        if($DryRun)
                        {
                            Write-Output "        [DRY RUN] Would renew certificate for hostname: $hostname"
                        }
                        else
                        {
                            New-AzWebAppCertificate -ResourceGroupName $webapp.ResourceGroup -WebAppName $webapp.Name -HostName $hostname -SslState SniEnabled -AddBinding
                            Remove-AzWebAppCertificate -ResourceGroupName $webapp.ResourceGroup -ThumbPrint $cert.Thumbprint
                        }
                    }
                }
            }
        }
    }
#endregion

#region Now update any App Gateway listeners
    if($WorkOnApplicationGateways)
    {
        $gateways = @()
        Write-Output "Getting the App Gateway listeners"
        $gateways += Get-AzApplicationGateway
        foreach($gateway in $gateways)
        {
            $certsInUse = @()
            $certsInUse += Get-AzAppGWCert -RG $gateway.ResourceGroupName -AppGWName $gateway.Name

            foreach($cert in $certsInUse)
            {
                if(($cert.NotAfter.Subtract((Get-Date)).Days -gt 50) -and ($cert.Subject -notmatch '\*\.'))
                {
                    $needsUpdating = $false
                }
                else
                {
                    # Use a random distributor to keep all the certs from expiring/renewing on the same day (to try and avoid the "only 50 certs per week" rate limiting.
                    try
                    {
                        $luckyDay = ((Get-Random -Minimum 0 -Maximum ($cert.NotAfter.Subtract((Get-Date)).Days)) -le $daysLeftWhenRenewing)
                    } catch {
                        $luckyDay = $true
                    }
                    # And make sure it isn't a protected subject that we aren't doing with LE certs
                    $needsUpdating = ($luckyDay) -and ($cert.Subject -notmatch $RegExDontUpdateTheseCerts)
                }
                $subject = [string[]]@()
                $subject += [string[]]($cert.Subject.Replace('CN=','').Trim().Split(',').Trim()) | Where-Object { $_.contains(".") }
                if($needsUpdating)
                {
                    Write-Output "Application gateway $($gateway.Name) certificate for $($subject[0]) will expire in $(($cert.NotAfter.Subtract((Get-Date)).Days)-1) days -- UPDATING" -ErrorAction SilentlyContinue

                    if($DryRun)
                    {
                        Write-Output "        [DRY RUN] Would generate and apply certificate for: $($subject -join ', ')"
                    }
                    else
                    {
                        try
                        {
	                        Write-Output "        generating new certificate"
                            $AcmeCert = New-AcmeCertificateWithFallback -Subject $subject -FriendlyName "$($gateway.Name) $($subject[0]) LetsEncrypt $((Get-Date).ToString("yyyy-MM-dd"))" -Plugin $AcmePlugin -PluginArgs $AcmePluginArgs -PfxPassword $CertPassword.SecretValue -Sleep $DnsSleep -Timeout $ValidationTimeout -Alias $DnsAlias

					        Write-Output "        setting the certificate to the App Gateway"
                            Set-AzApplicationGatewaySslCertificate -Name $subject[0] -ApplicationGateway $gateway -CertificateFile $AcmeCert.PfxFullChain -Password $CertPassword.SecretValue | Out-Null
                            Set-AzApplicationGateway -ApplicationGateway $gateway | Out-Null
	                        Write-Output "        certificate config updated"

                            if($SaveCertificateToKeyVault)
                            {
                                Save-CertToKeyVault -VaultName $keyVault -SubjectName $subject[0] -PfxPath $AcmeCert.PfxFullChain -PfxPassword $CertPassword.SecretValue
                            }
                        } catch {
                            Write-Output "!!! ERROR !!! Unable to set the certificate for $($gateway.Name) ($($subject[0]))"
                            Write-Output "        $($Error[0].Exception)"
                            continue
                        }
                        # Cleanup private keys so they aren't hanging about on unsecured machines
                        Remove-AcmeSensitiveFiles -CertKeyFile $AcmeCert.KeyFile
                    }
                }
            }
        }
    }
#endregion

Write-Output "`n`tWork's Done`n"

#region Upload changed posh-acme configuration and certificates
    if(-not $DryRun)
    {
        ## Create ZIP file of configuration
        Compress-Archive -Path $workingDirectory -DestinationPath $env:TEMP\posh-acme.zip -CompressionLevel Fastest -Force
        Set-AzStorageBlobContent -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.zip" -BlobType Block -File $env:TEMP\posh-acme.zip -Force | Out-Null
        Write-Output "`nPoSh-ACME configuration was backed up to the storage container 'posh-acme'`n"
    }
    else
    {
        Write-Output "`n[DRY RUN] Skipping posh-acme configuration upload`n"
    }
#endregion

#region Remove temporary files, folders and WriteLock
    Remove-AzStorageBlob -Context $storageAccount.Context -Container $storageContainer -Blob "posh-acme.settings.lock" -Force
    Remove-Item -Recurse -Force $workingDirectory
    if(Test-Path $env:TEMP\posh-acme.zip) { Remove-Item -Force $env:TEMP\posh-acme.zip }
#endregion

#region Disconnect
	Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
#endregion
