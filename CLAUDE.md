# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

AzureTools is a collection of Azure infrastructure automation and certificate management tools. It contains two independent modules with no shared build system, test framework, or CI/CD pipeline.

**Repository:** https://github.com/ImperatorRuscal/AzureTools

## Modules

### EntraPrivateAccess

Automates deployment of Microsoft Entra Private Network Connectors on Azure VM Scale Sets (Flexible orchestration). The VMSS instances auto-join an AD domain, install and register the EPNC connector, and report health — all hands-off after initial deployment.

- **epa-Connector-vmss.bicep** — Bicep template defining the VMSS with three ordered extensions: `JsonADDomainExtension` (domain join), `CustomScriptExtension` (connector install/register), `ApplicationHealthWindows` (HTTP health probe on port 8443 checking the WAPCSvc service). Includes CPU + memory autoscaling with a daily maintenance window (fixed capacity 04:00–04:30), automatic instance repair, and rolling upgrade policy. Supports two script source modes: public GitHub URL (community) or Azure Storage + managed identity (production).
- **epa-connector-vmss.sample.bicepparam** — Sample parameters file showing Key Vault secret references for `adminPassword` and `domainJoinPassword` via `az.getSecret()`.
- **epa-bootstrapper.ps1** — PowerShell script run by the CustomScriptExtension after domain join. Installs the EPNC connector, registers it with Entra via credentials from Key Vault, and starts a persistent HTTP health listener. All config comes via command-line parameters (no IMDS tag reading).

Key design decisions:
- Domain join handled by Azure's `JsonADDomainExtension`, not PowerShell (eliminates reboot-and-resume fragility).
- No secrets in VMSS tags or visible extension settings. `commandToExecute` is in `protectedSettings`.
- Automatic instance repair replaces unhealthy VMs (WAPCSvc not running for 30 min).
- Connector group assignment is a TODO (requires Graph Beta API + UAMI permissions).

### SSL-Updater

Automated SSL/TLS certificate lifecycle management for Azure AD Application Proxy, Application Gateways, and App Service Plans. Designed to run as a scheduled Azure Automation Runbook with a system-assigned Managed Identity.

- **SSL_Update_AzureADApps.ps1** — PowerShell runbook integrating with Posh-ACME (Let's Encrypt). Supports 14 DNS providers (Cloudflare, GoDaddy, DNSMadeEasy, etc.), Key Vault credential storage, blob-based distributed locking, and Microsoft Graph Beta APIs for App Proxy certificate deployment. Uses randomized renewal scheduling to avoid Let's Encrypt rate limits. Application Gateway (`-WorkOnApplicationGateways`) and App Service Plan (`-WorkOnAppServicePlans`) support via `[switch]` parameters. Includes `-DryRun` for read-only enumeration.

Key design decisions:
- All secrets come from Key Vault at runtime via parameter names (never hardcoded).
- `Get-AzAppGWCert` is embedded as an inline helper (parses X509 certs from App Gateway listener and backend settings).
- Helper functions `New-AcmeCertificateWithFallback`, `Remove-AcmeSensitiveFiles`, and `Save-CertToKeyVault` eliminate duplication across the App Proxy and App Gateway code paths.
- BSTR from `SecureStringToBSTR` is properly freed with `ZeroFreeBSTR` in try/finally.
- Posh-ACME state is persisted as a ZIP blob in Azure Storage with a blob-based lock file for concurrency control across runbooks.

## Key Architectural Patterns

- **Managed Identity everywhere** — VMs use User Assigned Managed Identities for Key Vault access and (optionally) storage account script download. No service principal keys on infrastructure.
- **Key Vault for all secrets** — Admin password and domain join password supplied via Key Vault references at deploy time. Registration credentials fetched at runtime via Managed Identity.
- **Bicep as source of truth** — No ARM JSON template is checked in. Generate one with `az bicep build` if needed.
- **Extension-driven provisioning** — Domain join, bootstrapping, and health monitoring are handled by Azure VM extensions with explicit ordering (`provisionAfterExtensions`), not multi-phase scripts.

## Working with the Code

There is no build system, package manager, or test framework. The codebase is PowerShell scripts and Azure Bicep templates.

- To validate Bicep: `az bicep build --file EntraPrivateAccess/epa-Connector-vmss.bicep`
- To deploy the VMSS: `az deployment group create --resource-group <rg> --template-file EntraPrivateAccess/epa-Connector-vmss.bicep --parameters EntraPrivateAccess/epa-connector-vmss.sample.bicepparam`
- PowerShell scripts use `$ErrorActionPreference = 'Stop'` and transcript logging to `C:\Scripts\`.
