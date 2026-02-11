# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

AzureTools is a collection of Azure infrastructure automation and certificate management tools. It contains two independent modules with no shared build system, test framework, or CI/CD pipeline.

**Repository:** https://github.com/ImperatorRuscal/AzureTools

## Modules

### EntraPrivateAccess

Automates deployment of Microsoft Entra Private Access connectors on Azure VM Scale Sets.

- **epa-Connector-vmss.bicep** — Bicep IaC defining VMSS with rolling upgrades, CPU-based autoscaling (1-10 instances), health monitoring, and custom script extension.
- **epa-connector-vmss.json** — ARM template compiled from the Bicep file (generated via `az bicep build`).
- **epa-bootstrapper.ps1** — PowerShell bootstrap script run on each VM instance. Handles AD domain join, EPA Connector installation, credential retrieval from Key Vault via Managed Identity/IMDS, and scheduled task registration.

### SSL-Updater

Automated SSL/TLS certificate lifecycle management for Azure AD Application Proxy.

- **SSL_Update_AzureADApps.ps1** — PowerShell script integrating with Posh-ACME (Let's Encrypt). Supports 14 DNS providers (Cloudflare, GoDaddy, DNSMadeEasy, etc.), Key Vault credential storage, blob-based distributed locking, and Microsoft Graph Beta APIs for App Proxy certificate deployment. Uses randomized renewal scheduling to avoid Let's Encrypt rate limits. Application Gateway and App Service Plan support are present but WIP (behind feature flags).

## Key Architectural Patterns

- **Managed Identity everywhere** — VMs use User Assigned Managed Identities; no service principal keys stored on infrastructure.
- **Key Vault for all secrets** — Credentials referenced via VMSS tags and retrieved at runtime through IMDS + Managed Identity.
- **Bicep as source of truth** — The ARM JSON template is a build artifact from Bicep, not hand-edited.
- **Bootstrap via Custom Script Extension** — PowerShell runs at VM startup with retry logic and exponential backoff; Application Health extension monitors readiness.

## Working with the Code

There is no build system, package manager, or test framework. The codebase is PowerShell scripts and Azure Bicep/ARM templates.

- To compile Bicep to ARM: `az bicep build --file EntraPrivateAccess/epa-Connector-vmss.bicep`
- To deploy the VMSS: `az deployment group create --resource-group <rg> --template-file EntraPrivateAccess/epa-Connector-vmss.bicep --parameters <params>`
- PowerShell scripts use `$ErrorActionPreference = 'Stop'` and transcript logging for diagnostics.
