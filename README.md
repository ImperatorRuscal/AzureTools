# AzureTools

A collection of infrastructure-as-code templates and automation scripts for managing Azure and Entra ID resources. Each module is self-contained with its own documentation.

## Modules

### [EntraPrivateAccess](EntraPrivateAccess/)

Bicep template that deploys a fully automated VM Scale Set whose instances join an AD domain, install and register the **Microsoft Entra Private Network Connector (EPNC)**, and report health -- all hands-off after initial deployment. Includes CPU-based autoscaling and automatic instance repair for unhealthy connectors.

- **IaC:** Bicep (Azure Resource Manager)
- **Runtime:** PowerShell bootstrap script on Windows Server
- **Key features:** Domain join, EPNC registration, HTTP health probes, rolling upgrades, RBAC automation

### [SSL-Updater](SSL-Updater/)

Azure Automation runbook that automates **Let's Encrypt certificate renewal** for Azure AD App Proxy applications, Application Gateway listeners, and App Service Plan web apps using [Posh-ACME](https://github.com/rmbolger/Posh-ACME). Supports 14 DNS providers for ACME validation and persists state to Azure Blob Storage.

- **Runtime:** PowerShell (Azure Automation Runbook)
- **Auth:** System-assigned Managed Identity
- **Key features:** Automatic renewal with rate-limit-aware scheduling, `-DryRun` mode, Key Vault certificate storage, blob-based concurrency lock

## Getting Started

Each module has its own `README.md` with detailed prerequisites, parameter references, and deployment instructions. Click through to the module you need.

## Security

- No secrets are stored in code, tags, or visible extension settings.
- All credentials are retrieved at runtime from Azure Key Vault via Managed Identity.
- Private key material is cleaned up after use.
- See each module's README for its specific security design.

