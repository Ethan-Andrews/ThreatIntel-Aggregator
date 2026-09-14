#Requires -Version 7
<#
.SYNOPSIS
    Azure + API tier: full SIEM-integrated deployment, storage in Azure Container Apps.
.DESCRIPTION
    Thin wrapper around infra/provision.ps1, which is the real, tested deployment
    runbook -- this script just does pre-flight checks and reminds you of the one
    piece provision.ps1 does NOT set up: the Postgres server itself.

    What this tier gets you beyond Basic/Basic+API: Microsoft Entra ID SSO,
    Azure AI Foundry-backed triage, and (optionally) the detections.ai pipeline
    orchestrator as a scheduled Container Apps Job for SIEM integration.

    What it does NOT do: provision Postgres. Container Apps has no managed
    Postgres offering -- point PG_DSN at any reachable server (Azure Database
    for PostgreSQL, a VM, etc.) and store it in the Key Vault as the "pg-dsn"
    secret before running this.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = './infra/migration.psd1',
    [string]$SubscriptionId = '',
    [switch]$GenerateMissingSecrets,
    [switch]$SkipImageImport
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

Write-Host '==> Checking prerequisites' -ForegroundColor Cyan
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error 'Azure CLI (az) is required. Install it: https://learn.microsoft.com/cli/azure/install-azure-cli'
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "PowerShell 7+ is required (found $($PSVersionTable.PSVersion)). Install: https://aka.ms/powershell"
    exit 1
}

Write-Host ''
Write-Host '==> Before continuing:' -ForegroundColor Yellow
Write-Host '    This tier does not provision Postgres. You need a reachable Postgres'
Write-Host '    server (Azure Database for PostgreSQL, or your own) with its connection'
Write-Host '    string already stored in the target Key Vault as the "pg-dsn" secret.'
Write-Host '    infra/provision.ps1 will prompt for any other missing secrets.'
Write-Host ''

$resolvedManifestPath = Join-Path $repoRoot ($ManifestPath -replace '^\.[/\\]', '')

if (-not (Test-Path $resolvedManifestPath)) {
    Write-Host "No manifest found at $resolvedManifestPath -- infra/provision.ps1 will create one from the example and stop so you can fill it in. Re-run this script after editing it." -ForegroundColor Yellow
}

$provisionArgs = @{
    ManifestPath = $resolvedManifestPath
}
if ($SubscriptionId) { $provisionArgs.SubscriptionId = $SubscriptionId }
if ($GenerateMissingSecrets) { $provisionArgs.GenerateMissingSecrets = $true }
if ($SkipImageImport) { $provisionArgs.SkipImageImport = $true }

Push-Location (Join-Path $repoRoot 'infra')
try {
    & ./provision.ps1 @provisionArgs
} finally {
    Pop-Location
}
