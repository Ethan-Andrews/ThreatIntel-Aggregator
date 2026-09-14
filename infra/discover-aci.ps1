#Requires -Version 7
<#
.SYNOPSIS
    Drafts a migration.psd1 manifest from an existing Azure Container Instances group.
.EXAMPLE
    ./discover-aci.ps1 -Name my-aci-group -ResourceGroup rg-old -OutFile ./migration.psd1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$OutFile = './migration.psd1'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/lib.ps1"

$group = Invoke-Az container show --resource-group $ResourceGroup --name $Name -o json | ConvertFrom-Json

$hasPublicIp = $null -ne $group.ipAddress -and $group.ipAddress.type -eq 'Public'
if ($group.containers.Count -gt 1) {
    Write-Warning "Container group has $($group.containers.Count) containers - each becomes its own container app. Review inter-app networking (sidecars may need redesign)."
}
if ($group.subnetIds) {
    Write-Warning 'ACI group is VNet-integrated; the kit does not use a custom VNet (spec decision). Review network requirements manually.'
}

$apps = @()
foreach ($c in $group.containers) {
    $env = @{}
    $secretEnv = @{}
    foreach ($e in @($c.environmentVariables)) {
        if ($null -ne $e.secureValue -or ($null -eq $e.value)) {
            # Secure values are not readable via the API - the secret must be re-provided.
            $secretEnv[$e.name] = ($e.name.ToLower() -replace '[^a-z0-9-]', '-')
            Write-Warning "Env var '$($e.name)' is secure; its value cannot be read. provision.ps1 will prompt for Key Vault secret '$($secretEnv[$e.name])'."
        } else {
            $env[$e.name] = $e.value
        }
    }

    $port = if (@($c.ports).Count -gt 0) { [int]@($c.ports)[0].port } else { 80 }
    $volumeShare = ''
    $mountPath = ''
    if (@($c.volumeMounts).Count -gt 0) {
        $vm = @($c.volumeMounts)[0]
        $vol = @($group.volumes) | Where-Object { $_.name -eq $vm.name } | Select-Object -First 1
        if ($vol -and $vol.azureFile) {
            $volumeShare = $vol.azureFile.shareName
            $mountPath = $vm.mountPath
        } else {
            Write-Warning "Volume '$($vm.name)' on container '$($c.name)' is not an Azure Files volume - map manually."
        }
    }

    $apps += @{
        Name        = "ca-$($c.name)"
        Image       = "$($c.name):latest"
        Source      = $c.image
        SourceAuth  = ($null -ne $group.imageRegistryCredentials -and @($group.imageRegistryCredentials).Count -gt 0)
        External    = $hasPublicIp
        TargetPort  = $port
        EasyAuth    = $false   # opt in per app after review
        SecretEnv   = $secretEnv
        VolumeShare = $volumeShare
        MountPath   = $mountPath
        # For apps.bicep: requested cpu=$($c.resources.requests.cpu) memoryGb=$($c.resources.requests.memoryInGB)
    }
}

$manifest = @{
    AppPrefix     = ($Name.ToLower() -replace '[^a-z0-9]', '')
    ResourceGroup = 'my-resource-group'
    Location      = $group.location
    Platform      = @{
        ResourceGroup = 'my-resource-group'
        Prefix        = 'myplat'
        LogAnalytics  = @{ UseExisting = $true; Name = ''; ResourceGroup = '' }
    }
    Apps                = $apps
    AppRegistrationName = ''
}

Set-Content -Path $OutFile -Value (ConvertTo-Psd1 -Value $manifest)
Write-Host "`nDraft manifest written to $OutFile" -ForegroundColor Green
Write-Host 'Review it: set External/EasyAuth per app, confirm ports, then edit apps.bicep to match (CPU/memory noted in comments above each container).'
Write-Host "Original ACI CPU/memory per container:"
foreach ($c in $group.containers) {
    Write-Host "  $($c.name): cpu=$($c.resources.requests.cpu) memoryGb=$($c.resources.requests.memoryInGB) (pick the nearest valid ACA pair, e.g. 0.5/1Gi, 1.0/2Gi, 2.0/4Gi)"
}
