# Shared helpers for aca-migration-kit scripts. Dot-source:  . "$PSScriptRoot/lib.ps1"

function Invoke-Az {
    # az wrapper that fails loudly. Do NOT merge stderr (2>&1) - az writes
    # warnings to stderr and merging corrupts JSON parsed by ConvertFrom-Json.
    $out = az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (see error output above)" }
    return $out
}

function Confirm-WhatIf {
    param([string]$Stage)
    $answer = Read-Host "`nReview the $Stage what-if output above. Apply? (y/N)"
    if ($answer -ne 'y') { throw "Aborted by user at $Stage stage." }
}

function Set-KvSecretWithRetry {
    param([string]$VaultName, [string]$Name, [string]$Value)
    # Role assignments created moments ago can lag Key Vault data-plane
    # propagation by a minute or more - retry with backoff.
    for ($i = 1; $i -le 6; $i++) {
        az keyvault secret set --vault-name $VaultName --name $Name --value $Value --output none 2>$null
        if ($LASTEXITCODE -eq 0) { return }
        Write-Host "    Key Vault write not permitted yet (RBAC propagation); retrying in 20s ($i/6)..."
        Start-Sleep -Seconds 20
    }
    throw "Could not write secret '$Name' to vault '$VaultName' after retries."
}

function Read-WithDefault {
    param([string]$Prompt, [string]$Default)
    $v = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($v)) { $Default } else { $v.Trim() }
}

function New-RandomSecret {
    $bytes = [byte[]]::new(48)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [Convert]::ToBase64String($bytes)
}

function ConvertTo-Psd1 {
    # Serializes nested hashtables/arrays/scalars to .psd1 text.
    param($Value, [int]$Indent = 0)
    $pad = '    ' * $Indent
    if ($Value -is [System.Collections.IDictionary]) {
        $lines = @('@{')
        foreach ($k in $Value.Keys) {
            $lines += "$pad    $k = $(ConvertTo-Psd1 -Value $Value[$k] -Indent ($Indent + 1))"
        }
        $lines += "$pad}"
        return ($lines -join "`n")
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        if (@($Value).Count -eq 0) { return '@()' }
        $items = @($Value) | ForEach-Object { "$pad    $(ConvertTo-Psd1 -Value $_ -Indent ($Indent + 1))" }
        return "@(`n$($items -join "`n")`n$pad)"
    }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return "$Value" }
    return "'$("$Value".Replace("'", "''"))'"
}
