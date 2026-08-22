[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $packageRoot 'artifacts\supply-chain'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

Push-Location $packageRoot
try {
    cargo deny check
    if ($LASTEXITCODE -ne 0) { throw "cargo deny failed" }

    cargo audit --deny warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo audit failed" }

    cargo metadata --locked --format-version 1 |
        Set-Content -LiteralPath (Join-Path $artifactRoot 'cargo-metadata.json') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed" }

    Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $packageRoot 'Cargo.lock') |
        Select-Object Algorithm, Hash, Path |
        ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $artifactRoot 'cargo-lock-sha256.json') -Encoding utf8

    [pscustomobject]@{
        status = 'verified'
        deny = 'verified'
        audit = 'verified'
        dependency_inventory = (Join-Path $artifactRoot 'cargo-metadata.json')
        cargo_lock_digest = (Join-Path $artifactRoot 'cargo-lock-sha256.json')
    } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $artifactRoot 'supply-chain-receipt.json') -Encoding utf8
}
finally {
    Pop-Location
}
