[CmdletBinding()]
param(
    [switch]$SkipApexContract
)

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $packageRoot 'artifacts\ci'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

Push-Location $packageRoot
try {
    cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed" }

    cargo clippy --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }

    cargo test --all-targets --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

    cargo run --locked -- security-scan --input tests\fixtures\security-sensitive.diff --out (Join-Path $artifactRoot 'security-scan.json')
    if ($LASTEXITCODE -ne 0) { throw "security fixture scan failed" }

    if (-not $SkipApexContract) {
        cargo test --manifest-path contract-tests\apex-compat\Cargo.toml --locked
        if ($LASTEXITCODE -ne 0) { throw "Apex compatibility test failed" }
    }

    [pscustomobject]@{
        status = 'verified'
        apex_contract = if ($SkipApexContract) { 'skipped' } else { 'verified' }
        security_scan = (Join-Path $artifactRoot 'security-scan.json')
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifactRoot 'ci-receipt.json') -Encoding utf8
}
finally {
    Pop-Location
}
