[CmdletBinding()]
param(
    [switch]$SkipApexContract
)

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path (Join-Path $packageRoot 'artifacts') 'ci'
$securityFixture = Join-Path (Join-Path $packageRoot 'tests') 'fixtures/security-sensitive.diff'
$apexManifest = Join-Path (Join-Path $packageRoot 'contract-tests') 'apex-compat/Cargo.toml'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

Push-Location $packageRoot
try {
    cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed" }

    cargo clippy --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }

    cargo test --all-targets --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    python -m unittest discover -s tests -p 'github_consumer_test.py' -v
    if ($LASTEXITCODE -ne 0) { throw "GitHub consumer contract tests failed" }

    cargo run --locked -- security-scan --input $securityFixture --out (Join-Path $artifactRoot 'security-scan.json')
    if ($LASTEXITCODE -ne 0) { throw "security fixture scan failed" }

    if (-not $SkipApexContract) {
        cargo test --manifest-path $apexManifest --locked
        if ($LASTEXITCODE -ne 0) { throw "Apex compatibility test failed" }
    }

    [pscustomobject]@{
        status = 'verified'
        apex_contract = if ($SkipApexContract) { 'skipped' } else { 'verified' }
        github_consumer_contract = 'verified'
        security_scan = (Join-Path $artifactRoot 'security-scan.json')
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifactRoot 'ci-receipt.json') -Encoding utf8
}
finally {
    Pop-Location
}
