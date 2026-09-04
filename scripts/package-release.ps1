[CmdletBinding()]
param(
    [string]$Version = '0.1.0-rc.1'
)

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $packageRoot 'artifacts\release'
$bundleRoot = Join-Path $artifactRoot "zero-review-$Version-windows-x86_64"
$archive = "$bundleRoot.zip"

Push-Location $packageRoot
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw "release build failed" }

    New-Item -ItemType Directory -Force -Path $bundleRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $packageRoot 'target\release\zero-review.exe') -Destination $bundleRoot -Force
    Copy-Item -LiteralPath (Join-Path $packageRoot 'README.md') -Destination $bundleRoot -Force
    Copy-Item -LiteralPath (Join-Path $packageRoot 'schemas\review-input-v1.schema.json') -Destination $bundleRoot -Force

    $binary = Join-Path $bundleRoot 'zero-review.exe'
    $binaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
    $commit = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw "git revision lookup failed" }

    [pscustomobject]@{
        schema_version = 'zero-review.release.v1'
        version = $Version
        commit = $commit.Trim()
        target = 'windows-x86_64'
        binary_sha256 = $binaryHash
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $bundleRoot 'release-manifest.json') -Encoding utf8

    Compress-Archive -Path (Join-Path $bundleRoot '*') -DestinationPath $archive -Force
    $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    [pscustomobject]@{
        archive = $archive
        archive_sha256 = $archiveHash
        binary_sha256 = $binaryHash
        manifest = (Join-Path $bundleRoot 'release-manifest.json')
    } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $artifactRoot 'release-receipt.json') -Encoding utf8

    Get-Content -LiteralPath (Join-Path $artifactRoot 'release-receipt.json') -Raw
}
finally {
    Pop-Location
}
