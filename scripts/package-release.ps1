param(
    [Parameter(Mandatory)][ValidateSet('windows-x86_64')][string]$Target,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
$dist = Join-Path $PWD 'dist'
$root = Join-Path $dist "zero-review-$Target"
$plannedOutputs = @(
    $root,
    (Join-Path $dist "zero-review-$Target.exe"),
    (Join-Path $dist "zero-review-$Target.zip"),
    (Join-Path $dist "zero-review-$Target.manifest.json")
)
if ($plannedOutputs | Where-Object { Test-Path -LiteralPath $_ }) {
    throw 'release output already exists; refusing to replace immutable package artifacts'
}
cargo build --release --locked
if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }
New-Item -ItemType Directory -Force $root | Out-Null
Copy-Item 'target\release\zero-review.exe' $root
Copy-Item 'target\release\zero-review.exe' (Join-Path $dist "zero-review-$Target.exe")
Copy-Item README.md $root
Copy-Item -Recurse schemas $root
cargo metadata --locked --format-version 1 | Out-File -LiteralPath (Join-Path $root 'dependency-inventory.json') -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit $LASTEXITCODE" }
$binaryHash = (Get-FileHash -Algorithm SHA256 (Join-Path $root 'zero-review.exe')).Hash.ToLowerInvariant()
$manifest = [ordered]@{ schema_version='zero-review.release.v1'; version=$Version; commit=$Commit; target=$Target; binary_sha256=$binaryHash }
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $root 'release-manifest.json'), ($manifest | ConvertTo-Json), $utf8)
Copy-Item (Join-Path $root 'release-manifest.json') (Join-Path $dist "zero-review-$Target.manifest.json")
Compress-Archive -Path "$root\*" -DestinationPath (Join-Path $dist "zero-review-$Target.zip")
foreach ($file in @("zero-review-$Target.exe", "zero-review-$Target.zip", "zero-review-$Target.manifest.json")) {
    $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $dist $file)).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $dist "$file.sha256"), "$hash  $file`n", $utf8)
}
