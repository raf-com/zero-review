param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$release = Get-Content (Join-Path $Root '.github\workflows\release.yml') -Raw
$lock = Join-Path $Root 'Cargo.lock'
if (-not (Test-Path $lock)) { throw 'Cargo.lock is missing' }
$unpinned = [regex]::Matches($release, '(?m)^\s*- uses: ([^@\s]+)@([^\s#]+)') | Where-Object { $_.Groups[2].Value -notmatch '^[0-9a-f]{40}$' }
if ($unpinned.Count) { throw ('Unpinned GitHub actions: ' + (($unpinned | ForEach-Object { $_.Groups[1].Value }) -join ', ')) }
foreach ($subject in @('zero-review-windows-x86_64.exe','zero-review-linux-x86_64','zero-review.cdx.json')) {
  if ($release -notmatch [regex]::Escape($subject)) { throw "Release workflow does not name subject: $subject" }
}
Write-Output 'supply-chain-static-check: PASS'
