[CmdletBinding()]
param(
    [string]$Destination = "$env:LOCALAPPDATA\zero-codereview\bin"
)

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
Push-Location $packageRoot
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -LiteralPath (Join-Path $packageRoot 'target\release\zero-codereview.exe') -Destination $Destination -Force
    & (Join-Path $Destination 'zero-codereview.exe') --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "installed binary smoke test failed with exit code $LASTEXITCODE"
    }
    Write-Output (Join-Path $Destination 'zero-codereview.exe')
}
finally {
    Pop-Location
}
