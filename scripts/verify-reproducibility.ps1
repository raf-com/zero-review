param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$First,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Second
)
$ErrorActionPreference = 'Stop'

function Get-TreeDigest([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $entries = Get-ChildItem -LiteralPath $resolved -File -Recurse |
        Where-Object { $_.Name -notlike '*.part' } |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($resolved, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "${relative}`t${hash}"
        } | Sort-Object
    $payload = [Text.Encoding]::UTF8.GetBytes(($entries -join "`n") + "`n")
    $digest = [Security.Cryptography.SHA256]::HashData($payload)
    [Convert]::ToHexString($digest).ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $First -PathType Container)) { throw "First directory does not exist: $First" }
if (-not (Test-Path -LiteralPath $Second -PathType Container)) { throw "Second directory does not exist: $Second" }
$firstDigest = Get-TreeDigest $First
$secondDigest = Get-TreeDigest $Second
if ($firstDigest -ne $secondDigest) {
    Write-Output "reproducibility: FAIL"
    Write-Output "first=$firstDigest"
    Write-Output "second=$secondDigest"
    exit 1
}
Write-Output "reproducibility: PASS"
Write-Output "tree_sha256=$firstDigest"
