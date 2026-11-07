$ErrorActionPreference = 'SilentlyContinue'
$relay = $PSScriptRoot
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$backup = Join-Path $relay 'hosts.backup'
$thumbFile = Join-Path $relay 'ca_thumbprint.txt'

if (Test-Path $thumbFile) {
    $thumb = (Get-Content -LiteralPath $thumbFile -Raw).Trim()
    $path = "Cert:\LocalMachine\Root\$thumb"
    if (Test-Path $path) {
        Remove-Item -LiteralPath $path -Force
        Write-Output "removed CA $thumb"
    }
}

if (Test-Path $backup) {
    Copy-Item -LiteralPath $backup -Destination $hosts -Force
    Write-Output "hosts restored"
}

