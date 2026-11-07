$ErrorActionPreference = 'Stop'
$relay = $PSScriptRoot
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$backup = Join-Path $relay 'hosts.backup'
$der = Join-Path $relay 'ca_cert.der'

# 1) backup hosts once (create it if missing)
if (Test-Path -LiteralPath $hosts) {
    if (-not (Test-Path $backup)) {
        Copy-Item -LiteralPath $hosts -Destination $backup -Force
    }
} else {
    New-Item -ItemType File -Path $hosts -Force | Out-Null
    Set-Content -LiteralPath $backup -Value '' -NoNewline
}

# 2) add entries if missing
$content = Get-Content -LiteralPath $hosts -Raw
$entries = @(
    "127.0.0.1 vntool.vn",
    "127.0.0.1 bypass.vntools.net",
    "127.0.0.1 mtk.unlocktool.net",
    "127.0.0.1 ut-data.vntool.net"
)
foreach ($e in $entries) {
    if ($content -notmatch [regex]::Escape($e)) {
        Add-Content -LiteralPath $hosts -Value $e
    }
}

# 3) install CA into machine root
$cert = Import-Certificate -FilePath $der -CertStoreLocation 'Cert:\LocalMachine\Root'
$cert.Thumbprint | Set-Content -LiteralPath (Join-Path $relay 'ca_thumbprint.txt')

Write-Output "CA thumbprint: $($cert.Thumbprint)"
Write-Output "hosts updated"

