$hosts = 'C:\Windows\System32\drivers\etc\hosts'
$report = Join-Path $PSScriptRoot 'hosts_report.txt'
$lines = @(
    '127.0.0.1 vntool.vn',
    '127.0.0.1 bypass.vntools.net',
    '127.0.0.1 mtk.unlocktool.net',
    '127.0.0.1 ut-data.vntool.net'
)
$out = @()
foreach ($l in $lines) {
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $existing = @(Get-Content -LiteralPath $hosts -ErrorAction Stop)
            if ($existing -contains $l) { $ok = $true; break }
            Add-Content -LiteralPath $hosts -Value $l -ErrorAction Stop
            $ok = $true
            break
        } catch {
            Start-Sleep -Milliseconds 400
        }
    }
    $out += ("{0} => {1}" -f $l, $ok)
}
$out += '--- final ---'
$out += @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue)
$out | Out-File -FilePath $report -Encoding utf8

