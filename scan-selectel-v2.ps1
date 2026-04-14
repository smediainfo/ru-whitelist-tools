#
# scan-selectel.ps1 - Selectel (AS49505) whitelist checker
# Checks 4 new Selectel /24 subnets for TSPU whitelist presence.
#
# Usage (PowerShell):
#   iex (iwr "https://raw.githubusercontent.com/smediainfo/ru-whitelist-tools/main/scan-selectel.ps1" -UseBasicParsing).Content
#
# Or download and run:
#   iwr "https://raw.githubusercontent.com/smediainfo/ru-whitelist-tools/main/scan-selectel.ps1" -OutFile scan-selectel.ps1
#   powershell -ExecutionPolicy Bypass -File scan-selectel.ps1
#

$ErrorActionPreference = 'SilentlyContinue'

# Config — multiple SNIs tried in order (first that wins is reported)
# Different RU mobile operators whitelist different SNIs, so we cycle through.
$snis     = @('max.ru', 'vk.com', 'gosuslugi.ru', 'yandex.ru')
$parallel = 30
$timeout  = 4000   # ms

# 4 Selectel /24 subnets (AS49505) — candidates for new White exits
$subnets  = @(
    '5.178.87',
    '92.53.90',
    '95.213.143',
    '212.92.101'
)

Write-Host ('=' * 60)
Write-Host "scan-selectel-v2.ps1 - Selectel whitelist checker (AS49505)"
Write-Host "SNIs:     $($snis -join ', ') (fallback chain)"
Write-Host "Subnets:  $($subnets -join ', ')"
Write-Host "Parallel: $parallel  |  Timeout: $timeout ms"
Write-Host ('=' * 60)

# Build IP list
$ips = New-Object System.Collections.ArrayList
foreach ($prefix in $subnets) {
    for ($i = 1; $i -le 254; $i++) {
        [void]$ips.Add("$prefix.$i")
    }
}
Write-Host "Total IPs to check: $($ips.Count)"
Write-Host ""

# Show outgoing IP via yandex.ru (in TSPU whitelist on all RU mobile operators)
try {
    $resp = (Invoke-WebRequest 'https://yandex.ru/internet/api/v0/ip' -UseBasicParsing -TimeoutSec 5).Content
    # Endpoint returns a plain JSON string like: "38.180.69.116"
    $myip = $resp -replace '"', ''
    Write-Host "Your outgoing IP: $myip (via yandex.ru)"
    Write-Host ""
} catch {
    Write-Host "Your outgoing IP: UNKNOWN (yandex.ru not reachable — operator might block ALL TLS)"
    Write-Host ""
}

# The worker script block — tries each SNI in order, returns first success
$workerScript = {
    param($ip, $snis, $timeout)
    foreach ($sni in $snis) {
        $tcp = $null
        $ssl = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar  = $tcp.BeginConnect($ip, 443, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($timeout)) {
                $tcp.Close()
                # TCP didn't connect — no point trying other SNIs to same IP:443
                return $null
            }
            $tcp.EndConnect($ar)
            $stream = $tcp.GetStream()
            $ssl = New-Object System.Net.Security.SslStream($stream, $false, {param($s,$c,$ch,$e) $true})
            $ssl.ReadTimeout  = $timeout
            $ssl.WriteTimeout = $timeout
            $ssl.AuthenticateAsClient($sni)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $subject = $cert.Subject
            $ssl.Close()
            $tcp.Close()
            return "OK[$sni] $ip $subject"
        } catch {
            if ($ssl) { try { $ssl.Close() } catch {} }
            if ($tcp) { try { $tcp.Close() } catch {} }
            # TLS failed for this SNI — try next one
            continue
        }
    }
    return $null
}

# Parallel execution via RunspacePool (PS 5.1 compatible)
$pool = [RunspaceFactory]::CreateRunspacePool(1, $parallel)
$pool.Open()

$jobs = @()
foreach ($ip in $ips) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($workerScript).AddArgument($ip).AddArgument($snis).AddArgument($timeout)
    $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip }
}

$ok_count    = 0
$interesting = New-Object System.Collections.ArrayList
$sni_stats   = @{}
foreach ($s in $snis) { $sni_stats[$s] = 0 }
$done        = 0
$total       = $jobs.Count

foreach ($job in $jobs) {
    $result = $job.PS.EndInvoke($job.Handle)
    $job.PS.Dispose()
    $done++
    if ($result) {
        Write-Host $result
        $ok_count++
        if ($result -match '^OK\[([^\]]+)\]') {
            $sni_stats[$matches[1]]++
        }
        if ($result -match 'rutube|yandex|vk|mail|gosuslugi|selsup|sberbank|cloud|selectel') {
            [void]$interesting.Add($result)
        }
    }
    if ($done % 50 -eq 0) {
        Write-Host "  ... $done/$total processed (OK=$ok_count)" -ForegroundColor DarkGray
    }
}

$pool.Close()
$pool.Dispose()

Write-Host ""
Write-Host ('=' * 60)
Write-Host "Total OK: $ok_count / $total"
Write-Host "By SNI:"
foreach ($s in $snis) {
    Write-Host ("  {0,-15} {1}" -f $s, $sni_stats[$s])
}
Write-Host ('=' * 60)

if ($interesting.Count -gt 0) {
    Write-Host ""
    Write-Host "Interesting (known whitelist domains):" -ForegroundColor Yellow
    foreach ($line in $interesting) {
        Write-Host "  $line" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done."
