#
# scan.ps1 - Selectel whitelist checker for Russia mobile TSPU
# Works on Windows PowerShell 5.1 and PowerShell 7+
#
# Usage (PowerShell):
#   iex (iwr "https://raw.githubusercontent.com/smediainfo/ru-whitelist-tools/main/scan.ps1" -UseBasicParsing).Content
#
# Or download and run:
#   iwr "https://raw.githubusercontent.com/smediainfo/ru-whitelist-tools/main/scan.ps1" -OutFile scan.ps1
#   powershell -ExecutionPolicy Bypass -File scan.ps1
#

$ErrorActionPreference = 'SilentlyContinue'

# Config
$sni      = 'max.ru'
$parallel = 30
$timeout  = 4000   # ms
$subnets  = @('80.93.187','84.38.185')

Write-Host ('=' * 50)
Write-Host "scan.ps1 - Selectel whitelist checker"
Write-Host "SNI:      $sni"
Write-Host "Subnets:  $($subnets -join ', ')"
Write-Host "Parallel: $parallel"
Write-Host ('=' * 50)

# Build IP list
$ips = New-Object System.Collections.ArrayList
foreach ($prefix in $subnets) {
    for ($i = 1; $i -le 254; $i++) {
        [void]$ips.Add("$prefix.$i")
    }
}
Write-Host "Total IPs to check: $($ips.Count)"
Write-Host ""

# Show outgoing IP
try {
    $myip = (Invoke-WebRequest 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 5).Content
    Write-Host "Your outgoing IP: $myip"
    Write-Host ""
} catch {
    Write-Host "Your outgoing IP: UNKNOWN (api.ipify.org not reachable)"
    Write-Host ""
}

# The worker script block
$workerScript = {
    param($ip, $sni, $timeout)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($ip, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($timeout)) {
            $tcp.Close()
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
        return "OK $ip $subject"
    } catch {
        return $null
    }
}

# Parallel execution via RunspacePool (PS 5.1 compatible)
$pool = [RunspaceFactory]::CreateRunspacePool(1, $parallel)
$pool.Open()

$jobs = @()
foreach ($ip in $ips) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($workerScript).AddArgument($ip).AddArgument($sni).AddArgument($timeout)
    $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip }
}

$ok_count    = 0
$interesting = New-Object System.Collections.ArrayList
$done        = 0
$total       = $jobs.Count

foreach ($job in $jobs) {
    $result = $job.PS.EndInvoke($job.Handle)
    $job.PS.Dispose()
    $done++
    if ($result) {
        Write-Host $result
        $ok_count++
        if ($result -match 'rutube|yandex|vk|mail|gosuslugi|selsup|sberbank|cloud') {
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
Write-Host ('=' * 50)
Write-Host "Total OK: $ok_count / $total"
Write-Host ('=' * 50)

if ($interesting.Count -gt 0) {
    Write-Host ""
    Write-Host "Interesting (known whitelist domains):"
    foreach ($line in $interesting) {
        Write-Host "  $line" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done."
