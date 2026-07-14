@echo off
REM ============================================================================
REM  vpn-leakcheck.bat  --  double-click to run a VPN / leak sweep.
REM  Self-contained: the batch header below launches the PowerShell that is
REM  embedded after the "#PSCODE#" marker at the bottom (which you can read and
REM  edit freely). Run as Administrator for full UDP process ownership.
REM ============================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=[IO.File]::ReadAllText('%~f0'); Invoke-Expression $c.Substring($c.LastIndexOf('#PSCODE#')+8)"
echo.
pause
exit /b

#PSCODE#
$ErrorActionPreference = 'SilentlyContinue'
$flags = @()

Write-Host ''
Write-Host '==================== VPN / LEAK CHECK ====================' -ForegroundColor Cyan

# 1) Is our tunnel running? (changes how a foreign exit IP should be read)
$tunnel = Get-Process tunnel -ErrorAction SilentlyContinue
if ($tunnel) {
    Write-Host ("[i] tunnel.exe RUNNING (PID {0}) - a non-home exit IP below is EXPECTED (you are tunneled)." -f ($tunnel.Id -join ',')) -ForegroundColor Yellow
    $tunnelUp = $true
} else {
    Write-Host '[i] tunnel.exe NOT running - external IP should be your HOME ISP.' -ForegroundColor Gray
    $tunnelUp = $false
}

# 2) External IP + country (what the internet actually sees)
$ip = try { Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8 } catch { $null }
if ($ip) {
    $geo = try { Invoke-RestMethod -Uri ("http://ip-api.com/json/{0}?fields=country,regionName,isp" -f $ip) -TimeoutSec 8 } catch { $null }
    $loc = if ($geo -and $geo.country) { "$($geo.country) / $($geo.regionName) - $($geo.isp)" } else { '(location lookup failed)' }
    Write-Host ("[i] External IP: {0}   [{1}]" -f $ip, $loc)
} else {
    Write-Host '[!] Could not reach the internet to determine external IP (network locked down, or offline).' -ForegroundColor Yellow
}

# 3) Third-party VPN virtual adapters that are UP (the strongest zombie tell),
#    excluding our own TUN (named "Tunnel"). WAN Miniport is only alarming when Up.
$vpnAdapters = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.Name -ne 'Tunnel' -and
    ($_.InterfaceDescription -match 'WireGuard|Proton|OpenVPN|TAP-Windows|TAP-ProtonVPN|WAN Miniport' -or
     $_.Name -match 'wg|proton|wireguard')
}
if ($vpnAdapters) {
    Write-Host '[!] VPN virtual adapter(s) UP - possible zombie tunnel:' -ForegroundColor Red
    ($vpnAdapters | Select-Object Name, InterfaceDescription, Status | Format-Table -Auto | Out-String).Trim() | Write-Host
    $flags += 'vpn-adapter'
} else {
    Write-Host '[ok] No third-party VPN adapters up.' -ForegroundColor Green
}

# 4) UDP endpoints on a REAL (non-loopback) address owned by a non-system process.
#    A WireGuard/OpenVPN zombie hides HERE - UDP has no ESTABLISHED state, so it
#    will not appear in a normal TCP connection list.
$susUdp = Get-NetUDPEndpoint |
    Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1','0.0.0.0','::') } |
    Select-Object LocalAddress, LocalPort, OwningProcess,
        @{n='Process';e={ (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName }} |
    Where-Object { $_.Process -and $_.Process -notmatch '^(tunnel|svchost|System|Idle)$' }
if ($susUdp) {
    Write-Host '[?] Non-loopback UDP endpoints from non-system processes (inspect - VPN clients live here):' -ForegroundColor Yellow
    ($susUdp | Format-Table -Auto | Out-String).Trim() | Write-Host
    $flags += 'udp'
} else {
    Write-Host '[ok] No suspicious UDP endpoints.' -ForegroundColor Green
}

# 5) External TCP connections (informational - normal CDN/cloud traffic lives here)
$extTcp = Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1|fe80)' } |
    Select-Object RemoteAddress, RemotePort, OwningProcess,
        @{n='Process';e={ (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName }} |
    Sort-Object RemoteAddress
Write-Host '[i] External TCP connections (informational):'
if ($extTcp) { ($extTcp | Format-Table -Auto | Out-String).Trim() | Write-Host } else { Write-Host '    (none)' }

# ---- Verdict -------------------------------------------------------------
Write-Host '==================== VERDICT ====================' -ForegroundColor Cyan
if ($flags -contains 'vpn-adapter') {
    Write-Host 'RESULT: POSSIBLE ZOMBIE VPN - a third-party VPN adapter is UP. Investigate the adapter(s) above.' -ForegroundColor Red
} elseif (-not $tunnelUp -and $flags.Count -gt 0) {
    Write-Host 'RESULT: SUSPICIOUS - tunnel is NOT running yet non-system network endpoints were found. Inspect them.' -ForegroundColor Yellow
} elseif (-not $tunnelUp) {
    Write-Host 'RESULT: No VPN software detected. Confirm the External IP above is your HOME location - if it is a foreign country, investigate.' -ForegroundColor Green
} else {
    Write-Host 'RESULT: Tunnel is running; a foreign exit IP is normal. No third-party VPN adapters - clean.' -ForegroundColor Green
}
Write-Host ''
