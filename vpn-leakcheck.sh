#!/usr/bin/env bash
# ============================================================================
#  vpn-leakcheck.sh  --  quick VPN / leak sweep (Linux equivalent of the .bat).
#  Run with sudo for full process ownership on others' sockets:
#      sudo ./vpn-leakcheck.sh
# ============================================================================
set -u

flags=()
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'; c_off=$'\033[0m'

echo
echo "${c_cyn}==================== VPN / LEAK CHECK ====================${c_off}"

# 1) Is our tunnel running?
if pgrep -x tunnel >/dev/null 2>&1; then
    echo "${c_yel}[i] tunnel RUNNING (PID $(pgrep -x tunnel | tr '\n' ' ')) - a non-home exit IP below is EXPECTED.${c_off}"
    tunnel_up=1
else
    echo "[i] tunnel NOT running - external IP should be your HOME ISP."
    tunnel_up=0
fi

# 2) External IP + country (what the internet sees)
ip=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null || true)
if [ -n "$ip" ]; then
    geo=$(curl -s --max-time 8 "http://ip-api.com/json/${ip}?fields=country,regionName,isp" 2>/dev/null || true)
    echo "[i] External IP: ${ip}   [${geo}]"
else
    echo "${c_yel}[!] Could not determine external IP (network locked down, or offline).${c_off}"
fi

# 3) VPN-looking interfaces (wg*/proton*/tap* are VPN-specific; plain tun* is NOT
#    checked because our own tunnel is a tun device and would false-positive).
vpnif=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -Ei '^(wg|proton|tap|ppp)' || true)
if [ -n "$vpnif" ]; then
    echo "${c_red}[!] VPN-looking interface(s) present - possible zombie tunnel:${c_off}"
    echo "$vpnif" | sed 's/^/    /'
    flags+=("vpn-if")
else
    echo "${c_grn}[ok] No third-party VPN interfaces (wg/proton/tap/ppp).${c_off}"
fi

# 4) Non-loopback UDP sockets owned by a non-tunnel process (WireGuard/OpenVPN
#    zombies hide here). Needs sudo to attribute other processes' sockets.
susudp=$(ss -unp 2>/dev/null | awk 'NR>1 && $5 !~ /127\.0\.0\.1|\[::1\]|^\*/' | grep -viE 'users:\(\("tunnel"' | grep -iE 'users:' || true)
if [ -n "$susudp" ]; then
    echo "${c_yel}[?] Non-loopback UDP sockets from non-tunnel processes (inspect):${c_off}"
    echo "$susudp" | sed 's/^/    /'
    flags+=("udp")
else
    echo "${c_grn}[ok] No suspicious UDP sockets.${c_off}"
fi

# 5) External TCP connections (informational)
echo "[i] External TCP connections (informational):"
ss -tnp state established 2>/dev/null \
  | awk 'NR>1 && $5 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|\[::1\]|\[fe80)/ {print "    "$0}' \
  || echo "    (none)"

# ---- Verdict -------------------------------------------------------------
echo "${c_cyn}==================== VERDICT ====================${c_off}"
has_vpnif=0
for f in "${flags[@]:-}"; do [ "$f" = "vpn-if" ] && has_vpnif=1; done

if [ "$has_vpnif" -eq 1 ]; then
    echo "${c_red}RESULT: POSSIBLE ZOMBIE VPN - a VPN interface is present. Investigate above.${c_off}"
elif [ "$tunnel_up" -eq 0 ] && [ "${#flags[@]}" -gt 0 ]; then
    echo "${c_yel}RESULT: SUSPICIOUS - tunnel not running yet non-tunnel sockets found. Inspect.${c_off}"
elif [ "$tunnel_up" -eq 0 ]; then
    echo "${c_grn}RESULT: No VPN software detected. Confirm the External IP above is your HOME location.${c_off}"
else
    echo "${c_grn}RESULT: Tunnel running; foreign exit IP is normal. No third-party VPN interfaces - clean.${c_off}"
fi
echo
