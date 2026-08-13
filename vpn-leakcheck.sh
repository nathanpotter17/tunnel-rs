#!/usr/bin/env bash
# ============================================================================
#  vpn-leakcheck.sh -- VPN / leak sweep, driven by what the internet sees.
#
#  The verdict comes from the external egress IP (compared to a recorded HOME
#  baseline and to a known-VPN-ISP list), NOT from a process name. Local
#  footprint -- our TUN, the /1 capture routes, the nft tables, the boringtun
#  UDP socket -- is used only to explain WHICH tunnel is responsible.
#
#  First run, off VPN:   sudo ./vpn-leakcheck.sh --set-home
#  Thereafter:           sudo ./vpn-leakcheck.sh
#
#  Env overrides: HOME_IP, HOME_COUNTRY, HOME_ISP (skip the baseline file).
# ============================================================================
set -u

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'; c_off=$'\033[0m'
baseline="${XDG_CONFIG_HOME:-$HOME/.config}/tunnel/home-egress"
set_home=0
[ "${1:-}" = "--set-home" ] && set_home=1

# ISP substrings that are VPN-exit infrastructure. Two tiers: named VPN brands
# (strong), and hosting ASNs that VPNs ride on but so do plain servers (weak).
vpn_brands='m247|mullvad|proton|nordvpn|tefincom|expressvpn|private internet|perfect privacy|windscribe|cyberghost|ivpn|azirevpn|ovpn'
vpn_hosting='datacamp|cdn77|leaseweb|g-core|gcore|clouvider|1337 services|packethub|packet exchange|hostroyale|the constant company|vultr| ovh'

echo
echo "${c_cyn}==================== VPN / LEAK CHECK ====================${c_off}"

# --- Ground truth: what is the internet seeing right now? --------------------
ip=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null || true)
country=""; isp=""
if [ -n "$ip" ]; then
    geo=$(curl -s --max-time 8 "http://ip-api.com/json/${ip}?fields=country,regionName,isp" 2>/dev/null || true)
    country=$(printf '%s' "$geo" | grep -oE '"country":"[^"]*"' | cut -d'"' -f4)
    isp=$(printf '%s' "$geo"     | grep -oE '"isp":"[^"]*"'     | cut -d'"' -f4)
    echo "[i] External IP: ${ip}   [country=${country:-?}, isp=${isp:-?}]"
else
    echo "${c_yel}[!] No external IP -- offline, or locked down after a tripwire fire.${c_off}"
fi

# --- Record baseline and exit ----------------------------------------------
if [ "$set_home" -eq 1 ]; then
    if [ -z "$ip" ]; then echo "${c_red}[x] Cannot record HOME with no external IP.${c_off}"; exit 1; fi
    mkdir -p "$(dirname "$baseline")"
    printf 'HOME_IP=%s\nHOME_COUNTRY=%s\nHOME_ISP=%s\n' "$ip" "$country" "$isp" > "$baseline"
    echo "${c_grn}[ok] HOME baseline recorded to ${baseline}${c_off}"
    echo "     ip=${ip} country=${country} isp=${isp}"
    echo "     (Run this only while OFF any VPN.)"
    exit 0
fi

# --- Load the HOME baseline (env wins over file) ----------------------------
home_ip="${HOME_IP:-}"; home_country="${HOME_COUNTRY:-}"; home_isp="${HOME_ISP:-}"
if [ -z "$home_ip" ] && [ -f "$baseline" ]; then
    # shellcheck disable=SC1090
    . "$baseline"
    home_ip="${HOME_IP:-}"; home_country="${HOME_COUNTRY:-}"; home_isp="${HOME_ISP:-}"
fi
if [ -n "$home_ip" ]; then
    echo "[i] HOME baseline: ip=${home_ip} country=${home_country:-?}"
else
    echo "${c_yel}[i] No HOME baseline -- run '--set-home' off-VPN for IP/country comparison.${c_off}"
fi

# --- Evaluate the egress against ground truth -------------------------------
egress_is_vpn=0; egress_reason=""
if [ -n "$ip" ]; then
    if [ -n "$home_ip" ] && [ "$ip" != "$home_ip" ]; then
        egress_is_vpn=1; egress_reason="external IP differs from HOME (${ip} != ${home_ip})"
    fi
    if [ -n "$home_country" ] && [ -n "$country" ] && [ "$country" != "$home_country" ]; then
        egress_is_vpn=1; egress_reason="egress country ${country} != HOME ${home_country}"
    fi
    if printf '%s' "$isp" | grep -qiE "$vpn_brands"; then
        egress_is_vpn=1; egress_reason="egress ISP '${isp}' is a known VPN provider"
    elif printf '%s' "$isp" | grep -qiE "$vpn_hosting"; then
        egress_is_vpn=1; egress_reason="egress ISP '${isp}' is VPN-hosting infrastructure"
    fi
fi

# --- Local footprint: is OUR tunnel the thing doing it? ---------------------
tun_dev=$(ip route show 0.0.0.0/1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
have_split=0; [ -n "$tun_dev" ] && ip route show 128.0.0.0/1 2>/dev/null | grep -q "dev $tun_dev" && have_split=1
have_ks=0;    nft list table inet tunnel_killswitch >/dev/null 2>&1 && have_ks=1
have_panic=0; nft list table inet tunnel_panic     >/dev/null 2>&1 && have_panic=1
# boringtun connects its UDP socket to the WG endpoint; a connected UDP peer is
# the datapath even when no wg* interface exists (userspace WireGuard).
wg_udp=$(ss -unp 2>/dev/null | awk 'NR>1 && $6 ~ /:[0-9]+$/ && $6 !~ /127\.0\.0\.1|\[::1\]|0\.0\.0\.0|\*/ {print}' | head -n3)

footprint=0
[ "$have_split" -eq 1 ] && { echo "${c_grn}[ok] Capture routes present on ${tun_dev} (0.0.0.0/1 + 128.0.0.0/1).${c_off}"; footprint=1; }
[ "$have_ks"    -eq 1 ] && { echo "${c_grn}[ok] Kill switch armed (nft inet tunnel_killswitch).${c_off}"; footprint=1; }
[ -n "$wg_udp" ]        && { echo "[i] Connected UDP datapath (userspace WireGuard endpoint):"; printf '    %s\n' "$wg_udp"; footprint=1; }
if [ "$footprint" -eq 0 ]; then
    echo "[i] No tunnel footprint (no capture routes, kill switch, or WG datapath)."
fi

# --- Verdict ----------------------------------------------------------------
echo "${c_cyn}==================== VERDICT ====================${c_off}"
if [ "$have_panic" -eq 1 ]; then
    echo "${c_red}RESULT: LOCKED DOWN -- the tripwire fired (nft inet tunnel_panic present).${c_off}"
    echo "${c_red}        A snooper was detected. Disconnect, reboot, rotate keys.${c_off}"
elif [ "$egress_is_vpn" -eq 1 ] && [ "$footprint" -eq 1 ]; then
    echo "${c_grn}RESULT: TUNNELED -- egress is a VPN and our tunnel owns it. Expected.${c_off}"
    echo "        ${egress_reason}"
elif [ "$egress_is_vpn" -eq 1 ] && [ "$footprint" -eq 0 ]; then
    echo "${c_red}RESULT: ON A VPN/PROXY, but NOT via our tunnel (no footprint).${c_off}"
    echo "${c_red}        ${egress_reason}${c_off}"
    echo "${c_red}        A zombie/other VPN is steering your egress. Investigate.${c_off}"
elif [ "$egress_is_vpn" -eq 0 ] && [ "$footprint" -eq 1 ]; then
    echo "${c_red}RESULT: LEAK -- tunnel footprint is present but egress looks like HOME.${c_off}"
    echo "${c_red}        The tunnel is up yet traffic is NOT being redirected. Investigate.${c_off}"
elif [ "$egress_is_vpn" -eq 0 ] && [ -n "$home_ip" ]; then
    echo "${c_grn}RESULT: CLEAN -- egress matches HOME, no tunnel active.${c_off}"
else
    echo "${c_yel}RESULT: INCONCLUSIVE -- no HOME baseline and ISP is not a known VPN.${c_off}"
    echo "        Confirm the External IP above is your home location, or run --set-home."
fi
echo