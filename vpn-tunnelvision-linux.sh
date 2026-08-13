#!/usr/bin/env bash
# ============================================================================
#  tunnel-attack.sh -- TunnelVision (CVE-2024-3661) test harness.
#
#  Injects a more-specific /32 route for one tripwire canary via the REAL
#  uplink, while the tunnel's /1 capture routes stay intact -- exactly the
#  condition src/tripwire.rs::detect_attack watches for. If the engine is
#  healthy it detects the route, locks the network down (nft inet tunnel_panic)
#  and exits 101.
#
#  DESTRUCTIVE: a PASS means the machine is locked down and needs a REBOOT.
#  Dry-run by default. Requires --fire (and a typed 'yes', unless --yes).
#
#      sudo ./tunnel-attack.sh              # dry-run: print what it would do
#      sudo ./tunnel-attack.sh --fire       # actually attack (asks to confirm)
#      sudo ./tunnel-attack.sh --fire --yes --canary 8.8.8.8
# ============================================================================
set -u

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'; c_off=$'\033[0m'
die(){ echo "${c_red}[x] $*${c_off}" >&2; exit 1; }

# Must match CANARIES in src/tripwire.rs -- a route to anything else is ignored.
canaries="1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 192.0.2.1 198.51.100.1 203.0.113.1"
canary="1.1.1.1"; fire=0; assume_yes=0; timeout=6

while [ $# -gt 0 ]; do
    case "$1" in
        --fire)   fire=1 ;;
        --yes)    assume_yes=1 ;;
        --canary) shift; canary="${1:-}" ;;
        *) die "unknown arg: $1" ;;
    esac; shift
done
printf '%s' "$canaries" | tr ' ' '\n' | grep -qx "$canary" \
    || die "canary $canary is not in the tripwire's list; it would not be checked."

echo
echo "${c_cyn}================= TUNNELVISION ATTACK TEST =================${c_off}"

# --- Preconditions: a real, armed tunnel. Otherwise this just litters the
#     routing table with a junk route and proves nothing. -------------------
[ "$(id -u)" -eq 0 ] || die "run as root (route injection needs CAP_NET_ADMIN)."
pgrep -x tunnel >/dev/null 2>&1 || die "no 'tunnel' process -- start the engine first."
tun_dev=$(ip route show 0.0.0.0/1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
[ -n "$tun_dev" ] || die "no 0.0.0.0/1 capture route -- the tunnel is not capturing (--no-route?)."
ip route show 128.0.0.0/1 2>/dev/null | grep -q "dev $tun_dev" \
    || die "128.0.0.0/1 not on $tun_dev -- capture looks half-installed; aborting."
nft list table inet tunnel_killswitch >/dev/null 2>&1 \
    || die "kill switch (inet tunnel_killswitch) not armed -- tripwire is not active."

# --- The real uplink still owns the default route; the /1 routes sit beside
#     it. Route the canary via that gateway to steer it off the tunnel. -----
read -r up_gw up_dev < <(ip route show default 2>/dev/null \
    | awk '/^default/{for(i=1;i<=NF;i++){if($i=="via")g=$(i+1); if($i=="dev")d=$(i+1)} print g, d; exit}')
[ -n "$up_gw" ] && [ -n "$up_dev" ] || die "cannot find the real uplink default route."
[ "$up_dev" != "$tun_dev" ] || die "default route is the TUN itself -- no real uplink to leak via."

route_cmd="ip route add ${canary}/32 via ${up_gw} dev ${up_dev} metric 1"
echo "[i] Tunnel:  capture on ${tun_dev}, kill switch armed."
echo "[i] Uplink:  gateway ${up_gw} via ${up_dev}."
echo "[i] Attack:  ${route_cmd}"
echo "             (a /32 beats the tunnel's /1, so ${canary} leaks off-tunnel)"

if [ "$fire" -eq 0 ]; then
    echo "${c_yel}[i] DRY RUN -- nothing injected. Re-run with --fire to attack.${c_off}"
    echo; exit 0
fi

echo "${c_red}[!] --fire: a PASS locks this machine down. You will need to REBOOT.${c_off}"
if [ "$assume_yes" -eq 0 ]; then
    printf "    Type 'yes' to inject the leak route: "; read -r ans
    [ "$ans" = "yes" ] || die "aborted."
fi

# Always remove our injected route on the way out -- if the tripwire does NOT
# fire, this is a genuine leak we created and must not leave behind; if it
# does, this tidies the table (connectivity still needs the reboot).
cleanup(){ ip route del "${canary}/32" 2>/dev/null; }
trap cleanup EXIT INT TERM

echo "[i] Injecting leak route..."
ip route add "${canary}/32" via "$up_gw" dev "$up_dev" metric 1 \
    || die "route injection failed."

echo "[i] Watching for the tripwire (up to ${timeout}s)..."
fired=0
for _ in $(seq 1 $((timeout*4))); do
    if nft list table inet tunnel_panic >/dev/null 2>&1 || ! pgrep -x tunnel >/dev/null 2>&1; then
        fired=1; break
    fi
    sleep 0.25
done

echo "${c_cyn}==================== RESULT ====================${c_off}"
if [ "$fired" -eq 1 ]; then
    echo "${c_grn}[PASS] Tripwire fired: route detected, engine locked the network down.${c_off}"
    nft list table inet tunnel_panic >/dev/null 2>&1 \
        && echo "       nft inet tunnel_panic is installed (drop-all lockdown)."
    pgrep -x tunnel >/dev/null 2>&1 || echo "       engine process has exited."
    echo "${c_yel}       The machine is now LOCKED DOWN -- reboot to restore networking,${c_off}"
    echo "${c_yel}       then rotate your keys. (The injected route was removed.)${c_off}"
else
    echo "${c_red}[FAIL] Tripwire did NOT fire within ${timeout}s.${c_off}"
    echo "${c_red}       ${canary} was leaking off-tunnel and the engine did not catch it.${c_off}"
    echo "       The injected route has been removed. Investigate src/tripwire.rs."
fi
echo