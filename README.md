# Tunnel RS — Windows

Software-defined egress engine with traffic observability. A single Windows
executable that routes all host traffic through a local virtual interface, out
an exit you choose, and shows you everything that passes through. Built for
solo blue teamers and small teams.

- One `.exe`, one TOML config. No installer, no service, no account.
- Zero telemetry. You own the binary outright.
- One-time price. No subscription.

## Requirements

- Windows 10/11, x64 or ARM64. `wintun.dll` is included (`bin\amd64`, `bin\arm64`).
- Run as **Administrator** — creating the adapter, rewriting routes, and arming
  the kill switch all need it.
- Optional: a WireGuard config from your provider (Proton, Mullvad, your own
  server).
- Linux support ships in a later release.

## Quick start

From an elevated PowerShell, in the folder that holds `tunnel.exe`:

```powershell
.\tunnel.exe init          # writes a starter tunnel.toml next to the exe
.\tunnel.exe tunnel.toml   # engine + dashboard
```

Ctrl-C in the console, or closing the dashboard window, stops the engine and
restores routing. Both the session flow CSV (`flows-<timestamp>.csv`) and, with
`--log`, the transcript (`tunnel-<timestamp>.txt`) are written next to the exe.

```
USAGE:
    tunnel [OPTIONS] [COMMAND] [SETTINGS.toml]

COMMANDS:
    gui                  Run the engine + dashboard (default)
    init                 Write a starter settings file

OPTIONS:
    -s, --settings <P>   Settings file (same as the positional form)
    -d, --direct         Direct exit on built-in defaults: transparent proxy out
                         the host uplink, dns 1.1.1.1, any [wireguard] ignored
        --no-route       Do not redirect the default route into the TUN
        --log            Also write the full log transcript to tunnel-<timestamp>.txt
    -v, --verbose        Verbose logging
    -h, --help / -V, --version
```

Unknown commands, arguments, or settings fields are errors — nothing is
silently ignored.

## Configuration

All fields are optional; the defaults are built in.

```toml
tun_ip = "198.18.0.1"   # our address on the TUN (RFC 2544 range, avoids LAN clashes)
tun_prefix = 15
mtu = 1400
dns = "1.1.1.1"         # pinned onto the TUN while capturing. Must be reachable
                        # via your exit — Proton's is 10.2.0.1.

# Optional WireGuard exit. Omit the whole section for Direct.
# [wireguard]
# private_key = "AAAA...=="          # Interface.PrivateKey
# public_key  = "BBBB...=="          # Peer.PublicKey
# endpoint    = "203.0.113.10:51820" # Peer.Endpoint
# address     = "10.2.0.2"           # Interface.Address without /32
# preshared_key = "CCCC...=="        # optional
# persistent_keepalive = 25
# port_forward = "nat-pmp"           # or a fixed number, e.g. 51413; omit for outbound-only
```

### Exits

- **Direct** — out your own uplink through a built-in transparent proxy.
  Observability with no VPN. `--direct`, or a config with no `[wireguard]`
  section.
- **WireGuard** — bring your own config from any provider. Encrypted
  in-process with no provider app and no router port forwarding: the endpoint
  socket is outbound-initiated and held open by `persistent_keepalive`. Turn
  the provider's own app (and its kill switch) off first.

### Port forwarding (WireGuard only)

`port_forward` holds exactly one inbound port open for the session: a number
for a port the provider assigned out of band, or `"nat-pmp"` for a lease
renewed for the life of the session (ProtonVPN-style). The dashboard shows the
port and a count of packets actually received on it. Most providers lease —
a fixed number pasted in on a leasing provider forwards nothing.

## Live dashboard

- Throughput graph, live flow table, per-host and per-port breakdowns, byte
  and packet counters.
- Protocol classification: DNS, mDNS, LLMNR, SSDP, NetBIOS, HTTP, TLS, QUIC,
  SSH, NTP, DHCP, WireGuard, OpenVPN, Shadowsocks, BitTorrent (peer handshake,
  uTP, DHT, UDP and HTTP trackers), ICMP, and more. Encrypted payload on an
  unknown port shows as **Obfuscated**; when the same host also speaks uTP or
  DHT it shows as **Obfuscated (uTP/DHT)**, which is what an encrypted
  BitTorrent peer looks like.
- **Peers and groups.** Every remote host gets a session-stable short id
  (`p17`) shown in the PEER column, so one peer's TCP, uTP and DHT rows read
  as one thing. The GROUP column shows, per the `port` / `/24` / `asn`
  selector, the local port the flow belongs to (all peers of one local
  application, e.g. a torrent client's listen port), the remote /24, or the
  remote network's ASN and name; the `group` sort clusters rows by it. The
  filter box matches peer ids and group text too.
- **ASN enrichment** fills the `asn` grouping in the background, one DNS
  query to Team Cymru per new /24 through the tunnel's resolver, at most two
  a second. Those lookups appear in FLOWS as `DNS intel` in the accent colour
  with the rest of the row muted, so they can never pass for the host's own
  DNS; type `intel` in the filter to see only them. The `asn` checkbox in
  the FLOWS toolbar stops them — every remote address is sent, reversed, to
  your resolver, which is worth knowing on a direct exit.
- Full session flow table written to CSV at shutdown (columns end
  `…,status,peer,asn,origin`). Optional timestamped log transcript (`--log`).

### Probes through the tunnel

- **Lookup** — A, AAAA, PTR, CNAME, TXT, MX, NS, SOA, CAA, TLSA.
- **Scan** — TCP connect scan over a port list. This is the only probe that
  contacts the target.
- **Intel** — reverse name, ASN, prefix, country, registry, org. Resolver-only
  (PTR plus Team Cymru's DNS-based ASN service); the target never sees it.

Every socket a probe opens — each DNS query, the TCP retry for a truncated
answer, every port-scan connect — is announced to the traffic monitor before
its first packet, so probe traffic shows in FLOWS tagged `intel` exactly like
the background enricher's, never as the host's own.

## Leak protection

- **Kill switch** — a WFP filter permits only Tunnel's own sockets out the
  uplink, IPv4 and IPv6. Fail-closed: if it cannot arm, the engine refuses to
  capture. See [What the kill switch does and does not cover](#what-the-kill-switch-does-and-does-not-cover).
- **DNS pinning** — the resolver is forced onto the tunnel adapter for the
  session and goes away with it on exit.
- **TunnelVision tripwire** — detects CVE-2024-3661 route injection, locks the
  host down, and exits. Test harness included
  (`vpn-tunnelvision-win.bat`, destructive — read its header).
- **Egress pinning** — exit sockets are bound to the real uplink so a hijacked
  route table cannot redirect them.
- Routes, resolver, filters, and adapter are restored on Ctrl-C, window close,
  or crash. The filters live in a dynamic WFP session, which Windows removes
  itself when the process dies for any reason.

### What the kill switch does and does not cover

The filter set, as installed (`src/killswitch.rs`):

| Filter | Layer | Scope |
| --- | --- | --- |
| Permit `tunnel.exe` | outbound connect, v4 + v6 | any interface |
| Permit DHCP client (UDP → 67) | outbound connect, v4 | any interface |
| Block everything else | outbound connect, v4 + v6 | **the uplink interface only** |

What that means in practice:

- Every new outbound connection from any other process out the uplink is
  dropped — TCP connects, UDP sends, and ICMP alike, over IPv4 and IPv6.
  Windows re-authorises already-open connections when the filters are added,
  so connections that predate the engine are cut too.
- The block is scoped to the **one** uplink the engine discovered. A second
  connected interface (a docked Ethernet port while on Wi-Fi, a USB tether,
  a second VPN adapter) is not fenced. Disconnect or disable anything you are
  not using.
- Inbound is not filtered. A service already listening on the uplink (RDP,
  SMB, a dev server) can still accept connections. That is not an egress leak,
  but it is not "locked down" either.
- Any process run from the same `tunnel.exe` path is permitted, not just this
  instance.
- Loopback and the tunnel adapter itself are unaffected.

## Windows: DNS must be on "Automatic" for the Wi-Fi adapter

While full-tunnel capture is active, the engine pins DNS on its own adapter
(`tunnel0`) and the kill switch drops every packet that leaves the uplink
outside the tunnel. Any resolver you have configured on the Wi-Fi/Ethernet
adapter itself — plain or DNS-over-HTTPS — is therefore unreachable for the
whole session. Windows still tries it alongside the tunnel's resolver, which
shows up as slow or failing lookups. Leave the uplink adapter's DNS on
**Automatic (DHCP)**; the engine supplies the resolver while it runs and the
setting dies with `tunnel0` on exit.

### Gotcha: Windows 11 has two places to set Wi-Fi DNS

Windows keeps a DNS assignment at **two** layers, and the adapter-level one
wins silently:

1. **Per network** — Settings → Network & internet → Wi-Fi → *\<your network\>*
   → DNS server assignment.
2. **For all Wi-Fi networks (adapter level)** — Settings → Network & internet
   → Wi-Fi → *Hardware properties* → DNS server assignment.

If layer 2 is set, layer 1 is ignored and its page shows the yellow banner
"The DNS settings for all Wi-Fi networks have been set. The settings below
won't be used." Setting DNS in one place and checking it in the other looks
exactly like something left the machine misconfigured — in our case it looked
like the engine had broken access to Cloudflare-fronted sites after exit.
It hadn't: a clean exit leaves no routes, adapter, DNS, NRPT or MTU changes
behind. Check both layers before auditing the engine:

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/1,128.0.0.0/1
Get-NetAdapter -IncludeHidden | Where-Object Name -match tunnel
```

All three should come back showing only your uplink's DHCP resolver, no `/1`
routes, and no `tunnel0` adapter once the engine has stopped.

The only state the engine deliberately leaves behind is the tripwire's
`tunnel panic` WFP lockdown, and that blocks *everything* until reboot — it is
not a partial outage. From an admin prompt:

```powershell
netsh wfp show state file=$env:TEMP\wfp.xml; findstr /i "tunnel" $env:TEMP\wfp.xml
```

### Recommended: disable IPv6 on the uplink adapter

The engine is IPv4-only — it never tunnels IPv6. The kill switch does block
IPv6 out the uplink while it is armed, but unbinding IPv6 from the adapter
(Wi-Fi adapter → Properties → untick *Internet Protocol Version 6
(TCP/IPv6)*, or `Disable-NetAdapterBinding -Name Wi-Fi -ComponentID ms_tcpip6`)
is additional leak protection that holds before the engine starts, after it
stops, and on any interface the kill switch is not scoped to: with no IPv6
address on the host, Windows ignores AAAA answers and nothing can reach a
dual-stack site over v6 around the tunnel. The engine does not do this for
you; it is a one-time manual setting and survives engine restarts. Re-enable
it with `Enable-NetAdapterBinding` if you ever need IPv6 off-tunnel.

## Building from source

```powershell
cargo build --release
```

`tunnel.exe` lands in `target\release\`. The loader looks for `wintun.dll` next
to the exe, then in `<arch>\`, then in `bin\<arch>\` beside it (`amd64`, `arm64`,
`x86`) — never in the working directory — and verifies its signature before
loading.
Build with `--no-default-features` for a headless engine without the dashboard.
