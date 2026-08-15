# tunnel

A software-defined egress engine with traffic observability.

`tunnel.exe` creates a virtual network adapter, takes over your machine's default
route, and sends every IPv4 packet either straight out your uplink or through a
WireGuard peer you supply — while a live dashboard shows you exactly what is
moving and where it is going.

It is a **client**. It does not need a server, a port forward on your router, or
a VPN provider's desktop app. If you have a WireGuard `.conf` from a provider
(Proton, Mullvad, anyone), you paste five fields into a TOML file and run it.

---

## What you get

| | |
|---|---|
| **Full capture** | Two `/1` routes over the top of your default route. Every IPv4 flow on the host goes through the engine. |
| **Your choice of exit** | `Direct` (out your own uplink, as a transparent proxy) or `WireGuard` (userspace boringtun, NAT44 behind the peer). |
| **Kill switch** | A Windows Filtering Platform filter scoped to your uplink interface: only this process may send out of it. Everything else — including IPv6 — is dropped. This is the [TunnelVision (CVE-2024-3661)](https://www.leviathansecurity.com/blog/tunnelvision) mitigation, and it is **fail-closed**: if it can't arm, the engine refuses to run. |
| **Snooper tripwire** | Watches for route-change events that steer canary addresses off the tunnel while the tunnel's own routes are intact. On a confirmed injection it slams a reboot-clearable network lockdown and exits `101`. |
| **DNS pinning** | The resolver is forced onto the tunnel adapter for the session and restored on exit — mandatory under capture, since the kill switch would otherwise silently eat every query to your LAN resolver. |
| **Live dashboard** | Throughput, flows, protocols, hosts, services, composition, counters, plus active probes (nslookup, port scan, address intel) asked *through* the tunnel. |
| **Flow record** | Every flow the session saw, including ones evicted from the live table, written to CSV at shutdown. |
| **Inbound port** | Optional NAT-PMP lease from the exit gateway, renewed for the life of the session. |

IPv4 only, by design. IPv6 is dropped at the uplink rather than allowed to
bypass the tunnel — expect IPv6 connectivity to disappear while the engine runs.

---

## Requirements

- **Windows 10/11**, x64 or ARM64.
- **Administrator.** The engine creates an adapter, rewrites the route table,
  installs WFP filters, and rebinds the resolver. There is no unprivileged mode.
- **`wintun.dll`**, architecture-matched. Already vendored in this repo under
  `bin/amd64/` and `bin/arm64/`; otherwise grab it from
  [wintun.net](https://www.wintun.net/).
- **Rust** (stable, 2021 edition) to build from source.
- A WireGuard config from your provider, if you want a remote exit. Optional —
  without one the engine runs as a transparent proxy out your own uplink.

If you use a commercial VPN, **turn its desktop app off**. Its own kill switch
will block this engine.

---

## Build

```bash
cargo build --release
```

The binary lands at `target\release\tunnel.exe`.

`wintun.dll` is searched for, in order:

1. next to `tunnel.exe`
2. `<exe dir>\amd64\` (or `arm64`)
3. `<exe dir>\bin\amd64\`
4. `bin\amd64\` relative to the working directory
5. `wintun.dll` in the working directory

The simplest setup is to copy the DLL next to the binary:

```bash
copy bin\amd64\wintun.dll target\release\
```

Headless build (no dashboard, no active probes):

```bash
cargo build --release --no-default-features
```

---

## Quick start

**1. Write a starter settings file.**

```bash
tunnel.exe init
```

This creates `tunnel.toml` in the working directory with the defaults spelled
out and a commented `[wireguard]` template. It refuses to overwrite an existing
file.

**2. Fill it in.** For a direct exit, the defaults are already fine. For a
WireGuard exit, open your provider's `.conf` and map the fields:

| WireGuard `.conf` | `tunnel.toml` |
|---|---|
| `[Interface] PrivateKey` | `private_key` |
| `[Interface] Address` | `address` (drop the `/32`) |
| `[Peer] PublicKey` | `public_key` |
| `[Peer] Endpoint` | `endpoint` |
| `[Peer] PresharedKey` | `preshared_key` (if present) |

Then set `dns` to a resolver reachable **through your exit** — Proton's is
`10.2.0.1`. A resolver your exit can't reach means no name resolution at all.

**3. Run it, from an elevated prompt.**

```bash
tunnel.exe
```

The dashboard opens and the engine comes up behind it. Closing the window (or
Ctrl-C) tears everything down cleanly: filters removed, resolver restored,
routes put back, adapter deleted, flow CSV written.

---

## Configuration

One file, engine and exit together. Unknown fields are hard parse errors —
nothing is silently ignored.

```toml
tun_ip     = "198.18.0.1"   # our address on the TUN (RFC 2544 range; avoids LAN clashes)
tun_prefix = 15
mtu        = 1400           # leave headroom under 1500 for WireGuard encapsulation
                            # (32 WG + 8 UDP + 20 IP = 60 bytes)
dns        = "1.1.1.1"      # pinned to the TUN under full capture

[wireguard]                 # optional — omit for a Direct exit
private_key          = "…=="
public_key           = "…=="
endpoint             = "203.0.113.10:51820"
address              = "10.2.0.2"
preshared_key        = "…=="    # optional
persistent_keepalive = 25
port_forward         = "nat-pmp" # optional; see below
```

If the settings file is missing, the engine runs on **built-in defaults** —
Direct exit, DNS `1.1.1.1` — and says so loudly. If you name a file explicitly
and it doesn't exist, that's a fatal error.

> `tunnel.toml` is gitignored: it holds your private key. Keep it that way.
> `tunnel.example.toml` is the annotated reference copy.

### Inbound port forwarding

Without it the tunnel is outbound-only, which is what any NAT gives you — peers
cannot dial in. Two shapes:

- `port_forward = "nat-pmp"` — lease a port from the exit gateway and keep
  renewing it. This is what Proton does; generate the WireGuard config with
  NAT-PMP enabled. There is no port number to copy from anywhere, it's
  negotiated at runtime.
- `port_forward = 51413` — a fixed port the provider assigned out of band. Rare.
  On Proton this forwards nothing; their ports are always leases.

The port is the same number on both sides, so point your application at it
(qBittorrent: *Connection → Listening Port*, with UPnP/NAT-PMP **off** — this
engine does the leasing). You will also need a Windows Firewall inbound rule for
that application on the tunnel adapter's profile, or packets arrive and get
dropped one layer past the engine — which looks exactly like a working forward
with no peers.

The dashboard header shows the leased port and a count of packets actually
received on it. **A count stuck at zero means the forward isn't live**, whatever
the port number says.

---

## Command line

```
tunnel [OPTIONS] [COMMAND] [SETTINGS.toml]

COMMANDS:
    gui                  Run the engine + dashboard (default)
    init                 Write a starter settings file

ARGS:
    <SETTINGS.toml>      Any positional ending in .toml.
                         Default: tunnel.toml in the working directory.

OPTIONS:
    -s, --settings <P>   Settings file (same as the positional form)
        --no-route       Do not redirect the default route into the TUN
        --log            Also write the full log transcript to tunnel-<stamp>.txt
    -v, --verbose        Verbose logging
    -h, --help / -V, --version
```

Unknown commands, arguments, or settings fields are errors.

`--no-route` runs the engine without capturing anything — no route hijack, no
kill switch, no DNS pin, no tripwire. Useful for a dry run; it is not a tunnel.

---

## The dashboard

Eight views, switchable from the header:

- **THROUGHPUT** — up/down rates over time.
- **FLOWS** — the live flow table.
- **PROTOCOLS**, **HOSTS**, **SERVICES**, **COMPOSITION** — what the traffic
  actually consists of, sliced four ways.
- **COUNTERS** — raw byte counts at both the TUN tap and the exit socket.
  Divergence between the two localises loss to a hop: exit reads high with TUN
  down low means bytes are dying inside the stack.
- **PROBE** — questions asked *through* the tunnel: `nslookup` (forward and
  reverse, against the pinned resolver), a bounded TCP port scan, and address
  intel (reverse name, ASN, prefix, country, registry, org).

The header carries connection state, the exit label, uptime, the forwarded port,
and — if the engine dies — the reason it died. A dead engine never keeps wearing
`CONNECTED`.

---

## Files the session writes

Both land **next to `tunnel.exe`**, not in the working directory (a
double-clicked GUI app inherits an unpredictable and often unwritable CWD), and
share one timestamp so they read as a pair:

- `flows-<stamp>.csv` — the full session flow table, written at shutdown.
- `tunnel-<stamp>.txt` — the log transcript, only with `--log`. Panics land here
  too.

---

## Verifying it works

Two harnesses ship with the repo (both are bash/batch, and the leak sweep is
Linux-oriented):

- `vpn-leakcheck.sh` — a leak sweep whose verdict comes from the **external
  egress IP** compared against a recorded home baseline, not from a process
  name. First run off-VPN with `--set-home` to record the baseline.
- `vpn-tunnelvision-win.bat` — injects a more-specific `/32` route for a
  tripwire canary via the real uplink, which is exactly the TunnelVision
  condition. A healthy engine detects it, locks the machine down, and exits
  `101`.

  **This is destructive. A PASS locks the machine down and you must reboot to
  recover.** It dry-runs by default and requires `--fire` plus a typed
  confirmation.

- `visualize_flows.py` — renders a finished session's CSV into four panels
  (bytes per protocol, protocol share, top remote endpoints, and a flow
  timeline). Needs pandas, matplotlib, seaborn, numpy:

  ```bash
  python visualize_flows.py flows-20260815-143000.csv
  ```

---

## When something goes wrong

**"wintun.dll not found"** — copy the architecture-matching DLL next to
`tunnel.exe` (see [Build](#build)).

**"failed to create Wintun adapter"** — you are not elevated. Run from an
Administrator prompt.

**Adapter came up as `tunnel0 2`** — a previous interface is still registered
under that name. Not fatal, but the host has cruft worth clearing; a reboot
sorts it.

**"failed to pin the resolver … refusing to run with capture"** — the engine
will not run captured without DNS on the tunnel, because the kill switch would
then drop every query with no visible error. Fix the cause or use `--no-route`.

**"failed to arm kill switch … refusing to run"** — same principle. The engine
does not run with an unprotected uplink.

**No connectivity, tunnel appears up** — check `dns`. A resolver your exit can't
reach is the most common cause. Proton needs `10.2.0.1`, not `1.1.1.1`.

**IPv6 stopped working** — intentional. See the note at the top.

**The machine is locked down and the network is dead** — the tripwire fired. A
snooper was detected on your route table. Disconnect from the network, reboot,
and rotate your keys. The lockdown is deliberately reboot-clearable and nothing
needs to stay running to enforce it. On the next start the engine will refuse to
run if it finds the lockdown still installed and the host un-rebooted.

**Exit code 101** — that's the tripwire, not a crash.

---

## Also runs on Linux

The same binary builds for Linux, where the equivalents are nftables instead of
WFP, `ip route` instead of `route.exe`, and systemd-resolved or
`/etc/resolv.conf` instead of `netsh` for the DNS pin. Preflight checks for
root, `/dev/net/tun`, iproute2, nftables with a writable `inet` family, and a
working resolver path before anything is installed. Run it as
`sudo -E ./tunnel <settings>.toml`.

---

## License

BSD.
