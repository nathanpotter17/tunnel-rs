//! The engine: bring up the TUN, capture the default route, arm the safety
//! guards, then run whichever data path the configured exit needs.
//!
//! Two exits, two mechanisms, chosen once at startup:
//!
//!   * **Direct** — transparent proxy. Captured flows terminate in a userspace
//!     smoltcp stack and are re-originated on pinned OS sockets. Re-originating
//!     raw IP would be cheaper, but Windows has refused raw TCP sends since XP
//!     SP2, so OS sockets are the only portable egress. See `conn.rs`.
//!
//!   * **WireGuard** — router. We own both ends of the path, so nothing needs
//!     terminating: packets are NAT'd to the WireGuard client address, encrypted,
//!     and sent. The app's TCP runs end to end. See `wg.rs`.
//!
//! The proxy path is fully event-driven in BOTH directions: it wakes on a TUN
//! packet (upstream), on the connection manager's readiness queue (a flow's
//! egress socket delivered bytes, or smoltcp fired a socket waker), on smoltcp's
//! own poll_delay (retransmit / delayed-ACK timers), on the next flow deadline,
//! or on shutdown. Downstream data is serviced the moment it arrives — never
//! parked on a timer. TUN egress is drained with an awaited send: lossless,
//! backpressured.

use anyhow::{bail, Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::conn::{self, ConnManager};
use crate::device::TunDevice;
use crate::inspect::{Direction, TrafficMonitor};
use crate::pin::EgressPin;
use crate::route::{self, FullTunnel};
use crate::settings::Settings;
use crate::state::{ExitStats, Shared};
use crate::tunio::TunIo;

/// Max packets drained from the TUN per wake (keeps one busy flow from starving
/// the loop; more are picked up next wake).
const DRAIN_BUDGET: usize = 1024;

/// Ceiling on how long the proxy loop may sleep with nothing else pending. Only
/// bounds shutdown latency — the data path is woken by events, never by this.
const MAX_IDLE: Duration = Duration::from_millis(200);

/// Drain everything smoltcp emitted toward the TUN. The awaited send is the
/// backpressure seam: smoltcp cannot be polled again until the TUN writer has
/// accepted the previous burst, so nothing is ever dropped. Returns false if
/// the TUN writer is gone.
async fn flush_tun(
    device: &mut TunDevice,
    tx: &mpsc::Sender<Vec<u8>>,
    monitor: &TrafficMonitor,
) -> bool {
    while let Some(pkt) = device.pop_outbound() {
        monitor.record(Direction::Down, &pkt);
        if tx.send(pkt).await.is_err() {
            warn!("TUN writer closed");
            return false;
        }
    }
    true
}

pub async fn run(
    settings: Settings,
    install_route: bool,
    egress: EgressPin,
    orig_gateway: String,
    dns_backend: crate::preflight::DnsBackend,
    shared: Arc<Shared>,
) -> Result<()> {
    let monitor = shared.monitor.clone();
    let stats = Arc::new(ExitStats::default());

    // The uplink was discovered and the egress pin verified in `main` — once,
    // before the route was hijacked — and handed in here, so the engine and the
    // exit share one source of truth. `egress` may be unpinned (and
    // `orig_gateway` empty) if discovery failed; the fallbacks below still hold.

    // Resolve the exit before anything is installed, so a malformed WireGuard
    // config costs one message instead of a half-configured network.
    let wg_config = match &settings.wireguard {
        Some(wg) => Some(crate::wg::WgConfig::from_settings(wg)?),
        None => None,
    };
    let exit_label = match &settings.wireguard {
        Some(wg) => format!("WireGuard → {}", wg.endpoint),
        None => "Direct (uplink)".to_string(),
    };
    info!("Exit: {}", exit_label);

    // Publish status for the dashboard.
    if let Ok(mut st) = shared.status.lock() {
        st.running = true;
        st.exit = exit_label;
        st.full_tunnel = install_route;
        st.started_at = Some(StdInstant::now());
    }

    // Bring up the TUN and keep the adapter alive for the session.
    let tun = TunIo::new(settings.tun_ip, settings.tun_prefix, settings.mtu)
        .context("failed to create TUN device")?;
    let (name, rx, tx, mut tun_keepalive) = tun.into_parts();
    info!("TUN '{}' up at {}/{}", name, settings.tun_ip, settings.tun_prefix);

    // Optionally redirect the default route into the TUN (full capture).
    let _route_guard = if install_route {
        let gateway = FullTunnel::default_gateway_for(settings.tun_ip);
        // Loopback server_ip skips the host-route step: the loop-break here is
        // egress pinning, not a host route to a tunnel server.
        match FullTunnel::install(
            std::net::IpAddr::from([127, 0, 0, 1]),
            &name,
            settings.tun_ip,
            gateway,
            &orig_gateway,
            &egress.device,
        ) {
            Ok(guard) => {
                info!("Default route redirected into the TUN — all traffic is now tunneled");
                Some(guard)
            }
            Err(e) => {
                warn!("Route install failed ({e}); continuing without capture");
                None
            }
        }
    } else {
        warn!(
            "Running WITHOUT --route: the default route is untouched, so no host \
             traffic is captured. Pass --route to tunnel all traffic."
        );
        None
    };

    // Resolver, pinned to the TUN and restored on drop. NOT optional under
    // capture: the kill switch below drops unmarked traffic out the uplink, and
    // that includes every query to a LAN resolver — so a resolver left on the
    // uplink is a host with no DNS at all, silently, with the kill switch doing
    // exactly its job. Declared AFTER _route_guard so it drops FIRST (resolver
    // restored, then routes), matching the kill-switch ordering below.
    let _dns_guard = if _route_guard.is_some() {
        match route::DnsGuard::install(&name, settings.dns, dns_backend) {
            Ok(g) => Some(g),
            Err(e) => bail!(
                "failed to pin the resolver to the tunnel ({e:#}); refusing to run \
                 with capture, because the kill switch would then drop every DNS \
                 query to your LAN resolver and name resolution would stop with no \
                 visible error. Fix the cause, or pass --no-route to run without \
                 capturing traffic."
            ),
        }
    } else {
        None
    };

    // TunnelVision (CVE-2024-3661) mitigation — packet-filter kill switch on the
    // uplink. With the default route hijacked, a rogue DHCP option-121 route can
    // steer app traffic straight out the uplink, bypassing the TUN; the
    // encryption never sees it. Routing can't defend a routing attack, so we
    // enforce the invariant one layer down: a filter that permits only our own
    // (marked / app-scoped) sockets out the uplink and drops everything else.
    // Armed only when we actually captured the route; fail-closed — if it can't
    // arm we refuse to run rather than run leaky. Declared AFTER _route_guard so
    // it drops FIRST on teardown (filter removed, then routes restored).
    let _killswitch_guard = if _route_guard.is_some() {
        match crate::killswitch::KillSwitch::install(&egress) {
            Ok(ks) => {
                info!("Kill switch armed — uplink egress restricted to the tunnel (TunnelVision mitigated)");
                Some(ks)
            }
            Err(e) => {
                bail!(
                    "failed to arm kill switch ({e}); refusing to run with an \
                     unprotected uplink (TunnelVision leak risk). Fix the cause, \
                     or pass --no-route to run without capturing traffic."
                );
            }
        }
    } else {
        None
    };

    // Event-driven snooper tripwire (tripwire.rs). Armed only under capture. On a
    // confirmed injection it locks the network down (a reboot-clearable kernel
    // block) and terminates — no recovery — so this guard's own Drop only runs on
    // a clean exit.
    #[cfg(unix)]
    let tun_id = name.clone();
    #[cfg(windows)]
    let tun_id = route::interface_id(&name, settings.tun_ip).unwrap_or_default();
    let _tripwire = if _killswitch_guard.is_some() {
        Some(crate::tripwire::spawn(tun_id, shared.clone()))
    } else {
        let _ = tun_id;
        None
    };

    // Throughput ticker (advances the observability series ~1 Hz), plus
    // exit-boundary rates. `traffic:` counts at the TUN tap; `exit io:` counts at
    // the exit socket. Divergence localises loss to a hop.
    let ticker = {
        let m = monitor.clone();
        let s = stats.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(1));
            let (mut prev_read, mut prev_written) = (0u64, 0u64);
            loop {
                iv.tick().await;
                m.tick();
                let snap = m.snapshot();
                if snap.rate_up > 0.0 || snap.rate_down > 0.0 {
                    info!(
                        "traffic: up {:.0} B/s, down {:.0} B/s, flows {}",
                        snap.rate_up, snap.rate_down, snap.active_flows
                    );
                }
                let read = s.read.load(Ordering::Relaxed);
                let written = s.written.load(Ordering::Relaxed);
                let dr = read.saturating_sub(prev_read);
                let dw = written.saturating_sub(prev_written);
                prev_read = read;
                prev_written = written;
                if dr > 0 || dw > 0 {
                    info!("exit io: read {} B/s, wrote {} B/s", dr, dw);
                }
            }
        })
    };

    info!("Engine running. Ctrl-C to stop and restore routing.");

    // The data path. Exactly one of these runs for the life of the session.
    let result = match wg_config {
        Some(cfg) => {
            crate::wg::route(cfg, egress, rx, tx, monitor.clone(), stats.clone(), shared.clone())
                .await
        }
        None => proxy(&settings, egress, rx, tx, monitor.clone(), stats.clone(), shared.clone())
            .await,
    };
    ticker.abort();

    // Teardown order: disarm the tripwire and kill switch, restore the resolver,
    // stop capturing traffic (route guard), THEN remove the TUN. Routes/filters
    // key on prefix and socket marks, not on the TUN handle, so removing the
    // interface last avoids a window where the default route points at a dead
    // interface. Awaiting the TUN shutdown makes interface removal deterministic
    // (its worker threads release the adapter handle here, not whenever the
    // runtime happens to reap them), so the next launch always starts clean.
    drop(_tripwire);
    drop(_killswitch_guard);
    drop(_dns_guard);
    drop(_route_guard);
    tun_keepalive.shutdown().await;

    // Session flow data → CSV: everything the monitor saw, including flows
    // evicted from the live table mid-session. The path is resolved once at
    // startup (see `SessionPaths`) so the CSV and the `--log` transcript are
    // named as a pair and land in the same directory.
    let csv_path = shared.session.flows_csv();
    match monitor.write_csv(&csv_path) {
        Ok(n) => info!("flow table written to {} ({} flows)", csv_path.display(), n),
        Err(e) => warn!("could not write flow CSV {}: {}", csv_path.display(), e),
    }

    result
}

/// Transparent-proxy data path, used when the exit is `Direct`.
async fn proxy(
    settings: &Settings,
    egress: EgressPin,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    monitor: Arc<TrafficMonitor>,
    stats: Arc<ExitStats>,
    shared: Arc<Shared>,
) -> Result<()> {
    // Build the smoltcp interface over the TUN device.
    let mut device = TunDevice::new(settings.mtu as usize);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.set_any_ip(true); // accept connections to arbitrary destination IPs
    let o = settings.tun_ip.octets();
    let cidr = IpCidr::new(IpAddress::v4(o[0], o[1], o[2], o[3]), settings.tun_prefix);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(cidr);
    });
    // A default route lets smoltcp emit replies to the app whatever source IP the
    // OS chose for the tunneled connection (not just addresses on the TUN subnet).
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(o[0], o[1], o[2], o[3]));

    let mut sockets = SocketSet::new(vec![]);
    let mut conn = ConnManager::new(egress, monitor.clone(), stats);
    // Readiness queue: smoltcp socket wakers and the egress tasks file flow ids
    // into it, so a wake carries the identity of what to service.
    let ready = conn.readiness();

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut shutdown_check = tokio::time::interval(Duration::from_millis(200));

    loop {
        // Sleep no longer than the soonest of: smoltcp's protocol timers, the
        // next flow deadline, and the shutdown-latency ceiling. Every one of
        // those is a timer; data never waits on this arm.
        let now_std = StdInstant::now();
        let protocol = iface
            .poll_delay(Instant::now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()));
        let deadline = conn
            .next_deadline()
            .map(|at| at.saturating_duration_since(now_std));
        let delay = match (protocol, deadline) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => MAX_IDLE,
        }
        .min(MAX_IDLE);

        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutdown signal — restoring routing");
                break;
            }
            first = rx.recv() => {
                match first {
                    Some(pkt) => {
                        monitor.record(Direction::Up, &pkt);
                        if let Some(flow) = conn::parse_flow(&pkt) {
                            conn.on_packet(&mut sockets, &flow);
                        }
                        device.inject(pkt);
                        // Opportunistically drain a burst so one wake amortises
                        // many packets.
                        let mut drained = 1;
                        while drained < DRAIN_BUDGET {
                            match rx.try_recv() {
                                Ok(pkt) => {
                                    monitor.record(Direction::Up, &pkt);
                                    if let Some(flow) = conn::parse_flow(&pkt) {
                                        conn.on_packet(&mut sockets, &flow);
                                    }
                                    device.inject(pkt);
                                    drained += 1;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        warn!("TUN reader closed — stopping");
                        break;
                    }
                }
            }
            _ = ready.wait() => {}
            _ = shutdown_check.tick() => {
                if shared.shutdown.load(Ordering::Relaxed) {
                    info!("Dashboard closed — restoring routing");
                    break;
                }
            }
            _ = tokio::time::sleep(delay) => {}
        }

        iface.poll(Instant::now(), &mut device, &mut sockets);
        if !flush_tun(&mut device, &tx, &monitor).await {
            break;
        }
        // Only the flows smoltcp or an egress task actually woke are touched.
        // A second poll runs only when dispatch put something in a tx buffer.
        if conn.dispatch(&mut sockets, StdInstant::now()) {
            iface.poll(Instant::now(), &mut device, &mut sockets);
            if !flush_tun(&mut device, &tx, &monitor).await {
                break;
            }
        }
    }
    Ok(())
}
