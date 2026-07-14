//! The engine: TUN → smoltcp netstack → ConnManager → Direct outbound.
//!
//! Fully event-driven in BOTH directions: wakes on a TUN packet (upstream), on
//! the ConnManager's downstream waker (an outbound task delivered server bytes),
//! on smoltcp's own poll_delay (retransmit / delayed-ACK timers), or shutdown.
//! Downstream data is serviced the moment it arrives — never parked on a timer.
//! TUN egress is drained with an awaited send: lossless, backpressured.

use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::conn::{self, ConnManager};
use crate::device::TunDevice;
use crate::inspect::{Direction, TrafficMonitor};
use crate::outbound::{Direct, Outbound};
use crate::pin::{self, EgressPin};
use crate::route::{self, FullTunnel};
use crate::settings::Settings;
use crate::state::Shared;
use crate::tunio::TunIo;

/// Max packets drained from the TUN per wake (keeps one busy flow from starving
/// the loop; more are picked up next wake).
const DRAIN_BUDGET: usize = 1024;

/// Drain everything smoltcp emitted toward the TUN. The awaited send is the
/// backpressure seam: smoltcp cannot be polled again until the TUN writer has
/// accepted the previous burst, so nothing is ever dropped. Returns false if
/// the TUN writer is gone.
async fn flush_tun(
    device: &mut TunDevice,
    tx: &mpsc::Sender<Vec<u8>>,
    monitor: &Arc<TrafficMonitor>,
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

pub async fn run(settings: Settings, install_route: bool, shared: Arc<Shared>) -> Result<()> {
    let monitor = shared.monitor.clone();

    // Discover the uplink BEFORE touching the routing table, from the OS's own
    // forwarding decision (never a metric-sorted route listing — that once
    // selected a defunct interface and every pinned connect died with
    // 'unreachable host'). Then VERIFY the pin: a pinned connect toward the
    // gateway must succeed now, or every outbound socket will fail the same
    // way at runtime — better one loud line here than 200 dead flows later.
    let (egress, orig_gateway) = match route::discover_uplink() {
        Ok((src, iface_id, gw)) => {
            let pin = EgressPin {
                ifindex: iface_id.parse().unwrap_or(0),
                device: iface_id,
                src: Some(std::net::IpAddr::V4(src)),
            };
            info!("Uplink: src {}, iface {}, gateway {}", src, pin.device, gw);
            let verified = gw
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("gateway '{gw}' is not an IPv4 address"),
                    )
                })
                .and_then(|gw_ip| pin::probe_source_ip(gw_ip, &pin));
            match verified {
                Ok(_) => info!("Egress pin verified (pinned route to {} works)", gw),
                Err(e) => warn!(
                    "EGRESS PIN VERIFICATION FAILED ({e}): pinned outbound sockets will \
                     likely fail with 'unreachable host' — iface {} may not be the \
                     active uplink",
                    pin.device
                ),
            }
            (pin, gw)
        }
        Err(e) => {
            warn!(
                "Could not discover uplink ({e}); egress unpinned — outbound sockets \
                 will follow the hijacked routing table and may loop"
            );
            (EgressPin { ifindex: 0, device: String::new(), src: None }, String::new())
        }
    };
    // Choose the exit: a WireGuard peer (BYO, e.g. Proton) if configured, else
    // Direct out the host's uplink. Both pin egress to `egress`.
    let (outbound, exit_label): (Arc<dyn Outbound>, String) = match &settings.wireguard {
        Some(wg) => {
            let cfg = crate::wg::WgConfig::from_settings(wg)?;
            let label = format!("WireGuard → {}", wg.endpoint);
            info!("Exit: {}", label);
            (Arc::new(crate::wg::WireGuard::start(cfg, egress.clone())?), label)
        }
        None => {
            info!("Exit: Direct (host uplink)");
            (Arc::new(Direct::new(egress.clone())), "Direct (uplink)".to_string())
        }
    };

    // Publish status for the dashboard.
    if let Ok(mut st) = shared.status.lock() {
        st.running = true;
        st.exit = exit_label;
        st.full_tunnel = install_route;
        st.started_at = Some(std::time::Instant::now());
    }

    // Bring up the TUN and keep the adapter alive for the session.
    let tun = TunIo::new(settings.tun_ip, settings.tun_prefix, settings.mtu)
        .context("failed to create TUN device")?;
    let (name, mut rx, tx, _tun_keepalive) = tun.into_parts();
    info!("TUN '{}' up at {}/{}", name, settings.tun_ip, settings.tun_prefix);

    // Optionally redirect the default route into the TUN (full capture).
    let _route_guard = if install_route {
        let gateway = FullTunnel::default_gateway_for(settings.tun_ip);
        // Loopback server_ip skips the host-route step: the loop-break here is
        // egress pinning (Direct), not a host route to a tunnel server.
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
                // Force DNS through the tunnel so lookups don't leak to a LAN
                // resolver the exit can't reach.
                match route::set_tun_dns(&name, settings.dns) {
                    Ok(()) => info!("DNS pinned to {} through the tunnel", settings.dns),
                    Err(e) => warn!("Could not set tunnel DNS ({e}); set it manually to {}", settings.dns),
                }
                Some(guard)
            }
            Err(e) => {
                warn!("Route install failed ({e}); continuing without capture");
                None
            }
        }
    } else {
        warn!("Running WITHOUT --route: the default route is untouched, so no host \
               traffic is captured. Pass --route to tunnel all traffic.");
        None
    };

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
    let mut conn = ConnManager::new(outbound);
    // Downstream waker: outbound tasks signal this the instant server bytes are
    // available, so the loop services them immediately instead of on a timer.
    let wake = conn.waker();

    // Throughput ticker (advances the observability series ~1 Hz), plus
    // exit-boundary rates. `traffic:` counts at the TUN tap; `exit io:` counts
    // at the real outbound sockets. Divergence localizes loss to a hop:
    //   exit read >> traffic down → bytes die inside our stack (smoltcp's log
    //                               feature now states the drop reason);
    //   exit read ~ 0 mid-transfer → server paused: our kernel window closed
    //                               because the app isn't ACKing — the TUN→app
    //                               delivery hop is the suspect.
    {
        let m = monitor.clone();
        let stats = conn.stats();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(1));
            let (mut prev_read, mut prev_written) = (0u64, 0u64);
            loop {
                iv.tick().await;
                m.tick();
                let s = m.snapshot();
                if s.rate_up > 0.0 || s.rate_down > 0.0 {
                    info!(
                        "traffic: up {:.0} B/s, down {:.0} B/s, flows {}",
                        s.rate_up, s.rate_down, s.active_flows
                    );
                }
                let read = stats.read.load(Ordering::Relaxed);
                let written = stats.written.load(Ordering::Relaxed);
                let dr = read.saturating_sub(prev_read);
                let dw = written.saturating_sub(prev_written);
                prev_read = read;
                prev_written = written;
                if dr > 0 || dw > 0 {
                    info!("exit io: read {} B/s, wrote {} B/s", dr, dw);
                }
            }
        });
    }

    info!("Engine running. Ctrl-C to stop and restore routing.");

    // Event-driven poll loop. Wake on: a TUN packet (upstream), the downstream
    // waker (server bytes arrived), smoltcp's poll_delay (retransmit /
    // delayed-ACK timers), a periodic shutdown check, or Ctrl-C. The timer arm
    // is now only smoltcp's protocol timers — never the data path.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut shutdown_check = tokio::time::interval(Duration::from_millis(200));
    loop {
        let delay = iface
            .poll_delay(Instant::now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(200))
            .min(Duration::from_millis(200));

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
                        // Opportunistically drain a burst so one wake amortizes many packets.
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
            _ = wake.notified() => {}
            _ = shutdown_check.tick() => {
                if shared.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    info!("Dashboard closed — restoring routing");
                    break;
                }
            }
            _ = tokio::time::sleep(delay) => {}
        }

        let now = Instant::now();
        iface.poll(now, &mut device, &mut sockets);
        if !flush_tun(&mut device, &tx, &monitor).await {
            break;
        }
        conn.dispatch(&mut sockets);
        // Second poll flushes anything dispatch queued into the sockets.
        iface.poll(Instant::now(), &mut device, &mut sockets);
        if !flush_tun(&mut device, &tx, &monitor).await {
            break;
        }
    }

    // Session flow data → CSV: everything the monitor saw, including flows
    // evicted from the live table mid-session. Written next to the executable
    // (the process CWD is unpredictable for a double-clicked GUI app and may
    // not be writable); timestamped so sessions never clobber each other.
    let csv_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let csv_path = csv_dir.join(format!(
        "flows-{}.csv",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    match monitor.write_csv(&csv_path) {
        Ok(n) => info!("flow table written to {} ({} flows)", csv_path.display(), n),
        Err(e) => warn!("could not write flow CSV {}: {}", csv_path.display(), e),
    }

    Ok(())
}
