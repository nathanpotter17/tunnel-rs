//! Full-tunnel routing with safe teardown.

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

use crate::preflight::DnsBackend;

/// An installed full-tunnel route set. Restores the previous routing on drop.
pub struct FullTunnel {
    server_ip: IpAddr,
    tun_ip: Ipv4Addr,
    tun_gateway: Ipv4Addr,
    /// Original default gateway, saved so the host route can be pinned to it.
    orig_gateway: String,
    /// OS interface index of the TUN (Windows) / interface name (Unix).
    tun_iface: String,
    orig_iface: String,
    installed: bool,
}

impl FullTunnel {
    /// Compute the conventional tunnel gateway (`.1` of the TUN's /24), unless
    /// the TUN itself owns that address.
    pub fn default_gateway_for(tun_ip: Ipv4Addr) -> Ipv4Addr {
        let o = tun_ip.octets();
        let gw = Ipv4Addr::new(o[0], o[1], o[2], 1);
        if gw == tun_ip {
            Ipv4Addr::new(o[0], o[1], o[2], 254)
        } else {
            gw
        }
    }

    /// Install the full-tunnel routes. `server_ip` is the tunnel server's real
    /// (untunneled) IP; `tun_name` is the TUN interface name; `tun_ip` is our
    /// address on the tunnel; `tun_gateway` is the next hop on the tunnel.
    /// `orig_gateway`/`orig_iface` are the discovered uplink (see
    /// [`discover_uplink`]) — passed in, not re-derived, so the host-route pin
    /// and the egress socket pin can never disagree about which uplink is real.
    pub fn install(
        server_ip: IpAddr,
        tun_name: &str,
        tun_ip: Ipv4Addr,
        tun_gateway: Ipv4Addr,
        orig_gateway: &str,
        orig_iface: &str,
    ) -> Result<Self> {
        let tun_iface = platform::iface_id(tun_name, tun_ip)
            .context("could not resolve TUN interface id")?;

        info!(
            "Full tunnel: original default via {} (iface {}), TUN {} via {} (iface {})",
            orig_gateway, orig_iface, tun_ip, tun_gateway, tun_iface
        );

        let mut ft = FullTunnel {
            server_ip,
            tun_ip,
            tun_gateway,
            orig_gateway: orig_gateway.to_string(),
            tun_iface,
            orig_iface: orig_iface.to_string(),
            installed: false,
        };
        ft.apply()?;
        ft.installed = true;
        info!("Full tunnel routing active — all traffic now flows through the tunnel");
        Ok(ft)
    }

    fn apply(&self) -> Result<()> {
        // Skip the loop-protection host route for loopback/private test servers
        // that are already reachable without touching the default route.
        if !is_loopback_or_unspecified(self.server_ip) {
            platform::add_host_route(self.server_ip, &self.orig_gateway, &self.orig_iface)
                .with_context(|| format!("failed to pin host route for server {}", self.server_ip))?;
        }
        platform::add_default_via_tun(self.tun_ip, self.tun_gateway, &self.tun_iface)
            .context("failed to redirect default route into the tunnel")?;
        Ok(())
    }

    fn teardown(&self) {
        if !self.installed {
            return;
        }
        platform::remove_default_via_tun(self.tun_gateway, &self.tun_iface);
        if !is_loopback_or_unspecified(self.server_ip) {
            platform::remove_host_route(self.server_ip);
        }
        info!("Full tunnel routing removed — original networking restored");
    }
}

impl Drop for FullTunnel {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn is_loopback_or_unspecified(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// The uplink as the OS actually forwards RIGHT NOW: `(source ip, interface
/// id, gateway ip)`. Derived from the OS's own forwarding decision for a real
/// destination — never from sorting route listings. Sorting `Get-NetRoute` by
/// RouteMetric alone once selected a defunct interface (Windows' effective
/// metric is RouteMetric + InterfaceMetric, and disconnected/virtual adapters
/// keep 0.0.0.0/0 entries), which made every pinned outbound connect fail
/// WSAEHOSTUNREACH. Must be called BEFORE the default route is hijacked.
pub fn discover_uplink() -> Result<(Ipv4Addr, String, String)> {
    platform::uplink()
}

/// The TUN's platform interface id — name on Unix, ifindex on Windows, matching
/// the EgressPin convention. The tripwire needs it to know which interface all
/// public traffic must egress.
pub fn interface_id(tun_name: &str, tun_ip: Ipv4Addr) -> Result<String> {
    platform::iface_id(tun_name, tun_ip)
}

/// The resolver, pinned to the tunnel for the session and restored on drop.
///
/// A guard, not a fire-and-forget setting, because under full capture the kill
/// switch drops unmarked traffic out the uplink — which includes every DNS query
/// to a LAN resolver. Moving the resolver onto the TUN is therefore PART of the
/// capture, and leaving a rewritten resolver behind after exit would strand the
/// host pointing at a server only reachable through a tunnel that no longer
/// exists.
pub struct DnsGuard {
    inner: platform::Dns,
}

impl DnsGuard {
    /// Pin resolution for `tun_name` to `server` using the backend preflight
    /// already resolved. Fails hard: a half-configured resolver under an armed
    /// kill switch is indistinguishable from a broken network.
    pub fn install(tun_name: &str, server: Ipv4Addr, backend: DnsBackend) -> Result<Self> {
        let inner = platform::install_dns(tun_name, server, backend)?;
        info!("DNS pinned to {} through the tunnel ({:?})", server, backend);
        Ok(Self { inner })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        platform::revert_dns(&mut self.inner);
    }
}

/// Run a command, returning an error carrying stderr on non-zero exit.
fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn `{}`", program))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "`{} {}` failed: {}{}",
            program,
            args.join(" "),
            stderr.trim(),
            stdout.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Best-effort variant that logs instead of propagating (used in teardown).
fn run_quiet(program: &str, args: &[&str]) {
    if let Err(e) = run(program, args) {
        warn!("route teardown: {}", e);
    }
}

// ============================================================================
// Windows
// ============================================================================

#[cfg(windows)]
mod platform {
    use super::*;

    fn powershell(cmd: &str) -> Result<String> {
        run("powershell", &["-NoProfile", "-NonInteractive", "-Command", cmd])
    }

    /// The functional uplink: source from the OS's own egress decision, index
    /// via the same IP→index query used for the TUN, gateway from THAT
    /// interface's default route (never a global metric sort).
    pub fn uplink() -> Result<(Ipv4Addr, String, String)> {
        let src = crate::pin::os_default_source()
            .context("OS reports no default egress (is the network up?)")?;
        let idx = iface_id("", src)
            .with_context(|| format!("no interface owns egress source {}", src))?;
        let out = powershell(&format!(
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 \
             -InterfaceIndex {} | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
            idx
        ))?;
        let gw = out.trim().lines().next().unwrap_or("").trim().to_string();
        if gw.is_empty() {
            return Err(anyhow!("no default route on uplink interface {}", idx));
        }
        Ok((src, idx, gw))
    }

    /// Interface index for the TUN, resolved from its assigned IP.
    pub fn iface_id(_name: &str, tun_ip: Ipv4Addr) -> Result<String> {
        let out = powershell(&format!(
            "(Get-NetIPAddress -IPAddress {} -AddressFamily IPv4).InterfaceIndex",
            tun_ip
        ))?;
        let idx = out.trim().lines().next().unwrap_or("").trim().to_string();
        if idx.is_empty() {
            return Err(anyhow!("TUN interface index not found for {}", tun_ip));
        }
        Ok(idx)
    }

    pub fn add_host_route(server: IpAddr, gateway: &str, iface: &str) -> Result<()> {
        run(
            "route",
            &["add", &server.to_string(), "mask", "255.255.255.255", gateway, "if", iface, "metric", "1"],
        )
        .map(|_| ())
    }

    pub fn remove_host_route(server: IpAddr) {
        run_quiet("route", &["delete", &server.to_string()]);
    }

    pub fn add_default_via_tun(_tun_ip: Ipv4Addr, gw: Ipv4Addr, iface: &str) -> Result<()> {
        let gw = gw.to_string();
        run("route", &["add", "0.0.0.0", "mask", "128.0.0.0", &gw, "if", iface, "metric", "1"])?;
        run("route", &["add", "128.0.0.0", "mask", "128.0.0.0", &gw, "if", iface, "metric", "1"])?;
        Ok(())
    }

    pub fn remove_default_via_tun(_gw: Ipv4Addr, _iface: &str) {
        run_quiet("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
        run_quiet("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
    }

    /// Windows has one mechanism: a static per-adapter resolver set with netsh.
    /// There is no backend choice to make, so the parameter is accepted and
    /// ignored rather than branched on.
    pub struct Dns;

    pub fn install_dns(tun_name: &str, server: Ipv4Addr, _backend: DnsBackend) -> Result<Dns> {
        run(
            "netsh",
            &[
                "interface", "ipv4", "set", "dnsservers",
                &format!("name={}", tun_name),
                "static", &server.to_string(), "primary",
            ],
        )
        .with_context(|| format!("could not pin DNS on adapter '{tun_name}'"))?;
        Ok(Dns)
    }

    /// The setting lives on the adapter; removing the adapter removes it. There
    /// is nothing to undo, and a netsh call against an interface that may
    /// already be gone would only log a spurious failure.
    pub fn revert_dns(_dns: &mut Dns) {}
}

// ============================================================================
// Unix (Linux) — used for a Linux client or a local VM/WSL dev loop
// ============================================================================

#[cfg(unix)]
mod platform {
    use super::*;

    /// The functional uplink, from the kernel's own forwarding decision:
    /// `ip route get` answers with gateway, device, and source in one shot —
    /// e.g. "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 0".
    pub fn uplink() -> Result<(Ipv4Addr, String, String)> {
        let out = run("ip", &["route", "get", "8.8.8.8"])?;
        let toks: Vec<&str> = out.split_whitespace().collect();
        let after = |key: &str| {
            toks.iter()
                .position(|t| *t == key)
                .and_then(|i| toks.get(i + 1))
                .map(|s| s.to_string())
        };
        let gw = after("via").ok_or_else(|| anyhow!("no gateway in: {}", out.trim()))?;
        let dev = after("dev").ok_or_else(|| anyhow!("no device in: {}", out.trim()))?;
        let src = after("src")
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| anyhow!("no source in: {}", out.trim()))?;
        Ok((src, dev, gw))
    }

    pub fn iface_id(name: &str, _tun_ip: Ipv4Addr) -> Result<String> {
        Ok(name.to_string())
    }

    pub fn add_host_route(server: IpAddr, gateway: &str, iface: &str) -> Result<()> {
        run(
            "ip",
            &["route", "add", &format!("{}/32", server), "via", gateway, "dev", iface],
        )
        .map(|_| ())
    }

    pub fn remove_host_route(server: IpAddr) {
        run_quiet("ip", &["route", "del", &format!("{}/32", server)]);
    }

    pub fn add_default_via_tun(_tun_ip: Ipv4Addr, gw: Ipv4Addr, iface: &str) -> Result<()> {
        let gw = gw.to_string();
        run("ip", &["route", "add", "0.0.0.0/1", "via", &gw, "dev", iface])?;
        run("ip", &["route", "add", "128.0.0.0/1", "via", &gw, "dev", iface])?;
        Ok(())
    }

    pub fn remove_default_via_tun(_gw: Ipv4Addr, _iface: &str) {
        run_quiet("ip", &["route", "del", "0.0.0.0/1"]);
        run_quiet("ip", &["route", "del", "128.0.0.0/1"]);
    }

    const RESOLV_CONF: &str = "/etc/resolv.conf";
    /// systemd-resolved learns links from rtnetlink; the TUN can be visible to
    /// us a few milliseconds before it is visible to resolved.
    const RESOLVED_LINK_RETRIES: u32 = 20;
    const RESOLVED_LINK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

    /// What the resolver looked like before we touched it.
    pub enum Restore {
        Symlink(std::path::PathBuf),
        Contents(Vec<u8>),
        Absent,
    }

    pub enum Dns {
        Resolved { link: String },
        ResolvConf { restore: Restore },
    }

    pub fn install_dns(tun_name: &str, server: Ipv4Addr, backend: DnsBackend) -> Result<Dns> {
        match backend {
            DnsBackend::SystemdResolved => install_resolved(tun_name, server),
            DnsBackend::ResolvConf => install_resolv_conf(server),
        }
    }

    fn install_resolved(link: &str, server: Ipv4Addr) -> Result<Dns> {
        let server = server.to_string();
        let mut last: Option<anyhow::Error> = None;
        for _ in 0..RESOLVED_LINK_RETRIES {
            match run("resolvectl", &["dns", link, &server]) {
                Ok(_) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(RESOLVED_LINK_BACKOFF);
                }
            }
        }
        if let Some(e) = last {
            return Err(e).with_context(|| {
                format!("systemd-resolved never saw the tunnel interface '{link}'")
            });
        }

        // `~.` is the whole point. Per-link servers alone leave the UPLINK link
        // also eligible for every query, so resolved fans out to a LAN resolver
        // whose packets the kill switch then drops — a resolver that half-works,
        // intermittently, with no error anywhere. The default routing domain
        // makes the tunnel the only eligible scope.
        run("resolvectl", &["domain", link, "~."])
            .with_context(|| format!("could not make '{link}' the default DNS route"))?;
        run("resolvectl", &["default-route", link, "yes"])
            .with_context(|| format!("could not set default-route on '{link}'"))?;
        // Answers cached against the pre-tunnel resolver must not survive the
        // switch — they were resolved on a path we are about to forbid.
        let _ = run("resolvectl", &["flush-caches"]);
        Ok(Dns::Resolved { link: link.to_string() })
    }

    fn install_resolv_conf(server: Ipv4Addr) -> Result<Dns> {
        let path = std::path::Path::new(RESOLV_CONF);
        let restore = match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = std::fs::read_link(path)
                    .with_context(|| format!("reading symlink {RESOLV_CONF}"))?;
                std::fs::remove_file(path)
                    .with_context(|| format!("replacing symlink {RESOLV_CONF}"))?;
                Restore::Symlink(target)
            }
            Ok(_) => Restore::Contents(
                std::fs::read(path).with_context(|| format!("reading {RESOLV_CONF}"))?,
            ),
            Err(_) => Restore::Absent,
        };
        let body = format!(
            "# Written by tunnel while the full tunnel is active.\n\
             # The previous configuration is restored when tunnel exits.\n\
             nameserver {server}\n\
             options edns0 trust-ad\n"
        );
        if let Err(e) = std::fs::write(path, body) {
            // Put back what we removed BEFORE reporting, or the host is left
            // with no resolver at all because of our own failed edit.
            let mut half = Dns::ResolvConf { restore };
            revert_dns(&mut half);
            return Err(e).with_context(|| {
                format!("could not write {RESOLV_CONF} (immutable? `lsattr {RESOLV_CONF}`)")
            });
        }
        Ok(Dns::ResolvConf { restore })
    }

    pub fn revert_dns(dns: &mut Dns) {
        match dns {
            // `revert` clears servers, domains and the default-route flag in one
            // call. The link usually disappears with the TUN a moment later, but
            // reverting explicitly keeps teardown independent of that ordering.
            Dns::Resolved { link } => run_quiet("resolvectl", &["revert", link]),
            Dns::ResolvConf { restore } => {
                let path = std::path::Path::new(RESOLV_CONF);
                let outcome = match std::mem::replace(restore, Restore::Absent) {
                    Restore::Symlink(target) => {
                        let _ = std::fs::remove_file(path);
                        std::os::unix::fs::symlink(&target, path)
                    }
                    Restore::Contents(bytes) => std::fs::write(path, bytes),
                    Restore::Absent => std::fs::remove_file(path),
                };
                match outcome {
                    Ok(()) => info!("resolver restored ({RESOLV_CONF})"),
                    Err(e) => warn!(
                        "could not restore {RESOLV_CONF}: {e} — set a nameserver \
                         manually or restart your network manager"
                    ),
                }
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use super::*;
    pub fn uplink() -> Result<(Ipv4Addr, String, String)> {
        Err(anyhow!("full-tunnel routing not supported on this platform"))
    }
    pub fn iface_id(_name: &str, _tun_ip: Ipv4Addr) -> Result<String> {
        Err(anyhow!("unsupported platform"))
    }
    pub fn add_host_route(_s: IpAddr, _g: &str, _i: &str) -> Result<()> { Ok(()) }
    pub fn remove_host_route(_s: IpAddr) {}
    pub fn add_default_via_tun(_t: Ipv4Addr, _g: Ipv4Addr, _i: &str) -> Result<()> { Ok(()) }
    pub fn remove_default_via_tun(_g: Ipv4Addr, _i: &str) {}
    pub struct Dns;
    pub fn install_dns(_n: &str, _s: Ipv4Addr, _b: DnsBackend) -> Result<Dns> {
        Err(anyhow!("setting tunnel DNS not supported on this platform"))
    }
    pub fn revert_dns(_d: &mut Dns) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_derivation() {
        assert_eq!(
            FullTunnel::default_gateway_for(Ipv4Addr::new(10, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 1)
        );
        // If the TUN owns .1, fall back to .254 so gateway != self.
        assert_eq!(
            FullTunnel::default_gateway_for(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 254)
        );
    }
}
