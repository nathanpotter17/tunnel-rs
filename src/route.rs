//! Full-tunnel routing with safe teardown.
//!
//! Installing a full tunnel means redirecting the host's default route into the
//! TUN interface so every application's traffic is captured, while keeping the
//! encrypted tunnel itself reachable. Concretely we:
//!
//! 1. Record the current default gateway (so we can restore it).
//! 2. Pin a host route to the tunnel *server's real IP* via that original
//!    gateway, so the encrypted UDP packets don't loop back into the TUN.
//! 3. Add two half-default routes (`0.0.0.0/1` and `128.0.0.0/1`) via the TUN.
//!    Two /1 routes beat the existing `0.0.0.0/0` default on longest-prefix
//!    match without deleting it — the classic WireGuard trick — so teardown is
//!    just removing our routes, leaving the original default intact.
//!
//! [`FullTunnel`] is an RAII guard: dropping it (on Ctrl-C, error, or normal
//! exit) tears the routes back down. Requires administrator/root, which the app
//! already needs to create the TUN device.

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

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

/// Pin DNS resolution for the tunnel interface to `server`, so lookups egress
/// through the tunnel instead of leaking to a LAN resolver the exit can't reach.
/// Scoped to the TUN interface (not global) — global resolver edits wouldn't
/// bind DNS to the tunnel path.
pub fn set_tun_dns(tun_name: &str, server: Ipv4Addr) -> Result<()> {
    platform::set_dns(tun_name, server)
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

    /// Set the TUN adapter's DNS server statically, addressing the interface by
    /// its friendly name (the same name used to create the wintun adapter).
    pub fn set_dns(tun_name: &str, server: Ipv4Addr) -> Result<()> {
        run(
            "netsh",
            &[
                "interface", "ipv4", "set", "dnsservers",
                &format!("name={}", tun_name),
                "static", &server.to_string(), "primary",
            ],
        )
        .map(|_| ())
    }
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

    /// Bind DNS to the tunnel interface via systemd-resolved. Per-interface
    /// resolution is exactly what pinning DNS to the tunnel requires — a global
    /// resolv.conf edit wouldn't scope lookups to the TUN egress path.
    pub fn set_dns(tun_name: &str, server: Ipv4Addr) -> Result<()> {
        run("resolvectl", &["dns", tun_name, &server.to_string()]).map(|_| ())
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
    pub fn set_dns(_n: &str, _s: Ipv4Addr) -> Result<()> {
        Err(anyhow!("setting tunnel DNS not supported on this platform"))
    }
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
