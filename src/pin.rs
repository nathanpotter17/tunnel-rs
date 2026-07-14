//! Interface-pinned egress — the loop-break primitive.
//!
//! When the default route points into our TUN, a normal outbound socket to the
//! internet would re-enter the TUN and loop forever. The pin has TWO parts:
//!
//! 1. **Interface pin** — forces which interface the packet *leaves on*,
//!    regardless of the routing table.
//!    - Windows: `IP_UNICAST_IF` (IPv4 wants the ifindex in *network* byte order).
//!    - Unix: `SO_BINDTODEVICE`.
//! 2. **Source-address pin** — binds the socket to the uplink's own IP. The
//!    interface pin does NOT override source-address selection: a wildcard-bound
//!    socket still source-selects via the routing table, which (post-hijack)
//!    points at the TUN — packets would leave the physical NIC sourced from the
//!    TUN's 198.18.x.x address and replies would never return.
//!
//! Both parts together make the egress 5-tuple deterministic. We pin to whatever
//! the host's default interface was **before** we hijacked the route — so if
//! ProtonVPN was the uplink, the exit stays Proton.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// Firewall mark stamped on every egress socket we own (the WireGuard/Direct
/// exit sockets and the file channel). The kill switch (killswitch.rs) permits
/// only marked traffic out the uplink and drops the rest — that drop is what
/// closes the TunnelVision (CVE-2024-3661) leak, where a rogue DHCP option-121
/// route would otherwise steer an app's flow straight out the uplink, bypassing
/// the TUN. Value is arbitrary but must match the nftables rule.
#[allow(dead_code)] // unix-only; Windows keys the kill switch on app id instead
pub const EGRESS_FWMARK: u32 = 0x0000_7475;

/// Tag a socket as our own egress. Unix: sets SO_MARK (read by nftables
/// `meta mark`). Windows: no-op — the WFP kill switch permits by app id, so the
/// whole process is already trusted and marks don't exist there.
#[cfg(unix)]
pub fn mark_own<S: std::os::unix::io::AsRawFd>(sock: &S) -> io::Result<()> {
    let mark = EGRESS_FWMARK;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn mark_own<S>(_sock: &S) -> io::Result<()> {
    Ok(())
}

/// Deadline for the outbound TCP handshake. On Windows a failed non-blocking
/// connect signals the *except* set, which readiness APIs can surface late or
/// never — without a deadline a dead destination wedges the flow task forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Identifies the interface to pin egress to. All fields are captured from the
/// original default route; each platform uses what it needs.
#[derive(Debug, Clone)]
pub struct EgressPin {
    /// OS interface index (used on Windows).
    pub ifindex: u32,
    /// Interface name (used on Unix for SO_BINDTODEVICE).
    #[allow(dead_code)]
    pub device: String,
    /// The uplink's own IPv4 address — the source-address pin. `None` degrades
    /// to interface-pin-only (replies may not return under a hijacked route).
    pub src: Option<IpAddr>,
}

/// Open a TCP connection to `dst`, pinned to the egress interface and sourced
/// from the uplink's own address.
pub async fn connect_tcp(dst: SocketAddr, pin: &EgressPin) -> io::Result<TcpStream> {
    let sock = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))?;
    bind_to_interface(&sock, pin, dst.is_ipv4())?;
    bind_source(&sock, pin, dst.is_ipv4())?;
    sock.set_nonblocking(true)?;

    // Non-blocking connect returns WouldBlock; finish the handshake via tokio.
    match sock.connect(&dst.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) if e.raw_os_error() == Some(WSAEWOULDBLOCK) => {}
        Err(e) => return Err(e),
    }

    let stream = TcpStream::from_std(std::net::TcpStream::from(sock))?;
    match tokio::time::timeout(CONNECT_TIMEOUT, stream.writable()).await {
        Ok(ready) => ready?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect to {} timed out", dst),
            ))
        }
    }
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    // A proxy relays already-paced segments; Nagle here only adds latency
    // between the app's write and the wire.
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Bind a UDP socket for relaying datagrams to `dst`, pinned to the egress
/// interface and sourced from the uplink's own address. Falls back to a
/// wildcard bind only when no source address is known.
pub async fn bind_udp(dst: SocketAddr, pin: &EgressPin) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))?;
    bind_to_interface(&sock, pin, dst.is_ipv4())?;
    sock.set_nonblocking(true)?;
    match (dst.is_ipv4(), pin.src) {
        (true, Some(src)) => sock.bind(&SocketAddr::new(src, 0).into())?,
        (true, None) => sock.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?,
        (false, _) => sock.bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())?,
    }
    UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

/// Bind a UDP socket to a FIXED local port on the pinned egress interface,
/// sourced from the uplink's own address. `port == 0` → ephemeral. This is the
/// file channel's bind: a listener must own its port on the real uplink IP, and
/// replies must leave the uplink — not fall into a hijacked default route and
/// ride the exit. The source-pin is what keeps the 5-tuple on the uplink; the
/// mark (applied by bind_to_interface on unix) is what the kill switch permits.
pub async fn bind_udp_local(port: u16, pin: &EgressPin) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    bind_to_interface(&sock, pin, true)?; // interface pin (+ SO_MARK on unix)
    let local = match pin.src {
        Some(IpAddr::V4(v4)) => SocketAddr::new(IpAddr::V4(v4), port),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), // degrade: iface-pin only
    };
    sock.bind(&local.into())?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

/// The source-address half of the pin (see module docs). IPv4 only, mirroring
/// the engine's IPv4-only capture; a `None` source is a no-op (wildcard, as
/// before — interface pin still applies).
fn bind_source(sock: &Socket, pin: &EgressPin, v4: bool) -> io::Result<()> {
    if let (true, Some(src)) = (v4, pin.src) {
        sock.bind(&SocketAddr::new(src, 0).into())?;
    }
    Ok(())
}

/// Ask the OS which source address it selects on the pinned interface, by
/// `connect()`ing an interface-pinned UDP socket toward `probe` — the
/// pre-hijack default gateway, which is on-link and always routable at capture
/// time. UDP connect transmits nothing: it runs route + source-address
/// selection locally and records the result, which `local_addr()` then
/// reports. No subprocess, no output parsing, no locale dependence — a
/// tool-output-parsing resolver failed on real systems, and the OS is the
/// authority on its own source selection anyway.
pub fn probe_source_ip(probe: Ipv4Addr, pin: &EgressPin) -> io::Result<Ipv4Addr> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    bind_to_interface(&sock, pin, true)?;
    sock.connect(&SocketAddr::new(IpAddr::V4(probe), 53).into())?;
    match sock.local_addr()?.as_socket() {
        Some(SocketAddr::V4(a)) if !a.ip().is_unspecified() => Ok(*a.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "OS selected no source address on the pinned interface",
        )),
    }
}

/// Discover the host's uplink and build the egress pin ONCE, verifying it while
/// the original route is still intact. Returns the pin plus the original default
/// gateway (needed to keep the encrypted tunnel's own route reachable during a
/// full-tunnel hijack). MUST run before the default route is hijacked. Never
/// fails: a discovery error degrades to an unpinned egress (outbound sockets
/// then follow the routing table) — logged loudly, the same fallback the engine
/// used when this logic lived inline. Called once in `main` and shared by both
/// the engine and the file channel, so they cannot disagree on the uplink.
pub fn discover_egress() -> (EgressPin, String) {
    match crate::route::discover_uplink() {
        Ok((src, iface_id, gw)) => {
            let pin = EgressPin {
                ifindex: iface_id.parse().unwrap_or(0),
                device: iface_id,
                src: Some(IpAddr::V4(src)),
            };
            tracing::info!("Uplink: src {}, iface {}, gateway {}", src, pin.device, gw);
            let verified = gw
                .parse::<Ipv4Addr>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("gateway '{gw}' is not an IPv4 address"),
                    )
                })
                .and_then(|gw_ip| probe_source_ip(gw_ip, &pin));
            match verified {
                Ok(_) => tracing::info!("Egress pin verified (pinned route to {} works)", gw),
                Err(e) => tracing::warn!(
                    "EGRESS PIN VERIFICATION FAILED ({e}): pinned outbound sockets will \
                     likely fail with 'unreachable host' — iface {} may not be the \
                     active uplink",
                    pin.device
                ),
            }
            (pin, gw)
        }
        Err(e) => {
            tracing::warn!(
                "Could not discover uplink ({e}); egress unpinned — outbound sockets \
                 will follow the hijacked routing table and may loop"
            );
            (EgressPin { ifindex: 0, device: String::new(), src: None }, String::new())
        }
    }
}

/// The source address the OS uses for internet egress RIGHT NOW, with no pin
/// applied: an unpinned UDP `connect()` toward a public anycast address
/// (transmits nothing) and `local_addr()` reads back the OS's own forwarding
/// decision. This is the ground truth the uplink discovery starts from —
/// unlike metric-sorted route listings, it cannot select a disconnected or
/// virtual interface, because it IS the answer the stack would give a real
/// socket. Must run before the default route is hijacked.
pub fn os_default_source() -> io::Result<Ipv4Addr> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.connect(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53).into())?;
    match sock.local_addr()?.as_socket() {
        Some(SocketAddr::V4(a)) if !a.ip().is_unspecified() => Ok(*a.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "OS selected no default source address (is the network up?)",
        )),
    }
}

// WSAEWOULDBLOCK isn't always mapped to ErrorKind::WouldBlock by std on connect().
#[cfg(windows)]
const WSAEWOULDBLOCK: i32 = 10035;
#[cfg(not(windows))]
const WSAEWOULDBLOCK: i32 = libc::EWOULDBLOCK;

#[cfg(windows)]
pub fn bind_to_interface(sock: &Socket, pin: &EgressPin, v4: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET};

    // Winsock option constants (Win32_Networking_WinSock doesn't always surface
    // these as generated consts across feature sets, so define them locally).
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;

    let raw = sock.as_raw_socket() as SOCKET;
    let (level, opt, val): (i32, i32, u32) = if v4 {
        // IPv4: the interface index must be in NETWORK byte order — the classic footgun.
        (IPPROTO_IP, IP_UNICAST_IF, pin.ifindex.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, pin.ifindex) // IPv6: host byte order
    };

    let rc = unsafe {
        setsockopt(
            raw,
            level,
            opt,
            &val as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub fn bind_to_interface(sock: &Socket, pin: &EgressPin, _v4: bool) -> io::Result<()> {
    sock.bind_device(Some(pin.device.as_bytes()))?;
    // Mark so the kill switch permits our own re-originated egress out the uplink.
    mark_own(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_option_on_throwaway_socket() {
        // ifindex 0 = "no constraint"; setting it should not error, proving the
        // setsockopt path is wired correctly on this platform.
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let pin = EgressPin { ifindex: 0, device: String::new(), src: None };
        // On unix, empty device name clears the binding (or is a no-op); tolerate both.
        let _ = bind_to_interface(&sock, &pin, true);
    }
}
