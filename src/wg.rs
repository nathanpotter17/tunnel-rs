//! WireGuard outbound — userspace WireGuard (boringtun) + an inner smoltcp stack.
//!
//! Flows routed here are originated *from the WireGuard client address* toward the
//! real destination through an inner smoltcp stack, encrypted by boringtun, and
//! sent as UDP to the WG endpoint (e.g. Proton). The endpoint socket is pinned to
//! the physical uplink so the encrypted packets don't loop back into our TUN.
//!
//! A single driver task owns the `Tunn`, the endpoint UDP socket, and the inner
//! stack. `connect_tcp`/`bind_udp` message it to open a flow and hand back a
//! channel-bridged stream (the sync poll loop talks to async callers via channels).

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context as TaskCx, Poll};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tracing::{debug, error};

use crate::outbound::{Outbound, UdpConn};
use crate::pin::{self, EgressPin};
use crate::settings::WgSettings;

/// Inner-stack TCP window for the WireGuard leg. Unlike the `Direct` exit — whose
/// OS kernel socket the OS receive-window-autotunes — THIS smoltcp buffer *is* the
/// WAN receive window for the encrypted path, so it is sized for the WAN
/// bandwidth-delay product, NOT the ~0-RTT app leg. Do not shrink it to match
/// conn.rs's app-leg window (`conn::APP_LEG_TCP_WINDOW`): that would cap
/// single-stream throughput over WireGuard. See the sizing agreement below.
const TCP_BUF: usize = 2 * 1024 * 1024;
const UDP_PAYLOAD_BUF: usize = 64 * 1024;
const UDP_META: usize = 32;
const SCRATCH: usize = 65535;

// Sizing agreement between the two legs of the split-TCP proxy. The app-leg
// window (conn.rs) and this WAN-leg window are intentionally different sizes for
// different hops; this check only pins their RELATIONSHIP — the WireGuard leg must
// never be the smaller window, or it becomes the artificial single-stream
// bottleneck. A future edit to either constant that inverts this fails to compile.
const _: () = assert!(
    TCP_BUF >= crate::conn::APP_LEG_TCP_WINDOW,
    "wg.rs inner TCP window must be >= conn.rs app-leg window (APP_LEG_TCP_WINDOW)"
);

/// Inner-stack MTU. This is the MSS clamp: smoltcp derives the TCP MSS it
/// advertises to the destination from this, so responses never exceed what fits
/// through WireGuard's encapsulation. 1280 (IPv6 minimum) leaves generous room
/// for the WG (32) + UDP (8) + IP (20) headers and any reduced path MTU, which
/// avoids PMTU blackholes that would otherwise stall large transfers — PMTUD
/// doesn't propagate cleanly through a userspace double tunnel.
const INNER_MTU: usize = 1280;

/// Resolved WireGuard parameters.
pub struct WgConfig {
    private_key: [u8; 32],
    peer_public: [u8; 32],
    preshared: Option<[u8; 32]>,
    endpoint: SocketAddr,
    address: Ipv4Addr,
    keepalive: Option<u16>,
}

impl WgConfig {
    pub fn from_settings(s: &WgSettings) -> Result<Self> {
        let private_key = decode_key(&s.private_key).context("invalid wireguard private_key")?;
        let peer_public = decode_key(&s.public_key).context("invalid wireguard public_key")?;
        let preshared = match &s.preshared_key {
            Some(k) => Some(decode_key(k).context("invalid preshared_key")?),
            None => None,
        };
        let endpoint = s
            .endpoint
            .to_socket_addrs()
            .with_context(|| format!("cannot resolve wireguard endpoint {}", s.endpoint))?
            .next()
            .ok_or_else(|| anyhow!("wireguard endpoint resolved to nothing"))?;
        let address: Ipv4Addr = s.address.parse().context("invalid wireguard address")?;
        let keepalive = if s.persistent_keepalive > 0 {
            Some(s.persistent_keepalive)
        } else {
            None
        };
        Ok(Self { private_key, peer_public, preshared, endpoint, address, keepalive })
    }
}

fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s.trim()).context("base64 decode")?;
    bytes.try_into().map_err(|_| anyhow!("key must be 32 bytes"))
}

/// Requests to the driver to open a flow.
enum OpenReq {
    Tcp(SocketAddr, oneshot::Sender<io::Result<ChannelStream>>),
    Udp(SocketAddr, oneshot::Sender<io::Result<ChannelUdp>>),
}

pub struct WireGuard {
    req_tx: mpsc::Sender<OpenReq>,
}

impl WireGuard {
    pub fn start(config: WgConfig, egress: EgressPin) -> Result<Self> {
        let (req_tx, req_rx) = mpsc::channel(256);
        tokio::spawn(async move {
            if let Err(e) = driver(config, egress, req_rx).await {
                error!("wireguard driver stopped: {e}");
            }
        });
        Ok(Self { req_tx })
    }
}

#[async_trait]
impl Outbound for WireGuard {
    async fn connect_tcp(&self, dst: SocketAddr) -> Result<Box<dyn crate::outbound::AsyncStream>> {
        let (tx, rx) = oneshot::channel();
        self.req_tx
            .send(OpenReq::Tcp(dst, tx))
            .await
            .map_err(|_| anyhow!("wireguard driver unavailable"))?;
        let stream = rx.await.map_err(|_| anyhow!("wireguard driver dropped request"))??;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpConn>> {
        let (tx, rx) = oneshot::channel();
        self.req_tx
            .send(OpenReq::Udp(dst, tx))
            .await
            .map_err(|_| anyhow!("wireguard driver unavailable"))?;
        let conn = rx.await.map_err(|_| anyhow!("wireguard driver dropped request"))??;
        Ok(Box::new(conn))
    }

    fn name(&self) -> &str {
        "wireguard"
    }
}

// ============================================================================
// Driver
// ============================================================================

struct TcpBridge {
    handle: SocketHandle,
    from_app: mpsc::UnboundedReceiver<Vec<u8>>,
    to_app: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pending: VecDeque<u8>,
    app_eof: bool,
    established: bool,
}

struct UdpBridge {
    handle: SocketHandle,
    dst: IpEndpoint,
    from_app: mpsc::UnboundedReceiver<Vec<u8>>,
    to_app: mpsc::UnboundedSender<Vec<u8>>,
}

async fn driver(config: WgConfig, egress: EgressPin, mut req_rx: mpsc::Receiver<OpenReq>) -> Result<()> {
    // Encrypted UDP socket to the WG endpoint, pinned to the physical uplink so it
    // bypasses our own TUN default route.
    let udp = pin::bind_udp(config.endpoint, &egress).await?;
    udp.connect(config.endpoint).await?;

    let priv_key = StaticSecret::from(config.private_key);
    let peer = PublicKey::from(config.peer_public);
    let mut tunn = Tunn::new(priv_key, peer, config.preshared, config.keepalive, 0, None);

    // Inner smoltcp stack, addressed as the WG client.
    let (enc_tx, mut enc_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut device = InnerDevice::new(enc_tx);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::now());
    let a = config.address.octets();
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(a[0], a[1], a[2], a[3]), 32));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(a[0], a[1], a[2], a[3]));

    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_conns: Vec<TcpBridge> = Vec::new();
    let mut udp_conns: Vec<UdpBridge> = Vec::new();
    let mut next_port: u16 = 20000;

    let mut scratch = vec![0u8; SCRATCH];
    // replace wg.rs lines 186-247 (recv_buf decl through end of the driver `loop`)
    let mut recv_buf = vec![0u8; SCRATCH];

    // boringtun needs its timers advanced periodically (handshake/keepalive/rekey);
    // this is independent of data flow. `stat` is diagnostics only.
    let mut wg_timer = tokio::time::interval(Duration::from_millis(250));
    let mut stat = tokio::time::interval(Duration::from_secs(2));

    // Wake source for the app-write path: every ChannelStream/ChannelUdp write
    // signals this, so the driver services `from_app` immediately instead of on a
    // fixed tick. notify_one() coalesces bursts into a single wake (batching).
    let wake = Arc::new(Notify::new());

    // Diagnostics: bytes into/out of the tunnel and whether the peer ever replied.
    let mut enc_bytes: u64 = 0;
    let mut dec_bytes: u64 = 0;
    let mut session_logged = false;

    debug!("wireguard driver up; endpoint {}", config.endpoint);

    loop {
        // smoltcp tells us the longest we may sleep before it needs servicing
        // (retransmit / delayed-ACK timers). None → nothing pending; cap the idle
        // wait so wg_timer/shutdown still make progress. Zero → immediate re-poll.
        let delay = iface
            .poll_delay(Instant::now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(250))
            .min(Duration::from_millis(250));

        tokio::select! {
            maybe = req_rx.recv() => {
                match maybe {
                    Some(req) => open_flow(req, &mut iface, &mut sockets, &mut tcp_conns, &mut udp_conns, &mut next_port, &wake),
                    None => return Ok(()),
                }
            }
            r = udp.recv(&mut recv_buf) => {
                if let Ok(n) = r {
                    dec_bytes += decapsulate(&mut tunn, &recv_buf[..n], &mut scratch, &mut device, &udp).await as u64;
                }
            }
            _ = wake.notified() => {}
            _ = wg_timer.tick() => {
                if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut scratch) {
                    let out = p.to_vec();
                    let _ = udp.send(&out).await;
                }
            }
            _ = stat.tick() => {
                debug!("wireguard: enc {} B, dec {} B, tcp {}, udp {}", enc_bytes, dec_bytes, tcp_conns.len(), udp_conns.len());
            }
            _ = tokio::time::sleep(delay) => {}
        }

        // Drain any burst of further incoming WG datagrams so a busy return path
        // isn't serviced one-datagram-per-wakeup.
        loop {
            match udp.try_recv(&mut recv_buf) {
                Ok(n) => {
                    dec_bytes += decapsulate(&mut tunn, &recv_buf[..n], &mut scratch, &mut device, &udp).await as u64;
                }
                Err(_) => break,
            }
        }
        if dec_bytes > 0 && !session_logged {
            debug!("wireguard: session established (first data decrypted from peer)");
            session_logged = true;
        }

        // Drive the inner stack, encapsulate its output, shuttle flow bytes.
        iface.poll(Instant::now(), &mut device, &mut sockets);
        enc_bytes += encapsulate_pending(&mut tunn, &mut enc_rx, &mut scratch, &udp).await as u64;
        service_tcp(&mut sockets, &mut tcp_conns);
        service_udp(&mut sockets, &mut udp_conns);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        enc_bytes += encapsulate_pending(&mut tunn, &mut enc_rx, &mut scratch, &udp).await as u64;
    }
}

/// Returns the number of plaintext bytes delivered into the inner tunnel.
async fn decapsulate(
    tunn: &mut Tunn,
    datagram: &[u8],
    scratch: &mut [u8],
    device: &mut InnerDevice,
    udp: &tokio::net::UdpSocket,
) -> usize {
    let mut delivered = 0;
    let mut input: &[u8] = datagram;
    loop {
        let res = tunn.decapsulate(None, input, scratch);
        input = &[];
        match res {
            TunnResult::WriteToNetwork(p) => {
                let out = p.to_vec();
                let _ = udp.send(&out).await;
            }
            TunnResult::WriteToTunnelV4(pkt, _) => {
                delivered += pkt.len();
                device.push_inbound(pkt.to_vec());
            }
            TunnResult::WriteToTunnelV6(pkt, _) => {
                delivered += pkt.len();
                device.push_inbound(pkt.to_vec());
            }
            TunnResult::Done | TunnResult::Err(_) => break,
        }
    }
    delivered
}

/// Returns the number of encrypted bytes sent to the peer.
async fn encapsulate_pending(
    tunn: &mut Tunn,
    enc_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    scratch: &mut [u8],
    udp: &tokio::net::UdpSocket,
) -> usize {
    let mut sent = 0;
    while let Ok(pkt) = enc_rx.try_recv() {
        if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&pkt, scratch) {
            sent += p.len();
            let out = p.to_vec();
            let _ = udp.send(&out).await;
        }
    }
    sent
}

fn open_flow(
    req: OpenReq,
    iface: &mut Interface,
    sockets: &mut SocketSet,
    tcp_conns: &mut Vec<TcpBridge>,
    udp_conns: &mut Vec<UdpBridge>,
    next_port: &mut u16,
    wake: &Arc<Notify>,
) {
    let lport = alloc_port(next_port);
    match req {
        OpenReq::Tcp(dst, reply) => {
            let remote = match to_endpoint(dst) {
                Some(e) => e,
                None => {
                    let _ = reply.send(Err(io::Error::new(io::ErrorKind::Other, "ipv6 unsupported")));
                    return;
                }
            };
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            );
            match sock.connect(iface.context(), remote, lport) {
                Ok(()) => {
                    let handle = sockets.add(sock);
                    let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
                    let (from_app_tx, from_app_rx) = mpsc::unbounded_channel();
                    tcp_conns.push(TcpBridge {
                        handle,
                        from_app: from_app_rx,
                        to_app: Some(to_app_tx),
                        pending: VecDeque::new(),
                        app_eof: false,
                        established: false,
                    });
                    let _ = reply.send(Ok(ChannelStream::new(from_app_tx, to_app_rx, wake.clone())));
                }
                Err(e) => {
                    let _ = reply.send(Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))));
                }
            }
        }
        OpenReq::Udp(dst, reply) => {
            let remote = match to_endpoint(dst) {
                Some(e) => e,
                None => {
                    let _ = reply.send(Err(io::Error::new(io::ErrorKind::Other, "ipv6 unsupported")));
                    return;
                }
            };
            let mut sock = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_META], vec![0u8; UDP_PAYLOAD_BUF]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_META], vec![0u8; UDP_PAYLOAD_BUF]),
            );
            if sock.bind(lport).is_err() {
                let _ = reply.send(Err(io::Error::new(io::ErrorKind::Other, "udp bind failed")));
                return;
            }
            let handle = sockets.add(sock);
            let (to_app_tx, to_app_rx) = mpsc::unbounded_channel();
            let (from_app_tx, from_app_rx) = mpsc::unbounded_channel();
            udp_conns.push(UdpBridge { handle, dst: remote, from_app: from_app_rx, to_app: to_app_tx });
            let _ = reply.send(Ok(ChannelUdp::new(from_app_tx, to_app_rx, wake.clone())));
        }
    }
}

fn service_tcp(sockets: &mut SocketSet, conns: &mut Vec<TcpBridge>) {
    conns.retain_mut(|c| {
        let sock = sockets.get_mut::<tcp::Socket>(c.handle);

        if sock.state() == tcp::State::Established {
            c.established = true;
        }

        // app -> pending -> smoltcp tx
        loop {
            if c.pending.len() >= TCP_BUF {
                break;
            }
            match c.from_app.try_recv() {
                Ok(d) => c.pending.extend(d),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    c.app_eof = true;
                    break;
                }
            }
        }
        while sock.can_send() && !c.pending.is_empty() {
            let (head, _) = c.pending.as_slices();
            match sock.send_slice(head) {
                Ok(0) => break,
                Ok(n) => {
                    c.pending.drain(..n);
                }
                Err(_) => break,
            }
        }

        // smoltcp rx -> app
        while sock.can_recv() {
            let Some(tx) = c.to_app.as_ref() else { break };
            match sock.recv(|b| {
                let n = b.len();
                (n, b[..n].to_vec())
            }) {
                Ok(data) if !data.is_empty() => {
                    if tx.send(data).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }

        // remote (dst) closed sending → signal EOF to the app. Guard on
        // `established`: a SynSent socket also has !may_recv(), so without this
        // the handshake would be mistaken for a half-close and torn down.
        if c.established && c.to_app.is_some() && !sock.may_recv() && !sock.can_recv() {
            c.to_app = None;
        }
        // app closed → FIN toward dst
        if c.app_eof && c.pending.is_empty() {
            sock.close();
        }

        if sock.state() == tcp::State::Closed {
            sockets.remove(c.handle);
            return false;
        }
        true
    });
}

fn service_udp(sockets: &mut SocketSet, conns: &mut Vec<UdpBridge>) {
    conns.retain_mut(|c| {
        let sock = sockets.get_mut::<udp::Socket>(c.handle);
        let mut disconnected = false;

        while sock.can_send() {
            match c.from_app.try_recv() {
                Ok(d) => {
                    let _ = sock.send_slice(&d, c.dst);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        while sock.can_recv() {
            match sock.recv() {
                Ok((data, _)) => {
                    if c.to_app.send(data.to_vec()).is_err() {
                        disconnected = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if disconnected {
            sockets.remove(c.handle);
            return false;
        }
        true
    });
}

fn alloc_port(next: &mut u16) -> u16 {
    let p = *next;
    *next = if *next >= 60000 { 20000 } else { *next + 1 };
    p
}

fn to_endpoint(dst: SocketAddr) -> Option<IpEndpoint> {
    match dst {
        SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            Some(IpEndpoint::new(IpAddress::v4(o[0], o[1], o[2], o[3]), v4.port()))
        }
        SocketAddr::V6(_) => None,
    }
}

// ============================================================================
// Inner smoltcp device (plaintext side of the WireGuard tunnel)
// ============================================================================

struct InnerDevice {
    inbound: VecDeque<Vec<u8>>,
    enc_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl InnerDevice {
    fn new(enc_tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { inbound: VecDeque::new(), enc_tx }
    }
    fn push_inbound(&mut self, pkt: Vec<u8>) {
        self.inbound.push_back(pkt);
    }
}

impl Device for InnerDevice {
    type RxToken<'a> = InRx;
    type TxToken<'a> = InTx;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.inbound.pop_front()?;
        Some((InRx { buf }, InTx { enc_tx: self.enc_tx.clone() }))
    }
    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(InTx { enc_tx: self.enc_tx.clone() })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = INNER_MTU;
        caps
    }
}

struct InRx {
    buf: Vec<u8>,
}
impl phy::RxToken for InRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

struct InTx {
    enc_tx: mpsc::UnboundedSender<Vec<u8>>,
}
impl phy::TxToken for InTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.enc_tx.send(buf);
        r
    }
}

// ============================================================================
// Channel-bridged stream / datagram conn (async caller side)
// ============================================================================

pub struct ChannelStream {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    wake: Arc<Notify>,
    rem: Vec<u8>,
    pos: usize,
}

impl ChannelStream {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>, rx: mpsc::UnboundedReceiver<Vec<u8>>, wake: Arc<Notify>) -> Self {
        Self { tx, rx, wake, rem: Vec::new(), pos: 0 }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos >= this.rem.len() {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    this.rem = data;
                    this.pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = std::cmp::min(buf.remaining(), this.rem.len() - this.pos);
        buf.put_slice(&this.rem[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => {
                self.wake.notify_one(); // driver services from_app immediately, not on a tick
                Poll::Ready(Ok(buf.len()))
            }
            Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "wg flow closed"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct ChannelUdp {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    wake: Arc<Notify>,
}

impl ChannelUdp {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>, rx: mpsc::UnboundedReceiver<Vec<u8>>, wake: Arc<Notify>) -> Self {
        Self { tx, rx: Mutex::new(rx), wake }
    }
}

#[async_trait]
impl UdpConn for ChannelUdp {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wg flow closed"))?;
        self.wake.notify_one();
        Ok(buf.len())
    }
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(data) => {
                let n = std::cmp::min(buf.len(), data.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
}
