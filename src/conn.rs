//! Connection manager — the core of the transparent proxy.
//!
//! smoltcp gives us a userspace TCP/UDP stack, but it's synchronous and its
//! `SocketSet` is owned by the poll loop, while outbounds are async. We bridge
//! them per flow: the poll loop moves bytes between each smoltcp socket and a
//! pair of channels, and a spawned async task moves bytes between those channels
//! and the outbound connection.
//!
//! New flows are detected by peeking at inbound IP packets (a TCP SYN, or the
//! first datagram of a UDP 5-tuple); `iface.set_any_ip(true)` lets us create a
//! socket bound to the *destination* the app is trying to reach.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::outbound::Outbound;

const TCP_BUF: usize = 2 * 1024 * 1024;
const UDP_PAYLOAD_BUF: usize = 256 * 1024;
const UDP_META: usize = 64;
const CHAN_CAP: usize = 128;
const READ_CHUNK: usize = 16 * 1024;
const UDP_IDLE: Duration = Duration::from_secs(30);

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FourTuple {
    src: SocketAddrV4,
    dst: SocketAddrV4,
}

/// A minimal IPv4 flow view of a packet.
pub struct Flow {
    pub proto: u8,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// True only for a bare TCP SYN (new connection).
    pub syn: bool,
}

/// Parse an IPv4 TCP/UDP packet into its flow tuple. Returns `None` for anything
/// we don't proxy (non-IPv4, non-TCP/UDP, truncated).
pub fn parse_flow(pkt: &[u8]) -> Option<Flow> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let proto = pkt[9];
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let l4 = &pkt[ihl..];

    match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let flags = l4[13];
            let syn = (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN set, ACK clear
            Some(Flow {
                proto,
                src: SocketAddrV4::new(src_ip, sport),
                dst: SocketAddrV4::new(dst_ip, dport),
                syn,
            })
        }
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            Some(Flow {
                proto,
                src: SocketAddrV4::new(src_ip, sport),
                dst: SocketAddrV4::new(dst_ip, dport),
                syn: false,
            })
        }
        _ => None,
    }
}

struct TcpConn {
    handle: SocketHandle,
    /// Poll loop → outbound (app bytes). `None` once the app half-closed.
    app_to_out: Option<mpsc::Sender<Vec<u8>>>,
    /// Outbound → poll loop (server bytes).
    out_to_app: mpsc::Receiver<Vec<u8>>,
    /// Server bytes waiting for room in the smoltcp tx buffer.
    pending_out: VecDeque<u8>,
    established: bool,
    out_eof: bool,
}

struct UdpConn {
    handle: SocketHandle,
    app_to_out: mpsc::Sender<Vec<u8>>,
    out_to_app: mpsc::Receiver<Vec<u8>>,
    /// The app-side endpoint to send replies to (learned on first datagram).
    app_src: Option<IpEndpoint>,
    last: Instant,
}

/// Byte counters at the *exit boundary* — the real outbound sockets. The
/// TUN-side monitor cannot see this hop; comparing the two localizes loss:
/// exit-read high with TUN-down low → bytes die inside our stack; exit-read
/// near zero mid-transfer → the server paused because our kernel window
/// closed, i.e. the app isn't ACKing and the TUN→app hop is the suspect.
#[derive(Default)]
pub struct ExitStats {
    /// Bytes read from the internet (server → us).
    pub read: AtomicU64,
    /// Bytes written to the internet (us → server).
    pub written: AtomicU64,
}

pub struct ConnManager {
    outbound: Arc<dyn Outbound>,
    tcp: HashMap<FourTuple, TcpConn>,
    udp: HashMap<FourTuple, UdpConn>,
    /// Downstream waker: outbound tasks signal it whenever server→app bytes
    /// land in an `out_to_app` channel (and on task exit, so EOF propagates
    /// promptly). The engine selects on it — same pattern as the wg.rs driver.
    wake: Arc<Notify>,
    /// Exit-boundary byte counters, shared with every flow task.
    stats: Arc<ExitStats>,
}

impl ConnManager {
    pub fn new(outbound: Arc<dyn Outbound>) -> Self {
        Self {
            outbound,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            wake: Arc::new(Notify::new()),
            stats: Arc::new(ExitStats::default()),
        }
    }

    /// Clone of the downstream waker for the engine's select loop.
    pub fn waker(&self) -> Arc<Notify> {
        self.wake.clone()
    }

    /// Clone of the exit-boundary counters for the engine's ticker.
    pub fn stats(&self) -> Arc<ExitStats> {
        self.stats.clone()
    }

    /// Inspect a captured packet and open a new flow if needed. Called before the
    /// packet is handed to smoltcp so the accepting socket exists in time.
    pub fn on_packet(&mut self, sockets: &mut SocketSet, flow: &Flow) {
        let key = FourTuple { src: flow.src, dst: flow.dst };
        match flow.proto {
            6 if flow.syn && !self.tcp.contains_key(&key) => self.open_tcp(sockets, key),
            17 if !self.udp.contains_key(&key) => self.open_udp(sockets, key),
            _ => {}
        }
    }

    fn open_tcp(&mut self, sockets: &mut SocketSet, key: FourTuple) {
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        let listen = IpListenEndpoint { addr: Some(smol_v4(*key.dst.ip())), port: key.dst.port() };
        if let Err(e) = sock.listen(listen) {
            warn!("tcp listen({}) failed: {:?}", key.dst, e);
            return;
        }
        let handle = sockets.add(sock);

        let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let dst = SocketAddr::V4(key.dst);
        let outbound = self.outbound.clone();
        tokio::spawn(tcp_task(outbound, dst, app_rx, out_tx, self.wake.clone(), self.stats.clone()));

        self.tcp.insert(
            key,
            TcpConn {
                handle,
                app_to_out: Some(app_tx),
                out_to_app: out_rx,
                pending_out: VecDeque::new(),
                established: false,
                out_eof: false,
            },
        );
        debug!("tcp open -> {}", dst);
    }

    fn open_udp(&mut self, sockets: &mut SocketSet, key: FourTuple) {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let mut sock = udp::Socket::new(rx, tx);
        let bind = IpListenEndpoint { addr: Some(smol_v4(*key.dst.ip())), port: key.dst.port() };
        if let Err(e) = sock.bind(bind) {
            warn!("udp bind({}) failed: {:?}", key.dst, e);
            return;
        }
        let handle = sockets.add(sock);

        let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let dst = SocketAddr::V4(key.dst);
        let outbound = self.outbound.clone();
        tokio::spawn(udp_task(outbound, dst, app_rx, out_tx, self.wake.clone(), self.stats.clone()));

        self.udp.insert(
            key,
            UdpConn {
                handle,
                app_to_out: app_tx,
                out_to_app: out_rx,
                app_src: None,
                last: Instant::now(),
            },
        );
        debug!("udp open -> {}", dst);
    }

    /// Move bytes between smoltcp sockets and the per-flow channels. Called each
    /// poll tick.
    pub fn dispatch(&mut self, sockets: &mut SocketSet) {
        self.dispatch_tcp(sockets);
        self.dispatch_udp(sockets);
    }

    fn dispatch_tcp(&mut self, sockets: &mut SocketSet) {
        let mut remove = Vec::new();
        for (key, conn) in self.tcp.iter_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

            let was_established = conn.established;
            if sock.state() == tcp::State::Established {
                conn.established = true;
            }
            if conn.established && !was_established {
                debug!("tcp established (app handshake done) -> {}", key.dst);
            }

            // outbound -> pending_out
            loop {
                if conn.pending_out.len() >= TCP_BUF {
                    break;
                }
                match conn.out_to_app.try_recv() {
                    Ok(d) => conn.pending_out.extend(d),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn.out_eof = true;
                        break;
                    }
                }
            }

            // pending_out -> smoltcp tx
            while sock.can_send() && !conn.pending_out.is_empty() {
                let (head, _) = conn.pending_out.as_slices();
                match sock.send_slice(head) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.pending_out.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            // smoltcp rx -> outbound
            while sock.can_recv() {
                let Some(tx) = conn.app_to_out.as_ref() else { break };
                match tx.try_reserve() {
                    Ok(permit) => {
                        let chunk = sock.recv(|buf| {
                            let n = buf.len();
                            (n, buf[..n].to_vec())
                        });
                        match chunk {
                            Ok(data) if !data.is_empty() => permit.send(data),
                            _ => break,
                        }
                    }
                    Err(_) => break, // channel full/closed → smoltcp window backpressure
                }
            }

            // app half-closed (FIN received, rx drained) → stop writing to outbound
            if conn.established
                && conn.app_to_out.is_some()
                && !sock.may_recv()
                && !sock.can_recv()
            {
                conn.app_to_out = None;
            }

            // outbound closed and everything flushed → close our side
            if conn.out_eof && conn.pending_out.is_empty() {
                sock.close();
            }

            if sock.state() == tcp::State::Closed {
                remove.push(*key);
            }
        }
        for key in remove {
            if let Some(conn) = self.tcp.remove(&key) {
                sockets.remove(conn.handle);
                debug!("tcp close {}", key.dst);
            }
        }
    }

    fn dispatch_udp(&mut self, sockets: &mut SocketSet) {
        let mut remove = Vec::new();
        for (key, conn) in self.udp.iter_mut() {
            let sock = sockets.get_mut::<udp::Socket>(conn.handle);

            // smoltcp rx -> outbound
            while sock.can_recv() {
                match conn.app_to_out.try_reserve() {
                    Ok(permit) => match sock.recv() {
                        Ok((data, meta)) => {
                            conn.app_src = Some(meta.endpoint);
                            conn.last = Instant::now();
                            permit.send(data.to_vec());
                        }
                        Err(_) => break,
                    },
                    Err(_) => break,
                }
            }

            // outbound -> smoltcp tx (reply to the app's source endpoint)
            if let Some(src) = conn.app_src {
                while sock.can_send() {
                    match conn.out_to_app.try_recv() {
                        Ok(data) => {
                            if sock.send_slice(&data, src).is_err() {
                                // Buffer full or truncated — stop for this cycle;
                                // UDP loss semantics, the sender recovers.
                                break;
                            }
                            conn.last = Instant::now();
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            }

            if conn.last.elapsed() > UDP_IDLE {
                remove.push(*key);
            }
        }
        for key in remove {
            if let Some(conn) = self.udp.remove(&key) {
                sockets.remove(conn.handle);
                debug!("udp expire {}", key.dst);
            }
        }
    }
}

async fn tcp_task(
    outbound: Arc<dyn Outbound>,
    dst: SocketAddr,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
    wake: Arc<Notify>,
    stats: Arc<ExitStats>,
) {
    let stream = match outbound.connect_tcp(dst).await {
        Ok(s) => {
            debug!("outbound tcp connected -> {}", dst);
            s
        }
        Err(e) => {
            warn!("outbound tcp {} failed: {}", dst, e);
            drop(out_tx); // poll loop closes the smoltcp side on next dispatch
            wake.notify_one(); // ...which we trigger now, not on a timer
            return;
        }
    };
    let (mut rd, mut wr) = tokio::io::split(stream);

    // outbound → app. Every delivery wakes the poll loop immediately —
    // downstream latency is scheduler latency, not a 200 ms timer. Dropping
    // out_tx signals EOF; the final notify makes the poll loop see it now.
    let reader_wake = wake.clone();
    let reader_stats = stats.clone();
    let reader = async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    reader_stats.read.fetch_add(n as u64, Ordering::Relaxed);
                    if out_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    reader_wake.notify_one();
                }
                Err(_) => break,
            }
        }
        drop(out_tx);
        reader_wake.notify_one();
    };

    // app → outbound
    let writer = async move {
        while let Some(chunk) = app_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
            stats.written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        let _ = wr.shutdown().await;
    };

    tokio::join!(reader, writer);
}

async fn udp_task(
    outbound: Arc<dyn Outbound>,
    dst: SocketAddr,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
    wake: Arc<Notify>,
    stats: Arc<ExitStats>,
) {
    let sock = match outbound.bind_udp(dst).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("outbound udp {} failed: {}", dst, e);
            drop(out_tx);
            wake.notify_one();
            return;
        }
    };

    let recv_sock = sock.clone();
    let receiver_wake = wake.clone();
    let receiver_stats = stats.clone();
    let receiver = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match recv_sock.recv(&mut buf).await {
                Ok(n) => {
                    receiver_stats.read.fetch_add(n as u64, Ordering::Relaxed);
                    if out_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    receiver_wake.notify_one();
                }
                Err(_) => break,
            }
        }
        drop(out_tx);
        receiver_wake.notify_one();
    };

    let send_sock = sock.clone();
    let sender = async move {
        while let Some(datagram) = app_rx.recv().await {
            if send_sock.send(&datagram).await.is_err() {
                break;
            }
            stats.written.fetch_add(datagram.len() as u64, Ordering::Relaxed);
        }
    };

    tokio::join!(receiver, sender);
}

fn smol_v4(ip: Ipv4Addr) -> IpAddress {
    let o = ip.octets();
    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_syn() {
        // IPv4 header (20B) + TCP header (20B); SYN flag set, ACK clear.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[33] = 0x02; // flags byte at l4 offset 13 → pkt[20+13]=pkt[33]
        let f = parse_flow(&pkt).unwrap();
        assert_eq!(f.proto, 6);
        assert!(f.syn);
        assert_eq!(f.dst.port(), 443);
        assert_eq!(f.src.port(), 40000);
    }

    #[test]
    fn parses_udp() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&5353u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        let f = parse_flow(&pkt).unwrap();
        assert_eq!(f.proto, 17);
        assert!(!f.syn);
        assert_eq!(f.dst.port(), 53);
    }

    #[test]
    fn ignores_non_ipv4() {
        assert!(parse_flow(&[0x60, 0, 0, 0]).is_none());
    }
}
