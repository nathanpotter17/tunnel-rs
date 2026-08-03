//! Connection manager — the transparent proxy behind the `Direct` exit.
//!
//! smoltcp gives us a userspace TCP/UDP stack, but it is synchronous and its
//! `SocketSet` is owned by the poll loop, while the egress sockets are async. We
//! bridge them per flow: the poll loop moves bytes between each smoltcp socket
//! and a pair of channels, and a spawned task moves bytes between those channels
//! and a pinned OS socket.
//!
//! New flows are detected by peeking at inbound IP packets (a TCP SYN, or the
//! first datagram of a UDP 5-tuple); `iface.set_any_ip(true)` lets us create a
//! socket bound to the *destination* the app is trying to reach.
//!
//! # Servicing is readiness-driven, not a table scan
//!
//! A wake is caused by one flow, so servicing must cost one flow. Every socket
//! registers a waker that files its own id into a deduplicated ready queue —
//! smoltcp fires those wakers on data arrival, on send-buffer space, and on every
//! state transition — and the egress tasks file the same ids when they deliver
//! bytes or free channel capacity. `dispatch` then drains that queue and touches
//! nothing else. Scanning every flow on every wake instead would make the cost of
//! one delivered chunk O(open flows): at this engine's admission ceiling that is
//! thousands of no-op probes per wake, thousands of times a second.
//!
//! Timeouts are the one thing readiness cannot express, so they live in a
//! deadline min-heap: O(log n) to arm, O(1) to find the next, and the engine
//! sleeps until it rather than polling for it.
//!
//! # This is split TCP, and it matters for sizing
//!
//! The app's connection terminates HERE — we answer its SYN — and we open a
//! SEPARATE outbound connection to the real server. So a smoltcp socket buffer
//! only ever spans the app<->proxy leg, which is a ~0-RTT hop across the local
//! TUN. The WAN bandwidth-delay product lives on the outbound leg, which is a
//! real OS kernel socket the OS receive-window-autotunes (we never clamp
//! SO_RCVBUF/SO_SNDBUF). The app-leg buffer therefore needs only to cover one
//! loop-latency hop, so a modest buffer sustains full single-stream throughput
//! AND lets far more flows share a fixed budget. Bigger app-leg buffers buy
//! bufferbloat, not speed.
//!
//! The WireGuard exit does not come through here at all: it owns both ends of its
//! path, so it routes packets instead of re-terminating TCP (see `wg.rs`).
//!
//! # Admission is by memory budget
//!
//! This engine captures the host's entire default route, so flow creation is an
//! attacker-influenced, unbounded input. Each new flow pins socket buffers and
//! spawns a real pinned outbound connection. Flows are therefore admitted against
//! a fixed global byte budget (buffer size x flow count trade off automatically —
//! the budget is the one knob), with a hard count backstop for structural
//! overhead and file descriptors. Past the gate the SYN is shed (the app retries,
//! as against a congested host), never allocated. Liveness is smoltcp keepalive +
//! timeout, so idle-but-alive sessions survive while dead peers are reset;
//! half-open flood flows are reaped by an explicit handshake deadline.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::inspect::{FlowStatus, TrafficMonitor};
use crate::pin::{self, EgressPin};
use crate::state::ExitStats;

/// Per-direction smoltcp socket buffer. Sized for the ~0-RTT app<->proxy leg (see
/// module docs): even at a pessimistic ~4 ms poll-loop latency this sustains
/// ~256 Mbit/s on that hop, and typical latency is far lower — never the WAN
/// bottleneck, which the outbound leg owns. Smaller than a WAN BDP on purpose:
/// it maximises flow density under the budget and avoids local bufferbloat.
const TCP_BUF: usize = 128 * 1024;

const UDP_PAYLOAD_BUF: usize = 256 * 1024;
const UDP_META: usize = 64;
const CHAN_CAP: usize = 128;
const READ_CHUNK: usize = 16 * 1024;
const UDP_IDLE: Duration = Duration::from_secs(30);

/// Global memory budgets — the primary admission gate. A flow is admitted only
/// while its worst-case footprint still fits. This is memory-anchored: change a
/// buffer size and admission re-derives itself, so there is ONE knob (the budget)
/// instead of a hand-tuned count that must be kept in sync with buffer sizes.
///   TCP: 1 GiB / TCP_FLOW_COST (384 KiB) ~= 2730 concurrent flows
///   UDP: 512 MiB / UDP_FLOW_COST (~514 KiB) ~= 1020 concurrent flows
const TCP_MEM_BUDGET: usize = 1024 * 1024 * 1024;
const UDP_MEM_BUDGET: usize = 512 * 1024 * 1024;

/// Worst-case bytes one flow can pin: both socket buffers plus the transient
/// queue/metadata. Charged at open, refunded at close, so the live sum is an
/// exact bound, not an estimate. The egress leg adds nothing to charge here — a
/// `Direct` flow's far side is a kernel socket the OS budgets and autotunes.
const TCP_FLOW_COST: usize = 2 * TCP_BUF + TCP_BUF; // rx + tx + pending_out ceiling
const UDP_FLOW_COST: usize =
    2 * UDP_PAYLOAD_BUF + 2 * UDP_META * std::mem::size_of::<udp::PacketMetadata>();

/// Hard count backstops, independent of bytes: bound the HashMap / SocketSet /
/// spawned-task / file-descriptor overhead so no degenerate low-byte regime can
/// explode structural memory. At the buffer sizes above the byte budget binds
/// first; these only matter if buffers are later shrunk hard.
const MAX_TCP_FLOWS: usize = 8192;
const MAX_UDP_FLOWS: usize = 4096;

/// Half-open flood guard: a flow that never reaches Established within this
/// window is an abandoned SYN or a flood probe. Reaped from the deadline heap —
/// this is the primary bound on flood-driven accumulation.
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Established-flow liveness. smoltcp sends keepalive probes every
/// `TCP_KEEPALIVE_SECS`; a live app's kernel ACKs them automatically (whether or
/// not the app is reading), so idle-but-alive sessions are refreshed and never
/// cut. A dead/crashed app stops ACKing and smoltcp aborts the connection after
/// `TCP_TIMEOUT_SECS` of silence, which is a state change, which fires the
/// socket's waker and surfaces here as `State::Closed`. This is correct
/// dead-vs-idle detection — it replaces any blunt idle timer, which could only
/// ever guess.
const TCP_KEEPALIVE_SECS: u64 = 15;
const TCP_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct FourTuple {
    src: SocketAddrV4,
    dst: SocketAddrV4,
}

/// Identifies one flow across the ready queue and the deadline heap.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum FlowId {
    Tcp(FourTuple),
    Udp(FourTuple),
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

// ============================================================================
// Readiness
// ============================================================================

/// Deduplicated queue of flows with work pending, plus the notification the
/// engine's select loop parks on. Both smoltcp (via socket wakers) and the
/// egress tasks file into it, so "something happened" always arrives with the
/// identity of what it happened to.
pub struct Ready {
    inner: Mutex<ReadyInner>,
    notify: Notify,
}

#[derive(Default)]
struct ReadyInner {
    queue: VecDeque<FlowId>,
    /// Membership set, so a flow woken a thousand times before the next dispatch
    /// is serviced once. Cleared as a unit when the queue is drained.
    marked: HashSet<FlowId>,
}

impl Ready {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ReadyInner::default()),
            notify: Notify::new(),
        })
    }

    fn mark(&self, id: FlowId) {
        {
            // Poisoning cannot strand the engine: the lock guards two plain
            // collections and nothing under it can panic, so recover the guard.
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !g.marked.insert(id) {
                // Already queued and not yet drained, so a permit is already
                // pending; a second notify would only cause a spurious wake.
                return;
            }
            g.queue.push_back(id);
        }
        self.notify.notify_one();
    }

    fn take(&self, out: &mut Vec<FlowId>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(g.queue.drain(..));
        g.marked.clear();
    }

    /// Park until at least one flow is ready.
    pub async fn wait(&self) {
        self.notify.notified().await;
    }
}

/// Turns a smoltcp socket wake into a ready-queue entry. One allocation per
/// flow, cloned by reference for each re-registration.
struct FlowWaker {
    ready: Arc<Ready>,
    id: FlowId,
}

impl Wake for FlowWaker {
    fn wake(self: Arc<Self>) {
        self.ready.mark(self.id);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.mark(self.id);
    }
}

// ============================================================================
// Per-flow state
// ============================================================================

/// Server bytes waiting for room in the smoltcp tx buffer, held as the chunks
/// they arrived in. A flat byte deque would pay a per-byte push on arrival and a
/// memmove per drain; chunks make both O(1) and let `front` hand smoltcp a
/// contiguous slice with no copy.
#[derive(Default)]
struct Pending {
    chunks: VecDeque<Vec<u8>>,
    /// Bytes of `chunks[0]` already handed to smoltcp.
    head: usize,
    bytes: usize,
}

impl Pending {
    fn push(&mut self, v: Vec<u8>) {
        if v.is_empty() {
            return;
        }
        self.bytes += v.len();
        self.chunks.push_back(v);
    }

    fn len(&self) -> usize {
        self.bytes
    }

    fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Contiguous unconsumed prefix. Empty only when the queue is empty.
    fn front(&self) -> &[u8] {
        match self.chunks.front() {
            Some(c) => &c[self.head..],
            None => &[],
        }
    }

    fn advance(&mut self, n: usize) {
        self.head += n;
        self.bytes -= n;
        if self.chunks.front().is_some_and(|c| self.head >= c.len()) {
            self.chunks.pop_front();
            self.head = 0;
        }
    }
}

struct TcpConn {
    handle: SocketHandle,
    /// Poll loop -> egress (app bytes). `None` once the app half-closed.
    app_to_out: Option<mpsc::Sender<Vec<u8>>>,
    /// Egress -> poll loop (server bytes).
    out_to_app: mpsc::Receiver<Vec<u8>>,
    pending_out: Pending,
    established: bool,
    out_eof: bool,
    /// The heap entry that currently owns this flow's timeout. A 4-tuple can be
    /// reused the moment it closes, so a deadline filed by a previous incarnation
    /// must not reap its successor: an entry is only honoured when it still
    /// matches this field.
    deadline: Instant,
    /// Re-registered with the socket after every service pass; smoltcp consumes a
    /// registration when it fires.
    waker: Waker,
}

struct UdpConn {
    handle: SocketHandle,
    app_to_out: mpsc::Sender<Vec<u8>>,
    out_to_app: mpsc::Receiver<Vec<u8>>,
    /// The app-side endpoint to send replies to (learned on first datagram).
    app_src: Option<IpEndpoint>,
    last: Instant,
    /// See `TcpConn::deadline`.
    deadline: Instant,
    waker: Waker,
}

// ============================================================================
// Manager
// ============================================================================

pub struct ConnManager {
    /// Egress pin for every outbound socket this manager opens. Cheap to clone
    /// into each flow task; the pin itself is resolved once, in `main`.
    egress: EgressPin,
    tcp: HashMap<FourTuple, TcpConn>,
    udp: HashMap<FourTuple, UdpConn>,
    /// Live sum of TCP_FLOW_COST over open TCP flows — the admission gate. Plain
    /// usize (not atomic): ConnManager is owned and mutated only by the engine's
    /// single poll task, so there is no sharing to synchronise.
    tcp_bytes: usize,
    udp_bytes: usize,
    /// Observability sink. Admission decisions (shed / reap) are reported here so
    /// the dashboard tags those flows as deliberate engine actions rather than
    /// letting them read as anomalous half-open / up-only conversations.
    monitor: Arc<TrafficMonitor>,
    ready: Arc<Ready>,
    /// Reusable buffer for the drained ready queue — the dispatch path allocates
    /// nothing per wake.
    scratch: Vec<FlowId>,
    /// Earliest-first timeouts: TCP handshake deadlines and UDP idle expiry.
    /// Entries are lazily validated on pop, so re-arming costs nothing until the
    /// deadline actually arrives.
    deadlines: BinaryHeap<Reverse<(Instant, FlowId)>>,
    /// Exit-boundary byte counters, shared with every flow task.
    stats: Arc<ExitStats>,
}

impl ConnManager {
    pub fn new(egress: EgressPin, monitor: Arc<TrafficMonitor>, stats: Arc<ExitStats>) -> Self {
        Self {
            egress,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            tcp_bytes: 0,
            udp_bytes: 0,
            monitor,
            ready: Ready::new(),
            scratch: Vec::new(),
            deadlines: BinaryHeap::new(),
            stats,
        }
    }

    /// Handle the engine's select loop parks on.
    pub fn readiness(&self) -> Arc<Ready> {
        self.ready.clone()
    }

    /// When the engine must wake even with no traffic, to honour a timeout.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.peek().map(|Reverse((at, _))| *at)
    }

    fn waker_for(&self, id: FlowId) -> Waker {
        Waker::from(Arc::new(FlowWaker { ready: self.ready.clone(), id }))
    }

    /// Inspect a captured packet and open a new flow if needed. Called before the
    /// packet is handed to smoltcp so the accepting socket exists in time. A new
    /// flow is admitted only while it fits the global byte budget and the hard
    /// count backstop; past either, the packet is shed (see module docs) rather
    /// than allocated.
    pub fn on_packet(&mut self, sockets: &mut SocketSet, flow: &Flow) {
        let key = FourTuple { src: flow.src, dst: flow.dst };
        match flow.proto {
            6 if flow.syn && !self.tcp.contains_key(&key) => {
                if self.tcp.len() >= MAX_TCP_FLOWS || self.tcp_bytes + TCP_FLOW_COST > TCP_MEM_BUDGET
                {
                    debug!(
                        "tcp admission denied (flows {}, {} MiB used) — shedding SYN -> {}",
                        self.tcp.len(),
                        self.tcp_bytes / (1024 * 1024),
                        key.dst
                    );
                    self.monitor
                        .note_flow(true, key.dst, key.src.port(), FlowStatus::Shed);
                    return;
                }
                self.open_tcp(sockets, key);
            }
            17 if !self.udp.contains_key(&key) => {
                if self.udp.len() >= MAX_UDP_FLOWS || self.udp_bytes + UDP_FLOW_COST > UDP_MEM_BUDGET
                {
                    debug!(
                        "udp admission denied (flows {}, {} MiB used) — shedding -> {}",
                        self.udp.len(),
                        self.udp_bytes / (1024 * 1024),
                        key.dst
                    );
                    self.monitor
                        .note_flow(false, key.dst, key.src.port(), FlowStatus::Shed);
                    return;
                }
                self.open_udp(sockets, key);
            }
            _ => {}
        }
    }

    fn open_tcp(&mut self, sockets: &mut SocketSet, key: FourTuple) {
        let id = FlowId::Tcp(key);
        let waker = self.waker_for(id);

        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        let listen = IpListenEndpoint { addr: Some(smol_v4(*key.dst.ip())), port: key.dst.port() };
        if let Err(e) = sock.listen(listen) {
            warn!("tcp listen({}) failed: {:?}", key.dst, e);
            return;
        }
        // Established-flow liveness (see module docs): keepalive probes keep an
        // idle-but-alive app's connection fresh; a dead app trips the timeout and
        // smoltcp aborts, surfacing as State::Closed on the next service pass.
        sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(TCP_KEEPALIVE_SECS)));
        sock.set_timeout(Some(smoltcp::time::Duration::from_secs(TCP_TIMEOUT_SECS)));
        sock.register_recv_waker(&waker);
        sock.register_send_waker(&waker);
        let handle = sockets.add(sock);

        let deadline = Instant::now() + TCP_HANDSHAKE_TIMEOUT;
        let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        tokio::spawn(tcp_task(
            self.egress.clone(),
            SocketAddr::V4(key.dst),
            app_rx,
            out_tx,
            self.ready.clone(),
            id,
            self.stats.clone(),
        ));

        self.tcp.insert(
            key,
            TcpConn {
                handle,
                app_to_out: Some(app_tx),
                out_to_app: out_rx,
                pending_out: Pending::default(),
                established: false,
                out_eof: false,
                deadline,
                waker,
            },
        );
        self.tcp_bytes += TCP_FLOW_COST;
        // Bounds SYN -> Established so a half-open flood cannot accumulate.
        self.deadlines.push(Reverse((deadline, id)));
        // Serviced on the next dispatch regardless of whether smoltcp fires a
        // waker while processing the SYN we are about to inject.
        self.ready.mark(id);
        // A prior SYN to this 5-tuple may have been shed under pressure; now that
        // it's admitted, clear that tag so the row reads as the live flow it is.
        self.monitor
            .note_flow(true, key.dst, key.src.port(), FlowStatus::Active);
        debug!("tcp open -> {}", key.dst);
    }

    fn open_udp(&mut self, sockets: &mut SocketSet, key: FourTuple) {
        let id = FlowId::Udp(key);
        let waker = self.waker_for(id);

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
        sock.register_recv_waker(&waker);
        sock.register_send_waker(&waker);
        let handle = sockets.add(sock);

        let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        tokio::spawn(udp_task(
            self.egress.clone(),
            SocketAddr::V4(key.dst),
            app_rx,
            out_tx,
            self.ready.clone(),
            id,
            self.stats.clone(),
        ));

        let now = Instant::now();
        self.udp.insert(
            key,
            UdpConn {
                handle,
                app_to_out: app_tx,
                out_to_app: out_rx,
                app_src: None,
                last: now,
                deadline: now + UDP_IDLE,
                waker,
            },
        );
        self.udp_bytes += UDP_FLOW_COST;
        self.deadlines.push(Reverse((now + UDP_IDLE, id)));
        self.ready.mark(id);
        self.monitor
            .note_flow(false, key.dst, key.src.port(), FlowStatus::Active);
        debug!("udp open -> {}", key.dst);
    }

    /// Service every flow with pending work, then retire anything that timed out.
    /// Returns true if bytes or a FIN were queued into smoltcp, which tells the
    /// engine a second poll is worth running.
    pub fn dispatch(&mut self, sockets: &mut SocketSet, now: Instant) -> bool {
        self.expire(sockets, now);
        let mut queued = false;

        let mut ids = std::mem::take(&mut self.scratch);
        ids.clear();
        self.ready.take(&mut ids);
        for id in ids.iter().copied() {
            match id {
                FlowId::Tcp(key) => queued |= self.service_tcp(sockets, key),
                FlowId::Udp(key) => queued |= self.service_udp(sockets, key, now),
            }
        }
        self.scratch = ids;
        queued
    }

    fn service_tcp(&mut self, sockets: &mut SocketSet, key: FourTuple) -> bool {
        let mut queued = false;
        let mut close = false;

        if let Some(conn) = self.tcp.get_mut(&key) {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

            if !conn.established && sock.state() == tcp::State::Established {
                conn.established = true;
                debug!("tcp established (app handshake done) -> {}", key.dst);
            }

            // egress -> pending_out
            loop {
                if conn.pending_out.len() >= TCP_BUF {
                    break;
                }
                match conn.out_to_app.try_recv() {
                    Ok(d) => conn.pending_out.push(d),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn.out_eof = true;
                        break;
                    }
                }
            }

            // pending_out -> smoltcp tx
            while sock.can_send() && !conn.pending_out.is_empty() {
                match sock.send_slice(conn.pending_out.front()) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        conn.pending_out.advance(n);
                        queued = true;
                    }
                }
            }

            // smoltcp rx -> egress. Reserve channel capacity BEFORE consuming from
            // smoltcp: on a full channel the bytes stay in the rx buffer, its
            // window closes, and the app is backpressured — no unbounded queue, no
            // loss. The egress writer files this flow ready again when it drains a
            // chunk, which is what reopens the window.
            while sock.can_recv() {
                let Some(tx) = conn.app_to_out.as_ref() else {
                    break;
                };
                match tx.try_reserve() {
                    Ok(permit) => match sock.recv(|buf| {
                        let n = buf.len();
                        (n, buf[..n].to_vec())
                    }) {
                        Ok(data) if !data.is_empty() => permit.send(data),
                        _ => break,
                    },
                    Err(_) => break,
                }
            }

            // app half-closed (FIN received, rx drained) -> stop writing to egress
            if conn.established && conn.app_to_out.is_some() && !sock.may_recv() && !sock.can_recv()
            {
                conn.app_to_out = None;
            }

            // egress closed and everything flushed -> close our side
            if conn.out_eof && conn.pending_out.is_empty() {
                sock.close();
                queued = true;
            }

            if sock.state() == tcp::State::Closed {
                close = true;
            } else {
                // smoltcp consumes a registration when it fires it, so re-arm.
                sock.register_recv_waker(&conn.waker);
                sock.register_send_waker(&conn.waker);
            }
        }

        if close {
            if let Some(conn) = self.tcp.remove(&key) {
                sockets.remove(conn.handle);
                self.tcp_bytes = self.tcp_bytes.saturating_sub(TCP_FLOW_COST);
                debug!("tcp close {}", key.dst);
            }
        }
        queued
    }

    fn service_udp(&mut self, sockets: &mut SocketSet, key: FourTuple, now: Instant) -> bool {
        let mut queued = false;
        let Some(conn) = self.udp.get_mut(&key) else {
            return false;
        };
        let sock = sockets.get_mut::<udp::Socket>(conn.handle);

        // smoltcp rx -> egress
        while sock.can_recv() {
            match conn.app_to_out.try_reserve() {
                Ok(permit) => match sock.recv() {
                    Ok((data, meta)) => {
                        conn.app_src = Some(meta.endpoint);
                        conn.last = now;
                        permit.send(data.to_vec());
                    }
                    Err(_) => break,
                },
                Err(_) => break,
            }
        }

        // egress -> smoltcp tx (reply to the app's source endpoint)
        if let Some(src) = conn.app_src {
            while sock.can_send() {
                match conn.out_to_app.try_recv() {
                    Ok(data) => {
                        if sock.send_slice(&data, src).is_err() {
                            // Buffer full or datagram too large — stop for this
                            // pass; UDP loss semantics, the sender recovers.
                            break;
                        }
                        conn.last = now;
                        queued = true;
                    }
                    Err(_) => break,
                }
            }
        }

        sock.register_recv_waker(&conn.waker);
        sock.register_send_waker(&conn.waker);
        queued
    }

    /// Retire flows whose deadlines have arrived. Entries are validated on pop, so
    /// a flow that made progress simply re-arms instead of being torn down.
    fn expire(&mut self, sockets: &mut SocketSet, now: Instant) {
        while let Some(Reverse((at, id))) = self.deadlines.peek().copied() {
            if at > now {
                break;
            }
            self.deadlines.pop();
            match id {
                FlowId::Tcp(key) => {
                    let Some(conn) = self.tcp.get(&key) else {
                        continue; // already closed; the entry was stale
                    };
                    if conn.established {
                        continue; // handshake completed; liveness is smoltcp's now
                    }
                    if conn.deadline != at {
                        continue; // filed by a previous flow on the same 4-tuple
                    }
                    // Never reached Established inside the window: abandoned or
                    // hostile. Abort drops it out of the handshake immediately and
                    // the budget is refunded on the spot; the app sees silence and
                    // retries, exactly as against a congested host.
                    let handle = conn.handle;
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.tcp.remove(&key);
                    sockets.remove(handle);
                    self.tcp_bytes = self.tcp_bytes.saturating_sub(TCP_FLOW_COST);
                    debug!("tcp reap {} (handshake timeout)", key.dst);
                    self.monitor
                        .note_flow(true, key.dst, key.src.port(), FlowStatus::Reaped);
                }
                FlowId::Udp(key) => {
                    let Some(conn) = self.udp.get(&key) else {
                        continue;
                    };
                    if conn.deadline != at {
                        continue; // filed by a previous flow on the same 4-tuple
                    }
                    if now.duration_since(conn.last) < UDP_IDLE {
                        // Still live: re-arm for the remaining window rather than
                        // pushing a new deadline on every datagram. Exactly one
                        // entry per flow stays live, so the heap cannot grow.
                        let next = conn.last + UDP_IDLE;
                        if let Some(c) = self.udp.get_mut(&key) {
                            c.deadline = next;
                        }
                        self.deadlines.push(Reverse((next, id)));
                        continue;
                    }
                    let handle = conn.handle;
                    self.udp.remove(&key);
                    sockets.remove(handle);
                    self.udp_bytes = self.udp_bytes.saturating_sub(UDP_FLOW_COST);
                    debug!("udp expire {}", key.dst);
                }
            }
        }
    }
}

// ============================================================================
// Egress tasks
// ============================================================================

async fn tcp_task(
    egress: EgressPin,
    dst: SocketAddr,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
    ready: Arc<Ready>,
    id: FlowId,
    stats: Arc<ExitStats>,
) {
    let stream = match pin::connect_tcp(dst, &egress).await {
        Ok(s) => {
            debug!("egress tcp connected -> {}", dst);
            s
        }
        Err(e) => {
            warn!("egress tcp {} failed: {}", dst, e);
            drop(out_tx); // the poll loop closes the smoltcp side on next service
            ready.mark(id); // ...which we trigger now, not on a timer
            return;
        }
    };
    let (mut rd, mut wr) = tokio::io::split(stream);

    // egress -> app. Every delivery files this flow ready, so downstream latency
    // is scheduler latency rather than a timer tick. Dropping out_tx signals EOF;
    // the final mark makes the poll loop see it immediately.
    let reader_ready = ready.clone();
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
                    reader_ready.mark(id);
                }
                Err(_) => break,
            }
        }
        drop(out_tx);
        reader_ready.mark(id);
    };

    // app -> egress. Draining a chunk frees channel capacity, which is the
    // condition the poll loop stalled on when it stopped reading the smoltcp rx
    // buffer, so it has to be told.
    let writer = async move {
        while let Some(chunk) = app_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
            stats.written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            ready.mark(id);
        }
        let _ = wr.shutdown().await;
    };

    tokio::join!(reader, writer);
}

async fn udp_task(
    egress: EgressPin,
    dst: SocketAddr,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
    ready: Arc<Ready>,
    id: FlowId,
    stats: Arc<ExitStats>,
) {
    let sock: Arc<UdpSocket> = match pin::bind_udp(dst, &egress).await {
        Ok(s) => match s.connect(dst).await {
            Ok(()) => Arc::new(s),
            Err(e) => {
                warn!("egress udp connect {} failed: {}", dst, e);
                drop(out_tx);
                ready.mark(id);
                return;
            }
        },
        Err(e) => {
            warn!("egress udp {} failed: {}", dst, e);
            drop(out_tx);
            ready.mark(id);
            return;
        }
    };

    let recv_sock = sock.clone();
    let receiver_ready = ready.clone();
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
                    receiver_ready.mark(id);
                }
                Err(_) => break,
            }
        }
        drop(out_tx);
        receiver_ready.mark(id);
    };

    let sender = async move {
        while let Some(datagram) = app_rx.recv().await {
            if sock.send(&datagram).await.is_err() {
                break;
            }
            stats.written.fetch_add(datagram.len() as u64, Ordering::Relaxed);
            ready.mark(id);
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
        pkt[33] = 0x02; // flags byte at l4 offset 13 -> pkt[20+13]=pkt[33]
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

    #[test]
    fn budget_costs_are_positive_and_fit() {
        // A single flow's worst case must fit its budget (else nothing is ever
        // admitted), and the byte-derived ceiling must sit within the hard count
        // backstop so the two gates are consistent.
        assert!(TCP_FLOW_COST > 0 && TCP_FLOW_COST <= TCP_MEM_BUDGET);
        assert!(UDP_FLOW_COST > 0 && UDP_FLOW_COST <= UDP_MEM_BUDGET);
        assert!(TCP_MEM_BUDGET / TCP_FLOW_COST <= MAX_TCP_FLOWS);
        assert!(UDP_MEM_BUDGET / UDP_FLOW_COST <= MAX_UDP_FLOWS);
    }

    fn tuple(port: u16) -> FourTuple {
        FourTuple {
            src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), port),
            dst: SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443),
        }
    }

    #[test]
    fn ready_queue_deduplicates_and_drains() {
        let r = Ready::new();
        let a = FlowId::Tcp(tuple(1));
        let b = FlowId::Udp(tuple(2));
        for _ in 0..1000 {
            r.mark(a);
        }
        r.mark(b);
        let mut out = Vec::new();
        r.take(&mut out);
        assert_eq!(out.len(), 2, "a flow woken repeatedly must be serviced once");
        assert!(out.contains(&a) && out.contains(&b));

        // Cleared as a unit: the same flow can be filed again immediately.
        r.mark(a);
        out.clear();
        r.take(&mut out);
        assert_eq!(out, vec![a]);
    }

    #[test]
    fn flow_waker_files_its_own_id() {
        let r = Ready::new();
        let id = FlowId::Tcp(tuple(7));
        let w = Waker::from(Arc::new(FlowWaker { ready: r.clone(), id }));
        w.wake_by_ref();
        let mut out = Vec::new();
        r.take(&mut out);
        assert_eq!(out, vec![id], "the wake must identify which flow woke");
    }

    #[test]
    fn pending_is_chunked_and_byte_exact() {
        let mut p = Pending::default();
        p.push(b"hello".to_vec());
        p.push(b"world".to_vec());
        p.push(Vec::new()); // empty pushes are not queued
        assert_eq!(p.len(), 10);
        assert_eq!(p.front(), b"hello");
        p.advance(2);
        assert_eq!(p.front(), b"llo");
        assert_eq!(p.len(), 8);
        p.advance(3);
        assert_eq!(p.front(), b"world", "must roll over to the next chunk");
        p.advance(5);
        assert!(p.is_empty());
        assert_eq!(p.front(), b"");
    }

    #[test]
    fn deadlines_pop_in_time_order() {
        let now = Instant::now();
        let mut h: BinaryHeap<Reverse<(Instant, FlowId)>> = BinaryHeap::new();
        h.push(Reverse((now + Duration::from_secs(30), FlowId::Udp(tuple(3)))));
        h.push(Reverse((now + Duration::from_secs(10), FlowId::Tcp(tuple(1)))));
        h.push(Reverse((now + Duration::from_secs(20), FlowId::Tcp(tuple(2)))));
        let Reverse((at, id)) = h.pop().unwrap();
        assert_eq!(at, now + Duration::from_secs(10));
        assert_eq!(id, FlowId::Tcp(tuple(1)));
    }
}
