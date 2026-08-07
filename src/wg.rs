//! WireGuard exit — NAT44 + boringtun encapsulation. No inner TCP stack.
//!
//! When the exit is WireGuard the engine owns the *entire* path: it reads the
//! app's IP packets off the TUN and it owns the encrypted socket to the peer.
//! There is therefore nothing to proxy. This module rewrites each packet's
//! source to the WireGuard client address (classic NAT44, incremental checksum
//! fixups), hands it to boringtun, and sends the ciphertext out the pinned
//! uplink socket. Return packets are decrypted, un-NAT'd, and written to the TUN.
//!
//! # Why not a second smoltcp stack
//!
//! Terminating TCP again inside the tunnel makes this a *double* split-TCP
//! proxy, and each inner socket must eagerly own a WAN-sized send+receive buffer
//! (smoltcp cannot resize after construction). At the engine's admission ceiling
//! that is gigabytes of committed buffer for the exit leg alone — memory the
//! connection manager's budget never charged, because it only ever accounted for
//! its own app-leg sockets. Routing makes per-flow state a NAT binding (~80
//! bytes), so the exit leg costs O(bindings) bytes rather than O(bindings x WAN
//! window).
//!
//! Routing is also *more* correct, not merely cheaper:
//!   - The app's TCP runs end to end against the real server, so congestion
//!     control, SACK, ECN, and RTT estimation belong to the real path instead of
//!     being spliced across two independent control loops.
//!   - MSS follows from one number (the TUN MTU) instead of an inner-MTU clamp
//!     pessimised to 1280 to survive a path it could not observe.
//!   - There is no window-sizing agreement between two legs to keep in sync.
//!
//! The `Direct` exit still proxies, for a hard technical reason rather than a
//! stylistic one: re-originating raw IP on the uplink needs raw sockets, and
//! Windows has refused raw TCP sends since XP SP2. Direct therefore has to go
//! through OS sockets. Here we own both ends, so we do not.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::inspect::{Direction, TrafficMonitor};
use crate::pin::{self, EgressPin};
use crate::settings::WgSettings;
use crate::state::{ExitStats, Shared};

/// Scratch for one encapsulated/decapsulated datagram. A WireGuard datagram
/// never exceeds the outer MTU, but the peer is untrusted input: size for the
/// largest IP datagram so a malformed length can never overflow.
const SCRATCH: usize = 65535;

/// Packets drained from the TUN per wake before yielding to the other select
/// arms. Keeps one saturating flow from starving handshake/keepalive servicing.
const DRAIN_BUDGET: usize = 1024;

/// Per-protocol binding ceiling. Sized above the connection manager's TCP flow
/// ceiling so admission is decided in one place, never silently by port
/// exhaustion. At ~80 bytes of key+value per binding this costs ~2.6 MiB at
/// saturation — the whole point of routing rather than proxying this leg.
const MAX_BINDINGS: usize = 16_384;

/// NAT binding lifetimes. A binding is refreshed on every packet in either
/// direction, so these bound only genuinely silent conversations. TCP gets the
/// long timer because an established-but-idle session is normal; a RST drops the
/// binding immediately regardless.
const TCP_IDLE: Duration = Duration::from_secs(600);
const UDP_IDLE: Duration = Duration::from_secs(120);
const ICMP_IDLE: Duration = Duration::from_secs(60);
/// Reassembly-window lifetime for the inbound fragment map (RFC 1122 suggests
/// 60s; fragments older than this are unreassemblable anyway).
const FRAG_IDLE: Duration = Duration::from_secs(30);

/// Ephemeral range the NAT allocates from. Below 1024 is reserved so a rewritten
/// source is never mistaken for a service port by a middlebox.
const PORT_LO: u16 = 1024;
const PORT_HI: u16 = 65535;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// NAT44
// ============================================================================

/// Forward key: the app's full 5-tuple. Keyed on the destination too, so the
/// same local port to two different servers gets two bindings and neither has to
/// be renumbered when the other closes.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FwdKey {
    proto: u8,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
}

/// Reverse key: what a returning packet carries. The allocated port is unique
/// per protocol, so this is a total function back to one binding.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct RevKey {
    proto: u8,
    port: u16,
}

/// Inbound fragment continuation. Only the first fragment of a datagram carries
/// the L4 header, so later fragments cannot be demultiplexed by port; they are
/// matched on the sender's IP identification field instead. Outbound fragments
/// need no state at all — every outbound packet gets the same new source
/// address, so a later fragment is rewritten identically to its first.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FragKey {
    src: Ipv4Addr,
    ip_id: u16,
    proto: u8,
}

#[derive(Clone, Copy)]
struct Binding {
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    last: Instant,
}

/// Why a packet was or was not translated. Distinguishes "not ours / not
/// routable" (silent, expected) from "no capacity" (reported, an admission
/// action) so the two never read the same in the log.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    /// Rewritten in place; forward it.
    Translate,
    /// Drop silently — not a packet this exit carries.
    Drop,
    /// Drop because the binding table is full.
    Exhausted,
}

/// Stateful NAT44 between the host's addresses and the single WireGuard client
/// address. One instance, owned by the driver task — no locking, no sharing.
pub struct Nat {
    wg_addr: Ipv4Addr,
    fwd: HashMap<FwdKey, u16>,
    rev: HashMap<RevKey, Binding>,
    frag: HashMap<FragKey, (Ipv4Addr, Instant)>,
    /// Rotating allocation cursor. Rotating (rather than lowest-free) keeps a
    /// just-released port out of reuse for a full cycle, so a late duplicate from
    /// a dead conversation cannot land on a new one.
    next_port: u16,
}

impl Nat {
    pub fn new(wg_addr: Ipv4Addr) -> Self {
        Self {
            wg_addr,
            fwd: HashMap::new(),
            rev: HashMap::new(),
            frag: HashMap::new(),
            next_port: PORT_LO,
        }
    }

    pub fn bindings(&self) -> usize {
        self.rev.len()
    }

    /// Allocate an unused port for `proto`. `None` at the ceiling, which the
    /// caller reports as an admission action rather than a silent drop.
    fn alloc_port(&mut self, proto: u8) -> Option<u16> {
        if self.rev.len() >= MAX_BINDINGS {
            return None;
        }
        let span = (PORT_HI - PORT_LO) as u32 + 1;
        for _ in 0..span {
            let port = self.next_port;
            self.next_port = if port >= PORT_HI { PORT_LO } else { port + 1 };
            if !self.rev.contains_key(&RevKey { proto, port }) {
                return Some(port);
            }
        }
        None
    }

    /// Host -> peer. Rewrites the source address (and port / ICMP identifier) in
    /// place and repairs every checksum that covers them.
    pub fn translate_out(&mut self, pkt: &mut [u8], now: Instant) -> Verdict {
        let Some(h) = Ipv4Hdr::parse(pkt) else {
            return Verdict::Drop;
        };
        // Nothing link-local, multicast, broadcast, or loopback leaves through a
        // remote exit; the peer has no path back for any of it.
        if !routable(h.dst) || h.dst == self.wg_addr {
            return Verdict::Drop;
        }
        let (src, dst, new_src) = (h.src, h.dst, self.wg_addr);

        // Later fragments carry no L4 header. Every outbound packet is rewritten
        // to the same source address, so they need only the address fixup — and
        // no L4 checksum patch, because the checksum lives in the first fragment.
        if h.frag_offset != 0 {
            rewrite_src_addr(pkt, h.ihl, src, new_src, None);
            return Verdict::Translate;
        }

        let l4 = &pkt[h.ihl..];
        let (sport, dport) = match h.proto {
            PROTO_TCP | PROTO_UDP => {
                if l4.len() < 8 {
                    return Verdict::Drop;
                }
                (
                    u16::from_be_bytes([l4[0], l4[1]]),
                    u16::from_be_bytes([l4[2], l4[3]]),
                )
            }
            PROTO_ICMP => {
                if l4.len() < 8 {
                    return Verdict::Drop;
                }
                match l4[0] {
                    // Echo request: the identifier is the demultiplexing key,
                    // exactly as a port is for TCP/UDP.
                    8 => (u16::from_be_bytes([l4[4], l4[5]]), 0),
                    // Anything else the host originates has no reply to
                    // demultiplex. Forward statelessly; the ICMP checksum does
                    // not cover the IPv4 header, so only the header needs repair.
                    _ => {
                        rewrite_src_addr(pkt, h.ihl, src, new_src, None);
                        return Verdict::Translate;
                    }
                }
            }
            // Protocols with no port space (ESP, GRE, ...) cannot be multiplexed
            // behind one address without their own keying. Exactly one host sits
            // behind this NAT, so a stateless address rewrite is unambiguous.
            _ => {
                rewrite_src_addr(pkt, h.ihl, src, new_src, None);
                return Verdict::Translate;
            }
        };

        let key = FwdKey { proto: h.proto, src, sport, dst, dport };
        let port = match self.fwd.get(&key) {
            Some(p) => *p,
            None => {
                let Some(p) = self.alloc_port(h.proto) else {
                    return Verdict::Exhausted;
                };
                self.fwd.insert(key, p);
                self.rev.insert(
                    RevKey { proto: h.proto, port: p },
                    Binding { src, sport, dst, dport, last: now },
                );
                debug!("nat open {}:{} -> {}:{} as :{}", src, sport, dst, dport, p);
                p
            }
        };
        if let Some(b) = self.rev.get_mut(&RevKey { proto: h.proto, port }) {
            b.last = now;
        }

        rewrite_src_addr(pkt, h.ihl, src, new_src, Some(h.proto));
        rewrite_src_port(pkt, h.ihl, h.proto, sport, port);

        // A RST ends the conversation now rather than holding the binding for the
        // idle timer; nothing else will arrive on it.
        if h.proto == PROTO_TCP && tcp_flags(pkt, h.ihl).is_some_and(|f| f & 0x04 != 0) {
            self.close(h.proto, port);
        }
        Verdict::Translate
    }

    /// Peer -> host. Restores the original destination address and port.
    pub fn translate_in(&mut self, pkt: &mut [u8], now: Instant) -> Verdict {
        let Some(h) = Ipv4Hdr::parse(pkt) else {
            return Verdict::Drop;
        };
        if h.dst != self.wg_addr {
            return Verdict::Drop;
        }

        // Later fragment: no L4 header to key on, so use the sender's IP
        // identification, recorded when the first fragment was translated.
        if h.frag_offset != 0 {
            let fk = FragKey { src: h.src, ip_id: h.ip_id, proto: h.proto };
            let Some((orig, _)) = self.frag.get(&fk).copied() else {
                return Verdict::Drop;
            };
            rewrite_dst_addr(pkt, h.ihl, h.dst, orig, None);
            return Verdict::Translate;
        }

        let l4 = &pkt[h.ihl..];
        let port = match h.proto {
            PROTO_TCP | PROTO_UDP => {
                if l4.len() < 8 {
                    return Verdict::Drop;
                }
                u16::from_be_bytes([l4[2], l4[3]])
            }
            PROTO_ICMP => {
                if l4.len() < 8 {
                    return Verdict::Drop;
                }
                match l4[0] {
                    // Echo reply: identifier is the key.
                    0 => u16::from_be_bytes([l4[4], l4[5]]),
                    // Destination unreachable / source quench / redirect / time
                    // exceeded / parameter problem all quote the packet that
                    // caused them. That quote is one of *our* translated packets,
                    // so the mapping lives in the quote, not the outer header.
                    // Path MTU discovery depends on this working.
                    3 | 4 | 5 | 11 | 12 => return self.translate_icmp_error(pkt, h.ihl, now),
                    _ => return Verdict::Drop,
                }
            }
            _ => return Verdict::Drop,
        };

        let Some(b) = self.rev.get_mut(&RevKey { proto: h.proto, port }).map(|b| {
            b.last = now;
            *b
        }) else {
            return Verdict::Drop;
        };

        // Record the reassembly window before rewriting, while the identification
        // field and the original destination are both still known.
        if h.more_fragments {
            self.frag.insert(
                FragKey { src: h.src, ip_id: h.ip_id, proto: h.proto },
                (b.src, now),
            );
        }

        rewrite_dst_addr(pkt, h.ihl, self.wg_addr, b.src, Some(h.proto));
        rewrite_dst_port(pkt, h.ihl, h.proto, port, b.sport);

        if h.proto == PROTO_TCP && tcp_flags(pkt, h.ihl).is_some_and(|f| f & 0x04 != 0) {
            self.close(h.proto, port);
        }
        Verdict::Translate
    }

    /// Un-NAT an ICMP error by rewriting the packet it quotes. Restoring the
    /// quote's source is what lets the host's kernel match the error back to the
    /// socket that caused it.
    fn translate_icmp_error(&mut self, pkt: &mut [u8], ihl: usize, now: Instant) -> Verdict {
        // ICMP header is 8 bytes; the quoted datagram follows.
        let q = ihl + 8;
        let Some(inner) = pkt.get(q..).and_then(Ipv4Hdr::parse) else {
            return Verdict::Drop;
        };
        // The quote must be a packet we emitted.
        if inner.src != self.wg_addr {
            return Verdict::Drop;
        }
        let inner_l4 = q + inner.ihl;
        let port = match inner.proto {
            PROTO_TCP | PROTO_UDP => match pkt.get(inner_l4..inner_l4 + 2) {
                Some(b) => u16::from_be_bytes([b[0], b[1]]),
                None => return Verdict::Drop,
            },
            PROTO_ICMP => match pkt.get(inner_l4..inner_l4 + 8) {
                Some(b) if b[0] == 8 => u16::from_be_bytes([b[4], b[5]]),
                _ => return Verdict::Drop,
            },
            _ => return Verdict::Drop,
        };
        let Some(b) = self.rev.get_mut(&RevKey { proto: inner.proto, port }).map(|b| {
            b.last = now;
            *b
        }) else {
            return Verdict::Drop;
        };

        // Restore the quote in place, patching its own checksums so a strict host
        // does not discard the error, then recompute the ICMP checksum outright:
        // it covers the whole message including the quote we just rewrote. ICMP
        // errors are rare and small, so an O(n) recompute here is not a hot path.
        {
            let quote = &mut pkt[q..];
            rewrite_src_addr(quote, inner.ihl, self.wg_addr, b.src, Some(inner.proto));
            rewrite_src_port(quote, inner.ihl, inner.proto, port, b.sport);
        }
        rewrite_dst_addr(pkt, ihl, self.wg_addr, b.src, None);
        let icmp = &mut pkt[ihl..];
        icmp[2] = 0;
        icmp[3] = 0;
        let c = checksum(icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        Verdict::Translate
    }

    fn close(&mut self, proto: u8, port: u16) {
        if let Some(b) = self.rev.remove(&RevKey { proto, port }) {
            self.fwd.remove(&FwdKey {
                proto,
                src: b.src,
                sport: b.sport,
                dst: b.dst,
                dport: b.dport,
            });
        }
    }

    /// Drop bindings whose conversations have gone silent. Runs on a slow timer
    /// over a table bounded by `MAX_BINDINGS`, never on the packet path.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.rev.len();
        let fwd = &mut self.fwd;
        self.rev.retain(|k, b| {
            let idle = match k.proto {
                PROTO_TCP => TCP_IDLE,
                PROTO_UDP => UDP_IDLE,
                _ => ICMP_IDLE,
            };
            if now.duration_since(b.last) < idle {
                return true;
            }
            fwd.remove(&FwdKey {
                proto: k.proto,
                src: b.src,
                sport: b.sport,
                dst: b.dst,
                dport: b.dport,
            });
            false
        });
        self.frag
            .retain(|_, (_, seen)| now.duration_since(*seen) < FRAG_IDLE);
        before - self.rev.len()
    }
}

/// Addresses a remote exit can actually route a reply back from.
fn routable(ip: Ipv4Addr) -> bool {
    !(ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local())
}

// ============================================================================
// Header access and checksum repair
// ============================================================================

struct Ipv4Hdr {
    ihl: usize,
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ip_id: u16,
    frag_offset: u16,
    more_fragments: bool,
}

impl Ipv4Hdr {
    fn parse(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        Some(Self {
            ihl,
            proto: pkt[9],
            src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            ip_id: u16::from_be_bytes([pkt[4], pkt[5]]),
            frag_offset: u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff,
            more_fragments: pkt[6] & 0x20 != 0,
        })
    }
}

/// Byte offset of the checksum field within a TCP/UDP header. `None` for
/// protocols whose checksum does not cover the IPv4 pseudo-header, which is the
/// signal that an address rewrite needs no L4 repair at all.
fn l4_csum_offset(proto: u8) -> Option<usize> {
    match proto {
        PROTO_TCP => Some(16),
        PROTO_UDP => Some(6),
        _ => None,
    }
}

/// RFC 1624 incremental update: the checksum after replacing 16-bit word `old`
/// with `new`. Exact, and O(1) — a full recompute would be O(segment length) for
/// a four-byte edit, on every packet.
fn patch16(csum: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!csum) as u32 + (!old) as u32 + new as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn patch32(csum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let c = patch16(
        csum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new[0], new[1]]),
    );
    patch16(
        c,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new[2], new[3]]),
    )
}

/// One's-complement checksum over `data`. Used only where an incremental patch
/// is unavailable (ICMP messages, whose checksum covers a rewritten payload).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Store a patched L4 checksum, honouring UDP's two special values: a stored 0
/// means "no checksum" and must stay 0, and a computed 0 must be sent as 0xffff.
fn store_l4_csum(pkt: &mut [u8], at: usize, proto: u8, value: u16) {
    let v = if value == 0 && proto == PROTO_UDP { 0xffff } else { value };
    pkt[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// `l4` carries the protocol whose pseudo-header checksum must also be patched,
/// or `None` where there is none to patch (later fragments, ICMP, unknown L4).
fn rewrite_src_addr(pkt: &mut [u8], ihl: usize, old: Ipv4Addr, new: Ipv4Addr, l4: Option<u8>) {
    let (o, n) = (old.octets(), new.octets());
    if o == n {
        return;
    }
    pkt[12..16].copy_from_slice(&n);
    patch_hdr_csum(pkt, o, n);
    if let Some(proto) = l4 {
        patch_l4_for_addr(pkt, ihl, proto, o, n);
    }
}

fn rewrite_dst_addr(pkt: &mut [u8], ihl: usize, old: Ipv4Addr, new: Ipv4Addr, l4: Option<u8>) {
    let (o, n) = (old.octets(), new.octets());
    if o == n {
        return;
    }
    pkt[16..20].copy_from_slice(&n);
    patch_hdr_csum(pkt, o, n);
    if let Some(proto) = l4 {
        patch_l4_for_addr(pkt, ihl, proto, o, n);
    }
}

fn patch_hdr_csum(pkt: &mut [u8], old: [u8; 4], new: [u8; 4]) {
    let cur = u16::from_be_bytes([pkt[10], pkt[11]]);
    let c = patch32(cur, old, new);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
}

/// The TCP/UDP checksum covers an IPv4 pseudo-header containing both addresses,
/// so an address rewrite invalidates it as surely as a port rewrite does.
fn patch_l4_for_addr(pkt: &mut [u8], ihl: usize, proto: u8, old: [u8; 4], new: [u8; 4]) {
    let Some(off) = l4_csum_offset(proto) else {
        return;
    };
    let at = ihl + off;
    if pkt.len() < at + 2 {
        return;
    }
    let cur = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
    if proto == PROTO_UDP && cur == 0 {
        return; // checksum disabled by the sender
    }
    store_l4_csum(pkt, at, proto, patch32(cur, old, new));
}

fn rewrite_src_port(pkt: &mut [u8], ihl: usize, proto: u8, old: u16, new: u16) {
    if old == new {
        return;
    }
    match proto {
        PROTO_TCP | PROTO_UDP => {
            if pkt.len() < ihl + 4 {
                return;
            }
            pkt[ihl..ihl + 2].copy_from_slice(&new.to_be_bytes());
            patch_l4_for_port(pkt, ihl, proto, old, new);
        }
        PROTO_ICMP => patch_icmp_id(pkt, ihl, old, new),
        _ => {}
    }
}

fn rewrite_dst_port(pkt: &mut [u8], ihl: usize, proto: u8, old: u16, new: u16) {
    if old == new {
        return;
    }
    match proto {
        PROTO_TCP | PROTO_UDP => {
            if pkt.len() < ihl + 4 {
                return;
            }
            pkt[ihl + 2..ihl + 4].copy_from_slice(&new.to_be_bytes());
            patch_l4_for_port(pkt, ihl, proto, old, new);
        }
        PROTO_ICMP => patch_icmp_id(pkt, ihl, old, new),
        _ => {}
    }
}

fn patch_l4_for_port(pkt: &mut [u8], ihl: usize, proto: u8, old: u16, new: u16) {
    let Some(off) = l4_csum_offset(proto) else {
        return;
    };
    let at = ihl + off;
    if pkt.len() < at + 2 {
        return;
    }
    let cur = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
    if proto == PROTO_UDP && cur == 0 {
        return;
    }
    store_l4_csum(pkt, at, proto, patch16(cur, old, new));
}

/// The ICMP checksum covers the identifier but not the IPv4 header, so an echo
/// rewrite needs exactly this one patch.
fn patch_icmp_id(pkt: &mut [u8], ihl: usize, old: u16, new: u16) {
    if pkt.len() < ihl + 8 {
        return;
    }
    pkt[ihl + 4..ihl + 6].copy_from_slice(&new.to_be_bytes());
    let at = ihl + 2;
    let cur = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
    let c = patch16(cur, old, new);
    pkt[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

fn tcp_flags(pkt: &[u8], ihl: usize) -> Option<u8> {
    pkt.get(ihl + 13).copied()
}

// ============================================================================
// Driver
// ============================================================================

/// Run the WireGuard exit until shutdown. Owns the encrypted socket, the
/// boringtun session, and the NAT table; nothing else touches them, so none of
/// it needs a lock.
pub async fn route(
    config: WgConfig,
    egress: EgressPin,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    monitor: Arc<TrafficMonitor>,
    stats: Arc<ExitStats>,
    shared: Arc<Shared>,
) -> Result<()> {
    // Encrypted socket to the peer, pinned to the physical uplink so it bypasses
    // our own TUN default route (and carries the kill switch's mark).
    let udp = pin::bind_udp(config.endpoint, &egress)
        .await
        .context("failed to bind the WireGuard endpoint socket")?;
    udp.connect(config.endpoint)
        .await
        .context("failed to connect the WireGuard endpoint socket")?;

    let mut tunn = Tunn::new(
        StaticSecret::from(config.private_key),
        PublicKey::from(config.peer_public),
        config.preshared,
        config.keepalive,
        0,
        None,
    );

    let mut nat = Nat::new(config.address);
    let mut scratch = vec![0u8; SCRATCH];
    let mut recv_buf = vec![0u8; SCRATCH];

    // boringtun's handshake, keepalive, and rekey timers advance independently of
    // data flow.
    let mut wg_timer = tokio::time::interval(Duration::from_millis(250));
    let mut housekeeping = tokio::time::interval(Duration::from_secs(10));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut session_logged = false;
    let mut shed: u64 = 0;
    info!(
        "WireGuard exit routing as {} -> {} (NAT44, no inner TCP stack)",
        config.address, config.endpoint
    );

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutdown signal — restoring routing");
                break;
            }
            first = tun_rx.recv() => {
                let Some(mut pkt) = first else {
                    warn!("TUN reader closed — stopping");
                    break;
                };
                // Drain a burst so one wake amortises many packets. The awaited
                // send is the only backpressure seam and it is per-datagram, so
                // nothing accumulates in an intermediate queue.
                let mut drained = 0usize;
                loop {
                    monitor.record(Direction::Up, &pkt);
                    match nat.translate_out(&mut pkt, Instant::now()) {
                        Verdict::Translate => {
                            if let TunnResult::WriteToNetwork(out) =
                                tunn.encapsulate(&pkt, &mut scratch)
                            {
                                stats.written.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                                if udp.send(out).await.is_err() {
                                    warn!("WireGuard endpoint socket closed");
                                    return Ok(());
                                }
                            }
                        }
                        Verdict::Exhausted => {
                            shed += 1;
                            if shed.is_power_of_two() {
                                warn!(
                                    "NAT table full at {} bindings — {} packets shed",
                                    nat.bindings(), shed
                                );
                            }
                        }
                        Verdict::Drop => {}
                    }
                    drained += 1;
                    if drained >= DRAIN_BUDGET {
                        break;
                    }
                    match tun_rx.try_recv() {
                        Ok(next) => pkt = next,
                        Err(_) => break,
                    }
                }
            }
            r = udp.recv(&mut recv_buf) => {
                let Ok(n) = r else { continue };
                if !deliver(&mut tunn, n, &recv_buf, &mut scratch, &mut nat,
                            &udp, &tun_tx, &monitor, &stats).await {
                    return Ok(());
                }
                if !session_logged && stats.read.load(Ordering::Relaxed) > 0 {
                    debug!("wireguard: session established (first data decrypted)");
                    session_logged = true;
                }
                // Drain the rest of the burst so a busy return path is not
                // serviced one datagram per wakeup.
                while let Ok(n) = udp.try_recv(&mut recv_buf) {
                    if !deliver(&mut tunn, n, &recv_buf, &mut scratch, &mut nat,
                                &udp, &tun_tx, &monitor, &stats).await {
                        return Ok(());
                    }
                }
            }
            _ = wg_timer.tick() => {
                if let TunnResult::WriteToNetwork(out) = tunn.update_timers(&mut scratch) {
                    let _ = udp.send(out).await;
                }
            }
            _ = housekeeping.tick() => {
                let dropped = nat.expire(Instant::now());
                if dropped > 0 {
                    debug!("nat: expired {} bindings, {} live", dropped, nat.bindings());
                }
            }
        }

        // wg_timer fires every 250 ms regardless of traffic, so a dashboard
        // close is observed within one tick — no dedicated polling arm needed.
        if shared.shutdown.load(Ordering::Relaxed) {
            info!("Dashboard closed — restoring routing");
            break;
        }
    }
    Ok(())
}

/// Decrypt one datagram from the peer and deliver whatever it yields. Returns
/// false when the TUN writer or endpoint socket is gone and the driver must stop.
#[allow(clippy::too_many_arguments)]
async fn deliver(
    tunn: &mut Tunn,
    n: usize,
    recv_buf: &[u8],
    scratch: &mut [u8],
    nat: &mut Nat,
    udp: &tokio::net::UdpSocket,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    monitor: &TrafficMonitor,
    stats: &ExitStats,
) -> bool {
    // boringtun queues packets during a handshake and releases them once the
    // session opens, so one datagram in can produce several out: feed it once,
    // then keep calling with an empty input until it reports Done. The ciphertext
    // lives in `recv_buf` and the plaintext in `scratch`, two disjoint buffers,
    // so the borrows never alias.
    let mut input: &[u8] = &recv_buf[..n];
    loop {
        let res = tunn.decapsulate(None, input, scratch);
        input = &[];
        match res {
            // Handshake / cookie / keepalive traffic back to the peer.
            TunnResult::WriteToNetwork(out) => {
                if udp.send(out).await.is_err() {
                    return false;
                }
            }
            TunnResult::WriteToTunnelV4(pkt, _) => {
                stats.read.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                if nat.translate_in(pkt, Instant::now()) == Verdict::Translate {
                    let owned = pkt.to_vec();
                    monitor.record(Direction::Down, &owned);
                    if tun_tx.send(owned).await.is_err() {
                        warn!("TUN writer closed");
                        return false;
                    }
                }
            }
            // The engine captures IPv4 only and the kill switch drops IPv6 out
            // the uplink, so an inner v6 packet has nowhere to go.
            TunnResult::WriteToTunnelV6(_, _) => {}
            TunnResult::Done | TunnResult::Err(_) => break,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
    const WG: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 2);
    const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// A valid IPv4 header sums to zero in one's complement.
    fn hdr_ok(pkt: &[u8]) -> bool {
        checksum(&pkt[..20]) == 0
    }

    /// A valid TCP checksum over the pseudo-header + segment sums to zero.
    fn tcp_ok(pkt: &[u8]) -> bool {
        let l4 = &pkt[20..];
        let mut buf = Vec::with_capacity(12 + l4.len());
        buf.extend_from_slice(&pkt[12..20]);
        buf.push(0);
        buf.push(PROTO_TCP);
        buf.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        buf.extend_from_slice(l4);
        checksum(&buf) == 0
    }

    fn tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50; // data offset 5
        p[33] = flags;
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(&p[12..20]);
        buf.push(0);
        buf.push(PROTO_TCP);
        buf.extend_from_slice(&20u16.to_be_bytes());
        buf.extend_from_slice(&p[20..]);
        let c = checksum(&buf);
        p[36..38].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn synthetic_packets_start_valid() {
        let p = tcp_packet(HOST, SERVER, 40000, 443, 0x02);
        assert!(hdr_ok(&p) && tcp_ok(&p));
    }

    #[test]
    fn tcp_round_trip_restores_the_original_tuple() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let mut out = tcp_packet(HOST, SERVER, 40000, 443, 0x02);

        assert_eq!(nat.translate_out(&mut out, now), Verdict::Translate);
        assert_eq!(out[12..16], WG.octets());
        let natted = u16::from_be_bytes([out[20], out[21]]);
        assert_ne!(natted, 40000);
        assert!(hdr_ok(&out), "IPv4 header checksum not repaired");
        assert!(tcp_ok(&out), "TCP checksum not repaired");

        let mut back = tcp_packet(SERVER, WG, 443, natted, 0x12);
        assert_eq!(nat.translate_in(&mut back, now), Verdict::Translate);
        assert_eq!(back[16..20], HOST.octets());
        assert_eq!(u16::from_be_bytes([back[22], back[23]]), 40000);
        assert!(hdr_ok(&back) && tcp_ok(&back));
    }

    #[test]
    fn same_local_port_to_two_servers_gets_two_bindings() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let other = Ipv4Addr::new(1, 1, 1, 1);
        let mut a = tcp_packet(HOST, SERVER, 40000, 443, 0x02);
        let mut b = tcp_packet(HOST, other, 40000, 443, 0x02);
        nat.translate_out(&mut a, now);
        nat.translate_out(&mut b, now);
        assert_ne!(
            u16::from_be_bytes([a[20], a[21]]),
            u16::from_be_bytes([b[20], b[21]])
        );
        assert_eq!(nat.bindings(), 2);
    }

    #[test]
    fn repeat_packets_reuse_one_binding() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        for _ in 0..16 {
            let mut p = tcp_packet(HOST, SERVER, 40000, 443, 0x10);
            assert_eq!(nat.translate_out(&mut p, now), Verdict::Translate);
        }
        assert_eq!(nat.bindings(), 1);
    }

    #[test]
    fn rst_closes_the_binding_immediately() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let mut p = tcp_packet(HOST, SERVER, 40000, 443, 0x02);
        nat.translate_out(&mut p, now);
        assert_eq!(nat.bindings(), 1);
        let mut r = tcp_packet(HOST, SERVER, 40000, 443, 0x04); // RST
        nat.translate_out(&mut r, now);
        assert_eq!(nat.bindings(), 0);
    }

    #[test]
    fn unsolicited_inbound_is_dropped() {
        let mut nat = Nat::new(WG);
        let mut p = tcp_packet(SERVER, WG, 443, 40000, 0x12);
        assert_eq!(nat.translate_in(&mut p, Instant::now()), Verdict::Drop);
    }

    #[test]
    fn multicast_and_broadcast_never_leave() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let mut m = tcp_packet(HOST, Ipv4Addr::new(224, 0, 0, 251), 5353, 5353, 0);
        assert_eq!(nat.translate_out(&mut m, now), Verdict::Drop);
        let mut b = tcp_packet(HOST, Ipv4Addr::new(255, 255, 255, 255), 68, 67, 0);
        assert_eq!(nat.translate_out(&mut b, now), Verdict::Drop);
    }

    #[test]
    fn idle_bindings_expire_by_protocol_timer() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let mut p = tcp_packet(HOST, SERVER, 40000, 443, 0x02);
        nat.translate_out(&mut p, now);
        assert_eq!(nat.expire(now + Duration::from_secs(60)), 0);
        assert_eq!(nat.expire(now + TCP_IDLE + Duration::from_secs(1)), 1);
        assert_eq!(nat.bindings(), 0);
    }

    #[test]
    fn incremental_patch_equals_full_recompute() {
        // The whole NAT rests on RFC 1624 being exact: patching a header must
        // give bit-for-bit what recomputing it from scratch would.
        let mut patched = tcp_packet(HOST, SERVER, 40000, 443, 0x18);
        rewrite_src_addr(&mut patched, 20, HOST, WG, Some(PROTO_TCP));

        let fresh = tcp_packet(WG, SERVER, 40000, 443, 0x18);
        assert_eq!(
            u16::from_be_bytes([patched[10], patched[11]]),
            u16::from_be_bytes([fresh[10], fresh[11]]),
            "IPv4 header checksum diverges from a full recompute"
        );
        assert_eq!(
            u16::from_be_bytes([patched[36], patched[37]]),
            u16::from_be_bytes([fresh[36], fresh[37]]),
            "TCP checksum diverges from a full recompute"
        );
    }

    #[test]
    fn udp_zero_checksum_is_left_disabled() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&HOST.octets());
        p[16..20].copy_from_slice(&SERVER.octets());
        p[20..22].copy_from_slice(&5353u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        // p[26..28] (checksum) stays zero: the sender disabled it.
        let mut nat = Nat::new(WG);
        assert_eq!(nat.translate_out(&mut p, Instant::now()), Verdict::Translate);
        assert_eq!(u16::from_be_bytes([p[26], p[27]]), 0);
    }

    #[test]
    fn icmp_echo_identifier_is_mapped_both_ways() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&HOST.octets());
        p[16..20].copy_from_slice(&SERVER.octets());
        p[20] = 8; // echo request
        p[24..26].copy_from_slice(&0xbeefu16.to_be_bytes());
        let c = checksum(&p[20..]);
        p[22..24].copy_from_slice(&c.to_be_bytes());

        let mut nat = Nat::new(WG);
        let now = Instant::now();
        assert_eq!(nat.translate_out(&mut p, now), Verdict::Translate);
        let id = u16::from_be_bytes([p[24], p[25]]);
        assert_ne!(id, 0xbeef);
        assert_eq!(checksum(&p[20..]), 0, "ICMP checksum not repaired");

        let mut r = vec![0u8; 28];
        r[0] = 0x45;
        r[9] = PROTO_ICMP;
        r[12..16].copy_from_slice(&SERVER.octets());
        r[16..20].copy_from_slice(&WG.octets());
        r[20] = 0; // echo reply
        r[24..26].copy_from_slice(&id.to_be_bytes());
        let c = checksum(&r[20..]);
        r[22..24].copy_from_slice(&c.to_be_bytes());
        assert_eq!(nat.translate_in(&mut r, now), Verdict::Translate);
        assert_eq!(u16::from_be_bytes([r[24], r[25]]), 0xbeef);
        assert_eq!(r[16..20], HOST.octets());
    }

    #[test]
    fn icmp_error_quote_is_restored_so_pmtud_works() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        let mut out = tcp_packet(HOST, SERVER, 40000, 443, 0x02);
        nat.translate_out(&mut out, now);

        // Fragmentation-needed error quoting our translated packet.
        let mut e = vec![0u8; 20 + 8 + out.len()];
        e[0] = 0x45;
        e[9] = PROTO_ICMP;
        e[12..16].copy_from_slice(&Ipv4Addr::new(10, 9, 9, 9).octets());
        e[16..20].copy_from_slice(&WG.octets());
        e[20] = 3; // destination unreachable
        e[21] = 4; // fragmentation needed
        e[26..28].copy_from_slice(&1400u16.to_be_bytes());
        e[28..].copy_from_slice(&out);
        let c = checksum(&e[20..]);
        e[22..24].copy_from_slice(&c.to_be_bytes());

        assert_eq!(nat.translate_in(&mut e, now), Verdict::Translate);
        assert_eq!(e[16..20], HOST.octets(), "error not addressed to the host");
        let quote = &e[28..];
        assert_eq!(quote[12..16], HOST.octets(), "quote source not restored");
        assert_eq!(
            u16::from_be_bytes([quote[20], quote[21]]),
            40000,
            "quote source port not restored"
        );
        assert_eq!(checksum(&e[20..]), 0, "ICMP checksum not recomputed");
    }

    #[test]
    fn binding_ceiling_is_reported_not_silently_dropped() {
        let mut nat = Nat::new(WG);
        let now = Instant::now();
        for i in 0..MAX_BINDINGS {
            let dport = 1 + (i % 65535) as u16;
            let sport = 1024u16.wrapping_add((i / 65535) as u16);
            let mut p = tcp_packet(HOST, SERVER, sport, dport, 0x02);
            assert_eq!(nat.translate_out(&mut p, now), Verdict::Translate);
        }
        let mut p = tcp_packet(HOST, Ipv4Addr::new(8, 8, 8, 8), 999, 8443, 0x02);
        assert_eq!(nat.translate_out(&mut p, now), Verdict::Exhausted);
    }
}
