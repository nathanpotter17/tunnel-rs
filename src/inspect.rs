//! Traffic inspection for observability.

use std::collections::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Number of throughput samples retained for the live graph (~2 minutes at 1s).
pub const SERIES_LEN: usize = 120;
/// Maximum flows REPORTED in a snapshot (display cap). Retention is total:
/// evicted flows are archived, never discarded — see `Inner::archive`.
const MAX_FLOWS: usize = 256;
/// Flows idle longer than this are moved from the live table to the archive.
const FLOW_IDLE_EVICT: Duration = Duration::from_secs(90);
/// Hard cap on live per-flow rows tracked at once. The data path (conn.rs) is
/// memory-budgeted against attacker-influenced unbounded flow creation; the
/// monitor MUST be too, or a flow flood exhausts memory here regardless of what
/// conn.rs sheds. Global byte/packet totals are always counted; only NEW
/// per-flow tracking is declined once full. Sized at conn.rs's MAX_TCP_FLOWS.
const MAX_LIVE_FLOWS: usize = 8192;
/// Maximum unique remote hosts reported in a snapshot (display cap).
const MAX_HOSTS: usize = 128;
/// Maximum unique remote service ports reported in a snapshot (display cap).
const MAX_PORTS: usize = 64;
/// Hard cap on archived (evicted) flow records. Oldest are dropped past this so
/// a long, churny session can't grow the archive without bound; the dropped
/// count is reported once at shutdown.
const MAX_ARCHIVE: usize = 65_536;

/// Cap on remote hosts remembered as uTP/DHT speakers (see `Inner::bt_hosts`).
const MAX_BT_HOSTS: usize = 65_536;

/// Packet direction relative to the local host.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound: leaving this host, headed into the tunnel.
    Up,
    /// Inbound: arriving from the tunnel, headed to this host.
    Down,
}

/// Layer-4 protocol.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl L4 {
    pub fn label(self) -> &'static str {
        match self {
            L4::Tcp => "TCP",
            L4::Udp => "UDP",
            L4::Icmp => "ICMP",
            // Name the IP protocols we can meet in practice; the generic "IP"
            // bucket is a last resort, not the default for anything known.
            L4::Other(n) => match n {
                2 => "IGMP",
                44 => "Frag", // non-first IPv6 fragment: L4 header not present
                47 => "GRE",
                50 => "ESP",
                51 => "AH",
                89 => "OSPF",
                132 => "SCTP",
                _ => "IP",
            },
        }
    }
}

/// Application-protocol classification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AppProto {
    Dns,
    Mdns,
    Llmnr,
    Ssdp,
    NetBios,
    Http,
    Tls,
    Quic,
    WireGuard,
    OpenVpn,
    Shadowsocks,
    Obfuscated,
    /// `Obfuscated`, to a host that also carries uTP or DHT — the shape of a
    /// BitTorrent peer with Message Stream Encryption, whose ciphertext has no
    /// signature of its own. Set by cross-referencing flows in the monitor,
    /// never by the per-packet classifier.
    ObfuscatedBt,
    /// Peer wire protocol over TCP (BEP 3).
    BitTorrent,
    /// Micro Transport Protocol (BEP 29) — BitTorrent's UDP transport, and the
    /// bulk of a swarm's bytes. Carries piece data, so it dominates a torrent
    /// session by volume while every other BitTorrent label stays tiny.
    ///
    /// Labelled `uTP`, not `µTP`. The bundled fonts do carry U+00B5, but this
    /// label is also written to the flow CSV, and ASCII there is worth more than
    /// the correct spelling here.
    Utp,
    /// Mainline DHT (BEP 5): bencoded KRPC over UDP. Many small exchanges with
    /// many peers, so it dominates by FLOW COUNT rather than by bytes.
    Dht,
    /// UDP tracker protocol (BEP 15).
    BtTracker,
    Ssh,
    Ntp,
    Dhcp,
    Dhcpv6,
    Igmp,
    Icmp,
    Other,
}

impl AppProto {
    pub fn label(self) -> &'static str {
        match self {
            AppProto::Dns => "DNS",
            AppProto::Mdns => "mDNS",
            AppProto::Llmnr => "LLMNR",
            AppProto::Ssdp => "SSDP",
            AppProto::NetBios => "NetBIOS",
            AppProto::Http => "HTTP",
            AppProto::Tls => "TLS",
            AppProto::Quic => "QUIC",
            AppProto::WireGuard => "WireGuard",
            AppProto::OpenVpn => "OpenVPN",
            AppProto::Shadowsocks => "Shadowsocks",
            AppProto::Obfuscated => "Obfuscated",
            AppProto::ObfuscatedBt => "Obfuscated (uTP/DHT)",
            AppProto::BitTorrent => "BitTorrent",
            AppProto::Utp => "uTP",
            AppProto::Dht => "DHT",
            AppProto::BtTracker => "BT Tracker",
            AppProto::Ssh => "SSH",
            AppProto::Ntp => "NTP",
            AppProto::Dhcp => "DHCP",
            AppProto::Dhcpv6 => "DHCPv6",
            AppProto::Igmp => "IGMP",
            AppProto::Icmp => "ICMP",
            AppProto::Other => "Other",
        }
    }

    /// Classification confidence tier. `record` only ever raises a flow's
    /// tier — a later weak guess must never overwrite an earlier strong
    /// identification (Obfuscated must not fall back to Other because one
    /// small low-entropy packet arrived).
    fn rank(self) -> u8 {
        match self {
            AppProto::Other => 0,
            // Equal so a later random packet can neither downgrade the host
            // relabel nor re-trigger it; a real signature still beats both.
            AppProto::Obfuscated | AppProto::ObfuscatedBt => 1,
            // Port-derived and L4-derived labels.
            AppProto::Dns
            | AppProto::Mdns
            | AppProto::Llmnr
            | AppProto::Ssdp
            | AppProto::NetBios
            | AppProto::Http
            | AppProto::Ssh
            | AppProto::Ntp
            | AppProto::Dhcp
            | AppProto::Dhcpv6
            | AppProto::OpenVpn
            | AppProto::Shadowsocks
            | AppProto::Igmp
            | AppProto::Icmp => 2,
            // Payload-signature protocols. The BitTorrent family sits here
            // because none of it is recognised by port — it is signature or
            // nothing. Ranking equal to the rest also means first-match wins
            // within a flow, which is what protects a tracker exchange whose
            // opening magic is unmistakable from being relabelled by a later
            // announce that carries no signature at all.
            AppProto::Tls
            | AppProto::Quic
            | AppProto::WireGuard
            | AppProto::BitTorrent
            | AppProto::Utp
            | AppProto::Dht
            | AppProto::BtTracker => 3,
        }
    }
}

/// Engine lifecycle status of a flow, set by the connection manager's admission
/// control. The default is `Active` (a normal proxied flow). `Shed` and `Reaped`
/// mark flows the engine deliberately did NOT carry — so the dashboard and CSV
/// present them as expected admission-control actions instead of anomalous
/// up-only or half-open conversations (a shed SYN gets no reply; a reaped
/// half-open dies before Established).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FlowStatus {
    /// Normal proxied flow.
    Active,
    /// Admission was denied (over the memory budget / flow ceiling); the SYN or
    /// first datagram was dropped rather than allocated. The peer retransmits.
    Shed,
    /// A half-open flow that never reached Established within the handshake
    /// window, torn down by the engine.
    Reaped,
}

impl FlowStatus {
    /// Display/CSV label. `Active` is empty so ordinary rows carry no badge.
    pub fn label(self) -> &'static str {
        match self {
            FlowStatus::Active => "",
            FlowStatus::Shed => "shed",
            FlowStatus::Reaped => "reaped",
        }
    }
}

/// A parsed packet's routing-relevant fields.
struct ParsedPacket {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    l4: L4,
    app: AppProto,
    len: usize,
}

/// Parse an IPv4/IPv6 packet enough to fingerprint the flow. Returns `None`
/// for packets we can't make sense of (truncated, unknown version, etc.).
fn parse(pkt: &[u8]) -> Option<ParsedPacket> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None,
    }
}

fn parse_v4(pkt: &[u8]) -> Option<ParsedPacket> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let proto = pkt[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let l4_payload = &pkt[ihl..];
    finish(src_ip, dst_ip, proto, l4_payload, pkt.len())
}

fn parse_v6(pkt: &[u8]) -> Option<ParsedPacket> {
    if pkt.len() < 40 {
        return None;
    }
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&pkt[8..24]);
    d.copy_from_slice(&pkt[24..40]);
    let src_ip = IpAddr::V6(Ipv6Addr::from(s));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(d));

    // Chase extension headers to the real transport header. Without this,
    // MLD (Hop-by-Hop → ICMPv6) and similar traffic reports as bare "IP".
    let mut next = pkt[6];
    let mut off = 40usize;
    loop {
        match next {
            // Hop-by-Hop (0), Routing (43), Destination Options (60):
            // [next header, hdr ext len in 8-byte units minus 1, ...].
            0 | 43 | 60 => {
                if pkt.len() < off + 8 {
                    return None;
                }
                let hdr_len = 8 + (pkt[off + 1] as usize) * 8;
                if pkt.len() < off + hdr_len {
                    return None;
                }
                next = pkt[off];
                off += hdr_len;
            }
            // Fragment (44): fixed 8 bytes. Only the first fragment carries
            // the transport header; later fragments are recorded as "Frag"
            // so their bytes are still counted, honestly labeled.
            44 => {
                if pkt.len() < off + 8 {
                    return None;
                }
                let frag_off = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) >> 3;
                let nh = pkt[off];
                off += 8;
                if frag_off != 0 {
                    return finish(src_ip, dst_ip, 44, &[], pkt.len());
                }
                next = nh;
            }
            // Authentication Header (51): payload len in 4-byte units, +2.
            51 => {
                if pkt.len() < off + 8 {
                    return None;
                }
                let hdr_len = ((pkt[off + 1] as usize) + 2) * 4;
                if pkt.len() < off + hdr_len {
                    return None;
                }
                next = pkt[off];
                off += hdr_len;
            }
            _ => break,
        }
    }
    finish(src_ip, dst_ip, next, &pkt[off..], pkt.len())
}

fn finish(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto: u8,
    l4: &[u8],
    total_len: usize,
) -> Option<ParsedPacket> {
    let (l4_kind, src_port, dst_port, payload) = match proto {
        6 => {
            // TCP: data offset (high nibble of byte 12) gives header length.
            if l4.len() < 20 {
                return None;
            }
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            let data_off = ((l4[12] >> 4) as usize) * 4;
            let payload = if l4.len() > data_off { &l4[data_off..] } else { &[][..] };
            (L4::Tcp, sp, dp, payload)
        }
        17 => {
            if l4.len() < 8 {
                return None;
            }
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            (L4::Udp, sp, dp, &l4[8..])
        }
        1 | 58 => (L4::Icmp, 0, 0, &[][..]),
        other => (L4::Other(other), 0, 0, &[][..]),
    };

    let app = classify(l4_kind, src_port, dst_port, payload);
    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        l4: l4_kind,
        app,
        len: total_len,
    })
}

/// Classify a packet by application protocol using port + signature heuristics.
fn classify(l4: L4, sport: u16, dport: u16, payload: &[u8]) -> AppProto {
    if matches!(l4, L4::Icmp) {
        return AppProto::Icmp;
    }
    if let L4::Other(2) = l4 {
        return AppProto::Igmp;
    }
    let has = |p: u16| sport == p || dport == p;

    // Strong payload signatures first — these beat port guesses.
    if matches!(l4, L4::Udp) {
        if is_wireguard(payload) {
            return AppProto::WireGuard;
        }
        if is_quic(payload) {
            return AppProto::Quic;
        }
        // BitTorrent negotiates its ports, so there is nothing to look them up
        // by — every one of these is decided on payload shape alone. Ordered
        // most specific first, though the three cannot collide: a tracker
        // request opens with two zero bytes, DHT with 'd' (0x64), and uTP
        // requires a version nibble of 1, which neither satisfies.
        if is_bt_tracker(payload) {
            return AppProto::BtTracker;
        }
        if is_dht(payload) {
            return AppProto::Dht;
        }
        if is_utp(payload) {
            return AppProto::Utp;
        }
    }
    if matches!(l4, L4::Tcp) {
        if is_tls(payload) {
            return AppProto::Tls;
        }
        if is_bittorrent(payload) {
            return AppProto::BitTorrent;
        }
        // HTTP trackers conventionally listen on 6969, 2710 or 1337 — none a
        // port rule knows — and on 80 they would otherwise read as plain HTTP.
        // (An HTTPS tracker is TLS like everything else on 443.)
        if is_http_tracker(payload) {
            return AppProto::BtTracker;
        }
    }

    // Well-known ports. 53 before 5353 so unicast DNS keeps its label.
    if has(53) {
        return AppProto::Dns;
    }
    if has(5353) {
        return AppProto::Mdns;
    }
    if has(5355) {
        return AppProto::Llmnr;
    }
    if has(1900) {
        return AppProto::Ssdp;
    }
    if has(137) || has(138) || has(139) {
        return AppProto::NetBios;
    }
    if has(67) || has(68) {
        return AppProto::Dhcp;
    }
    if has(546) || has(547) {
        return AppProto::Dhcpv6;
    }
    if has(123) {
        return AppProto::Ntp;
    }
    if has(22) {
        return AppProto::Ssh;
    }
    if has(51820) && matches!(l4, L4::Udp) {
        return AppProto::WireGuard;
    }
    if has(1194) {
        return AppProto::OpenVpn;
    }
    if has(8388) || has(8389) {
        return AppProto::Shadowsocks;
    }
    if has(443) {
        return if matches!(l4, L4::Udp) { AppProto::Quic } else { AppProto::Tls };
    }
    if has(80) || has(8080) {
        return AppProto::Http;
    }

    // Fallback: an unknown port carrying high-entropy TCP/UDP payload is a
    // strong hint of an obfuscated/encrypted proxy (Shadowsocks, VMess, a
    // BitTorrent peer with Message Stream Encryption, etc.).
    if matches!(l4, L4::Tcp | L4::Udp) && looks_random(payload) {
        return AppProto::Obfuscated;
    }

    AppProto::Other
}

/// WireGuard message: type byte in 1..=4, three reserved zero bytes, AND the
/// fixed/constrained lengths of the protocol's four message types. The length
/// check eliminates false positives (e.g. a DNS query with ID 0x01?? and zero
/// flags satisfies the 4-byte prefix alone).
fn is_wireguard(p: &[u8]) -> bool {
    if p.len() < 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
        return false;
    }
    match p[0] {
        1 => p.len() == 148,                              // handshake initiation
        2 => p.len() == 92,                               // handshake response
        3 => p.len() == 64,                               // cookie reply
        4 => p.len() >= 32 && (p.len() - 16) % 16 == 0,   // transport data
        _ => false,
    }
}

/// QUIC long header: header-form + fixed bit set, and a known version
/// (v1, v2, or version negotiation). Catches QUIC on any UDP port.
fn is_quic(p: &[u8]) -> bool {
    if p.len() < 5 || p[0] & 0xc0 != 0xc0 {
        return false;
    }
    let v = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    matches!(v, 0x0000_0000 | 0x0000_0001 | 0x6b33_43cf)
}

/// TLS record: handshake(0x16) with a plausible ProtocolVersion (0x03 0x0x).
fn is_tls(p: &[u8]) -> bool {
    p.len() >= 3 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04
}

/// BitTorrent peer handshake (BEP 3): a length byte of 19 followed by exactly
/// that many characters of the protocol name. Nothing to tune and no false
/// positive to weigh — but it only catches UNENCRYPTED peer connections. A
/// client with Message Stream Encryption on opens with a Diffie-Hellman key,
/// which is random by construction and lands in `Obfuscated` via
/// `looks_random` — that is the label most of today's swarm peers get.
fn is_bittorrent(p: &[u8]) -> bool {
    p.len() >= 20 && p[0] == 19 && &p[1..20] == b"BitTorrent protocol"
}

/// HTTP tracker request (BEP 3): a GET whose path ends in `announce` or
/// `scrape` — `/announce`, `/announce.php`, `/<passkey>/announce`. Only the
/// request line is examined, so a page that merely mentions the word does not
/// match, and the scan is bounded by the first line break.
fn is_http_tracker(p: &[u8]) -> bool {
    let Some(rest) = p.strip_prefix(b"GET /") else {
        return false;
    };
    // Request line: path up to the space before "HTTP/1.x". Bound the scan so
    // a huge first segment cannot make this walk the whole payload.
    let line = &rest[..rest.len().min(512)];
    let Some(end) = line.iter().position(|&b| b == b' ' || b == b'\r' || b == b'\n') else {
        return false;
    };
    let path = &line[..end];
    // Path without the query string.
    let path = match path.iter().position(|&b| b == b'?') {
        Some(q) => &path[..q],
        None => path,
    };
    let last = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    // Exactly the verb, or the verb with a script extension (announce.php).
    let verb = match last.iter().position(|&b| b == b'.') {
        Some(dot) => &last[..dot],
        None => last,
    };
    verb == b"announce" || verb == b"scrape"
}

/// uTP (BEP 29): 20-byte header, low nibble of byte 0 the version (always 1),
/// high nibble the packet type (0..=4).
///
/// Those nibbles alone match one byte in 51, which across a saturated swarm is a
/// steady trickle of mislabelled flows. Two structural checks close it: the
/// extension field is a short chain (0, 1 or 2 in every implementation in the
/// wild), and the advertised window is a real receive buffer rather than a
/// random word. Together they leave roughly one random payload in a million.
fn is_utp(p: &[u8]) -> bool {
    if p.len() < 20 {
        return false;
    }
    let (kind, version) = (p[0] >> 4, p[0] & 0x0f);
    if version != 1 || kind > 4 || p[1] > 2 {
        return false;
    }
    let window = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
    window <= 16 * 1024 * 1024
}

/// Mainline DHT (BEP 5): bencoded KRPC over UDP.
///
/// Matched on the first key only. Bencode sorts a dict's keys, so the opener is
/// fixed: `a` for a query's arguments, `r` for a response, `e` for an error, or
/// `ip` where a client prepends the caller's address (BEP 42) — which sorts
/// ahead of all three. The message-type key `y` would be a stronger signature
/// but sorts LAST, and finding it means walking the whole payload on the packet
/// path to reject most of them at the final byte.
fn is_dht(p: &[u8]) -> bool {
    if p.len() < 12 || p[0] != b'd' {
        return false;
    }
    let rest = &p[1..];
    rest.starts_with(b"1:ad")
        || rest.starts_with(b"1:rd")
        || rest.starts_with(b"1:el")
        || rest.starts_with(b"2:ip")
}

/// UDP tracker protocol (BEP 15) connect request: the protocol's magic
/// connection id followed by action 0.
///
/// Only the connect handshake is detectable — announce and scrape quote the id
/// the tracker just issued, which is indistinguishable from any other eight
/// bytes. That is enough, because connect is the FIRST packet of a tracker
/// exchange and a flow is labelled from its first packet.
fn is_bt_tracker(p: &[u8]) -> bool {
    const MAGIC: [u8; 8] = [0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80];
    p.len() >= 16 && p[..8] == MAGIC && p[8..12] == [0, 0, 0, 0]
}

/// Does this payload look like ciphertext or random padding?
///
/// Entropy is measured over at most 256 bytes, and a sample that small can
/// never approach 8 bits/byte even when it IS uniformly random: with 256
/// draws from 256 symbols the birthday collisions cap it around 7.2, and at
/// 96 draws around 6.2 (log2 of the sample size is the absolute ceiling). A
/// single fixed bar therefore has to move with the sample size, and it is set
/// a few tenths below the lowest entropy genuinely random data produces at
/// that size. Text, bencode, HTTP and other structured payloads top out near
/// 5.1 regardless of length, so the band between is wide.
///
/// The minimum of 96 bytes is the length of an MSE handshake opener (a 96-byte
/// Diffie-Hellman key, before padding), the shortest random-looking first
/// packet worth labelling. Anything shorter is left to a later packet: the
/// flow label is upgrade-only, so one full-size ciphertext packet fixes it.
fn looks_random(p: &[u8]) -> bool {
    let n = p.len().min(256);
    if n < 96 {
        return false;
    }
    // Floor of observed random-data entropy at each size (4000-trial
    // simulation): 96 → 5.9, 128 → 6.3, 192 → 6.7, 256 → 7.0.
    let bar = match n {
        0..=127 => 5.5,
        128..=191 => 6.0,
        192..=255 => 6.4,
        _ => 6.8,
    };
    entropy(p) > bar
}

/// Shannon entropy in bits/byte over the first 256 bytes.
fn entropy(p: &[u8]) -> f64 {
    let sample = &p[..p.len().min(256)];
    let mut counts = [0u32; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let n = sample.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let pr = c as f64 / n;
            h -= pr * pr.log2();
        }
    }
    h
}

/// Identifies a flow. `remote`/`local_port` are chosen by direction so the two
/// directions of one conversation collapse into a single row.
#[derive(Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
    l4: &'static str,
}

struct Flow {
    app: AppProto,
    up: u64,
    down: u64,
    pkts: u64,
    first_seen: Instant,
    last_seen: Instant,
    last_total: u64,
    rate: f64,
    /// Admission-control status, set out-of-band by the connection manager (see
    /// `TrafficMonitor::note_flow`). Packet recording never changes it.
    status: FlowStatus,
}

/// A flow's lifetime totals with wall-clock bounds — the unit the shutdown CSV
/// is written from. Eviction converts a live [`Flow`] into one of these;
/// nothing the monitor ever saw is discarded.
#[derive(Clone)]
struct FlowRecord {
    remote: String,
    l4: &'static str,
    app: &'static str,
    local_port: u16,
    up: u64,
    down: u64,
    pkts: u64,
    first: SystemTime,
    last: SystemTime,
    status: &'static str,
}

/// Convert a live flow to its archival record. Wall times derive from the
/// monitor's clock base pair (one wall+mono reading at construction), so the
/// per-packet hot path never reads the wall clock.
fn record_of(k: &FlowKey, f: &Flow, wall_base: SystemTime, mono_base: Instant) -> FlowRecord {
    let wall = |t: Instant| wall_base + t.duration_since(mono_base);
    FlowRecord {
        remote: fmt_endpoint(k.remote_ip, k.remote_port),
        l4: k.l4,
        app: f.app.label(),
        local_port: k.local_port,
        up: f.up,
        down: f.down,
        pkts: f.pkts,
        first: wall(f.first_seen),
        last: wall(f.last_seen),
        status: f.status.label(),
    }
}

/// Change a flow's label and move its previously counted bytes with it, so the
/// per-protocol totals track the flow's final identity, not its first packet.
fn relabel(flow: &mut Flow, proto_bytes: &mut HashMap<&'static str, u64>, app: AppProto) {
    let hist = flow.up + flow.down;
    if hist > 0 {
        let old = proto_bytes.entry(flow.app.label()).or_insert(0);
        *old = old.saturating_sub(hist);
        *proto_bytes.entry(app.label()).or_insert(0) += hist;
    }
    flow.app = app;
}

struct Inner {
    total_up: u64,
    total_down: u64,
    pkts_up: u64,
    pkts_down: u64,
    acc_up: u64,
    acc_down: u64,
    up_series: VecDeque<f64>,
    down_series: VecDeque<f64>,
    flows: HashMap<FlowKey, Flow>,
    /// Flows evicted from the live table, with their lifetime totals. Bounded
    /// ring (see `MAX_ARCHIVE`): oldest records fall off under sustained churn.
    archive: VecDeque<FlowRecord>,
    /// Archived records dropped to honor `MAX_ARCHIVE` — surfaced at shutdown so
    /// the CSV's incompleteness is stated, not silent.
    archive_dropped: u64,
    proto_bytes: HashMap<&'static str, u64>,
    /// Remote hosts seen speaking uTP or DHT this session. An `Obfuscated` TCP
    /// flow to one of them is almost certainly an encrypted BitTorrent peer, so
    /// it is relabelled `ObfuscatedBt`. Bounded: a large swarm is thousands of
    /// hosts, and past the cap the relabel simply stops learning new ones.
    bt_hosts: HashSet<IpAddr>,
    last_tick: Instant,
    /// Clock base pair for converting monotonic stamps to wall time at export.
    wall_base: SystemTime,
    mono_base: Instant,
}

impl Inner {
    fn new(now: Instant) -> Self {
        Inner {
            total_up: 0,
            total_down: 0,
            pkts_up: 0,
            pkts_down: 0,
            acc_up: 0,
            acc_down: 0,
            up_series: VecDeque::from(vec![0.0; SERIES_LEN]),
            down_series: VecDeque::from(vec![0.0; SERIES_LEN]),
            flows: HashMap::new(),
            archive: VecDeque::new(),
            archive_dropped: 0,
            proto_bytes: HashMap::new(),
            bt_hosts: HashSet::new(),
            last_tick: now,
            wall_base: SystemTime::now(),
            mono_base: now,
        }
    }
}

/// Aggregates inspected packets into live traffic statistics. Cheap to clone
/// (it's an `Arc` at the call sites) and safe to feed from multiple tasks.
pub struct TrafficMonitor {
    inner: Mutex<Inner>,
    /// Last rendered view, rebuilt once per `tick` and handed out by reference.
    ///
    /// The dashboard repaints at frame rate, but everything it shows advances at
    /// tick rate — the series, the per-flow rates, the eviction sweep. Building a
    /// fresh snapshot per frame would allocate a few hundred `String`s *while
    /// holding the same lock the per-packet path takes*, turning the render loop
    /// into a throughput tax. Publishing one `Arc` per tick makes a read O(1) and
    /// lock-disjoint from `record`, and costs nothing in freshness: a value that
    /// only changes at 1 Hz cannot be shown more often than that anyway.
    cache: Mutex<Arc<TrafficSnapshot>>,
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMonitor {
    pub fn new() -> Self {
        TrafficMonitor {
            inner: Mutex::new(Inner::new(Instant::now())),
            cache: Mutex::new(Arc::new(TrafficSnapshot::default())),
        }
    }

    /// The one way in — and it fails fast on purpose.
    ///
    /// Nothing under this lock can panic, so a poisoned guard means an invariant
    /// this module does not model has already been violated. The engine's policy
    /// for that is to stop, not to carry on with observability it can no longer
    /// vouch for: `record` runs on the packet path, so propagating the panic is
    /// what takes the data path down with the statistics rather than leaving a
    /// live tunnel reporting frozen numbers. Recovering here would invert that.
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("traffic monitor poisoned — engine must stop")
    }

    /// Record one plaintext IP packet observed at the TUN boundary.
    pub fn record(&self, dir: Direction, pkt: &[u8]) {
        let parsed = match parse(pkt) {
            Some(p) => p,
            None => return,
        };
        let len = parsed.len as u64;
        let (remote_ip, remote_port, local_port) = match dir {
            Direction::Up => (parsed.dst_ip, parsed.dst_port, parsed.src_port),
            Direction::Down => (parsed.src_ip, parsed.src_port, parsed.dst_port),
        };
        let key = FlowKey {
            remote_ip,
            remote_port,
            local_port,
            l4: parsed.l4.label(),
        };

        let mut inner = self.inner();
        let now = Instant::now();
        match dir {
            Direction::Up => {
                inner.total_up += len;
                inner.acc_up += len;
                inner.pkts_up += 1;
            }
            Direction::Down => {
                inner.total_down += len;
                inner.acc_down += len;
                inner.pkts_down += 1;
            }
        }

        // Split borrows: the flow entry and the per-protocol counters are
        // updated as one unit so they can never disagree.
        let Inner {
            flows,
            proto_bytes,
            bt_hosts,
            ..
        } = &mut *inner;

        if matches!(parsed.app, AppProto::Utp | AppProto::Dht) && bt_hosts.len() < MAX_BT_HOSTS {
            bt_hosts.insert(remote_ip);
        }

        // Bound live per-flow tracking against unbounded flow creation (the same
        // adversarial input conn.rs budgets for). The packet is already in the
        // global counters above; here we only decline to OPEN a new row once the
        // table is full. The `contains_key` probe is evaluated only at the cap,
        // so the common path keeps its single `entry` lookup.
        if flows.len() >= MAX_LIVE_FLOWS && !flows.contains_key(&key) {
            *proto_bytes.entry(parsed.app.label()).or_insert(0) += len;
            return;
        }

        let flow = flows.entry(key).or_insert_with(|| Flow {
            app: parsed.app,
            up: 0,
            down: 0,
            pkts: 0,
            first_seen: now,
            last_seen: now,
            last_total: 0,
            rate: 0.0,
            status: FlowStatus::Active,
        });

        // Upgrade-only classification: adopt the new label only when it is
        // strictly more confident than what the flow already carries, and
        // reattribute the flow's previously counted bytes so per-protocol
        // totals track the flow's final identity, not its first packet.
        if parsed.app.rank() > flow.app.rank() {
            relabel(flow, proto_bytes, parsed.app);
        }
        // Host already known to torrent: relabel on the spot. The other order
        // (this flow first, the host's uTP later) is caught by `tick`.
        if flow.app == AppProto::Obfuscated && bt_hosts.contains(&remote_ip) {
            relabel(flow, proto_bytes, AppProto::ObfuscatedBt);
        }
        *proto_bytes.entry(flow.app.label()).or_insert(0) += len;

        match dir {
            Direction::Up => flow.up += len,
            Direction::Down => flow.down += len,
        }
        flow.pkts += 1;
        flow.last_seen = now;
    }

    /// Advance the throughput series and per-flow rates. Call ~once per second.
    pub fn tick(&self) {
        let mut inner = self.inner();
        let now = Instant::now();
        let dt = now.duration_since(inner.last_tick).as_secs_f64().max(0.001);
        inner.last_tick = now;

        let up_bps = inner.acc_up as f64 / dt;
        let down_bps = inner.acc_down as f64 / dt;
        inner.acc_up = 0;
        inner.acc_down = 0;

        inner.up_series.push_back(up_bps);
        inner.down_series.push_back(down_bps);
        while inner.up_series.len() > SERIES_LEN {
            inner.up_series.pop_front();
        }
        while inner.down_series.len() > SERIES_LEN {
            inner.down_series.pop_front();
        }

        // Move idle flows from the live table to the archive — their lifetime
        // stats are session data, not disposable display state.
        let idle: Vec<FlowKey> = inner
            .flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.last_seen) >= FLOW_IDLE_EVICT)
            .map(|(k, _)| k.clone())
            .collect();
        for k in idle {
            if let Some(f) = inner.flows.remove(&k) {
                let rec = record_of(&k, &f, inner.wall_base, inner.mono_base);
                if inner.archive.len() >= MAX_ARCHIVE {
                    inner.archive.pop_front();
                    inner.archive_dropped += 1;
                }
                inner.archive.push_back(rec);
            }
        }
        let Inner {
            flows,
            proto_bytes,
            bt_hosts,
            ..
        } = &mut *inner;
        for (k, f) in flows.iter_mut() {
            let total = f.up + f.down;
            f.rate = (total.saturating_sub(f.last_total)) as f64 / dt;
            f.last_total = total;
            // Obfuscated flows that predate the host's first uTP/DHT packet.
            if f.app == AppProto::Obfuscated && bt_hosts.contains(&k.remote_ip) {
                relabel(f, proto_bytes, AppProto::ObfuscatedBt);
            }
        }

        // Publish the view while the lock is already held: one build per tick,
        // shared by every reader until the next one.
        let view = Arc::new(build_snapshot(&inner, now));
        drop(inner);
        if let Ok(mut c) = self.cache.lock() {
            *c = view;
        }
    }

    /// Tag a flow with an engine admission-control status so the dashboard and
    /// CSV show a deliberately shed or reaped flow as an expected action, not an
    /// anomalous half-open / up-only conversation. Keyed the same way `record`
    /// keys the two directions of a conversation, so it lands on the existing
    /// row. IPv4 only (mirrors the engine's capture); a no-op if the flow isn't
    /// in the live table (already archived, or never recorded).
    pub fn note_flow(&self, tcp: bool, remote: SocketAddrV4, local_port: u16, status: FlowStatus) {
        let key = FlowKey {
            remote_ip: IpAddr::V4(*remote.ip()),
            remote_port: remote.port(),
            local_port,
            l4: if tcp { "TCP" } else { "UDP" },
        };
        let mut inner = self.inner();
        if let Some(f) = inner.flows.get_mut(&key) {
            f.status = status;
        }
    }

    /// Write every flow of the session — archived AND still-live — as CSV to
    /// `path`, ordered by first-seen. Returns the number of rows. Called on
    /// shutdown.
    pub fn write_csv(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let inner = self.inner();
        if inner.archive_dropped > 0 {
            tracing::warn!(
                "flow archive capped at {} records; {} older flows were dropped and \
                 are absent from the CSV",
                MAX_ARCHIVE, inner.archive_dropped
            );
        }
        let mut records: Vec<FlowRecord> = inner.archive.iter().cloned().collect();
        for (k, f) in &inner.flows {
            records.push(record_of(k, f, inner.wall_base, inner.mono_base));
        }
        records.sort_by_key(|r| r.first);

        let mut out = String::with_capacity(80 + records.len() * 96);
        // `status` is appended last so existing name-based readers (e.g.
        // visualize_flows.py) are unaffected; it is empty for ordinary flows.
        out.push_str(
            "first_seen,last_seen,remote,l4,app,local_port,up_bytes,down_bytes,packets,status\n",
        );
        let fmt = |t: SystemTime| {
            chrono::DateTime::<chrono::Local>::from(t)
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string()
        };
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                fmt(r.first),
                fmt(r.last),
                r.remote,
                r.l4,
                r.app,
                r.local_port,
                r.up,
                r.down,
                r.pkts,
                r.status,
            ));
        }
        std::fs::write(path, out)?;
        Ok(records.len())
    }

    /// The current view, as published by the last `tick`. O(1): an `Arc` clone.
    pub fn snapshot(&self) -> Arc<TrafficSnapshot> {
        match self.cache.lock() {
            Ok(c) => c.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }
}

/// Render `Inner` into the immutable view the dashboard draws from. Called once
/// per tick, with the monitor lock already held.
///
/// Every aggregate the dashboard can display is derived here, from the FULL live
/// table — not from the truncated row slice, and not per frame in the renderer.
/// A host rollup computed from the top 256 rows is not a host rollup; and a
/// value that only moves once a second must not be recomputed sixty times a
/// second under the lock the packet path takes.
fn build_snapshot(inner: &Inner, now: Instant) -> TrafficSnapshot {
    let mut flows: Vec<FlowRow> = Vec::with_capacity(inner.flows.len());
    let mut hosts: HashMap<IpAddr, HostAcc> = HashMap::new();
    let mut ports: HashMap<(&'static str, u16), PortAcc> = HashMap::new();
    let mut app_flows: HashMap<&'static str, usize> = HashMap::new();
    let mut tcp_flows = 0usize;
    let mut udp_flows = 0usize;

    for (k, f) in &inner.flows {
        let idle_ms = now.duration_since(f.last_seen).as_millis() as u64;
        let bytes = f.up + f.down;
        let app = f.app.label();

        flows.push(FlowRow {
            remote: fmt_endpoint(k.remote_ip, k.remote_port),
            proto: k.l4,
            app,
            up: f.up,
            down: f.down,
            rate: f.rate,
            idle_ms,
            status: f.status.label(),
        });

        match k.l4 {
            "TCP" => tcp_flows += 1,
            "UDP" => udp_flows += 1,
            _ => {}
        }
        *app_flows.entry(app).or_insert(0) += 1;

        // Host rollup: one row per unique remote address, however many
        // conversations it carries. `idle` is the freshest of them, and the
        // label is taken from the heaviest — a host is identified by what it
        // mostly does, not by whichever flow hashed first.
        let h = hosts.entry(k.remote_ip).or_insert_with(|| HostAcc {
            idle_ms: u64::MAX,
            ..HostAcc::default()
        });
        h.flows += 1;
        h.up += f.up;
        h.down += f.down;
        h.rate += f.rate;
        h.idle_ms = h.idle_ms.min(idle_ms);
        if bytes >= h.top_bytes {
            h.top_bytes = bytes;
            h.app = app;
        }

        // Service rollup, keyed on the REMOTE port: the local port is ephemeral
        // and rolling it up would produce one row per flow.
        if k.remote_port != 0 {
            let p = ports.entry((k.l4, k.remote_port)).or_default();
            p.flows += 1;
            p.up += f.up;
            p.down += f.down;
            p.rate += f.rate;
        }
    }

    flows.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)));
    flows.truncate(MAX_FLOWS);

    let mut hosts: Vec<HostRow> = hosts
        .into_iter()
        .map(|(ip, a)| HostRow {
            ip: ip.to_string(),
            app: a.app,
            flows: a.flows,
            up: a.up,
            down: a.down,
            rate: a.rate,
            idle_ms: if a.idle_ms == u64::MAX { 0 } else { a.idle_ms },
        })
        .collect();
    hosts.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)));
    hosts.truncate(MAX_HOSTS);

    let mut ports: Vec<PortRow> = ports
        .into_iter()
        .map(|((l4, port), a)| PortRow {
            port,
            l4,
            service: service_name(port),
            flows: a.flows,
            up: a.up,
            down: a.down,
            rate: a.rate,
        })
        .collect();
    ports.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)));
    ports.truncate(MAX_PORTS);

    // Byte share is session-cumulative (it includes archived flows), so the
    // composition view stays honest across a long session; the flow count is
    // live, so the two columns answer different questions on purpose.
    let mut apps: Vec<AppRow> = inner
        .proto_bytes
        .iter()
        .map(|(name, bytes)| AppRow {
            name: *name,
            bytes: *bytes,
            flows: app_flows.get(*name).copied().unwrap_or(0),
        })
        .collect();
    apps.sort_by(|a, b| b.bytes.cmp(&a.bytes));

    TrafficSnapshot {
        total_up: inner.total_up,
        total_down: inner.total_down,
        pkts_up: inner.pkts_up,
        pkts_down: inner.pkts_down,
        rate_up: inner.up_series.back().copied().unwrap_or(0.0),
        rate_down: inner.down_series.back().copied().unwrap_or(0.0),
        up_series: inner.up_series.iter().copied().collect(),
        down_series: inner.down_series.iter().copied().collect(),
        active_flows: inner.flows.len(),
        tcp_flows,
        udp_flows,
        archived_flows: inner.archive.len(),
        flows,
        hosts,
        ports,
        apps,
    }
}

/// Accumulator for the per-host rollup. Not part of the published view.
#[derive(Default)]
struct HostAcc {
    app: &'static str,
    flows: usize,
    up: u64,
    down: u64,
    rate: f64,
    idle_ms: u64,
    top_bytes: u64,
}

/// Accumulator for the per-service rollup. Not part of the published view.
#[derive(Default)]
struct PortAcc {
    flows: usize,
    up: u64,
    down: u64,
    rate: f64,
}

/// Human name for a well-known remote port. Deliberately a superset of what
/// `classify` fingerprints: this labels the *destination service* even when the
/// flow's payload classification landed elsewhere (e.g. TLS on 993 is IMAPS).
///
/// Shared with `probe.rs`, which labels the ports a scan finds open. One table:
/// a scan and the SERVICES widget must not disagree about what port 993 is.
pub(crate) fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        123 => "ntp",
        137..=139 => "netbios",
        143 => "imap",
        161 | 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        546 | 547 => "dhcpv6",
        636 => "ldaps",
        853 => "dns-tls",
        993 => "imaps",
        995 => "pop3s",
        1194 => "openvpn",
        1900 => "ssdp",
        3128 | 8080 => "http-proxy",
        3306 => "mysql",
        3389 => "rdp",
        5222 => "xmpp",
        5353 => "mdns",
        5355 => "llmnr",
        5432 => "postgres",
        6379 => "redis",
        8388 | 8389 => "shadowsocks",
        8443 => "https-alt",
        27017 => "mongodb",
        51820 => "wireguard",
        _ => "",
    }
}

/// `ip:port`, bracketing a v6 literal so its colons are not read as the port.
/// Port 0 means the protocol has no port space (ICMP, ESP, …).
fn fmt_endpoint(ip: IpAddr, port: u16) -> String {
    match (ip, port) {
        (_, 0) => ip.to_string(),
        (IpAddr::V4(_), _) => format!("{ip}:{port}"),
        (IpAddr::V6(_), _) => format!("[{ip}]:{port}"),
    }
}

/// Immutable view of the monitor's state for rendering. Published once per tick
/// and handed out as an `Arc`; every field is final at publication, so the
/// dashboard never computes over live state.
#[derive(Clone, Default)]
pub struct TrafficSnapshot {
    pub total_up: u64,
    pub total_down: u64,
    pub pkts_up: u64,
    pub pkts_down: u64,
    pub rate_up: f64,
    pub rate_down: f64,
    pub up_series: Vec<f64>,
    pub down_series: Vec<f64>,
    /// Live flows tracked (untruncated count; `flows` is the display slice).
    pub active_flows: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    /// Flows evicted to the archive so far this session.
    pub archived_flows: usize,
    /// Heaviest flows, descending by total bytes (capped at `MAX_FLOWS`).
    pub flows: Vec<FlowRow>,
    /// Unique remote hosts, descending by total bytes (capped at `MAX_HOSTS`).
    pub hosts: Vec<HostRow>,
    /// Remote service ports, descending by total bytes (capped at `MAX_PORTS`).
    pub ports: Vec<PortRow>,
    /// Application protocols, descending by session bytes.
    pub apps: Vec<AppRow>,
}

/// One row of the live flow table.
#[derive(Clone)]
pub struct FlowRow {
    pub remote: String,
    pub proto: &'static str,
    pub app: &'static str,
    pub up: u64,
    pub down: u64,
    pub rate: f64,
    pub idle_ms: u64,
    /// Engine admission status: "" (active), "shed", or "reaped".
    pub status: &'static str,
}

/// One unique remote host, with every flow to it collapsed into one row.
#[derive(Clone)]
pub struct HostRow {
    pub ip: String,
    /// Label of the host's heaviest flow.
    pub app: &'static str,
    pub flows: usize,
    pub up: u64,
    pub down: u64,
    pub rate: f64,
    /// Idle time of the host's freshest flow.
    pub idle_ms: u64,
}

/// One remote service port, with every flow to it collapsed into one row.
#[derive(Clone)]
pub struct PortRow {
    pub port: u16,
    pub l4: &'static str,
    /// Well-known service name, or "" if the port is not recognised.
    pub service: &'static str,
    pub flows: usize,
    pub up: u64,
    pub down: u64,
    pub rate: f64,
}

/// One application protocol: session byte share and live flow count.
#[derive(Clone)]
pub struct AppRow {
    pub name: &'static str,
    /// Session-cumulative bytes, including flows already archived.
    pub bytes: u64,
    /// Flows currently live with this label.
    pub flows: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + payload.len()];
        p[0] = 0x45; // v4, IHL=5
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    fn v4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 20 + payload.len()];
        p[0] = 0x45; // v4, IHL=5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50; // data offset: 5 words, no options
        p[40..].copy_from_slice(payload);
        p
    }

    #[test]
    fn classifies_wireguard_by_signature() {
        // Handshake initiation: type=1, 3 reserved zero bytes, exactly 148 bytes.
        let mut payload = vec![0u8; 148];
        payload[0] = 1;
        let pkt = v4_udp([10, 0, 0, 2], [1, 2, 3, 4], 40000, 12345, &payload);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.app.label(), "WireGuard");
    }

    #[test]
    fn wireguard_prefix_without_length_is_not_wireguard() {
        // DNS-shaped: ID 0x0100, zero flags — the old 4-byte check matched this.
        let pkt = v4_udp([10, 0, 0, 2], [1, 2, 3, 4], 40000, 12345, &[1, 0, 0, 0, 9, 9]);
        assert_ne!(parse(&pkt).unwrap().app.label(), "WireGuard");
    }

    #[test]
    fn never_downgrades_classification() {
        let m = TrafficMonitor::new();
        let noise: Vec<u8> = (0..=255u8).collect();
        // High-entropy payload, unknown ports → Obfuscated.
        let p1 = v4_udp([10, 0, 0, 2], [5, 6, 7, 8], 40001, 40002, &noise);
        m.record(Direction::Up, &p1);
        // Tiny low-entropy packet on the same flow classifies as Other; the
        // flow label must not fall back.
        let p2 = v4_udp([10, 0, 0, 2], [5, 6, 7, 8], 40001, 40002, &[0, 0]);
        m.record(Direction::Up, &p2);
        m.tick();
        assert_eq!(m.snapshot().flows[0].app, "Obfuscated");
        // Payload signature on the same flow upgrades it.
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        let p3 = v4_udp([10, 0, 0, 2], [5, 6, 7, 8], 40001, 40002, &wg);
        m.record(Direction::Up, &p3);
        m.tick();
        let snap = m.snapshot();
        assert_eq!(snap.flows[0].app, "WireGuard");
        // Protocol byte totals were reattributed to the final identity.
        let total = (p1.len() + p2.len() + p3.len()) as u64;
        let wg = snap.apps.iter().find(|a| a.name == "WireGuard").unwrap();
        assert_eq!(wg.bytes, total);
        assert!(snap.apps.iter().all(|a| a.name == "WireGuard" || a.bytes == 0));
        assert_eq!(wg.flows, 1);
    }

    #[test]
    fn v6_extension_headers_are_chased() {
        // IPv6 + Hop-by-Hop → ICMPv6: the MLD shape that used to report as "IP".
        let mut p = vec![0u8; 40 + 8 + 4];
        p[0] = 0x60;
        p[6] = 0; // next header: hop-by-hop
        p[40] = 58; // hop-by-hop's next header: ICMPv6
        p[41] = 0; // extension length: 8 bytes total
        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.l4.label(), "ICMP");
        assert_eq!(parsed.app.label(), "ICMP");
    }

    /// A uTP header (BEP 29) with the given packet type.
    fn utp(kind: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = (kind << 4) | 1; // type + version 1
        h[1] = 0; // no extensions
        h[12..16].copy_from_slice(&65_536u32.to_be_bytes()); // wnd_size
        h
    }

    #[test]
    fn classifies_every_part_of_a_bittorrent_session() {
        // BitTorrent negotiates its ports, so none of these can be recognised by
        // port — a swarm is the traffic most likely to arrive unlabelled, and it
        // is the traffic a torrenting session is almost entirely made of.
        let app = |payload: &[u8]| {
            parse(&v4_udp([10, 0, 0, 2], [1, 2, 3, 4], 51413, 6881, payload))
                .unwrap()
                .app
                .label()
        };

        // uTP carries the piece data, so it is the bulk of the bytes.
        for kind in 0..=4u8 {
            assert_eq!(app(&utp(kind)), "uTP", "uTP packet type {kind}");
        }

        // DHT: bencoded KRPC, matched on the first key. All four openers.
        assert_eq!(app(b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:y1:qe"), "DHT");
        assert_eq!(app(b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:y1:re"), "DHT");
        assert_eq!(app(b"d1:eli201e23:A Generic Errore1:y1:ee"), "DHT");
        // Some clients prepend the caller's address, which sorts first (BEP 42).
        assert_eq!(app(b"d2:ip6:abcdef1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:y1:re"), "DHT");

        // BEP 15 tracker connect: the protocol's magic id, then action 0.
        let mut connect = vec![0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80];
        connect.extend_from_slice(&0u32.to_be_bytes()); // action: connect
        connect.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // transaction
        assert_eq!(app(&connect), "BT Tracker");

        // The unencrypted peer handshake, over TCP.
        let mut hs = vec![19u8];
        hs.extend_from_slice(b"BitTorrent protocol");
        hs.extend_from_slice(&[0u8; 8]);
        assert_eq!(classify(L4::Tcp, 51413, 6881, &hs).label(), "BitTorrent");
    }

    /// Deterministic pseudo-random bytes (xorshift64*), so the test exercises
    /// the collision statistics of real ciphertext rather than the one-of-each
    /// byte pattern that trivially hits 8 bits.
    fn pseudo_random(len: usize, mut seed: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                seed ^= seed >> 12;
                seed ^= seed << 25;
                seed ^= seed >> 27;
                (seed.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn encrypted_peer_handshakes_are_obfuscated_not_other() {
        // An MSE opener is a 96-byte DH public key plus 0..512 bytes of random
        // padding. Over a 256-byte sample, random data tops out near 7.2
        // bits/byte — the old fixed bar of 7.5 could never be met, and every
        // encrypted swarm peer fell through to Other.
        for len in [96, 128, 200, 256, 608, 1400] {
            for seed in 1..=50u64 {
                let p = pseudo_random(len, seed * 7919 + len as u64);
                assert_eq!(
                    classify(L4::Tcp, 51413, 6881, &p).label(),
                    "Obfuscated",
                    "{len}-byte random payload, seed {seed}"
                );
                assert_eq!(classify(L4::Udp, 51413, 6881, &p).label(), "Obfuscated");
            }
        }
        // Too short to judge: left for a later, longer packet to upgrade.
        assert_eq!(classify(L4::Tcp, 51413, 6881, &pseudo_random(64, 3)).label(), "Other");
    }

    #[test]
    fn structured_payloads_are_not_mistaken_for_ciphertext() {
        let text = b"The quick brown fox jumps over the lazy dog, and does it again                      and again until the buffer is comfortably past the sample                      size the entropy estimate draws from; bencode and HTTP are                      no denser than this, so neither can clear the bar either.                      0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assert!(text.len() > 256);
        assert_eq!(classify(L4::Tcp, 51413, 6881, text).label(), "Other");
        assert_eq!(classify(L4::Tcp, 51413, 6881, &text[..100]).label(), "Other");
        assert_eq!(classify(L4::Tcp, 51413, 6881, &text[..160]).label(), "Other");
        // Unknown-port HTTP that is not a tracker stays Other too.
        let get = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
        assert_eq!(classify(L4::Tcp, 51413, 6969, get).label(), "Other");
    }

    #[test]
    fn classifies_http_trackers_on_any_port() {
        let app = |port: u16, payload: &[u8]| classify(L4::Tcp, 51413, port, payload).label();
        let announce = b"GET /announce?info_hash=%AA%BB&peer_id=-qB4600-&port=51413 HTTP/1.1\r\nHost: t\r\n\r\n";
        assert_eq!(app(6969, announce), "BT Tracker");
        assert_eq!(app(2710, announce), "BT Tracker");
        // On 80 the signature beats the port rule, as signatures do everywhere.
        assert_eq!(app(80, announce), "BT Tracker");
        // Private-tracker and PHP shapes.
        assert_eq!(app(6969, b"GET /a1b2c3d4e5/announce?info_hash=x HTTP/1.1\r\n"), "BT Tracker");
        assert_eq!(app(6969, b"GET /announce.php?passkey=k HTTP/1.0\r\n"), "BT Tracker");
        assert_eq!(app(6969, b"GET /scrape?info_hash=x HTTP/1.1\r\n"), "BT Tracker");
        // The word elsewhere in the request is not a match.
        assert_eq!(app(6969, b"GET /blog/announce-party.html HTTP/1.1\r\n"), "Other");
        assert_eq!(app(80, b"GET / HTTP/1.1\r\nX: /announce\r\n"), "HTTP");
        // Unterminated request line within the bound: not a match, no panic.
        let mut long = b"GET /".to_vec();
        long.extend(std::iter::repeat(b'a').take(2000));
        assert_eq!(app(6969, &long), "Other");
        assert_eq!(app(6969, b"GET /ann"), "Other");
    }

    #[test]
    fn encrypted_peers_of_a_torrenting_host_are_relabelled() {
        let m = TrafficMonitor::new();
        let cipher = pseudo_random(300, 11);
        let peer = [5, 6, 7, 8];
        let other = [9, 9, 9, 9];

        // Host first seen on uTP, then an encrypted TCP connection: relabelled
        // as soon as the TCP flow is opened.
        let u = v4_udp([10, 0, 0, 2], peer, 51413, 6881, &utp(4));
        m.record(Direction::Up, &u);
        let t = v4_tcp([10, 0, 0, 2], peer, 40001, 6881, &cipher);
        m.record(Direction::Up, &t);
        // A host with no uTP/DHT stays plain Obfuscated.
        let o = v4_tcp([10, 0, 0, 2], other, 40002, 6881, &cipher);
        m.record(Direction::Up, &o);
        m.tick();
        let label = |snap: &TrafficSnapshot, host: &str| {
            snap.flows
                .iter()
                .find(|f| f.proto == "TCP" && f.remote.starts_with(host))
                .unwrap()
                .app
                .to_string()
        };
        let snap = m.snapshot();
        assert_eq!(label(&snap, "5.6.7.8"), "Obfuscated (uTP/DHT)");
        assert_eq!(label(&snap, "9.9.9.9"), "Obfuscated");
        // Bytes moved with the relabel.
        let bt = snap.apps.iter().find(|a| a.name == "Obfuscated (uTP/DHT)").unwrap();
        assert_eq!(bt.bytes, t.len() as u64);
        assert_eq!(bt.flows, 1);

        // The other order: the encrypted flow predates the host's first DHT
        // packet, and the next tick catches up.
        let d = v4_udp([10, 0, 0, 2], other, 51413, 6881, b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:y1:qe");
        m.record(Direction::Up, &d);
        m.tick();
        assert_eq!(label(&m.snapshot(), "9.9.9.9"), "Obfuscated (uTP/DHT)");
        // And a later random packet on it does not flip it back.
        m.record(Direction::Up, &o);
        m.tick();
        assert_eq!(label(&m.snapshot(), "9.9.9.9"), "Obfuscated (uTP/DHT)");
    }

    #[test]
    fn the_utp_signature_does_not_swallow_neighbouring_traffic() {
        let app = |payload: &[u8]| classify(L4::Udp, 51413, 6881, payload).label();

        // Version nibble must be 1: this is the check doing most of the work.
        let mut wrong_version = utp(0);
        wrong_version[0] = 0x02;
        assert_ne!(app(&wrong_version), "uTP");

        // Type nibble tops out at ST_SYN (4).
        let mut wrong_kind = utp(0);
        wrong_kind[0] = (5 << 4) | 1;
        assert_ne!(app(&wrong_kind), "uTP");

        // The extension field is a short chain, never an arbitrary byte.
        let mut wrong_ext = utp(0);
        wrong_ext[1] = 0x9f;
        assert_ne!(app(&wrong_ext), "uTP");

        // An implausible receive window is what rejects random payloads that
        // happen to open with a valid-looking first byte.
        let mut huge_window = utp(0);
        huge_window[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_ne!(app(&huge_window), "uTP");

        // Too short to be a header at all.
        assert_ne!(app(&utp(0)[..19]), "uTP");

        // And the protocols that share the wire with it keep their own labels:
        // a swarm runs alongside QUIC and DNS, and those are matched first.
        let mut quic = vec![0xc0];
        quic.extend_from_slice(&1u32.to_be_bytes());
        quic.extend_from_slice(&[0u8; 20]);
        assert_eq!(app(&quic), "QUIC");
        assert_eq!(classify(L4::Udp, 53, 40000, &utp(0)).label(), "uTP");
    }

    #[test]
    fn classifies_lan_protocols_and_offport_quic() {
        let m = v4_udp([10, 0, 0, 2], [224, 0, 0, 251], 5353, 5353, &[0xab; 20]);
        assert_eq!(parse(&m).unwrap().app.label(), "mDNS");
        let l = v4_udp([10, 0, 0, 2], [224, 0, 0, 252], 60000, 5355, &[0xab; 20]);
        assert_eq!(parse(&l).unwrap().app.label(), "LLMNR");
        // QUIC long header (v1) on a non-443 port.
        let q = v4_udp([10, 0, 0, 2], [1, 2, 3, 4], 50000, 8443, &[0xc3, 0, 0, 0, 1, 7, 7, 7]);
        assert_eq!(parse(&q).unwrap().app.label(), "QUIC");
    }

    #[test]
    fn classifies_dns_by_port() {
        let pkt = v4_udp([10, 0, 0, 2], [1, 1, 1, 1], 5353, 53, &[0xab; 20]);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.app.label(), "DNS");
    }

    #[test]
    fn monitor_accumulates_and_snapshots() {
        let m = TrafficMonitor::new();
        let pkt = v4_udp([10, 0, 0, 2], [1, 1, 1, 1], 5353, 53, &[0xab; 20]);
        m.record(Direction::Up, &pkt);
        m.record(Direction::Down, &pkt);
        m.tick();
        let snap = m.snapshot();
        assert_eq!(snap.total_up, pkt.len() as u64);
        assert_eq!(snap.total_down, pkt.len() as u64);
        assert_eq!(snap.pkts_up, 1);
        assert!(!snap.flows.is_empty());
        assert_eq!(snap.flows[0].app, "DNS");
    }

    #[test]
    fn rolls_up_hosts_ports_and_apps() {
        let m = TrafficMonitor::new();
        // Two conversations to one host on two services, one to another host.
        m.record(Direction::Up, &v4_udp([10, 0, 0, 2], [1, 1, 1, 1], 40001, 53, &[7; 40]));
        m.record(Direction::Up, &v4_udp([10, 0, 0, 2], [1, 1, 1, 1], 40002, 123, &[7; 40]));
        m.record(Direction::Up, &v4_udp([10, 0, 0, 2], [9, 9, 9, 9], 40003, 53, &[7; 10]));
        m.tick();
        let snap = m.snapshot();

        assert_eq!(snap.active_flows, 3);
        assert_eq!(snap.udp_flows, 3);
        assert_eq!(snap.tcp_flows, 0);

        // Three flows collapse to two host rows, heaviest first.
        assert_eq!(snap.hosts.len(), 2);
        assert_eq!(snap.hosts[0].ip, "1.1.1.1");
        assert_eq!(snap.hosts[0].flows, 2);
        assert_eq!(snap.hosts[1].ip, "9.9.9.9");
        assert_eq!(snap.hosts[1].flows, 1);

        // ...and to two service rows, keyed on the REMOTE port only.
        assert_eq!(snap.ports.len(), 2);
        let dns = snap.ports.iter().find(|p| p.port == 53).unwrap();
        assert_eq!(dns.flows, 2);
        assert_eq!(dns.service, "dns");
        assert_eq!(dns.l4, "UDP");
        let ntp = snap.ports.iter().find(|p| p.port == 123).unwrap();
        assert_eq!(ntp.flows, 1);
        assert_eq!(ntp.service, "ntp");

        let dns_app = snap.apps.iter().find(|a| a.name == "DNS").unwrap();
        assert_eq!(dns_app.flows, 2);
    }

    #[test]
    fn ignores_garbage() {
        let m = TrafficMonitor::new();
        m.record(Direction::Up, &[0xff, 0x00]);
        m.tick();
        let snap = m.snapshot();
        assert_eq!(snap.total_up, 0);
    }
}
