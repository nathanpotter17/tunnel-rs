//! Traffic inspection for observability.
//!
//! Parses the plaintext IP packets that cross the tunnel (captured at the TUN
//! boundary, before encryption on the way out and after decryption on the way
//! in), extracts the flow 5-tuple, and classifies each packet by application
//! protocol using lightweight heuristics. A [`TrafficMonitor`] aggregates the
//! results into rolling throughput series, counters, and a per-flow table that
//! the GUI renders live.
//!
//! Nothing here decrypts or stores payloads — it only reads packet headers and
//! (for a few protocols) the first handshake bytes to fingerprint the protocol.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// Number of throughput samples retained for the live graph (~2 minutes at 1s).
pub const SERIES_LEN: usize = 120;
/// Maximum flows REPORTED in a snapshot (display cap). Retention is total:
/// evicted flows are archived, never discarded — see `Inner::archive`.
const MAX_FLOWS: usize = 256;
/// Flows idle longer than this are moved from the live table to the archive.
const FLOW_IDLE_EVICT: Duration = Duration::from_secs(90);

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
            AppProto::Obfuscated => 1,
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
            // Payload-signature protocols.
            AppProto::Tls | AppProto::Quic | AppProto::WireGuard => 3,
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
    }
    if matches!(l4, L4::Tcp) && is_tls(payload) {
        return AppProto::Tls;
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
    // strong hint of an obfuscated/encrypted proxy (Shadowsocks, VMess, etc.).
    if matches!(l4, L4::Tcp | L4::Udp) && payload.len() >= 32 && entropy(payload) > 7.5 {
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
    }
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
    /// Every flow evicted from the live table, with its lifetime totals.
    archive: Vec<FlowRecord>,
    proto_bytes: HashMap<&'static str, u64>,
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
            archive: Vec::new(),
            proto_bytes: HashMap::new(),
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
        }
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

        let mut inner = self.inner.lock().unwrap();
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
            flows, proto_bytes, ..
        } = &mut *inner;

        let flow = flows.entry(key).or_insert_with(|| Flow {
            app: parsed.app,
            up: 0,
            down: 0,
            pkts: 0,
            first_seen: now,
            last_seen: now,
            last_total: 0,
            rate: 0.0,
        });

        // Upgrade-only classification: adopt the new label only when it is
        // strictly more confident than what the flow already carries, and
        // reattribute the flow's previously counted bytes so per-protocol
        // totals track the flow's final identity, not its first packet.
        if parsed.app.rank() > flow.app.rank() {
            let hist = flow.up + flow.down;
            if hist > 0 {
                let old = proto_bytes.entry(flow.app.label()).or_insert(0);
                *old = old.saturating_sub(hist);
                *proto_bytes.entry(parsed.app.label()).or_insert(0) += hist;
            }
            flow.app = parsed.app;
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
        let mut inner = self.inner.lock().unwrap();
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
                inner.archive.push(rec);
            }
        }
        for f in inner.flows.values_mut() {
            let total = f.up + f.down;
            f.rate = (total.saturating_sub(f.last_total)) as f64 / dt;
            f.last_total = total;
        }
    }

    /// Write every flow of the session — archived AND still-live — as CSV to
    /// `path`, ordered by first-seen. Returns the number of rows. Called on
    /// shutdown.
    pub fn write_csv(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let inner = self.inner.lock().unwrap();
        let mut records: Vec<FlowRecord> = inner.archive.clone();
        for (k, f) in &inner.flows {
            records.push(record_of(k, f, inner.wall_base, inner.mono_base));
        }
        records.sort_by_key(|r| r.first);

        let mut out = String::with_capacity(80 + records.len() * 96);
        out.push_str(
            "first_seen,last_seen,remote,l4,app,local_port,up_bytes,down_bytes,packets\n",
        );
        let fmt = |t: SystemTime| {
            chrono::DateTime::<chrono::Local>::from(t)
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string()
        };
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                fmt(r.first),
                fmt(r.last),
                r.remote,
                r.l4,
                r.app,
                r.local_port,
                r.up,
                r.down,
                r.pkts,
            ));
        }
        std::fs::write(path, out)?;
        Ok(records.len())
    }

    /// Produce a snapshot for the GUI.
    pub fn snapshot(&self) -> TrafficSnapshot {
        let inner = self.inner.lock().unwrap();
        let now = Instant::now();

        let mut flows: Vec<FlowRow> = inner
            .flows
            .iter()
            .map(|(k, f)| FlowRow {
                remote: fmt_endpoint(k.remote_ip, k.remote_port),
                proto: k.l4,
                app: f.app.label(),
                up: f.up,
                down: f.down,
                rate: f.rate,
                idle_ms: now.duration_since(f.last_seen).as_millis() as u64,
            })
            .collect();
        flows.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)));
        flows.truncate(MAX_FLOWS);

        let mut protos: Vec<(String, u64)> = inner
            .proto_bytes
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        protos.sort_by(|a, b| b.1.cmp(&a.1));

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
            flows,
            protos,
        }
    }
}

fn fmt_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(_) => {
            if port == 0 {
                ip.to_string()
            } else {
                format!("{}:{}", ip, port)
            }
        }
        IpAddr::V6(_) => {
            if port == 0 {
                ip.to_string()
            } else {
                format!("[{}]:{}", ip, port)
            }
        }
    }
}

/// Immutable view of the monitor's state for rendering.
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
    pub active_flows: usize,
    pub flows: Vec<FlowRow>,
    pub protos: Vec<(String, u64)>,
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
        assert_eq!(m.snapshot().flows[0].app, "Obfuscated");
        // Payload signature on the same flow upgrades it.
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        let p3 = v4_udp([10, 0, 0, 2], [5, 6, 7, 8], 40001, 40002, &wg);
        m.record(Direction::Up, &p3);
        let snap = m.snapshot();
        assert_eq!(snap.flows[0].app, "WireGuard");
        // Protocol byte totals were reattributed to the final identity.
        let total = (p1.len() + p2.len() + p3.len()) as u64;
        let wg_bytes = snap.protos.iter().find(|(k, _)| k == "WireGuard").unwrap().1;
        assert_eq!(wg_bytes, total);
        assert!(snap.protos.iter().all(|(k, v)| k == "WireGuard" || *v == 0));
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
    fn ignores_garbage() {
        let m = TrafficMonitor::new();
        m.record(Direction::Up, &[0xff, 0x00]);
        let snap = m.snapshot();
        assert_eq!(snap.total_up, 0);
    }
}
