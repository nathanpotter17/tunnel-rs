//! Active probes: questions the operator asks *through* the tunnel.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a probe waits for a response before giving up, per transport. A
/// probe that has to cross the tunnel and then the internet is slower than a
/// LAN lookup, but not by seconds — past this the answer is that the path is
/// broken, which is itself the result the operator wanted.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest UDP response accepted. Anything bigger is either EDNS0 (which we do
/// not advertise, so a server must not send it) or not a reply to us.
const MAX_UDP_RESPONSE: usize = 4096;

/// Answers kept from one response. A conforming server sends a handful; the cap
/// exists so a hostile one cannot make the render loop do its work.
const MAX_ANSWERS: usize = 64;

/// Compression-pointer jumps allowed while decoding one name. RFC 1035 permits
/// pointers to point anywhere earlier in the message, including at each other,
/// so the only safe termination condition is a budget.
const MAX_NAME_JUMPS: usize = 32;

/// Characters of RDATA text rendered. TXT records are attacker-authored and can
/// be kilobytes long.
const MAX_RDATA_CHARS: usize = 240;

// ---------------------------------------------------------------------------
// Question shape
// ---------------------------------------------------------------------------

/// What a probe *does*.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Resolve a name (or reverse-resolve an address) against a nameserver.
    Nslookup,
    /// TCP connect scan over a bounded port list.
    PortScan,
    /// Everything DNS alone can say about an address: reverse name, and the
    /// ASN, prefix, country, registry and org behind it.
    Intel,
}

impl Action {
    pub const ALL: [Action; 3] = [Action::Nslookup, Action::PortScan, Action::Intel];

    pub fn label(self) -> &'static str {
        match self {
            Action::Nslookup => "LOOKUP",
            Action::PortScan => "SCAN",
            Action::Intel => "INTEL",
        }
    }
}

/// Which record to ask for. `Auto` picks by the shape of the target, which is
/// what makes one control work for both halves of the host table: the rows are
/// addresses, and the only question you can ask an address is PTR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordType {
    Auto,
    A,
    Aaaa,
    Ptr,
    Cname,
    Txt,
    Mx,
    Ns,
    Soa,
    /// Which CAs the zone authorises to issue for it (RFC 8659). A statement of
    /// policy, not of what a server is presenting — reading the actual
    /// certificate would mean handshaking with it, which this module does not do.
    Caa,
    /// DANE certificate association (RFC 6698).
    Tlsa,
}

impl RecordType {
    pub const ALL: [RecordType; 11] = [
        RecordType::Auto,
        RecordType::A,
        RecordType::Aaaa,
        RecordType::Ptr,
        RecordType::Cname,
        RecordType::Txt,
        RecordType::Mx,
        RecordType::Ns,
        RecordType::Soa,
        RecordType::Caa,
        RecordType::Tlsa,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RecordType::Auto => "AUTO",
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Ptr => "PTR",
            RecordType::Cname => "CNAME",
            RecordType::Txt => "TXT",
            RecordType::Mx => "MX",
            RecordType::Ns => "NS",
            RecordType::Soa => "SOA",
            RecordType::Caa => "CAA",
            RecordType::Tlsa => "TLSA",
        }
    }

    /// Resolve `Auto` against a target: an address can only be asked backwards.
    fn concrete(self, target_is_ip: bool) -> RecordType {
        match self {
            RecordType::Auto if target_is_ip => RecordType::Ptr,
            RecordType::Auto => RecordType::A,
            other => other,
        }
    }

    fn code(self) -> u16 {
        match self {
            // `Auto` is resolved before this is called; A is the honest default
            // if it ever is not.
            RecordType::Auto | RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
            RecordType::Tlsa => 52,
            RecordType::Caa => 257,
        }
    }
}

/// Name of a record type as it appears in a response. Types we never ask for
/// can still arrive (a CNAME in the answer chain of an A query is the common
/// case), so this covers more than [`RecordType`].
fn type_name(code: u16) -> String {
    match code {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        39 => "DNAME".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        47 => "NSEC".into(),
        48 => "DNSKEY".into(),
        50 => "NSEC3".into(),
        52 => "TLSA".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        257 => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "RCODE?",
    }
}

// ---------------------------------------------------------------------------
// Request / result
// ---------------------------------------------------------------------------

/// One probe to run.
#[derive(Clone, Debug)]
pub struct Request {
    pub action: Action,
    /// A hostname or an IP literal, as typed or as picked from the host table.
    pub target: String,
    pub record: RecordType,
    /// The nameserver to ask. Defaults to the resolver the engine pinned onto
    /// the TUN, so the probe exercises the same resolver the rest of the host
    /// is using. `Intel` and a `PortScan` of a hostname use it too, so every
    /// action agrees about what the target resolves to.
    pub server: SocketAddr,
    pub timeout: Duration,
    /// Ports for [`Action::PortScan`], already parsed and capped by
    /// [`parse_ports`]. Empty for every other action.
    pub ports: Vec<u16>,
}

/// One record from a response, already rendered to text.
#[derive(Clone, Debug)]
pub struct Answer {
    pub name: String,
    pub kind: String,
    pub ttl: u32,
    pub data: String,
}

/// What a probe produced. One variant per [`Action`] — the widget matches on it
/// to pick a renderer, so a new action cannot forget to bring its own display.
#[derive(Clone, Debug)]
pub enum Outcome {
    Dns(DnsOutcome),
    Scan(ScanOutcome),
    Intel(IntelOutcome),
}

/// Whether a port answered, refused, or said nothing at all.
///
/// The three are genuinely different findings: `Closed` is a host that replied
/// and declined, `Filtered` is silence, which is either a firewall or a path
/// that never arrived.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// One open port.
#[derive(Clone, Debug)]
pub struct PortResult {
    pub port: u16,
    /// From `inspect::service_name` — the same table the SERVICES widget uses,
    /// so a scan and the flow table cannot disagree about what a port is.
    pub service: &'static str,
    /// What the service announced unprompted, escaped and clamped. `None` means
    /// it stayed quiet, which is most things: nothing is ever *sent* to draw a
    /// banner out.
    pub banner: Option<String>,
}

/// A scan, complete or in flight. Republished as each port finishes, so a sweep
/// that takes ten seconds is not ten seconds of blank widget.
#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub target: IpAddr,
    /// Ports finished so far, out of the whole list.
    pub done: usize,
    pub total: usize,
    pub elapsed: Duration,
    /// Open ports only. A hundred rows of "closed" is noise; the counts below
    /// carry what the rest of the list said.
    pub open: Vec<PortResult>,
    pub closed: usize,
    pub filtered: usize,
}

impl ScanOutcome {
    pub fn complete(&self) -> bool {
        self.done >= self.total
    }
}

/// What DNS alone can say about an address.
///
/// Every field is optional and independent: a lookup that half-works still
/// tells you something, and a dossier missing its org line beats an error.
#[derive(Clone, Debug, Default)]
pub struct IntelOutcome {
    pub target: String,
    pub ptr: Option<String>,
    pub asn: Option<u32>,
    pub prefix: Option<String>,
    pub country: Option<String>,
    pub registry: Option<String>,
    pub allocated: Option<String>,
    pub org: Option<String>,
    pub elapsed: Duration,
    pub note: Option<String>,
}

/// A completed lookup.
#[derive(Clone, Debug)]
pub struct DnsOutcome {
    /// The name actually put on the wire — for a reverse lookup this is the
    /// `in-addr.arpa` form, which is worth showing rather than hiding.
    pub question: String,
    pub record: RecordType,
    pub server: SocketAddr,
    /// "udp" or "tcp": a lookup that had to fall back says something about the
    /// path's MTU as well as about the answer.
    pub transport: &'static str,
    pub elapsed: Duration,
    pub rcode: &'static str,
    /// Whether the server claimed authority for the answer.
    pub authoritative: bool,
    pub answers: Vec<Answer>,
    /// Anything worth stating that is not an error: truncation and retry, a
    /// count that was capped.
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Job runner
// ---------------------------------------------------------------------------

/// A probe running on its own thread.
///
/// Deliberately a thread and a blocking socket rather than a task on the
/// engine's runtime. A probe is a rare, user-paced, short-lived thing, and the
/// GUI thread is not inside the runtime — routing it through the async engine
/// would mean carrying a `Handle` into the dashboard so that one keystroke could
/// borrow a worker from the packet path.
pub struct Job {
    slot: Arc<Mutex<Slot>>,
    started: Instant,
    /// What this job asked, for the "running" line in the UI.
    pub summary: String,
}

/// The worker's side of a job. `latest` carries partial results while a scan is
/// still walking its port list; `done` says whether anything further will arrive.
#[derive(Default)]
struct Slot {
    latest: Option<Result<Outcome, String>>,
    done: bool,
}

/// A sink the running action publishes progress through. `Sync` because a scan
/// hands it to every worker thread at once.
type Publish<'a> = &'a (dyn Fn(Outcome) + Sync);

impl Job {
    /// How long the probe has been running, for the pending indicator.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Read the latest result without consuming it. A scan republishes after
    /// every port, so this is what makes a long sweep watchable.
    pub fn snapshot(&self) -> Option<Result<Outcome, String>> {
        self.with_slot(|s| s.latest.clone())
    }

    /// Take the result if the probe has finished. Returns `None` while it is
    /// still in flight, so the caller can keep drawing a pending state.
    pub fn take(&self) -> Option<Result<Outcome, String>> {
        self.with_slot(|s| if s.done { s.latest.take() } else { None })
    }

    /// A panic in the worker cannot poison anything the caller needs — the guard
    /// holds plain data — so recover rather than wedge the widget on a
    /// permanently pending job.
    fn with_slot<T>(&self, f: impl FnOnce(&mut Slot) -> T) -> T {
        match self.slot.lock() {
            Ok(mut s) => f(&mut s),
            Err(e) => f(&mut e.into_inner()),
        }
    }
}

/// Start `req` on a worker thread. Never blocks the caller; a thread that
/// cannot be spawned is reported through the same slot as any other failure, so
/// the UI has exactly one path to render.
pub fn spawn(req: Request) -> Job {
    let summary = match req.action {
        Action::Nslookup => format!("{} {} {}", req.action.label(), req.record.label(), req.target),
        Action::PortScan => format!("{} {} ports {}", req.action.label(), req.ports.len(), req.target),
        Action::Intel => format!("{} {}", req.action.label(), req.target),
    };
    let slot: Arc<Mutex<Slot>> = Arc::new(Mutex::new(Slot::default()));
    let sink = slot.clone();

    let spawned = std::thread::Builder::new()
        .name("probe".to_string())
        .spawn(move || {
            let progress = sink.clone();
            let publish = move |o: Outcome| {
                if let Ok(mut s) = progress.lock() {
                    s.latest = Some(Ok(o));
                }
            };
            let out = run_with(&req, &publish);
            if let Ok(mut s) = sink.lock() {
                s.latest = Some(out);
                s.done = true;
            }
        });

    if let Err(e) = spawned {
        if let Ok(mut s) = slot.lock() {
            s.latest = Some(Err(format!("could not start probe thread: {e}")));
            s.done = true;
        }
    }

    Job { slot, started: Instant::now(), summary }
}

/// Execute a probe, publishing progress through `publish` as it goes. A caller
/// with nothing to show progress on passes `&|_| {}` and gets the final result.
fn run_with(req: &Request, publish: Publish) -> Result<Outcome, String> {
    match req.action {
        Action::Nslookup => nslookup(req).map(Outcome::Dns),
        Action::PortScan => scan(req, publish).map(Outcome::Scan),
        Action::Intel => intel(req).map(Outcome::Intel),
    }
}

// ---------------------------------------------------------------------------
// nslookup
// ---------------------------------------------------------------------------

fn nslookup(req: &Request) -> Result<DnsOutcome, String> {
    let target = req.target.trim();
    if target.is_empty() {
        return Err("no target: pick a host or type a name".to_string());
    }

    // An IP literal is asked backwards; a name is asked forwards. `Auto` is
    // resolved here, before anything is encoded, so `question` and `record` in
    // the outcome describe what actually went on the wire.
    let as_ip = target.parse::<IpAddr>().ok();
    let record = req.record.concrete(as_ip.is_some());
    let question = match (&as_ip, record) {
        (Some(ip), RecordType::Ptr) => reverse_name(*ip),
        (Some(_), other) => {
            return Err(format!(
                "{target} is an address: only PTR (or AUTO) applies, not {}",
                other.label()
            ))
        }
        (None, _) => target.to_string(),
    };

    let query = build_query(next_id(), &question, record.code())?;
    let started = Instant::now();

    let (mut bytes, mut transport) = (query_udp(req.server, &query, req.timeout)?, "udp");
    let mut note = None;

    // Truncated over UDP: retry over TCP rather than reporting a partial answer
    // as if it were the whole one. Worth surfacing either way — a lookup that
    // needs TCP is a fact about the path.
    if header_truncated(&bytes) {
        match query_tcp(req.server, &query, req.timeout) {
            Ok(full) => {
                bytes = full;
                transport = "tcp";
                note = Some("response was truncated over UDP; retried over TCP".to_string());
            }
            Err(e) => {
                note = Some(format!("response truncated and TCP retry failed: {e}"));
            }
        }
    }

    let elapsed = started.elapsed();
    let parsed = parse_response(&bytes, &query)?;
    if parsed.capped {
        note = Some(match note {
            Some(n) => format!("{n}; answer list capped at {MAX_ANSWERS} records"),
            None => format!("answer list capped at {MAX_ANSWERS} records"),
        });
    }

    Ok(DnsOutcome {
        question,
        record,
        server: req.server,
        transport,
        elapsed,
        rcode: parsed.rcode,
        authoritative: parsed.authoritative,
        answers: parsed.answers,
        note,
    })
}

/// An address's labels, least-significant first and without a zone suffix.
///
/// Split out because two different zones want the same reversal: `in-addr.arpa`
/// for a PTR, and Team Cymru's `origin.asn.cymru.com` for an ASN. Writing the
/// nibble expansion twice is how they would drift.
fn reverse_labels(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(64);
            for byte in v6.octets().iter().rev() {
                s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
                s.push('.');
                s.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                s.push('.');
            }
            s.pop(); // the trailing separator; the caller supplies the zone
            s
        }
    }
}

/// The `in-addr.arpa` / `ip6.arpa` name for an address.
fn reverse_name(ip: IpAddr) -> String {
    let zone = match ip {
        IpAddr::V4(_) => "in-addr.arpa",
        IpAddr::V6(_) => "ip6.arpa",
    };
    format!("{}.{}", reverse_labels(ip), zone)
}

// ---------------------------------------------------------------------------
// Port scan
// ---------------------------------------------------------------------------

/// Ports one scan may cover.
///
/// This cap is a NAT-table budget, not a preference. A port that never answers
/// leaves a binding behind for `wg.rs`'s `TCP_IDLE` — ten minutes — so a scan's
/// worst case is its whole list held against `MAX_BINDINGS` (16384) for that
/// long. At 1024 that is 6%; the default list is 0.6%. Raising this without
/// re-reading `wg.rs`'s expiry is how a scan starts shedding real traffic.
pub const MAX_SCAN_PORTS: usize = 1024;

/// Connections in flight at once. Bounds the *instantaneous* flow count, which
/// is what `conn.rs` admission control charges against its memory budget under
/// the Direct exit — each live TCP flow there owns a real send/receive buffer.
const SCAN_CONCURRENCY: usize = 16;

/// Per-port connect budget. Shorter than [`DEFAULT_TIMEOUT`]: a scan spends this
/// once per filtered port, and the list is long.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);

/// How long an open port is given to introduce itself. Nothing is sent, so this
/// is pure listening and most services will not use it.
const BANNER_TIMEOUT: Duration = Duration::from_millis(600);
const BANNER_BYTES: usize = 256;
const BANNER_CHARS: usize = 120;

/// The ports worth trying first — nmap's top-100 TCP, which is the empirical
/// answer to "what is actually listening on the internet".
pub const TOP_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

/// Parse a port specification: `22,80,443,8000-8100`.
///
/// Deduped and sorted so a list that names a port twice costs one connection,
/// and capped at [`MAX_SCAN_PORTS`] with an error rather than a silent trim —
/// a scan that quietly covered less than it was asked to would be a lie about
/// what was found.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports: Vec<u16> = Vec::new();
    for piece in spec.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let port = |s: &str| -> Result<u16, String> {
            s.trim()
                .parse::<u16>()
                .map_err(|_| format!("{s:?} is not a port number"))
                .and_then(|p| if p == 0 { Err("port 0 is not a port".into()) } else { Ok(p) })
        };
        match piece.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (port(lo)?, port(hi)?);
                if lo > hi {
                    return Err(format!("range {lo}-{hi} runs backwards"));
                }
                // Bounded before the extend, so a `1-65535` cannot allocate the
                // whole range on its way to being rejected.
                if (hi - lo) as usize + 1 + ports.len() > MAX_SCAN_PORTS {
                    return Err(format!("more than {MAX_SCAN_PORTS} ports"));
                }
                ports.extend(lo..=hi);
            }
            None => ports.push(port(piece)?),
        }
    }

    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("no ports given".to_string());
    }
    if ports.len() > MAX_SCAN_PORTS {
        return Err(format!(
            "{} ports: at most {MAX_SCAN_PORTS} per scan",
            ports.len()
        ));
    }
    Ok(ports)
}

/// Resolve a target to one address using the probe's own resolver rather than
/// the OS stub, so every action agrees about what the target points at.
fn resolve_one(req: &Request) -> Result<IpAddr, String> {
    let target = req.target.trim();
    if target.is_empty() {
        return Err("no target: pick a host or type a name".to_string());
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    let data = lookup_first(req, target, 1)
        .ok_or_else(|| format!("{target} does not resolve to an address"))?;
    data.parse::<IpAddr>()
        .map_err(|_| format!("{target} resolved to {data:?}, which is not an address"))
}

fn scan(req: &Request, publish: Publish) -> Result<ScanOutcome, String> {
    if req.ports.is_empty() {
        return Err("no ports to scan".to_string());
    }
    if req.ports.len() > MAX_SCAN_PORTS {
        return Err(format!("at most {MAX_SCAN_PORTS} ports per scan"));
    }
    let target = resolve_one(req)?;
    let started = Instant::now();
    let total = req.ports.len();

    // A shared cursor rather than a per-worker slice: ports differ wildly in how
    // long they take (a refusal is instant, a filtered port costs the whole
    // timeout), so a static split would leave workers idle behind one slow shard.
    let cursor = Mutex::new(0usize);
    let progress = Mutex::new(ScanOutcome {
        target,
        done: 0,
        total,
        elapsed: Duration::ZERO,
        open: Vec::new(),
        closed: 0,
        filtered: 0,
    });

    std::thread::scope(|s| {
        for _ in 0..SCAN_CONCURRENCY.min(total) {
            s.spawn(|| loop {
                let Some(port) = ({
                    let mut n = cursor.lock().unwrap_or_else(|e| e.into_inner());
                    let i = *n;
                    *n += 1;
                    req.ports.get(i).copied()
                }) else {
                    break;
                };

                let (state, found) = probe_port(target, port);
                let snapshot = {
                    let mut st = progress.lock().unwrap_or_else(|e| e.into_inner());
                    match state {
                        PortState::Open => st.open.extend(found),
                        PortState::Closed => st.closed += 1,
                        PortState::Filtered => st.filtered += 1,
                    }
                    st.done += 1;
                    st.elapsed = started.elapsed();
                    st.clone()
                };
                publish(Outcome::Scan(snapshot));
            });
        }
    });

    let mut out = progress.into_inner().unwrap_or_else(|e| e.into_inner());
    out.elapsed = started.elapsed();
    // Workers finish out of order, so the table is sorted once at the end
    // rather than kept ordered on every insert.
    out.open.sort_by_key(|p| p.port);
    Ok(out)
}

/// One port: how it answered, and its details when it is open.
fn probe_port(target: IpAddr, port: u16) -> (PortState, Option<PortResult>) {
    let addr = SocketAddr::new(target, port);
    let mut stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => return (connect_state(&e), None),
    };

    // Close with RST rather than FIN. `wg.rs` frees a NAT binding the moment it
    // sees a reset but otherwise holds it for TCP_IDLE, so without this every
    // open port would cost a binding for ten minutes — and the host would
    // accumulate TIME_WAIT for each one besides.
    socket2::SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .ok();

    // Listen, never speak. A service that announces itself is recorded; one
    // that waits is left alone rather than prodded with a synthetic request.
    let mut buf = [0u8; BANNER_BYTES];
    stream.set_read_timeout(Some(BANNER_TIMEOUT)).ok();
    let banner = match stream.read(&mut buf) {
        Ok(n) if n > 0 => banner_text(&buf[..n]),
        _ => None,
    };

    (
        PortState::Open,
        Some(PortResult { port, service: crate::inspect::service_name(port), banner }),
    )
}

/// A service's greeting, made safe to display.
///
/// The bytes are whatever the far end sent, so they go through the same escaping
/// as record text: a banner is one of the few places in this window where a
/// remote host chooses the characters. Whitespace-only is `None` — a service
/// that sent a bare newline has not introduced itself.
fn banner_text(bytes: &[u8]) -> Option<String> {
    // Trim the BYTES, then escape. The other order turns a trailing CRLF into
    // the literal text `\x0d\x0a`, which is no longer whitespace and so never
    // trims — every banner would end in six characters of framing.
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace())?;
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace())?;
    let mut text = String::new();
    push_escaped(&mut text, &bytes[start..=end]);
    Some(clamp_to(&text, BANNER_CHARS))
}

/// Classify a connect failure. Kept next to [`probe_port`] because the mapping
/// is the whole difference between "this host declined" and "nothing came back".
fn connect_state(e: &std::io::Error) -> PortState {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        _ => PortState::Filtered,
    }
}

// ---------------------------------------------------------------------------
// Intel
// ---------------------------------------------------------------------------

/// Ask one question and return the first answer of the type asked for.
///
/// Every failure collapses to `None`: for a dossier assembled from several
/// independent lookups, a missing field is a missing field, not an error that
/// throws away the fields that did arrive.
fn lookup_first(req: &Request, name: &str, qtype: u16) -> Option<String> {
    let query = build_query(next_id(), name, qtype).ok()?;
    let bytes = query_udp(req.server, &query, req.timeout).ok()?;
    let parsed = parse_response(&bytes, &query).ok()?;
    let want = type_name(qtype);
    parsed.answers.into_iter().find(|a| a.kind == want).map(|a| a.data)
}

/// Split a Team Cymru TXT record into its pipe-separated fields.
///
/// The record arrives already rendered by `render_txt`, so it is quoted and
/// escaped; the quotes come off here. Positional and short records are normal —
/// the caller reads fields by index and tolerates absence.
fn cymru_fields(data: &str) -> Vec<String> {
    data.replace('"', "")
        .split('|')
        .map(|f| f.trim().to_string())
        .collect()
}

fn intel(req: &Request) -> Result<IntelOutcome, String> {
    let target = resolve_one(req)?;
    let started = Instant::now();
    let mut out = IntelOutcome { target: target.to_string(), ..Default::default() };

    out.ptr = lookup_first(req, &reverse_name(target), 12);

    // Team Cymru's IP-to-ASN service is plain DNS, which is the whole reason
    // this action needs no dependency and no connection to the host itself.
    let zone = match target {
        IpAddr::V4(_) => "origin.asn.cymru.com",
        IpAddr::V6(_) => "origin6.asn.cymru.com",
    };
    let origin = lookup_first(req, &format!("{}.{}", reverse_labels(target), zone), 16);

    if let Some(fields) = origin.as_deref().map(cymru_fields) {
        // "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
        out.asn = fields.first().and_then(|s| s.parse::<u32>().ok());
        out.prefix = non_empty(fields.get(1));
        out.country = non_empty(fields.get(2));
        out.registry = non_empty(fields.get(3));
        out.allocated = non_empty(fields.get(4));
    }

    if let Some(asn) = out.asn {
        // "23028 | US | arin | 2002-01-04 | TEAM-CYMRU, US"
        let name = lookup_first(req, &format!("AS{asn}.asn.cymru.com"), 16);
        out.org = name.as_deref().map(cymru_fields).and_then(|f| non_empty(f.get(4)));
    }

    out.elapsed = started.elapsed();
    if out.ptr.is_none() && out.asn.is_none() {
        out.note = Some(format!(
            "no reverse name and no ASN from {} — the resolver may not be reaching \
             cymru.com, or the address is not routed",
            req.server
        ));
    }
    Ok(out)
}

fn non_empty(f: Option<&String>) -> Option<String> {
    f.filter(|s| !s.is_empty()).cloned()
}

/// Query ID.
///
/// Not a CSPRNG, and it does not need to be: the socket is `connect`ed, so the
/// kernel drops anything not from the server we asked, and the parser also
/// requires the echoed question to match. The ID's job here is to reject a late
/// reply to a previous query on a reused ephemeral port, and a counter mixed
/// with the process start offset does that.
fn next_id() -> u16 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((n ^ jitter.rotate_left(7)) & 0xffff) as u16
}

// ---------------------------------------------------------------------------
// Wire format — encode
// ---------------------------------------------------------------------------

fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    // Flags: standard query, recursion desired.
    p.extend_from_slice(&[0x01, 0x00]);
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN / NS / AR
    encode_name(name, &mut p)?;
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // class IN
    Ok(p)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let name = name.trim().trim_end_matches('.');
    let start = out.len();
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                return Err(format!("{name}: empty label (doubled dot?)"));
            }
            if label.len() > 63 {
                return Err(format!("{name}: label longer than 63 bytes"));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
            {
                return Err(format!(
                    "{name}: only letters, digits, '-', '_' and '*' are allowed in a label"
                ));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - start > 255 {
        return Err(format!("{name}: encoded name exceeds 255 bytes"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

fn query_udp(server: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    // Bind in the server's family. The socket is otherwise ordinary and
    // unmarked, which is the point: it takes the host's default route, so under
    // full-tunnel capture it goes through the engine like any other app.
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
    sock.connect(server).map_err(|e| format!("connect {server}: {e}"))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;
    sock.send(query).map_err(|e| format!("send to {server}: {e}"))?;

    // Read until the ID matches or the budget is spent: a stale datagram from an
    // earlier query on a recycled port must not be mistaken for this answer.
    let want = u16::from_be_bytes([query[0], query[1]]);
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; MAX_UDP_RESPONSE];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!("no response from {server} within {:?}", timeout));
        }
        sock.set_read_timeout(Some(remaining)).ok();
        match sock.recv(&mut buf) {
            Ok(n) if n >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == want => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(format!("no response from {server} within {timeout:?}"));
            }
            Err(e) => return Err(format!("recv from {server}: {e}")),
        }
    }
}

fn query_tcp(server: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut s = TcpStream::connect_timeout(&server, timeout)
        .map_err(|e| format!("tcp connect {server}: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();

    let len = u16::try_from(query.len()).map_err(|_| "query too long for TCP".to_string())?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    s.write_all(&framed).map_err(|e| format!("tcp write: {e}"))?;

    // Two-byte length prefix (RFC 1035 §4.2.2), so the response is exactly as
    // long as the server says and no read is unbounded.
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).map_err(|e| format!("tcp read: {e}"))?;
    let n = u16::from_be_bytes(hdr) as usize;
    if n < 12 {
        return Err("tcp response too short to be a DNS message".to_string());
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| format!("tcp read: {e}"))?;
    Ok(buf)
}

fn header_truncated(msg: &[u8]) -> bool {
    msg.len() >= 4 && msg[2] & 0x02 != 0
}

// ---------------------------------------------------------------------------
// Wire format — decode
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Parsed {
    rcode: &'static str,
    authoritative: bool,
    answers: Vec<Answer>,
    capped: bool,
}

fn parse_response(msg: &[u8], query: &[u8]) -> Result<Parsed, String> {
    if msg.len() < 12 {
        return Err("response shorter than a DNS header".to_string());
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != u16::from_be_bytes([query[0], query[1]]) {
        return Err("response ID does not match the query".to_string());
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return Err("response is not marked as a reply".to_string());
    }
    let rcode = rcode_name((flags & 0x000f) as u8);
    let authoritative = flags & 0x0400 != 0;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    // Walk the question section. It is echoed, so the first question must be the
    // one we asked — a server (or something in the middle) answering a different
    // question is not answering ours.
    let mut pos = 12;
    for i in 0..qdcount {
        let (name, next) = read_name(msg, pos)?;
        pos = next;
        let (qtype, qclass) = (read_u16(msg, pos)?, read_u16(msg, pos + 2)?);
        pos += 4;
        if i == 0 {
            let (want_name, want_next) = read_name(query, 12)?;
            let want_type = read_u16(query, want_next)?;
            if !name.eq_ignore_ascii_case(&want_name) || qtype != want_type || qclass != 1 {
                return Err(format!("response answers a different question ({name})"));
            }
        }
    }

    let mut answers = Vec::new();
    let mut capped = false;
    for _ in 0..ancount {
        if answers.len() >= MAX_ANSWERS {
            capped = true;
            break;
        }
        // A record that runs off the end of the message ends the section: the
        // records already decoded are real and worth showing.
        let (name, next) = match read_name(msg, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = next;
        let (kind, _class, ttl, rdlen) = match (
            read_u16(msg, pos),
            read_u16(msg, pos + 2),
            read_u32(msg, pos + 4),
            read_u16(msg, pos + 8),
        ) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d as usize),
            _ => break,
        };
        pos += 10;
        let Some(rdata) = msg.get(pos..pos + rdlen) else {
            break;
        };
        let data = render_rdata(msg, pos, rdata, kind);
        pos += rdlen;
        answers.push(Answer { name, kind: type_name(kind), ttl, data });
    }

    Ok(Parsed { rcode, authoritative, answers, capped })
}

/// Render one record's RDATA for display. `msg`/`off` are passed as well as the
/// slice because names inside RDATA may compress against the whole message.
fn render_rdata(msg: &[u8], off: usize, rdata: &[u8], kind: u16) -> String {
    let text = match kind {
        1 => match <[u8; 4]>::try_from(rdata) {
            Ok(o) => Ipv4Addr::from(o).to_string(),
            Err(_) => malformed(rdata),
        },
        28 => match <[u8; 16]>::try_from(rdata) {
            Ok(o) => Ipv6Addr::from(o).to_string(),
            Err(_) => malformed(rdata),
        },
        2 | 5 | 12 | 39 => match read_name(msg, off) {
            Ok((n, _)) => n,
            Err(e) => format!("<{e}>"),
        },
        15 => match (read_u16(rdata, 0), read_name(msg, off + 2)) {
            (Ok(pref), Ok((n, _))) => format!("{pref} {n}"),
            _ => malformed(rdata),
        },
        6 => render_soa(msg, off).unwrap_or_else(|| malformed(rdata)),
        16 => render_txt(rdata),
        52 => render_tlsa(rdata),
        257 => render_caa(rdata),
        _ => malformed(rdata),
    };
    clamp_text(&text)
}

/// CAA (RFC 8659): a flags byte, a length-prefixed tag, and the rest is value.
/// Rendered in zone-file order — `0 issue "letsencrypt.org"`.
fn render_caa(rdata: &[u8]) -> String {
    let (Some(&flags), Some(&taglen)) = (rdata.first(), rdata.get(1)) else {
        return malformed(rdata);
    };
    // RFC 8659 §4.1 puts the tag at 1..=15 bytes. A zero-length tag is not a
    // CAA record with an empty tag, it is something else wearing the type.
    if taglen == 0 || taglen > 15 {
        return malformed(rdata);
    }
    let Some(tag) = rdata.get(2..2 + taglen as usize) else {
        return malformed(rdata);
    };
    let mut out = format!("{flags} ");
    push_escaped(&mut out, tag);
    out.push_str(" \"");
    push_escaped(&mut out, &rdata[2 + taglen as usize..]);
    out.push('"');
    out
}

/// TLSA (RFC 6698): usage, selector, matching type, then the association data,
/// which is a hash and only meaningful as hex.
fn render_tlsa(rdata: &[u8]) -> String {
    let Some(head) = rdata.get(..3) else {
        return malformed(rdata);
    };
    let assoc = &rdata[3..];
    if assoc.is_empty() {
        return malformed(rdata);
    }
    let mut hex = String::with_capacity(64);
    for b in assoc.iter().take(32) {
        hex.push_str(&format!("{b:02x}"));
    }
    if assoc.len() > 32 {
        hex.push('…');
    }
    format!("{} {} {} {hex}", head[0], head[1], head[2])
}

fn render_soa(msg: &[u8], off: usize) -> Option<String> {
    let (mname, after_m) = read_name(msg, off).ok()?;
    let (rname, after_r) = read_name(msg, after_m).ok()?;
    let serial = read_u32(msg, after_r).ok()?;
    let refresh = read_u32(msg, after_r + 4).ok()?;
    let retry = read_u32(msg, after_r + 8).ok()?;
    let expire = read_u32(msg, after_r + 12).ok()?;
    let minimum = read_u32(msg, after_r + 16).ok()?;
    Some(format!(
        "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    ))
}

/// TXT RDATA is a sequence of length-prefixed byte strings, and the bytes are
/// whatever the zone owner put there — escape before it reaches a label.
fn render_txt(rdata: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        let Some(chunk) = rdata.get(i..i + len) else {
            break;
        };
        i += len;
        if !out.is_empty() {
            out.push(' ');
        }
        out.push('"');
        push_escaped(&mut out, chunk);
        out.push('"');
    }
    if out.is_empty() {
        malformed(rdata)
    } else {
        out
    }
}

fn malformed(rdata: &[u8]) -> String {
    let mut s = String::with_capacity(rdata.len() * 2 + 8);
    for b in rdata.iter().take(32) {
        s.push_str(&format!("{b:02x}"));
    }
    if rdata.len() > 32 {
        s.push('…');
    }
    if s.is_empty() {
        "<empty>".to_string()
    } else {
        format!("0x{s}")
    }
}

/// Append `bytes` as printable ASCII, escaping everything else. Control
/// characters in a record must never reach the UI as themselves.
fn push_escaped(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
}

fn clamp_text(s: &str) -> String {
    clamp_to(s, MAX_RDATA_CHARS)
}

fn clamp_to(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, String> {
    match buf.get(pos..pos + 2) {
        Some(b) => Ok(u16::from_be_bytes([b[0], b[1]])),
        None => Err("truncated record".to_string()),
    }
}

fn read_u32(buf: &[u8], pos: usize) -> Result<u32, String> {
    match buf.get(pos..pos + 4) {
        Some(b) => Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        None => Err("truncated record".to_string()),
    }
}

/// Decode a (possibly compressed) name, returning it and the offset just past
/// the name *in its original position* — following a pointer must not move the
/// caller's cursor into the pointed-at record.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut pos = start;
    let mut jumps = 0usize;
    let mut resume: Option<usize> = None;

    loop {
        let len = *buf.get(pos).ok_or("truncated name")? as usize;
        pos += 1;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    break;
                }
                let label = buf.get(pos..pos + len).ok_or("truncated label")?;
                if !out.is_empty() {
                    out.push('.');
                }
                push_escaped(&mut out, label);
                pos += len;
                // 255 is the protocol's own ceiling; enforcing it here also
                // bounds the string a pointer chain could build.
                if out.len() > 255 {
                    return Err("name longer than 255 bytes".to_string());
                }
            }
            0xc0 => {
                let lo = *buf.get(pos).ok_or("truncated compression pointer")? as usize;
                let target = ((len & 0x3f) << 8) | lo;
                pos += 1;
                if resume.is_none() {
                    resume = Some(pos);
                }
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return Err("compression pointer loop".to_string());
                }
                if target >= buf.len() {
                    return Err("compression pointer past end of message".to_string());
                }
                pos = target;
            }
            // 0x40 and 0x80 are reserved label types; nothing legitimate sends
            // them and guessing at a length here is how parsers get walked.
            _ => return Err("reserved label type in name".to_string()),
        }
    }

    if out.is_empty() {
        out.push('.');
    }
    Ok((out, resume.unwrap_or(pos)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a response for `qname`/`qtype` with the given answer records,
    /// each `(type, rdata)`. Names are written uncompressed except where a test
    /// builds its own bytes.
    fn response(id: u16, qname: &str, qtype: u16, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]);
        encode_name(qname, &mut p).unwrap();
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        for (kind, rdata) in answers {
            encode_name(qname, &mut p).unwrap();
            p.extend_from_slice(&kind.to_be_bytes());
            p.extend_from_slice(&1u16.to_be_bytes());
            p.extend_from_slice(&300u32.to_be_bytes());
            p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            p.extend_from_slice(rdata);
        }
        p
    }

    #[test]
    fn reverse_names_follow_the_arpa_zones() {
        assert_eq!(
            reverse_name("8.8.4.4".parse().unwrap()),
            "4.4.8.8.in-addr.arpa"
        );
        let v6 = reverse_name("2001:4860:4860::8888".parse().unwrap());
        assert!(v6.ends_with("ip6.arpa"));
        // 32 nibbles, each followed by a dot, then the suffix.
        assert_eq!(v6.matches('.').count(), 33);
        assert!(v6.starts_with("8.8.8.8.0.0.0.0"));
    }

    #[test]
    fn auto_picks_ptr_for_addresses_and_a_for_names() {
        assert_eq!(RecordType::Auto.concrete(true), RecordType::Ptr);
        assert_eq!(RecordType::Auto.concrete(false), RecordType::A);
        // An explicit choice is never overridden.
        assert_eq!(RecordType::Txt.concrete(true), RecordType::Txt);
    }

    #[test]
    fn a_and_aaaa_answers_decode_to_addresses() {
        let q = build_query(0x1234, "example.com", 1).unwrap();
        let r = response(0x1234, "example.com", 1, &[(1, vec![93, 184, 216, 34])]);
        let p = parse_response(&r, &q).unwrap();
        assert_eq!(p.rcode, "NOERROR");
        assert_eq!(p.answers.len(), 1);
        assert_eq!(p.answers[0].name, "example.com");
        assert_eq!(p.answers[0].kind, "A");
        assert_eq!(p.answers[0].ttl, 300);
        assert_eq!(p.answers[0].data, "93.184.216.34");

        let q6 = build_query(1, "example.com", 28).unwrap();
        let r6 = response(1, "example.com", 28, &[(28, vec![0x20, 0x01, 0x0d, 0xb8].into_iter().chain(std::iter::repeat(0).take(11)).chain(std::iter::once(1)).collect())]);
        let p6 = parse_response(&r6, &q6).unwrap();
        assert_eq!(p6.answers[0].data, "2001:db8::1");
    }

    #[test]
    fn a_response_to_a_different_question_is_rejected() {
        let q = build_query(9, "example.com", 1).unwrap();
        let r = response(9, "evil.example", 1, &[(1, vec![1, 2, 3, 4])]);
        assert!(parse_response(&r, &q).unwrap_err().contains("different question"));
        // ...and so is a mismatched ID, even with the right question.
        let wrong_id = response(10, "example.com", 1, &[(1, vec![1, 2, 3, 4])]);
        assert!(parse_response(&wrong_id, &q).unwrap_err().contains("ID"));
    }

    #[test]
    fn compression_pointer_loops_terminate() {
        // A name at offset 12 that points at itself: the classic parser hang.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xc0, 0x0c]);
        let err = read_name(&msg, 12).unwrap_err();
        assert!(err.contains("loop"), "{err}");

        // Two names pointing at each other terminates too.
        let mut ping = vec![0u8; 12];
        ping.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]);
        assert!(read_name(&ping, 12).is_err());
    }

    #[test]
    fn truncated_and_malformed_input_never_panics() {
        let q = build_query(1, "example.com", 1).unwrap();
        // Every prefix of a well-formed response must be handled.
        let full = response(1, "example.com", 1, &[(1, vec![9, 9, 9, 9])]);
        for n in 0..full.len() {
            let _ = parse_response(&full[..n], &q);
        }
        // Pointer past the end, reserved label type, empty message.
        let mut bad = vec![0u8; 12];
        bad.extend_from_slice(&[0xc0, 0xff]);
        assert!(read_name(&bad, 12).is_err());
        let mut reserved = vec![0u8; 12];
        reserved.extend_from_slice(&[0x80, 0x01]);
        assert!(read_name(&reserved, 12).is_err());
        assert!(read_name(&[], 0).is_err());
    }

    #[test]
    fn an_answer_count_that_lies_is_bounded_by_the_message() {
        // ANCOUNT claims 4000 records; the message carries one.
        let q = build_query(7, "example.com", 1).unwrap();
        let mut r = response(7, "example.com", 1, &[(1, vec![1, 1, 1, 1])]);
        r[6..8].copy_from_slice(&4000u16.to_be_bytes());
        let p = parse_response(&r, &q).unwrap();
        assert_eq!(p.answers.len(), 1);
        assert!(!p.capped);
    }

    #[test]
    fn record_text_is_escaped_and_clamped() {
        let q = build_query(3, "example.com", 16).unwrap();
        // A TXT record carrying a newline, a quote and a NUL.
        let payload = b"a\n\"b\0c";
        let mut rdata = vec![payload.len() as u8];
        rdata.extend_from_slice(payload);
        let r = response(3, "example.com", 16, &[(16, rdata)]);
        let p = parse_response(&r, &q).unwrap();
        assert_eq!(p.answers[0].data, "\"a\\x0a\\\"b\\x00c\"");
        assert!(!p.answers[0].data.contains('\n'));

        // Long records are clamped for display.
        let long = clamp_text(&"x".repeat(MAX_RDATA_CHARS * 2));
        assert_eq!(long.chars().count(), MAX_RDATA_CHARS);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn mx_and_soa_render_their_fields() {
        let q = build_query(4, "example.com", 15).unwrap();
        let mut rdata = 10u16.to_be_bytes().to_vec();
        encode_name("mail.example.com", &mut rdata).unwrap();
        let r = response(4, "example.com", 15, &[(15, rdata)]);
        let p = parse_response(&r, &q).unwrap();
        assert_eq!(p.answers[0].data, "10 mail.example.com");

        let qs = build_query(5, "example.com", 6).unwrap();
        let mut soa = Vec::new();
        encode_name("ns.example.com", &mut soa).unwrap();
        encode_name("hostmaster.example.com", &mut soa).unwrap();
        for v in [2024u32, 7200, 3600, 1209600, 300] {
            soa.extend_from_slice(&v.to_be_bytes());
        }
        let rs = response(5, "example.com", 6, &[(6, soa)]);
        let ps = parse_response(&rs, &qs).unwrap();
        assert_eq!(
            ps.answers[0].data,
            "ns.example.com hostmaster.example.com 2024 7200 3600 1209600 300"
        );
    }

    #[test]
    fn queries_reject_names_that_cannot_be_encoded() {
        assert!(build_query(1, "example..com", 1).is_err());
        assert!(build_query(1, &"a".repeat(64), 1).is_err());
        assert!(build_query(1, "bad host name", 1).is_err());
        // A trailing dot is the root form and is accepted.
        assert!(build_query(1, "example.com.", 1).is_ok());
    }

    #[test]
    fn an_address_target_only_accepts_a_reverse_question() {
        let req = |target: &str, record| Request {
            action: Action::Nslookup,
            target: target.to_string(),
            record,
            server: "127.0.0.1:53".parse().unwrap(),
            timeout: Duration::from_millis(1),
            ports: Vec::new(),
        };
        let err = nslookup(&req("1.1.1.1", RecordType::Mx)).unwrap_err();
        assert!(err.contains("only PTR"), "{err}");
        assert!(nslookup(&req("   ", RecordType::Auto))
            .unwrap_err()
            .contains("no target"));
    }

    #[test]
    fn a_port_list_is_normalised_before_anything_opens_a_socket() {
        assert_eq!(parse_ports("22").unwrap(), [22]);
        assert_eq!(parse_ports(" 80 , 22,443 ").unwrap(), [22, 80, 443]);
        assert_eq!(parse_ports("20-23").unwrap(), [20, 21, 22, 23]);
        // Sorted and deduped: a list that names a port twice costs one connect.
        assert_eq!(parse_ports("443,22,443,20-22").unwrap(), [20, 21, 22, 443]);
        // Trailing and doubled separators are typing, not an error.
        assert_eq!(parse_ports("22,,80,").unwrap(), [22, 80]);

        for bad in ["", "  ", ",", "0", "22-", "-22", "80-22", "99999", "http", "22-abc"] {
            assert!(parse_ports(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_scan_cannot_outgrow_the_nat_table() {
        // This cap is a NAT budget, not a preference. A filtered port leaves a
        // binding behind for wg.rs's TCP_IDLE (600s), so a scan's worst case is
        // its whole list held against MAX_BINDINGS (16384) for ten minutes.
        // At 1024 that is 6%; the default list is 0.6%.
        assert!(TOP_PORTS.len() < MAX_SCAN_PORTS);
        assert_eq!(parse_ports(&format!("1-{MAX_SCAN_PORTS}")).unwrap().len(), MAX_SCAN_PORTS);
        let over = parse_ports(&format!("1-{}", MAX_SCAN_PORTS + 1)).unwrap_err();
        assert!(over.contains(&MAX_SCAN_PORTS.to_string()), "{over}");

        // Rejected without ever building the list, so a full-range request
        // cannot allocate 65535 entries on its way to being refused.
        assert!(parse_ports("1-65535").is_err());
        // ...including when the overflow is spread across several pieces.
        let spread = format!("1-{},{}-{}", MAX_SCAN_PORTS, MAX_SCAN_PORTS + 1, MAX_SCAN_PORTS + 8);
        assert!(parse_ports(&spread).is_err());

        // The shipped list is itself well-formed: sorted, deduped, no port 0.
        let mut sorted = TOP_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TOP_PORTS.len(), "TOP_PORTS repeats a port");
        assert!(!TOP_PORTS.contains(&0));
    }

    #[test]
    fn a_scan_accounts_for_every_port_it_was_given() {
        // Sixteen workers pull from one cursor and fold results into one
        // accumulator, so the invariant that matters is arithmetic: every port
        // lands in exactly one bucket. A lost or double-counted result would
        // otherwise show up only as a scan whose totals quietly disagree.
        //
        // Loopback rather than a mock: `probe_port` is a socket, and the thing
        // worth testing is what it does with one.
        let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = open.local_addr().unwrap().port();
        let closed_port = {
            let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = s.local_addr().unwrap().port();
            drop(s); // nothing is listening here now
            p
        };

        let req = Request {
            action: Action::PortScan,
            target: "127.0.0.1".to_string(),
            record: RecordType::Auto,
            server: "127.0.0.1:53".parse().unwrap(),
            timeout: Duration::from_millis(200),
            ports: vec![open_port, closed_port],
        };

        let seen = Mutex::new(Vec::new());
        let out = match run_with(&req, &|o| {
            if let Outcome::Scan(s) = o {
                seen.lock().unwrap().push(s.done);
            }
        }) {
            Ok(Outcome::Scan(s)) => s,
            other => panic!("expected a scan outcome, got {other:?}"),
        };

        assert_eq!(out.total, 2);
        assert_eq!(out.done, 2);
        assert_eq!(
            out.open.len() + out.closed + out.filtered,
            out.total,
            "a port went missing: {out:?}"
        );
        assert!(out.complete());
        assert_eq!(out.open.len(), 1, "the bound listener should be open: {out:?}");
        assert_eq!(out.open[0].port, open_port);

        // Progress was published as it went, not only at the end — that is what
        // keeps a long sweep from being a blank widget.
        let progress = seen.into_inner().unwrap();
        assert_eq!(progress.len(), 2, "expected one publish per port");
        assert!(progress.contains(&2));
    }

    #[test]
    fn a_scan_refuses_a_list_it_should_never_have_been_handed() {
        // `parse_ports` is the gate, but `scan` is what opens sockets, so it
        // re-checks rather than trusting its caller with the NAT budget.
        let req = |ports: Vec<u16>| Request {
            action: Action::PortScan,
            target: "127.0.0.1".to_string(),
            record: RecordType::Auto,
            server: "127.0.0.1:53".parse().unwrap(),
            timeout: Duration::from_millis(1),
            ports,
        };
        assert!(scan(&req(Vec::new()), &|_| {}).is_err());
        assert!(scan(&req(vec![80; MAX_SCAN_PORTS + 1]), &|_| {})
            .unwrap_err()
            .contains(&MAX_SCAN_PORTS.to_string()));
    }

    #[test]
    fn a_connect_failure_says_which_kind_it_was() {
        use std::io::{Error, ErrorKind};
        // Refused is a host that answered and declined; everything else is
        // silence, which is a firewall or a path that never arrived.
        assert_eq!(
            connect_state(&Error::from(ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock, ErrorKind::PermissionDenied] {
            assert_eq!(connect_state(&Error::from(kind)), PortState::Filtered);
        }
    }

    #[test]
    fn a_banner_is_escaped_and_bounded_before_it_is_shown() {
        // The far end chooses these bytes, and they land in a label.
        assert_eq!(banner_text(b"SSH-2.0-OpenSSH_9.6\r\n").unwrap(), "SSH-2.0-OpenSSH_9.6");
        let hostile = banner_text(b"220 \x1b[2Jmail\0ready").unwrap();
        assert!(!hostile.contains('\x1b') && !hostile.contains('\0'), "{hostile}");
        assert!(hostile.contains("\\x1b"));

        // Whitespace only is not an introduction.
        assert_eq!(banner_text(b""), None);
        assert_eq!(banner_text(b"\r\n  \t"), None);

        // A chatty service cannot push the other columns off the row.
        let long = banner_text(&[b'x'; BANNER_BYTES]).unwrap();
        assert_eq!(long.chars().count(), BANNER_CHARS);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn cymru_records_survive_being_malformed() {
        // The well-formed shape, which is all that matters on a good day.
        let origin = cymru_fields("\"23028 | 216.90.108.0/24 | US | arin | 1998-09-25\"");
        assert_eq!(origin[0], "23028");
        assert_eq!(origin[1], "216.90.108.0/24");
        assert_eq!(origin[4], "1998-09-25");

        // Short, empty and absent fields are normal, not errors: the caller
        // reads by index and a partial dossier beats no dossier.
        assert_eq!(non_empty(cymru_fields("\"23028 |  | US\"").get(1)), None);
        assert_eq!(non_empty(cymru_fields("\"23028\"").get(4)), None);
        assert!(cymru_fields("").len() <= 1);

        // A record that is not a Cymru record at all yields nothing usable
        // rather than a wrong answer.
        assert_eq!(cymru_fields("\"v=spf1 -all\"")[0].parse::<u32>().ok(), None);
        // Pipes with nothing between them do not panic or misalign.
        assert_eq!(cymru_fields("\"|||||\"").len(), 6);
    }

    #[test]
    fn an_address_reverses_the_same_way_for_every_zone_that_wants_it() {
        // One reversal feeds both in-addr.arpa and Cymru's origin zone; writing
        // the nibble expansion twice is how the two would drift.
        let v4: IpAddr = "216.90.108.31".parse().unwrap();
        assert_eq!(reverse_labels(v4), "31.108.90.216");
        assert_eq!(reverse_name(v4), "31.108.90.216.in-addr.arpa");

        let v6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(reverse_name(v6).ends_with(".ip6.arpa"));
        assert_eq!(reverse_labels(v6).matches('.').count(), 31, "32 nibbles, 31 separators");
        assert!(!reverse_labels(v6).ends_with('.'), "the zone supplies its own separator");

        // Both forms have to survive encoding, or the query is never sent.
        for ip in [v4, v6] {
            assert!(build_query(1, &reverse_name(ip), 12).is_ok());
            assert!(build_query(1, &format!("{}.origin.asn.cymru.com", reverse_labels(ip)), 16).is_ok());
        }
    }

    #[test]
    fn caa_and_tlsa_render_their_fields() {
        let q = build_query(1, "example.com", 257).unwrap();
        let mut caa = vec![0u8, 5];
        caa.extend_from_slice(b"issue");
        caa.extend_from_slice(b"letsencrypt.org");
        let r = response(1, "example.com", 257, &[(257, caa)]);
        assert_eq!(
            parse_response(&r, &q).unwrap().answers[0].data,
            "0 issue \"letsencrypt.org\""
        );

        // RFC 8659 puts the tag at 1..=15 bytes, so a zero-length tag is
        // something else wearing the type — shown as bytes, not as a CAA record.
        assert!(render_caa(&[0, 0, b'x']).starts_with("0x"));
        assert!(render_caa(&[0, 99, b'x']).starts_with("0x"));
        assert!(render_caa(&[]).starts_with('<') || render_caa(&[]).starts_with("0x"));
        for n in 0..8 {
            let _ = render_caa(&[0u8, 5, b'i', b's', b's', b'u', b'e'][..n.min(7)]);
        }

        let tlsa = render_tlsa(&[3, 1, 1, 0xab, 0xcd]);
        assert_eq!(tlsa, "3 1 1 abcd");
        assert!(render_tlsa(&[3, 1, 1]).starts_with("0x") || render_tlsa(&[3, 1, 1]) == "<empty>");
        assert!(render_tlsa(&[3, 1]).starts_with("0x"));
    }

    #[test]
    fn rcodes_and_flags_are_reported() {
        let q = build_query(6, "nx.example", 1).unwrap();
        let mut r = response(6, "nx.example", 1, &[]);
        r[3] |= 3; // NXDOMAIN
        r[2] |= 0x04; // authoritative
        let p = parse_response(&r, &q).unwrap();
        assert_eq!(p.rcode, "NXDOMAIN");
        assert!(p.authoritative);
        assert!(p.answers.is_empty());
        assert!(header_truncated(&[0, 0, 0x02, 0]));
        assert!(!header_truncated(&r));
    }
}
