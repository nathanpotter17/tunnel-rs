//! Active probes: questions the operator asks *through* the tunnel.
//!
//! Everything else in this binary is passive — `inspect.rs` reports on packets
//! that were going to cross the TUN anyway. A probe is the opposite: it
//! originates traffic on purpose, out of an ordinary socket, so the OS routes it
//! down the same default route every other application uses. Under full-tunnel
//! capture that means the query enters the TUN, is proxied by the engine, and
//! egresses through the configured exit — so a probe answers "what does this
//! host actually see, from where the tunnel actually is", not "what does the
//! host's resolver stub have cached".
//!
//! The first (and so far only) action is nslookup. [`Action`] and
//! [`RecordType`] are the two axes a new action plugs into: `Action` for a new
//! *kind* of question, `RecordType` for another shape of this one.
//!
//! ## Parsing rules
//!
//! A DNS response is attacker-influenced input — the answer comes from whatever
//! is at the far end of the tunnel, which is the thing under examination. So the
//! parser here is written to the same standard as `inspect.rs`'s packet parser:
//! every read is bounds-checked and returns an error rather than panicking,
//! compression pointers are jump-limited so a self-referential name cannot spin,
//! record text is escaped before it reaches the UI, and the counts that drive
//! loops are capped independently of what the header claims.

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

/// What a probe *does*. One variant today; the enum exists so the widget's
/// dispatch and the job runner are already shaped for the next one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Resolve a name (or reverse-resolve an address) against a nameserver.
    Nslookup,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Nslookup => "nslookup",
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
}

impl RecordType {
    pub const ALL: [RecordType; 9] = [
        RecordType::Auto,
        RecordType::A,
        RecordType::Aaaa,
        RecordType::Ptr,
        RecordType::Cname,
        RecordType::Txt,
        RecordType::Mx,
        RecordType::Ns,
        RecordType::Soa,
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
    /// is using.
    pub server: SocketAddr,
    pub timeout: Duration,
}

/// One record from a response, already rendered to text.
#[derive(Clone, Debug)]
pub struct Answer {
    pub name: String,
    pub kind: String,
    pub ttl: u32,
    pub data: String,
}

/// A completed probe.
#[derive(Clone, Debug)]
pub struct Outcome {
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
    slot: Arc<Mutex<Option<Result<Outcome, String>>>>,
    started: Instant,
    /// What this job asked, for the "running" line in the UI.
    pub summary: String,
}

impl Job {
    /// How long the probe has been running, for the pending indicator.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Take the result if the probe has finished. Returns `None` while it is
    /// still in flight, so the caller can keep drawing a pending state.
    pub fn take(&self) -> Option<Result<Outcome, String>> {
        match self.slot.lock() {
            Ok(mut s) => s.take(),
            // A panic in the worker cannot poison anything the caller needs —
            // the guard holds a plain Option — so recover rather than wedge the
            // widget on a permanently pending job.
            Err(e) => e.into_inner().take(),
        }
    }
}

/// Start `req` on a worker thread. Never blocks the caller; a thread that
/// cannot be spawned is reported through the same slot as any other failure, so
/// the UI has exactly one path to render.
pub fn spawn(req: Request) -> Job {
    let summary = format!("{} {} {}", req.action.label(), req.record.label(), req.target);
    let slot: Arc<Mutex<Option<Result<Outcome, String>>>> = Arc::new(Mutex::new(None));
    let sink = slot.clone();

    let spawned = std::thread::Builder::new()
        .name("probe".to_string())
        .spawn(move || {
            let out = run(&req);
            if let Ok(mut s) = sink.lock() {
                *s = Some(out);
            }
        });

    if let Err(e) = spawned {
        if let Ok(mut s) = slot.lock() {
            *s = Some(Err(format!("could not start probe thread: {e}")));
        }
    }

    Job { slot, started: Instant::now(), summary }
}

/// Execute a probe synchronously. Public so a caller outside the GUI (a test,
/// or a future headless mode) can use the same path the dashboard does.
pub fn run(req: &Request) -> Result<Outcome, String> {
    match req.action {
        Action::Nslookup => nslookup(req),
    }
}

// ---------------------------------------------------------------------------
// nslookup
// ---------------------------------------------------------------------------

fn nslookup(req: &Request) -> Result<Outcome, String> {
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

    Ok(Outcome {
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

/// The `in-addr.arpa` / `ip6.arpa` name for an address.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
                s.push('.');
                s.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                s.push('.');
            }
            s.push_str("ip6.arpa");
            s
        }
    }
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
        _ => malformed(rdata),
    };
    clamp_text(&text)
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
    if s.chars().count() <= MAX_RDATA_CHARS {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(MAX_RDATA_CHARS - 1).collect();
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
        };
        let err = nslookup(&req("1.1.1.1", RecordType::Mx)).unwrap_err();
        assert!(err.contains("only PTR"), "{err}");
        assert!(nslookup(&req("   ", RecordType::Auto))
            .unwrap_err()
            .contains("no target"));
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
