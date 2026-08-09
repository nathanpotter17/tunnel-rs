//! NAT-PMP client (RFC 6886) — leasing the inbound port from the exit gateway.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// NAT-PMP listens here on the gateway.
const NATPMP_PORT: u16 = 5351;

const OP_EXTERNAL: u8 = 0;
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;
/// A response carries the request's opcode with the high bit set.
const RESPONSE_BIT: u8 = 0x80;

const REQUEST_LEN: usize = 12;
const MAP_RESPONSE_LEN: usize = 16;
const ADDR_RESPONSE_LEN: usize = 12;

/// Lease length asked for. The gateway may grant less; the renewal interval is
/// derived from what it actually granted, never from what was requested.
const LIFETIME: Duration = Duration::from_secs(60);
/// Floor on the renewal interval, so a gateway answering with an absurdly short
/// lease cannot turn this into a busy loop against the tunnel.
const MIN_RENEW: Duration = Duration::from_secs(10);
/// Delay before retrying after a failure. Shorter than a renewal because a lost
/// mapping is an outage, not a steady state.
const RETRY: Duration = Duration::from_secs(10);
/// Shutdown is observed at this granularity while sleeping between renewals.
const SLEEP_SLICE: Duration = Duration::from_millis(500);
/// Held off before the first request. The lease thread starts with the exit
/// driver, which is a millisecond before the default route finishes plumbing and
/// several before WireGuard has handshaked — asking then reports a failure that
/// is really just a session still coming up.
const STARTUP_GRACE: Duration = Duration::from_secs(3);
/// Failures tolerated before this is treated as a fault rather than a session
/// still settling. Governs the log level and the dashboard's state together, so
/// the two cannot disagree about when something has gone wrong.
const QUIET_FAILURES: u32 = 2;

/// Per-attempt read timeouts. RFC 6886 §3.1 specifies 250 ms doubling over nine
/// retries; that is two minutes of silence before giving up, which would hide an
/// outage for far longer than the lease it is protecting. Three attempts bound
/// the exchange at under two seconds and the renewal loop retries anyway.
const ATTEMPTS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1000),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn opcode(self) -> u8 {
        match self {
            Proto::Udp => OP_MAP_UDP,
            Proto::Tcp => OP_MAP_TCP,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
}

/// One granted mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mapping {
    pub external: u16,
    /// What the gateway actually granted, which may be less than was asked.
    pub lifetime: Duration,
    /// Seconds since the gateway's own start. A decrease means it restarted and
    /// dropped every mapping it held — see [`gateway_restarted`].
    pub epoch: u32,
}

/// What the lease loop tells the exit driver.
#[derive(Clone, Debug)]
pub enum Event {
    /// A lease is live on this external port. Sent on every successful renewal,
    /// not only on change, so the driver's view cannot drift from the gateway's.
    Mapped { port: u16 },
    /// No lease yet, and not yet a problem. Sent before the first request and
    /// while early attempts fail, because the opening seconds of a session are
    /// spent racing the WireGuard handshake and losing that race is ordinary.
    Pending { reason: String },
    /// No lease after repeated attempts. The forwarded port must be closed
    /// until one is granted again.
    Lost { reason: String },
}

/// RFC 6886 §3.5 result codes, in the terms of the thing that actually went
/// wrong. Code 2 is the one worth reading closely: on Proton it means the
/// WireGuard config was generated without the NAT-PMP flag, which is a config
/// mistake with no symptom other than this.
fn result_text(code: u16) -> &'static str {
    match code {
        1 => "gateway does not support this NAT-PMP version",
        2 => "not authorised — the exit is refusing to forward for this peer \
              (on Proton: regenerate the WireGuard config with NAT-PMP enabled, \
              and check the server supports port forwarding)",
        3 => "gateway has no network connectivity",
        4 => "gateway is out of resources",
        5 => "gateway does not support this operation",
        _ => "unrecognised result code",
    }
}

/// Has the gateway restarted since the last response?
///
/// RFC 6886 §3.6: the epoch counts seconds since the gateway came up, so it only
/// ever increases. A value below the last one means it restarted and silently
/// dropped every mapping — the lease looks healthy and forwards nothing. Renewal
/// alone would not notice, because renewing a mapping that no longer exists just
/// creates a new one on a different port.
fn gateway_restarted(previous: Option<u32>, current: u32) -> bool {
    previous.is_some_and(|p| current < p)
}

fn build_request(opcode: u8, internal: u16, suggested: u16, lifetime: u32) -> [u8; REQUEST_LEN] {
    let mut req = [0u8; REQUEST_LEN];
    req[0] = 0; // version
    req[1] = opcode;
    // req[2..4] reserved, must be zero
    req[4..6].copy_from_slice(&internal.to_be_bytes());
    req[6..8].copy_from_slice(&suggested.to_be_bytes());
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());
    req
}

/// Check the fields every response shares before any of it is trusted.
fn check_header(buf: &[u8], want_opcode: u8, min_len: usize) -> Result<(), String> {
    if buf.len() < min_len {
        return Err(format!("short response: {} bytes, want {}", buf.len(), min_len));
    }
    if buf[0] != 0 {
        return Err(format!("unexpected protocol version {}", buf[0]));
    }
    if buf[1] != want_opcode | RESPONSE_BIT {
        return Err(format!(
            "response opcode {} does not answer request {}",
            buf[1], want_opcode
        ));
    }
    let code = u16::from_be_bytes([buf[2], buf[3]]);
    if code != 0 {
        return Err(format!("gateway refused: {} (code {})", result_text(code), code));
    }
    Ok(())
}

fn parse_mapping(buf: &[u8], proto: Proto) -> Result<Mapping, String> {
    check_header(buf, proto.opcode(), MAP_RESPONSE_LEN)?;
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    if external == 0 {
        return Err("gateway granted port 0".to_string());
    }
    Ok(Mapping {
        external,
        lifetime: Duration::from_secs(u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64),
        epoch: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
    })
}

fn parse_external_address(buf: &[u8]) -> Result<Ipv4Addr, String> {
    check_header(buf, OP_EXTERNAL, ADDR_RESPONSE_LEN)?;
    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// One request/response exchange, retried on silence.
///
/// The socket is rebuilt per attempt because `connect` on a UDP socket sends
/// nothing — it is a route lookup, and it FAILS RATHER THAN BLOCKS when the
/// route is not there. Early in a session it will not be: the exit driver has
/// only just started, the default route is still being plumbed, and WireGuard
/// has not handshaked. Doing it once outside the loop turned three seconds of
/// ordinary startup into a hard error.
fn exchange(gateway: Ipv4Addr, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut last = String::from("no reply");
    // Whether the request ever actually left. It separates the two failures
    // that look identical from the outside: a tunnel that is not up yet, and a
    // gateway that is up and declining to answer.
    let mut sent = false;

    for timeout in ATTEMPTS {
        let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(s) => s,
            Err(e) => {
                last = format!("bind: {e}");
                continue;
            }
        };
        // Bound to the gateway: the kernel then discards datagrams from any
        // other source, so a spoofed reply cannot be read at all rather than
        // being read and rejected.
        if let Err(e) = sock.connect((gateway, NATPMP_PORT)) {
            last = format!("no route to {gateway} ({e})");
            std::thread::sleep(timeout);
            continue;
        }
        if sock.set_read_timeout(Some(timeout)).is_err() {
            last = "cannot set socket timeout".to_string();
            continue;
        }
        if let Err(e) = sock.send(request) {
            last = format!("send to {gateway}: {e}");
            continue;
        }
        sent = true;

        let mut buf = [0u8; 64];
        match sock.recv(&mut buf) {
            Ok(n) => return Ok(buf[..n].to_vec()),
            Err(_) => last = format!("{gateway} did not answer within {timeout:?}"),
        }
    }

    Err(if sent {
        // The request left and nothing came back. On Proton this is what an
        // ineligible session looks like — they drop the request rather than
        // refusing it, so there is no result code to report.
        format!(
            "{last} — the exit is not answering NAT-PMP at all. Check the server \
             supports port forwarding (it must be a P2P server) and that the \
             WireGuard config was generated with NAT-PMP enabled"
        )
    } else {
        format!("{last} — the tunnel is not carrying traffic yet")
    })
}

/// Ask for (or renew) a mapping. `suggested` is a hint the gateway may ignore.
pub fn map(
    gateway: Ipv4Addr,
    proto: Proto,
    suggested: u16,
    lifetime: Duration,
) -> Result<Mapping, String> {
    // Internal port 0: see the Proton convention in the module docs.
    let req = build_request(proto.opcode(), 0, suggested, lifetime.as_secs() as u32);
    let resp = exchange(gateway, &req)?;
    parse_mapping(&resp, proto)
}

/// Release a mapping. RFC 6886 §3.4: lifetime 0 and suggested port 0 deletes it.
/// Best effort — the lease expires on its own within a minute regardless.
fn release(gateway: Ipv4Addr, proto: Proto) {
    let req = build_request(proto.opcode(), 0, 0, 0);
    if let Err(e) = exchange(gateway, &req) {
        debug!("portmap: release {} failed (harmless): {}", proto.label(), e);
    }
}

/// The exit address peers reach us on, as the gateway sees it.
///
/// Not needed to forward anything — it is what makes a forwarded port testable,
/// since the endpoint in the config is the address we dial OUT to and not
/// necessarily the one that answers.
pub fn external_address(gateway: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let req = build_request(OP_EXTERNAL, 0, 0, 0);
    let resp = exchange(gateway, &req)?;
    parse_external_address(&resp)
}

/// Obtain or renew the lease for both protocols.
///
/// TCP is asked for second, suggesting the port UDP was granted, because a
/// BitTorrent client listens on ONE number for both.
fn renew(
    gateway: Ipv4Addr,
    current: &mut Option<u16>,
    epoch: &mut Option<u32>,
) -> Result<Mapping, String> {
    // Suggest the port already held so a renewal keeps it. Falls back to 1,
    // which is the hint Proton's own documented invocation sends.
    let suggested = current.unwrap_or(1);
    let udp = map(gateway, Proto::Udp, suggested, LIFETIME)?;

    if gateway_restarted(*epoch, udp.epoch) {
        // Every mapping the gateway held is gone, including the one this reply
        // appears to confirm. Drop what we think we know and let the next pass
        // negotiate from scratch rather than reporting a port nothing forwards.
        *epoch = Some(udp.epoch);
        *current = None;
        return Err("gateway restarted — every mapping was dropped".to_string());
    }
    *epoch = Some(udp.epoch);

    let tcp = map(gateway, Proto::Tcp, udp.external, LIFETIME)?;
    if tcp.external != udp.external {
        // One number is what a torrent client can listen on, so the UDP port
        // wins: uTP and DHT are the bulk of the traffic. Said out loud because
        // the consequence — inbound TCP quietly not arriving — is otherwise
        // indistinguishable from a quiet swarm.
        warn!(
            "portmap: gateway granted different ports for udp ({}) and tcp ({}) — \
             using {} for both; inbound TCP will not arrive",
            udp.external, tcp.external, udp.external
        );
    }

    *current = Some(udp.external);
    Ok(udp)
}

/// How long to wait before renewing a lease the gateway granted.
///
/// Half of what it actually granted, floored: renewing at the full lifetime
/// races the expiry, and trusting the lifetime we ASKED for would race it too
/// whenever the gateway grants less than it was asked.
fn renew_after(granted: Duration) -> Duration {
    (granted / 2).max(MIN_RENEW)
}

fn sleep_interruptibly(total: Duration, shutdown: &AtomicBool) {
    let mut left = total;
    while left > Duration::ZERO && !shutdown.load(Ordering::Relaxed) {
        let slice = left.min(SLEEP_SLICE);
        std::thread::sleep(slice);
        left -= slice;
    }
}

fn lease_loop(gateway: Ipv4Addr, tx: mpsc::Sender<Event>, shutdown: Arc<AtomicBool>) {
    let mut current: Option<u16> = None;
    let mut epoch: Option<u32> = None;
    let mut announced: Option<u16> = None;

    let mut failures: u32 = 0;

    info!("portmap: leasing an inbound port from {} (NAT-PMP)", gateway);
    // Say so before the grace period rather than after it: otherwise the widget
    // shows nothing for three seconds and then a state, which reads as the
    // feature having been off until it wasn't.
    if tx
        .blocking_send(Event::Pending {
            reason: format!("negotiating an inbound port with {gateway}"),
        })
        .is_err()
    {
        return;
    }
    sleep_interruptibly(STARTUP_GRACE, &shutdown);

    while !shutdown.load(Ordering::Relaxed) {
        let wait = match renew(gateway, &mut current, &mut epoch) {
            Ok(m) => {
                failures = 0;
                if announced != Some(m.external) {
                    // Report the address a peer actually dials. It is NOT the
                    // endpoint in the config — that is what we dial out to — and
                    // without it the only way to test a forwarded port is to go
                    // ask some outside service what our address is. Best effort:
                    // the opcode is optional and the lease works without it.
                    match external_address(gateway) {
                        Ok(ip) => info!(
                            "portmap: inbound port leased for {}s — peers reach this host at {}:{}",
                            m.lifetime.as_secs(),
                            ip,
                            m.external
                        ),
                        Err(e) => {
                            debug!("portmap: gateway would not report its address: {}", e);
                            info!(
                                "portmap: inbound port {} leased for {}s",
                                m.external,
                                m.lifetime.as_secs()
                            );
                        }
                    }
                    announced = Some(m.external);
                }
                // Sent every pass, not only on change: the driver's forwarded
                // port must track the gateway's, and a renewal is the only
                // evidence the mapping still exists.
                if tx.blocking_send(Event::Mapped { port: m.external }).is_err() {
                    break;
                }
                renew_after(m.lifetime)
            }
            Err(reason) => {
                failures += 1;
                announced = None;
                // One threshold decides both how loudly this is logged and what
                // the dashboard calls it, so the log and the widget cannot
                // disagree about whether anything is actually wrong.
                let settling = failures <= QUIET_FAILURES;
                if settling {
                    debug!("portmap: {} (attempt {})", reason, failures);
                } else {
                    warn!("portmap: {}", reason);
                }
                let event = if settling {
                    Event::Pending { reason }
                } else {
                    Event::Lost { reason }
                };
                if tx.blocking_send(event).is_err() {
                    break;
                }
                RETRY
            }
        };
        sleep_interruptibly(wait, &shutdown);
    }

    if current.is_some() {
        release(gateway, Proto::Udp);
        release(gateway, Proto::Tcp);
        debug!("portmap: lease released");
    }
}

/// Start the lease loop. Runs until `shutdown` is set or the receiver is closed.
///
/// A thread rather than a task: the exchange blocks for up to two seconds on a
/// silent gateway, and the exit driver it reports to is the data path.
pub fn spawn(
    gateway: Ipv4Addr,
    tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    match std::thread::Builder::new()
        .name("portmap".to_string())
        .spawn(move || lease_loop(gateway, tx, shutdown))
    {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("portmap: cannot start lease thread: {} — no inbound port", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed mapping response: `external` on port 51413, 60s, epoch 900.
    fn map_response(opcode: u8, result: u16, external: u16, lifetime: u32, epoch: u32) -> Vec<u8> {
        let mut b = vec![0u8; MAP_RESPONSE_LEN];
        b[0] = 0;
        b[1] = opcode | RESPONSE_BIT;
        b[2..4].copy_from_slice(&result.to_be_bytes());
        b[4..8].copy_from_slice(&epoch.to_be_bytes());
        b[8..10].copy_from_slice(&0u16.to_be_bytes());
        b[10..12].copy_from_slice(&external.to_be_bytes());
        b[12..16].copy_from_slice(&lifetime.to_be_bytes());
        b
    }

    #[test]
    fn a_request_is_encoded_exactly_as_the_rfc_specifies() {
        // Byte-for-byte, because a gateway will not tell us we got it wrong —
        // it will simply not answer, which looks identical to being offline.
        let req = build_request(OP_MAP_UDP, 0, 1, 60);
        assert_eq!(
            req,
            [
                0, // version
                1, // opcode: map UDP
                0, 0, // reserved
                0, 0, // internal port (0: the gateway picks — see module docs)
                0, 1, // suggested external port
                0, 0, 0, 60, // lifetime seconds
            ]
        );
        assert_eq!(build_request(OP_MAP_TCP, 0, 0, 0)[1], 2);
        assert_eq!(build_request(OP_EXTERNAL, 0, 0, 0)[1], 0);
    }

    #[test]
    fn a_granted_mapping_is_read_back_whole() {
        let m = parse_mapping(&map_response(OP_MAP_UDP, 0, 51413, 60, 900), Proto::Udp).unwrap();
        assert_eq!(m.external, 51413);
        assert_eq!(m.lifetime, Duration::from_secs(60));
        assert_eq!(m.epoch, 900);
    }

    #[test]
    fn a_response_is_never_trusted_before_it_is_checked() {
        // Every one of these is a datagram an attacker on the tunnel could send,
        // and every one must be a clean error rather than a panic or a mapping.
        let ok = map_response(OP_MAP_UDP, 0, 51413, 60, 900);

        for n in 0..MAP_RESPONSE_LEN {
            assert!(
                parse_mapping(&ok[..n], Proto::Udp).is_err(),
                "accepted a {n}-byte response"
            );
        }

        let mut wrong_version = ok.clone();
        wrong_version[0] = 1;
        assert!(parse_mapping(&wrong_version, Proto::Udp).is_err());

        // A TCP reply must not satisfy a UDP request: the two are separate
        // mappings and confusing them would report a port nothing forwards.
        assert!(parse_mapping(&map_response(OP_MAP_TCP, 0, 51413, 60, 900), Proto::Udp).is_err());
        // Nor may a request echo be mistaken for a response.
        let mut no_response_bit = ok.clone();
        no_response_bit[1] = OP_MAP_UDP;
        assert!(parse_mapping(&no_response_bit, Proto::Udp).is_err());

        // Port 0 is not a port.
        assert!(parse_mapping(&map_response(OP_MAP_UDP, 0, 0, 60, 900), Proto::Udp).is_err());

        // Trailing bytes are ignored, per RFC 6886.
        let mut padded = ok.clone();
        padded.extend_from_slice(&[0xAA; 8]);
        assert_eq!(parse_mapping(&padded, Proto::Udp).unwrap().external, 51413);
    }

    #[test]
    fn a_refusal_is_reported_in_the_terms_of_what_went_wrong() {
        for code in 1..=5u16 {
            let e = parse_mapping(&map_response(OP_MAP_UDP, code, 51413, 60, 900), Proto::Udp)
                .unwrap_err();
            assert!(e.contains(&format!("code {code}")), "{e}");
            assert!(!e.contains("unrecognised"), "code {code} has no message: {e}");
        }
        // The one a user will actually hit, and the only one they can fix.
        let refused =
            parse_mapping(&map_response(OP_MAP_UDP, 2, 51413, 60, 900), Proto::Udp).unwrap_err();
        assert!(refused.contains("NAT-PMP enabled"), "{refused}");
    }

    #[test]
    fn a_restarted_gateway_is_noticed_from_the_epoch_alone() {
        // The failure this catches is silent: renewing a mapping the gateway has
        // forgotten succeeds and returns a DIFFERENT port, so the lease looks
        // healthy while the port we publish forwards nothing.
        assert!(!gateway_restarted(None, 0), "first response cannot be a restart");
        assert!(!gateway_restarted(Some(900), 900), "a stalled clock is not a restart");
        assert!(!gateway_restarted(Some(900), 961));
        assert!(gateway_restarted(Some(900), 12));
    }

    #[test]
    fn renewal_is_paced_by_what_was_granted_not_what_was_asked() {
        // Renewing at the full lifetime races the expiry, and a gateway is free
        // to grant less than it was asked for.
        assert_eq!(renew_after(Duration::from_secs(60)), Duration::from_secs(30));
        assert_eq!(renew_after(Duration::from_secs(120)), Duration::from_secs(60));
        // A short or zero grant must not become a busy loop against the tunnel.
        assert_eq!(renew_after(Duration::from_secs(4)), MIN_RENEW);
        assert_eq!(renew_after(Duration::ZERO), MIN_RENEW);
    }

    #[test]
    fn the_external_address_is_read_from_the_right_four_bytes() {
        let mut b = vec![0u8; ADDR_RESPONSE_LEN];
        b[1] = OP_EXTERNAL | RESPONSE_BIT;
        b[4..8].copy_from_slice(&900u32.to_be_bytes());
        b[8..12].copy_from_slice(&[79, 127, 254, 119]);
        assert_eq!(parse_external_address(&b).unwrap(), Ipv4Addr::new(79, 127, 254, 119));

        for n in 0..ADDR_RESPONSE_LEN {
            assert!(parse_external_address(&b[..n]).is_err(), "accepted {n} bytes");
        }
    }

    #[test]
    fn sleeping_gives_up_promptly_when_shutdown_is_set() {
        let flag = Arc::new(AtomicBool::new(true));
        let start = std::time::Instant::now();
        sleep_interruptibly(Duration::from_secs(3600), &flag);
        assert!(start.elapsed() < Duration::from_secs(1), "ignored shutdown");
    }
}
