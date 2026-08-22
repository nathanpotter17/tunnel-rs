//! State shared between the async engine and the GUI.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::inspect::TrafficMonitor;

/// Byte counters at the *exit boundary* — the real egress sockets (Direct) or
/// the encrypted endpoint socket (WireGuard). The TUN-side monitor cannot see
/// this hop; comparing the two localises loss:
///   exit read high, TUN down low  -> bytes die inside our stack;
///   exit read ~0 mid-transfer     -> the far side paused because our receive
///                                    window closed, i.e. the TUN->app hop is
///                                    the suspect.
#[derive(Default)]
pub struct ExitStats {
    /// Bytes read from the internet (server -> us).
    pub read: AtomicU64,
    /// Bytes written to the internet (us -> server).
    pub written: AtomicU64,
}

/// Where the inbound forwarded port stands.
///
/// An enum rather than a port and an error side by side, because those two
/// admit combinations that cannot happen — open *and* failed — and because the
/// state that matters most has no value at all: a lease is negotiated over
/// several seconds, and for that stretch there is neither a port nor a fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forward {
    /// Being negotiated. Not a failure: the first attempt of a session races
    /// the WireGuard handshake and the route table, and losing that race is
    /// ordinary. The string says what is being waited on.
    Requesting(String),
    /// Leased, or fixed in the config, and open on this port.
    Open(u16),
    /// Given up on after repeated attempts. The string is the reason, usually
    /// the gateway's own.
    Failed(String),
}

/// Where this session's artifacts are written.
///
/// One directory and one timestamp, resolved once at startup, so the flow CSV
/// and the log transcript are named as a pair and land together. The executable's
/// directory is used rather than the process CWD: a double-clicked GUI app
/// inherits an unpredictable and often unwritable working directory.
pub struct SessionPaths {
    pub dir: PathBuf,
    pub stamp: String,
}

impl SessionPaths {
    pub fn new() -> Self {
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        SessionPaths {
            dir,
            stamp: chrono::Local::now().format("%Y%m%d-%H%M%S").to_string(),
        }
    }

    /// Full flow table for the session, written at shutdown.
    pub fn flows_csv(&self) -> PathBuf {
        self.dir.join(format!("flows-{}.csv", self.stamp))
    }

    /// Log transcript, written only when `--log` is given.
    pub fn log_txt(&self) -> PathBuf {
        self.dir.join(format!("tunnel-{}.txt", self.stamp))
    }
}

impl Default for SessionPaths {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle shared by the engine (writer) and the dashboard (reader).
pub struct Shared {
    pub monitor: Arc<TrafficMonitor>,
    pub status: Mutex<Status>,
    /// Artifact paths for this session (flow CSV, optional log transcript).
    pub session: SessionPaths,
    /// Set by the GUI on window close to ask the engine to shut down cleanly
    /// (so its route guard restores networking before the process exits).
    pub shutdown: AtomicBool,
    /// Whether the background ASN enricher (enrich.rs) may run. It sends every
    /// remote address, reversed, to the resolver — on by default, and one
    /// click to stop from the FLOWS toolbar.
    pub enrich: AtomicBool,
}

#[derive(Clone, Default)]
pub struct Status {
    pub running: bool,
    /// e.g. "WireGuard → 1.2.3.4:51820" or "Direct (uplink)".
    pub exit: String,
    pub full_tunnel: bool,
    /// The resolver the engine pinned onto the TUN, once it has. Published so
    /// an active probe (`probe.rs`) asks the same nameserver the rest of the
    /// host is using — a lookup aimed somewhere else would answer a question
    /// nobody asked.
    pub dns: Option<std::net::Ipv4Addr>,
    pub started_at: Option<Instant>,
    /// Where the inbound forwarded port stands, or `None` when none was asked
    /// for. Written by the exit driver as the gateway grants and regrants it, so
    /// it is what is actually open rather than what was configured.
    pub forward: Option<Forward>,
    /// Packets accepted through that port. Shown beside it because the port is
    /// assigned out of band and goes stale silently: on a working tunnel a count
    /// stuck at zero means the forward is not live, and nothing else tells the
    /// difference between that and a swarm nobody happens to be dialling.
    pub forwarded_in: u64,
    /// Why the engine stopped, when it stopped on an error. Written by `main`'s
    /// engine wrapper (the one place every exit passes through) and rendered by
    /// the dashboard header — a dead engine must never keep wearing CONNECTED.
    pub last_error: Option<String>,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            monitor: Arc::new(TrafficMonitor::new()),
            status: Mutex::new(Status::default()),
            session: SessionPaths::new(),
            shutdown: AtomicBool::new(false),
            enrich: AtomicBool::new(true),
        })
    }
}
