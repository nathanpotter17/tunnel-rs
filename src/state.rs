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
}

#[derive(Clone, Default)]
pub struct Status {
    pub running: bool,
    /// e.g. "WireGuard → 1.2.3.4:51820" or "Direct (uplink)".
    pub exit: String,
    pub full_tunnel: bool,
    pub started_at: Option<Instant>,
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
        })
    }
}
