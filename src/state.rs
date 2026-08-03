//! State shared between the async engine and the GUI.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::inspect::TrafficMonitor;

const MAX_LOGS: usize = 500;

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

/// Handle shared by the engine (writer) and the dashboard (reader).
pub struct Shared {
    pub monitor: Arc<TrafficMonitor>,
    pub status: Mutex<Status>,
    /// Recent log lines for the GUI log pane (bounded ring).
    pub logs: Mutex<VecDeque<LogLine>>,
    /// Bumped on every appended line. The dashboard renders at frame rate but
    /// the log changes at event rate, so this lets it skip cloning 500 strings
    /// per frame for a ring that has not moved.
    pub log_seq: AtomicU64,
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
}

#[derive(Clone)]
pub struct LogLine {
    pub level: &'static str,
    pub msg: String,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            monitor: Arc::new(TrafficMonitor::new()),
            status: Mutex::new(Status::default()),
            logs: Mutex::new(VecDeque::new()),
            log_seq: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        })
    }

    pub fn push_log(&self, level: &'static str, msg: String) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push_back(LogLine { level, msg });
            while logs.len() > MAX_LOGS {
                logs.pop_front();
            }
        }
        self.log_seq.fetch_add(1, Ordering::Relaxed);
    }
}
