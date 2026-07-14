//! State shared between the async engine and the GUI.

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::inspect::TrafficMonitor;

const MAX_LOGS: usize = 500;

/// Handle shared by the engine (writer) and the dashboard (reader).
pub struct Shared {
    pub monitor: Arc<TrafficMonitor>,
    pub status: Mutex<Status>,
    /// Recent log lines for the GUI log pane (bounded ring).
    pub logs: Mutex<VecDeque<LogLine>>,
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
    }
}
