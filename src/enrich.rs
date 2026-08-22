//! Background origin-ASN enrichment for the host arena.
//!
//! One thread, one lookup at a time, at most two a second: the most recently
//! seen host without an ASN is asked about via Team Cymru's DNS service, and
//! the answer is stored for its whole prefix. Every query rides the tunnel
//! like any other socket, so each is declared to the traffic monitor before
//! it sends and shows up in the flow table marked `intel`, never as host DNS.
//!
//! Runs only while the engine is up (under capture the only resolver that
//! works is the tunnel's) and while `Shared::enrich` allows it.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::probe::{self, FALLBACK_DNS};
use crate::state::Shared;

/// Gap between lookups, and the shutdown poll interval.
const INTERVAL: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(3);

pub fn spawn(shared: Arc<Shared>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("enrich".to_string())
        .spawn(move || run(&shared))
        .expect("spawn enrich thread")
}

fn run(shared: &Shared) {
    loop {
        std::thread::sleep(INTERVAL);
        if shared.shutdown.load(Ordering::Relaxed) {
            return;
        }
        if !shared.enrich.load(Ordering::Relaxed) {
            continue;
        }
        let (running, dns) = match shared.status.lock() {
            Ok(st) => (st.running, st.dns),
            Err(_) => continue,
        };
        if !running {
            continue;
        }
        let server = SocketAddr::from((dns.unwrap_or(FALLBACK_DNS), 53));
        let Some(ip) = shared.monitor.enrich_candidate() else {
            continue;
        };
        let monitor = &shared.monitor;
        let mark = move |port: u16| monitor.mark_own(server, port, false);
        let info = probe::asn_origin(server, ip, TIMEOUT, &mark);
        shared.monitor.enrich(ip, info);
    }
}
