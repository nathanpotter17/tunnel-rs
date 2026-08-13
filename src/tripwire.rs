//! Event-driven snooper tripwire — detect, lock down, exit.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::error;

use crate::state::Shared;

/// Canaries spread across the address space so a wide redirect can't miss all of
/// them. TEST-NET blocks have no real hosts — pure routing probes; nothing is
/// ever sent (we only read the forwarding decision).
const CANARIES: &[&str] = &[
    "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
];

/// Confirm delay: on a suspected leak, re-verify after this to defeat a torn read
/// sampled mid route-table transaction. The always-on kill switch blocks any real
/// leak during it, so it only removes false positives.
const CONFIRM_MS: u64 = 25;

/// Per-session context handed to the watcher / callback.
pub struct Ctx {
    /// TUN id: interface name on Unix, ifindex string on Windows.
    tun: String,
    shared: Arc<Shared>,
}

/// Held for the session. Drop only matters on a clean exit — the trip path never
/// returns.
pub struct Tripwire {
    _w: platform::Watcher,
}

pub fn spawn(tun: String, shared: Arc<Shared>) -> Tripwire {
    Tripwire { _w: platform::spawn(Ctx { tun, shared }) }
}

/// The verdict. `Some(reason)` iff this is a real injection: a canary routes off
/// the TUN while the tunnel's own `/1` routes are still intact, confirmed twice.
/// `None` for "no leak" and — critically — for "leak, but our routes are gone"
/// (a benign transient / our own teardown).
fn detect_attack(ctx: &Ctx) -> Option<String> {
    let leak = platform::first_leaking_canary(CANARIES, &ctx.tun)?;
    if !platform::tunnel_routes_intact(&ctx.tun) {
        return None; // our /1 routes absent → benign transient, not an injection
    }
    std::thread::sleep(std::time::Duration::from_millis(CONFIRM_MS));
    if ctx.shared.shutdown.load(Ordering::Relaxed) {
        return None;
    }
    let leak2 = platform::first_leaking_canary(CANARIES, &ctx.tun)?;
    if !platform::tunnel_routes_intact(&ctx.tun) {
        return None;
    }
    let _ = leak;
    Some(format!(
        "public traffic to {leak2} is routed off the tunnel while the tunnel's own \
         /1 routes are still intact — a more-specific route was injected (TunnelVision)"
    ))
}

/// Lock the network down and terminate. Never returns.
fn nuke(ctx: &Ctx, reason: &str) -> ! {
    // Slam the reboot-clearable kernel block. It holds AFTER we exit (nothing has
    // to stay alive to enforce it) and clears on reboot. No adapter disable, no
    // child process, nothing to race.
    let locked = platform::lockdown();

    // What the operator is told depends on whether that worked, because
    // `exit(101)` below skips every Drop: on a failed lockdown the guards never
    // restore anything and no filter replaced them, so the machine is left
    // exposed with a confirmed snooper on it. Rebooting does not help there —
    // on Windows it comes back equally open, and on Linux it also clears the
    // kill-switch table that `exit` happened to leave behind. The only action
    // that is right under every failure is to take the machine off the wire.
    //
    // Branched rather than appended: printing "locked down" unconditionally put
    // a reassurance underneath the warning that contradicts it, and the
    // reassurance had the last word.
    //
    // Stated without naming a mechanism, so this reads the same whichever
    // platform's filter did or did not install.
    let (log_line, console_line) = if locked {
        (
            "Locking down. User must reboot and rotate keys — a snooper was found.",
            "[tunnel] Network locked down. Reboot and rotate keys — a snooper was found.\n",
        )
    } else {
        (
            "LOCKDOWN FAILED — traffic is NOT blocked. Disconnect this machine now.",
            "[tunnel] LOCKDOWN FAILED — traffic is NOT blocked.\n\
             [tunnel] Disconnect this machine from the network now, then reboot and rotate keys.\n",
        )
    };

    // Console only — the process is about to die; make the reason unmistakable on
    // both the tracing sink and raw stderr (in case the layer is mid-flush).
    error!("SNOOPER DETECTED: {reason}");
    error!("{log_line}");
    eprintln!("\n[tunnel] SNOOPER DETECTED: {reason}");
    eprintln!("{console_line}");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    // exit() skips Drop, so FullTunnel/KillSwitch never restore the poisoned
    // routing table. The lockdown is kernel state that outlives this process and
    // is cleared by a reboot — deliberate, so a compromised session cannot be
    // silently resumed.
    std::process::exit(101);
}

// ============================================================================
// Linux — NETLINK_ROUTE detection + nftables lockdown
// ============================================================================
#[cfg(target_os = "linux")]
mod platform {
    use super::Ctx;
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use tracing::warn;

    const RTMGRP_IPV4_ROUTE: u32 = 0x40;
    const RTMGRP_IPV6_ROUTE: u32 = 0x400;

    pub struct Watcher {
        stop: Arc<AtomicBool>,
        join: Option<JoinHandle<()>>,
    }

    pub fn spawn(ctx: Ctx) -> Watcher {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let join = std::thread::Builder::new()
            .name("tripwire".into())
            .spawn(move || watch_loop(ctx, stop2))
            .expect("spawn tripwire thread");
        Watcher { stop, join: Some(join) }
    }

    fn watch_loop(ctx: Ctx, stop: Arc<AtomicBool>) {
        let fd = match open_netlink() {
            Some(fd) => fd,
            None => super::nuke(&ctx, "route-change monitor unavailable (netlink open failed)"),
        };
        if let Some(reason) = super::detect_attack(&ctx) {
            super::nuke(&ctx, &reason);
        }
        let mut buf = [0u8; 8192];
        loop {
            if stop.load(Ordering::Relaxed) || ctx.shared.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                continue;
            }
            if !ctx.shared.shutdown.load(Ordering::Relaxed) {
                if let Some(reason) = super::detect_attack(&ctx) {
                    super::nuke(&ctx, &reason);
                }
            }
        }
        unsafe { libc::close(fd) };
    }

    fn open_netlink() -> Option<RawFd> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return None;
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        Some(fd)
    }

    /// The first canary whose egress interface is not the TUN (and not loopback).
    pub fn first_leaking_canary(canaries: &[&str], tun: &str) -> Option<String> {
        for c in canaries {
            match egress_dev(c) {
                Some(dev) if dev != tun && dev != "lo" => return Some((*c).to_string()),
                _ => {}
            }
        }
        None
    }

    fn egress_dev(dst: &str) -> Option<String> {
        let out = std::process::Command::new("ip").args(["route", "get", dst]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        after_key(&String::from_utf8_lossy(&out.stdout), "dev")
    }

    /// True iff BOTH half-default routes still resolve to the TUN — i.e. our own
    /// capture is intact. If they're gone, an off-TUN canary is a benign transient
    /// (TUN flap / teardown), not an injection.
    pub fn tunnel_routes_intact(tun: &str) -> bool {
        route_dev("0.0.0.0/1").as_deref() == Some(tun)
            && route_dev("128.0.0.0/1").as_deref() == Some(tun)
    }

    fn route_dev(prefix: &str) -> Option<String> {
        let out = std::process::Command::new("ip").args(["route", "show", prefix]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        after_key(&String::from_utf8_lossy(&out.stdout), "dev")
    }

    fn after_key(text: &str, key: &str) -> Option<String> {
        let toks: Vec<&str> = text.split_whitespace().collect();
        toks.iter()
            .position(|t| *t == key)
            .and_then(|i| toks.get(i + 1))
            .map(|s| s.to_string())
    }

    /// The lockdown: a kernel-state nft table that survives our process exit and
    /// is cleared on reboot (nft runtime rules are not persisted). Loopback is
    /// spared so the desktop isn't wedged; priority -300 puts it ahead of
    /// everything.
    /// Returns whether the block is actually in place; `nuke` tells the operator
    /// which of two very different situations they are in.
    pub fn lockdown() -> bool {
        const SCRIPT: &str = "add table inet tunnel_panic\n\
             flush table inet tunnel_panic\n\
             add chain inet tunnel_panic input { type filter hook input priority -300 ; policy drop ; }\n\
             add chain inet tunnel_panic output { type filter hook output priority -300 ; policy drop ; }\n\
             add chain inet tunnel_panic forward { type filter hook forward priority -300 ; policy drop ; }\n\
             add rule inet tunnel_panic input iifname \"lo\" accept\n\
             add rule inet tunnel_panic output oifname \"lo\" accept\n";
        // Through preflight, which knows where `nft` is. With the bare name this
        // silently did nothing on a host whose PATH omits /usr/sbin — on the one
        // path where doing nothing means a confirmed snooper keeps the network.
        match crate::preflight::nft_apply(SCRIPT) {
            Ok(()) => true,
            Err(e) => {
                warn!("lockdown nft block failed: {e}");
                false
            }
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }
}

// ============================================================================
// Windows — NotifyRouteChange2 detection + WFP lockdown
// ============================================================================
//
// Detection uses windows-sys IpHelper. The lockdown uses the `windows` crate WFP
// API (same as killswitch.rs) to install a NON-dynamic block that survives our
// process exit and is cleared on reboot.
#[cfg(windows)]
mod platform {
    use super::Ctx;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use tracing::warn;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, GetBestInterfaceEx, NotifyRouteChange2, MIB_IPFORWARD_ROW2,
        MIB_NOTIFICATION_TYPE,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR, SOCKADDR_IN};

    pub struct Watcher {
        handle: HANDLE,
        ctx_ptr: *mut Ctx,
    }
    unsafe impl Send for Watcher {}

    pub fn spawn(ctx: Ctx) -> Watcher {
        if let Some(reason) = super::detect_attack(&ctx) {
            super::nuke(&ctx, &reason);
        }
        let ctx_ptr = Box::into_raw(Box::new(ctx));
        let mut handle: HANDLE = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC as u16,
                Some(route_change_cb),
                ctx_ptr as *const c_void,
                0, // initialnotification = false
                &mut handle,
            )
        };
        if rc != 0 {
            let ctx = unsafe { Box::from_raw(ctx_ptr) };
            super::nuke(&ctx, "route-change monitor unavailable (NotifyRouteChange2 failed)");
        }
        Watcher { handle, ctx_ptr }
    }

    unsafe extern "system" fn route_change_cb(
        callercontext: *const c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        if callercontext.is_null() {
            return;
        }
        let ctx = &*(callercontext as *const Ctx);
        if ctx.shared.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Some(reason) = super::detect_attack(ctx) {
            super::nuke(ctx, &reason);
        }
    }

    pub fn first_leaking_canary(canaries: &[&str], tun_ifindex: &str) -> Option<String> {
        let tun: u32 = tun_ifindex.parse().ok()?;
        for c in canaries {
            match best_ifindex(c) {
                Some(idx) if idx != tun => return Some((*c).to_string()),
                _ => {}
            }
        }
        None
    }

    /// The OS's own best-interface decision for `dst` (no packet sent).
    fn best_ifindex(dst: &str) -> Option<u32> {
        let ip: Ipv4Addr = dst.parse().ok()?;
        let mut sa: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        sa.sin_family = AF_INET as u16;
        unsafe { sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets()) };
        let mut idx: u32 = 0;
        let rc = unsafe { GetBestInterfaceEx(&sa as *const SOCKADDR_IN as *const SOCKADDR, &mut idx) };
        if rc == 0 {
            Some(idx)
        } else {
            None
        }
    }

    /// True iff both /1 capture routes still point at the TUN. Reads the IPv4
    /// forwarding table in-process: Get-NetRoute meant two powershell spawns
    /// here, and this is on the tripwire's decision path — four spawns per
    /// confirmation, ~1s of latency ahead of a µs teardown.
    pub fn tunnel_routes_intact(tun_ifindex: &str) -> bool {
        let tun: u32 = match tun_ifindex.parse() {
            Ok(v) => v,
            Err(_) => return false,
        };

        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // AF_INET (2). Table is heap-allocated by the OS; freed below.
        let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
        if rc != 0 || table.is_null() {
            return false;
        }

        let (mut lo, mut hi) = (false, false);
        unsafe {
            let n = (*table).NumEntries as usize;
            let rows = (*table).Table.as_ptr();
            for i in 0..n {
                let row = &*rows.add(i);
                if row.InterfaceIndex != tun {
                    continue;
                }
                let p = &row.DestinationPrefix;
                if p.PrefixLength != 1 || p.Prefix.si_family != AF_INET {
                    continue;
                }
                // Network-order octets of the destination address.
                match p.Prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() {
                    [0, 0, 0, 0] => lo = true,     // 0.0.0.0/1 on the TUN
                    [128, 0, 0, 0] => hi = true,   // 128.0.0.0/1 on the TUN
                    _ => {}
                }
            }
            FreeMibTable(table as *const _);
        }
        lo && hi
    }

    /// The lockdown: a NON-dynamic WFP block that SURVIVES our process exit and is
    /// cleared on reboot (it is not flagged persistent). No child process. Blocks
    /// all new outbound connects and inbound accepts (v4 + v6), sparing loopback
    /// so the machine isn't wedged before the user can reboot.
    /// Returns whether the block is actually in place; `nuke` tells the operator
    /// which of two very different situations they are in. The advice does not
    /// live here: this process's kill switch is a DYNAMIC WFP session, so exiting
    /// tears it down for us, and the `/1` routes die with the wintun adapter —
    /// a failed lockdown leaves the host on its original default route with a
    /// confirmed snooper on it, which a reboot does nothing to change.
    pub fn lockdown() -> bool {
        match wfp_block() {
            Ok(()) => true,
            Err(e) => {
                warn!("in-kernel WFP lockdown failed: {e}");
                false
            }
        }
    }

    fn wfp_block() -> Result<(), String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;

        use windows::core::{GUID, PCWSTR, PWSTR};
        use windows::Win32::Foundation::HANDLE as WHANDLE;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0,
            FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_UINT32, FWP_UINT8,
        };

        const RPC_C_AUTHN_WINNT: u32 = 10;
        const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;
        // FWPM_CONDITION_FLAGS = {632ce23b-5167-435c-86d7-e903684aa80c}.
        let cond_flags: GUID = GUID::from_u128(0x632ce23b_5167_435c_86d7_e903684aa80c);
        // FWP_MATCH_FLAGS_ANY_SET == 7 in FWP_MATCH_TYPE.
        let match_flags_any_set =
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_TYPE(7);

        let sublayer_key: GUID = GUID::from_u128(0x50a1_7c0d_9b2e_4f61_a3d7_9c11_2233_4455);
        let layers = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ];

        fn wide(s: &str) -> Vec<u16> {
            OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
        }

        unsafe {
            // NON-dynamic session → the filters SURVIVE our process exit (nothing
            // needs to stay alive) and are cleared on reboot (not flagged
            // persistent). The engine handle is irrelevant to non-dynamic filter
            // lifetime; we simply leak it as we are about to exit.
            let session: FWPM_SESSION0 = std::mem::zeroed();
            let mut engine = WHANDLE(ptr::null_mut());
            let rc =
                FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine);
            if rc != 0 {
                return Err(format!("FwpmEngineOpen0 failed: {rc}"));
            }

            let mut sub_name = wide("tunnel panic");
            let mut sub: FWPM_SUBLAYER0 = std::mem::zeroed();
            sub.subLayerKey = sublayer_key;
            sub.displayData.name = PWSTR(sub_name.as_mut_ptr());
            sub.weight = 0xffff;
            let rc = FwpmSubLayerAdd0(engine, &sub, None);
            if rc != 0 {
                return Err(format!("FwpmSubLayerAdd0 failed: {rc}"));
            }

            for layer in layers {
                // Loopback permit (higher weight) so local IPC isn't wedged.
                let mut p_name = wide("tunnel panic permit loopback");
                let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                cond.fieldKey = cond_flags;
                cond.matchType = match_flags_any_set;
                cond.conditionValue.r#type = FWP_UINT32;
                cond.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

                let mut pf: FWPM_FILTER0 = std::mem::zeroed();
                pf.displayData.name = PWSTR(p_name.as_mut_ptr());
                pf.layerKey = layer;
                pf.subLayerKey = sublayer_key;
                pf.weight.r#type = FWP_UINT8;
                pf.weight.Anonymous.uint8 = 15;
                pf.action.r#type = FWP_ACTION_PERMIT;
                pf.numFilterConditions = 1;
                pf.filterCondition = &mut cond;
                let rc = FwpmFilterAdd0(engine, &pf, None, None);
                if rc != 0 {
                    return Err(format!("FwpmFilterAdd0(loopback permit) failed: {rc}"));
                }

                // Block everything else (no conditions → match all), lower weight.
                let mut b_name = wide("tunnel panic block all");
                let mut bf: FWPM_FILTER0 = std::mem::zeroed();
                bf.displayData.name = PWSTR(b_name.as_mut_ptr());
                bf.layerKey = layer;
                bf.subLayerKey = sublayer_key;
                bf.weight.r#type = FWP_UINT8;
                bf.weight.Anonymous.uint8 = 1;
                bf.action.r#type = FWP_ACTION_BLOCK;
                bf.numFilterConditions = 0;
                bf.filterCondition = ptr::null_mut();
                let rc = FwpmFilterAdd0(engine, &bf, None, None);
                if rc != 0 {
                    return Err(format!("FwpmFilterAdd0(block all) failed: {rc}"));
                }
            }
        }
        Ok(())
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            unsafe {
                CancelMibChangeNotify2(self.handle);
                if !self.ctx_ptr.is_null() {
                    drop(Box::from_raw(self.ctx_ptr));
                }
            }
        }
    }
}

// ============================================================================
// Unsupported platforms (e.g. macOS): never reached — killswitch::install
// already fails there and the engine bails before the tripwire is spawned.
// ============================================================================
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::Ctx;

    pub struct Watcher;

    pub fn spawn(_ctx: Ctx) -> Watcher {
        Watcher
    }
    pub fn first_leaking_canary(_c: &[&str], _tun: &str) -> Option<String> {
        None
    }
    pub fn tunnel_routes_intact(_tun: &str) -> bool {
        true
    }
    /// Nothing to install, so nothing is in place. Unreachable in practice —
    /// `killswitch::install` fails here and the engine bails before the tripwire
    /// is spawned — but `false` is the only honest answer if it ever were.
    pub fn lockdown() -> bool {
        false
    }
}
