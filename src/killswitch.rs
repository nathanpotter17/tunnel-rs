//! TunnelVision (CVE-2024-3661) mitigation: a packet-filter kill switch on the
//! uplink.
//!
//! Full-tunnel capture (route.rs) redirects the default route into the TUN with
//! two `/1` routes. That is a *routing-table* control, and a rogue DHCP server
//! can beat it with an option-121 classless static route that is more specific
//! than a `/1`: the affected flow then egresses the physical uplink directly,
//! never entering the TUN, so nothing downstream (smoltcp, WireGuard, the egress
//! pin) ever sees it. A routing control cannot defend a routing attack.
//!
//! So we enforce the invariant one layer down, where option-121 cannot reach:
//! a packet filter on the uplink that permits ONLY our own egress traffic (plus
//! DHCP, so the lease survives) and drops everything else.
//!   - Linux: nftables. Our sockets carry SO_MARK (pin::EGRESS_FWMARK); the
//!     chain accepts `meta mark <mark>` and drops other `oifname == uplink`.
//!   - Windows: WFP. An ALE app-id permit for this exe, weighted above an
//!     interface-scoped block. (Windows has no socket marks, and the classic
//!     firewall can't permit-over-block without IPsec — WFP is the only correct
//!     tool.)
//!
//! [`KillSwitch`] is an RAII guard: dropping it (Ctrl-C, error, exit) removes
//! the filter. Install is fail-closed — the caller refuses to run if it can't
//! arm, rather than run with an unprotected uplink.

use anyhow::{anyhow, Result};

use crate::pin::EgressPin;

/// An armed kill switch. Drops restore unrestricted uplink egress.
pub struct KillSwitch {
    _inner: platform::Guard,
}

impl KillSwitch {
    /// Arm the kill switch, scoped to `uplink`. Errors if the uplink can't be
    /// identified or the filter can't be installed.
    pub fn install(uplink: &EgressPin) -> Result<Self> {
        Ok(Self { _inner: platform::install(uplink)? })
    }
}

// ============================================================================
// Linux — nftables
// ============================================================================
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use tracing::warn;

    const TABLE: &str = "tunnel_killswitch";

    pub struct Guard {
        installed: bool,
    }

    pub fn install(uplink: &EgressPin) -> Result<Guard> {
        if uplink.device.is_empty() {
            return Err(anyhow!(
                "no uplink interface identified — cannot scope the kill switch \
                 (uplink discovery must succeed first)"
            ));
        }
        // The device name is interpolated into an nft script; allow only the
        // characters a real interface name can contain.
        if !uplink
            .device
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        {
            return Err(anyhow!("refusing unusual uplink interface name: {:?}", uplink.device));
        }

        // One atomic `nft -f` script: (re)create the table, then rules.
        //  - traffic NOT leaving the uplink (TUN, lo, ...) is never policed
        //  - our own marked egress may leave the uplink
        //  - DHCP client renewals may leave the uplink so the lease holds
        //  - anything else out the uplink is a leak → drop
        // The chain also covers IPv6 out the uplink: the engine is IPv4-only, so
        // IPv6 is never tunneled; dropping it here prevents an IPv6 side-leak.
        let ruleset = format!(
            "add table inet {table}\n\
             flush table inet {table}\n\
             add chain inet {table} output {{ type filter hook output priority 0 ; policy accept ; }}\n\
             add rule inet {table} output oifname != \"{dev}\" accept\n\
             add rule inet {table} output meta mark {mark:#010x} accept\n\
             add rule inet {table} output udp sport 68 udp dport 67 accept\n\
             add rule inet {table} output drop\n",
            table = TABLE,
            dev = uplink.device,
            mark = crate::pin::EGRESS_FWMARK,
        );
        nft_apply(&ruleset)?;
        Ok(Guard { installed: true })
    }

    fn nft_apply(script: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("failed to spawn nft (is the nftables package installed?): {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("nft stdin unavailable"))?
            .write_all(script.as_bytes())
            .map_err(|e| anyhow!("writing nft ruleset: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| anyhow!("waiting on nft: {e}"))?;
        if !out.status.success() {
            return Err(anyhow!("nft failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(())
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.installed {
                return;
            }
            if let Err(e) = nft_apply(&format!("delete table inet {}\n", TABLE)) {
                warn!(
                    "kill switch teardown failed: {e}; remove it manually with: \
                     sudo nft delete table inet {}",
                    TABLE
                );
            }
        }
    }
}

// ============================================================================
// Windows — WFP (Windows Filtering Platform) via the `windows` crate
// ============================================================================
//
// windows-sys 0.59 ships only a subset of Win32 and OMITS the WFP management
// structs (FWPM_SESSION0/FILTER0/FILTER_CONDITION0/SUBLAYER0) and therefore the
// functions that take them (FwpmEngineOpen0/FilterAdd0/SubLayerAdd0). The full
// projection lives in the `windows` crate, used here for the WFP calls only.
// windows-sys is retained for ConvertInterfaceIndexToLuid (a plain-u32 binding).
//
// Two residual touch-up points if a future `windows` shifts shapes:
//   1. Return types: these WFP fns are treated as returning u32 (compared `!= 0`).
//      If your `windows` returns WIN32_ERROR, change `!= 0` to `.0 != 0`.
//   2. FwpmEngineOpen0's optional pointer params are passed as None / Some(&_).
#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use tracing::warn;

    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
        FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT64, FWP_UINT8,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    const RPC_C_AUTHN_WINNT: u32 = 10;
    // Objects added in a dynamic session are removed when the engine handle
    // closes — including on process crash. A kill switch must never outlive the
    // process that manages it (that would brick the NIC), so dynamic is right.
    const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;

    // Stable sublayer identity for this run (any fresh GUID).
    const SUBLAYER_KEY: GUID = GUID::from_u128(0x7c9a_11ef_4d3b_4c21_9a1e_5b0e_1122_3344);

    pub struct Guard {
        engine: HANDLE,
        app_id: *mut FWP_BYTE_BLOB,
    }
    // The WFP handle and blob pointer are process-wide and only touched on this
    // guard; the guard is held across .await in engine::run, which tokio::spawn
    // requires to be Send. Sound: no aliasing, freed once on Drop.
    unsafe impl Send for Guard {}

    pub fn install(uplink: &EgressPin) -> Result<Guard> {
        if uplink.ifindex == 0 {
            return Err(anyhow!("no uplink interface index — cannot scope the kill switch"));
        }

        // Uplink LUID (block filter is scoped to this interface only, so flows
        // out the TUN — a different interface — are never blocked). windows-sys
        // IpHelper returns a plain u32 here.
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        let rc = unsafe { ConvertInterfaceIndexToLuid(uplink.ifindex, &mut luid) };
        if rc != 0 {
            return Err(anyhow!("ConvertInterfaceIndexToLuid({}) failed: {rc}", uplink.ifindex));
        }
        let luid_val: u64 = unsafe { luid.Value };

        // App-id blob for THIS exe — the permit condition. `windows`'
        // FwpmGetAppIdFromFileName0 performs the DOS→NT path conversion WFP needs.
        let exe = std::env::current_exe().map_err(|e| anyhow!("current_exe: {e}"))?;
        let wide: Vec<u16> = OsStr::new(&exe).encode_wide().chain(std::iter::once(0)).collect();
        let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let rc = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut app_id) };
        if rc != 0 {
            return Err(anyhow!("FwpmGetAppIdFromFileName0 failed: {rc}"));
        }

        // Dynamic session → filters auto-cleaned on handle close / crash.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine = HANDLE(ptr::null_mut());
        let rc = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine)
        };
        if rc != 0 {
            unsafe { FwpmFreeMemory0(&mut (app_id as *mut c_void)) };
            return Err(anyhow!("FwpmEngineOpen0 failed: {rc}"));
        }

        // Any failure past here closes the engine (freeing partial filters via
        // the dynamic session) before returning.
        let built = (|| -> Result<()> {
            let mut name = wide_str("tunnel kill switch");
            let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub.subLayerKey = SUBLAYER_KEY;
            sub.displayData.name = PWSTR(name.as_mut_ptr());
            sub.weight = 0x8000;
            let rc = unsafe { FwpmSubLayerAdd0(engine, &sub, None) };
            if rc != 0 {
                return Err(anyhow!("FwpmSubLayerAdd0 failed: {rc}"));
            }

            // Permit our own process out any interface, v4 + v6.
            add_app_permit(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, app_id)?;
            add_app_permit(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, app_id)?;
            // Permit DHCP client renewals so the uplink lease holds (v4).
            add_dhcp_permit(engine)?;
            // Block everything else leaving the uplink, v4 + v6.
            add_iface_block(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, luid_val)?;
            add_iface_block(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, luid_val)?;
            Ok(())
        })();

        if let Err(e) = built {
            unsafe {
                FwpmEngineClose0(engine);
                FwpmFreeMemory0(&mut (app_id as *mut c_void));
            }
            return Err(e);
        }

        Ok(Guard { engine, app_id })
    }

    fn wide_str(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn add_app_permit(engine: HANDLE, layer: GUID, app_id: *mut FWP_BYTE_BLOB) -> Result<()> {
        let mut name = wide_str("tunnel permit self");
        let mut cond: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.Anonymous.byteBlob = app_id;

        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData.name = PWSTR(name.as_mut_ptr());
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 15; // high: permit beats block
        filter.action.r#type = FWP_ACTION_PERMIT;
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut cond;

        let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
        if rc != 0 {
            return Err(anyhow!("FwpmFilterAdd0(app permit) failed: {rc}"));
        }
        Ok(())
    }

    fn add_dhcp_permit(engine: HANDLE) -> Result<()> {
        let mut name = wide_str("tunnel permit dhcp");
        let proto: u8 = 17; // UDP
        let port: u16 = 67; // DHCP server
        let mut conds: [FWPM_FILTER_CONDITION0; 2] = unsafe { std::mem::zeroed() };
        conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conds[0].matchType = FWP_MATCH_EQUAL;
        conds[0].conditionValue.r#type = FWP_UINT8;
        conds[0].conditionValue.Anonymous.uint8 = proto;
        conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.r#type = FWP_UINT16;
        conds[1].conditionValue.Anonymous.uint16 = port;

        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData.name = PWSTR(name.as_mut_ptr());
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 15;
        filter.action.r#type = FWP_ACTION_PERMIT;
        filter.numFilterConditions = 2;
        filter.filterCondition = conds.as_mut_ptr();

        let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
        if rc != 0 {
            return Err(anyhow!("FwpmFilterAdd0(dhcp permit) failed: {rc}"));
        }
        Ok(())
    }

    fn add_iface_block(engine: HANDLE, layer: GUID, luid_val: u64) -> Result<()> {
        let mut name = wide_str("tunnel block uplink");
        // FWP_UINT64 stores a POINTER to the u64; keep it alive across the add.
        let luid_stable: u64 = luid_val;
        let mut cond: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.r#type = FWP_UINT64;
        cond.conditionValue.Anonymous.uint64 = &luid_stable as *const u64 as *mut u64;

        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData.name = PWSTR(name.as_mut_ptr());
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 1; // low: loses to the permits above
        filter.action.r#type = FWP_ACTION_BLOCK;
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut cond;

        let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
        if rc != 0 {
            return Err(anyhow!("FwpmFilterAdd0(iface block) failed: {rc}"));
        }
        Ok(())
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                // Closing the dynamic-session engine removes the sublayer and all
                // filters atomically — the uplink is unrestricted again.
                let rc = FwpmEngineClose0(self.engine);
                if rc != 0 {
                    warn!("kill switch teardown (FwpmEngineClose0) failed: {rc}");
                }
                if !self.app_id.is_null() {
                    FwpmFreeMemory0(&mut (self.app_id as *mut c_void));
                }
            }
        }
    }
}

// ============================================================================
// Unsupported platforms (e.g. macOS): fail closed.
// ============================================================================
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub struct Guard;

    pub fn install(_uplink: &EgressPin) -> Result<Guard> {
        Err(anyhow!(
            "kill switch not implemented on this platform; refusing full-tunnel \
             capture without TunnelVision protection (use --no-route to run \
             without capture)"
        ))
    }
}
