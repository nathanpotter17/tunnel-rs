//! TUN device as raw IP-packet channels.
//!
//! Exposes the platform TUN as a pair of channels — an inbound receiver of IP
//! packets read from the interface and an outbound sender of packets to write to
//! it — which is exactly what a synchronous smoltcp `Device` needs to poll against.

use anyhow::Result;
use tokio::sync::mpsc;

/// A configured TUN, decomposed into packet channels. Keep [`TunIo`] alive for the
/// session — dropping it tears down the adapter and the reader/writer tasks.
pub struct TunIo {
    pub name: String,
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub tx: mpsc::Sender<Vec<u8>>,
    keepalive: KeepAlive,
}

impl TunIo {
    pub fn new(ip: std::net::Ipv4Addr, prefix: u8, mtu: u16) -> Result<Self> {
        platform::create(ip, prefix, mtu)
    }

    /// Decompose into (name, packet receiver, packet sender, keepalive guard).
    /// Hold the guard for the session, then call [`KeepAlive::shutdown`] on a
    /// clean exit for deterministic interface removal; dropping the guard is the
    /// panic-safety backstop.
    pub fn into_parts(self) -> (String, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>, KeepAlive) {
        (self.name, self.rx, self.tx, self.keepalive)
    }
}

// ============================================================================
// Windows (wintun)
// ============================================================================

#[cfg(windows)]
mod platform {
    use super::*;
    use anyhow::{bail, Context};
    // OsStrExt: UTF-16 for the WinTrust call. OpenOptionsExt: the share mode
    // that keeps the verified bytes from being swapped before they are mapped.
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const RING_CAPACITY: u32 = 0x400000; // 4 MB
    /// Fixed wintun adapter name — the friendly name Windows shows in adapter
    /// lists. Reclaimed at startup and removed on teardown so a session never
    /// adopts a prior session's adapter (and its stale config).
    const ADAPTER_NAME: &str = "tunnel0";
    /// Device description, i.e. wintun's "tunnel type". Cosmetic; it is what sits
    /// in the description column beside [`ADAPTER_NAME`].
    const ADAPTER_TYPE: &str = "Tunnel";

    // The adapter GUID is deliberately NOT pinned. Wintun derives both the device
    // instance id (`SWD\Wintun\{GUID}`) and, through it, the NET_LUID from the
    // GUID — so a fixed GUID would hand every session the same stable, externally
    // readable interface identity to fingerprint and target. A session-random GUID
    // keeps that identity fresh per run. Only the NAME is stable, because routing,
    // DNS pinning, and the kill switch all reference it.
    //
    // The cost of a random GUID is that the identity to clean up is only known at
    // runtime — so it is carried on [`KeepAlive`] rather than read off a constant,
    // and a leftover is found by name (see the reclamation in `create`).

    /// RAII teardown guard for the wintun interface. Owns everything required to
    /// stop the worker threads/tasks and release every handle to the adapter —
    /// which is what actually triggers `WintunCloseAdapter` and removes the
    /// interface. Prefer the async [`KeepAlive::shutdown`] on a clean exit for
    /// deterministic removal; `Drop` is the panic-safety backstop.
    pub struct KeepAlive {
        session: Option<Arc<wintun::Session>>,
        adapter: Option<Arc<wintun::Adapter>>,
        reader: Option<std::thread::JoinHandle<()>>,
        writer: Option<tokio::task::JoinHandle<()>>,
        stopping: Arc<AtomicBool>,
        name: String,
        /// This session's adapter GUID, captured at create time. It IS the device
        /// instance id, and it is the only handle on the interface that survives
        /// every handle being dropped — so teardown can remove the device it
        /// actually created rather than whatever currently answers to the name.
        guid: u128,
    }

    impl KeepAlive {
        /// Deterministic, awaited teardown: unblock and reap both workers so they
        /// release their `Session` clones, then drop ours plus the adapter — the
        /// last handle closing removes the interface before this returns.
        pub async fn shutdown(&mut self) {
            if self.session.is_none() {
                return; // already torn down
            }
            self.stopping.store(true, Ordering::Relaxed);
            if let Some(s) = self.session.as_ref() {
                let _ = s.shutdown(); // wakes the reader out of receive_blocking()
            }
            if let Some(w) = self.writer.take() {
                w.abort();
                let _ = w.await; // reclaim the writer's Session clone
            }
            if let Some(r) = self.reader.take() {
                // Join the blocking thread off the async runtime.
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = r.join();
                })
                .await;
            }
            // Workers gone: dropping the Session (ends it, releases its internal
            // Adapter clone) then the last Adapter Arc closes the handle, which
            // removes the interface from the system.
            self.session.take();
            self.adapter.take();
            // Belt and suspenders: the close above is the driver's cooperation,
            // not a guarantee. Sweep this session's device instance so no path out
            // of this process can leave the interface installed for the next
            // session — or for whatever the user has bound to it.
            remove_device_instance(self.guid);
            tracing::info!("TUN '{}' removed", self.name);
        }
    }

    impl Drop for KeepAlive {
        fn drop(&mut self) {
            if self.session.is_none() {
                return; // shutdown() already ran
            }
            self.stopping.store(true, Ordering::Relaxed);
            if let Some(s) = self.session.as_ref() {
                let _ = s.shutdown();
            }
            if let Some(w) = self.writer.take() {
                w.abort(); // fire-and-forget; runtime reclaims the task promptly
            }
            if let Some(r) = self.reader.take() {
                let _ = r.join(); // safe: shutdown() unblocked receive_blocking()
            }
            self.session.take();
            self.adapter.take();
            remove_device_instance(self.guid);
        }
    }

    /// Where the arch-matched `wintun.dll` is, if it is anywhere we look.
    ///
    /// Public because `preflight` asks the same question first, and must ask it
    /// of the same list: two search paths means a preflight that passes and a
    /// loader that then fails, which is the failure preflight exists to prevent.
    pub fn locate_wintun_dll() -> Option<PathBuf> {
        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86"
        };
        // Anchored to the executable, never to the working directory. This
        // process always runs elevated, and a DLL resolved through a
        // CWD-relative path is loaded from wherever the user happened to be
        // when they started it — a download folder, a share, a removable
        // drive. Anything that can write there would be executing inside an
        // elevated process. The install directory is a smaller target than
        // "any directory the user might cd into", and `verify_signature`
        // below covers what remains of it.
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll"));
                candidates.push(dir.join(arch).join("wintun.dll"));
                candidates.push(dir.join("bin").join(arch).join("wintun.dll"));
            }
        }
        candidates.into_iter().find(|p| p.exists())
    }

    /// The publisher the shipped `wintun.dll` is signed by.
    ///
    /// Pinned, because "carries a valid Authenticode signature" is not by
    /// itself a check — a certificate is something an attacker can obtain and
    /// sign their own payload with. The question worth asking is not whether
    /// the file is signed but whether it is signed by *them*.
    const WINTUN_SIGNER: &str = "WireGuard LLC";

    /// Deny writers for as long as we hold the file.
    ///
    /// The gap between "the signature checked out" and "LoadLibrary read the
    /// bytes" is a race, and against an attacker who can rewrite the file it is
    /// a race they can simply retry until they win. Holding one handle across
    /// both — verifying *through* it, then loading while it is still open —
    /// means the bytes that were checked are the bytes that get mapped.
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    /// Verify `path` carries a valid Authenticode signature from
    /// [`WINTUN_SIGNER`], reading the signer off the very chain WinVerifyTrust
    /// validated rather than parsing the file a second time.
    pub(super) fn verify_signature(path: &Path, file: &std::fs::File) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
            WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG,
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };

        let wide: Vec<u16> = std::ffi::OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wide.as_ptr();
        file_info.hFile = file.as_raw_handle() as HANDLE;

        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        // No online revocation check. This process rewrites the host's routing
        // and resolver, and arms a kill switch that drops unmarked traffic —
        // so a CRL fetch here can hang or fail for reasons that have nothing to
        // do with the file, including reasons we caused. Chain validity plus
        // the pinned subject below is the check that is actually being made.
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file_info };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_SAFER_FLAG;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let pdata = &mut data as *mut WINTRUST_DATA as *mut std::ffi::c_void;
        let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, pdata) };

        // Read the signer before the state handle is closed — it owns the chain.
        let signer = if status == 0 { unsafe { signer_name(data.hWVTStateData) } } else { None };

        // Always release the provider state, whatever the verdict. The pointer
        // is retaken rather than reusing `pdata`: liveness analysis does not
        // follow raw pointers, so assigning through the binding and passing a
        // pointer made earlier reads as a dead store.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let pclose = &mut data as *mut WINTRUST_DATA as *mut std::ffi::c_void;
        unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, pclose) };

        if status != 0 {
            bail!(
                "{} failed Authenticode verification (0x{:08X}).\n\
                 This file is loaded into a process running with administrator \
                 rights, so an unverifiable copy is refused rather than trusted. \
                 Replace it with the signed release from https://www.wintun.net/",
                path.display(),
                status as u32
            );
        }
        match signer.as_deref() {
            Some(WINTUN_SIGNER) => Ok(()),
            Some(other) => bail!(
                "{} is signed by {:?}, not {:?}.\n\
                 A valid signature from the wrong publisher is what a substituted \
                 DLL looks like. Replace it with the signed release from \
                 https://www.wintun.net/",
                path.display(),
                other,
                WINTUN_SIGNER
            ),
            None => bail!(
                "{} verified, but its signer could not be read — refusing to load it",
                path.display()
            ),
        }
    }

    /// Leaf-certificate subject of the first signer on a verified chain.
    ///
    /// # Safety
    /// `state` must be the `hWVTStateData` of a WinVerifyTrust call that
    /// returned success and has not yet been closed.
    unsafe fn signer_name(state: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
        use windows_sys::Win32::Security::Cryptography::{
            CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        };
        use windows_sys::Win32::Security::WinTrust::{
            WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
            WTHelperProvDataFromStateData,
        };

        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() {
            return None;
        }
        // Index 0 is the leaf: the certificate that actually signed the file.
        let cert = WTHelperGetProvCertFromChain(sgnr, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return None;
        }
        let ctx = (*cert).pCert;

        let len = CertGetNameStringW(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        );
        if len <= 1 {
            return None; // 1 == the terminating NUL alone, i.e. no name
        }
        let mut buf = vec![0u16; len as usize];
        let got = CertGetNameStringW(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            buf.as_mut_ptr(),
            len,
        );
        if got == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..got as usize - 1]))
    }

    pub fn create(ip: std::net::Ipv4Addr, prefix: u8, mtu: u16) -> Result<TunIo> {
        let dll = locate_wintun_dll().context(
            "wintun.dll not found; place the arch-matching DLL next to the exe or in bin/<arch>/",
        )?;

        // Open once, deny writers, verify through that handle, and keep it open
        // across the load. Under the shipped layout the DLL sits in a directory
        // the user can write to, which means anything running as the user can
        // rewrite it and wait for the next elevated launch — so the signature is
        // checked, and checked on the bytes that actually get mapped.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&dll)
            .with_context(|| format!("could not open {} for verification", dll.display()))?;
        verify_signature(&dll, &file)?;
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .with_context(|| format!("failed to load wintun dll from {}", dll.display()))?;
        drop(file);
        tracing::debug!("wintun.dll verified: signed by {}", WINTUN_SIGNER);

        // Startup reclamation: a clean shutdown removes the adapter, so a leftover
        // means a prior run was hard-killed (or tripped the tripwire lockdown,
        // which exits past every Drop). Its GUID died with that run, so recover it
        // by name — `Adapter::open` resolves the friendly name to a GUID — and
        // then remove that device instance. Opening the orphan and dropping the
        // handle does NOT remove it, because wintun only removes adapters the
        // closing process itself created; that is why leftovers used to survive
        // into the next session. NO create-then-open fallback: we never adopt a
        // stale adapter (that is what bound us to old config).
        if let Ok(stale) = wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            let stale_guid = stale.get_guid();
            drop(stale); // release the handle before removing the device under it
            if remove_device_instance(stale_guid) {
                tracing::warn!(
                    "removed a leftover '{}' adapter from a previous run",
                    ADAPTER_NAME
                );
                // Device removal is not instantaneous, and the name stays taken
                // until it lands — create too early and Windows hands us
                // 'tunnel0 2'. Only paid when there was actually an orphan.
                std::thread::sleep(std::time::Duration::from_millis(500));
            } else {
                tracing::warn!(
                    "a leftover '{}' adapter is present and could not be removed; \
                     the new adapter may come up under a suffixed name",
                    ADAPTER_NAME
                );
            }
        }

        // Argument order is (name, tunnel_type): friendly name first, description
        // second. GUID is None on purpose — see the note above the constants.
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_TYPE, None)
            .with_context(|| format!("failed to create Wintun adapter '{}'", ADAPTER_NAME))?;
        let guid = adapter.get_guid();
        let name = adapter.get_name().unwrap_or_else(|_| ADAPTER_NAME.to_string());
        // Windows suffixes a name that is still claimed by a lingering registry
        // entry ('tunnel0 2'). Everything downstream — routes, the DNS pin, the
        // kill switch — keys off `name`, so this is not fatal; but it means the
        // host has cruft worth knowing about.
        if name != ADAPTER_NAME {
            tracing::warn!(
                "adapter came up as '{}' rather than '{}' — a previous interface \
                 is still registered under that name",
                name,
                ADAPTER_NAME
            );
        }

        // netsh failures are fatal, not ignored: an adapter without its address
        // or MTU produces a session that "runs" and moves nothing, and the
        // failure would otherwise surface much later as unroutable traffic with
        // no cause in sight. Erroring here drops the adapter Arc, which removes
        // the half-configured interface before returning.
        let mask = prefix_to_mask(prefix);
        netsh(&[
            "interface", "ip", "set", "address", &name, "static",
            &ip.to_string(), &mask,
        ])
        .with_context(|| format!("could not assign {ip}/{mask} to adapter '{name}'"))?;
        netsh(&[
            "interface", "ipv4", "set", "subinterface", &name,
            &format!("mtu={}", mtu),
        ])
        .with_context(|| format!("could not set MTU {mtu} on adapter '{name}'"))?;

        let session = Arc::new(
            adapter.start_session(RING_CAPACITY).context("failed to start Wintun session")?,
        );

        let (read_tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let (tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

        let stopping = Arc::new(AtomicBool::new(false));

        // Reader: a blocking OS thread (wintun receive_blocking has no async form).
        // Stopped by session.shutdown(); `stopping` distinguishes that from a real
        // error so teardown doesn't log a spurious failure.
        let read_session = session.clone();
        let reader_stopping = stopping.clone();
        let reader = std::thread::spawn(move || loop {
            match read_session.receive_blocking() {
                Ok(packet) => {
                    if read_tx.blocking_send(packet.bytes().to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if !reader_stopping.load(Ordering::Relaxed) {
                        tracing::error!("wintun read error: {}", e);
                    }
                    break;
                }
            }
        });

        // Writer: a tokio task (ring sends are non-blocking), so teardown can
        // abort it without waiting on the engine's tx-sender drop order.
        let write_session = session.clone();
        let writer = tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                match write_session.allocate_send_packet(data.len() as u16) {
                    Ok(mut packet) => {
                        packet.bytes_mut().copy_from_slice(&data);
                        write_session.send_packet(packet);
                    }
                    Err(e) => tracing::error!("wintun write error: {}", e),
                }
            }
        });

        Ok(TunIo {
            name: name.clone(),
            rx,
            tx,
            keepalive: KeepAlive {
                session: Some(session),
                adapter: Some(adapter),
                reader: Some(reader),
                writer: Some(writer),
                stopping,
                name,
                guid,
            },
        })
    }

    /// The PnP device instance wintun creates for an adapter with GUID `g`.
    fn device_instance_id(g: u128) -> String {
        format!(
            "SWD\\Wintun\\{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
            (g >> 96) as u32,
            (g >> 80) as u16,
            (g >> 64) as u16,
            (g >> 48) as u16,
            (g & 0xFFFF_FFFF_FFFF) as u64,
        )
    }

    /// Remove the device instance for GUID `g`, returning whether anything was
    /// actually removed.
    ///
    /// This is the guarantee that exiting leaves no interface behind.
    /// `WintunCloseAdapter` removes the adapter only for the process that created
    /// it, and only if the driver is in a position to oblige — a leaked handle
    /// clone, a wedged session, or a prior run that never reached its teardown all
    /// leave the interface installed. Removing the PnP device is unconditional.
    /// Needs the admin rights the engine already requires.
    ///
    /// Failure is the normal case on a clean exit (the adapter is already gone),
    /// hence the quiet bool rather than an error.
    fn remove_device_instance(g: u128) -> bool {
        std::process::Command::new("pnputil")
            .args(["/remove-device", &device_instance_id(g)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run netsh, failing with its own output on a non-zero exit.
    fn netsh(args: &[&str]) -> Result<()> {
        let out = std::process::Command::new("netsh")
            .args(args)
            .output()
            .context("failed to spawn netsh")?;
        if !out.status.success() {
            anyhow::bail!(
                "`netsh {}` failed: {}{}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim(),
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
        Ok(())
    }

    fn prefix_to_mask(prefix: u8) -> String {
        let bits: u32 = if prefix >= 32 { u32::MAX } else { !(u32::MAX >> prefix) };
        std::net::Ipv4Addr::from(bits).to_string()
    }
}

// ============================================================================
// Unix (Linux)
// ============================================================================

#[cfg(unix)]
mod platform {
    use super::*;
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Fixed interface name. Pinned (not left to the kernel) so reclamation can
    /// target it and routing/DNS — which reference the name — never desync.
    const IFACE_NAME: &str = "tun0";

    /// RAII teardown guard. Owns both worker tasks and the interface name.
    /// [`KeepAlive::shutdown`] aborts+reaps the tasks (closing the fd → a
    /// non-persistent TUN is removed) and deletes the link as a guarantee;
    /// `Drop` is the panic-safety backstop.
    pub struct KeepAlive {
        name: String,
        reader: Option<tokio::task::JoinHandle<()>>,
        writer: Option<tokio::task::JoinHandle<()>>,
    }

    impl KeepAlive {
        pub async fn shutdown(&mut self) {
            if self.reader.is_none() && self.writer.is_none() {
                return;
            }
            if let Some(h) = self.reader.take() {
                h.abort();
                let _ = h.await; // drop the reader half → release the fd
            }
            if let Some(h) = self.writer.take() {
                h.abort();
                let _ = h.await; // drop the writer half → last fd closes
            }
            // Dropping both halves removes a non-persistent TUN; the explicit
            // delete also clears a persistent leftover and stays symmetric with
            // the startup reclamation.
            delete_link(&self.name);
            tracing::info!("TUN '{}' removed", self.name);
        }
    }

    impl Drop for KeepAlive {
        fn drop(&mut self) {
            if let Some(h) = self.reader.take() {
                h.abort();
            }
            if let Some(h) = self.writer.take() {
                h.abort();
            }
            delete_link(&self.name);
        }
    }

    /// Best-effort interface removal. Needs the same admin/root the TUN create,
    /// route hijack, and DNS pin already require.
    fn delete_link(name: &str) {
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", name])
            .output();
    }

    pub fn create(ip: std::net::Ipv4Addr, prefix: u8, mtu: u16) -> Result<TunIo> {
        let name = IFACE_NAME.to_string();

        // Startup reclamation: remove any leftover from a hard-killed prior run so
        // create binds the fixed name cleanly. No adopting stale config.
        delete_link(&name);

        let mut config = tun::Configuration::default();
        config
            .name(IFACE_NAME)
            .address(ip)
            .netmask(mask_octets(prefix))
            .mtu(mtu as i32)
            .up();
        #[cfg(target_os = "linux")]
        config.platform(|c| {
            c.packet_information(false);
        });

        let dev = tun::create_as_async(&config).context("failed to create TUN device")?;

        let (mut reader, mut writer) = tokio::io::split(dev);
        let (read_tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let (tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

        let reader_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if read_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let writer_task = tokio::spawn(async move {
            while let Some(pkt) = write_rx.recv().await {
                if writer.write_all(&pkt).await.is_err() {
                    break;
                }
            }
        });

        Ok(TunIo {
            name: name.clone(),
            rx,
            tx,
            keepalive: KeepAlive {
                name,
                reader: Some(reader_task),
                writer: Some(writer_task),
            },
        })
    }

    fn mask_octets(prefix: u8) -> (u8, u8, u8, u8) {
        let bits: u32 = if prefix >= 32 { u32::MAX } else { !(u32::MAX >> prefix) };
        let o = bits.to_be_bytes();
        (o[0], o[1], o[2], o[3])
    }
}

pub use platform::KeepAlive;

#[cfg(windows)]
pub use platform::locate_wintun_dll;

#[cfg(all(windows, test))]
mod tests {
    use std::os::windows::fs::OpenOptionsExt;

    /// The DLL this repo ships must pass the check the engine makes of it.
    ///
    /// Worth a test because the two halves fail in opposite directions and
    /// neither is visible from the other: too strict and every launch is
    /// refused, too loose and the check is theatre. It also proves the deny-
    /// write share mode does not stop `LoadLibrary` — verifying and then
    /// loading through one handle is the part that closes the swap window, and
    /// it would be a poor way to discover a sharing violation.
    #[test]
    fn the_wintun_we_ship_is_signed_by_who_we_expect_and_still_loads() {
        let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
        let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("bin")
            .join(arch)
            .join("wintun.dll");
        if !dll.exists() {
            eprintln!("skipping: {} not present", dll.display());
            return;
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001) // FILE_SHARE_READ
            .open(&dll)
            .expect("open the shipped dll");
        super::platform::verify_signature(&dll, &file).expect("shipped wintun.dll must verify");

        // Still loadable while that handle is held open.
        unsafe { wintun::load_from_path(&dll) }.expect("verified dll must still load");
        drop(file);
    }

    /// An unsigned file must be refused, not merely noted.
    #[test]
    fn an_unsigned_dll_is_refused() {
        let dir = std::env::temp_dir().join(format!("tunnel-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("wintun.dll");
        // Any unsigned bytes will do: the check runs before the loader does.
        std::fs::write(&fake, b"MZ not a real dll").unwrap();

        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&fake)
            .unwrap();
        assert!(
            super::platform::verify_signature(&fake, &file).is_err(),
            "an unsigned file must not pass verification"
        );
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
