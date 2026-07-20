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
    use anyhow::Context;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const RING_CAPACITY: u32 = 0x400000; // 4 MB
    /// Fixed wintun adapter name. Reclaimed at startup and removed on teardown so
    /// a session never adopts a prior session's adapter (and its stale config).
    const ADAPTER_NAME: &str = "tunnel0";

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
        }
    }

    fn locate_wintun_dll() -> Option<PathBuf> {
        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86"
        };
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll"));
                candidates.push(dir.join(arch).join("wintun.dll"));
                candidates.push(dir.join("bin").join(arch).join("wintun.dll"));
            }
        }
        candidates.push(PathBuf::from(format!("bin/{}/wintun.dll", arch)));
        candidates.push(PathBuf::from("wintun.dll"));
        candidates.into_iter().find(|p| p.exists())
    }

    pub fn create(ip: std::net::Ipv4Addr, prefix: u8, mtu: u16) -> Result<TunIo> {
        let dll = locate_wintun_dll().context(
            "wintun.dll not found; place the arch-matching DLL next to the exe or in bin/<arch>/",
        )?;
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .with_context(|| format!("failed to load wintun dll from {}", dll.display()))?;

        // Startup reclamation: a clean shutdown removes the adapter, so a leftover
        // means a prior run was hard-killed. Opening then dropping the orphan
        // closes its last handle, removing it. NO create-then-open fallback: we
        // never adopt a stale adapter (that is what bound us to old config).
        if let Ok(stale) = wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            drop(stale);
            tracing::warn!(
                "removed a leftover '{}' adapter from a previous run",
                ADAPTER_NAME
            );
        }

        let adapter = wintun::Adapter::create(&wintun, "Tunnel", ADAPTER_NAME, None)
            .with_context(|| format!("failed to create Wintun adapter '{}'", ADAPTER_NAME))?;
        let name = adapter.get_name().unwrap_or_else(|_| ADAPTER_NAME.to_string());

        let mask = prefix_to_mask(prefix);
        let _ = std::process::Command::new("netsh")
            .args([
                "interface", "ip", "set", "address", &name, "static",
                &ip.to_string(), &mask,
            ])
            .output();
        let _ = std::process::Command::new("netsh")
            .args([
                "interface", "ipv4", "set", "subinterface", &name,
                &format!("mtu={}", mtu),
            ])
            .output();

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
            },
        })
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
