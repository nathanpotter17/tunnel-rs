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
    /// Hold the guard for the session — dropping it tears down the adapter.
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
    use std::sync::Arc;

    const RING_CAPACITY: u32 = 0x400000; // 4 MB

    pub struct KeepAlive {
        _adapter: Arc<wintun::Adapter>,
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

        let adapter = match wintun::Adapter::create(&wintun, "Tunnel", "tunnel0", None) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::open(&wintun, "tunnel0")
                .context("failed to create or open Wintun adapter")?,
        };
        let name = adapter.get_name().unwrap_or_else(|_| "tunnel0".to_string());

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

        let read_session = session.clone();
        std::thread::spawn(move || loop {
            match read_session.receive_blocking() {
                Ok(packet) => {
                    if read_tx.blocking_send(packet.bytes().to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("wintun read error: {}", e);
                    break;
                }
            }
        });

        let write_session = session.clone();
        std::thread::spawn(move || {
            while let Some(data) = write_rx.blocking_recv() {
                match write_session.allocate_send_packet(data.len() as u16) {
                    Ok(mut packet) => {
                        packet.bytes_mut().copy_from_slice(&data);
                        write_session.send_packet(packet);
                    }
                    Err(e) => tracing::error!("wintun write error: {}", e),
                }
            }
        });

        Ok(TunIo { name, rx, tx, keepalive: KeepAlive { _adapter: adapter } })
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

    pub struct KeepAlive;

    pub fn create(ip: std::net::Ipv4Addr, prefix: u8, mtu: u16) -> Result<TunIo> {
        let mut config = tun::Configuration::default();
        config
            .address(ip)
            .netmask(mask_octets(prefix))
            .mtu(mtu as i32)
            .up();
        #[cfg(target_os = "linux")]
        config.platform(|c| {
            c.packet_information(false);
        });

        let dev = tun::create_as_async(&config).context("failed to create TUN device")?;
        let name = "tun0".to_string();

        let (mut reader, mut writer) = tokio::io::split(dev);
        let (read_tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let (tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

        tokio::spawn(async move {
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

        tokio::spawn(async move {
            while let Some(pkt) = write_rx.recv().await {
                if writer.write_all(&pkt).await.is_err() {
                    break;
                }
            }
        });

        Ok(TunIo { name, rx, tx, keepalive: KeepAlive })
    }

    fn mask_octets(prefix: u8) -> (u8, u8, u8, u8) {
        let bits: u32 = if prefix >= 32 { u32::MAX } else { !(u32::MAX >> prefix) };
        let o = bits.to_be_bytes();
        (o[0], o[1], o[2], o[3])
    }
}

pub use platform::KeepAlive;
