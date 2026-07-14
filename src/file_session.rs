//! Standalone encrypted peer channel for file sharing.
//!
//! Decoupled from the egress engine: the engine connects the host to the
//! internet, this connects two `tunnel` instances to each other. One Noise IK
//! handshake, then `file_transfer.rs` frames over a dedicated UDP socket. No IP
//! data plane, no rekey — a file session lives only as long as sharing.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::crypto::{self, CryptoSession, HandshakeBuilder, MAX_PACKET_SIZE};
use crate::file_transfer::{FileProcessResult, FileTransferManager, RequestId, TransferDirection};
use crate::protocol::PacketType;
use crate::state::Shared;

const TRANSFER_TICK: Duration = Duration::from_millis(5);
const IDLE_TICK: Duration = Duration::from_millis(200);
const ACTION_CAP: usize = 128;
/// Emit a keepalive at least this often so an idle peer keeps its liveness fresh.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Reap the channel if nothing (keepalive, frame, disconnect) arrives within this.
/// The correctness backstop: teardown no longer depends on the Disconnect landing.
const PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// GUI → channel commands (mirrors the old GuiAction set).
#[derive(Debug, Clone)]
pub enum FileAction {
    Share(PathBuf),
    Unshare(String),
    RequestList,
    Download(String),
    Approve(RequestId),
    Deny(RequestId),
}

/// One pending approval, flattened for the dashboard.
#[derive(Clone)]
pub struct PendingView {
    pub id: RequestId,
    pub direction: &'static str,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
}

/// Snapshot the dashboard renders each frame.
#[derive(Clone, Default)]
pub struct FileView {
    pub connected: bool,
    pub peer: Option<SocketAddr>,
    pub shared: Vec<crate::file_transfer::FileInfo>,
    pub remote: Vec<crate::file_transfer::FileInfo>,
    pub pending: Vec<PendingView>,
    /// (file_name, percent, is_upload)
    pub transfer: Option<(String, f32, bool)>,
}

/// Cloneable handle the GUI holds: send actions, read the view.
#[derive(Clone)]
pub struct FileHandle {
    pub actions: mpsc::Sender<FileAction>,
    pub view: Arc<Mutex<FileView>>,
}

/// How this side of the channel comes up.
pub enum Role {
    /// Wait for a peer to connect (responder).
    Listen { bind: SocketAddr },
    /// Dial a peer (initiator); needs the peer's static public key.
    Connect { bind: SocketAddr, peer: SocketAddr, remote_public: [u8; 32] },
}

/// Settings for the file manager backing the channel.
pub struct FileConfig {
    pub local_private: [u8; 32],
    pub download_dir: PathBuf,
    pub auto_accept: bool,
    pub approval_timeout: Option<Duration>,
}

/// Spawn the channel task; return the GUI handle plus the task's join handle so
/// the caller can await a clean teardown on shutdown. Actions sent before a peer
/// connects are buffered until the handshake completes.
pub fn spawn(
    role: Role,
    cfg: FileConfig,
    shared: Arc<Shared>,
) -> (FileHandle, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(ACTION_CAP);
    let view = Arc::new(Mutex::new(FileView::default()));
    let handle = FileHandle { actions: tx, view: view.clone() };
    let task = tokio::spawn(async move {
        if let Err(e) = run(role, cfg, shared.clone(), rx, view).await {
            shared.push_log("error", format!("file channel: {e:#}"));
        }
    });
    (handle, task)
}

async fn run(
    role: Role,
    cfg: FileConfig,
    shared: Arc<Shared>,
    mut actions: mpsc::Receiver<FileAction>,
    view: Arc<Mutex<FileView>>,
) -> Result<()> {
    let (socket, crypto) = handshake(&role, cfg.local_private, &shared).await?;
    let peer = socket.peer_addr().ok();
    shared.push_log("info", format!("file channel established with {peer:?}"));

    let mut mgr =
        FileTransferManager::with_approval(cfg.download_dir, cfg.auto_accept, cfg.approval_timeout);

    let mut chan = Channel { socket, crypto };
    {
        let mut v = view.lock().unwrap();
        v.connected = true;
        v.peer = peer;
    }

    let mut recv = vec![0u8; MAX_PACKET_SIZE + 64];
    let mut plain = vec![0u8; MAX_PACKET_SIZE];
    let mut resp = vec![0u8; MAX_PACKET_SIZE];

    let mut last_seen = Instant::now();
    let mut last_keepalive = Instant::now();

    loop {
        if shared.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            chan.send_disconnect().await;
            break;
        }
        if last_seen.elapsed() >= PEER_TIMEOUT {
            shared.push_log("warn", "file peer timed out — closing channel".to_string());
            break;
        }
        let tick = if mgr.has_active_transfer() { TRANSFER_TICK } else { IDLE_TICK };

        tokio::select! {
            biased;

            act = actions.recv() => match act {
                Some(a) => on_action(&mut chan, &mut mgr, a, &shared, &mut resp)?,
                None => { chan.send_disconnect().await; break; } // GUI dropped the sender
            },

            r = chan.socket.recv(&mut recv) => {
                let n = r.context("file socket recv")?;
                last_seen = Instant::now();
                match on_datagram(&mut chan, &mut mgr, &recv[..n], &shared, &mut plain, &mut resp) {
                    Ok(Step::Stop) => break,
                    Ok(Step::Continue) => {}
                    Err(e) => shared.push_log("warn", format!("file frame: {e}")),
                }
            }

            _ = tokio::time::sleep(tick) => {
                if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                    let _ = chan.send_tagged(PacketType::Keepalive, &[]);
                    last_keepalive = Instant::now();
                }
                drain_pending(&mut chan, &mut mgr, &mut plain)?;
                for (len, _id) in mgr.expire_pending_requests(&mut plain) {
                    chan.send_tagged(PacketType::FileTransfer, &plain[..len])?;
                }
            }
        }

        refresh_view(&view, &mgr, peer);
    }

    if let Ok(mut v) = view.lock() {
        v.connected = false;
    }
    shared.push_log("info", "file channel closed".to_string());
    Ok(())
}

/// Post-handshake transport wrapper.
struct Channel {
    socket: UdpSocket,
    crypto: CryptoSession,
}

impl Channel {
    /// Encrypt `plain` and send it under `tag` → `[tag][nonce][ct]`.
    fn send_tagged(&self, tag: PacketType, plain: &[u8]) -> Result<()> {
        let mut out = [0u8; MAX_PACKET_SIZE + 64];
        out[0] = tag as u8;
        let clen = self.crypto.encrypt(plain, &mut out[1..])?;
        match self.socket.try_send(&out[..1 + clen]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e).context("file socket send"),
        }
    }

    /// Awaited graceful teardown: encrypt an empty Disconnect and hand it to the
    /// kernel with a real await, so a momentarily-full send buffer can't silently
    /// drop it the way `try_send` would. Wire loss is still possible — the peer's
    /// idle timeout is the correctness backstop, not this packet.
    async fn send_disconnect(&self) {
        let mut out = [0u8; MAX_PACKET_SIZE + 64];
        out[0] = PacketType::Disconnect as u8;
        let Ok(clen) = self.crypto.encrypt(&[], &mut out[1..]) else { return };
        let _ = self.socket.send(&out[..1 + clen]).await;
    }
}

async fn handshake(
    role: &Role,
    local_private: [u8; 32],
    shared: &Arc<Shared>,
) -> Result<(UdpSocket, CryptoSession)> {
    match role {
        Role::Connect { bind, peer, remote_public } => {
            let socket = UdpSocket::bind(bind).await.context("bind file socket")?;
            crate::pin::mark_own(&socket).context("mark file socket")?;
            socket.connect(peer).await.context("connect file peer")?;
            shared.push_log("info", format!("dialing file peer {peer}"));

            let builder = HandshakeBuilder::new(local_private).with_remote_public(*remote_public);
            let mut noise = builder.build_initiator()?;
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let len = noise.write_message(&[], &mut buf)?;
            socket.send(&buf[..len]).await?;

            let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
                .await
                .context("file handshake timeout")??;
            let mut tmp = vec![0u8; MAX_PACKET_SIZE];
            noise.read_message(&buf[..n], &mut tmp)?;
            let crypto = crypto::client_handshake_finish(noise, *remote_public)?;
            Ok((socket, crypto))
        }
        Role::Listen { bind } => {
            let socket = UdpSocket::bind(bind).await.context("bind file socket")?;
            crate::pin::mark_own(&socket).context("mark file socket")?;
            shared.push_log("info", format!("file channel listening on {bind}"));

            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let (n, from) = socket.recv_from(&mut buf).await.context("file accept")?;
            socket.connect(from).await.context("pin file peer")?;

            let (noise, response) = crypto::server_handshake_start(local_private, &buf[..n])?;
            socket.send(&response).await?;
            let crypto = crypto::server_handshake_finish(noise)?;
            Ok((socket, crypto))
        }
    }
}

/// Whether the receive loop keeps running after a datagram.
enum Step {
    Continue,
    Stop,
}

fn on_datagram(
    chan: &mut Channel,
    mgr: &mut FileTransferManager,
    datagram: &[u8],
    shared: &Arc<Shared>,
    plain: &mut [u8],
    resp: &mut [u8],
) -> Result<Step> {
    if datagram.is_empty() {
        return Ok(Step::Continue);
    }
    match PacketType::try_from(datagram[0])? {
        PacketType::Keepalive => Ok(Step::Continue),
        PacketType::Disconnect => {
            shared.push_log("info", "peer disconnected file channel".to_string());
            Ok(Step::Stop)
        }
        PacketType::FileTransfer => {
            let len = chan.crypto.decrypt(&datagram[1..], plain)?;
            let result = mgr.process_packet(&plain[..len], resp)?;
            handle_result(chan, mgr, result, shared, resp, plain)?;
            Ok(Step::Continue)
        }
    }
}

fn on_action(
    chan: &mut Channel,
    mgr: &mut FileTransferManager,
    action: FileAction,
    shared: &Arc<Shared>,
    resp: &mut [u8],
) -> Result<()> {
    match action {
        FileAction::Share(path) => {
            match mgr.shared.add(path) {
                Ok(info) => shared.push_log("info", format!("+ {}", info.name)),
                Err(e) => shared.push_log("warn", format!("share failed: {e}")),
            }
            Ok(())
        }
        FileAction::Unshare(name) => {
            mgr.shared.remove(&name);
            shared.push_log("info", format!("- {name}"));
            Ok(())
        }
        FileAction::RequestList => {
            let len = mgr.create_list_request(resp);
            chan.send_tagged(PacketType::FileTransfer, &resp[..len])
        }
        FileAction::Download(name) => {
            let len = mgr.create_download_request(&name, resp);
            chan.send_tagged(PacketType::FileTransfer, &resp[..len])
        }
        FileAction::Approve(id) => {
            if let Some(res) = mgr.approve_request(id, resp)? {
                let mut plain = [0u8; MAX_PACKET_SIZE];
                handle_result(chan, mgr, res, shared, resp, &mut plain)?;
            }
            Ok(())
        }
        FileAction::Deny(id) => {
            if let Some(len) = mgr.deny_request(id, resp)? {
                chan.send_tagged(PacketType::FileTransfer, &resp[..len])?;
            }
            Ok(())
        }
    }
}

/// Act on a FileProcessResult: forward any response frame, drive chunk flow.
fn handle_result(
    chan: &mut Channel,
    mgr: &mut FileTransferManager,
    result: FileProcessResult,
    shared: &Arc<Shared>,
    resp: &mut [u8],
    plain: &mut [u8],
) -> Result<()> {
    use FileProcessResult::*;
    match result {
        SendResponse(len) => chan.send_tagged(PacketType::FileTransfer, &resp[..len]),
        SendResponseAndNotify(len, info) => {
            shared.push_log("info", format!("transfer started: {}", info.name));
            chan.send_tagged(PacketType::FileTransfer, &resp[..len])
        }
        // Header/ACK acknowledged → push the next window of chunks now.
        HeaderAcked | AckReceived(_) => drain_pending(chan, mgr, plain),
        TransferCompleteWithAck(len, name, path) => {
            shared.push_log("info", format!("received {name} -> {}", path.display()));
            chan.send_tagged(PacketType::FileTransfer, &resp[..len])
        }
        FileListReceived => Ok(()),
        ChunkReceived(_) => Ok(()),
        SendComplete(name) => {
            if !name.is_empty() {
                shared.push_log("info", format!("sent {name}"));
            }
            Ok(())
        }
        Error(msg) => {
            shared.push_log("warn", format!("transfer error: {msg}"));
            Ok(())
        }
        ApprovalRequired(len, _id) => {
            if len > 0 {
                chan.send_tagged(PacketType::FileTransfer, &resp[..len])?;
            }
            shared.push_log("info", "transfer awaiting local approval".to_string());
            Ok(())
        }
        DownloadPendingRemote => Ok(()),
        DownloadDeniedRemote(msg) => {
            shared.push_log("warn", format!("download denied: {msg}"));
            Ok(())
        }
        Ignored => Ok(()),
    }
}

/// Flush all queued outbound file packets (chunks / retransmits).
fn drain_pending(chan: &mut Channel, mgr: &mut FileTransferManager, plain: &mut [u8]) -> Result<()> {
    while let Some((len, _is_retransmit)) = mgr.get_packets_to_send(plain)? {
        chan.send_tagged(PacketType::FileTransfer, &plain[..len])?;
    }
    Ok(())
}

fn refresh_view(view: &Arc<Mutex<FileView>>, mgr: &FileTransferManager, peer: Option<SocketAddr>) {
    let shared = mgr.shared.list().unwrap_or_default();
    let pending = mgr
        .pending_requests
        .iter()
        .map(|p| PendingView {
            id: p.id,
            direction: match p.direction {
                TransferDirection::Upload => "send",
                TransferDirection::Download => "receive",
            },
            file_name: p.file_name.clone(),
            file_size: p.file_size,
            file_type: p.file_type.clone(),
        })
        .collect();

    if let Ok(mut v) = view.lock() {
        v.connected = true;
        v.peer = peer;
        v.shared = shared;
        v.remote = mgr.remote_files.clone();
        v.pending = pending;
        v.transfer = mgr.transfer_progress();
    }
}