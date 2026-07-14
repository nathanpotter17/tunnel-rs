//! File transfer protocol for secure peer-to-peer file sharing.
//!
//! Implements a sliding window protocol with:
//! - Chunked transfers for reliability
//! - Selective acknowledgments
//! - Automatic retransmission with exponential backoff
//! - Out-of-order chunk handling
//! - **Transfer approval**: all downloads/uploads require explicit
//!   local-user approval before data flows (unless `auto_accept_files`
//!   is set in config)

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum chunk size (max mtu 1400) (outer type (1) + nonce (8) + auth tag (16) + file type (1) + chunk num (4) + data len (2) = 32 bytes overhead = 1368 bytes available)
pub const CHUNK_SIZE: usize = 1350;

/// How many unacknowledged chunks we allow (sliding window)
pub const WINDOW_SIZE: u32 = 32;

/// Timeout before retransmitting a chunk
pub const CHUNK_TIMEOUT: Duration = Duration::from_millis(1000);

/// Maximum retries per chunk before aborting
pub const MAX_RETRIES: u32 = 20;

/// File transfer packet types (0x10-0x1F reserved for file ops)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilePacketType {
    /// Request list of shared files
    ListRequest = 0x10,
    /// Response with shared file list
    ListResponse = 0x11,
    /// Request to download a file
    DownloadRequest = 0x12,
    /// File header (name, size) - starts transfer
    FileHeader = 0x13,
    /// File data chunk
    FileChunk = 0x14,
    /// Acknowledge received chunk(s)
    FileAck = 0x15,
    /// Transfer complete
    FileComplete = 0x16,
    /// Cancel/error
    FileError = 0x17,
    /// Header acknowledgment (ready to receive)
    FileHeaderAck = 0x18,
    /// Download request is pending approval on remote side
    DownloadPending = 0x19,
    /// Download request was denied by remote user
    DownloadDenied = 0x1A,
}

impl TryFrom<u8> for FilePacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x10 => Ok(FilePacketType::ListRequest),
            0x11 => Ok(FilePacketType::ListResponse),
            0x12 => Ok(FilePacketType::DownloadRequest),
            0x13 => Ok(FilePacketType::FileHeader),
            0x14 => Ok(FilePacketType::FileChunk),
            0x15 => Ok(FilePacketType::FileAck),
            0x16 => Ok(FilePacketType::FileComplete),
            0x17 => Ok(FilePacketType::FileError),
            0x18 => Ok(FilePacketType::FileHeaderAck),
            0x19 => Ok(FilePacketType::DownloadPending),
            0x1A => Ok(FilePacketType::DownloadDenied),
            _ => bail!("Unknown file packet type: 0x{:02x}", value),
        }
    }
}

// ============================================================================
// File metadata
// ============================================================================

/// Metadata for a shared file
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub file_type: String,
}

impl FileInfo {
    pub fn from_path(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path)?;
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = path.extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        Ok(Self {
            name,
            size: metadata.len(),
            file_type: ext,
        })
    }

    /// Encode file info: [name_len:2][name][size:8][type_len:1][type]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let name_bytes = self.name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.size.to_le_bytes());
        let type_bytes = self.file_type.as_bytes();
        buf.push(type_bytes.len() as u8);
        buf.extend_from_slice(type_bytes);
        buf
    }

    /// Decode file info from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 3 {
            bail!("FileInfo too short");
        }

        let name_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + name_len + 9 {
            bail!("FileInfo truncated");
        }

        let name = String::from_utf8_lossy(&data[2..2 + name_len]).to_string();
        let size = u64::from_le_bytes(data[2 + name_len..2 + name_len + 8].try_into()?);
        let type_len = data[2 + name_len + 8] as usize;

        if data.len() < 2 + name_len + 9 + type_len {
            bail!("FileInfo type truncated");
        }

        let file_type = String::from_utf8_lossy(
            &data[2 + name_len + 9..2 + name_len + 9 + type_len]
        ).to_string();

        let total_len = 2 + name_len + 9 + type_len;

        Ok((Self { name, size, file_type }, total_len))
    }
}

/// Reduce a fully-untrusted, peer-supplied file name to a safe bare filename, or
/// fail closed. A received name arrives inside the encrypted frame but the PEER
/// is not the local user: `download_dir.join(name)` with an absolute name
/// (`/etc/cron.d/x`, `C:\Windows\...`) or a traversal (`../../.bashrc`) resolves
/// OUTSIDE the download dir — arbitrary file write, i.e. trivial code execution.
/// Rules are applied regardless of host OS so a sender can't target a peer on a
/// different platform.
fn sanitize_filename(raw: &str) -> Result<String> {
    let name = raw.trim();

    if name.is_empty() {
        bail!("rejected file name: empty");
    }
    // No separators of ANY platform, no drive/ADS colon, no NUL, no other control
    // chars, and no Unicode bidirectional-formatting chars — `char::is_control`
    // is category Cc only and would miss these, yet they disguise a real
    // extension (e.g. "invoice\u{202E}fdp.exe" renders as "invoiceexe.pdf").
    fn is_bidi_control(c: char) -> bool {
        matches!(c,
            '\u{200E}' | '\u{200F}' | '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
        )
    }
    if name.contains(['/', '\\', ':', '\0'])
        || name.chars().any(|c| c.is_control() || is_bidi_control(c))
    {
        bail!("rejected file name with path/control characters: {name:?}");
    }
    // Directory references, never real files.
    if name == "." || name == ".." {
        bail!("rejected file name: {name:?}");
    }
    // The OS must also agree this is exactly one component: `file_name()` returns
    // None for `.`/`..`/roots and strips any directory part not already rejected.
    let component = Path::new(name)
        .file_name()
        .and_then(|c| c.to_str())
        .ok_or_else(|| anyhow::anyhow!("rejected file name: not a plain file: {name:?}"))?;
    if component != name {
        bail!("rejected file name: not a single path component: {name:?}");
    }
    // Windows strips trailing dots/spaces and reserves device names; an aliasing
    // name can land unexpectedly. Reject on every platform.
    if component.ends_with('.') || component.ends_with(' ') {
        bail!("rejected file name with trailing dot/space: {name:?}");
    }
    let stem_upper = component
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem_upper.as_str()) {
        bail!("rejected reserved device name: {name:?}");
    }
    if component.len() > 255 {
        bail!("rejected file name: too long ({} bytes)", component.len());
    }
    Ok(component.to_string())
}

/// Hard ceiling on a single inbound transfer regardless of the peer's declared
/// size. A policy constant, not a protocol limit: raise it for larger transfers.
pub const MAX_INBOUND_FILE_SIZE: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB

// ============================================================================
// Shared files registry
// ============================================================================

#[derive(Default)]
pub struct SharedFiles {
    files: HashMap<String, PathBuf>,
}

impl SharedFiles {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, path: PathBuf) -> Result<FileInfo> {
        let info = FileInfo::from_path(&path)?;
        if self.files.contains_key(&info.name) {
            return Ok(info);
        }
        self.files.insert(info.name.clone(), path);
        Ok(info)
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.files.remove(name).is_some()
    }

    pub fn get_path(&self, name: &str) -> Option<&PathBuf> {
        self.files.get(name)
    }

    pub fn list(&self) -> Result<Vec<FileInfo>> {
        let mut infos = Vec::new();
        for path in self.files.values() {
            if let Ok(info) = FileInfo::from_path(path) {
                infos.push(info);
            }
        }
        Ok(infos)
    }

    pub fn encode_list(&self) -> Result<Vec<u8>> {
        let files = self.list()?;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(files.len() as u16).to_le_bytes());
        for file in files {
            buf.extend_from_slice(&file.encode());
        }
        Ok(buf)
    }

    pub fn decode_list(data: &[u8]) -> Result<Vec<FileInfo>> {
        if data.len() < 2 {
            bail!("File list too short");
        }

        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut files = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            let (info, len) = FileInfo::decode(&data[offset..])?;
            files.push(info);
            offset += len;
        }

        Ok(files)
    }
}

// ============================================================================
// Pending transfer approval
// ============================================================================

/// Unique identifier for a pending transfer request
pub type RequestId = u32;

/// Direction of a pending transfer from the local user's perspective
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Peer wants to download one of our files (outbound data)
    Upload,
    /// Peer wants to send us a file (inbound data)
    Download,
}

/// A transfer request awaiting local user approval
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub id: RequestId,
    pub direction: TransferDirection,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub requested_at: Instant,
    /// For Upload: the local path to send from
    local_path: Option<PathBuf>,
    /// For Download: the raw FileHeader payload to replay on approval
    header_payload: Option<Vec<u8>>,
}

impl PendingRequest {
    /// Human-readable description for UI
    pub fn description(&self) -> String {
        let dir = match self.direction {
            TransferDirection::Upload => "send",
            TransferDirection::Download => "receive",
        };
        format!("{} \"{}\" ({})", dir, self.file_name, format_size(self.file_size))
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================================
// Sender / Receiver
// ============================================================================

#[derive(Debug)]
struct ChunkInFlight {
    chunk_num: u32,
    data: Vec<u8>,
    sent_at: Instant,
    retries: u32,
}

/// Active file transfer state - SENDING
pub struct FileSender {
    pub file_name: String,
    pub file_size: u64,
    pub transferred: u64,
    #[allow(dead_code)]
    pub started_at: Instant,
    file: File,
    next_chunk: u32,
    total_chunks: u32,
    in_flight: HashMap<u32, ChunkInFlight>,
    acked_up_to: Option<u32>,
    header_acked: bool,
}

impl FileSender {
    pub fn new(path: &Path) -> Result<Self> {
        let info = FileInfo::from_path(path)?;
        let file = File::open(path).context("Failed to open file")?;
        let total_chunks = ((info.size as f64) / (CHUNK_SIZE as f64)).ceil() as u32;

        Ok(Self {
            file_name: info.name,
            file_size: info.size,
            transferred: 0,
            started_at: Instant::now(),
            file,
            next_chunk: 0,
            total_chunks,
            in_flight: HashMap::new(),
            acked_up_to: None,
            header_acked: false,
        })
    }

    #[cfg(test)]
    pub fn waiting_for_header_ack(&self) -> bool {
        !self.header_acked
    }

    pub fn header_acknowledged(&mut self) {
        self.header_acked = true;
    }

    pub fn can_send(&self) -> bool {
        self.header_acked
            && self.in_flight.len() < WINDOW_SIZE as usize
            && self.next_chunk < self.total_chunks
    }

    pub fn next_chunk(&mut self) -> Result<Option<(u32, Vec<u8>)>> {
        if !self.can_send() {
            return Ok(None);
        }

        let chunk_num = self.next_chunk;
        let offset = chunk_num as u64 * CHUNK_SIZE as u64;

        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = self.file.read(&mut buf)?;

        if n == 0 {
            return Ok(None);
        }

        buf.truncate(n);

        self.in_flight.insert(chunk_num, ChunkInFlight {
            chunk_num,
            data: buf.clone(),
            sent_at: Instant::now(),
            retries: 0,
        });

        self.next_chunk += 1;
        Ok(Some((chunk_num, buf)))
    }

    pub fn get_retransmits(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut retransmits = Vec::new();
        let now = Instant::now();

        for chunk in self.in_flight.values_mut() {
            if now.duration_since(chunk.sent_at) > CHUNK_TIMEOUT {
                if chunk.retries >= MAX_RETRIES {
                    continue;
                }
                chunk.retries += 1;
                chunk.sent_at = now;
                retransmits.push((chunk.chunk_num, chunk.data.clone()));
            }
        }

        retransmits
    }

    pub fn has_failed_chunks(&self) -> bool {
        self.in_flight.values().any(|c| c.retries >= MAX_RETRIES)
    }

    pub fn process_ack(&mut self, acked_chunk: u32) {
        self.in_flight.retain(|&num, _| num > acked_chunk);

        let newly_acked = match self.acked_up_to {
            Some(prev) if acked_chunk > prev => acked_chunk - prev,
            None => acked_chunk + 1,
            _ => 0,
        };

        self.transferred += newly_acked as u64 * CHUNK_SIZE as u64;
        self.transferred = self.transferred.min(self.file_size);
        self.acked_up_to = Some(acked_chunk);
    }

    pub fn is_complete(&self) -> bool {
        self.in_flight.is_empty() && self.next_chunk >= self.total_chunks
    }

    pub fn progress(&self) -> f32 {
        if self.file_size == 0 {
            100.0
        } else {
            (self.transferred as f32 / self.file_size as f32) * 100.0
        }
    }
}

/// Active file transfer state - RECEIVING
pub struct FileReceiver {
    pub file_name: String,
    pub file_size: u64,
    pub transferred: u64,
    #[allow(dead_code)]
    pub started_at: Instant,
    file: File,
    path: PathBuf,
    expected_chunk: u32,
    buffered: HashMap<u32, Vec<u8>>,
    last_ack_sent: Instant,
}

impl FileReceiver {
    pub fn new(name: String, size: u64, download_dir: &Path) -> Result<Self> {
        // Choke point: last code before File::create. Re-validate here so no
        // caller — present or future — can create a receiver that escapes
        // download_dir, even if it skipped the sanitizer upstream.
        let safe = sanitize_filename(&name)?;
        let path = download_dir.join(&safe);

        // Defense in depth (symlinked download dir / TOCTOU): the target's
        // parent, canonicalized, must BE the canonical download dir. The dir
        // exists (created in FileTransferManager::with_approval), so this
        // succeeds; if it was removed mid-run we fail closed.
        let canon_dir = fs::canonicalize(download_dir)
            .with_context(|| format!("canonicalize download dir {}", download_dir.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("refusing write: target has no parent"))?;
        let canon_parent = fs::canonicalize(parent)
            .with_context(|| format!("canonicalize target parent {}", parent.display()))?;
        if canon_parent != canon_dir {
            bail!(
                "refusing write outside download dir: {} resolves under {}",
                path.display(),
                canon_parent.display()
            );
        }

        let file = File::create(&path).context("Failed to create file")?;

        Ok(Self {
            file_name: safe,
            file_size: size.min(MAX_INBOUND_FILE_SIZE), // cap the peer's declared size
            transferred: 0,
            started_at: Instant::now(),
            file,
            path,
            expected_chunk: 0,
            buffered: HashMap::new(),
            last_ack_sent: Instant::now(),
        })
    }

    pub fn write_chunk(&mut self, chunk_num: u32, data: &[u8]) -> Result<(bool, u32)> {
        if chunk_num < self.expected_chunk {
            return Ok((true, self.expected_chunk.saturating_sub(1)));
        }

        if chunk_num == self.expected_chunk {
            // Never write past the declared length: a peer that streams beyond
            // its own header cannot fill the disk.
            let remaining = self.file_size.saturating_sub(self.transferred);
            let take = (data.len() as u64).min(remaining) as usize;
            self.file.write_all(&data[..take])?;
            self.transferred += take as u64;
            self.expected_chunk += 1;

            while let Some(buffered_data) = self.buffered.remove(&self.expected_chunk) {
                let rem = self.file_size.saturating_sub(self.transferred);
                let t = (buffered_data.len() as u64).min(rem) as usize;
                self.file.write_all(&buffered_data[..t])?;
                self.transferred += t as u64;
                self.expected_chunk += 1;
            }

            self.last_ack_sent = Instant::now();
            Ok((true, self.expected_chunk - 1))
        } else {
            if self.buffered.len() < WINDOW_SIZE as usize * 2 {
                self.buffered.insert(chunk_num, data.to_vec());
            }
            if self.expected_chunk > 0 {
                Ok((true, self.expected_chunk - 1))
            } else {
                Ok((false, 0))
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.transferred >= self.file_size
    }

    pub fn finalize(&mut self) -> Result<PathBuf> {
        self.file.flush()?;
        Ok(self.path.clone())
    }

    pub fn progress(&self) -> f32 {
        if self.file_size == 0 {
            100.0
        } else {
            (self.transferred as f32 / self.file_size as f32) * 100.0
        }
    }
}

// ============================================================================
// File transfer manager
// ============================================================================

pub struct FileTransferManager {
    pub shared: SharedFiles,
    pub sending: Option<FileSender>,
    pub receiving: Option<FileReceiver>,
    pub download_dir: PathBuf,
    pub remote_files: Vec<FileInfo>,
    existing_downloads: std::collections::HashSet<String>,
    pub transfer_in_progress: bool,

    // -- Approval system --
    auto_accept: bool,
    approval_timeout: Option<Duration>,
    pub pending_requests: Vec<PendingRequest>,
    next_request_id: RequestId,
}

impl FileTransferManager {
    pub fn default_download_dir() -> PathBuf {
        dirs::download_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("tunnel_downloads")
    }

    /// Create with default approval settings (require approval, 60s timeout).
    /// Use `with_approval` for explicit control.
    pub fn new(download_dir: PathBuf) -> Self {
        Self::with_approval(download_dir, false, Some(Duration::from_secs(60)))
    }

    /// Create with explicit approval settings.
    pub fn with_approval(
        download_dir: PathBuf,
        auto_accept: bool,
        approval_timeout: Option<Duration>,
    ) -> Self {
        let _ = fs::create_dir_all(&download_dir);

        let mut existing_downloads = std::collections::HashSet::new();
        if let Ok(entries) = fs::read_dir(&download_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    existing_downloads.insert(name.to_string());
                }
            }
        }

        Self {
            shared: SharedFiles::new(),
            sending: None,
            receiving: None,
            download_dir,
            remote_files: Vec::new(),
            existing_downloads,
            transfer_in_progress: false,
            auto_accept,
            approval_timeout,
            pending_requests: Vec::new(),
            next_request_id: 1,
        }
    }

    fn unique_filename(&self, name: &str) -> String {
        if !self.existing_downloads.contains(name) {
            return name.to_string();
        }

        let path = Path::new(name);
        let stem = path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| name.to_string());
        let ext = path.extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();

        for i in 1..1000 {
            let new_name = format!("{}_{}{}", stem, i, ext);
            if !self.existing_downloads.contains(&new_name) {
                return new_name;
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{}_{}{}", stem, timestamp, ext)
    }

    fn alloc_request_id(&mut self) -> RequestId {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    // ========================================================================
    // Packet constructors
    // ========================================================================

    pub fn create_list_request(&self, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::ListRequest as u8;
        1
    }

    pub fn create_list_response(&self, out: &mut [u8]) -> Result<usize> {
        let list_data = self.shared.encode_list()?;
        if 1 + list_data.len() > out.len() {
            bail!("shared file list too large for one datagram ({} bytes)", list_data.len());
        }
        out[0] = FilePacketType::ListResponse as u8;
        out[1..1 + list_data.len()].copy_from_slice(&list_data);
        Ok(1 + list_data.len())
    }

    pub fn create_download_request(&self, file_name: &str, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::DownloadRequest as u8;
        let name_bytes = file_name.as_bytes();
        out[1..3].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out[3..3 + name_bytes.len()].copy_from_slice(name_bytes);
        3 + name_bytes.len()
    }

    pub fn create_file_header(&self, info: &FileInfo, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileHeader as u8;
        let encoded = info.encode();
        out[1..1 + encoded.len()].copy_from_slice(&encoded);
        1 + encoded.len()
    }

    pub fn create_header_ack(&self, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileHeaderAck as u8;
        1
    }

    pub fn create_file_chunk(&self, chunk_num: u32, data: &[u8], out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileChunk as u8;
        out[1..5].copy_from_slice(&chunk_num.to_le_bytes());
        out[5..7].copy_from_slice(&(data.len() as u16).to_le_bytes());
        out[7..7 + data.len()].copy_from_slice(data);
        7 + data.len()
    }

    pub fn create_ack(&self, acked_chunk: u32, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileAck as u8;
        out[1..5].copy_from_slice(&acked_chunk.to_le_bytes());
        5
    }

    #[allow(dead_code)]
    pub fn create_file_complete(&self, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileComplete as u8;
        1
    }

    pub fn create_file_error(&self, message: &str, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::FileError as u8;
        let msg_bytes = message.as_bytes();
        let len = msg_bytes.len().min(200);
        out[1] = len as u8;
        out[2..2 + len].copy_from_slice(&msg_bytes[..len]);
        2 + len
    }

    fn create_download_pending(&self, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::DownloadPending as u8;
        1
    }

    fn create_download_denied(&self, reason: &str, out: &mut [u8]) -> usize {
        out[0] = FilePacketType::DownloadDenied as u8;
        let msg_bytes = reason.as_bytes();
        let len = msg_bytes.len().min(200);
        out[1] = len as u8;
        out[2..2 + len].copy_from_slice(&msg_bytes[..len]);
        2 + len
    }

    // ========================================================================
    // Approval API
    // ========================================================================

    /// Approve a pending transfer request.
    /// Returns a FileProcessResult containing the response packet to send.
    pub fn approve_request(&mut self, request_id: RequestId, out: &mut [u8]) -> Result<Option<FileProcessResult>> {
        let idx = self.pending_requests.iter().position(|r| r.id == request_id);
        let request = match idx {
            Some(i) => self.pending_requests.remove(i),
            None => bail!("No pending request with id {}", request_id),
        };

        match request.direction {
            TransferDirection::Upload => {
                // Peer requested our file — start sending now
                let path = request.local_path
                    .context("Missing local path for upload approval")?;
                let info = FileInfo::from_path(&path)?;
                self.sending = Some(FileSender::new(&path)?);
                self.transfer_in_progress = true;
                let len = self.create_file_header(&info, out);
                Ok(Some(FileProcessResult::SendResponse(len)))
            }
            TransferDirection::Download => {
                // Peer sent us a FileHeader — accept it now by sending HeaderAck
                let payload = request.header_payload
                    .context("Missing header payload for download approval")?;
                let (info, _) = FileInfo::decode(&payload)?;
                let safe = sanitize_filename(&info.name)?; // fail closed on a hostile name
                let unique_name = self.unique_filename(&safe);
                self.existing_downloads.insert(unique_name.clone());

                self.receiving = Some(FileReceiver::new(
                    unique_name.clone(),
                    info.size,
                    &self.download_dir,
                )?);
                self.transfer_in_progress = true;

                let len = self.create_header_ack(out);
                Ok(Some(FileProcessResult::SendResponseAndNotify(len, FileInfo {
                    name: unique_name,
                    size: info.size,
                    file_type: info.file_type,
                })))
            }
        }
    }

    /// Deny a pending transfer request. Returns response packet length.
    pub fn deny_request(&mut self, request_id: RequestId, out: &mut [u8]) -> Result<Option<usize>> {
        let idx = self.pending_requests.iter().position(|r| r.id == request_id);
        let request = match idx {
            Some(i) => self.pending_requests.remove(i),
            None => bail!("No pending request with id {}", request_id),
        };

        match request.direction {
            TransferDirection::Upload => {
                let len = self.create_download_denied("Transfer denied by user", out);
                Ok(Some(len))
            }
            TransferDirection::Download => {
                let len = self.create_file_error("Transfer denied by user", out);
                Ok(Some(len))
            }
        }
    }

    /// Expire pending requests that have exceeded the approval timeout.
    /// Returns list of (response_packet_len, expired_request_id).
    pub fn expire_pending_requests(&mut self, out: &mut [u8]) -> Vec<(usize, RequestId)> {
        let timeout = match self.approval_timeout {
            Some(t) => t,
            None => return Vec::new(),
        };

        let now = Instant::now();
        let expired_ids: Vec<RequestId> = self.pending_requests.iter()
            .filter(|r| now.duration_since(r.requested_at) >= timeout)
            .map(|r| r.id)
            .collect();

        let mut responses = Vec::new();
        for id in expired_ids {
            if let Ok(Some(len)) = self.deny_request(id, out) {
                responses.push((len, id));
            }
        }
        responses
    }

    // ========================================================================
    // Packet processing
    // ========================================================================

    pub fn process_packet(&mut self, data: &[u8], out: &mut [u8]) -> Result<FileProcessResult> {
        if data.is_empty() {
            bail!("Empty file packet");
        }

        let packet_type = FilePacketType::try_from(data[0])?;
        let payload = &data[1..];

        match packet_type {
            FilePacketType::ListRequest => {
                let len = self.create_list_response(out)?;
                Ok(FileProcessResult::SendResponse(len))
            }

            FilePacketType::ListResponse => {
                self.remote_files = SharedFiles::decode_list(payload)?;
                Ok(FileProcessResult::FileListReceived)
            }

            FilePacketType::DownloadRequest => {
                self.handle_download_request(payload, out)
            }

            FilePacketType::FileHeader => {
                self.handle_file_header(payload, out)
            }

            FilePacketType::FileHeaderAck => {
                if let Some(ref mut sender) = self.sending {
                    sender.header_acknowledged();
                    Ok(FileProcessResult::HeaderAcked)
                } else {
                    Ok(FileProcessResult::Ignored)
                }
            }

            FilePacketType::FileChunk => {
                if payload.len() < 6 {
                    bail!("Chunk packet too short");
                }
                let chunk_num = u32::from_le_bytes(payload[0..4].try_into()?);
                let data_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
                if payload.len() < 6 + data_len {
                    bail!("Chunk data truncated");
                }
                let chunk_data = &payload[6..6 + data_len];

                if let Some(ref mut receiver) = self.receiving {
                    let (should_ack, ack_num) = receiver.write_chunk(chunk_num, chunk_data)?;

                    if receiver.is_complete() {
                        let path = receiver.finalize()?;
                        let name = receiver.file_name.clone();
                        self.receiving = None;
                        self.transfer_in_progress = self.sending.is_some();

                        let len = self.create_ack(ack_num, out);
                        return Ok(FileProcessResult::TransferCompleteWithAck(len, name, path));
                    }

                    if should_ack {
                        let len = self.create_ack(ack_num, out);
                        Ok(FileProcessResult::SendResponse(len))
                    } else {
                        Ok(FileProcessResult::ChunkReceived(receiver.progress()))
                    }
                } else {
                    bail!("Received chunk but no transfer in progress")
                }
            }

            FilePacketType::FileAck => {
                if payload.len() < 4 {
                    bail!("ACK packet too short");
                }
                let acked_chunk = u32::from_le_bytes(payload[0..4].try_into()?);

                if let Some(ref mut sender) = self.sending {
                    sender.process_ack(acked_chunk);

                    if sender.is_complete() {
                        let name = sender.file_name.clone();
                        self.sending = None;
                        self.transfer_in_progress = self.receiving.is_some();
                        return Ok(FileProcessResult::SendComplete(name));
                    }

                    Ok(FileProcessResult::AckReceived(sender.progress()))
                } else {
                    Ok(FileProcessResult::Ignored)
                }
            }

            FilePacketType::FileComplete => {
                self.sending = None;
                self.transfer_in_progress = self.receiving.is_some();
                Ok(FileProcessResult::SendComplete(String::new()))
            }

            FilePacketType::FileError => {
                let msg_len = payload.first().copied().unwrap_or(0) as usize;
                let message = if payload.len() > 1 {
                    String::from_utf8_lossy(&payload[1..1 + msg_len.min(payload.len() - 1)]).to_string()
                } else {
                    String::from("Unknown error")
                };
                self.sending = None;
                self.receiving = None;
                self.transfer_in_progress = false;
                Ok(FileProcessResult::Error(message))
            }

            FilePacketType::DownloadPending => {
                Ok(FileProcessResult::DownloadPendingRemote)
            }

            FilePacketType::DownloadDenied => {
                let msg_len = payload.first().copied().unwrap_or(0) as usize;
                let message = if payload.len() > 1 {
                    String::from_utf8_lossy(&payload[1..1 + msg_len.min(payload.len() - 1)]).to_string()
                } else {
                    String::from("Denied")
                };
                Ok(FileProcessResult::DownloadDeniedRemote(message))
            }
        }
    }

    /// Peer wants to download one of our files.
    /// If auto_accept: serve immediately. Otherwise: queue for approval.
    fn handle_download_request(&mut self, payload: &[u8], out: &mut [u8]) -> Result<FileProcessResult> {
        if payload.len() < 2 {
            bail!("Download request too short");
        }
        let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + name_len {
            bail!("Download request name truncated");
        }
        let name = String::from_utf8_lossy(&payload[2..2 + name_len]).to_string();

        let path = match self.shared.get_path(&name) {
            Some(p) => p.clone(),
            None => {
                let len = self.create_file_error("File not found", out);
                return Ok(FileProcessResult::SendResponse(len));
            }
        };

        let info = FileInfo::from_path(&path)?;

        if self.auto_accept {
            self.sending = Some(FileSender::new(&path)?);
            self.transfer_in_progress = true;
            let len = self.create_file_header(&info, out);
            Ok(FileProcessResult::SendResponse(len))
        } else {
            let id = self.alloc_request_id();
            self.pending_requests.push(PendingRequest {
                id,
                direction: TransferDirection::Upload,
                file_name: info.name.clone(),
                file_size: info.size,
                file_type: info.file_type.clone(),
                requested_at: Instant::now(),
                local_path: Some(path),
                header_payload: None,
            });

            let len = self.create_download_pending(out);
            Ok(FileProcessResult::ApprovalRequired(len, id))
        }
    }

    /// Peer wants to send us a file.
    /// If auto_accept: send HeaderAck immediately. Otherwise: queue for approval.
    fn handle_file_header(&mut self, payload: &[u8], out: &mut [u8]) -> Result<FileProcessResult> {
        let (info, _) = FileInfo::decode(payload)?;

        // Fail closed on a hostile name before any state is created, and refuse
        // an over-large transfer up front instead of mid-stream.
        let safe = sanitize_filename(&info.name)?;
        if info.size > MAX_INBOUND_FILE_SIZE {
            let len = self.create_file_error("File exceeds size limit", out);
            return Ok(FileProcessResult::SendResponse(len));
        }

        if self.auto_accept {
            let unique_name = self.unique_filename(&safe);
            self.existing_downloads.insert(unique_name.clone());

            self.receiving = Some(FileReceiver::new(
                unique_name.clone(),
                info.size,
                &self.download_dir,
            )?);
            self.transfer_in_progress = true;

            let len = self.create_header_ack(out);
            Ok(FileProcessResult::SendResponseAndNotify(len, FileInfo {
                name: unique_name,
                size: info.size,
                file_type: info.file_type,
            }))
        } else {
            let id = self.alloc_request_id();
            self.pending_requests.push(PendingRequest {
                id,
                direction: TransferDirection::Download,
                // Display the sanitized name — the user approves exactly what lands.
                file_name: safe,
                file_size: info.size,
                file_type: info.file_type.clone(),
                requested_at: Instant::now(),
                local_path: None,
                header_payload: Some(payload.to_vec()),
            });

            // Don't send HeaderAck — sender waits until we approve
            Ok(FileProcessResult::ApprovalRequired(0, id))
        }
    }

    // ========================================================================
    // Outgoing packet generation
    // ========================================================================

    pub fn get_packets_to_send(&mut self, out: &mut [u8]) -> Result<Option<(usize, bool)>> {
        if let Some(ref mut sender) = self.sending {
            if sender.has_failed_chunks() {
                let len = self.create_file_error("Max retries exceeded", out);
                self.sending = None;
                self.transfer_in_progress = self.receiving.is_some();
                return Ok(Some((len, false)));
            }

            let retransmits = sender.get_retransmits();
            if let Some((chunk_num, data)) = retransmits.into_iter().next() {
                let len = self.create_file_chunk(chunk_num, &data, out);
                return Ok(Some((len, true)));
            }

            if let Some((chunk_num, data)) = sender.next_chunk()? {
                let len = self.create_file_chunk(chunk_num, &data, out);
                return Ok(Some((len, false)));
            }
        }

        Ok(None)
    }

    pub fn has_active_transfer(&self) -> bool {
        self.transfer_in_progress
    }

    pub fn transfer_progress(&self) -> Option<(String, f32, bool)> {
        if let Some(ref t) = self.sending {
            Some((t.file_name.clone(), t.progress(), true))
        } else if let Some(ref t) = self.receiving {
            Some((t.file_name.clone(), t.progress(), false))
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn cancel_transfer(&mut self) {
        self.sending = None;
        self.receiving = None;
        self.transfer_in_progress = false;
    }
}

// ============================================================================
// Process result
// ============================================================================

#[derive(Debug)]
pub enum FileProcessResult {
    /// Need to send a response packet of this length
    SendResponse(usize),
    /// Send response AND notify about transfer start
    SendResponseAndNotify(usize, FileInfo),
    /// Received updated file list from peer
    FileListReceived,
    /// Header was acknowledged, ready to send chunks
    HeaderAcked,
    /// Received a chunk, progress percentage
    ChunkReceived(f32),
    /// Received an ACK, progress percentage
    AckReceived(f32),
    /// Transfer complete with final ACK to send
    TransferCompleteWithAck(usize, String, PathBuf),
    /// Finished sending file
    SendComplete(String),
    /// Error occurred
    Error(String),
    /// Packet was ignored
    Ignored,
    /// Transfer requires local user approval before proceeding.
    /// (response_packet_len, request_id). Len may be 0 if no
    /// immediate wire response is needed (inbound file header case).
    ApprovalRequired(usize, RequestId),
    /// Remote side told us our download is pending their approval
    DownloadPendingRemote,
    /// Remote side denied our download request
    DownloadDeniedRemote(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_file_info_roundtrip() {
        let info = FileInfo {
            name: "test.txt".to_string(),
            size: 1234,
            file_type: "txt".to_string(),
        };

        let encoded = info.encode();
        let (decoded, _) = FileInfo::decode(&encoded).unwrap();

        assert_eq!(decoded.name, info.name);
        assert_eq!(decoded.size, info.size);
        assert_eq!(decoded.file_type, info.file_type);
    }

    #[test]
    fn test_sanitize_filename_rejects_hostile_names() {
        // Plain names pass through unchanged.
        assert_eq!(sanitize_filename("report.pdf").unwrap(), "report.pdf");
        assert_eq!(sanitize_filename("  spaced.txt  ").unwrap(), "spaced.txt");
        assert_eq!(sanitize_filename(".bashrc").unwrap(), ".bashrc"); // hidden, but stays in dir

        // Traversal / absolute / drive / ADS / device / control → rejected.
        for bad in [
            "",
            ".",
            "..",
            "../evil",
            "../../etc/passwd",
            "/etc/cron.d/x",
            "a/b",
            "..\\..\\evil",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "file.txt:hidden",
            "CON",
            "com1.txt",
            "nul",
            "trailingdot.",
            "trailing.dots..",
            "bad\u{0000}name",
            "bidi\u{202E}gpj.exe",
        ] {
            assert!(
                sanitize_filename(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn test_receiver_refuses_traversal() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");
        std::fs::create_dir_all(&dl_dir).unwrap();

        // Absolute and traversal names must never create a receiver.
        assert!(FileReceiver::new("../../escape".to_string(), 10, &dl_dir).is_err());
        assert!(FileReceiver::new("/tmp/pwn".to_string(), 10, &dl_dir).is_err());

        // A clean name lands inside the download dir.
        let r = FileReceiver::new("ok.bin".to_string(), 10, &dl_dir).unwrap();
        assert_eq!(r.path, dl_dir.join("ok.bin"));
        assert!(dl_dir.join("ok.bin").exists());
    }

    #[test]
    fn test_shared_files_list() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let mut shared = SharedFiles::new();
        shared.add(file_path).unwrap();

        let encoded = shared.encode_list().unwrap();
        let decoded = SharedFiles::decode_list(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "test.txt");
        assert_eq!(decoded[0].size, 11);
    }

    #[test]
    fn test_chunk_ack_flow() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(&vec![0xAB; 5000]).unwrap();
        }

        let mut sender = FileSender::new(&file_path).unwrap();

        assert!(sender.waiting_for_header_ack());
        assert!(!sender.can_send());

        sender.header_acknowledged();
        assert!(sender.can_send());

        let (chunk_num, data) = sender.next_chunk().unwrap().unwrap();
        assert_eq!(chunk_num, 0);
        assert!(!data.is_empty());

        sender.process_ack(0);
        assert!(sender.in_flight.is_empty() || !sender.in_flight.contains_key(&0));
    }

    #[test]
    fn test_auto_accept_serves_immediately() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");

        let file_path = dir.path().join("secret.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"secret data").unwrap();
        }

        let mut mgr = FileTransferManager::with_approval(dl_dir, true, None);
        mgr.shared.add(file_path).unwrap();

        let mut req_buf = [0u8; 256];
        let req_len = mgr.create_download_request("secret.txt", &mut req_buf);

        let mut out = [0u8; 1500];
        let result = mgr.process_packet(&req_buf[..req_len], &mut out).unwrap();

        match result {
            FileProcessResult::SendResponse(len) => {
                assert!(len > 0);
                assert_eq!(out[0], FilePacketType::FileHeader as u8);
            }
            other => panic!("Expected SendResponse, got {:?}", other),
        }
        assert!(mgr.sending.is_some());
        assert!(mgr.pending_requests.is_empty());
    }

    #[test]
    fn test_approval_required_blocks_download() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");

        let file_path = dir.path().join("secret.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"secret data").unwrap();
        }

        let mut mgr = FileTransferManager::with_approval(
            dl_dir, false, Some(Duration::from_secs(60)),
        );
        mgr.shared.add(file_path).unwrap();

        let mut req_buf = [0u8; 256];
        let req_len = mgr.create_download_request("secret.txt", &mut req_buf);

        let mut out = [0u8; 1500];
        let result = mgr.process_packet(&req_buf[..req_len], &mut out).unwrap();

        match result {
            FileProcessResult::ApprovalRequired(len, req_id) => {
                assert!(len > 0);
                assert_eq!(out[0], FilePacketType::DownloadPending as u8);
                assert_eq!(req_id, 1);
            }
            other => panic!("Expected ApprovalRequired, got {:?}", other),
        }
        assert!(mgr.sending.is_none());
        assert_eq!(mgr.pending_requests.len(), 1);
    }

    #[test]
    fn test_approve_then_send() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");

        let file_path = dir.path().join("secret.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"secret data").unwrap();
        }

        let mut mgr = FileTransferManager::with_approval(
            dl_dir, false, Some(Duration::from_secs(60)),
        );
        mgr.shared.add(file_path).unwrap();

        let mut req_buf = [0u8; 256];
        let req_len = mgr.create_download_request("secret.txt", &mut req_buf);
        let mut out = [0u8; 1500];
        let result = mgr.process_packet(&req_buf[..req_len], &mut out).unwrap();

        let req_id = match result {
            FileProcessResult::ApprovalRequired(_, id) => id,
            other => panic!("Expected ApprovalRequired, got {:?}", other),
        };

        // Approve it
        let result = mgr.approve_request(req_id, &mut out).unwrap().unwrap();
        match result {
            FileProcessResult::SendResponse(len) => {
                assert!(len > 0);
                assert_eq!(out[0], FilePacketType::FileHeader as u8);
            }
            other => panic!("Expected SendResponse after approval, got {:?}", other),
        }
        assert!(mgr.sending.is_some());
        assert!(mgr.pending_requests.is_empty());
    }

    #[test]
    fn test_deny_download_request() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");

        let file_path = dir.path().join("secret.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"secret data").unwrap();
        }

        let mut mgr = FileTransferManager::with_approval(
            dl_dir, false, Some(Duration::from_secs(60)),
        );
        mgr.shared.add(file_path).unwrap();

        let mut req_buf = [0u8; 256];
        let req_len = mgr.create_download_request("secret.txt", &mut req_buf);
        let mut out = [0u8; 1500];
        mgr.process_packet(&req_buf[..req_len], &mut out).unwrap();

        let req_id = mgr.pending_requests[0].id;
        let len = mgr.deny_request(req_id, &mut out).unwrap().unwrap();
        assert!(len > 0);
        assert_eq!(out[0], FilePacketType::DownloadDenied as u8);
        assert!(mgr.sending.is_none());
        assert!(mgr.pending_requests.is_empty());
    }

    #[test]
    fn test_approval_required_inbound_file() {
        let dir = tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");
        std::fs::create_dir_all(&dl_dir).unwrap();

        let mut mgr = FileTransferManager::with_approval(
            dl_dir, false, Some(Duration::from_secs(60)),
        );

        let info = FileInfo {
            name: "surprise.exe".to_string(),
            size: 999999,
            file_type: "exe".to_string(),
        };
        let mut header_buf = [0u8; 256];
        let header_len = mgr.create_file_header(&info, &mut header_buf);

        let mut out = [0u8; 1500];
        let result = mgr.process_packet(&header_buf[..header_len], &mut out).unwrap();

        match result {
            FileProcessResult::ApprovalRequired(len, req_id) => {
                assert_eq!(len, 0); // No wire response yet
                assert_eq!(req_id, 1);
            }
            other => panic!("Expected ApprovalRequired, got {:?}", other),
        }
        assert!(mgr.receiving.is_none());
        assert_eq!(mgr.pending_requests.len(), 1);
        assert_eq!(mgr.pending_requests[0].file_name, "surprise.exe");
    }
}