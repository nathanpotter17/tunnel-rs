//! Cryptographic primitives for the tunnel.
//!
//! Uses the Noise IK protocol pattern with X25519 key exchange and
//! ChaCha20-Poly1305 encryption. The `snow` crate handles the Noise
//! protocol, while `x25519-dalek` is used solely for deriving public
//! keys from private keys (which snow doesn't expose directly).
//!
//! # UDP Safety
//!
//! This module uses `StatelessTransportState` with explicit nonces to
//! handle UDP packet loss and reordering. Each packet includes its
//! nonce, so lost packets don't break the session.
//!
//! # Concurrency
//!
//! `CryptoSession::encrypt` and `decrypt` take `&self` (not `&mut self`)
//! because `StatelessTransportState` methods take `&self` and all internal
//! counters are atomic. This allows concurrent encrypt/decrypt from
//! different tasks without a write lock.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

/// Anti-replay window width in packets (reorder tolerance).
const REPLAY_WINDOW: u64 = 1024;
const REPLAY_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// RFC 6479-style sliding-window replay filter over the 64-bit packet nonce.
/// Tracks WHICH nonces within the window were already accepted — not just the
/// high-water-mark — so a captured authentic frame cannot be re-injected.
struct ReplayWindow {
    highest: u64,
    seen: [u64; REPLAY_WORDS],
    started: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self { highest: 0, seen: [0; REPLAY_WORDS], started: false }
    }

    #[inline]
    fn slot(nonce: u64) -> (usize, u64) {
        let s = nonce % REPLAY_WINDOW;
        ((s / 64) as usize, s % 64)
    }
    #[inline]
    fn set(&mut self, nonce: u64) {
        let (w, b) = Self::slot(nonce);
        self.seen[w] |= 1 << b;
    }
    #[inline]
    fn clear(&mut self, nonce: u64) {
        let (w, b) = Self::slot(nonce);
        self.seen[w] &= !(1 << b);
    }
    #[inline]
    fn is_set(&self, nonce: u64) -> bool {
        let (w, b) = Self::slot(nonce);
        self.seen[w] & (1 << b) != 0
    }

    /// Fresh nonce → record and Ok. Replayed or too-old → Err.
    /// Call only AFTER the frame authenticates, so a forged high nonce cannot
    /// advance the window and lock out real packets.
    fn check_and_set(&mut self, nonce: u64) -> Result<()> {
        if !self.started {
            self.started = true;
            self.highest = nonce;
            self.set(nonce);
            return Ok(());
        }
        if nonce > self.highest {
            let shift = nonce - self.highest;
            if shift >= REPLAY_WINDOW {
                self.seen = [0; REPLAY_WORDS];
            } else {
                // Clear slots scrolled into view before marking the new top.
                for n in (self.highest + 1)..=nonce {
                    self.clear(n);
                }
            }
            self.highest = nonce;
            self.set(nonce);
            Ok(())
        } else {
            if self.highest - nonce >= REPLAY_WINDOW {
                anyhow::bail!("Nonce too old (outside replay window)");
            }
            if self.is_set(nonce) {
                anyhow::bail!("Nonce replayed");
            }
            self.set(nonce);
            Ok(())
        }
    }
}

/// Noise protocol pattern: IK provides mutual authentication
/// - Initiator knows responder's static key beforehand
/// - Responder learns initiator's static key during handshake
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Maximum packet size (MTU + encryption overhead)
pub const MAX_PACKET_SIZE: usize = 1500;

/// Nonce size in bytes (u64)
pub const NONCE_SIZE: usize = 8;

/// X25519 keypair for identity and encryption.
pub struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;

        Ok(Self {
            private: keypair.private.try_into().expect("key size"),
            public: keypair.public.try_into().expect("key size"),
        })
    }

    /// Reconstruct keypair from a private key.
    ///
    /// Uses x25519-dalek to derive the public key since snow doesn't
    /// expose this functionality directly.
    pub fn from_private(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret);
        Self {
            private,
            public: *public.as_bytes(),
        }
    }

    pub fn private_key_base64(&self) -> String {
        BASE64.encode(self.private)
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public)
    }

    /// Decode a public key from base64.
    pub fn decode_public_key(encoded: &str) -> Result<[u8; 32]> {
        let bytes = BASE64
            .decode(encoded)
            .context("Invalid base64 in public key")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))
    }
}

/// Generate and print a new keypair to stdout.
pub fn generate_keypair() -> Result<()> {
    let keypair = Keypair::generate()?;

    println!("Private key: {}", keypair.private_key_base64());
    println!("Public key:  {}", keypair.public_key_base64());
    println!();
    println!("Add to tunnel.toml:");
    println!("[identity]");
    println!("private_key = \"{}\"", keypair.private_key_base64());

    Ok(())
}

/// Encrypted session state with explicit nonces for UDP safety.
///
/// Uses `StatelessTransportState` which requires explicit nonces for
/// each encrypt/decrypt operation, making it safe for lossy transports
/// like UDP where packets can be lost or reordered.
///
/// All methods take `&self` — safe for concurrent use from multiple
/// tasks because:
/// - `StatelessTransportState::write_message/read_message` take `&self`
/// - All counters are `AtomicU64`
pub struct CryptoSession {
    transport: StatelessTransportState,
    /// Next nonce to use for sending (atomically incremented)
    send_nonce: AtomicU64,
    /// Sliding-window replay filter (interior-mutable; decrypt stays &self).
    replay: Mutex<ReplayWindow>,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    /// Remote peer's static public key (learned during handshake)
    remote_static: Option<[u8; 32]>,
}

impl CryptoSession {
    pub fn new(
        transport: StatelessTransportState,
        remote_static: Option<[u8; 32]>,
    ) -> Self {
        Self {
            transport,
            send_nonce: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            remote_static,
        }
    }

    /// Encrypt plaintext with explicit nonce.
    /// Output format: [nonce:8][ciphertext]
    /// Returns total length written to out.
    ///
    /// Takes `&self` — safe for concurrent use. The nonce is atomically
    /// incremented, and `StatelessTransportState::write_message` is
    /// internally thread-safe.
    pub fn encrypt(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        // Relaxed: single logical writer (nonce uniqueness guaranteed by
        // atomic increment), no cross-field ordering requirements.
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);

        // Write nonce first
        out[..NONCE_SIZE].copy_from_slice(&nonce.to_le_bytes());

        // Encrypt with explicit nonce
        let len = self
            .transport
            .write_message(nonce, plaintext, &mut out[NONCE_SIZE..])
            .context("Encryption failed")?;

        let total = NONCE_SIZE + len;
        self.bytes_sent.fetch_add(total as u64, Ordering::Relaxed);
        Ok(total)
    }

    /// Decrypt ciphertext with explicit nonce.
    /// Input format: [nonce:8][ciphertext]
    /// Returns plaintext length.
    ///
    /// Takes `&self` — safe for concurrent use. Replay protection is an
    /// RFC 6479 sliding-window bitmap (`ReplayWindow`) behind a `Mutex`: each
    /// nonce is accepted at most once within a 1024-packet reorder window.
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
        if ciphertext.len() < NONCE_SIZE {
            anyhow::bail!("Ciphertext too short for nonce");
        }

        // Extract nonce
        let nonce = u64::from_le_bytes(ciphertext[..NONCE_SIZE].try_into().unwrap());
        let encrypted = &ciphertext[NONCE_SIZE..];

        // Authenticate FIRST. A forged nonce fails the AEAD tag here and never
        // reaches the replay window, so it cannot poison it and lock out real
        // packets.
        let len = self
            .transport
            .read_message(nonce, encrypted, out)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        // Only authentic frames update the window; a replayed authentic frame is
        // decrypted but rejected here before delivery.
        self.replay
            .lock()
            .unwrap()
            .check_and_set(nonce)?;

        self.bytes_received
            .fetch_add(ciphertext.len() as u64, Ordering::Relaxed);
        Ok(len)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed) + self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn needs_rekey(&self, max_bytes: u64) -> bool {
        self.total_bytes() >= max_bytes
    }

    pub fn remote_static_key(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }

    /// Get the current send nonce (for debugging/stats)
    #[allow(dead_code)]
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce.load(Ordering::Relaxed)
    }
}

/// Builder for creating Noise handshake states.
pub struct HandshakeBuilder {
    local_private: [u8; 32],
    remote_public: Option<[u8; 32]>,
}

impl HandshakeBuilder {
    pub fn new(local_private: [u8; 32]) -> Self {
        Self {
            local_private,
            remote_public: None,
        }
    }

    pub fn with_remote_public(mut self, key: [u8; 32]) -> Self {
        self.remote_public = Some(key);
        self
    }

    /// Build initiator handshake state (client side).
    pub fn build_initiator(&self) -> Result<HandshakeState> {
        let remote = self
            .remote_public
            .context("Remote public key required for initiator")?;

        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&self.local_private)
            .remote_public_key(&remote)
            .build_initiator()
            .context("Failed to build initiator")
    }

    /// Build responder handshake state (server side).
    pub fn build_responder(&self) -> Result<HandshakeState> {
        Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&self.local_private)
            .build_responder()
            .context("Failed to build responder")
    }
}

/// Start server-side handshake, returns state and response message.
pub fn server_handshake_start(
    local_private: [u8; 32],
    initial_message: &[u8],
) -> Result<(HandshakeState, Vec<u8>)> {
    let builder = HandshakeBuilder::new(local_private);
    let mut noise = builder.build_responder()?;

    let mut payload = vec![0u8; MAX_PACKET_SIZE];

    // <- e, es, s, ss
    noise.read_message(initial_message, &mut payload)?;

    // -> e, ee, se
    let mut response = vec![0u8; MAX_PACKET_SIZE];
    let len = noise.write_message(&[], &mut response)?;
    response.truncate(len);

    Ok((noise, response))
}

/// Complete server-side handshake, returns crypto session.
pub fn server_handshake_finish(noise: HandshakeState) -> Result<CryptoSession> {
    let remote_static = noise.get_remote_static().and_then(|k| k.try_into().ok());

    // Use stateless transport mode for UDP safety
    let transport = noise
        .into_stateless_transport_mode()
        .context("Failed to enter stateless transport mode")?;

    Ok(CryptoSession::new(transport, remote_static))
}

/// Complete client-side handshake after receiving response.
pub fn client_handshake_finish(
    noise: HandshakeState,
    remote_public: [u8; 32],
) -> Result<CryptoSession> {
    let transport = noise
        .into_stateless_transport_mode()
        .context("Failed to enter stateless transport mode")?;

    Ok(CryptoSession::new(transport, Some(remote_public)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = Keypair::generate().unwrap();
        let recovered = Keypair::from_private(keypair.private);
        assert_eq!(keypair.public, recovered.public);
    }

    #[test]
    fn test_decode_public_key() {
        let keypair = Keypair::generate().unwrap();
        let encoded = keypair.public_key_base64();
        let decoded = Keypair::decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, keypair.public);
    }

    #[test]
    fn test_stateless_encrypt_decrypt() {
        let (priv1, pub1) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };
        let (priv2, pub2) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };

        // Client handshake
        let builder = HandshakeBuilder::new(priv1).with_remote_public(pub2);
        let mut client = builder.build_initiator().unwrap();

        // Server handshake
        let builder = HandshakeBuilder::new(priv2);
        let mut server = builder.build_responder().unwrap();

        // Handshake messages
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let len = client.write_message(&[], &mut buf).unwrap();

        let mut tmp = vec![0u8; MAX_PACKET_SIZE];
        server.read_message(&buf[..len], &mut tmp).unwrap();

        let len = server.write_message(&[], &mut buf).unwrap();
        client.read_message(&buf[..len], &mut tmp).unwrap();

        // Convert to stateless transport
        let client_session = CryptoSession::new(
            client.into_stateless_transport_mode().unwrap(),
            Some(pub2),
        );
        let server_session = CryptoSession::new(
            server.into_stateless_transport_mode().unwrap(),
            Some(pub1),
        );

        // Test encrypt/decrypt (now using &self)
        let plaintext = b"Hello, World!";
        let mut ciphertext = vec![0u8; 256];
        let mut decrypted = vec![0u8; 256];

        let enc_len = client_session.encrypt(plaintext, &mut ciphertext).unwrap();
        let dec_len = server_session
            .decrypt(&ciphertext[..enc_len], &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..dec_len], plaintext);

        // Test other direction
        let enc_len = server_session.encrypt(plaintext, &mut ciphertext).unwrap();
        let dec_len = client_session
            .decrypt(&ciphertext[..enc_len], &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..dec_len], plaintext);
    }

    #[test]
    fn test_replay_is_rejected() {
        let (priv1, pub1) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };
        let (priv2, pub2) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };

        let builder = HandshakeBuilder::new(priv1).with_remote_public(pub2);
        let mut client = builder.build_initiator().unwrap();
        let builder = HandshakeBuilder::new(priv2);
        let mut server = builder.build_responder().unwrap();

        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let len = client.write_message(&[], &mut buf).unwrap();
        let mut tmp = vec![0u8; MAX_PACKET_SIZE];
        server.read_message(&buf[..len], &mut tmp).unwrap();
        let len = server.write_message(&[], &mut buf).unwrap();
        client.read_message(&buf[..len], &mut tmp).unwrap();

        let client_session =
            CryptoSession::new(client.into_stateless_transport_mode().unwrap(), Some(pub2));
        let server_session =
            CryptoSession::new(server.into_stateless_transport_mode().unwrap(), Some(pub1));

        let mut ct = vec![0u8; 256];
        let mut pt = vec![0u8; 256];
        let n = client_session.encrypt(b"once", &mut ct).unwrap();

        // First delivery accepted.
        assert!(server_session.decrypt(&ct[..n], &mut pt).is_ok());
        // Exact replay of the same authentic frame is rejected.
        assert!(server_session.decrypt(&ct[..n], &mut pt).is_err());
    }

    #[test]
    fn test_replay_window_edges() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0).is_ok());
        assert!(w.check_and_set(0).is_err()); // immediate replay of first
        assert!(w.check_and_set(5).is_ok());
        assert!(w.check_and_set(3).is_ok()); // in-window, unseen
        assert!(w.check_and_set(3).is_err()); // in-window, replay
        assert!(w.check_and_set(5).is_err()); // replay of current top
        // Advance far, then an ancient nonce is outside the window.
        assert!(w.check_and_set(5000).is_ok());
        assert!(w.check_and_set(100).is_err());
    }

    #[test]
    fn test_out_of_order_packets() {
        // Setup two sessions
        let (priv1, pub1) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };
        let (priv2, pub2) = {
            let kp = Keypair::generate().unwrap();
            (kp.private, kp.public)
        };

        let builder = HandshakeBuilder::new(priv1).with_remote_public(pub2);
        let mut client = builder.build_initiator().unwrap();
        let builder = HandshakeBuilder::new(priv2);
        let mut server = builder.build_responder().unwrap();

        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let len = client.write_message(&[], &mut buf).unwrap();
        let mut tmp = vec![0u8; MAX_PACKET_SIZE];
        server.read_message(&buf[..len], &mut tmp).unwrap();
        let len = server.write_message(&[], &mut buf).unwrap();
        client.read_message(&buf[..len], &mut tmp).unwrap();

        let client_session = CryptoSession::new(
            client.into_stateless_transport_mode().unwrap(),
            Some(pub2),
        );
        let server_session = CryptoSession::new(
            server.into_stateless_transport_mode().unwrap(),
            Some(pub1),
        );

        // Encrypt 3 packets
        let mut packets = Vec::new();
        for i in 0..3 {
            let msg = format!("Message {}", i);
            let mut ct = vec![0u8; 256];
            let len = client_session.encrypt(msg.as_bytes(), &mut ct).unwrap();
            ct.truncate(len);
            packets.push(ct);
        }

        // Decrypt out of order: 2, 0, 1
        let mut decrypted = vec![0u8; 256];

        let len = server_session
            .decrypt(&packets[2], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..len], b"Message 2");

        let len = server_session
            .decrypt(&packets[0], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..len], b"Message 0");

        let len = server_session
            .decrypt(&packets[1], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..len], b"Message 1");
    }
}