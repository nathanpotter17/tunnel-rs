//! Minimal P0 configuration.
//!
//! P0 has no routing rules or outbounds to configure yet — just the TUN address
//! (default in the RFC 2544 benchmarking range to avoid colliding with home/office
//! LANs) and the MTU. Loaded from a TOML file if present, otherwise defaults.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::{info, warn};

use crate::crypto;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// This host's address on the TUN (the transparent-proxy virtual interface).
    pub tun_ip: Ipv4Addr,
    /// TUN subnet prefix length. /15 spans 198.18.0.0–198.19.255.255.
    pub tun_prefix: u8,
    /// TUN MTU. Leave headroom under 1500 for whatever the real path needs.
    pub mtu: u16,
    /// Resolver forced onto the TUN while full-tunnel is active, so DNS travels
    /// through the tunnel (no leak to a LAN resolver that the exit can't reach).
    pub dns: Ipv4Addr,
    /// Optional WireGuard exit (BYO, e.g. Proton). When present, all traffic
    /// egresses through it; otherwise it goes out the host's uplink (Direct).
    pub wireguard: Option<WgSettings>,
    /// Optional file-sharing identity. Absent → the engine runs normally and
    /// file sharing is OFF. Create one with `tunnel.exe keygen` and paste the
    /// printed `[identity]` section into this file.
    pub identity: Option<Identity>,
}

/// The file-sharing identity: a static X25519 private key. Only the encrypted
/// file channel needs it — the VPN engine does not.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Base64 X25519 private key, as printed by `tunnel.exe keygen`.
    pub private_key: String,
}

impl Identity {
    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        let bytes = BASE64
            .decode(&self.private_key)
            .context("invalid base64 in [identity] private_key")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("[identity] private_key must decode to 32 bytes"))
    }

    pub fn public_key(&self) -> Result<String> {
        Ok(crypto::Keypair::from_private(self.private_key_bytes()?).public_key_base64())
    }
}

/// A WireGuard peer (wg-quick fields). Keys are base64 as in `.conf` files.
/// Unknown fields are fatal parse errors, never silently ignored — a misnamed
/// section or key once ran the engine as Direct while the WG config sat unread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgSettings {
    /// Our client private key (Interface.PrivateKey).
    pub private_key: String,
    /// The server's public key (Peer.PublicKey).
    pub public_key: String,
    /// The server endpoint host:port (Peer.Endpoint).
    pub endpoint: String,
    /// Our address on the WG network (Interface.Address, e.g. "10.2.0.2").
    pub address: String,
    /// Optional preshared key (Peer.PresharedKey).
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Persistent keepalive seconds (0 = off).
    #[serde(default = "default_wg_keepalive")]
    pub persistent_keepalive: u16,
}

fn default_wg_keepalive() -> u16 {
    25
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tun_ip: Ipv4Addr::new(198, 18, 0, 1),
            tun_prefix: 15,
            mtu: 1400,
            dns: Ipv4Addr::new(1, 1, 1, 1),
            wireguard: None,
            identity: None,
        }
    }
}

impl Settings {
    /// Load from `path` if it exists; otherwise return defaults. Either way,
    /// says so out loud — a silent default once ran the engine as Direct with
    /// DNS 1.1.1.1 while the user's real WireGuard config sat unread.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            warn!(
                "settings file {} not found — running on BUILT-IN DEFAULTS \
                 (exit: Direct, dns: 1.1.1.1, mtu: 1400). Pass your settings \
                 file explicitly: tunnel.exe <path>.toml",
                path.display()
            );
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read settings: {}", path.display()))?;
        let s: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse settings: {}", path.display()))?;
        info!(
            "settings loaded from {} — exit: {}, dns: {}, mtu: {}, tun: {}/{}, file sharing: {}",
            path.display(),
            match &s.wireguard {
                Some(wg) => format!("WireGuard → {}", wg.endpoint),
                None => "Direct".to_string(),
            },
            s.dns,
            s.mtu,
            s.tun_ip,
            s.tun_prefix,
            if s.identity.is_some() { "on" } else { "off (no [identity])" },
        );
        Ok(s)
    }
}

/// Write a starter settings file with a fresh file-sharing identity, the
/// engine defaults spelled out, and a commented [wireguard] template.
/// Refuses to overwrite an existing file.
pub fn init_config(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("settings file already exists at {}", path.display());
    }
    let keypair = crypto::Keypair::generate()?;
    let content = format!(
        r#"# tunnel settings — one file for everything.

tun_ip = "198.18.0.1"   # our address on the TUN (RFC 2544 range, avoids LAN clashes)
tun_prefix = 15
mtu = 1400
dns = "1.1.1.1"         # resolver forced onto the TUN under full-tunnel; must be
                        # reachable via your exit (Proton's is 10.2.0.1)

# File-sharing identity (generated for you). Delete this section to disable
# file sharing; regenerate with `tunnel.exe keygen`.
[identity]
private_key = "{}"
# your public key (share with peers): {}

# Optional WireGuard exit (BYO VPN, e.g. ProtonVPN). Uncomment and fill in
# from your provider's WireGuard .conf:
#   [Interface] PrivateKey   -> private_key
#   [Interface] Address      -> address (drop the "/32")
#   [Peer]      PublicKey    -> public_key
#   [Peer]      Endpoint     -> endpoint
#   [Peer]      PresharedKey -> preshared_key (if present)
# [wireguard]
# private_key = "AAAA...=="
# public_key  = "BBBB...=="
# endpoint    = "203.0.113.10:51820"
# address     = "10.2.0.2"
# preshared_key = "CCCC...=="
# persistent_keepalive = 25
"#,
        keypair.private_key_base64(),
        keypair.public_key_base64(),
    );
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, content)?;
    println!("Settings created at: {}", path.display());
    println!("Your public key: {}", keypair.public_key_base64());
    Ok(())
}
