//! Engine configuration — one TOML file.
//!
//! The TUN address (default in the RFC 2544 benchmarking range to avoid
//! colliding with home/office LANs), the MTU, the resolver pinned to the tunnel
//! under full capture, and an optional WireGuard exit. Loaded from a TOML file
//! if present, otherwise defaults.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// This host's address on the TUN (the transparent-proxy virtual interface).
    pub tun_ip: Ipv4Addr,
    /// TUN subnet prefix length. /15 spans 198.18.0.0–198.19.255.255.
    pub tun_prefix: u8,
    /// TUN MTU. This is what the host derives its TCP MSS from, so under a
    /// WireGuard exit it sets the payload size end to end: leave headroom under
    /// 1500 for the encapsulation (32 WireGuard + 8 UDP + 20 IP = 60 bytes) and
    /// for whatever the real path needs beyond that.
    pub mtu: u16,
    /// Resolver forced onto the TUN while full-tunnel is active, so DNS travels
    /// through the tunnel (no leak to a LAN resolver that the exit can't reach).
    pub dns: Ipv4Addr,
    /// Optional WireGuard exit (BYO, e.g. Proton). When present, all traffic
    /// egresses through it; otherwise it goes out the host's uplink (Direct).
    pub wireguard: Option<WgSettings>,
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
    /// How an inbound port is obtained, if one is wanted at all. Absent (the
    /// default) is outbound-only, which is what any NAT does; present opens
    /// exactly one port and nothing else.
    ///
    /// It lives here rather than on `Settings` because it is meaningless without
    /// a remote exit — under Direct there is no provider forwarding anything and
    /// no address a peer could dial. On the WireGuard section, that is
    /// unconfigurable rather than a runtime error.
    #[serde(default)]
    pub port_forward: Option<PortForward>,
}

/// Where the forwarded port comes from.
///
/// Written as one field with two shapes rather than two fields, because
/// `port_forward` and `forward_port` side by side would be a misreading waiting
/// to happen — and the two are mutually exclusive, which a single field states
/// and a pair of them only documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortForward {
    /// `port_forward = 51413` — a port the provider assigned out of band and
    /// holds indefinitely. Rare. Most providers lease, including Proton, where a
    /// number pasted in here forwards nothing at all.
    Fixed(u16),
    /// `port_forward = "nat-pmp"` — leased from the exit gateway and renewed for
    /// the life of the session.
    Leased(Method),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    NatPmp,
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
            "settings loaded from {} — exit: {}, dns: {}, mtu: {}, tun: {}/{}",
            path.display(),
            match &s.wireguard {
                Some(wg) => format!("WireGuard → {}", wg.endpoint),
                None => "Direct".to_string(),
            },
            s.dns,
            s.mtu,
            s.tun_ip,
            s.tun_prefix,
        );
        Ok(s)
    }
}

/// Write a starter settings file with the engine defaults spelled out and a
/// commented [wireguard] template. Refuses to overwrite an existing file.
pub fn init_config(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("settings file already exists at {}", path.display());
    }
    let content = r#"# tunnel settings — one file for everything.

tun_ip = "198.18.0.1"   # our address on the TUN (RFC 2544 range, avoids LAN clashes)
tun_prefix = 15
mtu = 1400
dns = "1.1.1.1"         # resolver pinned to the TUN under full-tunnel; must be
                        # reachable via your exit (Proton's is 10.2.0.1)

# Optional WireGuard exit (BYO VPN, e.g. ProtonVPN). Uncomment and fill in from
# your provider's WireGuard .conf. It is a pure CLIENT config: the endpoint
# socket is outbound-initiated from an ephemeral port, so NO router port
# forwarding is required on your side.
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
#
# Inbound port forwarding (optional). Without it the tunnel is outbound-only,
# which is what any NAT is: peers cannot open connections TO you.
#
#   port_forward = "nat-pmp"   lease a port from the exit gateway and keep
#                              renewing it. This is what Proton does — generate
#                              the WireGuard config with NAT-PMP enabled, and
#                              the port is negotiated at runtime. There is no
#                              port number to copy from anywhere.
#   port_forward = 51413       a port the provider assigned out of band and holds
#                              indefinitely. Rare. On Proton this forwards
#                              nothing: their ports are always leases.
#
# The port is the same number on both sides, so set your application to listen on
# it (qBittorrent: Connection -> Listening Port, UPnP/NAT-PMP left OFF — this
# engine does the leasing). The dashboard header shows the port and a count of
# packets that have actually arrived on it; a count stuck at zero means the
# forward is not live, whatever the port says.
#
# You will also need a Windows Firewall inbound rule for your application on the
# tunnel adapter's profile — packets reach the engine and are dropped after it
# otherwise, which reads as a working forward with no peers.
# port_forward = "nat-pmp"
"#;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, content)?;
    println!("Settings created at: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg_with(line: &str) -> Result<Settings, toml::de::Error> {
        toml::from_str(&format!(
            r#"
            [wireguard]
            private_key = "aaaa"
            public_key = "bbbb"
            endpoint = "203.0.113.10:51820"
            address = "10.2.0.2"
            {line}
            "#
        ))
    }

    fn forward_of(s: &Settings) -> Option<PortForward> {
        s.wireguard.as_ref().and_then(|w| w.port_forward)
    }

    #[test]
    fn port_forward_reads_both_of_its_shapes() {
        // An untagged enum silently picks the first variant that fits, so which
        // TOML scalar lands on which arm is worth stating rather than assuming.
        assert_eq!(
            forward_of(&wg_with(r#"port_forward = "nat-pmp""#).unwrap()),
            Some(PortForward::Leased(Method::NatPmp))
        );
        assert_eq!(
            forward_of(&wg_with("port_forward = 51413").unwrap()),
            Some(PortForward::Fixed(51413))
        );
        // Absent is outbound-only, which is the default a NAT gives you.
        assert_eq!(forward_of(&wg_with("").unwrap()), None);
    }

    #[test]
    fn a_misspelled_port_forward_is_refused_rather_than_ignored() {
        // The failure mode this guards is the expensive one: a config that parses
        // and quietly forwards nothing looks exactly like a provider outage, and
        // this whole feature is unobservable until a peer tries to connect.
        for bad in [
            r#"port_forward = "natpmp""#,
            r#"port_forward = "nat_pmp""#,
            r#"port_forward = "NAT-PMP""#,
            r#"port_forward = "upnp""#,
            "port_forward = true",
            "port_forward = 70000",
            "port_forward = -1",
        ] {
            assert!(wg_with(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn the_starter_config_this_ships_actually_parses() {
        // The template is a literal, so nothing else would catch a typo in it,
        // and it is the first thing a new user runs.
        let dir = std::env::temp_dir().join(format!("tunnel-cfg-{}", std::process::id()));
        let path = dir.join("tunnel.toml");
        let _ = std::fs::remove_dir_all(&dir);
        init_config(&path).unwrap();
        let parsed = Settings::load_or_default(&path).unwrap();
        assert_eq!(parsed.tun_ip, Settings::default().tun_ip);
        assert!(parsed.wireguard.is_none(), "the template's [wireguard] is commented out");
        // Refuses to clobber an existing file.
        assert!(init_config(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
