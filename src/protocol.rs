//! Wire framing for the file-transfer peer channel.
//!
//! The engine (smoltcp) is the data path; this protocol carries only the file
//! sub-protocol over a dedicated Noise channel. No IP data frame, no rekey
//! (file sessions are short-lived). Handshake datagrams are raw Noise messages,
//! disambiguated by connection state, so they carry no tag byte.

use anyhow::{bail, Result};

/// Tag byte prefixing a transport-mode datagram: `[tag:1][nonce:8][ciphertext]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Keepalive (empty encrypted payload).
    Keepalive = 0x01,
    /// Graceful disconnect.
    Disconnect = 0x05,
    /// File-transfer frame (subtypes handled by FileTransferManager).
    FileTransfer = 0x06,
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(PacketType::Keepalive),
            0x05 => Ok(PacketType::Disconnect),
            0x06 => Ok(PacketType::FileTransfer),
            _ => bail!("Unknown packet type: 0x{:02x}", value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_types_roundtrip() {
        assert_eq!(PacketType::try_from(0x01).unwrap(), PacketType::Keepalive);
        assert_eq!(PacketType::try_from(0x05).unwrap(), PacketType::Disconnect);
        assert_eq!(PacketType::try_from(0x06).unwrap(), PacketType::FileTransfer);
        assert!(PacketType::try_from(0x00).is_err()); // old Data frame gone
        assert!(PacketType::try_from(0x02).is_err()); // old RekeyInit gone
    }
}