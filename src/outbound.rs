//! The outbound seam.
//!
//! An `Outbound` is "how a captured flow reaches the outside world." Because some
//! outbounds (WireGuard) don't produce OS sockets, `connect_tcp` returns a boxed
//! async stream and `bind_udp` returns a boxed datagram conn — so `Direct` (real
//! pinned sockets) and `WireGuard` (channel-bridged inner smoltcp) share one API.
//! Chaining later is just an outbound whose dialer is another `Outbound`.

use anyhow::Result;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

use crate::pin::{self, EgressPin};

/// A bidirectional byte stream (TCP-like).
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncStream for T {}

/// A connected datagram conn (UDP-like), already targeting a fixed destination.
#[async_trait]
pub trait UdpConn: Send + Sync {
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait Outbound: Send + Sync {
    /// Open a byte stream to `dst`.
    async fn connect_tcp(&self, dst: SocketAddr) -> Result<Box<dyn AsyncStream>>;
    /// Open a datagram conn to `dst`.
    async fn bind_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpConn>>;
    /// Human-readable label for observability.
    #[allow(dead_code)]
    fn name(&self) -> &str;
}

/// Forward straight to the destination over the host's real uplink, with the
/// egress socket pinned so it doesn't loop back into our TUN.
pub struct Direct {
    egress: EgressPin,
}

impl Direct {
    pub fn new(egress: EgressPin) -> Self {
        Self { egress }
    }
}

#[async_trait]
impl Outbound for Direct {
    async fn connect_tcp(&self, dst: SocketAddr) -> Result<Box<dyn AsyncStream>> {
        let stream = pin::connect_tcp(dst, &self.egress).await?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpConn>> {
        let sock = pin::bind_udp(dst, &self.egress).await?;
        sock.connect(dst).await?;
        Ok(Box::new(DirectUdp(sock)))
    }

    fn name(&self) -> &str {
        "direct"
    }
}

struct DirectUdp(UdpSocket);

#[async_trait]
impl UdpConn for DirectUdp {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf).await
    }
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
}
