//! smoltcp `Device` fed by an inject queue, emitting into an owned outbound queue.
//!
//! The engine drains packets from the TUN, peeks them (to open new flows), then
//! `inject`s them here for smoltcp to consume on the next poll. Packets smoltcp
//! emits are pushed into `outbound`; the engine drains that queue after each poll
//! and writes it to the TUN with an *awaited* send — lossless, with real
//! backpressure. No channels, no per-packet Arc clones, no silent drops.

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::collections::VecDeque;

pub struct TunDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TunDevice {
    pub fn new(mtu: usize) -> Self {
        Self { inbound: VecDeque::new(), outbound: VecDeque::new(), mtu }
    }

    /// Queue a packet (read from the TUN) for smoltcp to consume.
    pub fn inject(&mut self, pkt: Vec<u8>) {
        self.inbound.push_back(pkt);
    }

    /// Pop the next packet smoltcp emitted toward the TUN. The engine drains
    /// this after every poll; between polls the queue is bounded by what the
    /// socket tx buffers can emit in a single poll.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

impl Device for TunDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.inbound.pop_front()?;
        Some((RxToken { buf }, TxToken { queue: &mut self.outbound }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { queue: &mut self.outbound })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buf: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.queue.push_back(buf);
        result
    }
}
