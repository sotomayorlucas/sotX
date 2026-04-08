//! Network interface abstraction (ifnet).
//!
//! Each NIC is represented as a capability-gated device SecureObject.
//! The NIC driver domain holds MMIO+IRQ caps only and sends raw frames
//! to the network domain through shared-memory channels. The network
//! domain owns the interface objects and mediates all access.

use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// MAC address (6 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// Interface flags (UP, BROADCAST, LOOPBACK, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfFlags(u32);

impl IfFlags {
    pub const UP: u32 = 1 << 0;
    pub const BROADCAST: u32 = 1 << 1;
    pub const LOOPBACK: u32 = 1 << 2;
    pub const RUNNING: u32 = 1 << 3;
    pub const PROMISC: u32 = 1 << 4;

    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }
}

/// Rights on an interface capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfRights(u32);

impl IfRights {
    pub const TX: u32 = 1 << 0;
    pub const RX: u32 = 1 << 1;
    pub const CONFIG: u32 = 1 << 2;
    pub const STATS: u32 = 1 << 3;

    pub const ALL: Self = Self(Self::TX | Self::RX | Self::CONFIG | Self::STATS);

    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn has(self, right: u32) -> bool {
        self.0 & right != 0
    }

    pub const fn attenuate(self, mask: u32) -> Self {
        Self(self.0 & mask)
    }
}

/// Capability granting access to a specific interface.
#[derive(Debug, Clone)]
pub struct IfCap {
    pub if_id: u64,
    pub rights: IfRights,
}

impl IfCap {
    pub fn new(if_id: u64, rights: IfRights) -> Self {
        Self { if_id, rights }
    }

    pub fn attenuate(&self, mask: u32) -> Self {
        Self {
            if_id: self.if_id,
            rights: self.rights.attenuate(mask),
        }
    }
}

/// Interface statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IfStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
}

/// Errors from interface operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfError {
    PermissionDenied,
    InterfaceDown,
    MtuExceeded,
    QueueFull,
    NotFound,
}

/// A network interface (ifnet) SecureObject.
///
/// The NIC driver domain communicates with this object through
/// shared-memory frame channels: it writes raw received frames into
/// an RX ring and reads outbound frames from a TX ring.
#[derive(Debug)]
pub struct NetInterface {
    pub id: u64,
    /// Short name (e.g. "eth0", "lo0").
    pub name: [u8; 16],
    pub name_len: usize,
    pub mac: MacAddr,
    pub ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    pub flags: IfFlags,
    pub stats: IfStats,
    /// Outbound queue (frames waiting for driver to pick up).
    pub tx_queue: Vec<Vec<u8>>,
    /// Maximum outbound queue depth.
    pub tx_queue_max: usize,
}

impl NetInterface {
    /// Create a new interface in the DOWN state.
    pub fn new(id: u64, name: &[u8], mac: MacAddr) -> Self {
        let mut n = [0u8; 16];
        let len = name.len().min(16);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            id,
            name: n,
            name_len: len,
            mac,
            ipv4: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            mtu: 1500,
            flags: IfFlags::new(0),
            stats: IfStats::default(),
            tx_queue: Vec::new(),
            tx_queue_max: 256,
        }
    }

    /// Create a loopback interface.
    pub fn loopback(id: u64) -> Self {
        let mut iface = Self::new(id, b"lo0", MacAddr::ZERO);
        iface.ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        iface.netmask = Ipv4Addr::new(255, 0, 0, 0);
        iface.mtu = 65535;
        iface.flags.set(IfFlags::UP | IfFlags::LOOPBACK | IfFlags::RUNNING);
        iface
    }

    /// Bring the interface up.
    pub fn up(&mut self, cap: &IfCap) -> Result<(), IfError> {
        self.check(cap, IfRights::CONFIG)?;
        self.flags.set(IfFlags::UP | IfFlags::RUNNING);
        Ok(())
    }

    /// Bring the interface down.
    pub fn down(&mut self, cap: &IfCap) -> Result<(), IfError> {
        self.check(cap, IfRights::CONFIG)?;
        self.flags.clear(IfFlags::UP | IfFlags::RUNNING);
        self.tx_queue.clear();
        Ok(())
    }

    /// Configure IPv4 address and netmask.
    pub fn set_addr(
        &mut self,
        cap: &IfCap,
        ipv4: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<(), IfError> {
        self.check(cap, IfRights::CONFIG)?;
        self.ipv4 = ipv4;
        self.netmask = netmask;
        Ok(())
    }

    /// Enqueue a frame for transmission.
    pub fn transmit(&mut self, cap: &IfCap, frame: Vec<u8>) -> Result<(), IfError> {
        self.check(cap, IfRights::TX)?;
        if !self.flags.has(IfFlags::UP) {
            return Err(IfError::InterfaceDown);
        }
        if frame.len() > self.mtu as usize {
            return Err(IfError::MtuExceeded);
        }
        if self.tx_queue.len() >= self.tx_queue_max {
            self.stats.tx_dropped += 1;
            return Err(IfError::QueueFull);
        }
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len() as u64;
        self.tx_queue.push(frame);
        Ok(())
    }

    /// Called by the NIC driver domain to drain the TX queue.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.tx_queue)
    }

    /// Called when the NIC driver delivers a received frame.
    pub fn receive(&mut self, cap: &IfCap, frame: &[u8]) -> Result<Vec<u8>, IfError> {
        self.check(cap, IfRights::RX)?;
        if !self.flags.has(IfFlags::UP) {
            return Err(IfError::InterfaceDown);
        }
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += frame.len() as u64;
        Ok(frame.to_vec())
    }

    /// Read interface statistics.
    pub fn stats(&self, cap: &IfCap) -> Result<IfStats, IfError> {
        self.check(cap, IfRights::STATS)?;
        Ok(self.stats)
    }

    fn check(&self, cap: &IfCap, right: u32) -> Result<(), IfError> {
        if cap.if_id != self.id {
            return Err(IfError::PermissionDenied);
        }
        if !cap.rights.has(right) {
            return Err(IfError::PermissionDenied);
        }
        Ok(())
    }
}

/// Table of all interfaces known to the network domain.
pub struct IfTable {
    interfaces: Vec<NetInterface>,
    next_id: u64,
}

impl IfTable {
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a new interface. Returns its id and a full-rights cap.
    pub fn register(&mut self, name: &[u8], mac: MacAddr) -> (u64, IfCap) {
        let id = self.next_id;
        self.next_id += 1;
        self.interfaces.push(NetInterface::new(id, name, mac));
        (id, IfCap::new(id, IfRights::ALL))
    }

    /// Register a loopback interface.
    pub fn register_loopback(&mut self) -> (u64, IfCap) {
        let id = self.next_id;
        self.next_id += 1;
        self.interfaces.push(NetInterface::loopback(id));
        (id, IfCap::new(id, IfRights::ALL))
    }

    pub fn get(&self, id: u64) -> Option<&NetInterface> {
        self.interfaces.iter().find(|i| i.id == id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut NetInterface> {
        self.interfaces.iter_mut().find(|i| i.id == id)
    }
}

impl Default for IfTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_up() {
        let mut tbl = IfTable::new();
        let (id, _cap) = tbl.register_loopback();
        let iface = tbl.get(id).unwrap();
        assert!(iface.flags.has(IfFlags::UP));
        assert!(iface.flags.has(IfFlags::LOOPBACK));
    }

    #[test]
    fn transmit_requires_up() {
        let mut tbl = IfTable::new();
        let (id, cap) = tbl.register(b"eth0", MacAddr::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]));
        let iface = tbl.get_mut(id).unwrap();
        // Interface starts down.
        let result = iface.transmit(&cap, alloc::vec![0u8; 64]);
        assert_eq!(result, Err(IfError::InterfaceDown));

        iface.up(&cap).unwrap();
        assert!(iface.transmit(&cap, alloc::vec![0u8; 64]).is_ok());
    }

    #[test]
    fn mtu_enforced() {
        let mut tbl = IfTable::new();
        let (id, cap) = tbl.register(b"eth0", MacAddr::new([0; 6]));
        let iface = tbl.get_mut(id).unwrap();
        iface.up(&cap).unwrap();

        let big_frame = alloc::vec![0u8; 9000]; // jumbo frame, but MTU is 1500
        assert_eq!(iface.transmit(&cap, big_frame), Err(IfError::MtuExceeded));
    }

    #[test]
    fn stats_accumulate() {
        let mut tbl = IfTable::new();
        let (id, cap) = tbl.register(b"eth0", MacAddr::new([0; 6]));
        let iface = tbl.get_mut(id).unwrap();
        iface.up(&cap).unwrap();

        iface.transmit(&cap, alloc::vec![0u8; 100]).unwrap();
        iface.transmit(&cap, alloc::vec![0u8; 200]).unwrap();

        let s = iface.stats(&cap).unwrap();
        assert_eq!(s.tx_packets, 2);
        assert_eq!(s.tx_bytes, 300);
    }

    #[test]
    fn attenuated_cap_blocks_config() {
        let mut tbl = IfTable::new();
        let (id, cap) = tbl.register(b"eth0", MacAddr::new([0; 6]));
        let tx_only = cap.attenuate(IfRights::TX);
        let iface = tbl.get_mut(id).unwrap();

        assert_eq!(iface.up(&tx_only), Err(IfError::PermissionDenied));
    }
}
