//! ARP (Address Resolution Protocol) — request/reply + cache table.

/// ARP hardware type: Ethernet.
const HW_ETHERNET: u16 = 1;
/// ARP operation: request.
const ARP_REQUEST: u16 = 1;
/// ARP operation: reply.
const ARP_REPLY: u16 = 2;

/// ARP packet length for IPv4-over-Ethernet (28 bytes).
pub const ARP_PKT_LEN: usize = 28;

/// ARP cache table entry.
#[derive(Clone, Copy)]
struct ArpEntry {
    ip: u32,
    mac: [u8; 6],
    valid: bool,
}

/// ARP cache.
pub struct ArpTable {
    entries: [ArpEntry; 32],
}

impl ArpTable {
    pub const fn new() -> Self {
        Self {
            entries: [ArpEntry { ip: 0, mac: [0; 6], valid: false }; 32],
        }
    }

    /// Lookup MAC for an IP. Returns None if not cached.
    pub fn lookup(&self, ip: u32) -> Option<[u8; 6]> {
        for e in &self.entries {
            if e.valid && e.ip == ip {
                return Some(e.mac);
            }
        }
        None
    }

    /// Insert or update an ARP entry.
    pub fn insert(&mut self, ip: u32, mac: [u8; 6]) {
        // Update existing.
        for e in self.entries.iter_mut() {
            if e.valid && e.ip == ip {
                e.mac = mac;
                return;
            }
        }
        // Find free slot.
        for e in self.entries.iter_mut() {
            if !e.valid {
                *e = ArpEntry { ip, mac, valid: true };
                return;
            }
        }
        // Evict first entry.
        self.entries[0] = ArpEntry { ip, mac, valid: true };
    }
}

/// Parsed ARP packet.
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

/// Parse an ARP packet (Ethernet/IPv4 only).
pub fn parse(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < ARP_PKT_LEN {
        return None;
    }
    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto = u16::from_be_bytes([data[2], data[3]]);
    if hw_type != HW_ETHERNET || proto != 0x0800 {
        return None;
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[8..14]);
    let sender_ip = u32::from_be_bytes([data[14], data[15], data[16], data[17]]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&data[18..24]);
    let target_ip = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    Some(ArpPacket { op, sender_mac, sender_ip, target_mac, target_ip })
}

/// Handle an incoming ARP packet. Updates the table and optionally returns a reply frame payload.
/// `our_ip` and `our_mac` are the local interface's addresses.
/// Returns the ARP reply bytes (28 bytes) if we should reply, or None.
pub fn handle(table: &mut ArpTable, pkt: &ArpPacket, our_ip: u32, our_mac: &[u8; 6]) -> Option<[u8; 28]> {
    // Always learn sender.
    table.insert(pkt.sender_ip, pkt.sender_mac);

    if pkt.op == ARP_REQUEST && pkt.target_ip == our_ip {
        // Build ARP reply.
        Some(build_reply(our_mac, our_ip, &pkt.sender_mac, pkt.sender_ip))
    } else {
        None
    }
}

/// Build an ARP request packet (28 bytes).
pub fn build_request(our_mac: &[u8; 6], our_ip: u32, target_ip: u32) -> [u8; 28] {
    let mut buf = [0u8; 28];
    buf[0..2].copy_from_slice(&HW_ETHERNET.to_be_bytes());
    buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[4] = 6; // hw addr len
    buf[5] = 4; // proto addr len
    buf[6..8].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    buf[8..14].copy_from_slice(our_mac);
    buf[14..18].copy_from_slice(&our_ip.to_be_bytes());
    // target MAC = 0 (unknown)
    buf[24..28].copy_from_slice(&target_ip.to_be_bytes());
    buf
}

fn build_reply(our_mac: &[u8; 6], our_ip: u32, target_mac: &[u8; 6], target_ip: u32) -> [u8; 28] {
    let mut buf = [0u8; 28];
    buf[0..2].copy_from_slice(&HW_ETHERNET.to_be_bytes());
    buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[4] = 6;
    buf[5] = 4;
    buf[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
    buf[8..14].copy_from_slice(our_mac);
    buf[14..18].copy_from_slice(&our_ip.to_be_bytes());
    buf[18..24].copy_from_slice(target_mac);
    buf[24..28].copy_from_slice(&target_ip.to_be_bytes());
    buf
}
