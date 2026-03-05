//! Ethernet frame parsing and building.

pub const ETH_HDR_LEN: usize = 14;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// Parsed Ethernet header.
pub struct EthHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

/// Parse an Ethernet frame. Returns header and payload slice.
pub fn parse(data: &[u8]) -> Option<(EthHeader, &[u8])> {
    if data.len() < ETH_HDR_LEN {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    Some((EthHeader { dst, src, ethertype }, &data[ETH_HDR_LEN..]))
}

/// Build an Ethernet frame into `buf`.
/// Returns total frame length (header + payload).
pub fn build(buf: &mut [u8], dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> usize {
    let total = ETH_HDR_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }
    buf[0..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    buf[ETH_HDR_LEN..ETH_HDR_LEN + payload.len()].copy_from_slice(payload);
    total
}
