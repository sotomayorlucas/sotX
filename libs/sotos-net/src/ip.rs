//! IPv4 packet parsing and building.

use crate::checksum;

pub const IP_HDR_LEN: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Parsed IPv4 header.
pub struct Ipv4Header {
    pub src: u32,
    pub dst: u32,
    pub protocol: u8,
    pub total_len: u16,
    pub ttl: u8,
    pub id: u16,
}

/// Parse an IPv4 packet. Returns header and payload slice.
pub fn parse(data: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    if data.len() < IP_HDR_LEN {
        return None;
    }
    let version = data[0] >> 4;
    let ihl = (data[0] & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let hdr_len = ihl * 4;
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    if data.len() < total_len as usize || (total_len as usize) < hdr_len {
        return None;
    }
    let id = u16::from_be_bytes([data[4], data[5]]);
    let ttl = data[8];
    let protocol = data[9];
    let src = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let dst = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    let payload = &data[hdr_len..total_len as usize];
    Some((Ipv4Header { src, dst, protocol, total_len, ttl, id }, payload))
}

/// Build an IPv4 packet into `buf`. Returns total packet length.
/// `payload` is the transport-layer data (ICMP/UDP/TCP segment).
pub fn build(buf: &mut [u8], src: u32, dst: u32, protocol: u8, id: u16, payload: &[u8]) -> usize {
    build_with_ttl(buf, src, dst, protocol, id, 64, payload)
}

/// Build an IPv4 packet with a specific TTL. Returns total packet length.
pub fn build_with_ttl(buf: &mut [u8], src: u32, dst: u32, protocol: u8, id: u16, ttl: u8, payload: &[u8]) -> usize {
    let total_len = IP_HDR_LEN + payload.len();
    if buf.len() < total_len {
        return 0;
    }
    buf[0] = 0x45; // version=4, IHL=5
    buf[1] = 0;    // DSCP/ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6] = 0x40; // Don't Fragment
    buf[7] = 0;
    buf[8] = ttl;
    buf[9] = protocol;
    buf[10] = 0;   // checksum (filled below)
    buf[11] = 0;
    buf[12..16].copy_from_slice(&src.to_be_bytes());
    buf[16..20].copy_from_slice(&dst.to_be_bytes());

    // IP header checksum.
    let cksum = checksum::internet_checksum(&buf[..IP_HDR_LEN]);
    buf[10..12].copy_from_slice(&cksum.to_be_bytes());

    buf[IP_HDR_LEN..total_len].copy_from_slice(payload);
    total_len
}
