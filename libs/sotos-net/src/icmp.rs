//! ICMP echo request/reply handling.

use crate::checksum;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_TIME_EXCEEDED: u8 = 11;

/// Build an ICMP echo request. Returns length written to `buf`.
pub fn build_echo_request(buf: &mut [u8], id: u16, seq: u16) -> usize {
    let len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    if buf.len() < len {
        return 0;
    }
    buf[0] = ICMP_ECHO_REQUEST;
    buf[1] = 0; // code
    buf[2] = 0; // checksum (filled below)
    buf[3] = 0;
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    let cksum = checksum::internet_checksum(&buf[..len]);
    buf[2..4].copy_from_slice(&cksum.to_be_bytes());
    len
}

/// Check if an ICMP packet is an echo reply. Returns (id, seq) if so.
pub fn is_echo_reply(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 8 {
        return None;
    }
    if data[0] != ICMP_ECHO_REPLY {
        return None;
    }
    let id = u16::from_be_bytes([data[4], data[5]]);
    let seq = u16::from_be_bytes([data[6], data[7]]);
    Some((id, seq))
}

/// Check if an ICMP packet is a Time Exceeded message (TTL expired in transit).
/// Returns the source IP of the original packet embedded in the ICMP payload.
pub fn is_time_exceeded(data: &[u8]) -> bool {
    data.len() >= 8 && data[0] == ICMP_TIME_EXCEEDED
}

/// Handle an ICMP packet. If it's an echo request, return an echo reply payload.
/// The returned slice is the ICMP reply (header + data), ready to be wrapped in IP.
pub fn handle(icmp_data: &[u8], buf: &mut [u8]) -> Option<usize> {
    if icmp_data.len() < 8 {
        return None;
    }
    let msg_type = icmp_data[0];
    if msg_type != ICMP_ECHO_REQUEST {
        return None;
    }
    if buf.len() < icmp_data.len() {
        return None;
    }

    // Copy the entire ICMP packet, change type to reply.
    buf[..icmp_data.len()].copy_from_slice(icmp_data);
    buf[0] = ICMP_ECHO_REPLY;
    // Zero checksum field before recalculating.
    buf[2] = 0;
    buf[3] = 0;
    let cksum = checksum::internet_checksum(&buf[..icmp_data.len()]);
    buf[2..4].copy_from_slice(&cksum.to_be_bytes());

    Some(icmp_data.len())
}
