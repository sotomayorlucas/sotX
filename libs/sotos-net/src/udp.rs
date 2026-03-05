//! UDP datagram parsing, building, and simple socket table.

use crate::checksum;

pub const UDP_HDR_LEN: usize = 8;

/// Parsed UDP header.
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

/// A bound UDP socket.
#[derive(Clone, Copy)]
pub struct UdpSocket {
    pub local_port: u16,
    pub active: bool,
}

/// Received datagram info.
pub struct UdpDatagram {
    pub src_ip: u32,
    pub src_port: u16,
    pub data_offset: usize,
    pub data_len: usize,
}

/// UDP socket table with receive buffer.
pub struct UdpTable {
    pub sockets: [UdpSocket; 16],
    /// Pending received datagrams.
    pub rx_queue: [Option<UdpDatagram>; 16],
    /// Data buffer for received payloads.
    pub rx_data: [u8; 1024],
    pub rx_data_used: usize,
}

impl UdpTable {
    pub const fn new() -> Self {
        Self {
            sockets: [UdpSocket { local_port: 0, active: false }; 16],
            rx_queue: [const { None }; 16],
            rx_data: [0; 1024],
            rx_data_used: 0,
        }
    }

    /// Bind a UDP socket to a local port.
    pub fn bind(&mut self, port: u16) -> Option<usize> {
        for (i, s) in self.sockets.iter_mut().enumerate() {
            if !s.active {
                s.local_port = port;
                s.active = true;
                return Some(i);
            }
        }
        None
    }

    /// Check if a port is bound.
    pub fn is_bound(&self, port: u16) -> bool {
        self.sockets.iter().any(|s| s.active && s.local_port == port)
    }
}

/// Parse a UDP datagram. Returns header and payload slice.
pub fn parse(data: &[u8]) -> Option<(UdpHeader, &[u8])> {
    if data.len() < UDP_HDR_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    if (length as usize) < UDP_HDR_LEN || data.len() < length as usize {
        return None;
    }
    let payload = &data[UDP_HDR_LEN..length as usize];
    Some((UdpHeader { src_port, dst_port, length }, payload))
}

/// Build a UDP datagram into `buf`. Returns total UDP segment length.
pub fn build(buf: &mut [u8], src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, payload: &[u8]) -> usize {
    let total = UDP_HDR_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    buf[6] = 0; // checksum (filled below)
    buf[7] = 0;
    buf[UDP_HDR_LEN..total].copy_from_slice(payload);

    let cksum = checksum::pseudo_header_checksum(src_ip, dst_ip, 17, &buf[..total]);
    // If checksum is 0, use 0xFFFF per RFC 768.
    let cksum = if cksum == 0 { 0xFFFF } else { cksum };
    buf[6..8].copy_from_slice(&cksum.to_be_bytes());

    total
}
