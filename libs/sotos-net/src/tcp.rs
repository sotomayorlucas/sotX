//! TCP state machine — 3-way handshake, data transfer, FIN teardown.
//!
//! Minimal implementation: fixed window (4096), no congestion control,
//! simple retransmit. Supports both active (connect) and passive (listen) open.

use crate::checksum;

pub const TCP_HDR_LEN: usize = 20;
const TCP_WINDOW: u16 = 4096;

// TCP flags.
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// TCP connection state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closed,
}

/// A single TCP connection.
pub struct TcpConn {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,
    pub snd_nxt: u32,  // next sequence number to send
    pub snd_una: u32,  // oldest unacknowledged
    pub rcv_nxt: u32,  // next expected from remote
    /// Receive buffer.
    pub recv_buf: [u8; 512],
    pub recv_len: usize,
    pub active: bool,
}

impl TcpConn {
    pub const fn empty() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            recv_buf: [0; 512],
            recv_len: 0,
            active: false,
        }
    }
}

/// TCP connection table.
pub struct TcpTable {
    pub conns: [TcpConn; 16],
    seq_counter: u32,
}

/// Parsed TCP segment header.
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8, // in 32-bit words
    pub flags: u8,
    pub window: u16,
}

impl TcpTable {
    pub const fn new() -> Self {
        Self {
            conns: [const { TcpConn::empty() }; 16],
            seq_counter: 1000,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(64000);
        s
    }

    /// Listen on a local port (passive open).
    pub fn listen(&mut self, port: u16) -> Option<usize> {
        for (i, c) in self.conns.iter_mut().enumerate() {
            if !c.active {
                c.active = true;
                c.state = TcpState::Listen;
                c.local_port = port;
                c.remote_ip = 0;
                c.remote_port = 0;
                c.recv_len = 0;
                return Some(i);
            }
        }
        None
    }

    /// Active open: initiate a TCP connection (send SYN).
    /// Returns (conn_id, SYN segment length).
    pub fn connect(
        &mut self,
        local_port: u16,
        remote_ip: u32,
        remote_port: u16,
        our_ip: u32,
        reply_buf: &mut [u8],
    ) -> Option<(usize, usize)> {
        // Find a free slot.
        let ci = self.conns.iter().position(|c| !c.active)?;
        let iss = self.next_seq();
        let c = &mut self.conns[ci];
        c.active = true;
        c.state = TcpState::SynSent;
        c.local_port = local_port;
        c.remote_ip = remote_ip;
        c.remote_port = remote_port;
        c.snd_nxt = iss.wrapping_add(1);
        c.snd_una = iss;
        c.rcv_nxt = 0;
        c.recv_len = 0;
        let seg_len = build_segment(
            reply_buf, our_ip, remote_ip,
            local_port, remote_port,
            iss, 0,
            SYN, TCP_WINDOW, &[],
        );
        Some((ci, seg_len))
    }

    /// Find a connection matching remote, or a listener on the port.
    fn find_conn(&mut self, src_ip: u32, src_port: u16, dst_port: u16) -> Option<usize> {
        // Exact match first.
        for (i, c) in self.conns.iter().enumerate() {
            if c.active && c.local_port == dst_port
                && c.remote_ip == src_ip && c.remote_port == src_port
                && c.state != TcpState::Listen
            {
                return Some(i);
            }
        }
        // Listener match.
        for (i, c) in self.conns.iter().enumerate() {
            if c.active && c.local_port == dst_port && c.state == TcpState::Listen {
                return Some(i);
            }
        }
        None
    }

    /// Handle an incoming TCP segment. Returns optional reply segment bytes and length.
    /// `src_ip` is the sender's IP. `segment` is the raw TCP segment (header + data).
    /// `our_ip` is needed for checksum.
    pub fn handle_segment(
        &mut self,
        src_ip: u32,
        our_ip: u32,
        segment: &[u8],
        reply_buf: &mut [u8],
    ) -> Option<usize> {
        let hdr = parse_header(segment)?;
        let data_start = (hdr.data_offset as usize) * 4;
        let payload = if data_start < segment.len() { &segment[data_start..] } else { &[] };

        let ci = self.find_conn(src_ip, hdr.src_port, hdr.dst_port)?;

        match self.conns[ci].state {
            TcpState::Listen => {
                if hdr.flags & SYN != 0 {
                    // SYN received → send SYN+ACK, transition to SynRcvd.
                    let iss = self.next_seq();
                    let c = &mut self.conns[ci];
                    c.remote_ip = src_ip;
                    c.remote_port = hdr.src_port;
                    c.rcv_nxt = hdr.seq.wrapping_add(1);
                    c.snd_nxt = iss.wrapping_add(1);
                    c.snd_una = iss;
                    c.state = TcpState::SynRcvd;
                    c.recv_len = 0;
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        iss, c.rcv_nxt,
                        SYN | ACK, TCP_WINDOW, &[],
                    ));
                }
                None
            }
            TcpState::SynSent => {
                // Expecting SYN+ACK from remote.
                if hdr.flags & SYN != 0 && hdr.flags & ACK != 0 {
                    let c = &mut self.conns[ci];
                    c.snd_una = hdr.ack;
                    c.rcv_nxt = hdr.seq.wrapping_add(1);
                    c.state = TcpState::Established;
                    // Send ACK to complete 3-way handshake.
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, TCP_WINDOW, &[],
                    ));
                }
                None
            }
            TcpState::SynRcvd => {
                if hdr.flags & ACK != 0 {
                    let c = &mut self.conns[ci];
                    c.snd_una = hdr.ack;
                    c.state = TcpState::Established;
                }
                None
            }
            TcpState::Established => {
                let c = &mut self.conns[ci];

                // Process ACK.
                if hdr.flags & ACK != 0 {
                    c.snd_una = hdr.ack;
                }

                // Process incoming data.
                if !payload.is_empty() && hdr.seq == c.rcv_nxt {
                    let space = c.recv_buf.len() - c.recv_len;
                    let copy_len = payload.len().min(space);
                    c.recv_buf[c.recv_len..c.recv_len + copy_len]
                        .copy_from_slice(&payload[..copy_len]);
                    c.recv_len += copy_len;
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(copy_len as u32);

                    // Send ACK.
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, TCP_WINDOW, &[],
                    ));
                }

                // FIN received.
                if hdr.flags & FIN != 0 {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                    c.state = TcpState::CloseWait;
                    // ACK the FIN, then send our own FIN.
                    let ack_len = build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK | FIN, TCP_WINDOW, &[],
                    );
                    c.snd_nxt = c.snd_nxt.wrapping_add(1);
                    c.state = TcpState::LastAck;
                    return Some(ack_len);
                }

                None
            }
            TcpState::FinWait1 => {
                let c = &mut self.conns[ci];
                if hdr.flags & ACK != 0 {
                    c.snd_una = hdr.ack;
                    if hdr.flags & FIN != 0 {
                        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                        c.state = TcpState::Closed;
                        c.active = false;
                        return Some(build_segment(
                            reply_buf, our_ip, src_ip,
                            c.local_port, c.remote_port,
                            c.snd_nxt, c.rcv_nxt,
                            ACK, TCP_WINDOW, &[],
                        ));
                    }
                    c.state = TcpState::FinWait2;
                }
                None
            }
            TcpState::FinWait2 => {
                let c = &mut self.conns[ci];
                if hdr.flags & FIN != 0 {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                    c.state = TcpState::Closed;
                    c.active = false;
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, TCP_WINDOW, &[],
                    ));
                }
                None
            }
            TcpState::LastAck => {
                if hdr.flags & ACK != 0 {
                    let c = &mut self.conns[ci];
                    c.state = TcpState::Closed;
                    // Re-arm listener on same port.
                    c.state = TcpState::Listen;
                    c.remote_ip = 0;
                    c.remote_port = 0;
                    c.recv_len = 0;
                }
                None
            }
            TcpState::CloseWait => {
                // We should send FIN; handled by close().
                None
            }
            _ => None,
        }
    }

    /// Send data on an established connection. Returns the TCP segment to transmit.
    pub fn send(
        &mut self,
        conn_id: usize,
        our_ip: u32,
        data: &[u8],
        reply_buf: &mut [u8],
    ) -> Option<usize> {
        let c = &mut self.conns[conn_id];
        if c.state != TcpState::Established || !c.active {
            return None;
        }
        let len = build_segment(
            reply_buf, our_ip, c.remote_ip,
            c.local_port, c.remote_port,
            c.snd_nxt, c.rcv_nxt,
            ACK | PSH, TCP_WINDOW, data,
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(data.len() as u32);
        Some(len)
    }

    /// Read received data from a connection's buffer. Returns bytes read.
    pub fn read(&mut self, conn_id: usize, out: &mut [u8]) -> usize {
        let c = &mut self.conns[conn_id];
        let n = c.recv_len.min(out.len());
        out[..n].copy_from_slice(&c.recv_buf[..n]);
        // Shift remaining data.
        if n < c.recv_len {
            c.recv_buf.copy_within(n..c.recv_len, 0);
        }
        c.recv_len -= n;
        n
    }

    /// Close a connection (active close). Returns FIN segment to transmit.
    pub fn close(
        &mut self,
        conn_id: usize,
        our_ip: u32,
        reply_buf: &mut [u8],
    ) -> Option<usize> {
        let c = &mut self.conns[conn_id];
        if !c.active {
            return None;
        }
        let len = build_segment(
            reply_buf, our_ip, c.remote_ip,
            c.local_port, c.remote_port,
            c.snd_nxt, c.rcv_nxt,
            FIN | ACK, TCP_WINDOW, &[],
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.state = TcpState::FinWait1;
        Some(len)
    }
}

/// Parse a TCP segment header.
pub fn parse_header(data: &[u8]) -> Option<TcpHeader> {
    if data.len() < TCP_HDR_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = data[12] >> 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    Some(TcpHeader { src_port, dst_port, seq, ack, data_offset, flags, window })
}

/// Build a TCP segment (header + payload) into `buf`. Returns total length.
pub fn build_segment(
    buf: &mut [u8],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> usize {
    let total = TCP_HDR_LEN + payload.len();
    if buf.len() < total {
        return 0;
    }
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = 5 << 4; // data offset = 5 (20 bytes, no options)
    buf[13] = flags;
    buf[14..16].copy_from_slice(&window.to_be_bytes());
    buf[16] = 0; // checksum (filled below)
    buf[17] = 0;
    buf[18] = 0; // urgent pointer
    buf[19] = 0;
    if !payload.is_empty() {
        buf[TCP_HDR_LEN..total].copy_from_slice(payload);
    }

    let cksum = checksum::pseudo_header_checksum(src_ip, dst_ip, 6, &buf[..total]);
    buf[16..18].copy_from_slice(&cksum.to_be_bytes());

    total
}
