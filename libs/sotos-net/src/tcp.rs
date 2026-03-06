//! TCP state machine — 3-way handshake, data transfer, FIN teardown.
//!
//! Features: Reno-style congestion control (slow start + congestion avoidance),
//! TCP window scaling (RFC 7323), retransmit with exponential backoff.
//! Supports both active (connect) and passive (listen) open.

use crate::checksum;

pub const TCP_HDR_LEN: usize = 20;
/// Base TCP header length with window scale option (20 + 4 = 24, padded to 24).
pub const TCP_HDR_LEN_WITH_OPTS: usize = 24;
/// Default receive window size (unscaled, advertised in SYN).
const TCP_WINDOW_BASE: u16 = 4096;
/// Maximum Segment Size for congestion control calculations.
pub const MSS: u32 = 536;
/// Default initial slow start threshold.
const INITIAL_SSTHRESH: u32 = 65535;
/// Default window scale factor we request.
const DEFAULT_RCV_WND_SCALE: u8 = 7;

// TCP flags.
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

// TCP option kinds.
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_WINDOW_SCALE: u8 = 3;

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

/// Maximum retransmit buffer size (enough for SYN/FIN + small data).
const RETRANSMIT_BUF_SIZE: usize = 128;
/// Maximum retransmit attempts before giving up.
const MAX_RETRANSMITS: u8 = 5;
/// Retransmit interval in ticks (caller's tick rate).
const RETRANSMIT_TICKS: u32 = 100;

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
    pub recv_buf: [u8; 2048],
    pub recv_len: usize,
    pub active: bool,
    /// Retransmit state: saved last unACKed segment.
    retransmit_buf: [u8; RETRANSMIT_BUF_SIZE],
    retransmit_len: usize,
    retransmit_count: u8,
    retransmit_tick: u32,

    // --- Congestion control (Reno) ---
    /// Congestion window in bytes.
    pub cwnd: u32,
    /// Slow start threshold in bytes.
    pub ssthresh: u32,
    /// Estimated round-trip time in ticks.
    pub rtt_estimate: u32,

    // --- Window scaling (RFC 7323) ---
    /// Our receive window scale factor (0-14), sent in SYN.
    pub rcv_wnd_scale: u8,
    /// Peer's window scale factor, learned from SYN/SYN-ACK.
    pub snd_wnd_scale: u8,
    /// Actual receive window size (after applying our scale factor).
    pub rcv_window: u32,
    /// Whether window scaling was negotiated for this connection.
    pub wnd_scale_enabled: bool,
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
            recv_buf: [0; 2048],
            recv_len: 0,
            active: false,
            retransmit_buf: [0; RETRANSMIT_BUF_SIZE],
            retransmit_len: 0,
            retransmit_count: 0,
            retransmit_tick: 0,
            cwnd: MSS,
            ssthresh: INITIAL_SSTHRESH,
            rtt_estimate: RETRANSMIT_TICKS,
            rcv_wnd_scale: DEFAULT_RCV_WND_SCALE,
            snd_wnd_scale: 0,
            rcv_window: (TCP_WINDOW_BASE as u32) << DEFAULT_RCV_WND_SCALE,
            wnd_scale_enabled: false,
        }
    }

    /// Get the advertised window value for outgoing segments.
    /// If window scaling is negotiated, the advertised value is
    /// rcv_window >> rcv_wnd_scale (the raw 16-bit field).
    fn advertised_window(&self) -> u16 {
        if self.wnd_scale_enabled {
            let shifted = self.rcv_window >> (self.rcv_wnd_scale as u32);
            if shifted > 0xFFFF { 0xFFFF } else { shifted as u16 }
        } else {
            // During handshake or if not negotiated, use base window.
            TCP_WINDOW_BASE
        }
    }

    /// Called when an ACK advances snd_una (new data acknowledged).
    /// Updates congestion window per Reno algorithm.
    fn on_ack_received(&mut self, bytes_acked: u32) {
        if self.cwnd < self.ssthresh {
            // Slow start: cwnd += min(bytes_acked, MSS) per ACK.
            self.cwnd = self.cwnd.saturating_add(bytes_acked.min(MSS));
        } else {
            // Congestion avoidance: cwnd += MSS * MSS / cwnd per ACK.
            let inc = (MSS as u64 * MSS as u64) / self.cwnd as u64;
            self.cwnd = self.cwnd.saturating_add(inc.max(1) as u32);
        }
    }

    /// Called on packet loss (retransmit timeout).
    /// Reduces ssthresh and resets cwnd per Reno.
    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * MSS);
        self.cwnd = MSS;
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
        // Initialize congestion control.
        c.cwnd = MSS;
        c.ssthresh = INITIAL_SSTHRESH;
        c.rcv_wnd_scale = DEFAULT_RCV_WND_SCALE;
        c.snd_wnd_scale = 0;
        c.wnd_scale_enabled = false;
        c.rcv_window = (TCP_WINDOW_BASE as u32) << DEFAULT_RCV_WND_SCALE;
        // Send SYN with window scale option.
        let seg_len = build_segment_with_options(
            reply_buf, our_ip, remote_ip,
            local_port, remote_port,
            iss, 0,
            SYN, TCP_WINDOW_BASE, &[],
            Some(c.rcv_wnd_scale),
        );
        Self::save_for_retransmit(&mut self.conns[ci], &reply_buf[..seg_len], 0);
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

        // Parse TCP options from the segment.
        let opts = parse_tcp_options(segment, &hdr);

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
                    // Initialize congestion control for passive open.
                    c.cwnd = MSS;
                    c.ssthresh = INITIAL_SSTHRESH;
                    // Check if peer sent window scale option.
                    if let Some(peer_scale) = opts.window_scale {
                        c.snd_wnd_scale = peer_scale;
                        c.wnd_scale_enabled = true;
                    } else {
                        c.snd_wnd_scale = 0;
                        c.wnd_scale_enabled = false;
                    }
                    // Reply with SYN+ACK including our window scale option.
                    let wnd_opt = if c.wnd_scale_enabled {
                        Some(c.rcv_wnd_scale)
                    } else {
                        None
                    };
                    return Some(build_segment_with_options(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        iss, c.rcv_nxt,
                        SYN | ACK, TCP_WINDOW_BASE, &[],
                        wnd_opt,
                    ));
                }
                None
            }
            TcpState::SynSent => {
                // RST received — abort connection.
                if hdr.flags & RST != 0 {
                    let c = &mut self.conns[ci];
                    c.state = TcpState::Closed;
                    c.active = false;
                    c.retransmit_len = 0;
                    return None;
                }
                // Expecting SYN+ACK from remote.
                if hdr.flags & SYN != 0 && hdr.flags & ACK != 0 {
                    let c = &mut self.conns[ci];
                    c.snd_una = hdr.ack;
                    c.rcv_nxt = hdr.seq.wrapping_add(1);
                    c.state = TcpState::Established;
                    c.retransmit_len = 0;
                    c.retransmit_count = 0;
                    // Check window scale option in SYN+ACK.
                    if let Some(peer_scale) = opts.window_scale {
                        c.snd_wnd_scale = peer_scale;
                        c.wnd_scale_enabled = true;
                    }
                    // Congestion control: connection established, cwnd starts at MSS.
                    c.cwnd = MSS;
                    let win = c.advertised_window();
                    // Send ACK to complete 3-way handshake.
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, win, &[],
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

                // RST received — abort connection.
                if hdr.flags & RST != 0 {
                    c.state = TcpState::Closed;
                    c.active = false;
                    c.retransmit_len = 0;
                    return None;
                }

                // Process ACK — clear retransmit if all data acknowledged.
                if hdr.flags & ACK != 0 {
                    let old_una = c.snd_una;
                    c.snd_una = hdr.ack;
                    // Bytes newly acknowledged.
                    let bytes_acked = hdr.ack.wrapping_sub(old_una);
                    if bytes_acked > 0 && bytes_acked < 0x80000000 {
                        c.on_ack_received(bytes_acked);
                    }
                    if c.snd_una == c.snd_nxt {
                        c.retransmit_len = 0;
                        c.retransmit_count = 0;
                    }
                }

                // Process incoming data.
                let mut got_data = false;
                if !payload.is_empty() && hdr.seq == c.rcv_nxt {
                    let space = c.recv_buf.len() - c.recv_len;
                    let copy_len = payload.len().min(space);
                    c.recv_buf[c.recv_len..c.recv_len + copy_len]
                        .copy_from_slice(&payload[..copy_len]);
                    c.recv_len += copy_len;
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(copy_len as u32);
                    got_data = true;
                }

                // FIN received (may arrive on the same segment as data).
                if hdr.flags & FIN != 0 {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                    c.state = TcpState::CloseWait;
                    let win = c.advertised_window();
                    // ACK the FIN, then send our own FIN.
                    let ack_len = build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK | FIN, win, &[],
                    );
                    c.snd_nxt = c.snd_nxt.wrapping_add(1);
                    c.state = TcpState::LastAck;
                    return Some(ack_len);
                }

                // Pure data (no FIN) — send ACK.
                if got_data {
                    let win = c.advertised_window();
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, win, &[],
                    ));
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
                        let win = c.advertised_window();
                        return Some(build_segment(
                            reply_buf, our_ip, src_ip,
                            c.local_port, c.remote_port,
                            c.snd_nxt, c.rcv_nxt,
                            ACK, win, &[],
                        ));
                    }
                    c.state = TcpState::FinWait2;
                }
                None
            }
            TcpState::FinWait2 => {
                let c = &mut self.conns[ci];
                // Buffer any incoming data before FIN.
                if !payload.is_empty() && hdr.seq == c.rcv_nxt {
                    let space = c.recv_buf.len() - c.recv_len;
                    let copy_len = payload.len().min(space);
                    c.recv_buf[c.recv_len..c.recv_len + copy_len]
                        .copy_from_slice(&payload[..copy_len]);
                    c.recv_len += copy_len;
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(copy_len as u32);
                }
                if hdr.flags & FIN != 0 {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                    c.state = TcpState::Closed;
                    c.active = false;
                    let win = c.advertised_window();
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, win, &[],
                    ));
                }
                // ACK data if we received some.
                if !payload.is_empty() {
                    let win = c.advertised_window();
                    return Some(build_segment(
                        reply_buf, our_ip, src_ip,
                        c.local_port, c.remote_port,
                        c.snd_nxt, c.rcv_nxt,
                        ACK, win, &[],
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
    /// Respects the congestion window: only sends up to cwnd bytes of in-flight data.
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
        // Check congestion window: bytes in flight must not exceed cwnd.
        let in_flight = c.snd_nxt.wrapping_sub(c.snd_una);
        if in_flight >= c.cwnd {
            return None; // Congestion window full — wait for ACKs.
        }
        let allowed = (c.cwnd - in_flight) as usize;
        let send_data = if data.len() > allowed { &data[..allowed] } else { data };
        let win = c.advertised_window();
        let len = build_segment(
            reply_buf, our_ip, c.remote_ip,
            c.local_port, c.remote_port,
            c.snd_nxt, c.rcv_nxt,
            ACK | PSH, win, send_data,
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(send_data.len() as u32);
        Self::save_for_retransmit(c, &reply_buf[..len], 0);
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

    /// Check all connections for retransmit timeouts. Returns the first segment
    /// that needs retransmission as (conn_id, segment_bytes, length), or None.
    /// `current_tick` is a monotonic counter provided by the caller.
    ///
    /// On timeout, triggers congestion control loss response (Reno):
    /// ssthresh = cwnd/2, cwnd = MSS.
    pub fn check_retransmit(&mut self, current_tick: u32, out: &mut [u8]) -> Option<(usize, usize)> {
        for (i, c) in self.conns.iter_mut().enumerate() {
            if !c.active || c.retransmit_len == 0 {
                continue;
            }
            // Check if all sent data has been ACKed.
            if c.snd_una == c.snd_nxt {
                c.retransmit_len = 0;
                c.retransmit_count = 0;
                continue;
            }
            let elapsed = current_tick.wrapping_sub(c.retransmit_tick);
            // Use rtt_estimate as base interval for retransmit (with backoff).
            let base = if c.rtt_estimate > 0 { c.rtt_estimate } else { RETRANSMIT_TICKS };
            let interval = base << (c.retransmit_count as u32).min(4);
            if elapsed >= interval {
                if c.retransmit_count >= MAX_RETRANSMITS {
                    // Give up — reset connection.
                    c.state = TcpState::Closed;
                    c.active = false;
                    c.retransmit_len = 0;
                    continue;
                }
                // Congestion control: loss detected.
                c.on_loss();
                c.retransmit_count += 1;
                c.retransmit_tick = current_tick;
                let len = c.retransmit_len.min(out.len());
                out[..len].copy_from_slice(&c.retransmit_buf[..len]);
                return Some((i, len));
            }
        }
        None
    }

    /// Save a segment for potential retransmission.
    fn save_for_retransmit(conn: &mut TcpConn, segment: &[u8], current_tick: u32) {
        let len = segment.len().min(RETRANSMIT_BUF_SIZE);
        conn.retransmit_buf[..len].copy_from_slice(&segment[..len]);
        conn.retransmit_len = len;
        conn.retransmit_count = 0;
        conn.retransmit_tick = current_tick;
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
        let win = c.advertised_window();
        let len = build_segment(
            reply_buf, our_ip, c.remote_ip,
            c.local_port, c.remote_port,
            c.snd_nxt, c.rcv_nxt,
            FIN | ACK, win, &[],
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
/// This is the standard segment builder with no TCP options.
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

/// Build a TCP segment with optional TCP options (e.g., window scale in SYN).
/// If `wnd_scale` is Some(shift), includes the window scale option (kind=3, len=3, shift).
/// Options are padded to a 4-byte boundary with NOP.
pub fn build_segment_with_options(
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
    wnd_scale: Option<u8>,
) -> usize {
    // Calculate options length.
    let opts_len = if wnd_scale.is_some() {
        4 // NOP(1) + kind(1) + len(1) + shift(1) = 4 bytes (already aligned)
    } else {
        0
    };
    let hdr_len = TCP_HDR_LEN + opts_len;
    let total = hdr_len + payload.len();
    if buf.len() < total {
        return 0;
    }

    let data_offset = (hdr_len / 4) as u8; // In 32-bit words.

    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = data_offset << 4;
    buf[13] = flags;
    buf[14..16].copy_from_slice(&window.to_be_bytes());
    buf[16] = 0; // checksum (filled below)
    buf[17] = 0;
    buf[18] = 0; // urgent pointer
    buf[19] = 0;

    // Write options after the base 20-byte header.
    if let Some(shift) = wnd_scale {
        buf[20] = TCP_OPT_NOP;              // NOP padding for alignment
        buf[21] = TCP_OPT_WINDOW_SCALE;     // kind = 3
        buf[22] = 3;                         // length = 3
        buf[23] = shift.min(14);             // shift count (0-14)
    }

    if !payload.is_empty() {
        buf[hdr_len..total].copy_from_slice(payload);
    }

    let cksum = checksum::pseudo_header_checksum(src_ip, dst_ip, 6, &buf[..total]);
    buf[16..18].copy_from_slice(&cksum.to_be_bytes());

    total
}

/// Parsed TCP options from a segment.
struct TcpOptions {
    /// Window scale shift count, if present (kind=3).
    window_scale: Option<u8>,
}

/// Parse TCP options from a segment. Looks for window scale (kind=3).
fn parse_tcp_options(segment: &[u8], hdr: &TcpHeader) -> TcpOptions {
    let mut opts = TcpOptions {
        window_scale: None,
    };
    let opts_end = (hdr.data_offset as usize) * 4;
    if opts_end <= TCP_HDR_LEN || opts_end > segment.len() {
        return opts;
    }
    let mut pos = TCP_HDR_LEN;
    while pos < opts_end {
        let kind = segment[pos];
        if kind == TCP_OPT_END {
            break;
        }
        if kind == TCP_OPT_NOP {
            pos += 1;
            continue;
        }
        // All other options have kind + length.
        if pos + 1 >= opts_end {
            break;
        }
        let opt_len = segment[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > opts_end {
            break;
        }
        if kind == TCP_OPT_WINDOW_SCALE && opt_len == 3 && pos + 2 < opts_end {
            let shift = segment[pos + 2];
            opts.window_scale = Some(shift.min(14));
        }
        pos += opt_len;
    }
    opts
}
