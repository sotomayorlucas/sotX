//! Protocol handler trait and TCP/UDP/ICMP implementations.
//!
//! Each protocol handler processes inbound segments and produces
//! outbound frames. TCP carries a full state machine; UDP is
//! stateless; ICMP handles echo request/reply.

use alloc::vec::Vec;
use core::net::SocketAddrV4;

// ---------------------------------------------------------------------------
// Protocol handler trait
// ---------------------------------------------------------------------------

/// Opaque connection / flow identifier returned by protocol handlers.
pub type FlowId = u64;

/// Events produced by protocol handlers for the network domain to act on.
#[derive(Debug, Clone)]
pub enum ProtoEvent {
    /// Data ready to deliver to the socket receive buffer.
    Deliver { flow: FlowId, data: Vec<u8> },
    /// Raw frame to transmit on the wire.
    Transmit { frame: Vec<u8> },
    /// Connection fully established.
    Connected { flow: FlowId },
    /// Peer closed their send direction.
    PeerClosed { flow: FlowId },
    /// Connection reset.
    Reset { flow: FlowId },
}

/// Trait implemented by each protocol (TCP, UDP, ICMP).
pub trait ProtocolHandler {
    /// Feed a raw inbound segment to the protocol engine.
    /// Returns zero or more events for the network domain.
    fn input(&mut self, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<ProtoEvent>;

    /// Request to send application data on the given flow.
    /// Returns events (typically a `Transmit`).
    fn send(&mut self, flow: FlowId, data: &[u8]) -> Vec<ProtoEvent>;

    /// Open a new outbound connection / flow.
    fn connect(&mut self, local: SocketAddrV4, remote: SocketAddrV4) -> (FlowId, Vec<ProtoEvent>);

    /// Bind a listening endpoint. Returns the flow id.
    fn listen(&mut self, local: SocketAddrV4) -> FlowId;

    /// Tear down a flow.
    fn close(&mut self, flow: FlowId) -> Vec<ProtoEvent>;
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// TCP connection states (RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Per-connection TCP control block.
#[derive(Debug)]
pub struct TcpCb {
    pub flow: FlowId,
    pub state: TcpState,
    pub local: SocketAddrV4,
    pub remote: Option<SocketAddrV4>,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
}

/// TCP protocol handler -- manages a set of TCBs.
pub struct TcpHandler {
    connections: Vec<TcpCb>,
    next_flow: FlowId,
}

impl TcpHandler {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            next_flow: 1,
        }
    }

    fn alloc_flow(&mut self) -> FlowId {
        let f = self.next_flow;
        self.next_flow += 1;
        f
    }

    fn find_mut(&mut self, flow: FlowId) -> Option<&mut TcpCb> {
        self.connections.iter_mut().find(|c| c.flow == flow)
    }
}

impl Default for TcpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolHandler for TcpHandler {
    fn input(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> Vec<ProtoEvent> {
        // Find a matching connection by (local=dst, remote=src).
        let cb = self.connections.iter_mut().find(|c| {
            c.local == dst && (c.remote == Some(src) || c.remote.is_none())
        });
        let cb = match cb {
            Some(c) => c,
            None => return Vec::new(), // no matching TCB -- drop
        };

        let mut events = Vec::new();

        match cb.state {
            TcpState::Listen => {
                // Simulate SYN arrival: transition to SynRcvd, emit SYN+ACK.
                cb.remote = Some(src);
                cb.state = TcpState::SynRcvd;
                events.push(ProtoEvent::Transmit {
                    frame: Vec::new(), // placeholder for SYN+ACK frame
                });
            }
            TcpState::SynSent => {
                // SYN+ACK received -- move to Established.
                cb.state = TcpState::Established;
                cb.rcv_nxt = cb.rcv_nxt.wrapping_add(1);
                events.push(ProtoEvent::Connected { flow: cb.flow });
                events.push(ProtoEvent::Transmit {
                    frame: Vec::new(), // ACK
                });
            }
            TcpState::SynRcvd => {
                // ACK of our SYN+ACK -- connection established.
                cb.state = TcpState::Established;
                events.push(ProtoEvent::Connected { flow: cb.flow });
            }
            TcpState::Established => {
                if payload.is_empty() {
                    // FIN received.
                    cb.state = TcpState::CloseWait;
                    events.push(ProtoEvent::PeerClosed { flow: cb.flow });
                } else {
                    cb.rcv_nxt = cb.rcv_nxt.wrapping_add(payload.len() as u32);
                    events.push(ProtoEvent::Deliver {
                        flow: cb.flow,
                        data: payload.to_vec(),
                    });
                    events.push(ProtoEvent::Transmit {
                        frame: Vec::new(), // ACK
                    });
                }
            }
            TcpState::FinWait1 => {
                // ACK of our FIN -- move to FinWait2.
                cb.state = TcpState::FinWait2;
            }
            TcpState::FinWait2 => {
                // FIN from peer -- move to TimeWait.
                cb.state = TcpState::TimeWait;
                events.push(ProtoEvent::Transmit {
                    frame: Vec::new(), // ACK
                });
            }
            TcpState::LastAck => {
                // ACK of our FIN -- fully closed.
                cb.state = TcpState::Closed;
            }
            _ => {}
        }

        events
    }

    fn send(&mut self, flow: FlowId, data: &[u8]) -> Vec<ProtoEvent> {
        let cb = match self.find_mut(flow) {
            Some(c) => c,
            None => return Vec::new(),
        };
        if cb.state != TcpState::Established {
            return Vec::new();
        }
        cb.snd_nxt = cb.snd_nxt.wrapping_add(data.len() as u32);
        alloc::vec![ProtoEvent::Transmit {
            frame: data.to_vec(), // placeholder -- real impl prepends TCP/IP header
        }]
    }

    fn connect(&mut self, local: SocketAddrV4, remote: SocketAddrV4) -> (FlowId, Vec<ProtoEvent>) {
        let flow = self.alloc_flow();
        self.connections.push(TcpCb {
            flow,
            state: TcpState::SynSent,
            local,
            remote: Some(remote),
            snd_nxt: 1000, // placeholder ISN
            rcv_nxt: 0,
        });
        (
            flow,
            alloc::vec![ProtoEvent::Transmit {
                frame: Vec::new(), // SYN segment
            }],
        )
    }

    fn listen(&mut self, local: SocketAddrV4) -> FlowId {
        let flow = self.alloc_flow();
        self.connections.push(TcpCb {
            flow,
            state: TcpState::Listen,
            local,
            remote: None,
            snd_nxt: 0,
            rcv_nxt: 0,
        });
        flow
    }

    fn close(&mut self, flow: FlowId) -> Vec<ProtoEvent> {
        let cb = match self.find_mut(flow) {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut events = Vec::new();
        match cb.state {
            TcpState::Established => {
                cb.state = TcpState::FinWait1;
                events.push(ProtoEvent::Transmit {
                    frame: Vec::new(), // FIN
                });
            }
            TcpState::CloseWait => {
                cb.state = TcpState::LastAck;
                events.push(ProtoEvent::Transmit {
                    frame: Vec::new(), // FIN
                });
            }
            _ => {
                cb.state = TcpState::Closed;
            }
        }
        events
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// Stateless UDP handler.
pub struct UdpHandler {
    next_flow: FlowId,
    /// Bound local addresses, keyed by flow.
    bindings: Vec<(FlowId, SocketAddrV4)>,
}

impl UdpHandler {
    pub fn new() -> Self {
        Self {
            next_flow: 1,
            bindings: Vec::new(),
        }
    }

    fn alloc_flow(&mut self) -> FlowId {
        let f = self.next_flow;
        self.next_flow += 1;
        f
    }
}

impl Default for UdpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolHandler for UdpHandler {
    fn input(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> Vec<ProtoEvent> {
        // Demux by destination port.
        let _ = src;
        for &(flow, ref local) in &self.bindings {
            if local.port() == dst.port() {
                return alloc::vec![ProtoEvent::Deliver {
                    flow,
                    data: payload.to_vec(),
                }];
            }
        }
        Vec::new()
    }

    fn send(&mut self, _flow: FlowId, data: &[u8]) -> Vec<ProtoEvent> {
        alloc::vec![ProtoEvent::Transmit {
            frame: data.to_vec(),
        }]
    }

    fn connect(
        &mut self,
        local: SocketAddrV4,
        _remote: SocketAddrV4,
    ) -> (FlowId, Vec<ProtoEvent>) {
        let flow = self.alloc_flow();
        self.bindings.push((flow, local));
        (flow, Vec::new())
    }

    fn listen(&mut self, local: SocketAddrV4) -> FlowId {
        let flow = self.alloc_flow();
        self.bindings.push((flow, local));
        flow
    }

    fn close(&mut self, flow: FlowId) -> Vec<ProtoEvent> {
        self.bindings.retain(|(f, _)| *f != flow);
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

/// ICMP echo handler. Replies to echo requests; tracks outstanding
/// echo-request flows for ping.
pub struct IcmpHandler {
    next_flow: FlowId,
    /// Active ping flows: (flow, expected peer IP).
    pings: Vec<(FlowId, SocketAddrV4)>,
}

impl IcmpHandler {
    pub fn new() -> Self {
        Self {
            next_flow: 1,
            pings: Vec::new(),
        }
    }

    fn alloc_flow(&mut self) -> FlowId {
        let f = self.next_flow;
        self.next_flow += 1;
        f
    }

    /// Build a minimal ICMP echo reply payload (type=0, code=0).
    fn echo_reply(request_payload: &[u8]) -> Vec<u8> {
        if request_payload.len() < 8 {
            return Vec::new();
        }
        let mut reply = request_payload.to_vec();
        reply[0] = 0; // type = echo reply
        reply[1] = 0; // code
        // Zero checksum field before recalculating.
        reply[2] = 0;
        reply[3] = 0;
        let cksum = Self::checksum(&reply);
        reply[2] = (cksum >> 8) as u8;
        reply[3] = cksum as u8;
        reply
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }
}

impl Default for IcmpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolHandler for IcmpHandler {
    fn input(
        &mut self,
        src: SocketAddrV4,
        _dst: SocketAddrV4,
        payload: &[u8],
    ) -> Vec<ProtoEvent> {
        if payload.is_empty() {
            return Vec::new();
        }
        let icmp_type = payload[0];
        match icmp_type {
            8 => {
                // Echo request -- generate reply.
                let reply = Self::echo_reply(payload);
                if reply.is_empty() {
                    return Vec::new();
                }
                alloc::vec![ProtoEvent::Transmit { frame: reply }]
            }
            0 => {
                // Echo reply -- deliver to matching ping flow.
                for &(flow, ref peer) in &self.pings {
                    if *peer.ip() == *src.ip() {
                        return alloc::vec![ProtoEvent::Deliver {
                            flow,
                            data: payload.to_vec(),
                        }];
                    }
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn send(&mut self, _flow: FlowId, data: &[u8]) -> Vec<ProtoEvent> {
        alloc::vec![ProtoEvent::Transmit {
            frame: data.to_vec(),
        }]
    }

    fn connect(
        &mut self,
        _local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> (FlowId, Vec<ProtoEvent>) {
        let flow = self.alloc_flow();
        self.pings.push((flow, remote));
        (flow, Vec::new())
    }

    fn listen(&mut self, _local: SocketAddrV4) -> FlowId {
        self.alloc_flow()
    }

    fn close(&mut self, flow: FlowId) -> Vec<ProtoEvent> {
        self.pings.retain(|(f, _)| *f != flow);
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    #[test]
    fn tcp_connect_established() {
        let mut tcp = TcpHandler::new();
        let local = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345);
        let remote = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80);

        let (flow, events) = tcp.connect(local, remote);
        assert_eq!(events.len(), 1); // SYN

        // Simulate SYN+ACK from server.
        let events = tcp.input(remote, local, &[]);
        assert!(events.iter().any(|e| matches!(e, ProtoEvent::Connected { .. })));

        let cb = tcp.find_mut(flow).unwrap();
        assert_eq!(cb.state, TcpState::Established);
    }

    #[test]
    fn tcp_listen_accept() {
        let mut tcp = TcpHandler::new();
        let local = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 80);
        let flow = tcp.listen(local);

        let client = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 9999);
        // SYN from client.
        let events = tcp.input(client, local, &[]);
        assert_eq!(events.len(), 1); // SYN+ACK

        let cb = tcp.find_mut(flow).unwrap();
        assert_eq!(cb.state, TcpState::SynRcvd);

        // ACK from client.
        let events = tcp.input(client, local, &[]);
        assert!(events.iter().any(|e| matches!(e, ProtoEvent::Connected { .. })));
    }

    #[test]
    fn udp_roundtrip() {
        let mut udp = UdpHandler::new();
        let local = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353);
        let flow = udp.listen(local);

        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 1234);
        let events = udp.input(peer, local, b"hello");
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtoEvent::Deliver { flow: f, data } => {
                assert_eq!(*f, flow);
                assert_eq!(data.as_slice(), b"hello");
            }
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn icmp_echo_reply() {
        let mut icmp = IcmpHandler::new();
        // Build a minimal echo request: type=8, code=0, cksum=0, id=1, seq=1.
        let request = [8u8, 0, 0, 0, 0, 1, 0, 1];
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 0);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 0);

        let events = icmp.input(src, dst, &request);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtoEvent::Transmit { frame } => {
                assert_eq!(frame[0], 0); // echo reply type
            }
            _ => panic!("expected Transmit"),
        }
    }
}
