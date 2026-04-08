//! BSD socket model where each socket is a SecureObject.
//!
//! Every socket carries a capability that encodes the permitted
//! operations (send, recv, bind, listen, accept, connect). All
//! socket operations validate the caller's capability before
//! proceeding, enforcing least-privilege at the network layer.

use alloc::vec::Vec;
use core::net::SocketAddrV4;

/// Rights that a socket capability may grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketRights(u32);

impl SocketRights {
    pub const SEND: u32 = 1 << 0;
    pub const RECV: u32 = 1 << 1;
    pub const BIND: u32 = 1 << 2;
    pub const LISTEN: u32 = 1 << 3;
    pub const ACCEPT: u32 = 1 << 4;
    pub const CONNECT: u32 = 1 << 5;

    /// Full rights -- every operation permitted.
    pub const ALL: Self = Self(
        Self::SEND | Self::RECV | Self::BIND | Self::LISTEN | Self::ACCEPT | Self::CONNECT,
    );

    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn has(self, right: u32) -> bool {
        self.0 & right != 0
    }

    /// Attenuate: produce a subset that keeps only the requested rights.
    pub const fn attenuate(self, mask: u32) -> Self {
        Self(self.0 & mask)
    }
}

/// Capability token bound to a specific socket.
#[derive(Debug, Clone)]
pub struct SocketCap {
    /// Opaque id of the socket this capability refers to.
    pub socket_id: u64,
    /// Permitted operations.
    pub rights: SocketRights,
}

impl SocketCap {
    pub fn new(socket_id: u64, rights: SocketRights) -> Self {
        Self { socket_id, rights }
    }

    /// Derive a weaker capability (can only remove rights, never add).
    pub fn attenuate(&self, mask: u32) -> Self {
        Self {
            socket_id: self.socket_id,
            rights: self.rights.attenuate(mask),
        }
    }
}

/// Socket type (mirrors BSD SOCK_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Stream, // SOCK_STREAM -- TCP
    Dgram,  // SOCK_DGRAM  -- UDP
    Raw,    // SOCK_RAW    -- raw IP / ICMP
}

/// Socket lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connected,
    Closed,
}

/// A single BSD socket as a SecureObject.
#[derive(Debug)]
pub struct SocketSO {
    pub id: u64,
    pub sock_type: SocketType,
    pub state: SocketState,
    pub local_addr: Option<SocketAddrV4>,
    pub remote_addr: Option<SocketAddrV4>,
    /// Per-socket receive buffer (application data).
    pub recv_buf: Vec<u8>,
}

/// Errors returned by socket operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// The capability does not carry the required right.
    PermissionDenied,
    /// Operation invalid in current socket state.
    InvalidState,
    /// Address already in use.
    AddrInUse,
    /// Receive buffer is empty / would block.
    WouldBlock,
    /// Socket has been closed.
    Closed,
}

impl SocketSO {
    /// Create a new unbound socket.
    pub fn new(id: u64, sock_type: SocketType) -> Self {
        Self {
            id,
            sock_type,
            state: SocketState::Unbound,
            local_addr: None,
            remote_addr: None,
            recv_buf: Vec::new(),
        }
    }

    /// Bind the socket to a local address.
    pub fn bind(&mut self, cap: &SocketCap, addr: SocketAddrV4) -> Result<(), SocketError> {
        Self::check(cap, self.id, SocketRights::BIND)?;
        if self.state != SocketState::Unbound {
            return Err(SocketError::InvalidState);
        }
        self.local_addr = Some(addr);
        self.state = SocketState::Bound;
        Ok(())
    }

    /// Mark a stream socket as listening.
    pub fn listen(&mut self, cap: &SocketCap) -> Result<(), SocketError> {
        Self::check(cap, self.id, SocketRights::LISTEN)?;
        if self.sock_type != SocketType::Stream || self.state != SocketState::Bound {
            return Err(SocketError::InvalidState);
        }
        self.state = SocketState::Listening;
        Ok(())
    }

    /// Initiate a connection (stream) or set the default peer (dgram).
    pub fn connect(
        &mut self,
        cap: &SocketCap,
        remote: SocketAddrV4,
    ) -> Result<(), SocketError> {
        Self::check(cap, self.id, SocketRights::CONNECT)?;
        match self.sock_type {
            SocketType::Stream => {
                if self.state != SocketState::Unbound && self.state != SocketState::Bound {
                    return Err(SocketError::InvalidState);
                }
            }
            SocketType::Dgram | SocketType::Raw => {
                if self.state == SocketState::Closed {
                    return Err(SocketError::InvalidState);
                }
            }
        }
        self.remote_addr = Some(remote);
        self.state = SocketState::Connected;
        Ok(())
    }

    /// Accept a connection on a listening socket.
    /// Returns the id that the caller should use to create the child socket.
    pub fn accept(&self, cap: &SocketCap, child_id: u64) -> Result<SocketSO, SocketError> {
        Self::check(cap, self.id, SocketRights::ACCEPT)?;
        if self.state != SocketState::Listening {
            return Err(SocketError::InvalidState);
        }
        // In a real implementation this would dequeue from the accept
        // backlog. Here we return a connected child socket placeholder.
        let mut child = SocketSO::new(child_id, SocketType::Stream);
        child.local_addr = self.local_addr;
        child.state = SocketState::Connected;
        Ok(child)
    }

    /// Send data on a connected socket.
    pub fn send(&self, cap: &SocketCap, data: &[u8]) -> Result<usize, SocketError> {
        Self::check(cap, self.id, SocketRights::SEND)?;
        if self.state != SocketState::Connected {
            return Err(SocketError::InvalidState);
        }
        // Actual transmission is delegated to the protocol handler.
        // Return the number of bytes accepted.
        Ok(data.len())
    }

    /// Pull data from the receive buffer.
    pub fn recv(&mut self, cap: &SocketCap, buf: &mut [u8]) -> Result<usize, SocketError> {
        Self::check(cap, self.id, SocketRights::RECV)?;
        if self.state == SocketState::Closed {
            return Err(SocketError::Closed);
        }
        if self.recv_buf.is_empty() {
            return Err(SocketError::WouldBlock);
        }
        let n = buf.len().min(self.recv_buf.len());
        buf[..n].copy_from_slice(&self.recv_buf[..n]);
        // Drain consumed bytes.
        self.recv_buf.drain(..n);
        Ok(n)
    }

    /// Close the socket.
    pub fn close(&mut self) {
        self.state = SocketState::Closed;
        self.recv_buf.clear();
    }

    fn check(cap: &SocketCap, expected_id: u64, right: u32) -> Result<(), SocketError> {
        if cap.socket_id != expected_id {
            return Err(SocketError::PermissionDenied);
        }
        if !cap.rights.has(right) {
            return Err(SocketError::PermissionDenied);
        }
        Ok(())
    }
}

/// A table that maps socket ids to live sockets.
/// Network domain keeps exactly one of these.
pub struct SocketTable {
    sockets: Vec<SocketSO>,
    next_id: u64,
}

impl SocketTable {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
            next_id: 1,
        }
    }

    /// Allocate a new socket and return its id + full-rights capability.
    pub fn create(&mut self, sock_type: SocketType) -> (u64, SocketCap) {
        let id = self.next_id;
        self.next_id += 1;
        self.sockets.push(SocketSO::new(id, sock_type));
        (id, SocketCap::new(id, SocketRights::ALL))
    }

    /// Look up a socket by id (mutable).
    pub fn get_mut(&mut self, id: u64) -> Option<&mut SocketSO> {
        self.sockets.iter_mut().find(|s| s.id == id)
    }

    /// Look up a socket by id (shared).
    pub fn get(&self, id: u64) -> Option<&SocketSO> {
        self.sockets.iter().find(|s| s.id == id)
    }

    /// Remove a closed socket from the table.
    pub fn remove(&mut self, id: u64) {
        self.sockets.retain(|s| s.id != id);
    }
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    #[test]
    fn bind_and_listen() {
        let mut tbl = SocketTable::new();
        let (id, cap) = tbl.create(SocketType::Stream);
        let sock = tbl.get_mut(id).unwrap();

        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080);
        assert!(sock.bind(&cap, addr).is_ok());
        assert!(sock.listen(&cap).is_ok());
        assert_eq!(sock.state, SocketState::Listening);
    }

    #[test]
    fn attenuated_cap_blocks_listen() {
        let mut tbl = SocketTable::new();
        let (id, cap) = tbl.create(SocketType::Stream);
        // Remove LISTEN right.
        let weak = cap.attenuate(SocketRights::SEND | SocketRights::RECV | SocketRights::BIND);
        let sock = tbl.get_mut(id).unwrap();

        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80);
        assert!(sock.bind(&weak, addr).is_ok());
        assert_eq!(sock.listen(&weak), Err(SocketError::PermissionDenied));
    }

    #[test]
    fn connect_and_send() {
        let mut tbl = SocketTable::new();
        let (id, cap) = tbl.create(SocketType::Stream);
        let sock = tbl.get_mut(id).unwrap();

        let remote = SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 443);
        assert!(sock.connect(&cap, remote).is_ok());
        assert_eq!(sock.send(&cap, b"GET / HTTP/1.0\r\n"), Ok(16));
    }

    #[test]
    fn recv_with_data() {
        let mut tbl = SocketTable::new();
        let (id, cap) = tbl.create(SocketType::Stream);
        let sock = tbl.get_mut(id).unwrap();

        let remote = SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 80);
        sock.connect(&cap, remote).unwrap();

        // Simulate inbound data arrival.
        sock.recv_buf.extend_from_slice(b"HTTP/1.0 200 OK\r\n");

        let mut buf = [0u8; 64];
        let n = sock.recv(&cap, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.0 200 OK\r\n");
    }

    #[test]
    fn wrong_socket_id_denied() {
        let mut tbl = SocketTable::new();
        let (id, _cap) = tbl.create(SocketType::Dgram);
        let (_id2, cap2) = tbl.create(SocketType::Dgram);
        let sock = tbl.get_mut(id).unwrap();

        // cap2 refers to a different socket -- must be rejected.
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
        assert_eq!(sock.bind(&cap2, addr), Err(SocketError::PermissionDenied));
    }
}
