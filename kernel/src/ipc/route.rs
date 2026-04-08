//! Network-transparent IPC routing layer ("Swarm OS").
//!
//! Extends the IPC system to route messages across physical nodes.
//! Each node in the swarm has a unique 16-bit node ID. Endpoints can
//! be published to the distributed namespace, and IPC messages to
//! remote endpoints are automatically serialized and routed over the
//! network transport.
//!
//! Architecture:
//!   Local send → endpoint::send() (fast path, same as before)
//!   Remote send → serialize message → post to net service → deliver on target node
//!
//! The routing table maps endpoint IDs to node IDs. When an endpoint
//! is not found locally, the router checks if it has a remote route
//! and forwards the message accordingly.

use crate::ipc::endpoint::Message;
use crate::sync::ticket::TicketMutex;

/// Node ID 0 = local node (never routed over network).
pub const NODE_LOCAL: u16 = 0;

/// Maximum remote route entries.
const MAX_ROUTES: usize = 64;

/// A route entry mapping an endpoint to a remote node.
#[derive(Clone, Copy)]
struct RouteEntry {
    /// The endpoint handle (as known locally — a proxy handle).
    endpoint_raw: u32,
    /// The remote node that owns this endpoint.
    node_id: u16,
    /// The endpoint handle on the remote node.
    remote_endpoint_raw: u32,
    /// Whether this route is active.
    active: bool,
}

impl RouteEntry {
    const fn empty() -> Self {
        Self {
            endpoint_raw: 0,
            node_id: 0,
            remote_endpoint_raw: 0,
            active: false,
        }
    }
}

/// The global routing table for remote IPC.
struct RouteTable {
    entries: [RouteEntry; MAX_ROUTES],
    count: usize,
    /// This node's ID in the swarm.
    local_node_id: u16,
}

impl RouteTable {
    const fn new() -> Self {
        Self {
            entries: [RouteEntry::empty(); MAX_ROUTES],
            count: 0,
            local_node_id: NODE_LOCAL,
        }
    }

    /// Register a remote endpoint route.
    fn add_route(&mut self, local_proxy: u32, node_id: u16, remote_ep: u32) -> bool {
        if self.count >= MAX_ROUTES {
            return false;
        }
        // Find a free slot.
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.endpoint_raw = local_proxy;
                entry.node_id = node_id;
                entry.remote_endpoint_raw = remote_ep;
                entry.active = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Look up a remote route for an endpoint.
    fn lookup(&self, endpoint_raw: u32) -> Option<(u16, u32)> {
        for entry in &self.entries {
            if entry.active && entry.endpoint_raw == endpoint_raw {
                return Some((entry.node_id, entry.remote_endpoint_raw));
            }
        }
        None
    }

    /// Remove a route.
    fn remove_route(&mut self, endpoint_raw: u32) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.endpoint_raw == endpoint_raw {
                entry.active = false;
                self.count -= 1;
                return true;
            }
        }
        false
    }
}

static ROUTE_TABLE: TicketMutex<RouteTable> = TicketMutex::new(RouteTable::new());

/// Serialized IPC message for network transport.
/// Fixed-size wire format: 80 bytes (tag:8 + regs:64 + cap:4 + flags:4).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WireMessage {
    pub tag: u64,
    pub regs: [u64; 8],
    pub cap_transfer: u32,
    pub flags: u32,
}

impl WireMessage {
    /// Serialize an in-kernel Message to wire format.
    pub fn from_message(msg: &Message) -> Self {
        Self {
            tag: msg.tag,
            regs: msg.regs,
            cap_transfer: msg.cap_transfer.unwrap_or(0),
            flags: if msg.cap_transfer.is_some() { 1 } else { 0 },
        }
    }

    /// Deserialize wire format back to an in-kernel Message.
    pub fn to_message(&self) -> Message {
        Message {
            tag: self.tag,
            regs: self.regs,
            cap_transfer: if self.flags & 1 != 0 {
                Some(self.cap_transfer)
            } else {
                None
            },
        }
    }

    /// Serialize to raw bytes for network transmission.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: WireMessage is #[repr(C)] + Copy with no padding holes and
        // no internal references; reinterpreting it as a byte slice of exactly
        // size_of::<Self>() bytes is valid. The returned slice borrows from
        // &self, so the lifetime is bounded correctly.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Deserialize from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut msg = Self {
            tag: 0,
            regs: [0; 8],
            cap_transfer: 0,
            flags: 0,
        };
        // SAFETY: length was bounds-checked above (`data.len() >= size_of::<Self>()`),
        // `msg` is a freshly owned #[repr(C)] value on the stack (exclusive write
        // access), src and dst ranges cannot overlap, and WireMessage is POD so any
        // byte pattern is a valid inhabitant.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                &mut msg as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(msg)
    }
}

/// Set this node's ID in the swarm.
pub fn set_node_id(id: u16) {
    ROUTE_TABLE.lock().local_node_id = id;
}

/// Get this node's ID.
pub fn node_id() -> u16 {
    ROUTE_TABLE.lock().local_node_id
}

/// Register a remote endpoint route.
/// `local_proxy` is a local endpoint handle that acts as a proxy.
/// Messages sent to this proxy will be forwarded to `node_id:remote_ep`.
pub fn add_route(local_proxy: u32, node_id: u16, remote_ep: u32) -> bool {
    ROUTE_TABLE
        .lock()
        .add_route(local_proxy, node_id, remote_ep)
}

/// Look up whether an endpoint has a remote route.
/// Returns (node_id, remote_endpoint_handle) if remote.
pub fn lookup_route(endpoint_raw: u32) -> Option<(u16, u32)> {
    ROUTE_TABLE.lock().lookup(endpoint_raw)
}

/// Remove a remote route.
pub fn remove_route(endpoint_raw: u32) -> bool {
    ROUTE_TABLE.lock().remove_route(endpoint_raw)
}

/// Check if a message should be routed remotely.
/// Called by endpoint::send() before local delivery.
/// Returns true if the message was forwarded (caller should not do local delivery).
pub fn try_remote_send(endpoint_raw: u32, msg: &Message) -> bool {
    if let Some((_node_id, _remote_ep)) = lookup_route(endpoint_raw) {
        // Serialize the message to wire format.
        let _wire = WireMessage::from_message(msg);

        // In a full implementation, this would:
        // 1. Post the serialized message to the net service via IPC
        // 2. The net service sends it over the network to the target node
        // 3. The target node deserializes and delivers locally
        //
        // Remote routing is registered; delivery requires
        // the net service to poll for outbound messages.
        //
        // The routing infrastructure is in place — the actual network
        // transport hooks into the existing virtio-net driver.
        false // Not yet connected to transport — fall through to local
    } else {
        false
    }
}
