//! In-memory provenance graph built incrementally from entry streams.

use crate::types::ProvenanceEntry;

/// Maximum nodes (SOs) tracked simultaneously.
const MAX_NODES: usize = 512;
/// Maximum edges (domain -> SO relationships) tracked.
const MAX_EDGES: usize = 2048;

/// A node in the provenance graph representing a semantic object.
#[derive(Clone, Copy)]
pub struct GraphNode {
    pub so_id: u64,
    pub so_type: u8,
    /// First epoch this SO was seen.
    pub first_seen: u64,
    /// Last epoch this SO was touched.
    pub last_seen: u64,
    /// How many operations targeted this SO.
    pub touch_count: u32,
    pub active: bool,
}

impl GraphNode {
    pub const fn empty() -> Self {
        Self {
            so_id: 0,
            so_type: 0,
            first_seen: 0,
            last_seen: 0,
            touch_count: 0,
            active: false,
        }
    }
}

/// A directed edge: domain performed operation on SO.
#[derive(Clone, Copy)]
pub struct GraphEdge {
    pub domain_id: u32,
    pub so_id: u64,
    pub operation: u16,
    pub epoch: u64,
    pub rights: u32,
    pub active: bool,
}

impl GraphEdge {
    pub const fn empty() -> Self {
        Self {
            domain_id: 0,
            so_id: 0,
            operation: 0,
            epoch: 0,
            rights: 0,
            active: false,
        }
    }
}

/// Per-domain activity summary for fan-out detection.
#[derive(Clone, Copy)]
pub struct DomainActivity {
    pub domain_id: u32,
    /// Distinct SOs touched (ring buffer of recent SO IDs).
    pub recent_sos: [u64; 64],
    pub recent_count: usize,
    /// Epoch of the oldest entry in `recent_sos`.
    pub window_start: u64,
    /// Whether this domain read a credential-type SO.
    pub read_credential: bool,
    /// Whether this domain wrote to a system binary SO.
    pub wrote_system_binary: bool,
    /// Whether this domain accessed the network after reading sensitive data.
    pub accessed_network: bool,
    /// Whether this domain modified a config/startup SO.
    pub modified_config: bool,
    /// Whether this domain granted a cap to another domain.
    pub granted_cap: bool,
    /// Target domain of the most recent grant (0 = none).
    pub grant_target: u32,
    pub active: bool,
}

impl DomainActivity {
    pub const fn empty() -> Self {
        Self {
            domain_id: 0,
            recent_sos: [0; 64],
            recent_count: 0,
            window_start: 0,
            read_credential: false,
            wrote_system_binary: false,
            accessed_network: false,
            modified_config: false,
            granted_cap: false,
            grant_target: 0,
            active: false,
        }
    }
}

/// Maximum domains tracked.
const MAX_DOMAINS: usize = 64;

/// Live provenance graph built incrementally from entry streams.
pub struct ProvenanceGraph {
    pub nodes: [GraphNode; MAX_NODES],
    pub node_count: usize,
    pub edges: [GraphEdge; MAX_EDGES],
    pub edge_count: usize,
    pub domains: [DomainActivity; MAX_DOMAINS],
    pub domain_count: usize,
}

impl ProvenanceGraph {
    pub const fn new() -> Self {
        Self {
            nodes: [GraphNode::empty(); MAX_NODES],
            node_count: 0,
            edges: [GraphEdge::empty(); MAX_EDGES],
            edge_count: 0,
            domains: [DomainActivity::empty(); MAX_DOMAINS],
            domain_count: 0,
        }
    }

    /// Find or create a node for the given SO.
    pub fn ensure_node(&mut self, so_id: u64, so_type: u8, epoch: u64) -> Option<usize> {
        // Search for existing node.
        for i in 0..self.node_count {
            if self.nodes[i].active && self.nodes[i].so_id == so_id {
                self.nodes[i].last_seen = epoch;
                self.nodes[i].touch_count += 1;
                return Some(i);
            }
        }
        // Create new node.
        if self.node_count >= MAX_NODES {
            return None;
        }
        let idx = self.node_count;
        self.nodes[idx] = GraphNode {
            so_id,
            so_type,
            first_seen: epoch,
            last_seen: epoch,
            touch_count: 1,
            active: true,
        };
        self.node_count += 1;
        Some(idx)
    }

    /// Record an edge (domain -> SO operation).
    pub fn add_edge(&mut self, entry: &ProvenanceEntry) -> Option<usize> {
        if self.edge_count >= MAX_EDGES {
            return None;
        }
        let idx = self.edge_count;
        self.edges[idx] = GraphEdge {
            domain_id: entry.domain_id,
            so_id: entry.so_id,
            operation: entry.operation,
            epoch: entry.epoch,
            rights: entry.rights,
            active: true,
        };
        self.edge_count += 1;
        Some(idx)
    }

    /// Find or create domain activity tracker.
    pub fn ensure_domain(&mut self, domain_id: u32) -> Option<&mut DomainActivity> {
        // Search existing.
        for i in 0..self.domain_count {
            if self.domains[i].active && self.domains[i].domain_id == domain_id {
                return Some(&mut self.domains[i]);
            }
        }
        // Create new.
        if self.domain_count >= MAX_DOMAINS {
            return None;
        }
        let idx = self.domain_count;
        self.domains[idx] = DomainActivity {
            domain_id,
            active: true,
            ..DomainActivity::empty()
        };
        self.domain_count += 1;
        Some(&mut self.domains[idx])
    }

    /// Ingest one provenance entry, updating nodes, edges, and domain activity.
    pub fn ingest_entry(&mut self, entry: &ProvenanceEntry) {
        self.ensure_node(entry.so_id, entry.so_type, entry.epoch);
        self.add_edge(entry);

        if let Some(da) = self.ensure_domain(entry.domain_id) {
            // Track distinct SOs in sliding window.
            let already_tracked = da.recent_sos[..da.recent_count]
                .iter()
                .any(|&id| id == entry.so_id);
            if !already_tracked && da.recent_count < 64 {
                da.recent_sos[da.recent_count] = entry.so_id;
                da.recent_count += 1;
            }
            if da.window_start == 0 {
                da.window_start = entry.epoch;
            }

            // Update behavioral flags based on operation + SO type.
            update_domain_flags(da, entry);
        }
    }

    /// Get domain activity by ID (immutable).
    pub fn domain_activity(&self, domain_id: u32) -> Option<&DomainActivity> {
        for i in 0..self.domain_count {
            if self.domains[i].active && self.domains[i].domain_id == domain_id {
                return Some(&self.domains[i]);
            }
        }
        None
    }

    /// Count distinct SOs a domain touched within a given epoch window.
    pub fn domain_fanout(&self, domain_id: u32, window_start: u64) -> u32 {
        let mut seen = [0u64; 256];
        let mut seen_count = 0usize;

        for i in 0..self.edge_count {
            let e = &self.edges[i];
            if e.active && e.domain_id == domain_id && e.epoch >= window_start {
                let already = seen[..seen_count].iter().any(|&id| id == e.so_id);
                if !already && seen_count < 256 {
                    seen[seen_count] = e.so_id;
                    seen_count += 1;
                }
            }
        }
        seen_count as u32
    }
}

/// Update per-domain behavioral flags from a single entry.
fn update_domain_flags(da: &mut DomainActivity, entry: &ProvenanceEntry) {
    use crate::types::{Operation, SoType};

    let op = Operation::from_u16(entry.operation);
    let st = SoType::from_u8(entry.so_type);

    match (op, st) {
        (Some(Operation::Read), Some(SoType::Credential)) => {
            da.read_credential = true;
        }
        (Some(Operation::Write), Some(SoType::SystemBinary)) => {
            da.wrote_system_binary = true;
        }
        (Some(Operation::NetworkAccess), _) => {
            if da.read_credential {
                da.accessed_network = true;
            }
        }
        (Some(Operation::Write), Some(SoType::ConfigFile)) => {
            da.modified_config = true;
        }
        (Some(Operation::Grant), _) => {
            da.granted_cap = true;
            // secondary_so encodes the target domain for grants.
            da.grant_target = entry.secondary_so as u32;
        }
        _ => {}
    }
}
