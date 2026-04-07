//! HAMMER2 clustering for distributed deception (Phase 3).
//!
//! Multiple nodes maintain synchronized copies via SOT IPC channels.

/// Node operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Online,
    Syncing,
    Offline,
    Failed,
}

/// A single node in the HAMMER2 cluster.
#[derive(Debug, Clone, Copy)]
pub struct ClusterNode {
    pub id: u32,
    /// SOT IPC channel capability to this node.
    pub channel_cap: u64,
    /// Last synchronized transaction ID.
    pub mirror_tid: u64,
    pub state: NodeState,
}

/// HAMMER2 cluster -- distributed filesystem for Phase 3 deception.
pub struct Hammer2Cluster {
    pub nodes: [Option<ClusterNode>; 8],
    pub node_count: usize,
    /// Number of nodes that must agree for quorum.
    pub quorum: usize,
    /// Master transaction ID (highest committed across quorum).
    pub master_tid: u64,
}

impl Hammer2Cluster {
    /// Create a new cluster with the given quorum requirement.
    pub fn new(quorum: usize) -> Self {
        Self {
            nodes: [None; 8],
            node_count: 0,
            quorum: quorum.max(1),
            master_tid: 0,
        }
    }

    /// Add a node to the cluster. Returns its index, or None if full.
    pub fn add_node(&mut self, id: u32, channel_cap: u64) -> Option<usize> {
        if self.node_count >= 8 {
            return None;
        }
        for (i, slot) in self.nodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(ClusterNode {
                    id,
                    channel_cap,
                    mirror_tid: 0,
                    state: NodeState::Syncing,
                });
                self.node_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a node by index. Returns the removed node, or None.
    pub fn remove_node(&mut self, idx: usize) -> Option<ClusterNode> {
        if idx >= 8 {
            return None;
        }
        let node = self.nodes[idx].take();
        if node.is_some() {
            self.node_count -= 1;
        }
        node
    }

    /// Mark a node as online with its current mirror_tid.
    pub fn node_online(&mut self, idx: usize, mirror_tid: u64) {
        if let Some(node) = self.nodes.get_mut(idx).and_then(|s| s.as_mut()) {
            node.state = NodeState::Online;
            node.mirror_tid = mirror_tid;
        }
    }

    /// Mark a node as failed.
    pub fn node_failed(&mut self, idx: usize) {
        if let Some(node) = self.nodes.get_mut(idx).and_then(|s| s.as_mut()) {
            node.state = NodeState::Failed;
        }
    }

    /// Check whether a quorum of online nodes exists.
    pub fn has_quorum(&self) -> bool {
        let online = self
            .nodes
            .iter()
            .filter(|s| matches!(s, Some(n) if n.state == NodeState::Online))
            .count();
        online >= self.quorum
    }

    /// Advance the master transaction ID. Returns false if quorum is lost.
    pub fn advance_master_tid(&mut self) -> bool {
        if !self.has_quorum() {
            return false;
        }
        self.master_tid += 1;
        true
    }

    /// Return indices of nodes that are behind master_tid and need sync.
    pub fn nodes_needing_sync(&self) -> [Option<usize>; 8] {
        let mut result: [Option<usize>; 8] = [None; 8];
        let mut out = 0;
        for (i, slot) in self.nodes.iter().enumerate() {
            if let Some(node) = slot {
                if node.mirror_tid < self.master_tid
                    && node.state != NodeState::Failed
                {
                    result[out] = Some(i);
                    out += 1;
                }
            }
        }
        result
    }
}
