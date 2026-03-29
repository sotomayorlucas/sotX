use alloc::vec::Vec;

/// Unique identifier for a Secure Object.
pub type SOId = u64;

/// Type tag for a Secure Object node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SOType {
    File = 0,
    Process = 1,
    Socket = 2,
    Device = 3,
    Pipe = 4,
    SharedMemory = 5,
    Capability = 6,
}

/// A node in the provenance DAG representing a Secure Object.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: SOId,
    pub so_type: SOType,
}

/// A directed edge representing an operation between two Secure Objects.
#[derive(Debug, Clone)]
pub struct Edge {
    pub src: SOId,
    pub dst: SOId,
    pub operation: u16,
    pub domain_id: u32,
    pub timestamp: u64,
    pub tx_id: u64,
}

/// Provenance DAG using adjacency lists.
///
/// Nodes are stored in a flat `Vec`; edges are stored per-source-node
/// in `adjacency`, which is kept in sync with `nodes` by index.
pub struct ProvenanceGraph {
    nodes: Vec<Node>,
    adjacency: Vec<Vec<Edge>>,
}

impl ProvenanceGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            adjacency: Vec::new(),
        }
    }

    /// Insert a node. Duplicate ids are silently ignored.
    pub fn add_node(&mut self, id: SOId, so_type: SOType) {
        if self.find_index(id).is_some() {
            return;
        }
        self.nodes.push(Node { id, so_type });
        self.adjacency.push(Vec::new());
    }

    /// Insert a directed edge. Both endpoints must already exist.
    /// Returns `true` on success, `false` if either node is missing.
    pub fn add_edge(&mut self, edge: Edge) -> bool {
        let src_idx = match self.find_index(edge.src) {
            Some(i) => i,
            None => return false,
        };
        if self.find_index(edge.dst).is_none() {
            return false;
        }
        self.adjacency[src_idx].push(edge);
        true
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.adjacency.iter().map(|adj| adj.len()).sum()
    }

    /// Look up the node vec index for a given SOId.
    pub fn find_index(&self, id: SOId) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == id)
    }

    /// Return the node at the given vec index.
    pub fn node_at(&self, index: usize) -> Option<&Node> {
        self.nodes.get(index)
    }

    /// Return all outgoing edges for a node.
    pub fn edges_from(&self, id: SOId) -> &[Edge] {
        match self.find_index(id) {
            Some(idx) => &self.adjacency[idx],
            None => &[],
        }
    }

    /// Return all edges across the entire graph.
    pub fn all_edges(&self) -> impl Iterator<Item = &Edge> {
        self.adjacency.iter().flat_map(|adj| adj.iter())
    }

    /// Return all nodes.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }
}

impl Default for ProvenanceGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_nodes_and_edges() {
        let mut g = ProvenanceGraph::new();
        g.add_node(1, SOType::File);
        g.add_node(2, SOType::Process);
        assert_eq!(g.node_count(), 2);

        let ok = g.add_edge(Edge {
            src: 1,
            dst: 2,
            operation: 1,
            domain_id: 10,
            timestamp: 100,
            tx_id: 0,
        });
        assert!(ok);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn duplicate_node_ignored() {
        let mut g = ProvenanceGraph::new();
        g.add_node(1, SOType::File);
        g.add_node(1, SOType::Process);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn edge_to_missing_node_fails() {
        let mut g = ProvenanceGraph::new();
        g.add_node(1, SOType::File);
        let ok = g.add_edge(Edge {
            src: 1,
            dst: 99,
            operation: 0,
            domain_id: 0,
            timestamp: 0,
            tx_id: 0,
        });
        assert!(!ok);
        assert_eq!(g.edge_count(), 0);
    }
}
