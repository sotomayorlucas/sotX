use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::graph::{Edge, Node, ProvenanceGraph, SOId};

/// A subset of the provenance graph filtered to a time window.
pub struct SubGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// Kind of anomaly detected during provenance analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A domain modified a sensitive binary and then read a credential file
    /// (or vice-versa) within the same causal window.
    WriteExecThenReadCred,
    /// A domain accessed an unusually large number of distinct SOs.
    ExcessiveFanOut { count: usize },
}

/// An anomaly detected by `anomaly_check`.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub domain_id: u32,
    pub kind: AnomalyKind,
    pub related_edges: Vec<Edge>,
}

/// Threshold for the excessive-fan-out heuristic.
const FAN_OUT_THRESHOLD: usize = 64;

/// Return all SO ids transitively reachable from `start` via outgoing edges.
pub fn reachable_from(graph: &ProvenanceGraph, start: SOId) -> Vec<SOId> {
    let mut visited = Vec::new();
    let mut queue = VecDeque::new();

    if graph.find_index(start).is_none() {
        return visited;
    }

    queue.push_back(start);

    while let Some(current) = queue.pop_front() {
        if visited.contains(&current) {
            continue;
        }
        visited.push(current);
        for edge in graph.edges_from(current) {
            if !visited.contains(&edge.dst) {
                queue.push_back(edge.dst);
            }
        }
    }

    // Remove the start node itself -- callers want the *reachable set*, not
    // the source.
    visited.retain(|&id| id != start);
    visited
}

/// Return all SO ids that `domain_id` has touched (appears on any edge).
pub fn accessed_by(graph: &ProvenanceGraph, domain_id: u32) -> Vec<SOId> {
    let mut result = Vec::new();
    for edge in graph.all_edges() {
        if edge.domain_id == domain_id {
            if !result.contains(&edge.src) {
                result.push(edge.src);
            }
            if !result.contains(&edge.dst) {
                result.push(edge.dst);
            }
        }
    }
    result
}

/// Find the shortest path (by hop count) from `from` to `to`.
/// Returns `None` if no path exists.
pub fn causal_chain(graph: &ProvenanceGraph, from: SOId, to: SOId) -> Option<Vec<Edge>> {
    if graph.find_index(from).is_none() || graph.find_index(to).is_none() {
        return None;
    }
    if from == to {
        return Some(Vec::new());
    }

    // BFS tracking the edge that led to each node.
    let mut visited: Vec<SOId> = Vec::new();
    // Each entry: (node, edge index in parent_edges that reached it)
    let mut parent_edges: Vec<Edge> = Vec::new();
    let mut parent_node: Vec<SOId> = Vec::new();
    let mut queue = VecDeque::new();

    visited.push(from);
    queue.push_back(from);

    let mut found = false;
    while let Some(current) = queue.pop_front() {
        for edge in graph.edges_from(current) {
            if !visited.contains(&edge.dst) {
                visited.push(edge.dst);
                parent_edges.push(edge.clone());
                parent_node.push(current);
                if edge.dst == to {
                    found = true;
                    break;
                }
                queue.push_back(edge.dst);
            }
        }
        if found {
            break;
        }
    }

    if !found {
        return None;
    }

    // Walk backwards from `to` to `from` via parent_edges.
    let mut path = Vec::new();
    let mut cursor = to;
    while cursor != from {
        // Find the parent_edges entry whose dst == cursor.
        let idx = parent_edges.iter().position(|e| e.dst == cursor)?;
        path.push(parent_edges[idx].clone());
        cursor = parent_node[idx];
    }
    path.reverse();
    Some(path)
}

/// Return a subgraph containing only edges whose timestamp falls within
/// `[start_epoch, end_epoch]` and the nodes they reference.
pub fn temporal_window(
    graph: &ProvenanceGraph,
    start_epoch: u64,
    end_epoch: u64,
) -> SubGraph {
    let mut edges = Vec::new();
    let mut node_ids: Vec<SOId> = Vec::new();

    for edge in graph.all_edges() {
        if edge.timestamp >= start_epoch && edge.timestamp <= end_epoch {
            edges.push(edge.clone());
            if !node_ids.contains(&edge.src) {
                node_ids.push(edge.src);
            }
            if !node_ids.contains(&edge.dst) {
                node_ids.push(edge.dst);
            }
        }
    }

    let nodes: Vec<Node> = node_ids
        .iter()
        .filter_map(|&id| {
            graph.find_index(id).and_then(|i| graph.node_at(i).cloned())
        })
        .collect();

    SubGraph { nodes, edges }
}

/// Basic anomaly detection for a domain:
///
/// 1. **WriteExecThenReadCred** -- the domain wrote to a binary-like SO
///    (type Process) and also read a credential-like SO (type File with a
///    different id) within the recorded window.
/// 2. **ExcessiveFanOut** -- the domain touched more than `FAN_OUT_THRESHOLD`
///    distinct SOs.
pub fn anomaly_check(graph: &ProvenanceGraph, domain_id: u32) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    let domain_edges: Vec<&Edge> = graph
        .all_edges()
        .filter(|e| e.domain_id == domain_id)
        .collect();

    if domain_edges.is_empty() {
        return anomalies;
    }

    // Pattern 1: write to a Process SO + read from a File SO.
    let mut writes_to_exec = Vec::new();
    let mut reads_from_cred = Vec::new();
    for &edge in &domain_edges {
        let dst_node = graph.find_index(edge.dst).and_then(|i| graph.node_at(i));
        let src_node = graph.find_index(edge.src).and_then(|i| graph.node_at(i));
        // Heuristic: operation & 0x01 == write, & 0x02 == read.
        let is_write = edge.operation & 0x01 != 0;
        let is_read = edge.operation & 0x02 != 0;
        if is_write {
            if let Some(n) = dst_node {
                if n.so_type == crate::graph::SOType::Process {
                    writes_to_exec.push(edge.clone());
                }
            }
        }
        if is_read {
            if let Some(n) = src_node {
                if n.so_type == crate::graph::SOType::File {
                    reads_from_cred.push(edge.clone());
                }
            }
        }
    }
    if !writes_to_exec.is_empty() && !reads_from_cred.is_empty() {
        let mut related = writes_to_exec;
        related.extend(reads_from_cred);
        anomalies.push(Anomaly {
            domain_id,
            kind: AnomalyKind::WriteExecThenReadCred,
            related_edges: related,
        });
    }

    // Pattern 2: excessive fan-out.
    let touched = accessed_by(graph, domain_id);
    if touched.len() > FAN_OUT_THRESHOLD {
        anomalies.push(Anomaly {
            domain_id,
            kind: AnomalyKind::ExcessiveFanOut {
                count: touched.len(),
            },
            related_edges: Vec::new(),
        });
    }

    anomalies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, ProvenanceGraph, SOType};

    fn sample_graph() -> ProvenanceGraph {
        let mut g = ProvenanceGraph::new();
        g.add_node(1, SOType::File);
        g.add_node(2, SOType::Process);
        g.add_node(3, SOType::Socket);
        g.add_node(4, SOType::File);

        g.add_edge(Edge {
            src: 1,
            dst: 2,
            operation: 2,
            domain_id: 10,
            timestamp: 100,
            tx_id: 0,
        });
        g.add_edge(Edge {
            src: 2,
            dst: 3,
            operation: 1,
            domain_id: 10,
            timestamp: 200,
            tx_id: 0,
        });
        g.add_edge(Edge {
            src: 3,
            dst: 4,
            operation: 2,
            domain_id: 20,
            timestamp: 300,
            tx_id: 0,
        });
        g
    }

    #[test]
    fn test_reachable_from() {
        let g = sample_graph();
        let r = reachable_from(&g, 1);
        assert!(r.contains(&2));
        assert!(r.contains(&3));
        assert!(r.contains(&4));
        assert!(!r.contains(&1));
    }

    #[test]
    fn test_accessed_by() {
        let g = sample_graph();
        let a = accessed_by(&g, 10);
        assert!(a.contains(&1));
        assert!(a.contains(&2));
        assert!(a.contains(&3));
        assert!(!a.contains(&4));
    }

    #[test]
    fn test_causal_chain() {
        let g = sample_graph();
        let chain = causal_chain(&g, 1, 4).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].src, 1);
        assert_eq!(chain[2].dst, 4);
    }

    #[test]
    fn test_causal_chain_no_path() {
        let g = sample_graph();
        assert!(causal_chain(&g, 4, 1).is_none());
    }

    #[test]
    fn test_temporal_window() {
        let g = sample_graph();
        let sub = temporal_window(&g, 150, 250);
        assert_eq!(sub.edges.len(), 1);
        assert_eq!(sub.edges[0].timestamp, 200);
    }

    #[test]
    fn test_anomaly_write_exec_read_cred() {
        let mut g = ProvenanceGraph::new();
        g.add_node(1, SOType::File); // credential-like
        g.add_node(2, SOType::Process); // binary-like

        // Domain 10 reads from file (op & 0x02 set) with src=1
        g.add_edge(Edge {
            src: 1,
            dst: 2,
            operation: 0x02,
            domain_id: 10,
            timestamp: 100,
            tx_id: 0,
        });
        // Domain 10 writes to process (op & 0x01 set) with dst=2
        g.add_edge(Edge {
            src: 1,
            dst: 2,
            operation: 0x01,
            domain_id: 10,
            timestamp: 200,
            tx_id: 0,
        });

        let anomalies = anomaly_check(&g, 10);
        assert!(anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::WriteExecThenReadCred));
    }
}
