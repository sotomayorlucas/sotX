//! # Treewidth Checker
//!
//! Computes an upper bound on the treewidth of the sotFS metadata graph
//! using a greedy elimination ordering (min-degree heuristic).
//!
//! **Theorem 8.1:** If hard link count per inode ≤ LINK_MAX, then
//! tw(TG) ≤ LINK_MAX + O(1). For filesystems without hard links, tw ≤ 6.
//!
//! The checker runs after each DPO rule application and raises an alert
//! if the treewidth exceeds the configured bound.

use std::collections::{BTreeMap, BTreeSet};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;

/// Result of a treewidth check.
#[derive(Debug, Clone)]
pub struct TreewidthResult {
    /// Upper bound on treewidth (from greedy elimination).
    pub upper_bound: usize,
    /// Whether the bound is within the configured limit.
    pub within_limit: bool,
    /// The configured limit.
    pub limit: usize,
    /// Number of nodes in the graph.
    pub node_count: usize,
    /// Number of edges in the undirected skeleton.
    pub edge_count: usize,
}

/// Compute an upper bound on the treewidth of the metadata graph.
///
/// Uses the **min-degree greedy elimination** heuristic:
/// 1. Build the undirected skeleton of TG (ignoring edge types/directions).
/// 2. Repeatedly eliminate the vertex with minimum degree.
/// 3. When eliminating vertex v: connect all neighbors of v into a clique,
///    then remove v. The width of the elimination is max degree at elimination.
/// 4. The treewidth upper bound is the maximum width across all eliminations.
///
/// This is O(n²) in the worst case but very fast for the tree-like graphs
/// that sotFS produces (most vertices have degree ≤ 3).
pub fn compute_treewidth(graph: &TypeGraph) -> usize {
    // Build undirected adjacency as a simple node ID → neighbor set map.
    let mut adj: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();

    // Assign unique IDs to all nodes
    let mut node_ids: Vec<u64> = Vec::new();
    let mut next_uid = 0u64;

    // Map each node type to a unique u64 for the undirected skeleton
    let mut id_map: BTreeMap<NodeId, u64> = BTreeMap::new();

    for &iid in graph.inodes.keys() {
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Inode(iid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for &did in graph.dirs.keys() {
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Directory(did), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for &cid in graph.caps.keys() {
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Capability(cid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for &bid in graph.blocks.keys() {
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Block(bid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for &vid in graph.versions.keys() {
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Version(vid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }

    // Add undirected edges from the typed edge set
    for edge in graph.edges.values() {
        let src = edge.src_node();
        let tgt = edge.tgt_node();
        if let (Some(&su), Some(&tu)) = (id_map.get(&src), id_map.get(&tgt)) {
            if su != tu {
                adj.entry(su).or_default().insert(tu);
                adj.entry(tu).or_default().insert(su);
            }
        }
    }

    // Greedy elimination: min-degree heuristic
    let mut max_width = 0usize;
    let mut remaining: BTreeSet<u64> = node_ids.iter().copied().collect();

    while !remaining.is_empty() {
        // Find vertex with minimum degree among remaining
        let &v = remaining
            .iter()
            .min_by_key(|&&u| {
                adj.get(&u)
                    .map(|nbrs| nbrs.iter().filter(|n| remaining.contains(n)).count())
                    .unwrap_or(0)
            })
            .unwrap();

        // Degree of v in the remaining graph
        let neighbors: Vec<u64> = adj
            .get(&v)
            .map(|nbrs| {
                nbrs.iter()
                    .filter(|n| remaining.contains(n))
                    .copied()
                    .collect()
            })
            .unwrap_or_default();

        let degree = neighbors.len();
        if degree > max_width {
            max_width = degree;
        }

        // Fill: connect all neighbors of v to each other
        for i in 0..neighbors.len() {
            for j in (i + 1)..neighbors.len() {
                let a = neighbors[i];
                let b = neighbors[j];
                adj.entry(a).or_default().insert(b);
                adj.entry(b).or_default().insert(a);
            }
        }

        // Eliminate v
        remaining.remove(&v);
    }

    max_width
}

/// Check that the treewidth of the graph is within the given limit.
pub fn check_treewidth(graph: &TypeGraph, limit: usize) -> TreewidthResult {
    let upper_bound = compute_treewidth(graph);

    let node_count = graph.inodes.len()
        + graph.dirs.len()
        + graph.caps.len()
        + graph.blocks.len()
        + graph.versions.len();

    let edge_count = graph.edges.len();

    TreewidthResult {
        upper_bound,
        within_limit: upper_bound <= limit,
        limit,
        node_count,
        edge_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_graph::types::Permissions;

    #[test]
    fn empty_graph_treewidth_is_one() {
        // Root dir only: one inode + one dir + one "." edge = tw ≤ 1
        let g = TypeGraph::new();
        let tw = compute_treewidth(&g);
        assert!(tw <= 1, "root-only graph tw={}", tw);
    }

    #[test]
    fn linear_chain_treewidth_is_one() {
        // / → a/ → b/ → c/ (chain of directories) = tree = tw 1
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let a = sotfs_ops::mkdir(&mut g, rd, "a", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let b = sotfs_ops::mkdir(&mut g, a.dir_id.unwrap(), "b", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        sotfs_ops::mkdir(&mut g, b.dir_id.unwrap(), "c", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let tw = compute_treewidth(&g);
        assert!(tw <= 2, "linear chain tw={}", tw);
    }

    #[test]
    fn star_topology_treewidth_is_one() {
        // Root with 10 files = star = tw 1
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        for i in 0..10 {
            let name = format!("f{}", i);
            sotfs_ops::create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT).unwrap();
        }
        let tw = compute_treewidth(&g);
        assert!(tw <= 2, "star topology tw={}", tw);
    }

    #[test]
    fn hard_link_increases_treewidth() {
        // File with 2 hard links from different dirs → tw may increase
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let fid = sotfs_ops::create_file(&mut g, rd, "shared", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let d = sotfs_ops::mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        sotfs_ops::link(&mut g, d.dir_id.unwrap(), "alias", fid).unwrap();

        let tw = compute_treewidth(&g);
        // With one hard link, tw should be at most 3
        assert!(tw <= 3, "hard link tw={}", tw);
    }

    #[test]
    fn check_within_default_limit() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        sotfs_ops::create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::mkdir(&mut g, rd, "b", 0, 0, Permissions::DIR_DEFAULT).unwrap();

        let result = check_treewidth(&g, 10);
        assert!(result.within_limit);
        assert!(result.upper_bound <= 10);
    }

    #[test]
    fn complex_tree_bounded_treewidth() {
        // /usr/bin/{ls,cat,grep}, /usr/lib/{libc.so}, /tmp/file
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let usr = sotfs_ops::mkdir(&mut g, rd, "usr", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let ud = usr.dir_id.unwrap();
        let bin = sotfs_ops::mkdir(&mut g, ud, "bin", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let bd = bin.dir_id.unwrap();
        let lib = sotfs_ops::mkdir(&mut g, ud, "lib", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let ld = lib.dir_id.unwrap();
        let tmp = sotfs_ops::mkdir(&mut g, rd, "tmp", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let td = tmp.dir_id.unwrap();

        sotfs_ops::create_file(&mut g, bd, "ls", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::create_file(&mut g, bd, "cat", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::create_file(&mut g, bd, "grep", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::create_file(&mut g, ld, "libc.so", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::create_file(&mut g, td, "file", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        let result = check_treewidth(&g, 6);
        assert!(
            result.within_limit,
            "complex tree tw={} exceeds limit=6",
            result.upper_bound
        );
    }
}
