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

    for aid in graph.inodes.keys() {
        let iid = aid.0 as u64;
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Inode(iid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for aid in graph.dirs.keys() {
        let did = aid.0 as u64;
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Directory(did), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for aid in graph.caps.keys() {
        let cid = aid.0 as u64;
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Capability(cid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for aid in graph.blocks.keys() {
        let bid = aid.0 as u64;
        let uid = next_uid;
        next_uid += 1;
        id_map.insert(NodeId::Block(bid), uid);
        node_ids.push(uid);
        adj.entry(uid).or_default();
    }
    for aid in graph.versions.keys() {
        let vid = aid.0 as u64;
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

// ---------------------------------------------------------------------------
// Incremental treewidth maintenance
// ---------------------------------------------------------------------------

/// Maximum number of nodes supported by the dynamic tracker.
pub const MAX_NODES: usize = 1024;
/// Maximum degree (neighbors) per node.
pub const MAX_DEGREE: usize = 64;

/// Incremental treewidth tracker.
///
/// Caches a greedy min-degree elimination ordering so that small graph edits
/// (add/remove node/edge) can be handled without full recomputation.
///
/// **Invariant**: `self.bound` is always an upper bound on the treewidth of
/// the tracked graph, computed via the min-degree heuristic. After any
/// incremental update, `self.bound` matches what a fresh `full_recompute()`
/// would produce.
///
/// Uses heap allocation via `Box` because the fixed-size arrays are too large
/// for the default thread stack. Internally all data is in fixed-size arrays
/// (no_std-compatible data layout).
pub struct DynamicTreewidth {
    /// Current treewidth upper bound.
    pub bound: usize,
    /// Cached elimination ordering (node IDs in elimination order).
    ordering: Box<[u64; MAX_NODES]>,
    ordering_len: usize,
    /// Cached fill-in edges per elimination step.
    /// `fill_edges[step][0..fill_counts[step]]` are the neighbor IDs that
    /// were connected (fill) when the node at `ordering[step]` was eliminated.
    fill_edges: Box<[[u64; MAX_DEGREE]; MAX_NODES]>,
    fill_counts: Box<[usize; MAX_NODES]>,
    /// Width (degree at elimination) per step.
    step_width: Box<[usize; MAX_NODES]>,

    // --- Underlying graph (undirected skeleton) ---
    /// Node IDs present in the graph.
    nodes: Box<[u64; MAX_NODES]>,
    node_count: usize,
    /// Adjacency lists: `adj[i][0..adj_len[i]]` are neighbors of `nodes[i]`.
    adj: Box<[[u64; MAX_DEGREE]; MAX_NODES]>,
    adj_len: Box<[usize; MAX_NODES]>,

    /// Dirty flags: `dirty[i]` is true if node at index `i` needs re-evaluation.
    dirty: Box<[bool; MAX_NODES]>,
}

impl DynamicTreewidth {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            bound: 0,
            ordering: Box::new([0; MAX_NODES]),
            ordering_len: 0,
            fill_edges: Box::new([[0; MAX_DEGREE]; MAX_NODES]),
            fill_counts: Box::new([0; MAX_NODES]),
            step_width: Box::new([0; MAX_NODES]),
            nodes: Box::new([0; MAX_NODES]),
            node_count: 0,
            adj: Box::new([[0; MAX_DEGREE]; MAX_NODES]),
            adj_len: Box::new([0; MAX_NODES]),
            dirty: Box::new([false; MAX_NODES]),
        }
    }

    /// Build from a `TypeGraph`, computing the initial elimination ordering.
    pub fn from_type_graph(graph: &TypeGraph) -> Self {
        let mut dt = Self::new();
        dt.load_type_graph(graph);
        dt.full_recompute();
        dt
    }

    /// Load the undirected skeleton of a `TypeGraph` into the tracker.
    fn load_type_graph(&mut self, graph: &TypeGraph) {
        // Reset
        self.node_count = 0;
        for i in 0..MAX_NODES {
            self.adj_len[i] = 0;
        }

        // Map NodeId -> u64
        let mut id_map: BTreeMap<NodeId, u64> = BTreeMap::new();
        let mut next_uid = 0u64;

        for aid in graph.inodes.keys() {
            id_map.insert(NodeId::Inode(aid.0 as u64), next_uid);
            self.add_node_internal(next_uid);
            next_uid += 1;
        }
        for aid in graph.dirs.keys() {
            id_map.insert(NodeId::Directory(aid.0 as u64), next_uid);
            self.add_node_internal(next_uid);
            next_uid += 1;
        }
        for aid in graph.caps.keys() {
            id_map.insert(NodeId::Capability(aid.0 as u64), next_uid);
            self.add_node_internal(next_uid);
            next_uid += 1;
        }
        for aid in graph.blocks.keys() {
            id_map.insert(NodeId::Block(aid.0 as u64), next_uid);
            self.add_node_internal(next_uid);
            next_uid += 1;
        }
        for aid in graph.versions.keys() {
            id_map.insert(NodeId::Version(aid.0 as u64), next_uid);
            self.add_node_internal(next_uid);
            next_uid += 1;
        }

        for edge in graph.edges.values() {
            let src = edge.src_node();
            let tgt = edge.tgt_node();
            if let (Some(&su), Some(&tu)) = (id_map.get(&src), id_map.get(&tgt)) {
                if su != tu {
                    self.add_edge_internal(su, tu);
                }
            }
        }
    }

    // --- Internal graph manipulation (no ordering update) ---

    fn node_index(&self, id: u64) -> Option<usize> {
        for i in 0..self.node_count {
            if self.nodes[i] == id {
                return Some(i);
            }
        }
        None
    }

    fn has_adj_edge(&self, idx: usize, neighbor: u64) -> bool {
        for j in 0..self.adj_len[idx] {
            if self.adj[idx][j] == neighbor {
                return true;
            }
        }
        false
    }

    fn add_node_internal(&mut self, id: u64) {
        if self.node_index(id).is_some() {
            return;
        }
        assert!(self.node_count < MAX_NODES, "DynamicTreewidth: MAX_NODES exceeded");
        let idx = self.node_count;
        self.nodes[idx] = id;
        self.adj_len[idx] = 0;
        self.node_count += 1;
    }

    fn add_edge_internal(&mut self, u: u64, v: u64) {
        if u == v {
            return;
        }
        if let Some(ui) = self.node_index(u) {
            if !self.has_adj_edge(ui, v) {
                assert!(
                    self.adj_len[ui] < MAX_DEGREE,
                    "DynamicTreewidth: MAX_DEGREE exceeded for node {}",
                    u
                );
                self.adj[ui][self.adj_len[ui]] = v;
                self.adj_len[ui] += 1;
            }
        }
        if let Some(vi) = self.node_index(v) {
            if !self.has_adj_edge(vi, u) {
                assert!(
                    self.adj_len[vi] < MAX_DEGREE,
                    "DynamicTreewidth: MAX_DEGREE exceeded for node {}",
                    v
                );
                self.adj[vi][self.adj_len[vi]] = u;
                self.adj_len[vi] += 1;
            }
        }
    }

    fn remove_edge_internal(&mut self, u: u64, v: u64) {
        if let Some(ui) = self.node_index(u) {
            let mut j = 0;
            while j < self.adj_len[ui] {
                if self.adj[ui][j] == v {
                    self.adj_len[ui] -= 1;
                    self.adj[ui][j] = self.adj[ui][self.adj_len[ui]];
                    break;
                }
                j += 1;
            }
        }
        if let Some(vi) = self.node_index(v) {
            let mut j = 0;
            while j < self.adj_len[vi] {
                if self.adj[vi][j] == u {
                    self.adj_len[vi] -= 1;
                    self.adj[vi][j] = self.adj[vi][self.adj_len[vi]];
                    break;
                }
                j += 1;
            }
        }
    }

    fn remove_node_internal(&mut self, id: u64) {
        if let Some(idx) = self.node_index(id) {
            // Collect neighbors and remove edges from them
            let len = self.adj_len[idx];
            let mut nbrs = [0u64; MAX_DEGREE];
            for j in 0..len {
                nbrs[j] = self.adj[idx][j];
            }
            for j in 0..len {
                let n = nbrs[j];
                if let Some(ni) = self.node_index(n) {
                    let mut k = 0;
                    while k < self.adj_len[ni] {
                        if self.adj[ni][k] == id {
                            self.adj_len[ni] -= 1;
                            self.adj[ni][k] = self.adj[ni][self.adj_len[ni]];
                            break;
                        }
                        k += 1;
                    }
                }
            }
            // Swap-remove node
            self.node_count -= 1;
            if idx < self.node_count {
                self.nodes[idx] = self.nodes[self.node_count];
                // Copy adjacency data from the swapped node
                self.adj_len[idx] = self.adj_len[self.node_count];
                for j in 0..self.adj_len[self.node_count] {
                    self.adj[idx][j] = self.adj[self.node_count][j];
                }
                // Copy dirty flag
                self.dirty[idx] = self.dirty[self.node_count];
            }
        }
    }

    // --- Full recompute (min-degree elimination) ---

    /// Recompute the elimination ordering from scratch on the current graph.
    pub fn full_recompute(&mut self) {
        // Work on a copy of the adjacency so we can add fill edges.
        // Boxed to avoid stack overflow (512KB+ per array).
        let mut work_adj: Box<[[u64; MAX_DEGREE]; MAX_NODES]> = Box::new([[0u64; MAX_DEGREE]; MAX_NODES]);
        let mut work_len: Box<[usize; MAX_NODES]> = Box::new([0usize; MAX_NODES]);
        // Map from work-graph index to node id
        let mut work_nodes: Box<[u64; MAX_NODES]> = Box::new([0u64; MAX_NODES]);
        let n = self.node_count;

        for i in 0..n {
            work_nodes[i] = self.nodes[i];
            work_len[i] = self.adj_len[i];
            for j in 0..self.adj_len[i] {
                work_adj[i][j] = self.adj[i][j];
            }
        }

        let mut eliminated = [false; MAX_NODES];
        let mut max_width = 0usize;
        self.ordering_len = 0;

        for _step in 0..n {
            // Find remaining node with minimum degree
            let mut min_deg = usize::MAX;
            let mut min_idx = 0;
            for i in 0..n {
                if eliminated[i] {
                    continue;
                }
                // Count remaining neighbors
                let mut deg = 0;
                for j in 0..work_len[i] {
                    let nbr = work_adj[i][j];
                    // Find index of nbr
                    for k in 0..n {
                        if work_nodes[k] == nbr && !eliminated[k] {
                            deg += 1;
                            break;
                        }
                    }
                }
                if deg < min_deg {
                    min_deg = deg;
                    min_idx = i;
                }
            }

            let v = min_idx;
            let vid = work_nodes[v];

            // Collect remaining neighbors
            let mut nbrs = [0u64; MAX_DEGREE];
            let mut nbr_count = 0;
            for j in 0..work_len[v] {
                let nbr = work_adj[v][j];
                for k in 0..n {
                    if work_nodes[k] == nbr && !eliminated[k] {
                        nbrs[nbr_count] = nbr;
                        nbr_count += 1;
                        break;
                    }
                }
            }

            let degree = nbr_count;
            if degree > max_width {
                max_width = degree;
            }

            // Record in ordering
            let step = self.ordering_len;
            self.ordering[step] = vid;
            self.step_width[step] = degree;
            self.fill_counts[step] = nbr_count;
            for i in 0..nbr_count {
                self.fill_edges[step][i] = nbrs[i];
            }

            // Fill: connect all pairs of remaining neighbors
            for i in 0..nbr_count {
                for j in (i + 1)..nbr_count {
                    let a = nbrs[i];
                    let b = nbrs[j];
                    // Find indices
                    let mut ai = 0;
                    let mut bi = 0;
                    for k in 0..n {
                        if work_nodes[k] == a {
                            ai = k;
                        }
                        if work_nodes[k] == b {
                            bi = k;
                        }
                    }
                    // Check if edge a-b already exists
                    let mut exists = false;
                    for k in 0..work_len[ai] {
                        if work_adj[ai][k] == b {
                            exists = true;
                            break;
                        }
                    }
                    if !exists {
                        // Add fill edge
                        if work_len[ai] < MAX_DEGREE {
                            work_adj[ai][work_len[ai]] = b;
                            work_len[ai] += 1;
                        }
                        if work_len[bi] < MAX_DEGREE {
                            work_adj[bi][work_len[bi]] = a;
                            work_len[bi] += 1;
                        }
                    }
                }
            }

            self.ordering_len += 1;
            eliminated[v] = true;
        }

        self.bound = max_width;

        // Clear dirty flags
        for i in 0..MAX_NODES {
            self.dirty[i] = false;
        }
    }

    // --- Position lookup in ordering ---

    fn ordering_position(&self, node_id: u64) -> Option<usize> {
        for i in 0..self.ordering_len {
            if self.ordering[i] == node_id {
                return Some(i);
            }
        }
        None
    }

    // --- Count how many nodes are dirty ---

    fn dirty_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.node_count {
            if self.dirty[i] {
                count += 1;
            }
        }
        count
    }

    /// Mark a node as dirty (needs re-evaluation in the ordering).
    fn mark_dirty(&mut self, node_id: u64) {
        if let Some(idx) = self.node_index(node_id) {
            self.dirty[idx] = true;
        }
    }

    /// Perform a partial re-elimination of the dirty suffix of the ordering.
    ///
    /// Finds the earliest dirty node in the ordering and re-eliminates from
    /// that point forward using the min-degree heuristic.
    fn incremental_reeliminate(&mut self) {
        // Find the earliest dirty position in the ordering
        let mut earliest_dirty = self.ordering_len;
        for pos in 0..self.ordering_len {
            let nid = self.ordering[pos];
            if let Some(idx) = self.node_index(nid) {
                if self.dirty[idx] {
                    earliest_dirty = pos;
                    break;
                }
            }
        }

        // Also check: if a node in the ordering no longer exists, or if a new
        // node exists but is not in the ordering, we need recompute.
        let mut has_new_node = false;
        for i in 0..self.node_count {
            let nid = self.nodes[i];
            if self.ordering_position(nid).is_none() {
                has_new_node = true;
                break;
            }
        }

        if earliest_dirty >= self.ordering_len && !has_new_node {
            // Nothing dirty, check if bound needs updating from removed nodes
            // that might have lowered the bound.
            let mut valid_ordering_len = 0;
            for pos in 0..self.ordering_len {
                let nid = self.ordering[pos];
                if self.node_index(nid).is_some() {
                    valid_ordering_len = pos + 1;
                }
            }
            if valid_ordering_len < self.ordering_len {
                // Some ordering entries reference removed nodes -- recompute suffix
                earliest_dirty = 0;
                for pos in 0..self.ordering_len {
                    let nid = self.ordering[pos];
                    if self.node_index(nid).is_none() {
                        earliest_dirty = pos;
                        break;
                    }
                }
            } else {
                // Clear dirty and return
                for i in 0..MAX_NODES {
                    self.dirty[i] = false;
                }
                return;
            }
        }

        // Re-eliminate from earliest_dirty onward.
        // Build work adjacency from the original graph (including fill edges
        // introduced by the ordering prefix [0..earliest_dirty]).
        // Boxed to avoid stack overflow.
        let mut work_adj: Box<[[u64; MAX_DEGREE]; MAX_NODES]> = Box::new([[0u64; MAX_DEGREE]; MAX_NODES]);
        let mut work_len: Box<[usize; MAX_NODES]> = Box::new([0usize; MAX_NODES]);
        let mut work_nodes: Box<[u64; MAX_NODES]> = Box::new([0u64; MAX_NODES]);
        let n = self.node_count;

        for i in 0..n {
            work_nodes[i] = self.nodes[i];
            work_len[i] = self.adj_len[i];
            for j in 0..self.adj_len[i] {
                work_adj[i][j] = self.adj[i][j];
            }
        }

        // Replay the prefix: eliminate nodes in ordering[0..earliest_dirty]
        // and apply their fill edges.
        let mut eliminated = [false; MAX_NODES];

        for pos in 0..earliest_dirty {
            let vid = self.ordering[pos];
            // Find in work_nodes
            let mut found = false;
            for k in 0..n {
                if work_nodes[k] == vid {
                    eliminated[k] = true;
                    found = true;
                    break;
                }
            }
            if !found {
                // Node was removed -- skip
                continue;
            }

            // Re-apply fill: get remaining neighbors of vid and connect them
            let mut vi = 0;
            for k in 0..n {
                if work_nodes[k] == vid {
                    vi = k;
                    break;
                }
            }
            let mut nbrs = [0u64; MAX_DEGREE];
            let mut nbr_count = 0;
            for j in 0..work_len[vi] {
                let nbr = work_adj[vi][j];
                for k in 0..n {
                    if work_nodes[k] == nbr && !eliminated[k] {
                        nbrs[nbr_count] = nbr;
                        nbr_count += 1;
                        break;
                    }
                }
            }

            // Fill
            for i in 0..nbr_count {
                for j in (i + 1)..nbr_count {
                    let a = nbrs[i];
                    let b = nbrs[j];
                    let mut ai = 0;
                    let mut bi = 0;
                    for k in 0..n {
                        if work_nodes[k] == a { ai = k; }
                        if work_nodes[k] == b { bi = k; }
                    }
                    let mut exists = false;
                    for k in 0..work_len[ai] {
                        if work_adj[ai][k] == b { exists = true; break; }
                    }
                    if !exists {
                        if work_len[ai] < MAX_DEGREE {
                            work_adj[ai][work_len[ai]] = b;
                            work_len[ai] += 1;
                        }
                        if work_len[bi] < MAX_DEGREE {
                            work_adj[bi][work_len[bi]] = a;
                            work_len[bi] += 1;
                        }
                    }
                }
            }
        }

        // Now re-eliminate remaining nodes with min-degree heuristic
        let remaining_count = n - eliminated.iter().take(n).filter(|&&e| e).count();
        let mut new_suffix_len = 0;
        let mut new_ordering_suffix: Box<[u64; MAX_NODES]> = Box::new([0u64; MAX_NODES]);
        let mut new_step_width: Box<[usize; MAX_NODES]> = Box::new([0usize; MAX_NODES]);
        let mut new_fill_edges: Box<[[u64; MAX_DEGREE]; MAX_NODES]> = Box::new([[0u64; MAX_DEGREE]; MAX_NODES]);
        let mut new_fill_counts: Box<[usize; MAX_NODES]> = Box::new([0usize; MAX_NODES]);

        for _step in 0..remaining_count {
            // Find remaining node with minimum degree
            let mut min_deg = usize::MAX;
            let mut min_idx = 0;
            for i in 0..n {
                if eliminated[i] { continue; }
                let mut deg = 0;
                for j in 0..work_len[i] {
                    let nbr = work_adj[i][j];
                    for k in 0..n {
                        if work_nodes[k] == nbr && !eliminated[k] {
                            deg += 1;
                            break;
                        }
                    }
                }
                if deg < min_deg {
                    min_deg = deg;
                    min_idx = i;
                }
            }

            let v = min_idx;
            let vid = work_nodes[v];

            // Collect remaining neighbors
            let mut nbrs = [0u64; MAX_DEGREE];
            let mut nbr_count = 0;
            for j in 0..work_len[v] {
                let nbr = work_adj[v][j];
                for k in 0..n {
                    if work_nodes[k] == nbr && !eliminated[k] {
                        nbrs[nbr_count] = nbr;
                        nbr_count += 1;
                        break;
                    }
                }
            }

            let degree = nbr_count;

            // Record
            new_ordering_suffix[new_suffix_len] = vid;
            new_step_width[new_suffix_len] = degree;
            new_fill_counts[new_suffix_len] = nbr_count;
            for i in 0..nbr_count {
                new_fill_edges[new_suffix_len][i] = nbrs[i];
            }
            new_suffix_len += 1;

            // Fill
            for i in 0..nbr_count {
                for j in (i + 1)..nbr_count {
                    let a = nbrs[i];
                    let b = nbrs[j];
                    let mut ai = 0;
                    let mut bi = 0;
                    for k in 0..n {
                        if work_nodes[k] == a { ai = k; }
                        if work_nodes[k] == b { bi = k; }
                    }
                    let mut exists = false;
                    for k in 0..work_len[ai] {
                        if work_adj[ai][k] == b { exists = true; break; }
                    }
                    if !exists {
                        if work_len[ai] < MAX_DEGREE {
                            work_adj[ai][work_len[ai]] = b;
                            work_len[ai] += 1;
                        }
                        if work_len[bi] < MAX_DEGREE {
                            work_adj[bi][work_len[bi]] = a;
                            work_len[bi] += 1;
                        }
                    }
                }
            }

            eliminated[v] = true;
        }

        // Rebuild ordering: keep prefix [0..earliest_dirty] that still exist,
        // then append new suffix.
        let mut new_ordering_len = 0;

        // Keep valid prefix entries
        for pos in 0..earliest_dirty {
            let nid = self.ordering[pos];
            if self.node_index(nid).is_some() {
                self.ordering[new_ordering_len] = nid;
                new_ordering_len += 1;
            }
        }

        // If prefix entries were removed, do full recompute for correctness.
        let prefix_compacted = new_ordering_len < earliest_dirty;
        if prefix_compacted {
            self.full_recompute();
            return;
        }

        // Append new suffix
        for i in 0..new_suffix_len {
            let pos = new_ordering_len + i;
            self.ordering[pos] = new_ordering_suffix[i];
            self.step_width[pos] = new_step_width[i];
            self.fill_counts[pos] = new_fill_counts[i];
            for j in 0..new_fill_counts[i] {
                self.fill_edges[pos][j] = new_fill_edges[i][j];
            }
        }
        self.ordering_len = new_ordering_len + new_suffix_len;

        // Recompute bound
        let mut max_w = 0;
        for i in 0..self.ordering_len {
            if self.step_width[i] > max_w {
                max_w = self.step_width[i];
            }
        }
        self.bound = max_w;

        // Clear dirty
        for i in 0..MAX_NODES {
            self.dirty[i] = false;
        }
    }

    // --- Public incremental API ---

    /// Notify the tracker that edge (u, v) was added to the graph.
    pub fn on_add_edge(&mut self, u: u64, v: u64) {
        if u == v {
            return;
        }
        self.add_edge_internal(u, v);
        self.mark_dirty(u);
        self.mark_dirty(v);

        // Also mark neighbors -- the fill pattern may change for any node
        // that had u or v as a neighbor.
        self.mark_neighbors_dirty(u);
        self.mark_neighbors_dirty(v);

        self.maybe_update();
    }

    /// Notify the tracker that edge (u, v) was removed from the graph.
    pub fn on_remove_edge(&mut self, u: u64, v: u64) {
        if u == v {
            return;
        }
        self.remove_edge_internal(u, v);
        self.mark_dirty(u);
        self.mark_dirty(v);

        self.mark_neighbors_dirty(u);
        self.mark_neighbors_dirty(v);

        self.maybe_update();
    }

    /// Notify the tracker that a new isolated node was added.
    pub fn on_add_node(&mut self, n: u64) {
        self.add_node_internal(n);
        // An isolated node has degree 0 and would be eliminated first
        // (or at least early). Mark dirty so it gets placed properly.
        self.mark_dirty(n);
        self.maybe_update();
    }

    /// Notify the tracker that node `n` (and all its edges) was removed.
    pub fn on_remove_node(&mut self, n: u64) {
        // Collect and mark neighbors dirty before removal
        if let Some(idx) = self.node_index(n) {
            for j in 0..self.adj_len[idx] {
                let nbr = self.adj[idx][j];
                self.mark_dirty(nbr);
            }
        }
        self.remove_node_internal(n);
        self.maybe_update();
    }

    /// Mark all neighbors of a node as dirty.
    fn mark_neighbors_dirty(&mut self, node_id: u64) {
        if let Some(idx) = self.node_index(node_id) {
            // Collect neighbor IDs first to avoid borrow issues
            let len = self.adj_len[idx];
            let mut nbrs = [0u64; MAX_DEGREE];
            for j in 0..len {
                nbrs[j] = self.adj[idx][j];
            }
            for j in 0..len {
                self.mark_dirty(nbrs[j]);
            }
        }
    }

    /// Decide whether to do incremental re-elimination or full recompute.
    fn maybe_update(&mut self) {
        if self.node_count == 0 {
            self.bound = 0;
            self.ordering_len = 0;
            for i in 0..MAX_NODES {
                self.dirty[i] = false;
            }
            return;
        }

        let dirty = self.dirty_count();
        // Fallback: if dirty set exceeds 20% of |V|, full recompute
        let threshold = (self.node_count + 4) / 5; // ceil(node_count/5)
        if dirty > threshold || self.ordering_len == 0 {
            self.full_recompute();
        } else {
            self.incremental_reeliminate();
        }
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

    // -----------------------------------------------------------------------
    // DynamicTreewidth tests
    // -----------------------------------------------------------------------

    /// Helper: compute treewidth on a raw adjacency (fixed-size arrays)
    /// by building a DynamicTreewidth from scratch and returning its bound.
    fn fresh_bound(nodes: &[u64], edges: &[(u64, u64)]) -> usize {
        let mut dt = DynamicTreewidth::new();
        for &n in nodes {
            dt.add_node_internal(n);
        }
        for &(u, v) in edges {
            dt.add_edge_internal(u, v);
        }
        dt.full_recompute();
        dt.bound
    }

    #[test]
    fn dynamic_empty_graph() {
        let dt = DynamicTreewidth::new();
        assert_eq!(dt.bound, 0);
    }

    #[test]
    fn dynamic_single_node() {
        let mut dt = DynamicTreewidth::new();
        dt.on_add_node(1);
        assert_eq!(dt.bound, 0);
    }

    #[test]
    fn dynamic_single_edge() {
        let mut dt = DynamicTreewidth::new();
        dt.on_add_node(1);
        dt.on_add_node(2);
        dt.on_add_edge(1, 2);
        assert_eq!(dt.bound, 1);
    }

    #[test]
    fn dynamic_path_graph() {
        // 1-2-3-4 : treewidth = 1
        let mut dt = DynamicTreewidth::new();
        for i in 1..=4 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        dt.on_add_edge(3, 4);

        let reference = fresh_bound(&[1, 2, 3, 4], &[(1, 2), (2, 3), (3, 4)]);
        assert_eq!(dt.bound, reference);
    }

    #[test]
    fn dynamic_triangle() {
        // K3 : treewidth = 2
        let mut dt = DynamicTreewidth::new();
        for i in 1..=3 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        dt.on_add_edge(1, 3);

        let reference = fresh_bound(&[1, 2, 3], &[(1, 2), (2, 3), (1, 3)]);
        assert_eq!(dt.bound, reference);
    }

    #[test]
    fn dynamic_add_edge_updates_bound() {
        // Start with path 1-2-3, then add edge 1-3 making it a triangle.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=3 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        let path_bound = dt.bound;

        dt.on_add_edge(1, 3);
        let triangle_bound = dt.bound;

        let reference = fresh_bound(&[1, 2, 3], &[(1, 2), (2, 3), (1, 3)]);
        assert_eq!(triangle_bound, reference);
        assert!(triangle_bound >= path_bound);
    }

    #[test]
    fn dynamic_remove_edge_updates_bound() {
        // Start with triangle, remove one edge.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=3 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        dt.on_add_edge(1, 3);

        dt.on_remove_edge(1, 3);

        let reference = fresh_bound(&[1, 2, 3], &[(1, 2), (2, 3)]);
        assert_eq!(dt.bound, reference);
    }

    #[test]
    fn dynamic_add_node_isolated() {
        // Path 1-2-3, then add isolated node 4.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=3 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        let before = dt.bound;

        dt.on_add_node(4);

        let reference = fresh_bound(&[1, 2, 3, 4], &[(1, 2), (2, 3)]);
        assert_eq!(dt.bound, reference);
        // Adding an isolated node should not increase treewidth
        assert!(dt.bound <= before);
    }

    #[test]
    fn dynamic_remove_node() {
        // K4 minus one node should reduce treewidth.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=4 {
            dt.on_add_node(i);
        }
        dt.on_add_edge(1, 2);
        dt.on_add_edge(1, 3);
        dt.on_add_edge(1, 4);
        dt.on_add_edge(2, 3);
        dt.on_add_edge(2, 4);
        dt.on_add_edge(3, 4);

        dt.on_remove_node(4);

        let reference = fresh_bound(&[1, 2, 3], &[(1, 2), (1, 3), (2, 3)]);
        assert_eq!(dt.bound, reference);
    }

    #[test]
    fn dynamic_from_type_graph_matches_reference() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        sotfs_ops::create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::create_file(&mut g, rd, "b", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();

        let reference = compute_treewidth(&g);
        let dt = DynamicTreewidth::from_type_graph(&g);
        assert_eq!(dt.bound, reference);
    }

    #[test]
    fn dynamic_incremental_matches_full_star() {
        // Build a star graph incrementally and verify at each step.
        let mut dt = DynamicTreewidth::new();
        dt.on_add_node(0); // center

        for i in 1..=8u64 {
            dt.on_add_node(i);
            dt.on_add_edge(0, i);

            // Build the same graph from scratch
            let nodes: Vec<u64> = (0..=i).collect();
            let edges: Vec<(u64, u64)> = (1..=i).map(|j| (0, j)).collect();
            let reference = fresh_bound(&nodes, &edges);

            assert_eq!(
                dt.bound, reference,
                "star with {} leaves: incremental={}, reference={}",
                i, dt.bound, reference
            );
        }
    }

    #[test]
    fn dynamic_incremental_matches_full_after_removals() {
        // Build K5, then remove edges one by one.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=5u64 {
            dt.on_add_node(i);
        }
        let all_edges: Vec<(u64, u64)> = vec![
            (1, 2), (1, 3), (1, 4), (1, 5),
            (2, 3), (2, 4), (2, 5),
            (3, 4), (3, 5),
            (4, 5),
        ];
        for &(u, v) in &all_edges {
            dt.on_add_edge(u, v);
        }

        // Verify initial K5
        let reference = fresh_bound(&[1, 2, 3, 4, 5], &all_edges);
        assert_eq!(dt.bound, reference, "K5 initial");

        // Remove edges and verify
        let mut remaining = all_edges.clone();
        for &(u, v) in &[(1, 5), (2, 4), (3, 5)] {
            dt.on_remove_edge(u, v);
            remaining.retain(|&(a, b)| !((a == u && b == v) || (a == v && b == u)));

            let reference = fresh_bound(&[1, 2, 3, 4, 5], &remaining);
            assert_eq!(
                dt.bound, reference,
                "after removing ({}, {}): incremental={}, reference={}",
                u, v, dt.bound, reference
            );
        }
    }

    #[test]
    fn dynamic_mixed_operations() {
        // A sequence of add/remove node/edge operations.
        let mut dt = DynamicTreewidth::new();

        // Build path 1-2-3
        dt.on_add_node(1);
        dt.on_add_node(2);
        dt.on_add_node(3);
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        assert_eq!(dt.bound, fresh_bound(&[1, 2, 3], &[(1, 2), (2, 3)]));

        // Add node 4 connected to 1 and 3 -> creates cycle
        dt.on_add_node(4);
        dt.on_add_edge(4, 1);
        dt.on_add_edge(4, 3);
        assert_eq!(
            dt.bound,
            fresh_bound(&[1, 2, 3, 4], &[(1, 2), (2, 3), (4, 1), (4, 3)])
        );

        // Remove node 2 from the graph
        dt.on_remove_edge(1, 2);
        dt.on_remove_edge(2, 3);
        dt.on_remove_node(2);
        assert_eq!(
            dt.bound,
            fresh_bound(&[1, 3, 4], &[(4, 1), (4, 3)])
        );

        // Add edge 1-3 to make a triangle
        dt.on_add_edge(1, 3);
        assert_eq!(
            dt.bound,
            fresh_bound(&[1, 3, 4], &[(4, 1), (4, 3), (1, 3)])
        );
    }

    #[test]
    fn dynamic_fallback_threshold() {
        // With 5 nodes, dirtying more than 1 (20% of 5) triggers full recompute.
        // Verify the result is still correct either way.
        let mut dt = DynamicTreewidth::new();
        for i in 1..=5u64 {
            dt.on_add_node(i);
        }
        // Build a path
        dt.on_add_edge(1, 2);
        dt.on_add_edge(2, 3);
        dt.on_add_edge(3, 4);
        dt.on_add_edge(4, 5);

        // Now add many edges at once, which will dirty > 20%
        dt.on_add_edge(1, 3);
        dt.on_add_edge(1, 4);
        dt.on_add_edge(1, 5);

        let reference = fresh_bound(
            &[1, 2, 3, 4, 5],
            &[(1, 2), (2, 3), (3, 4), (4, 5), (1, 3), (1, 4), (1, 5)],
        );
        assert_eq!(dt.bound, reference);
    }
}
