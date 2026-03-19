//! IPC graph topology checker (debug-only, feature-gated).
//!
//! Tracks IPC edges (sender -> receiver) and detects:
//! - Cycles (B1 > 0): DFS-based cycle detection
//! - High treewidth: greedy vertex elimination (degree > 2 at removal = tw > 2)
//!
//! Zero overhead when `ipc-audit` feature is disabled.

use spin::Mutex;

/// Maximum IPC edges tracked.
const MAX_EDGES: usize = 128;
/// Maximum unique threads in the graph.
const MAX_NODES: usize = 64;

/// An IPC communication edge.
#[derive(Clone, Copy)]
struct Edge {
    sender: u32,
    receiver: u32,
    endpoint: u32,
}

/// Adjacency list entry (node index -> neighbor list).
struct AdjList {
    neighbors: [u32; MAX_NODES],
    count: usize,
}

impl AdjList {
    const fn new() -> Self {
        Self { neighbors: [0; MAX_NODES], count: 0 }
    }
    fn add(&mut self, n: u32) {
        if self.count < MAX_NODES && !self.contains(n) {
            self.neighbors[self.count] = n;
            self.count += 1;
        }
    }
    fn contains(&self, n: u32) -> bool {
        for i in 0..self.count {
            if self.neighbors[i] == n { return true; }
        }
        false
    }
}

/// The IPC communication graph.
pub struct IpcGraph {
    edges: [Option<Edge>; MAX_EDGES],
    edge_count: usize,
    /// Unique node (thread) IDs.
    nodes: [u32; MAX_NODES],
    node_count: usize,
    /// Cycle detection counter.
    cycles_detected: u32,
    /// Last treewidth estimate.
    treewidth_estimate: u32,
    /// Call counter for periodic checks.
    call_count: u64,
}

impl IpcGraph {
    const fn new() -> Self {
        Self {
            edges: [None; MAX_EDGES],
            edge_count: 0,
            nodes: [0; MAX_NODES],
            node_count: 0,
            cycles_detected: 0,
            treewidth_estimate: 0,
            call_count: 0,
        }
    }

    fn ensure_node(&mut self, tid: u32) -> usize {
        for i in 0..self.node_count {
            if self.nodes[i] == tid { return i; }
        }
        if self.node_count < MAX_NODES {
            self.nodes[self.node_count] = tid;
            self.node_count += 1;
            self.node_count - 1
        } else {
            0 // overflow -- reuse slot 0
        }
    }

    fn record_edge(&mut self, sender: u32, receiver: u32, endpoint: u32) {
        // Avoid duplicate edges.
        for i in 0..self.edge_count {
            if let Some(e) = &self.edges[i] {
                if e.sender == sender && e.receiver == receiver && e.endpoint == endpoint {
                    return;
                }
            }
        }
        if self.edge_count < MAX_EDGES {
            self.edges[self.edge_count] = Some(Edge { sender, receiver, endpoint });
            self.edge_count += 1;
        }
    }

    /// DFS cycle detection on the directed IPC graph.
    fn has_cycle(&self) -> bool {
        // States: 0=white, 1=gray, 2=black
        let mut color = [0u8; MAX_NODES];
        for start in 0..self.node_count {
            if color[start] == 0 && self.dfs_visit(start, &mut color) {
                return true;
            }
        }
        false
    }

    fn dfs_visit(&self, node: usize, color: &mut [u8; MAX_NODES]) -> bool {
        color[node] = 1; // gray
        let src_tid = self.nodes[node];
        for i in 0..self.edge_count {
            if let Some(e) = &self.edges[i] {
                if e.sender == src_tid {
                    let dst = self.node_index(e.receiver);
                    if let Some(d) = dst {
                        if color[d] == 1 { return true; } // back edge = cycle
                        if color[d] == 0 && self.dfs_visit(d, color) { return true; }
                    }
                }
            }
        }
        color[node] = 2; // black
        false
    }

    fn node_index(&self, tid: u32) -> Option<usize> {
        for i in 0..self.node_count {
            if self.nodes[i] == tid { return Some(i); }
        }
        None
    }

    /// Greedy elimination treewidth estimate.
    /// Removes minimum-degree vertex, tracks max degree at removal.
    fn estimate_treewidth(&self) -> u32 {
        if self.node_count == 0 { return 0; }

        // Build undirected adjacency (ignoring directions for treewidth).
        let mut adj: [[bool; MAX_NODES]; MAX_NODES] = [[false; MAX_NODES]; MAX_NODES];
        let mut alive = [false; MAX_NODES];

        for i in 0..self.node_count { alive[i] = true; }
        for i in 0..self.edge_count {
            if let Some(e) = &self.edges[i] {
                if let (Some(s), Some(r)) = (self.node_index(e.sender), self.node_index(e.receiver)) {
                    adj[s][r] = true;
                    adj[r][s] = true;
                }
            }
        }

        let mut max_degree = 0u32;
        for _ in 0..self.node_count {
            // Find alive vertex with minimum degree.
            let mut min_deg = u32::MAX;
            let mut min_v = 0;
            for v in 0..self.node_count {
                if !alive[v] { continue; }
                let deg = (0..self.node_count)
                    .filter(|&u| alive[u] && adj[v][u])
                    .count() as u32;
                if deg < min_deg {
                    min_deg = deg;
                    min_v = v;
                }
            }
            if min_deg == u32::MAX { break; }
            if min_deg > max_degree { max_degree = min_deg; }

            // Connect neighbors of min_v (fill-in).
            let nbrs: [usize; MAX_NODES] = {
                let mut n = [0usize; MAX_NODES];
                let mut c = 0;
                for u in 0..self.node_count {
                    if alive[u] && adj[min_v][u] {
                        n[c] = u;
                        c += 1;
                    }
                }
                n
            };
            let nbr_count = (0..self.node_count).filter(|&u| alive[u] && adj[min_v][u]).count();
            for i in 0..nbr_count {
                for j in (i+1)..nbr_count {
                    adj[nbrs[i]][nbrs[j]] = true;
                    adj[nbrs[j]][nbrs[i]] = true;
                }
            }
            alive[min_v] = false;
        }
        max_degree
    }
}

static IPC_GRAPH: Mutex<IpcGraph> = Mutex::new(IpcGraph::new());

/// Record an IPC call/send edge. Periodically checks for cycles and treewidth.
pub fn record(sender_tid: u32, receiver_tid: u32, endpoint_id: u32) {
    let mut g = IPC_GRAPH.lock();
    g.ensure_node(sender_tid);
    g.ensure_node(receiver_tid);
    g.record_edge(sender_tid, receiver_tid, endpoint_id);
    g.call_count += 1;

    // Periodic analysis: every 1024 calls.
    if g.call_count & 1023 == 0 {
        if g.has_cycle() {
            g.cycles_detected += 1;
            crate::kprintln!("[ipc-audit] CYCLE detected! (count={})", g.cycles_detected);
        }
        let tw = g.estimate_treewidth();
        if tw != g.treewidth_estimate {
            g.treewidth_estimate = tw;
            if tw > 2 {
                crate::kprintln!("[ipc-audit] treewidth={} (>2, consider restructuring)", tw);
            }
        }
    }
}
