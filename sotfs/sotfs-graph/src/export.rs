//! # Graph Export — GraphViz, D3 JSON, and Graph Hunter temporal multigraph
//!
//! Provides serialization of the TypeGraph into three formats:
//! - **GraphViz DOT** for static visualization and debugging
//! - **D3.js JSON** for interactive browser-based exploration
//! - **Graph Hunter temporal multigraph** for advanced graph analytics
//!
//! All exports are read-only snapshots; the TypeGraph is not modified.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use crate::graph::TypeGraph;
use crate::types::*;

// ---------------------------------------------------------------------------
// GraphViz DOT export
// ---------------------------------------------------------------------------

/// Style configuration for DOT export.
pub struct DotStyle {
    /// Include file data sizes as labels on Inode nodes.
    pub show_sizes: bool,
    /// Include capability rights as labels on grants edges.
    pub show_rights: bool,
    /// Include block sector info on Block nodes.
    pub show_blocks: bool,
    /// Include xattr count on Inode nodes.
    pub show_xattrs: bool,
}

impl Default for DotStyle {
    fn default() -> Self {
        Self {
            show_sizes: true,
            show_rights: true,
            show_blocks: false,
            show_xattrs: true,
        }
    }
}

/// Export the TypeGraph as a GraphViz DOT string.
///
/// Nodes are color-coded by type:
/// - Inode (Regular): lightblue
/// - Inode (Directory): gold
/// - Inode (Symlink): plum
/// - Directory: lightyellow
/// - Capability: lightgreen
/// - Block: lightcoral
/// - Transaction: lightsalmon
/// - Version: lavender
///
/// Edges are styled by type:
/// - contains: solid black with name label
/// - grants: dashed green with rights label
/// - delegates: dotted purple
/// - pointsTo: solid gray with offset label
/// - supersedes: bold red
/// - derivesFrom: dashed blue
/// - hasXattr: dotted orange
pub fn to_dot(g: &TypeGraph, style: &DotStyle) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("digraph sotFS {\n");
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [fontname=\"monospace\", fontsize=10];\n");
    out.push_str("  edge [fontname=\"monospace\", fontsize=8];\n\n");

    // --- Inode nodes ---
    for (_aid, inode) in g.inodes.iter() {
        let color = match inode.vtype {
            VnodeType::Directory => "gold",
            VnodeType::Symlink => "plum",
            _ => "lightblue",
        };
        let vtype_str = match inode.vtype {
            VnodeType::Regular => "file",
            VnodeType::Directory => "dir",
            VnodeType::Symlink => "sym",
            VnodeType::CharDevice => "chr",
            VnodeType::BlockDevice => "blk",
        };
        let mut label = format!("I{}\\n{}\\nlc={}", inode.id, vtype_str, inode.link_count);
        if style.show_sizes && inode.vtype == VnodeType::Regular {
            label.push_str(&format!("\\n{}B", inode.size));
        }
        if style.show_xattrs {
            if let Some(xids) = g.inode_xattrs.get(&inode.id) {
                if !xids.is_empty() {
                    label.push_str(&format!("\\nxa:{}", xids.len()));
                }
            }
        }
        out.push_str(&format!(
            "  I{} [label=\"{}\", shape=box, style=filled, fillcolor={}];\n",
            inode.id, label, color
        ));
    }

    // --- Directory nodes ---
    for (_aid, dir) in g.dirs.iter() {
        out.push_str(&format!(
            "  D{} [label=\"D{}\\nino={}\", shape=folder, style=filled, fillcolor=lightyellow];\n",
            dir.id, dir.id, dir.inode_id
        ));
    }

    // --- Capability nodes ---
    for (_aid, cap) in g.caps.iter() {
        let rights_str = format_rights(cap.rights);
        out.push_str(&format!(
            "  C{} [label=\"C{}\\n{}\", shape=diamond, style=filled, fillcolor=lightgreen];\n",
            cap.id, cap.id, rights_str
        ));
    }

    // --- Block nodes ---
    for (_aid, block) in g.blocks.iter() {
        let mut label = format!("B{}\\nrc={}", block.id, block.refcount);
        if style.show_blocks {
            label.push_str(&format!("\\nsec {}+{}", block.sector_start, block.sector_count));
        }
        out.push_str(&format!(
            "  B{} [label=\"{}\", shape=cylinder, style=filled, fillcolor=lightcoral];\n",
            block.id, label
        ));
    }

    // --- Version nodes ---
    for (_aid, ver) in g.versions.iter() {
        out.push_str(&format!(
            "  V{} [label=\"V{}\\nt={}\", shape=oval, style=filled, fillcolor=lavender];\n",
            ver.id, ver.id, ver.timestamp
        ));
    }

    out.push('\n');

    // --- Edges ---
    for (_aid, edge) in g.edges.iter() {
        match edge {
            Edge::Contains { src, tgt, name, .. } => {
                let escaped = name.replace('\"', "\\\"");
                out.push_str(&format!(
                    "  D{} -> I{} [label=\"{}\", color=black];\n",
                    src, tgt, escaped
                ));
            }
            Edge::Grants { src, tgt, rights, .. } => {
                let label = if style.show_rights {
                    format_rights(*rights)
                } else {
                    "grants".into()
                };
                out.push_str(&format!(
                    "  C{} -> I{} [label=\"{}\", style=dashed, color=green4];\n",
                    src, tgt, label
                ));
            }
            Edge::Delegates { src, tgt, .. } => {
                out.push_str(&format!(
                    "  C{} -> C{} [label=\"delegates\", style=dotted, color=purple];\n",
                    src, tgt
                ));
            }
            Edge::DerivedFrom { src, tgt, .. } => {
                out.push_str(&format!(
                    "  V{} -> V{} [label=\"derives\", style=dashed, color=blue];\n",
                    src, tgt
                ));
            }
            Edge::Supersedes { src, tgt, .. } => {
                out.push_str(&format!(
                    "  I{} -> I{} [label=\"supersedes\", style=bold, color=red];\n",
                    src, tgt
                ));
            }
            Edge::PointsTo { src, tgt, offset, .. } => {
                out.push_str(&format!(
                    "  I{} -> B{} [label=\"@{}\", color=gray50];\n",
                    src, tgt, offset
                ));
            }
            Edge::HasXattr { src, tgt, .. } => {
                out.push_str(&format!(
                    "  I{} -> XA{} [style=dotted, color=orange];\n",
                    src, tgt
                ));
            }
        }
    }

    out.push_str("}\n");
    out
}

fn format_rights(r: Rights) -> String {
    let mut s = String::new();
    if r.contains(Rights::READ) { s.push('r'); }
    if r.contains(Rights::WRITE) { s.push('w'); }
    if r.contains(Rights::EXECUTE) { s.push('x'); }
    if r.contains(Rights::GRANT) { s.push('g'); }
    if r.contains(Rights::REVOKE) { s.push('v'); }
    if s.is_empty() { s.push_str("none"); }
    s
}

// ---------------------------------------------------------------------------
// D3.js JSON export
// ---------------------------------------------------------------------------

/// Export the TypeGraph as a D3.js force-directed graph JSON string.
///
/// Format: `{ "nodes": [...], "links": [...] }`
/// Each node has: `{ "id": "I1", "type": "inode", "label": "...", ... }`
/// Each link has: `{ "source": "D1", "target": "I1", "type": "contains", "label": "..." }`
pub fn to_d3_json(g: &TypeGraph) -> String {
    let mut nodes = Vec::new();
    let mut links = Vec::new();

    // Nodes
    for (_aid, inode) in g.inodes.iter() {
        let vtype = match inode.vtype {
            VnodeType::Regular => "file",
            VnodeType::Directory => "dir",
            VnodeType::Symlink => "symlink",
            VnodeType::CharDevice => "chardev",
            VnodeType::BlockDevice => "blockdev",
        };
        nodes.push(format!(
            "{{\"id\":\"I{}\",\"type\":\"inode\",\"vtype\":\"{}\",\"size\":{},\"link_count\":{},\"uid\":{},\"gid\":{},\"mtime\":{}}}",
            inode.id, vtype, inode.size, inode.link_count, inode.uid, inode.gid, inode.mtime
        ));
    }
    for (_aid, dir) in g.dirs.iter() {
        nodes.push(format!(
            "{{\"id\":\"D{}\",\"type\":\"directory\",\"inode_id\":{}}}",
            dir.id, dir.inode_id
        ));
    }
    for (_aid, cap) in g.caps.iter() {
        nodes.push(format!(
            "{{\"id\":\"C{}\",\"type\":\"capability\",\"rights\":{},\"epoch\":{}}}",
            cap.id, cap.rights.0, cap.epoch
        ));
    }
    for (_aid, block) in g.blocks.iter() {
        nodes.push(format!(
            "{{\"id\":\"B{}\",\"type\":\"block\",\"sector_start\":{},\"sector_count\":{},\"refcount\":{}}}",
            block.id, block.sector_start, block.sector_count, block.refcount
        ));
    }
    for (_aid, ver) in g.versions.iter() {
        nodes.push(format!(
            "{{\"id\":\"V{}\",\"type\":\"version\",\"timestamp\":{},\"root_inode\":{}}}",
            ver.id, ver.timestamp, ver.root_inode_id
        ));
    }

    // Links
    for (_aid, edge) in g.edges.iter() {
        let link = match edge {
            Edge::Contains { id, src, tgt, name } => format!(
                "{{\"id\":{},\"source\":\"D{}\",\"target\":\"I{}\",\"type\":\"contains\",\"name\":{}}}",
                id, src, tgt, json_str(name)
            ),
            Edge::Grants { id, src, tgt, rights } => format!(
                "{{\"id\":{},\"source\":\"C{}\",\"target\":\"I{}\",\"type\":\"grants\",\"rights\":{}}}",
                id, src, tgt, rights.0
            ),
            Edge::Delegates { id, src, tgt } => format!(
                "{{\"id\":{},\"source\":\"C{}\",\"target\":\"C{}\",\"type\":\"delegates\"}}",
                id, src, tgt
            ),
            Edge::DerivedFrom { id, src, tgt } => format!(
                "{{\"id\":{},\"source\":\"V{}\",\"target\":\"V{}\",\"type\":\"derivesFrom\"}}",
                id, src, tgt
            ),
            Edge::Supersedes { id, src, tgt } => format!(
                "{{\"id\":{},\"source\":\"I{}\",\"target\":\"I{}\",\"type\":\"supersedes\"}}",
                id, src, tgt
            ),
            Edge::PointsTo { id, src, tgt, offset } => format!(
                "{{\"id\":{},\"source\":\"I{}\",\"target\":\"B{}\",\"type\":\"pointsTo\",\"offset\":{}}}",
                id, src, tgt, offset
            ),
            Edge::HasXattr { id, src, tgt } => format!(
                "{{\"id\":{},\"source\":\"I{}\",\"target\":\"XA{}\",\"type\":\"hasXattr\"}}",
                id, src, tgt
            ),
        };
        links.push(link);
    }

    let nodes_str = nodes.join(",\n    ");
    let links_str = links.join(",\n    ");
    format!("{{\n  \"nodes\": [\n    {}\n  ],\n  \"links\": [\n    {}\n  ]\n}}", nodes_str, links_str)
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

// ---------------------------------------------------------------------------
// Graph Hunter temporal multigraph export
// ---------------------------------------------------------------------------

/// A temporal event for the Graph Hunter format.
/// Each node/edge creation carries a timestamp.
#[derive(Debug, Clone)]
pub struct TemporalEvent {
    pub timestamp: u64,
    pub event_type: EventType,
}

/// Types of temporal events.
#[derive(Debug, Clone)]
pub enum EventType {
    NodeAdd { id: String, node_type: String, attrs: String },
    EdgeAdd { id: u64, src: String, tgt: String, edge_type: String, attrs: String },
}

/// Export the TypeGraph as a Graph Hunter temporal multigraph JSON.
///
/// Format: `{ "meta": {...}, "events": [...] }`
///
/// Graph Hunter expects a sequence of timestamped add/remove events.
/// Since we export a snapshot, all events share the Inode's ctime or mtime.
/// Nodes are prefixed by type (I=Inode, D=Directory, C=Capability, B=Block, V=Version).
///
/// The temporal dimension comes from Inode ctime/mtime: files created earlier
/// appear earlier in the event stream, enabling Graph Hunter to replay the
/// filesystem's construction history.
pub fn to_graph_hunter(g: &TypeGraph) -> String {
    let mut events: Vec<(u64, String)> = Vec::new();

    // Collect inode nodes with their creation timestamps
    for (_aid, inode) in g.inodes.iter() {
        let vtype = match inode.vtype {
            VnodeType::Regular => "file",
            VnodeType::Directory => "dir",
            VnodeType::Symlink => "symlink",
            VnodeType::CharDevice => "chardev",
            VnodeType::BlockDevice => "blockdev",
        };
        let event = format!(
            "{{\"t\":{},\"op\":\"add_node\",\"id\":\"I{}\",\"type\":\"inode\",\"vtype\":\"{}\",\"size\":{},\"link_count\":{},\"perms\":{},\"uid\":{},\"gid\":{}}}",
            inode.ctime, inode.id, vtype, inode.size, inode.link_count,
            inode.permissions.mode(), inode.uid, inode.gid
        );
        events.push((inode.ctime, event));
    }

    // Directory nodes (use paired inode's ctime)
    for (_aid, dir) in g.dirs.iter() {
        let ts = g.get_inode(dir.inode_id)
            .map(|i| i.ctime)
            .unwrap_or(0);
        let event = format!(
            "{{\"t\":{},\"op\":\"add_node\",\"id\":\"D{}\",\"type\":\"directory\",\"inode_id\":{}}}",
            ts, dir.id, dir.inode_id
        );
        events.push((ts, event));
    }

    // Capability nodes
    for (_aid, cap) in g.caps.iter() {
        let event = format!(
            "{{\"t\":{},\"op\":\"add_node\",\"id\":\"C{}\",\"type\":\"capability\",\"rights\":{},\"epoch\":{}}}",
            cap.epoch, cap.id, cap.rights.0, cap.epoch
        );
        events.push((cap.epoch, event));
    }

    // Block nodes
    for (_aid, block) in g.blocks.iter() {
        let event = format!(
            "{{\"t\":0,\"op\":\"add_node\",\"id\":\"B{}\",\"type\":\"block\",\"sectors\":{},\"refcount\":{}}}",
            block.id, block.sector_count, block.refcount
        );
        events.push((0, event));
    }

    // Version nodes
    for (_aid, ver) in g.versions.iter() {
        let event = format!(
            "{{\"t\":{},\"op\":\"add_node\",\"id\":\"V{}\",\"type\":\"version\",\"root\":{}}}",
            ver.timestamp, ver.id, ver.root_inode_id
        );
        events.push((ver.timestamp, event));
    }

    // Edges — timestamp from target inode's mtime (best approximation)
    for (_aid, edge) in g.edges.iter() {
        let (ts, event) = match edge {
            Edge::Contains { id, src, tgt, name } => {
                let ts = g.get_inode(*tgt).map(|i| i.ctime).unwrap_or(0);
                (ts, format!(
                    "{{\"t\":{},\"op\":\"add_edge\",\"id\":{},\"src\":\"D{}\",\"tgt\":\"I{}\",\"type\":\"contains\",\"name\":{}}}",
                    ts, id, src, tgt, json_str(name)
                ))
            }
            Edge::Grants { id, src, tgt, rights } => {
                let ts = g.get_cap(*src).map(|c| c.epoch).unwrap_or(0);
                (ts, format!(
                    "{{\"t\":{},\"op\":\"add_edge\",\"id\":{},\"src\":\"C{}\",\"tgt\":\"I{}\",\"type\":\"grants\",\"rights\":{}}}",
                    ts, id, src, tgt, rights.0
                ))
            }
            Edge::Delegates { id, src, tgt } => (0, format!(
                "{{\"t\":0,\"op\":\"add_edge\",\"id\":{},\"src\":\"C{}\",\"tgt\":\"C{}\",\"type\":\"delegates\"}}",
                id, src, tgt
            )),
            Edge::DerivedFrom { id, src, tgt } => {
                let ts = g.versions.values().find(|v| v.id == *src).map(|v| v.timestamp).unwrap_or(0);
                (ts, format!(
                    "{{\"t\":{},\"op\":\"add_edge\",\"id\":{},\"src\":\"V{}\",\"tgt\":\"V{}\",\"type\":\"derivesFrom\"}}",
                    ts, id, src, tgt
                ))
            }
            Edge::Supersedes { id, src, tgt } => (0, format!(
                "{{\"t\":0,\"op\":\"add_edge\",\"id\":{},\"src\":\"I{}\",\"tgt\":\"I{}\",\"type\":\"supersedes\"}}",
                id, src, tgt
            )),
            Edge::PointsTo { id, src, tgt, offset } => (0, format!(
                "{{\"t\":0,\"op\":\"add_edge\",\"id\":{},\"src\":\"I{}\",\"tgt\":\"B{}\",\"type\":\"pointsTo\",\"offset\":{}}}",
                id, src, tgt, offset
            )),
            Edge::HasXattr { id, src, tgt } => (0, format!(
                "{{\"t\":0,\"op\":\"add_edge\",\"id\":{},\"src\":\"I{}\",\"tgt\":\"XA{}\",\"type\":\"hasXattr\"}}",
                id, src, tgt
            )),
        };
        events.push((ts, event));
    }

    // Sort by timestamp for temporal replay
    events.sort_by_key(|(ts, _)| *ts);

    let meta = format!(
        "{{\"format\":\"graph-hunter-temporal\",\"version\":1,\"node_count\":{},\"edge_count\":{},\"node_types\":[\"inode\",\"directory\",\"capability\",\"block\",\"version\"],\"edge_types\":[\"contains\",\"grants\",\"delegates\",\"derivesFrom\",\"supersedes\",\"pointsTo\",\"hasXattr\"]}}",
        g.inodes.len() + g.dirs.len() + g.caps.len() + g.blocks.len() + g.versions.len(),
        g.edges.len()
    );

    let events_str: Vec<&str> = events.iter().map(|(_, e)| e.as_str()).collect();
    format!(
        "{{\n  \"meta\": {},\n  \"events\": [\n    {}\n  ]\n}}",
        meta,
        events_str.join(",\n    ")
    )
}

// ---------------------------------------------------------------------------
// Snapshot statistics (useful for dashboards)
// ---------------------------------------------------------------------------

/// Summary statistics of a TypeGraph snapshot.
#[derive(Debug, Clone)]
pub struct GraphStats {
    pub inode_count: usize,
    pub dir_count: usize,
    pub cap_count: usize,
    pub block_count: usize,
    pub version_count: usize,
    pub edge_count: usize,
    pub file_count: usize,
    pub symlink_count: usize,
    pub xattr_count: usize,
    pub total_file_bytes: u64,
    pub max_link_count: u32,
    pub max_dir_entries: usize,
    pub depth_estimate: usize,
}

/// Compute summary statistics for the TypeGraph.
pub fn stats(g: &TypeGraph) -> GraphStats {
    let mut file_count = 0usize;
    let mut symlink_count = 0usize;
    let mut total_file_bytes = 0u64;
    let mut max_link_count = 0u32;

    for (_aid, inode) in g.inodes.iter() {
        match inode.vtype {
            VnodeType::Regular => {
                file_count += 1;
                total_file_bytes += inode.size;
            }
            VnodeType::Symlink => { symlink_count += 1; }
            _ => {}
        }
        if inode.link_count > max_link_count {
            max_link_count = inode.link_count;
        }
    }

    let max_dir_entries = g.dir_contains.values()
        .map(|s| s.len())
        .max()
        .unwrap_or(0);

    // Estimate depth via longest path from root
    let depth_estimate = estimate_depth(g);

    GraphStats {
        inode_count: g.inodes.len(),
        dir_count: g.dirs.len(),
        cap_count: g.caps.len(),
        block_count: g.blocks.len(),
        version_count: g.versions.len(),
        edge_count: g.edges.len(),
        file_count,
        symlink_count,
        xattr_count: g.xattrs.len(),
        total_file_bytes,
        max_link_count,
        max_dir_entries,
        depth_estimate,
    }
}

fn estimate_depth(g: &TypeGraph) -> usize {
    // BFS from root directory to find max depth
    let mut max_depth = 0usize;
    let mut queue = Vec::new();
    queue.push((g.root_dir, 0usize));

    #[cfg(feature = "std")]
    let mut visited = std::collections::HashSet::new();
    #[cfg(not(feature = "std"))]
    let mut visited = alloc::collections::BTreeSet::new();

    visited.insert(g.root_dir);

    while let Some((dir, depth)) = queue.pop() {
        if depth > max_depth {
            max_depth = depth;
        }
        if let Some(edge_ids) = g.dir_contains.get(&dir) {
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = g.get_edge(eid) {
                    if name == "." || name == ".." { continue; }
                    if let Some(inode) = g.get_inode(*tgt) {
                        if inode.vtype == VnodeType::Directory {
                            if let Some(child_dir) = g.dir_for_inode(*tgt) {
                                if visited.insert(child_dir) {
                                    queue.push((child_dir, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    max_depth
}
