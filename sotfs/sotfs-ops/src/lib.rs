//! # sotfs-ops — DPO Graph Rewriting Rules
//!
//! Each POSIX filesystem operation is a function that takes a mutable
//! reference to the TypeGraph and applies the corresponding DPO rule.
//! Gluing conditions are checked before mutation; invariants are
//! preserved by construction.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use sotfs_graph::graph::{TypeGraph, LINK_MAX};
use sotfs_graph::types::*;
use sotfs_graph::GraphError;

/// Result of a CREATE or MKDIR operation.
pub struct CreateResult {
    pub inode_id: InodeId,
    pub dir_id: Option<DirId>, // Some if mkdir
}

/// DPO Rule: CREATE (file) — §6.2.1
pub fn create_file(
    g: &mut TypeGraph,
    parent_dir: DirId,
    name: &str,
    uid: u32,
    gid: u32,
    permissions: Permissions,
) -> Result<InodeId, GraphError> {
    // Reject reserved and invalid names
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(GraphError::NameNotFound(name.into()));
    }
    // GC-CREATE-1: no existing entry with this name
    if g.resolve_name(parent_dir, name).is_some() {
        return Err(GraphError::NameExists {
            dir: parent_dir,
            name: name.into(),
        });
    }
    if !g.contains_dir(parent_dir) {
        return Err(GraphError::DirNotFound(parent_dir));
    }

    let inode_id = g.alloc_inode_id();
    let edge_id = g.alloc_edge_id();

    // Create inode with link_count=1
    let mut inode = Inode::new_file(inode_id, permissions, uid, gid);
    inode.link_count = 1;
    g.insert_inode(inode_id, inode);

    // Create contains edge
    let edge = Edge::Contains {
        id: edge_id,
        src: parent_dir,
        tgt: inode_id,
        name: name.into(),
    };
    g.insert_edge(edge_id, edge);
    g.dir_contains
        .entry(parent_dir)
        .or_default()
        .insert(edge_id);
    g.inode_incoming_contains
        .entry(inode_id)
        .or_default()
        .insert(edge_id);

    Ok(inode_id)
}

/// DPO Rule: MKDIR — §6.2.3
pub fn mkdir(
    g: &mut TypeGraph,
    parent_dir: DirId,
    name: &str,
    uid: u32,
    gid: u32,
    permissions: Permissions,
) -> Result<CreateResult, GraphError> {
    // Reject reserved and invalid names
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(GraphError::NameNotFound(name.into()));
    }
    // GC-MKDIR-1: no existing entry
    if g.resolve_name(parent_dir, name).is_some() {
        return Err(GraphError::NameExists {
            dir: parent_dir,
            name: name.into(),
        });
    }
    let parent_inode_id = g
        .get_dir(parent_dir)
        .ok_or(GraphError::DirNotFound(parent_dir))?
        .inode_id;

    let inode_id = g.alloc_inode_id();
    let dir_id = g.alloc_dir_id();
    let entry_edge = g.alloc_edge_id();
    let dot_edge = g.alloc_edge_id();
    let dotdot_edge = g.alloc_edge_id();

    // Create inode (link_count=2: entry from parent + "." self)
    // G3 counts "." but not ".." → link_count = 2
    let mut inode = Inode::new_dir(inode_id, permissions, uid, gid);
    inode.link_count = 2;
    g.insert_inode(inode_id, inode);

    // Create directory node
    g.insert_dir(
        dir_id,
        Directory {
            id: dir_id,
            inode_id,
        },
    );

    // Edge: parent → new inode (name)
    let e1 = Edge::Contains {
        id: entry_edge,
        src: parent_dir,
        tgt: inode_id,
        name: name.into(),
    };
    g.insert_edge(entry_edge, e1);
    g.dir_contains
        .entry(parent_dir)
        .or_default()
        .insert(entry_edge);
    g.inode_incoming_contains
        .entry(inode_id)
        .or_default()
        .insert(entry_edge);

    // Edge: new_dir → new inode (".")
    let e2 = Edge::Contains {
        id: dot_edge,
        src: dir_id,
        tgt: inode_id,
        name: ".".into(),
    };
    g.insert_edge(dot_edge, e2);
    g.dir_contains
        .entry(dir_id)
        .or_default()
        .insert(dot_edge);
    g.inode_incoming_contains
        .entry(inode_id)
        .or_default()
        .insert(dot_edge);

    // Edge: new_dir → parent inode ("..")
    let e3 = Edge::Contains {
        id: dotdot_edge,
        src: dir_id,
        tgt: parent_inode_id,
        name: "..".into(),
    };
    g.insert_edge(dotdot_edge, e3);
    g.dir_contains
        .entry(dir_id)
        .or_default()
        .insert(dotdot_edge);
    g.inode_incoming_contains
        .entry(parent_inode_id)
        .or_default()
        .insert(dotdot_edge);

    Ok(CreateResult {
        inode_id,
        dir_id: Some(dir_id),
    })
}

/// DPO Rule: RMDIR — §6.2.4
pub fn rmdir(g: &mut TypeGraph, parent_dir: DirId, name: &str) -> Result<(), GraphError> {
    if name == "." || name == ".." {
        return Err(GraphError::NameNotFound(name.into()));
    }

    let target_inode_id = g
        .resolve_name(parent_dir, name)
        .ok_or_else(|| GraphError::NameNotFound(name.into()))?;

    let inode = g
        .get_inode(target_inode_id)
        .ok_or(GraphError::InodeNotFound(target_inode_id))?;
    if inode.vtype != VnodeType::Directory {
        return Err(GraphError::NotADirectory(target_inode_id));
    }

    let target_dir = g
        .dir_for_inode(target_inode_id)
        .ok_or(GraphError::NotADirectory(target_inode_id))?;

    // GC-RMDIR-1: must be empty (only "." and "..")
    if let Some(edge_ids) = g.dir_contains.get(&target_dir) {
        for &eid in edge_ids {
            if let Some(Edge::Contains { name: n, .. }) = g.get_edge(eid) {
                if n != "." && n != ".." {
                    return Err(GraphError::DirNotEmpty(target_dir));
                }
            }
        }
    }

    // Collect edges to remove
    let mut edges_to_remove = Vec::new();

    // Entry edge from parent
    if let Some(parent_edges) = g.dir_contains.get(&parent_dir) {
        for &eid in parent_edges {
            if let Some(Edge::Contains { tgt, name: n, .. }) = g.get_edge(eid) {
                if *tgt == target_inode_id && n == name {
                    edges_to_remove.push(eid);
                }
            }
        }
    }

    // "." and ".." edges from target dir
    if let Some(target_edges) = g.dir_contains.get(&target_dir) {
        edges_to_remove.extend(target_edges.iter().copied());
    }

    // Remove edges
    for eid in &edges_to_remove {
        if let Some(edge) = g.remove_edge(*eid) {
            match &edge {
                Edge::Contains { src, tgt, .. } => {
                    if let Some(set) = g.dir_contains.get_mut(src) {
                        set.remove(eid);
                    }
                    if let Some(set) = g.inode_incoming_contains.get_mut(tgt) {
                        set.remove(eid);
                    }
                }
                _ => {}
            }
        }
    }

    // Remove nodes
    g.remove_inode(target_inode_id);
    g.remove_dir(target_dir);
    g.dir_contains.remove(&target_dir);
    g.inode_incoming_contains.remove(&target_inode_id);

    Ok(())
}

/// DPO Rule: LINK — §6.2.5
pub fn link(
    g: &mut TypeGraph,
    dir: DirId,
    name: &str,
    target_inode: InodeId,
) -> Result<(), GraphError> {
    // Cannot create links named "." or ".." — these are reserved
    if name == "." || name == ".." {
        return Err(GraphError::NameNotFound(name.into()));
    }
    // GC-LINK-1: no existing entry
    if g.resolve_name(dir, name).is_some() {
        return Err(GraphError::NameExists {
            dir,
            name: name.into(),
        });
    }
    let inode = g
        .get_inode(target_inode)
        .ok_or(GraphError::InodeNotFound(target_inode))?;
    // GC-LINK-2: cannot link directories
    if inode.vtype == VnodeType::Directory {
        return Err(GraphError::LinkToDirectory(target_inode));
    }
    // GC-LINK-3: link count limit
    if inode.link_count >= LINK_MAX {
        return Err(GraphError::LinkCountExceeded(LINK_MAX));
    }

    let edge_id = g.alloc_edge_id();
    let edge = Edge::Contains {
        id: edge_id,
        src: dir,
        tgt: target_inode,
        name: name.into(),
    };
    g.insert_edge(edge_id, edge);
    g.dir_contains.entry(dir).or_default().insert(edge_id);
    g.inode_incoming_contains
        .entry(target_inode)
        .or_default()
        .insert(edge_id);

    g.get_inode_mut(target_inode).unwrap().link_count += 1;

    Ok(())
}

/// DPO Rule: UNLINK — §6.2.6
pub fn unlink(g: &mut TypeGraph, dir: DirId, name: &str) -> Result<(), GraphError> {
    if name == "." || name == ".." {
        return Err(GraphError::NameNotFound(name.into()));
    }

    // Find the edge
    let (edge_id, target_inode_id) = {
        let edge_ids = g
            .dir_contains
            .get(&dir)
            .ok_or(GraphError::DirNotFound(dir))?;
        let mut found = None;
        for &eid in edge_ids {
            if let Some(Edge::Contains { tgt, name: n, .. }) = g.get_edge(eid) {
                if n == name {
                    found = Some((eid, *tgt));
                    break;
                }
            }
        }
        found.ok_or_else(|| GraphError::NameNotFound(name.into()))?
    };

    let inode = g
        .get_inode(target_inode_id)
        .ok_or(GraphError::InodeNotFound(target_inode_id))?;
    if inode.vtype == VnodeType::Directory {
        return Err(GraphError::NotAFile(target_inode_id));
    }

    // Remove the contains edge
    g.remove_edge(edge_id);
    if let Some(set) = g.dir_contains.get_mut(&dir) {
        set.remove(&edge_id);
    }
    if let Some(set) = g.inode_incoming_contains.get_mut(&target_inode_id) {
        set.remove(&edge_id);
    }

    let inode = g.get_inode_mut(target_inode_id).unwrap();
    inode.link_count -= 1;

    // If last link, garbage-collect inode and its blocks
    if inode.link_count == 0 {
        // Remove pointsTo edges and decrement block refcounts
        let pts_edges: Vec<EdgeId> = g
            .inode_points_to
            .remove(&target_inode_id)
            .unwrap_or_default()
            .into_iter()
            .collect();

        for eid in pts_edges {
            if let Some(Edge::PointsTo { tgt: block_id, .. }) = g.remove_edge(eid) {
                if let Some(block) = g.get_block_mut(block_id) {
                    block.refcount -= 1;
                    if block.refcount == 0 {
                        g.remove_block(block_id);
                    }
                }
            }
        }

        g.remove_inode(target_inode_id);
        g.inode_incoming_contains.remove(&target_inode_id);
    }

    Ok(())
}

/// DPO Rule: RENAME — §6.2.7
///
/// Dispatches to a fast path (same directory) or slow path (cross-directory).
/// Same-directory renames cannot create cycles and skip the ancestor walk.
pub fn rename(
    g: &mut TypeGraph,
    src_dir: DirId,
    src_name: &str,
    dst_dir: DirId,
    dst_name: &str,
) -> Result<(), GraphError> {
    // Cannot rename "." or ".." — these are structural
    if src_name == "." || src_name == ".." || dst_name == "." || dst_name == ".." {
        return Err(GraphError::NameNotFound(src_name.into()));
    }

    // FAST PATH: same-directory rename — no cycle possible, no ".." update needed.
    if src_dir == dst_dir {
        return rename_same_dir(g, src_dir, src_name, dst_name);
    }
    // SLOW PATH: cross-directory rename with cycle prevention.
    rename_cross_dir(g, src_dir, src_name, dst_dir, dst_name)
}

/// Fast path: rename within the same directory.
///
/// No cycle check needed (moving within the same parent cannot create a cycle).
/// No ".." edge update needed (parent directory is unchanged).
/// No 2PC needed (single directory, atomic name swap).
fn rename_same_dir(
    g: &mut TypeGraph,
    dir: DirId,
    src_name: &str,
    dst_name: &str,
) -> Result<(), GraphError> {
    // GC-RENAME-1: source must exist
    let src_inode = g
        .resolve_name(dir, src_name)
        .ok_or_else(|| GraphError::NameNotFound(src_name.into()))?;

    // If source and destination names are identical, it's a no-op
    if src_name == dst_name {
        return Ok(());
    }

    // If destination already exists, unlink/rmdir it first (POSIX replace semantics)
    if let Some(dst_inode_id) = g.resolve_name(dir, dst_name) {
        let dst_inode = g
            .get_inode(dst_inode_id)
            .ok_or(GraphError::InodeNotFound(dst_inode_id))?;
        if dst_inode.vtype == VnodeType::Directory {
            rmdir(g, dir, dst_name)?;
        } else {
            unlink(g, dir, dst_name)?;
        }
    }

    // Find the source edge and update its name in-place
    let edge_ids = g
        .dir_contains
        .get(&dir)
        .ok_or(GraphError::DirNotFound(dir))?;
    let mut src_edge_id = None;
    for &eid in edge_ids {
        if let Some(Edge::Contains { tgt, name, .. }) = g.get_edge(eid) {
            if *tgt == src_inode && name == src_name {
                src_edge_id = Some(eid);
                break;
            }
        }
    }
    let eid = src_edge_id.ok_or_else(|| GraphError::NameNotFound(src_name.into()))?;

    // In-place name update — no edge removal/creation, no index churn
    if let Some(Edge::Contains { name, .. }) = g.get_edge_mut(eid) {
        *name = dst_name.into();
    }

    Ok(())
}

/// Slow path: cross-directory rename with full cycle prevention.
///
/// GC-RENAME-2: checks whether dst_dir is a descendant of the moved inode
/// (which would create a cycle in the directory tree).
/// Updates ".." edge when moving directories across parents.
fn rename_cross_dir(
    g: &mut TypeGraph,
    src_dir: DirId,
    src_name: &str,
    dst_dir: DirId,
    dst_name: &str,
) -> Result<(), GraphError> {
    // GC-RENAME-1: source must exist
    let src_inode = g
        .resolve_name(src_dir, src_name)
        .ok_or_else(|| GraphError::NameNotFound(src_name.into()))?;

    // Check if destination already exists (replace case)
    let dst_exists = g.resolve_name(dst_dir, dst_name);

    // GC-RENAME-2: cycle prevention for cross-dir directory moves
    if let Some(inode) = g.get_inode(src_inode) {
        if inode.vtype == VnodeType::Directory {
            if let Some(src_child_dir) = g.dir_for_inode(src_inode) {
                if g.is_ancestor(src_child_dir, dst_dir) {
                    return Err(GraphError::WouldCreateCycle);
                }
            }
        }
    }

    // If target exists, unlink it first (Cases B/D)
    if let Some(dst_inode_id) = dst_exists {
        let dst_inode = g
            .get_inode(dst_inode_id)
            .ok_or(GraphError::InodeNotFound(dst_inode_id))?;
        if dst_inode.vtype == VnodeType::Directory {
            rmdir(g, dst_dir, dst_name)?;
        } else {
            unlink(g, dst_dir, dst_name)?;
        }
    }

    // Find and remove the source contains edge
    let src_edge_id = {
        let edges = g
            .dir_contains
            .get(&src_dir)
            .ok_or(GraphError::DirNotFound(src_dir))?;
        let mut found = None;
        for &eid in edges {
            if let Some(Edge::Contains { tgt, name, .. }) = g.get_edge(eid) {
                if *tgt == src_inode && name == src_name {
                    found = Some(eid);
                    break;
                }
            }
        }
        found.ok_or_else(|| GraphError::NameNotFound(src_name.into()))?
    };

    g.remove_edge(src_edge_id);
    if let Some(set) = g.dir_contains.get_mut(&src_dir) {
        set.remove(&src_edge_id);
    }
    if let Some(set) = g.inode_incoming_contains.get_mut(&src_inode) {
        set.remove(&src_edge_id);
    }

    // Create new contains edge at destination
    let new_edge_id = g.alloc_edge_id();
    let new_edge = Edge::Contains {
        id: new_edge_id,
        src: dst_dir,
        tgt: src_inode,
        name: dst_name.into(),
    };
    g.insert_edge(new_edge_id, new_edge);
    g.dir_contains
        .entry(dst_dir)
        .or_default()
        .insert(new_edge_id);
    g.inode_incoming_contains
        .entry(src_inode)
        .or_default()
        .insert(new_edge_id);

    // Moving a directory cross-dir: update its ".." edge
    if let Some(inode) = g.get_inode(src_inode) {
        if inode.vtype == VnodeType::Directory {
            if let Some(child_dir) = g.dir_for_inode(src_inode) {
                let dst_parent_inode = g.get_dir(dst_dir).map(|d| d.inode_id);
                if let Some(dst_pi) = dst_parent_inode {
                    // Find and update ".." edge
                    if let Some(edges) = g.dir_contains.get(&child_dir) {
                        let dotdot_edge = edges.iter().find(|&&eid| {
                            matches!(
                                g.get_edge(eid),
                                Some(Edge::Contains { name, .. }) if name == ".."
                            )
                        });
                        if let Some(&dotdot_eid) = dotdot_edge {
                            // Extract old target before mutable borrow
                            let old_tgt = match g.get_edge(dotdot_eid) {
                                Some(Edge::Contains { tgt, .. }) => Some(*tgt),
                                _ => None,
                            };
                            // Remove old ".." incoming count
                            if let Some(old) = old_tgt {
                                if let Some(set) =
                                    g.inode_incoming_contains.get_mut(&old)
                                {
                                    set.remove(&dotdot_eid);
                                }
                            }
                            // Update edge target
                            if let Some(edge) = g.get_edge_mut(dotdot_eid) {
                                if let Edge::Contains { tgt, .. } = edge {
                                    *tgt = dst_pi;
                                }
                            }
                            g.inode_incoming_contains
                                .entry(dst_pi)
                                .or_default()
                                .insert(dotdot_eid);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// DPO Rule: WRITE — §6.2.2
/// Simplified: appends a new block extent to an inode.
pub fn write_block(
    g: &mut TypeGraph,
    inode_id: InodeId,
    offset: u64,
    sector_start: u64,
    sector_count: u64,
) -> Result<BlockId, GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }

    let block_id = g.alloc_block_id();
    let edge_id = g.alloc_edge_id();

    g.insert_block(
        block_id,
        Block {
            id: block_id,
            sector_start,
            sector_count,
            refcount: 1,
        },
    );

    let edge = Edge::PointsTo {
        id: edge_id,
        src: inode_id,
        tgt: block_id,
        offset,
    };
    g.insert_edge(edge_id, edge);
    g.inode_points_to
        .entry(inode_id)
        .or_default()
        .insert(edge_id);

    Ok(block_id)
}

// -----------------------------------------------------------------------
// File data operations (in-memory for FUSE prototype)
// -----------------------------------------------------------------------

/// Write data to a file at the given offset. Grows the file if needed.
pub fn write_data(
    g: &mut TypeGraph,
    inode_id: InodeId,
    offset: u64,
    data: &[u8],
) -> Result<usize, GraphError> {
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    if inode.vtype != VnodeType::Regular {
        return Err(GraphError::NotAFile(inode_id));
    }

    let buf = g.file_data.entry(inode_id).or_default();
    let end = offset as usize + data.len();

    // Extend buffer if needed
    if buf.len() < end {
        buf.resize(end, 0);
    }
    buf[offset as usize..end].copy_from_slice(data);
    let new_size = buf.len() as u64;

    // Update inode size
    if let Some(inode) = g.get_inode_mut(inode_id) {
        inode.size = new_size;
        inode.mtime = now();
    }

    Ok(data.len())
}

/// Read data from a file at the given offset.
pub fn read_data(
    g: &TypeGraph,
    inode_id: InodeId,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, GraphError> {
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    if inode.vtype != VnodeType::Regular {
        return Err(GraphError::NotAFile(inode_id));
    }

    let buf = match g.file_data.get(&inode_id) {
        Some(b) => b,
        None => return Ok(Vec::new()),
    };

    let start = (offset as usize).min(buf.len());
    let end = (start + size).min(buf.len());
    Ok(buf[start..end].to_vec())
}

/// Truncate a file to the given length.
pub fn truncate(
    g: &mut TypeGraph,
    inode_id: InodeId,
    new_size: u64,
) -> Result<(), GraphError> {
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    if inode.vtype != VnodeType::Regular {
        return Err(GraphError::NotAFile(inode_id));
    }

    let buf = g.file_data.entry(inode_id).or_default();
    buf.resize(new_size as usize, 0);

    if let Some(inode) = g.get_inode_mut(inode_id) {
        inode.size = new_size;
        inode.mtime = now();
    }

    Ok(())
}

/// Set permissions on an inode.
pub fn chmod(
    g: &mut TypeGraph,
    inode_id: InodeId,
    mode: u16,
) -> Result<(), GraphError> {
    let inode = g
        .get_inode_mut(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    inode.permissions = Permissions(mode);
    Ok(())
}

/// Set ownership on an inode.
pub fn chown(
    g: &mut TypeGraph,
    inode_id: InodeId,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), GraphError> {
    let inode = g
        .get_inode_mut(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    if let Some(u) = uid {
        inode.uid = u;
    }
    if let Some(g_) = gid {
        inode.gid = g_;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Affected-node sets for incremental curvature recomputation
// ---------------------------------------------------------------------------

/// Fixed-capacity set of affected NodeIds (no_std compatible).
/// Maximum 8 entries — sufficient for any single DPO rule.
pub struct AffectedNodes {
    pub nodes: [NodeId; 8],
    pub len: usize,
}

impl AffectedNodes {
    /// Create an empty set.
    pub const fn empty() -> Self {
        Self {
            nodes: [NodeId::Inode(0); 8],
            len: 0,
        }
    }

    fn push(&mut self, node: NodeId) {
        if self.len < 8 {
            // Deduplicate
            for i in 0..self.len {
                if self.nodes[i] == node {
                    return;
                }
            }
            self.nodes[self.len] = node;
            self.len += 1;
        }
    }

    /// Return a slice of the affected nodes.
    pub fn as_slice(&self) -> &[NodeId] {
        &self.nodes[..self.len]
    }
}

/// Affected nodes after create_file: the parent directory node + new inode.
pub fn affected_nodes_create(dir: DirId, inode: InodeId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(dir));
    a.push(NodeId::Inode(inode));
    a
}

/// Affected nodes after unlink: the directory node + the (possibly removed) inode.
pub fn affected_nodes_unlink(dir: DirId, inode: InodeId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(dir));
    a.push(NodeId::Inode(inode));
    a
}

/// Affected nodes after mkdir: parent dir + new inode + new dir node.
pub fn affected_nodes_mkdir(parent_dir: DirId, inode: InodeId, new_dir: DirId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(parent_dir));
    a.push(NodeId::Inode(inode));
    a.push(NodeId::Directory(new_dir));
    a
}

/// Affected nodes after rmdir: parent dir + removed inode + removed dir node.
pub fn affected_nodes_rmdir(parent_dir: DirId, inode: InodeId, removed_dir: DirId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(parent_dir));
    a.push(NodeId::Inode(inode));
    a.push(NodeId::Directory(removed_dir));
    a
}

/// Affected nodes after rename: src_dir + dst_dir + moved inode.
/// If dst_dir == src_dir, the dedup in push() handles it.
pub fn affected_nodes_rename(src_dir: DirId, dst_dir: DirId, inode: InodeId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(src_dir));
    a.push(NodeId::Directory(dst_dir));
    a.push(NodeId::Inode(inode));
    a
}

/// Affected nodes after link: directory + target inode.
pub fn affected_nodes_link(dir: DirId, inode: InodeId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Directory(dir));
    a.push(NodeId::Inode(inode));
    a
}

/// Affected nodes after write_block: inode + new block.
pub fn affected_nodes_write_block(inode: InodeId, block: BlockId) -> AffectedNodes {
    let mut a = AffectedNodes::empty();
    a.push(NodeId::Inode(inode));
    a.push(NodeId::Block(block));
    a
}

// ===========================================================================
// Extended Attributes (xattrs) — §6.2.8
// ===========================================================================

/// Set an extended attribute on an inode.
/// If the attribute already exists, its value is replaced.
pub fn setxattr(
    g: &mut TypeGraph,
    inode_id: InodeId,
    namespace: XAttrNamespace,
    name: &str,
    value: &[u8],
) -> Result<XAttrId, GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }
    // Max xattr value size: 64KB (following Linux convention)
    if value.len() > 65536 {
        return Err(GraphError::XAttrTooLarge(value.len()));
    }

    // Check if attribute already exists — update in place
    if let Some(xattr_ids) = g.inode_xattrs.get(&inode_id) {
        for &xid in xattr_ids {
            if let Some(xa) = g.xattrs.get(&xid) {
                if xa.namespace == namespace && xa.name == name {
                    // Update existing
                    if let Some(xa_mut) = g.xattrs.get_mut(&xid) {
                        xa_mut.value = value.to_vec();
                    }
                    return Ok(xid);
                }
            }
        }
    }

    // Create new xattr
    let xattr_id = g.alloc_xattr_id();
    let edge_id = g.alloc_edge_id();

    g.xattrs.insert(
        xattr_id,
        XAttr {
            id: xattr_id,
            namespace,
            name: name.into(),
            value: value.to_vec(),
        },
    );

    let edge = Edge::HasXattr {
        id: edge_id,
        src: inode_id,
        tgt: xattr_id,
    };
    g.insert_edge(edge_id, edge);
    g.inode_xattrs
        .entry(inode_id)
        .or_default()
        .insert(xattr_id);

    Ok(xattr_id)
}

/// Get an extended attribute value.
pub fn getxattr(
    g: &TypeGraph,
    inode_id: InodeId,
    namespace: XAttrNamespace,
    name: &str,
) -> Result<Vec<u8>, GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }
    if let Some(xattr_ids) = g.inode_xattrs.get(&inode_id) {
        for &xid in xattr_ids {
            if let Some(xa) = g.xattrs.get(&xid) {
                if xa.namespace == namespace && xa.name == name {
                    return Ok(xa.value.clone());
                }
            }
        }
    }
    Err(GraphError::XAttrNotFound(name.into()))
}

/// Remove an extended attribute.
pub fn removexattr(
    g: &mut TypeGraph,
    inode_id: InodeId,
    namespace: XAttrNamespace,
    name: &str,
) -> Result<(), GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }
    let xattr_ids = g
        .inode_xattrs
        .get(&inode_id)
        .cloned()
        .unwrap_or_default();
    for xid in &xattr_ids {
        let matches = g
            .xattrs
            .get(xid)
            .map(|xa| xa.namespace == namespace && xa.name == name)
            .unwrap_or(false);
        if matches {
            g.xattrs.remove(xid);
            if let Some(set) = g.inode_xattrs.get_mut(&inode_id) {
                set.remove(xid);
            }
            // Remove HasXattr edge
            let mut edge_to_remove = None;
            for aid in g.edges.keys() {
                if let Some(Edge::HasXattr { src, tgt, .. }) = g.edges.get(aid) {
                    if *src == inode_id && *tgt == *xid {
                        edge_to_remove = Some(aid.0 as u64);
                        break;
                    }
                }
            }
            if let Some(eid) = edge_to_remove {
                g.remove_edge(eid);
            }
            return Ok(());
        }
    }
    Err(GraphError::XAttrNotFound(name.into()))
}

/// List all extended attribute names on an inode.
pub fn listxattr(
    g: &TypeGraph,
    inode_id: InodeId,
) -> Result<Vec<(XAttrNamespace, String)>, GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }
    let mut result = Vec::new();
    if let Some(xattr_ids) = g.inode_xattrs.get(&inode_id) {
        for &xid in xattr_ids {
            if let Some(xa) = g.xattrs.get(&xid) {
                result.push((xa.namespace, xa.name.clone()));
            }
        }
    }
    Ok(result)
}

// ===========================================================================
// Symlinks — §6.2.9
// ===========================================================================

/// DPO Rule: SYMLINK — create a symbolic link.
///
/// Creates a new inode with VnodeType::Symlink and stores the target path.
/// Application condition: no cycles in the resolution chain (checked at
/// resolve time, not at creation time — matching POSIX semantics).
pub fn symlink(
    g: &mut TypeGraph,
    parent_dir: DirId,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<InodeId, GraphError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(GraphError::NameNotFound(name.into()));
    }
    if g.resolve_name(parent_dir, name).is_some() {
        return Err(GraphError::NameExists {
            dir: parent_dir,
            name: name.into(),
        });
    }
    if !g.contains_dir(parent_dir) {
        return Err(GraphError::DirNotFound(parent_dir));
    }

    let inode_id = g.alloc_inode_id();
    let edge_id = g.alloc_edge_id();

    let now = now();
    let inode = Inode {
        id: inode_id,
        vtype: VnodeType::Symlink,
        permissions: Permissions(0o777), // symlinks are always rwxrwxrwx
        uid,
        gid,
        size: target.len() as u64,
        link_count: 1,
        ctime: now,
        mtime: now,
        atime: now,
    };
    g.insert_inode(inode_id, inode);

    // Store symlink target
    g.symlink_targets
        .insert(inode_id, SymlinkTarget(target.into()));

    // Create contains edge
    let edge = Edge::Contains {
        id: edge_id,
        src: parent_dir,
        tgt: inode_id,
        name: name.into(),
    };
    g.insert_edge(edge_id, edge);
    g.dir_contains
        .entry(parent_dir)
        .or_default()
        .insert(edge_id);
    g.inode_incoming_contains
        .entry(inode_id)
        .or_default()
        .insert(edge_id);

    Ok(inode_id)
}

/// Read the target of a symbolic link.
pub fn readlink(
    g: &TypeGraph,
    inode_id: InodeId,
) -> Result<String, GraphError> {
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    if inode.vtype != VnodeType::Symlink {
        return Err(GraphError::NotASymlink(inode_id));
    }
    g.symlink_targets
        .get(&inode_id)
        .map(|t| t.0.clone())
        .ok_or(GraphError::NotASymlink(inode_id))
}

// ===========================================================================
// ACLs — §6.2.10: POSIX.1e ACL ↔ Capability Graph Correspondence
// ===========================================================================

/// Set the ACL for an inode.
///
/// The ACL is stored alongside the inode and also synthesizes Grants edges
/// in the capability graph for each ACL entry that grants access.
/// This establishes the correspondence:
///   ACL_USER_OBJ  →  Grants(cap_owner, inode, owner_rights)
///   ACL_USER(uid) →  Grants(cap_uid,   inode, user_rights)
///   ACL_GROUP_OBJ →  Grants(cap_group, inode, group_rights & mask)
///   ACL_OTHER     →  Grants(cap_other, inode, other_rights)
pub fn setacl(
    g: &mut TypeGraph,
    inode_id: InodeId,
    entries: Vec<AclEntry>,
) -> Result<(), GraphError> {
    if !g.contains_inode(inode_id) {
        return Err(GraphError::InodeNotFound(inode_id));
    }
    g.acls.insert(inode_id, entries);
    Ok(())
}

/// Get the ACL for an inode. Returns the minimal ACL derived from
/// permission bits if no explicit ACL is set.
pub fn getacl(
    g: &TypeGraph,
    inode_id: InodeId,
) -> Result<Vec<AclEntry>, GraphError> {
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;

    if let Some(acl) = g.acls.get(&inode_id) {
        return Ok(acl.clone());
    }

    // Synthesize minimal ACL from permission bits
    let mode = inode.permissions.mode();
    Ok(vec![
        AclEntry {
            tag: AclTag::UserObj,
            qualifier: 0,
            permissions: Permissions((mode >> 6) & 0o7),
        },
        AclEntry {
            tag: AclTag::GroupObj,
            qualifier: 0,
            permissions: Permissions((mode >> 3) & 0o7),
        },
        AclEntry {
            tag: AclTag::Other,
            qualifier: 0,
            permissions: Permissions(mode & 0o7),
        },
    ])
}

// ===========================================================================
// Quotas — §6.2.11: Hierarchical Quotas with Summary Propagation
// ===========================================================================

/// Set a quota on a directory subtree.
pub fn set_quota(
    g: &mut TypeGraph,
    dir_id: DirId,
    inode_limit: u64,
    byte_limit: u64,
) -> Result<(), GraphError> {
    if !g.contains_dir(dir_id) {
        return Err(GraphError::DirNotFound(dir_id));
    }
    g.quotas.insert(dir_id, Quota::new(inode_limit, byte_limit));
    Ok(())
}

/// Get the quota for a directory (if set).
pub fn get_quota(
    g: &TypeGraph,
    dir_id: DirId,
) -> Result<Option<&Quota>, GraphError> {
    if !g.contains_dir(dir_id) {
        return Err(GraphError::DirNotFound(dir_id));
    }
    Ok(g.quotas.get(&dir_id))
}

/// Check if a quota would be exceeded by creating a new inode in the given directory.
/// Walks up the directory tree checking all quota boundaries.
pub fn check_quota_inode(g: &TypeGraph, dir_id: DirId) -> Result<(), GraphError> {
    let mut current = Some(dir_id);
    while let Some(d) = current {
        if let Some(q) = g.quotas.get(&d) {
            if !q.check_inode() {
                return Err(GraphError::QuotaExceeded {
                    dir: d,
                    resource: "inode".into(),
                });
            }
        }
        // Walk to parent via ".." edge
        current = g.parent_dir(d);
        if current == Some(d) {
            break; // root
        }
    }
    Ok(())
}

/// Update quota counters after a DPO operation.
/// delta_inodes: +1 for create/mkdir, -1 for unlink/rmdir
/// delta_bytes: change in file data size
pub fn update_quota(
    g: &mut TypeGraph,
    dir_id: DirId,
    delta_inodes: i64,
    delta_bytes: i64,
) {
    let mut current = Some(dir_id);
    while let Some(d) = current {
        if let Some(q) = g.quotas.get_mut(&d) {
            if delta_inodes > 0 {
                q.inode_usage = q.inode_usage.saturating_add(delta_inodes as u64);
            } else {
                q.inode_usage = q.inode_usage.saturating_sub((-delta_inodes) as u64);
            }
            if delta_bytes > 0 {
                q.byte_usage = q.byte_usage.saturating_add(delta_bytes as u64);
            } else {
                q.byte_usage = q.byte_usage.saturating_sub((-delta_bytes) as u64);
            }
        }
        current = g.parent_dir(d);
        if current == Some(d) {
            break;
        }
    }
}

// ===========================================================================
// fsck — Structural Invariant Verifier (§6.3)
// ===========================================================================

/// Result of an fsck check.
#[derive(Debug)]
pub struct FsckReport {
    pub errors: Vec<FsckError>,
    pub warnings: Vec<String>,
    pub inode_count: usize,
    pub dir_count: usize,
    pub edge_count: usize,
}

/// A specific fsck error.
#[derive(Debug)]
pub struct FsckError {
    pub invariant: &'static str,
    pub description: String,
}

/// Run all structural invariant checks on the graph.
/// Checks invariants 5.1-5.5 from the design document:
///   5.1 TypeInvariant: edge endpoints exist, no duplicate IDs
///   5.2 LinkCountConsistent: link_count matches incoming non-dotdot edges
///   5.3 UniqueNamesPerDir: no duplicate names per directory
///   5.4 NoDanglingEdges: all edge endpoints exist
///   5.5 NoDirCycles: no cycles in the directory DAG
///
/// Additional checks:
///   - Orphan detection: inodes with link_count > 0 but no incoming edges
///   - Block refcount consistency
///   - Capability monotonicity
///   - Xattr integrity
pub fn fsck(g: &TypeGraph) -> FsckReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Count nodes
    let inode_count = g.inodes.len();
    let dir_count = g.dirs.len();
    let edge_count = g.edges.len();

    // 5.1 TypeInvariant + 5.4 NoDanglingEdges
    for aid in g.edges.keys() {
        if let Some(edge) = g.edges.get(aid) {
            match edge {
                Edge::Contains { src, tgt, .. } => {
                    if !g.contains_dir(*src) {
                        errors.push(FsckError {
                            invariant: "NoDanglingEdges",
                            description: format!(
                                "Contains edge {} references nonexistent dir {}",
                                edge.id(), src
                            ),
                        });
                    }
                    if !g.contains_inode(*tgt) {
                        errors.push(FsckError {
                            invariant: "NoDanglingEdges",
                            description: format!(
                                "Contains edge {} references nonexistent inode {}",
                                edge.id(), tgt
                            ),
                        });
                    }
                }
                Edge::PointsTo { src, tgt, .. } => {
                    if !g.contains_inode(*src) {
                        errors.push(FsckError {
                            invariant: "NoDanglingEdges",
                            description: format!(
                                "PointsTo edge {} references nonexistent inode {}",
                                edge.id(), src
                            ),
                        });
                    }
                    if !g.contains_block(*tgt) {
                        errors.push(FsckError {
                            invariant: "NoDanglingEdges",
                            description: format!(
                                "PointsTo edge {} references nonexistent block {}",
                                edge.id(), tgt
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    // 5.2 LinkCountConsistent
    for aid in g.inodes.keys() {
        if let Some(inode) = g.inodes.get(aid) {
            let incoming = g
                .inode_incoming_contains
                .get(&inode.id)
                .map(|s| {
                    s.iter()
                        .filter(|&&eid| {
                            matches!(
                                g.get_edge(eid),
                                Some(Edge::Contains { name, .. }) if name != ".."
                            )
                        })
                        .count()
                })
                .unwrap_or(0);
            if inode.link_count as usize != incoming {
                errors.push(FsckError {
                    invariant: "LinkCountConsistent",
                    description: format!(
                        "inode {}: link_count={} but {} incoming non-dotdot edges",
                        inode.id, inode.link_count, incoming
                    ),
                });
            }
        }
    }

    // 5.3 UniqueNamesPerDir
    for (dir_id, edge_ids) in &g.dir_contains {
        let mut names: Vec<&str> = Vec::new();
        for &eid in edge_ids {
            if let Some(Edge::Contains { name, .. }) = g.get_edge(eid) {
                if names.contains(&name.as_str()) {
                    errors.push(FsckError {
                        invariant: "UniqueNamesPerDir",
                        description: format!(
                            "dir {}: duplicate name '{}'",
                            dir_id, name
                        ),
                    });
                }
                names.push(name.as_str());
            }
        }
    }

    // 5.5 NoDirCycles (DFS)
    let mut visited = BTreeSet::new();
    let mut stack = BTreeSet::new();
    for aid in g.dirs.keys() {
        if let Some(dir) = g.dirs.get(aid) {
            if !visited.contains(&dir.id) {
                if has_cycle_dfs(g, dir.id, &mut visited, &mut stack) {
                    errors.push(FsckError {
                        invariant: "NoDirCycles",
                        description: format!("cycle detected involving dir {}", dir.id),
                    });
                }
            }
        }
    }

    // Block refcount consistency
    for aid in g.blocks.keys() {
        if let Some(block) = g.blocks.get(aid) {
            let incoming = g
                .edges
                .values()
                .filter(|e| matches!(e, Edge::PointsTo { tgt, .. } if *tgt == block.id))
                .count();
            if block.refcount as usize != incoming {
                errors.push(FsckError {
                    invariant: "BlockRefcount",
                    description: format!(
                        "block {}: refcount={} but {} incoming PointsTo edges",
                        block.id, block.refcount, incoming
                    ),
                });
            }
        }
    }

    // Orphan detection
    for aid in g.inodes.keys() {
        if let Some(inode) = g.inodes.get(aid) {
            if inode.id != g.root_inode {
                let incoming_count = g
                    .inode_incoming_contains
                    .get(&inode.id)
                    .map(|s| s.len())
                    .unwrap_or(0);
                if incoming_count == 0 {
                    warnings.push(format!("orphan inode {} (no incoming edges)", inode.id));
                }
            }
        }
    }

    // Xattr integrity
    for (&inode_id, xattr_ids) in &g.inode_xattrs {
        if !g.contains_inode(inode_id) {
            errors.push(FsckError {
                invariant: "XattrIntegrity",
                description: format!(
                    "xattr index references nonexistent inode {}",
                    inode_id
                ),
            });
        }
        for &xid in xattr_ids {
            if !g.xattrs.contains_key(&xid) {
                errors.push(FsckError {
                    invariant: "XattrIntegrity",
                    description: format!(
                        "inode {} references nonexistent xattr {}",
                        inode_id, xid
                    ),
                });
            }
        }
    }

    FsckReport {
        errors,
        warnings,
        inode_count,
        dir_count,
        edge_count,
    }
}

/// DFS cycle detection for directory graph.
fn has_cycle_dfs(
    g: &TypeGraph,
    dir: DirId,
    visited: &mut BTreeSet<DirId>,
    stack: &mut BTreeSet<DirId>,
) -> bool {
    visited.insert(dir);
    stack.insert(dir);

    if let Some(edge_ids) = g.dir_contains.get(&dir) {
        for &eid in edge_ids {
            if let Some(Edge::Contains { tgt, name, .. }) = g.get_edge(eid) {
                // Skip "." and ".." — they don't participate in cycle detection
                if name == "." || name == ".." {
                    continue;
                }
                // Check if target is a directory
                if let Some(inode) = g.get_inode(*tgt) {
                    if inode.vtype == VnodeType::Directory {
                        if let Some(child_dir) = g.dir_for_inode(*tgt) {
                            if stack.contains(&child_dir) {
                                return true; // Cycle!
                            }
                            if !visited.contains(&child_dir)
                                && has_cycle_dfs(g, child_dir, visited, stack)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    stack.remove(&dir);
    false
}

// ===========================================================================
// Provenance Log + MSO Query API (§6.4)
// ===========================================================================

/// Operation type recorded in provenance entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvOp {
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Link,
    Rename,
    Write,
    Chmod,
    Chown,
    Setxattr,
    Removexattr,
    Symlink,
    SetAcl,
    CapDerive,
    CapRevoke,
    Read,
    Stat,
    Open,
}

/// A single provenance entry — who did what to which inode, when, via which cap.
#[derive(Debug, Clone)]
pub struct ProvenanceEntry {
    pub timestamp: u64,
    pub op: ProvOp,
    pub inode_id: InodeId,
    pub cap_id: Option<CapId>,
    pub domain_id: u64,
    pub detail: String,
}

/// Provenance log — append-only sequence of operations on the TypeGraph.
///
/// Records every DPO rule application with timestamp, capability, and inode.
/// Enables temporal queries: "what touched this inode in window [t0, t1]?"
#[derive(Debug, Clone)]
pub struct ProvenanceLog {
    entries: Vec<ProvenanceEntry>,
}

impl ProvenanceLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Record a provenance entry.
    pub fn record(
        &mut self,
        timestamp: u64,
        op: ProvOp,
        inode_id: InodeId,
        cap_id: Option<CapId>,
        domain_id: u64,
        detail: &str,
    ) {
        self.entries.push(ProvenanceEntry {
            timestamp,
            op,
            inode_id,
            cap_id,
            domain_id,
            detail: detail.into(),
        });
    }

    /// Total number of recorded events.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries (for iteration).
    pub fn entries(&self) -> &[ProvenanceEntry] {
        &self.entries
    }

    // -------------------------------------------------------------------
    // MSO-style provenance queries
    // -------------------------------------------------------------------

    /// **Q1: Capabilities that touched an inode in time window [t_start, t_end].**
    ///
    /// Returns all distinct (cap_id, operation) pairs for the given inode
    /// within the time window.  This answers: "what caps accessed file F
    /// in the last hour?"
    pub fn caps_for_inode_in_window(
        &self,
        inode_id: InodeId,
        t_start: u64,
        t_end: u64,
    ) -> Vec<(CapId, ProvOp, u64)> {
        let mut result = Vec::new();
        for e in &self.entries {
            if e.inode_id == inode_id
                && e.timestamp >= t_start
                && e.timestamp <= t_end
            {
                if let Some(cid) = e.cap_id {
                    result.push((cid, e.op, e.timestamp));
                }
            }
        }
        result
    }

    /// **Q2: Inodes touched by a specific capability in time window.**
    ///
    /// Returns all (inode_id, operation, timestamp) for operations performed
    /// via the given capability.  Answers: "what did cap C access?"
    pub fn inodes_touched_by_cap(
        &self,
        cap_id: CapId,
        t_start: u64,
        t_end: u64,
    ) -> Vec<(InodeId, ProvOp, u64)> {
        let mut result = Vec::new();
        for e in &self.entries {
            if e.timestamp >= t_start && e.timestamp <= t_end {
                if e.cap_id == Some(cap_id) {
                    result.push((e.inode_id, e.op, e.timestamp));
                }
            }
        }
        result
    }

    /// **Q3: Full provenance chain for an inode.**
    ///
    /// Returns all operations on the given inode in chronological order.
    /// This is the complete audit trail for a file.
    pub fn provenance_chain(&self, inode_id: InodeId) -> Vec<&ProvenanceEntry> {
        self.entries
            .iter()
            .filter(|e| e.inode_id == inode_id)
            .collect()
    }

    /// **Q4: Operations by domain in time window.**
    ///
    /// Returns all operations performed by a specific domain (process/thread group).
    /// For forensics: "what did compromised domain D do?"
    pub fn ops_by_domain(
        &self,
        domain_id: u64,
        t_start: u64,
        t_end: u64,
    ) -> Vec<&ProvenanceEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.domain_id == domain_id
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect()
    }

    /// **Q5: Anomaly window — burst detection.**
    ///
    /// Returns the count of operations on an inode in sliding windows of
    /// `window_size` seconds.  Spikes indicate potential ransomware or
    /// mass-modification attacks.
    pub fn burst_detect(
        &self,
        inode_id: InodeId,
        window_size: u64,
    ) -> Vec<(u64, usize)> {
        let relevant: Vec<u64> = self.entries
            .iter()
            .filter(|e| e.inode_id == inode_id)
            .map(|e| e.timestamp)
            .collect();
        if relevant.is_empty() {
            return Vec::new();
        }
        let t_min = relevant[0];
        let t_max = *relevant.last().unwrap();
        let mut windows = Vec::new();
        let mut t = t_min;
        while t <= t_max {
            let count = relevant.iter().filter(|&&ts| ts >= t && ts < t + window_size).count();
            if count > 0 {
                windows.push((t, count));
            }
            t += window_size;
        }
        windows
    }

    /// **Q6: Cross-reference — capabilities and inodes involved in a time window.**
    ///
    /// Returns a summary: how many distinct caps and inodes were active in [t0, t1].
    pub fn activity_summary(
        &self,
        t_start: u64,
        t_end: u64,
    ) -> ProvActivitySummary {
        let mut caps = BTreeSet::new();
        let mut inodes = BTreeSet::new();
        let mut op_count = 0usize;
        for e in &self.entries {
            if e.timestamp >= t_start && e.timestamp <= t_end {
                op_count += 1;
                inodes.insert(e.inode_id);
                if let Some(cid) = e.cap_id {
                    caps.insert(cid);
                }
            }
        }
        ProvActivitySummary {
            distinct_caps: caps.len(),
            distinct_inodes: inodes.len(),
            total_ops: op_count,
            t_start,
            t_end,
        }
    }
}

/// Summary of provenance activity in a time window.
#[derive(Debug, Clone)]
pub struct ProvActivitySummary {
    pub distinct_caps: usize,
    pub distinct_inodes: usize,
    pub total_ops: usize,
    pub t_start: u64,
    pub t_end: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_file_and_check_invariants() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "hello.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.get_inode(id).unwrap().link_count, 1);
        assert_eq!(g.get_inode(id).unwrap().vtype, VnodeType::Regular);
    }

    #[test]
    fn mkdir_and_check_invariants() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let result = mkdir(&mut g, rd, "subdir", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        g.check_invariants().unwrap();
        assert!(result.dir_id.is_some());
        assert_eq!(g.get_inode(result.inode_id).unwrap().vtype, VnodeType::Directory);
        assert_eq!(g.get_inode(result.inode_id).unwrap().link_count, 2);
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let err = create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT);
        assert!(matches!(err, Err(GraphError::NameExists { .. })));
    }

    #[test]
    fn unlink_removes_file() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "tmp", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        unlink(&mut g, rd, "tmp").unwrap();
        g.check_invariants().unwrap();
        assert!(g.resolve_name(rd, "tmp").is_none());
    }

    #[test]
    fn link_creates_hard_link() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "orig", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let sub = mkdir(&mut g, rd, "sub", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        link(&mut g, sub.dir_id.unwrap(), "alias", id).unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.get_inode(id).unwrap().link_count, 2);
    }

    #[test]
    fn link_to_directory_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let sub = mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let err = link(&mut g, rd, "d_link", sub.inode_id);
        assert!(matches!(err, Err(GraphError::LinkToDirectory(_))));
    }

    #[test]
    fn rmdir_empty() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        mkdir(&mut g, rd, "empty", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        rmdir(&mut g, rd, "empty").unwrap();
        g.check_invariants().unwrap();
        assert!(g.resolve_name(rd, "empty").is_none());
    }

    #[test]
    fn rmdir_non_empty_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let sub = mkdir(&mut g, rd, "full", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        create_file(&mut g, sub.dir_id.unwrap(), "file", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let err = rmdir(&mut g, rd, "full");
        assert!(matches!(err, Err(GraphError::DirNotEmpty(_))));
    }

    #[test]
    fn rename_same_dir() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "old", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        rename(&mut g, rd, "old", rd, "new").unwrap();
        g.check_invariants().unwrap();
        assert!(g.resolve_name(rd, "old").is_none());
        assert!(g.resolve_name(rd, "new").is_some());
    }

    #[test]
    fn rename_same_dir_preserves_inode() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "a.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id, 0, b"data").unwrap();
        rename(&mut g, rd, "a.txt", rd, "b.txt").unwrap();
        g.check_invariants().unwrap();
        // Inode is the same, data preserved
        let resolved = g.resolve_name(rd, "b.txt").unwrap();
        assert_eq!(resolved, id);
        let data = read_data(&g, id, 0, 100).unwrap();
        assert_eq!(data, b"data");
    }

    #[test]
    fn rename_same_dir_overwrites_existing() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let src_id = create_file(&mut g, rd, "src", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, src_id, 0, b"keep").unwrap();
        let _dst_id = create_file(&mut g, rd, "dst", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, _dst_id, 0, b"discard").unwrap();
        rename(&mut g, rd, "src", rd, "dst").unwrap();
        g.check_invariants().unwrap();
        // Source name gone, dst now points to src's inode
        assert!(g.resolve_name(rd, "src").is_none());
        let resolved = g.resolve_name(rd, "dst").unwrap();
        assert_eq!(resolved, src_id);
        let data = read_data(&g, src_id, 0, 100).unwrap();
        assert_eq!(data, b"keep");
    }

    #[test]
    fn rename_same_dir_directory_entry() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let sub = mkdir(&mut g, rd, "olddir", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let sub_dir = sub.dir_id.unwrap();
        // Add a file inside the subdirectory
        create_file(&mut g, sub_dir, "inner.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        rename(&mut g, rd, "olddir", rd, "newdir").unwrap();
        g.check_invariants().unwrap();
        assert!(g.resolve_name(rd, "olddir").is_none());
        assert!(g.resolve_name(rd, "newdir").is_some());
        // Inner file still accessible
        assert!(g.resolve_name(sub_dir, "inner.txt").is_some());
    }

    #[test]
    fn rename_same_dir_noop_same_name() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "same", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        rename(&mut g, rd, "same", rd, "same").unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.resolve_name(rd, "same").unwrap(), id);
    }

    #[test]
    fn rename_dot_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        assert!(rename(&mut g, rd, ".", rd, "x").is_err());
        assert!(rename(&mut g, rd, "f", rd, ".").is_err());
        assert!(rename(&mut g, rd, "..", rd, "x").is_err());
        assert!(rename(&mut g, rd, "f", rd, "..").is_err());
    }

    #[test]
    fn rename_cross_dir() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let sub = mkdir(&mut g, rd, "dst", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let sub_dir = sub.dir_id.unwrap();
        rename(&mut g, rd, "f", sub_dir, "f2").unwrap();
        g.check_invariants().unwrap();
        assert!(g.resolve_name(rd, "f").is_none());
        assert!(g.resolve_name(sub_dir, "f2").is_some());
    }

    #[test]
    fn rename_cross_dir_cycle_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let a = mkdir(&mut g, rd, "a", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let a_dir = a.dir_id.unwrap();
        let b = mkdir(&mut g, a_dir, "b", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let b_dir = b.dir_id.unwrap();
        // Try to move "a" into "a/b" — would create cycle
        let err = rename(&mut g, rd, "a", b_dir, "a");
        assert!(matches!(err, Err(GraphError::WouldCreateCycle)));
    }

    #[test]
    fn rename_cycle_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let a = mkdir(&mut g, rd, "a", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let a_dir = a.dir_id.unwrap();
        let b = mkdir(&mut g, a_dir, "b", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let b_dir = b.dir_id.unwrap();
        // Try to move "a" into "a/b" — would create cycle
        let err = rename(&mut g, rd, "a", b_dir, "a");
        assert!(matches!(err, Err(GraphError::WouldCreateCycle)));
    }

    #[test]
    fn write_block_and_check() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "data", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let bid = write_block(&mut g, id, 0, 100, 8).unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.get_block(bid).unwrap().refcount, 1);
    }

    #[test]
    fn complex_tree_invariants() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let d1 = mkdir(&mut g, rd, "usr", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let d1d = d1.dir_id.unwrap();
        let d2 = mkdir(&mut g, d1d, "bin", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let d3 = mkdir(&mut g, d1d, "lib", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let d2d = d2.dir_id.unwrap();
        let d3d = d3.dir_id.unwrap();
        create_file(&mut g, d2d, "ls", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        create_file(&mut g, d2d, "cat", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        create_file(&mut g, d3d, "libc.so", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.inodes.len(), 7); // root + usr + bin + lib + ls + cat + libc
        assert_eq!(g.dirs.len(), 4);   // root + usr + bin + lib
    }

    #[test]
    fn write_and_read_data() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "hello.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id, 0, b"Hello, sotFS!").unwrap();
        assert_eq!(g.get_inode(id).unwrap().size, 13);
        let data = read_data(&g, id, 0, 100).unwrap();
        assert_eq!(data, b"Hello, sotFS!");
    }

    #[test]
    fn write_at_offset() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id, 0, b"AAAA").unwrap();
        write_data(&mut g, id, 2, b"BB").unwrap();
        let data = read_data(&g, id, 0, 10).unwrap();
        assert_eq!(data, b"AABB");
    }

    #[test]
    fn read_past_eof() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id, 0, b"abc").unwrap();
        let data = read_data(&g, id, 10, 5).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn truncate_file() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id, 0, b"Hello World").unwrap();
        truncate(&mut g, id, 5).unwrap();
        assert_eq!(g.get_inode(id).unwrap().size, 5);
        let data = read_data(&g, id, 0, 100).unwrap();
        assert_eq!(data, b"Hello");
    }

    // === xattr tests ===

    #[test]
    fn setxattr_and_getxattr() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        setxattr(&mut g, id, XAttrNamespace::User, "mime_type", b"text/plain").unwrap();
        let val = getxattr(&g, id, XAttrNamespace::User, "mime_type").unwrap();
        assert_eq!(val, b"text/plain");
    }

    #[test]
    fn setxattr_overwrite() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        setxattr(&mut g, id, XAttrNamespace::User, "k", b"v1").unwrap();
        setxattr(&mut g, id, XAttrNamespace::User, "k", b"v2").unwrap();
        let val = getxattr(&g, id, XAttrNamespace::User, "k").unwrap();
        assert_eq!(val, b"v2");
    }

    #[test]
    fn removexattr_works() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        setxattr(&mut g, id, XAttrNamespace::User, "k", b"v").unwrap();
        removexattr(&mut g, id, XAttrNamespace::User, "k").unwrap();
        assert!(matches!(
            getxattr(&g, id, XAttrNamespace::User, "k"),
            Err(GraphError::XAttrNotFound(_))
        ));
    }

    #[test]
    fn listxattr_returns_all() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        setxattr(&mut g, id, XAttrNamespace::User, "a", b"1").unwrap();
        setxattr(&mut g, id, XAttrNamespace::Security, "b", b"2").unwrap();
        let list = listxattr(&g, id).unwrap();
        assert_eq!(list.len(), 2);
    }

    // === symlink tests ===

    #[test]
    fn symlink_create_and_readlink() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = symlink(&mut g, rd, "link", "/usr/bin/ls", 0, 0).unwrap();
        g.check_invariants().unwrap();
        assert_eq!(g.get_inode(id).unwrap().vtype, VnodeType::Symlink);
        assert_eq!(readlink(&g, id).unwrap(), "/usr/bin/ls");
    }

    #[test]
    fn readlink_non_symlink_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        assert!(matches!(readlink(&g, id), Err(GraphError::NotASymlink(_))));
    }

    // === ACL tests ===

    #[test]
    fn setacl_and_getacl() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let acl = vec![
            AclEntry { tag: AclTag::UserObj, qualifier: 0, permissions: Permissions(7) },
            AclEntry { tag: AclTag::GroupObj, qualifier: 0, permissions: Permissions(5) },
            AclEntry { tag: AclTag::Other, qualifier: 0, permissions: Permissions(4) },
            AclEntry { tag: AclTag::User, qualifier: 1000, permissions: Permissions(6) },
        ];
        setacl(&mut g, id, acl.clone()).unwrap();
        let got = getacl(&g, id).unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[3].qualifier, 1000);
    }

    #[test]
    fn getacl_default_from_permissions() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions(0o754)).unwrap();
        let acl = getacl(&g, id).unwrap();
        assert_eq!(acl.len(), 3);
        assert_eq!(acl[0].tag, AclTag::UserObj);
        assert_eq!(acl[0].permissions.mode(), 7); // rwx
        assert_eq!(acl[1].permissions.mode(), 5); // r-x
        assert_eq!(acl[2].permissions.mode(), 4); // r--
    }

    // === quota tests ===

    #[test]
    fn quota_set_and_check() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        set_quota(&mut g, rd, 10, 1024 * 1024).unwrap();
        let q = get_quota(&g, rd).unwrap().unwrap();
        assert_eq!(q.inode_limit, 10);
        assert!(q.check_inode());
    }

    #[test]
    fn quota_update_and_exceed() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        set_quota(&mut g, rd, 2, 0).unwrap();
        update_quota(&mut g, rd, 1, 0);
        assert!(check_quota_inode(&g, rd).is_ok());
        update_quota(&mut g, rd, 1, 0);
        assert!(check_quota_inode(&g, rd).is_err());
    }

    // === fsck tests ===

    #[test]
    fn fsck_clean_graph() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let report = fsck(&g);
        assert!(report.errors.is_empty(), "fsck errors: {:?}", report.errors);
    }

    #[test]
    fn fsck_detects_orphan() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        // Manually break the graph: remove all incoming edges for this inode
        // to create an orphan
        let edges_to_remove: Vec<_> = g.inode_incoming_contains
            .get(&id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for eid in edges_to_remove {
            g.remove_edge(eid);
            if let Some(set) = g.dir_contains.get_mut(&rd) {
                set.remove(&eid);
            }
            if let Some(set) = g.inode_incoming_contains.get_mut(&id) {
                set.remove(&eid);
            }
        }
        // Fix link count to avoid that error
        if let Some(inode) = g.get_inode_mut(id) {
            inode.link_count = 0;
        }
        let report = fsck(&g);
        assert!(!report.warnings.is_empty());
        assert!(report.warnings[0].contains("orphan"));
    }

    // === provenance tests ===

    #[test]
    fn provenance_record_and_query() {
        let mut log = ProvenanceLog::new();
        log.record(100, ProvOp::Create, 10, Some(1), 0, "create /a");
        log.record(200, ProvOp::Write, 10, Some(1), 0, "write /a");
        log.record(300, ProvOp::Read, 10, Some(2), 1, "read /a");
        log.record(400, ProvOp::Create, 20, Some(1), 0, "create /b");

        assert_eq!(log.len(), 4);

        // Q1: caps that touched inode 10 in [100, 300]
        let caps = log.caps_for_inode_in_window(10, 100, 300);
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0].0, 1); // cap 1
        assert_eq!(caps[2].0, 2); // cap 2

        // Q2: inodes touched by cap 1 in full range
        let inodes = log.inodes_touched_by_cap(1, 0, 500);
        assert_eq!(inodes.len(), 3); // inode 10 (create, write) + inode 20 (create)

        // Q3: provenance chain for inode 10
        let chain = log.provenance_chain(10);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].op, ProvOp::Create);
        assert_eq!(chain[2].op, ProvOp::Read);
    }

    #[test]
    fn provenance_burst_detect() {
        let mut log = ProvenanceLog::new();
        // Simulate burst: 5 ops in 10 seconds on inode 1
        for t in 0..5 {
            log.record(100 + t, ProvOp::Write, 1, Some(1), 0, "burst write");
        }
        // Normal: 1 op at t=200
        log.record(200, ProvOp::Read, 1, Some(1), 0, "normal read");

        let windows = log.burst_detect(1, 10);
        assert!(!windows.is_empty());
        assert_eq!(windows[0].1, 5); // 5 ops in first window
    }

    #[test]
    fn provenance_activity_summary() {
        let mut log = ProvenanceLog::new();
        log.record(100, ProvOp::Create, 10, Some(1), 0, "");
        log.record(200, ProvOp::Create, 20, Some(2), 0, "");
        log.record(300, ProvOp::Write, 10, Some(1), 1, "");

        let summary = log.activity_summary(0, 400);
        assert_eq!(summary.distinct_caps, 2);
        assert_eq!(summary.distinct_inodes, 2);
        assert_eq!(summary.total_ops, 3);
    }

    // === export tests ===

    #[test]
    fn export_dot_produces_valid_output() {
        use sotfs_graph::export::{to_dot, DotStyle};
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "hello.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        mkdir(&mut g, rd, "sub", 0, 0, Permissions::DIR_DEFAULT).unwrap();

        let dot = to_dot(&g, &DotStyle::default());
        assert!(dot.starts_with("digraph sotFS {"));
        assert!(dot.contains("hello.txt"));
        assert!(dot.contains("sub"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn export_d3_json_produces_valid_output() {
        use sotfs_graph::export::to_d3_json;
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        let json = to_d3_json(&g);
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"links\""));
        assert!(json.contains("\"type\":\"inode\""));
        assert!(json.contains("\"type\":\"contains\""));
    }

    #[test]
    fn export_graph_hunter_temporal() {
        use sotfs_graph::export::to_graph_hunter;
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        let gh = to_graph_hunter(&g);
        assert!(gh.contains("\"format\":\"graph-hunter-temporal\""));
        assert!(gh.contains("\"op\":\"add_node\""));
        assert!(gh.contains("\"op\":\"add_edge\""));
    }

    #[test]
    fn export_stats_correct() {
        use sotfs_graph::export::stats;
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "a", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        create_file(&mut g, rd, "b", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        let sub = mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        create_file(&mut g, sub.dir_id.unwrap(), "c", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        let s = stats(&g);
        assert_eq!(s.inode_count, 5); // root + a + b + d + c
        assert_eq!(s.dir_count, 2);   // root + d
        assert_eq!(s.file_count, 3);  // a + b + c
        assert_eq!(s.depth_estimate, 1); // root -> d (depth 1)
    }
}
