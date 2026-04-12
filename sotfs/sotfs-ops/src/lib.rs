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
use alloc::vec::Vec;

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
}
