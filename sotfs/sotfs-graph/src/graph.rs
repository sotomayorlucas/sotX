//! # TypeGraph — in-memory representation of the sotFS metadata graph
//!
//! Implements TG = (V, E, src, tgt, τ_V, τ_E, attr) from Definition 5.1.
//! Provides O(1) node/edge lookup and O(n) invariant checking.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::GraphError;
use crate::types::*;

/// Maximum hard links per inode (bounds treewidth via GC-LINK-3).
pub const LINK_MAX: u32 = 65535;

/// The sotFS typed metadata graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeGraph {
    // --- Node pools ---
    pub inodes: BTreeMap<InodeId, Inode>,
    pub dirs: BTreeMap<DirId, Directory>,
    pub caps: BTreeMap<CapId, Capability>,
    pub transactions: BTreeMap<TxnId, Transaction>,
    pub versions: BTreeMap<VersionId, Version>,
    pub blocks: BTreeMap<BlockId, Block>,

    // --- Edge pool ---
    pub edges: BTreeMap<EdgeId, Edge>,

    // --- Indexes for fast lookup ---
    /// Directory → set of contains edge IDs (outgoing)
    pub dir_contains: BTreeMap<DirId, BTreeSet<EdgeId>>,
    /// Inode → set of contains edge IDs (incoming)
    pub inode_incoming_contains: BTreeMap<InodeId, BTreeSet<EdgeId>>,
    /// Inode → set of pointsTo edge IDs (outgoing)
    pub inode_points_to: BTreeMap<InodeId, BTreeSet<EdgeId>>,
    /// Capability → grants edge ID
    pub cap_grants: BTreeMap<CapId, EdgeId>,
    /// Capability → parent cap (via delegates edge)
    pub cap_parent: BTreeMap<CapId, CapId>,
    /// Capability → children caps (via delegates edges)
    pub cap_children: BTreeMap<CapId, BTreeSet<CapId>>,

    // --- File data (in-memory for FUSE prototype) ---
    /// InodeId → file content bytes
    pub file_data: BTreeMap<InodeId, Vec<u8>>,

    // --- ID allocators ---
    next_inode: u64,
    next_dir: u64,
    next_cap: u64,
    next_txn: u64,
    next_version: u64,
    next_block: u64,
    next_edge: u64,

    // --- Root ---
    pub root_dir: DirId,
    pub root_inode: InodeId,
}

impl TypeGraph {
    // -----------------------------------------------------------------------
    // Construction: CREATE-ROOT (ADR-003)
    // -----------------------------------------------------------------------

    /// Create a new type graph with the root directory (CREATE-ROOT DPO rule).
    pub fn new() -> Self {
        let inode_id = 1u64;
        let dir_id = 1u64;

        let root_inode = Inode::new_dir(inode_id, Permissions::DIR_DEFAULT, 0, 0);
        let root_dir = Directory {
            id: dir_id,
            inode_id,
        };

        // "." self-reference edge
        let dot_edge_id = 1u64;
        let dot_edge = Edge::Contains {
            id: dot_edge_id,
            src: dir_id,
            tgt: inode_id,
            name: ".".into(),
        };

        let mut g = Self {
            inodes: BTreeMap::new(),
            dirs: BTreeMap::new(),
            caps: BTreeMap::new(),
            transactions: BTreeMap::new(),
            versions: BTreeMap::new(),
            blocks: BTreeMap::new(),
            edges: BTreeMap::new(),
            dir_contains: BTreeMap::new(),
            inode_incoming_contains: BTreeMap::new(),
            inode_points_to: BTreeMap::new(),
            cap_grants: BTreeMap::new(),
            cap_parent: BTreeMap::new(),
            cap_children: BTreeMap::new(),
            file_data: BTreeMap::new(),
            next_inode: 2,
            next_dir: 2,
            next_cap: 1,
            next_txn: 1,
            next_version: 1,
            next_block: 1,
            next_edge: 2,
            root_dir: dir_id,
            root_inode: inode_id,
        };

        // Insert root inode with link_count=2 (entry from parent "." + self ".")
        // For root, there's no parent, so link_count = 1 (just ".")
        // Actually POSIX: root has nlink=2 for "." even without parent.
        let mut ri = root_inode;
        ri.link_count = 1; // just "." — G3 excludes ".."
        g.inodes.insert(inode_id, ri);
        g.dirs.insert(dir_id, root_dir);

        g.edges.insert(dot_edge_id, dot_edge);
        g.dir_contains
            .entry(dir_id)
            .or_default()
            .insert(dot_edge_id);
        g.inode_incoming_contains
            .entry(inode_id)
            .or_default()
            .insert(dot_edge_id);

        g
    }

    // -----------------------------------------------------------------------
    // ID allocation
    // -----------------------------------------------------------------------

    pub fn alloc_inode_id(&mut self) -> InodeId {
        let id = self.next_inode;
        self.next_inode += 1;
        id
    }

    pub fn alloc_dir_id(&mut self) -> DirId {
        let id = self.next_dir;
        self.next_dir += 1;
        id
    }

    pub fn alloc_cap_id(&mut self) -> CapId {
        let id = self.next_cap;
        self.next_cap += 1;
        id
    }

    pub fn alloc_block_id(&mut self) -> BlockId {
        let id = self.next_block;
        self.next_block += 1;
        id
    }

    pub fn alloc_edge_id(&mut self) -> EdgeId {
        let id = self.next_edge;
        self.next_edge += 1;
        id
    }

    // -----------------------------------------------------------------------
    // Typed accessors (thin wrappers for forward-compatibility with Arena)
    // -----------------------------------------------------------------------

    /// Insert an inode.
    #[inline]
    pub fn insert_inode(&mut self, id: InodeId, inode: Inode) {
        self.inodes.insert(id, inode);
    }

    /// Insert a directory.
    #[inline]
    pub fn insert_dir(&mut self, id: DirId, dir: Directory) {
        self.dirs.insert(id, dir);
    }

    /// Insert a capability.
    #[inline]
    pub fn insert_cap(&mut self, id: CapId, cap: Capability) {
        self.caps.insert(id, cap);
    }

    /// Insert a block.
    #[inline]
    pub fn insert_block(&mut self, id: BlockId, block: Block) {
        self.blocks.insert(id, block);
    }

    /// Insert an edge.
    #[inline]
    pub fn insert_edge(&mut self, id: EdgeId, edge: Edge) {
        self.edges.insert(id, edge);
    }

    /// Get a reference to an inode by ID.
    #[inline]
    pub fn get_inode(&self, id: InodeId) -> Option<&Inode> {
        self.inodes.get(&id)
    }

    /// Get a mutable reference to an inode by ID.
    #[inline]
    pub fn get_inode_mut(&mut self, id: InodeId) -> Option<&mut Inode> {
        self.inodes.get_mut(&id)
    }

    /// Get a reference to a directory by ID.
    #[inline]
    pub fn get_dir(&self, id: DirId) -> Option<&Directory> {
        self.dirs.get(&id)
    }

    /// Get a reference to a capability by ID.
    #[inline]
    pub fn get_cap(&self, id: CapId) -> Option<&Capability> {
        self.caps.get(&id)
    }

    /// Get a reference to a block by ID.
    #[inline]
    pub fn get_block(&self, id: BlockId) -> Option<&Block> {
        self.blocks.get(&id)
    }

    /// Get a mutable reference to a block by ID.
    #[inline]
    pub fn get_block_mut(&mut self, id: BlockId) -> Option<&mut Block> {
        self.blocks.get_mut(&id)
    }

    /// Get a reference to an edge by ID.
    #[inline]
    pub fn get_edge(&self, id: EdgeId) -> Option<&Edge> {
        self.edges.get(&id)
    }

    /// Get a mutable reference to an edge by ID.
    #[inline]
    pub fn get_edge_mut(&mut self, id: EdgeId) -> Option<&mut Edge> {
        self.edges.get_mut(&id)
    }

    /// Check if an inode exists.
    #[inline]
    pub fn contains_inode(&self, id: InodeId) -> bool {
        self.inodes.contains_key(&id)
    }

    /// Check if a directory exists.
    #[inline]
    pub fn contains_dir(&self, id: DirId) -> bool {
        self.dirs.contains_key(&id)
    }

    /// Check if a capability exists.
    #[inline]
    pub fn contains_cap(&self, id: CapId) -> bool {
        self.caps.contains_key(&id)
    }

    /// Check if a block exists.
    #[inline]
    pub fn contains_block(&self, id: BlockId) -> bool {
        self.blocks.contains_key(&id)
    }

    /// Remove an inode.
    #[inline]
    pub fn remove_inode(&mut self, id: InodeId) -> Option<Inode> {
        self.inodes.remove(&id)
    }

    /// Remove a directory.
    #[inline]
    pub fn remove_dir(&mut self, id: DirId) -> Option<Directory> {
        self.dirs.remove(&id)
    }

    /// Remove a block.
    #[inline]
    pub fn remove_block(&mut self, id: BlockId) -> Option<Block> {
        self.blocks.remove(&id)
    }

    /// Remove an edge.
    #[inline]
    pub fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.edges.remove(&id)
    }

    // -----------------------------------------------------------------------
    // Directory name lookup
    // -----------------------------------------------------------------------

    /// Find a contains edge in directory `dir` with the given name.
    pub fn lookup_name(&self, dir: DirId, name: &str) -> Option<&Edge> {
        let edge_ids = self.dir_contains.get(&dir)?;
        for &eid in edge_ids {
            if let Some(Edge::Contains {
                name: ref n, ..
            }) = self.edges.get(&eid)
            {
                if n == name {
                    return self.edges.get(&eid);
                }
            }
        }
        None
    }

    /// Find the inode ID targeted by a name in a directory.
    pub fn resolve_name(&self, dir: DirId, name: &str) -> Option<InodeId> {
        match self.lookup_name(dir, name)? {
            Edge::Contains { tgt, .. } => Some(*tgt),
            _ => None,
        }
    }

    /// Get all names in a directory (for readdir).
    pub fn list_dir(&self, dir: DirId) -> Vec<(String, InodeId)> {
        let mut entries = Vec::new();
        if let Some(edge_ids) = self.dir_contains.get(&dir) {
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = self.edges.get(&eid) {
                    entries.push((name.clone(), *tgt));
                }
            }
        }
        entries
    }

    /// Find the Directory node paired with an inode (the dir whose "." points to it).
    pub fn dir_for_inode(&self, inode_id: InodeId) -> Option<DirId> {
        self.dirs
            .values()
            .find(|d| d.inode_id == inode_id)
            .map(|d| d.id)
    }

    // -----------------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------------

    /// Resolve a path like "/foo/bar/baz" to (parent_dir, final_name, target_inode).
    pub fn resolve_path(&self, path: &str) -> Result<(DirId, InodeId), GraphError> {
        let components: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();

        let mut current_inode = self.root_inode;
        let mut current_dir = self.root_dir;

        for component in &components {
            if component == &".." {
                // Resolve ".." — find parent
                if let Some(parent_inode) = self.resolve_name(current_dir, "..") {
                    current_inode = parent_inode;
                    current_dir = self
                        .dir_for_inode(parent_inode)
                        .ok_or(GraphError::NotADirectory(parent_inode))?;
                }
                continue;
            }

            let target_inode = self
                .resolve_name(current_dir, component)
                .ok_or_else(|| GraphError::NameNotFound(component.to_string()))?;

            current_inode = target_inode;

            // If not the last component, it must be a directory
            if let Some(inode) = self.inodes.get(&target_inode) {
                if inode.vtype == VnodeType::Directory {
                    current_dir = self
                        .dir_for_inode(target_inode)
                        .ok_or(GraphError::NotADirectory(target_inode))?;
                }
            }
        }

        Ok((current_dir, current_inode))
    }

    /// Resolve path to parent dir + final component name.
    pub fn resolve_parent(
        &self,
        path: &str,
    ) -> Result<(DirId, String), GraphError> {
        let path = path.trim_end_matches('/');
        let (parent_path, name) = match path.rfind('/') {
            Some(pos) => {
                let parent = if pos == 0 { "/" } else { &path[..pos] };
                (parent, &path[pos + 1..])
            }
            None => ("/", path),
        };

        let (parent_dir, _) = self.resolve_path(parent_path)?;
        Ok((parent_dir, name.to_string()))
    }

    // -----------------------------------------------------------------------
    // Cycle detection (for rename — GC-RENAME-2)
    // -----------------------------------------------------------------------

    /// Check if `ancestor_dir` is an ancestor of (or equal to) `descendant_dir`
    /// in the contains subgraph (excluding "." and "..").
    /// Walks downward from `ancestor_dir` looking for `descendant_dir`.
    pub fn is_ancestor(&self, ancestor_dir: DirId, descendant_dir: DirId) -> bool {
        if ancestor_dir == descendant_dir {
            return true;
        }
        let mut visited = BTreeSet::new();
        self.is_descendant_of(ancestor_dir, descendant_dir, &mut visited)
    }

    /// Walk children of `current` looking for `target` among descendants.
    fn is_descendant_of(
        &self,
        current: DirId,
        target: DirId,
        visited: &mut BTreeSet<DirId>,
    ) -> bool {
        if !visited.insert(current) {
            return false;
        }
        if let Some(edge_ids) = self.dir_contains.get(&current) {
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = self.edges.get(&eid) {
                    if name == "." || name == ".." {
                        continue;
                    }
                    if let Some(inode) = self.inodes.get(tgt) {
                        if inode.vtype == VnodeType::Directory {
                            if let Some(child_dir) = self.dir_for_inode(*tgt) {
                                if child_dir == target {
                                    return true;
                                }
                                if self.is_descendant_of(child_dir, target, visited) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Invariant checking (§5.4-5.5)
    // -----------------------------------------------------------------------

    /// Check all graph invariants. Returns Ok(()) or the first violation.
    pub fn check_invariants(&self) -> Result<(), GraphError> {
        self.check_link_count_consistency()?;
        self.check_unique_names()?;
        self.check_dir_self_ref()?;
        self.check_no_dangling_edges()?;
        self.check_block_refcount()?;
        self.check_no_dir_cycles()?;
        self.check_cap_monotonicity()?;
        Ok(())
    }

    /// I2 + G3: link_count = |incoming contains edges excluding ".."|
    fn check_link_count_consistency(&self) -> Result<(), GraphError> {
        for (id, inode) in &self.inodes {
            let count = self
                .inode_incoming_contains
                .get(id)
                .map(|edges| {
                    edges
                        .iter()
                        .filter(|&&eid| {
                            matches!(
                                self.edges.get(&eid),
                                Some(Edge::Contains { name, .. }) if name != ".."
                            )
                        })
                        .count() as u32
                })
                .unwrap_or(0);

            if inode.link_count != count {
                return Err(GraphError::InvariantViolation(format!(
                    "Inode {} link_count={} but has {} incoming contains edges (excl. ..)",
                    id, inode.link_count, count
                )));
            }
        }
        Ok(())
    }

    /// C1 + I4: unique names per directory
    fn check_unique_names(&self) -> Result<(), GraphError> {
        for (dir_id, edge_ids) in &self.dir_contains {
            let mut names = BTreeSet::new();
            for &eid in edge_ids {
                if let Some(Edge::Contains { name, .. }) = self.edges.get(&eid) {
                    if !names.insert(name.clone()) {
                        return Err(GraphError::InvariantViolation(format!(
                            "Directory {} has duplicate name '{}'",
                            dir_id, name
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// I3: every directory has a "." self-reference
    fn check_dir_self_ref(&self) -> Result<(), GraphError> {
        for (dir_id, dir) in &self.dirs {
            let has_dot = self
                .dir_contains
                .get(dir_id)
                .map(|edges| {
                    edges.iter().any(|&eid| {
                        matches!(
                            self.edges.get(&eid),
                            Some(Edge::Contains { tgt, name, .. })
                                if name == "." && *tgt == dir.inode_id
                        )
                    })
                })
                .unwrap_or(false);

            if !has_dot {
                return Err(GraphError::InvariantViolation(format!(
                    "Directory {} missing '.' self-reference",
                    dir_id
                )));
            }
        }
        Ok(())
    }

    /// G2: no dangling edges
    fn check_no_dangling_edges(&self) -> Result<(), GraphError> {
        for (eid, edge) in &self.edges {
            let src_exists = match edge.src_node() {
                NodeId::Inode(id) => self.inodes.contains_key(&id),
                NodeId::Directory(id) => self.dirs.contains_key(&id),
                NodeId::Capability(id) => self.caps.contains_key(&id),
                NodeId::Transaction(id) => self.transactions.contains_key(&id),
                NodeId::Version(id) => self.versions.contains_key(&id),
                NodeId::Block(id) => self.blocks.contains_key(&id),
            };
            let tgt_exists = match edge.tgt_node() {
                NodeId::Inode(id) => self.inodes.contains_key(&id),
                NodeId::Directory(id) => self.dirs.contains_key(&id),
                NodeId::Capability(id) => self.caps.contains_key(&id),
                NodeId::Transaction(id) => self.transactions.contains_key(&id),
                NodeId::Version(id) => self.versions.contains_key(&id),
                NodeId::Block(id) => self.blocks.contains_key(&id),
            };
            if !src_exists || !tgt_exists {
                return Err(GraphError::InvariantViolation(format!(
                    "Edge {} has dangling endpoint (src_exists={}, tgt_exists={})",
                    eid, src_exists, tgt_exists
                )));
            }
        }
        Ok(())
    }

    /// I8: block refcount = |incoming pointsTo edges|
    fn check_block_refcount(&self) -> Result<(), GraphError> {
        for (id, block) in &self.blocks {
            let actual = self
                .edges
                .values()
                .filter(|e| matches!(e, Edge::PointsTo { tgt, .. } if *tgt == *id))
                .count() as u32;
            if block.refcount != actual {
                return Err(GraphError::InvariantViolation(format!(
                    "Block {} refcount={} but has {} incoming pointsTo edges",
                    id, block.refcount, actual
                )));
            }
        }
        Ok(())
    }

    /// G5: no directory cycles (excluding "." and "..")
    fn check_no_dir_cycles(&self) -> Result<(), GraphError> {
        for &dir_id in self.dirs.keys() {
            let mut visited = BTreeSet::new();
            if self.has_cycle_from(dir_id, &mut visited) {
                return Err(GraphError::InvariantViolation(format!(
                    "Directory cycle detected involving dir {}",
                    dir_id
                )));
            }
        }
        Ok(())
    }

    fn has_cycle_from(&self, start: DirId, visited: &mut BTreeSet<DirId>) -> bool {
        if !visited.insert(start) {
            return true;
        }
        if let Some(edge_ids) = self.dir_contains.get(&start) {
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = self.edges.get(&eid) {
                    if name == "." || name == ".." {
                        continue;
                    }
                    if let Some(inode) = self.inodes.get(tgt) {
                        if inode.vtype == VnodeType::Directory {
                            if let Some(child_dir) = self.dir_for_inode(*tgt) {
                                if self.has_cycle_from(child_dir, visited) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        visited.remove(&start);
        false
    }

    /// G4: capability monotonicity along delegation chains
    fn check_cap_monotonicity(&self) -> Result<(), GraphError> {
        for (&child_id, &parent_id) in &self.cap_parent {
            if let (Some(child), Some(parent)) = (self.caps.get(&child_id), self.caps.get(&parent_id))
            {
                if !child.rights.is_subset_of(&parent.rights) {
                    return Err(GraphError::InvariantViolation(format!(
                        "Capability {} rights {:?} not subset of parent {} rights {:?}",
                        child_id, child.rights, parent_id, parent.rights
                    )));
                }
            }
        }
        Ok(())
    }
}

impl Default for TypeGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_graph_satisfies_invariants() {
        let g = TypeGraph::new();
        g.check_invariants().unwrap();
        assert_eq!(g.inodes.len(), 1);
        assert_eq!(g.dirs.len(), 1);
        assert_eq!(g.edges.len(), 1); // "." edge
    }

    #[test]
    fn root_has_dot_entry() {
        let g = TypeGraph::new();
        let target = g.resolve_name(g.root_dir, ".");
        assert_eq!(target, Some(g.root_inode));
    }

    #[test]
    fn root_link_count_is_one() {
        let g = TypeGraph::new();
        assert_eq!(g.inodes[&g.root_inode].link_count, 1);
    }
}
