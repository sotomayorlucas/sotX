//! # Deceptive Subgraph Projections
//!
//! Implements capability-gated graph projections (§10 of design doc).
//! Different security domains see different subgraphs of the filesystem.
//!
//! The D_FS functor maps the real TypeGraph to a projected view:
//! - **Passthrough:** Domain sees the real graph (identity functor).
//! - **Restrict:** Domain sees only a subtree rooted at its capability.
//! - **Fabricate:** Synthetic nodes/edges added to the projected view.
//! - **Redirect:** Certain paths resolve to different inodes (honeypots).

use std::collections::{BTreeMap, BTreeSet};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;

/// Interposition policy for a domain's projection.
#[derive(Debug, Clone)]
pub enum Policy {
    /// See the real graph unchanged.
    Passthrough,
    /// See only the subtree rooted at a specific directory.
    Restrict { root_dir: DirId },
    /// See the real graph plus fabricated entries.
    Fabricate { synthetic: Vec<SyntheticEntry> },
    /// Certain paths resolve to different inodes.
    Redirect { redirects: BTreeMap<String, InodeId> },
}

/// A fabricated directory entry that doesn't exist in the real graph.
#[derive(Debug, Clone)]
pub struct SyntheticEntry {
    pub parent_dir: DirId,
    pub name: String,
    pub inode: Inode,
    pub data: Vec<u8>,
}

/// A projected view of the filesystem for a specific domain.
#[derive(Debug)]
pub struct ProjectedView {
    /// Visible inodes (subset of real + synthetic).
    pub visible_inodes: BTreeMap<InodeId, Inode>,
    /// Visible directory entries.
    pub visible_entries: BTreeMap<DirId, Vec<(String, InodeId)>>,
    /// Fabricated file data (for synthetic entries).
    pub fabricated_data: BTreeMap<InodeId, Vec<u8>>,
    /// Redirect map: original inode → replacement inode.
    pub redirects: BTreeMap<InodeId, InodeId>,
    /// Policy used to create this projection.
    pub policy: String,
}

/// Compute the projected view of the graph for a domain with the given policy.
pub fn project(graph: &TypeGraph, policy: &Policy) -> ProjectedView {
    match policy {
        Policy::Passthrough => project_passthrough(graph),
        Policy::Restrict { root_dir } => project_restrict(graph, *root_dir),
        Policy::Fabricate { synthetic } => project_fabricate(graph, synthetic),
        Policy::Redirect { redirects } => project_redirect(graph, redirects),
    }
}

/// Passthrough: the domain sees everything as-is.
fn project_passthrough(graph: &TypeGraph) -> ProjectedView {
    let mut entries: BTreeMap<DirId, Vec<(String, InodeId)>> = BTreeMap::new();
    for (&dir_id, edge_ids) in &graph.dir_contains {
        let mut dir_entries = Vec::new();
        for &eid in edge_ids {
            if let Some(Edge::Contains { tgt, name, .. }) = graph.get_edge(eid) {
                dir_entries.push((name.clone(), *tgt));
            }
        }
        entries.insert(dir_id, dir_entries);
    }

    ProjectedView {
        visible_inodes: graph.inodes.iter().map(|(aid, v)| (aid.0 as u64, v.clone())).collect(),
        visible_entries: entries,
        fabricated_data: BTreeMap::new(),
        redirects: BTreeMap::new(),
        policy: "passthrough".into(),
    }
}

/// Restrict: only show the subtree rooted at root_dir.
fn project_restrict(graph: &TypeGraph, root_dir: DirId) -> ProjectedView {
    let mut visible_inodes = BTreeMap::new();
    let mut visible_entries: BTreeMap<DirId, Vec<(String, InodeId)>> = BTreeMap::new();
    let mut queue = vec![root_dir];
    let mut visited_dirs = BTreeSet::new();

    while let Some(dir_id) = queue.pop() {
        if !visited_dirs.insert(dir_id) {
            continue;
        }

        // Add this dir's inode
        if let Some(dir) = graph.get_dir(dir_id) {
            if let Some(inode) = graph.get_inode(dir.inode_id) {
                visible_inodes.insert(dir.inode_id, inode.clone());
            }
        }

        // Walk contains edges
        if let Some(edge_ids) = graph.dir_contains.get(&dir_id) {
            let mut dir_list = Vec::new();
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = graph.get_edge(eid) {
                    if let Some(inode) = graph.get_inode(*tgt) {
                        visible_inodes.insert(*tgt, inode.clone());
                        dir_list.push((name.clone(), *tgt));

                        // Recurse into subdirectories
                        if inode.vtype == VnodeType::Directory && name != "." && name != ".." {
                            if let Some(child_dir) = graph.dir_for_inode(*tgt) {
                                queue.push(child_dir);
                            }
                        }
                    }
                }
            }
            visible_entries.insert(dir_id, dir_list);
        }
    }

    ProjectedView {
        visible_inodes,
        visible_entries,
        fabricated_data: BTreeMap::new(),
        redirects: BTreeMap::new(),
        policy: format!("restrict(root={})", root_dir),
    }
}

/// Fabricate: add synthetic entries to the real graph.
fn project_fabricate(graph: &TypeGraph, synthetic: &[SyntheticEntry]) -> ProjectedView {
    let mut view = project_passthrough(graph);
    view.policy = "fabricate".into();

    for entry in synthetic {
        // Add synthetic inode
        view.visible_inodes.insert(entry.inode.id, entry.inode.clone());

        // Add synthetic directory entry
        view.visible_entries
            .entry(entry.parent_dir)
            .or_default()
            .push((entry.name.clone(), entry.inode.id));

        // Add fabricated data
        if !entry.data.is_empty() {
            view.fabricated_data.insert(entry.inode.id, entry.data.clone());
        }
    }

    view
}

/// Redirect: certain inodes resolve to different inodes (honeypots).
fn project_redirect(graph: &TypeGraph, redirects: &BTreeMap<String, InodeId>) -> ProjectedView {
    let mut view = project_passthrough(graph);
    view.policy = "redirect".into();

    // Build redirect map from name-based redirects
    for (_dir_id, entries) in &mut view.visible_entries {
        for (name, inode_id) in entries.iter_mut() {
            if let Some(&redirect_to) = redirects.get(name.as_str()) {
                view.redirects.insert(*inode_id, redirect_to);
                *inode_id = redirect_to;
            }
        }
    }

    view
}

/// Resolve a name in a projected view's directory.
pub fn projected_lookup(view: &ProjectedView, dir: DirId, name: &str) -> Option<InodeId> {
    view.visible_entries
        .get(&dir)?
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, id)| *id)
}

/// Read data from a projected view (checks fabricated data first).
pub fn projected_read(
    view: &ProjectedView,
    graph: &TypeGraph,
    inode_id: InodeId,
    offset: u64,
    len: usize,
) -> Option<Vec<u8>> {
    // Check fabricated data first
    if let Some(data) = view.fabricated_data.get(&inode_id) {
        let start = (offset as usize).min(data.len());
        let end = (start + len).min(data.len());
        return Some(data[start..end].to_vec());
    }

    // Follow redirects
    let actual_id = view.redirects.get(&inode_id).copied().unwrap_or(inode_id);

    // Read from real graph
    graph
        .file_data
        .get(&actual_id)
        .map(|data| {
            let start = (offset as usize).min(data.len());
            let end = (start + len).min(data.len());
            data[start..end].to_vec()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_graph::types::Permissions;

    fn build_test_graph() -> TypeGraph {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let f = sotfs_ops::create_file(&mut g, rd, "secret.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, f, 0, b"TOP SECRET DATA").unwrap();
        let d = sotfs_ops::mkdir(&mut g, rd, "public", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let p = sotfs_ops::create_file(&mut g, d.dir_id.unwrap(), "readme.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, p, 0, b"Hello World").unwrap();
        g
    }

    #[test]
    fn passthrough_sees_everything() {
        let g = build_test_graph();
        let view = project(&g, &Policy::Passthrough);
        assert_eq!(view.visible_inodes.len(), g.inodes.len());
        assert!(projected_lookup(&view, g.root_dir, "secret.txt").is_some());
        assert!(projected_lookup(&view, g.root_dir, "public").is_some());
    }

    #[test]
    fn restrict_hides_sibling_subtrees() {
        let g = build_test_graph();
        let public_dir = g.dir_for_inode(
            g.resolve_name(g.root_dir, "public").unwrap()
        ).unwrap();

        let view = project(&g, &Policy::Restrict { root_dir: public_dir });

        // Can see readme.txt in /public
        assert!(projected_lookup(&view, public_dir, "readme.txt").is_some());

        // Cannot see /secret.txt (outside restricted subtree)
        assert!(
            !view.visible_inodes.values().any(|i| {
                view.visible_entries
                    .values()
                    .any(|entries| entries.iter().any(|(n, _)| n == "secret.txt"))
            }),
            "restricted view should not contain secret.txt"
        );
    }

    #[test]
    fn fabricate_adds_honeypot_files() {
        let g = build_test_graph();

        let honeypot_inode = Inode::new_file(9999, Permissions::FILE_DEFAULT, 0, 0);
        let synthetic = vec![SyntheticEntry {
            parent_dir: g.root_dir,
            name: "passwords.txt".into(),
            inode: honeypot_inode,
            data: b"admin:hunter2\nroot:toor".to_vec(),
        }];

        let view = project(&g, &Policy::Fabricate { synthetic });

        // Real files still visible
        assert!(projected_lookup(&view, g.root_dir, "secret.txt").is_some());

        // Honeypot file visible
        let hp_id = projected_lookup(&view, g.root_dir, "passwords.txt");
        assert!(hp_id.is_some());
        assert_eq!(hp_id.unwrap(), 9999);

        // Honeypot data readable
        let data = projected_read(&view, &g, 9999, 0, 100).unwrap();
        assert_eq!(data, b"admin:hunter2\nroot:toor");
    }

    #[test]
    fn redirect_swaps_file_contents() {
        let mut g = build_test_graph();
        let rd = g.root_dir;

        // Create a decoy file with fake data
        let decoy = sotfs_ops::create_file(&mut g, rd, "decoy", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, decoy, 0, b"NOTHING TO SEE HERE").unwrap();

        // Redirect "secret.txt" → decoy inode
        let mut redirects = BTreeMap::new();
        redirects.insert("secret.txt".into(), decoy);

        let view = project(&g, &Policy::Redirect { redirects });

        // Lookup "secret.txt" now returns the decoy inode
        let resolved = projected_lookup(&view, rd, "secret.txt").unwrap();
        assert_eq!(resolved, decoy);

        // Reading through the projected view gives decoy data
        let data = projected_read(&view, &g, resolved, 0, 100).unwrap();
        assert_eq!(data, b"NOTHING TO SEE HERE");
    }

    #[test]
    fn projection_preserves_dot_entries() {
        let g = build_test_graph();
        let view = project(&g, &Policy::Passthrough);

        // "." should resolve to root inode
        let dot = projected_lookup(&view, g.root_dir, ".");
        assert_eq!(dot, Some(g.root_inode));
    }
}
