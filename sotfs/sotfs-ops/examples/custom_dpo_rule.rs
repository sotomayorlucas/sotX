//! # Tutorial: Write Your Own DPO Rule
//!
//! This example walks through creating a new DPO graph rewriting rule for
//! sotFS step by step. We implement `TOUCH` — a rule that updates an
//! inode's atime/mtime without modifying file content.
//!
//! ## DPO Formalism Recap
//!
//! A DPO rule ρ = (L ←l— K —r→ R) consists of:
//!   - L (left-hand side): pattern to match in the host graph
//!   - K (interface): elements preserved by the rule
//!   - R (right-hand side): replacement pattern
//!
//! For TOUCH:
//!   - L = { i:Inode }                     — match an existing inode
//!   - K = { i:Inode }                     — the inode is preserved
//!   - R = { i:Inode[mtime=now, atime=now] } — same inode, updated timestamps
//!
//! ## Step-by-step guide
//!
//! 1. Define the preconditions (gluing conditions)
//! 2. Implement the graph mutation
//! 3. Define the affected nodes for incremental curvature
//! 4. Write tests
//! 5. (Optional) Write the Coq invariant preservation proof
//!
//! Run this example:
//!   cargo run --example custom_dpo_rule

use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_graph::GraphError;

// ========================================================================
// Step 1: Define Preconditions (Gluing Conditions)
// ========================================================================
//
// Every DPO rule needs preconditions that check whether the rule can be
// applied to the current graph state. These map to the "gluing conditions"
// in the DPO formalism.
//
// For TOUCH, the preconditions are simple:
//   GC-TOUCH-1: The target inode must exist
//   GC-TOUCH-2: The inode must be a regular file or symlink (not a directory)
//               (Directories use utime via their paired inode.)

// ========================================================================
// Step 2: Implement the Graph Mutation
// ========================================================================
//
// The rule function takes a mutable reference to the TypeGraph and applies
// the transformation. It returns Result<T, GraphError> to signal gluing
// condition violations.

/// DPO Rule: TOUCH — update timestamps on a file inode.
///
/// ```text
/// L = { i:Inode }
/// K = { i:Inode }
/// R = { i:Inode[mtime=new_mtime, atime=new_atime] }
/// ```
///
/// This rule only modifies attributes, not graph structure (no nodes or
/// edges added/removed). It's the simplest possible DPO rule — useful
/// as a template for understanding the framework.
fn touch(
    g: &mut TypeGraph,
    inode_id: InodeId,
    new_mtime: Timestamp,
    new_atime: Timestamp,
) -> Result<(), GraphError> {
    // ----- Gluing condition checks -----

    // GC-TOUCH-1: inode must exist
    let inode = g
        .get_inode(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;

    // GC-TOUCH-2: must be a file or symlink
    if inode.vtype == VnodeType::Directory {
        return Err(GraphError::NotAFile(inode_id));
    }

    // ----- Apply the rule -----
    // Since we're only changing attributes (not structure), we mutate in place.
    // For rules that add/remove nodes or edges, you'd use the full
    // insert_inode/insert_edge/remove_edge API.

    let inode_mut = g
        .get_inode_mut(inode_id)
        .ok_or(GraphError::InodeNotFound(inode_id))?;
    inode_mut.mtime = new_mtime;
    inode_mut.atime = new_atime;

    Ok(())
}

// ========================================================================
// Step 3: Define Affected Nodes for Incremental Curvature
// ========================================================================
//
// After each DPO rule, the curvature monitor needs to know which nodes
// were affected so it can recompute curvature only in the 2-hop
// neighborhood. For TOUCH, only the inode itself is affected (no
// structural change).

fn affected_nodes_touch(inode_id: InodeId) -> Vec<NodeId> {
    vec![NodeId::Inode(inode_id)]
}

// ========================================================================
// Step 4: Write Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_ops::{create_file, mkdir};

    #[test]
    fn touch_updates_timestamps() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let id = create_file(&mut g, rd, "f.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        touch(&mut g, id, 999, 1000).unwrap();

        let inode = g.get_inode(id).unwrap();
        assert_eq!(inode.mtime, 999);
        assert_eq!(inode.atime, 1000);

        // Invariants still hold (TOUCH doesn't change structure)
        g.check_invariants().unwrap();
    }

    #[test]
    fn touch_directory_rejected() {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let sub = mkdir(&mut g, rd, "d", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let result = touch(&mut g, sub.inode_id, 999, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn touch_nonexistent_inode_rejected() {
        let mut g = TypeGraph::new();
        let result = touch(&mut g, 99999, 0, 0);
        assert!(matches!(result, Err(GraphError::InodeNotFound(99999))));
    }

    #[test]
    fn affected_nodes_returns_inode() {
        let affected = affected_nodes_touch(42);
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0], NodeId::Inode(42));
    }
}

// ========================================================================
// Step 5: Coq Proof Sketch (for reference)
// ========================================================================
//
// To prove TOUCH preserves WellFormed in Coq, create formal/coq/DpoTouch.v:
//
// ```coq
// (* DpoTouch.v — TOUCH preserves WellFormed *)
// Require Import SotfsGraph.
//
// (* TOUCH only changes attributes, not structure.
//    All 5 invariants are trivially preserved because:
//    - TypeInvariant: no nodes/edges added or removed
//    - LinkCountConsistent: link_count unchanged
//    - UniqueNamesPerDir: no edges changed
//    - NoDanglingEdges: no edges changed
//    - NoDirCycles: no edges changed
//
//    Proof: unfold WellFormed; apply HWF (hypothesis).
// *)
//
// Definition touch (g : Graph) (ino : InodeId) : Graph := g.
// (* In Coq, attribute-only changes don't affect the structural graph. *)
//
// Theorem touch_preserves_WellFormed :
//   forall g ino, WellFormed g -> WellFormed (touch g ino).
// Proof. intros g ino HWF. exact HWF. Qed.
// ```
//
// For rules that DO change structure (add/remove nodes/edges), the proof
// is more involved. See DpoCreate.v and DpoUnlink.v for full examples.

// ========================================================================
// Main: demonstration
// ========================================================================

fn main() {
    println!("=== sotFS DPO Rule Tutorial: TOUCH ===\n");

    // Create a graph with some files
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    let file_id = sotfs_ops::create_file(
        &mut g, rd, "example.txt", 1000, 1000, Permissions::FILE_DEFAULT,
    ).unwrap();
    sotfs_ops::write_data(&mut g, file_id, 0, b"Hello, DPO!").unwrap();

    println!("Created file (inode {})", file_id);
    let inode = g.get_inode(file_id).unwrap();
    println!("  Before: mtime={}, atime={}", inode.mtime, inode.atime);

    // Apply our custom TOUCH rule
    touch(&mut g, file_id, 1713000000, 1713000001).unwrap();

    let inode = g.get_inode(file_id).unwrap();
    println!("  After:  mtime={}, atime={}", inode.mtime, inode.atime);

    // Verify invariants still hold
    g.check_invariants().unwrap();
    println!("\nInvariants: ALL PASS");

    // Show affected nodes for curvature monitor
    let affected = affected_nodes_touch(file_id);
    println!("Affected nodes: {:?}", affected);

    // Export the graph for visualization
    let dot = sotfs_graph::export::to_dot(&g, &sotfs_graph::export::DotStyle::default());
    println!("\nGraphViz DOT output ({} chars):", dot.len());
    println!("{}", &dot[..dot.len().min(200)]);
    println!("...");

    println!("\n=== Tutorial complete ===");
    println!("\nNext steps:");
    println!("  1. Copy this pattern for your own rule");
    println!("  2. Add structural mutations (insert_inode, insert_edge, remove_edge)");
    println!("  3. Check gluing conditions BEFORE mutating");
    println!("  4. Call check_invariants() in tests to verify preservation");
    println!("  5. Write a Coq proof in formal/coq/Dpo<YourRule>.v");
}
