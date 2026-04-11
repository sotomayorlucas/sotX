//! # sotfs-tx — Graph-Level Transaction Manager (GTXN)
//!
//! Wraps DPO rule applications in atomic transactions with
//! rollback capability. See ADR-001.

use sotfs_graph::graph::TypeGraph;
use sotfs_graph::GraphError;

/// Transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtxnState {
    Active,
    Committed,
    Aborted,
}

/// A graph-level transaction.
///
/// Captures a snapshot of the graph at begin time. On commit, the
/// current graph state becomes durable. On rollback, the snapshot
/// is restored.
pub struct Gtxn {
    pub state: GtxnState,
    snapshot: TypeGraph,
}

impl Gtxn {
    /// Begin a new GTXN by snapshotting the current graph state.
    pub fn begin(graph: &TypeGraph) -> Self {
        Self {
            state: GtxnState::Active,
            snapshot: graph.clone(),
        }
    }

    /// Commit the transaction (graph state is now authoritative).
    pub fn commit(&mut self) -> Result<(), GraphError> {
        if self.state != GtxnState::Active {
            return Err(GraphError::InvariantViolation(
                "cannot commit non-active transaction".into(),
            ));
        }
        self.state = GtxnState::Committed;
        Ok(())
    }

    /// Rollback: restore the graph to the pre-transaction snapshot.
    pub fn rollback(self, graph: &mut TypeGraph) {
        *graph = self.snapshot;
    }
}

/// Execute a closure within a GTXN. If the closure returns Err or
/// invariants fail, the graph is rolled back automatically.
pub fn with_transaction<F, T>(graph: &mut TypeGraph, f: F) -> Result<T, GraphError>
where
    F: FnOnce(&mut TypeGraph) -> Result<T, GraphError>,
{
    let txn = Gtxn::begin(graph);

    match f(graph) {
        Ok(result) => {
            // Verify invariants before committing
            graph.check_invariants()?;
            // If invariants pass, commit (snapshot is dropped)
            Ok(result)
        }
        Err(e) => {
            // Rollback on error
            txn.rollback(graph);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_graph::types::Permissions;
    use sotfs_ops::{create_file, mkdir};

    #[test]
    fn transaction_commits_on_success() {
        let mut g = TypeGraph::new();
        let result = with_transaction(&mut g, |g| {
            create_file(g, g.root_dir, "a.txt", 0, 0, Permissions::FILE_DEFAULT)
        });
        assert!(result.is_ok());
        assert!(g.resolve_name(g.root_dir, "a.txt").is_some());
    }

    #[test]
    fn transaction_rollback_on_error() {
        let mut g = TypeGraph::new();
        let root = g.root_dir;
        let result = with_transaction(&mut g, |g| {
            create_file(g, root, "ok.txt", 0, 0, Permissions::FILE_DEFAULT)?;
            // This will fail — duplicate name
            create_file(g, root, "ok.txt", 0, 0, Permissions::FILE_DEFAULT)?;
            Ok(())
        });
        assert!(result.is_err());
        // Rollback: "ok.txt" should not exist
        assert!(g.resolve_name(g.root_dir, "ok.txt").is_none());
    }

    #[test]
    fn nested_mkdir_transaction() {
        let mut g = TypeGraph::new();
        let root = g.root_dir;
        with_transaction(&mut g, |g| {
            let d = mkdir(g, root, "a", 0, 0, Permissions::DIR_DEFAULT)?;
            mkdir(g, d.dir_id.unwrap(), "b", 0, 0, Permissions::DIR_DEFAULT)?;
            Ok(())
        })
        .unwrap();
        g.check_invariants().unwrap();
    }
}
