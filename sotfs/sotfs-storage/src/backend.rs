//! redb-backed persistence for the sotFS type graph.

use std::path::Path;

use redb::{Database, TableDefinition};
use sotfs_graph::graph::TypeGraph;

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

/// Persistent storage backend using redb.
pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }

    /// Save the entire graph to disk (atomic via redb transaction).
    pub fn save(&self, graph: &TypeGraph) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_vec(graph)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(METADATA_TABLE)?;
            table.insert("graph", serialized.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Load the graph from disk. Returns None if no graph is stored.
    pub fn load(&self) -> Result<Option<TypeGraph>, Box<dyn std::error::Error>> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(METADATA_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get("graph")? {
            Some(data) => {
                let graph: TypeGraph = serde_json::from_slice(data.value())?;
                Ok(Some(graph))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_graph::types::Permissions;
    use sotfs_ops::create_file;

    #[test]
    fn round_trip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");

        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        create_file(&mut g, rd, "test.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();

        let backend = RedbBackend::open(&db_path).unwrap();
        backend.save(&g).unwrap();

        let loaded = backend.load().unwrap().unwrap();
        assert_eq!(loaded.inodes.len(), g.inodes.len());
        assert!(loaded.resolve_name(loaded.root_dir, "test.txt").is_some());
    }
}
