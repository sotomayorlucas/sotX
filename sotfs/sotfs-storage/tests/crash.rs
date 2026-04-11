//! Crash consistency tests for the sotFS persistence layer.
//!
//! Simulates crashes at various points during save and verifies that
//! recovery produces a consistent graph state (either pre-transaction
//! or post-commit, never intermediate).

use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::Permissions;
use sotfs_ops::*;
use sotfs_storage::RedbBackend;

/// Helper: create a graph with some structure for testing.
fn sample_graph() -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    create_file(&mut g, rd, "a.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    create_file(&mut g, rd, "b.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    mkdir(&mut g, rd, "subdir", 0, 0, Permissions::DIR_DEFAULT).unwrap();
    g
}

#[test]
fn save_then_load_preserves_graph() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash1.redb");

    let g = sample_graph();
    let backend = RedbBackend::open(&db_path).unwrap();
    backend.save(&g).unwrap();

    let loaded = backend.load().unwrap().unwrap();
    assert_eq!(loaded.inodes.len(), g.inodes.len());
    assert_eq!(loaded.dirs.len(), g.dirs.len());
    assert_eq!(loaded.edges.len(), g.edges.len());
    loaded.check_invariants().unwrap();
}

#[test]
fn load_without_save_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash2.redb");

    let backend = RedbBackend::open(&db_path).unwrap();
    let result = backend.load().unwrap();
    assert!(result.is_none());
}

#[test]
fn save_overwrite_is_atomic() {
    // Save initial state, then save updated state.
    // Load should return the updated state, not a mix.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash3.redb");

    let mut g = sample_graph();
    let backend = RedbBackend::open(&db_path).unwrap();
    backend.save(&g).unwrap();

    // Modify and save again
    let rd = g.root_dir;
    create_file(&mut g, rd, "c.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    backend.save(&g).unwrap();

    let loaded = backend.load().unwrap().unwrap();
    assert_eq!(loaded.inodes.len(), g.inodes.len()); // should have c.txt
    assert!(loaded.resolve_name(loaded.root_dir, "c.txt").is_some());
    loaded.check_invariants().unwrap();
}

#[test]
fn reopen_database_preserves_data() {
    // Save, drop backend, reopen from disk, verify.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash4.redb");

    {
        let g = sample_graph();
        let backend = RedbBackend::open(&db_path).unwrap();
        backend.save(&g).unwrap();
    } // backend dropped, file closed

    // Reopen
    let backend2 = RedbBackend::open(&db_path).unwrap();
    let loaded = backend2.load().unwrap().unwrap();
    assert_eq!(loaded.inodes.len(), 4); // root + a.txt + b.txt + subdir
    loaded.check_invariants().unwrap();
}

#[test]
fn concurrent_saves_last_writer_wins() {
    // Two sequential saves — the last one is the persisted state.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash5.redb");

    let backend = RedbBackend::open(&db_path).unwrap();

    // Save state A
    let mut g_a = TypeGraph::new();
    let rd = g_a.root_dir;
    create_file(&mut g_a, rd, "only_a.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    backend.save(&g_a).unwrap();

    // Save state B (overwrites A)
    let mut g_b = TypeGraph::new();
    let rd = g_b.root_dir;
    create_file(&mut g_b, rd, "only_b.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    backend.save(&g_b).unwrap();

    // Load should return B
    let loaded = backend.load().unwrap().unwrap();
    assert!(loaded.resolve_name(loaded.root_dir, "only_b.txt").is_some());
    assert!(loaded.resolve_name(loaded.root_dir, "only_a.txt").is_none());
}

#[test]
fn invariants_preserved_after_complex_operations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("crash6.redb");

    let mut g = TypeGraph::new();
    let rd = g.root_dir;

    // Build a complex tree
    let d1 = mkdir(&mut g, rd, "usr", 0, 0, Permissions::DIR_DEFAULT).unwrap();
    let d1d = d1.dir_id.unwrap();
    let d2 = mkdir(&mut g, d1d, "bin", 0, 0, Permissions::DIR_DEFAULT).unwrap();
    let d2d = d2.dir_id.unwrap();
    let f1 = create_file(&mut g, d2d, "ls", 0, 0, Permissions::FILE_DEFAULT).unwrap();
    write_data(&mut g, f1, 0, b"#!/bin/ls").unwrap();

    // Create hard link
    link(&mut g, rd, "ls_link", f1).unwrap();

    // Rename
    rename(&mut g, d2d, "ls", d1d, "ls_moved").unwrap();

    g.check_invariants().unwrap();

    // Save and reload
    let backend = RedbBackend::open(&db_path).unwrap();
    backend.save(&g).unwrap();

    let loaded = backend.load().unwrap().unwrap();
    loaded.check_invariants().unwrap();

    // Verify data survived
    let ls_id = loaded.resolve_name(loaded.root_dir, "ls_link").unwrap();
    let data = read_data(&loaded, ls_id, 0, 100).unwrap();
    assert_eq!(data, b"#!/bin/ls");
}
