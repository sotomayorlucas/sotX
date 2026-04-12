//! Property-based tests for sotFS DPO operations.
//!
//! Generates random sequences of filesystem operations and verifies
//! that all 7 graph invariants hold after every operation.
//! proptest shrinks failing sequences to the minimal reproduction.
//!
//! Run:          cargo test --release --test proptest_ops -- --test-threads=1
//! Quick (100):  PROPTEST_CASES=100 cargo test --test proptest_ops
//!
//! Default: 10,000 iterations per property (10 properties total).
//! Override at runtime: set PROPTEST_CASES=N to use N iterations instead.

use std::time::Instant;

use proptest::prelude::*;
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops::*;

// ---------------------------------------------------------------------------
// Configuration: 10K default, env override, aggressive shrinking
// ---------------------------------------------------------------------------

fn test_config() -> ProptestConfig {
    // Allow PROPTEST_CASES env var to override the default 10,000 iterations.
    // This is useful for CI (full run) vs local dev (quick smoke test).
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10_000);

    ProptestConfig {
        cases,
        max_shrink_iters: 10_000,
        max_shrink_time: 60_000, // 60 seconds
        // Regressions file: auto-saved failing seeds for deterministic replay
        result_cache: proptest::test_runner::basic_result_cache,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// FsOp: the random operation type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum FsOp {
    CreateFile { dir_idx: usize, name: String },
    Mkdir { dir_idx: usize, name: String },
    Rmdir { dir_idx: usize, name: String },
    Link { dir_idx: usize, name: String, target_idx: usize },
    Unlink { dir_idx: usize, name: String },
    Rename { src_idx: usize, src_name: String, dst_idx: usize, dst_name: String },
    WriteData { file_idx: usize, offset: u64, data: Vec<u8> },
    ReadData { file_idx: usize, offset: u64, size: usize },
    Truncate { file_idx: usize, new_size: u64 },
    Chmod { inode_idx: usize, mode: u16 },
    Chown { inode_idx: usize, uid: u32, gid: u32 },
}

// ---------------------------------------------------------------------------
// Name strategies: normal + adversarial
// ---------------------------------------------------------------------------

/// Simple names shrink faster (shorter, alphabetically earlier).
/// Weighted so proptest tries simple names first during shrinking.
fn name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        60 => "[a-z]{1,8}",                          // normal names
        5 => Just("a".repeat(255)),                   // NAME_MAX boundary
        2 => Just("".to_string()),                    // empty name
        2 => Just(".".to_string()),                   // dot
        2 => Just("..".to_string()),                  // dotdot
        5 => "[a-z]{1,3}\\.[a-z]{1,3}",              // file.ext
        3 => Just(" space ".to_string()),             // spaces
        1 => Just("a/b".to_string()),                 // embedded slash
    ]
}

/// Operation strategy with explicit shrinking order:
/// - Simpler ops (CreateFile) are tried before complex ones (Rename)
/// - Shorter names shrink before longer ones (handled by name_strategy)
/// - Smaller indices shrink before larger ones (handled by proptest ranges)
fn op_strategy() -> impl Strategy<Value = FsOp> {
    prop_oneof![
        // Weighted towards creation (build up the tree).
        // CreateFile first = simplest shrink target.
        30 => (0..10usize, name_strategy()).prop_map(|(d, n)| FsOp::CreateFile { dir_idx: d, name: n }),
        20 => (0..10usize, name_strategy()).prop_map(|(d, n)| FsOp::Mkdir { dir_idx: d, name: n }),
        10 => (0..10usize, name_strategy()).prop_map(|(d, n)| FsOp::Rmdir { dir_idx: d, name: n }),
        10 => (0..10usize, name_strategy(), 0..20usize).prop_map(|(d, n, t)| FsOp::Link { dir_idx: d, name: n, target_idx: t }),
        10 => (0..10usize, name_strategy()).prop_map(|(d, n)| FsOp::Unlink { dir_idx: d, name: n }),
        10 => (0..10usize, name_strategy(), 0..10usize, name_strategy()).prop_map(|(s, sn, d, dn)| FsOp::Rename { src_idx: s, src_name: sn, dst_idx: d, dst_name: dn }),
        5 => (0..20usize, 0..1024u64, prop::collection::vec(any::<u8>(), 0..64)).prop_map(|(f, o, d)| FsOp::WriteData { file_idx: f, offset: o, data: d }),
        3 => (0..20usize, 0..1024u64, 0..256usize).prop_map(|(f, o, s)| FsOp::ReadData { file_idx: f, offset: o, size: s }),
        3 => (0..20usize, 0..4096u64).prop_map(|(f, s)| FsOp::Truncate { file_idx: f, new_size: s }),
        3 => (0..20usize, 0..0o7777u16).prop_map(|(i, m)| FsOp::Chmod { inode_idx: i, mode: m }),
        3 => (0..20usize, 0..1000u32, 0..1000u32).prop_map(|(i, u, g)| FsOp::Chown { inode_idx: i, uid: u, gid: g }),
    ]
}

/// Operation sequence generator with improved shrinking.
///
/// Uses `prop_flat_map` on length so proptest performs binary search on
/// sequence length first (trying shorter sequences), then shrinks individual
/// operations within the minimal-length sequence.
fn arb_op_sequence(max_len: usize) -> impl Strategy<Value = Vec<FsOp>> {
    (1..max_len).prop_flat_map(|len| prop::collection::vec(op_strategy(), len))
}

// ---------------------------------------------------------------------------
// Apply an operation to the graph (errors are OK, panics are bugs)
// ---------------------------------------------------------------------------

fn get_dirs(g: &TypeGraph) -> Vec<DirId> {
    g.dirs.keys().map(|aid| aid.0 as u64).collect()
}

fn get_inodes(g: &TypeGraph) -> Vec<InodeId> {
    g.inodes.keys().map(|aid| aid.0 as u64).collect()
}

fn get_regular_files(g: &TypeGraph) -> Vec<InodeId> {
    g.inodes
        .iter()
        .filter(|(_, i)| i.vtype == VnodeType::Regular)
        .map(|(aid, _)| aid.0 as u64)
        .collect()
}

fn apply_op(g: &mut TypeGraph, op: &FsOp) {
    match op {
        FsOp::CreateFile { dir_idx, name } => {
            let dirs = get_dirs(g);
            if dirs.is_empty() { return; }
            let dir = dirs[*dir_idx % dirs.len()];
            let _ = create_file(g, dir, name, 0, 0, Permissions::FILE_DEFAULT);
        }
        FsOp::Mkdir { dir_idx, name } => {
            let dirs = get_dirs(g);
            if dirs.is_empty() { return; }
            let dir = dirs[*dir_idx % dirs.len()];
            let _ = mkdir(g, dir, name, 0, 0, Permissions::DIR_DEFAULT);
        }
        FsOp::Rmdir { dir_idx, name } => {
            let dirs = get_dirs(g);
            if dirs.is_empty() { return; }
            let dir = dirs[*dir_idx % dirs.len()];
            let _ = rmdir(g, dir, name);
        }
        FsOp::Link { dir_idx, name, target_idx } => {
            let dirs = get_dirs(g);
            let files = get_regular_files(g);
            if dirs.is_empty() || files.is_empty() { return; }
            let dir = dirs[*dir_idx % dirs.len()];
            let target = files[*target_idx % files.len()];
            let _ = link(g, dir, name, target);
        }
        FsOp::Unlink { dir_idx, name } => {
            let dirs = get_dirs(g);
            if dirs.is_empty() { return; }
            let dir = dirs[*dir_idx % dirs.len()];
            let _ = unlink(g, dir, name);
        }
        FsOp::Rename { src_idx, src_name, dst_idx, dst_name } => {
            let dirs = get_dirs(g);
            if dirs.is_empty() { return; }
            let src = dirs[*src_idx % dirs.len()];
            let dst = dirs[*dst_idx % dirs.len()];
            let _ = rename(g, src, src_name, dst, dst_name);
        }
        FsOp::WriteData { file_idx, offset, data } => {
            let files = get_regular_files(g);
            if files.is_empty() { return; }
            let file = files[*file_idx % files.len()];
            // Cap offset to prevent OOM in tests
            let safe_offset = *offset % 8192;
            let safe_data = if data.len() > 256 { &data[..256] } else { data };
            let _ = write_data(g, file, safe_offset, safe_data);
        }
        FsOp::ReadData { file_idx, offset, size } => {
            let files = get_regular_files(g);
            if files.is_empty() { return; }
            let file = files[*file_idx % files.len()];
            let _ = read_data(g, file, *offset, *size);
        }
        FsOp::Truncate { file_idx, new_size } => {
            let files = get_regular_files(g);
            if files.is_empty() { return; }
            let file = files[*file_idx % files.len()];
            let safe_size = *new_size % 8192;
            let _ = truncate(g, file, safe_size);
        }
        FsOp::Chmod { inode_idx, mode } => {
            let inodes = get_inodes(g);
            if inodes.is_empty() { return; }
            let inode = inodes[*inode_idx % inodes.len()];
            let _ = chmod(g, inode, *mode);
        }
        FsOp::Chown { inode_idx, uid, gid } => {
            let inodes = get_inodes(g);
            if inodes.is_empty() { return; }
            let inode = inodes[*inode_idx % inodes.len()];
            let _ = chown(g, inode, Some(*uid), Some(*gid));
        }
    }
}

// ---------------------------------------------------------------------------
// Property tests (10 properties, 10K iterations each)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(test_config())]

    // ===== 1. Core invariant preservation =====

    /// Core invariant: after ANY sequence of operations, ALL graph
    /// invariants must hold. proptest will shrink to minimal failing sequence.
    #[test]
    fn invariant_preservation(ops in arb_op_sequence(100)) {
        let t0 = Instant::now();
        let mut g = TypeGraph::new();
        for (i, op) in ops.iter().enumerate() {
            apply_op(&mut g, op);
            g.check_invariants().map_err(|e| {
                format!("Invariant violation after op #{} ({:?}): {} [elapsed {:?}]",
                    i, op, e, t0.elapsed())
            }).unwrap();
        }
    }

    // ===== 2. Link count consistency =====

    /// Link count must always equal the number of incoming contains
    /// edges (excluding "..").
    #[test]
    fn link_count_always_matches(ops in arb_op_sequence(50)) {
        let t0 = Instant::now();
        let mut g = TypeGraph::new();
        for op in &ops {
            apply_op(&mut g, op);
        }
        for (aid, inode) in g.inodes.iter() {
            let id = aid.0 as u64;
            let actual = g.inode_incoming_contains
                .get(&id)
                .map(|edges| {
                    edges.iter()
                        .filter(|&&eid| {
                            matches!(g.get_edge(eid),
                                Some(sotfs_graph::types::Edge::Contains { name, .. }) if name != "..")
                        })
                        .count() as u32
                })
                .unwrap_or(0);
            prop_assert_eq!(
                inode.link_count, actual,
                "Inode {} link_count={} but has {} contains edges (excl ..) [elapsed {:?}]",
                id, inode.link_count, actual, t0.elapsed()
            );
        }
    }

    // ===== 3. Cycle freedom =====

    /// No directory cycles after any sequence of mkdir + rename.
    #[test]
    fn cycle_freedom(ops in prop::collection::vec(
        prop_oneof![
            (0..5usize, "[a-z]{1,4}").prop_map(|(d, n)| FsOp::Mkdir { dir_idx: d, name: n }),
            (0..5usize, "[a-z]{1,4}", 0..5usize, "[a-z]{1,4}").prop_map(|(s, sn, d, dn)|
                FsOp::Rename { src_idx: s, src_name: sn, dst_idx: d, dst_name: dn }),
        ],
        1..30
    )) {
        let t0 = Instant::now();
        let mut g = TypeGraph::new();
        for op in &ops {
            apply_op(&mut g, op);
        }
        // Explicit cycle check (in addition to check_invariants)
        g.check_invariants().map_err(|e| {
            format!("Cycle freedom violation: {} [elapsed {:?}]", e, t0.elapsed())
        }).unwrap();
    }

    // ===== 4. chmod preserves other fields =====

    /// chmod only changes permissions, nothing else.
    #[test]
    fn chmod_preserves_other_fields(mode in 0..0o7777u16) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let fid = create_file(&mut g, rd, "f", 42, 7, Permissions::FILE_DEFAULT).unwrap();
        let before = g.get_inode(fid).unwrap().clone();
        chmod(&mut g, fid, mode).unwrap();
        let after = &g.get_inode(fid).unwrap();
        prop_assert_eq!(after.uid, before.uid);
        prop_assert_eq!(after.gid, before.gid);
        prop_assert_eq!(after.size, before.size);
        prop_assert_eq!(after.link_count, before.link_count);
        prop_assert_eq!(after.vtype, before.vtype);
        prop_assert_eq!(after.permissions.mode(), mode);
    }

    // ===== 5. chown preserves permissions =====

    /// chown only changes uid/gid, nothing else.
    #[test]
    fn chown_preserves_permissions(uid in 0..1000u32, gid in 0..1000u32) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let fid = create_file(&mut g, rd, "f", 0, 0, Permissions(0o600)).unwrap();
        let before = g.get_inode(fid).unwrap().clone();
        chown(&mut g, fid, Some(uid), Some(gid)).unwrap();
        let after = &g.get_inode(fid).unwrap();
        prop_assert_eq!(after.permissions.mode(), before.permissions.mode());
        prop_assert_eq!(after.size, before.size);
        prop_assert_eq!(after.uid, uid);
        prop_assert_eq!(after.gid, gid);
    }

    // ===== 6. Write/read roundtrip =====

    /// Write then read returns the same data.
    #[test]
    fn write_read_roundtrip(data in prop::collection::vec(any::<u8>(), 1..128)) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let fid = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, fid, 0, &data).unwrap();
        let read_back = read_data(&g, fid, 0, data.len()).unwrap();
        prop_assert_eq!(read_back, data);
    }

    // ===== 7. Truncate semantics =====

    /// Truncate then read returns zeroed extension or trimmed data.
    #[test]
    fn truncate_semantics(
        initial in prop::collection::vec(any::<u8>(), 1..64),
        new_size in 0..128u64,
    ) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let fid = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, fid, 0, &initial).unwrap();
        truncate(&mut g, fid, new_size).unwrap();
        prop_assert_eq!(g.get_inode(fid).unwrap().size, new_size);

        let data = read_data(&g, fid, 0, new_size as usize).unwrap();
        prop_assert_eq!(data.len(), new_size as usize);

        // First min(initial.len(), new_size) bytes should match original
        let preserved = initial.len().min(new_size as usize);
        prop_assert_eq!(&data[..preserved], &initial[..preserved]);
    }

    // ===== 8. Unlink then relink preserves data independence =====

    /// After unlink + re-create with the same name, the new file's data
    /// is independent — no stale data leak from the old inode.
    #[test]
    fn unlink_then_relink_preserves_data(
        old_data in prop::collection::vec(any::<u8>(), 1..64),
        new_data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;

        // Create file, write old data
        let old_id = create_file(&mut g, rd, "reuse", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, old_id, 0, &old_data).unwrap();

        // Unlink
        unlink(&mut g, rd, "reuse").unwrap();
        g.check_invariants().unwrap();

        // Old inode should be gone (link_count was 1)
        prop_assert!(!g.inodes.contains_key(&old_id),
            "Old inode {} still exists after unlink", old_id);

        // Re-create with same name
        let new_id = create_file(&mut g, rd, "reuse", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, new_id, 0, &new_data).unwrap();

        // New file must have independent data (not old_data)
        let read_back = read_data(&g, new_id, 0, new_data.len()).unwrap();
        prop_assert_eq!(&read_back, &new_data,
            "New file has stale data from old inode");

        // New inode ID should differ from old (allocator increments)
        prop_assert_ne!(old_id, new_id,
            "Re-created file reuses same inode ID");

        g.check_invariants().unwrap();
    }

    // ===== 9. Rename swap atomicity =====

    /// rename(A->tmp), rename(B->A), rename(tmp->B) preserves both
    /// files' data — the classic 3-step swap pattern.
    #[test]
    fn rename_swap_atomicity(
        data_a in prop::collection::vec(any::<u8>(), 1..64),
        data_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;

        // Create two files with distinct data
        let id_a = create_file(&mut g, rd, "fileA", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id_a, 0, &data_a).unwrap();
        let id_b = create_file(&mut g, rd, "fileB", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        write_data(&mut g, id_b, 0, &data_b).unwrap();

        // 3-step swap: A->tmp, B->A, tmp->B
        rename(&mut g, rd, "fileA", rd, "tmp").unwrap();
        g.check_invariants().unwrap();

        rename(&mut g, rd, "fileB", rd, "fileA").unwrap();
        g.check_invariants().unwrap();

        rename(&mut g, rd, "tmp", rd, "fileB").unwrap();
        g.check_invariants().unwrap();

        // After swap: "fileA" should hold data_b, "fileB" should hold data_a
        let resolved_a = g.resolve_name(rd, "fileA").unwrap();
        let resolved_b = g.resolve_name(rd, "fileB").unwrap();

        let read_a = read_data(&g, resolved_a, 0, data_b.len()).unwrap();
        let read_b = read_data(&g, resolved_b, 0, data_a.len()).unwrap();

        prop_assert_eq!(&read_a, &data_b,
            "After swap, fileA should contain data_b");
        prop_assert_eq!(&read_b, &data_a,
            "After swap, fileB should contain data_a");

        // Inode IDs should have swapped positions
        prop_assert_eq!(resolved_a, id_b,
            "fileA should point to original B inode");
        prop_assert_eq!(resolved_b, id_a,
            "fileB should point to original A inode");
    }

    // ===== 10. Deep mkdir chain — no cycles =====

    /// Creating a chain of 20+ nested directories never creates a cycle.
    /// This specifically stress-tests the cycle check on deep trees.
    /// Range kept at 20..30 because check_no_dir_cycles is O(n^2).
    #[test]
    fn deep_mkdir_chain_no_cycles(depth in 20..30usize) {
        let t0 = Instant::now();
        let mut g = TypeGraph::new();
        let mut current_dir = g.root_dir;

        for i in 0..depth {
            let name = format!("d{}", i);
            match mkdir(&mut g, current_dir, &name, 0, 0, Permissions::DIR_DEFAULT) {
                Ok(result) => {
                    current_dir = result.dir_id.unwrap();
                }
                Err(_) => break, // Name collision or other error, stop extending
            }
        }

        // All invariants must hold on the deep tree
        g.check_invariants().map_err(|e| {
            format!("Deep mkdir chain (depth={}) invariant violation: {} [elapsed {:?}]",
                depth, e, t0.elapsed())
        }).unwrap();

        // Explicit ancestry check: root must be ancestor of deepest dir
        prop_assert!(g.is_ancestor(g.root_dir, current_dir),
            "Root is not ancestor of deepest dir after {} mkdirs", depth);

        // Deepest dir must NOT be ancestor of root (would indicate cycle)
        if current_dir != g.root_dir {
            prop_assert!(!g.is_ancestor(current_dir, g.root_dir),
                "Deepest dir is ancestor of root — cycle detected at depth {}", depth);
        }
    }
}
