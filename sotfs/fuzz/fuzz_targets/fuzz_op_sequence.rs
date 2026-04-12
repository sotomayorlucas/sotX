//! Fuzz target: random DPO operation sequences.
//!
//! Generates arbitrary sequences of filesystem operations and applies
//! them to a TypeGraph. After the sequence, check_invariants() must pass.
//! Any invariant violation is a bug.
//!
//! Run: cd sotfs/fuzz && cargo +nightly fuzz run fuzz_op_sequence -- -runs=1000000

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops;

/// Compact operation enum that derives Arbitrary for structured fuzzing.
/// Uses u8 indices to select from existing graph nodes.
#[derive(Debug, Arbitrary)]
enum FuzzOp {
    /// Create a regular file: (parent_dir_index, name_seed)
    Create(u8, u8),
    /// Create a directory: (parent_dir_index, name_seed)
    Mkdir(u8, u8),
    /// Remove a directory: (parent_dir_index, name_seed)
    Rmdir(u8, u8),
    /// Hard link: (dir_index, name_seed, target_file_index)
    Link(u8, u8, u8),
    /// Unlink: (dir_index, name_seed)
    Unlink(u8, u8),
    /// Rename: (src_dir, src_name, dst_dir, dst_name)
    Rename(u8, u8, u8, u8),
    /// Write data: (file_index, offset_lo, data_byte)
    Write(u8, u8, u8),
    /// Truncate: (file_index, new_size_lo)
    Truncate(u8, u8),
    /// Chmod: (inode_index, mode_lo)
    Chmod(u8, u8),
    /// Chown: (inode_index, uid, gid)
    Chown(u8, u8, u8),
}

/// Convert a u8 seed to a valid filename (a-z, 1-4 chars).
fn seed_to_name(seed: u8) -> &'static str {
    const NAMES: [&str; 16] = [
        "a", "b", "c", "d", "e", "f", "g", "h",
        "ab", "cd", "ef", "gh", "ij", "kl", "mn", "op",
    ];
    NAMES[(seed % 16) as usize]
}

fn apply(g: &mut TypeGraph, op: &FuzzOp) {
    let dirs: Vec<DirId> = g.dirs.keys().map(|aid| aid.0 as u64).collect();
    let files: Vec<InodeId> = g
        .inodes
        .iter()
        .filter(|(_, i)| i.vtype == VnodeType::Regular)
        .map(|(aid, _)| aid.0 as u64)
        .collect();
    let all_inodes: Vec<InodeId> = g.inodes.keys().map(|aid| aid.0 as u64).collect();

    match op {
        FuzzOp::Create(di, ns) => {
            if dirs.is_empty() { return; }
            let dir = dirs[(*di as usize) % dirs.len()];
            let _ = sotfs_ops::create_file(
                g, dir, seed_to_name(*ns), 0, 0, Permissions::FILE_DEFAULT,
            );
        }
        FuzzOp::Mkdir(di, ns) => {
            if dirs.is_empty() { return; }
            let dir = dirs[(*di as usize) % dirs.len()];
            let _ = sotfs_ops::mkdir(
                g, dir, seed_to_name(*ns), 0, 0, Permissions::DIR_DEFAULT,
            );
        }
        FuzzOp::Rmdir(di, ns) => {
            if dirs.is_empty() { return; }
            let dir = dirs[(*di as usize) % dirs.len()];
            let _ = sotfs_ops::rmdir(g, dir, seed_to_name(*ns));
        }
        FuzzOp::Link(di, ns, ti) => {
            if dirs.is_empty() || files.is_empty() { return; }
            let dir = dirs[(*di as usize) % dirs.len()];
            let target = files[(*ti as usize) % files.len()];
            let _ = sotfs_ops::link(g, dir, seed_to_name(*ns), target);
        }
        FuzzOp::Unlink(di, ns) => {
            if dirs.is_empty() { return; }
            let dir = dirs[(*di as usize) % dirs.len()];
            let _ = sotfs_ops::unlink(g, dir, seed_to_name(*ns));
        }
        FuzzOp::Rename(si, sn, di, dn) => {
            if dirs.is_empty() { return; }
            let src = dirs[(*si as usize) % dirs.len()];
            let dst = dirs[(*di as usize) % dirs.len()];
            let _ = sotfs_ops::rename(g, src, seed_to_name(*sn), dst, seed_to_name(*dn));
        }
        FuzzOp::Write(fi, off, byte) => {
            if files.is_empty() { return; }
            let file = files[(*fi as usize) % files.len()];
            let _ = sotfs_ops::write_data(g, file, *off as u64, &[*byte; 4]);
        }
        FuzzOp::Truncate(fi, sz) => {
            if files.is_empty() { return; }
            let file = files[(*fi as usize) % files.len()];
            let _ = sotfs_ops::truncate(g, file, *sz as u64);
        }
        FuzzOp::Chmod(ii, mode) => {
            if all_inodes.is_empty() { return; }
            let inode = all_inodes[(*ii as usize) % all_inodes.len()];
            let _ = sotfs_ops::chmod(g, inode, (*mode as u16) & 0o7777);
        }
        FuzzOp::Chown(ii, uid, gid) => {
            if all_inodes.is_empty() { return; }
            let inode = all_inodes[(*ii as usize) % all_inodes.len()];
            let _ = sotfs_ops::chown(g, inode, Some(*uid as u32), Some(*gid as u32));
        }
    }
}

fuzz_target!(|ops: Vec<FuzzOp>| {
    // Limit sequence length to keep execution fast
    let ops = if ops.len() > 50 { &ops[..50] } else { &ops };

    let mut g = TypeGraph::new();
    for op in ops {
        apply(&mut g, op);
    }

    // THE CRITICAL ASSERTION: invariants must hold after ANY sequence
    g.check_invariants()
        .expect("INVARIANT VIOLATION after fuzzed operation sequence");
});
