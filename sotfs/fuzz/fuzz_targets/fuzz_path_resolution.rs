//! Fuzz target: path resolution with arbitrary byte sequences.
//!
//! Feeds random strings to TypeGraph::resolve_path() and resolve_parent().
//! Must never panic — only Ok or Err(GraphError).
//!
//! Run: cd sotfs/fuzz && cargo +nightly fuzz run fuzz_path_resolution -- -runs=500000

#![no_main]

use libfuzzer_sys::fuzz_target;
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::Permissions;

fuzz_target!(|data: &[u8]| {
    // Only test valid UTF-8 paths (FUSE guarantees UTF-8)
    let path = match core::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Skip extremely long paths to keep execution bounded
    if path.len() > 512 {
        return;
    }

    // Build a small graph to have some directories to resolve into
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    let _ = sotfs_ops::mkdir(&mut g, rd, "a", 0, 0, Permissions::DIR_DEFAULT);
    let _ = sotfs_ops::mkdir(&mut g, rd, "b", 0, 0, Permissions::DIR_DEFAULT);
    let _ = sotfs_ops::create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT);

    // These must NEVER panic — only return Ok or Err
    let _ = g.resolve_path(path);
    let _ = g.resolve_parent(path);
});
