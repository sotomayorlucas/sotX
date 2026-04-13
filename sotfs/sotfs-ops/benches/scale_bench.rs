//! Real-world scale benchmarks: characterize treewidth and latency at
//! 10^4, 10^5, 10^6 nodes over realistic filesystem distributions.
//!
//! Three distribution models:
//! - **linux_rootfs**: Wide + shallow (many dirs with 10-50 entries each, depth 3-5)
//! - **node_modules**: Deep nesting (depth 20-50, narrow directories)
//! - **kernel_tree**: Balanced tree (moderate depth 5-8, moderate width 10-30)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops::*;

// ---------------------------------------------------------------------------
// Distribution generators
// ---------------------------------------------------------------------------

/// Build a wide+shallow tree mimicking a Linux rootfs:
/// ~20 top-level dirs, each with ~width files and ~3 subdirs.
fn build_linux_rootfs(target_nodes: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    let mut count = 1; // root inode
    let top_dirs = 20usize.min(target_nodes / 50);
    let files_per_dir = (target_nodes / top_dirs.max(1)).min(200);

    for i in 0..top_dirs {
        if count >= target_nodes { break; }
        let name = format!("d{}", i);
        let sub = mkdir(&mut g, rd, &name, 0, 0, Permissions::DIR_DEFAULT).unwrap();
        count += 1;
        let sd = sub.dir_id.unwrap();

        // Add files to this directory
        for j in 0..files_per_dir {
            if count >= target_nodes { break; }
            let fname = format!("f{}_{}", i, j);
            create_file(&mut g, sd, &fname, 0, 0, Permissions::FILE_DEFAULT).unwrap();
            count += 1;
        }

        // Add 3 subdirs each with some files
        for k in 0..3 {
            if count >= target_nodes { break; }
            let sname = format!("s{}_{}", i, k);
            let ss = mkdir(&mut g, sd, &sname, 0, 0, Permissions::DIR_DEFAULT).unwrap();
            count += 1;
            let ssd = ss.dir_id.unwrap();
            for j in 0..(files_per_dir / 4) {
                if count >= target_nodes { break; }
                let fname = format!("sf{}_{}_{}", i, k, j);
                create_file(&mut g, ssd, &fname, 0, 0, Permissions::FILE_DEFAULT).unwrap();
                count += 1;
            }
        }
    }
    g
}

/// Build a deeply nested tree mimicking node_modules:
/// Many packages nested 10-20 levels deep, narrow (1-5 entries per dir).
fn build_node_modules(target_nodes: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    let nm = mkdir(&mut g, rd, "node_modules", 0, 0, Permissions::DIR_DEFAULT).unwrap();
    let mut count = 2;
    let mut current_dir = nm.dir_id.unwrap();
    let packages = (target_nodes / 25).max(1);

    for pkg in 0..packages {
        if count >= target_nodes { break; }
        // Each package: depth 5-15, 2-4 files per level
        let pname = format!("pkg{}", pkg);
        let p = mkdir(&mut g, current_dir, &pname, 0, 0, Permissions::DIR_DEFAULT).unwrap();
        count += 1;
        let mut pd = p.dir_id.unwrap();

        let depth = 5 + (pkg % 11); // 5 to 15
        for d in 0..depth {
            if count >= target_nodes { break; }
            // Add index.js + package.json at each level
            let f1 = format!("index{}.js", d);
            create_file(&mut g, pd, &f1, 0, 0, Permissions::FILE_DEFAULT).unwrap();
            count += 1;
            if count >= target_nodes { break; }
            let f2 = format!("pkg{}.json", d);
            create_file(&mut g, pd, &f2, 0, 0, Permissions::FILE_DEFAULT).unwrap();
            count += 1;
            if count >= target_nodes { break; }

            // Nest deeper
            let dn = format!("nm{}", d);
            let sub = mkdir(&mut g, pd, &dn, 0, 0, Permissions::DIR_DEFAULT).unwrap();
            count += 1;
            pd = sub.dir_id.unwrap();
        }
        // Reset to node_modules root for next package
        current_dir = nm.dir_id.unwrap();
    }
    g
}

/// Build a balanced tree mimicking a kernel source tree:
/// Moderate depth (5-8), moderate width (10-30 entries per dir).
fn build_kernel_tree(target_nodes: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    let mut count = 1;
    let width = 15;

    fn populate(
        g: &mut TypeGraph,
        dir: DirId,
        count: &mut usize,
        target: usize,
        depth: usize,
        max_depth: usize,
        width: usize,
        prefix: &str,
    ) {
        // Add files at this level
        let files_here = width;
        for i in 0..files_here {
            if *count >= target { return; }
            let name = format!("{}_f{}.c", prefix, i);
            create_file(g, dir, &name, 0, 0, Permissions::FILE_DEFAULT).unwrap();
            *count += 1;
        }

        // Add subdirs if not at max depth
        if depth < max_depth {
            let subdirs = width / 3;
            for i in 0..subdirs {
                if *count >= target { return; }
                let name = format!("{}_d{}", prefix, i);
                let sub = mkdir(g, dir, &name, 0, 0, Permissions::DIR_DEFAULT).unwrap();
                *count += 1;
                populate(g, sub.dir_id.unwrap(), count, target, depth + 1, max_depth, width, &name);
            }
        }
    }

    let max_depth = if target_nodes > 100_000 { 6 } else if target_nodes > 10_000 { 5 } else { 4 };
    populate(&mut g, rd, &mut count, target_nodes, 0, max_depth, width, "k");
    g
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_build_distributions(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_distribution");
    group.sample_size(10);

    for &size in &[1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("linux_rootfs", size),
            &size,
            |b, &n| b.iter(|| build_linux_rootfs(black_box(n))),
        );
        group.bench_with_input(
            BenchmarkId::new("node_modules", size),
            &size,
            |b, &n| b.iter(|| build_node_modules(black_box(n))),
        );
        group.bench_with_input(
            BenchmarkId::new("kernel_tree", size),
            &size,
            |b, &n| b.iter(|| build_kernel_tree(black_box(n))),
        );
    }
    group.finish();
}

fn bench_check_invariants_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_invariants_scale");
    group.sample_size(10);

    for &(name, size) in &[("1K", 1_000), ("10K", 10_000)] {
        let g_rootfs = build_linux_rootfs(size);
        let g_nm = build_node_modules(size);
        let g_kernel = build_kernel_tree(size);

        group.bench_with_input(
            BenchmarkId::new("linux_rootfs", name),
            &g_rootfs,
            |b, g| b.iter(|| g.check_invariants().unwrap()),
        );
        group.bench_with_input(
            BenchmarkId::new("node_modules", name),
            &g_nm,
            |b, g| b.iter(|| g.check_invariants().unwrap()),
        );
        group.bench_with_input(
            BenchmarkId::new("kernel_tree", name),
            &g_kernel,
            |b, g| b.iter(|| g.check_invariants().unwrap()),
        );
    }
    group.finish();
}

fn bench_create_file_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_file_at_scale");
    group.sample_size(10);

    for &(name, size) in &[("1K", 1_000), ("10K", 10_000)] {
        // Pre-build graph, then measure cost of one more create_file
        let base = build_linux_rootfs(size);

        group.bench_with_input(
            BenchmarkId::new("marginal_create", name),
            &base,
            |b, base_g| {
                b.iter_with_setup(
                    || base_g.clone(),
                    |mut g| {
                        let rd = g.root_dir;
                        create_file(&mut g, rd, "bench_file", 0, 0, Permissions::FILE_DEFAULT).unwrap();
                    },
                )
            },
        );
    }
    group.finish();
}

fn bench_fsck_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsck_scale");
    group.sample_size(10);

    for &(name, size) in &[("1K", 1_000), ("10K", 10_000)] {
        let g = build_linux_rootfs(size);
        group.bench_with_input(
            BenchmarkId::new("linux_rootfs", name),
            &g,
            |b, g| b.iter(|| fsck(black_box(g))),
        );
    }
    group.finish();
}

fn bench_export_at_scale(c: &mut Criterion) {
    use sotfs_graph::export::{to_dot, to_d3_json, to_graph_hunter, stats, DotStyle};

    let mut group = c.benchmark_group("export_scale");
    group.sample_size(10);

    for &(name, size) in &[("1K", 1_000), ("5K", 5_000)] {
        let g = build_linux_rootfs(size);

        group.bench_with_input(
            BenchmarkId::new("dot", name),
            &g,
            |b, g| b.iter(|| to_dot(black_box(g), &DotStyle::default())),
        );
        group.bench_with_input(
            BenchmarkId::new("d3_json", name),
            &g,
            |b, g| b.iter(|| to_d3_json(black_box(g))),
        );
        group.bench_with_input(
            BenchmarkId::new("graph_hunter", name),
            &g,
            |b, g| b.iter(|| to_graph_hunter(black_box(g))),
        );
        group.bench_with_input(
            BenchmarkId::new("stats", name),
            &g,
            |b, g| b.iter(|| stats(black_box(g))),
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_build_distributions,
    bench_check_invariants_at_scale,
    bench_create_file_at_scale,
    bench_fsck_at_scale,
    bench_export_at_scale,
);
criterion_main!(benches);
