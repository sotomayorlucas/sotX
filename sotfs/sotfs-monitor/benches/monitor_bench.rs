//! Criterion benchmarks for sotFS structural monitors.
//!
//! Measures treewidth computation and curvature computation at scale.
//! These expose the O(n²) and O(E·V) scaling characteristics.
//!
//! Run: cd sotfs && cargo bench --bench monitor_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops::*;
use sotfs_monitor::{treewidth, curvature};

/// Build a graph with N files in root (star topology).
fn build_star(n: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    for i in 0..n {
        let name = format!("f{}", i);
        let _ = create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT);
    }
    g
}

/// Build a graph with N nested directories (chain topology).
fn build_chain(n: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let mut current = g.root_dir;
    for i in 0..n {
        let name = format!("d{}", i);
        match mkdir(&mut g, current, &name, 0, 0, Permissions::DIR_DEFAULT) {
            Ok(r) => current = r.dir_id.unwrap(),
            Err(_) => break,
        }
    }
    g
}

/// Build a mixed tree: 3 levels, N dirs at each level with 2 files each.
fn build_tree(breadth: usize) -> TypeGraph {
    let mut g = TypeGraph::new();
    let rd = g.root_dir;
    for i in 0..breadth {
        let dname = format!("d{}", i);
        if let Ok(d) = mkdir(&mut g, rd, &dname, 0, 0, Permissions::DIR_DEFAULT) {
            let dd = d.dir_id.unwrap();
            let _ = create_file(&mut g, dd, "a", 0, 0, Permissions::FILE_DEFAULT);
            let _ = create_file(&mut g, dd, "b", 0, 0, Permissions::FILE_DEFAULT);
            for j in 0..breadth.min(5) {
                let sdname = format!("s{}", j);
                if let Ok(sd) = mkdir(&mut g, dd, &sdname, 0, 0, Permissions::DIR_DEFAULT) {
                    let sdd = sd.dir_id.unwrap();
                    let _ = create_file(&mut g, sdd, "x", 0, 0, Permissions::FILE_DEFAULT);
                }
            }
        }
    }
    g
}

/// Benchmark: compute_treewidth at various graph sizes.
fn bench_treewidth(c: &mut Criterion) {
    let mut group = c.benchmark_group("treewidth");

    // Star topology (all files in root)
    for n in [50, 100, 200, 500] {
        let g = build_star(n);
        group.bench_with_input(BenchmarkId::new("star", n), &g, |b, g| {
            b.iter(|| black_box(treewidth::compute_treewidth(g)));
        });
    }

    // Chain topology (nested dirs)
    for n in [50, 100, 200] {
        let g = build_chain(n);
        group.bench_with_input(BenchmarkId::new("chain", n), &g, |b, g| {
            b.iter(|| black_box(treewidth::compute_treewidth(g)));
        });
    }

    // Tree topology
    for breadth in [5, 10, 20] {
        let g = build_tree(breadth);
        let label = format!("tree_b{}", breadth);
        group.bench_with_input(BenchmarkId::new(&label, breadth), &g, |b, g| {
            b.iter(|| black_box(treewidth::compute_treewidth(g)));
        });
    }

    group.finish();
}

/// Benchmark: compute_curvatures at various graph sizes.
fn bench_curvature(c: &mut Criterion) {
    let mut group = c.benchmark_group("curvature");

    for n in [50, 100, 200, 500] {
        let g = build_star(n);
        group.bench_with_input(BenchmarkId::new("star", n), &g, |b, g| {
            b.iter(|| black_box(curvature::compute_curvatures(g)));
        });
    }

    for n in [50, 100, 200] {
        let g = build_chain(n);
        group.bench_with_input(BenchmarkId::new("chain", n), &g, |b, g| {
            b.iter(|| black_box(curvature::compute_curvatures(g)));
        });
    }

    group.finish();
}

/// Benchmark: check_treewidth (compute + compare against limit).
fn bench_treewidth_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("treewidth_check");
    for n in [100, 500] {
        let g = build_star(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &g, |b, g| {
            b.iter(|| {
                let result = treewidth::check_treewidth(g, 10);
                black_box(result);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_treewidth,
    bench_curvature,
    bench_treewidth_check,
);
criterion_main!(benches);
