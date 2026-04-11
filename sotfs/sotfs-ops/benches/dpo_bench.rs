//! Criterion benchmarks for sotFS DPO operations.
//!
//! Measures per-operation latency and throughput at scale.
//! Run: cd sotfs && cargo bench --bench dpo_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;
use sotfs_ops::*;

/// Benchmark: create N files in root directory.
fn bench_create_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_file");
    for n in [100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut g = TypeGraph::new();
                let rd = g.root_dir;
                for i in 0..n {
                    let name = format!("f{}", i);
                    let _ = create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT);
                }
                black_box(&g);
            });
        });
    }
    group.finish();
}

/// Benchmark: create N nested directories (chain).
fn bench_mkdir_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("mkdir_chain");
    for n in [50, 200, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut g = TypeGraph::new();
                let mut current = g.root_dir;
                for i in 0..n {
                    let name = format!("d{}", i);
                    match mkdir(&mut g, current, &name, 0, 0, Permissions::DIR_DEFAULT) {
                        Ok(r) => current = r.dir_id.unwrap(),
                        Err(_) => break,
                    }
                }
                black_box(&g);
            });
        });
    }
    group.finish();
}

/// Benchmark: create N files then unlink all of them.
fn bench_unlink(c: &mut Criterion) {
    let mut group = c.benchmark_group("unlink");
    for n in [100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut g = TypeGraph::new();
                let rd = g.root_dir;
                let mut names = Vec::new();
                for i in 0..n {
                    let name = format!("f{}", i);
                    let _ = create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT);
                    names.push(name);
                }
                for name in &names {
                    let _ = unlink(&mut g, rd, name);
                }
                black_box(&g);
            });
        });
    }
    group.finish();
}

/// Benchmark: rename N files within the same directory.
fn bench_rename_same_dir(c: &mut Criterion) {
    let mut group = c.benchmark_group("rename_same_dir");
    for n in [100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut g = TypeGraph::new();
                let rd = g.root_dir;
                for i in 0..n {
                    let name = format!("f{}", i);
                    let _ = create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT);
                }
                for i in 0..n {
                    let old = format!("f{}", i);
                    let new = format!("r{}", i);
                    let _ = rename(&mut g, rd, &old, rd, &new);
                }
                black_box(&g);
            });
        });
    }
    group.finish();
}

/// Benchmark: hard-link a file N times.
fn bench_hard_links(c: &mut Criterion) {
    let mut group = c.benchmark_group("hard_link");
    for n in [10, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut g = TypeGraph::new();
                let rd = g.root_dir;
                let fid = create_file(&mut g, rd, "target", 0, 0, Permissions::FILE_DEFAULT).unwrap();
                for i in 0..n {
                    let name = format!("link{}", i);
                    let _ = link(&mut g, rd, &name, fid);
                }
                black_box(&g);
            });
        });
    }
    group.finish();
}

/// Benchmark: write + read data at various sizes.
fn bench_write_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_read");
    for size in [64, 1024, 4096, 65536] {
        group.bench_with_input(BenchmarkId::new("write", size), &size, |b, &size| {
            let data = vec![0xABu8; size];
            b.iter(|| {
                let mut g = TypeGraph::new();
                let rd = g.root_dir;
                let fid = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
                write_data(&mut g, fid, 0, &data).unwrap();
                black_box(&g);
            });
        });
        group.bench_with_input(BenchmarkId::new("read", size), &size, |b, &size| {
            let data = vec![0xABu8; size];
            let mut g = TypeGraph::new();
            let rd = g.root_dir;
            let fid = create_file(&mut g, rd, "f", 0, 0, Permissions::FILE_DEFAULT).unwrap();
            write_data(&mut g, fid, 0, &data).unwrap();
            b.iter(|| {
                let result = read_data(&g, fid, 0, size).unwrap();
                black_box(result);
            });
        });
    }
    group.finish();
}

/// Benchmark: check_invariants at various graph sizes.
fn bench_invariant_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_invariants");
    for n in [10, 100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut g = TypeGraph::new();
            let rd = g.root_dir;
            for i in 0..n {
                let name = format!("f{}", i);
                let _ = create_file(&mut g, rd, &name, 0, 0, Permissions::FILE_DEFAULT);
            }
            b.iter(|| {
                g.check_invariants().unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_create_files,
    bench_mkdir_chain,
    bench_unlink,
    bench_rename_same_dir,
    bench_hard_links,
    bench_write_read,
    bench_invariant_check,
);
criterion_main!(benches);
