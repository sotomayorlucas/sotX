//! Criterion benchmarks for WAL hash index vs linear scan.
//!
//! The WalIndex data structure lives in `sotos-objstore` (no_std), so
//! we duplicate its pure-logic implementation here for benchmarking on
//! the host. The canonical source of truth remains `libs/sotos-objstore/src/wal.rs`.
//!
//! Run: cd sotfs && cargo bench --bench wal_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

// ---------------------------------------------------------------------------
// FNV-1a hash (mirror of sotos-objstore/src/wal.rs)
// ---------------------------------------------------------------------------

const fn fnv1a(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < key.len() {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

const fn hash_sector(sector: u32) -> u64 {
    let bytes = sector.to_le_bytes();
    fnv1a(&bytes)
}

// ---------------------------------------------------------------------------
// WalIndex (mirror of sotos-objstore/src/wal.rs)
// ---------------------------------------------------------------------------

const WAL_INDEX_CAPACITY: usize = 256;
const EMPTY_HASH: u64 = 0;

struct WalIndex {
    buckets: [(u64, u32); WAL_INDEX_CAPACITY],
    len: usize,
}

impl WalIndex {
    fn new() -> Self {
        Self {
            buckets: [(EMPTY_HASH, 0); WAL_INDEX_CAPACITY],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        for i in 0..WAL_INDEX_CAPACITY {
            self.buckets[i] = (EMPTY_HASH, 0);
        }
    }

    fn insert(&mut self, key_hash: u64, offset: u32) {
        let h = if key_hash == EMPTY_HASH { key_hash.wrapping_add(1) } else { key_hash };
        let start = (h as usize) & (WAL_INDEX_CAPACITY - 1);
        let mut idx = start;
        loop {
            if self.buckets[idx].0 == EMPTY_HASH {
                self.buckets[idx] = (h, offset);
                self.len += 1;
                return;
            }
            if self.buckets[idx].0 == h {
                self.buckets[idx].1 = offset;
                return;
            }
            idx = (idx + 1) & (WAL_INDEX_CAPACITY - 1);
            if idx == start { return; }
        }
    }

    fn lookup(&self, key_hash: u64) -> Option<u32> {
        let h = if key_hash == EMPTY_HASH { key_hash.wrapping_add(1) } else { key_hash };
        let start = (h as usize) & (WAL_INDEX_CAPACITY - 1);
        let mut idx = start;
        loop {
            if self.buckets[idx].0 == EMPTY_HASH { return None; }
            if self.buckets[idx].0 == h { return Some(self.buckets[idx].1); }
            idx = (idx + 1) & (WAL_INDEX_CAPACITY - 1);
            if idx == start { return None; }
        }
    }
}

// ---------------------------------------------------------------------------
// Simulated WAL (simplified, no I/O)
// ---------------------------------------------------------------------------

const WAL_MAX_ENTRIES_SIM: usize = 1024; // Larger than real WAL for benchmark scaling.

struct SimWal {
    targets: Vec<u32>,
    index: WalIndex,
}

impl SimWal {
    fn new() -> Self {
        Self {
            targets: Vec::new(),
            index: WalIndex::new(),
        }
    }

    fn begin(&mut self) {
        self.targets.clear();
        self.index.clear();
    }

    fn stage(&mut self, sector: u32) {
        let offset = self.targets.len() as u32;
        self.targets.push(sector);
        self.index.insert(hash_sector(sector), offset);
    }

    /// O(1) indexed lookup.
    fn lookup_indexed(&self, sector: u32) -> Option<usize> {
        let h = hash_sector(sector);
        if let Some(offset) = self.index.lookup(h) {
            let off = offset as usize;
            if off < self.targets.len() && self.targets[off] == sector {
                return Some(off);
            }
        }
        None
    }

    /// O(n) linear scan lookup.
    fn lookup_linear(&self, sector: u32) -> Option<usize> {
        for (i, &t) in self.targets.iter().enumerate() {
            if t == sector {
                return Some(i);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmark: linear-scan WAL lookup at various entry counts.
fn bench_wal_lookup_linear(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal_lookup_linear");
    for n in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut wal = SimWal::new();
            wal.begin();
            for i in 0..n {
                wal.stage(i as u32 * 7 + 134); // realistic sector offsets
            }
            // Lookup the last entry (worst case for linear scan).
            let target = (n as u32 - 1) * 7 + 134;
            b.iter(|| {
                black_box(wal.lookup_linear(black_box(target)));
            });
        });
    }
    group.finish();
}

/// Benchmark: indexed WAL lookup at various entry counts.
fn bench_wal_lookup_indexed(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal_lookup_indexed");
    for n in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut wal = SimWal::new();
            wal.begin();
            for i in 0..n {
                wal.stage(i as u32 * 7 + 134);
            }
            let target = (n as u32 - 1) * 7 + 134;
            b.iter(|| {
                black_box(wal.lookup_indexed(black_box(target)));
            });
        });
    }
    group.finish();
}

/// Benchmark: DPO-like operation sequence with indexed WAL.
///
/// Simulates the pattern from the DPO benchmarks: a sequence of
/// metadata commits, each staging 2 sectors (superblock + dir entry),
/// with a lookup before each stage to check for duplicates.
fn bench_dpo_sequence_indexed(c: &mut Criterion) {
    let mut group = c.benchmark_group("dpo_sequence_indexed");
    for n in [10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut wal = SimWal::new();
                for op in 0..n {
                    wal.begin();
                    // Each DPO op stages superblock (sector 0) + a dir sector.
                    let dir_sector = 134 + (op as u32 % 2048);
                    wal.stage(0); // superblock
                    wal.stage(dir_sector);
                    // Lookup both to simulate read-through.
                    black_box(wal.lookup_indexed(0));
                    black_box(wal.lookup_indexed(dir_sector));
                }
                black_box(&wal);
            });
        });
    }
    group.finish();
}

/// Benchmark: DPO-like sequence with linear scan (for comparison).
fn bench_dpo_sequence_linear(c: &mut Criterion) {
    let mut group = c.benchmark_group("dpo_sequence_linear");
    for n in [10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut wal = SimWal::new();
                for op in 0..n {
                    wal.begin();
                    let dir_sector = 134 + (op as u32 % 2048);
                    wal.stage(0);
                    wal.stage(dir_sector);
                    black_box(wal.lookup_linear(0));
                    black_box(wal.lookup_linear(dir_sector));
                }
                black_box(&wal);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_wal_lookup_linear,
    bench_wal_lookup_indexed,
    bench_dpo_sequence_indexed,
    bench_dpo_sequence_linear,
);
criterion_main!(benches);
