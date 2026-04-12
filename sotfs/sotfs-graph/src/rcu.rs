//! # Epoch-based RCU (Read-Copy-Update) for the sotFS TypeGraph
//!
//! Provides lock-free reads for directory operations (lookup, readdir, stat,
//! path resolution) while writers mutate a shadow copy and swap atomically.
//!
//! ## Design
//!
//! Two heap-allocated copies of the TypeGraph are maintained. An atomic
//! `active` index tells readers which copy is current. Writers:
//!   1. Acquire the write lock (single-writer)
//!   2. Clone active -> inactive
//!   3. Mutate the inactive copy
//!   4. Swap `active` (atomic store with Release)
//!   5. Wait for all readers to leave the old epoch (rcu_synchronize)
//!   6. Release write lock
//!
//! Readers bump a per-slot epoch counter on entry and clear it on exit.
//! Graph copies are `Box`-allocated on the heap because each `TypeGraph`
//! contains ~35 MB of arena storage (too large for any thread stack).

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::graph::TypeGraph;

/// Maximum concurrent readers. Fixed at compile time for no_alloc.
pub const MAX_READERS: usize = 8;

/// Sentinel value indicating a reader slot is not active.
const EPOCH_INACTIVE: u64 = 0;

/// Epoch-based RCU wrapper around two `TypeGraph` copies.
///
/// Readers get lock-free access to the active graph via `read()`.
/// Writers get exclusive mutable access to a shadow copy via `write()`,
/// which is swapped in atomically after mutation completes.
///
/// Both graph copies live on the heap (`Box`) to avoid stack overflow —
/// each `TypeGraph` contains ~35 MB of arena-backed node/edge pools.
pub struct RcuGraph {
    /// Two heap-allocated copies of the graph. Readers see `graphs[active]`,
    /// writer mutates `graphs[1 - active]`. Wrapped in `UnsafeCell` for
    /// interior mutability — the write lock ensures exclusive access.
    graphs: UnsafeCell<[Box<TypeGraph>; 2]>,

    /// Index (0 or 1) of the graph copy currently visible to readers.
    active: AtomicUsize,

    /// Global epoch counter, incremented by each `rcu_read_lock`.
    global_epoch: AtomicU64,

    /// Per-reader epoch stamps. A non-zero value means the reader entered
    /// at that epoch and has not yet exited.
    reader_epochs: [AtomicU64; MAX_READERS],

    /// Single-writer exclusion flag. Only one `write()` at a time.
    write_locked: AtomicBool,
}

impl RcuGraph {
    /// Create a new RCU-protected graph pair, both initialized via `TypeGraph::new()`.
    pub fn new() -> Self {
        Self {
            graphs: UnsafeCell::new([
                TypeGraph::new_boxed(),
                TypeGraph::new_boxed(),
            ]),
            active: AtomicUsize::new(0),
            global_epoch: AtomicU64::new(1), // start at 1; 0 is INACTIVE sentinel
            reader_epochs: [
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
            ],
            write_locked: AtomicBool::new(false),
        }
    }

    /// Create an RCU-protected graph from an existing boxed `TypeGraph`.
    /// Both copies are initialized to clones of the provided graph.
    /// Takes `Box<TypeGraph>` to avoid placing ~35 MB on the stack.
    pub fn from_graph(g: Box<TypeGraph>) -> Self {
        let g2 = g.clone_boxed();
        Self {
            graphs: UnsafeCell::new([g, g2]),
            active: AtomicUsize::new(0),
            global_epoch: AtomicU64::new(1),
            reader_epochs: [
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
                AtomicU64::new(EPOCH_INACTIVE),
            ],
            write_locked: AtomicBool::new(false),
        }
    }

    // -----------------------------------------------------------------------
    // Reader API (lock-free)
    // -----------------------------------------------------------------------

    /// Execute a read-only closure against the current active graph.
    ///
    /// Multiple readers can execute concurrently without blocking each other.
    /// The closure receives an immutable reference to the `TypeGraph`.
    ///
    /// # Panics
    ///
    /// Panics if all `MAX_READERS` slots are occupied (extremely unlikely
    /// with 8 slots in a microkernel environment).
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&TypeGraph) -> R,
    {
        let slot = self.rcu_read_lock();
        // Acquire: ensures we see the latest `active` written by a writer's Release store.
        let idx = self.active.load(Ordering::Acquire);
        // SAFETY: readers only access the active copy; the write lock ensures
        // the inactive copy is never read concurrently with a writer.
        let result = f(unsafe { &*(*self.graphs.get())[idx] });
        self.rcu_read_unlock(slot);
        result
    }

    /// Register as an active reader. Returns the slot index used.
    fn rcu_read_lock(&self) -> usize {
        let epoch = self.global_epoch.fetch_add(1, Ordering::Relaxed) + 1;

        // Find a free slot (EPOCH_INACTIVE == 0).
        for i in 0..MAX_READERS {
            if self
                .reader_epochs[i]
                .compare_exchange(
                    EPOCH_INACTIVE,
                    epoch,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return i;
            }
        }

        // All slots occupied. In a real microkernel this would be unreachable
        // with MAX_READERS >= number of CPUs. Panic is acceptable here.
        panic!("RcuGraph: all {} reader slots occupied", MAX_READERS);
    }

    /// Deregister a reader, freeing its slot.
    fn rcu_read_unlock(&self, slot: usize) {
        self.reader_epochs[slot].store(EPOCH_INACTIVE, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // Writer API (exclusive, copy-on-write)
    // -----------------------------------------------------------------------

    /// Execute a mutating closure against a shadow copy of the graph,
    /// then atomically swap it in as the active copy.
    ///
    /// Only one writer can be active at a time (spin-waits on the write lock).
    /// After swapping, the writer waits for all pre-swap readers to finish
    /// before returning (grace period).
    pub fn write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut TypeGraph) -> R,
    {
        self.acquire_write_lock();

        let current = self.active.load(Ordering::Acquire);
        let inactive = 1 - current;

        // Snapshot the epoch BEFORE we start the grace period later.
        let pre_swap_epoch = self.global_epoch.load(Ordering::Acquire);

        // Clone active -> inactive (copy phase of RCU).
        // SAFETY: We hold the write lock, so no other writer is touching inactive.
        // Readers only access `graphs[current]`, never `graphs[inactive]`.
        // Use clone_boxed() for heap-to-heap clone (avoids 35 MB stack temp).
        let graphs = self.graphs.get();
        let cloned: Box<TypeGraph> = unsafe { (*graphs)[current].clone_boxed() };
        unsafe {
            // Drop old inactive, replace with cloned copy.
            core::ptr::write(&mut (*graphs)[inactive], cloned);
        }

        // Mutate the inactive copy (update phase).
        let inactive_mut: &mut TypeGraph = unsafe { &mut *(*graphs)[inactive] };
        let result = f(inactive_mut);

        // Swap: make the mutated copy visible to new readers.
        self.active.store(inactive, Ordering::Release);

        // Grace period: wait for all readers that entered BEFORE the swap
        // to finish. Any reader that entered after the swap already sees
        // the new copy.
        self.rcu_synchronize(pre_swap_epoch);

        self.release_write_lock();
        result
    }

    /// Wait until all readers that were active before the swap have exited.
    ///
    /// A reader with `epoch <= pre_swap_epoch` was reading the old copy.
    /// We spin until all such readers have cleared their slots.
    fn rcu_synchronize(&self, pre_swap_epoch: u64) {
        loop {
            let mut all_clear = true;
            for i in 0..MAX_READERS {
                let e = self.reader_epochs[i].load(Ordering::Acquire);
                if e != EPOCH_INACTIVE && e <= pre_swap_epoch {
                    all_clear = false;
                    break;
                }
            }
            if all_clear {
                return;
            }
            // Yield to avoid busy-spin. In no_std kernel, this would be
            // `core::hint::spin_loop()`. In std tests, same effect.
            core::hint::spin_loop();
        }
    }

    /// Spin-acquire the single-writer lock.
    fn acquire_write_lock(&self) {
        loop {
            if self
                .write_locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Release the single-writer lock.
    fn release_write_lock(&self) {
        self.write_locked.store(false, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // Direct access for initialization / single-threaded setup
    // -----------------------------------------------------------------------

    /// Get a mutable reference to the active graph.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent readers or writers exist.
    /// Intended for single-threaded initialization only.
    pub unsafe fn active_mut(&self) -> &mut TypeGraph {
        let idx = self.active.load(Ordering::Relaxed);
        &mut *(*self.graphs.get())[idx]
    }

    /// Get an immutable reference to the active graph (non-RCU, for tests).
    pub fn active_ref(&self) -> &TypeGraph {
        let idx = self.active.load(Ordering::Acquire);
        unsafe { &*(*self.graphs.get())[idx] }
    }
}

// SAFETY: RcuGraph uses only atomic operations for synchronization.
// The interior mutability in `write()` is protected by the write lock +
// reader epoch tracking (grace period).
unsafe impl Sync for RcuGraph {}
unsafe impl Send for RcuGraph {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::TypeGraph;
    use crate::types::*;

    #[cfg(feature = "std")]
    use std::sync::Arc;

    #[test]
    fn new_rcu_graph_satisfies_invariants() {
        let rcu = RcuGraph::new();
        rcu.read(|g| {
            g.check_invariants().unwrap();
            assert_eq!(g.inodes.len(), 1);
            assert_eq!(g.dirs.len(), 1);
        });
    }

    #[test]
    fn read_after_write_sees_new_state() {
        let rcu = RcuGraph::new();

        // Initially: root has 1 inode
        rcu.read(|g| {
            assert_eq!(g.inodes.len(), 1);
        });

        // Write: add a file inode
        rcu.write(|g| {
            let inode_id = g.alloc_inode_id();
            let edge_id = g.alloc_edge_id();
            let mut inode = Inode::new_file(inode_id, Permissions::FILE_DEFAULT, 0, 0);
            inode.link_count = 1;
            g.insert_inode(inode_id, inode);

            let edge = Edge::Contains {
                id: edge_id,
                src: g.root_dir,
                tgt: inode_id,
                name: "test.txt".into(),
            };
            g.insert_edge(edge_id, edge);
            g.dir_contains
                .entry(g.root_dir)
                .or_default()
                .insert(edge_id);
            g.inode_incoming_contains
                .entry(inode_id)
                .or_default()
                .insert(edge_id);
        });

        // Read after write: should see 2 inodes
        rcu.read(|g| {
            assert_eq!(g.inodes.len(), 2);
            let resolved = g.resolve_name(g.root_dir, "test.txt");
            assert!(resolved.is_some());
            g.check_invariants().unwrap();
        });
    }

    #[test]
    fn write_preserves_invariants() {
        let rcu = RcuGraph::new();

        // Perform a series of writes, checking invariants after each
        for i in 0..5 {
            let name_str: String = {
                #[cfg(feature = "std")]
                { format!("file_{}", i) }
                #[cfg(not(feature = "std"))]
                {
                    use alloc::format;
                    format!("file_{}", i)
                }
            };

            rcu.write(|g| {
                let inode_id = g.alloc_inode_id();
                let edge_id = g.alloc_edge_id();
                let mut inode = Inode::new_file(inode_id, Permissions::FILE_DEFAULT, 0, 0);
                inode.link_count = 1;
                g.insert_inode(inode_id, inode);

                let edge = Edge::Contains {
                    id: edge_id,
                    src: g.root_dir,
                    tgt: inode_id,
                    name: name_str.clone(),
                };
                g.insert_edge(edge_id, edge);
                g.dir_contains
                    .entry(g.root_dir)
                    .or_default()
                    .insert(edge_id);
                g.inode_incoming_contains
                    .entry(inode_id)
                    .or_default()
                    .insert(edge_id);
            });

            rcu.read(|g| {
                g.check_invariants().unwrap();
            });
        }

        rcu.read(|g| {
            // root inode + 5 files = 6
            assert_eq!(g.inodes.len(), 6);
        });
    }

    #[test]
    fn from_graph_preserves_state() {
        let mut g = TypeGraph::new_boxed();
        let inode_id = g.alloc_inode_id();
        let edge_id = g.alloc_edge_id();
        let mut inode = Inode::new_file(inode_id, Permissions::FILE_DEFAULT, 0, 0);
        inode.link_count = 1;
        g.insert_inode(inode_id, inode);
        let edge = Edge::Contains {
            id: edge_id,
            src: g.root_dir,
            tgt: inode_id,
            name: "existing.txt".into(),
        };
        g.insert_edge(edge_id, edge);
        g.dir_contains
            .entry(g.root_dir)
            .or_default()
            .insert(edge_id);
        g.inode_incoming_contains
            .entry(inode_id)
            .or_default()
            .insert(edge_id);

        let rcu = RcuGraph::from_graph(g);
        rcu.read(|g| {
            assert_eq!(g.inodes.len(), 2);
            assert!(g.resolve_name(g.root_dir, "existing.txt").is_some());
            g.check_invariants().unwrap();
        });
    }

    #[test]
    fn multiple_sequential_reads_dont_block() {
        let rcu = RcuGraph::new();

        // Multiple reads in sequence should all succeed
        for _ in 0..100 {
            rcu.read(|g| {
                assert_eq!(g.root_dir, 1);
            });
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn concurrent_readers_dont_block_each_other() {
        let rcu = Arc::new(RcuGraph::new());
        let mut handles = Vec::new();

        // Spawn 4 reader threads
        for _ in 0..4 {
            let rcu_clone = Arc::clone(&rcu);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    rcu_clone.read(|g| {
                        assert_eq!(g.inodes.len(), 1);
                        let _ = g.resolve_name(g.root_dir, ".");
                    });
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn writer_waits_for_readers() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let rcu = Arc::new(RcuGraph::new());
        let reader_started = Arc::new(AtomicBool::new(false));
        let reader_done = Arc::new(AtomicBool::new(false));

        // Start a reader that holds the read lock for a while
        let rcu_r = Arc::clone(&rcu);
        let rs = Arc::clone(&reader_started);
        let rd = Arc::clone(&reader_done);
        let reader_handle = std::thread::spawn(move || {
            rcu_r.read(|g| {
                rs.store(true, Ordering::Release);
                assert_eq!(g.inodes.len(), 1);
                // Hold the read lock for a bit
                std::thread::sleep(Duration::from_millis(50));
                rd.store(true, Ordering::Release);
            });
        });

        // Wait for reader to start
        while !reader_started.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        // Writer should complete (it copies + swaps, then waits for the
        // reader during synchronize). The reader will finish eventually.
        let rcu_w = Arc::clone(&rcu);
        let write_handle = std::thread::spawn(move || {
            rcu_w.write(|g| {
                let inode_id = g.alloc_inode_id();
                let edge_id = g.alloc_edge_id();
                let mut inode = Inode::new_file(inode_id, Permissions::FILE_DEFAULT, 0, 0);
                inode.link_count = 1;
                g.insert_inode(inode_id, inode);
                let edge = Edge::Contains {
                    id: edge_id,
                    src: g.root_dir,
                    tgt: inode_id,
                    name: "written.txt".into(),
                };
                g.insert_edge(edge_id, edge);
                g.dir_contains
                    .entry(g.root_dir)
                    .or_default()
                    .insert(edge_id);
                g.inode_incoming_contains
                    .entry(inode_id)
                    .or_default()
                    .insert(edge_id);
            });
        });

        reader_handle.join().unwrap();
        write_handle.join().unwrap();

        // After both complete, new state is visible
        rcu.read(|g| {
            assert_eq!(g.inodes.len(), 2);
            g.check_invariants().unwrap();
        });
    }

    #[cfg(feature = "std")]
    #[test]
    fn concurrent_readers_with_writer() {
        let rcu = Arc::new(RcuGraph::new());
        let mut handles = Vec::new();

        // Writer thread
        let rcu_w = Arc::clone(&rcu);
        handles.push(std::thread::spawn(move || {
            for i in 0..20 {
                let name = format!("f{}", i);
                rcu_w.write(|g| {
                    let inode_id = g.alloc_inode_id();
                    let edge_id = g.alloc_edge_id();
                    let mut inode =
                        Inode::new_file(inode_id, Permissions::FILE_DEFAULT, 0, 0);
                    inode.link_count = 1;
                    g.insert_inode(inode_id, inode);
                    let edge = Edge::Contains {
                        id: edge_id,
                        src: g.root_dir,
                        tgt: inode_id,
                        name: name.clone(),
                    };
                    g.insert_edge(edge_id, edge);
                    g.dir_contains
                        .entry(g.root_dir)
                        .or_default()
                        .insert(edge_id);
                    g.inode_incoming_contains
                        .entry(inode_id)
                        .or_default()
                        .insert(edge_id);
                });
            }
        }));

        // Reader threads
        for _ in 0..4 {
            let rcu_r = Arc::clone(&rcu);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    rcu_r.read(|g| {
                        // Must always see a valid graph (invariants hold)
                        g.check_invariants().unwrap();
                        // Number of inodes grows monotonically
                        assert!(g.inodes.len() >= 1);
                    });
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Final state: 1 root + 20 files = 21
        rcu.read(|g| {
            assert_eq!(g.inodes.len(), 21);
            g.check_invariants().unwrap();
        });
    }

    #[test]
    fn invariants_hold_through_rcu_write_cycle() {
        let rcu = RcuGraph::new();

        // Create a directory via write
        rcu.write(|g| {
            let inode_id = g.alloc_inode_id();
            let dir_id = g.alloc_dir_id();
            let entry_edge = g.alloc_edge_id();
            let dot_edge = g.alloc_edge_id();
            let dotdot_edge = g.alloc_edge_id();
            let parent_inode_id = g.root_inode;

            // New directory inode (link_count=2: parent entry + ".")
            let mut inode = Inode::new_dir(inode_id, Permissions::DIR_DEFAULT, 0, 0);
            inode.link_count = 2;
            g.insert_inode(inode_id, inode);

            g.insert_dir(
                dir_id,
                Directory {
                    id: dir_id,
                    inode_id,
                },
            );

            // parent -> new inode ("subdir")
            let e1 = Edge::Contains {
                id: entry_edge,
                src: g.root_dir,
                tgt: inode_id,
                name: "subdir".into(),
            };
            g.insert_edge(entry_edge, e1);
            g.dir_contains
                .entry(g.root_dir)
                .or_default()
                .insert(entry_edge);
            g.inode_incoming_contains
                .entry(inode_id)
                .or_default()
                .insert(entry_edge);

            // new_dir -> new inode (".")
            let e2 = Edge::Contains {
                id: dot_edge,
                src: dir_id,
                tgt: inode_id,
                name: ".".into(),
            };
            g.insert_edge(dot_edge, e2);
            g.dir_contains
                .entry(dir_id)
                .or_default()
                .insert(dot_edge);
            g.inode_incoming_contains
                .entry(inode_id)
                .or_default()
                .insert(dot_edge);

            // new_dir -> parent inode ("..")
            let e3 = Edge::Contains {
                id: dotdot_edge,
                src: dir_id,
                tgt: parent_inode_id,
                name: "..".into(),
            };
            g.insert_edge(dotdot_edge, e3);
            g.dir_contains
                .entry(dir_id)
                .or_default()
                .insert(dotdot_edge);
            g.inode_incoming_contains
                .entry(parent_inode_id)
                .or_default()
                .insert(dotdot_edge);
        });

        // Verify all invariants pass after the RCU write
        rcu.read(|g| {
            g.check_invariants().unwrap();
            assert_eq!(g.dirs.len(), 2);
            assert!(g.resolve_name(g.root_dir, "subdir").is_some());
        });
    }
}
