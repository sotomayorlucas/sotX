# sotFS — Trust Assumptions and Verification Status

**Date:** April 2026  
**Authors:** Lucas Sotomayor

This document describes what properties of sotFS are formally proven, what
is enforced by the compiler, what is tested, and what is assumed. It is
organized by verification layer, following the four-layer plan from the
design document (§11).

---

## Layer 1: TLA+ Model Checking (Bounded)

**Tool:** TLC model checker  
**Status:** Complete — 4 specifications verified  
**Confidence:** Model-checked for all reachable states within bounded parameters

### Verified Properties

| Spec | Property | Bound | Status |
|------|----------|-------|--------|
| `sotfs_graph.tla` | LinkCountConsistent | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_graph.tla` | UniqueNamesPerDir | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_graph.tla` | DirHasSelfRef | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_graph.tla` | NoDanglingEdges | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_graph.tla` | BlockRefcountConsistent | 5 inodes, 3 blocks, 6 ops | Verified |
| `sotfs_graph.tla` | NoDirCycles | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_graph.tla` | ReachableHaveLinks | 5 inodes, 3 dirs, 6 ops | Verified |
| `sotfs_transactions.tla` | Isolation | 2 GTXNs, 3 SOs, 8 ops | Verified |
| `sotfs_transactions.tla` | Atomicity | 2 GTXNs, 3 SOs, 8 ops | Verified |
| `sotfs_transactions.tla` | NoStaleLocks | 2 GTXNs, 3 SOs, 8 ops | Verified |
| `sotfs_transactions.tla` | RollbackCorrect | 2 GTXNs, 3 SOs, 8 ops | Verified |
| `sotfs_transactions.tla` | TierMapping | 2 GTXNs, 3 SOs, 8 ops | Verified |
| `sotfs_capabilities.tla` | MonotonicAttenuation | 4 caps, 2 inodes, 6 ops | Verified |
| `sotfs_capabilities.tla` | GrantsConsistency | 4 caps, 2 inodes, 6 ops | Verified |
| `sotfs_capabilities.tla` | DelegationForest | 4 caps, 2 inodes, 6 ops | Verified |
| `sotfs_capabilities.tla` | NoForgery | 4 caps, 2 inodes, 6 ops | Verified |
| `sotfs_capabilities.tla` | TransitiveRevocation | 4 caps, 2 inodes, 6 ops | Verified |
| `sotfs_crash.tla` | RecoveryConsistency | 2 SOs, 8 ops | Verified |
| `sotfs_crash.tla` | NoPartialApplication | 2 SOs, 8 ops | Verified |
| `sotfs_crash.tla` | RollbackToSnapshot | 2 SOs, 8 ops | Verified |

### Limitations

- Bounded model checking: properties verified for small configurations only.
  Unbounded verification requires Coq/Perennial (Layer 4).
- The TLA+ model abstracts data content (values are integers, not byte arrays).
- Concurrency model assumes sequentially consistent memory.

---

## Layer 2: Crash Refinement (Tested)

**Tool:** Integration tests with redb ACID backend  
**Status:** Complete — 6 crash scenario tests passing  
**Confidence:** Tested (not proven)

### Tested Properties

| Test | Property |
|------|----------|
| `save_then_load_preserves_graph` | Round-trip persistence preserves all nodes/edges/invariants |
| `load_without_save_returns_none` | Empty database returns None (clean initial state) |
| `save_overwrite_is_atomic` | Sequential saves don't produce intermediate states |
| `reopen_database_preserves_data` | Data survives process restart (close + reopen) |
| `concurrent_saves_last_writer_wins` | Last save is the committed state (no mixing) |
| `invariants_preserved_after_complex_operations` | Complex tree + hard links + rename + data survives persist |

### What This Depends On

- **redb's ACID guarantees:** We rely on redb (v2.1.0) for atomic
  write transactions. redb uses an MVCC copy-on-write B+ tree with
  a two-phase commit protocol. Our crash consistency is only as good
  as redb's.
- **Filesystem fsync behavior:** redb calls `fsync()` on commit. We
  assume the OS honors fsync semantics (data reaches non-volatile storage).

---

## Layer 3: Typestate in Rust (Compile-Time)

**Tool:** Rust type system (phantom types, ownership, move semantics)  
**Status:** Complete — 4 typestate modules implemented  
**Confidence:** Enforced for ALL inputs (compile-time guarantee)

### Enforced Properties

| Typestate | Property | Mechanism |
|-----------|----------|-----------|
| `InodeHandle<Created/Linked/Orphaned>` | Cannot read/write an unlinked inode | Method only on `Linked` |
| `InodeHandle<Orphaned>` | Use-after-gc is impossible | `gc()` consumes the handle |
| `TxHandle<Active/Committed/Aborted>` | Active transaction cannot be dropped silently | `#[must_use]` |
| `TxHandle<Active>` | Cannot apply rules after commit/abort | Methods only on `Active` |
| `DirHandle<Empty/NonEmpty>` | Cannot rmdir a non-empty directory | `rmdir()` only on `Empty` |
| `CapHandle` | Attenuation never escalates rights | `rights & mask` (AND operation) |

### What This Does NOT Cover

- The typestate layer enforces **structural** constraints (state transitions)
  but not **semantic** constraints (e.g., "link_count equals the number of
  incoming contains edges"). Semantic invariants are checked at runtime via
  `TypeGraph::check_invariants()`.
- Typestate handles are separate from the main `TypeGraph` implementation.
  The graph itself uses runtime checks. The typestate layer provides an
  optional "safe API" that wraps graph operations in typed handles.

---

## Layer 4: Loom Concurrency Testing (Bounded)

**Tool:** Loom (v0.7) — deterministic concurrency testing  
**Status:** Complete — 3 concurrency tests  
**Confidence:** Exhaustively tested for all thread interleavings within bounds

### Tested Properties

| Test | Property | Interleavings |
|------|----------|---------------|
| `concurrent_transactions_isolation` | Two GTXNs with disjoint write sets both succeed | All (loom exhaustive) |
| `rollback_restores_state` | Aborted GTXN restores pre-transaction values | All |
| `conflicting_writes_serialized` | Same-slot writes serialized by mutex | All |

### Limitations

- Loom tests use a simplified graph model (arrays, not BTreeMap) because
  loom overrides std synchronization primitives.
- The real `TypeGraph` uses `BTreeMap` which is not loom-aware. Full
  verification of the real data structure requires runtime testing or
  a custom loom-compatible map.

---

## Assumptions (Not Verified)

### Hardware Assumptions

1. **CPU correctness:** We assume the x86_64 CPU correctly implements
   memory ordering (TSO), page table walks, and arithmetic operations.
2. **Storage durability:** We assume that after `fsync()` returns, data
   is on non-volatile media. Write caches with battery backup are trusted.
3. **No bit rot:** We assume stored data doesn't silently corrupt. Checksum
   verification (e.g., block-level CRC) is not implemented.

### Compiler Assumptions

1. **Rust compiler correctness:** We assume `rustc` correctly implements
   the Rust type system, including move semantics, phantom types, and the
   `#[must_use]` attribute that our typestate layer depends on.
2. **No undefined behavior:** All code is safe Rust (no `unsafe` blocks
   in the FUSE prototype). The bare-metal service uses `unsafe` for the
   global allocator and fixed-address access only.
3. **Optimization preserves semantics:** We assume LTO and release-mode
   optimizations don't change observable behavior.

### Design Assumptions

1. **IPC reliability:** The sotOS IPC primitive (synchronous send/recv)
   is assumed to deliver messages exactly once, in order, without
   corruption. This is verified by a separate TLA+ spec (`formal/ipc.tla`).
2. **Capability unforgery:** We assume the kernel correctly enforces
   capability access control. A compromised kernel invalidates all
   security guarantees.
3. **Single-writer per GTXN:** The current GTXN implementation uses a
   Mutex (or IPC serialization in the bare-metal service) to ensure
   single-writer access. We assume the Mutex implementation is correct.

---

## Verification Roadmap (Future)

| Layer | Tool | Target | Status |
|-------|------|--------|--------|
| 1 | TLA+/TLC | Graph invariants, GTXN, caps, crash | **Done** |
| 2 | Integration tests | Crash consistency (redb) | **Done** |
| 3 | Rust typestate | Compile-time state machine enforcement | **Done** |
| 3b | Loom | Concurrency isolation | **Done** |
| 4 | Verus/Coq | Commit atomicity proof | Planned |
| 4 | Verus/Coq | Rollback correctness proof | Planned |
| 4 | Verus/Coq | Capability unforgeability proof | Planned |
| 4 | Verus/Coq | Treewidth preservation proof | Planned |
| 4 | Verus/Coq | DPO confluence proof | Planned |

---

## Summary

| Category | Coverage | Confidence Level |
|----------|----------|-----------------|
| Graph invariants (7 properties) | TLA+ model-checked | Bounded |
| GTXN protocol (5 properties) | TLA+ model-checked | Bounded |
| Capability safety (5 properties) | TLA+ model-checked | Bounded |
| Crash recovery (3 properties) | TLA+ model-checked + integration tested | Bounded + tested |
| State machine transitions | Rust typestate (compile-time) | **All inputs** |
| Transaction isolation | Loom (exhaustive interleavings) | Bounded |
| Data persistence | Integration tests (redb ACID) | Tested |
| DPO rule correctness | Runtime invariant checks (24 unit tests) | Tested |
| Commit atomicity (unbounded) | Not yet verified | Planned (Coq) |
| Treewidth preservation (unbounded) | Not yet verified | Planned (Coq) |
