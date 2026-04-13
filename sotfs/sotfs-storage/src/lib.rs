//! # sotfs-storage — Persistence Layer
//!
//! Persists the TypeGraph to disk using redb (embedded key-value store
//! with ACID transactions). The graph is serialized as key-value pairs:
//! one table per node type, one table for edges.
//!
//! Phase 2 implementation — will be replaced with a custom CoW B+ tree
//! in Phase 3 when porting to sotX.

pub mod backend;

pub use backend::RedbBackend;
