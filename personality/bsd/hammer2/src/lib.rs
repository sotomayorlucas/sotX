//! SOT-HAMMER2: HAMMER2 filesystem integration for sotOS.
//!
//! CoW B-tree filesystem with instant snapshots and clustering
//! for distributed deception (Phase 3).

#![no_std]

extern crate alloc;

pub mod volume;
pub mod cluster;
pub mod snapshot;
