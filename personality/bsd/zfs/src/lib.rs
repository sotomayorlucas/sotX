//! SOT-ZFS: ZFS transactional integration for sotX.
//!
//! Connects SOT transactions to ZFS-style pool/dataset/snapshot semantics,
//! enabling forensic-grade rollback via automatic snapshots on tx_commit.

#![no_std]

extern crate alloc;

pub mod pool;
pub mod dataset;
pub mod snapshot;
pub mod txg;
