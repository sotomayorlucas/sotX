//! SOT (Secure Object Transactions) subsystem.
//!
//! Provides tiered transactional access to kernel objects:
//! - Tier 0: Epoch-based RCU for read-only paths
//! - Tier 1: Per-object WAL for single-object mutations
//! - Tier 2: Two-phase commit for multi-object operations

pub mod tx;
pub mod tx_wal;
