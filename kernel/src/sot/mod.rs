//! SOT (Secure Object Transactional) exokernel subsystem.
//!
//! Core SOT primitives: Secure Objects, capability epoch tracking,
//! transactions (Tier 0/1/2), provenance ring buffers, and domains.

pub mod cap_epoch;
pub mod provenance;
pub mod so;
pub mod tx;
pub mod tx_wal;
pub mod types;

pub use so::{CapObjectAdapter, SecureObject};
pub use types::{Policy, SOId, SOOperation, SOType, SOVersion};
