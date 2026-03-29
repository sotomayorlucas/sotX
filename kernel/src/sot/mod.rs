//! SOT Secure Object system — trait, types, and adapters.
//!
//! This module defines the `SecureObject` trait that every kernel-managed
//! resource implements, along with the type system (SOType, SOId, Policy,
//! SOVersion) and the adapter bridging the existing capability objects.

pub mod so;
pub mod types;

pub use so::{CapObjectAdapter, SecureObject};
pub use types::{Policy, SOId, SOOperation, SOType, SOVersion};
