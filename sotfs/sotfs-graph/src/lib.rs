//! # sotfs-graph — Type Graph Data Structures
//!
//! Core data structures for the sotFS typed metadata graph (TG).
//! Implements the six node types, six edge types, and graph invariant
//! checking from the sotFS design document (§5).
//!
//! Supports both `std` (default, for FUSE prototype) and `no_std` + `alloc`
//! (for bare-metal sotOS service).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod arena;
pub mod types;
pub mod graph;
pub mod error;
pub mod rcu;
pub mod typestate;

pub use error::GraphError;
pub use graph::TypeGraph;
pub use rcu::RcuGraph;
pub use types::*;
