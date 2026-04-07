//! sotos-provenance -- provenance-native security services.
//!
//! This crate provides two system services:
//!
//! - **Graph Hunter**: real-time anomaly detection over provenance graphs.
//!   Ingests kernel provenance entries, matches attack patterns, emits alerts.
//!
//! - **BlastRadius**: capability graph attack path analysis.
//!   Computes what a compromised domain can reach via BFS through delegation chains.
//!
//! Both operate on fixed-size arrays (no heap) for use inside the sotOS microkernel
//! or privileged userspace servers.

#![no_std]

pub mod types;
pub mod graph;
pub mod graph_hunter;
pub mod blast_radius;

pub use types::{ProvenanceEntry, Operation, SoType};
pub use graph::ProvenanceGraph;
pub use graph_hunter::{GraphHunter, DetectionRule, DetectionPattern, DetectionAction, Alert, HunterStats};
pub use blast_radius::{BlastRadius, BlastReport, BlastDelta, CapEntry, DomainCaps};
