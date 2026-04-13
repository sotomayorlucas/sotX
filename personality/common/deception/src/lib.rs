//! Deception subsystem for sotX.
//!
//! Provides anomaly detection, capability interposition, deception
//! profiles, and the migration orchestrator that transparently moves
//! a compromised domain into a controlled deception environment.
//!
//! ## Architecture
//!
//! ```text
//! Provenance entries
//!        |
//!        v
//!  AnomalyDetector  -->  AnomalyReport
//!        |
//!        v
//!  MigrationOrchestrator
//!        |--- creates InterpositionRules via InterpositionEngine
//!        |--- selects DeceptionProfile for fake responses
//!        `--- records MigrationRecord for forensics
//! ```

#![no_std]

pub mod anomaly;
pub mod interpose;
pub mod migration;
pub mod profile;
