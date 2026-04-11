//! # sotfs-monitor — Structural Monitors for sotFS
//!
//! Three structural differentiators from the design document:
//!
//! - **Treewidth checker** (§8): Verify tw(TG) ≤ k after each DPO rule.
//!   Uses greedy elimination ordering for upper-bound computation.
//!
//! - **Ollivier-Ricci curvature** (§9): Incremental edge curvature
//!   computation for anomaly detection. Wasserstein-1 on lazy random walks.
//!
//! - **Deceptive projections** (§10): Capability-gated graph projections.
//!   Different domains see different subgraphs (D_FS functor).

pub mod treewidth;
pub mod curvature;
pub mod deception;
