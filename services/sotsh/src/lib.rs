//! sotSh — capability-first native shell for sotOS.
//!
//! Design philosophy:
//! - Capability-first: every built-in declares its required caps up front;
//!   the dispatcher checks before running.
//! - Graph-native: pipelines are DAGs, not byte streams — future work will
//!   integrate with sotFS / the provenance graph.
//! - Deception-aware: the `arm` built-in inspects active deception profiles
//!   from the `sotos-deception` crate (personality/common/deception/).
//!
//! This is Wave-1 seed work. Wave-2 workers each replace one stub in
//! `src/builtins/{ls,cat,cd,ps,cap,arm}.rs`.

pub mod ast;
pub mod builtins;
pub mod context;
pub mod error;
pub mod parser;
pub mod value;
