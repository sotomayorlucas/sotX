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
//! B1 port: the crate now builds for `x86_64-unknown-none`. The host-std
//! prototype used `rustyline` + `std::fs`; the no_std build uses a
//! framebuffer-backed line editor (`linedit`) and stubs the filesystem
//! built-ins (ls/cat/cd) — B2a replaces those stubs with real syscalls.

#![no_std]

extern crate alloc;

pub mod ast;
pub mod builtins;
pub mod context;
pub mod error;
pub mod history;
pub mod linedit;
pub mod parser;
pub mod value;
