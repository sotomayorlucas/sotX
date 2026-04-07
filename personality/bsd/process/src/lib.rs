//! BSD Process Server — POSIX-to-SOT translation layer.
//!
//! Translates POSIX process semantics into SOT microkernel primitives:
//! - Processes become capability domains
//! - File descriptors become capabilities
//! - Signals become IPC messages
//! - Credentials become capability exec policies (no setuid)
//! - exec() becomes a transactional domain reset

#![no_std]

extern crate alloc;

pub mod posix;
pub mod proc;
pub mod signal;
pub mod credentials;
pub mod exec;
