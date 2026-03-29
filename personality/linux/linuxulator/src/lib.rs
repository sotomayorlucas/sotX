//! sot-linuxulator: Linux personality layer for SOT domains.
//!
//! This crate provides the translation layer that lets SOT domains run
//! Linux binaries by mapping Linux x86_64 syscalls to SOT primitives:
//!
//! - [`syscall_table`] -- Complete Linux x86_64 syscall number table (~335 entries)
//!   with name and category metadata for dispatch routing.
//!
//! - [`translate`] -- Translation engine that maps each Linux syscall to either
//!   a direct SOT operation, a composite multi-step sequence, an LKL forward,
//!   or a stub. This is the central dispatch point for the process server.
//!
//! - [`procfs`] -- Virtual /proc and /sys filesystem generator. Synthesizes
//!   Linux-format output from SOT domain metadata, with optional deception
//!   mode for presenting fake hardware/kernel information.
//!
//! # Architecture
//!
//! ```text
//! Linux binary
//!    |  syscall (x86_64 ABI)
//!    v
//! Process Server (intercept via redirect endpoint)
//!    |
//!    v
//! translate(nr, args) -> TranslateResult
//!    |         |              |
//!    v         v              v
//!  Direct   Composite    ForwardToLkl
//!  SOT op   multi-step   LKL domain IPC
//! ```

#![no_std]

extern crate alloc;

pub mod procfs;
pub mod syscall_table;
pub mod translate;
