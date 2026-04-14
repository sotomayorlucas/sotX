//! `sotos-linux-abi` -- Linux ABI backend abstraction.
//!
//! Wave-1 seed of the LUCAS -> LKL migration. See the crate-level README
//! plan in `CLAUDE.md` / project memory for the bigger picture.
//!
//! The `LinuxBackend` trait is the single entry point for Linux-syscall
//! dispatch across the sotOS tree. LUCAS (the existing hand-rolled ABI
//! layer inside `services/init`) and LKL (Linux Kernel Library, gated by
//! `SOTOS_LKL=1`) will both implement it. Today only a type-marker
//! `LucasBackend` exists; dispatch still runs through the legacy
//! child_handler match statement. This crate introduces the trait shape
//! without changing any semantics.

#![no_std]

pub mod ctx;
pub mod trait_def;
pub mod types;

#[cfg(feature = "backend-lucas")]
pub mod lucas;

pub use ctx::SyscallCtx;
pub use trait_def::LinuxBackend;
pub use types::{CapSet, Fd, LinuxPid, ProcessImage, Signal, SyscallResult};
