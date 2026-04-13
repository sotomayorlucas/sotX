//! sotX WASM Runtime — Bare-metal WebAssembly interpreter.
//!
//! A minimal, `no_std`-compatible WASM bytecode interpreter for
//! Software Fault Isolation (SFI). Services compiled to WASM can
//! execute in Ring 0 with memory safety enforced by bounds checking
//! on every memory access, not by hardware page tables.
//!
//! Supported features:
//! - i32/i64 arithmetic and comparison operations
//! - Local and global variables
//! - Control flow (block, loop, if/else, br, br_if, return)
//! - Linear memory with bounds checking (SFI guarantee)
//! - Function calls (internal)
//! - Stack-based execution model
//!
//! Not yet supported: f32/f64, tables, imports, multi-value returns.

#![no_std]

mod decode;
mod exec;
mod module;
pub mod sfi;
mod types;

pub use exec::{HostFn, Runtime, Trap};
pub use module::{Import, Module, ParseError};
pub use types::{Value, ValType};

/// Maximum stack depth (in values).
pub const MAX_STACK: usize = 1024;

/// Maximum call depth.
pub const MAX_CALL_DEPTH: usize = 64;

/// Default linear memory size (64 KiB pages, WASM standard).
pub const WASM_PAGE_SIZE: usize = 65536;

/// Maximum linear memory (16 pages = 1 MiB for kernel SFI modules).
pub const MAX_MEMORY_PAGES: usize = 16;
