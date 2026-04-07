//! SOT Rump Kernel Adaptation Layer
//!
//! Maps NetBSD rump kernel hypercalls to SOT exokernel primitives.
//! The rump kernel calls ~30 `rumpuser_*` functions (the "hypervisor
//! interface") to create threads, allocate memory, perform I/O, etc.
//! This crate translates every one of those into SOT domain operations
//! (capabilities, IPC, frame allocation).
#![no_std]
extern crate alloc;

pub mod bio;
pub mod hypercall;
pub mod mem;
pub mod sync;
pub mod thread;

/// SOT capability handle (opaque to rump code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SotCap(pub u64);

/// SOT domain handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainHandle(pub u32);

/// Error type for rump-to-SOT translation.
#[derive(Debug)]
pub enum RumpError {
    /// Frame allocator or slab allocator exhausted.
    OutOfMemory,
    /// Capability was revoked or never existed.
    InvalidCap,
    /// Lock ordering violation detected.
    Deadlock,
    /// Block or network I/O failure (carries BSD errno).
    IoError(i32),
    /// Hypercall has no SOT equivalent.
    NotSupported,
}
