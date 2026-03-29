//! Hardware Abstraction Layer traits for sotOS / sotBSD.
//!
//! This crate defines platform-portable trait interfaces for core hardware
//! operations: CPU control, interrupt management, timers, and console I/O.
//! Each trait is implemented per-architecture in the kernel; this crate
//! contains only the trait definitions and marker structs.

#![no_std]

pub mod console;
pub mod cpu;
pub mod interrupt;
pub mod timer;
