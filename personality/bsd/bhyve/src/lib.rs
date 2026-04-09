//! sot-bhyve -- Type-2 hypervisor domain framework for sotOS.
//!
//! Provides a bhyve-inspired VMM that extends SOT domain deception
//! into VM introspection: CPUID/MSR spoofing, memory watches, and
//! built-in deception profiles that make the guest appear to run on
//! bare-metal Intel/AMD hardware (or inside VMware, for nested
//! deception).

#![no_std]

pub mod vmm;
pub mod vcpu;
pub mod vmcs;
pub mod deception;
pub mod introspect;

#[cfg(feature = "kernel-backend")]
pub mod backend;
