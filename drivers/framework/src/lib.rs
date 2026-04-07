//! SOT Driver-as-Domain Framework
//!
//! Provides the traits and types for writing hardware drivers that run
//! as isolated capability-guarded domains. Each driver receives only
//! the MMIO regions, IRQ channels, and DMA capabilities it needs --
//! nothing more.

#![no_std]

pub mod device;
pub mod dma;
pub mod irq_channel;
pub mod mmio_so;

/// Errors returned by driver operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    /// Hardware not found during probe.
    NotFound,
    /// Capability check failed -- caller lacks permission.
    CapabilityDenied,
    /// MMIO offset out of range for the mapped region.
    MmioOutOfRange,
    /// DMA allocation failed (no contiguous memory, bad alignment, etc.).
    DmaAllocFailed,
    /// IRQ line could not be configured.
    IrqConfigFailed,
    /// Device returned an unexpected status.
    DeviceError,
    /// Operation not supported by this driver.
    Unsupported,
    /// The device is not in the right state for this operation.
    InvalidState,
}
