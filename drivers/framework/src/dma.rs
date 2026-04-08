//! Capability-gated DMA buffer allocation.
//!
//! A driver domain receives a `DmaCap` that grants it the right to
//! allocate physically-contiguous buffers within a pre-approved
//! physical range.  All allocations are bounds-checked against the
//! capability.

use crate::DriverError;

/// Capability authorising DMA within a physical region.
#[derive(Debug, Clone, Copy)]
pub struct DmaCap {
    /// Start of the allowed physical region.
    pub phys_base: u64,
    /// Size of the allowed physical region in bytes.
    pub size: u64,
    /// SOT capability that authorises this DMA region.
    pub cap: u64,
}

/// A single DMA buffer carved from a `DmaCap` region.
#[derive(Debug)]
pub struct DmaBuffer {
    /// Virtual address usable by the driver.
    pub virt: *mut u8,
    /// Physical address to hand to the device.
    pub phys: u64,
    /// Size in bytes.
    pub size: usize,
    /// Capability that backs this buffer.
    pub cap: u64,
}

/// Allocate a DMA buffer of `size` bytes with the given alignment,
/// carved from the region described by `dma_cap`.
///
/// Returns `DriverError::CapabilityDenied` if the capability is zero,
/// or `DriverError::DmaAllocFailed` if the request cannot be satisfied.
///
/// # Safety
/// The physical region described by `dma_cap` must be identity-mapped
/// (or otherwise accessible) at `phys_base` in the current address space.
/// The caller must ensure `align` is a power of two.
pub unsafe fn alloc_dma(
    dma_cap: &DmaCap,
    size: usize,
    align: usize,
) -> Result<DmaBuffer, DriverError> {
    if dma_cap.cap == 0 {
        return Err(DriverError::CapabilityDenied);
    }
    if size == 0 || !align.is_power_of_two() {
        return Err(DriverError::DmaAllocFailed);
    }

    // Align the base address up.
    let base = dma_cap.phys_base as usize;
    let aligned = (base + align - 1) & !(align - 1);
    let offset = aligned - base;

    if offset + size > dma_cap.size as usize {
        return Err(DriverError::DmaAllocFailed);
    }

    let phys = aligned as u64;
    Ok(DmaBuffer {
        virt: phys as *mut u8,
        phys,
        size,
        cap: dma_cap.cap,
    })
}

/// Release a DMA buffer.
///
/// In the current implementation this is a no-op -- the backing memory
/// belongs to the `DmaCap` region and is freed when the capability is
/// revoked.  The function exists so drivers have a clear place to drop
/// buffers and we can add bookkeeping later.
pub fn free_dma(_buf: DmaBuffer) {
    // Intentional no-op.  Future: track sub-allocations inside the
    // DmaCap region and reclaim them.
}
