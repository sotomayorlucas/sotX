//! Memory-mapped I/O framework.
//!
//! Provides a generic `MmioRegion` helper for drivers to perform volatile
//! reads and writes to device registers through the HHDM (Higher Half
//! Direct Map). All accesses use volatile operations to prevent compiler
//! reordering or elision.

use core::ptr;

/// A memory-mapped I/O region accessed through the HHDM.
///
/// `base` is the physical base address of the MMIO region.
/// All reads/writes go through `base + hhdm_offset + offset`.
pub struct MmioRegion {
    /// Physical base address of the MMIO region.
    base: u64,
    /// Size of the region in bytes (for bounds checking).
    size: usize,
}

impl MmioRegion {
    /// Create a new MMIO region descriptor.
    ///
    /// # Safety
    /// The caller must ensure that `phys_base..phys_base+size` is a valid
    /// MMIO region (not regular RAM) and that the HHDM identity-maps it.
    pub unsafe fn new(phys_base: u64, size: usize) -> Self {
        Self {
            base: phys_base,
            size,
        }
    }

    /// Return the physical base address of this region.
    pub fn phys_base(&self) -> u64 {
        self.base
    }

    /// Return the size of this region in bytes.
    pub fn region_size(&self) -> usize {
        self.size
    }

    /// Compute the virtual address for a given offset within the region.
    #[inline(always)]
    fn vaddr(&self, offset: usize) -> *mut u8 {
        let hhdm = crate::mm::hhdm_offset();
        (self.base + hhdm + offset as u64) as *mut u8
    }

    /// Read a 32-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 4 > size` (debug builds only).
    #[inline]
    pub fn read32(&self, offset: usize) -> u32 {
        debug_assert!(
            offset + 4 <= self.size,
            "MMIO read32 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: `MmioRegion::new` is unsafe, so its caller already promised
        // that `[base..base+size)` is a valid HHDM-mapped MMIO region. The
        // debug_assert above guarantees `offset + 4 <= size`. Volatile read
        // prevents elision/reordering of the MMIO access.
        unsafe { ptr::read_volatile(self.vaddr(offset) as *const u32) }
    }

    /// Write a 32-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 4 > size` (debug builds only).
    #[inline]
    pub fn write32(&self, offset: usize, val: u32) {
        debug_assert!(
            offset + 4 <= self.size,
            "MMIO write32 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — caller of `MmioRegion::new` guarantees the
        // mapping is valid; the debug_assert bounds-checks the offset.
        unsafe { ptr::write_volatile(self.vaddr(offset) as *mut u32, val) }
    }

    /// Read a 64-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 8 > size` (debug builds only).
    #[inline]
    pub fn read64(&self, offset: usize) -> u64 {
        debug_assert!(
            offset + 8 <= self.size,
            "MMIO read64 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 8-byte width.
        unsafe { ptr::read_volatile(self.vaddr(offset) as *const u64) }
    }

    /// Write a 64-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 8 > size` (debug builds only).
    #[inline]
    pub fn write64(&self, offset: usize, val: u64) {
        debug_assert!(
            offset + 8 <= self.size,
            "MMIO write64 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 8-byte width.
        unsafe { ptr::write_volatile(self.vaddr(offset) as *mut u64, val) }
    }

    /// Read an 8-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 1 > size` (debug builds only).
    #[inline]
    pub fn read8(&self, offset: usize) -> u8 {
        debug_assert!(
            offset < self.size,
            "MMIO read8 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 1-byte width.
        unsafe { ptr::read_volatile(self.vaddr(offset) as *const u8) }
    }

    /// Write an 8-bit value at the given byte offset.
    ///
    /// # Panics
    /// Panics if `offset + 1 > size` (debug builds only).
    #[inline]
    pub fn write8(&self, offset: usize, val: u8) {
        debug_assert!(
            offset < self.size,
            "MMIO write8 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 1-byte width.
        unsafe { ptr::write_volatile(self.vaddr(offset) as *mut u8, val) }
    }

    /// Read a 16-bit value at the given byte offset.
    #[inline]
    pub fn read16(&self, offset: usize) -> u16 {
        debug_assert!(
            offset + 2 <= self.size,
            "MMIO read16 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 2-byte width.
        unsafe { ptr::read_volatile(self.vaddr(offset) as *const u16) }
    }

    /// Write a 16-bit value at the given byte offset.
    #[inline]
    pub fn write16(&self, offset: usize, val: u16) {
        debug_assert!(
            offset + 2 <= self.size,
            "MMIO write16 out of bounds: offset={:#x} size={:#x}",
            offset,
            self.size
        );
        // SAFETY: see `read32` — same safety contract, 2-byte width.
        unsafe { ptr::write_volatile(self.vaddr(offset) as *mut u16, val) }
    }
}
