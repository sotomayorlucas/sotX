//! MMIO regions as Secure Objects with typed access.
//!
//! Every MMIO region is guarded by a SOT capability.  Before any
//! read or write the capability is validated (non-zero check --
//! the real enforcement happens in the kernel when the mapping was
//! created).  Offsets are bounds-checked against the region size.

use crate::DriverError;

/// Flags controlling cache behaviour of an MMIO mapping.
#[derive(Debug, Clone, Copy)]
pub struct MmioFlags {
    /// Map as Uncacheable (UC).  Required for device registers.
    pub uncacheable: bool,
    /// Map as Write-Combining (WC).  Useful for frame-buffers.
    pub write_combine: bool,
}

/// A capability-guarded MMIO region.
#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    /// Physical base address of the region.
    pub base_phys: u64,
    /// Size in bytes.
    pub size: u64,
    /// Secure Object capability that authorises access.
    pub cap: u64,
    /// Cache behaviour flags.
    pub flags: MmioFlags,
}

impl MmioRegion {
    /// Validate that `cap` is non-zero and `offset + len` fits inside the region.
    #[inline]
    fn check(&self, offset: u64, len: u64) -> Result<(), DriverError> {
        if self.cap == 0 {
            return Err(DriverError::CapabilityDenied);
        }
        if offset.checked_add(len).map_or(true, |end| end > self.size) {
            return Err(DriverError::MmioOutOfRange);
        }
        Ok(())
    }

    /// Typed volatile read (8 bit).
    ///
    /// # Safety
    /// The region must be validly mapped at `base_phys` in the current
    /// address space and the hardware must tolerate a byte-wide read
    /// at `offset`.
    pub unsafe fn read_u8(&self, offset: u64) -> Result<u8, DriverError> {
        self.check(offset, 1)?;
        let ptr = (self.base_phys + offset) as *const u8;
        Ok(core::ptr::read_volatile(ptr))
    }

    /// Typed volatile write (8 bit).
    ///
    /// # Safety
    /// Same requirements as [`read_u8`].
    pub unsafe fn write_u8(&self, offset: u64, val: u8) -> Result<(), DriverError> {
        self.check(offset, 1)?;
        let ptr = (self.base_phys + offset) as *mut u8;
        core::ptr::write_volatile(ptr, val);
        Ok(())
    }

    /// Typed volatile read (16 bit, naturally aligned).
    ///
    /// # Safety
    /// The region must be mapped and `offset` must be 2-byte aligned.
    pub unsafe fn read_u16(&self, offset: u64) -> Result<u16, DriverError> {
        self.check(offset, 2)?;
        let ptr = (self.base_phys + offset) as *const u16;
        Ok(core::ptr::read_volatile(ptr))
    }

    /// Typed volatile write (16 bit).
    pub unsafe fn write_u16(&self, offset: u64, val: u16) -> Result<(), DriverError> {
        self.check(offset, 2)?;
        let ptr = (self.base_phys + offset) as *mut u16;
        core::ptr::write_volatile(ptr, val);
        Ok(())
    }

    /// Typed volatile read (32 bit, naturally aligned).
    ///
    /// # Safety
    /// The region must be mapped and `offset` must be 4-byte aligned.
    pub unsafe fn read_u32(&self, offset: u64) -> Result<u32, DriverError> {
        self.check(offset, 4)?;
        let ptr = (self.base_phys + offset) as *const u32;
        Ok(core::ptr::read_volatile(ptr))
    }

    /// Typed volatile write (32 bit).
    pub unsafe fn write_u32(&self, offset: u64, val: u32) -> Result<(), DriverError> {
        self.check(offset, 4)?;
        let ptr = (self.base_phys + offset) as *mut u32;
        core::ptr::write_volatile(ptr, val);
        Ok(())
    }

    /// Typed volatile read (64 bit, naturally aligned).
    ///
    /// # Safety
    /// The region must be mapped and `offset` must be 8-byte aligned.
    pub unsafe fn read_u64(&self, offset: u64) -> Result<u64, DriverError> {
        self.check(offset, 8)?;
        let ptr = (self.base_phys + offset) as *const u64;
        Ok(core::ptr::read_volatile(ptr))
    }

    /// Typed volatile write (64 bit).
    pub unsafe fn write_u64(&self, offset: u64, val: u64) -> Result<(), DriverError> {
        self.check(offset, 8)?;
        let ptr = (self.base_phys + offset) as *mut u64;
        core::ptr::write_volatile(ptr, val);
        Ok(())
    }
}
