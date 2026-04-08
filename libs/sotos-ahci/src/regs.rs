//! AHCI HBA MMIO register definitions and volatile access helpers.

// ---------------------------------------------------------------------------
// Generic Host Control registers (offsets from ABAR / HBA base)
// ---------------------------------------------------------------------------

/// Host Capabilities (32-bit, read-only).
pub const REG_CAP: usize = 0x00;
/// Global Host Control (32-bit, read-write).
pub const REG_GHC: usize = 0x04;
/// Interrupt Status (32-bit, read-write1c).
pub const REG_IS: usize = 0x08;
/// Ports Implemented (32-bit, read-only) — bitmask of which ports exist.
pub const REG_PI: usize = 0x0C;
/// AHCI Version (32-bit, read-only).
pub const REG_VS: usize = 0x10;
/// Command Completion Coalescing Control.
pub const REG_CCC_CTL: usize = 0x14;
/// Command Completion Coalescing Ports.
pub const REG_CCC_PORTS: usize = 0x18;
/// Enclosure Management Location.
pub const REG_EM_LOC: usize = 0x1C;
/// Enclosure Management Control.
pub const REG_EM_CTL: usize = 0x20;
/// Host Capabilities Extended (32-bit, read-only).
pub const REG_CAP2: usize = 0x24;
/// BIOS/OS Handoff Control and Status.
pub const REG_BOHC: usize = 0x28;

// ---------------------------------------------------------------------------
// CAP register bits
// ---------------------------------------------------------------------------

/// Number of Ports (bits 4:0) — 0-based (actual = NP + 1).
pub const CAP_NP_MASK: u32 = 0x1F;
/// Supports Command List Override (bit 24).
pub const CAP_SCLO: u32 = 1 << 24;
/// Supports Staggered Spin-up (bit 27).
pub const CAP_SSS: u32 = 1 << 27;
/// Supports 64-bit Addressing (bit 31).
pub const CAP_S64A: u32 = 1 << 31;
/// Number of Command Slots (bits 12:8) — 0-based.
pub const CAP_NCS_SHIFT: u32 = 8;
/// 5-bit mask used to extract the NCS field from `CAP`.
pub const CAP_NCS_MASK: u32 = 0x1F;

/// Extract number of command slots supported (1-based).
pub fn cap_num_cmd_slots(cap: u32) -> u8 {
    (((cap >> CAP_NCS_SHIFT) & CAP_NCS_MASK) + 1) as u8
}

/// Extract number of ports (1-based).
pub fn cap_num_ports(cap: u32) -> u8 {
    ((cap & CAP_NP_MASK) + 1) as u8
}

// ---------------------------------------------------------------------------
// GHC register bits
// ---------------------------------------------------------------------------

/// HBA Reset (bit 0) — self-clearing.
pub const GHC_HR: u32 = 1 << 0;
/// Interrupt Enable (bit 1).
pub const GHC_IE: u32 = 1 << 1;
/// AHCI Enable (bit 31).
pub const GHC_AE: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// Port registers (base = ABAR + 0x100 + port * 0x80)
// ---------------------------------------------------------------------------

/// Port x Command List Base Address (32-bit, lower).
pub const PORT_CLB: usize = 0x00;
/// Port x Command List Base Address Upper (32-bit).
pub const PORT_CLBU: usize = 0x04;
/// Port x FIS Base Address (32-bit, lower).
pub const PORT_FB: usize = 0x08;
/// Port x FIS Base Address Upper (32-bit).
pub const PORT_FBU: usize = 0x0C;
/// Port x Interrupt Status (32-bit, RW1C).
pub const PORT_IS: usize = 0x10;
/// Port x Interrupt Enable (32-bit).
pub const PORT_IE: usize = 0x14;
/// Port x Command and Status (32-bit).
pub const PORT_CMD: usize = 0x18;
/// Port x Task File Data (32-bit, read-only).
pub const PORT_TFD: usize = 0x20;
/// Port x Signature (32-bit, read-only).
pub const PORT_SIG: usize = 0x24;
/// Port x Serial ATA Status (32-bit, read-only).
pub const PORT_SSTS: usize = 0x28;
/// Port x Serial ATA Control (32-bit).
pub const PORT_SCTL: usize = 0x2C;
/// Port x Serial ATA Error (32-bit, RW1C).
pub const PORT_SERR: usize = 0x30;
/// Port x Serial ATA Active (32-bit) — bitmask of commands using NCQ.
pub const PORT_SACT: usize = 0x34;
/// Port x Command Issue (32-bit) — bitmask of commands to process.
pub const PORT_CI: usize = 0x38;

// ---------------------------------------------------------------------------
// PORT_CMD bits
// ---------------------------------------------------------------------------

/// Start — enables command processing.
pub const CMD_ST: u32 = 1 << 0;
/// Spin-Up Device.
pub const CMD_SUD: u32 = 1 << 1;
/// Power On Device.
pub const CMD_POD: u32 = 1 << 2;
/// Command List Override.
pub const CMD_CLO: u32 = 1 << 3;
/// FIS Receive Enable.
pub const CMD_FRE: u32 = 1 << 4;
/// Current Command Slot (bits 12:8, read-only).
pub const CMD_CCS_SHIFT: u32 = 8;
/// 5-bit mask used to extract the CCS field from `PORT_CMD`.
pub const CMD_CCS_MASK: u32 = 0x1F;
/// FIS Receive Running (read-only).
pub const CMD_FR: u32 = 1 << 14;
/// Command List Running (read-only).
pub const CMD_CR: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// PORT_TFD bits
// ---------------------------------------------------------------------------

/// Task File Status: ERR bit.
pub const TFD_ERR: u32 = 1 << 0;
/// Task File Status: DRQ bit.
pub const TFD_DRQ: u32 = 1 << 3;
/// Task File Status: BSY bit.
pub const TFD_BSY: u32 = 1 << 7;

// ---------------------------------------------------------------------------
// PORT_SSTS (SStatus) fields
// ---------------------------------------------------------------------------

/// Device Detection (bits 3:0).
pub const SSTS_DET_MASK: u32 = 0x0F;
/// Device present and Phy communication established.
pub const SSTS_DET_PRESENT: u32 = 0x03;
/// Interface Power Management (bits 11:8).
pub const SSTS_IPM_MASK: u32 = 0x0F00;
/// Interface in active state.
pub const SSTS_IPM_ACTIVE: u32 = 0x0100;
/// Interface speed (bits 7:4).
pub const SSTS_SPD_MASK: u32 = 0xF0;

// ---------------------------------------------------------------------------
// PORT_SCTL (SControl) fields
// ---------------------------------------------------------------------------

/// Device detection initialization (bits 3:0).
pub const SCTL_DET_MASK: u32 = 0x0F;
/// Perform interface communication initialization (COMRESET).
pub const SCTL_DET_INIT: u32 = 0x01;
/// No device detection action.
pub const SCTL_DET_NONE: u32 = 0x00;

// ---------------------------------------------------------------------------
// PORT_IS / PORT_IE interrupt bits
// ---------------------------------------------------------------------------

/// Device to Host Register FIS Interrupt.
pub const IS_DHRS: u32 = 1 << 0;
/// PIO Setup FIS Interrupt.
pub const IS_PSS: u32 = 1 << 1;
/// DMA Setup FIS Interrupt.
pub const IS_DSS: u32 = 1 << 2;
/// Set Device Bits Interrupt.
pub const IS_SDBS: u32 = 1 << 3;
/// Unknown FIS Interrupt.
pub const IS_UFS: u32 = 1 << 4;
/// Descriptor Processed.
pub const IS_DPS: u32 = 1 << 5;
/// Port Connect Change Status.
pub const IS_PCS: u32 = 1 << 6;
/// Device Mechanical Presence Status.
pub const IS_DMPS: u32 = 1 << 7;
/// PhyRdy Change Status.
pub const IS_PRCS: u32 = 1 << 22;
/// Incorrect Port Multiplier Status.
pub const IS_IPMS: u32 = 1 << 23;
/// Overflow Status.
pub const IS_OFS: u32 = 1 << 24;
/// Interface Non-fatal Error Status.
pub const IS_INFS: u32 = 1 << 26;
/// Interface Fatal Error Status.
pub const IS_IFS: u32 = 1 << 27;
/// Host Bus Data Error Status.
pub const IS_HBDS: u32 = 1 << 28;
/// Host Bus Fatal Error Status.
pub const IS_HBFS: u32 = 1 << 29;
/// Task File Error Status.
pub const IS_TFES: u32 = 1 << 30;

// ---------------------------------------------------------------------------
// SATA Signature values (PORT_SIG)
// ---------------------------------------------------------------------------

/// SATA drive (ATA device).
pub const SIG_ATA: u32 = 0x00000101;
/// SATAPI device (ATAPI).
pub const SIG_ATAPI: u32 = 0xEB140101;
/// Enclosure management bridge.
pub const SIG_SEMB: u32 = 0xC33C0101;
/// Port multiplier.
pub const SIG_PM: u32 = 0x96690101;

// ---------------------------------------------------------------------------
// Port register base address calculation
// ---------------------------------------------------------------------------

/// Calculate the offset of port `n` registers from HBA base.
/// Port registers start at 0x100 with a stride of 0x80 per port.
pub const fn port_offset(port: u8) -> usize {
    0x100 + (port as usize) * 0x80
}

// ---------------------------------------------------------------------------
// Volatile MMIO helpers (same pattern as sotos-nvme)
// ---------------------------------------------------------------------------

/// Volatile read of a 32-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn read32(base: *const u8, offset: usize) -> u32 {
    let ptr = base.add(offset) as *const u32;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile write of a 32-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn write32(base: *mut u8, offset: usize, val: u32) {
    let ptr = base.add(offset) as *mut u32;
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Volatile read of a 64-bit MMIO register (as two 32-bit reads).
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn read64(base: *const u8, offset: usize) -> u64 {
    let lo = unsafe { read32(base, offset) } as u64;
    let hi = unsafe { read32(base, offset + 4) } as u64;
    (hi << 32) | lo
}

/// Volatile write of a 64-bit MMIO register (as two 32-bit writes).
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn write64(base: *mut u8, offset: usize, val: u64) {
    unsafe {
        write32(base, offset, val as u32);
        write32(base, offset + 4, (val >> 32) as u32);
    }
}
