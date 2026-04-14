//! xHCI host controller MMIO register offsets and volatile access helpers.

// ---------------------------------------------------------------------------
// Capability Registers (base = MMIO BAR0)
// ---------------------------------------------------------------------------

/// CAPLENGTH (8-bit): Capability Register Length.
pub const CAP_CAPLENGTH: usize = 0x00;
/// HCIVERSION (16-bit): Interface Version Number.
pub const CAP_HCIVERSION: usize = 0x02;
/// HCSPARAMS1 (32-bit): Structural Parameters 1.
pub const CAP_HCSPARAMS1: usize = 0x04;
/// HCSPARAMS2 (32-bit): Structural Parameters 2.
pub const CAP_HCSPARAMS2: usize = 0x08;
/// HCCPARAMS1 (32-bit): Capability Parameters 1.
pub const CAP_HCCPARAMS1: usize = 0x10;
/// DBOFF (32-bit): Doorbell Offset.
pub const CAP_DBOFF: usize = 0x14;
/// RTSOFF (32-bit): Runtime Register Space Offset.
pub const CAP_RTSOFF: usize = 0x18;

// ---------------------------------------------------------------------------
// Operational Registers (base = MMIO + CAPLENGTH)
// ---------------------------------------------------------------------------

/// USB Command Register.
pub const OP_USBCMD: usize = 0x00;
/// USB Status Register.
pub const OP_USBSTS: usize = 0x04;
/// Command Ring Control Register (64-bit).
pub const OP_CRCR: usize = 0x18;
/// Device Context Base Address Array Pointer (64-bit).
pub const OP_DCBAAP: usize = 0x30;
/// Configure Register.
pub const OP_CONFIG: usize = 0x38;
/// Port Status and Control base (port 1 at +0x400, stride 0x10).
pub const OP_PORTSC_BASE: usize = 0x400;

// ---------------------------------------------------------------------------
// Runtime Register offsets (base = MMIO + RTSOFF)
// ---------------------------------------------------------------------------

/// Interrupter 0 register set base (within runtime regs).
pub const RT_IR0_BASE: usize = 0x20;
/// Interrupter Management Register (relative to IR base).
pub const IR_IMAN: usize = 0x00;
/// Event Ring Segment Table Size.
pub const IR_ERSTSZ: usize = 0x08;
/// Event Ring Segment Table Base Address (64-bit).
pub const IR_ERSTBA: usize = 0x10;
/// Event Ring Dequeue Pointer (64-bit).
pub const IR_ERDP: usize = 0x18;

// ---------------------------------------------------------------------------
// USBCMD bits
// ---------------------------------------------------------------------------

/// Run/Stop — set to 1 to run the controller.
pub const CMD_RS: u32 = 1 << 0;
/// Host Controller Reset.
pub const CMD_HCRST: u32 = 1 << 1;
/// Interrupter Enable.
pub const CMD_INTE: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// USBSTS bits
// ---------------------------------------------------------------------------

/// HCHalted — 1 when controller is halted.
pub const STS_HCH: u32 = 1 << 0;
/// Controller Not Ready.
pub const STS_CNR: u32 = 1 << 11;

// ---------------------------------------------------------------------------
// PORTSC bits
// ---------------------------------------------------------------------------

/// Current Connect Status.
pub const PORTSC_CCS: u32 = 1 << 0;
/// Port Enabled/Disabled.
pub const PORTSC_PED: u32 = 1 << 1;
/// Port Reset.
pub const PORTSC_PR: u32 = 1 << 4;
/// Port Power.
pub const PORTSC_PP: u32 = 1 << 9;
/// Connect Status Change (RW1C).
pub const PORTSC_CSC: u32 = 1 << 17;
/// Port Reset Change (RW1C).
pub const PORTSC_PRC: u32 = 1 << 21;

/// Mask of RW1C status-change bits — must be preserved when writing PORTSC.
pub const PORTSC_RW1C_MASK: u32 = PORTSC_CSC | PORTSC_PRC | PORTSC_PED
    | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 22) | (1 << 23);

// ---------------------------------------------------------------------------
// IMAN bits
// ---------------------------------------------------------------------------

/// Interrupt Pending.
pub const IMAN_IP: u32 = 1 << 0;
/// Interrupt Enable.
pub const IMAN_IE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// ERDP bits
// ---------------------------------------------------------------------------

/// Event Handler Busy.
pub const ERDP_EHB: u64 = 1 << 3;

// ---------------------------------------------------------------------------
// CRCR bits
// ---------------------------------------------------------------------------

/// Ring Cycle State.
pub const CRCR_RCS: u64 = 1 << 0;

// ---------------------------------------------------------------------------
// HCSPARAMS1 extractors
// ---------------------------------------------------------------------------

/// Extract MaxSlots from HCSPARAMS1.
pub fn hcs1_max_slots(hcs1: u32) -> u8 {
    (hcs1 & 0xFF) as u8
}

/// Extract MaxPorts from HCSPARAMS1.
pub fn hcs1_max_ports(hcs1: u32) -> u8 {
    ((hcs1 >> 24) & 0xFF) as u8
}

// ---------------------------------------------------------------------------
// HCSPARAMS2 extractors
// ---------------------------------------------------------------------------

/// Extract Max Scratchpad Buffers from HCSPARAMS2.
/// Combined from bits 31:27 (hi) and 25:21 (lo).
pub fn hcs2_max_scratchpad(hcs2: u32) -> u32 {
    let hi = (hcs2 >> 27) & 0x1F;
    let lo = (hcs2 >> 21) & 0x1F;
    (hi << 5) | lo
}

// ---------------------------------------------------------------------------
// HCCPARAMS1 extractors
// ---------------------------------------------------------------------------

/// Extract Context Size flag (CSZ) from HCCPARAMS1. If 1, 64-byte contexts.
pub fn hcc1_csz(hcc1: u32) -> bool {
    hcc1 & (1 << 2) != 0
}

/// Extract xECP (Extended Capabilities Pointer) from HCCPARAMS1.
/// Bits 31:16 give the offset in DWORDs from the MMIO base (multiply by 4
/// for byte offset). 0 means there are no extended capabilities.
pub fn hcc1_xecp(hcc1: u32) -> u32 {
    (hcc1 >> 16) & 0xFFFF
}

// ---------------------------------------------------------------------------
// Extended Capabilities — USB Legacy Support (cap ID 0x01)
// ---------------------------------------------------------------------------

/// Extended Capability ID for USB Legacy Support (xHCI 1.x §7.1).
pub const XECP_ID_USBLEGSUP: u32 = 0x01;
/// Extended Capability ID for Supported Protocol (xHCI 1.x §7.2).
/// Used to learn which root-hub ports are USB2 vs USB3 — xHCI splits the
/// port number space between the two and the same physical port appears
/// twice (once per protocol).
pub const XECP_ID_SUPPORTED_PROTOCOL: u32 = 0x02;

/// USBLEGSUP byte offset relative to the cap base (the first dword of
/// the cap is the cap header itself).
pub const USBLEGSUP_OFFSET: usize = 0x00;
/// USBLEGCTLSTS — control/status follows USBLEGSUP at +4. Bits 0..4 are
/// SMI enables, bits 16..19 are SMI status.
pub const USBLEGCTLSTS_OFFSET: usize = 0x04;

/// HC BIOS Owned Semaphore — set to 1 by BIOS to claim the controller,
/// cleared by BIOS when the OS takes over.
pub const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
/// HC OS Owned Semaphore — written by the OS to request ownership.
pub const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

/// Mask of all SMI enable bits in USBLEGCTLSTS (bits 0..4 + 13..16).
/// We clear these after handoff so a buggy BIOS can't pull SMIs that
/// trap back into firmware while we're using the controller.
pub const USBLEGCTLSTS_SMI_ENABLES: u32 = 0xFFFF_0000;

// ---------------------------------------------------------------------------
// Port register offset
// ---------------------------------------------------------------------------

/// Extract Port Speed from PORTSC (bits 13:10).
/// 1=Full, 2=Low, 3=High, 4=SuperSpeed.
pub fn portsc_speed(portsc: u32) -> u8 {
    ((portsc >> 10) & 0xF) as u8
}

/// Default EP0 MaxPacketSize for a given port speed.
pub fn ep0_max_packet_for_speed(speed: u8) -> u16 {
    match speed {
        1 => 8,    // Full Speed
        2 => 8,    // Low Speed
        3 => 64,   // High Speed
        4 => 512,  // SuperSpeed
        _ => 64,
    }
}

/// PORTSC offset for 1-based port number.
pub fn portsc_offset(port: u8) -> usize {
    OP_PORTSC_BASE + ((port as usize - 1) * 0x10)
}

// ---------------------------------------------------------------------------
// Volatile MMIO helpers (same pattern as sotos-nvme)
// ---------------------------------------------------------------------------

/// Volatile read of a single byte at `base + offset`.
///
/// # Safety
/// `base` must point to a valid MMIO region (UC-mapped) of at least
/// `offset + 1` bytes; the caller is responsible for the lifetime and
/// alignment of the mapping.
#[inline]
pub unsafe fn read8(base: *const u8, offset: usize) -> u8 {
    let ptr = base.add(offset);
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile read of a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a valid MMIO region (UC-mapped) of at least
/// `offset + 4` bytes.
#[inline]
pub unsafe fn read32(base: *const u8, offset: usize) -> u32 {
    let ptr = base.add(offset) as *const u32;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile write of a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a writable, UC-mapped MMIO region of at least
/// `offset + 4` bytes.
#[inline]
pub unsafe fn write32(base: *mut u8, offset: usize, val: u32) {
    let ptr = base.add(offset) as *mut u32;
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Volatile read of a 64-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a valid MMIO region (UC-mapped) of at least
/// `offset + 8` bytes.
#[inline]
pub unsafe fn read64(base: *const u8, offset: usize) -> u64 {
    let ptr = base.add(offset) as *const u64;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile write of a 64-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a writable, UC-mapped MMIO region of at least
/// `offset + 8` bytes.
#[inline]
pub unsafe fn write64(base: *mut u8, offset: usize, val: u64) {
    let ptr = base.add(offset) as *mut u64;
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Volatile read of a 16-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a valid MMIO region (UC-mapped) of at least
/// `offset + 2` bytes.
#[inline]
pub unsafe fn read16(base: *const u8, offset: usize) -> u16 {
    let ptr = base.add(offset) as *const u16;
    unsafe { core::ptr::read_volatile(ptr) }
}
