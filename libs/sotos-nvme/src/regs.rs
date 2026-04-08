//! NVMe controller MMIO register offsets and volatile access helpers.
//!
//! All offsets are relative to BAR0 and match NVMe 1.4 §3.1 (Controller
//! Properties). The doorbell array starts at `0x1000` and its stride is
//! encoded in `CAP.DSTRD`; use [`sq_doorbell_offset`] /
//! [`cq_doorbell_offset`] rather than hard-coding offsets.

/// `CAP` — Controller Capabilities (64-bit, RO). NVMe 1.4 §3.1.1.
pub const REG_CAP: usize = 0x00;
/// `VS` — Version (32-bit, RO). High word major, mid byte minor.
pub const REG_VS: usize = 0x08;
/// `INTMS` — Interrupt Mask Set (32-bit, RW1S).
pub const REG_INTMS: usize = 0x0C;
/// `INTMC` — Interrupt Mask Clear (32-bit, RW1C).
pub const REG_INTMC: usize = 0x10;
/// `CC` — Controller Configuration (32-bit, RW). NVMe 1.4 §3.1.5.
pub const REG_CC: usize = 0x14;
/// `CSTS` — Controller Status (32-bit, RO). NVMe 1.4 §3.1.6.
pub const REG_CSTS: usize = 0x1C;
/// `AQA` — Admin Queue Attributes (32-bit, RW). Holds 0-based ASQS/ACQS.
pub const REG_AQA: usize = 0x24;
/// `ASQ` — Admin Submission Queue Base Address (64-bit, RW). Physical.
pub const REG_ASQ: usize = 0x28;
/// `ACQ` — Admin Completion Queue Base Address (64-bit, RW). Physical.
pub const REG_ACQ: usize = 0x30;

/// `CC.EN` — controller enable bit. Write 1 to start, 0 to reset.
pub const CC_EN: u32 = 1 << 0;
/// `CC.CSS` field set to *NVM command set* (bits 6:4 = 0).
pub const CC_CSS_NVM: u32 = 0 << 4;
/// `CC.MPS` field set to 4 KiB host page size (bits 10:7 = 0,
/// meaning 2^(12+0) = 4096 bytes).
pub const CC_MPS_4K: u32 = 0 << 7;
/// `CC.AMS` field set to round-robin arbitration (bits 13:11 = 0).
pub const CC_AMS_RR: u32 = 0 << 11;
/// `CC.IOSQES` = 6 → 2^6 = 64 byte SQ entries (bits 19:16).
pub const CC_IOSQES_64: u32 = 6 << 16;
/// `CC.IOCQES` = 4 → 2^4 = 16 byte CQ entries (bits 23:20).
pub const CC_IOCQES_16: u32 = 4 << 20;

/// `CSTS.RDY` — set by the controller once it is ready to accept
/// admin commands after a CC.EN transition.
pub const CSTS_RDY: u32 = 1 << 0;

/// Volatile read of a 32-bit MMIO register at `base + offset`.
///
/// # Safety
/// `base` must point to a valid MMIO region (UC-mapped) of at least
/// `offset + 4` bytes; the caller is responsible for the lifetime and
/// alignment of the mapping.
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

/// Extract `MQES` (Maximum Queue Entries Supported) from a `CAP` value.
///
/// MQES is 0-based, so the actual maximum queue depth is `MQES + 1`.
pub fn cap_mqes(cap: u64) -> u16 {
    (cap & 0xFFFF) as u16
}

/// Extract `DSTRD` (Doorbell Stride) from a `CAP` value.
///
/// The doorbell register stride in bytes is `2^(2 + DSTRD)`.
pub fn cap_dstrd(cap: u64) -> u8 {
    ((cap >> 32) & 0xF) as u8
}

/// Compute the offset of submission-queue *y*'s tail doorbell.
///
/// Per NVMe 1.4 §3.1.20: `0x1000 + (2y) * (4 << DSTRD)`. `qid = 0` is
/// the admin queue.
pub fn sq_doorbell_offset(qid: u16, dstrd: u8) -> usize {
    0x1000 + (2 * qid as usize) * (4 << dstrd as usize)
}

/// Compute the offset of completion-queue *y*'s head doorbell.
///
/// Per NVMe 1.4 §3.1.21: `0x1000 + (2y + 1) * (4 << DSTRD)`. `qid = 0`
/// is the admin queue.
pub fn cq_doorbell_offset(qid: u16, dstrd: u8) -> usize {
    0x1000 + (2 * qid as usize + 1) * (4 << dstrd as usize)
}
