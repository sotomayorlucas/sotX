//! NVMe command opcodes and SQE builders.
//!
//! All builders return a fully-populated [`SqEntry`] with `cdw0.opcode`
//! set; the command ID is filled in later by
//! [`crate::queue::SubmissionQueue::submit`]. Field encodings follow
//! NVMe 1.4 §5 (Admin Command Set) and §6 (NVM Command Set).

use crate::queue::SqEntry;

// --- Admin command opcodes (NVMe 1.4 Figure 139) ---

/// Identify — admin opcode `0x06`. CNS in CDW10 selects controller vs
/// namespace data structure.
pub const ADMIN_IDENTIFY: u8 = 0x06;
/// Create I/O Completion Queue — admin opcode `0x05`.
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
/// Create I/O Submission Queue — admin opcode `0x01`.
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;

// --- I/O command opcodes (NVMe 1.4 NVM command set, Figure 346) ---

/// Read — NVM I/O opcode `0x02`.
pub const IO_READ: u8 = 0x02;
/// Write — NVM I/O opcode `0x01`.
pub const IO_WRITE: u8 = 0x01;

/// Build an *Identify Controller* command (CNS = `0x01`).
///
/// `prp1_phys` is the physical address of a 4 KiB host buffer the
/// controller will fill with the Identify Controller data structure
/// (NVMe 1.4 §5.15.2.1).
pub fn identify_controller(prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_IDENTIFY as u32;
    e.prp1 = prp1_phys;
    e.cdw10 = 1; // CNS = 01h (Identify Controller)
    e
}

/// Build an *Identify Namespace* command (CNS = `0x00`).
///
/// `nsid` selects the namespace; `prp1_phys` is the host buffer for
/// the Identify Namespace data structure (NVMe 1.4 §5.15.2.2).
pub fn identify_namespace(nsid: u32, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_IDENTIFY as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = 0; // CNS = 00h (Identify Namespace)
    e
}

/// Build a *Create I/O Completion Queue* admin command.
///
/// - `qid`: I/O completion queue identifier (1-based).
/// - `prp1_phys`: physical address of the (physically contiguous) CQ
///   buffer.
/// - `size`: 0-based queue size, i.e. `actual_entries - 1`.
///
/// CDW11 hard-codes `IEN=1, PC=1` (interrupts enabled, physically
/// contiguous). Interrupt vector is left at 0.
pub fn create_io_cq(qid: u16, prp1_phys: u64, size: u16) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_CREATE_IO_CQ as u32;
    e.prp1 = prp1_phys;
    // CDW10: QSIZE (31:16) | QID (15:0)
    e.cdw10 = ((size as u32) << 16) | (qid as u32);
    // CDW11: IEN=1 (bit 1), PC=1 (bit 0) — physically contiguous, interrupts enabled
    e.cdw11 = 0x03;
    e
}

/// Build a *Create I/O Submission Queue* admin command.
///
/// - `qid`: I/O submission queue identifier (1-based).
/// - `prp1_phys`: physical address of the (physically contiguous) SQ
///   buffer.
/// - `size`: 0-based queue size.
/// - `cqid`: identifier of the completion queue this SQ should post to.
///
/// CDW11 sets `PC=1` and queue priority `0` (urgent).
pub fn create_io_sq(qid: u16, prp1_phys: u64, size: u16, cqid: u16) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_CREATE_IO_SQ as u32;
    e.prp1 = prp1_phys;
    // CDW10: QSIZE (31:16) | QID (15:0)
    e.cdw10 = ((size as u32) << 16) | (qid as u32);
    // CDW11: CQID (31:16) | QPRIO=0 (13:12) | PC=1 (bit 0)
    e.cdw11 = ((cqid as u32) << 16) | 0x01;
    e
}

/// Build a single-PRP NVM *Read* command.
///
/// - `nsid`: namespace identifier.
/// - `lba`: starting logical block address (split across CDW10/CDW11).
/// - `count`: 0-based number of logical blocks (NLB) to read.
/// - `prp1_phys`: physical address of the data buffer; must be
///   page-aligned for DMA. Single-PRP transfers are at most one host
///   page (4 KiB at the configured MPS).
pub fn io_read(nsid: u32, lba: u64, count: u16, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_READ as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build an NVM *Read* command with PRP1 + PRP2 set, supporting up to
/// two pages directly or a PRP-list page in PRP2 for larger transfers.
///
/// - `nsid`: namespace identifier.
/// - `lba`: starting LBA.
/// - `count`: 0-based NLB.
/// - `prp1_phys`: physical address of the first data page.
/// - `prp2_phys`: physical address of the second data page if exactly
///   two pages, or the physical address of a PRP List page when the
///   transfer spans more than two pages.
pub fn io_read_prp(nsid: u32, lba: u64, count: u16, prp1_phys: u64, prp2_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_READ as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.prp2 = prp2_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build a single-PRP NVM *Write* command.
///
/// Mirror of [`io_read`] for the NVM Write opcode (`0x01`). Same
/// alignment and length constraints apply to `prp1_phys`.
pub fn io_write(nsid: u32, lba: u64, count: u16, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_WRITE as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build an NVM *Write* command with PRP1 + PRP2 set.
///
/// Mirror of [`io_read_prp`] for the NVM Write opcode. Used by
/// `crate::io::write_sectors_prp` for multi-page transfers.
pub fn io_write_prp(nsid: u32, lba: u64, count: u16, prp1_phys: u64, prp2_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_WRITE as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.prp2 = prp2_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}
