//! NVMe Submission and Completion queue layouts and ring state.
//!
//! Mirrors NVMe 1.4 §4.2 (SQE, 64 bytes) and §4.6 (CQE, 16 bytes). The
//! queue ring buffers themselves are caller-owned pages — this module
//! only describes the per-entry layout and the head/tail bookkeeping.

/// NVMe Submission Queue Entry — 64 bytes, `repr(C)`.
///
/// Layout matches NVMe 1.4 §4.2 exactly so the controller can DMA from
/// it. Most callers should not write fields directly; use the helpers
/// in [`crate::cmd`] which return a fully-built entry ready for
/// [`SubmissionQueue::submit`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqEntry {
    /// Command Dword 0: opcode (7:0), fuse (9:8), PSDT (15:14), CID (31:16).
    pub cdw0: u32,
    /// Namespace identifier (`NSID`).
    pub nsid: u32,
    /// Reserved — controller writes 0. Bytes 8..12.
    pub cdw2: u32,
    /// Reserved — controller writes 0. Bytes 12..16.
    pub cdw3: u32,
    /// Metadata pointer (`MPTR`). 0 when no metadata is in use.
    pub mptr: u64,
    /// Data pointer — PRP Entry 1.
    pub prp1: u64,
    /// Data pointer — PRP Entry 2, or PRP List physical address when
    /// the transfer spans more than two pages.
    pub prp2: u64,
    /// Command-specific Dword 10 (e.g. LBA low for NVM I/O).
    pub cdw10: u32,
    /// Command-specific Dword 11 (e.g. LBA high for NVM I/O).
    pub cdw11: u32,
    /// Command-specific Dword 12 (e.g. NLB for NVM I/O).
    pub cdw12: u32,
    /// Command-specific Dword 13.
    pub cdw13: u32,
    /// Command-specific Dword 14.
    pub cdw14: u32,
    /// Command-specific Dword 15.
    pub cdw15: u32,
}

const _: () = assert!(core::mem::size_of::<SqEntry>() == 64);

impl SqEntry {
    /// All-zeros SQE. `const` so command builders can construct one
    /// without runtime cost.
    pub const fn zeroed() -> Self {
        Self {
            cdw0: 0, nsid: 0, cdw2: 0, cdw3: 0,
            mptr: 0, prp1: 0, prp2: 0,
            cdw10: 0, cdw11: 0, cdw12: 0,
            cdw13: 0, cdw14: 0, cdw15: 0,
        }
    }
}

/// NVMe Completion Queue Entry — 16 bytes, `repr(C)`.
///
/// Mirrors NVMe 1.4 §4.6. The controller writes one CQE per completed
/// command and toggles the *phase* bit on each wrap so software can
/// detect new entries without an explicit head pointer in MMIO.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CqEntry {
    /// Command-specific result (DW0).
    pub dw0: u32,
    /// Reserved (DW1).
    pub dw1: u32,
    /// SQ Head Pointer (15:0) | SQ Identifier (31:16).
    pub sq_head_sqid: u32,
    /// Command ID (15:0) | Phase Tag (16) | Status Field (31:17).
    pub cid_status: u32,
}

const _: () = assert!(core::mem::size_of::<CqEntry>() == 16);

impl CqEntry {
    /// All-zeros CQE; useful for initialising buffers.
    pub const fn zeroed() -> Self {
        Self { dw0: 0, dw1: 0, sq_head_sqid: 0, cid_status: 0 }
    }

    /// Extract the phase bit (DW3 bit 16). Compared against the
    /// driver's expected phase to decide whether the slot is filled.
    pub fn phase(&self) -> bool {
        (self.cid_status & (1 << 16)) != 0
    }

    /// Extract the 15-bit Status Field from DW3 bits 31:17.
    ///
    /// `0` indicates success; non-zero is a status code from NVMe 1.4
    /// §4.6.1 (Status Code Type / Status Code).
    pub fn status(&self) -> u16 {
        ((self.cid_status >> 17) & 0x7FFF) as u16
    }

    /// Extract the 16-bit Command ID echoed from the original SQE.
    pub fn cid(&self) -> u16 {
        (self.cid_status & 0xFFFF) as u16
    }
}

/// Default queue depth (entries) used by the driver. Kept small so a
/// single 4 KiB page holds the SQ and the CQ comfortably.
pub const QUEUE_DEPTH: usize = 32;

/// Number of [`SqEntry`] slots that fit in one 4 KiB page (64 bytes
/// per entry → 64 entries).
pub const SQ_ENTRIES_PER_PAGE: usize = 4096 / 64; // 64

/// Number of [`CqEntry`] slots that fit in one 4 KiB page (16 bytes
/// per entry → 256 entries).
pub const CQ_ENTRIES_PER_PAGE: usize = 4096 / 16; // 256

/// Software-side state for an NVMe Submission Queue ring.
///
/// Owns the producer cursor (`tail`) and the next-CID counter; the
/// underlying memory is provided by the caller and lives at `base` /
/// `phys`.
pub struct SubmissionQueue {
    /// Virtual address of the SQ buffer (page-aligned).
    pub base: *mut SqEntry,
    /// Physical address of the SQ buffer (the value programmed into
    /// `ASQ`/`PRP1` when the queue is created).
    pub phys: u64,
    /// Current tail index — slot the next [`submit`](Self::submit)
    /// call will populate. Wraps modulo `depth`.
    pub tail: u16,
    /// Queue depth in entries (matches the value passed to the
    /// controller in CDW10 + 1).
    pub depth: u16,
    /// Next command ID to assign. Wraps on overflow; the kernel does
    /// not track in-flight CIDs.
    pub next_cid: u16,
}

impl SubmissionQueue {
    /// Wrap a pre-allocated SQ buffer.
    ///
    /// Zeroes `depth * 64` bytes starting at `virt` so a freshly
    /// allocated DMA page is in a known state. `phys` is the physical
    /// address that the controller will use for DMA.
    pub fn new(virt: *mut u8, phys: u64, depth: u16) -> Self {
        // Zero-init the queue memory.
        unsafe { core::ptr::write_bytes(virt, 0, depth as usize * 64); }
        Self {
            base: virt as *mut SqEntry,
            phys,
            tail: 0,
            depth,
            next_cid: 0,
        }
    }

    /// Write `entry` into the slot at `tail`, advance `tail`, and
    /// return the assigned command ID.
    ///
    /// `entry.cdw0` has its CID field overwritten with the next CID
    /// from the internal counter; the caller does not need to set it.
    /// The doorbell is *not* rung — the caller must follow up with the
    /// appropriate `regs::write32` to the SQ tail doorbell.
    pub fn submit(&mut self, mut entry: SqEntry) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        // Set CID in CDW0 bits 31:16.
        entry.cdw0 = (entry.cdw0 & 0xFFFF) | ((cid as u32) << 16);
        unsafe {
            core::ptr::write_volatile(self.base.add(self.tail as usize), entry);
        }
        self.tail = (self.tail + 1) % self.depth;
        cid
    }
}

/// Software-side state for an NVMe Completion Queue ring.
///
/// Tracks the consumer cursor (`head`) and the expected phase bit;
/// the underlying memory is provided by the caller.
pub struct CompletionQueue {
    /// Virtual address of the CQ buffer (page-aligned).
    pub base: *mut CqEntry,
    /// Physical address of the CQ buffer.
    pub phys: u64,
    /// Current head index — next slot to inspect.
    pub head: u16,
    /// Queue depth in entries.
    pub depth: u16,
    /// Phase bit the next valid CQE is expected to carry. Toggles on
    /// every wrap of `head` per NVMe 1.4 §4.6.
    pub phase: bool,
}

impl CompletionQueue {
    /// Wrap a pre-allocated CQ buffer.
    ///
    /// Zeroes `depth * 16` bytes starting at `virt`. Phase starts at
    /// `true` (matches the spec's initial expected value of 1).
    pub fn new(virt: *mut u8, phys: u64, depth: u16) -> Self {
        // Zero-init the queue memory.
        unsafe { core::ptr::write_bytes(virt, 0, depth as usize * 16); }
        Self {
            base: virt as *mut CqEntry,
            phys,
            head: 0,
            depth,
            phase: true, // Phase starts at 1
        }
    }

    /// Volatile-read the slot at `head` and return it if its phase bit
    /// matches the expected phase, i.e. if the controller has posted a
    /// new completion. Returns `None` otherwise.
    pub fn poll(&self) -> Option<CqEntry> {
        let entry = unsafe { core::ptr::read_volatile(self.base.add(self.head as usize)) };
        if entry.phase() == self.phase {
            Some(entry)
        } else {
            None
        }
    }

    /// Advance `head` past the just-consumed CQE, wrapping and
    /// flipping the expected phase bit on overflow.
    pub fn advance(&mut self) {
        self.head += 1;
        if self.head >= self.depth {
            self.head = 0;
            self.phase = !self.phase;
        }
    }
}
