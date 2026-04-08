//! Demand paging — lazy page mapping with deferred physical allocation.
//!
//! Allows registering virtual address regions that won't be backed by
//! physical frames until the first access triggers a page fault. The
//! page fault handler calls `handle_fault` to allocate and map the page
//! on demand.

use crate::kdebug;
use crate::mm::{self, frame::PhysFrame};
use crate::sync::ticket::TicketMutex;

/// Maximum number of lazy-mapped regions tracked globally.
const MAX_DEMAND_ENTRIES: usize = 256;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Flags for demand-paged regions.
#[derive(Debug, Clone, Copy)]
pub struct DemandFlags {
    /// Page is writable.
    pub writable: bool,
    /// Page is user-accessible (Ring 3).
    pub user: bool,
    /// Page is executable (no NX bit).
    pub executable: bool,
}

impl DemandFlags {
    /// Default flags: writable, user-accessible, not executable.
    pub const fn default_user() -> Self {
        Self {
            writable: true,
            user: true,
            executable: false,
        }
    }

    /// Read-only user mapping.
    pub const fn readonly_user() -> Self {
        Self {
            writable: false,
            user: true,
            executable: false,
        }
    }
}

/// A single demand-page region entry.
#[derive(Clone, Copy)]
struct DemandEntry {
    /// Start virtual address (page-aligned).
    vaddr_start: u64,
    /// End virtual address (exclusive, page-aligned).
    vaddr_end: u64,
    /// Mapping flags.
    flags: DemandFlags,
    /// Whether this slot is in use.
    active: bool,
    /// CR3 (address space) this region belongs to (0 = current/kernel).
    cr3: u64,
}

impl DemandEntry {
    const fn empty() -> Self {
        Self {
            vaddr_start: 0,
            vaddr_end: 0,
            flags: DemandFlags {
                writable: false,
                user: false,
                executable: false,
            },
            active: false,
            cr3: 0,
        }
    }

    /// Check if a virtual address falls within this region.
    fn contains(&self, vaddr: u64) -> bool {
        self.active && vaddr >= self.vaddr_start && vaddr < self.vaddr_end
    }
}

/// The global demand page table.
struct DemandPageTable {
    entries: [DemandEntry; MAX_DEMAND_ENTRIES],
}

impl DemandPageTable {
    const fn new() -> Self {
        Self {
            entries: [DemandEntry::empty(); MAX_DEMAND_ENTRIES],
        }
    }

    /// Find an empty slot.
    fn find_free_slot(&self) -> Option<usize> {
        for i in 0..MAX_DEMAND_ENTRIES {
            if !self.entries[i].active {
                return Some(i);
            }
        }
        None
    }

    /// Find the entry covering a given virtual address in a given address space.
    fn find_entry(&self, vaddr: u64, cr3: u64) -> Option<usize> {
        for i in 0..MAX_DEMAND_ENTRIES {
            if self.entries[i].active
                && self.entries[i].cr3 == cr3
                && self.entries[i].contains(vaddr)
            {
                return Some(i);
            }
        }
        None
    }
}

static DEMAND_TABLE: TicketMutex<DemandPageTable> = TicketMutex::new(DemandPageTable::new());

/// Register a lazy-mapped virtual region.
///
/// No physical memory is allocated until a page fault occurs within this region.
/// `vaddr` must be page-aligned. `size` is rounded up to a page boundary.
/// `cr3` identifies the address space (0 for kernel/current).
///
/// Returns `true` if successfully registered, `false` if the table is full.
pub fn register_lazy(vaddr: u64, size: u64, flags: DemandFlags, cr3: u64) -> bool {
    let aligned_start = vaddr & !(PAGE_SIZE - 1);
    let aligned_end = (vaddr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut table = DEMAND_TABLE.lock();
    let slot = match table.find_free_slot() {
        Some(s) => s,
        None => return false,
    };

    table.entries[slot] = DemandEntry {
        vaddr_start: aligned_start,
        vaddr_end: aligned_end,
        flags,
        active: true,
        cr3,
    };

    kdebug!(
        "demand: registered lazy region {:#x}..{:#x} cr3={:#x}",
        aligned_start,
        aligned_end,
        cr3
    );
    true
}

/// Unregister a lazy-mapped region starting at `vaddr` in address space `cr3`.
///
/// Returns `true` if found and removed.
pub fn unregister_lazy(vaddr: u64, cr3: u64) -> bool {
    let aligned = vaddr & !(PAGE_SIZE - 1);
    let mut table = DEMAND_TABLE.lock();
    for i in 0..MAX_DEMAND_ENTRIES {
        if table.entries[i].active
            && table.entries[i].cr3 == cr3
            && table.entries[i].vaddr_start == aligned
        {
            table.entries[i].active = false;
            return true;
        }
    }
    false
}

/// Handle a page fault at `vaddr` in address space `cr3`.
///
/// If the faulting address falls within a registered demand-page region,
/// allocates a physical frame and returns it. The caller is responsible
/// for mapping the frame into the page tables with the appropriate flags.
///
/// Returns `Some((frame, flags))` if a frame was allocated for this fault,
/// or `None` if the address is not in any demand-page region.
pub fn handle_fault(vaddr: u64, cr3: u64) -> Option<(PhysFrame, DemandFlags)> {
    let table = DEMAND_TABLE.lock();
    let idx = table.find_entry(vaddr, cr3)?;
    let flags = table.entries[idx].flags;
    drop(table); // Release lock before allocating.

    let frame = mm::alloc_frame()?;

    // Zero the allocated frame for security (prevent information leaks).
    let hhdm = mm::hhdm_offset();
    let frame_virt = (frame.addr() + hhdm) as *mut u8;
    unsafe {
        core::ptr::write_bytes(frame_virt, 0, 4096);
    }

    kdebug!(
        "demand: fault at {:#x} cr3={:#x} -> allocated frame {:#x}",
        vaddr,
        cr3,
        frame.addr()
    );

    Some((frame, flags))
}

/// Return the number of active demand-page regions.
pub fn active_regions() -> usize {
    let table = DEMAND_TABLE.lock();
    table.entries.iter().filter(|e| e.active).count()
}

/// Return the total number of pages covered by all active demand-page regions.
pub fn total_lazy_pages() -> u64 {
    let table = DEMAND_TABLE.lock();
    let mut total = 0u64;
    for entry in &table.entries {
        if entry.active {
            total += (entry.vaddr_end - entry.vaddr_start) / PAGE_SIZE;
        }
    }
    total
}
