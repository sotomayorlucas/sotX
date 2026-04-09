//! Phase D — Real EPT (Extended Page Table) for VT-x guests.
//!
//! Replaces the Phase B `MiniEpt` (which pre-allocated PDPT/PD/PT
//! frames eagerly to identity-map a single 2 MiB window) with a
//! proper 4-level EPT that grows on demand: any guest physical
//! address up to 2^48 can be mapped, intermediate tables are
//! allocated lazily on the first `map_4k` that needs them, and the
//! whole tree is freed back to `mm::alloc_frame` when the
//! `EptRoot` is dropped.
//!
//! The exit dispatcher (`vm::exit::handle_ept_violation`) calls
//! `EptRoot::map_4k` whenever a guest touches a previously-unmapped
//! GPA, allowing the kernel to declare a 256 MiB guest budget but
//! only allocate host frames for the pages the guest actually
//! touches — exactly the lazy-faulted memory model the Phase F
//! Linux boot needs to fit in tens of MiB instead of hundreds.
//!
//! ## EPT layout
//!
//! Same shape as x86_64 4-level paging: PML4 → PDPT → PD → PT, with
//! 4 KiB leaves at the PT level. Each table is a 4 KiB physical frame
//! holding 512 8-byte entries; bits 12..47 of each entry hold the
//! physical address of the next level (or, at the leaf, the host
//! frame), and the low bits encode permissions.
//!
//! ## EPT entry bits (Intel SDM Vol 3C 28.2.2)
//!
//! Non-leaf (any of PML4 / PDPT / PD / PT pointing to another table):
//!   bit 0    R   — read access permitted
//!   bit 1    W   — write access permitted
//!   bit 2    X   — supervisor execute permitted
//!   bits 3-5 reserved (must be 0 for non-leaf)
//!   bit 7    PS  — page size; 0 = pointer to next level
//!
//! 4 KiB leaf (PT entry):
//!   bit 0    R
//!   bit 1    W
//!   bit 2    X (supervisor)
//!   bits 3-5 EPT memory type (0=UC, 1=WC, 4=WT, 5=WP, 6=WB)
//!   bit 6    Ignore PAT (combine memory type with guest's PAT)
//!   bit 7    must be 0 (PS=1 only valid at PD/PDPT levels for huge pages)
//!
//! Phase D uses 4 KiB leaves only — Phase F may add 2 MiB / 1 GiB
//! huge pages at the PD/PDPT level once we measure boot-time TLB
//! pressure under real Linux.

use crate::mm;
use crate::mm::PhysFrame;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// EPT non-leaf entry permission bits: R | W | X.
const EPT_NONLEAF_FLAGS: u64 = 0b111;

/// EPT leaf entry default permissions: R | W | X | (WB << 3).
/// `R|W|X` is `0x07`, memory type WB is `6 << 3 = 0x30`. Combined:
/// `0x37`. Bit 6 (Ignore PAT) is left clear; the host PAT applies.
pub const EPT_LEAF_RWX_WB: u64 = 0x07 | (6 << 3);

/// Mask of the physical-address bits in an EPT entry. Bits 12..51
/// hold the next-level / leaf frame address.
const EPT_PA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Errors raised by the EPT module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptError {
    /// `mm::alloc_frame()` returned None while building an intermediate
    /// table or installing a leaf.
    OutOfFrames,
    /// `gpa` had non-zero bits beyond the 48-bit guest physical limit
    /// or wasn't 4 KiB aligned.
    BadGpa,
    /// `host_phys` wasn't 4 KiB aligned.
    BadHpa,
}

/// Index helpers — same as the kernel paging module, but kept local
/// so we don't accidentally couple EPT walks to host CR3 walks.
#[inline]
fn pml4_index(gpa: u64) -> usize {
    ((gpa >> 39) & 0x1FF) as usize
}
#[inline]
fn pdpt_index(gpa: u64) -> usize {
    ((gpa >> 30) & 0x1FF) as usize
}
#[inline]
fn pd_index(gpa: u64) -> usize {
    ((gpa >> 21) & 0x1FF) as usize
}
#[inline]
fn pt_index(gpa: u64) -> usize {
    ((gpa >> 12) & 0x1FF) as usize
}

/// A 4-level Extended Page Table.
///
/// Owns its `pml4_phys` frame plus every intermediate table the
/// `map_4k` walks have lazily allocated. `Drop` walks the whole tree
/// and returns every page to the frame allocator — leaf entries are
/// **not** freed because the leaves point at frames owned by the
/// guest's memory budget (the exit dispatcher allocates them on
/// demand and they're released by `VmObject::destroy`).
pub struct EptRoot {
    /// Physical address of the PML4 frame. The VMCS EPTP field gets
    /// `pml4_phys | (3 << 3) | 6` — 4-level walk + WB memory type.
    pub pml4_phys: u64,
    /// Every intermediate-level table frame the EPT has allocated so
    /// far, recorded so `Drop` can free them. PT frames at the leaf
    /// level are included; their leaf entries (which point at guest
    /// memory frames) are NOT freed here — those belong to the VM
    /// pool and are released via `VmObject::destroy`.
    intermediate_frames: Vec<u64>,
}

impl EptRoot {
    /// Allocate an empty EPT. Only the PML4 frame is allocated up
    /// front; the rest of the tree is filled in by `map_4k`.
    pub fn new() -> Result<Self, EptError> {
        let pml4 = mm::alloc_frame().ok_or(EptError::OutOfFrames)?;
        let pml4_phys = pml4.addr();
        zero_frame(pml4_phys);
        Ok(Self {
            pml4_phys,
            intermediate_frames: Vec::new(),
        })
    }

    /// Map a 4 KiB guest physical page to a 4 KiB host physical
    /// frame, with the given leaf flags (typically `EPT_LEAF_RWX_WB`).
    /// Allocates intermediate PDPT / PD / PT frames lazily.
    ///
    /// Both `gpa` and `host_phys` must be 4 KiB aligned. `gpa` must
    /// fit in 48 bits.
    pub fn map_4k(&mut self, gpa: u64, host_phys: u64, leaf_flags: u64) -> Result<(), EptError> {
        if gpa & 0xFFF != 0 || gpa >> 48 != 0 {
            return Err(EptError::BadGpa);
        }
        if host_phys & 0xFFF != 0 {
            return Err(EptError::BadHpa);
        }
        let pdpt_phys = self.ensure_next_level(self.pml4_phys, pml4_index(gpa))?;
        let pd_phys = self.ensure_next_level(pdpt_phys, pdpt_index(gpa))?;
        let pt_phys = self.ensure_next_level(pd_phys, pd_index(gpa))?;
        // Install the leaf entry. Overwrites any prior mapping at the
        // same GPA — Phase D never re-maps so this is effectively
        // first-write-wins; Phase F will add a "remap or fault" check.
        let leaf_idx = pt_index(gpa);
        write_entry(pt_phys, leaf_idx, host_phys | leaf_flags);
        Ok(())
    }

    /// Walk the EPT and return the host physical frame backing `gpa`,
    /// or `None` if there is no leaf at that GPA. Used by sanity
    /// checks and the lazy-fault dispatcher to detect double faults.
    #[allow(dead_code)]
    pub fn walk(&self, gpa: u64) -> Option<u64> {
        if gpa & 0xFFF != 0 {
            return None;
        }
        let pdpt_phys = read_entry_phys(self.pml4_phys, pml4_index(gpa))?;
        let pd_phys = read_entry_phys(pdpt_phys, pdpt_index(gpa))?;
        let pt_phys = read_entry_phys(pd_phys, pd_index(gpa))?;
        read_entry_phys(pt_phys, pt_index(gpa))
    }

    /// EPTP value for `vmwrite(VMCS_EPTP, ...)`. Encodes:
    ///   bits 0-2:   memory type (6 = WB)
    ///   bits 3-5:   page-walk length minus 1 (3 → 4-level)
    ///   bit 6:      accessed/dirty flag enable (we leave it 0)
    ///   bits 12-N:  PML4 physical address
    pub fn eptp(&self) -> u64 {
        self.pml4_phys | (3 << 3) | 6
    }

    /// Internal: ensure the entry at `(table_phys, idx)` points at a
    /// next-level table; allocate one + record it for cleanup if not.
    /// Returns the physical address of the next-level table.
    fn ensure_next_level(&mut self, table_phys: u64, idx: usize) -> Result<u64, EptError> {
        let entry = read_entry(table_phys, idx);
        if entry & 0x1 != 0 {
            // Bit 0 (R) set on a non-leaf entry means "this points at
            // a populated table". The next-level frame is in bits
            // 12..51.
            return Ok(entry & EPT_PA_MASK);
        }
        // Allocate a new intermediate table and link it in.
        let next = mm::alloc_frame().ok_or(EptError::OutOfFrames)?;
        let next_phys = next.addr();
        zero_frame(next_phys);
        write_entry(table_phys, idx, next_phys | EPT_NONLEAF_FLAGS);
        self.intermediate_frames.push(next_phys);
        Ok(next_phys)
    }
}

impl Drop for EptRoot {
    /// Free every table frame this EPT allocated. Leaf-level GUEST
    /// memory frames (the host pages the leaf entries point at) are
    /// NOT freed here — `VmObject::destroy` handles those because the
    /// guest's `mem_pages_used` budget tracks them.
    fn drop(&mut self) {
        for &phys in &self.intermediate_frames {
            mm::free_frame(PhysFrame::from_addr(phys));
        }
        // Free the PML4 frame too.
        mm::free_frame(PhysFrame::from_addr(self.pml4_phys));
        EPT_DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
}

/// Lifetime counter — useful for asserting "all VMs cleaned up" at
/// shutdown and for the Phase D test's "we freed N EPTs" check.
pub static EPT_DROP_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Low-level table I/O via the kernel HHDM
// ---------------------------------------------------------------------------

/// Zero a 4 KiB physical frame via its HHDM mapping. The kernel maps
/// all RAM in the upper half so we can write directly without an
/// extra `map_page` step.
fn zero_frame(phys: u64) {
    let virt = phys + mm::hhdm_offset();
    // SAFETY: caller passes a freshly-allocated 4 KiB frame whose
    // HHDM mapping is writable; nothing else holds a reference.
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
    }
}

/// Read the raw 8-byte entry at `(table_phys, idx)`.
fn read_entry(table_phys: u64, idx: usize) -> u64 {
    let virt = table_phys + mm::hhdm_offset();
    // SAFETY: `table_phys` is an EPT table frame this module
    // allocated; `idx` is in `0..512`. The HHDM mapping makes the
    // read sound.
    unsafe { *(virt as *const u64).add(idx) }
}

/// Write the raw 8-byte entry at `(table_phys, idx)`.
fn write_entry(table_phys: u64, idx: usize, value: u64) {
    let virt = table_phys + mm::hhdm_offset();
    // SAFETY: same as `read_entry`. Writes are bounded by `0..512`
    // and use the HHDM mapping.
    unsafe {
        *(virt as *mut u64).add(idx) = value;
    }
}

/// For non-leaf entries: extract the next-level physical address if
/// the entry is present, else None.
fn read_entry_phys(table_phys: u64, idx: usize) -> Option<u64> {
    let entry = read_entry(table_phys, idx);
    if entry & 0x1 == 0 {
        None
    } else {
        Some(entry & EPT_PA_MASK)
    }
}
