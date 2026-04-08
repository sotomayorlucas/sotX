//! Bootstrap page tables for user processes.
//!
//! The steady-state VMM server handles paging in userspace.
//! This module provides the minimal kernel-side support needed
//! to create the first user address space.

use super::{alloc_frame, hhdm_offset};

pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;
#[allow(dead_code)]
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

/// Boot-time CR3 value (Limine's page tables). Stored once at init.
static BOOT_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// W^X relaxation bitmap — per-address-space opt-out of W^X enforcement.
// Used by Wine/glibc processes that need RWX pages (IAT fixups, JIT, etc.).
// Lock-free: uses atomic fetch_or/fetch_and for set, atomic load for check.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering};

static WX_RELAXED: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

pub fn set_wx_relaxed(cr3: u64, relaxed: bool) {
    let idx = (cr3 >> 12) as usize % 256;
    let word = idx / 64;
    let bit = idx % 64;
    if relaxed {
        WX_RELAXED[word].fetch_or(1u64 << bit, Ordering::Release);
    } else {
        WX_RELAXED[word].fetch_and(!(1u64 << bit), Ordering::Release);
    }
}

#[inline]
pub fn is_wx_relaxed(cr3: u64) -> bool {
    let idx = (cr3 >> 12) as usize % 256;
    let word = idx / 64;
    let bit = idx % 64;
    WX_RELAXED[word].load(Ordering::Acquire) & (1u64 << bit) != 0
}

/// Read the current CR3 register (physical address of PML4).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Store the boot CR3 for later use (kernel-thread address space).
pub fn init_boot_cr3() {
    BOOT_CR3.store(read_cr3(), core::sync::atomic::Ordering::Relaxed);
}

/// Return the boot CR3 value.
pub fn boot_cr3() -> u64 {
    BOOT_CR3.load(core::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Virtual address → table index extraction
// ---------------------------------------------------------------------------

fn pml4_index(virt: u64) -> usize {
    ((virt >> 39) & 0x1FF) as usize
}
fn pdp_index(virt: u64) -> usize {
    ((virt >> 30) & 0x1FF) as usize
}
fn pd_index(virt: u64) -> usize {
    ((virt >> 21) & 0x1FF) as usize
}
fn pt_index(virt: u64) -> usize {
    ((virt >> 12) & 0x1FF) as usize
}

/// Allocate a zeroed 4 KiB frame for use as a page table.
fn alloc_table_frame() -> u64 {
    let frame = alloc_frame().expect("out of frames for page table");
    let virt = frame.addr() + hhdm_offset();
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
    }
    frame.addr()
}

/// Invalidate the TLB entry for a single page.
pub fn invlpg(vaddr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Flush the entire TLB by reloading CR3.
pub fn flush_tlb() {
    let cr3 = read_cr3();
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// If the entry is present, extract its physical address.
/// Otherwise allocate a new table frame, write the entry, and return its address.
fn ensure_table(entry: &mut u64, flags: u64) -> u64 {
    if *entry & PAGE_PRESENT != 0 {
        *entry & 0x000F_FFFF_FFFF_F000 // mask out flags, extract phys addr
    } else {
        let frame = alloc_table_frame();
        *entry = frame | flags;
        frame
    }
}

// ---------------------------------------------------------------------------
// AddressSpace
// ---------------------------------------------------------------------------

/// A user-mode address space (owns a PML4).
pub struct AddressSpace {
    pml4_phys: u64,
}

impl AddressSpace {
    /// Reconstruct an AddressSpace from a CR3 value.
    pub fn from_cr3(cr3: u64) -> Self {
        Self {
            pml4_phys: cr3 & !0xFFF,
        }
    }

    /// Create a new user address space.
    ///
    /// Allocates a fresh PML4 and copies the kernel-half entries (256..512)
    /// from the boot page tables so the kernel remains mapped.
    pub fn new_user() -> Self {
        let pml4_phys = alloc_table_frame(); // already zeroed
        let pml4_virt = pml4_phys + hhdm_offset();

        // Copy upper-half PML4 entries from the boot page tables.
        // Use boot_cr3() (saved at init) rather than read_cr3() to avoid
        // copying from a user AS if called after context switches start.
        let boot = boot_cr3();
        let boot_pml4_virt = boot + hhdm_offset();

        unsafe {
            let src = boot_pml4_virt as *const u64;
            let dst = pml4_virt as *mut u64;
            for i in 256..512 {
                *dst.add(i) = *src.add(i);
            }
        }

        // Verify kernel code is mapped (PML4[511] must be present).
        let entry_511 = unsafe { *(pml4_virt as *const u64).add(511) };
        debug_assert!(
            entry_511 & 1 != 0,
            "new_user: PML4[511] not present after copy! boot_cr3={:#x} pml4={:#x}",
            boot,
            pml4_phys
        );

        Self { pml4_phys }
    }

    /// Physical address of the PML4 (for loading into CR3).
    pub fn cr3(&self) -> u64 {
        self.pml4_phys
    }

    /// Map a single 4 KiB page.
    ///
    /// `virt` and `phys` must be 4 KiB-aligned.
    /// Intermediate table entries get PRESENT | WRITABLE | USER so that
    /// the final leaf flags control actual permissions.
    pub fn map_page(&self, virt: u64, phys: u64, flags: u64) {
        let hhdm = hhdm_offset();
        let table_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

        // PML4 → PDP
        let pml4 = (self.pml4_phys + hhdm) as *mut u64;
        let pml4e = unsafe { &mut *pml4.add(pml4_index(virt)) };
        let pdp_phys = ensure_table(pml4e, table_flags);

        // PDP → PD
        let pdp = (pdp_phys + hhdm) as *mut u64;
        let pdpe = unsafe { &mut *pdp.add(pdp_index(virt)) };
        let pd_phys = ensure_table(pdpe, table_flags);

        // PD → PT
        let pd = (pd_phys + hhdm) as *mut u64;
        let pde = unsafe { &mut *pd.add(pd_index(virt)) };
        let pt_phys = ensure_table(pde, table_flags);

        // Set PT entry (leaf)
        let pt = (pt_phys + hhdm) as *mut u64;
        unsafe {
            *pt.add(pt_index(virt)) = (phys & !0xFFF) | flags;
        }
    }

    /// Look up the physical address mapped at `virt` in this address space.
    /// Returns `Some(phys_addr)` if the page is present, `None` otherwise.
    pub fn lookup_phys(&self, virt: u64) -> Option<u64> {
        let hhdm = hhdm_offset();

        // PML4 → PDP
        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return None;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        // PDP → PD
        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return None;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        // PD → PT
        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return None;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        // Read leaf PTE
        let pt = (pt_phys + hhdm) as *const u64;
        let pte = unsafe { *pt.add(pt_index(virt)) };
        if pte & PAGE_PRESENT == 0 {
            return None;
        }
        Some(pte & 0x000F_FFFF_FFFF_F000)
    }

    /// Unmap a single 4 KiB page.
    ///
    /// Walks the page table levels (read-only) and clears the leaf PTE.
    /// Returns `true` if the page was present and has been unmapped,
    /// `false` if the walk failed (missing intermediate table or PTE not present).
    pub fn unmap_page(&self, virt: u64) -> bool {
        self.unmap_page_phys(virt).is_some()
    }

    /// Unmap a single 4 KiB page, returning the physical address of the
    /// frame that was mapped there (if any).
    pub fn unmap_page_phys(&self, virt: u64) -> Option<u64> {
        let hhdm = hhdm_offset();

        // PML4 → PDP
        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return None;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        // PDP → PD
        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return None;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        // PD → PT
        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return None;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        // Clear leaf PTE and return its physical address
        let pt = (pt_phys + hhdm) as *mut u64;
        let pte = unsafe { &mut *pt.add(pt_index(virt)) };
        if *pte & PAGE_PRESENT == 0 {
            return None;
        }
        let phys = *pte & 0x000F_FFFF_FFFF_F000;
        *pte = 0;
        Some(phys)
    }

    /// Read the raw PTE for a virtual address. Returns (phys, flags) if present.
    /// Used by VMM for CoW fault handling (to read the old frame address and flags).
    pub fn lookup_pte(&self, virt: u64) -> Option<(u64, u64)> {
        let hhdm = hhdm_offset();

        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return None;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return None;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return None;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        let pt = (pt_phys + hhdm) as *const u64;
        let pte = unsafe { *pt.add(pt_index(virt)) };
        if pte & PAGE_PRESENT == 0 {
            return None;
        }
        let phys = pte & 0x000F_FFFF_FFFF_F000;
        let flags = pte & !0x000F_FFFF_FFFF_F000;
        Some((phys, flags))
    }

    /// Return a mutable pointer to the leaf PTE for `virt`, if present.
    /// Used by VmWrite to update CoW pages in-place.
    pub fn lookup_pte_mut(&self, virt: u64) -> Option<*mut u64> {
        let hhdm = hhdm_offset();

        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return None;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return None;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return None;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        let pt = (pt_phys + hhdm) as *mut u64;
        let pte_ptr = unsafe { pt.add(pt_index(virt)) };
        let pte = unsafe { *pte_ptr };
        if pte & PAGE_PRESENT == 0 {
            return None;
        }
        Some(pte_ptr)
    }

    /// Check if a virtual address falls in init's service regions that must
    /// stay writable in the parent during CoW fork (DMA, ring buffers, handler
    /// stacks, VFS storage, etc.).
    #[inline]
    fn is_init_service_region(virt: u64) -> bool {
        matches!(virt,
            0x510000..=0x52FFFF       // KB + Mouse ring buffers
            | 0xA00000..=0xAFFFFF     // SPSC ring + aux stacks
            | 0xC00000..=0xE7FFFF     // Virtio MMIO + ObjStore + VFS + LUCAS + handler stacks
        )
    }

    /// Clone this address space for fork (symmetric CoW).
    ///
    /// Creates a new PML4, walks all user-half page tables (entries 0..256),
    /// and for each present leaf PTE:
    ///   1. Copy PTE to child with WRITABLE removed (child triggers CoW on write)
    ///   2. Parent PTE is ALSO marked read-only (symmetric CoW)
    ///   3. Increment refcount for the physical frame
    /// Kernel-half entries (256..512) are shared as usual.
    ///
    /// Exclusions: init service regions (KB/mouse rings, SPSC, virtio MMIO,
    /// ObjectStore, VFS, handler stacks) and UC/MMIO pages are left writable
    /// in the parent to avoid breaking DMA and handler thread writes.
    ///
    /// The caller MUST flush the TLB after this call if the parent is the
    /// current CR3, since parent PTEs have been changed to read-only.
    pub fn clone_cow(&self) -> Self {
        use super::frame_refcount_inc;

        let hhdm = hhdm_offset();
        let table_flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

        // Allocate new PML4
        let new_pml4_phys = alloc_table_frame();
        let new_pml4 = (new_pml4_phys + hhdm) as *mut u64;

        // Copy kernel-half entries (256..512) — shared, not cloned
        let src_pml4 = (self.pml4_phys + hhdm) as *mut u64;
        unsafe {
            for i in 256..512 {
                *new_pml4.add(i) = *src_pml4.add(i);
            }
        }

        // Walk user-half (entries 0..256) and clone with CoW
        for pml4_i in 0..256usize {
            let pml4e = unsafe { *src_pml4.add(pml4_i) };
            if pml4e & PAGE_PRESENT == 0 {
                continue;
            }
            let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

            // Allocate new PDP for child
            let new_pdp_phys = alloc_table_frame();
            unsafe {
                *new_pml4.add(pml4_i) = new_pdp_phys | table_flags;
            }

            let src_pdp = (pdp_phys + hhdm) as *mut u64;
            let new_pdp = (new_pdp_phys + hhdm) as *mut u64;

            for pdp_i in 0..512usize {
                let pdpe = unsafe { *src_pdp.add(pdp_i) };
                if pdpe & PAGE_PRESENT == 0 {
                    continue;
                }
                let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

                // Allocate new PD for child
                let new_pd_phys = alloc_table_frame();
                unsafe {
                    *new_pdp.add(pdp_i) = new_pd_phys | table_flags;
                }

                let src_pd = (pd_phys + hhdm) as *mut u64;
                let new_pd = (new_pd_phys + hhdm) as *mut u64;

                for pd_i in 0..512usize {
                    let pde = unsafe { *src_pd.add(pd_i) };
                    if pde & PAGE_PRESENT == 0 {
                        continue;
                    }
                    let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

                    // Allocate new PT for child
                    let new_pt_phys = alloc_table_frame();
                    unsafe {
                        *new_pd.add(pd_i) = new_pt_phys | table_flags;
                    }
                    let src_pt = (pt_phys + hhdm) as *mut u64;
                    let new_pt = (new_pt_phys + hhdm) as *mut u64;

                    for pt_i in 0..512usize {
                        let pte = unsafe { *src_pt.add(pt_i) };
                        if pte & PAGE_PRESENT == 0 {
                            continue;
                        }

                        let phys = pte & 0x000F_FFFF_FFFF_F000;

                        // Child gets read-only PTE (CoW on write).
                        let child_pte = pte & !PAGE_WRITABLE;
                        unsafe {
                            *new_pt.add(pt_i) = child_pte;
                        }

                        // Symmetric CoW: also mark parent read-only, unless
                        // the page is UC/MMIO or in init's service regions.
                        if pte & PAGE_WRITABLE != 0 && pte & PAGE_CACHE_DISABLE == 0 {
                            let virt = ((pml4_i as u64) << 39)
                                | ((pdp_i as u64) << 30)
                                | ((pd_i as u64) << 21)
                                | ((pt_i as u64) << 12);
                            if !Self::is_init_service_region(virt) {
                                unsafe {
                                    *src_pt.add(pt_i) = pte & !PAGE_WRITABLE;
                                }
                            }
                        }

                        // Increment refcount: if frame was previously untracked (rc=0),
                        // set to 2 (parent + child). If already tracked, just +1.
                        let idx = (phys >> 12) as usize;
                        if idx < super::MAX_REFCOUNT_FRAMES {
                            let mut rc = super::FRAME_REFCOUNT.lock();
                            if rc[idx] == 0 {
                                rc[idx] = 2;
                            } else {
                                rc[idx] = rc[idx].saturating_add(1);
                            }
                        }
                    }
                }
            }
        }

        Self {
            pml4_phys: new_pml4_phys,
        }
    }

    /// Update the flags of an already-mapped page (mprotect-like).
    ///
    /// Walks the page table to find the leaf PTE, preserves the physical
    /// address, and replaces the flags. Returns `true` if the page was
    /// present and has been updated, `false` otherwise.
    pub fn protect_page(&self, virt: u64, new_flags: u64) -> bool {
        let hhdm = hhdm_offset();

        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return false;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return false;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return false;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        let pt = (pt_phys + hhdm) as *mut u64;
        let pte = unsafe { &mut *pt.add(pt_index(virt)) };
        if *pte & PAGE_PRESENT == 0 {
            return false;
        }
        let phys = *pte & 0x000F_FFFF_FFFF_F000;
        *pte = phys | new_flags;
        true
    }
}
