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
        Self { pml4_phys: cr3 & !0xFFF }
    }

    /// Create a new user address space.
    ///
    /// Allocates a fresh PML4 and copies the kernel-half entries (256..512)
    /// from the boot page tables so the kernel remains mapped.
    pub fn new_user() -> Self {
        let pml4_phys = alloc_table_frame(); // already zeroed
        let pml4_virt = pml4_phys + hhdm_offset();

        // Copy upper-half PML4 entries from boot tables.
        let boot = read_cr3() & !0xFFF;
        let boot_pml4_virt = boot + hhdm_offset();

        unsafe {
            let src = boot_pml4_virt as *const u64;
            let dst = pml4_virt as *mut u64;
            for i in 256..512 {
                *dst.add(i) = *src.add(i);
            }
        }

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
        let hhdm = hhdm_offset();

        // PML4 → PDP
        let pml4 = (self.pml4_phys + hhdm) as *const u64;
        let pml4e = unsafe { *pml4.add(pml4_index(virt)) };
        if pml4e & PAGE_PRESENT == 0 {
            return false;
        }
        let pdp_phys = pml4e & 0x000F_FFFF_FFFF_F000;

        // PDP → PD
        let pdp = (pdp_phys + hhdm) as *const u64;
        let pdpe = unsafe { *pdp.add(pdp_index(virt)) };
        if pdpe & PAGE_PRESENT == 0 {
            return false;
        }
        let pd_phys = pdpe & 0x000F_FFFF_FFFF_F000;

        // PD → PT
        let pd = (pd_phys + hhdm) as *const u64;
        let pde = unsafe { *pd.add(pd_index(virt)) };
        if pde & PAGE_PRESENT == 0 {
            return false;
        }
        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;

        // Clear leaf PTE
        let pt = (pt_phys + hhdm) as *mut u64;
        let pte = unsafe { &mut *pt.add(pt_index(virt)) };
        if *pte & PAGE_PRESENT == 0 {
            return false;
        }
        *pte = 0;
        true
    }
}
