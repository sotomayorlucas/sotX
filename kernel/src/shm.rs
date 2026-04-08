//! Kernel shared memory primitive.
//!
//! Provides anonymous shared memory regions that can be mapped into
//! multiple address spaces. Used by the Wayland compositor for
//! wl_shm_pool buffer sharing between clients and the compositor.
//!
//! Syscalls:
//!   180 SHM_CREATE — allocate N contiguous frames, return handle
//!   181 SHM_MAP    — map shared region into a target address space
//!   182 SHM_UNMAP  — unmap shared region from a target address space
//!   183 SHM_DESTROY — destroy handle, free frames when refcount=0

use crate::mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
use crate::mm::{self, PhysFrame};
use spin::Mutex;

/// Maximum pages per shared memory object (256 pages = 1 MiB).
pub const SHM_MAX_PAGES: usize = 256;

/// Maximum number of concurrent shared memory objects.
const SHM_TABLE_SIZE: usize = 64;

/// A shared memory object: a set of physical frames that can be
/// mapped into multiple address spaces.
struct ShmObject {
    active: bool,
    /// Physical addresses of allocated frames.
    pages: [u64; SHM_MAX_PAGES],
    /// Number of pages in this object.
    page_count: usize,
    /// Number of address spaces this object is mapped into.
    refcount: u32,
}

impl ShmObject {
    const fn empty() -> Self {
        Self {
            active: false,
            pages: [0; SHM_MAX_PAGES],
            page_count: 0,
            refcount: 0,
        }
    }
}

/// Global shared memory table.
static SHM_TABLE: Mutex<[ShmObject; SHM_TABLE_SIZE]> =
    Mutex::new([const { ShmObject::empty() }; SHM_TABLE_SIZE]);

/// Create a shared memory object with `num_pages` physical frames.
/// Returns the handle (index) on success, or negative error.
pub fn shm_create(num_pages: usize) -> i64 {
    if num_pages == 0 || num_pages > SHM_MAX_PAGES {
        return -4; // InvalidArg
    }

    let mut table = SHM_TABLE.lock();

    // Find a free slot.
    let slot = match table.iter().position(|s| !s.active) {
        Some(i) => i,
        None => return -3, // OutOfResources
    };

    // Allocate physical frames.
    let mut pages = [0u64; SHM_MAX_PAGES];
    for i in 0..num_pages {
        match mm::alloc_frame() {
            Some(frame) => {
                let phys = frame.addr();
                // Zero the frame for security.
                let hhdm = mm::hhdm_offset();
                unsafe {
                    core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
                }
                pages[i] = phys;
            }
            None => {
                // Free already-allocated frames on failure.
                for j in 0..i {
                    mm::free_frame(PhysFrame::from_addr(pages[j]));
                }
                return -3; // OutOfResources
            }
        }
    }

    table[slot] = ShmObject {
        active: true,
        pages,
        page_count: num_pages,
        refcount: 1,
    };

    slot as i64
}

/// Map a shared memory object into a target address space at `vaddr`.
/// `flags`: bit 0 = writable (default: read-only).
/// Returns 0 on success, negative error on failure.
pub fn shm_map(handle: u32, cr3: u64, vaddr: u64, flags: u64) -> i64 {
    let table = SHM_TABLE.lock();

    let slot = handle as usize;
    if slot >= SHM_TABLE_SIZE || !table[slot].active {
        return -4; // InvalidArg
    }

    let obj = &table[slot];
    let addr_space = AddressSpace::from_cr3(cr3);
    let mut pte_flags = PAGE_PRESENT | PAGE_USER;
    if flags & 1 != 0 {
        pte_flags |= PAGE_WRITABLE;
    }

    for i in 0..obj.page_count {
        addr_space.map_page(vaddr + (i as u64) * 0x1000, obj.pages[i], pte_flags);
    }

    drop(table);
    // Increment refcount outside the mapping loop.
    SHM_TABLE.lock()[slot].refcount += 1;

    0
}

/// Unmap a shared memory object from a target address space.
/// Returns 0 on success, negative error on failure.
pub fn shm_unmap(handle: u32, cr3: u64, vaddr: u64) -> i64 {
    let mut table = SHM_TABLE.lock();

    let slot = handle as usize;
    if slot >= SHM_TABLE_SIZE || !table[slot].active {
        return -4; // InvalidArg
    }

    let page_count = table[slot].page_count;
    let addr_space = AddressSpace::from_cr3(cr3);

    for i in 0..page_count {
        addr_space.unmap_page(vaddr + (i as u64) * 0x1000);
    }

    if table[slot].refcount > 0 {
        table[slot].refcount -= 1;
    }

    0
}

/// Destroy a shared memory object. Frees physical frames when refcount reaches 0.
/// Returns 0 on success, negative error on failure.
pub fn shm_destroy(handle: u32) -> i64 {
    let mut table = SHM_TABLE.lock();

    let slot = handle as usize;
    if slot >= SHM_TABLE_SIZE || !table[slot].active {
        return -4; // InvalidArg
    }

    if table[slot].refcount > 1 {
        table[slot].refcount -= 1;
        return 0;
    }

    // Refcount is 0 or 1 — free all frames.
    let page_count = table[slot].page_count;
    for i in 0..page_count {
        let phys = table[slot].pages[i];
        if phys != 0 {
            mm::free_frame(PhysFrame::from_addr(phys));
        }
    }

    table[slot] = ShmObject::empty();
    0
}
