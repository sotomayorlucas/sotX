//! Memory allocation -- maps rump malloc/free/mmap to SOT frame capabilities.
//!
//! The rump kernel expects three allocation primitives:
//!   - `rumpuser_malloc(size, align)` -- general-purpose allocator
//!   - `rumpuser_free(ptr, size)` -- paired free
//!   - `rumpuser_anonmmap(size)` -- anonymous page-backed mapping
//!
//! On SOT these translate to frame allocation + page table manipulation
//! via the VMM service.

use crate::{RumpError, SotCap};

/// Page size assumed by the adaptation layer (4 KiB on x86-64).
pub const PAGE_SIZE: usize = 4096;

/// Maximum tracked anonymous mappings.
const MAX_ANON_MAPS: usize = 256;

/// Descriptor for an anonymous mapping (backing frames + virtual range).
#[derive(Debug, Clone, Copy)]
pub struct AnonMap {
    /// SOT frame capability covering the allocation.
    pub frame_cap: SotCap,
    /// Virtual address returned to the rump kernel.
    pub vaddr: usize,
    /// Size in bytes (page-aligned).
    pub size: usize,
}

/// Tracks outstanding anonymous mappings so they can be freed.
pub struct AnonMapTable {
    maps: [Option<AnonMap>; MAX_ANON_MAPS],
    count: usize,
}

impl AnonMapTable {
    pub const fn new() -> Self {
        const NONE: Option<AnonMap> = None;
        Self {
            maps: [NONE; MAX_ANON_MAPS],
            count: 0,
        }
    }

    /// Record a new mapping.
    pub fn insert(&mut self, map: AnonMap) -> Result<(), RumpError> {
        for slot in self.maps.iter_mut() {
            if slot.is_none() {
                *slot = Some(map);
                self.count += 1;
                return Ok(());
            }
        }
        Err(RumpError::OutOfMemory)
    }

    /// Remove (and return) the mapping at `vaddr`.
    pub fn remove(&mut self, vaddr: usize) -> Option<AnonMap> {
        for slot in self.maps.iter_mut() {
            if let Some(ref m) = slot {
                if m.vaddr == vaddr {
                    let map = *m;
                    *slot = None;
                    self.count -= 1;
                    return Some(map);
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Round `size` up to the next page boundary.
pub const fn page_align(size: usize) -> usize {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Allocate `size` bytes with the given alignment.
///
/// Maps to SOT frame allocation + VMM mapping.  Returns a pointer to
/// the mapped region.
pub fn malloc(
    anon_maps: &mut AnonMapTable,
    size: usize,
    _align: usize,
) -> Result<*mut u8, RumpError> {
    let aligned_size = page_align(size);
    let _num_frames = aligned_size / PAGE_SIZE;

    // TODO: SOT syscalls:
    //   1. Allocate physical frames:
    //      let frame_cap = sot_sys::frame_alloc(num_frames)?;
    //   2. Map into current address space via VMM IPC:
    //      let vaddr = vmm_ipc::map_frames(frame_cap, aligned_size, align)?;
    //   3. Record the mapping for later free().

    let frame_cap = SotCap(0); // placeholder
    let vaddr: usize = 0; // placeholder

    let map = AnonMap {
        frame_cap,
        vaddr,
        size: aligned_size,
    };
    anon_maps.insert(map)?;

    Ok(vaddr as *mut u8)
}

/// Free a previous allocation.
pub fn free(anon_maps: &mut AnonMapTable, ptr: *mut u8, _size: usize) {
    let vaddr = ptr as usize;

    if let Some(_map) = anon_maps.remove(vaddr) {
        // TODO: SOT syscalls:
        //   1. Unmap from address space:
        //      vmm_ipc::unmap(map.vaddr, map.size);
        //   2. Release physical frames:
        //      sot_sys::frame_free(map.frame_cap);
    }
}

/// Create an anonymous memory mapping of `size` bytes.
///
/// This is the rump equivalent of `mmap(NULL, size, PROT_READ|PROT_WRITE,
/// MAP_ANON|MAP_PRIVATE, -1, 0)`.
pub fn anonmmap(anon_maps: &mut AnonMapTable, size: usize) -> Result<*mut u8, RumpError> {
    // Identical to malloc at the SOT level -- both allocate frames and map
    // them.  Kept separate because rump tracks them differently.
    malloc(anon_maps, size, PAGE_SIZE)
}
