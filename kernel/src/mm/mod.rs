//! Physical memory management.
//!
//! The kernel only manages physical frames. Virtual memory (paging)
//! is handled by the userspace VMM server — this is the key
//! microkernel/exokernel hybrid design decision.

pub mod frame;
pub mod paging;
pub mod slab;

pub use frame::{alloc_frame, alloc_contiguous, free_frame, PhysFrame};

use core::sync::atomic::{AtomicU64, Ordering};
use limine::response::MemoryMapResponse;

/// Global HHDM offset for phys→virt conversion.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Return the Higher Half Direct Map offset.
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

/// Initialize the physical frame allocator from the bootloader memory map.
pub fn init(memory_map: &MemoryMapResponse, hhdm_offset: u64) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Relaxed);
    frame::init(memory_map, hhdm_offset);
}
