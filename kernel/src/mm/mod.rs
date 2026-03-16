//! Physical memory management.
//!
//! The kernel only manages physical frames. Virtual memory (paging)
//! is handled by the userspace VMM server — this is the key
//! microkernel/exokernel hybrid design decision.

pub mod demand;
pub mod frame;
pub mod mmio;
pub mod page_cache;
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

// ---------------------------------------------------------------
// Frame refcount table — tracks CoW sharing.
// Index = (phys_addr >> 12). Supports up to 2GB RAM (524288 frames).
// Refcount 0 = untracked (normal single-owner frame).
// Refcount 1 = shared but only one reference left (can make writable).
// Refcount >= 2 = shared, CoW copy needed on write.
// Table size: 524288 × 2 bytes = 1 MB static allocation.
// ---------------------------------------------------------------
const MAX_REFCOUNT_FRAMES: usize = 524288; // 512K frames = 2GB RAM
static FRAME_REFCOUNT: spin::Mutex<[u16; MAX_REFCOUNT_FRAMES]> =
    spin::Mutex::new([0u16; MAX_REFCOUNT_FRAMES]);

/// Increment refcount for a physical frame. Called during CoW clone.
pub fn frame_refcount_inc(phys: u64) {
    let idx = (phys >> 12) as usize;
    if idx < MAX_REFCOUNT_FRAMES {
        let mut rc = FRAME_REFCOUNT.lock();
        rc[idx] = rc[idx].saturating_add(1);
    }
}

/// Decrement refcount for a physical frame. Returns new count.
/// When count reaches 0, the frame can be freed via bitmap allocator.
pub fn frame_refcount_dec(phys: u64) -> u16 {
    let idx = (phys >> 12) as usize;
    if idx < MAX_REFCOUNT_FRAMES {
        let mut rc = FRAME_REFCOUNT.lock();
        if rc[idx] > 0 {
            rc[idx] -= 1;
        }
        rc[idx]
    } else {
        0
    }
}

/// Get current refcount for a physical frame.
pub fn frame_refcount_get(phys: u64) -> u16 {
    let idx = (phys >> 12) as usize;
    if idx < MAX_REFCOUNT_FRAMES {
        FRAME_REFCOUNT.lock()[idx]
    } else {
        0
    }
}

/// Simple RDTSC-seeded xorshift64 PRNG for ASLR jitter.
static PRNG_STATE: AtomicU64 = AtomicU64::new(0);

/// Return a pseudo-random u64 (RDTSC-seeded xorshift64).
pub fn random_u64() -> u64 {
    let mut s = PRNG_STATE.load(Ordering::Relaxed);
    if s == 0 {
        // Seed from RDTSC.
        let lo: u32;
        let hi: u32;
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); }
        s = ((hi as u64) << 32) | (lo as u64);
        if s == 0 { s = 1; }
    }
    // xorshift64
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    PRNG_STATE.store(s, Ordering::Relaxed);
    s
}
