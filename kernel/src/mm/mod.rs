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
