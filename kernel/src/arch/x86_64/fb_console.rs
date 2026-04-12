//! Kernel-side console ring writer.
//!
//! After the unified-console merge (Unit 10), the kernel no longer owns a
//! framebuffer text console. Instead it pushes bytes into a SPSC ring at
//! `CONSOLE_RING_ADDR` that init drains each loop iteration and feeds
//! through its own vte parser + framebuffer renderer.
//!
//! This module provides:
//!   - `init(phys)`: record the ring's physical address (identity-mapped).
//!   - `push_byte(b)`: append one byte to the ring (non-blocking, drops on full).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static RING_READY: AtomicBool = AtomicBool::new(false);
static RING_BASE: AtomicU64 = AtomicU64::new(0);

/// Ring capacity in bytes (must match `sotos_common::CONSOLE_RING_CAP`).
const RING_CAP: u32 = 4088;

/// Initialise the console ring. `phys` is the identity-mapped physical
/// address of the 4 KiB page that holds:
///   `[write_idx: u32, read_idx: u32, data: [u8; RING_CAP]]`
pub fn init(phys: u64) {
    RING_BASE.store(phys, Ordering::Release);
    // Zero write and read indices.
    unsafe {
        let base = phys as *mut u32;
        core::ptr::write_volatile(base, 0);        // write_idx
        core::ptr::write_volatile(base.add(1), 0);  // read_idx
    }
    RING_READY.store(true, Ordering::Release);
}

/// Returns true if the ring has been initialised.
pub fn is_ready() -> bool {
    RING_READY.load(Ordering::Relaxed)
}

/// Push a single byte into the console ring. Non-blocking; silently
/// drops the byte if the ring is full.
pub fn push_byte(byte: u8) {
    if !RING_READY.load(Ordering::Relaxed) {
        return;
    }
    let base = RING_BASE.load(Ordering::Relaxed) as *mut u32;
    unsafe {
        let write_idx = core::ptr::read_volatile(base);
        let read_idx = core::ptr::read_volatile(base.add(1));
        let next = (write_idx + 1) % RING_CAP;
        if next == read_idx {
            return; // full — drop
        }
        let data = (base as *mut u8).add(8 + write_idx as usize);
        core::ptr::write_volatile(data, byte);
        core::ptr::write_volatile(base, next);
    }
}
