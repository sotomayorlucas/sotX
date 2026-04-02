//! Input handling -- reads from KB_RING and MOUSE_RING.
//!
//! The keyboard driver writes PS/2 scancodes to KB_RING_ADDR.
//! The mouse driver writes packets to MOUSE_RING_ADDR.
//! We poll these rings and convert to Wayland events.
//!
//! Input device initialization is NON-FATAL: if the ring buffer
//! addresses are not mapped or the rings appear invalid, the
//! compositor continues without input. A warning is printed once.

use sotos_common::{KB_RING_ADDR, MOUSE_RING_ADDR};

/// Simple ring buffer reader (matches the spsc ring protocol in kbd driver).
/// Ring layout at addr:
///   [0..2]: write index (u16)
///   [2..4]: read index (u16)
///   [4..4096]: data bytes
const RING_DATA_OFFSET: usize = 4;
const RING_DATA_SIZE: usize = 4096 - RING_DATA_OFFSET;

/// Whether input rings have been validated as accessible.
/// false = not yet checked or check failed (input disabled).
static mut INPUT_AVAILABLE: bool = false;
static mut INPUT_CHECKED: bool = false;

/// Mouse packet: dx, dy, buttons.
pub struct MousePacket {
    pub dx: i32,
    pub dy: i32,
    pub buttons: u8,
}

/// Attempt to initialize input devices. Returns true if input rings
/// appear accessible, false otherwise. Non-fatal: never panics.
/// The caller is responsible for logging the result.
pub fn try_init() -> bool {
    unsafe {
        if INPUT_CHECKED {
            return INPUT_AVAILABLE;
        }
        INPUT_CHECKED = true;

        // Probe ring indices -- valid rings have both indices < RING_DATA_SIZE.
        let kb_ok = probe_ring(KB_RING_ADDR);
        let mouse_ok = probe_ring(MOUSE_RING_ADDR);

        INPUT_AVAILABLE = kb_ok || mouse_ok;
        INPUT_AVAILABLE
    }
}

/// Probe whether a ring buffer address appears valid.
/// Returns true if the indices look like a valid (possibly empty) ring.
unsafe fn probe_ring(ring_addr: u64) -> bool {
    if ring_addr == 0 {
        return false;
    }
    let base = ring_addr as *const u16;
    // Read the write and read indices. For a valid ring, both should
    // be within [0, RING_DATA_SIZE).
    let write_idx = core::ptr::read_volatile(base) as usize;
    let read_idx = core::ptr::read_volatile(base.add(1)) as usize;
    write_idx < RING_DATA_SIZE && read_idx < RING_DATA_SIZE
}

/// Read one byte from the keyboard ring. Returns None if empty or
/// if input is not available.
pub fn read_kb_scancode() -> Option<u8> {
    unsafe {
        if !INPUT_AVAILABLE {
            return None;
        }
    }
    read_ring_byte(KB_RING_ADDR)
}

/// Read a mouse packet (3 bytes) from the mouse ring. Returns None
/// if < 3 bytes available or if input is not available.
pub fn read_mouse_packet() -> Option<MousePacket> {
    unsafe {
        if !INPUT_AVAILABLE {
            return None;
        }
    }
    let b0 = read_ring_byte(MOUSE_RING_ADDR)?;
    let b1 = read_ring_byte(MOUSE_RING_ADDR)?;
    let b2 = read_ring_byte(MOUSE_RING_ADDR)?;

    let buttons = b0 & 0x07;
    let mut dx = b1 as i32;
    let mut dy = b2 as i32;

    // Sign extension from PS/2 packet bits
    if b0 & 0x10 != 0 { dx -= 256; }
    if b0 & 0x20 != 0 { dy -= 256; }
    // PS/2 Y axis is inverted
    dy = -dy;

    Some(MousePacket { dx, dy, buttons })
}

/// Read one byte from a ring buffer at the given address.
fn read_ring_byte(ring_addr: u64) -> Option<u8> {
    let base = ring_addr as *mut u8;
    unsafe {
        let write_idx = core::ptr::read_volatile(base as *const u16) as usize;
        let read_idx = core::ptr::read_volatile(base.add(2) as *const u16) as usize;

        if read_idx == write_idx {
            return None; // empty
        }

        let byte = core::ptr::read_volatile(base.add(RING_DATA_OFFSET + read_idx));
        let new_read = (read_idx + 1) % RING_DATA_SIZE;
        core::ptr::write_volatile(base.add(2) as *mut u16, new_read as u16);

        Some(byte)
    }
}
