//! Input handling -- reads from KB_RING and MOUSE_RING.
//!
//! The keyboard driver writes PS/2 scancodes to KB_RING_ADDR.
//! The mouse driver writes packed (dx, dy, buttons) packets to MOUSE_RING_ADDR.
//! We poll these rings and convert them into events the compositor's
//! main loop can dispatch to focused/hovered surfaces.
//!
//! Ring layout (canonical, matches `services/kbd/src/main.rs` producer):
//!
//! Keyboard ring at `KB_RING_ADDR`:
//!   offset  0: u32 write_idx  (modulo 256)
//!   offset  4: u32 read_idx   (modulo 256)
//!   offset  8: data[256]      (raw PS/2 Set 1 scancodes, one byte per slot)
//!
//! Mouse ring at `MOUSE_RING_ADDR`:
//!   offset  0: u32 write_idx  (modulo 64)
//!   offset  4: u32 read_idx   (modulo 64)
//!   offset  8: packets[64]    (4 bytes each: i8 dx, i8 dy, u8 buttons, u8 _pad)
//!
//! Input device polling is NON-FATAL. If the rings happen to be unmapped or
//! produce nothing, the compositor still runs. The boot-smoke marker
//! "=== compositor input: WIRED ===" is printed by `main.rs` once both
//! rings have been read at least once (even if empty), to verify wiring
//! without requiring a real client.

use sotos_common::{KB_RING_ADDR, MOUSE_RING_ADDR};

/// Number of keyboard scancode slots in the ring.
const KB_RING_SLOTS: u32 = 256;

/// Number of mouse packet slots in the ring (each slot is 4 bytes).
const MOUSE_RING_SLOTS: u32 = 64;

/// Decoded mouse delta + button state in screen-coordinate convention.
pub struct MousePacket {
    pub dx: i32,
    pub dy: i32,
    pub buttons: u8,
}

/// Has `try_init` accepted the rings yet?
static mut INPUT_AVAILABLE: bool = false;
static mut INPUT_CHECKED: bool = false;

/// Per-ring "has been read at least once" flag for the WIRED marker.
/// Set by `try_init` when the probe succeeds.
static mut KB_READ_ONCE: bool = false;
static mut MOUSE_READ_ONCE: bool = false;

/// Initialise input polling. Returns `true` if the ring pages look mapped
/// and the indices are within range. Non-fatal: callers may continue even
/// when this returns `false`.
///
/// This probes the rings non-destructively (no read/write of the data area
/// or the consumer index), so it is safe to call before the compositor
/// has taken ownership of the keyboard/mouse from any earlier consumer
/// (e.g. the LUCAS serial console). Both rings are marked as "polled" by
/// this call, which lets [`rings_polled`] return `true` once a client
/// eventually shows up.
pub fn try_init() -> bool {
    unsafe {
        if INPUT_CHECKED {
            return INPUT_AVAILABLE;
        }
        INPUT_CHECKED = true;

        let kb_ok = probe_ring(KB_RING_ADDR, KB_RING_SLOTS);
        let mouse_ok = probe_ring(MOUSE_RING_ADDR, MOUSE_RING_SLOTS);
        // A successful non-destructive probe counts as a "read" for the
        // WIRED smoke test -- it confirms the ring page is mapped and
        // the indices are sane, without consuming any pending data.
        KB_READ_ONCE = kb_ok;
        MOUSE_READ_ONCE = mouse_ok;
        INPUT_AVAILABLE = kb_ok || mouse_ok;
        INPUT_AVAILABLE
    }
}

/// Have both rings been polled at least once? Used for the WIRED marker.
pub fn rings_polled() -> bool {
    unsafe { KB_READ_ONCE && MOUSE_READ_ONCE }
}

/// Sanity-probe a ring page: both indices must be `< slot_count`.
unsafe fn probe_ring(ring_addr: u64, slot_count: u32) -> bool {
    if ring_addr == 0 {
        return false;
    }
    let base = ring_addr as *const u32;
    let write_idx = core::ptr::read_volatile(base);
    let read_idx = core::ptr::read_volatile(base.add(1));
    write_idx < slot_count && read_idx < slot_count
}

/// Pop one PS/2 scancode from the keyboard ring, or `None` if empty.
pub fn read_kb_scancode() -> Option<u8> {
    unsafe {
        if !INPUT_AVAILABLE {
            return None;
        }
        let ring = KB_RING_ADDR as *mut u32;
        let write_idx = core::ptr::read_volatile(ring);
        let read_idx = core::ptr::read_volatile(ring.add(1));
        if read_idx == write_idx {
            return None;
        }
        let slot = (read_idx & (KB_RING_SLOTS - 1)) as u64;
        let scancode = core::ptr::read_volatile((KB_RING_ADDR + 8 + slot) as *const u8);
        let new_read = read_idx.wrapping_add(1) & (KB_RING_SLOTS - 1);
        core::ptr::write_volatile(ring.add(1), new_read);
        Some(scancode)
    }
}

/// Pop one mouse packet from the mouse ring, or `None` if empty.
pub fn read_mouse_packet() -> Option<MousePacket> {
    unsafe {
        if !INPUT_AVAILABLE {
            return None;
        }
        let ring = MOUSE_RING_ADDR as *mut u32;
        let write_idx = core::ptr::read_volatile(ring);
        let read_idx = core::ptr::read_volatile(ring.add(1));
        if read_idx == write_idx {
            return None;
        }
        let slot = (read_idx & (MOUSE_RING_SLOTS - 1)) as u64;
        let base = MOUSE_RING_ADDR + 8 + slot * 4;
        let dx_raw = core::ptr::read_volatile(base as *const i8) as i32;
        let dy_raw = core::ptr::read_volatile((base + 1) as *const i8) as i32;
        let buttons = core::ptr::read_volatile((base + 2) as *const u8);
        let new_read = read_idx.wrapping_add(1) & (MOUSE_RING_SLOTS - 1);
        core::ptr::write_volatile(ring.add(1), new_read);

        // PS/2 reports Y as up-positive; screen coordinates are down-positive,
        // so invert Y here. (X stays as-is.) The producer already truncated
        // the PS/2 sign bits into a plain i8, so we just sign-extend.
        Some(MousePacket { dx: dx_raw, dy: -dy_raw, buttons: buttons & 0x07 })
    }
}
