// ---------------------------------------------------------------------------
// evdev.rs — Linux evdev input device emulation
//
// Provides /dev/input/event0 (keyboard) and /dev/input/event1 (mouse) for
// libinput/Weston. Translates from sotX hardware ring buffers (PS/2 scancodes
// at KB_RING_ADDR, 3-byte mouse packets at MOUSE_RING_ADDR) into Linux
// struct input_event sequences.
// ---------------------------------------------------------------------------

use sotos_common::{KB_RING_ADDR, MOUSE_RING_ADDR, SyncUnsafeCell};
use crate::syscalls::context::SyscallContext;

// ---------------------------------------------------------------------------
// Linux input event types
// ---------------------------------------------------------------------------
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_MSC: u16 = 0x04;

// Synchronization codes
const SYN_REPORT: u16 = 0;

// Relative axis codes
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_WHEEL: u16 = 8;

// Miscellaneous codes
const MSC_SCAN: u16 = 4;

// Button codes
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

// ---------------------------------------------------------------------------
// Evdev ioctl decoding
//
// Linux ioctl encoding: bits [7:0] = nr, [15:8] = type char, [29:16] = size,
// [31:30] = direction (0=none, 1=write, 2=read, 3=rw).
// Base type char for evdev is 'E' = 0x45.
// ---------------------------------------------------------------------------
const EVDEV_TYPE_CHAR: u64 = 0x45; // 'E'

/// Extract the ioctl "nr" field (bits 7..0).
fn ioctl_nr(cmd: u64) -> u64 { cmd & 0xFF }
/// Extract the ioctl "type" field (bits 15..8).
fn ioctl_type(cmd: u64) -> u64 { (cmd >> 8) & 0xFF }
/// Extract the ioctl "size" field (bits 29..16).
fn ioctl_size(cmd: u64) -> u64 { (cmd >> 16) & 0x3FFF }

// Well-known evdev ioctl nr values
const EVIOCGVERSION_NR: u64 = 0x01;
const EVIOCGID_NR: u64 = 0x02;
const EVIOCGREP_NR: u64 = 0x03;
const EVIOCGNAME_NR: u64 = 0x06;
const EVIOCGPHYS_NR: u64 = 0x07;
const EVIOCGUNIQ_NR: u64 = 0x08;
const EVIOCGPROP_NR: u64 = 0x09;
const EVIOCGKEY_NR: u64 = 0x18;
const EVIOCGLED_NR: u64 = 0x19;
// EVIOCGBIT: nr = 0x20 + ev_type
const EVIOCGBIT_BASE: u64 = 0x20;
// EVIOCGABS: nr = 0x40 + axis
const EVIOCGABS_BASE: u64 = 0x40;
// EVIOCGRAB: nr = 0x90
const EVIOCGRAB_NR: u64 = 0x90;

// ---------------------------------------------------------------------------
// input_id struct (8 bytes)
// ---------------------------------------------------------------------------
const BUS_VIRTUAL: u16 = 0x06;

// ---------------------------------------------------------------------------
// Device identifiers
// ---------------------------------------------------------------------------
pub(crate) const EVDEV_KBD: u8 = 0;   // /dev/input/event0
pub(crate) const EVDEV_MOUSE: u8 = 1; // /dev/input/event1

// ---------------------------------------------------------------------------
// InputEvent — Linux struct input_event (24 bytes on x86_64)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
struct InputEvent {
    tv_sec: i64,
    tv_usec: i64,
    type_: u16,
    code: u16,
    value: i32,
}

const INPUT_EVENT_SIZE: usize = core::mem::size_of::<InputEvent>(); // 24

impl InputEvent {
    const fn zero() -> Self {
        Self { tv_sec: 0, tv_usec: 0, type_: 0, code: 0, value: 0 }
    }

    fn new(type_: u16, code: u16, value: i32) -> Self {
        let (sec, usec) = tsc_to_timeval();
        Self { tv_sec: sec, tv_usec: usec, type_, code, value }
    }

    fn as_bytes(&self) -> &[u8; INPUT_EVENT_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; INPUT_EVENT_SIZE]) }
    }
}

// ---------------------------------------------------------------------------
// Event ring buffer (per-device)
// ---------------------------------------------------------------------------
const EVDEV_RING_SIZE: usize = 64;

struct EvdevRing {
    events: [InputEvent; EVDEV_RING_SIZE],
    head: usize, // read position
    tail: usize, // write position
}

impl EvdevRing {
    const fn new() -> Self {
        Self {
            events: [InputEvent::zero(); EVDEV_RING_SIZE],
            head: 0,
            tail: 0,
        }
    }

    fn is_empty(&self) -> bool { self.head == self.tail }

    fn count(&self) -> usize {
        if self.tail >= self.head {
            self.tail - self.head
        } else {
            EVDEV_RING_SIZE - self.head + self.tail
        }
    }

    fn push(&mut self, ev: InputEvent) {
        let next = (self.tail + 1) % EVDEV_RING_SIZE;
        if next == self.head {
            // Ring full — drop oldest event
            self.head = (self.head + 1) % EVDEV_RING_SIZE;
        }
        self.events[self.tail] = ev;
        self.tail = next;
    }

    fn pop(&mut self) -> Option<InputEvent> {
        if self.is_empty() { return None; }
        let ev = self.events[self.head];
        self.head = (self.head + 1) % EVDEV_RING_SIZE;
        Some(ev)
    }
}

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------
static KBD_RING: SyncUnsafeCell<EvdevRing> = SyncUnsafeCell::new(EvdevRing::new());
static MOUSE_RING_STATE: SyncUnsafeCell<EvdevRing> = SyncUnsafeCell::new(EvdevRing::new());

/// Previous mouse button state (bits 0..2 = left, right, middle).
static MOUSE_PREV_BUTTONS: SyncUnsafeCell<u8> = SyncUnsafeCell::new(0);

// ---------------------------------------------------------------------------
// Timestamp helper (RDTSC → timeval, assumes 2 GHz TSC)
// ---------------------------------------------------------------------------
const TSC_FREQ_HZ: u64 = 2_000_000_000;

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn tsc_to_timeval() -> (i64, i64) {
    let tsc = rdtsc();
    let secs = tsc / TSC_FREQ_HZ;
    let remainder = tsc % TSC_FREQ_HZ;
    let usecs = remainder / (TSC_FREQ_HZ / 1_000_000);
    (secs as i64, usecs as i64)
}

// ---------------------------------------------------------------------------
// PS/2 scancode → Linux KEY_* code mapping
//
// PS/2 Set 1 scancodes map almost 1:1 to Linux keycodes for basic keys.
// Release scancodes have bit 7 set (scancode | 0x80).
// ---------------------------------------------------------------------------
fn scancode_to_keycode(scancode: u8) -> u16 {
    // For PS/2 Set 1, the make codes 0x01..0x58 map directly to Linux
    // keycodes 1..88 for most standard keys. This table covers the
    // common cases; extended scancodes (0xE0 prefix) are not handled here.
    let sc = scancode & 0x7F; // strip release bit
    match sc {
        0x01 => 1,   // KEY_ESC
        0x02 => 2,   // KEY_1
        0x03 => 3,   // KEY_2
        0x04 => 4,   // KEY_3
        0x05 => 5,   // KEY_4
        0x06 => 6,   // KEY_5
        0x07 => 7,   // KEY_6
        0x08 => 8,   // KEY_7
        0x09 => 9,   // KEY_8
        0x0A => 10,  // KEY_9
        0x0B => 11,  // KEY_0
        0x0C => 12,  // KEY_MINUS
        0x0D => 13,  // KEY_EQUAL
        0x0E => 14,  // KEY_BACKSPACE
        0x0F => 15,  // KEY_TAB
        0x10 => 16,  // KEY_Q
        0x11 => 17,  // KEY_W
        0x12 => 18,  // KEY_E
        0x13 => 19,  // KEY_R
        0x14 => 20,  // KEY_T
        0x15 => 21,  // KEY_Y
        0x16 => 22,  // KEY_U
        0x17 => 23,  // KEY_I
        0x18 => 24,  // KEY_O
        0x19 => 25,  // KEY_P
        0x1A => 26,  // KEY_LEFTBRACE
        0x1B => 27,  // KEY_RIGHTBRACE
        0x1C => 28,  // KEY_ENTER
        0x1D => 29,  // KEY_LEFTCTRL
        0x1E => 30,  // KEY_A
        0x1F => 31,  // KEY_S
        0x20 => 32,  // KEY_D
        0x21 => 33,  // KEY_F
        0x22 => 34,  // KEY_G
        0x23 => 35,  // KEY_H
        0x24 => 36,  // KEY_J
        0x25 => 37,  // KEY_K
        0x26 => 38,  // KEY_L
        0x27 => 39,  // KEY_SEMICOLON
        0x28 => 40,  // KEY_APOSTROPHE
        0x29 => 41,  // KEY_GRAVE
        0x2A => 42,  // KEY_LEFTSHIFT
        0x2B => 43,  // KEY_BACKSLASH
        0x2C => 44,  // KEY_Z
        0x2D => 45,  // KEY_X
        0x2E => 46,  // KEY_C
        0x2F => 47,  // KEY_V
        0x30 => 48,  // KEY_B
        0x31 => 49,  // KEY_N
        0x32 => 50,  // KEY_M
        0x33 => 51,  // KEY_COMMA
        0x34 => 52,  // KEY_DOT
        0x35 => 53,  // KEY_SLASH
        0x36 => 54,  // KEY_RIGHTSHIFT
        0x37 => 55,  // KEY_KPASTERISK
        0x38 => 56,  // KEY_LEFTALT
        0x39 => 57,  // KEY_SPACE
        0x3A => 58,  // KEY_CAPSLOCK
        0x3B => 59,  // KEY_F1
        0x3C => 60,  // KEY_F2
        0x3D => 61,  // KEY_F3
        0x3E => 62,  // KEY_F4
        0x3F => 63,  // KEY_F5
        0x40 => 64,  // KEY_F6
        0x41 => 65,  // KEY_F7
        0x42 => 66,  // KEY_F8
        0x43 => 67,  // KEY_F9
        0x44 => 68,  // KEY_F10
        0x45 => 69,  // KEY_NUMLOCK
        0x46 => 70,  // KEY_SCROLLLOCK
        0x47 => 71,  // KEY_KP7
        0x48 => 72,  // KEY_KP8
        0x49 => 73,  // KEY_KP9
        0x4A => 74,  // KEY_KPMINUS
        0x4B => 75,  // KEY_KP4
        0x4C => 76,  // KEY_KP5
        0x4D => 77,  // KEY_KP6
        0x4E => 78,  // KEY_KPPLUS
        0x4F => 79,  // KEY_KP1
        0x50 => 80,  // KEY_KP2
        0x51 => 81,  // KEY_KP3
        0x52 => 82,  // KEY_KP0
        0x53 => 83,  // KEY_KPDOT
        0x57 => 87,  // KEY_F11
        0x58 => 88,  // KEY_F12
        _ => 0,      // unknown — ignore
    }
}

// ---------------------------------------------------------------------------
// Hardware ring buffer polling
// ---------------------------------------------------------------------------

/// Read one raw scancode from the keyboard ring buffer at KB_RING_ADDR.
/// Returns None if the ring is empty.
///
/// Ring layout (matches framebuffer.rs):
///   offset 0: u32 write_idx
///   offset 4: u32 read_idx
///   offset 8..263: scancode bytes (256 entries, masked with 0xFF)
unsafe fn kb_ring_read_scancode() -> Option<u8> {
    let ring = KB_RING_ADDR as *mut u32;
    let write_idx = core::ptr::read_volatile(ring);
    let read_idx = core::ptr::read_volatile(ring.add(1));
    if read_idx == write_idx {
        return None;
    }
    let scancode = *((KB_RING_ADDR + 8 + (read_idx & 0xFF) as u64) as *const u8);
    let new_read = (read_idx + 1) & 0xFF;
    core::ptr::write_volatile(ring.add(1), new_read);
    Some(scancode)
}

/// Check if the keyboard ring has data without consuming it.
unsafe fn kb_ring_has_data() -> bool {
    let ring = KB_RING_ADDR as *const u32;
    let write_idx = core::ptr::read_volatile(ring);
    let read_idx = core::ptr::read_volatile(ring.add(1));
    read_idx != write_idx
}

/// Read one 3-byte PS/2 mouse packet from the mouse ring at MOUSE_RING_ADDR.
/// Returns None if fewer than 3 bytes are available.
///
/// Ring layout (same structure as KB ring):
///   offset 0: u32 write_idx
///   offset 4: u32 read_idx
///   offset 8..263: data bytes (256 entries)
unsafe fn mouse_ring_read_packet() -> Option<[u8; 3]> {
    let ring = MOUSE_RING_ADDR as *mut u32;
    let write_idx = core::ptr::read_volatile(ring);
    let read_idx = core::ptr::read_volatile(ring.add(1));
    // Need at least 3 bytes available
    let avail = write_idx.wrapping_sub(read_idx) & 0xFF;
    if avail < 3 {
        return None;
    }
    let mut pkt = [0u8; 3];
    for i in 0..3 {
        let idx = (read_idx + i as u32) & 0xFF;
        pkt[i] = *((MOUSE_RING_ADDR + 8 + idx as u64) as *const u8);
    }
    let new_read = (read_idx + 3) & 0xFF;
    core::ptr::write_volatile(ring.add(1), new_read);
    Some(pkt)
}

/// Check if the mouse ring has at least 3 bytes (one full packet).
unsafe fn mouse_ring_has_data() -> bool {
    let ring = MOUSE_RING_ADDR as *const u32;
    let write_idx = core::ptr::read_volatile(ring);
    let read_idx = core::ptr::read_volatile(ring.add(1));
    let avail = write_idx.wrapping_sub(read_idx) & 0xFF;
    avail >= 3
}

// ---------------------------------------------------------------------------
// Hardware → evdev event conversion
// ---------------------------------------------------------------------------

/// Convert a PS/2 scancode into input_events and push them onto the evdev ring.
/// Each key event generates: EV_MSC(MSC_SCAN) + EV_KEY(keycode, press/release) + EV_SYN.
fn scancode_to_events(scancode: u8, ring: &mut EvdevRing) {
    let keycode = scancode_to_keycode(scancode);
    if keycode == 0 { return; } // unmapped scancode

    let is_release = scancode & 0x80 != 0;
    let value: i32 = if is_release { 0 } else { 1 };

    // EV_MSC with raw scancode
    ring.push(InputEvent::new(EV_MSC, MSC_SCAN, scancode as i32));
    // EV_KEY with Linux keycode
    ring.push(InputEvent::new(EV_KEY, keycode, value));
    // EV_SYN to terminate the event group
    ring.push(InputEvent::new(EV_SYN, SYN_REPORT, 0));
}

/// Convert a PS/2 3-byte mouse packet into input_events.
///
/// PS/2 mouse packet format:
///   byte 0: [YO XO YS XS 1 MB RB LB]
///     bits 0-2 = buttons (left, right, middle)
///     bit 3 = always 1
///     bit 4 = X sign
///     bit 5 = Y sign
///     bits 6-7 = X/Y overflow
///   byte 1: X movement (unsigned, sign in byte 0 bit 4)
///   byte 2: Y movement (unsigned, sign in byte 0 bit 5)
fn mouse_packet_to_events(packet: [u8; 3], ring: &mut EvdevRing) {
    let buttons = packet[0] & 0x07;
    let prev = unsafe { *MOUSE_PREV_BUTTONS.get() };

    // Decode signed X/Y movement
    let raw_dx = packet[1] as i32;
    let raw_dy = packet[2] as i32;
    let dx = if packet[0] & 0x10 != 0 { raw_dx - 256 } else { raw_dx };
    // PS/2 Y is inverted relative to screen coordinates
    let dy = if packet[0] & 0x20 != 0 { raw_dy - 256 } else { raw_dy };
    let dy = -dy; // invert for screen convention

    // Button changes
    let btn_map: [(u8, u16); 3] = [
        (0x01, BTN_LEFT),
        (0x02, BTN_RIGHT),
        (0x04, BTN_MIDDLE),
    ];
    for &(mask, code) in &btn_map {
        let was = prev & mask != 0;
        let now = buttons & mask != 0;
        if was != now {
            ring.push(InputEvent::new(EV_KEY, code, if now { 1 } else { 0 }));
        }
    }

    // Relative movement
    if dx != 0 {
        ring.push(InputEvent::new(EV_REL, REL_X, dx));
    }
    if dy != 0 {
        ring.push(InputEvent::new(EV_REL, REL_Y, dy));
    }

    // Always emit SYN_REPORT if we generated any events
    if buttons != prev || dx != 0 || dy != 0 {
        ring.push(InputEvent::new(EV_SYN, SYN_REPORT, 0));
    }

    unsafe { *MOUSE_PREV_BUTTONS.get() = buttons; }
}

// ---------------------------------------------------------------------------
// Poll hardware and fill evdev rings
// ---------------------------------------------------------------------------

/// Drain available keyboard scancodes from the hardware ring into the evdev ring.
fn poll_kbd_hardware() {
    let ring = unsafe { &mut *KBD_RING.get() };
    // Read up to 16 scancodes per poll to avoid starving the caller
    for _ in 0..16 {
        match unsafe { kb_ring_read_scancode() } {
            Some(sc) => scancode_to_events(sc, ring),
            None => break,
        }
    }
}

/// Drain available mouse packets from the hardware ring into the evdev ring.
fn poll_mouse_hardware() {
    let ring = unsafe { &mut *MOUSE_RING_STATE.get() };
    for _ in 0..16 {
        match unsafe { mouse_ring_read_packet() } {
            Some(pkt) => mouse_packet_to_events(pkt, ring),
            None => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle an evdev ioctl on the given device (0=kbd, 1=mouse).
/// Writes results into the child's memory at `arg`.
pub(crate) fn evdev_ioctl(ctx: &mut SyscallContext, _fd: usize, cmd: u64, arg: u64, device: u8) -> i64 {
    let typ = ioctl_type(cmd);
    let nr = ioctl_nr(cmd);
    let size = ioctl_size(cmd) as usize;

    // All evdev ioctls use type char 'E' (0x45)
    if typ != EVDEV_TYPE_CHAR {
        return -sotos_common::linux_abi::ENOTTY;
    }

    match nr {
        // ---------------------------------------------------------------
        // EVIOCGVERSION — return EV_VERSION (1.0.1 = 0x010001)
        // ---------------------------------------------------------------
        EVIOCGVERSION_NR => {
            let ver: u32 = 0x010001;
            ctx.guest_write(arg, &ver.to_le_bytes());
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGID — return struct input_id (8 bytes)
        // ---------------------------------------------------------------
        EVIOCGID_NR => {
            let product: u16 = if device == EVDEV_KBD { 0x0001 } else { 0x0002 };
            let mut buf = [0u8; 8];
            // bustype
            buf[0] = (BUS_VIRTUAL & 0xFF) as u8;
            buf[1] = (BUS_VIRTUAL >> 8) as u8;
            // vendor
            buf[2] = 0x01; buf[3] = 0x00;
            // product
            buf[4] = (product & 0xFF) as u8;
            buf[5] = (product >> 8) as u8;
            // version
            buf[6] = 0x01; buf[7] = 0x00;
            ctx.guest_write(arg, &buf);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGREP — return repeat settings [delay_ms, rate_ms]
        // ---------------------------------------------------------------
        EVIOCGREP_NR => {
            let rep: [u32; 2] = [250, 33]; // 250ms delay, 33ms repeat
            let bytes = unsafe {
                core::slice::from_raw_parts(rep.as_ptr() as *const u8, 8)
            };
            ctx.guest_write(arg, bytes);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGNAME — return device name string
        // ---------------------------------------------------------------
        EVIOCGNAME_NR => {
            let name: &[u8] = if device == EVDEV_KBD {
                b"sotX Virtual Keyboard\0"
            } else {
                b"sotX Virtual Mouse\0"
            };
            let len = name.len().min(size);
            ctx.guest_write(arg, &name[..len]);
            len as i64
        }

        // ---------------------------------------------------------------
        // EVIOCGPHYS — physical path (empty string)
        // ---------------------------------------------------------------
        EVIOCGPHYS_NR => {
            let phys = b"\0";
            let len = phys.len().min(size);
            ctx.guest_write(arg, &phys[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGUNIQ — unique identifier (empty string)
        // ---------------------------------------------------------------
        EVIOCGUNIQ_NR => {
            let uniq = b"\0";
            let len = uniq.len().min(size);
            ctx.guest_write(arg, &uniq[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGPROP — device properties (empty)
        // ---------------------------------------------------------------
        EVIOCGPROP_NR => {
            let zeros = [0u8; 8];
            let len = size.min(8);
            ctx.guest_write(arg, &zeros[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGKEY — currently pressed keys (empty bitmap)
        // ---------------------------------------------------------------
        EVIOCGKEY_NR => {
            // Return zeroed bitmap (no keys currently reported as held)
            let zeros = [0u8; 96]; // KEY_CNT/8 = 768/8 = 96
            let len = size.min(96);
            ctx.guest_write(arg, &zeros[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGLED — LED state (empty)
        // ---------------------------------------------------------------
        EVIOCGLED_NR => {
            let zeros = [0u8; 8];
            let len = size.min(8);
            ctx.guest_write(arg, &zeros[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGSW — switch state (empty)
        // ---------------------------------------------------------------
        0x1b => {
            let zeros = [0u8; 8];
            let len = size.min(8);
            ctx.guest_write(arg, &zeros[..len]);
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGRAB — exclusive grab (always succeed)
        // ---------------------------------------------------------------
        EVIOCGRAB_NR => {
            0
        }

        // ---------------------------------------------------------------
        // EVIOCGBIT(ev_type, len) — capability bitmaps
        // nr = 0x20 + ev_type
        // ---------------------------------------------------------------
        nr if nr >= EVIOCGBIT_BASE && nr < EVIOCGABS_BASE => {
            let ev_type = nr - EVIOCGBIT_BASE;
            evdev_ioctl_gbit(ctx, arg, size, ev_type, device)
        }

        // ---------------------------------------------------------------
        // EVIOCGABS(axis) — absolute axis info
        // nr = 0x40 + axis
        // ---------------------------------------------------------------
        nr if nr >= EVIOCGABS_BASE && nr < EVIOCGRAB_NR => {
            if device == EVDEV_KBD {
                // Keyboard has no absolute axes
                -sotos_common::linux_abi::EINVAL
            } else {
                // Mouse has no absolute axes either (pure relative)
                // Return zeroed input_absinfo (24 bytes) to be safe
                let zeros = [0u8; 24];
                let len = size.min(24);
                ctx.guest_write(arg, &zeros[..len]);
                0
            }
        }

        _ => {
            // Unknown evdev ioctl — return ENOTTY
            -sotos_common::linux_abi::ENOTTY
        }
    }
}

/// Handle EVIOCGBIT for a specific event type.
fn evdev_ioctl_gbit(ctx: &mut SyscallContext, arg: u64, size: usize, ev_type: u64, device: u8) -> i64 {
    // Work buffer — largest bitmap we support is KEY_CNT/8 = 96 bytes
    let mut bits = [0u8; 96];

    match ev_type {
        // EVIOCGBIT(0, len) — which EV_* types this device supports
        0 => {
            // Set bits for supported event types
            if device == EVDEV_KBD {
                // EV_SYN(0) | EV_KEY(1) | EV_MSC(4) | EV_REP(0x14=20)
                set_bit(&mut bits, EV_SYN as usize);
                set_bit(&mut bits, EV_KEY as usize);
                set_bit(&mut bits, EV_MSC as usize);
                set_bit(&mut bits, 0x14); // EV_REP
            } else {
                // EV_SYN(0) | EV_KEY(1) | EV_REL(2)
                set_bit(&mut bits, EV_SYN as usize);
                set_bit(&mut bits, EV_KEY as usize);
                set_bit(&mut bits, EV_REL as usize);
            }
        }

        // EVIOCGBIT(EV_KEY, len) — which keys/buttons are supported
        1 => {
            if device == EVDEV_KBD {
                // Set all standard keys: KEY_ESC(1) through KEY_F12(88),
                // plus KEY_DELETE(111) range.
                for k in 1..=88 {
                    set_bit(&mut bits, k);
                }
                // Additional common keys
                for k in 96..=111 {
                    // KEY_KPENTER(96), KEY_RIGHTCTRL(97), ..., KEY_DELETE(111)
                    set_bit(&mut bits, k);
                }
            } else {
                // Mouse buttons: BTN_LEFT(0x110), BTN_RIGHT(0x111), BTN_MIDDLE(0x112)
                set_bit(&mut bits, BTN_LEFT as usize);
                set_bit(&mut bits, BTN_RIGHT as usize);
                set_bit(&mut bits, BTN_MIDDLE as usize);
            }
        }

        // EVIOCGBIT(EV_REL, len) — relative axes
        2 => {
            if device == EVDEV_MOUSE {
                set_bit(&mut bits, REL_X as usize);
                set_bit(&mut bits, REL_Y as usize);
                set_bit(&mut bits, REL_WHEEL as usize);
            }
            // Keyboard: no relative axes → zeroed bitmap
        }

        // EVIOCGBIT(EV_ABS, len) — absolute axes (neither device has any)
        3 => {
            // Return zeroed bitmap
        }

        // EVIOCGBIT(EV_MSC, len) — miscellaneous events
        4 => {
            if device == EVDEV_KBD {
                set_bit(&mut bits, MSC_SCAN as usize);
            }
        }

        // Any other event type — return empty bitmap
        _ => {}
    }

    let len = size.min(bits.len());
    ctx.guest_write(arg, &bits[..len]);
    0
}

/// Set a bit in a bitmap byte array.
fn set_bit(bitmap: &mut [u8], bit: usize) {
    let byte_idx = bit / 8;
    let bit_idx = bit % 8;
    if byte_idx < bitmap.len() {
        bitmap[byte_idx] |= 1 << bit_idx;
    }
}

/// Read input_event structs from the evdev device into the child's buffer.
/// Returns bytes read (multiple of 24) or negative errno.
///
/// If the evdev ring is empty, polls the hardware ring first.
/// Returns 0 (no data) rather than blocking — callers use poll/epoll to wait.
pub(crate) fn evdev_read(ctx: &mut SyscallContext, _fd: usize, buf: u64, count: u64, device: u8) -> i64 {
    // Must request at least one full event
    if (count as usize) < INPUT_EVENT_SIZE {
        return -sotos_common::linux_abi::EINVAL;
    }

    // Poll hardware to fill the evdev ring
    if device == EVDEV_KBD {
        poll_kbd_hardware();
    } else {
        poll_mouse_hardware();
    }

    let ring = if device == EVDEV_KBD {
        unsafe { &mut *KBD_RING.get() }
    } else {
        unsafe { &mut *MOUSE_RING_STATE.get() }
    };

    let max_events = (count as usize) / INPUT_EVENT_SIZE;
    let mut written = 0usize;

    for _ in 0..max_events {
        match ring.pop() {
            Some(ev) => {
                ctx.guest_write(buf + written as u64, ev.as_bytes());
                written += INPUT_EVENT_SIZE;
            }
            None => break,
        }
    }

    written as i64
}

/// Check if the evdev device has events ready.
/// Returns POLLIN (1) if data is available, 0 otherwise.
pub(crate) fn evdev_poll(device: u8) -> u32 {
    // Check the evdev ring first
    let ring_has_data = if device == EVDEV_KBD {
        let ring = unsafe { &*KBD_RING.get() };
        !ring.is_empty()
    } else {
        let ring = unsafe { &*MOUSE_RING_STATE.get() };
        !ring.is_empty()
    };

    if ring_has_data {
        return 1; // POLLIN
    }

    // Check the hardware ring
    let hw_has_data = if device == EVDEV_KBD {
        unsafe { kb_ring_has_data() }
    } else {
        unsafe { mouse_ring_has_data() }
    };

    if hw_has_data { 1 } else { 0 }
}
