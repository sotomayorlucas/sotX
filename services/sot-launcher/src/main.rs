//! sot-launcher -- Tokyo Night keyboard-driven application launcher.
//!
//! A Wayland client that renders a centered modal-style launcher with a
//! search box and fuzzy-matched result list. Keyboard events (`j`/`k` for
//! navigate, `Enter` to select, `Esc` to hide) drive the UI; pressing any
//! letter appends to the search string and filters the list.
//!
//! Rationale for approach (UX redesign Unit 19)
//! --------------------------------------------
//! The sotOS compositor does NOT currently plumb a global hotkey up to
//! layer-shell clients (Super+Space or F1 wouldn't reach us on an
//! unfocused layer surface), and layer-shell keyboard focus routing is
//! only wired for `xdg_toplevel` on this branch. To keep the launcher
//! reachable by keyboard we take the "SIMPLE APPROACH" explicitly
//! documented in the task:
//!
//!     The launcher creates a regular `xdg_toplevel` sized 500x400, which
//!     gets auto-focused by the compositor as soon as it's mapped. All
//!     key events flow to this window immediately. To emulate hide/show
//!     without destroying/recreating the surface, the launcher tracks a
//!     `visible` bit and repaints either the full modal or an all-opaque
//!     "placeholder" frame; pressing `Esc` toggles it to a 1x1 logical
//!     footprint (the surface stays but is drawn as a single pixel).
//!
//! The file structure mirrors `services/hello-gui/src/main.rs` verbatim
//! for the Wayland wire protocol (`WireBuilder`, `wl_call`) because the
//! compositor dispatcher keys off exact byte layouts.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Modal dimensions when visible.
const WIN_W: u32 = 500;
const WIN_H: u32 = 400;

/// Bytes per pixel (XRGB8888).
const BPP: u32 = 4;

/// SHM pool big enough for the full modal.
const POOL_SIZE: u32 = WIN_W * WIN_H * BPP;

/// Base virtual address where we map the SHM pool in our own AS.
///
/// 0x9100000 sits safely above the interp load base (0x6000000) and
/// compositor's own 0x8000000, and below the interp buf base (0xA000000).
const CLIENT_POOL_BASE: u64 = 0x9100000;

/// Max bytes per IPC message (8 regs * 8 bytes).
const IPC_DATA_MAX: usize = 64;

/// IPC tags — must match compositor's `wayland::mod` constants.
const WL_MSG_TAG: u64 = 0x574C;
const WL_CONNECT_TAG: u64 = 0x574C_434F;
const WL_SHM_POOL_TAG: u64 = 0x574C_5348;

// ---------------------------------------------------------------------------
// Wayland object IDs (client-allocated, 1 = wl_display is server-owned)
// ---------------------------------------------------------------------------

const WL_DISPLAY_ID: u32 = 1;
const REGISTRY_ID: u32 = 2;
const SHM_ID: u32 = 3;
const COMPOSITOR_ID: u32 = 4;
const XDG_WM_BASE_ID: u32 = 5;
const SEAT_ID: u32 = 6;
const KEYBOARD_ID: u32 = 7;
const POOL_ID: u32 = 8;
const BUFFER_ID: u32 = 9;
const SURFACE_ID: u32 = 10;
const XDG_SURFACE_ID: u32 = 11;
const XDG_TOPLEVEL_ID: u32 = 12;

// ---------------------------------------------------------------------------
// Tokyo Night palette (XRGB8888)
//
// Sourced from services/compositor/src/decorations.rs:68.
// ---------------------------------------------------------------------------

const TN_BG: u32 = 0xFF1A1B26; // modal background
const TN_BG_DARK: u32 = 0xFF16161E; // search box background variant
const TN_BG_LIGHT: u32 = 0xFF24283B; // row / chrome background
const TN_FG: u32 = 0xFFC0CAF5; // foreground text
const TN_ACCENT: u32 = 0xFF7AA2F7; // blue accent / border / selection
const TN_DIM: u32 = 0xFF565F89; // dim text (placeholder)
const TN_WHITE: u32 = 0xFFFFFFFF;

const BORDER_PX: u32 = 15;

// ---------------------------------------------------------------------------
// Linux keycodes we care about (matches
// services/compositor/src/wayland/seat.rs scancode_to_linux_keycode).
// ---------------------------------------------------------------------------

const KEY_ESC: u32 = 1;
const KEY_BACKSPACE: u32 = 14;
const KEY_ENTER: u32 = 28;
const KEY_SPACE: u32 = 57;

// Letter keycodes (Linux evdev codes for KEY_A..KEY_Z subset).
const KEY_J: u32 = 36;
const KEY_K: u32 = 37;

// ---------------------------------------------------------------------------
// Candidate binaries — populated statically rather than via
// `sys::svc_list()` (which doesn't exist on this branch) or VFS getdents
// (which would require opening /bin, also not wired yet). These names map
// 1:1 with entries produced by `just initrd` under services/.
// ---------------------------------------------------------------------------

const CANDIDATE_COUNT: usize = 20;
static CANDIDATES: [&[u8]; CANDIDATE_COUNT] = [
    b"hello",
    b"hello-linux",
    b"compositor",
    b"lucas-shell",
    b"sot-statusbar",
    b"sot-dtrace",
    b"sot-pkg",
    b"sot-carp",
    b"sot-cheri",
    b"styx-test",
    b"posix-test",
    b"kernel-test",
    b"rump-vfs",
    b"sotfs",
    b"net-test",
    b"nvme",
    b"xhci",
    b"vmm",
    b"kbd",
    b"abi-fuzz",
];

// ---------------------------------------------------------------------------
// Tiny stdout helpers (serial)
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u32(mut val: u32) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < buf.len() {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    print(b"0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        sys::debug_print(hex[nibble]);
    }
}

// ---------------------------------------------------------------------------
// Wayland wire builder (byte-for-byte identical to services/hello-gui)
// ---------------------------------------------------------------------------

struct WireBuilder {
    buf: [u8; IPC_DATA_MAX],
    len: usize,
}

impl WireBuilder {
    fn new(object_id: u32, opcode: u16) -> Self {
        let mut b = Self {
            buf: [0u8; IPC_DATA_MAX],
            len: 8,
        };
        b.buf[0..4].copy_from_slice(&object_id.to_ne_bytes());
        let op = (opcode as u32).to_ne_bytes();
        b.buf[4..8].copy_from_slice(&op);
        b
    }

    fn put_u32(&mut self, val: u32) {
        let bytes = val.to_ne_bytes();
        self.buf[self.len..self.len + 4].copy_from_slice(&bytes);
        self.len += 4;
    }

    fn put_i32(&mut self, val: i32) {
        self.put_u32(val as u32);
    }

    fn put_string(&mut self, s: &[u8]) {
        let len_with_nul = s.len() + 1;
        self.put_u32(len_with_nul as u32);
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.buf[self.len + s.len()] = 0;
        let padded = (len_with_nul + 3) & !3;
        self.len += padded;
    }

    fn finish(&mut self) -> IpcMsg {
        let size_opcode = ((self.len as u32) << 16)
            | (u32::from_ne_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) & 0xFFFF);
        self.buf[4..8].copy_from_slice(&size_opcode.to_ne_bytes());

        let mut msg = IpcMsg::empty();
        msg.tag = WL_MSG_TAG | ((self.len as u64) << 16);
        let dst = &mut msg.regs as *mut u64 as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(self.buf.as_ptr(), dst, self.len);
        }
        msg
    }
}

fn wl_call(ep: u64, msg: &IpcMsg) -> IpcMsg {
    match sys::call(ep, msg) {
        Ok(reply) => reply,
        Err(e) => {
            print(b"sot-launcher: IPC call failed ");
            print_hex(e as u64);
            print(b"\n");
            IpcMsg::empty()
        }
    }
}

fn reply_bytes(msg: &IpcMsg) -> ([u8; IPC_DATA_MAX], usize) {
    let byte_count = ((msg.tag >> 16) & 0xFFFF) as usize;
    let byte_count = byte_count.min(IPC_DATA_MAX);
    let mut buf = [0u8; IPC_DATA_MAX];
    let src = &msg.regs as *const u64 as *const u8;
    unsafe {
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), byte_count);
    }
    (buf, byte_count)
}

/// Walk the packed events in `buf[..len]` for a `wl_keyboard::key`
/// event (opcode 3). Returns `(keycode, state)` where state is 1 for
/// press and 0 for release.
fn find_key_event(buf: &[u8], len: usize, kbd_id: u32) -> Option<(u32, u32)> {
    let mut off = 0usize;
    while off + 8 <= len {
        let obj = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let size_op = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;

        if size < 8 || off + size > len {
            return None;
        }

        // wl_keyboard::key (opcode 3) payload: serial(4) time(4) key(4) state(4).
        if obj == kbd_id && opcode == 3 && size >= 24 {
            let key = u32::from_ne_bytes([
                buf[off + 16],
                buf[off + 17],
                buf[off + 18],
                buf[off + 19],
            ]);
            let state = u32::from_ne_bytes([
                buf[off + 20],
                buf[off + 21],
                buf[off + 22],
                buf[off + 23],
            ]);
            return Some((key, state));
        }

        off += size;
    }
    None
}

// ---------------------------------------------------------------------------
// 8x8 bitmap font (ASCII 0x20..=0x7E) — mirrors services/hello-gui.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
static FONT_8X8: [[u8; 8]; 95] = [
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00], // 32 ' '
    [0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00], // 33 '!'
    [0x6C,0x6C,0x00,0x00,0x00,0x00,0x00,0x00], // 34 '"'
    [0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00], // 35 '#'
    [0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0x00], // 36 '$'
    [0x00,0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00], // 37 '%'
    [0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00], // 38 '&'
    [0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00], // 39 '\''
    [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00], // 40 '('
    [0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00], // 41 ')'
    [0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00], // 42 '*'
    [0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00], // 43 '+'
    [0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30], // 44 ','
    [0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00], // 45 '-'
    [0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00], // 46 '.'
    [0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00], // 47 '/'
    [0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0x7C,0x00], // 48 '0'
    [0x18,0x38,0x78,0x18,0x18,0x18,0x7E,0x00], // 49 '1'
    [0x7C,0xC6,0x06,0x1C,0x30,0x66,0xFE,0x00], // 50 '2'
    [0x7C,0xC6,0x06,0x3C,0x06,0xC6,0x7C,0x00], // 51 '3'
    [0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00], // 52 '4'
    [0xFE,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0x00], // 53 '5'
    [0x38,0x60,0xC0,0xFC,0xC6,0xC6,0x7C,0x00], // 54 '6'
    [0xFE,0xC6,0x0C,0x18,0x30,0x30,0x30,0x00], // 55 '7'
    [0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0x7C,0x00], // 56 '8'
    [0x7C,0xC6,0xC6,0x7E,0x06,0x0C,0x78,0x00], // 57 '9'
    [0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x00], // 58 ':'
    [0x00,0x18,0x18,0x00,0x00,0x18,0x18,0x30], // 59 ';'
    [0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00], // 60 '<'
    [0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00], // 61 '='
    [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00], // 62 '>'
    [0x7C,0xC6,0x0C,0x18,0x18,0x00,0x18,0x00], // 63 '?'
    [0x7C,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0x00], // 64 '@'
    [0x38,0x6C,0xC6,0xFE,0xC6,0xC6,0xC6,0x00], // 65 'A'
    [0xFC,0x66,0x66,0x7C,0x66,0x66,0xFC,0x00], // 66 'B'
    [0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00], // 67 'C'
    [0xF8,0x6C,0x66,0x66,0x66,0x6C,0xF8,0x00], // 68 'D'
    [0xFE,0x62,0x68,0x78,0x68,0x62,0xFE,0x00], // 69 'E'
    [0xFE,0x62,0x68,0x78,0x68,0x60,0xF0,0x00], // 70 'F'
    [0x3C,0x66,0xC0,0xC0,0xCE,0x66,0x3E,0x00], // 71 'G'
    [0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00], // 72 'H'
    [0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00], // 73 'I'
    [0x1E,0x0C,0x0C,0x0C,0xCC,0xCC,0x78,0x00], // 74 'J'
    [0xE6,0x66,0x6C,0x78,0x6C,0x66,0xE6,0x00], // 75 'K'
    [0xF0,0x60,0x60,0x60,0x62,0x66,0xFE,0x00], // 76 'L'
    [0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0x00], // 77 'M'
    [0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00], // 78 'N'
    [0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00], // 79 'O'
    [0xFC,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00], // 80 'P'
    [0x7C,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x06], // 81 'Q'
    [0xFC,0x66,0x66,0x7C,0x6C,0x66,0xE6,0x00], // 82 'R'
    [0x7C,0xC6,0xC0,0x7C,0x06,0xC6,0x7C,0x00], // 83 'S'
    [0x7E,0x5A,0x18,0x18,0x18,0x18,0x3C,0x00], // 84 'T'
    [0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00], // 85 'U'
    [0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00], // 86 'V'
    [0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00], // 87 'W'
    [0xC6,0x6C,0x38,0x38,0x6C,0xC6,0xC6,0x00], // 88 'X'
    [0x66,0x66,0x66,0x3C,0x18,0x18,0x3C,0x00], // 89 'Y'
    [0xFE,0xC6,0x8C,0x18,0x32,0x66,0xFE,0x00], // 90 'Z'
    [0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00], // 91 '['
    [0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00], // 92 '\\'
    [0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00], // 93 ']'
    [0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00], // 94 '^'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF], // 95 '_'
    [0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00], // 96 '`'
    [0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00], // 97 'a'
    [0xE0,0x60,0x7C,0x66,0x66,0x66,0xDC,0x00], // 98 'b'
    [0x00,0x00,0x7C,0xC6,0xC0,0xC6,0x7C,0x00], // 99 'c'
    [0x1C,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0x00], // 100 'd'
    [0x00,0x00,0x7C,0xC6,0xFE,0xC0,0x7C,0x00], // 101 'e'
    [0x1C,0x36,0x30,0x78,0x30,0x30,0x78,0x00], // 102 'f'
    [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x78], // 103 'g'
    [0xE0,0x60,0x6C,0x76,0x66,0x66,0xE6,0x00], // 104 'h'
    [0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00], // 105 'i'
    [0x06,0x00,0x0E,0x06,0x06,0x66,0x66,0x3C], // 106 'j'
    [0xE0,0x60,0x66,0x6C,0x78,0x6C,0xE6,0x00], // 107 'k'
    [0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00], // 108 'l'
    [0x00,0x00,0xEC,0xFE,0xD6,0xC6,0xC6,0x00], // 109 'm'
    [0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x00], // 110 'n'
    [0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0x00], // 111 'o'
    [0x00,0x00,0xDC,0x66,0x66,0x7C,0x60,0xF0], // 112 'p'
    [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E], // 113 'q'
    [0x00,0x00,0xDC,0x76,0x60,0x60,0xF0,0x00], // 114 'r'
    [0x00,0x00,0x7C,0xC0,0x7C,0x06,0xFC,0x00], // 115 's'
    [0x10,0x30,0x7C,0x30,0x30,0x34,0x18,0x00], // 116 't'
    [0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00], // 117 'u'
    [0x00,0x00,0xC6,0xC6,0xC6,0x6C,0x38,0x00], // 118 'v'
    [0x00,0x00,0xC6,0xC6,0xD6,0xFE,0x6C,0x00], // 119 'w'
    [0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00], // 120 'x'
    [0x00,0x00,0xC6,0xC6,0xCE,0x76,0x06,0x7C], // 121 'y'
    [0x00,0x00,0xFE,0x0C,0x38,0x60,0xFE,0x00], // 122 'z'
    [0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00], // 123 '{'
    [0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00], // 124 '|'
    [0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00], // 125 '}'
    [0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00], // 126 '~'
];

fn draw_char(buf: *mut u32, stride_px: u32, x: u32, y: u32, ch: u8, fg: u32) {
    let idx = if (0x20..=0x7E).contains(&ch) {
        (ch - 0x20) as usize
    } else {
        0
    };
    let glyph = &FONT_8X8[idx];
    for row in 0..8u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            if bits & (0x80 >> col) != 0 {
                let offset = ((y + row) * stride_px + (x + col)) as usize;
                unsafe {
                    buf.add(offset).write_volatile(fg);
                }
            }
        }
    }
}

fn draw_string(buf: *mut u32, stride_px: u32, x: u32, y: u32, s: &[u8], fg: u32) {
    for (i, &ch) in s.iter().enumerate() {
        draw_char(buf, stride_px, x + (i as u32) * 8, y, ch, fg);
    }
}

// ---------------------------------------------------------------------------
// Pixel rendering helpers
// ---------------------------------------------------------------------------

fn fill_rect(pool: *mut u32, stride_px: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for row in 0..h {
        for col in 0..w {
            let off = ((y + row) * stride_px + (x + col)) as usize;
            unsafe {
                pool.add(off).write_volatile(color);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Launcher state
// ---------------------------------------------------------------------------

const MAX_QUERY: usize = 32;

struct Launcher {
    visible: bool,
    /// Running search query (ASCII, lowercase canonicalized).
    query: [u8; MAX_QUERY],
    query_len: usize,
    /// Filtered candidate indices (into `CANDIDATES`).
    matches: [usize; CANDIDATE_COUNT],
    match_count: usize,
    /// Currently highlighted row within `matches`.
    selected: usize,
}

impl Launcher {
    const fn new() -> Self {
        Self {
            visible: true,
            query: [0u8; MAX_QUERY],
            query_len: 0,
            matches: [0usize; CANDIDATE_COUNT],
            match_count: 0,
            selected: 0,
        }
    }

    fn refilter(&mut self) {
        self.match_count = 0;
        for (i, cand) in CANDIDATES.iter().enumerate() {
            if subsequence_case_insensitive(&self.query[..self.query_len], cand) {
                self.matches[self.match_count] = i;
                self.match_count += 1;
            }
        }
        if self.selected >= self.match_count {
            self.selected = 0;
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.match_count == 0 {
            self.selected = 0;
            return;
        }
        let n = self.match_count as i32;
        let mut s = self.selected as i32 + delta;
        // Wrap around for a bouncy feel.
        while s < 0 {
            s += n;
        }
        s %= n;
        self.selected = s as usize;
    }

    fn selected_binary(&self) -> Option<&'static [u8]> {
        if self.match_count == 0 {
            return None;
        }
        let idx = self.matches[self.selected];
        Some(CANDIDATES[idx])
    }

    fn push_char(&mut self, ch: u8) {
        if self.query_len < MAX_QUERY {
            self.query[self.query_len] = ch;
            self.query_len += 1;
            self.refilter();
        }
    }

    fn pop_char(&mut self) {
        if self.query_len > 0 {
            self.query_len -= 1;
            self.refilter();
        }
    }

    fn clear_query(&mut self) {
        self.query_len = 0;
        self.refilter();
    }
}

/// Case-insensitive subsequence match: every byte of `needle` must appear
/// in `haystack` in order, but not necessarily contiguously. An empty
/// needle matches everything.
fn subsequence_case_insensitive(needle: &[u8], haystack: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut ni = 0usize;
    for &h in haystack {
        if ni >= needle.len() {
            break;
        }
        if ascii_lower(h) == ascii_lower(needle[ni]) {
            ni += 1;
        }
    }
    ni == needle.len()
}

const fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// Linux-keycode → ASCII char for letter/digit input.
//
// Matches the scancode_to_linux_keycode table in the compositor so the
// launcher can rebuild a user-visible query string from wl_keyboard
// events. Only lowercase — shift isn't tracked since the compositor
// doesn't forward modifier state yet.
// ---------------------------------------------------------------------------

fn keycode_to_char(keycode: u32) -> Option<u8> {
    // Digits 1..0 on the number row (evdev KEY_1 == 2).
    if (2..=11).contains(&keycode) {
        let d = (keycode - 2) as u8;
        return Some(if d == 9 { b'0' } else { b'1' + d });
    }
    match keycode {
        30 => Some(b'a'),
        48 => Some(b'b'),
        46 => Some(b'c'),
        32 => Some(b'd'),
        18 => Some(b'e'),
        33 => Some(b'f'),
        34 => Some(b'g'),
        35 => Some(b'h'),
        23 => Some(b'i'),
        36 => Some(b'j'),
        37 => Some(b'k'),
        38 => Some(b'l'),
        50 => Some(b'm'),
        49 => Some(b'n'),
        24 => Some(b'o'),
        25 => Some(b'p'),
        16 => Some(b'q'),
        19 => Some(b'r'),
        31 => Some(b's'),
        20 => Some(b't'),
        22 => Some(b'u'),
        47 => Some(b'v'),
        17 => Some(b'w'),
        45 => Some(b'x'),
        21 => Some(b'y'),
        44 => Some(b'z'),
        12 => Some(b'-'),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// Draw the full launcher modal into the SHM pool.
fn draw_launcher(pool: *mut u32, launcher: &Launcher) {
    let stride_px = WIN_W;

    if !launcher.visible {
        // Hidden state: single pixel is enough since we'll commit a 1x1
        // damage rect anyway. Fill background so any leftover pixels
        // vanish under the next show.
        fill_rect(pool, stride_px, 0, 0, WIN_W, WIN_H, 0x00000000);
        return;
    }

    // ── Step 1: modal background ─────────────────────────────────────
    fill_rect(pool, stride_px, 0, 0, WIN_W, WIN_H, TN_BG);

    // ── Step 2: 15px accent border ───────────────────────────────────
    fill_rect(pool, stride_px, 0, 0, WIN_W, BORDER_PX, TN_ACCENT);
    fill_rect(pool, stride_px, 0, WIN_H - BORDER_PX, WIN_W, BORDER_PX, TN_ACCENT);
    fill_rect(pool, stride_px, 0, 0, BORDER_PX, WIN_H, TN_ACCENT);
    fill_rect(pool, stride_px, WIN_W - BORDER_PX, 0, BORDER_PX, WIN_H, TN_ACCENT);

    // ── Step 3: header strip ─────────────────────────────────────────
    fill_rect(
        pool,
        stride_px,
        BORDER_PX,
        BORDER_PX,
        WIN_W - 2 * BORDER_PX,
        24,
        TN_BG_LIGHT,
    );
    draw_string(
        pool,
        stride_px,
        BORDER_PX + 8,
        BORDER_PX + 8,
        b"sot-launcher",
        TN_FG,
    );

    // ── Step 4: search box ───────────────────────────────────────────
    let search_x = BORDER_PX + 8;
    let search_y = BORDER_PX + 40;
    let search_w = WIN_W - 2 * BORDER_PX - 16;
    let search_h = 28u32;
    fill_rect(pool, stride_px, search_x, search_y, search_w, search_h, TN_BG_DARK);
    // Inner 1px accent underline.
    fill_rect(
        pool,
        stride_px,
        search_x,
        search_y + search_h - 1,
        search_w,
        1,
        TN_ACCENT,
    );

    // Prompt ">" + query text + cursor bar.
    draw_string(pool, stride_px, search_x + 6, search_y + 10, b">", TN_ACCENT);
    if launcher.query_len > 0 {
        draw_string(
            pool,
            stride_px,
            search_x + 22,
            search_y + 10,
            &launcher.query[..launcher.query_len],
            TN_WHITE,
        );
    } else {
        draw_string(
            pool,
            stride_px,
            search_x + 22,
            search_y + 10,
            b"search applications...",
            TN_DIM,
        );
    }
    // Solid cursor bar after the last query char.
    let cursor_x = search_x + 22 + (launcher.query_len as u32) * 8;
    fill_rect(pool, stride_px, cursor_x, search_y + 8, 2, 12, TN_ACCENT);

    // ── Step 5: result list ─────────────────────────────────────────
    let list_x = BORDER_PX + 8;
    let list_y = search_y + search_h + 12;
    let row_h = 22u32;
    let list_w = WIN_W - 2 * BORDER_PX - 16;
    let mut y = list_y;
    let max_rows = ((WIN_H - list_y - BORDER_PX - 8) / row_h) as usize;
    let visible_rows = launcher.match_count.min(max_rows);

    for i in 0..visible_rows {
        let cand_idx = launcher.matches[i];
        let name = CANDIDATES[cand_idx];
        let is_selected = i == launcher.selected;
        let bg = if is_selected { TN_ACCENT } else { TN_BG_LIGHT };
        let fg = if is_selected { TN_BG } else { TN_FG };
        fill_rect(pool, stride_px, list_x, y, list_w, row_h, bg);
        draw_string(pool, stride_px, list_x + 10, y + 7, name, fg);
        y += row_h + 2;
    }

    // ── Step 6: footer hint ─────────────────────────────────────────
    let hint_y = WIN_H - BORDER_PX - 18;
    draw_string(
        pool,
        stride_px,
        BORDER_PX + 8,
        hint_y,
        b"j/k move  Enter run  Esc hide",
        TN_DIM,
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sot-launcher: starting keyboard-driven launcher\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"sot-launcher: no valid BootInfo\n");
        idle_forever();
    }
    let self_as_cap = boot_info.self_as_cap;
    if self_as_cap == 0 {
        print(b"sot-launcher: WARNING: no self_as_cap, cannot map SHM\n");
        idle_forever();
    }

    // -- Step 1: look up compositor service ----------------------------
    let comp_ep = {
        let name = b"compositor";
        let mut attempts = 0u32;
        loop {
            match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
                Ok(ep) if ep != 0 => break ep,
                _ => {
                    sys::yield_now();
                    attempts += 1;
                    if attempts > 10_000 {
                        print(b"sot-launcher: compositor not available\n");
                        idle_forever();
                    }
                }
            }
        }
    };
    print(b"sot-launcher: compositor ep=");
    print_hex(comp_ep);
    print(b"\n");

    // -- Step 2: connect -----------------------------------------------
    let mut connect = IpcMsg::empty();
    connect.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sot-launcher: connection rejected\n");
        idle_forever();
    }
    print(b"sot-launcher: connected\n");

    // -- Step 3: wl_display.get_registry -------------------------------
    {
        let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
        msg.put_u32(REGISTRY_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }

    // -- Step 4: bind wl_compositor, wl_shm, xdg_wm_base, wl_seat ------
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(1);
        m.put_string(b"wl_compositor");
        m.put_u32(4);
        m.put_u32(COMPOSITOR_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(2);
        m.put_string(b"wl_shm");
        m.put_u32(1);
        m.put_u32(SHM_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(3);
        m.put_string(b"xdg_wm_base");
        m.put_u32(2);
        m.put_u32(XDG_WM_BASE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    // Best-effort wl_seat bind — harmless if the compositor advertises
    // it on a different name, the auto-focus path sends events anyway.
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(4);
        m.put_string(b"wl_seat");
        m.put_u32(5);
        m.put_u32(SEAT_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    // wl_seat::get_keyboard (opcode 1)
    {
        let mut m = WireBuilder::new(SEAT_ID, 1);
        m.put_u32(KEYBOARD_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    print(b"sot-launcher: globals bound\n");

    // -- Step 5: allocate SHM pool --------------------------------------
    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"sot-launcher: shm_create failed ");
            print_hex(e as u64);
            print(b"\n");
            idle_forever();
        }
    };

    {
        let mut m = WireBuilder::new(SHM_ID, 0);
        m.put_u32(POOL_ID);
        m.put_i32(shm_handle as i32);
        m.put_u32(POOL_SIZE);
        let reply = wl_call(comp_ep, &m.finish());
        if reply.tag != WL_SHM_POOL_TAG {
            print(b"sot-launcher: unexpected pool reply\n");
            idle_forever();
        }
    }

    const SHM_MAP_WRITABLE: u64 = 1;
    if sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, SHM_MAP_WRITABLE).is_err() {
        print(b"sot-launcher: shm_map failed\n");
        idle_forever();
    }

    // Create buffer from pool.
    let stride = WIN_W * BPP;
    {
        let mut m = WireBuilder::new(POOL_ID, 0);
        m.put_u32(BUFFER_ID);
        m.put_i32(0);
        m.put_i32(WIN_W as i32);
        m.put_i32(WIN_H as i32);
        m.put_i32(stride as i32);
        m.put_u32(1); // XRGB8888
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 6: create wl_surface + xdg_surface + xdg_toplevel --------
    {
        let mut m = WireBuilder::new(COMPOSITOR_ID, 0);
        m.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(XDG_WM_BASE_ID, 1);
        m.put_u32(XDG_SURFACE_ID);
        m.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(XDG_SURFACE_ID, 1);
        m.put_u32(XDG_TOPLEVEL_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(XDG_TOPLEVEL_ID, 2);
        m.put_string(b"sot-launcher");
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 7: initial render ---------------------------------------
    let pool = CLIENT_POOL_BASE as *mut u32;
    let mut launcher = Launcher::new();
    launcher.refilter();
    draw_launcher(pool, &launcher);

    // Attach, damage, commit.
    {
        let mut m = WireBuilder::new(SURFACE_ID, 1);
        m.put_u32(BUFFER_ID);
        m.put_i32(0);
        m.put_i32(0);
        let _ = wl_call(comp_ep, &m.finish());
    }
    damage_and_commit(comp_ep, WIN_W, WIN_H);

    print(b"=== sot-launcher: WIRED ===\n");

    // -- Step 8: event loop -------------------------------------------
    //
    // Poll the compositor endpoint for wl_keyboard::key events. Only
    // redraw + commit when `dirty` is set, otherwise yield so we don't
    // hot-spin. recv_timeout returns Err on timeout (every scheduler
    // tick) so the loop always progresses regardless of traffic.
    let mut last_visible = true;
    let mut dirty = false;
    loop {
        if let Ok(msg) = sys::recv_timeout(comp_ep, 1) {
            let (buf, len) = reply_bytes(&msg);
            if let Some((keycode, state)) = find_key_event(&buf, len, KEYBOARD_ID) {
                if state == 1 {
                    handle_key(&mut launcher, keycode);
                    dirty = true;
                }
            }
        }

        // Serial breadcrumb on visibility transitions (test harness hook).
        if launcher.visible != last_visible {
            if launcher.visible {
                print(b"sot-launcher: shown\n");
            } else {
                print(b"sot-launcher: hidden\n");
            }
            last_visible = launcher.visible;
        }

        if dirty {
            draw_launcher(pool, &launcher);
            let (dw, dh) = if launcher.visible { (WIN_W, WIN_H) } else { (1u32, 1u32) };
            damage_and_commit(comp_ep, dw, dh);
            dirty = false;
        } else {
            sys::yield_now();
        }
    }
}

/// Dispatch a keycode (press event) to the launcher state machine.
fn handle_key(launcher: &mut Launcher, keycode: u32) {
    match keycode {
        KEY_ESC => {
            // Hide and clear the query so re-showing starts fresh.
            launcher.visible = false;
            launcher.clear_query();
            launcher.selected = 0;
        }
        KEY_SPACE => {
            // Space toggles visibility (our stand-in for Super+Space).
            // When hidden it pops the launcher back up; when visible
            // it's a literal space in the search string.
            if !launcher.visible {
                launcher.visible = true;
            } else {
                launcher.push_char(b' ');
            }
        }
        KEY_ENTER => {
            if launcher.visible {
                if let Some(bin) = launcher.selected_binary() {
                    print(b"sot-launcher: selected '");
                    print(bin);
                    print(b"' (execve not wired from layer client)\n");
                    // Launch would route through init via an IPC
                    // "spawn this name" request; that service doesn't
                    // exist yet, so we log and auto-hide instead.
                    launcher.visible = false;
                    launcher.clear_query();
                    launcher.selected = 0;
                }
            }
        }
        KEY_J => {
            if launcher.visible {
                // Letter 'j' both navigates and, because the launcher
                // is also a search input, appends to the query. We
                // prefer navigation when the query is empty and the
                // list has results.
                if launcher.query_len == 0 && launcher.match_count > 0 {
                    launcher.move_selection(1);
                } else {
                    launcher.push_char(b'j');
                }
            }
        }
        KEY_K => {
            if launcher.visible {
                if launcher.query_len == 0 && launcher.match_count > 0 {
                    launcher.move_selection(-1);
                } else {
                    launcher.push_char(b'k');
                }
            }
        }
        KEY_BACKSPACE => {
            if launcher.visible {
                launcher.pop_char();
            }
        }
        _ => {
            if launcher.visible {
                if let Some(ch) = keycode_to_char(keycode) {
                    launcher.push_char(ch);
                }
            }
        }
    }
}

/// Send `wl_surface::damage(0, 0, w, h)` + `wl_surface::commit`.
fn damage_and_commit(ep: u64, w: u32, h: u32) {
    let mut dmg = WireBuilder::new(SURFACE_ID, 2);
    dmg.put_i32(0);
    dmg.put_i32(0);
    dmg.put_i32(w as i32);
    dmg.put_i32(h as i32);
    let _ = wl_call(ep, &dmg.finish());

    let mut commit = WireBuilder::new(SURFACE_ID, 6);
    let _ = wl_call(ep, &commit.finish());
}

fn idle_forever() -> ! {
    loop {
        sys::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"sot-launcher: PANIC");
    if let Some(loc) = info.location() {
        print(b" at ");
        for &b in loc.file().as_bytes() {
            sys::debug_print(b);
        }
        print(b":");
        print_u32(loc.line());
    }
    print(b"\n");
    idle_forever();
}
