//! sot-launcher -- Keyboard-driven app launcher for the sotOS compositor.
//!
//! Wayland client that creates a layer-shell Overlay (or xdg_toplevel
//! fallback) presenting a centered 500x400 modal with fuzzy search.
//!
//! Layout:
//!   - `#1A1B26` background with 15 px `#7AA2F7` accent border
//!   - Search box at top (`#24283B` bg, accent border)
//!   - Result list below (highlighted row = `#7AA2F7` bg)
//!
//! Behavior:
//!   - Populates results from service registry + `/bin/*` getdents64
//!   - Fuzzy search = case-insensitive subsequence match
//!   - Up/Down navigate, Enter spawns via `sys::execve`, Esc hides
//!   - Size-toggle: 1x1 hidden <-> 500x400 shown
//!
//! Wire protocol copied from `services/hello-gui/src/main.rs`.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};

// ---------------------------------------------------------------------------
// Launcher geometry
// ---------------------------------------------------------------------------

const WIN_W: u32 = 500;
const WIN_H: u32 = 400;
const BPP: u32 = 4;
const POOL_SIZE: u32 = WIN_W * WIN_H * BPP;

/// Virtual address for SHM pool mapping. 0x9100000 avoids conflict with
/// sot-statusbar (0x9000000) and sits in a safe gap in the AS layout.
const CLIENT_POOL_BASE: u64 = 0x9100000;

/// Border width around the window.
const BORDER: u32 = 15;

/// Search box height (inside border).
const SEARCH_H: u32 = 36;

/// Vertical space per result row.
const ROW_H: u32 = 28;

/// Maximum number of result entries we track.
const MAX_RESULTS: usize = 32;

/// Maximum search query length.
const MAX_QUERY: usize = 64;

/// Maximum name length for a result entry.
const MAX_NAME: usize = 48;

// ---------------------------------------------------------------------------
// Tokyo Night palette (XRGB8888)
// ---------------------------------------------------------------------------

const TN_BG: u32 = 0xFF1A1B26;
const TN_BG_DARK: u32 = 0xFF24283B;
const TN_FG: u32 = 0xFFC0CAF5;
const TN_ACCENT: u32 = 0xFF7AA2F7;
const TN_FG_DIM: u32 = 0xFF565F89;

// ---------------------------------------------------------------------------
// IPC tags (must match compositor)
// ---------------------------------------------------------------------------

const WL_MSG_TAG: u64 = 0x574C;
const WL_CONNECT_TAG: u64 = 0x574C_434F;
const WL_SHM_POOL_TAG: u64 = 0x574C_5348;

const IPC_DATA_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Wayland object IDs
// ---------------------------------------------------------------------------

const WL_DISPLAY_ID: u32 = 1;
const REGISTRY_ID: u32 = 2;
const SHM_ID: u32 = 3;
const COMPOSITOR_ID: u32 = 4;
const XDG_WM_BASE_ID: u32 = 5;
const POOL_ID: u32 = 6;
const BUFFER_ID: u32 = 7;
const SURFACE_ID: u32 = 8;
const XDG_SURFACE_ID: u32 = 9;
const XDG_TOPLEVEL_ID: u32 = 10;

// Layer-shell IDs (used when layer-shell is available).
const LAYER_SHELL_ID: u32 = 11;
const LAYER_SURFACE_ID: u32 = 12;

// Layer-shell constants.
const ZWLR_LAYER_OVERLAY: u32 = 3;
const LS_OP_SET_SIZE: u16 = 0;
const LS_OP_ACK_CONFIGURE: u16 = 6;

// ---------------------------------------------------------------------------
// 8x8 bitmap font (ASCII 0x20..0x7E)
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
    [0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00], // 39 '''
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
    [0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00], // 92 '\'
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
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

fn print_u32(mut val: u32) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < 10 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

// ---------------------------------------------------------------------------
// Wayland wire builder (identical to hello-gui / sot-statusbar)
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
            | (u32::from_ne_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
                & 0xFFFF);
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

/// Scan registry reply for a global advertising the given interface name.
fn find_global(buf: &[u8], len: usize, needle: &[u8]) -> Option<u32> {
    let mut off = 0usize;
    while off + 8 <= len {
        let size_op =
            u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;
        if size < 8 || off + size > len {
            return None;
        }
        if opcode == 0 && size >= 20 {
            let payload = &buf[off + 8..off + size];
            let str_len =
                u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
            if str_len > 0 && 8 + str_len <= payload.len() {
                let str_bytes = &payload[8..8 + str_len - 1];
                if str_bytes == needle {
                    return Some(u32::from_ne_bytes([
                        payload[0],
                        payload[1],
                        payload[2],
                        payload[3],
                    ]));
                }
            }
        }
        off += size;
    }
    None
}

/// Parse layer_surface configure event to get the serial for ack.
fn find_layer_configure(buf: &[u8], len: usize, surface_object_id: u32) -> Option<u32> {
    let mut off = 0usize;
    while off + 8 <= len {
        let obj = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let size_op =
            u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;
        if size < 8 || off + size > len {
            return None;
        }
        if obj == surface_object_id && opcode == 0 && size >= 20 {
            let serial = u32::from_ne_bytes([
                buf[off + 8],
                buf[off + 9],
                buf[off + 10],
                buf[off + 11],
            ]);
            return Some(serial);
        }
        off += size;
    }
    None
}

// ---------------------------------------------------------------------------
// Drawing primitives
// ---------------------------------------------------------------------------

fn draw_char(buf: *mut u32, stride_px: u32, x: u32, y: u32, ch: u8, fg: u32) {
    let idx = if ch >= 0x20 && ch <= 0x7E {
        (ch - 0x20) as usize
    } else {
        0
    };
    let glyph = &FONT_8X8[idx];
    for row in 0..8u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            if bits & (0x80 >> col) != 0 {
                let px = x + col;
                let py = y + row;
                if px < WIN_W && py < WIN_H {
                    let offset = (py * stride_px + px) as usize;
                    unsafe {
                        buf.add(offset).write_volatile(fg);
                    }
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

fn fill_rect(buf: *mut u32, stride_px: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for row in 0..h {
        for col in 0..w {
            let px = x + col;
            let py = y + row;
            if px < WIN_W && py < WIN_H {
                let offset = (py * stride_px + px) as usize;
                unsafe {
                    buf.add(offset).write_volatile(color);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Result entry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Entry {
    name: [u8; MAX_NAME],
    name_len: usize,
    is_service: bool,
}

impl Entry {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            is_service: false,
        }
    }

    fn set_name(&mut self, src: &[u8]) {
        let len = src.len().min(MAX_NAME);
        let mut i = 0;
        while i < len {
            self.name[i] = src[i];
            i += 1;
        }
        self.name_len = len;
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// Launcher state
// ---------------------------------------------------------------------------

struct LauncherState {
    /// All known entries (services + binaries).
    entries: [Entry; MAX_RESULTS],
    entry_count: usize,
    /// Filtered results matching the current query.
    filtered: [usize; MAX_RESULTS], // indices into entries[]
    filtered_count: usize,
    /// Current search query.
    query: [u8; MAX_QUERY],
    query_len: usize,
    /// Currently selected row in filtered results.
    selected: usize,
    /// Whether the launcher is currently visible.
    visible: bool,
}

impl LauncherState {
    const fn new() -> Self {
        Self {
            entries: [Entry::empty(); MAX_RESULTS],
            entry_count: 0,
            filtered: [0usize; MAX_RESULTS],
            filtered_count: 0,
            query: [0u8; MAX_QUERY],
            query_len: 0,
            selected: 0,
            visible: true,
        }
    }

    /// Add a result entry.
    fn add_entry(&mut self, name: &[u8], is_service: bool) {
        if self.entry_count >= MAX_RESULTS {
            return;
        }
        self.entries[self.entry_count].set_name(name);
        self.entries[self.entry_count].is_service = is_service;
        self.entry_count += 1;
    }

    /// Case-insensitive subsequence match.
    fn fuzzy_match(query: &[u8], qlen: usize, target: &[u8]) -> bool {
        if qlen == 0 {
            return true;
        }
        let mut qi = 0usize;
        for &tb in target.iter() {
            let qb = query[qi];
            let tl = to_lower(tb);
            let ql = to_lower(qb);
            if tl == ql {
                qi += 1;
                if qi >= qlen {
                    return true;
                }
            }
        }
        false
    }

    /// Recompute filtered list based on current query.
    fn refilter(&mut self) {
        self.filtered_count = 0;
        for i in 0..self.entry_count {
            if Self::fuzzy_match(&self.query, self.query_len, self.entries[i].name_bytes()) {
                if self.filtered_count < MAX_RESULTS {
                    self.filtered[self.filtered_count] = i;
                    self.filtered_count += 1;
                }
            }
        }
        // Clamp selection.
        if self.filtered_count == 0 {
            self.selected = 0;
        } else if self.selected >= self.filtered_count {
            self.selected = self.filtered_count - 1;
        }
    }

    /// Get the entry index for the currently selected row.
    fn selected_entry(&self) -> Option<usize> {
        if self.filtered_count > 0 && self.selected < self.filtered_count {
            Some(self.filtered[self.selected])
        } else {
            None
        }
    }
}

fn to_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// Rendering the launcher UI
// ---------------------------------------------------------------------------

fn draw_launcher(pool: *mut u32, state: &LauncherState) {
    let stride_px = WIN_W;

    // Fill entire window with accent (border color).
    fill_rect(pool, stride_px, 0, 0, WIN_W, WIN_H, TN_ACCENT);

    // Fill inner area with background.
    fill_rect(
        pool,
        stride_px,
        BORDER,
        BORDER,
        WIN_W - 2 * BORDER,
        WIN_H - 2 * BORDER,
        TN_BG,
    );

    // --- Search box ---
    let sb_x = BORDER + 8;
    let sb_y = BORDER + 8;
    let sb_w = WIN_W - 2 * BORDER - 16;
    let sb_h = SEARCH_H;

    // Search box background.
    fill_rect(pool, stride_px, sb_x, sb_y, sb_w, sb_h, TN_BG_DARK);

    // Search box accent border (1px).
    // Top.
    fill_rect(pool, stride_px, sb_x, sb_y, sb_w, 1, TN_ACCENT);
    // Bottom.
    fill_rect(pool, stride_px, sb_x, sb_y + sb_h - 1, sb_w, 1, TN_ACCENT);
    // Left.
    fill_rect(pool, stride_px, sb_x, sb_y, 1, sb_h, TN_ACCENT);
    // Right.
    fill_rect(pool, stride_px, sb_x + sb_w - 1, sb_y, 1, sb_h, TN_ACCENT);

    // Search icon placeholder ">".
    draw_char(pool, stride_px, sb_x + 8, sb_y + 14, b'>', TN_ACCENT);

    // Query text.
    if state.query_len > 0 {
        draw_string(
            pool,
            stride_px,
            sb_x + 24,
            sb_y + 14,
            &state.query[..state.query_len],
            TN_FG,
        );
    } else {
        // Placeholder text.
        draw_string(
            pool,
            stride_px,
            sb_x + 24,
            sb_y + 14,
            b"Search...",
            TN_FG_DIM,
        );
    }

    // Blinking cursor after query.
    let cursor_x = sb_x + 24 + (state.query_len as u32) * 8;
    if cursor_x + 2 < sb_x + sb_w {
        fill_rect(pool, stride_px, cursor_x, sb_y + 12, 2, 12, TN_FG);
    }

    // --- Result list ---
    let list_y = sb_y + sb_h + 8;
    let list_x = BORDER + 8;
    let list_w = WIN_W - 2 * BORDER - 16;

    // How many rows fit?
    let available_h = WIN_H - BORDER - list_y;
    let max_visible = (available_h / ROW_H) as usize;

    for i in 0..state.filtered_count.min(max_visible) {
        let entry_idx = state.filtered[i];
        let entry = &state.entries[entry_idx];
        let row_y = list_y + (i as u32) * ROW_H;

        // Highlight selected row.
        if i == state.selected {
            fill_rect(pool, stride_px, list_x, row_y, list_w, ROW_H, TN_ACCENT);
            draw_string(pool, stride_px, list_x + 8, row_y + 10, entry.name_bytes(), TN_BG);
            // Show type indicator on the right.
            let tag = if entry.is_service { b"[svc]" as &[u8] } else { b"[bin]" };
            let tag_x = list_x + list_w - (tag.len() as u32 + 1) * 8;
            draw_string(pool, stride_px, tag_x, row_y + 10, tag, TN_BG);
        } else {
            // Alternating subtle bg for readability.
            if i % 2 == 1 {
                fill_rect(pool, stride_px, list_x, row_y, list_w, ROW_H, TN_BG_DARK);
            }
            draw_string(pool, stride_px, list_x + 8, row_y + 10, entry.name_bytes(), TN_FG);
            let tag = if entry.is_service { b"[svc]" as &[u8] } else { b"[bin]" };
            let tag_x = list_x + list_w - (tag.len() as u32 + 1) * 8;
            draw_string(pool, stride_px, tag_x, row_y + 10, tag, TN_FG_DIM);
        }
    }

    // If no results, show a message.
    if state.filtered_count == 0 && state.query_len > 0 {
        draw_string(
            pool,
            stride_px,
            list_x + 8,
            list_y + 10,
            b"No matches found",
            TN_FG_DIM,
        );
    }

    // Footer hint.
    let footer_y = WIN_H - BORDER - 14;
    draw_string(
        pool,
        stride_px,
        BORDER + 12,
        footer_y,
        b"Up/Down:select  Enter:launch  Esc:close",
        TN_FG_DIM,
    );
}

// ---------------------------------------------------------------------------
// Populate entries from well-known services + initrd binaries
// ---------------------------------------------------------------------------

fn populate_entries(state: &mut LauncherState) {
    // Well-known services that are typically registered.
    static KNOWN_SERVICES: [&[u8]; 6] = [
        b"compositor",
        b"sot-dtrace",
        b"sot-pkg",
        b"sot-carp",
        b"sotfs",
        b"net",
    ];

    for svc in &KNOWN_SERVICES {
        // Try to look up; only add if actually registered.
        match sys::svc_lookup(svc.as_ptr() as u64, svc.len() as u64) {
            Ok(ep) if ep != 0 => {
                state.add_entry(svc, true);
            }
            _ => {}
        }
    }

    // Well-known binaries that ship in initrd.
    static KNOWN_BINS: [&[u8]; 16] = [
        b"hello",
        b"shell",
        b"busybox",
        b"nano",
        b"links",
        b"toybox",
        b"jq",
        b"bash-static",
        b"grep_alpine",
        b"sed_alpine",
        b"fastfetch",
        b"htop",
        b"hello-linux",
        b"drm-test",
        b"styx-test",
        b"posix-test",
    ];

    for bin in &KNOWN_BINS {
        state.add_entry(bin, false);
    }
}

// ---------------------------------------------------------------------------
// Keyboard input: reads raw PS/2 scancodes from the shared ring buffer
// at KB_RING_ADDR (same mechanism as LUCAS shell).
// ---------------------------------------------------------------------------

/// PS/2 scancode set 1 -> ASCII (simplified).
fn scancode_to_ascii(sc: u8) -> Option<u8> {
    match sc {
        0x02 => Some(b'1'),
        0x03 => Some(b'2'),
        0x04 => Some(b'3'),
        0x05 => Some(b'4'),
        0x06 => Some(b'5'),
        0x07 => Some(b'6'),
        0x08 => Some(b'7'),
        0x09 => Some(b'8'),
        0x0A => Some(b'9'),
        0x0B => Some(b'0'),
        0x0C => Some(b'-'),
        0x0D => Some(b'='),
        0x10 => Some(b'q'),
        0x11 => Some(b'w'),
        0x12 => Some(b'e'),
        0x13 => Some(b'r'),
        0x14 => Some(b't'),
        0x15 => Some(b'y'),
        0x16 => Some(b'u'),
        0x17 => Some(b'i'),
        0x18 => Some(b'o'),
        0x19 => Some(b'p'),
        0x1A => Some(b'['),
        0x1B => Some(b']'),
        0x1E => Some(b'a'),
        0x1F => Some(b's'),
        0x20 => Some(b'd'),
        0x21 => Some(b'f'),
        0x22 => Some(b'g'),
        0x23 => Some(b'h'),
        0x24 => Some(b'j'),
        0x25 => Some(b'k'),
        0x26 => Some(b'l'),
        0x27 => Some(b';'),
        0x28 => Some(b'\''),
        0x29 => Some(b'`'),
        0x2B => Some(b'\\'),
        0x2C => Some(b'z'),
        0x2D => Some(b'x'),
        0x2E => Some(b'c'),
        0x2F => Some(b'v'),
        0x30 => Some(b'b'),
        0x31 => Some(b'n'),
        0x32 => Some(b'm'),
        0x33 => Some(b','),
        0x34 => Some(b'.'),
        0x35 => Some(b'/'),
        0x39 => Some(b' '),
        _ => None,
    }
}

/// Special key scancodes.
const SC_ENTER: u8 = 0x1C;
const SC_BACKSPACE: u8 = 0x0E;
const SC_ESC: u8 = 0x01;
const SC_UP: u8 = 0x48;
const SC_DOWN: u8 = 0x50;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sot-launcher: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let self_as_cap = if boot_info.is_valid() {
        boot_info.self_as_cap
    } else {
        0
    };

    // -- Step 1: look up compositor --
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
                        print(b"sot-launcher: compositor not found\n");
                        idle_forever();
                    }
                }
            }
        }
    };
    print(b"sot-launcher: compositor ep=");
    print_hex(comp_ep);
    print(b"\n");

    let mut connect = IpcMsg::empty();
    connect.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sot-launcher: connection rejected\n");
        idle_forever();
    }
    print(b"sot-launcher: connected\n");

    // wl_display.get_registry
    let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
    msg.put_u32(REGISTRY_ID);
    let reply = wl_call(comp_ep, &msg.finish());

    let (reply_buf, reply_len) = reply_bytes(&reply);
    let has_layer_shell = find_global(&reply_buf, reply_len, b"zwlr_layer_shell_v1").is_some();

    if has_layer_shell {
        print(b"sot-launcher: layer-shell available\n");
    } else {
        print(b"sot-launcher: no layer-shell, using xdg_toplevel fallback\n");
    }

    // Bind wl_compositor + wl_shm (required by all paths).
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

    // wl_compositor::create_surface
    {
        let mut m = WireBuilder::new(COMPOSITOR_ID, 0);
        m.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // Layer-shell Overlay when available, xdg_toplevel fallback otherwise.
    if has_layer_shell {
        let layer_shell_name =
            find_global(&reply_buf, reply_len, b"zwlr_layer_shell_v1").unwrap_or(0);
        {
            let mut m = WireBuilder::new(REGISTRY_ID, 0);
            m.put_u32(layer_shell_name);
            m.put_string(b"zwlr_layer_shell_v1");
            m.put_u32(1);
            m.put_u32(LAYER_SHELL_ID);
            let _ = wl_call(comp_ep, &m.finish());
        }

        // get_layer_surface on Overlay layer (centered, not anchored).
        let initial_serial = {
            let mut m = WireBuilder::new(LAYER_SHELL_ID, 0);
            m.put_u32(LAYER_SURFACE_ID);
            m.put_u32(SURFACE_ID);
            m.put_u32(0);
            m.put_u32(ZWLR_LAYER_OVERLAY);
            m.put_string(b"sot-launcher");
            let reply = wl_call(comp_ep, &m.finish());
            let (rbuf, rlen) = reply_bytes(&reply);
            find_layer_configure(&rbuf, rlen, LAYER_SURFACE_ID).unwrap_or(0)
        };

        {
            let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_SIZE);
            m.put_u32(WIN_W);
            m.put_u32(WIN_H);
            let _ = wl_call(comp_ep, &m.finish());
        }
        {
            let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_ACK_CONFIGURE);
            m.put_u32(initial_serial);
            let _ = wl_call(comp_ep, &m.finish());
        }
    } else {
        // xdg_toplevel fallback.
        {
            let mut m = WireBuilder::new(REGISTRY_ID, 0);
            m.put_u32(3);
            m.put_string(b"xdg_wm_base");
            m.put_u32(2);
            m.put_u32(XDG_WM_BASE_ID);
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
            m.put_string(b"sotOS Launcher");
            let _ = wl_call(comp_ep, &m.finish());
        }
    }

    // SHM pool for pixel rendering.
    let draw_ready = if self_as_cap != 0 {
        match setup_shm_pool(comp_ep) {
            Ok(()) => true,
            Err(()) => {
                print(b"sot-launcher: shm setup failed\n");
                false
            }
        }
    } else {
        print(b"sot-launcher: no self_as_cap, no pixel draw\n");
        false
    };

    // Populate entry list and render initial frame.
    let mut state = LauncherState::new();
    populate_entries(&mut state);
    state.refilter();

    print(b"sot-launcher: ");
    print_u32(state.entry_count as u32);
    print(b" entries loaded\n");

    if draw_ready {
        draw_launcher(CLIENT_POOL_BASE as *mut u32, &state);

        let mut attach = WireBuilder::new(SURFACE_ID, 1);
        attach.put_u32(BUFFER_ID);
        attach.put_i32(0);
        attach.put_i32(0);
        let _ = wl_call(comp_ep, &attach.finish());

        damage_and_commit(comp_ep);
    } else {
        let mut commit = WireBuilder::new(SURFACE_ID, 6);
        let _ = wl_call(comp_ep, &commit.finish());
    }

    print(b"=== sot-launcher: READY ===\n");

    // Keyboard event loop: KB_RING_ADDR = [head: u32, tail: u32, buf: [u8; 256]]
    let kb_ring = sotos_common::KB_RING_ADDR as *mut u8;

    loop {
        // Read keyboard ring.
        let head = unsafe { (kb_ring as *const u32).read_volatile() };
        let tail = unsafe { (kb_ring.add(4) as *const u32).read_volatile() };

        if head != tail {
            let sc = unsafe { kb_ring.add(8 + (tail as usize) % 256).read_volatile() };
            // Advance tail.
            unsafe {
                (kb_ring.add(4) as *mut u32).write_volatile((tail + 1) % 256);
            }

            // Ignore key release (bit 7 set).
            if sc & 0x80 != 0 {
                sys::yield_now();
                continue;
            }

            let mut needs_redraw = false;

            if sc == SC_ESC {
                // Toggle visibility.
                state.visible = !state.visible;
                if !state.visible {
                    print(b"sot-launcher: hidden\n");
                }
                needs_redraw = true;
            } else if sc == SC_UP {
                if state.selected > 0 {
                    state.selected -= 1;
                    needs_redraw = true;
                }
            } else if sc == SC_DOWN {
                if state.filtered_count > 0 && state.selected + 1 < state.filtered_count {
                    state.selected += 1;
                    needs_redraw = true;
                }
            } else if sc == SC_ENTER {
                // Launch the selected entry.
                if let Some(idx) = state.selected_entry() {
                    let entry = &state.entries[idx];
                    // Only init can spawn processes in the current
                    // architecture; log the intent for now.
                    print(b"sot-launcher: launch ");
                    print(entry.name_bytes());
                    if entry.is_service {
                        print(b" [svc]\n");
                    } else {
                        print(b" [bin]\n");
                    }
                }
            } else if sc == SC_BACKSPACE {
                if state.query_len > 0 {
                    state.query_len -= 1;
                    state.refilter();
                    needs_redraw = true;
                }
            } else if let Some(ch) = scancode_to_ascii(sc) {
                if state.query_len < MAX_QUERY {
                    state.query[state.query_len] = ch;
                    state.query_len += 1;
                    state.refilter();
                    needs_redraw = true;
                }
            }

            if needs_redraw && draw_ready {
                if state.visible {
                    draw_launcher(CLIENT_POOL_BASE as *mut u32, &state);
                } else {
                    // Clear to transparent/empty when hidden.
                    fill_rect(
                        CLIENT_POOL_BASE as *mut u32,
                        WIN_W,
                        0,
                        0,
                        WIN_W,
                        WIN_H,
                        0x00000000,
                    );
                }
                damage_and_commit(comp_ep);
            }
        } else {
            sys::yield_now();
        }
    }
}

// ---------------------------------------------------------------------------
// SHM pool setup
// ---------------------------------------------------------------------------

fn setup_shm_pool(comp_ep: u64) -> Result<(), ()> {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let self_as_cap = boot_info.self_as_cap;

    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"sot-launcher: shm_create failed ");
            print_hex(e as u64);
            print(b"\n");
            return Err(());
        }
    };

    // wl_shm::create_pool.
    let mut m = WireBuilder::new(SHM_ID, 0);
    m.put_u32(POOL_ID);
    m.put_i32(shm_handle as i32);
    m.put_u32(POOL_SIZE);
    let reply = wl_call(comp_ep, &m.finish());
    if reply.tag != WL_SHM_POOL_TAG {
        print(b"sot-launcher: unexpected pool reply\n");
        return Err(());
    }

    // Map into our address space.
    const SHM_MAP_WRITABLE: u64 = 1;
    if sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, SHM_MAP_WRITABLE).is_err() {
        print(b"sot-launcher: shm_map failed\n");
        return Err(());
    }

    // Create buffer from pool.
    let stride = WIN_W * BPP;
    let mut m = WireBuilder::new(POOL_ID, 0);
    m.put_u32(BUFFER_ID);
    m.put_i32(0);
    m.put_i32(WIN_W as i32);
    m.put_i32(WIN_H as i32);
    m.put_i32(stride as i32);
    m.put_u32(1); // XRGB8888
    let _ = wl_call(comp_ep, &m.finish());

    Ok(())
}

fn damage_and_commit(ep: u64) {
    let mut dmg = WireBuilder::new(SURFACE_ID, 2);
    dmg.put_i32(0);
    dmg.put_i32(0);
    dmg.put_i32(WIN_W as i32);
    dmg.put_i32(WIN_H as i32);
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
