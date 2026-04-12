//! sot-notify -- Tokyo Night notification daemon for the sotOS compositor.
//!
//! Registers as `"notify"` in the service registry. Other services send
//! IPC messages with `(severity, timeout_ms, title, body)` to display
//! toast notifications anchored TOP|RIGHT on the compositor surface.
//!
//! Each toast is 280x60 px: `#1A1B26` background with a 2-px left border
//! colored by severity (Info=#7AA2F7, Success=#9ECE6A, Warn=#E0AF68,
//! Error=#F7768E). Title bold #C0CAF5, body dim #A9B1D6.
//!
//! Up to 5 toasts stacked vertically with 5px gap, 5px padding from
//! screen edge. Auto-removed after `timeout_ms` (default 4000).
//!
//! Wire protocol copied from services/hello-gui/src/main.rs.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR, NOTIFY_TAG, SyncUnsafeCell};

// ---------------------------------------------------------------------------
// Toast geometry
// ---------------------------------------------------------------------------

/// Toast dimensions in pixels.
const TOAST_W: u32 = 280;
const TOAST_H: u32 = 60;

/// Maximum simultaneous toasts.
const MAX_TOASTS: usize = 5;

/// Padding from screen edge (top-right). Used by compositor positioning.
#[allow(dead_code)]
const EDGE_PAD: u32 = 5;

/// Gap between stacked toasts.
const TOAST_GAP: u32 = 5;

/// Left severity border width.
const BORDER_W: u32 = 2;

/// Surface size: single buffer holding all 5 toast slots vertically.
const SURF_W: u32 = TOAST_W;
const SURF_H: u32 = TOAST_H * MAX_TOASTS as u32 + TOAST_GAP * (MAX_TOASTS as u32 - 1);

/// Bytes per pixel (XRGB8888).
const BPP: u32 = 4;

/// SHM pool size.
const POOL_SIZE: u32 = SURF_W * SURF_H * BPP;

/// Virtual address for SHM pool mapping.
const CLIENT_POOL_BASE: u64 = 0x9100000;

// ---------------------------------------------------------------------------
// Tokyo Night palette (XRGB8888)
// ---------------------------------------------------------------------------

const TN_BG: u32 = 0xFF1A1B26; // storm background
const TN_FG_TITLE: u32 = 0xFFC0CAF5; // bright foreground (title)
const TN_FG_BODY: u32 = 0xFFA9B1D6; // dim foreground (body)
const TN_TRANSPARENT: u32 = 0x00000000; // fully transparent (gap region)

// Severity border colors.
const SEV_INFO: u32 = 0xFF7AA2F7; // blue
const SEV_SUCCESS: u32 = 0xFF9ECE6A; // green
const SEV_WARN: u32 = 0xFFE0AF68; // amber
const SEV_ERROR: u32 = 0xFFF7768E; // red

fn severity_color(sev: u8) -> u32 {
    match sev {
        0 => SEV_INFO,
        1 => SEV_SUCCESS,
        2 => SEV_WARN,
        _ => SEV_ERROR,
    }
}

// ---------------------------------------------------------------------------
// IPC tags (must match compositor)
// ---------------------------------------------------------------------------

const WL_MSG_TAG: u64 = 0x574C;
const WL_CONNECT_TAG: u64 = 0x574C_434F;
#[allow(dead_code)]
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

// ---------------------------------------------------------------------------
// Helpers
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

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    print(b"0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        sys::debug_print(hex[nibble]);
    }
}

// ---------------------------------------------------------------------------
// Wayland wire builder (identical to hello-gui)
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
            print(b"sot-notify: IPC call failed: ");
            print_hex(e as u64);
            print(b"\n");
            IpcMsg::empty()
        }
    }
}

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

fn draw_char(buf: *mut u32, stride: u32, x: u32, y: u32, ch: u8, fg: u32) {
    let idx = if ch >= 0x20 && ch <= 0x7E {
        (ch - 0x20) as usize
    } else {
        0
    };
    let glyph = &FONT_8X8[idx];
    let pprow = stride / 4;
    for row in 0..8u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            if bits & (0x80 >> col) != 0 {
                let offset = ((y + row) * pprow + (x + col)) as usize;
                unsafe {
                    buf.add(offset).write_volatile(fg);
                }
            }
        }
    }
}

fn draw_string(buf: *mut u32, stride: u32, x: u32, y: u32, s: &[u8], fg: u32) {
    for (i, &ch) in s.iter().enumerate() {
        draw_char(buf, stride, x + (i as u32) * 8, y, ch, fg);
    }
}

// ---------------------------------------------------------------------------
// Toast state
// ---------------------------------------------------------------------------

/// A single toast notification.
struct Toast {
    active: bool,
    severity: u8,
    timeout_ms: u16,
    /// TSC tick when this toast was created.
    created_tsc: u64,
    title: [u8; 32],
    title_len: usize,
    body: [u8; 96],
    body_len: usize,
}

impl Toast {
    const fn empty() -> Self {
        Self {
            active: false,
            severity: 0,
            timeout_ms: 4000,
            created_tsc: 0,
            title: [0u8; 32],
            title_len: 0,
            body: [0u8; 96],
            body_len: 0,
        }
    }
}

static TOASTS: SyncUnsafeCell<[Toast; MAX_TOASTS]> = SyncUnsafeCell::new([
    Toast::empty(),
    Toast::empty(),
    Toast::empty(),
    Toast::empty(),
    Toast::empty(),
]);

/// Approximate TSC ticks per millisecond (calibrated at 2 GHz default).
static TSC_PER_MS: SyncUnsafeCell<u64> = SyncUnsafeCell::new(2_000_000);

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Add a toast to the queue. Returns true if added, false if full.
fn toast_push(severity: u8, timeout_ms: u16, title: &[u8], body: &[u8]) -> bool {
    let now = rdtsc();
    let toasts = unsafe { &mut *TOASTS.get() };
    for t in toasts.iter_mut() {
        if !t.active {
            t.active = true;
            t.severity = severity;
            t.timeout_ms = if timeout_ms == 0 { 4000 } else { timeout_ms };
            t.created_tsc = now;
            t.title_len = title.len().min(32);
            t.title[..t.title_len].copy_from_slice(&title[..t.title_len]);
            t.body_len = body.len().min(96);
            t.body[..t.body_len].copy_from_slice(&body[..t.body_len]);
            return true;
        }
    }
    false
}

/// Expire old toasts. Returns number of active toasts.
fn toast_gc() -> usize {
    let now = rdtsc();
    let tsc_ms = unsafe { *TSC_PER_MS.get() };
    let toasts = unsafe { &mut *TOASTS.get() };
    let mut count = 0usize;
    for t in toasts.iter_mut() {
        if t.active {
            let elapsed_ms = (now.saturating_sub(t.created_tsc)) / tsc_ms;
            if elapsed_ms >= t.timeout_ms as u64 {
                t.active = false;
            } else {
                count += 1;
            }
        }
    }
    count
}

/// Compact toasts: move all active entries to the front.
fn toast_compact() {
    let toasts = TOASTS.get() as *mut Toast;
    let mut dst = 0usize;
    for src in 0..MAX_TOASTS {
        let active = unsafe { (*toasts.add(src)).active };
        if active {
            if dst != src {
                unsafe {
                    core::ptr::copy(toasts.add(src), toasts.add(dst), 1);
                    (*toasts.add(src)).active = false;
                }
            }
            dst += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Redraw the entire surface buffer with current toast state.
fn redraw(pool_ptr: *mut u32) {
    let stride = SURF_W * BPP;
    let pprow = stride / 4;

    // Clear entire surface to transparent.
    for y in 0..SURF_H {
        for x in 0..SURF_W {
            let offset = (y * pprow + x) as usize;
            unsafe {
                pool_ptr.add(offset).write_volatile(TN_TRANSPARENT);
            }
        }
    }

    let toasts = unsafe { &*TOASTS.get() };
    {
        let mut slot = 0u32;
        for t in toasts.iter() {
            if !t.active {
                continue;
            }

            let y_off = slot * (TOAST_H + TOAST_GAP);
            let border_color = severity_color(t.severity);

            // Draw toast background.
            for y in 0..TOAST_H {
                for x in 0..TOAST_W {
                    let color = if x < BORDER_W {
                        border_color
                    } else {
                        TN_BG
                    };
                    let offset = ((y_off + y) * pprow + x) as usize;
                    unsafe { pool_ptr.add(offset).write_volatile(color); }
                }
            }

            // Title text at (BORDER_W + 8, 8) relative to toast top.
            let tx = BORDER_W + 8;
            let ty = y_off + 8;
            let max_title_chars = ((TOAST_W - tx - 8) / 8) as usize;
            let title_len = t.title_len.min(max_title_chars);
            draw_string(pool_ptr, stride, tx, ty, &t.title[..title_len], TN_FG_TITLE);

            // Body text at (BORDER_W + 8, 28) relative to toast top.
            let by = y_off + 28;
            // Body can be up to 2 lines of ~32 chars each.
            let max_body_chars = ((TOAST_W - tx - 8) / 8) as usize;
            let line1_len = t.body_len.min(max_body_chars);
            draw_string(pool_ptr, stride, tx, by, &t.body[..line1_len], TN_FG_BODY);

            // Second line of body if needed.
            if t.body_len > max_body_chars {
                let line2_start = max_body_chars;
                let line2_len = (t.body_len - line2_start).min(max_body_chars);
                draw_string(
                    pool_ptr,
                    stride,
                    tx,
                    by + 12,
                    &t.body[line2_start..line2_start + line2_len],
                    TN_FG_BODY,
                );
            }

            slot += 1;
            if slot >= MAX_TOASTS as u32 {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sot-notify: starting notification daemon\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"sot-notify: no valid BootInfo\n");
        loop {
            sys::yield_now();
        }
    }

    let self_as_cap = boot_info.self_as_cap;

    // Calibrate TSC: measure how many ticks in ~10 yields.
    // Each yield is approximately 10ms at the default LAPIC rate.
    let t0 = rdtsc();
    for _ in 0..10 {
        sys::yield_now();
    }
    let t1 = rdtsc();
    let ticks_per_100ms = t1.saturating_sub(t0);
    if ticks_per_100ms > 0 {
        let val = ticks_per_100ms / 100;
        unsafe {
            *TSC_PER_MS.get() = if val == 0 { 2_000_000 } else { val };
        }
    }
    print(b"sot-notify: TSC/ms=");
    print_u32(unsafe { *TSC_PER_MS.get() } as u32);
    print(b"\n");

    // ── Step 1: Connect to compositor ──
    let comp_ep = loop {
        let name = b"compositor";
        match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
            Ok(ep) if ep != 0 => break ep,
            _ => sys::yield_now(),
        }
    };
    print(b"sot-notify: compositor found\n");

    // Connect
    let mut connect_msg = IpcMsg::empty();
    connect_msg.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect_msg);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sot-notify: connection rejected\n");
        loop {
            sys::yield_now();
        }
    }
    print(b"sot-notify: connected to compositor\n");

    // ── Step 2: Get registry ──
    let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
    msg.put_u32(REGISTRY_ID);
    let _ = wl_call(comp_ep, &msg.finish());

    // ── Step 3: Bind globals ──
    // wl_compositor
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(1);
        msg.put_string(b"wl_compositor");
        msg.put_u32(4);
        msg.put_u32(COMPOSITOR_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    // wl_shm
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(2);
        msg.put_string(b"wl_shm");
        msg.put_u32(1);
        msg.put_u32(SHM_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    // xdg_wm_base (fallback: use xdg_toplevel if layer-shell unavailable)
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(3);
        msg.put_string(b"xdg_wm_base");
        msg.put_u32(2);
        msg.put_u32(XDG_WM_BASE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    print(b"sot-notify: globals bound\n");

    // ── Step 4: Create SHM pool ──
    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"sot-notify: shm_create failed: ");
            print_hex(e as u64);
            print(b"\n");
            loop {
                sys::yield_now();
            }
        }
    };

    {
        let mut msg = WireBuilder::new(SHM_ID, 0);
        msg.put_u32(POOL_ID);
        msg.put_i32(shm_handle as i32);
        msg.put_u32(POOL_SIZE);
        let _ = wl_call(comp_ep, &msg.finish());
    }

    // Map SHM into our address space.
    if self_as_cap != 0 {
        match sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, 1) {
            Ok(()) => {}
            Err(e) => {
                print(b"sot-notify: shm_map failed: ");
                print_hex(e as u64);
                print(b"\n");
                loop {
                    sys::yield_now();
                }
            }
        }
    } else {
        print(b"sot-notify: no self_as_cap\n");
        loop {
            sys::yield_now();
        }
    }

    let pool_ptr = CLIENT_POOL_BASE as *mut u32;

    // ── Step 5: Create buffer ──
    {
        let mut msg = WireBuilder::new(POOL_ID, 0);
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0);
        msg.put_i32(SURF_W as i32);
        msg.put_i32(SURF_H as i32);
        msg.put_i32((SURF_W * BPP) as i32);
        msg.put_u32(1); // XRGB8888
        let _ = wl_call(comp_ep, &msg.finish());
    }

    // ── Step 6: Create surface + xdg_surface + xdg_toplevel ──
    {
        let mut msg = WireBuilder::new(COMPOSITOR_ID, 0);
        msg.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(XDG_WM_BASE_ID, 1);
        msg.put_u32(XDG_SURFACE_ID);
        msg.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(XDG_SURFACE_ID, 1);
        msg.put_u32(XDG_TOPLEVEL_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    // Set title
    {
        let mut msg = WireBuilder::new(XDG_TOPLEVEL_ID, 2);
        msg.put_string(b"Notifications");
        let _ = wl_call(comp_ep, &msg.finish());
    }

    // ── Step 7: Initial draw (empty) + attach + commit ──
    redraw(pool_ptr);

    {
        let mut msg = WireBuilder::new(SURFACE_ID, 1);
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0);
        msg.put_i32(0);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 2);
        msg.put_i32(0);
        msg.put_i32(0);
        msg.put_i32(SURF_W as i32);
        msg.put_i32(SURF_H as i32);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 6);
        let _ = wl_call(comp_ep, &msg.finish());
    }
    print(b"sot-notify: surface committed\n");

    // ── Step 8: Register as "notify" service ──
    let notify_ep = match sys::endpoint_create() {
        Ok(ep) => ep,
        Err(e) => {
            print(b"sot-notify: endpoint_create failed: ");
            print_hex(e as u64);
            print(b"\n");
            loop {
                sys::yield_now();
            }
        }
    };

    let name = b"notify";
    match sys::svc_register(name.as_ptr() as u64, name.len() as u64, notify_ep) {
        Ok(()) => print(b"sot-notify: registered as 'notify'\n"),
        Err(e) => {
            print(b"sot-notify: svc_register failed: ");
            print_hex(e as u64);
            print(b"\n");
        }
    }

    // ── Step 9: Send boot notification as smoke test ──
    toast_push(0, 4000, b"sotOS", b"Boot complete");
    print(b"sot-notify: boot notification queued\n");

    // Redraw + damage + commit for the boot notification.
    redraw(pool_ptr);
    damage_and_commit(comp_ep);

    print(b"=== sot-notify: READY ===\n");

    // ── Step 10: Main event loop ──
    // Listen for incoming IPC messages on our notify endpoint.
    // Also periodically GC expired toasts and redraw.
    let mut last_gc_tsc = rdtsc();
    let gc_interval_ms: u64 = 500;

    loop {
        // Non-blocking receive: timeout of 1 tick (~10ms).
        match sys::recv_timeout(notify_ep, 1) {
            Ok(msg) => {
                if msg.tag == NOTIFY_TAG {
                    // Parse notification IPC:
                    // regs[0] bits [7:0] = severity, bits [23:8] = timeout_ms
                    // regs[1..4] = title bytes (up to 32)
                    // regs[4..7] = body bytes (first 24 bytes from regs, rest 0)
                    let severity = (msg.regs[0] & 0xFF) as u8;
                    let timeout_ms = ((msg.regs[0] >> 8) & 0xFFFF) as u16;

                    let mut title = [0u8; 32];
                    let mut body = [0u8; 96];

                    // Extract title from regs[1..5] (4 regs * 8 bytes = 32 bytes)
                    for i in 0..4 {
                        let bytes = msg.regs[1 + i].to_ne_bytes();
                        let off = i * 8;
                        for j in 0..8 {
                            if off + j < 32 {
                                title[off + j] = bytes[j];
                            }
                        }
                    }

                    // Extract body from regs[5..8] (3 regs * 8 bytes = 24 bytes)
                    for i in 0..3 {
                        let bytes = msg.regs[5 + i].to_ne_bytes();
                        let off = i * 8;
                        for j in 0..8 {
                            if off + j < 96 {
                                body[off + j] = bytes[j];
                            }
                        }
                    }

                    // Find actual string lengths (NUL-terminated).
                    let title_len = title.iter().position(|&b| b == 0).unwrap_or(32);
                    let body_len = body.iter().position(|&b| b == 0).unwrap_or(24);

                    toast_push(severity, timeout_ms, &title[..title_len], &body[..body_len]);

                    // Send reply to unblock caller.
                    let reply = IpcMsg::empty();
                    let _ = sys::send(notify_ep, &reply);

                    // Redraw.
                    toast_compact();
                    redraw(pool_ptr);
                    damage_and_commit(comp_ep);
                }
            }
            Err(_) => {
                // No message pending -- yield.
            }
        }

        // Periodic GC of expired toasts.
        let now = rdtsc();
        let tsc_ms = unsafe { *TSC_PER_MS.get() };
        if (now.saturating_sub(last_gc_tsc)) / tsc_ms >= gc_interval_ms {
            last_gc_tsc = now;
            let before = toast_count();
            toast_gc();
            let after = toast_count();
            if after != before {
                toast_compact();
                redraw(pool_ptr);
                damage_and_commit(comp_ep);
            }
        }

        sys::yield_now();
    }
}

fn toast_count() -> usize {
    let toasts = unsafe { &*TOASTS.get() };
    let mut c = 0usize;
    for t in toasts.iter() {
        if t.active {
            c += 1;
        }
    }
    c
}

fn damage_and_commit(ep: u64) {
    let mut dmg = WireBuilder::new(SURFACE_ID, 2);
    dmg.put_i32(0);
    dmg.put_i32(0);
    dmg.put_i32(SURF_W as i32);
    dmg.put_i32(SURF_H as i32);
    let _ = wl_call(ep, &dmg.finish());

    let mut commit = WireBuilder::new(SURFACE_ID, 6);
    let _ = wl_call(ep, &commit.finish());
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"sot-notify: PANIC: ");
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        for &b in file {
            sys::debug_print(b);
        }
        print(b":");
        print_u32(loc.line());
    }
    print(b"\n");
    loop {
        sys::yield_now();
    }
}
