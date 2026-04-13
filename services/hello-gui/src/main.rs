//! hello-gui: Minimal Wayland client for sotX.
//!
//! Demonstrates real SHM buffer sharing with the compositor:
//! 1. Connect to compositor service via IPC
//! 2. Bind wl_shm, wl_compositor, xdg_wm_base
//! 3. Create kernel SHM object + wl_shm_pool
//! 4. Map shared memory into own address space
//! 5. Write pixel data to shared buffer
//! 6. Create surface + xdg_surface + xdg_toplevel
//! 7. Attach buffer, damage, commit

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Window dimensions.
const WIN_W: u32 = 400;
const WIN_H: u32 = 300;

/// Bytes per pixel (XRGB8888).
const BPP: u32 = 4;

/// Pool size = width * height * bpp.
const POOL_SIZE: u32 = WIN_W * WIN_H * BPP;

/// Base virtual address where client maps the SHM pool.
const CLIENT_POOL_BASE: u64 = 0x7000000;

/// IPC tags (must match compositor).
const WL_MSG_TAG: u64 = 0x574C;
const WL_CONNECT_TAG: u64 = 0x574C_434F;
const WL_SHM_POOL_TAG: u64 = 0x574C_5348;

/// Wayland object IDs (client-side allocation starts at 2).
const WL_DISPLAY_ID: u32 = 1;

// Client-allocated object IDs.
const REGISTRY_ID: u32 = 2;
const SHM_ID: u32 = 3;
const COMPOSITOR_ID: u32 = 4;
const XDG_WM_BASE_ID: u32 = 5;
const POOL_ID: u32 = 6;
const BUFFER_ID: u32 = 7;
const SURFACE_ID: u32 = 8;
const XDG_SURFACE_ID: u32 = 9;
const XDG_TOPLEVEL_ID: u32 = 10;

/// Maximum bytes per IPC message (8 regs * 8 bytes).
const IPC_DATA_MAX: usize = 64;

// Colors (XRGB8888 format).
const COLOR_WINDOW_BG: u32 = 0xFF2D5BA4; // blue window body (app-specific)
const COLOR_BANNER: u32 = 0xFF1A3A6B;    // darker blue banner (app-specific)
const COLOR_WHITE: u32 = sotos_theme::TOKYO_NIGHT.fg_bright;

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
// Wayland wire protocol helpers
// ---------------------------------------------------------------------------

/// Build a Wayland wire message in a byte buffer.
/// Returns the total message length.
struct WireBuilder {
    buf: [u8; IPC_DATA_MAX],
    len: usize,
}

impl WireBuilder {
    fn new(object_id: u32, opcode: u16) -> Self {
        let mut b = Self {
            buf: [0u8; IPC_DATA_MAX],
            len: 8, // header reserved
        };
        let id_bytes = object_id.to_ne_bytes();
        b.buf[0..4].copy_from_slice(&id_bytes);
        // Opcode in lower 16 bits; size filled on finish().
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
        self.buf[self.len + s.len()] = 0; // NUL
        let padded = (len_with_nul + 3) & !3;
        self.len += padded;
    }

    /// Finalize: write size into header, return as IpcMsg.
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

/// Send a Wayland message and receive the reply.
fn wl_call(ep: u64, msg: &IpcMsg) -> IpcMsg {
    match sys::call(ep, msg) {
        Ok(reply) => reply,
        Err(e) => {
            print(b"hello-gui: IPC call failed: ");
            print_hex(e as u64);
            print(b"\n");
            IpcMsg::empty()
        }
    }
}

// ---------------------------------------------------------------------------
// 8x8 bitmap font (minimal: space + ASCII subset for "Hello from SHM!")
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

/// Draw a character at (x, y) in the pixel buffer.
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
                unsafe { buf.add(offset).write_volatile(fg); }
            }
        }
    }
}

/// Draw a string at (x, y) in the pixel buffer.
fn draw_string(buf: *mut u32, stride: u32, x: u32, y: u32, s: &[u8], fg: u32) {
    for (i, &ch) in s.iter().enumerate() {
        draw_char(buf, stride, x + (i as u32) * 8, y, ch, fg);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"hello-gui: starting Wayland client\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"hello-gui: no valid BootInfo\n");
        loop { sys::yield_now(); }
    }

    // Get our own AS cap (needed for shm_map).
    let self_as_cap = boot_info.self_as_cap;
    if self_as_cap == 0 {
        print(b"hello-gui: WARNING: no self_as_cap\n");
    }
    print(b"hello-gui: self_as_cap=");
    print_hex(self_as_cap);
    print(b"\n");

    // ── Step 1: Look up compositor service ──
    let comp_ep = loop {
        let name = b"compositor";
        match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
            Ok(ep) if ep != 0 => break ep,
            _ => {
                // Compositor not ready yet, retry.
                sys::yield_now();
            }
        }
    };
    print(b"hello-gui: compositor endpoint=");
    print_hex(comp_ep);
    print(b"\n");

    // ── Step 2: Connect ──
    let mut connect_msg = IpcMsg::empty();
    connect_msg.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect_msg);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"hello-gui: connection rejected\n");
        loop { sys::yield_now(); }
    }
    print(b"hello-gui: connected to compositor\n");

    // ── Step 3: wl_display.get_registry (opcode 1) ──
    // Args: registry_id (new_id)
    let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
    msg.put_u32(REGISTRY_ID);
    let reply = wl_call(comp_ep, &msg.finish());
    // Reply contains global advertisements; we just consume them.
    print(b"hello-gui: got registry, binding globals\n");

    // ── Step 4: Bind globals ──
    // wl_registry.bind(name, interface_str, version, client_id)
    // Opcode 0 = bind. Args: name(u32), interface(string), version(u32), id(new_id)
    // Global name 1 = wl_compositor, name 2 = wl_shm, name 3 = xdg_wm_base

    // Bind wl_compositor (global name 1)
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(1); // global name
        msg.put_string(b"wl_compositor");
        msg.put_u32(4); // version
        msg.put_u32(COMPOSITOR_ID);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: bound wl_compositor\n");
    }

    // Bind wl_shm (global name 2)
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(2); // global name
        msg.put_string(b"wl_shm");
        msg.put_u32(1); // version
        msg.put_u32(SHM_ID);
        let reply = wl_call(comp_ep, &msg.finish());
        // Reply contains wl_shm::format events; consume.
        print(b"hello-gui: bound wl_shm\n");
    }

    // Bind xdg_wm_base (global name 3)
    {
        let mut msg = WireBuilder::new(REGISTRY_ID, 0);
        msg.put_u32(3); // global name
        msg.put_string(b"xdg_wm_base");
        msg.put_u32(2); // version
        msg.put_u32(XDG_WM_BASE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: bound xdg_wm_base\n");
    }

    // ── Step 5: Create kernel SHM object ──
    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"hello-gui: shm_create failed: ");
            print_hex(e as u64);
            print(b"\n");
            loop { sys::yield_now(); }
        }
    };
    print(b"hello-gui: shm_create handle=");
    print_u32(shm_handle as u32);
    print(b" pages=");
    print_u32(pages as u32);
    print(b"\n");

    // ── Step 6: Send wl_shm.create_pool ──
    // wl_shm::create_pool (opcode 0)
    // Args: pool_id(new_id), fd(fd), size(int)
    // We pass the SHM handle as the "fd" field so the compositor knows
    // the client already created the SHM object.
    {
        let mut msg = WireBuilder::new(SHM_ID, 0);
        msg.put_u32(POOL_ID);
        msg.put_i32(shm_handle as i32); // fd = SHM handle
        msg.put_u32(POOL_SIZE);
        let reply = wl_call(comp_ep, &msg.finish());

        // The compositor replies with WL_SHM_POOL_TAG containing the
        // confirmed SHM handle.
        if reply.tag == WL_SHM_POOL_TAG {
            let confirmed_handle = reply.regs[0];
            let confirmed_pages = reply.regs[1] as u32;
            let confirmed_pool_id = reply.regs[2] as u32;
            print(b"hello-gui: pool confirmed: handle=");
            print_u32(confirmed_handle as u32);
            print(b" pages=");
            print_u32(confirmed_pages);
            print(b" pool_id=");
            print_u32(confirmed_pool_id);
            print(b"\n");
        } else {
            print(b"hello-gui: unexpected pool reply tag=");
            print_hex(reply.tag);
            print(b"\n");
        }
    }

    // ── Step 7: Map SHM into our address space ──
    if self_as_cap != 0 {
        // flags: bit 0 = writable
        match sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, 1) {
            Ok(()) => {
                print(b"hello-gui: shm_map OK at ");
                print_hex(CLIENT_POOL_BASE);
                print(b"\n");
            }
            Err(e) => {
                print(b"hello-gui: shm_map failed: ");
                print_hex(e as u64);
                print(b"\n");
                loop { sys::yield_now(); }
            }
        }
    } else {
        print(b"hello-gui: cannot map SHM (no AS cap)\n");
        loop { sys::yield_now(); }
    }

    // ── Step 8: Write pixels to shared memory ──
    let pool_ptr = CLIENT_POOL_BASE as *mut u32;
    let stride = WIN_W * BPP;
    let pprow = stride / 4; // pixels per row

    // Fill window background.
    for y in 0..WIN_H {
        for x in 0..WIN_W {
            let offset = (y * pprow + x) as usize;
            unsafe {
                pool_ptr.add(offset).write_volatile(COLOR_WINDOW_BG);
            }
        }
    }

    // Draw a banner strip at the top (32px high).
    let banner_h = 32u32;
    for y in 0..banner_h {
        for x in 0..WIN_W {
            let offset = (y * pprow + x) as usize;
            unsafe {
                pool_ptr.add(offset).write_volatile(COLOR_BANNER);
            }
        }
    }

    // Draw text on the banner.
    draw_string(pool_ptr, stride, 20, 12, b"Hello from SHM!", COLOR_WHITE);

    // Draw a colored rectangle in the center to prove pixel control.
    let rect_x = 100u32;
    let rect_y = 80u32;
    let rect_w = 200u32;
    let rect_h = 150u32;
    for y in rect_y..(rect_y + rect_h).min(WIN_H) {
        for x in rect_x..(rect_x + rect_w).min(WIN_W) {
            // Gradient: red increases left-to-right, green top-to-bottom.
            let r = ((x - rect_x) * 255 / rect_w.max(1)) as u32;
            let g = ((y - rect_y) * 255 / rect_h.max(1)) as u32;
            let b = 0x60u32;
            let pixel = 0xFF000000 | (r << 16) | (g << 8) | b;
            let offset = (y * pprow + x) as usize;
            unsafe {
                pool_ptr.add(offset).write_volatile(pixel);
            }
        }
    }

    print(b"hello-gui: pixels written to SHM\n");

    // ── Step 9: Create buffer from pool ──
    // wl_shm_pool::create_buffer (opcode 0)
    // Args: buffer_id(new_id), offset(int), width(int), height(int), stride(int), format(uint)
    {
        let mut msg = WireBuilder::new(POOL_ID, 0);
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0);           // offset
        msg.put_i32(WIN_W as i32); // width
        msg.put_i32(WIN_H as i32); // height
        msg.put_i32(stride as i32); // stride (bytes per row)
        msg.put_u32(1);            // format: XRGB8888
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: buffer created\n");
    }

    // ── Step 10: Create surface ──
    // wl_compositor::create_surface (opcode 0)
    // Args: surface_id(new_id)
    {
        let mut msg = WireBuilder::new(COMPOSITOR_ID, 0);
        msg.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: surface created\n");
    }

    // ── Step 11: Create xdg_surface ──
    // xdg_wm_base::get_xdg_surface (opcode 1)
    // Args: xdg_surface_id(new_id), surface(object)
    {
        let mut msg = WireBuilder::new(XDG_WM_BASE_ID, 1);
        msg.put_u32(XDG_SURFACE_ID);
        msg.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: xdg_surface created\n");
    }

    // ── Step 12: Create xdg_toplevel ──
    // xdg_surface::get_toplevel (opcode 1)
    // Args: toplevel_id(new_id)
    {
        let mut msg = WireBuilder::new(XDG_SURFACE_ID, 1);
        msg.put_u32(XDG_TOPLEVEL_ID);
        let reply = wl_call(comp_ep, &msg.finish());
        // Reply contains toplevel_configure + xdg_surface::configure events.
        print(b"hello-gui: toplevel created\n");
    }

    // ── Step 13: Set title ──
    // xdg_toplevel::set_title (opcode 2)
    // Args: title(string)
    {
        let mut msg = WireBuilder::new(XDG_TOPLEVEL_ID, 2);
        msg.put_string(b"Hello SHM");
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: title set\n");
    }

    // ── Step 14: Attach buffer to surface ──
    // wl_surface::attach (opcode 1)
    // Args: buffer(object), x(int), y(int)
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 1);
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0); // x
        msg.put_i32(0); // y
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: buffer attached\n");
    }

    // ── Step 15: Damage surface ──
    // wl_surface::damage (opcode 2)
    // Args: x(int), y(int), width(int), height(int)
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 2);
        msg.put_i32(0);
        msg.put_i32(0);
        msg.put_i32(WIN_W as i32);
        msg.put_i32(WIN_H as i32);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: damage sent\n");
    }

    // ── Step 16: Commit ──
    // wl_surface::commit (opcode 6)
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 6);
        let _ = wl_call(comp_ep, &msg.finish());
        print(b"hello-gui: committed! Window should be visible.\n");
    }

    print(b"hello-gui: SHM Wayland client complete, entering idle loop\n");

    // Keep alive so the window stays.
    loop {
        sys::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"hello-gui: PANIC: ");
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        for &b in file { sys::debug_print(b); }
        print(b":");
        print_u32(loc.line());
    }
    print(b"\n");
    loop { sys::yield_now(); }
}
