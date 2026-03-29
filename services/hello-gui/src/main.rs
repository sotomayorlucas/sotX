#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

// Framebuffer address (must match kernel mapping)
const FB_ADDR: u64 = 0x4000000;

// Window parameters
const WIN_X: u32 = 100;
const WIN_Y: u32 = 100;
const WIN_W: u32 = 400;
const WIN_H: u32 = 300;

// Title bar height in pixels
const TITLE_H: u32 = 24;

// Colors (BGRA format: B, G, R, A)
const COLOR_BLUE: u32 = 0xFF2D5BA4; // #2D5BA4 -> B=0xA4, G=0x5B, R=0x2D
const COLOR_TITLE_BG: u32 = 0xFF1A3A6B; // darker blue for title bar
const COLOR_TITLE_TEXT: u32 = 0xFFFFFFFF; // white text

// 8x16 bitmap font for printable ASCII (space 0x20 through tilde 0x7E).
// Each character is 16 bytes (one byte per row, 8 pixels wide).
// Only the characters needed for "Hello GUI" are fully defined;
// remaining slots are blank to keep the binary small.
static FONT_8X16: [[u8; 16]; 95] = {
    let mut table = [[0u8; 16]; 95];

    // 'G' (0x47, index 39)
    table[39] = [
        0x00, 0x00, 0x3C, 0x66, 0xC0, 0xC0, 0xC0, 0xCE,
        0xC6, 0xC6, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'H' (0x48, index 40)
    table[40] = [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xFE, 0xC6,
        0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'I' (0x49, index 41)
    table[41] = [
        0x00, 0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'U' (0x55, index 53)
    table[53] = [
        0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6,
        0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'e' (0x65, index 69)
    table[69] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6,
        0xFE, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'l' (0x6C, index 76)
    table[76] = [
        0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00,
    ];

    // 'o' (0x6F, index 79)
    table[79] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6,
        0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
    ];

    table
};

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

#[inline]
fn put_pixel(fb: *mut u8, pitch: u32, x: u32, y: u32, color: u32) {
    let offset = (y as usize) * (pitch as usize) + (x as usize) * 4;
    unsafe {
        let ptr = fb.add(offset) as *mut u32;
        ptr.write_volatile(color);
    }
}

fn fill_rect(fb: *mut u8, pitch: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for row in 0..h {
        for col in 0..w {
            put_pixel(fb, pitch, x + col, y + row, color);
        }
    }
}

fn draw_char(fb: *mut u8, pitch: u32, cx: u32, cy: u32, ch: u8, fg: u32, bg: u32) {
    let idx = if ch >= 0x20 && ch <= 0x7E {
        (ch - 0x20) as usize
    } else {
        0 // fallback to space
    };
    let glyph = &FONT_8X16[idx];
    for row in 0..16u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            let on = (bits >> (7 - col)) & 1;
            let color = if on != 0 { fg } else { bg };
            put_pixel(fb, pitch, cx + col, cy + row, color);
        }
    }
}

fn draw_string(fb: *mut u8, pitch: u32, sx: u32, sy: u32, s: &[u8], fg: u32, bg: u32) {
    for (i, &ch) in s.iter().enumerate() {
        draw_char(fb, pitch, sx + (i as u32) * 8, sy, ch, fg, bg);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"HELLO-GUI: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"HELLO-GUI: no valid BootInfo, exiting\n");
        sys::thread_exit();
    }

    if boot_info.fb_addr == 0 || boot_info.fb_bpp != 32 {
        print(b"HELLO-GUI: no framebuffer or unsupported bpp, exiting\n");
        sys::thread_exit();
    }

    let fb_width = boot_info.fb_width;
    let fb_height = boot_info.fb_height;
    let fb_pitch = boot_info.fb_pitch;

    print(b"HELLO-GUI: fb at 0x4000000, drawing window\n");

    let fb = FB_ADDR as *mut u8;

    // Clamp window to framebuffer bounds
    let max_x = if WIN_X + WIN_W > fb_width { fb_width.saturating_sub(WIN_X) } else { WIN_W };
    let max_y = if WIN_Y + WIN_H > fb_height { fb_height.saturating_sub(WIN_Y) } else { WIN_H };

    if max_x == 0 || max_y == 0 {
        print(b"HELLO-GUI: window out of bounds, exiting\n");
        sys::thread_exit();
    }

    let title_h = if TITLE_H > max_y { max_y } else { TITLE_H };
    fill_rect(fb, fb_pitch, WIN_X, WIN_Y, max_x, title_h, COLOR_TITLE_BG);

    if max_y > title_h {
        fill_rect(fb, fb_pitch, WIN_X, WIN_Y + title_h, max_x, max_y - title_h, COLOR_BLUE);
    }

    let title = b"Hello GUI";
    let text_w = (title.len() as u32) * 8;
    let text_x = WIN_X + (max_x.saturating_sub(text_w)) / 2;
    let text_y = WIN_Y + (title_h.saturating_sub(16)) / 2;
    draw_string(fb, fb_pitch, text_x, text_y, title, COLOR_TITLE_TEXT, COLOR_TITLE_BG);

    print(b"HELLO-GUI: window drawn at (100,100) 400x300\n");
    print(b"HELLO-GUI: exiting cleanly\n");
    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"HELLO-GUI: PANIC!\n");
    sys::thread_exit();
}
