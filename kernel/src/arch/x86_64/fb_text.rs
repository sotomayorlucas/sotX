//! Early kernel-side framebuffer text renderer.
//!
//! Writes glyphs directly to the Limine framebuffer from inside the kernel,
//! bypassing the userspace init service. The userspace path (push bytes into
//! `fb_console` SPSC ring, drain in init, feed vte parser, blit) only works
//! *after* init is running — which is useless on a laptop with no serial port
//! if the kernel crashes in Stage 0/1. This module gives the kernel a visible
//! console from the moment it enters `kmain`.
//!
//! Lifecycle:
//!   1. `kmain()` calls `init(...)` right after `serial::init()`.
//!   2. `SerialWriter::write_str` mirrors every byte into `putchar()`.
//!   3. Just before spawning init, `hand_off_to_init()` silences the kernel
//!      so init's vte renderer can own the FB without conflicts.
//!   4. On panic, `reclaim_for_panic()` takes the FB back and clears it so
//!      the panic trace is visible.
//!
//! ANSI support is a minimal subset — enough to render `boot_splash` output
//! legibly: `CSI [ H/f` (cursor position), `CSI [ J` (clear screen),
//! `CSI [ K` (clear to end of line), `CSI [ m` (SGR: reset, bold, 24-bit
//! fg/bg via `38;2;R;G;B` and `48;2;R;G;B`). Cursor visibility toggles are
//! parsed and ignored.

use super::fb_font::FONT_8X16;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

const CELL_W: u32 = 8;
const CELL_H: u32 = 16;
const MAX_PARAMS: usize = 8;

/// Snapshot of the Limine framebuffer, cached once at init.
#[derive(Clone, Copy)]
struct Fb {
    addr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Normal,
    Esc,
    Csi,
}

struct State {
    fb: Option<Fb>,
    row: u32,
    col: u32,
    /// Current foreground in packed 0x00RRGGBB.
    fg: u32,
    /// Current background in packed 0x00RRGGBB.
    bg: u32,
    esc: EscState,
    params: [u32; MAX_PARAMS],
    n_params: u8,
    cur_param: u32,
    cur_has_digit: bool,
}

const INITIAL_STATE: State = State {
    fb: None,
    row: 0,
    col: 0,
    fg: 0x00FF_FFFF,
    bg: 0x0000_0000,
    esc: EscState::Normal,
    params: [0; MAX_PARAMS],
    n_params: 0,
    cur_param: 0,
    cur_has_digit: false,
};

static STATE: Mutex<State> = Mutex::new(INITIAL_STATE);

/// When true, userspace owns the FB and the kernel stops rendering. Panic
/// handlers can clear this to reclaim the display for crash output.
static INIT_OWNS: AtomicBool = AtomicBool::new(false);

/// Cache the Limine framebuffer geometry and clear the screen.
///
/// The Limine HHDM mapping for the FB may be WB-cached, so pixel writes
/// through it can sit in the CPU cache. `clflush` after each glyph forces
/// the affected cachelines back to physical FB memory.
pub fn init(
    addr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
) {
    // Sanity-check the geometry. A malformed framebuffer response would panic
    // below when we compute pixel offsets, and we'd rather degrade to serial.
    if addr == 0 || width == 0 || height == 0 || pitch == 0 || bpp < 8 {
        return;
    }
    let mut s = STATE.lock();
    s.fb = Some(Fb {
        addr,
        width,
        height,
        pitch,
        bpp,
        red_shift,
        green_shift,
        blue_shift,
    });
    clear_screen(&mut s);
}

/// Called by `SerialWriter::write_str` for every emitted byte. No-op if the
/// FB isn't initialized yet or init has taken ownership.
pub fn putchar(byte: u8) {
    if INIT_OWNS.load(Ordering::Relaxed) {
        return;
    }
    let mut s = STATE.lock();
    if s.fb.is_none() {
        return;
    }
    process_byte(&mut s, byte);
}

/// Mark userspace init as the FB owner. Called from kmain right before the
/// init service is spawned, so the compositor/vte renderer can take over
/// without the kernel clobbering its output.
pub fn hand_off_to_init() {
    INIT_OWNS.store(true, Ordering::Release);
}

/// Retake the FB for panic output. Clears the screen so the crash trace
/// starts on a clean canvas.
pub fn reclaim_for_panic() {
    INIT_OWNS.store(false, Ordering::Release);
    let mut s = STATE.lock();
    s.fg = 0x00FF_FFFF;
    s.bg = 0x0000_0000;
    s.row = 0;
    s.col = 0;
    s.esc = EscState::Normal;
    clear_screen(&mut s);
}

// ---------------------------------------------------------------------------
// ANSI parser
// ---------------------------------------------------------------------------

fn process_byte(s: &mut State, byte: u8) {
    match s.esc {
        EscState::Normal => {
            if byte == 0x1B {
                s.esc = EscState::Esc;
                return;
            }
            match byte {
                b'\n' => {
                    s.col = 0;
                    s.row += 1;
                    scroll_if_needed(s);
                }
                b'\r' => s.col = 0,
                b'\t' => {
                    // Soft tab: advance to next multiple of 8, bounded by cols.
                    let cols = text_cols(s);
                    let next = (s.col + 8) & !7;
                    s.col = next.min(cols.saturating_sub(1));
                }
                0x08 => {
                    // Backspace: move left one cell (no erase).
                    if s.col > 0 {
                        s.col -= 1;
                    }
                }
                _ => {
                    draw_glyph(s, byte);
                    s.col += 1;
                    if s.col >= text_cols(s) {
                        s.col = 0;
                        s.row += 1;
                        scroll_if_needed(s);
                    }
                }
            }
        }
        EscState::Esc => {
            if byte == b'[' {
                s.esc = EscState::Csi;
                s.n_params = 0;
                s.cur_param = 0;
                s.cur_has_digit = false;
            } else {
                // Unsupported escape: bail back to normal. boot_splash only
                // uses CSI sequences, so we don't lose any fidelity here.
                s.esc = EscState::Normal;
            }
        }
        EscState::Csi => match byte {
            b'0'..=b'9' => {
                s.cur_param = s.cur_param.saturating_mul(10) + (byte - b'0') as u32;
                s.cur_has_digit = true;
            }
            b';' => finalize_param(s),
            b'?' => {} // private CSI prefix: ignore
            b'J' => {
                finalize_param(s);
                let n = s.params.first().copied().unwrap_or(0);
                if n == 2 {
                    s.row = 0;
                    s.col = 0;
                    clear_screen(s);
                }
                s.esc = EscState::Normal;
            }
            b'H' | b'f' => {
                finalize_param(s);
                let row = if s.n_params >= 1 {
                    s.params[0].saturating_sub(1)
                } else {
                    0
                };
                let col = if s.n_params >= 2 {
                    s.params[1].saturating_sub(1)
                } else {
                    0
                };
                let rows = text_rows(s);
                let cols = text_cols(s);
                s.row = row.min(rows.saturating_sub(1));
                s.col = col.min(cols.saturating_sub(1));
                s.esc = EscState::Normal;
            }
            b'K' => {
                finalize_param(s);
                clear_eol(s);
                s.esc = EscState::Normal;
            }
            b'm' => {
                finalize_param(s);
                apply_sgr(s);
                s.esc = EscState::Normal;
            }
            b'h' | b'l' | b'A' | b'B' | b'C' | b'D' => {
                // Cursor show/hide + single-direction moves. No-op / unsupported.
                s.esc = EscState::Normal;
            }
            _ => {
                // Anything else we don't understand: drop back to normal.
                s.esc = EscState::Normal;
            }
        },
    }
}

fn finalize_param(s: &mut State) {
    if s.cur_has_digit || s.n_params > 0 {
        if (s.n_params as usize) < MAX_PARAMS {
            s.params[s.n_params as usize] = s.cur_param;
            s.n_params += 1;
        }
    }
    s.cur_param = 0;
    s.cur_has_digit = false;
}

fn apply_sgr(s: &mut State) {
    let mut i = 0;
    let n = s.n_params as usize;
    if n == 0 {
        // `CSI m` with no params = reset
        s.fg = 0x00FF_FFFF;
        s.bg = 0x0000_0000;
        return;
    }
    while i < n {
        let p = s.params[i];
        match p {
            0 => {
                s.fg = 0x00FF_FFFF;
                s.bg = 0x0000_0000;
            }
            1 | 22 => {} // bold on/off: font has no bold variant, no-op
            30 => s.fg = 0x0000_0000,
            31 => s.fg = 0x00CC_0000,
            32 => s.fg = 0x0000_CC00,
            33 => s.fg = 0x00CC_CC00,
            34 => s.fg = 0x0000_00CC,
            35 => s.fg = 0x00CC_00CC,
            36 => s.fg = 0x0000_CCCC,
            37 | 39 => s.fg = 0x00FF_FFFF,
            40 => s.bg = 0x0000_0000,
            47 | 49 => s.bg = 0x0000_0000,
            38 => {
                // 38;2;R;G;B — 24-bit foreground.
                if i + 4 < n && s.params[i + 1] == 2 {
                    let r = s.params[i + 2] & 0xFF;
                    let g = s.params[i + 3] & 0xFF;
                    let b = s.params[i + 4] & 0xFF;
                    s.fg = (r << 16) | (g << 8) | b;
                    i += 4;
                }
            }
            48 => {
                // 48;2;R;G;B — 24-bit background.
                if i + 4 < n && s.params[i + 1] == 2 {
                    let r = s.params[i + 2] & 0xFF;
                    let g = s.params[i + 3] & 0xFF;
                    let b = s.params[i + 4] & 0xFF;
                    s.bg = (r << 16) | (g << 8) | b;
                    i += 4;
                }
            }
            _ => {}
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Rendering primitives
// ---------------------------------------------------------------------------

fn text_cols(s: &State) -> u32 {
    s.fb.map_or(0, |fb| fb.width / CELL_W)
}

fn text_rows(s: &State) -> u32 {
    s.fb.map_or(0, |fb| fb.height / CELL_H)
}

fn clear_screen(s: &mut State) {
    let Some(fb) = s.fb else { return };
    let bg = s.bg;
    for y in 0..fb.height {
        for x in 0..fb.width {
            put_pixel(&fb, x, y, bg);
        }
    }
    fb_flush_all(&fb);
}

fn clear_eol(s: &mut State) {
    let Some(fb) = s.fb else { return };
    let row = s.row;
    let col = s.col;
    let bg = s.bg;
    let y0 = row * CELL_H;
    let y1 = (y0 + CELL_H).min(fb.height);
    let x0 = col * CELL_W;
    for y in y0..y1 {
        for x in x0..fb.width {
            put_pixel(&fb, x, y, bg);
        }
    }
    // Flush the affected row of cells.
    let bytes_per_pixel = (fb.bpp / 8) as u64;
    for y in y0..y1 {
        let line_start = fb.addr + (y as u64) * (fb.pitch as u64)
            + (x0 as u64) * bytes_per_pixel;
        let line_end = fb.addr + (y as u64) * (fb.pitch as u64)
            + (fb.width as u64) * bytes_per_pixel;
        let mut a = line_start;
        while a < line_end {
            unsafe {
                core::arch::asm!("clflush [{}]", in(reg) a, options(nostack, preserves_flags));
            }
            a += 64;
        }
    }
    unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
}

fn scroll_if_needed(s: &mut State) {
    let Some(fb) = s.fb else { return };
    let rows = text_rows(s);
    if s.row < rows {
        return;
    }
    // Scroll up by one cell row: memmove pitch*CELL_H bytes down.
    let overflow = s.row - (rows - 1);
    let scroll_px = overflow * CELL_H;
    let scroll_bytes = (scroll_px as u64) * (fb.pitch as u64);
    let total_bytes = (fb.height as u64) * (fb.pitch as u64);
    unsafe {
        let base = fb.addr as *mut u8;
        // Source = base + scroll_bytes, dest = base, len = total - scroll.
        if scroll_bytes < total_bytes {
            let copy_len = (total_bytes - scroll_bytes) as usize;
            core::ptr::copy(base.add(scroll_bytes as usize), base, copy_len);
        }
    }
    // Zero the exposed bottom rows.
    let y_start = (rows - overflow) * CELL_H;
    let bg = s.bg;
    for y in y_start..fb.height {
        for x in 0..fb.width {
            put_pixel(&fb, x, y, bg);
        }
    }
    fb_flush_all(&fb);
    s.row = rows - 1;
}

fn draw_glyph(s: &mut State, byte: u8) {
    let Some(fb) = s.fb else { return };
    // FONT_8X16 is 256 × 16 bytes. Any u8 index is in-bounds.
    let glyph_base = (byte as usize) * (CELL_H as usize);
    let y_base = s.row * CELL_H;
    let x_base = s.col * CELL_W;
    let fg = s.fg;
    let bg = s.bg;
    for dy in 0..CELL_H {
        let bits = FONT_8X16[glyph_base + dy as usize];
        for dx in 0..CELL_W {
            let on = (bits & (0x80u8 >> dx)) != 0;
            let color = if on { fg } else { bg };
            put_pixel(&fb, x_base + dx, y_base + dy, color);
        }
    }
    fb_flush_cell(&fb, x_base, y_base);
}

fn put_pixel(fb: &Fb, x: u32, y: u32, rgb: u32) {
    if x >= fb.width || y >= fb.height {
        return;
    }
    let bytes_per_pixel = (fb.bpp / 8) as u64;
    let offset = (y as u64) * (fb.pitch as u64) + (x as u64) * bytes_per_pixel;
    let r = (rgb >> 16) & 0xFF;
    let g = (rgb >> 8) & 0xFF;
    let b = rgb & 0xFF;
    let pixel: u32 =
        (r << fb.red_shift) | (g << fb.green_shift) | (b << fb.blue_shift);
    let ptr = (fb.addr + offset) as *mut u8;
    unsafe {
        match bytes_per_pixel {
            4 => core::ptr::write_volatile(ptr as *mut u32, pixel),
            3 => {
                core::ptr::write_volatile(ptr, (pixel & 0xFF) as u8);
                core::ptr::write_volatile(ptr.add(1), ((pixel >> 8) & 0xFF) as u8);
                core::ptr::write_volatile(ptr.add(2), ((pixel >> 16) & 0xFF) as u8);
            }
            2 => core::ptr::write_volatile(ptr as *mut u16, pixel as u16),
            _ => {}
        }
    }
}

/// Flush the pixel writes for a glyph cell back to physical framebuffer
/// memory. The Limine HHDM mapping may be WB-cached, in which case writes
/// linger in L1/L2 and never reach the FB device before init takes over.
/// `clflush` per cacheline + `mfence` forces visibility.
fn fb_flush_cell(fb: &Fb, x_base: u32, y_base: u32) {
    let bytes_per_pixel = (fb.bpp / 8) as u64;
    let row_bytes = (CELL_W as u64) * bytes_per_pixel;
    for dy in 0..CELL_H {
        let y = (y_base + dy) as u64;
        let line_start = fb.addr + y * (fb.pitch as u64) + (x_base as u64) * bytes_per_pixel;
        // Cacheline is 64 bytes; one 8x32-bit row fits in one cacheline,
        // but flush every 64-byte chunk that overlaps the row to be safe.
        let mut off: u64 = 0;
        while off <= row_bytes {
            let addr = line_start + off;
            unsafe {
                core::arch::asm!(
                    "clflush [{}]",
                    in(reg) addr,
                    options(nostack, preserves_flags),
                );
            }
            off += 64;
        }
    }
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

/// Flush the entire framebuffer back to memory. Used after `clear_screen` so
/// the post-clear state actually becomes visible.
fn fb_flush_all(fb: &Fb) {
    let total = (fb.height as u64) * (fb.pitch as u64);
    let mut off: u64 = 0;
    while off < total {
        let addr = fb.addr + off;
        unsafe {
            core::arch::asm!(
                "clflush [{}]",
                in(reg) addr,
                options(nostack, preserves_flags),
            );
        }
        off += 64;
    }
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}
