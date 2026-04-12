//! sot-statusbar -- Tokyo Night layer-shell status bar for the sotOS compositor.
//!
//! Connects to the native `compositor` IPC service, walks the Wayland
//! handshake (get_registry, bind wl_compositor/wl_shm/zwlr_layer_shell_v1),
//! and anchors a 24 px top bar with exclusive_zone = 24 so regular
//! toplevels stop at y=24. Content, left to right:
//!
//!   [sotOS logo] ... [time] | [CPU% + sparkline] | [free mem %] | [threads]
//!
//! Post unit 15 (compositor advertises and dispatches layer_shell fully),
//! the bar draws pixels into an SHM buffer and commits once every ~500 ms.
//! If anything in the handshake fails, we print a clear diagnostic and
//! idle instead of silently spinning.
//!
//! Wire-protocol bytes mirror services/hello-gui/src/main.rs verbatim.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};

// ---------------------------------------------------------------------------
// Status bar geometry
// ---------------------------------------------------------------------------

/// Status bar height in pixels (matches exclusive_zone).
const BAR_H: u32 = 24;

/// Placeholder width -- real compositors send a configure event with the
/// actual output size. Sticking to a sane default keeps the unit testable.
const BAR_W: u32 = 1280;

/// Bytes per pixel (XRGB8888).
const BPP: u32 = 4;

/// SHM pool size in bytes.
const POOL_SIZE: u32 = BAR_W * BAR_H * BPP;

/// Virtual address where we map the SHM pool in sot-statusbar's own AS.
///
/// 0x9000000 sits in the documented gap above the interp load base
/// (0x6000000) and below the interp buf base (0xA000000). Avoids 0x7000000,
/// which historically aliased CHILD_BRK (see MEMORY.md gotchas).
const CLIENT_POOL_BASE: u64 = 0x9000000;

// ---------------------------------------------------------------------------
// Tokyo Night palette (XRGB8888)
// ---------------------------------------------------------------------------

const TN_BG: u32      = 0xFF1A1B26; // storm background
const TN_FG: u32      = 0xFFC0CAF5; // foreground text
const TN_DIM: u32     = 0xFF565F89; // comment / divider
const TN_ACCENT: u32  = 0xFF7AA2F7; // blue accent
const TN_GREEN: u32   = 0xFF9ECE6A; // healthy metric
const TN_YELLOW: u32  = 0xFFE0AF68; // warning metric
const TN_RED: u32     = 0xFFF7768E; // critical metric

// ---------------------------------------------------------------------------
// IPC tags (must match compositor::wayland::mod constants verbatim)
// ---------------------------------------------------------------------------

const WL_MSG_TAG: u64 = 0x574C;            // "WL"
const WL_CONNECT_TAG: u64 = 0x574C_434F;   // "WLCO"
const WL_SHM_POOL_TAG: u64 = 0x574C_5348;  // "WLSH"

/// Max bytes per IPC message payload (8 regs * 8 bytes).
const IPC_DATA_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Wayland object IDs (client-allocated, start at 2)
// ---------------------------------------------------------------------------

const WL_DISPLAY_ID: u32      = 1;
const REGISTRY_ID: u32        = 2;
const SHM_ID: u32             = 3;
const COMPOSITOR_ID: u32      = 4;
const LAYER_SHELL_ID: u32     = 5;
const POOL_ID: u32            = 6;
const BUFFER_ID: u32          = 7;
const SURFACE_ID: u32         = 8;
const LAYER_SURFACE_ID: u32   = 9;

/// Well-known global `name` for `zwlr_layer_shell_v1` assigned by
/// services/compositor/src/wayland/registry.rs. Hardcoding it matches
/// what hello-gui does for wl_compositor/wl_shm/xdg_wm_base and avoids
/// the fragility of parsing a packed-event registry reply (only ~2
/// globals fit in one 64 B IPC message).
const LAYER_SHELL_NAME: u32 = 5;

// zwlr_layer_shell_v1 layer enum
const ZWLR_LAYER_TOP: u32 = 2;

// zwlr_layer_surface_v1 request opcodes
const LS_OP_SET_SIZE: u16 = 0;
const LS_OP_SET_ANCHOR: u16 = 1;
const LS_OP_SET_EXCLUSIVE_ZONE: u16 = 2;
const LS_OP_ACK_CONFIGURE: u16 = 6;
const LS_EVT_CONFIGURE_OPCODE: u16 = 0;

// zwlr_layer_surface_v1 anchor bitmask: top | left | right
const ANCHOR_TOP: u32 = 1;
const ANCHOR_LEFT: u32 = 4;
const ANCHOR_RIGHT: u32 = 8;
const ANCHOR_TOP_FULL: u32 = ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT;

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

fn print_u64(mut val: u64) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
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
            print(b"sot-statusbar: IPC call failed ");
            print_hex(e as u64);
            print(b"\n");
            IpcMsg::empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Reply parsing: scan packed events for layer_surface::configure
// ---------------------------------------------------------------------------

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

/// Walk packed events for `zwlr_layer_surface_v1::configure(serial, w, h)`
/// targeting `surface_object_id`. Returns Some(serial) if found.
fn find_layer_configure(buf: &[u8], len: usize, surface_object_id: u32) -> Option<u32> {
    let mut off = 0usize;
    while off + 8 <= len {
        let obj = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let size_op = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;

        if size < 8 || off + size > len {
            return None;
        }

        // configure payload = serial(4) + width(4) + height(4), 20B incl header.
        if obj == surface_object_id && opcode == LS_EVT_CONFIGURE_OPCODE && size >= 20 {
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
// Font: 6 px cell = 5 px glyph + 1 px right gap, 7 rows tall. Each row is a
// u8 with the low 5 bits used, MSB leftmost. Only the characters we render
// are encoded -- unknown bytes fall through as blanks.
// ---------------------------------------------------------------------------

const GLYPH_W: u32 = 6;
const GLYPH_ROWS: usize = 7;

/// Vertically centred baseline for text inside the bar.
const TEXT_Y: i32 = (BAR_H as i32 - GLYPH_ROWS as i32) / 2;

/// Look up a glyph by ASCII code. Returns `None` for unencoded characters;
/// callers reserve a `GLYPH_W`-wide blank in that case.
fn glyph(ch: u8) -> Option<[u8; GLYPH_ROWS]> {
    Some(match ch {
        b'0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        b'1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        b'2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        b'3' => [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
        b'4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        b'5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        b'6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        b'7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        b'9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        b':' => [0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00],
        b'%' => [0x18, 0x19, 0x02, 0x04, 0x08, 0x13, 0x03],
        b'|' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04],
        b'/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        b' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b's' => [0x00, 0x00, 0x0F, 0x10, 0x0E, 0x01, 0x1E],
        b'o' => [0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E],
        b't' => [0x08, 0x08, 0x1C, 0x08, 0x08, 0x09, 0x06],
        b'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        b'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        b'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        b'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Pixel primitives (no-op when the SHM pool is not mapped)
// ---------------------------------------------------------------------------

/// Set pixel inside the bar. Out-of-range coordinates are silently ignored,
/// which keeps every draw call bounds-checked without special cases.
#[inline]
fn put_pixel(pool: *mut u32, x: i32, y: i32, color: u32) {
    if x < 0 || y < 0 || (x as u32) >= BAR_W || (y as u32) >= BAR_H {
        return;
    }
    let off = (y as u32 * BAR_W + x as u32) as usize;
    unsafe { pool.add(off).write_volatile(color); }
}

fn fill_rect(pool: *mut u32, x: i32, y: i32, w: u32, h: u32, color: u32) {
    for row in 0..h as i32 {
        for col in 0..w as i32 {
            put_pixel(pool, x + col, y + row, color);
        }
    }
}

fn clear_bar(pool: *mut u32) {
    let total = (BAR_W * BAR_H) as usize;
    for i in 0..total {
        unsafe { pool.add(i).write_volatile(TN_BG); }
    }
}

/// Render a single glyph at (`x`, `y`) with the given color. `y` is the
/// top-of-cell row in absolute bar coordinates; GLYPH_ROWS rows of pixels
/// are consumed. Blank glyphs render as empty space. Returns the horizontal
/// advance (always GLYPH_W).
fn draw_char(pool: *mut u32, x: i32, y: i32, ch: u8, color: u32) -> i32 {
    if let Some(g) = glyph(ch) {
        for (r, row_bits) in g.iter().enumerate() {
            let py = y + r as i32;
            for c in 0..5i32 {
                // MSB-first in the 5-bit glyph data: bit 4 = column 0.
                let bit = (row_bits >> (4 - c)) & 1;
                if bit != 0 {
                    put_pixel(pool, x + c, py, color);
                }
            }
        }
    }
    GLYPH_W as i32
}

/// Draw a left-aligned string starting at (`x`, `y`). Returns the x coord
/// immediately after the last glyph.
fn draw_text(pool: *mut u32, x: i32, y: i32, text: &[u8], color: u32) -> i32 {
    let mut cx = x;
    for &ch in text {
        cx += draw_char(pool, cx, y, ch, color);
    }
    cx
}

/// Pixel width of a string in the 6x10 font (wraps to u32).
fn text_width(text: &[u8]) -> u32 {
    text.len() as u32 * GLYPH_W
}

/// Draw a right-aligned string with its rightmost pixel at `right_x`.
/// Returns the leftmost x coord occupied by the resulting text block.
fn draw_text_right(pool: *mut u32, right_x: i32, y: i32, text: &[u8], color: u32) -> i32 {
    let start = right_x - text_width(text) as i32;
    draw_text(pool, start, y, text, color);
    start
}

/// Vertical divider between metric groups.
fn draw_divider(pool: *mut u32, x: i32) {
    for row in 4..(BAR_H as i32 - 5) {
        put_pixel(pool, x, row, TN_DIM);
    }
}

/// Draw a 32-sample CPU sparkline rooted at (`x`, `y`). Each sample is a
/// vertical bar whose height scales with the sample (0..100).
fn draw_sparkline(pool: *mut u32, x: i32, y: i32, samples: &[u8], color: u32) {
    const SPARK_H: u32 = 14;
    const SPARK_BAR_W: i32 = 2;
    let base_y = y + SPARK_H as i32;
    let mut cx = x;
    for &s in samples {
        let h = ((s.min(100) as u32) * SPARK_H) / 100;
        let top = base_y - h as i32;
        fill_rect(pool, cx, top, SPARK_BAR_W as u32, h.max(1), color);
        cx += SPARK_BAR_W;
    }
}

// ---------------------------------------------------------------------------
// Metrics (sampled on every redraw)
// ---------------------------------------------------------------------------

/// Boot TSC assumption. Matches services/init/src/vdso.rs -- do not drift
/// from there without updating the vDSO at the same time.
const TSC_HZ: u64 = 2_000_000_000;

/// Max thread pool index we sweep when summing CPU ticks. A real sotOS
/// image peaks around 40 active threads; 64 gives headroom.
const MAX_THREAD_SAMPLES: u32 = 64;

/// Raw wrapper around SYS_THREAD_INFO (syscall 140). Returns the per-thread
/// CPU tick count via r8, or None for an empty pool slot. The generated
/// wrapper in sotos_common::sys::thread_info throws away the extra regs,
/// so we cannot use it here -- reaching past rax is the whole point.
fn thread_ticks(idx: u32) -> Option<u64> {
    let rax: u64;
    let r8: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 140u64 => rax,
            in("rdi") idx as u64,
            lateout("rsi") _,
            lateout("rdx") _,
            lateout("r8") r8,
            lateout("r9") _,
            lateout("r10") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if (rax as i64) < 0 {
        None
    } else {
        Some(r8)
    }
}

/// Sum CPU ticks across every live thread in the pool.
fn system_cpu_ticks() -> u64 {
    let mut total = 0u64;
    for i in 0..MAX_THREAD_SAMPLES {
        if let Some(ticks) = thread_ticks(i) {
            total = total.saturating_add(ticks);
        }
    }
    total
}

#[derive(Clone, Copy)]
struct Metrics {
    clock_secs: u64,
    cpu_pct: u32,
    mem_pct: u32,
    procs: u32,
}

/// Statusbar-local state threaded through every redraw so we can compute
/// deltas for the CPU meter and feed the sparkline ring buffer.
struct Runtime {
    baseline_free: u64,
    prev_tsc: u64,
    prev_busy: u64,
    spark: [u8; 32],
    spark_head: usize,
}

impl Runtime {
    fn new() -> Self {
        let baseline_free = sys::debug_free_frames().max(1);
        let prev_tsc = sys::rdtsc();
        let prev_busy = system_cpu_ticks();
        Self {
            baseline_free,
            prev_tsc,
            prev_busy,
            spark: [0u8; 32],
            spark_head: 0,
        }
    }

    fn sample(&mut self) -> Metrics {
        let now_tsc = sys::rdtsc();
        let now_busy = system_cpu_ticks();

        // TSC delta is our wall-clock window. Busy delta is total kernel-tracked
        // CPU time across every live thread in the same window. cpu% is the
        // ratio capped at 100 so spurious kernel accounting cannot push the bar
        // past its right edge.
        let dt_tsc = now_tsc.saturating_sub(self.prev_tsc).max(1);
        let dt_busy = now_busy.saturating_sub(self.prev_busy);
        let cpu_pct = ((dt_busy.saturating_mul(100)) / dt_tsc).min(100) as u32;

        self.prev_tsc = now_tsc;
        self.prev_busy = now_busy;

        let free_now = sys::debug_free_frames();
        let mem_pct =
            ((free_now.min(self.baseline_free) * 100) / self.baseline_free) as u32;

        self.spark[self.spark_head] = cpu_pct as u8;
        self.spark_head = (self.spark_head + 1) % self.spark.len();

        Metrics {
            clock_secs: now_tsc / TSC_HZ,
            cpu_pct,
            mem_pct,
            procs: sys::thread_count() as u32,
        }
    }

    /// Copy the ring buffer into a linear oldest -> newest buffer so the
    /// sparkline renders left-to-right in historical order.
    fn ordered_spark(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.spark[(self.spark_head + i) % 32];
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Pixel rendering (only runs when layer-shell is live + self_as_cap is set)
// ---------------------------------------------------------------------------

/// Select a palette color for a percentage metric: green at the healthy
/// end, yellow in the middle, red when critical. `higher_is_better` flips
/// the thresholds for metrics like free memory where high is good.
fn pct_color(pct: u32, higher_is_better: bool) -> u32 {
    let healthy = if higher_is_better {
        pct >= 50
    } else {
        pct < 50
    };
    let warning = if higher_is_better {
        pct >= 20
    } else {
        pct < 80
    };
    if healthy {
        TN_GREEN
    } else if warning {
        TN_YELLOW
    } else {
        TN_RED
    }
}

/// Format a u32 into the given buffer, filling right-to-left. Returns the
/// slice of `buf` that contains the digits.
fn u32_to_bytes(mut val: u32, buf: &mut [u8]) -> &[u8] {
    if val == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while val > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &buf[i..]
}

/// Format the clock as HH:MM:SS into the given fixed-size buffer.
fn format_clock(secs: u64, out: &mut [u8; 8]) {
    let h = ((secs / 3600) % 100) as u32;
    let m = ((secs / 60) % 60) as u32;
    let s = (secs % 60) as u32;
    out[0] = b'0' + (h / 10) as u8;
    out[1] = b'0' + (h % 10) as u8;
    out[2] = b':';
    out[3] = b'0' + (m / 10) as u8;
    out[4] = b'0' + (m % 10) as u8;
    out[5] = b':';
    out[6] = b'0' + (s / 10) as u8;
    out[7] = b'0' + (s % 10) as u8;
}

/// Right-align a metric cell of the form `<label>:<value>[unit]` and return
/// the leftmost x of the rendered block. `label` is a single ASCII byte
/// (e.g. `b'C'` for CPU). `unit` is an optional trailing byte (e.g. `b'%'`
/// for percentages, `0` for no unit).
fn draw_metric_right(
    pool: *mut u32,
    right_x: i32,
    label: u8,
    value: u32,
    unit: u8,
    color: u32,
) -> i32 {
    let mut digits_buf = [0u8; 8];
    let digits = u32_to_bytes(value, &mut digits_buf);
    let mut cell = [0u8; 16];
    cell[0] = label;
    cell[1] = b':';
    cell[2..2 + digits.len()].copy_from_slice(digits);
    let mut cell_len = 2 + digits.len();
    if unit != 0 {
        cell[cell_len] = unit;
        cell_len += 1;
    }
    draw_text_right(pool, right_x, TEXT_Y, &cell[..cell_len], color)
}

/// Gap between a metric cell and the next element to its left.
const CELL_GAP: i32 = 4;

/// Draw the full status bar for the given metrics into the SHM pool.
fn draw_bar(pool: *mut u32, rt: &Runtime, m: &Metrics) {
    clear_bar(pool);
    fill_rect(pool, 0, BAR_H as i32 - 1, BAR_W, 1, TN_ACCENT);

    // Left side: sotOS logo.
    draw_text(pool, 8, TEXT_Y, b"sotOS", TN_ACCENT);

    // Right-to-left metrics. Each metric pulls `right_edge` further left,
    // leaving room for a thin divider between groups.
    let mut right_edge = BAR_W as i32 - 8;

    // Wall clock HH:MM:SS.
    let mut clock_buf = [0u8; 8];
    format_clock(m.clock_secs, &mut clock_buf);
    right_edge = draw_text_right(pool, right_edge, TEXT_Y, &clock_buf, TN_ACCENT) - CELL_GAP;
    draw_divider(pool, right_edge);
    right_edge -= CELL_GAP;

    // Live thread count.
    right_edge =
        draw_metric_right(pool, right_edge, b'P', m.procs, 0, TN_FG) - CELL_GAP;
    draw_divider(pool, right_edge);
    right_edge -= CELL_GAP;

    // Free memory percentage (high = good).
    let mem_color = pct_color(m.mem_pct, /*higher_is_better*/ true);
    right_edge =
        draw_metric_right(pool, right_edge, b'M', m.mem_pct.min(100), b'%', mem_color)
            - CELL_GAP;
    draw_divider(pool, right_edge);
    right_edge -= CELL_GAP;

    // CPU utilisation (high = bad).
    let cpu_color = pct_color(m.cpu_pct, /*higher_is_better*/ false);
    right_edge =
        draw_metric_right(pool, right_edge, b'C', m.cpu_pct.min(100), b'%', cpu_color)
            - CELL_GAP;

    // 32-sample CPU sparkline, immediately left of the CPU cell.
    const SPARK_COLS: i32 = 32 * 2;
    let spark = rt.ordered_spark();
    draw_sparkline(pool, right_edge - SPARK_COLS, TEXT_Y - 3, &spark, TN_ACCENT);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sot-statusbar: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let self_as_cap = if boot_info.is_valid() {
        boot_info.self_as_cap
    } else {
        0
    };

    let comp_ep = match lookup_compositor() {
        Some(ep) => ep,
        None => {
            print(b"sot-statusbar: compositor never registered, aborting\n");
            idle_forever();
        }
    };
    print(b"sot-statusbar: compositor ep=");
    print_hex(comp_ep);
    print(b"\n");

    let mut connect = IpcMsg::empty();
    connect.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sot-statusbar: connection rejected by compositor\n");
        idle_forever();
    }
    print(b"sot-statusbar: connected\n");

    // We do not parse the registry reply: the compositor advertises globals
    // in a fixed order (see services/compositor/src/wayland/registry.rs) and
    // a 64 B IPC reply can hold only ~2 packed events. Hardcoding the `name`
    // constants matches hello-gui's approach.
    {
        let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
        msg.put_u32(REGISTRY_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }

    bind_global(comp_ep, 1, b"wl_compositor", 4, COMPOSITOR_ID);
    bind_global(comp_ep, 2, b"wl_shm", 1, SHM_ID);
    bind_global(comp_ep, LAYER_SHELL_NAME, b"zwlr_layer_shell_v1", 1, LAYER_SHELL_ID);

    // wl_compositor::create_surface
    {
        let mut m = WireBuilder::new(COMPOSITOR_ID, 0);
        m.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // zwlr_layer_shell_v1::get_layer_surface. The reply carries the initial
    // configure(serial, 0, 0) event packed in the IPC buffer -- capture the
    // serial so we can ack it below.
    let initial_configure_serial: u32 = {
        let mut m = WireBuilder::new(LAYER_SHELL_ID, 0);
        m.put_u32(LAYER_SURFACE_ID);
        m.put_u32(SURFACE_ID);
        m.put_u32(0);              // output = null (default)
        m.put_u32(ZWLR_LAYER_TOP);
        m.put_string(b"sot-statusbar");
        let reply = wl_call(comp_ep, &m.finish());
        let (rbuf, rlen) = reply_bytes(&reply);
        find_layer_configure(&rbuf, rlen, LAYER_SURFACE_ID).unwrap_or(0)
    };

    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_SIZE);
        m.put_u32(BAR_W);
        m.put_u32(BAR_H);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_ANCHOR);
        m.put_u32(ANCHOR_TOP_FULL);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_EXCLUSIVE_ZONE);
        m.put_i32(BAR_H as i32);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // Per wlr-layer-shell-unstable-v1, the surface is NOT mapped until we
    // ack the compositor's configure event. sotOS accepts any serial as an
    // ack, so falling through with 0 (when the event did not arrive in the
    // get_layer_surface reply) is safe.
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_ACK_CONFIGURE);
        m.put_u32(initial_configure_serial);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // Running without self_as_cap means init::spawn_process did not forward
    // it yet, so pixel draw is disabled. We still commit a frameless surface
    // so the compositor knows we exist and exercises every handshake path.
    let draw_ready = if self_as_cap != 0 {
        match setup_shm_pool(comp_ep, self_as_cap) {
            Ok(()) => true,
            Err(()) => {
                print(b"sot-statusbar: SHM pool setup failed\n");
                false
            }
        }
    } else {
        print(b"sot-statusbar: no self_as_cap -- running headless\n");
        false
    };

    let mut rt = Runtime::new();
    let metrics = rt.sample();

    if draw_ready {
        draw_bar(CLIENT_POOL_BASE as *mut u32, &rt, &metrics);

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

    print(b"=== sot-statusbar: WIRED ===\n");

    // 500 ms cadence matches the task brief; 32 samples of sparkline
    // therefore summarise ~16 seconds of CPU history.
    const REDRAW_PERIOD_TSC: u64 = TSC_HZ / 2;

    loop {
        let deadline = sys::rdtsc().wrapping_add(REDRAW_PERIOD_TSC);
        while sys::rdtsc() < deadline {
            sys::yield_now();
        }

        let metrics = rt.sample();

        if draw_ready {
            draw_bar(CLIENT_POOL_BASE as *mut u32, &rt, &metrics);
            damage_and_commit(comp_ep);
        }

        // Serial heartbeat so boot-smoke CI can confirm the bar is alive.
        print(b"sot-statusbar: tick clock=");
        print_u64(metrics.clock_secs);
        print(b" cpu=");
        print_u32(metrics.cpu_pct);
        print(b"% mem=");
        print_u32(metrics.mem_pct);
        print(b"% procs=");
        print_u32(metrics.procs);
        print(b"\n");
    }
}

/// Send `wl_registry::bind(name, interface, version, new_id)`.
fn bind_global(ep: u64, name: u32, interface: &[u8], version: u32, new_id: u32) {
    let mut m = WireBuilder::new(REGISTRY_ID, 0);
    m.put_u32(name);
    m.put_string(interface);
    m.put_u32(version);
    m.put_u32(new_id);
    let _ = wl_call(ep, &m.finish());
}

/// Look up the compositor service, yielding until it registers or we give
/// up. Returns `None` if the compositor never appears after ~10k yields.
fn lookup_compositor() -> Option<u64> {
    let name = b"compositor";
    for _ in 0..10_000u32 {
        if let Ok(ep) = sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
            if ep != 0 {
                return Some(ep);
            }
        }
        sys::yield_now();
    }
    None
}

/// Send wl_surface damage + commit for the full bar. Called by both the
/// initial draw and every tick of the redraw loop.
fn damage_and_commit(ep: u64) {
    let mut dmg = WireBuilder::new(SURFACE_ID, 2);
    dmg.put_i32(0);
    dmg.put_i32(0);
    dmg.put_i32(BAR_W as i32);
    dmg.put_i32(BAR_H as i32);
    let _ = wl_call(ep, &dmg.finish());

    let mut commit = WireBuilder::new(SURFACE_ID, 6);
    let _ = wl_call(ep, &commit.finish());
}

// ---------------------------------------------------------------------------
// SHM pool setup (only called on the happy path)
// ---------------------------------------------------------------------------

fn setup_shm_pool(comp_ep: u64, self_as_cap: u64) -> Result<(), ()> {
    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"sot-statusbar: shm_create failed ");
            print_hex(e as u64);
            print(b"\n");
            return Err(());
        }
    };

    // wl_shm::create_pool (opcode 0): pool_id, fd, size
    let mut m = WireBuilder::new(SHM_ID, 0);
    m.put_u32(POOL_ID);
    m.put_i32(shm_handle as i32);
    m.put_u32(POOL_SIZE);
    let reply = wl_call(comp_ep, &m.finish());
    if reply.tag != WL_SHM_POOL_TAG {
        print(b"sot-statusbar: unexpected pool reply\n");
        return Err(());
    }

    // shm_map's 4th arg is a flags bitmap (bit 0 = writable), NOT a page
    // count -- the kernel pulls page_count from the ShmObject itself
    // (see kernel/src/shm.rs). All `pages` allocated above get mapped.
    const SHM_MAP_WRITABLE: u64 = 1;
    if sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, SHM_MAP_WRITABLE).is_err() {
        print(b"sot-statusbar: shm_map failed\n");
        return Err(());
    }

    // wl_shm_pool::create_buffer (opcode 0)
    let stride = BAR_W * BPP;
    let mut m = WireBuilder::new(POOL_ID, 0);
    m.put_u32(BUFFER_ID);
    m.put_i32(0);
    m.put_i32(BAR_W as i32);
    m.put_i32(BAR_H as i32);
    m.put_i32(stride as i32);
    m.put_u32(1); // XRGB8888
    let _ = wl_call(comp_ep, &m.finish());

    Ok(())
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
    print(b"sot-statusbar: PANIC");
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
