//! Multi-shape cursor glyphs for the compositor.
//!
//! Each glyph is a hand-crafted static BGRA bitmap. `0` is treated as a
//! fully transparent pixel; opaque pixels are written straight to the
//! framebuffer by [`draw`]. Glyphs are small (16x24 max) so they fit
//! comfortably in `.rodata` with no heap allocation.
//!
//! Only `CursorShape::Default` is wired into the compose loop today; the
//! other variants and glyphs are staged for future hover/drag logic, so
//! dead-code is suppressed at the module level.
#![allow(dead_code)]

use crate::render::Framebuffer;

/// Logical cursor shape requested by the compositor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorShape {
    /// Classic top-left arrow.
    Default,
    /// Hand with extended index finger (link / button hover).
    Pointer,
    /// Text I-beam.
    Text,
    /// Wait / busy indicator (hourglass).
    Wait,
    /// Four-direction move arrow.
    Move,
    /// Vertical resize (up-down).
    ResizeNS,
    /// Horizontal resize (left-right).
    ResizeEW,
    /// "Not allowed" circle-slash.
    NotAllowed,
}

/// A statically allocated cursor bitmap.
pub struct CursorGlyph {
    pub width: usize,
    pub height: usize,
    /// Hot-spot X offset (relative to the glyph's top-left).
    pub hot_x: usize,
    /// Hot-spot Y offset (relative to the glyph's top-left).
    pub hot_y: usize,
    /// Row-major BGRA pixels. `0x00000000` is transparent.
    pub pixels: &'static [u32],
}

// ---------------------------------------------------------------------------
// Color palette used by the hand-crafted glyphs.
// ---------------------------------------------------------------------------

const T: u32 = 0x00000000; // transparent
const K: u32 = 0xFF000000; // opaque black (outline)
const W: u32 = 0xFFFFFFFF; // opaque white (fill)

// ---------------------------------------------------------------------------
// Glyph bitmaps.
//
// Layout note: each row is exactly `width` entries. Glyph dimensions are
// kept modest (<= 24x24) so the total static footprint stays well under
// 4 KiB.
// ---------------------------------------------------------------------------

/// Default arrow — 12 wide, 19 tall. Hot-spot at (0, 0) (top-left).
#[rustfmt::skip]
static DEFAULT_PIXELS: [u32; 12 * 19] = [
    K,T,T,T,T,T,T,T,T,T,T,T,
    K,K,T,T,T,T,T,T,T,T,T,T,
    K,W,K,T,T,T,T,T,T,T,T,T,
    K,W,W,K,T,T,T,T,T,T,T,T,
    K,W,W,W,K,T,T,T,T,T,T,T,
    K,W,W,W,W,K,T,T,T,T,T,T,
    K,W,W,W,W,W,K,T,T,T,T,T,
    K,W,W,W,W,W,W,K,T,T,T,T,
    K,W,W,W,W,W,W,W,K,T,T,T,
    K,W,W,W,W,W,W,W,W,K,T,T,
    K,W,W,W,W,W,W,W,W,W,K,T,
    K,W,W,W,W,W,W,K,K,K,K,K,
    K,W,W,W,K,W,W,K,T,T,T,T,
    K,W,W,K,T,K,W,W,K,T,T,T,
    K,W,K,T,T,K,W,W,K,T,T,T,
    K,K,T,T,T,T,K,W,W,K,T,T,
    T,T,T,T,T,T,K,W,W,K,T,T,
    T,T,T,T,T,T,T,K,K,K,T,T,
    T,T,T,T,T,T,T,T,T,T,T,T,
];

pub static DEFAULT_GLYPH: CursorGlyph = CursorGlyph {
    width: 12,
    height: 19,
    hot_x: 0,
    hot_y: 0,
    pixels: &DEFAULT_PIXELS,
};

/// Pointer (hand) — 14 wide, 18 tall. Hot-spot (5, 0) at fingertip.
#[rustfmt::skip]
static POINTER_PIXELS: [u32; 14 * 18] = [
    T,T,T,T,T,K,K,T,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,K,K,T,T,T,T,
    T,T,T,T,T,K,W,W,K,W,K,K,T,T,
    T,T,T,T,T,K,W,W,K,W,K,W,K,T,
    T,K,K,T,K,K,W,W,K,W,K,W,K,T,
    K,W,W,K,K,W,W,W,W,W,W,W,K,T,
    K,W,W,W,K,W,W,W,W,W,W,W,K,T,
    T,K,W,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,W,W,W,W,W,W,K,T,T,T,
    T,T,T,T,K,K,K,K,K,K,T,T,T,T,
    T,T,T,T,T,T,T,T,T,T,T,T,T,T,
];

pub static POINTER_GLYPH: CursorGlyph = CursorGlyph {
    width: 14,
    height: 18,
    hot_x: 5,
    hot_y: 0,
    pixels: &POINTER_PIXELS,
};

/// Text I-beam — 7 wide, 16 tall. Hot-spot (3, 8) at the center.
#[rustfmt::skip]
static TEXT_PIXELS: [u32; 7 * 16] = [
    K,K,K,T,K,K,K,
    T,K,W,K,W,K,T,
    T,T,K,W,K,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,T,W,T,T,T,
    T,T,K,W,K,T,T,
    T,K,W,K,W,K,T,
    K,K,K,T,K,K,K,
];

pub static TEXT_GLYPH: CursorGlyph = CursorGlyph {
    width: 7,
    height: 16,
    hot_x: 3,
    hot_y: 8,
    pixels: &TEXT_PIXELS,
};

/// Wait hourglass — 14 wide, 16 tall. Hot-spot (7, 8) at center.
#[rustfmt::skip]
static WAIT_PIXELS: [u32; 14 * 16] = [
    K,K,K,K,K,K,K,K,K,K,K,K,K,K,
    K,W,W,W,W,W,W,W,W,W,W,W,W,K,
    T,K,W,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,W,W,W,W,W,W,K,T,T,T,
    T,T,T,T,K,W,W,W,W,K,T,T,T,T,
    T,T,T,T,T,K,W,W,K,T,T,T,T,T,
    T,T,T,T,T,T,K,K,T,T,T,T,T,T,
    T,T,T,T,T,T,K,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,W,K,T,T,T,T,T,
    T,T,T,T,K,W,W,W,W,K,T,T,T,T,
    T,T,T,K,W,W,W,W,W,W,K,T,T,T,
    T,T,K,W,W,W,W,W,W,W,W,K,T,T,
    T,K,W,W,W,W,W,W,W,W,W,W,K,T,
    K,W,W,W,W,W,W,W,W,W,W,W,W,K,
    K,K,K,K,K,K,K,K,K,K,K,K,K,K,
];

pub static WAIT_GLYPH: CursorGlyph = CursorGlyph {
    width: 14,
    height: 16,
    hot_x: 7,
    hot_y: 8,
    pixels: &WAIT_PIXELS,
};

/// Move four-arrow cross — 16 wide, 16 tall. Hot-spot (8, 8) at center.
#[rustfmt::skip]
static MOVE_PIXELS: [u32; 16 * 16] = [
    T,T,T,T,T,T,T,K,K,T,T,T,T,T,T,T,
    T,T,T,T,T,T,K,W,W,K,T,T,T,T,T,T,
    T,T,T,T,T,K,W,W,W,W,K,T,T,T,T,T,
    T,T,T,T,K,W,W,W,W,W,W,K,T,T,T,T,
    T,T,T,T,K,K,K,W,W,K,K,K,T,T,T,T,
    T,T,T,T,T,T,K,W,W,K,T,T,T,T,T,T,
    T,T,K,K,K,K,K,W,W,K,K,K,K,K,T,T,
    T,K,W,W,W,W,W,W,W,W,W,W,W,W,K,T,
    T,K,W,W,W,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,K,K,K,K,W,W,K,K,K,K,K,T,T,
    T,T,T,T,T,T,K,W,W,K,T,T,T,T,T,T,
    T,T,T,T,K,K,K,W,W,K,K,K,T,T,T,T,
    T,T,T,T,K,W,W,W,W,W,W,K,T,T,T,T,
    T,T,T,T,T,K,W,W,W,W,K,T,T,T,T,T,
    T,T,T,T,T,T,K,W,W,K,T,T,T,T,T,T,
    T,T,T,T,T,T,T,K,K,T,T,T,T,T,T,T,
];

pub static MOVE_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 16,
    hot_x: 8,
    hot_y: 8,
    pixels: &MOVE_PIXELS,
};

/// Vertical double-arrow — 8 wide, 16 tall. Hot-spot (4, 8) at center.
#[rustfmt::skip]
static RESIZE_NS_PIXELS: [u32; 8 * 16] = [
    T,T,T,K,K,T,T,T,
    T,T,K,W,W,K,T,T,
    T,K,W,W,W,W,K,T,
    K,W,W,W,W,W,W,K,
    K,K,K,W,W,K,K,K,
    T,T,K,W,W,K,T,T,
    T,T,K,W,W,K,T,T,
    T,T,K,W,W,K,T,T,
    T,T,K,W,W,K,T,T,
    T,T,K,W,W,K,T,T,
    T,T,K,W,W,K,T,T,
    K,K,K,W,W,K,K,K,
    K,W,W,W,W,W,W,K,
    T,K,W,W,W,W,K,T,
    T,T,K,W,W,K,T,T,
    T,T,T,K,K,T,T,T,
];

pub static RESIZE_NS_GLYPH: CursorGlyph = CursorGlyph {
    width: 8,
    height: 16,
    hot_x: 4,
    hot_y: 8,
    pixels: &RESIZE_NS_PIXELS,
};

/// Horizontal double-arrow — 16 wide, 8 tall. Hot-spot (8, 4) at center.
#[rustfmt::skip]
static RESIZE_EW_PIXELS: [u32; 16 * 8] = [
    T,T,T,K,T,T,T,T,T,T,T,T,K,T,T,T,
    T,T,K,K,T,T,T,T,T,T,T,T,K,K,T,T,
    T,K,W,K,K,K,K,K,K,K,K,K,K,W,K,T,
    K,W,W,W,W,W,W,W,W,W,W,W,W,W,W,K,
    K,W,W,W,W,W,W,W,W,W,W,W,W,W,W,K,
    T,K,W,K,K,K,K,K,K,K,K,K,K,W,K,T,
    T,T,K,K,T,T,T,T,T,T,T,T,K,K,T,T,
    T,T,T,K,T,T,T,T,T,T,T,T,K,T,T,T,
];

pub static RESIZE_EW_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 8,
    hot_x: 8,
    hot_y: 4,
    pixels: &RESIZE_EW_PIXELS,
};

/// "Not allowed" circle-slash — 16 wide, 16 tall. Hot-spot (8, 8).
#[rustfmt::skip]
static NOT_ALLOWED_PIXELS: [u32; 16 * 16] = [
    T,T,T,T,T,K,K,K,K,K,K,T,T,T,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,K,W,W,W,W,W,W,W,K,K,K,K,T,T,
    T,K,W,W,W,W,W,W,W,K,K,W,W,K,K,T,
    T,K,W,W,W,W,W,W,K,K,W,W,W,W,K,T,
    K,W,W,W,W,W,W,K,K,W,W,W,W,W,W,K,
    K,W,W,W,W,W,K,K,W,W,W,W,W,W,W,K,
    K,W,W,W,W,K,K,W,W,W,W,W,W,W,W,K,
    K,W,W,W,W,K,W,W,W,W,W,W,W,W,W,K,
    K,W,W,W,K,K,W,W,W,W,W,W,W,W,W,K,
    K,W,W,K,K,W,W,W,W,W,W,W,W,W,W,K,
    T,K,W,K,W,W,W,W,W,W,W,W,W,W,K,T,
    T,K,K,W,W,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,K,W,W,W,W,W,W,W,W,K,K,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,T,T,T,K,K,K,K,K,K,T,T,T,T,T,
];

pub static NOT_ALLOWED_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 16,
    hot_x: 8,
    hot_y: 8,
    pixels: &NOT_ALLOWED_PIXELS,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Map a logical cursor shape to its static bitmap.
pub fn glyph_for(shape: CursorShape) -> &'static CursorGlyph {
    match shape {
        CursorShape::Default => &DEFAULT_GLYPH,
        CursorShape::Pointer => &POINTER_GLYPH,
        CursorShape::Text => &TEXT_GLYPH,
        CursorShape::Wait => &WAIT_GLYPH,
        CursorShape::Move => &MOVE_GLYPH,
        CursorShape::ResizeNS => &RESIZE_NS_GLYPH,
        CursorShape::ResizeEW => &RESIZE_EW_GLYPH,
        CursorShape::NotAllowed => &NOT_ALLOWED_GLYPH,
    }
}

/// Draw `shape` at framebuffer position `(x, y)`, where `(x, y)` is the
/// hot-spot (the logical pointer location).
///
/// Transparent pixels (`0`) are skipped. Opaque pixels are written via
/// direct volatile stores to the framebuffer, matching the style used
/// by `Framebuffer::draw_text` — a single bounds check per pixel and
/// no redundant function-call overhead.
pub fn draw(fb: &Framebuffer, x: i32, y: i32, shape: CursorShape) {
    if fb.addr == 0 {
        return;
    }

    let glyph = glyph_for(shape);
    let origin_x = x - glyph.hot_x as i32;
    let origin_y = y - glyph.hot_y as i32;
    let pixels_per_row = fb.pitch / 4;
    let dst = fb.addr as *mut u32;
    let fb_w = fb.width as i32;
    let fb_h = fb.height as i32;

    for row in 0..glyph.height {
        let py = origin_y + row as i32;
        if py < 0 || py >= fb_h {
            continue;
        }
        let row_base = row * glyph.width;
        let dst_row = py as u32 * pixels_per_row;
        for col in 0..glyph.width {
            let pixel = glyph.pixels[row_base + col];
            if pixel == 0 {
                continue;
            }
            let px = origin_x + col as i32;
            if px < 0 || px >= fb_w {
                continue;
            }
            unsafe {
                let offset = (dst_row + px as u32) as isize;
                dst.offset(offset).write_volatile(pixel);
            }
        }
    }
}
