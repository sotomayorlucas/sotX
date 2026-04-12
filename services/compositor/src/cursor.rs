//! Multi-shape cursor theme for the compositor.
//!
//! Each glyph is a hand-crafted static BGRA bitmap. `0` is treated as a
//! fully transparent pixel; opaque pixels are written straight to the
//! framebuffer by [`draw`]. Glyphs stay under 24x24 so the whole theme
//! fits comfortably in `.rodata` with no heap allocation.
//!
//! The compose loop picks a shape from hover state and passes it (with
//! the current animation frame for `Wait`) to [`draw`]. Glyphs are looked
//! up through [`glyph_for`], which returns a `&'static CursorGlyph`.

use crate::render::Framebuffer;

/// Logical cursor shape requested by the compositor.
///
/// Hover detection in `main.rs` maps pointer position + window geometry
/// to one of these variants and stores it in `CURRENT_SHAPE`. Every
/// frame the compose loop reads the static and calls [`draw`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorShape {
    /// Classic top-left arrow — default everywhere no other shape wins.
    Default,
    /// Pointing hand — shown over clickable chrome (traffic lights, title).
    Pointer,
    /// Text I-beam — shown over a toplevel's client area.
    IBeam,
    /// Busy indicator — 4-frame spinning circle. Reserved for future
    /// long-running operations; no hover path selects it today.
    #[allow(dead_code)]
    Wait,
    /// Resize from the top edge (vertical ↕).
    ResizeN,
    /// Resize from the bottom edge (vertical ↕).
    ResizeS,
    /// Resize from the right edge (horizontal ↔).
    ResizeE,
    /// Resize from the left edge (horizontal ↔).
    ResizeW,
    /// Resize from the top-right corner (diagonal ⤡).
    ResizeNE,
    /// Resize from the top-left corner (diagonal ⤢).
    ResizeNW,
    /// Resize from the bottom-right corner (diagonal ⤢).
    ResizeSE,
    /// Resize from the bottom-left corner (diagonal ⤡).
    ResizeSW,
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
// Color palette used by every glyph.
// ---------------------------------------------------------------------------

const T: u32 = 0x00000000; // transparent
const K: u32 = 0xFF000000; // opaque black (outline)
const W: u32 = 0xFFFFFFFF; // opaque white (fill)

// ---------------------------------------------------------------------------
// Glyph bitmaps
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
static IBEAM_PIXELS: [u32; 7 * 16] = [
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

pub static IBEAM_GLYPH: CursorGlyph = CursorGlyph {
    width: 7,
    height: 16,
    hot_x: 3,
    hot_y: 8,
    pixels: &IBEAM_PIXELS,
};

// ---------------------------------------------------------------------------
// Wait spinner: 4 frames of a rotating quadrant marker inside a ring.
// Frame N lights up the quadrant clockwise from 12 o'clock; the rest of
// the ring stays outlined. 16×16 with hotspot at center.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
static WAIT_FRAME_0: [u32; 16 * 16] = [
    T,T,T,T,T,K,K,W,W,K,K,T,T,T,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,K,W,W,W,W,W,W,W,W,W,W,K,T,T,
    T,K,W,W,W,T,T,T,T,T,T,W,W,W,K,T,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    T,K,W,W,W,T,T,T,T,T,T,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
];

#[rustfmt::skip]
static WAIT_FRAME_1: [u32; 16 * 16] = [
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
    T,T,T,K,K,W,W,T,T,W,W,K,K,T,T,T,
    T,T,K,W,W,W,W,T,T,W,W,W,W,K,T,T,
    T,K,W,W,W,T,T,T,T,T,T,W,W,W,K,T,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    T,K,W,W,W,W,W,T,T,W,W,W,W,W,K,T,
    T,T,K,W,W,W,W,T,T,W,W,W,W,K,T,T,
    T,T,T,K,K,W,W,T,T,W,W,K,K,T,T,T,
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
];

#[rustfmt::skip]
static WAIT_FRAME_2: [u32; 16 * 16] = [
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
    T,T,T,K,K,T,T,T,T,W,W,K,K,T,T,T,
    T,T,K,W,W,T,T,T,T,W,W,W,W,K,T,T,
    T,K,W,W,W,T,T,T,T,T,T,W,W,W,K,T,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    T,K,W,W,W,W,W,W,W,W,W,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,T,T,T,K,K,W,W,K,K,T,T,T,T,T,
];

#[rustfmt::skip]
static WAIT_FRAME_3: [u32; 16 * 16] = [
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
    T,T,T,K,K,T,T,T,T,T,T,K,K,T,T,T,
    T,T,K,W,W,T,T,T,T,T,T,W,W,K,T,T,
    T,K,W,W,W,T,T,T,T,T,T,W,W,W,K,T,
    T,K,W,W,T,T,T,T,T,T,T,T,W,W,K,T,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,T,T,T,T,T,T,T,T,T,T,T,T,W,K,
    K,W,W,T,T,T,T,T,T,T,T,T,T,W,W,K,
    K,W,W,W,W,W,W,W,W,T,T,T,T,W,W,K,
    T,K,W,W,W,W,W,W,W,T,T,T,W,W,K,T,
    T,K,W,W,W,W,W,W,W,T,T,W,W,W,K,T,
    T,T,K,W,W,W,W,W,W,W,W,W,W,K,T,T,
    T,T,T,K,K,W,W,W,W,W,W,K,K,T,T,T,
    T,T,T,T,T,K,K,T,T,K,K,T,T,T,T,T,
];

pub static WAIT_GLYPHS: [CursorGlyph; 4] = [
    CursorGlyph { width: 16, height: 16, hot_x: 8, hot_y: 8, pixels: &WAIT_FRAME_0 },
    CursorGlyph { width: 16, height: 16, hot_x: 8, hot_y: 8, pixels: &WAIT_FRAME_1 },
    CursorGlyph { width: 16, height: 16, hot_x: 8, hot_y: 8, pixels: &WAIT_FRAME_2 },
    CursorGlyph { width: 16, height: 16, hot_x: 8, hot_y: 8, pixels: &WAIT_FRAME_3 },
];

// ---------------------------------------------------------------------------
// Resize cursors — directional double-arrows
// ---------------------------------------------------------------------------

/// Vertical double-arrow (N/S) — 8 wide, 16 tall. Hot-spot (4, 8).
#[rustfmt::skip]
static RESIZE_VERT_PIXELS: [u32; 8 * 16] = [
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

pub static RESIZE_VERT_GLYPH: CursorGlyph = CursorGlyph {
    width: 8,
    height: 16,
    hot_x: 4,
    hot_y: 8,
    pixels: &RESIZE_VERT_PIXELS,
};

/// Horizontal double-arrow (E/W) — 16 wide, 8 tall. Hot-spot (8, 4).
#[rustfmt::skip]
static RESIZE_HORZ_PIXELS: [u32; 16 * 8] = [
    T,T,T,K,T,T,T,T,T,T,T,T,K,T,T,T,
    T,T,K,K,T,T,T,T,T,T,T,T,K,K,T,T,
    T,K,W,K,K,K,K,K,K,K,K,K,K,W,K,T,
    K,W,W,W,W,W,W,W,W,W,W,W,W,W,W,K,
    K,W,W,W,W,W,W,W,W,W,W,W,W,W,W,K,
    T,K,W,K,K,K,K,K,K,K,K,K,K,W,K,T,
    T,T,K,K,T,T,T,T,T,T,T,T,K,K,T,T,
    T,T,T,K,T,T,T,T,T,T,T,T,K,T,T,T,
];

pub static RESIZE_HORZ_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 8,
    hot_x: 8,
    hot_y: 4,
    pixels: &RESIZE_HORZ_PIXELS,
};

/// Diagonal ＼ double-arrow (NW-SE) — 16 wide, 16 tall. Hot-spot (8, 8).
#[rustfmt::skip]
static RESIZE_DIAG_NWSE_PIXELS: [u32; 16 * 16] = [
    K,K,K,K,K,T,T,T,T,T,T,T,T,T,T,T,
    K,W,W,W,K,T,T,T,T,T,T,T,T,T,T,T,
    K,W,W,K,T,T,T,T,T,T,T,T,T,T,T,T,
    K,W,K,W,K,T,T,T,T,T,T,T,T,T,T,T,
    K,K,T,K,W,K,T,T,T,T,T,T,T,T,T,T,
    T,T,T,T,K,W,K,T,T,T,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,T,T,
    T,T,T,T,T,T,K,W,K,T,T,T,T,T,T,T,
    T,T,T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,T,T,T,K,W,K,T,T,T,T,T,
    T,T,T,T,T,T,T,T,T,K,W,K,T,T,T,T,
    T,T,T,T,T,T,T,T,T,T,K,W,K,T,T,K,
    T,T,T,T,T,T,T,T,T,T,T,K,W,K,T,K,
    T,T,T,T,T,T,T,T,T,T,T,T,K,W,K,K,
    T,T,T,T,T,T,T,T,T,T,T,K,W,W,W,K,
    T,T,T,T,T,T,T,T,T,T,T,K,K,K,K,K,
];

pub static RESIZE_DIAG_NWSE_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 16,
    hot_x: 8,
    hot_y: 8,
    pixels: &RESIZE_DIAG_NWSE_PIXELS,
};

/// Diagonal ／ double-arrow (NE-SW) — 16 wide, 16 tall. Hot-spot (8, 8).
#[rustfmt::skip]
static RESIZE_DIAG_NESW_PIXELS: [u32; 16 * 16] = [
    T,T,T,T,T,T,T,T,T,T,T,K,K,K,K,K,
    T,T,T,T,T,T,T,T,T,T,T,K,W,W,W,K,
    T,T,T,T,T,T,T,T,T,T,T,T,K,W,W,K,
    T,T,T,T,T,T,T,T,T,T,T,K,W,K,W,K,
    T,T,T,T,T,T,T,T,T,T,K,W,K,T,K,K,
    T,T,T,T,T,T,T,T,T,K,W,K,T,T,T,T,
    T,T,T,T,T,T,T,T,K,W,K,T,T,T,T,T,
    T,T,T,T,T,T,T,K,W,K,T,T,T,T,T,T,
    T,T,T,T,T,T,K,W,K,T,T,T,T,T,T,T,
    T,T,T,T,T,K,W,K,T,T,T,T,T,T,T,T,
    T,T,T,T,K,W,K,T,T,T,T,T,T,T,T,T,
    K,T,T,K,W,K,T,T,T,T,T,T,T,T,T,T,
    K,T,K,W,K,T,T,T,T,T,T,T,T,T,T,T,
    K,K,W,K,T,T,T,T,T,T,T,T,T,T,T,T,
    K,W,W,W,K,T,T,T,T,T,T,T,T,T,T,T,
    K,K,K,K,K,T,T,T,T,T,T,T,T,T,T,T,
];

pub static RESIZE_DIAG_NESW_GLYPH: CursorGlyph = CursorGlyph {
    width: 16,
    height: 16,
    hot_x: 8,
    hot_y: 8,
    pixels: &RESIZE_DIAG_NESW_PIXELS,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Map a logical cursor shape + animation frame to its static bitmap.
///
/// `frame` is only consulted for [`CursorShape::Wait`]; it is masked into
/// the four available wait frames. All other shapes ignore `frame`.
pub fn glyph_for(shape: CursorShape, frame: u8) -> &'static CursorGlyph {
    match shape {
        CursorShape::Default => &DEFAULT_GLYPH,
        CursorShape::Pointer => &POINTER_GLYPH,
        CursorShape::IBeam => &IBEAM_GLYPH,
        CursorShape::Wait => &WAIT_GLYPHS[(frame & 0x03) as usize],
        // N/S share the vertical double-arrow, E/W the horizontal one.
        CursorShape::ResizeN | CursorShape::ResizeS => &RESIZE_VERT_GLYPH,
        CursorShape::ResizeE | CursorShape::ResizeW => &RESIZE_HORZ_GLYPH,
        // NW-SE corner arrow serves both NW and SE, NE-SW serves both NE and SW.
        CursorShape::ResizeNW | CursorShape::ResizeSE => &RESIZE_DIAG_NWSE_GLYPH,
        CursorShape::ResizeNE | CursorShape::ResizeSW => &RESIZE_DIAG_NESW_GLYPH,
    }
}

/// Draw `shape` at framebuffer position `(x, y)`, where `(x, y)` is the
/// hot-spot (the logical pointer location).
///
/// `frame` animates [`CursorShape::Wait`]; pass `0` for every non-animated
/// shape. Transparent pixels (`0`) are skipped. Opaque pixels are written
/// via direct volatile stores — a single bounds check per pixel and no
/// redundant function-call overhead.
pub fn draw(fb: &Framebuffer, x: i32, y: i32, shape: CursorShape, frame: u8) {
    if fb.addr == 0 {
        return;
    }

    let glyph = glyph_for(shape, frame);
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
