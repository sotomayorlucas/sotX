//! Compositor wallpaper / desktop background.
//!
//! Replaces the old single-color clear with a vertical Tokyo Night
//! gradient. The gradient is computed once into a static cache; the
//! compose loop just blits cached rows. Optional BMP image support is
//! exposed via `set_image()`.

use crate::render::Framebuffer;
use sotos_common::SyncUnsafeCell;

/// Tokyo Night background top color (BGRA: 26, 27, 38).
pub const BG_TOP: u32 = 0xFF1A1B26;

/// Tokyo Night background bottom color (BGRA: 16, 16, 28).
pub const BG_BOT: u32 = 0xFF10101C;

/// Maximum supported framebuffer height (4K headroom).
pub const MAX_GRADIENT_HEIGHT: usize = 2160;

/// Wallpaper state: gradient cache + optional override image.
pub struct Wallpaper {
    /// One BGRA color per row.
    gradient_cache: [u32; MAX_GRADIENT_HEIGHT],
    /// Number of valid rows in `gradient_cache`.
    gradient_height: usize,
    /// Optional override image (BGRA u32 pixels).
    image: Option<&'static [u32]>,
    image_width: usize,
    image_height: usize,
}

impl Wallpaper {
    pub const fn empty() -> Self {
        Self {
            gradient_cache: [0u32; MAX_GRADIENT_HEIGHT],
            gradient_height: 0,
            image: None,
            image_width: 0,
            image_height: 0,
        }
    }
}

/// Global wallpaper instance.
static WALLPAPER: SyncUnsafeCell<Wallpaper> = SyncUnsafeCell::new(Wallpaper::empty());

/// Extract the (a, r, g, b) channels from a BGRA u32.
/// Layout: bits 24..31 = A, 16..23 = R, 8..15 = G, 0..7 = B.
#[inline]
fn channels(c: u32) -> (u32, u32, u32, u32) {
    (
        (c >> 24) & 0xFF,
        (c >> 16) & 0xFF,
        (c >> 8) & 0xFF,
        c & 0xFF,
    )
}

/// Pack (a, r, g, b) channels into a BGRA u32.
#[inline]
fn pack(a: u32, r: u32, g: u32, b: u32) -> u32 {
    ((a & 0xFF) << 24) | ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF)
}

/// Linearly blend `top` and `bot` channel-wise. `num/den` is the
/// fractional position from top (0/den = top, den/den = bot).
#[inline]
fn blend(top: u32, bot: u32, num: u32, den: u32) -> u32 {
    let (_, tr, tg, tb) = channels(top);
    let (_, br, bg, bb) = channels(bot);
    let inv = den - num;
    let r = (tr * inv + br * num) / den;
    let g = (tg * inv + bg * num) / den;
    let b = (tb * inv + bb * num) / den;
    pack(0xFF, r, g, b)
}

/// Compute the gradient cache for `height` rows. Linear interpolation
/// from BG_TOP (row 0) to BG_BOT (row height-1).
pub fn init(height: usize) {
    let h = height.min(MAX_GRADIENT_HEIGHT);
    let wp = unsafe { &mut *WALLPAPER.get() };
    wp.gradient_height = h;
    wp.image = None;
    wp.image_width = 0;
    wp.image_height = 0;

    if h == 0 {
        return;
    }
    if h == 1 {
        wp.gradient_cache[0] = BG_TOP;
        return;
    }

    let den = (h - 1) as u32;
    for i in 0..h {
        wp.gradient_cache[i] = blend(BG_TOP, BG_BOT, i as u32, den);
    }
}

/// Override the wallpaper with a static image. The image must already
/// be in BGRA u32 format and live for the lifetime of the compositor.
#[allow(dead_code)]
pub fn set_image(pixels: &'static [u32], width: usize, height: usize) {
    let wp = unsafe { &mut *WALLPAPER.get() };
    wp.image = Some(pixels);
    wp.image_width = width;
    wp.image_height = height;
}

/// Draw the wallpaper to the framebuffer over the rect (x, y, w, h).
/// Compatible with the damage-rectangle workflow: only the requested
/// region is drawn.
pub fn draw(fb: &mut Framebuffer, x: i32, y: i32, w: i32, h: i32) {
    if fb.addr == 0 || w <= 0 || h <= 0 {
        return;
    }
    let wp = unsafe { &*WALLPAPER.get() };

    if let Some(img) = wp.image {
        let iw = wp.image_width as i32;
        let ih = wp.image_height as i32;
        if iw <= 0 || ih <= 0 {
            return;
        }
        // Tile the image starting at fb origin (0, 0). Drawn as 1x1
        // fills so out-of-rect pixels are clipped by `fill_rect`.
        for py in y..(y + h) {
            let sy = py.rem_euclid(ih);
            let row_off = (sy as usize) * (iw as usize);
            for px in x..(x + w) {
                let sx = px.rem_euclid(iw);
                let src_idx = row_off + sx as usize;
                if src_idx >= img.len() {
                    continue;
                }
                fb.fill_rect(px, py, 1, 1, img[src_idx]);
            }
        }
        return;
    }

    // Gradient path: one cached color per row, drawn as a horizontal
    // span. `fill_rect` does the framebuffer-edge clipping for us.
    let cache_h = wp.gradient_height;
    if cache_h == 0 {
        return;
    }
    for py in y..(y + h) {
        if py < 0 {
            continue;
        }
        let row = (py as usize).min(cache_h - 1);
        fb.fill_rect(x, py, w as u32, 1, wp.gradient_cache[row]);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn read_cache(idx: usize) -> u32 {
        unsafe { (*WALLPAPER.get()).gradient_cache[idx] }
    }

    fn read_height() -> usize {
        unsafe { (*WALLPAPER.get()).gradient_height }
    }

    #[test]
    fn gradient_endpoints_match() {
        let h = 1080;
        init(h);
        assert_eq!(read_height(), h);
        assert_eq!(read_cache(0), BG_TOP);
        assert_eq!(read_cache(h - 1), BG_BOT);
    }

    #[test]
    fn gradient_single_row_uses_top() {
        init(1);
        assert_eq!(read_cache(0), BG_TOP);
    }

    #[test]
    fn gradient_clamps_to_max_height() {
        init(MAX_GRADIENT_HEIGHT + 500);
        assert_eq!(read_height(), MAX_GRADIENT_HEIGHT);
        assert_eq!(read_cache(0), BG_TOP);
        assert_eq!(read_cache(MAX_GRADIENT_HEIGHT - 1), BG_BOT);
    }
}
