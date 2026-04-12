//! Framebuffer rendering — blits client buffers to the display.
//!
//! Operates directly on raw BGRA pixel data in the framebuffer.

/// Framebuffer state.
pub struct Framebuffer {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

impl Framebuffer {
    pub const fn empty() -> Self {
        Self { addr: 0, width: 0, height: 0, pitch: 0, bpp: 0 }
    }

    /// Fill the entire framebuffer with a solid color (BGRA).
    pub fn clear(&self, color: u32) {
        if self.addr == 0 { return; }
        let pixels_per_row = self.pitch / 4;
        let fb = self.addr as *mut u32;
        for y in 0..self.height {
            for x in 0..self.width {
                unsafe {
                    let offset = (y * pixels_per_row + x) as isize;
                    fb.offset(offset).write_volatile(color);
                }
            }
        }
    }

    /// Fill a rectangle with a solid color.
    pub fn fill_rect(&self, x: i32, y: i32, w: u32, h: u32, color: u32) {
        if self.addr == 0 { return; }
        let pixels_per_row = self.pitch / 4;
        let fb = self.addr as *mut u32;
        for dy in 0..h as i32 {
            let py = y + dy;
            if py < 0 || py >= self.height as i32 { continue; }
            for dx in 0..w as i32 {
                let px = x + dx;
                if px < 0 || px >= self.width as i32 { continue; }
                unsafe {
                    let offset = (py as u32 * pixels_per_row + px as u32) as isize;
                    fb.offset(offset).write_volatile(color);
                }
            }
        }
    }

    /// Blit a client XRGB8888/ARGB8888 buffer to the framebuffer at (x, y).
    /// `src`: pointer to pixel data, `src_stride`: bytes per row.
    pub fn blit(&self, x: i32, y: i32, w: u32, h: u32, src: *const u32, src_stride: u32) {
        if self.addr == 0 || src.is_null() { return; }
        let pixels_per_row = self.pitch / 4;
        let src_pixels_per_row = src_stride / 4;
        let fb = self.addr as *mut u32;

        for dy in 0..h as i32 {
            let py = y + dy;
            if py < 0 || py >= self.height as i32 { continue; }
            for dx in 0..w as i32 {
                let px = x + dx;
                if px < 0 || px >= self.width as i32 { continue; }
                let src_offset = (dy as u32 * src_pixels_per_row + dx as u32) as isize;
                let dst_offset = (py as u32 * pixels_per_row + px as u32) as isize;
                unsafe {
                    let pixel = src.offset(src_offset).read_volatile();
                    fb.offset(dst_offset).write_volatile(pixel);
                }
            }
        }
    }

    /// Draw a title bar for a window.
    ///
    /// Thin forwarder to `crate::decorations::draw_title_bar`, which owns all
    /// the Tokyo Night-styled chrome (traffic lights, rounded corners).
    /// Kept on `Framebuffer` for backwards compatibility with older callers.
    pub fn draw_title_bar(&mut self, x: i32, y: i32, w: u32, title: &[u8]) {
        let title_str = core::str::from_utf8(title).unwrap_or("");
        crate::decorations::draw_title_bar(self, x, y, w as i32, true, title_str);
    }

    /// Draw text at `(x, y)` using the compact `FONT_6X10` font.
    ///
    /// This is a backwards-compatible wrapper that accepts a byte slice
    /// (the old 8x8 bitmap font API). For new code, call
    /// [`crate::font::draw_text`] directly with an explicit size.
    pub fn draw_text(&self, x: i32, y: i32, text: &[u8], color: u32) {
        let s = core::str::from_utf8(text).unwrap_or("");
        crate::font::draw_text(self, x, y, s, color, false);
    }

    /// Draw the default arrow cursor at (x, y).
    ///
    /// Thin forwarder to [`crate::cursor::draw`] with the `Default`
    /// shape; kept on `Framebuffer` for compatibility with existing
    /// call sites. Multi-shape rendering lives in `crate::cursor`.
    pub fn draw_cursor(&self, x: i32, y: i32) {
        crate::cursor::draw(self, x, y, crate::cursor::CursorShape::Default);
    }

    /// Blit a client buffer with alpha blending and nearest-neighbor scaling.
    ///
    /// `alpha`: 0 = fully transparent, 255 = fully opaque.
    /// `scale`: 1.0 = original size. The source is sampled at `1/scale`
    /// coordinates (nearest-neighbor) and drawn centered within the
    /// original (x, y, w, h) rect.
    pub fn blit_scaled_alpha(
        &self,
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        src: *const u32,
        src_stride: u32,
        alpha: u8,
        scale: f32,
    ) {
        if self.addr == 0 || src.is_null() || alpha == 0 { return; }

        if alpha == 255 && scale >= 0.999 {
            self.blit(x, y, w, h, src, src_stride);
            return;
        }

        let pixels_per_row = self.pitch / 4;
        let src_pixels_per_row = src_stride / 4;
        let fb = self.addr as *mut u32;

        let sw = (w as f32 * scale) as u32;
        let sh = (h as f32 * scale) as u32;
        if sw == 0 || sh == 0 { return; }

        let off_x = ((w as i32) - (sw as i32)) / 2;
        let off_y = ((h as i32) - (sh as i32)) / 2;
        let inv_scale = 1.0 / scale;

        for dy in 0..sh as i32 {
            let py = y + off_y + dy;
            if py < 0 || py >= self.height as i32 { continue; }
            let src_y = ((dy as f32) * inv_scale) as u32;
            if src_y >= h { continue; }

            for dx in 0..sw as i32 {
                let px = x + off_x + dx;
                if px < 0 || px >= self.width as i32 { continue; }

                let src_x = ((dx as f32) * inv_scale) as u32;
                if src_x >= w { continue; }

                let src_offset = (src_y * src_pixels_per_row + src_x) as isize;
                let dst_offset = (py as u32 * pixels_per_row + px as u32) as isize;

                unsafe {
                    let sp = src.offset(src_offset).read_volatile();
                    if alpha == 255 {
                        fb.offset(dst_offset).write_volatile(sp);
                    } else {
                        let dp = fb.offset(dst_offset).read_volatile();
                        fb.offset(dst_offset)
                            .write_volatile(alpha_blend(sp, dp, alpha));
                    }
                }
            }
        }
    }

    /// Fill a rectangle with a solid color and alpha blending.
    pub fn fill_rect_alpha(&self, x: i32, y: i32, w: u32, h: u32, color: u32, alpha: u8) {
        if self.addr == 0 || alpha == 0 { return; }
        if alpha == 255 {
            self.fill_rect(x, y, w, h, color);
            return;
        }
        let pixels_per_row = self.pitch / 4;
        let fb = self.addr as *mut u32;
        for dy in 0..h as i32 {
            let py = y + dy;
            if py < 0 || py >= self.height as i32 { continue; }
            for dx in 0..w as i32 {
                let px = x + dx;
                if px < 0 || px >= self.width as i32 { continue; }
                unsafe {
                    let offset = (py as u32 * pixels_per_row + px as u32) as isize;
                    let dp = fb.offset(offset).read_volatile();
                    fb.offset(offset)
                        .write_volatile(alpha_blend(color, dp, alpha));
                }
            }
        }
    }
}

/// Blend two BGRA pixels: `out = (src * alpha + dst * (255 - alpha)) / 255`.
/// Output alpha is forced to 0xFF.
#[inline(always)]
fn alpha_blend(src: u32, dst: u32, alpha: u8) -> u32 {
    let a = alpha as u32;
    let inv_a = 255 - a;
    let blend = |s: u32, d: u32| (s * a + d * inv_a) / 255;
    let b = blend(src & 0xFF, dst & 0xFF);
    let g = blend((src >> 8) & 0xFF, (dst >> 8) & 0xFF);
    let r = blend((src >> 16) & 0xFF, (dst >> 16) & 0xFF);
    0xFF000000 | (r << 16) | (g << 8) | b
}

// The old inline 8x8 bitmap font has been replaced by `embedded-graphics`'
// mono fonts. See `crate::font` for the new `draw_text` implementation.
