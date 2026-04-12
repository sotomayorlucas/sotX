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

    /// Read back the pixel at `(px, py)` from the framebuffer.
    ///
    /// Returns 0 for out-of-bounds or null addresses.
    #[inline]
    pub fn read_pixel(&self, px: i32, py: i32) -> u32 {
        if self.addr == 0 { return 0; }
        if px < 0 || py < 0 { return 0; }
        if (px as u32) >= self.width || (py as u32) >= self.height { return 0; }
        let pixels_per_row = self.pitch / 4;
        let fb = self.addr as *const u32;
        unsafe {
            let offset = (py as u32 * pixels_per_row + px as u32) as isize;
            fb.offset(offset).read_volatile()
        }
    }

    /// Write a single pixel at `(px, py)`.
    #[inline]
    pub fn write_pixel(&self, px: i32, py: i32, color: u32) {
        if self.addr == 0 { return; }
        if px < 0 || py < 0 { return; }
        if (px as u32) >= self.width || (py as u32) >= self.height { return; }
        let pixels_per_row = self.pitch / 4;
        let fb = self.addr as *mut u32;
        unsafe {
            let offset = (py as u32 * pixels_per_row + px as u32) as isize;
            fb.offset(offset).write_volatile(color);
        }
    }

    /// Draw a soft drop-shadow behind a window rectangle.
    ///
    /// The shadow is rendered as a blurred rectangle offset from the window
    /// position by `(SHADOW_OFS_X, SHADOW_OFS_Y)` with a blur spread of
    /// `blur` pixels. Each shadow pixel is alpha-blended onto the existing
    /// framebuffer content using quadratic falloff:
    ///
    ///   `alpha = max(0, 1 - (d / r)^2)`
    ///
    /// where `d` is the distance from the pixel to the nearest edge of the
    /// inner rectangle (the window footprint shifted by the offset) and `r`
    /// is the blur radius. The shadow color is `TOKYO_NIGHT.shadow`
    /// (`0x55000000` -- semi-transparent black). Blending uses standard
    /// `dst = dst * (1 - a) + shadow * a`.
    pub fn draw_shadow(&self, x: i32, y: i32, w: u32, h: u32, blur: i32) {
        if self.addr == 0 || blur <= 0 { return; }

        const SHADOW_OFS_X: i32 = 4;
        const SHADOW_OFS_Y: i32 = 6;

        let shadow_color = crate::decorations::TOKYO_NIGHT.shadow;
        // Extract the shadow base alpha and RGB.
        let s_alpha_max = ((shadow_color >> 24) & 0xFF) as i32; // 0x55 = 85
        let s_r = ((shadow_color >> 16) & 0xFF) as i32;
        let s_g = ((shadow_color >> 8) & 0xFF) as i32;
        let s_b = (shadow_color & 0xFF) as i32;

        // Inner rectangle (the shadow source rect, offset from window).
        let ix0 = x + SHADOW_OFS_X;
        let iy0 = y + SHADOW_OFS_Y;
        let ix1 = ix0 + w as i32;
        let iy1 = iy0 + h as i32;

        // Outer rectangle (inner expanded by blur radius on all sides).
        let ox0 = ix0 - blur;
        let oy0 = iy0 - blur;
        let ox1 = ix1 + blur;
        let oy1 = iy1 + blur;

        let r_sq = blur * blur;
        let w_i32 = w as i32;
        let h_i32 = h as i32;

        for py in oy0..oy1 {
            if py < 0 || py >= self.height as i32 { continue; }

            // Per-row vertical distance component.
            let dy = if py < iy0 {
                iy0 - py
            } else if py >= iy1 {
                py - iy1 + 1
            } else {
                0
            };
            let dy_sq = dy * dy;
            if dy_sq >= r_sq { continue; }

            for px in ox0..ox1 {
                if px < 0 || px >= self.width as i32 { continue; }

                // Skip pixels covered by the window (overdrawn by title bar + body).
                if px >= x && px < x + w_i32 && py >= y && py < y + h_i32 {
                    continue;
                }

                let dx = if px < ix0 {
                    ix0 - px
                } else if px >= ix1 {
                    px - ix1 + 1
                } else {
                    0
                };

                let d_sq = dx * dx + dy_sq;
                if d_sq >= r_sq { continue; }

                // Quadratic falloff: alpha = max(0, 1 - (d/r)^2), scaled to 0..s_alpha_max.
                let a = s_alpha_max * (r_sq - d_sq) / r_sq;
                if a <= 0 { continue; }

                // Alpha-blend shadow onto destination.
                let dst = self.read_pixel(px, py);
                let d_r = ((dst >> 16) & 0xFF) as i32;
                let d_g = ((dst >> 8) & 0xFF) as i32;
                let d_b = (dst & 0xFF) as i32;

                let inv_a = 255 - a;
                let out_r = ((d_r * inv_a + s_r * a) / 255) & 0xFF;
                let out_g = ((d_g * inv_a + s_g * a) / 255) & 0xFF;
                let out_b = ((d_b * inv_a + s_b * a) / 255) & 0xFF;

                self.write_pixel(px, py, 0xFF00_0000 | (out_r << 16) as u32 | (out_g << 8) as u32 | out_b as u32);
            }
        }
    }
}

// The old inline 8x8 bitmap font has been replaced by `embedded-graphics`'
// mono fonts. See `crate::font` for the new `draw_text` implementation.
