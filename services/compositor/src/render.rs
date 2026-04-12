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
    pub fn draw_title_bar(&mut self, x: i32, y: i32, w: u32, title: &[u8], focused: bool) {
        // Strip trailing NUL bytes before UTF-8 conversion.
        let mut end = title.len();
        while end > 0 && title[end - 1] == 0 { end -= 1; }
        let title_str = core::str::from_utf8(&title[..end]).unwrap_or("");
        crate::decorations::draw_title_bar(self, x, y, w as i32, focused, title_str);
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
}

// The old inline 8x8 bitmap font has been replaced by `embedded-graphics`'
// mono fonts. See `crate::font` for the new `draw_text` implementation.
