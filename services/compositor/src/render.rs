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

    /// Draw a simple title bar for a window.
    pub fn draw_title_bar(&self, x: i32, y: i32, w: u32, title: &[u8]) {
        const BAR_HEIGHT: u32 = 24;
        const BAR_COLOR: u32 = 0xFF404040; // dark gray
        const CLOSE_COLOR: u32 = 0xFFFF5555; // red
        const CLOSE_SIZE: u32 = 16;

        self.fill_rect(x, y, w, BAR_HEIGHT, BAR_COLOR);

        // Close button (top-right)
        let close_x = x + w as i32 - CLOSE_SIZE as i32 - 4;
        let close_y = y + 4;
        self.fill_rect(close_x, close_y, CLOSE_SIZE, CLOSE_SIZE, CLOSE_COLOR);

        // Title text — large font, centered vertically in the title bar.
        let text_x = x + 6;
        let text_y = y + ((BAR_HEIGHT as i32 - crate::font::TITLE_FONT_HEIGHT) / 2).max(0);
        let max_chars = ((w as i32 - (CLOSE_SIZE as i32 + 14)) / 10).max(0) as usize;
        let len = title.len().min(max_chars);
        let s = core::str::from_utf8(&title[..len]).unwrap_or("");
        crate::font::draw_text(self, text_x, text_y, s, 0xFFEEEEEE, true);
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

    /// Draw a mouse cursor at (x, y).
    pub fn draw_cursor(&self, x: i32, y: i32) {
        const CURSOR_COLOR: u32 = 0xFFFFFFFF; // white
        const CURSOR_SIZE: i32 = 12;
        // Simple arrow cursor
        for i in 0..CURSOR_SIZE {
            for j in 0..=i {
                self.fill_rect(x + j, y + i, 1, 1, CURSOR_COLOR);
            }
        }
    }
}

// The old inline 8x8 bitmap font has been replaced by `embedded-graphics`'
// mono fonts. See `crate::font` for the new `draw_text` implementation.
