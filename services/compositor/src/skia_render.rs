//! Path-based rendering backend using `tiny-skia`.
//!
//! # Purpose
//!
//! Used for compositor-drawn elements (window decorations, cursor outlines,
//! gradients, animations, rounded corners). Client SHM buffers still go
//! through the raw `Framebuffer::blit` in `render.rs` for performance —
//! this module is layered ALONGSIDE that path, not replacing it.
//!
//! # `alloc` requirement
//!
//! `tiny-skia` requires the `alloc` crate (it allocates `Pixmap` pixel
//! buffers on the heap). The compositor is `#![no_std]` and currently
//! does NOT provide a global allocator, so this module is gated behind
//! the `skia` Cargo feature and is COMPILED OUT by default.
//!
//! Enabling `--features skia` will fail to link until the compositor
//! pulls in an allocator (`extern crate alloc;` + a `#[global_allocator]`).
//! The compositor works without this module — it is purely additive.
//!
//! # Integration story (future PR)
//!
//! Once an allocator lands in the compositor, a follow-up change can
//! invoke the path renderer from `compose()` like this:
//!
//! ```ignore
//! #[cfg(feature = "skia")]
//! {
//!     if let Some(mut canvas) = skia_render::SkiaCanvas::new(w, h) {
//!         canvas.fill_rounded_rect(0.0, 0.0, w as f32, h as f32, 8.0, 0xFF2D2D3D);
//!         canvas.stroke_rounded_rect(0.0, 0.0, w as f32, h as f32, 8.0, 1.0, 0xFF505060);
//!         canvas.present(fb, x, y);
//!     }
//! }
//! ```
//!
//! Example use cases: G3 title-bar decorations with rounded corners,
//! cursor anti-aliased outlines, smooth gradient backgrounds, focus
//! glow effects, loading spinners.
//!
//! # Pixel format
//!
//! `tiny-skia` produces premultiplied RGBA8888. The sotOS framebuffer is
//! BGRA8888 (little-endian `u32`). `present()` performs the R/B channel
//! swap per-pixel during upload, and clips destination coordinates to
//! the framebuffer bounds.

#![cfg(feature = "skia")]

extern crate alloc;

use tiny_skia::{
    Color, FillRule, GradientStop, LinearGradient, Paint, PathBuilder, Pixmap, Point, Rect,
    SpreadMode, Stroke, Transform,
};

use crate::render::Framebuffer;

/// A path-rendering canvas backed by an owned `tiny-skia` `Pixmap`.
///
/// Create one per compositor-drawn element (or reuse by re-filling),
/// draw into it with the helper methods, then `present()` it onto
/// the framebuffer at the desired destination.
pub struct SkiaCanvas {
    pub pixmap: Pixmap,
}

impl SkiaCanvas {
    /// Allocate a new canvas of the given size. Returns `None` if the
    /// dimensions are zero or allocation fails.
    pub fn new(width: u32, height: u32) -> Option<Self> {
        Pixmap::new(width, height).map(|pixmap| Self { pixmap })
    }

    /// Clear the entire canvas to fully transparent.
    pub fn clear(&mut self) {
        self.pixmap.fill(Color::TRANSPARENT);
    }

    /// Fill a rounded rectangle with a solid BGRA color.
    pub fn fill_rounded_rect(&mut self, x: f32, y: f32, w: f32, h: f32, radius: f32, color: u32) {
        let Some(path) = build_rounded_rect(x, y, w, h, radius) else { return; };
        let mut paint = Paint::default();
        paint.set_color(bgra_to_skia(color));
        paint.anti_alias = true;
        self.pixmap
            .fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
    }

    /// Stroke a rounded rectangle with a solid BGRA color.
    pub fn stroke_rounded_rect(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        radius: f32,
        width: f32,
        color: u32,
    ) {
        let Some(path) = build_rounded_rect(x, y, w, h, radius) else { return; };
        let mut paint = Paint::default();
        paint.set_color(bgra_to_skia(color));
        paint.anti_alias = true;
        let mut stroke = Stroke::default();
        stroke.width = width;
        self.pixmap
            .stroke_path(&path, &paint, &stroke, Transform::identity(), None);
    }

    /// Fill a circle with a solid BGRA color.
    pub fn fill_circle(&mut self, cx: f32, cy: f32, r: f32, color: u32) {
        let Some(path) = PathBuilder::from_circle(cx, cy, r) else { return; };
        let mut paint = Paint::default();
        paint.set_color(bgra_to_skia(color));
        paint.anti_alias = true;
        self.pixmap
            .fill_path(&path, &paint, FillRule::Winding, Transform::identity(), None);
    }

    /// Fill a rectangle with a vertical linear gradient between two BGRA colors.
    pub fn linear_gradient(
        &mut self,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        start_color: u32,
        end_color: u32,
    ) {
        let Some(rect) = Rect::from_xywh(x, y, w, h) else { return; };
        let stops = [
            GradientStop::new(0.0, bgra_to_skia(start_color)),
            GradientStop::new(1.0, bgra_to_skia(end_color)),
        ];
        let shader = match LinearGradient::new(
            Point::from_xy(x, y),
            Point::from_xy(x, y + h),
            stops.to_vec(),
            SpreadMode::Pad,
            Transform::identity(),
        ) {
            Some(s) => s,
            None => return,
        };
        let mut paint = Paint::default();
        paint.shader = shader;
        paint.anti_alias = true;
        self.pixmap
            .fill_rect(rect, &paint, Transform::identity(), None);
    }

    /// Flush the Skia pixmap onto the BGRA framebuffer at offset `(dst_x, dst_y)`.
    ///
    /// - Skia produces premultiplied RGBA; the framebuffer is BGRA — R and B
    ///   are swapped per pixel.
    /// - Source pixels with alpha = 0 are skipped so transparent canvas
    ///   regions don't clobber what's already on the framebuffer.
    /// - Destination coordinates are clipped to the framebuffer bounds.
    pub fn present(&self, fb: &mut Framebuffer, dst_x: i32, dst_y: i32) {
        if fb.addr == 0 { return; }
        let pixels_per_row = fb.pitch / 4;
        let fb_ptr = fb.addr as *mut u32;
        let src_w = self.pixmap.width();
        let src_h = self.pixmap.height();
        let src_data = self.pixmap.data();

        for sy in 0..src_h {
            let py = dst_y + sy as i32;
            if py < 0 || py >= fb.height as i32 { continue; }
            for sx in 0..src_w {
                let px = dst_x + sx as i32;
                if px < 0 || px >= fb.width as i32 { continue; }

                let src_idx = ((sy * src_w + sx) * 4) as usize;
                let r = src_data[src_idx];
                let g = src_data[src_idx + 1];
                let b = src_data[src_idx + 2];
                let a = src_data[src_idx + 3];
                if a == 0 { continue; }

                // BGRA little-endian -> u32 = 0xAARRGGBB layout in memory.
                let bgra = ((a as u32) << 24)
                    | ((r as u32) << 16)
                    | ((g as u32) << 8)
                    | (b as u32);
                unsafe {
                    let offset = (py as u32 * pixels_per_row + px as u32) as isize;
                    fb_ptr.offset(offset).write_volatile(bgra);
                }
            }
        }
    }
}

/// Build a rounded-rectangle path. Returns `None` if the rect is degenerate.
fn build_rounded_rect(x: f32, y: f32, w: f32, h: f32, radius: f32) -> Option<tiny_skia::Path> {
    if w <= 0.0 || h <= 0.0 { return None; }
    let r = radius.max(0.0).min(w * 0.5).min(h * 0.5);
    let mut pb = PathBuilder::new();
    if r == 0.0 {
        let rect = Rect::from_xywh(x, y, w, h)?;
        pb.push_rect(rect);
    } else {
        // Manual rounded-rect using quads for the corners.
        pb.move_to(x + r, y);
        pb.line_to(x + w - r, y);
        pb.quad_to(x + w, y, x + w, y + r);
        pb.line_to(x + w, y + h - r);
        pb.quad_to(x + w, y + h, x + w - r, y + h);
        pb.line_to(x + r, y + h);
        pb.quad_to(x, y + h, x, y + h - r);
        pb.line_to(x, y + r);
        pb.quad_to(x, y, x + r, y);
        pb.close();
    }
    pb.finish()
}

/// Unpack a compositor color `u32` (same packing as `BG_COLOR = 0xFF2D2D3D`,
/// i.e. `0xAARRGGBB`) into a `tiny-skia` `Color`. Despite being stored in
/// BGRA little-endian memory, compositor code writes these constants in
/// AARRGGBB form, so we decode them that way here.
fn bgra_to_skia(c: u32) -> Color {
    let a = ((c >> 24) & 0xFF) as u8;
    let r = ((c >> 16) & 0xFF) as u8;
    let g = ((c >> 8) & 0xFF) as u8;
    let b = (c & 0xFF) as u8;
    Color::from_rgba8(r, g, b, a)
}
