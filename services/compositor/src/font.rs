//! Anti-aliased mono text rendering for the compositor.
//!
//! Wraps the compositor's raw BGRA framebuffer in a thin `DrawTarget`
//! adapter so we can reuse `embedded-graphics`' mono fonts instead of
//! the old 8x8 bitmap font. See `libs/sotos-gui/src/display.rs` for the
//! reference implementation this is modeled on.

use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::text::{Baseline, Text};

pub use embedded_graphics::mono_font::ascii::{FONT_10X20, FONT_6X10};

use crate::render::Framebuffer;

/// Title/large font row height in pixels (matches `FONT_10X20`).
pub const TITLE_FONT_HEIGHT: i32 = 20;

/// Compact font row height in pixels (matches `FONT_6X10`).
pub const COMPACT_FONT_HEIGHT: i32 = 10;

/// Thin `DrawTarget` adapter over a borrowed `Framebuffer`.
///
/// Unlike `libs/sotos-gui::FramebufferDisplay` which stores a raw
/// pointer, this adapter borrows the compositor's existing `Framebuffer`
/// struct so we don't duplicate state.
struct FbTarget<'a> {
    fb: &'a Framebuffer,
}

impl<'a> FbTarget<'a> {
    #[inline(always)]
    fn to_bgra(color: Rgb888) -> u32 {
        0xFF000000
            | ((color.r() as u32) << 16)
            | ((color.g() as u32) << 8)
            | (color.b() as u32)
    }
}

impl<'a> DrawTarget for FbTarget<'a> {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb888>>,
    {
        if self.fb.addr == 0 {
            return Ok(());
        }
        let stride = (self.fb.pitch / 4) as i32;
        let w = self.fb.width as i32;
        let h = self.fb.height as i32;
        let base = self.fb.addr as *mut u32;
        for Pixel(point, color) in pixels {
            let x = point.x;
            let y = point.y;
            if x < 0 || y < 0 || x >= w || y >= h {
                continue;
            }
            unsafe {
                base.offset((y * stride + x) as isize)
                    .write_volatile(Self::to_bgra(color));
            }
        }
        Ok(())
    }
    // `fill_solid` is intentionally left as the default (iterates via
    // `draw_iter`) — glyph rendering only emits individual pixels, and
    // the compositor uses `Framebuffer::fill_rect` for background fills.
}

impl<'a> OriginDimensions for FbTarget<'a> {
    fn size(&self) -> Size {
        Size::new(self.fb.width, self.fb.height)
    }
}

/// Convert our BGRA u32 (0xAARRGGBB) into `Rgb888` for embedded-graphics.
#[inline(always)]
fn bgra_to_rgb888(color: u32) -> Rgb888 {
    Rgb888::new(
        ((color >> 16) & 0xFF) as u8,
        ((color >> 8) & 0xFF) as u8,
        (color & 0xFF) as u8,
    )
}

/// Draw `text` at `(x, y)` into `fb` using a mono font from
/// `embedded-graphics`. `large=true` uses `FONT_10X20`, otherwise
/// `FONT_6X10`. The baseline is `Top`, so `y` is the top pixel row.
///
/// `fb` is taken by shared reference to match the rest of the
/// `Framebuffer` API (`clear`, `fill_rect`, `blit` — all `&self`);
/// writes to the underlying pixels go through the raw pointer stored
/// inside `Framebuffer`.
pub fn draw_text(fb: &Framebuffer, x: i32, y: i32, text: &str, color: u32, large: bool) {
    if fb.addr == 0 || text.is_empty() {
        return;
    }
    let font = if large { &FONT_10X20 } else { &FONT_6X10 };
    let style = MonoTextStyleBuilder::new()
        .font(font)
        .text_color(bgra_to_rgb888(color))
        .build();
    let mut target = FbTarget { fb };
    let _ = Text::with_baseline(text, Point::new(x, y), style, Baseline::Top)
        .draw(&mut target);
}
