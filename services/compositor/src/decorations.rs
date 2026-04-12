//! Modern window decorations.
//!
//! Tokyo Night-styled window chrome: gradient title bar with rounded
//! traffic-light buttons on the LEFT side of the title bar.
//!
//! The title bar is 28px tall (replacing the previous bare 24px bar).
//! Traffic-light buttons mirror macOS layout:
//!     close (red) | minimize (yellow) | maximize (green)
//! The close button is the LEFTMOST circle; `close_button_rect()`
//! returns its bounding square so hit-testing stays straightforward.

use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle, Rectangle};

use crate::render::Framebuffer;
use sotos_theme::{TOKYO_NIGHT, geometry};

// ---------------------------------------------------------------------------
// Public geometry constants (re-exported from sotos-theme)
// ---------------------------------------------------------------------------

/// Height of the decorated title bar in pixels.
pub const TITLE_BAR_HEIGHT: i32 = geometry::TITLE_BAR_HEIGHT;

/// Rounded-corner radius for future window rounding (title bar is squared for now).
#[allow(dead_code)]
pub const BORDER_RADIUS: i32 = geometry::BORDER_RADIUS;

const GLYPH_ADVANCE: i32 = geometry::GLYPH_ADVANCE_6X10;
const BUTTON_DIAMETER: i32 = geometry::BUTTON_DIAMETER;
const BUTTON_GAP: i32 = geometry::BUTTON_GAP;
const BUTTON_LEFT_INSET: i32 = geometry::BUTTON_LEFT_INSET;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Paint a modern title bar at `(x, y)` with width `w`.
///
/// Layout:
///   row 0..TITLE_BAR_HEIGHT-1: vertical gradient (active/inactive color).
///   row TITLE_BAR_HEIGHT-1   : 1px border line.
///   traffic lights: 3 circles on the LEFT, vertically centered.
///   title text: centered horizontally, 8px from top.
pub fn draw_title_bar(fb: &mut Framebuffer, x: i32, y: i32, w: i32, focused: bool, title: &str) {
    if w <= 0 {
        return;
    }
    let width = w as u32;

    // Base color for this state.
    let base = if focused {
        TOKYO_NIGHT.accent
    } else {
        TOKYO_NIGHT.title_inactive
    };
    let bottom = darken(base, 5);

    // Vertical gradient across the bar, row by row.
    let bar_rows = TITLE_BAR_HEIGHT.max(1);
    for row in 0..bar_rows {
        let t = row as i32;
        let color = blend(base, bottom, t, bar_rows - 1);
        fb.fill_rect(x, y + row, width, 1, color);
    }

    // 1px bottom border line inside the title bar.
    fb.fill_rect(x, y + TITLE_BAR_HEIGHT - 1, width, 1, TOKYO_NIGHT.bg_highlight);

    // No drop-shadow strip: rows below the bar coincide with the start of
    // the client content area, so the compose loop would overwrite any
    // shadow painted here on the same frame.

    // Traffic-light buttons on the LEFT.
    let cy = y + TITLE_BAR_HEIGHT / 2;
    let (cx0, cx1, cx2) = button_centers(x);
    draw_traffic_light(fb, cx0, cy, TOKYO_NIGHT.red);
    draw_traffic_light(fb, cx1, cy, TOKYO_NIGHT.yellow);
    draw_traffic_light(fb, cx2, cy, TOKYO_NIGHT.green);

    // Title text: centered horizontally, 8px from top. Clipped so it never
    // overlaps the traffic lights.
    let bytes = title.as_bytes();
    let reserved_left = cx2 + BUTTON_DIAMETER / 2 + 8;
    let available = (x + w - 8 - reserved_left).max(0);
    let max_chars = ((available / GLYPH_ADVANCE).max(0) as usize).min(bytes.len());
    if max_chars > 0 {
        let draw_width = (max_chars as i32) * GLYPH_ADVANCE;
        let tx = (x + (w - draw_width) / 2).max(reserved_left);
        fb.draw_text(tx, y + 8, &bytes[..max_chars], TOKYO_NIGHT.fg);
    }
}

/// Draw a single traffic-light circle centered at `(cx, cy)`.
pub fn draw_traffic_light(fb: &mut Framebuffer, cx: i32, cy: i32, color: u32) {
    let diameter = BUTTON_DIAMETER as u32;
    let top_left = Point::new(cx - BUTTON_DIAMETER / 2, cy - BUTTON_DIAMETER / 2);

    let mut target = FbTarget::new(fb);
    let style = PrimitiveStyle::with_fill(rgb888_from_bgra(color));
    let _ = Circle::new(top_left, diameter).into_styled(style).draw(&mut target);
}

/// Return the bounding square of the LEFTMOST traffic-light (the close button).
///
/// Returned tuple is `(x, y, w, h)` in framebuffer coordinates. Callers use
/// this for hit-testing so the layout of the decorations stays encapsulated.
pub fn close_button_rect(x: i32, y: i32, _w: i32) -> (i32, i32, i32, i32) {
    let cy = y + TITLE_BAR_HEIGHT / 2;
    let (cx0, _cx1, _cx2) = button_centers(x);
    let bx = cx0 - BUTTON_DIAMETER / 2;
    let by = cy - BUTTON_DIAMETER / 2;
    (bx, by, BUTTON_DIAMETER, BUTTON_DIAMETER)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Center X coordinates of the three traffic lights.
fn button_centers(x: i32) -> (i32, i32, i32) {
    let cx0 = x + BUTTON_LEFT_INSET + BUTTON_DIAMETER / 2;
    let cx1 = cx0 + BUTTON_GAP;
    let cx2 = cx1 + BUTTON_GAP;
    (cx0, cx1, cx2)
}

/// Linear blend between two BGRA `0xFFRRGGBB` colors. `num/den` is the blend factor
/// (0 = all `a`, `den` = all `b`). Alpha is preserved from `a`.
fn blend(a: u32, b: u32, num: i32, den: i32) -> u32 {
    if den <= 0 {
        return a;
    }
    let (ar, ag, ab) = ((a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
    let (br, bg, bb) = ((b >> 16) & 0xFF, (b >> 8) & 0xFF, b & 0xFF);
    let lerp = |x: u32, y: u32| -> u32 {
        let xi = x as i32;
        let yi = y as i32;
        (xi + (yi - xi) * num / den) as u32 & 0xFF
    };
    (a & 0xFF00_0000) | (lerp(ar, br) << 16) | (lerp(ag, bg) << 8) | lerp(ab, bb)
}

/// Darken a color by `percent`% toward black. Alpha preserved.
fn darken(c: u32, percent: u32) -> u32 {
    let p = percent.min(100);
    let scale = 100 - p;
    let r = (((c >> 16) & 0xFF) * scale / 100) & 0xFF;
    let g = (((c >> 8) & 0xFF) * scale / 100) & 0xFF;
    let b = ((c & 0xFF) * scale / 100) & 0xFF;
    (c & 0xFF00_0000) | (r << 16) | (g << 8) | b
}

/// Convert a BGRA `0xFFRRGGBB` u32 into an `embedded_graphics` `Rgb888`.
fn rgb888_from_bgra(c: u32) -> Rgb888 {
    let r = ((c >> 16) & 0xFF) as u8;
    let g = ((c >> 8) & 0xFF) as u8;
    let b = (c & 0xFF) as u8;
    Rgb888::new(r, g, b)
}

// ---------------------------------------------------------------------------
// FbTarget: lightweight DrawTarget adapter over Framebuffer
// ---------------------------------------------------------------------------

/// Adapter that lets `embedded_graphics` primitives render into the compositor
/// `Framebuffer` without pulling in `sotos-gui` as a dependency.
struct FbTarget<'a> {
    fb: &'a Framebuffer,
}

impl<'a> FbTarget<'a> {
    fn new(fb: &'a Framebuffer) -> Self {
        Self { fb }
    }

    #[inline]
    fn put(&self, x: i32, y: i32, color: Rgb888) {
        if self.fb.addr == 0 {
            return;
        }
        if x < 0 || y < 0 {
            return;
        }
        if (x as u32) >= self.fb.width || (y as u32) >= self.fb.height {
            return;
        }
        let pixel = 0xFF00_0000
            | (color.r() as u32) << 16
            | (color.g() as u32) << 8
            | color.b() as u32;
        let pixels_per_row = self.fb.pitch / 4;
        let ptr = self.fb.addr as *mut u32;
        unsafe {
            let offset = (y as u32 * pixels_per_row + x as u32) as isize;
            ptr.offset(offset).write_volatile(pixel);
        }
    }
}

impl<'a> DrawTarget for FbTarget<'a> {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb888>>,
    {
        for Pixel(point, color) in pixels {
            self.put(point.x, point.y, color);
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb888) -> Result<(), Self::Error> {
        let pixel = 0xFF00_0000
            | (color.r() as u32) << 16
            | (color.g() as u32) << 8
            | color.b() as u32;
        self.fb.fill_rect(
            area.top_left.x,
            area.top_left.y,
            area.size.width,
            area.size.height,
            pixel,
        );
        Ok(())
    }
}

impl<'a> OriginDimensions for FbTarget<'a> {
    fn size(&self) -> Size {
        Size::new(self.fb.width, self.fb.height)
    }
}
