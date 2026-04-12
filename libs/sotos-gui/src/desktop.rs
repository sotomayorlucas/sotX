//! Modern desktop renderer using embedded-graphics.
//!
//! Draws a macOS-inspired desktop with rounded windows, traffic-light buttons,
//! and a taskbar. Uses the Tokyo Night color palette.

use embedded_graphics::prelude::*;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::primitives::{
    Circle, Line, PrimitiveStyle, PrimitiveStyleBuilder,
    Rectangle, RoundedRectangle, CornerRadii,
};
use embedded_graphics::mono_font::ascii::{FONT_10X20, FONT_9X15};
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::text::{Text, Baseline};

use crate::display::FramebufferDisplay;

// ---------------------------------------------------------------------------
// Tokyo Night color palette (sourced from sotos-theme)
// ---------------------------------------------------------------------------

/// Convert a BGRA `0xAARRGGBB` u32 to an `Rgb888` triplet.
const fn rgb(c: u32) -> Rgb888 {
    let (r, g, b) = sotos_theme::palette::rgb_components(c);
    Rgb888::new(r, g, b)
}

/// Extract (R, G, B) tuple from BGRA u32.
const fn rgb_tuple(c: u32) -> (u8, u8, u8) {
    sotos_theme::palette::rgb_components(c)
}

const TN: sotos_theme::Palette = sotos_theme::TOKYO_NIGHT;

const BG_TOP: (u8, u8, u8) = rgb_tuple(TN.bg);       // #1a1b26
const BG_BOT: (u8, u8, u8) = rgb_tuple(TN.bg_dark);   // #10101c
const TASKBAR_BG: Rgb888 = rgb(TN.bg_surface);         // #1e1e2e
const BORDER: Rgb888 = rgb(TN.border);                  // #414868
// Note: the desktop title bar uses a slightly different blue (0xFF3461A7)
// than the compositor (0xFF7AA2F7). We keep the original value here to
// preserve identical visual output.
const TITLE_ACTIVE: Rgb888 = Rgb888::new(52, 97, 167);  // #3461a7 (desktop-specific)
const WIN_BG: Rgb888 = rgb(TN.bg);                      // #1a1b26
const SHADOW_COLOR: Rgb888 = Rgb888::new(10, 10, 18);   // #0a0a12 (desktop shadow, darker than TN.shadow)
const CLOSE_RED: Rgb888 = rgb(TN.red);                   // #f7768e
const MIN_YELLOW: Rgb888 = rgb(TN.yellow);               // #e0af68
const MAX_GREEN: Rgb888 = rgb(TN.green);                 // #73daca
const TEXT_WHITE: Rgb888 = rgb(TN.fg_bright);             // #ffffff
const TEXT_BRIGHT: Rgb888 = rgb(TN.fg_secondary);         // #cdd6f4
const ACCENT: Rgb888 = rgb(TN.accent);                    // #7aa2f7

// Layout constants
const CORNER_RADIUS: u32 = 10;
const TITLE_HEIGHT: u32 = 36;
const TB_HEIGHT: u32 = 44;
const WIN_MARGIN: u32 = 12;
const SHADOW_OFFSET: u32 = 4;
const BTN_DIAMETER: u32 = 14;

/// Layout information returned after drawing the desktop.
/// Used by init to position terminal text.
pub struct DesktopLayout {
    pub win_x: u32,
    pub win_y: u32,
    pub win_w: u32,
    pub win_h: u32,
    /// Top-left of the text area (inside the terminal client area).
    pub text_x: u32,
    pub text_y: u32,
    /// Terminal dimensions in characters (8x16 VGA font).
    pub text_cols: u32,
    pub text_rows: u32,
}

/// Draw the complete modern desktop and return the terminal text layout.
pub fn draw_modern_desktop(display: &mut FramebufferDisplay, title: &[u8]) -> DesktopLayout {
    let w = display.width();
    let h = display.height();

    // 1. Desktop gradient background
    display.gradient_v(
        BG_TOP.0, BG_TOP.1, BG_TOP.2,
        BG_BOT.0, BG_BOT.1, BG_BOT.2,
    );

    // 2. Compute window geometry
    let win_x = WIN_MARGIN;
    let win_y = WIN_MARGIN;
    let win_w = w - WIN_MARGIN * 2;
    let win_h = h - WIN_MARGIN * 2 - TB_HEIGHT;

    // 3. Window shadow (offset down-right)
    RoundedRectangle::with_equal_corners(
        Rectangle::new(
            Point::new(
                win_x as i32 + SHADOW_OFFSET as i32 / 2,
                win_y as i32 + SHADOW_OFFSET as i32,
            ),
            Size::new(win_w, win_h),
        ),
        Size::new(CORNER_RADIUS + 2, CORNER_RADIUS + 2),
    )
    .into_styled(PrimitiveStyle::with_fill(SHADOW_COLOR))
    .draw(display)
    .ok();

    // 4. Window body (filled rounded rectangle with border)
    RoundedRectangle::with_equal_corners(
        Rectangle::new(
            Point::new(win_x as i32, win_y as i32),
            Size::new(win_w, win_h),
        ),
        Size::new(CORNER_RADIUS, CORNER_RADIUS),
    )
    .into_styled(
        PrimitiveStyleBuilder::new()
            .fill_color(WIN_BG)
            .stroke_color(BORDER)
            .stroke_width(1)
            .build(),
    )
    .draw(display)
    .ok();

    // 5. Title bar (rounded top corners, flat bottom)
    RoundedRectangle::new(
        Rectangle::new(
            Point::new(win_x as i32 + 1, win_y as i32 + 1),
            Size::new(win_w - 2, TITLE_HEIGHT),
        ),
        CornerRadii {
            top_left: Size::new(CORNER_RADIUS - 1, CORNER_RADIUS - 1),
            top_right: Size::new(CORNER_RADIUS - 1, CORNER_RADIUS - 1),
            bottom_left: Size::new(0, 0),
            bottom_right: Size::new(0, 0),
        },
    )
    .into_styled(PrimitiveStyle::with_fill(TITLE_ACTIVE))
    .draw(display)
    .ok();

    // 6. Traffic light buttons (macOS-style circles)
    let btn_cy = win_y as i32 + (TITLE_HEIGHT / 2) as i32;

    // Close (red)
    Circle::with_center(Point::new(win_x as i32 + 22, btn_cy), BTN_DIAMETER)
        .into_styled(PrimitiveStyle::with_fill(CLOSE_RED))
        .draw(display)
        .ok();

    // Minimize (yellow)
    Circle::with_center(Point::new(win_x as i32 + 44, btn_cy), BTN_DIAMETER)
        .into_styled(PrimitiveStyle::with_fill(MIN_YELLOW))
        .draw(display)
        .ok();

    // Maximize (green)
    Circle::with_center(Point::new(win_x as i32 + 66, btn_cy), BTN_DIAMETER)
        .into_styled(PrimitiveStyle::with_fill(MAX_GREEN))
        .draw(display)
        .ok();

    // 7. Title text (centered in title bar)
    let title_str = core::str::from_utf8(title).unwrap_or("Terminal");
    let title_pixel_w = title_str.len() as i32 * 10; // FONT_10X20 = 10px wide
    let title_x = win_x as i32 + (win_w as i32 - title_pixel_w) / 2;

    let title_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(TEXT_WHITE)
        .build();

    Text::with_baseline(
        title_str,
        Point::new(title_x, win_y as i32 + 8),
        title_style,
        Baseline::Top,
    )
    .draw(display)
    .ok();

    // 8. Separator line below title bar
    let sep_y = win_y as i32 + TITLE_HEIGHT as i32 + 1;
    Line::new(
        Point::new(win_x as i32 + 1, sep_y),
        Point::new(win_x as i32 + win_w as i32 - 2, sep_y),
    )
    .into_styled(PrimitiveStyle::with_stroke(BORDER, 1))
    .draw(display)
    .ok();

    // 9. Taskbar
    let tb_y = h - TB_HEIGHT;

    // Taskbar background
    Rectangle::new(
        Point::new(0, tb_y as i32),
        Size::new(w, TB_HEIGHT),
    )
    .into_styled(PrimitiveStyle::with_fill(TASKBAR_BG))
    .draw(display)
    .ok();

    // Taskbar top border
    Line::new(
        Point::new(0, tb_y as i32),
        Point::new(w as i32 - 1, tb_y as i32),
    )
    .into_styled(PrimitiveStyle::with_stroke(BORDER, 1))
    .draw(display)
    .ok();

    // "sotOS" branding (accent color)
    let brand_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(ACCENT)
        .build();

    Text::with_baseline(
        "sotOS",
        Point::new(16, tb_y as i32 + 12),
        brand_style,
        Baseline::Top,
    )
    .draw(display)
    .ok();

    // Vertical separator after branding
    let sep_x = 80;
    Line::new(
        Point::new(sep_x, tb_y as i32 + 8),
        Point::new(sep_x, tb_y as i32 + TB_HEIGHT as i32 - 8),
    )
    .into_styled(PrimitiveStyle::with_stroke(BORDER, 1))
    .draw(display)
    .ok();

    // Active window indicator (green dot)
    Circle::with_center(
        Point::new(sep_x + 16, tb_y as i32 + TB_HEIGHT as i32 / 2),
        10,
    )
    .into_styled(PrimitiveStyle::with_fill(MAX_GREEN))
    .draw(display)
    .ok();

    // Window title in taskbar
    let tb_text_style = MonoTextStyleBuilder::new()
        .font(&FONT_9X15)
        .text_color(TEXT_BRIGHT)
        .build();

    Text::with_baseline(
        "Terminal",
        Point::new(sep_x + 28, tb_y as i32 + 15),
        tb_text_style,
        Baseline::Top,
    )
    .draw(display)
    .ok();

    // 10. Welcome splash — gradient strip with text at bottom of client area
    let splash_h = 48u32;
    let splash_y = win_y + win_h - splash_h - 4;

    // Draw gradient strip (purple → teal)
    for i in 0..splash_h {
        let r = (122u32.saturating_sub(80 * i / splash_h)) as u8;
        let g = (80 + 100 * i / splash_h) as u8;
        let b = (200u32.saturating_sub(50 * i / splash_h)) as u8;
        let color = Rgb888::new(r, g, b);
        Rectangle::new(
            Point::new(win_x as i32 + 2, splash_y as i32 + i as i32),
            Size::new(win_w - 4, 1),
        )
        .into_styled(PrimitiveStyle::with_fill(color))
        .draw(display)
        .ok();
    }

    // Welcome text centered in the gradient strip
    let welcome_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(TEXT_WHITE)
        .build();
    let msg = "Welcome to sotOS";
    let msg_w = msg.len() as i32 * 10;
    let msg_x = win_x as i32 + (win_w as i32 - msg_w) / 2;
    let msg_y = splash_y as i32 + (splash_h as i32 - 20) / 2;
    Text::with_baseline(msg, Point::new(msg_x, msg_y), welcome_style, Baseline::Top)
        .draw(display)
        .ok();

    // 11. Return text area layout (for VGA 8x16 terminal font)
    let text_x = win_x + 6;
    let text_y = win_y + TITLE_HEIGHT + 4;
    let text_area_w = win_w - 12;
    let text_area_h = win_h - TITLE_HEIGHT - splash_h - 12;
    let text_cols = text_area_w / 8;
    let text_rows = text_area_h / 16;

    DesktopLayout {
        win_x,
        win_y,
        win_w,
        win_h,
        text_x,
        text_y,
        text_cols,
        text_rows,
    }
}
