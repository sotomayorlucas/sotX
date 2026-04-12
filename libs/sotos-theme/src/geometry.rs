//! Layout and geometry constants shared across the sotOS UI.
//!
//! These values are used by the compositor's window decorations,
//! `sotos-gui`'s desktop renderer, and the init framebuffer console.

// ---------------------------------------------------------------------------
// Title bar / window chrome
// ---------------------------------------------------------------------------

/// Height of the compositor's decorated title bar in pixels.
pub const TITLE_BAR_HEIGHT: i32 = 28;

/// Rounded-corner radius for window clipping.
pub const BORDER_RADIUS: i32 = 8;

/// Drop-shadow blur spread in pixels.
pub const SHADOW_BLUR: i32 = 12;

// ---------------------------------------------------------------------------
// Traffic-light buttons (macOS-style)
// ---------------------------------------------------------------------------

/// Diameter of each traffic-light button circle.
pub const BUTTON_DIAMETER: i32 = 14;

/// Center-to-center gap between traffic-light buttons.
pub const BUTTON_GAP: i32 = BUTTON_DIAMETER + 8;

/// Left inset before the first traffic-light button center.
pub const BUTTON_LEFT_INSET: i32 = 10;

// ---------------------------------------------------------------------------
// Glyph metrics
// ---------------------------------------------------------------------------

/// Advance (in pixels) of the 6x10 embedded-graphics font used for
/// compositor title text.
pub const GLYPH_ADVANCE_6X10: i32 = 6;

/// Glyph cell size for the 8x16 VGA/CP437 bitmap font used by the
/// init framebuffer text console.
pub const GLYPH_WIDTH_8X16: u32 = 8;
pub const GLYPH_HEIGHT_8X16: u32 = 16;

/// Glyph cell size for the 10x20 embedded-graphics font used for
/// desktop title text in sotos-gui.
pub const GLYPH_WIDTH_10X20: u32 = 10;
pub const GLYPH_HEIGHT_10X20: u32 = 20;

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

/// Status bar height in pixels (layer-shell exclusive zone).
pub const STATUS_BAR_HEIGHT: u32 = 24;
