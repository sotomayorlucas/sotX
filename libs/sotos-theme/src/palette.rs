//! Tokyo Night color palette.
//!
//! All colors are BGRA `0xAARRGGBB` (alpha in high byte, red next, then green,
//! then blue). This matches the convention used by the sotOS framebuffer,
//! compositor, and all Wayland clients.
//!
//! Values taken from the canonical Tokyo Night (storm) spec:
//! <https://github.com/folke/tokyonight.nvim/blob/main/extras/lua/tokyonight_night.lua>

/// A named color palette with all the values needed across the sotOS UI.
#[derive(Clone, Copy)]
pub struct Palette {
    // -- Backgrounds --
    /// Storm background (`#1a1b26`).
    pub bg: u32,
    /// Darker background / gradient bottom (`#10101c`).
    pub bg_dark: u32,
    /// Surface/card background (`#1e1e2e`).
    pub bg_surface: u32,
    /// Background highlight (`#24283b`).
    pub bg_highlight: u32,

    // -- Foreground / text --
    /// Primary foreground (`#c0caf5`).
    pub fg: u32,
    /// Bright foreground / pure white (`#ffffff`).
    pub fg_bright: u32,
    /// Subdued foreground (`#a9b1d6`).
    pub fg_muted: u32,
    /// Secondary / dim text (`#cdd6f4`).
    pub fg_secondary: u32,

    // -- Accent --
    /// Blue accent (`#7aa2f7`).
    pub accent: u32,

    // -- Semantic --
    /// Red — close, error (`#f7768e`).
    pub red: u32,
    /// Yellow — minimize, warning (`#e0af68`).
    pub yellow: u32,
    /// Green — maximize, success, teal variant (`#73daca`).
    pub green: u32,
    /// Green — memory OK, lime variant (`#9ece6a`).
    pub green_alt: u32,

    // -- Chrome --
    /// Border / separator (`#414868`).
    pub border: u32,
    /// Window shadow (semi-transparent black).
    pub shadow: u32,
    /// Title bar active color (same as accent).
    pub title_active: u32,
    /// Title bar inactive color (same as bg_highlight).
    pub title_inactive: u32,
}

/// The canonical Tokyo Night palette used across all of sotOS.
pub const TOKYO_NIGHT: Palette = Palette {
    // Backgrounds
    bg:           0xFF1A1B26,
    bg_dark:      0xFF10101C,
    bg_surface:   0xFF1E1E2E,
    bg_highlight: 0xFF24283B,

    // Foreground
    fg:           0xFFC0CAF5,
    fg_bright:    0xFFFFFFFF,
    fg_muted:     0xFFA9B1D6,
    fg_secondary: 0xFFCDD6F4,

    // Accent
    accent:       0xFF7AA2F7,

    // Semantic
    red:          0xFFF7768E,
    yellow:       0xFFE0AF68,
    green:        0xFF73DACA,
    green_alt:    0xFF9ECE6A,

    // Chrome
    border:       0xFF414868,
    shadow:       0x55000000,
    title_active: 0xFF7AA2F7,
    title_inactive: 0xFF24283B,
};

/// Standard 16-color ANSI palette mapped to Tokyo Night values.
///
/// Index 0-7: normal colors, 8-15: bright/bold variants.
/// Order: black, red, green, yellow, blue, magenta, cyan, white.
pub const ANSI_16: [u32; 16] = [
    // Normal
    0xFF1A1B26, // 0  black   — bg
    0xFFF7768E, // 1  red
    0xFF9ECE6A, // 2  green
    0xFFE0AF68, // 3  yellow
    0xFF7AA2F7, // 4  blue
    0xFFBB9AF7, // 5  magenta — TN purple
    0xFF73DACA, // 6  cyan    — TN teal
    0xFFA9B1D6, // 7  white   — fg_muted

    // Bright
    0xFF414868, // 8  bright black  — border/comment
    0xFFFF9E64, // 9  bright red    — TN orange
    0xFF73DACA, // 10 bright green  — TN teal
    0xFFE0AF68, // 11 bright yellow
    0xFF7DCFFF, // 12 bright blue   — lighter blue
    0xFFBB9AF7, // 13 bright magenta
    0xFF89DDFF, // 14 bright cyan   — lighter cyan
    0xFFC0CAF5, // 15 bright white  — fg
];

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Extract the (R, G, B) components from a BGRA `0xAARRGGBB` u32.
pub const fn rgb_components(c: u32) -> (u8, u8, u8) {
    (
        ((c >> 16) & 0xFF) as u8,
        ((c >> 8) & 0xFF) as u8,
        (c & 0xFF) as u8,
    )
}
