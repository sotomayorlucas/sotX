//! Tokyo Night terminal palette + xterm256 + truecolor helpers.
//!
//! All colors are stored as packed `BGRA` `0xAARRGGBB` (what the
//! framebuffer actually accepts). `ANSI_PALETTE[0..=7]` are the normal
//! ANSI colors; `ANSI_PALETTE[8..=15]` are the "bright" variants that
//! SGR `1` (bold) and `90-97`/`100-107` select.
//!
//! The 256-color cube and gray ramp match xterm's canonical table so
//! that TUIs (`nano`, `htop`, `busybox vi`, …) render identically to
//! what a user expects from their host terminal.
//!
//! Unit 22 will fold this into a shared `sotos-theme` crate; for now
//! each worker keeps a local copy to avoid cross-unit merge conflicts.

/// 16 ANSI base colors (BGRA). Indices 0..=7 normal, 8..=15 bright.
/// Mapped to Tokyo Night (Storm) so the fake "LUCAS Terminal" window
/// chrome and the character cells stay on-palette.
pub const ANSI_PALETTE: [u32; 16] = [
    0xFF1A1B26, // 0  black       (bg)
    0xFFF7768E, // 1  red
    0xFF9ECE6A, // 2  green
    0xFFE0AF68, // 3  yellow
    0xFF7AA2F7, // 4  blue
    0xFFBB9AF7, // 5  magenta
    0xFF7DCFFF, // 6  cyan
    0xFFA9B1D6, // 7  white       (fg)
    0xFF414868, // 8  bright black (comment grey)
    0xFFFF7A93, // 9  bright red
    0xFFB9F27C, // 10 bright green
    0xFFFF9E64, // 11 bright yellow (orange)
    0xFF7DA6FF, // 12 bright blue
    0xFFBB9AF7, // 13 bright magenta
    0xFFB4F9F8, // 14 bright cyan
    0xFFC0CAF5, // 15 bright white
];

/// Default foreground color (`\x1b[39m`): normal white.
pub const DEFAULT_FG: u32 = ANSI_PALETTE[7];

/// Default background color (`\x1b[49m`): terminal background.
pub const DEFAULT_BG: u32 = ANSI_PALETTE[0];

/// Pack an 8-bit RGB truecolor triple into the framebuffer `BGRA` format.
#[inline]
pub const fn truecolor(r: u8, g: u8, b: u8) -> u32 {
    0xFF00_0000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Resolve an xterm 256-color index into a packed `BGRA` color.
///
/// Layout:
/// - `0..=15`   : ANSI base palette.
/// - `16..=231` : 6x6x6 RGB cube, steps `[0, 95, 135, 175, 215, 255]`.
/// - `232..=255`: 24 grey levels, `8 + 10*n`.
pub const fn xterm256(n: u8) -> u32 {
    if n < 16 {
        return ANSI_PALETTE[n as usize];
    }
    if n >= 232 {
        let g = 8 + (n - 232) * 10;
        return truecolor(g, g, g);
    }
    // 6x6x6 cube: n = 16 + 36*r + 6*g + b
    let idx = n - 16;
    let r_idx = idx / 36;
    let g_idx = (idx / 6) % 6;
    let b_idx = idx % 6;
    let steps: [u8; 6] = [0, 95, 135, 175, 215, 255];
    truecolor(steps[r_idx as usize], steps[g_idx as usize], steps[b_idx as usize])
}
