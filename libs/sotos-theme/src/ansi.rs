//! ANSI SGR escape helpers for serial/terminal output.
//!
//! All values are `&[u8]` byte slices suitable for `print()` or
//! `sys::debug_print()` in `#![no_std]` contexts.

/// Reset all attributes.
pub const RESET: &[u8] = b"\x1b[0m";

/// Bold / bright.
pub const BOLD: &[u8] = b"\x1b[1m";

/// Dim / faint.
pub const DIM: &[u8] = b"\x1b[2m";

/// Underline.
pub const UNDERLINE: &[u8] = b"\x1b[4m";

/// Reverse video.
pub const REVERSE: &[u8] = b"\x1b[7m";

// ---------------------------------------------------------------------------
// Foreground colors (Tokyo Night mapped to 256-color SGR)
// ---------------------------------------------------------------------------

/// Blue accent foreground (`#7aa2f7` -> 256-color 111).
pub const FG_ACCENT: &[u8] = b"\x1b[38;5;111m";

/// Red foreground (`#f7768e` -> 256-color 204).
pub const FG_RED: &[u8] = b"\x1b[38;5;204m";

/// Green foreground (`#9ece6a` -> 256-color 149).
pub const FG_GREEN: &[u8] = b"\x1b[38;5;149m";

/// Yellow foreground (`#e0af68` -> 256-color 179).
pub const FG_YELLOW: &[u8] = b"\x1b[38;5;179m";

/// Teal/cyan foreground (`#73daca` -> 256-color 79).
pub const FG_TEAL: &[u8] = b"\x1b[38;5;79m";

/// Purple/magenta foreground (`#bb9af7` -> 256-color 141).
pub const FG_PURPLE: &[u8] = b"\x1b[38;5;141m";

/// Muted text foreground (`#a9b1d6` -> 256-color 146).
pub const FG_MUTED: &[u8] = b"\x1b[38;5;146m";

/// Bright white foreground.
pub const FG_WHITE: &[u8] = b"\x1b[38;5;15m";

// ---------------------------------------------------------------------------
// Background colors
// ---------------------------------------------------------------------------

/// Storm background (`#1a1b26` -> 256-color 234).
pub const BG_STORM: &[u8] = b"\x1b[48;5;234m";

/// Highlight background (`#24283b` -> 256-color 236).
pub const BG_HIGHLIGHT: &[u8] = b"\x1b[48;5;236m";

// ---------------------------------------------------------------------------
// Conversion helper
// ---------------------------------------------------------------------------

/// Convert a BGRA `0xAARRGGBB` u32 to a 24-bit truecolor SGR foreground
/// sequence. Writes `\x1b[38;2;R;G;B m` into `buf` and returns the number
/// of bytes written. `buf` must be at least 20 bytes.
pub fn bgra_to_fg_sgr(color: u32, buf: &mut [u8]) -> usize {
    let r = ((color >> 16) & 0xFF) as u8;
    let g = ((color >> 8) & 0xFF) as u8;
    let b = (color & 0xFF) as u8;
    write_truecolor_sgr(38, r, g, b, buf)
}

/// Convert a BGRA `0xAARRGGBB` u32 to a 24-bit truecolor SGR background
/// sequence. Writes `\x1b[48;2;R;G;B m` into `buf` and returns the number
/// of bytes written. `buf` must be at least 20 bytes.
pub fn bgra_to_bg_sgr(color: u32, buf: &mut [u8]) -> usize {
    let r = ((color >> 16) & 0xFF) as u8;
    let g = ((color >> 8) & 0xFF) as u8;
    let b = (color & 0xFF) as u8;
    write_truecolor_sgr(48, r, g, b, buf)
}

/// Write `\x1b[{kind};2;{r};{g};{b}m` into buf, return bytes written.
fn write_truecolor_sgr(kind: u8, r: u8, g: u8, b: u8, buf: &mut [u8]) -> usize {
    // Prefix: ESC [
    buf[0] = 0x1b;
    buf[1] = b'[';
    let mut pos = 2;
    // kind (38 or 48)
    pos += write_u8(kind, &mut buf[pos..]);
    buf[pos] = b';';
    pos += 1;
    buf[pos] = b'2';
    pos += 1;
    buf[pos] = b';';
    pos += 1;
    pos += write_u8(r, &mut buf[pos..]);
    buf[pos] = b';';
    pos += 1;
    pos += write_u8(g, &mut buf[pos..]);
    buf[pos] = b';';
    pos += 1;
    pos += write_u8(b, &mut buf[pos..]);
    buf[pos] = b'm';
    pos + 1
}

/// Write a u8 decimal value into buf, return bytes written.
fn write_u8(val: u8, buf: &mut [u8]) -> usize {
    if val >= 100 {
        buf[0] = b'0' + val / 100;
        buf[1] = b'0' + (val / 10) % 10;
        buf[2] = b'0' + val % 10;
        3
    } else if val >= 10 {
        buf[0] = b'0' + val / 10;
        buf[1] = b'0' + val % 10;
        2
    } else {
        buf[0] = b'0' + val;
        1
    }
}
