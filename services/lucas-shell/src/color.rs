//! ANSI SGR color helpers with Tokyo Night palette.
//!
//! All output respects the `$NO_COLOR` environment variable
//! (<https://no-color.org/>). When `NO_COLOR` is set (to any value),
//! every helper emits an empty byte slice instead of an escape sequence.

use crate::env::env_get;
use crate::syscall::linux_write;

// ---------------------------------------------------------------------------
// $NO_COLOR gate
// ---------------------------------------------------------------------------

/// Returns `true` when color output is suppressed.
#[inline]
pub fn no_color() -> bool {
    env_get(b"NO_COLOR").is_some()
}

// ---------------------------------------------------------------------------
// Tokyo Night (storm) truecolor SGR sequences
//
// Canonical hex values from
//   services/compositor/src/decorations.rs:68
//   (BGRA 0xAARRGGBB  ->  RGB)
// ---------------------------------------------------------------------------

/// TN blue  #7AA2F7
pub const FG_BLUE: &[u8]      = b"\x1b[38;2;122;162;247m";
/// TN green #73DACA
pub const FG_GREEN: &[u8]     = b"\x1b[38;2;115;218;202m";
/// TN cyan  #7DCFFF
pub const FG_CYAN: &[u8]      = b"\x1b[38;2;125;207;255m";
/// TN magenta #BB9AF7
pub const FG_MAGENTA: &[u8]   = b"\x1b[38;2;187;154;247m";
/// TN red   #F7768E
pub const FG_RED: &[u8]       = b"\x1b[38;2;247;118;142m";
/// TN yellow #E0AF68
pub const FG_YELLOW: &[u8]    = b"\x1b[38;2;224;175;104m";
/// TN comment #565F89
pub const FG_DIM: &[u8]       = b"\x1b[38;2;86;95;137m";
/// Bold + TN red (grep match highlight)
pub const BOLD_RED: &[u8]     = b"\x1b[1;38;2;247;118;142m";

/// Bold attribute
pub const BOLD: &[u8]         = b"\x1b[1m";
/// Reset all attributes
pub const RESET: &[u8]        = b"\x1b[0m";

// ---------------------------------------------------------------------------
// Helpers that honor $NO_COLOR
// ---------------------------------------------------------------------------

/// Write a color escape to stdout, respecting $NO_COLOR.
#[inline]
pub fn color(seq: &[u8]) {
    if !no_color() {
        linux_write(1, seq.as_ptr(), seq.len());
    }
}

/// Write RESET to stdout, respecting $NO_COLOR.
#[inline]
pub fn reset() {
    color(RESET);
}
