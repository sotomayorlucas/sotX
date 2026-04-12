//! Boot splash — centered Tokyo Night ASCII logo with staged progress bar.
//!
//! Replaces the flood of `[ok]` lines with a clean, centered splash that
//! ticks through 5 init stages:
//!   0. CPU + memory
//!   1. Scheduler + IPC
//!   2. Capabilities
//!   3. Drivers
//!   4. Userspace
//!
//! The splash is drawn to the serial console using ANSI escape codes.
//! All output goes through `kprint!`/`kprintln!` (serial COM1).

use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Tokyo Night palette (ANSI SGR sequences for serial terminal)
// ---------------------------------------------------------------------------
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const FG_BLUE: &str = "\x1b[38;2;122;162;247m"; // #7aa2f7
const FG_PURPLE: &str = "\x1b[38;2;187;154;247m"; // #bb9af7
const FG_CYAN: &str = "\x1b[38;2;125;207;255m"; // #7dcfff
const FG_GREEN: &str = "\x1b[38;2;158;206;106m"; // #9ece6a
const FG_DARK: &str = "\x1b[38;2;86;95;137m"; // #565f89

/// Total number of boot stages.
pub const STAGE_COUNT: u8 = 5;

/// Whether the splash has been shown yet.
static SPLASH_SHOWN: AtomicBool = AtomicBool::new(false);

/// Runtime verbose flag. When true, `kinfo!`/`kdebug!` print normally.
/// When false (default), only `kerror!` and the splash are visible.
/// Initialized from the `verbose` feature at compile time; can be
/// overridden at runtime if a cmdline parser is added later.
pub static VERBOSE: AtomicBool = AtomicBool::new(cfg!(feature = "verbose"));

/// Print the centered splash banner (logo + version + empty progress bar).
/// Called once at the start of `kmain()`, after serial init.
pub fn show() {
    if SPLASH_SHOWN.swap(true, Ordering::Relaxed) {
        return; // already shown
    }

    // Clear screen + hide cursor
    crate::kprint!("\x1b[2J\x1b[H\x1b[?25l");

    // Leave a few blank lines for vertical centering on an 80x25 terminal
    crate::kprintln!();
    crate::kprintln!();
    crate::kprintln!();

    // ASCII logo — compact, centered with leading spaces
    crate::kprintln!(
        "{}{}                         _    ___  ___{}",
        BOLD, FG_BLUE, RESET
    );
    crate::kprintln!(
        "{}{}                  ___  __| |_ / _ \\/ __|{}",
        BOLD, FG_BLUE, RESET
    );
    crate::kprintln!(
        "{}{}                 (_-< / _ \\  _| (_) \\__ \\{}",
        BOLD, FG_PURPLE, RESET
    );
    crate::kprintln!(
        "{}{}                 /__/ \\___/\\__|\\___/|___/{}",
        BOLD, FG_PURPLE, RESET
    );
    crate::kprintln!();
    crate::kprintln!(
        "{}                    v0.1.0 microkernel{}",
        FG_DARK, RESET
    );
    crate::kprintln!();

    // Empty progress bar
    draw_progress(0, "initializing...");
}

/// Update the progress bar to stage `n` (0-based) with `label`.
/// Redraws the progress bar line in-place using ANSI cursor control.
pub fn set_progress(stage: u8, label: &str) {
    draw_progress(stage.min(STAGE_COUNT), label);
}

/// Draw the progress bar at the current cursor position.
/// Uses ANSI codes to overwrite the previous bar.
///
/// Format:  `               [##########..........] Stage label`
///
/// CP437 block chars via UTF-8:
///   - filled:  \u{2588} (FULL BLOCK)
///   - empty:   \u{2591} (LIGHT SHADE)
fn draw_progress(filled_stages: u8, label: &str) {
    const BAR_WIDTH: usize = 25;

    // Calculate how many bar segments are filled
    let filled = if STAGE_COUNT > 0 {
        ((filled_stages as usize) * BAR_WIDTH) / (STAGE_COUNT as usize)
    } else {
        0
    };

    // Move to the progress bar line (line 11 from top, column 1)
    // Use absolute positioning so repeated calls overwrite
    crate::kprint!("\x1b[11;1H");

    // Leading padding for centering (~80 col terminal)
    crate::kprint!("                 ");

    // Opening bracket
    crate::kprint!("{}[", FG_DARK);

    // Filled portion (single color switch)
    crate::kprint!("{}", FG_CYAN);
    for _ in 0..filled {
        crate::kprint!("\u{2588}");
    }

    // Empty portion (single color switch)
    crate::kprint!("{}", FG_DARK);
    for _ in filled..BAR_WIDTH {
        crate::kprint!("\u{2591}");
    }

    // Closing bracket + label
    crate::kprint!("] {}{}{}", FG_GREEN, label, RESET);

    // Clear to end of line (remove leftover chars from longer labels)
    crate::kprint!("\x1b[K");
    crate::kprintln!();
}

/// Called when all stages complete — finalize the splash.
/// Shows cursor again and prints the "ready" line.
pub fn finish() {
    draw_progress(STAGE_COUNT, "ready");
    crate::kprintln!();
    crate::kprintln!(
        "{}                 Kernel ready \u{2014} entering idle loop{}",
        FG_GREEN, RESET
    );
    crate::kprintln!();
    // Show cursor again
    crate::kprint!("\x1b[?25h");
}

