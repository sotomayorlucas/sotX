//! Runtime trace facility for the LUCAS shell.
//!
//! Trace output is written to fd 2 (stderr) so it never mixes with
//! normal shell stdout. The `shell_trace!` macro is feature-gated on
//! `trace` (default on) and compiles to nothing when the feature is off.

use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

/// Current maximum trace verbosity (0=Error .. 4=Trace).
pub static TRACE_LEVEL: AtomicU8 = AtomicU8::new(3); // Debug

/// Bitmask of enabled trace categories (all enabled by default).
pub static TRACE_CATS: AtomicU16 = AtomicU16::new(0xFFFF);

/// Set the trace verbosity ceiling. Values above 4 are clamped.
pub fn set_level(level: u8) {
    TRACE_LEVEL.store(level.min(4), Ordering::Relaxed);
}

/// Replace the category bitmask wholesale.
pub fn set_categories(mask: u16) {
    TRACE_CATS.store(mask, Ordering::Relaxed);
}

/// Return the current category bitmask.
pub fn get_categories() -> u16 {
    TRACE_CATS.load(Ordering::Relaxed)
}

/// Return the current level byte.
pub fn get_level() -> u8 {
    TRACE_LEVEL.load(Ordering::Relaxed)
}

/// Check whether a message at `level` in `cat` should be emitted.
pub fn trace_enabled(level: sotos_common::trace::TraceLevel, cat: u16) -> bool {
    level.as_byte() <= TRACE_LEVEL.load(Ordering::Relaxed)
        && (cat & TRACE_CATS.load(Ordering::Relaxed)) != 0
}

// ---------------------------------------------------------------
// Low-level write helper (fd 2)
// ---------------------------------------------------------------

#[inline(always)]
fn write_stderr(buf: &[u8]) {
    crate::syscall::linux_write(2, buf.as_ptr(), buf.len());
}

#[cfg(feature = "trace")]
pub fn write_prefix(level: sotos_common::trace::TraceLevel, cat: u16) {
    let label = level.label();
    write_stderr(b"[");
    write_stderr(core::slice::from_ref(&label));
    write_stderr(b" ");
    write_stderr(sotos_common::trace::cat_name_bytes(cat));
    write_stderr(b"] ");
}

#[cfg(feature = "trace")]
pub fn write_newline() {
    write_stderr(b"\n");
}

#[cfg(feature = "trace")]
pub fn trace_write(buf: &[u8]) {
    write_stderr(buf);
}

/// Write a u64 in decimal to stderr.
#[cfg(feature = "trace")]
pub fn trace_write_u64(mut n: u64) {
    if n == 0 {
        write_stderr(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0usize;
    while j < i / 2 {
        let tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
        j += 1;
    }
    write_stderr(&buf[..i]);
}

/// Write a u64 in hex to stderr (with 0x prefix).
#[cfg(feature = "trace")]
pub fn trace_write_hex(val: u64) {
    write_stderr(b"0x");
    if val == 0 {
        write_stderr(b"0");
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 0usize;
    let mut tmp = val;
    while tmp != 0 {
        let nib = (tmp & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        tmp >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write_stderr(&buf[i..i + 1]);
    }
}

// ---------------------------------------------------------------
// Macros
// ---------------------------------------------------------------

/// Emit a structured trace message when the `trace` feature is enabled.
///
/// Usage: `shell_trace!(Info, PROCESS, { trace_write(b"exec: "); trace_write(name); })`
///
/// The body block is only evaluated when the level/category is enabled.
/// Output goes to fd 2 (stderr).
#[cfg(feature = "trace")]
#[macro_export]
macro_rules! shell_trace {
    ($level:ident, $cat:ident, $body:block) => {
        {
            use sotos_common::trace::{TraceLevel, cat};
            if $crate::trace::trace_enabled(TraceLevel::$level, cat::$cat) {
                $crate::trace::write_prefix(TraceLevel::$level, cat::$cat);
                $body
                $crate::trace::write_newline();
            }
        }
    };
}

/// No-op when `trace` feature is off.
#[cfg(not(feature = "trace"))]
#[macro_export]
macro_rules! shell_trace {
    ($level:ident, $cat:ident, $body:block) => { {} };
}

/// Convenience: trace command execution at Info/PROCESS level.
///
/// Usage: `shell_trace_cmd!(cmd_name_bytes)`
#[cfg(feature = "trace")]
#[macro_export]
macro_rules! shell_trace_cmd {
    ($cmd:expr) => {
        $crate::shell_trace!(Info, PROCESS, {
            $crate::trace::trace_write(b"cmd: ");
            $crate::trace::trace_write($cmd);
        });
    };
}

#[cfg(not(feature = "trace"))]
#[macro_export]
macro_rules! shell_trace_cmd {
    ($cmd:expr) => { {} };
}
