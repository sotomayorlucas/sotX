//! Kernel-side structured tracing.
//!
//! Provides runtime-filterable trace macros that delegate to the existing
//! `kprint!`/`kprintln!` serial output. Filters use `Ordering::Relaxed`
//! atomics — cheap to read, no memory fences needed for diagnostic output.

use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

/// Runtime trace level threshold (default: Debug=3 to show everything in dev).
pub static TRACE_LEVEL: AtomicU8 = AtomicU8::new(3);

/// Runtime category mask (default: all categories enabled).
pub static TRACE_CATS: AtomicU16 = AtomicU16::new(0xFFFF);

/// Set the maximum trace level that will be emitted (0=Error only .. 4=Trace).
pub fn set_level(level: u8) {
    TRACE_LEVEL.store(level.min(4), Ordering::Relaxed);
}

/// Set the category bitmask — only categories with set bits will be emitted.
pub fn set_categories(mask: u16) {
    TRACE_CATS.store(mask, Ordering::Relaxed);
}

/// Core trace macro. Gated on the `verbose` feature. Checks both the level
/// threshold and the category mask before emitting output.
///
/// Usage: `ktrace!(TraceLevel::Info, cat::MM, "frame count: {}", n);`
#[macro_export]
macro_rules! ktrace {
    ($level:expr, $cat:expr, $($arg:tt)*) => {
        #[cfg(feature = "verbose")]
        {
            let lvl: sotos_common::trace::TraceLevel = $level;
            let cat_mask: u16 = $cat;
            if (lvl as u8) <= $crate::trace::TRACE_LEVEL.load(core::sync::atomic::Ordering::Relaxed)
                && (cat_mask & $crate::trace::TRACE_CATS.load(core::sync::atomic::Ordering::Relaxed)) != 0
            {
                let name_bytes = sotos_common::trace::cat_name_bytes(cat_mask);
                let name_str = match core::str::from_utf8(name_bytes) {
                    Ok(s) => s,
                    Err(_) => "???",
                };
                $crate::kprint!("[");
                $crate::kprint!("{}", lvl.as_byte() as char);
                $crate::kprint!(" ");
                $crate::kprint!("{}", name_str);
                $crate::kprint!("] ");
                $crate::kprintln!($($arg)*);
            }
        }
    };
}

/// Error-level trace (always compiled — not gated on `verbose`).
/// Only the category mask is checked; errors are never filtered by level.
#[macro_export]
macro_rules! kerror {
    ($cat:expr, $($arg:tt)*) => {
        {
            let cat_mask: u16 = $cat;
            if (cat_mask & $crate::trace::TRACE_CATS.load(core::sync::atomic::Ordering::Relaxed)) != 0
            {
                let name_bytes = sotos_common::trace::cat_name_bytes(cat_mask);
                let name_str = match core::str::from_utf8(name_bytes) {
                    Ok(s) => s,
                    Err(_) => "???",
                };
                $crate::kprint!("[");
                $crate::kprint!("{}", sotos_common::trace::TraceLevel::Error.as_byte() as char);
                $crate::kprint!(" ");
                $crate::kprint!("{}", name_str);
                $crate::kprint!("] ");
                $crate::kprintln!($($arg)*);
            }
        }
    };
}

/// Warn-level trace (gated on `verbose`).
#[macro_export]
macro_rules! kwarn {
    ($cat:expr, $($arg:tt)*) => {
        $crate::ktrace!(sotos_common::trace::TraceLevel::Warn, $cat, $($arg)*)
    };
}

/// Info-level trace (gated on `verbose`).
#[macro_export]
macro_rules! kinfo {
    ($cat:expr, $($arg:tt)*) => {
        $crate::ktrace!(sotos_common::trace::TraceLevel::Info, $cat, $($arg)*)
    };
}

/// Debug-level trace (gated on `verbose`).
#[macro_export]
macro_rules! kdtrace {
    ($cat:expr, $($arg:tt)*) => {
        $crate::ktrace!(sotos_common::trace::TraceLevel::Debug, $cat, $($arg)*)
    };
}

/// Trace-level (most verbose) trace (gated on `verbose`).
#[macro_export]
macro_rules! ktrace_v {
    ($cat:expr, $($arg:tt)*) => {
        $crate::ktrace!(sotos_common::trace::TraceLevel::Trace, $cat, $($arg)*)
    };
}
