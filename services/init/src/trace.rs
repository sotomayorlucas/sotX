// ---------------------------------------------------------------------------
// Structured tracing for the init process.
//
// Runtime-configurable level and category filtering via atomics.
// Feature-gated: `trace` feature enables output, otherwise macros are no-ops.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

/// Current maximum trace level (inclusive). Default: Debug (3).
pub(crate) static TRACE_LEVEL: AtomicU8 = AtomicU8::new(3);

/// Enabled category bitmask. Default: ALL (0xFFFF).
pub(crate) static TRACE_CATS: AtomicU16 = AtomicU16::new(0xFFFF);

/// Check if a trace at the given level and category should be emitted.
#[inline]
pub(crate) fn trace_enabled(level: sotos_common::trace::TraceLevel, cat: u16) -> bool {
    level.as_byte() <= TRACE_LEVEL.load(Ordering::Relaxed)
        && (TRACE_CATS.load(Ordering::Relaxed) & cat) != 0
}

// ---------------------------------------------------------------------------
// Macros (active when `trace` feature is enabled)
// ---------------------------------------------------------------------------

/// Emit a structured trace line: `[L CAT] <body>\n`
///
/// Usage: `trace!(Info, PROCESS, { print(b"hello"); print_u64(42); })`
#[cfg(feature = "trace")]
macro_rules! trace {
    ($level:ident, $cat:ident, $body:block) => {{
        use sotos_common::trace::{TraceLevel, cat};
        if $crate::trace::trace_enabled(TraceLevel::$level, cat::$cat) {
            let prefix: &[u8] = match TraceLevel::$level {
                TraceLevel::Error => b"[E ",
                TraceLevel::Warn  => b"[W ",
                TraceLevel::Info  => b"[I ",
                TraceLevel::Debug => b"[D ",
                TraceLevel::Trace => b"[T ",
            };
            $crate::framebuffer::print(prefix);
            $crate::framebuffer::print(sotos_common::trace::cat_name_bytes(cat::$cat));
            $crate::framebuffer::print(b"] ");
            $body
            $crate::framebuffer::print(b"\n");
        }
    }};
}

/// Emit a standardized syscall trace line.
///
/// Usage: `trace_syscall!(pid, nr, arg0, ret)`
#[cfg(feature = "trace")]
macro_rules! trace_syscall {
    ($pid:expr, $nr:expr, $arg0:expr, $ret:expr) => {{
        use sotos_common::trace::{TraceLevel, cat};
        if $crate::trace::trace_enabled(TraceLevel::Debug, cat::SYSCALL) {
            $crate::framebuffer::print(b"[D SYSCALL] P");
            $crate::framebuffer::print_u64($pid as u64);
            $crate::framebuffer::print(b" ");
            $crate::framebuffer::print(sotos_common::trace::syscall_name($nr as u64));
            $crate::framebuffer::print(b"(");
            $crate::framebuffer::print_u64($nr as u64);
            $crate::framebuffer::print(b") arg0=0x");
            $crate::framebuffer::print_hex64($arg0 as u64);
            $crate::framebuffer::print(b" ret=");
            let __ret = $ret as i64;
            if __ret < 0 {
                $crate::framebuffer::print(b"-");
                $crate::framebuffer::print_u64((-__ret) as u64);
            } else {
                $crate::framebuffer::print_u64(__ret as u64);
            }
            $crate::framebuffer::print(b"\n");
        }
    }};
}

// ---------------------------------------------------------------------------
// No-op versions when `trace` feature is disabled
// ---------------------------------------------------------------------------

#[cfg(not(feature = "trace"))]
macro_rules! trace {
    ($level:ident, $cat:ident, $body:block) => { };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace_syscall {
    ($pid:expr, $nr:expr, $arg0:expr, $ret:expr) => { };
}

pub(crate) use trace;
pub(crate) use trace_syscall;
