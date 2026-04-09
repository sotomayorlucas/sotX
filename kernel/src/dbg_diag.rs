//! Recursion-free serial diagnostics. Bypasses `kprintln` entirely (no
//! `SERIAL_LOCK`, no `fmt::Write`, no `current_percpu` lookups).
//!
//! Use these primitives to instrument code paths that *call* (or live
//! inside) `current_percpu`, `lock_order::*`, the panic handler, the
//! syscall/interrupt entry stubs, or anything else where invoking the
//! normal print macros would either deadlock or recurse-fault.
//!
//! Functions are gated behind `#[allow(dead_code)]` because they exist
//! to be hot-patched in during a debug session and are not part of the
//! normal kernel print path.

use crate::arch::x86_64::serial::write_byte;

#[allow(dead_code)]
#[inline]
fn write_str_raw(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

#[allow(dead_code)]
#[inline]
fn write_hex_u64(value: u64) {
    write_byte(b'0');
    write_byte(b'x');
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nib = ((value >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
    }
    for &c in buf.iter() {
        write_byte(c);
    }
}

/// Print `label` followed by `value` in hex. NO trailing newline.
#[allow(dead_code)]
#[inline]
pub fn dbg_say(label: &str, value: u64) {
    write_str_raw(label);
    write_hex_u64(value);
}

#[allow(dead_code)]
#[inline]
pub fn dbg_nl() {
    write_byte(b'\r');
    write_byte(b'\n');
}
