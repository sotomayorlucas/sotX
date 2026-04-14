//! Built-in: `cap` — inspect the current process's capability set.
//!
//! Enumerates the kernel capability table via `sys::cap_list` (syscall 190).
//! Replaces the Wave-2 empty-Table stub (PR #114) now that the B1.5c
//! kernel syscall + `sotos_common` wrapper exist.
//!
//! Row schema: `[("cap_id", Value::Int), ("kind", Value::Str), ("rights", Value::Str)]`.
//!
//! Required capabilities: none (see [`super::required_caps`]).

use alloc::string::String;
use alloc::vec::Vec;

use sotos_common::{sys, CapInfo};

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

/// Safety cap: never request more than this many entries from the kernel,
/// regardless of how large the cap table actually is. Matches the kernel's
/// `CAP_LIST_MAX`.
const MAX_ENTRIES: usize = 64;

/// Map a [`CapInfo::KIND_*`] discriminant to a short display name.
fn kind_name(kind: u32) -> &'static str {
    match kind {
        CapInfo::KIND_NULL => "null",
        CapInfo::KIND_MEMORY => "memory",
        CapInfo::KIND_ENDPOINT => "endpoint",
        CapInfo::KIND_CHANNEL => "channel",
        CapInfo::KIND_THREAD => "thread",
        CapInfo::KIND_IRQ => "irq",
        CapInfo::KIND_IOPORT => "ioport",
        CapInfo::KIND_NOTIFICATION => "notify",
        CapInfo::KIND_DOMAIN => "domain",
        CapInfo::KIND_ADDR_SPACE => "addrspace",
        CapInfo::KIND_INTERPOSED => "interposed",
        CapInfo::KIND_VM => "vm",
        CapInfo::KIND_MSI => "msi",
        _ => "other",
    }
}

/// Render the `Rights` bitmask as a compact `rwxgv`-style string.
///
/// Bits (from `kernel::cap::Rights`): READ=1, WRITE=2, EXECUTE=4,
/// GRANT=8, REVOKE=16.
fn rights_str(rights: u32) -> String {
    let mut s = String::with_capacity(5);
    s.push(if rights & 0x01 != 0 { 'r' } else { '-' });
    s.push(if rights & 0x02 != 0 { 'w' } else { '-' });
    s.push(if rights & 0x04 != 0 { 'x' } else { '-' });
    s.push(if rights & 0x08 != 0 { 'g' } else { '-' });
    s.push(if rights & 0x10 != 0 { 'v' } else { '-' });
    s
}

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let mut buf = [CapInfo::zeroed(); MAX_ENTRIES];
    let n = sys::cap_list(&mut buf).map_err(|e| Error::Io(e as i32))?;

    let mut rows: Vec<Row> = Vec::with_capacity(n);
    for entry in &buf[..n] {
        rows.push(
            Row::new()
                .with("cap_id", Value::Int(entry.cap_id as i64))
                .with("kind", Value::Str(kind_name(entry.kind).into()))
                .with("rights", Value::Str(rights_str(entry.rights))),
        );
    }
    Ok(Value::Table(rows))
}
