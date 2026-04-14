//! Built-in: `cap` — inspect the current process's capability set.
//!
//! TODO: replace stub once sotsh runs under sotOS. Will enumerate the
//! per-thread capability table via a syscall (TBD — candidates:
//! `sotos-common::sys` inventory of cap-related calls).
//!
//! Future row schema (once real):
//!   `[("cap_id", Value::Int), ("type", Value::Str), ("rights", Value::Str)]`
//!
//! Required capabilities: none (see [`super::required_caps`]).

use alloc::vec::Vec;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    Ok(Value::Table(Vec::new()))
}
