//! Built-in: `ls` — list directory contents.
//!
//! Required capabilities: `fs:read` (see [`super::required_caps`]).
//!
//! B1 port: stubbed. B2a rewrites this body over
//! `sotos_common::sys::openat` / `read` / `getdents64` once those entry
//! points reach the shell. The host-std prototype used `std::fs::read_dir`.

use alloc::string::ToString;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    // TODO(B2a): rewrite with sotos_common::sys::openat / read / getdents64.
    Ok(Value::Str(
        "not implemented — B2a rewrites this with syscalls".to_string(),
    ))
}
