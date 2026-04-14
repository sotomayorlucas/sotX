//! Built-in: `cd` — change the shell's working directory.
//!
//! Required capabilities: none (see [`super::required_caps`]).
//!
//! B1 port: stubbed. B2a rewrites this body to resolve paths through
//! `sotos_common::sys` (sotOS has no per-process chdir syscall today, so
//! the real impl will manage `Context::cwd` client-side and verify
//! targets via `openat(O_DIRECTORY)`).

use alloc::string::ToString;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    // TODO(B2a): rewrite with sotos_common::sys::openat(O_DIRECTORY) and
    //            ctx.cwd mutation.
    Ok(Value::Str(
        "not implemented — B2a rewrites this with syscalls".to_string(),
    ))
}
